"""Tests for radar.calibration.scenario_apply (Phase 1 of the
scenario_improver ↔ tier governor seam fix, 2026-05-08).

Pins the contract that:
  - applying a proposal mutates the live scenarios / scenario_participants
    tables (the bug being fixed)
  - the analyst Apply route and the future auto-apply path produce
    identical mutations — same call, same result
  - every supported proposal_type rewrites the participant set correctly
  - guard rails: non-pending / unsupported / inactive scenario all
    refuse to mutate AND leave the ledger untouched
  - applied proposal row gets state_changed_by populated for NP6 trail
"""
from __future__ import annotations

import json
import os
import time
import uuid

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

import pytest  # noqa: E402

from radar.calibration.scenario_apply import (  # noqa: E402
    apply_scenario_improver_proposal,
)
from radar.database import db  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def _proposals_sandbox():
    conn = db._get_conn()  # noqa: SLF001
    cols = [d[0] for d in conn.execute(
        "SELECT * FROM scenario_proposals LIMIT 0"
    ).description]
    rows = list(conn.execute(
        f"SELECT {','.join(cols)} FROM scenario_proposals"
    ))
    with conn.writing():
        conn.execute("DELETE FROM scenario_proposals")
    yield (conn, cols)
    with conn.writing():
        conn.execute("DELETE FROM scenario_proposals")
        if rows:
            placeholders = ",".join("?" for _ in cols)
            conn.executemany(
                f"INSERT INTO scenario_proposals ({','.join(cols)}) "
                f"VALUES ({placeholders})",
                [tuple(r) for r in rows],
            )


@pytest.fixture
def _scenarios_sandbox():
    """Create + cleanup test scenarios. We write our own scenarios so
    we never mutate the production preset rows."""
    conn = db._get_conn()  # noqa: SLF001
    test_ids: list[str] = []
    yield (conn, test_ids)
    with conn.writing():
        for sid in test_ids:
            conn.execute("DELETE FROM scenario_participants "
                         "WHERE scenario_id=?", (sid,))
            conn.execute("DELETE FROM scenarios WHERE id=?", (sid,))
            conn.execute("DELETE FROM scenario_change_log "
                         "WHERE scenario_id=?", (sid,))


def _make_test_scenario(conn, sid: str, *, state: str = "active",
                          participants: dict | None = None) -> None:
    if participants is None:
        participants = {
            "TW": {"weight": 1.0, "role": "primary_target"},
            "US": {"weight": 0.85, "role": "primary_ally"},
        }
    now = time.time()
    with conn.writing():
        conn.execute(
            "INSERT INTO scenarios "
            "(id, name_en, name_ja, description_en, description_ja, "
            " core_country, state, enabled, tier, created_at, updated_at) "
            "VALUES (?, ?, ?, '', '', ?, ?, 1, 'L1', ?, ?)",
            (sid, sid, sid,
             list(participants.keys())[0] if participants else None,
             state, now, now),
        )
        for cc, pdata in participants.items():
            conn.execute(
                "INSERT INTO scenario_participants "
                "(scenario_id, country, weight, role) "
                "VALUES (?, ?, ?, ?)",
                (sid, cc, float(pdata["weight"]), pdata["role"]),
            )


def _insert_proposal(
    conn, *,
    scenario_id: str,
    proposal_type: str,
    target_country: "str | None",
    suggested_value: dict,
    state: str = "pending",
) -> int:
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, "
            " sample_n, why_string, state) "
            "VALUES (?, ?, ?, ?, ?, '{}', 'test#v1', 0, 'test', ?)",
            (time.time(), scenario_id, proposal_type, target_country,
             json.dumps(suggested_value), state),
        )
        return int(cur.lastrowid)


def _participants(conn, scenario_id: str) -> dict:
    rows = conn.execute(
        "SELECT country, weight, role FROM scenario_participants "
        "WHERE scenario_id=?", (scenario_id,),
    ).fetchall()
    return {r["country"]: {"weight": r["weight"], "role": r["role"]}
            for r in rows}


def _proposal_state(conn, pid: int) -> tuple:
    row = conn.execute(
        "SELECT state, state_changed_by FROM scenario_proposals "
        "WHERE id=?", (pid,),
    ).fetchone()
    return (row["state"], row["state_changed_by"]) if row else (None, None)


# ── weight_too_low / weight_too_high ─────────────────────────────────────────


class TestWeightProposals:
    def test_weight_too_low_raises_weight(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_w_low_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 0.40, "role": "primary_target"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="weight_too_low",
            target_country="TW",
            suggested_value={"weight": 0.85, "from": 0.40},
        )

        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )

        assert result.ok is True
        assert result.proposal_type == "weight_too_low"
        assert result.target_country == "TW"
        # Mutation persisted.
        assert _participants(s_conn, sid)["TW"]["weight"] == 0.85
        # Ledger flipped with attribution.
        st, by = _proposal_state(conn, pid)
        assert st == "applied"
        assert by == "admin:test"

    def test_weight_too_high_lowers_weight(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_w_high_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 0.95, "role": "primary_target"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="weight_too_high",
            target_country="TW",
            suggested_value={"weight": 0.40, "from": 0.95},
        )

        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )

        assert result.ok is True
        assert _participants(s_conn, sid)["TW"]["weight"] == 0.40

    def test_weight_proposal_preserves_role(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        """Weight-only mutations must NOT change role."""
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_role_preserve_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 0.40, "role": "forward_base"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="weight_too_low",
            target_country="TW",
            suggested_value={"weight": 0.85},
        )

        apply_scenario_improver_proposal(pid, applied_by="admin:test")

        assert _participants(s_conn, sid)["TW"]["role"] == "forward_base"


# ── missing_participant ─────────────────────────────────────────────────────


class TestMissingParticipant:
    def test_adds_new_participant(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_missing_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 1.0, "role": "primary_target"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="missing_participant",
            target_country="JP",
            suggested_value={"weight": 0.30, "role": "strategic_observer"},
        )

        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )

        assert result.ok is True
        ps = _participants(s_conn, sid)
        assert "JP" in ps
        assert ps["JP"]["weight"] == 0.30
        assert ps["JP"]["role"] == "strategic_observer"
        # Existing participants untouched.
        assert ps["TW"]["weight"] == 1.0

    def test_rejects_when_already_participant(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_already_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 1.0, "role": "primary_target"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="missing_participant",
            target_country="TW",  # already there
            suggested_value={"weight": 0.30, "role": "strategic_observer"},
        )

        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )

        assert result.ok is False
        assert "target_already_participant" in result.error
        # Ledger unchanged.
        st, by = _proposal_state(conn, pid)
        assert st == "pending"
        assert by is None


# ── dormant_participant ─────────────────────────────────────────────────────


class TestDormantParticipant:
    def test_lowers_weight_to_floor(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_dormant_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 0.85, "role": "primary_target"},
            "JP": {"weight": 0.55, "role": "primary_ally"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="dormant_participant",
            target_country="JP",
            suggested_value={"weight_from": 0.55, "weight_to": 0.10,
                             "action_hint": "review_relevance"},
        )

        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )

        assert result.ok is True
        ps = _participants(s_conn, sid)
        assert ps["JP"]["weight"] == 0.10
        assert ps["TW"]["weight"] == 0.85  # untouched


# ── role_reclassify ─────────────────────────────────────────────────────────


class TestRoleReclassify:
    def test_changes_role(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_role_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 1.0, "role": "primary_target"},
            "JP": {"weight": 0.55, "role": "strategic_observer"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="role_reclassify",
            target_country="JP",
            suggested_value={"role_from": "strategic_observer",
                             "role_to": "primary_ally",
                             "weight": 0.55},
        )

        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )

        assert result.ok is True
        ps = _participants(s_conn, sid)
        assert ps["JP"]["role"] == "primary_ally"
        # Weight preserved (rule-of-thumb: role change does not move weight).
        assert ps["JP"]["weight"] == 0.55


# ── Guard paths ─────────────────────────────────────────────────────────────


class TestGuards:
    def test_unknown_proposal_type_refuses(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_unknown_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid)
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="scenario_discovery",
            target_country=None,
            suggested_value={},
        )
        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )
        assert result.ok is False
        assert "unsupported_proposal_type" in result.error
        st, _ = _proposal_state(conn, pid)
        assert st == "pending"

    def test_already_applied_proposal_refuses(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_alreadyapplied_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid)
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="weight_too_low",
            target_country="TW",
            suggested_value={"weight": 0.85},
            state="applied",
        )
        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )
        assert result.ok is False
        assert "proposal_not_pending" in result.error

    def test_inactive_scenario_refuses(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_paused_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, state="paused")
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="weight_too_low",
            target_country="TW",
            suggested_value={"weight": 0.85},
        )
        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )
        assert result.ok is False
        assert "scenario_not_active" in result.error
        st, _ = _proposal_state(conn, pid)
        assert st == "pending"

    def test_missing_proposal_id_refuses(
        self, _proposals_sandbox,
    ):
        result = apply_scenario_improver_proposal(
            999_999_999, applied_by="admin:test",
        )
        assert result.ok is False
        assert "proposal_not_found" in result.error

    def test_target_not_a_participant_refuses(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_nopart_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 1.0, "role": "primary_target"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="weight_too_low",
            target_country="JP",  # not a participant
            suggested_value={"weight": 0.85},
        )
        result = apply_scenario_improver_proposal(
            pid, applied_by="admin:test",
        )
        assert result.ok is False
        assert "target_not_a_participant" in result.error


# ── Symmetry: analyst route and auto-apply share the same primitive ─────────


class TestApplyByContractIsSourceAgnostic:
    """Same call, same result — regardless of `applied_by` source.
    Future Phase-3 auto-apply path will pass an
    'auto:scenario_improver:<type>' marker; analyst path passes
    'admin:<jwt_id>'. Both must produce identical mutations."""

    @pytest.mark.parametrize("applied_by", [
        "admin:alice",
        "auto:scenario_improver:weight_too_low",
    ])
    def test_mutation_is_actor_agnostic(
        self, _proposals_sandbox, _scenarios_sandbox, applied_by,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_actor_" + uuid.uuid4().hex[:8]
        _make_test_scenario(s_conn, sid, participants={
            "TW": {"weight": 0.40, "role": "primary_target"},
        })
        test_ids.append(sid)
        pid = _insert_proposal(
            conn, scenario_id=sid, proposal_type="weight_too_low",
            target_country="TW",
            suggested_value={"weight": 0.85},
        )
        result = apply_scenario_improver_proposal(
            pid, applied_by=applied_by,
        )
        assert result.ok is True
        assert _participants(s_conn, sid)["TW"]["weight"] == 0.85
        # `state_changed_by` propagates whatever the caller passed.
        _, by = _proposal_state(conn, pid)
        assert by == applied_by
