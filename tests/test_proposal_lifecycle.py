"""Tests for radar.calibration.proposal_lifecycle (D1 + D2 of the
2026-05-08 mechanical-auto-process closing).

D1: auto_dismiss_inactive_scenario_proposals
    pending proposal on a paused / archived scenario → dismissed
D2: supersede_duplicate_pending
    new pending proposal of same (scenario, type, target_country) →
    older pending rows marked superseded
"""
from __future__ import annotations

import os
import time

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

import pytest  # noqa: E402

from radar.calibration import proposal_lifecycle as pl  # noqa: E402
from radar.database import db  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def _proposals_sandbox():
    """Snapshot/restore scenario_proposals so tests don't leak."""
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
    """Snapshot/restore the scenarios table around tests that mutate
    scenario state. We add and remove specific test scenarios so we
    don't perturb the production preset set."""
    conn = db._get_conn()  # noqa: SLF001
    test_ids: list[str] = []
    yield (conn, test_ids)
    with conn.writing():
        for sid in test_ids:
            conn.execute("DELETE FROM scenarios WHERE id=?", (sid,))


def _insert_scenario(conn, *, sid: str, state: str = "active") -> None:
    """Minimal scenarios row insert. Schema columns:
    id / name_en / name_ja / description_en / description_ja /
    core_country / state / enabled / tier / created_at / updated_at /
    updated_by."""
    with conn.writing():
        conn.execute(
            "INSERT INTO scenarios "
            "(id, name_en, name_ja, description_en, description_ja, "
            " core_country, state, enabled, tier, created_at, updated_at) "
            "VALUES (?, ?, ?, '', '', NULL, ?, 1, 'L1', ?, ?)",
            (sid, sid, sid, state, time.time(), time.time()),
        )


def _insert_proposal(
    conn, *,
    scenario_id: str,
    proposal_type: str = "weight_too_high",
    state: str = "pending",
    target_country: "str | None" = None,
    emitted_at: "float | None" = None,
) -> int:
    if emitted_at is None:
        emitted_at = time.time()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, "
            " sample_n, why_string, state) "
            "VALUES (?, ?, ?, ?, '{}', '{}', 'test#v1', 0, 'test', ?)",
            (float(emitted_at), scenario_id, proposal_type,
             target_country, state),
        )
        return int(cur.lastrowid)


# ── D1: auto_dismiss_inactive_scenario_proposals ─────────────────────────────


class TestAutoDismissInactive:
    def test_no_inactive_scenarios_returns_zero(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        _insert_scenario(s_conn, sid="test_active", state="active")
        test_ids.append("test_active")
        _insert_proposal(conn, scenario_id="test_active")
        assert pl.auto_dismiss_inactive_scenario_proposals() == 0

    def test_dismisses_pending_on_paused_scenario(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        _insert_scenario(s_conn, sid="test_paused", state="paused")
        test_ids.append("test_paused")
        pid = _insert_proposal(conn, scenario_id="test_paused")
        assert pl.auto_dismiss_inactive_scenario_proposals() == 1
        row = conn.execute(
            "SELECT state, state_changed_by FROM scenario_proposals "
            "WHERE id=?", (pid,),
        ).fetchone()
        assert row["state"] == "dismissed"
        assert row["state_changed_by"] == "auto:inactive_scenario"

    def test_dismisses_pending_on_archived_scenario(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        _insert_scenario(s_conn, sid="test_archived", state="archived")
        test_ids.append("test_archived")
        _insert_proposal(conn, scenario_id="test_archived")
        assert pl.auto_dismiss_inactive_scenario_proposals() == 1

    def test_does_not_touch_already_resolved_proposals(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        """Only state='pending' rows are dismissed. Applied / dismissed
        / superseded rows are history."""
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        _insert_scenario(s_conn, sid="test_paused2", state="paused")
        test_ids.append("test_paused2")
        _insert_proposal(conn, scenario_id="test_paused2",
                          state="applied")
        _insert_proposal(conn, scenario_id="test_paused2",
                          state="dismissed")
        assert pl.auto_dismiss_inactive_scenario_proposals() == 0

    def test_idempotent(self, _proposals_sandbox, _scenarios_sandbox):
        conn, _ = _proposals_sandbox
        s_conn, test_ids = _scenarios_sandbox
        _insert_scenario(s_conn, sid="test_paused3", state="paused")
        test_ids.append("test_paused3")
        _insert_proposal(conn, scenario_id="test_paused3")
        assert pl.auto_dismiss_inactive_scenario_proposals() == 1
        assert pl.auto_dismiss_inactive_scenario_proposals() == 0


# ── D2: supersede_duplicate_pending ─────────────────────────────────────────


class TestSupersedeDuplicatePending:
    def test_supersedes_older_same_target_country(
        self, _proposals_sandbox,
    ):
        conn, _ = _proposals_sandbox
        old = _insert_proposal(
            conn, scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW",
            emitted_at=time.time() - 10 * 86400.0,  # 10 days ago
        )
        new = _insert_proposal(
            conn, scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW",
        )
        n = pl.supersede_duplicate_pending(
            scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW", new_proposal_id=new,
        )
        assert n == 1
        old_row = conn.execute(
            "SELECT state, state_changed_by FROM scenario_proposals "
            "WHERE id=?", (old,),
        ).fetchone()
        assert old_row["state"] == "superseded"
        assert old_row["state_changed_by"] == f"auto:supersede_by_id_{new}"
        # The new row stays pending.
        new_row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?", (new,),
        ).fetchone()
        assert new_row["state"] == "pending"

    def test_supersedes_older_when_target_country_is_null(
        self, _proposals_sandbox,
    ):
        """target_country IS NULL must match other NULL rows, not match
        rows where target_country is set. SQL NULL semantics caveat."""
        conn, _ = _proposals_sandbox
        old = _insert_proposal(
            conn, scenario_id="s1", proposal_type="role_reclassify",
            target_country=None,
            emitted_at=time.time() - 10 * 86400.0,
        )
        unrelated = _insert_proposal(
            conn, scenario_id="s1", proposal_type="role_reclassify",
            target_country="TW",
        )
        new = _insert_proposal(
            conn, scenario_id="s1", proposal_type="role_reclassify",
            target_country=None,
        )
        n = pl.supersede_duplicate_pending(
            scenario_id="s1", proposal_type="role_reclassify",
            target_country=None, new_proposal_id=new,
        )
        assert n == 1
        # Unrelated TW row must NOT be touched.
        unrelated_row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?",
            (unrelated,),
        ).fetchone()
        assert unrelated_row["state"] == "pending"

    def test_does_not_supersede_different_proposal_type(
        self, _proposals_sandbox,
    ):
        conn, _ = _proposals_sandbox
        weight_old = _insert_proposal(
            conn, scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW",
            emitted_at=time.time() - 10 * 86400.0,
        )
        role_new = _insert_proposal(
            conn, scenario_id="s1", proposal_type="role_reclassify",
            target_country="TW",
        )
        n = pl.supersede_duplicate_pending(
            scenario_id="s1", proposal_type="role_reclassify",
            target_country="TW", new_proposal_id=role_new,
        )
        assert n == 0
        weight_row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?",
            (weight_old,),
        ).fetchone()
        assert weight_row["state"] == "pending"

    def test_does_not_supersede_already_resolved_rows(
        self, _proposals_sandbox,
    ):
        """An older row already in dismissed/applied/superseded state
        is not re-marked. Mechanical safety: state transitions are
        terminal."""
        conn, _ = _proposals_sandbox
        old_dismissed = _insert_proposal(
            conn, scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW", state="dismissed",
            emitted_at=time.time() - 10 * 86400.0,
        )
        new = _insert_proposal(
            conn, scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW",
        )
        n = pl.supersede_duplicate_pending(
            scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW", new_proposal_id=new,
        )
        assert n == 0
        old_row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?",
            (old_dismissed,),
        ).fetchone()
        assert old_row["state"] == "dismissed"

    def test_does_not_supersede_self(self, _proposals_sandbox):
        """If the helper is called with new_proposal_id == an existing
        pending row's id, that row is excluded by id != ?."""
        conn, _ = _proposals_sandbox
        sole = _insert_proposal(
            conn, scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW",
        )
        n = pl.supersede_duplicate_pending(
            scenario_id="s1", proposal_type="weight_too_high",
            target_country="TW", new_proposal_id=sole,
        )
        assert n == 0
        sole_row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?",
            (sole,),
        ).fetchone()
        assert sole_row["state"] == "pending"
