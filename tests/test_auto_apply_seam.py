"""Tests for the scenario_improver auto-apply seam (Phase 3 of the
2026-05-08 closure). These verify the gate behaviour at the
`scenario_improver._emit` exit point — the contract is:

- Flag OFF → every emission stays pending regardless of tier.
- Flag ON + tier T0 → all stay pending.
- Flag ON + tier T1 + recall-positive → applied (NP1 honoured).
- Flag ON + tier T1 + recall-reducing → pending (impact too high).
- Flag ON + tier T3 + recall-reducing + strong evidence + non-protected
  role → applied + HIGH cooldown engaged.
- Flag ON + tier T3 + protected role → pending (NP7).
- Flag ON + tier T3 + weak evidence → pending (evidence floor).
- The mutation that lands is the same one the analyst path would
  produce — same primitive (apply_scenario_improver_proposal).
"""
from __future__ import annotations

import os
import time
import uuid

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

import pytest  # noqa: E402

from radar.calibration import scenario_improver  # noqa: E402
from radar.calibration import auto_apply_tier_governor as tg  # noqa: E402
from radar.calibration._proposal_writer import ProposalEvent  # noqa: E402
from radar.database import db  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def _scenarios_sandbox():
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
            conn.execute("DELETE FROM scenario_proposals "
                         "WHERE scenario_id=?", (sid,))


def _make_scenario(conn, sid: str, *,
                    participants: dict | None = None) -> None:
    if participants is None:
        participants = {
            "TC": {"weight": 0.40, "role": "primary_target"},
            "JP": {"weight": 0.55, "role": "primary_ally"},
        }
    now = time.time()
    with conn.writing():
        conn.execute(
            "INSERT INTO scenarios "
            "(id, name_en, name_ja, description_en, description_ja, "
            " core_country, state, enabled, tier, created_at, updated_at) "
            "VALUES (?, ?, ?, '', '', ?, 'active', 1, 'L1', ?, ?)",
            (sid, sid, sid,
             list(participants.keys())[0] if participants else None,
             now, now),
        )
        for cc, pdata in participants.items():
            conn.execute(
                "INSERT INTO scenario_participants "
                "(scenario_id, country, weight, role) "
                "VALUES (?, ?, ?, ?)",
                (sid, cc, float(pdata["weight"]), pdata["role"]),
            )


def _set_tier(conn, tier: int) -> None:
    """Force the tier governor to a specific tier by inserting a
    state row + marker. Both the latest_state_row and marker_get
    paths read these."""
    with conn.writing():
        conn.execute("DELETE FROM auto_apply_tier_state")
        conn.execute("DELETE FROM auto_apply_tier_marker")
        conn.execute("DELETE FROM auto_apply_cooldown")
        if tier > 0:
            conn.execute(
                "INSERT INTO auto_apply_tier_state "
                "(observed_at, tier, transition, reason, metrics_json) "
                "VALUES (?, ?, 'promote', 'test', '{}')",
                (time.time(), tier),
            )
            conn.execute(
                "INSERT INTO auto_apply_tier_marker "
                "(marker_key, tier, entered_at, updated_at, metadata_json) "
                "VALUES ('current_tier_entered_at', ?, ?, ?, '{}')",
                (tier, time.time() - 60 * 86400, time.time()),
            )


@pytest.fixture
def _gov_sandbox():
    """Snapshot/restore tier governor state around each test."""
    conn = db._get_conn()  # noqa: SLF001
    state_rows = list(conn.execute(
        "SELECT id, observed_at, tier, transition, reason, metrics_json "
        "FROM auto_apply_tier_state"
    ))
    marker_rows = list(conn.execute(
        "SELECT marker_key, tier, entered_at, updated_at, metadata_json "
        "FROM auto_apply_tier_marker"
    ))
    cooldown_rows = list(conn.execute(
        "SELECT impact_level, cooldown_until, triggered_by, set_at "
        "FROM auto_apply_cooldown"
    ))
    yield conn
    with conn.writing():
        conn.execute("DELETE FROM auto_apply_tier_state")
        conn.execute("DELETE FROM auto_apply_tier_marker")
        conn.execute("DELETE FROM auto_apply_cooldown")
        for r in state_rows:
            conn.execute(
                "INSERT INTO auto_apply_tier_state "
                "(id, observed_at, tier, transition, reason, metrics_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                tuple(r),
            )
        for r in marker_rows:
            conn.execute(
                "INSERT INTO auto_apply_tier_marker "
                "(marker_key, tier, entered_at, updated_at, metadata_json) "
                "VALUES (?, ?, ?, ?, ?)",
                tuple(r),
            )
        for r in cooldown_rows:
            conn.execute(
                "INSERT INTO auto_apply_cooldown "
                "(impact_level, cooldown_until, triggered_by, set_at) "
                "VALUES (?, ?, ?, ?)",
                tuple(r),
            )


@pytest.fixture(autouse=True)
def _force_scenario_reload(monkeypatch):
    """The auto-apply path calls scenario_store.reload(); without an
    actual scenario_store load happening (tests don't go through the
    app initializer), the reload is a no-op. Patch it to a noop so
    the apply path doesn't break, and patch the role-protection
    re-check to use the just-mutated DB row directly."""
    # No scenario_store dependency in the role guard path — it reads
    # via scenarios.scenario_store.get(). For tests we want it to
    # return a Scenario with the participants we set in DB. Easiest:
    # patch is_role_protected to inspect the DB participants table.
    def _is_role_protected_via_db(participant):
        # Test scenarios use plain dicts via scenario_store; this
        # patched version is only used when the test's _maybe_auto_apply
        # path looks up scenarios.scenario_store.get(...).
        from radar.calibration._proposal_guards import _role_value
        return _role_value(participant) in {
            "primary_target", "principal_belligerent", "adversary",
            "core_country",
        }

    # The auto-apply path also imports scenario_store; we need to
    # patch its `.get()` to construct an in-memory Scenario from
    # the test's DB rows so the role re-check passes.
    from radar import scenarios as _sc
    real_get = _sc.scenario_store.get

    def _get_or_synth(sid):
        live = real_get(sid)
        if live is not None:
            return live
        # Synthesise a minimal Scenario from DB.
        sc_data = db.scenario_get(sid)
        if sc_data is None:
            return None
        from radar.scenarios import Scenario, Participant, Role
        ps = {}
        for cc, pdata in (sc_data.get("participants") or {}).items():
            try:
                role = Role(pdata["role"])
            except Exception:
                role = Role.STRATEGIC_OBSERVER
            ps[cc] = Participant(country=cc, weight=pdata["weight"],
                                 role=role)
        return Scenario(
            id=sid,
            name_en=sc_data.get("name_en", sid),
            name_ja=sc_data.get("name_ja", sid),
            description_en="", description_ja="",
            core_country=sc_data.get("core_country"),
            state=sc_data.get("state", "active"),
            enabled=bool(sc_data.get("enabled", True)),
            tier=sc_data.get("tier", 1),
            participants=ps,
        )

    monkeypatch.setattr(_sc.scenario_store, "get", _get_or_synth)
    yield


def _emit_event(*, scenario_id, proposal_type, target_country,
                 suggested_value, evidence_strength="strong",
                 vitality_state="active") -> int | None:
    return scenario_improver._emit(
        ProposalEvent(
            scenario_id=scenario_id,
            proposal_type=proposal_type,
            target_country=target_country,
            suggested_value=suggested_value,
            evidence={},
            formula_ref="test#auto_apply_seam",
            sample_n=20,
            why_string="test",
        ),
        evidence_strength=evidence_strength,
        vitality_state=vitality_state,
    )


def _proposal_state(conn, pid: int) -> tuple:
    row = conn.execute(
        "SELECT state, state_changed_by FROM scenario_proposals WHERE id=?",
        (pid,),
    ).fetchone()
    return (row["state"], row["state_changed_by"]) if row else (None, None)


def _participant(conn, sid: str, cc: str) -> dict | None:
    row = conn.execute(
        "SELECT weight, role FROM scenario_participants "
        "WHERE scenario_id=? AND country=?",
        (sid, cc),
    ).fetchone()
    return dict(row) if row else None


# ── Flag OFF ─────────────────────────────────────────────────────────────────


class TestFlagOff:
    def test_flag_off_keeps_pending_regardless_of_tier(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_flagoff_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid)
        test_ids.append(sid)
        _set_tier(s_conn, 3)  # would-allow if flag were on
        # Force the flag OFF at *both* layers (DB override + env)
        # so a production-with-flag-on environment doesn't leak into
        # this isolation test.
        monkeypatch.delenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", raising=False)
        from radar.calibration import scenario_improver as si
        monkeypatch.setattr(si, "_auto_apply_enabled", lambda: False)

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_low",
            target_country="TC",
            suggested_value={"weight": 0.85},
        )
        assert pid is not None
        st, by = _proposal_state(s_conn, pid)
        assert st == "pending"
        assert by is None
        # Scenario weight unchanged.
        assert _participant(s_conn, sid, "TC")["weight"] == 0.40


# ── Flag ON: tier 0 ─────────────────────────────────────────────────────────


class TestTier0:
    def test_t0_blocks_all_auto_apply(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_t0_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid)
        test_ids.append(sid)
        _set_tier(s_conn, 0)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_low",
            target_country="TC",
            suggested_value={"weight": 0.85},
        )
        assert _proposal_state(s_conn, pid)[0] == "pending"


# ── Flag ON: tier 1 ─────────────────────────────────────────────────────────


class TestTier1:
    def test_t1_recall_positive_auto_applies(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_t1_pos_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid)
        test_ids.append(sid)
        _set_tier(s_conn, 1)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_low",
            target_country="TC",
            suggested_value={"weight": 0.85},
            evidence_strength="weak",  # below recall+ floor for missing
                                        # but above weight_too_low's floor
        )
        st, by = _proposal_state(s_conn, pid)
        assert st == "applied"
        assert by == "auto:scenario_improver:weight_too_low"
        # Scenario actually mutated.
        assert _participant(s_conn, sid, "TC")["weight"] == 0.85

    def test_t1_recall_reducing_stays_pending(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        """At T1 a HIGH-impact proposal (weight_too_high) is correctly
        held back — even with strong evidence, the tier governor
        doesn't allow HIGH at T1."""
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_t1_neg_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid, participants={
            "TC": {"weight": 0.95, "role": "forward_base"},
        })
        test_ids.append(sid)
        _set_tier(s_conn, 1)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_high",
            target_country="TC",
            suggested_value={"weight": 0.40},
            evidence_strength="strong",
        )
        assert _proposal_state(s_conn, pid)[0] == "pending"
        assert _participant(s_conn, sid, "TC")["weight"] == 0.95


# ── Flag ON: tier 3 ─────────────────────────────────────────────────────────


class TestTier3:
    def test_t3_recall_reducing_strong_evidence_applies_and_cooldowns(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_t3_neg_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid, participants={
            "TC": {"weight": 0.95, "role": "forward_base"},
        })
        test_ids.append(sid)
        _set_tier(s_conn, 3)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_high",
            target_country="TC",
            suggested_value={"weight": 0.40},
            evidence_strength="strong",
            vitality_state="active",
        )
        # Applied.
        st, by = _proposal_state(s_conn, pid)
        assert st == "applied"
        assert by == "auto:scenario_improver:weight_too_high"
        # Mutation persisted.
        assert _participant(s_conn, sid, "TC")["weight"] == 0.40
        # HIGH cooldown set on LOW + MED.
        cd_rows = list(s_conn.execute(
            "SELECT impact_level, triggered_by FROM auto_apply_cooldown"
        ))
        impacts = {r["impact_level"] for r in cd_rows}
        assert "low" in impacts
        assert "med" in impacts

    def test_t3_recall_reducing_weak_evidence_stays_pending(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_t3_weak_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid, participants={
            "TC": {"weight": 0.95, "role": "forward_base"},
        })
        test_ids.append(sid)
        _set_tier(s_conn, 3)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_high",
            target_country="TC",
            suggested_value={"weight": 0.40},
            evidence_strength="moderate",  # below 'strong' floor
        )
        assert _proposal_state(s_conn, pid)[0] == "pending"
        assert _participant(s_conn, sid, "TC")["weight"] == 0.95

    def test_t3_recall_reducing_protected_role_stays_pending(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        """NP7: the role re-check inside _maybe_auto_apply blocks HIGH
        proposals against participants in PROTECTED_ROLES even at T3."""
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_t3_prot_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid, participants={
            "TC": {"weight": 0.95, "role": "primary_target"},  # protected
        })
        test_ids.append(sid)
        _set_tier(s_conn, 3)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_high",
            target_country="TC",
            suggested_value={"weight": 0.40},
            evidence_strength="strong",
            vitality_state="active",
        )
        assert _proposal_state(s_conn, pid)[0] == "pending"
        assert _participant(s_conn, sid, "TC")["weight"] == 0.95


# ── Discovery / unsupported types stay pending ──────────────────────────────


class TestDiscoveryAndUnsupported:
    def test_scenario_discovery_never_auto_applies(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        """NP7 boundary: scenario lifecycle is an organizational
        decision; the calibrator must never create new scenarios."""
        s_conn, test_ids = _scenarios_sandbox
        # Use a unique virtual id so the proposer's dedup window
        # doesn't collide with whatever the production __discovery__
        # ledger already holds.
        virtual_sid = "__test_disco_" + uuid.uuid4().hex[:8] + "__"
        unique_target = "ZX_" + uuid.uuid4().hex[:6].upper()
        _set_tier(s_conn, 3)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=virtual_sid,
            proposal_type="scenario_discovery",
            target_country=unique_target,
            suggested_value={"candidate_id": "xyz"},
            evidence_strength="strong",
        )
        try:
            assert pid is not None
            assert _proposal_state(s_conn, pid)[0] == "pending"
        finally:
            with s_conn.writing():
                s_conn.execute(
                    "DELETE FROM scenario_proposals "
                    "WHERE scenario_id=?", (virtual_sid,),
                )


# ── Source-agnostic mutation symmetry ───────────────────────────────────────


class TestFlagReadPath:
    """Pin the contract that _auto_apply_enabled() reads via the
    layered config registry (DB override → env → default), not just
    the raw env. Regression test for the bug discovered during Phase
    5 rollout: SETTINGS UI saves go to the DB layer, and an env-only
    reader misses them entirely.
    """

    def test_db_override_takes_precedence_over_env_default(
        self, monkeypatch,
    ):
        # Make sure env is unset so DB override is the only source.
        monkeypatch.delenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", raising=False)
        # Stub get_config to return True (simulating SETTINGS save).
        from radar import config_layered
        monkeypatch.setattr(
            config_layered, "get_config",
            lambda key: True if key == "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED" else None,
        )
        from radar.calibration import scenario_improver as si
        assert si._auto_apply_enabled() is True

    def test_env_string_truthy_values_recognized(self, monkeypatch):
        """When config_layered raises (older deployments) the function
        falls back to env. The fallback must accept the same truthy
        strings the layered code does."""
        from radar import config_layered

        def _boom(*_a, **_kw):
            raise RuntimeError("registry unavailable")
        monkeypatch.setattr(config_layered, "get_config", _boom)
        from radar.calibration import scenario_improver as si
        for truthy in ("1", "true", "TRUE", "yes", "on"):
            monkeypatch.setenv(
                "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", truthy)
            assert si._auto_apply_enabled() is True, truthy

    def test_unset_returns_false(self, monkeypatch):
        from radar import config_layered
        monkeypatch.setattr(
            config_layered, "get_config", lambda key: False,
        )
        monkeypatch.delenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", raising=False)
        from radar.calibration import scenario_improver as si
        assert si._auto_apply_enabled() is False


class TestSymmetryWithAnalystPath:
    def test_auto_apply_uses_same_primitive_as_analyst(
        self, _scenarios_sandbox, _gov_sandbox, monkeypatch,
    ):
        """Same call, same result — auto-apply must invoke
        apply_scenario_improver_proposal exactly like the analyst
        route does. We assert by checking that the resulting
        state_changed_by is the marker we provided, and the
        participants table has the new value."""
        s_conn, test_ids = _scenarios_sandbox
        sid = "test_sym_" + uuid.uuid4().hex[:8]
        _make_scenario(s_conn, sid)
        test_ids.append(sid)
        _set_tier(s_conn, 1)
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")

        pid = _emit_event(
            scenario_id=sid, proposal_type="weight_too_low",
            target_country="TC",
            suggested_value={"weight": 0.85},
        )
        st, by = _proposal_state(s_conn, pid)
        assert st == "applied"
        # The marker carries the proposal_type for NP6 traceability.
        assert by == "auto:scenario_improver:weight_too_low"
        # Mutation landed.
        assert _participant(s_conn, sid, "TC")["weight"] == 0.85
