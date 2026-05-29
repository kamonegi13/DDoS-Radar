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
    suggested_value: dict | None = None,
) -> int:
    if emitted_at is None:
        emitted_at = time.time()
    import json as _json
    sv = _json.dumps(suggested_value) if suggested_value is not None else "{}"
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, "
            " sample_n, why_string, state) "
            "VALUES (?, ?, ?, ?, ?, '{}', 'test#v1', 0, 'test', ?)",
            (float(emitted_at), scenario_id, proposal_type,
             target_country, sv, state),
        )
        return int(cur.lastrowid)


@pytest.fixture
def _drift_events_sandbox():
    """Snapshot/restore scenario_drift_events around drift lifecycle tests."""
    conn = db._get_conn()  # noqa: SLF001
    cols = [d[0] for d in conn.execute(
        "SELECT * FROM scenario_drift_events LIMIT 0"
    ).description]
    rows = list(conn.execute(
        f"SELECT {','.join(cols)} FROM scenario_drift_events"
    ))
    with conn.writing():
        conn.execute("DELETE FROM scenario_drift_events")
    yield (conn, cols)
    with conn.writing():
        conn.execute("DELETE FROM scenario_drift_events")
        if rows:
            placeholders = ",".join("?" for _ in cols)
            conn.executemany(
                f"INSERT INTO scenario_drift_events ({','.join(cols)}) "
                f"VALUES ({placeholders})",
                [tuple(r) for r in rows],
            )


def _insert_drift_event(
    conn, *,
    scenario_id: str = "test_sc",
    drift_signal: str = "weight_stale",
    severity: str = "amber",
    ack_state: str = "unack",
    target_country: "str | None" = None,
    emitted_at: "float | None" = None,
) -> int:
    if emitted_at is None:
        emitted_at = time.time()
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_drift_events "
            "(emitted_at, scenario_id, drift_signal, severity, target_country, "
            " evidence_json, formula_ref, sample_n, why_string, ack_state, "
            " consecutive_runs) "
            "VALUES (?, ?, ?, ?, ?, '{}', 'test#v1', 1, 'test', ?, 1)",
            (float(emitted_at), scenario_id, drift_signal, severity,
             target_country, ack_state),
        )
        return int(cur.lastrowid)


class TestAutoDismissStalePending:
    """D5 (2026-05-10): auto-dismiss long-stale actionable proposals."""

    def test_stale_actionable_pending_gets_dismissed(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        _, test_ids = _scenarios_sandbox
        sid = "test_sc_d5_stale"
        test_ids.append(sid)
        _insert_scenario(conn, sid=sid, state="active")
        old = time.time() - 35 * 86400
        pid = _insert_proposal(
            conn, scenario_id=sid,
            proposal_type="weight_too_high",
            state="pending", emitted_at=old,
        )
        n = pl.auto_dismiss_stale_pending_proposals(stale_days=30.0)
        assert n == 1
        row = conn.execute(
            "SELECT state, state_changed_by FROM scenario_proposals WHERE id=?",
            (pid,),
        ).fetchone()
        assert row[0] == "dismissed"
        assert row[1] == "auto:timeout_no_action"

    def test_recent_pending_unchanged(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        conn, _ = _proposals_sandbox
        _, test_ids = _scenarios_sandbox
        sid = "test_sc_d5_recent"
        test_ids.append(sid)
        _insert_scenario(conn, sid=sid, state="active")
        recent = time.time() - 10 * 86400  # below 30d threshold
        _insert_proposal(
            conn, scenario_id=sid,
            proposal_type="weight_too_high",
            state="pending", emitted_at=recent,
        )
        n = pl.auto_dismiss_stale_pending_proposals(stale_days=30.0)
        assert n == 0

    def test_diagnostic_types_skipped(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        """Diagnostic types are handled by D3 at 7d — D5 must not double-process."""
        conn, _ = _proposals_sandbox
        _, test_ids = _scenarios_sandbox
        sid = "test_sc_d5_diag"
        test_ids.append(sid)
        _insert_scenario(conn, sid=sid, state="active")
        old = time.time() - 35 * 86400
        _insert_proposal(
            conn, scenario_id=sid,
            proposal_type="needs_more_data",  # diagnostic type
            state="pending", emitted_at=old,
        )
        n = pl.auto_dismiss_stale_pending_proposals(stale_days=30.0)
        assert n == 0  # D3 handles this, not D5

    def test_inactive_scenario_skipped(
        self, _proposals_sandbox, _scenarios_sandbox,
    ):
        """Inactive scenarios are handled by D1 — D5 must not double-process."""
        conn, _ = _proposals_sandbox
        _, test_ids = _scenarios_sandbox
        sid = "test_sc_d5_paused"
        test_ids.append(sid)
        _insert_scenario(conn, sid=sid, state="paused")
        old = time.time() - 35 * 86400
        _insert_proposal(
            conn, scenario_id=sid,
            proposal_type="weight_too_high",
            state="pending", emitted_at=old,
        )
        n = pl.auto_dismiss_stale_pending_proposals(stale_days=30.0)
        assert n == 0  # D1 handles paused scenarios


class TestDriftAutoAcknowledge:
    def test_amber_unack_old_gets_acknowledged(self, _drift_events_sandbox):
        conn, _ = _drift_events_sandbox
        old = time.time() - 5 * 86400  # 5 days ago
        eid = _insert_drift_event(conn, severity="amber",
                                  ack_state="unack", emitted_at=old)
        n = pl.auto_acknowledge_amber_drift_events(stale_days=3.0)
        assert n == 1
        row = conn.execute(
            "SELECT ack_state, ack_by FROM scenario_drift_events WHERE id=?",
            (eid,),
        ).fetchone()
        assert row[0] == "acknowledged"
        assert row[1] == "system_timeout_amber"

    def test_amber_recent_unchanged(self, _drift_events_sandbox):
        conn, _ = _drift_events_sandbox
        recent = time.time() - 1 * 86400  # 1 day ago
        _insert_drift_event(conn, severity="amber",
                            ack_state="unack", emitted_at=recent)
        n = pl.auto_acknowledge_amber_drift_events(stale_days=3.0)
        assert n == 0

    def test_red_never_auto_ack(self, _drift_events_sandbox):
        """Red severity must NOT be auto-ack'd — it goes through the
        notification path so analysts are paged."""
        conn, _ = _drift_events_sandbox
        old = time.time() - 5 * 86400
        eid = _insert_drift_event(conn, severity="red",
                                  ack_state="unack", emitted_at=old)
        n = pl.auto_acknowledge_amber_drift_events(stale_days=3.0)
        assert n == 0
        row = conn.execute(
            "SELECT ack_state FROM scenario_drift_events WHERE id=?",
            (eid,),
        ).fetchone()
        assert row[0] == "unack"

    def test_red_old_unack_returned_for_notification(self, _drift_events_sandbox):
        conn, _ = _drift_events_sandbox
        old = time.time() - 2 * 86400
        recent = time.time() - 0.5 * 86400  # too fresh
        _insert_drift_event(conn, severity="red", ack_state="unack",
                            emitted_at=old, drift_signal="participant_silent")
        _insert_drift_event(conn, severity="red", ack_state="unack",
                            emitted_at=recent, drift_signal="ignore_me")
        events = pl.list_old_unack_red_drift_events(stale_days=1.0)
        signals = {e["drift_signal"] for e in events}
        assert signals == {"participant_silent"}
        # Each row carries a days_unack number.
        for e in events:
            assert e["days_unack"] >= 1.0


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


# ── D3: auto_acknowledge_diagnostic_proposals ───────────────────────────────


class TestAutoAcknowledgeDiagnostic:
    @pytest.mark.parametrize("ptype", [
        "sensor_gap_detected",
        "scenario_dormant",
        "needs_more_data",
    ])
    def test_dismisses_old_diagnostic_proposals(
        self, _proposals_sandbox, ptype,
    ):
        """Each of the three diagnostic types is auto-dismissed after
        the staleness window, with a distinguishing
        state_changed_by marker."""
        conn, _ = _proposals_sandbox
        pid = _insert_proposal(
            conn, scenario_id="s1", proposal_type=ptype,
            emitted_at=time.time() - 10 * 86400.0,  # 10 days old
        )
        n = pl.auto_acknowledge_diagnostic_proposals()
        assert n >= 1
        row = conn.execute(
            "SELECT state, state_changed_by FROM scenario_proposals "
            "WHERE id=?", (pid,),
        ).fetchone()
        assert row["state"] == "dismissed"
        assert row["state_changed_by"] == "auto:diagnostic_acknowledged"

    def test_does_not_dismiss_recent_diagnostic(
        self, _proposals_sandbox,
    ):
        """Below the 7-day window the row stays pending — analyst may
        still want to see it as 'recent observation'."""
        conn, _ = _proposals_sandbox
        pid = _insert_proposal(
            conn, scenario_id="s1",
            proposal_type="sensor_gap_detected",
            emitted_at=time.time() - 1 * 86400.0,  # 1 day old
        )
        pl.auto_acknowledge_diagnostic_proposals()
        row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?", (pid,),
        ).fetchone()
        assert row["state"] == "pending"

    def test_does_not_dismiss_actionable_proposal_types(
        self, _proposals_sandbox,
    ):
        """Non-diagnostic types (e.g. weight_too_high) are NOT touched
        by D3 even when old. Their lifecycle goes through other paths
        (analyst Apply, auto-apply gate, chronic_pending watch)."""
        conn, _ = _proposals_sandbox
        pid = _insert_proposal(
            conn, scenario_id="s1",
            proposal_type="weight_too_high",
            emitted_at=time.time() - 30 * 86400.0,  # 30 days old
        )
        pl.auto_acknowledge_diagnostic_proposals()
        row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?", (pid,),
        ).fetchone()
        assert row["state"] == "pending"

    def test_idempotent(self, _proposals_sandbox):
        conn, _ = _proposals_sandbox
        _insert_proposal(
            conn, scenario_id="s1",
            proposal_type="sensor_gap_detected",
            emitted_at=time.time() - 10 * 86400.0,
        )
        assert pl.auto_acknowledge_diagnostic_proposals() == 1
        assert pl.auto_acknowledge_diagnostic_proposals() == 0

    def test_already_resolved_rows_not_touched(
        self, _proposals_sandbox,
    ):
        conn, _ = _proposals_sandbox
        _insert_proposal(
            conn, scenario_id="s1",
            proposal_type="sensor_gap_detected",
            state="dismissed",
            emitted_at=time.time() - 30 * 86400.0,
        )
        assert pl.auto_acknowledge_diagnostic_proposals() == 0


# ── D4: reprocess_pending_through_gate ──────────────────────────────────────


class TestReprocessPendingThroughGate:
    """Drip existing pending rows through the Phase 3 auto-apply gate.
    These tests build full scenarios + tier governor state so the
    underlying _maybe_auto_apply path can run end-to-end. Sandbox
    fixture restores scenarios + tier_state at teardown."""

    @pytest.fixture
    def _full_sandbox(self, _proposals_sandbox):
        conn = db._get_conn()  # noqa: SLF001
        # snapshot scenarios + participants + tier governor state
        sc_rows = list(conn.execute("SELECT * FROM scenarios"))
        sc_cols = [d[0] for d in conn.execute(
            "SELECT * FROM scenarios LIMIT 0").description]
        p_rows = list(conn.execute(
            "SELECT * FROM scenario_participants"))
        p_cols = [d[0] for d in conn.execute(
            "SELECT * FROM scenario_participants LIMIT 0").description]
        ts_rows = list(conn.execute("SELECT * FROM auto_apply_tier_state"))
        ts_cols = [d[0] for d in conn.execute(
            "SELECT * FROM auto_apply_tier_state LIMIT 0").description]
        with conn.writing():
            conn.execute("DELETE FROM scenarios")
            conn.execute("DELETE FROM scenario_participants")
            conn.execute("DELETE FROM auto_apply_tier_state")
            conn.execute("DELETE FROM auto_apply_tier_marker")
            conn.execute("DELETE FROM auto_apply_cooldown")
            conn.execute("DELETE FROM scenario_change_log")
        test_ids: list[str] = []
        yield (conn, test_ids)
        with conn.writing():
            conn.execute("DELETE FROM scenarios")
            conn.execute("DELETE FROM scenario_participants")
            conn.execute("DELETE FROM auto_apply_tier_state")
            conn.execute("DELETE FROM auto_apply_tier_marker")
            conn.execute("DELETE FROM auto_apply_cooldown")
            conn.execute("DELETE FROM scenario_change_log")
            if sc_rows:
                ph = ",".join("?" for _ in sc_cols)
                conn.executemany(
                    f"INSERT INTO scenarios ({','.join(sc_cols)}) "
                    f"VALUES ({ph})",
                    [tuple(r) for r in sc_rows],
                )
            if p_rows:
                ph = ",".join("?" for _ in p_cols)
                conn.executemany(
                    f"INSERT INTO scenario_participants "
                    f"({','.join(p_cols)}) VALUES ({ph})",
                    [tuple(r) for r in p_rows],
                )
            if ts_rows:
                ph = ",".join("?" for _ in ts_cols)
                conn.executemany(
                    f"INSERT INTO auto_apply_tier_state "
                    f"({','.join(ts_cols)}) VALUES ({ph})",
                    [tuple(r) for r in ts_rows],
                )

    def _make_scenario(self, conn, sid, *, participants):
        now = time.time()
        with conn.writing():
            conn.execute(
                "INSERT INTO scenarios "
                "(id, name_en, name_ja, description_en, description_ja, "
                " core_country, state, enabled, tier, created_at, updated_at) "
                "VALUES (?, ?, ?, '', '', ?, 'active', 1, 'L1', ?, ?)",
                (sid, sid, sid,
                 list(participants.keys())[0], now, now),
            )
            for cc, pdata in participants.items():
                conn.execute(
                    "INSERT INTO scenario_participants "
                    "(scenario_id, country, weight, role) "
                    "VALUES (?, ?, ?, ?)",
                    (sid, cc, float(pdata["weight"]), pdata["role"]),
                )

    def _set_tier(self, conn, tier):
        with conn.writing():
            conn.execute("DELETE FROM auto_apply_tier_state")
            conn.execute("DELETE FROM auto_apply_tier_marker")
            if tier > 0:
                conn.execute(
                    "INSERT INTO auto_apply_tier_state "
                    "(observed_at, tier, transition, reason, metrics_json) "
                    "VALUES (?, ?, 'promote', 'test', '{}')",
                    (time.time(), tier),
                )
                conn.execute(
                    "INSERT INTO auto_apply_tier_marker "
                    "(marker_key, tier, entered_at, updated_at, "
                    " metadata_json) "
                    "VALUES ('current_tier_entered_at', ?, ?, ?, '{}')",
                    (tier, time.time() - 60 * 86400, time.time()),
                )

    def test_flag_off_returns_early(self, _full_sandbox, monkeypatch):
        from radar.calibration import scenario_improver as si
        monkeypatch.setattr(si, "_auto_apply_enabled", lambda: False)
        result = pl.reprocess_pending_through_gate()
        assert result["flag_off"] is True
        assert result["applied"] == 0

    def test_skips_non_auto_applicable_types(
        self, _full_sandbox, monkeypatch,
    ):
        """scenario_discovery / sensor_gap_detected / scenario_dormant
        / needs_more_data are not auto-applicable. They must be
        counted in skipped_type, not checked, and never applied."""
        conn, _ = _full_sandbox
        monkeypatch.setenv(
            "SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "true")
        from radar.calibration import scenario_improver as si
        monkeypatch.setattr(si, "_auto_apply_enabled", lambda: True)
        self._set_tier(conn, 3)
        for ptype in ("scenario_discovery", "sensor_gap_detected",
                      "scenario_dormant", "needs_more_data"):
            _insert_proposal(
                conn, scenario_id="__discovery__"
                if ptype == "scenario_discovery" else "ee",
                proposal_type=ptype,
            )
        result = pl.reprocess_pending_through_gate()
        assert result["applied"] == 0
        assert result["skipped_type"] == 4

    def test_skips_too_old_rows(self, _full_sandbox, monkeypatch):
        conn, test_ids = _full_sandbox
        monkeypatch.setattr(
            __import__("radar.calibration.scenario_improver",
                        fromlist=["_auto_apply_enabled"]),
            "_auto_apply_enabled", lambda: True,
        )
        self._make_scenario(conn, "test_old", participants={
            "TC": {"weight": 0.40, "role": "primary_target"},
        })
        test_ids.append("test_old")
        self._set_tier(conn, 3)
        # 35 days old > 30d cap
        _insert_proposal(
            conn, scenario_id="test_old",
            proposal_type="weight_too_low",
            target_country="TC",
            emitted_at=time.time() - 35 * 86400.0,
        )
        result = pl.reprocess_pending_through_gate()
        assert result["applied"] == 0
        assert result["skipped_age"] == 1

    def test_recall_positive_at_t1_applies(
        self, _full_sandbox, monkeypatch,
    ):
        conn, test_ids = _full_sandbox
        monkeypatch.setattr(
            __import__("radar.calibration.scenario_improver",
                        fromlist=["_auto_apply_enabled"]),
            "_auto_apply_enabled", lambda: True,
        )
        self._make_scenario(conn, "test_t1pos", participants={
            "TC": {"weight": 0.40, "role": "primary_target"},
        })
        test_ids.append("test_t1pos")
        self._set_tier(conn, 1)
        pid = _insert_proposal(
            conn, scenario_id="test_t1pos",
            proposal_type="weight_too_low",
            target_country="TC",
            suggested_value={"weight": 0.85},
        )
        # Force the proposal row to have evidence_strength set so it
        # passes the per-type evidence floor.
        with conn.writing():
            conn.execute(
                "UPDATE scenario_proposals SET evidence_strength=?, "
                "vitality_state=? WHERE id=?",
                ("strong", "active", pid),
            )

        result = pl.reprocess_pending_through_gate()
        assert result["applied"] == 1

        row = conn.execute(
            "SELECT state, state_changed_by FROM scenario_proposals "
            "WHERE id=?", (pid,),
        ).fetchone()
        assert row["state"] == "applied"
        assert row["state_changed_by"] \
            == "auto:scenario_improver:weight_too_low"

    def test_recall_reducing_at_t1_stays_pending(
        self, _full_sandbox, monkeypatch,
    ):
        """Phase 3 gate logic: recall-reducing requires T3."""
        conn, test_ids = _full_sandbox
        monkeypatch.setattr(
            __import__("radar.calibration.scenario_improver",
                        fromlist=["_auto_apply_enabled"]),
            "_auto_apply_enabled", lambda: True,
        )
        self._make_scenario(conn, "test_t1neg", participants={
            "TC": {"weight": 0.95, "role": "secondary_ally"},
        })
        test_ids.append("test_t1neg")
        self._set_tier(conn, 1)
        pid = _insert_proposal(
            conn, scenario_id="test_t1neg",
            proposal_type="weight_too_high",
            target_country="TC",
            suggested_value={"weight": 0.40},
        )
        with conn.writing():
            conn.execute(
                "UPDATE scenario_proposals SET evidence_strength=?, "
                "vitality_state=? WHERE id=?",
                ("strong", "active", pid),
            )
        result = pl.reprocess_pending_through_gate()
        # _maybe_auto_apply silently rejects → not in applied count.
        assert result["applied"] == 0
        # But it WAS checked (passed type + age filter).
        assert result["checked"] >= 1
        row = conn.execute(
            "SELECT state FROM scenario_proposals WHERE id=?", (pid,),
        ).fetchone()
        assert row["state"] == "pending"

    def test_rate_limit_caps_applies_per_call(
        self, _full_sandbox, monkeypatch,
    ):
        """Insert MORE eligible rows than REPROCESS_MAX_PER_TICK and
        verify only the cap is applied. The remaining rows stay
        pending and will be picked up next call."""
        conn, test_ids = _full_sandbox
        monkeypatch.setattr(
            __import__("radar.calibration.scenario_improver",
                        fromlist=["_auto_apply_enabled"]),
            "_auto_apply_enabled", lambda: True,
        )
        # Make several scenarios so each has a unique target.
        ids = []
        for i in range(pl.REPROCESS_MAX_PER_TICK + 2):
            sid = f"test_rate_{i}"
            self._make_scenario(conn, sid, participants={
                "TC": {"weight": 0.40, "role": "primary_target"},
            })
            test_ids.append(sid)
            pid = _insert_proposal(
                conn, scenario_id=sid,
                proposal_type="weight_too_low",
                target_country="TC",
                suggested_value={"weight": 0.85},
            )
            with conn.writing():
                conn.execute(
                    "UPDATE scenario_proposals SET evidence_strength=?, "
                    "vitality_state=? WHERE id=?",
                    ("strong", "active", pid),
                )
            ids.append(pid)
        self._set_tier(conn, 1)

        result = pl.reprocess_pending_through_gate()
        assert result["applied"] == pl.REPROCESS_MAX_PER_TICK
        # 2 rows stayed pending.
        n_pending = conn.execute(
            "SELECT COUNT(*) FROM scenario_proposals "
            "WHERE state='pending' AND id IN (%s)" % (
                ",".join(str(i) for i in ids),
            ),
        ).fetchone()[0]
        assert n_pending == 2

    def test_state_changed_mid_loop_skipped(
        self, _full_sandbox, monkeypatch,
    ):
        """If another hook (D1/D2/D3) flips a row's state to dismissed
        between the SELECT and the apply, reprocess must NOT touch it."""
        conn, test_ids = _full_sandbox
        monkeypatch.setattr(
            __import__("radar.calibration.scenario_improver",
                        fromlist=["_auto_apply_enabled"]),
            "_auto_apply_enabled", lambda: True,
        )
        self._make_scenario(conn, "test_mid", participants={
            "TC": {"weight": 0.40, "role": "primary_target"},
        })
        test_ids.append("test_mid")
        self._set_tier(conn, 1)
        pid = _insert_proposal(
            conn, scenario_id="test_mid",
            proposal_type="weight_too_low",
            target_country="TC",
            suggested_value={"weight": 0.85},
        )
        # Pre-flip the state to simulate a concurrent dismiss.
        with conn.writing():
            conn.execute(
                "UPDATE scenario_proposals SET state='dismissed' "
                "WHERE id=?", (pid,),
            )
        result = pl.reprocess_pending_through_gate()
        # No pending rows remain; reprocess sees nothing.
        assert result["applied"] == 0
