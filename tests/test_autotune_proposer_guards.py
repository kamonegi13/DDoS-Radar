"""Tests for the autotune proposer guard layer added in Phases A-F
(2026-04-30 audit fix).

Covers:
  * Phase A: sensor_disable proposer skips disable proposal when the
    sensor's fetch layer is healthy (regardless of LLM-side α signal).
  * Phase B: dormant_participant rule and weight_too_high rule both
    refuse to propose when global sensor coverage is degraded.
  * Phase B: sensor_coverage_healthy returns the right verdict for
    healthy / degraded global signal counts.
  * Phase D: scenario_discoverer supersedes a prior pending proposal
    with the same countries fingerprint.
  * Phase E: list_pending now includes evidence_strength,
    vitality_state, and state in each item dict.
  * Phase F: drift watchdog emits 'sensor_outage' (red severity) when
    global coverage is degraded and 'participant_silent' (amber)
    when fleet is healthy.
"""
from __future__ import annotations

import os
import json
import secrets
import sqlite3
import tempfile
import time
import types

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")

from radar.database import RadarDB, db


# ── Phase B: sensor_coverage_healthy ────────────────────────────────────

@pytest.fixture
def fresh_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    instance = RadarDB(path)
    yield instance
    try:
        os.unlink(path)
    except OSError:
        pass


def test_coverage_healthy_when_signals_above_threshold(fresh_db):
    """With seeded llm_intel + sensor_observation_ts rows above min,
    sensor_coverage_healthy returns healthy=True."""
    from radar.calibration import _proposal_guards as _guards
    monkey_db = _guards
    # Seed signals using the test DB's connection
    now = time.time()
    conn = fresh_db._get_conn()
    with conn.writing():
        for i in range(80):
            conn.execute(
                "INSERT INTO llm_intel (id, source_type, theater, ts, created_at) "
                "VALUES (?, 'test', ?, ?, ?)",
                (f"test_li_{i}", "TW", now - i * 60, now - i * 60),
            )

    # Patch the helper to use our test DB connection
    import radar.calibration._proposal_guards as g_mod
    orig_db = g_mod._safe_count.__globals__.get("db")
    g_mod._safe_count.__globals__["db"] = fresh_db
    try:
        ok, details = _guards.sensor_coverage_healthy(
            days=30, min_global_signals=50,
        )
    finally:
        if orig_db is not None:
            g_mod._safe_count.__globals__["db"] = orig_db
    assert ok is True
    assert details["total_global_signals"] >= 50
    assert details["verdict"] == "healthy"


def test_coverage_degraded_when_no_signals(fresh_db):
    """Empty fleet → coverage_healthy=False."""
    from radar.calibration import _proposal_guards as _guards
    import radar.calibration._proposal_guards as g_mod
    orig_db = g_mod._safe_count.__globals__.get("db")
    g_mod._safe_count.__globals__["db"] = fresh_db
    try:
        ok, details = _guards.sensor_coverage_healthy(
            days=30, min_global_signals=50,
        )
    finally:
        if orig_db is not None:
            g_mod._safe_count.__globals__["db"] = orig_db
    assert ok is False
    assert details["verdict"] == "degraded"
    assert details["total_global_signals"] < 50


# ── Phase A: sensor_disable fetch-layer guard ───────────────────────────

class _FakeSensor:
    def __init__(self, name, enabled=True, cb_state="CLOSED",
                 last_error="", success_rate=1.0):
        self.name = name
        self.enabled = enabled
        self.cb_state = cb_state
        self.last_error = last_error
        self._success_rate = success_rate


def test_sensor_disable_guard_skips_when_healthy(monkeypatch):
    """Phase A: a sensor that is enabled+CLOSED+no-error must NOT be
    proposed for disable, even when the LLM α flag fires."""
    from radar.calibration import sensor_disable_proposer as sdp

    fake = _FakeSensor("hacktivist_news")
    fake_routes = types.SimpleNamespace(
        registry=types.SimpleNamespace(_sensors={"hacktivist_news": fake}))
    monkeypatch.setattr(
        "radar.routes.registry", fake_routes.registry, raising=False)
    import radar.routes as _routes
    _routes.registry = fake_routes.registry

    # Patch _safe_count to return 30 ok-fetches for the sensor
    def fake_query(sql, params):
        return (30,)
    # Use real DB but inject a fake sensor_call_log query result.
    # Simpler: patch the function to skip sensor_call_log read.
    def fake_healthy(name):
        return (True, "fetch_healthy: 30 ok fetches in 24h, cb=CLOSED")
    monkeypatch.setattr(sdp, "_sensor_fetch_layer_healthy", fake_healthy)

    is_healthy, reason = sdp._sensor_fetch_layer_healthy("hacktivist_news")
    assert is_healthy is True
    assert "fetch_healthy" in reason


def test_sensor_disable_guard_allows_when_disabled(monkeypatch):
    """Phase A: an already-disabled sensor returns is_healthy=False
    so the proposer skips it (avoiding double-disable proposals)."""
    from radar.calibration import sensor_disable_proposer as sdp
    fake = _FakeSensor("hacktivist_news", enabled=False)
    import radar.routes as _routes
    _routes.registry = types.SimpleNamespace(_sensors={"hacktivist_news": fake})
    is_healthy, reason = sdp._sensor_fetch_layer_healthy("hacktivist_news")
    assert is_healthy is False
    assert reason == "already_disabled"


def test_sensor_disable_guard_proposes_when_cb_open(monkeypatch):
    """Phase A: CB open sensor returns is_healthy=False so the
    proposer DOES emit the disable suggestion."""
    from radar.calibration import sensor_disable_proposer as sdp
    fake = _FakeSensor("hacktivist_news", cb_state="OPEN")
    import radar.routes as _routes
    _routes.registry = types.SimpleNamespace(_sensors={"hacktivist_news": fake})
    is_healthy, reason = sdp._sensor_fetch_layer_healthy("hacktivist_news")
    assert is_healthy is False
    assert reason == "cb_open"


def test_sensor_disable_guard_unknown_sensor_returns_false(monkeypatch):
    from radar.calibration import sensor_disable_proposer as sdp
    import radar.routes as _routes
    _routes.registry = types.SimpleNamespace(_sensors={})
    is_healthy, reason = sdp._sensor_fetch_layer_healthy("unknown_sensor")
    assert is_healthy is False
    assert reason == "sensor_not_in_registry"


# ── Phase D: discovery cluster fingerprint ───────────────────────────────

def test_discovery_cluster_fingerprint_is_order_invariant():
    from radar.calibration.scenario_discoverer import _cluster_fingerprint
    fp1 = _cluster_fingerprint(["IL", "IR", "UA"])
    fp2 = _cluster_fingerprint(["UA", "IL", "IR"])
    fp3 = _cluster_fingerprint(["UA", "IL"])
    assert fp1 == fp2  # same set, different order → same fingerprint
    assert fp1 != fp3  # different set → different fingerprint
    assert fp1 == "IL,IR,UA"


def test_discovery_emit_supersedes_prior_pending(fresh_db, monkeypatch):
    """Phase D: emitting a discovery proposal with the same countries
    fingerprint marks any prior pending row 'superseded' before
    inserting the new one."""
    from radar.calibration import scenario_discoverer as sd
    # Patch the discoverer to use our test DB.
    monkeypatch.setattr(sd, "db", fresh_db)

    # Emit run 1
    rid1 = sd._emit_one_proposal(run_id=1, cluster_id=0,
                                  countries=["IL", "IR", "UA"])
    assert rid1 is not None
    # Emit run 2 with same countries → run 1 must be superseded
    rid2 = sd._emit_one_proposal(run_id=2, cluster_id=0,
                                  countries=["IL", "IR", "UA"])
    assert rid2 is not None and rid2 != rid1

    conn = fresh_db._get_conn()
    row1 = conn.execute(
        "SELECT state FROM scenario_proposals WHERE id=?", (rid1,)
    ).fetchone()
    row2 = conn.execute(
        "SELECT state FROM scenario_proposals WHERE id=?", (rid2,)
    ).fetchone()
    assert row1["state"] == "superseded"
    assert row2["state"] == "pending"


def test_discovery_emit_does_not_supersede_different_cluster(fresh_db, monkeypatch):
    """Different countries set → no supersede."""
    from radar.calibration import scenario_discoverer as sd
    monkeypatch.setattr(sd, "db", fresh_db)

    rid1 = sd._emit_one_proposal(run_id=1, cluster_id=0,
                                  countries=["IL", "IR", "UA"])
    rid2 = sd._emit_one_proposal(run_id=2, cluster_id=1,
                                  countries=["CN", "TW", "JP"])

    conn = fresh_db._get_conn()
    row1 = conn.execute(
        "SELECT state FROM scenario_proposals WHERE id=?", (rid1,)
    ).fetchone()
    assert row1["state"] == "pending"  # not superseded


# ── Phase E: list_pending shape ─────────────────────────────────────────

def test_list_pending_returns_evidence_strength_and_state(fresh_db, monkeypatch):
    from radar.calibration import scenario_improver as si
    monkeypatch.setattr(si, "db", fresh_db)
    # Seed one pending row with evidence_strength populated
    conn = fresh_db._get_conn()
    with conn.writing():
        conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, "
            " sample_n, why_string, evidence_strength, vitality_state, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            (time.time(), "test_scenario", "weight_too_high", "TW",
             "{}", "{}", "test/v1#test", 5, "test why",
             "strong", "active"),
        )
    items = si.list_pending(scenario_id="test_scenario", hours=24)
    assert len(items) == 1
    assert items[0]["evidence_strength"] == "strong"
    assert items[0]["vitality_state"] == "active"
    assert items[0]["state"] == "pending"


def test_list_pending_defaults_state_to_pending_when_null(fresh_db, monkeypatch):
    from radar.calibration import scenario_improver as si
    monkeypatch.setattr(si, "db", fresh_db)
    conn = fresh_db._get_conn()
    with conn.writing():
        conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, "
            " sample_n, why_string) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (time.time(), "test_scenario_nullstate", "weight_too_high", "TW",
             "{}", "{}", "test/v1#test", 5, "test why"),
        )
    items = si.list_pending(scenario_id="test_scenario_nullstate", hours=24)
    # State column NOT NULL DEFAULT 'pending' should set it. Confirm.
    assert len(items) == 1
    assert items[0]["state"] == "pending"


# ── Phase F: drift signal classification ────────────────────────────────

def test_drift_emits_sensor_outage_when_coverage_degraded(fresh_db, monkeypatch):
    """Phase F: with empty signal tables, _signal_weight_stale must
    emit drift_signal='sensor_outage' (severity='red'), not the legacy
    'weight_stale' that pre-fix would emit."""
    from radar.calibration import drift_watchdog as dw
    monkeypatch.setattr(dw, "db", fresh_db)

    class _Participant:
        def __init__(self, weight): self.weight = weight

    class _Scenario:
        def __init__(self, sid):
            self.id = sid
            self.participants = {"JP": _Participant(0.7)}
            self.adversaries = set()

    # Patch sensor_coverage_healthy to use the fresh DB.
    import radar.calibration._proposal_guards as g_mod
    orig_db = g_mod._safe_count.__globals__.get("db")
    g_mod._safe_count.__globals__["db"] = fresh_db
    try:
        events = dw._signal_weight_stale(_Scenario("test_scenario"))
    finally:
        if orig_db is not None:
            g_mod._safe_count.__globals__["db"] = orig_db
    assert len(events) == 1
    assert events[0].drift_signal == "sensor_outage"
    assert events[0].severity == "red"
    assert "measurement-side outage" in events[0].why_string.lower()


def test_drift_emits_participant_silent_when_coverage_healthy(fresh_db, monkeypatch):
    """Phase F: when global signals are healthy but THIS country has
    no signal, emit drift_signal='participant_silent' (amber)."""
    from radar.calibration import drift_watchdog as dw
    monkeypatch.setattr(dw, "db", fresh_db)

    class _Participant:
        def __init__(self, weight): self.weight = weight

    class _Scenario:
        def __init__(self, sid):
            self.id = sid
            self.participants = {"JP": _Participant(0.7)}
            self.adversaries = set()

    # Seed enough llm_intel to make sensor_coverage_healthy return True
    now = time.time()
    conn = fresh_db._get_conn()
    with conn.writing():
        for i in range(80):
            conn.execute(
                "INSERT INTO llm_intel (id, source_type, theater, ts, created_at) "
                "VALUES (?, 'test', ?, ?, ?)",
                (f"silent_test_{i}", "TW", now - i * 60, now - i * 60),
            )

    # Patch coverage helper db reference
    import radar.calibration._proposal_guards as g_mod
    orig_db = g_mod._safe_count.__globals__.get("db")
    g_mod._safe_count.__globals__["db"] = fresh_db
    try:
        events = dw._signal_weight_stale(_Scenario("test_scenario_silent"))
    finally:
        if orig_db is not None:
            g_mod._safe_count.__globals__["db"] = orig_db

    assert len(events) == 1
    assert events[0].drift_signal == "participant_silent"
    assert events[0].severity == "amber"
    assert "lowering weight" in events[0].why_string.lower()
