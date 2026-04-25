"""Tests for v2.0 Phase 1 priority 7: per-Conclusion calibration_status.

Validates that calibration_status_for(db, scenario_id):
- Returns INSUFFICIENT_DATA envelope when no shadow rows exist
- Returns INSUFFICIENT_DATA verdict when sample_n < 8
- Returns OK when drift_direction='stable' AND sample_n >= 8
- Returns DRIFTING when drift_direction in (increasing, decreasing) and
  sample_n >= 8
- Returns DEGRADED when recent_miss_rate >= 0.30 (overrides DRIFTING)
- Pulls last_sampled_at from shadow_sampler_state when present
- Never raises — DB failures fall back to INSUFFICIENT_DATA (NP3)
- Is wired into _maybe_persist_tl_conclusion so persisted Conclusion rows
  carry the calibration snapshot
"""

from __future__ import annotations

import os
import time
from unittest.mock import patch

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

import radar_api  # noqa: F401  -- ensure singletons initialised
from radar import config
from radar.conclusions import calibration_status_for
from radar.database import db


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM focus_switch_log "
                         "WHERE scenario_id LIKE 'test_%'")
            conn.execute("DELETE FROM shadow_sampler_state "
                         "WHERE scenario_id LIKE 'test_%'")
            conn.execute("DELETE FROM conclusions "
                         "WHERE scenario_id LIKE 'test_%'")
    except Exception:
        pass


def _seed_shadow_rows(scenario_id: str, *, n: int, delta: float,
                      is_miss: bool = False,
                      anchor_at: float | None = None) -> None:
    """Insert n shadow_sampler rows spread evenly across the lookback
    window so the drift calculation has both early and recent halves."""
    if anchor_at is None:
        anchor_at = time.time()
    period = 28 * 86400
    step = period / max(n, 1)
    conn = db._get_conn()
    with conn.writing():
        for i in range(n):
            ts = anchor_at - period + step * i + 60
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, "
                " delta, is_miss, source, shadow_score_kind) "
                "VALUES (?, ?, ?, ?, ?, ?, 'shadow_sampler', 'piggyback')",
                (scenario_id, ts, 0.0, delta, delta, 1 if is_miss else 0),
            )


def _seed_drifting_rows(scenario_id: str, *, n_per_half: int,
                        early_delta: float, recent_delta: float) -> None:
    """Seed n_per_half rows in the early half and n_per_half in the recent
    half with different deltas, producing a clear drift signal."""
    now = time.time()
    period = 28 * 86400
    midpoint = now - period / 2.0
    conn = db._get_conn()
    with conn.writing():
        for i in range(n_per_half):
            # early half: between cutoff and midpoint
            early_ts = midpoint - (period / 4.0) + (i * 60)
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, "
                " delta, is_miss, source, shadow_score_kind) "
                "VALUES (?, ?, 0, 0, ?, 0, 'shadow_sampler', 'piggyback')",
                (scenario_id, early_ts, early_delta),
            )
        for i in range(n_per_half):
            recent_ts = midpoint + (period / 4.0) + (i * 60)
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, "
                " delta, is_miss, source, shadow_score_kind) "
                "VALUES (?, ?, 0, 0, ?, 0, 'shadow_sampler', 'piggyback')",
                (scenario_id, recent_ts, recent_delta),
            )


# ── verdict classification ──────────────────────────────────────────────

def test_insufficient_data_when_no_shadow_rows():
    sid = "test_calib_empty"
    status = calibration_status_for(db, sid)
    assert status["sampler"] == "INSUFFICIENT_DATA"
    assert status["sample_n"] == 0
    assert status["drift_direction"] == "insufficient_data"


def test_insufficient_data_when_sample_n_below_threshold():
    sid = "test_calib_low_n"
    _seed_shadow_rows(sid, n=4, delta=0.1)
    status = calibration_status_for(db, sid)
    assert status["sampler"] == "INSUFFICIENT_DATA"


def test_ok_when_stable_with_enough_samples():
    sid = "test_calib_ok"
    _seed_drifting_rows(sid, n_per_half=10,
                        early_delta=0.10, recent_delta=0.105)
    status = calibration_status_for(db, sid)
    assert status["sampler"] == "OK"
    assert status["drift_direction"] == "stable"
    assert status["sample_n"] == 20


def test_drifting_when_increasing_with_enough_samples():
    sid = "test_calib_drift_up"
    _seed_drifting_rows(sid, n_per_half=10,
                        early_delta=0.10, recent_delta=0.50)
    status = calibration_status_for(db, sid)
    assert status["sampler"] == "DRIFTING"
    assert status["drift_direction"] == "increasing"
    assert status["drift_magnitude_pct"] > 25.0


def test_drifting_when_decreasing_with_enough_samples():
    sid = "test_calib_drift_down"
    _seed_drifting_rows(sid, n_per_half=10,
                        early_delta=0.50, recent_delta=0.10)
    status = calibration_status_for(db, sid)
    assert status["sampler"] == "DRIFTING"
    assert status["drift_direction"] == "decreasing"
    assert status["drift_magnitude_pct"] < -25.0


def test_degraded_overrides_drifting_when_miss_rate_high():
    """recent_miss_rate >= 0.30 → DEGRADED. The drift verdict is
    secondary; loose calibration is the louder problem."""
    sid = "test_calib_degraded"
    now = time.time()
    period = 28 * 86400
    midpoint = now - period / 2.0
    conn = db._get_conn()
    with conn.writing():
        # 10 stable early
        for i in range(10):
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, "
                " delta, is_miss, source, shadow_score_kind) "
                "VALUES (?, ?, 0, 0, 0.1, 0, 'shadow_sampler', 'piggyback')",
                (sid, midpoint - period / 4 + i * 60),
            )
        # 10 recent — half are misses (miss_rate = 0.5 ≥ 0.30)
        for i in range(10):
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, "
                " delta, is_miss, source, shadow_score_kind) "
                "VALUES (?, ?, 0, 0, 0.1, ?, 'shadow_sampler', 'piggyback')",
                (sid, midpoint + period / 4 + i * 60, 1 if i < 5 else 0),
            )
    status = calibration_status_for(db, sid)
    assert status["sampler"] == "DEGRADED"
    assert status["recent_miss_rate"] >= 0.30


# ── last_sampled_at integration ─────────────────────────────────────────

def test_last_sampled_at_pulled_from_sampler_state():
    sid = "test_calib_last_sampled"
    _seed_drifting_rows(sid, n_per_half=10, early_delta=0.1, recent_delta=0.1)
    db.shadow_sampler_state_upsert(
        scenario_id=sid, last_sampled_at=12345.0,
        lite_score=0.0, full_score=0.0, delta=0.0,
    )
    status = calibration_status_for(db, sid)
    assert status["last_sampled_at"] == 12345.0


def test_last_sampled_at_is_none_when_state_missing():
    sid = "test_calib_no_state"
    _seed_drifting_rows(sid, n_per_half=10, early_delta=0.1, recent_delta=0.1)
    status = calibration_status_for(db, sid)
    assert status["last_sampled_at"] is None


# ── failure swallow (NP3) ───────────────────────────────────────────────

def test_calibration_returns_insufficient_on_db_failure():
    """If the underlying DB read raises, the caller must still get a
    valid calibration_status dict — observability cannot break scoring."""
    with patch.object(db, "shadow_drift_stats",
                      side_effect=RuntimeError("simulated outage")):
        status = calibration_status_for(db, "test_calib_outage")
    assert status["sampler"] == "INSUFFICIENT_DATA"
    assert status["source"] == "shadow_sampler"


# ── persistence wiring ──────────────────────────────────────────────────

def test_persisted_conclusion_carries_calibration_snapshot(monkeypatch):
    """End-to-end: when V2_CONCLUSION_LEDGER_ENABLED, a fired conclusion
    must reach the ledger with calibration_status populated."""
    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", True)

    sid = "test_calib_persist"
    _seed_drifting_rows(sid, n_per_half=10,
                        early_delta=0.10, recent_delta=0.50)

    from radar.scoring import _maybe_persist_tl_conclusion
    from types import SimpleNamespace
    state = SimpleNamespace(
        scenario_id=sid, tl=3, score=9.0,
        scoring_mode="FULL", is_focused=True,
        domains={}, active_countries=["TW", "US"],
        convergence_bonus=0.5,
        contributions=[],
    )
    _maybe_persist_tl_conclusion(state)

    from radar.conclusions import ConclusionType, latest_conclusion
    persisted = latest_conclusion(db, sid, ConclusionType.THREAT_LEVEL)
    assert persisted is not None
    assert persisted.calibration_status["sampler"] == "DRIFTING"
    assert persisted.calibration_status["sample_n"] == 20
