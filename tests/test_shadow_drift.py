"""Tests for D: shadow_sampler calibration drift detection.

The existing /api/analytics/cmedium_recommendation reports a binary
status from a static threshold. It cannot tell an analyst that the
delta between lite/full scoring is *trending upward* until the
threshold is breached — by then the calibration drift has already
materialised.

shadow_drift_stats() splits the lookback window into early and recent
halves and reports per-scenario:
  - early_avg_delta, recent_avg_delta
  - early_miss_rate, recent_miss_rate
  - drift_direction: 'increasing' | 'decreasing' | 'stable'
  - drift_magnitude_pct: signed (recent-early)/early as percentage

This lets the UI flag "watch list" scenarios well before the binary
recommendation flips, supporting NP1 (sensitivity) over precision.
"""
import os
import time
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.database import db


@pytest.fixture
def shadow_rows():
    """Insert shadow_sampler focus_switch_log rows with controllable
    early/recent delta distribution. Yield probe scenario id; cleanup."""
    probe = f"sd_{uuid.uuid4().hex[:8]}"
    now = time.time()
    early_ts = now - 20 * 86400  # 20 days ago — "early half" of 28d window
    recent_ts = now - 2 * 86400   # 2 days ago — "recent half"
    conn = db._get_conn()
    with conn.writing():
        # Early: low deltas (calibration good)
        for delta in [0.05, 0.07, 0.06, 0.08]:
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, delta, "
                " is_miss, source, shadow_score_kind) "
                "VALUES (?, ?, ?, ?, ?, ?, 'shadow_sampler', 'piggyback')",
                (probe, early_ts, 0.5, 0.5 + delta, delta, 0),
            )
        # Recent: high deltas (calibration drift)
        for delta in [0.35, 0.42, 0.38, 0.45]:
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, delta, "
                " is_miss, source, shadow_score_kind) "
                "VALUES (?, ?, ?, ?, ?, ?, 'shadow_sampler', 'piggyback')",
                (probe, recent_ts, 0.5, 0.5 + delta, delta, 1),
            )
    yield probe
    with conn.writing():
        conn.execute(
            "DELETE FROM focus_switch_log WHERE scenario_id = ?", (probe,),
        )


class TestShadowDriftStats:
    def test_returns_per_scenario_drift_metrics(self, shadow_rows):
        out = db.shadow_drift_stats(days=28)
        assert "by_scenario" in out
        assert shadow_rows in out["by_scenario"]
        row = out["by_scenario"][shadow_rows]
        for key in ("early_avg_delta", "recent_avg_delta",
                    "early_miss_rate", "recent_miss_rate",
                    "drift_direction", "drift_magnitude_pct"):
            assert key in row, f"missing key {key!r}"

    def test_detects_increasing_drift(self, shadow_rows):
        out = db.shadow_drift_stats(days=28)
        row = out["by_scenario"][shadow_rows]
        # Early avg ≈ 0.065, recent avg ≈ 0.40 → strong upward drift
        assert row["recent_avg_delta"] > row["early_avg_delta"]
        assert row["drift_direction"] == "increasing"
        # Magnitude should be substantial (>= 100% increase)
        assert row["drift_magnitude_pct"] >= 100.0

    def test_recent_miss_rate_higher(self, shadow_rows):
        out = db.shadow_drift_stats(days=28)
        row = out["by_scenario"][shadow_rows]
        # Early: 0/4 misses, recent: 4/4 misses
        assert row["early_miss_rate"] == 0.0
        assert row["recent_miss_rate"] == 1.0

    def test_only_shadow_sampler_source_counted(self, shadow_rows):
        """Analyst rows must NOT contaminate drift stats — drift is
        a property of the calibration harness, not analyst rotation."""
        probe = shadow_rows
        now = time.time()
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, delta, "
                " is_miss, source) "
                "VALUES (?, ?, 0.5, 0.6, 0.10, 0, 'analyst')",
                (probe, now - 1 * 86400),
            )
        out = db.shadow_drift_stats(days=28)
        row = out["by_scenario"][probe]
        # 4 early + 4 recent shadow rows — analyst row excluded
        assert row["sample_count"] == 8

    def test_insufficient_data_when_one_half_empty(self):
        """A scenario with rows in only one half must report
        drift_direction='insufficient_data' rather than infinity."""
        probe = f"sd_{uuid.uuid4().hex[:8]}"
        now = time.time()
        conn = db._get_conn()
        with conn.writing():
            for delta in [0.10, 0.12]:
                conn.execute(
                    "INSERT INTO focus_switch_log "
                    "(scenario_id, switched_at, lite_score, full_score, delta, "
                    " is_miss, source, shadow_score_kind) "
                    "VALUES (?, ?, 0.5, 0.6, ?, 0, 'shadow_sampler', 'piggyback')",
                    (probe, now - 2 * 86400, delta),
                )
        try:
            out = db.shadow_drift_stats(days=28)
            row = out["by_scenario"].get(probe)
            assert row is not None
            assert row["drift_direction"] == "insufficient_data"
        finally:
            with conn.writing():
                conn.execute(
                    "DELETE FROM focus_switch_log WHERE scenario_id = ?",
                    (probe,),
                )

    def test_stable_when_change_within_noise_band(self):
        """drift_direction must be 'stable' when |magnitude_pct| < 25%
        (the noise band) so analyst attention isn't drawn to wobble."""
        probe = f"sd_{uuid.uuid4().hex[:8]}"
        now = time.time()
        conn = db._get_conn()
        with conn.writing():
            for ts, delta in [
                (now - 20 * 86400, 0.20), (now - 19 * 86400, 0.22),
                (now - 2 * 86400, 0.21),  (now - 1 * 86400, 0.23),
            ]:
                conn.execute(
                    "INSERT INTO focus_switch_log "
                    "(scenario_id, switched_at, lite_score, full_score, delta, "
                    " is_miss, source, shadow_score_kind) "
                    "VALUES (?, ?, 0.5, 0.6, ?, 0, 'shadow_sampler', 'piggyback')",
                    (probe, ts, delta),
                )
        try:
            out = db.shadow_drift_stats(days=28)
            row = out["by_scenario"][probe]
            assert row["drift_direction"] == "stable"
        finally:
            with conn.writing():
                conn.execute(
                    "DELETE FROM focus_switch_log WHERE scenario_id = ?",
                    (probe,),
                )

    def test_days_param_filters_window(self, shadow_rows):
        """A short days window must exclude old rows."""
        out = db.shadow_drift_stats(days=5)
        # 20-day-old early rows fall outside 5d window → may be
        # absent or report insufficient_data
        row = out["by_scenario"].get(shadow_rows)
        if row is not None:
            assert row["drift_direction"] == "insufficient_data"
