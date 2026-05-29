"""Tests for E: scenario_contribution_log retention.

The v18 scenario_contribution_log table writes one row per
(scenario_id, country) per scoring cycle (~4 rows/cycle every 30s
for a 4-participant scenario = ~11,520 rows/scenario/day). Without
retention the table grows unbounded.

The weight_advisory endpoint queries at most 720h (30d). 90 days
gives ~1M rows for the busiest scenario (manageable) plus 60d
margin for trend analysis beyond the live query window.

Configurable via SCENARIO_CONTRIB_RETENTION_DAYS env var, mirroring
the pattern used for scenario_tl_observation, focus_switch_log,
daily_summary, etc.
"""
import os
import time
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.database import db


@pytest.fixture
def fresh_contributions():
    """Insert old + recent rows; yield probe id; cleanup."""
    probe = f"test_{uuid.uuid4().hex[:8]}"
    now = time.time()
    very_old = now - 100 * 86400   # 100 days — outside default 90d retention
    recent = now - 1 * 86400        # 1 day — must survive
    conn = db._get_conn()
    with conn.writing():
        for ts, total in [(very_old, 1.0), (very_old, 2.0), (recent, 3.0)]:
            conn.execute(
                "INSERT INTO scenario_contribution_log "
                "(scenario_id, country, contribution_sum, logged_at) "
                "VALUES (?, ?, ?, ?)",
                (probe, "TW", total, ts),
            )
    yield probe
    with conn.writing():
        conn.execute(
            "DELETE FROM scenario_contribution_log WHERE scenario_id = ?",
            (probe,),
        )


def _row_count(probe: str) -> int:
    return db._get_conn().execute(
        "SELECT COUNT(*) AS c FROM scenario_contribution_log "
        "WHERE scenario_id = ?", (probe,),
    ).fetchone()["c"]


class TestScenarioContributionRetention:
    def test_prune_drops_rows_older_than_default_retention(self, fresh_contributions):
        probe = fresh_contributions
        assert _row_count(probe) == 3, "fixture pre-condition"

        deleted = db._prune_stale_rows()
        assert "scenario_contribution_log" in deleted, \
            "_prune_stale_rows must report the new table in its deleted dict"
        # 2 very-old rows dropped, 1 recent survives
        assert _row_count(probe) == 1, \
            f"expected 1 surviving row, got {_row_count(probe)}"

    def test_prune_returns_count_for_new_table(self, fresh_contributions):
        deleted = db._prune_stale_rows()
        assert isinstance(deleted.get("scenario_contribution_log"), int)

    def test_retention_honors_env_override(self, fresh_contributions, monkeypatch):
        """Setting SCENARIO_CONTRIB_RETENTION_DAYS=200 must keep the
        100-day-old rows alive."""
        probe = fresh_contributions
        monkeypatch.setenv("SCENARIO_CONTRIB_RETENTION_DAYS", "200")
        db._prune_stale_rows()
        assert _row_count(probe) == 3, \
            "200d retention should preserve 100d-old rows"
