"""Tests for C: weight_advisory timeseries variant.

The point-in-time /api/scenario/<id>/weight_advisory shows current
utilization but cannot answer "is YE's underperformance worsening or
recovering?". The timeseries variant slices the contribution log
into N equal buckets over the lookback window and returns the
per-participant utilization series so analysts can see the trend
before deciding whether to edit the static weight.

Pure helper compute_weight_utilization_timeseries() takes a scenario,
a list of (logged_at, country, total) rows, and bucket parameters,
and returns:
  {
    "buckets": [<midpoint_ts>, ...],
    "series": {
      "TW": [{"observed_share": .., "utilization_pct": ..}, ...],
      "US": [...],
      ...
    }
  }
"""
import time
from dataclasses import dataclass

import pytest

from radar.scenarios import Participant, Role, Scenario


def _scenario(parts: dict[str, float]) -> Scenario:
    return Scenario(
        id="ts_test",
        name_en="TS Test", name_ja="時系列",
        description_en="", description_ja="",
        core_country=list(parts.keys())[0] if parts else None,
        state="active", enabled=True, tier=1,
        participants={
            cc: Participant(country=cc, weight=w, role=Role.PRIMARY_TARGET)
            for cc, w in parts.items()
        },
    )


class TestComputeWeightUtilizationTimeseries:
    def test_returns_buckets_and_series(self):
        from radar.scoring import compute_weight_utilization_timeseries
        sc = _scenario({"TW": 1.0, "US": 0.5})
        now = time.time()
        rows = [
            (now - 3 * 3600, "TW", 5.0),
            (now - 3 * 3600, "US", 1.0),
            (now - 1 * 3600, "TW", 5.0),
            (now - 1 * 3600, "US", 5.0),
        ]
        out = compute_weight_utilization_timeseries(
            sc, rows, hours=4, bucket_count=2,
        )
        assert "buckets" in out
        assert "series" in out
        assert len(out["buckets"]) == 2
        assert set(out["series"].keys()) == {"TW", "US"}

    def test_each_series_matches_bucket_count(self):
        from radar.scoring import compute_weight_utilization_timeseries
        sc = _scenario({"TW": 1.0})
        now = time.time()
        rows = [(now - i * 600, "TW", 1.0) for i in range(20)]
        out = compute_weight_utilization_timeseries(
            sc, rows, hours=4, bucket_count=8,
        )
        assert len(out["series"]["TW"]) == 8
        for entry in out["series"]["TW"]:
            assert "observed_share" in entry
            assert "utilization_pct" in entry

    def test_empty_bucket_yields_zero_share(self):
        """A window slice with no rows must report observed_share=0
        and utilization_pct=0, not null/NaN/missing — the UI relies
        on a continuous series for charting."""
        from radar.scoring import compute_weight_utilization_timeseries
        sc = _scenario({"TW": 1.0})
        now = time.time()
        rows = [(now - 0.5 * 3600, "TW", 5.0)]  # only in the last bucket
        out = compute_weight_utilization_timeseries(
            sc, rows, hours=4, bucket_count=4,
        )
        # First three buckets are empty
        for entry in out["series"]["TW"][:3]:
            assert entry["observed_share"] == 0.0
            assert entry["utilization_pct"] == 0.0

    def test_buckets_in_chronological_order(self):
        from radar.scoring import compute_weight_utilization_timeseries
        sc = _scenario({"TW": 1.0})
        now = time.time()
        rows = [(now - 1 * 3600, "TW", 1.0)]
        out = compute_weight_utilization_timeseries(
            sc, rows, hours=4, bucket_count=4,
        )
        for i in range(len(out["buckets"]) - 1):
            assert out["buckets"][i] < out["buckets"][i + 1], \
                "buckets must be ascending in time"

    def test_global_rows_excluded_from_share(self):
        from radar.scoring import compute_weight_utilization_timeseries
        sc = _scenario({"TW": 1.0, "US": 0.5})
        now = time.time()
        rows = [
            (now - 1 * 3600, "TW", 6.0),
            (now - 1 * 3600, "US", 4.0),
            (now - 1 * 3600, "GLOBAL", 8.0),
        ]
        out = compute_weight_utilization_timeseries(
            sc, rows, hours=2, bucket_count=1,
        )
        # GLOBAL must not skew shares: TW=60%, US=40%
        tw_share = out["series"]["TW"][0]["observed_share"]
        us_share = out["series"]["US"][0]["observed_share"]
        assert abs(tw_share - 0.6) < 0.01
        assert abs(us_share - 0.4) < 0.01

    def test_bucket_count_clamped_to_reasonable_range(self):
        """bucket_count <= 0 must default safely (e.g. 1) instead of
        raising — analysts may pass bad query params."""
        from radar.scoring import compute_weight_utilization_timeseries
        sc = _scenario({"TW": 1.0})
        out = compute_weight_utilization_timeseries(
            sc, [], hours=4, bucket_count=0,
        )
        assert len(out["buckets"]) >= 1
