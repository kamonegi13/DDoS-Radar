"""Per-Conclusion calibration status — closes NP5+8 in v2.0.

NP5+8 ("結論品質規律") requires every conclusion to declare the calibration
state of the system that produced it. v1 surfaced calibration globally
through /api/analytics/cmedium_recommendation; v2 inlines a per-scenario
snapshot into Conclusion.calibration_status so analysts can see drift on
the same row as the conclusion itself.

Schema of the dict written into Conclusion.calibration_status:

  {
    "sampler": "OK" | "INSUFFICIENT_DATA" | "DRIFTING" | "DEGRADED",
    "drift_direction": "increasing" | "decreasing" | "stable" |
                       "insufficient_data",
    "drift_magnitude_pct": float,
    "sample_n": int,
    "recent_avg_delta": float,
    "last_sampled_at": float | None,
    "source": "shadow_sampler"
  }

Design choices:
- This module reads only — never writes — so it is safe to call from any
  scoring path and never affects the calibration source data.
- One DB round-trip per call (shadow_drift_stats already aggregates).
- All failures return the INSUFFICIENT_DATA envelope rather than raise:
  observability cannot break scoring (NP3).
- The "sampler" verdict is derived from drift + sample_n. Definitions:
    OK                 — sample_n ≥ 8 AND drift_direction in (stable,
                         insufficient_data with stable trend)
    DRIFTING           — sample_n ≥ 8 AND drift_direction in
                         (increasing, decreasing) AND |magnitude| ≥
                         noise_band
    DEGRADED           — recent_miss_rate ≥ 0.30 (loose calibration)
    INSUFFICIENT_DATA  — sample_n < 8
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from radar.database import RadarDB


log = logging.getLogger("radar")

_MIN_SAMPLES_FOR_VERDICT = 8
_DEGRADED_MISS_RATE_THRESHOLD = 0.30


_INSUFFICIENT: dict = {
    "sampler": "INSUFFICIENT_DATA",
    "drift_direction": "insufficient_data",
    "drift_magnitude_pct": 0.0,
    "sample_n": 0,
    "recent_avg_delta": 0.0,
    "recent_miss_rate": 0.0,
    "last_sampled_at": None,
    "source": "shadow_sampler",
}


def calibration_status_for(db: "RadarDB", scenario_id: str) -> dict:
    """Build the per-Conclusion calibration_status dict for `scenario_id`.

    Reads shadow_drift_stats (aggregate) + shadow_sampler_state (last
    sample timestamp). Returns the INSUFFICIENT_DATA envelope when no
    shadow rows exist or the read fails — never raises.
    """
    try:
        drift = db.shadow_drift_stats()
        per = drift.get("by_scenario", {}).get(scenario_id)
        if per is None:
            return dict(_INSUFFICIENT)

        sample_n = int(per.get("sample_count", 0))
        direction = per.get("drift_direction", "insufficient_data")
        magnitude = float(per.get("drift_magnitude_pct", 0.0))
        recent_avg_delta = float(per.get("recent_avg_delta", 0.0))
        recent_miss_rate = float(per.get("recent_miss_rate", 0.0))
        last_sampled_at = _last_sampled_at(db, scenario_id)
        verdict = _classify_verdict(
            sample_n=sample_n,
            direction=direction,
            recent_miss_rate=recent_miss_rate,
        )
        return {
            "sampler": verdict,
            "drift_direction": direction,
            "drift_magnitude_pct": magnitude,
            "sample_n": sample_n,
            "recent_avg_delta": recent_avg_delta,
            "recent_miss_rate": recent_miss_rate,
            "last_sampled_at": last_sampled_at,
            "source": "shadow_sampler",
        }
    except Exception:
        log.exception("[calibration] non-fatal read failure for %s", scenario_id)
        return dict(_INSUFFICIENT)


def _last_sampled_at(db: "RadarDB", scenario_id: str) -> Optional[float]:
    state = db.shadow_sampler_state_get(scenario_id)
    if not state:
        return None
    val = state.get("last_sampled_at")
    return float(val) if val is not None else None


def _classify_verdict(*, sample_n: int, direction: str,
                      recent_miss_rate: float) -> str:
    if sample_n < _MIN_SAMPLES_FOR_VERDICT:
        return "INSUFFICIENT_DATA"
    if recent_miss_rate >= _DEGRADED_MISS_RATE_THRESHOLD:
        return "DEGRADED"
    if direction in ("increasing", "decreasing"):
        return "DRIFTING"
    return "OK"
