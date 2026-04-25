"""DDoS-Radar v2.0 Conclusion Model.

Single source of truth for tool output: every conclusion (threat level, trend,
per-domain, anomaly, attack mode) is wrapped in the unified `Conclusion`
schema (NP4 + NP5+8 + NP6 + NP7 satisfaction in one type).

See docs/design/v2-migration.md for full design.
"""

from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    new_conclusion_id,
)
from radar.conclusions.calibration import calibration_status_for
from radar.conclusions.diff_sampler import sample_focused_tl_diff
from radar.conclusions.persistence import (
    get_conclusion_by_id,
    latest_conclusion,
    save_conclusion,
)

__all__ = [
    "Conclusion",
    "ConclusionType",
    "ConclusionUnavailableReason",
    "new_conclusion_id",
    "save_conclusion",
    "latest_conclusion",
    "get_conclusion_by_id",
    "sample_focused_tl_diff",
    "calibration_status_for",
]
