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
from radar.conclusions.persistence import (
    get_conclusion_by_id,
    latest_conclusion,
    save_conclusion,
)
from radar.conclusions.anomaly import derive_anomaly
from radar.conclusions.attack_mode import derive_attack_mode
from radar.conclusions.per_domain import derive_per_domain
from radar.conclusions.threat_level import derive_threat_level
from radar.conclusions.trend import derive_trend

__all__ = [
    "Conclusion",
    "ConclusionType",
    "ConclusionUnavailableReason",
    "new_conclusion_id",
    "save_conclusion",
    "latest_conclusion",
    "get_conclusion_by_id",
    "calibration_status_for",
    "derive_anomaly",
    "derive_attack_mode",
    "derive_per_domain",
    "derive_threat_level",
    "derive_trend",
]
