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

__all__ = [
    "Conclusion",
    "ConclusionType",
    "ConclusionUnavailableReason",
    "new_conclusion_id",
]
