"""Conclusion dataclass — the v2.0 single output schema.

Every tool conclusion (TL, trend, per-domain, anomaly, attack mode) must be
returned as a `Conclusion` instance. This guarantees NP6 (full disclosure of
formula/threshold/sources/LLM prompt), NP5+8 (calibration metadata + explicit
unavailable state), and NP7 (final-judgment disclaimer at the schema level).

Constraint ⑤ + ⑥ from v2-migration.md §2.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ConclusionType(str, Enum):
    """The 5 conclusion domains specified by CLAUDE.md tool definition."""

    THREAT_LEVEL = "threat_level"
    TREND = "trend"
    PER_DOMAIN = "per_domain"
    ANOMALY = "anomaly"
    ATTACK_MODE = "attack_mode"


class ConclusionUnavailableReason(str, Enum):
    """Reasons a conclusion cannot be derived (NP5+8 explicit unavailable state).

    Distinguish transient (`is_transient=True` in metadata) from structural
    via `inconclusive_continuity_log` 7-day rule (ADR-V2-010).
    """

    INSUFFICIENT_DATA = "insufficient_data"
    CALIBRATION_PENDING = "calibration_pending"
    SENSOR_DEGRADED = "sensor_degraded"
    UPSTREAM_FAILURE = "upstream_failure"


def new_conclusion_id() -> str:
    """Generate a fresh UUID for a Conclusion (used by builders + tests)."""
    return str(uuid.uuid4())


@dataclass(frozen=True)
class Conclusion:
    """v2.0 unified output schema. See docs/design/v2-migration.md §5.1.

    Frozen for NP6 — once a conclusion is derived, downstream code must not
    mutate it. Persistence layer serializes via `to_dict()`.
    """

    id: str
    scenario_id: str
    conclusion_type: ConclusionType
    state: Optional[str]
    confidence: float
    observed_at: float
    formula_ref: str
    threshold_ref: dict
    source_urls: tuple
    final_judgment_disclaimer: str
    llm_prompt_sha256: Optional[str] = None
    calibration_status: dict = field(default_factory=dict)
    conclusion_unavailable_reason: Optional[ConclusionUnavailableReason] = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be in [0.0, 1.0], got {self.confidence!r}"
            )
        if self.conclusion_unavailable_reason is None and self.state is None:
            raise ValueError(
                "Conclusion with no unavailable_reason must have non-null state"
            )
        if self.conclusion_unavailable_reason is not None and self.state is not None:
            raise ValueError(
                "Conclusion with unavailable_reason must have state=None"
            )
        if not self.final_judgment_disclaimer:
            raise ValueError(
                "final_judgment_disclaimer is required (NP7 / constraint ⑥)"
            )

    def is_available(self) -> bool:
        """True if the conclusion produced a usable state."""
        return self.conclusion_unavailable_reason is None

    def to_dict(self) -> dict:
        """Serialize to dict for API/DB. Enums become their string values."""
        return {
            "id": self.id,
            "scenario_id": self.scenario_id,
            "conclusion_type": self.conclusion_type.value,
            "state": self.state,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "formula_ref": self.formula_ref,
            "threshold_ref": dict(self.threshold_ref),
            "source_urls": list(self.source_urls),
            "llm_prompt_sha256": self.llm_prompt_sha256,
            "calibration_status": dict(self.calibration_status),
            "conclusion_unavailable_reason": (
                self.conclusion_unavailable_reason.value
                if self.conclusion_unavailable_reason is not None
                else None
            ),
            "final_judgment_disclaimer": self.final_judgment_disclaimer,
            "metadata": dict(self.metadata),
        }

    def to_db_row(self) -> dict:
        """Serialize for direct sqlite3 INSERT into the `conclusions` table."""
        return {
            "id": self.id,
            "scenario_id": self.scenario_id,
            "conclusion_type": self.conclusion_type.value,
            "state": self.state,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
            "formula_ref": self.formula_ref,
            "threshold_ref": json.dumps(self.threshold_ref, sort_keys=True),
            "source_urls": json.dumps(list(self.source_urls)),
            "llm_prompt_sha256": self.llm_prompt_sha256,
            "calibration_status": json.dumps(self.calibration_status, sort_keys=True),
            "conclusion_unavailable_reason": (
                self.conclusion_unavailable_reason.value
                if self.conclusion_unavailable_reason is not None
                else None
            ),
            "metadata": json.dumps(self.metadata, sort_keys=True),
        }
