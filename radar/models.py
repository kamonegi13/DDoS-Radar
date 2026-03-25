"""radar.models -- Data classes."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ── Direction classification constants ───────────────────────────────────────
DIRECTION_ADVERSARY_OFFENSIVE = "ADVERSARY_OFFENSIVE"
DIRECTION_FRIENDLY_DEFENSIVE  = "FRIENDLY_DEFENSIVE"
DIRECTION_TARGET_IMPACT       = "TARGET_IMPACT"
DIRECTION_UNKNOWN             = "UNKNOWN"

VALID_DIRECTIONS = {
    DIRECTION_ADVERSARY_OFFENSIVE,
    DIRECTION_FRIENDLY_DEFENSIVE,
    DIRECTION_TARGET_IMPACT,
    DIRECTION_UNKNOWN,
}


@dataclass
class RationaleEntry:
    sensor: str
    domain: str
    status: str
    value: str
    score: int
    fired_reason: Optional[str] = None
    suppressed: bool = False
    suppress_reason: Optional[str] = None
    confidence: float = 1.0
    # Signal source group: sensors sharing the same signal_source are
    # deduplicated (max-scored) in compute_domain_scores() to prevent
    # the same underlying event from being counted multiple times.
    # e.g. "bgp" for IODA/BgpRouting/IHR (all measure BGP anomalies)
    signal_source: str = ""
    # ── Context-Aware Convergence (CAC) fields ───────────────────────────────
    # Direction: who is acting and toward whom
    direction: str = DIRECTION_UNKNOWN
    direction_confidence: float = 0.0
    # Temporal context: time-domain features of this signal
    temporal_context: dict = field(default_factory=dict)
    # Spatial context: geographic proximity / chokepoint relevance
    spatial_context: dict = field(default_factory=dict)
    # Target context: relationship between signal source and monitored targets
    target_context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "sensor": self.sensor, "domain": self.domain, "status": self.status,
            "value": self.value, "score": self.score, "fired_reason": self.fired_reason,
            "suppressed": self.suppressed, "suppress_reason": self.suppress_reason,
            "confidence": round(self.confidence, 3),
            "direction": self.direction,
            "direction_confidence": round(self.direction_confidence, 3),
        }
        if self.temporal_context:
            d["temporal_context"] = self.temporal_context
        if self.spatial_context:
            d["spatial_context"] = self.spatial_context
        if self.target_context:
            d["target_context"] = self.target_context
        return d


@dataclass
class NoiseExclusion:
    """Analyst-defined noise exclusion rule."""
    id: int = 0
    sensor: str = ""
    theater: str = ""           # "" = global
    pattern: str = ""           # match pattern (e.g. ASN, country code)
    reason: str = ""            # factual classification: exercise / maintenance / known_noise
    created_at: float = 0.0
    created_by: str = ""
    expires_at: Optional[float] = None  # None = permanent

    def to_dict(self) -> dict:
        return {
            "id": self.id, "sensor": self.sensor, "theater": self.theater,
            "pattern": self.pattern, "reason": self.reason,
            "created_at": self.created_at, "created_by": self.created_by,
            "expires_at": self.expires_at,
        }


@dataclass
class ConfirmedThreat:
    """Analyst-confirmed threat event for co-occurrence learning."""
    id: int = 0
    theater: str = ""
    timestamp: float = 0.0
    classification: str = ""    # exercise / maintenance / confirmed_threat / false_positive
    sensors_active: list = field(default_factory=list)
    threat_level: int = 5
    notes: str = ""
    created_by: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "theater": self.theater, "timestamp": self.timestamp,
            "classification": self.classification, "sensors_active": self.sensors_active,
            "threat_level": self.threat_level, "notes": self.notes,
            "created_by": self.created_by,
        }
