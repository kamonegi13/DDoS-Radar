"""radar.models -- Data classes."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

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

    def to_dict(self) -> dict:
        return {
            "sensor": self.sensor, "domain": self.domain, "status": self.status,
            "value": self.value, "score": self.score, "fired_reason": self.fired_reason,
            "suppressed": self.suppressed, "suppress_reason": self.suppress_reason,
            "confidence": round(self.confidence, 3),
        }
