"""The records the ledger accepts, expressed in kernel types.

The API boundary is where a raw float or a bare dict would otherwise slip
in and become a stored "fact" nobody can trace. Both record types below
refuse that at construction: an observation must arrive as kernel
`Evidence` (so it carries its own freshness horizon and source), and a
threat level must arrive as kernel `ThreatLevel` (so the inverted scale
cannot be misread on the way in).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional

from v3.kernel import Evidence, ThreatLevel
from v3.kernel.errors import DomainError


def _require_text(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(f"{name} must be a non-empty string, got {value!r}")
    return value.strip()


def _optional_number(value, *, name: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(f"{name} must be a number or None, got {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric):
        raise DomainError(
            f"{name} must be finite, got {value!r}: a NaN stored as a fact "
            f"compares False against every later threshold")
    return numeric


@dataclass(frozen=True, slots=True)
class SignalObservation:
    """One sensor signal for one country at one tick (S5-VERIF-018)."""

    tick_id: str
    sensor: str
    signal_source: str
    domain: str
    country: str
    evidence: Evidence
    status: str
    raw_score: Optional[float] = None
    confidence: Optional[float] = None
    flags: Mapping[str, Any] = field(default_factory=dict)
    suppressed: bool = False
    suppress_reason: Optional[str] = None
    evidence_url: Optional[str] = None

    def __init_subclass__(cls, **kwargs):
        raise TypeError("SignalObservation is final.")

    def __post_init__(self) -> None:
        for name in ("tick_id", "sensor", "signal_source", "domain",
                     "country", "status"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        if not isinstance(self.evidence, Evidence):
            raise DomainError(
                f"observation evidence must be a kernel Evidence, got "
                f"{type(self.evidence).__name__}. A bare payload carries no "
                f"observation time and no freshness horizon, which is how "
                f"stale data became a stored fact (B-03).")
        object.__setattr__(self, "raw_score",
                           _optional_number(self.raw_score, name="raw_score"))
        object.__setattr__(
            self, "confidence",
            _optional_number(self.confidence, name="confidence"))
        if not isinstance(self.flags, Mapping):
            raise DomainError(
                f"flags must be a mapping, got {type(self.flags).__name__}")
        # A read-only view: a stored fact must not be editable through the
        # record that describes it.
        object.__setattr__(self, "flags", MappingProxyType(dict(self.flags)))
        if not isinstance(self.suppressed, bool):
            # bool("false") is True, and the migration ETL will be reading
            # exactly that kind of string out of the old rows.
            raise DomainError(
                f"suppressed must be a real bool, got "
                f"{type(self.suppressed).__name__} {self.suppressed!r}; "
                f"coercing would make bool('false') mean True")

    @property
    def observed_at(self) -> float:
        return self.evidence.observed_at

    def flags_json(self) -> str:
        # allow_nan=False: a NaN would serialise to the non-standard
        # `NaN` token, which every strict JSON reader downstream rejects.
        return json.dumps(dict(self.flags), sort_keys=True, default=str,
                          allow_nan=False, ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class TLObservation:
    """One scenario's threat level at one tick. `threat_level=None` is the
    null zone — a first-class state, not a missing row (NP5+8)."""

    tick_id: str
    scenario_id: str
    observed_at: float
    threat_level: Optional[ThreatLevel]
    score: float
    cyber: float = 0.0
    physical: float = 0.0
    info: float = 0.0
    convergence_bonus: float = 0.0
    scoring_mode: str = "full"
    active_countries: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs):
        raise TypeError("TLObservation is final.")

    def __post_init__(self) -> None:
        object.__setattr__(self, "tick_id",
                           _require_text(self.tick_id, name="tick_id"))
        object.__setattr__(self, "scenario_id",
                           _require_text(self.scenario_id, name="scenario_id"))
        observed_at = _optional_number(self.observed_at, name="observed_at")
        if observed_at is None or observed_at <= 0:
            raise DomainError(
                f"observed_at must be a positive timestamp, "
                f"got {self.observed_at!r}")
        object.__setattr__(self, "observed_at", observed_at)
        if self.threat_level is not None and \
                not isinstance(self.threat_level, ThreatLevel):
            raise DomainError(
                f"threat_level must be a kernel ThreatLevel or None (null "
                f"zone), got {type(self.threat_level).__name__}. A raw int "
                f"loses the inverted-scale guard that calibration incident "
                f"#2 turned on.")
        score = _optional_number(self.score, name="score")
        if score is None:
            # 0.0 is a legitimate score, so coercing None to it would turn
            # a missing value into a real measurement.
            raise DomainError("score is required; None is not a score")
        object.__setattr__(self, "score", score)
        for name in ("cyber", "physical", "info", "convergence_bonus"):
            value = _optional_number(getattr(self, name), name=name)
            object.__setattr__(self, name, 0.0 if value is None else value)
        object.__setattr__(self, "active_countries",
                           tuple(self.active_countries))

    @property
    def tl_value(self) -> Optional[int]:
        return None if self.threat_level is None else self.threat_level.value

    def countries_json(self) -> str:
        return json.dumps(list(self.active_countries), allow_nan=False,
                          ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class ConclusionRecord:
    """One conclusion row (S3-DATA-010's shape).

    Explicit fields rather than a **kwargs bag: a bag accepts a typo
    silently and stores a row missing the field the caller thought they
    set. L1 owns storage and retention for these; L3 (WP-3.1) owns the
    semantics.
    """

    conclusion_id: str
    scenario_id: str
    conclusion_type: str
    observed_at: float
    confidence: float
    state: Optional[str] = None
    formula_ref: str = ""
    threshold_ref: str = ""
    source_urls: tuple[str, ...] = ()
    llm_prompt_sha256: Optional[str] = None
    calibration_status: str = ""
    conclusion_unavailable_reason: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs):
        raise TypeError("ConclusionRecord is final.")

    def __post_init__(self) -> None:
        for name in ("conclusion_id", "scenario_id", "conclusion_type"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        observed_at = _optional_number(self.observed_at, name="observed_at")
        if observed_at is None or observed_at <= 0:
            raise DomainError(
                f"observed_at must be a positive timestamp, "
                f"got {self.observed_at!r}")
        object.__setattr__(self, "observed_at", observed_at)
        confidence = _optional_number(self.confidence, name="confidence")
        if confidence is None:
            raise DomainError("confidence is required")
        object.__setattr__(self, "confidence", confidence)
        if not isinstance(self.metadata, Mapping):
            raise DomainError(
                f"metadata must be a mapping, got "
                f"{type(self.metadata).__name__}")
        object.__setattr__(self, "metadata",
                           MappingProxyType(dict(self.metadata)))
        object.__setattr__(self, "source_urls", tuple(self.source_urls))

    def source_urls_json(self) -> str:
        return json.dumps(list(self.source_urls), allow_nan=False,
                          ensure_ascii=False)

    def metadata_json(self) -> str:
        return json.dumps(dict(self.metadata), sort_keys=True, default=str,
                          allow_nan=False, ensure_ascii=False)


__all__ = ["SignalObservation", "TLObservation", "ConclusionRecord"]
