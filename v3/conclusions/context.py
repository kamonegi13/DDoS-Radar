"""Everything a derivation is allowed to see. Nothing it can change.

The five derivations are pure functions of (scored tick, ledger views,
thresholds). This record is the first argument, and building it is the
caller's impure step — the same split `resolve_settings()` / `score_tick()`
uses in L2, and for the same reason: a tick that reads a clock or a
database mid-derivation is a tick that cannot be replayed, and replay is
what parity measurement rests on.

`result` is Optional because a scenario can fail to score at all. That
case must still produce conclusions (five of them, all unavailable) —
S1-CONC-010: a row that cannot be derived is not a row that may be
dropped, because the chronic-null-zone view reads the gaps.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional

from v3.conclusions import thresholds as T
from v3.conclusions.availability import InputHealth
from v3.kernel.errors import DomainError
from v3.scoring.result import ScoringResult


@dataclass(frozen=True, slots=True)
class ScenarioContext:
    """One scenario's inputs for one tick."""

    scenario_id: str
    now: float
    health: InputHealth
    result: Optional[ScoringResult] = None
    participants: tuple[str, ...] = ()
    evidence_urls: Mapping[str, str] = field(default_factory=dict)
    prior_domain_scores: Mapping[str, float] = field(default_factory=dict)
    calibration_status: Mapping[str, Any] = field(default_factory=dict)
    anomaly_limit: int = T.ANOMALY_DEFAULT_LIMIT
    observation_times: Mapping[str, float] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs):
        raise TypeError("ScenarioContext is final.")

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_id, str) or \
                not self.scenario_id.strip():
            raise DomainError("scenario_id must be a non-empty string")
        object.__setattr__(self, "scenario_id", self.scenario_id.strip())
        if isinstance(self.now, bool) or not isinstance(self.now, (int, float)) \
                or self.now <= 0:
            raise DomainError(
                f"now must be a positive timestamp, got {self.now!r}: a "
                f"derivation that defaults its own clock is not replayable")
        object.__setattr__(self, "now", float(self.now))
        if not isinstance(self.health, InputHealth):
            raise DomainError(
                f"a derivation context must carry InputHealth, got "
                f"{type(self.health).__name__}. Without it a quiet tick and "
                f"a dead pipeline are the same input (G-17).")
        if self.result is not None and \
                not isinstance(self.result, ScoringResult):
            raise DomainError(
                f"result must be a ScoringResult or None, got "
                f"{type(self.result).__name__}")
        if self.result is not None and self.result.scenario_id != self.scenario_id:
            raise DomainError(
                f"context is for {self.scenario_id!r} but the scoring result "
                f"is for {self.result.scenario_id!r}: cross-scenario "
                f"attribution is calibration incident #3")
        object.__setattr__(self, "participants", tuple(self.participants))
        for name in ("evidence_urls", "prior_domain_scores",
                     "calibration_status", "observation_times"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise DomainError(
                    f"{name} must be a mapping, got {type(value).__name__}")
            object.__setattr__(self, name, MappingProxyType(dict(value)))
        if isinstance(self.anomaly_limit, bool) or \
                not isinstance(self.anomaly_limit, int) or \
                self.anomaly_limit < 1:
            raise DomainError(
                f"anomaly_limit must be a positive integer, "
                f"got {self.anomaly_limit!r}")

    @property
    def domain_scores(self) -> Mapping[str, float]:
        return {} if self.result is None else self.result.domain_scores

    @property
    def contributions(self) -> tuple:
        return () if self.result is None else self.result.contributions

    def url_for(self, signal_source: str) -> Optional[str]:
        return self.evidence_urls.get(signal_source)


__all__ = ["ScenarioContext"]
