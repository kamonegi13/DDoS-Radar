"""What a scored tick hands back — including how it got there.

Every result carries a kernel `Provenance` whose `formula_ref` names the
clauses that produced it and whose `inputs` record the material values.
That is NP6's requirement made structural: a conclusion whose derivation
cannot be reconstructed does not leave this layer, because there is no
constructor that omits the record.

The threat level is a kernel `ThreatLevel`, never an int, so the inverted
scale (TL1 = CRITICAL) cannot be compared the wrong way round — the defect
that reached calibration in 2026-08-02. `severity()` is the only ordering
surface, and it is 6 - TL everywhere (P6 O-15).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Optional

from v3.kernel import Provenance, ThreatLevel
from v3.kernel.errors import DomainError
from v3.scoring.contributions import Contribution
from v3.scoring.inputs import SequenceEvent


@dataclass(frozen=True, slots=True)
class BonusBreakdown:
    """S1-PIPE-026's fold, itemised.

    Kept apart from the total because "the score rose by 3" and "the score
    rose by 3 because a chain completed" are different conclusions, and
    only the second one an analyst can act on or dispute.
    """

    sequence: float = 0.0
    temporal_coherence: float = 0.0
    velocity: float = 0.0
    acceleration: float = 0.0
    silent_divergence: float = 0.0
    context_alignment: float = 0.0

    @property
    def total(self) -> float:
        return (self.sequence + self.temporal_coherence + self.velocity
                + self.acceleration + self.silent_divergence
                + self.context_alignment)

    def as_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "temporal_coherence": self.temporal_coherence,
            "velocity": self.velocity,
            "acceleration": self.acceleration,
            "silent_divergence": self.silent_divergence,
            "context_alignment": self.context_alignment,
            "total": self.total,
        }


@dataclass(frozen=True, slots=True)
class ScoringResult:
    """One scenario's score for one tick."""

    scenario_id: str
    scoring_mode: str
    threat_level: ThreatLevel
    raw_threat_level: ThreatLevel
    hysteresis_held: bool
    score: float
    base_score: float
    domain_scores: Mapping[str, float]
    convergence: str
    convergence_bonus: float
    bonuses: BonusBreakdown
    active_domains: tuple[str, ...]
    active_countries: tuple[str, ...]
    contributions: tuple[Contribution, ...]
    provenance: Provenance

    def __init_subclass__(cls, **kwargs):
        raise TypeError("ScoringResult is final.")

    def __post_init__(self) -> None:
        for name in ("threat_level", "raw_threat_level"):
            level = getattr(self, name)
            if not isinstance(level, ThreatLevel):
                raise DomainError(
                    f"{name} must be a kernel ThreatLevel, got "
                    f"{type(level).__name__}. A raw int loses the "
                    f"inverted-scale guard.")
        if not isinstance(self.provenance, Provenance):
            raise DomainError(
                f"a scoring result must carry a kernel Provenance, got "
                f"{type(self.provenance).__name__}: a number without its "
                f"derivation is not a disclosed conclusion (NP6).")
        object.__setattr__(self, "domain_scores",
                           MappingProxyType(dict(self.domain_scores)))
        object.__setattr__(self, "contributions", tuple(self.contributions))
        object.__setattr__(self, "active_domains", tuple(self.active_domains))
        object.__setattr__(self, "active_countries",
                           tuple(self.active_countries))

    def severity(self) -> int:
        """6 - TL. The only scale in v3 (P6 O-15)."""
        return self.threat_level.severity()

    def __reduce__(self):
        # mappingproxy is unpicklable and deepcopy takes the same path.
        # Rebuilding through the constructor re-validates, so a restored
        # result cannot be one the constructor would have rejected.
        return (type(self), (
            self.scenario_id, self.scoring_mode, self.threat_level,
            self.raw_threat_level, self.hysteresis_held, self.score,
            self.base_score, dict(self.domain_scores), self.convergence,
            self.convergence_bonus, self.bonuses, self.active_domains,
            self.active_countries, self.contributions, self.provenance))

    @property
    def physical_score(self) -> float:
        return self.domain_scores.get("physical", 0.0)

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "scoring_mode": self.scoring_mode,
            "tl": self.threat_level.value,
            "raw_tl": self.raw_threat_level.value,
            "severity": self.severity(),
            "hysteresis_held": self.hysteresis_held,
            "score": self.score,
            "base_score": self.base_score,
            "domains": dict(self.domain_scores),
            "convergence": self.convergence,
            "convergence_bonus": self.convergence_bonus,
            "bonuses": self.bonuses.as_dict(),
            "active_domains": list(self.active_domains),
            "active_countries": list(self.active_countries),
            "contributions": [c.as_dict() for c in self.contributions],
            "provenance": self.provenance.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class TickResult:
    """Every scorable scenario's result, plus the successor chain state.

    `next_sequence_events` is the other half of the state machine: this
    tick's input was `PriorState.sequence_events`, and the caller feeds
    this back on the next tick. Nothing was written anywhere, which is
    what makes the tick replayable (S5-VERIF-020, S5-VERIF-021).
    """

    now: float
    results: Mapping[str, ScoringResult]
    global_threat: Mapping[str, object]
    next_sequence_events: tuple[SequenceEvent, ...] = ()
    skipped: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "results",
                           MappingProxyType(dict(self.results)))
        # Nested mappings are frozen too, defensively: a read-only outer
        # dict around a mutable inner one is not immutable, and the inner
        # one here holds published domain figures.
        envelope = {
            key: MappingProxyType(dict(value)) if isinstance(value, Mapping)
            else value
            for key, value in dict(self.global_threat).items()}
        object.__setattr__(self, "global_threat", MappingProxyType(envelope))
        object.__setattr__(self, "next_sequence_events",
                           tuple(self.next_sequence_events))
        object.__setattr__(self, "skipped", tuple(self.skipped))

    def __reduce__(self):
        return (type(self), (
            self.now, dict(self.results),
            {key: dict(value) if isinstance(value, Mapping) else value
             for key, value in self.global_threat.items()},
            self.next_sequence_events, self.skipped))

    def next_prior_state(self) -> "PriorState":
        """The `PriorState` for the following tick, built from this one."""
        from v3.scoring.inputs import PriorState
        return PriorState(
            previous_tl={scenario_id: result.threat_level
                         for scenario_id, result in self.results.items()},
            sequence_events=self.next_sequence_events)

    def worst(self) -> Optional[ThreatLevel]:
        """The most severe level across scenarios, or None if none scored."""
        levels = [result.threat_level for result in self.results.values()]
        return ThreatLevel.worst_of(levels) if levels else None


__all__ = ["ScoringResult", "TickResult", "BonusBreakdown"]
