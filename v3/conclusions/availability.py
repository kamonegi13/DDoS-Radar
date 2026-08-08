"""Why the tool cannot conclude — with a live path behind every answer.

F-12: three of the four `ConclusionUnavailableReason` values had no
generation path anywhere in the codebase. Everything collapsed into
`insufficient_data`, so "the feeds are down", "the sensors are stale",
"this scenario is too new to trust my own thresholds" and "the world is
quiet" were one word. G-17 is the same hole seen from the other side: the
SALUTE and weather endpoints read an empty cache and answered ROUTINE /
CLEAR / NORMAL, which is not a degraded conclusion but a fabricated one.

Three structures close both:

1. **A registry.** `GUARDS` pairs every reason with the condition that
   emits it. `reasons_with_a_generation_path()` reads the registry rather
   than a hand-kept list, so a reason added to the vocabulary without a
   guard fails the C-08 test instead of quietly re-creating F-12.

2. **Calm-only suppression.** A guard may only convert a CALM candidate
   into an unavailable conclusion. An alerting candidate is published
   whatever the input health says, carrying the guard's verdict as an
   overridden `Suppression`. That asymmetry is NP1 in one rule: partial
   inputs are a reason to distrust silence, never a reason to withhold an
   alarm.

3. **A record either way.** Suppression never deletes anything. E-17 found
   guards stopping an emit with no persistent trace at all — only a log
   line — so here the suppressed conclusion IS the record: it names the
   guard, the reason, the detail and every guard that was evaluated. A
   `Conclusion` refuses to be unavailable without one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from v3.conclusions import thresholds as T
from v3.conclusions import vocabulary as V
from v3.kernel.errors import DomainError


@dataclass(frozen=True, slots=True)
class InputHealth:
    """What the tick actually had to work with.

    Sources are counted, not trusted: "we asked twelve feeds, nine
    answered, two errored and one was older than its freshness horizon" is
    a different fact from "the world was quiet", and G-17 exists because
    the two were the same absence in the cache.

    `history_span_sec` is how long this scenario has been observed at all
    (a derived read over L1's unthinned TL stream, never a counter kept
    here — P6 O-16).
    """

    sources_ok: tuple[str, ...] = ()
    sources_failed: tuple[str, ...] = ()
    sources_stale: tuple[str, ...] = ()
    history_span_sec: float = 0.0

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "InputHealth is final: a subclass could report a healthier "
            "picture than the tick had, which is defect G-17.")

    def __post_init__(self) -> None:
        for name in ("sources_ok", "sources_failed", "sources_stale"):
            value = getattr(self, name)
            if isinstance(value, (str, bytes)):
                raise DomainError(
                    f"InputHealth {name} must be a sequence of source names, "
                    f"not the string {value!r}: a bare string counts its "
                    f"characters as sources")
            object.__setattr__(self, name, tuple(value))
        overlap = (set(self.sources_ok) & set(self.sources_failed)) | \
                  (set(self.sources_ok) & set(self.sources_stale))
        if overlap:
            raise DomainError(
                f"a source cannot be both healthy and unusable: "
                f"{sorted(overlap)}. Double-counting inflates the healthy "
                f"denominator, which is the direction that hides an outage.")
        span = self.history_span_sec
        if isinstance(span, bool) or not isinstance(span, (int, float)) \
                or span < 0:
            raise DomainError(
                f"history_span_sec must be a non-negative number of "
                f"seconds, got {span!r}")
        object.__setattr__(self, "history_span_sec", float(span))

    @property
    def consulted(self) -> int:
        return (len(self.sources_ok) + len(self.sources_failed)
                + len(self.sources_stale))

    @property
    def unusable(self) -> int:
        return len(self.sources_failed) + len(self.sources_stale)

    @property
    def failure_ratio(self) -> float:
        """Fraction of consulted sources that hard-failed. 0.0 if none."""
        return 0.0 if not self.consulted \
            else len(self.sources_failed) / self.consulted

    @property
    def degraded_ratio(self) -> float:
        """Fraction unusable for any reason (failed OR stale)."""
        return 0.0 if not self.consulted else self.unusable / self.consulted

    @property
    def has_no_basis(self) -> bool:
        """No source was consulted at all — the empty-cache shape (G-17)."""
        return self.consulted == 0

    def as_dict(self) -> dict:
        return {
            "sources_ok": list(self.sources_ok),
            "sources_failed": list(self.sources_failed),
            "sources_stale": list(self.sources_stale),
            "consulted": self.consulted,
            "failure_ratio": round(self.failure_ratio, 3),
            "degraded_ratio": round(self.degraded_ratio, 3),
            "history_span_sec": round(self.history_span_sec, 3),
        }


@dataclass(frozen=True, slots=True)
class Candidate:
    """What the type-specific derivation would like to publish.

    `derivable` False means the derivation itself came up empty — TREND
    with no window holding enough samples, ATTACK_MODE with no rule
    firing. That is a real inability to conclude and is distinct from a
    quiet-but-healthy tick, which is a genuine calm verdict and must stay
    sayable (otherwise "missing data" and "genuine calm" collapse the
    other way and every tick is unavailable — NP5+8's design failure).
    """

    state: Optional[str]
    calm: bool
    derivable: bool = True
    detail: str = ""

    def __post_init__(self) -> None:
        if self.derivable and self.state is None:
            raise DomainError(
                "a derivable candidate must carry a state; None state with "
                "derivable=True is the shape that publishes an empty verdict")
        if not self.derivable and self.state is not None:
            raise DomainError(
                f"an underivable candidate cannot carry the state "
                f"{self.state!r}")
        if not self.derivable and not self.calm:
            raise DomainError(
                "an underivable candidate cannot be alerting: there is no "
                "verdict to alert with, and marking it so would let it "
                "override the guards (NP1's asymmetry runs one way only)")


@dataclass(frozen=True, slots=True)
class GuardVerdict:
    """One guard's answer, kept whether it fired or not (NP6)."""

    guard_id: str
    reason: str
    fired: bool
    detail: str

    def as_dict(self) -> dict:
        return {"guard_id": self.guard_id, "reason": self.reason,
                "fired": self.fired, "detail": self.detail}


@dataclass(frozen=True, slots=True)
class Suppression:
    """The record E-17 found missing: what stopped a conclusion, and why.

    `overridden` marks the NP1 case — the guard fired, the candidate was
    alerting, and the alarm was published anyway. The verdict is still
    recorded, because "we nearly withheld this" is exactly the fact an
    auditor asks about after an incident.
    """

    guard_id: str
    reason: str
    detail: str
    overridden: bool
    evaluated: tuple[GuardVerdict, ...] = ()

    def __post_init__(self) -> None:
        V.require_unavailable_reason(self.reason)
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise DomainError(
                "a suppression must say why in plain text: a reason code "
                "alone is what made E-17 untraceable")
        object.__setattr__(self, "evaluated", tuple(self.evaluated))

    def as_dict(self) -> dict:
        return {"guard_id": self.guard_id, "reason": self.reason,
                "detail": self.detail, "overridden": self.overridden,
                "evaluated": [v.as_dict() for v in self.evaluated]}


@dataclass(frozen=True, slots=True)
class Guard:
    """One condition that makes a conclusion unavailable.

    `predicate` returns the plain-text detail when it fires and None when
    it does not — one return value instead of a bool plus a message
    assembled somewhere else, so a fired guard cannot exist without its
    explanation.
    """

    guard_id: str
    reason: str
    describes: str
    predicate: Callable[[InputHealth, Candidate], Optional[str]]

    def evaluate(self, health: InputHealth,
                 candidate: Candidate) -> GuardVerdict:
        detail = self.predicate(health, candidate)
        return GuardVerdict(guard_id=self.guard_id, reason=self.reason,
                            fired=detail is not None,
                            detail=detail or "condition not met")


# ── the conditions (one per reason, plus TREND/ATTACK_MODE's own) ─────────

def _upstream_total_loss(health: InputHealth,
                         candidate: Candidate) -> Optional[str]:
    if not health.consulted:
        return None
    if health.failure_ratio < T.UPSTREAM_FAILURE_RATIO:
        return None
    return (f"every consulted source failed to fetch "
            f"({len(health.sources_failed)}/{health.consulted}): "
            f"{', '.join(sorted(health.sources_failed))}. What survives is "
            f"a sample of the pipeline, not of the world.")


def _sensor_coverage_degraded(health: InputHealth,
                              candidate: Candidate) -> Optional[str]:
    if not health.consulted:
        return None
    if health.degraded_ratio < T.SENSOR_DEGRADED_RATIO:
        return None
    return (f"{health.unusable} of {health.consulted} consulted sources were "
            f"unusable ({len(health.sources_failed)} failed, "
            f"{len(health.sources_stale)} past their freshness horizon), "
            f"at or above the {T.SENSOR_DEGRADED_RATIO:.0%} floor. A quiet "
            f"reading here describes the sensors, not the region.")


def _no_basis_at_all(health: InputHealth,
                     candidate: Candidate) -> Optional[str]:
    if not health.has_no_basis:
        return None
    return ("no source was consulted for this tick, so there is nothing to "
            "conclude from. This is the empty-cache state that G-17's "
            "reports rendered as ROUTINE / CLEAR / NORMAL.")


def _derivation_produced_nothing(health: InputHealth,
                                 candidate: Candidate) -> Optional[str]:
    if candidate.derivable:
        return None
    return candidate.detail or ("the derivation for this conclusion type "
                                "produced no verdict")


def _history_below_calibration_window(health: InputHealth,
                                      candidate: Candidate) -> Optional[str]:
    if health.history_span_sec >= T.CALIBRATION_MIN_HISTORY_SEC:
        return None
    return (f"this scenario has been observed for "
            f"{health.history_span_sec / 86400.0:.2f} days, less than the "
            f"{T.CALIBRATION_MIN_HISTORY_DAYS:g}-day calibration window the "
            f"thresholds assume. A calm verdict on that history is false "
            f"precision; it resolves as the stream fills.")


# Precedence, most concrete first. "The pipes are broken" outranks "the
# pipes are patchy" outranks "there were no pipes" outranks "the formula
# had nothing to chew on" outranks "I have not watched this long enough".
GUARDS: tuple[Guard, ...] = (
    Guard(guard_id="upstream_total_loss", reason=V.UPSTREAM_FAILURE,
          describes="every consulted source hard-failed this tick",
          predicate=_upstream_total_loss),
    Guard(guard_id="sensor_coverage_degraded", reason=V.SENSOR_DEGRADED,
          describes="a majority of consulted sources failed or were stale",
          predicate=_sensor_coverage_degraded),
    Guard(guard_id="no_basis_at_all", reason=V.INSUFFICIENT_DATA,
          describes="no source was consulted at all (empty-cache / G-17)",
          predicate=_no_basis_at_all),
    Guard(guard_id="derivation_produced_nothing", reason=V.INSUFFICIENT_DATA,
          describes="the type's own derivation reached no verdict",
          predicate=_derivation_produced_nothing),
    Guard(guard_id="history_below_calibration_window",
          reason=V.CALIBRATION_PENDING,
          describes="the scenario is younger than one calibration window",
          predicate=_history_below_calibration_window),
)


def reasons_with_a_generation_path() -> frozenset:
    """Read off the registry, never hand-maintained (cutover C-08)."""
    return frozenset(guard.reason for guard in GUARDS)


def registry_disclosure() -> list[dict]:
    """reason -> the condition that produces it, for the audit surface."""
    return [{"guard_id": guard.guard_id, "reason": guard.reason,
             "condition": guard.describes} for guard in GUARDS]


@dataclass(frozen=True, slots=True)
class Availability:
    """The chain's answer: publish, or publish an unavailable conclusion."""

    available: bool
    reason: Optional[str]
    suppression: Optional[Suppression]

    def __post_init__(self) -> None:
        if self.available and self.reason is not None:
            raise DomainError(
                "an available conclusion cannot carry an unavailable reason")
        if not self.available and self.suppression is None:
            raise DomainError(
                "an unavailable conclusion without a suppression record is "
                "defect E-17: the guard stopped it and left no trace")


def evaluate(health: InputHealth, candidate: Candidate) -> Availability:
    """Run every guard, in order, and decide what may be published.

    Every guard runs even after one fires: `evaluated` is the disclosure,
    and an auditor asking "was the calibration window also short?" should
    not have to re-derive it. The FIRST firing guard owns the outcome.
    """
    if not isinstance(health, InputHealth):
        raise TypeError(
            f"evaluate needs an InputHealth, got {type(health).__name__}: "
            f"without one there is no way to tell an empty cache from a "
            f"quiet world (G-17)")
    if not isinstance(candidate, Candidate):
        raise TypeError(
            f"evaluate needs a Candidate, got {type(candidate).__name__}")

    verdicts = tuple(guard.evaluate(health, candidate) for guard in GUARDS)
    fired = next((v for v in verdicts if v.fired), None)
    if fired is None:
        return Availability(available=True, reason=None, suppression=None)

    # NP1's override has one limit, and it is not a matter of degree: an
    # alarm may be published from PARTIAL evidence, never from NONE. With
    # no source consulted there is nothing for the alarm to be about, and
    # `Conclusion` refuses the state anyway (G-17) — so overriding here
    # would raise out of the derivation and delete all five conclusions
    # for exactly the alerting scenarios, which reads downstream as a
    # healthy tick. Silence about the loudest scenario is the worst
    # possible reading of NP1.
    if not candidate.calm and not health.has_no_basis:
        # NP1. The alarm ships; the near-miss is recorded.
        return Availability(
            available=True, reason=None,
            suppression=Suppression(
                guard_id=fired.guard_id, reason=fired.reason,
                detail=(f"{fired.detail} The candidate was alerting, so NP1 "
                        f"published it anyway rather than withhold a warning "
                        f"for want of clean inputs."),
                overridden=True, evaluated=verdicts))

    detail = fired.detail
    if not candidate.calm:
        detail = (f"{detail} The candidate was alerting, but with no source "
                  f"consulted there is no evidence for an alarm to rest on, "
                  f"so NP1's override does not apply.")
    return Availability(
        available=False, reason=fired.reason,
        suppression=Suppression(guard_id=fired.guard_id, reason=fired.reason,
                                detail=detail, overridden=False,
                                evaluated=verdicts))


__all__ = ["InputHealth", "Candidate", "Guard", "GuardVerdict", "Suppression",
           "Availability", "GUARDS", "evaluate",
           "reasons_with_a_generation_path", "registry_disclosure"]
