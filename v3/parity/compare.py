"""Comparing two systems' conclusions, in severity space and nowhere else.

S5-VERIF-024 is categorical: every agreement test, magnitude comparison and
direction classification converts to `severity = 6 - TL` first, and raw TL
numbers are never ordered. That clause exists because the 2026-07-03
calibration incident inverted exactly this comparison and the expression
read correctly while doing so.

So this module never sees a TL integer. `Reading.threat_level` is a kernel
`ThreatLevel`, whose ordering operators raise, and the only number that
leaves it is `severity()`. A reviewer looking for "did they compare raw
TLs" has no place to find one.

Four distinctions this module refuses to collapse, each because collapsing
it would flatter the result:

    absent            no row on one side (S5-VERIF-023) — counted apart,
                      never as agreement, never as disagreement
    null zone         a row saying "no conclusion" (tl=None). Two of them
                      agree; one against a real level does not
    insensitive       v3 called it quieter than legacy. NP1 says blocking
    sensitive         v3 called it louder. Reported, not blocking
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional, Sequence

from v3.kernel import ThreatLevel
from v3.kernel.errors import DomainError

# ── verdicts ──────────────────────────────────────────────────────────────
MATCH = "MATCH"
MISMATCH = "MISMATCH"
ONE_SIDE_MISSING = "ONE_SIDE_MISSING"
PARTIAL = "PARTIAL"

# ── directions (S5-VERIF-029) ─────────────────────────────────────────────
INSENSITIVE = "INSENSITIVE"   # v3 quieter than legacy — blocking under NP1
SENSITIVE = "SENSITIVE"       # v3 louder — reported only

SIDE_LEGACY = "legacy"
SIDE_V3 = "v3"

# ── conclusion types (S5-VERIF-027) ───────────────────────────────────────
THREAT_LEVEL = "threat_level"
PER_DOMAIN = "per_domain"
ATTACK_MODE = "attack_mode"
TREND = "trend"
ANOMALY = "anomaly"

#: S5-VERIF-023's one-side-missing ceiling. Above this the run is void:
#: the two series are not describing the same window any more, and an
#: agreement rate computed over what remains would be measuring the
#: overlap rather than the systems.
MAX_ONE_SIDE_MISSING_RATE = 0.05


@dataclass(frozen=True, slots=True)
class Contributor:
    """One (sensor, signal_source, country) that fed a conclusion."""

    sensor: str
    signal_source: str
    country: str

    def as_tuple(self) -> tuple:
        return (self.sensor, self.signal_source, self.country)


@dataclass(frozen=True, slots=True)
class Reading:
    """One system's output for one (scenario, type, tick).

    `threat_level=None` is the null zone — a stated "no conclusion", not a
    missing row. Absence is represented by having no Reading at all.
    """

    threat_level: Optional[ThreatLevel] = None
    state: Optional[str] = None
    unavailable_reason: Optional[str] = None
    domain_states: Mapping[str, str] = field(default_factory=dict)
    anomaly_keys: frozenset = frozenset()
    contributing: tuple[Contributor, ...] = ()

    def __post_init__(self) -> None:
        if self.threat_level is not None and \
                not isinstance(self.threat_level, ThreatLevel):
            raise DomainError(
                f"Reading.threat_level must be a kernel ThreatLevel or None "
                f"(null zone), got {type(self.threat_level).__name__}. A raw "
                f"int would let this module order TLs directly, which is "
                f"the inversion S5-VERIF-024 forbids.")
        object.__setattr__(self, "domain_states", dict(self.domain_states))
        object.__setattr__(self, "anomaly_keys", frozenset(self.anomaly_keys))
        object.__setattr__(self, "contributing", tuple(self.contributing))

    @property
    def severity(self) -> Optional[int]:
        """6 - TL, or None in the null zone. The ONLY number for ordering."""
        return None if self.threat_level is None \
            else self.threat_level.severity()

    @property
    def contributor_set(self) -> frozenset:
        return frozenset(c.as_tuple() for c in self.contributing)


@dataclass(frozen=True, slots=True)
class TickKey:
    """S5-VERIF-023's comparison primary key."""

    scenario_id: str
    conclusion_type: str
    tick_ts: float

    def as_dict(self) -> dict:
        return {"scenario_id": self.scenario_id,
                "conclusion_type": self.conclusion_type,
                "tick_ts": self.tick_ts}


@dataclass(frozen=True, slots=True)
class TickComparison:
    """One key's verdict, with everything needed to explain it."""

    key: TickKey
    verdict: str
    direction: Optional[str] = None
    missing_side: Optional[str] = None
    legacy_severity: Optional[int] = None
    v3_severity: Optional[int] = None
    legacy_state: Optional[str] = None
    v3_state: Optional[str] = None
    jaccard: Optional[float] = None
    detail: str = ""

    @property
    def is_blocking(self) -> bool:
        """NP1: only a v3 that saw LESS blocks a cutover."""
        return self.verdict == MISMATCH and self.direction == INSENSITIVE

    def as_dict(self) -> dict:
        return {
            **self.key.as_dict(),
            "verdict": self.verdict,
            "direction": self.direction,
            "missing_side": self.missing_side,
            "legacy_severity": self.legacy_severity,
            "v3_severity": self.v3_severity,
            "legacy_state": self.legacy_state,
            "v3_state": self.v3_state,
            "jaccard": self.jaccard,
            "detail": self.detail,
        }


def _direction(legacy: Reading, v3: Reading) -> Optional[str]:
    """S5-VERIF-029, in severity space.

    A null zone on one side is a direction too: v3 declining to conclude
    where legacy raised a level is v3 being quieter, which is exactly the
    failure NP1 refuses to accept.
    """
    legacy_severity, v3_severity = legacy.severity, v3.severity
    if legacy_severity is None and v3_severity is None:
        return None
    if v3_severity is None:
        return INSENSITIVE
    if legacy_severity is None:
        return SENSITIVE
    if v3_severity < legacy_severity:
        return INSENSITIVE
    if v3_severity > legacy_severity:
        return SENSITIVE
    return None


def _jaccard(left: frozenset, right: frozenset) -> float:
    """S5-VERIF-028. Two empty sets agree completely."""
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 1.0


# ── per-type match rules (S5-VERIF-027) ───────────────────────────────────

def _match_threat_level(legacy: Reading, v3: Reading) -> tuple[bool, str]:
    if legacy.severity is None and v3.severity is None:
        return True, "both in the null zone"
    return legacy.severity == v3.severity, "severity comparison"


def _match_per_domain(legacy: Reading, v3: Reading) -> tuple[bool, str]:
    domains = set(legacy.domain_states) | set(v3.domain_states)
    differing = sorted(d for d in domains
                       if legacy.domain_states.get(d) != v3.domain_states.get(d))
    return (not differing,
            "all domain states agree" if not differing
            else f"domains differing: {differing}")


def _match_state(legacy: Reading, v3: Reading) -> tuple[bool, str]:
    return legacy.state == v3.state, "state string comparison"


def _match_trend(legacy: Reading, v3: Reading) -> tuple[bool, str]:
    if legacy.state == v3.state:
        return True, "state string comparison"
    # S5-VERIF-027: direction-only agreement is counted separately rather
    # than folded into either bucket.
    if _trend_direction(legacy.state) == _trend_direction(v3.state) \
            and _trend_direction(legacy.state) is not None:
        return False, "PARTIAL: same direction, different magnitude"
    return False, "state string comparison"


def _trend_direction(state: Optional[str]) -> Optional[str]:
    if not state:
        return None
    upper = state.upper()
    if "ESCALAT" in upper and "DE" not in upper.split("ESCALAT")[0][-3:]:
        return "UP"
    if "DE-ESCALAT" in upper or "DE_ESCALAT" in upper:
        return "DOWN"
    return None


def _match_anomaly(legacy: Reading, v3: Reading) -> tuple[bool, str]:
    """Set comparison; multiplicity ignored (S5-VERIF-027)."""
    only_legacy = sorted(legacy.anomaly_keys - v3.anomaly_keys)
    only_v3 = sorted(v3.anomaly_keys - legacy.anomaly_keys)
    if not only_legacy and not only_v3:
        return True, "anomaly key sets agree"
    return False, (f"missing from v3: {only_legacy}; "
                   f"extra in v3: {only_v3}")


_MATCHERS = {
    THREAT_LEVEL: _match_threat_level,
    PER_DOMAIN: _match_per_domain,
    ATTACK_MODE: _match_state,
    TREND: _match_trend,
    ANOMALY: _match_anomaly,
}


def compare_tick(key: TickKey, legacy: Optional[Reading],
                 v3: Optional[Reading]) -> TickComparison:
    """One (scenario, type, tick). Absence is its own verdict.

    S5-VERIF-023: a tick present on only one side counts as neither
    agreement nor disagreement. Folding it into either would let a run
    where half the rows are missing report a healthy agreement rate.
    """
    if legacy is None and v3 is None:
        raise DomainError(
            f"compare_tick called with nothing on either side for {key}: "
            f"a key exists because at least one system produced it")
    if legacy is None or v3 is None:
        missing = SIDE_LEGACY if legacy is None else SIDE_V3
        present = v3 if legacy is None else legacy
        return TickComparison(
            key=key, verdict=ONE_SIDE_MISSING, missing_side=missing,
            legacy_severity=None if legacy is None else legacy.severity,
            v3_severity=None if v3 is None else v3.severity,
            legacy_state=None if legacy is None else legacy.state,
            v3_state=None if v3 is None else v3.state,
            detail=f"no row on the {missing} side; "
                   f"the other reported {present.state or present.severity}")

    matcher = _MATCHERS.get(key.conclusion_type)
    if matcher is None:
        raise DomainError(
            f"no match rule for conclusion_type {key.conclusion_type!r}; "
            f"S5-VERIF-027 defines one per type: {sorted(_MATCHERS)}")
    matched, detail = matcher(legacy, v3)

    # S5-VERIF-027: the unavailability reason is part of identity. Two
    # "no conclusion" answers for different reasons are not the same
    # answer — that distinction is the whole of F-12's repair.
    if matched and legacy.unavailable_reason != v3.unavailable_reason:
        matched = False
        detail = (f"same state, different unavailable_reason: "
                  f"{legacy.unavailable_reason!r} vs "
                  f"{v3.unavailable_reason!r}")

    jaccard = _jaccard(legacy.contributor_set, v3.contributor_set)
    if matched:
        return TickComparison(
            key=key, verdict=MATCH, legacy_severity=legacy.severity,
            v3_severity=v3.severity, legacy_state=legacy.state,
            v3_state=v3.state, jaccard=jaccard, detail=detail)

    direction = _direction(legacy, v3)
    if direction is None and key.conclusion_type == ANOMALY:
        # S5-VERIF-029: a type without a magnitude still has a direction —
        # anything legacy saw and v3 did not is v3 seeing less.
        if legacy.anomaly_keys - v3.anomaly_keys:
            direction = INSENSITIVE
        elif v3.anomaly_keys - legacy.anomaly_keys:
            direction = SENSITIVE
    verdict = PARTIAL if detail.startswith("PARTIAL") else MISMATCH
    return TickComparison(
        key=key, verdict=verdict, direction=direction,
        legacy_severity=legacy.severity, v3_severity=v3.severity,
        legacy_state=legacy.state, v3_state=v3.state, jaccard=jaccard,
        detail=detail)


# ── transitions (S5-VERIF-026) ────────────────────────────────────────────

ESCALATE = "ESCALATE"
DE_ESCALATE = "DE_ESCALATE"


@dataclass(frozen=True, slots=True)
class Transition:
    """A change of severity, with when and which way."""

    at: float
    from_severity: Optional[int]
    to_severity: Optional[int]

    @property
    def direction(self) -> str:
        # Severity space: rising severity is escalation, whichever way the
        # underlying TL integer moved.
        if self.from_severity is None:
            return ESCALATE if self.to_severity is not None else DE_ESCALATE
        if self.to_severity is None:
            return DE_ESCALATE
        return ESCALATE if self.to_severity > self.from_severity \
            else DE_ESCALATE


def extract_transitions(series: Sequence[tuple[float, Reading]]
                        ) -> tuple[Transition, ...]:
    """Every severity change in a time-ordered series.

    Entering and leaving the null zone count as transitions: a system that
    stops concluding has changed what it is telling the analyst, and
    S5-VERIF-026 pairs on direction and destination, both of which are
    defined for None.
    """
    ordered = sorted(series, key=lambda pair: pair[0])
    transitions: list[Transition] = []
    previous: Optional[int] = None
    started = False
    for at, reading in ordered:
        current = reading.severity
        if started and current != previous:
            transitions.append(Transition(at=at, from_severity=previous,
                                          to_severity=current))
        previous = current
        started = True
    return tuple(transitions)


@dataclass(frozen=True, slots=True)
class TransitionTiming:
    """S5-VERIF-026's three reported numbers."""

    median_delta_sec: Optional[float]
    p95_delta_sec: Optional[float]
    unpaired_legacy: int
    unpaired_v3: int
    deltas: tuple[float, ...] = ()

    def as_dict(self) -> dict:
        return {"median_delta_sec": self.median_delta_sec,
                "p95_delta_sec": self.p95_delta_sec,
                "unpaired_legacy": self.unpaired_legacy,
                "unpaired_v3": self.unpaired_v3,
                "paired": len(self.deltas)}


def compare_transitions(legacy: Iterable[Transition],
                        v3: Iterable[Transition]) -> TransitionTiming:
    """Pair nearest transitions of the same direction AND destination.

    Anything left unpaired is reported as a one-sided transition rather
    than matched to something merely nearby — a v3 escalation with no
    legacy counterpart is a finding, not a timing difference.
    """
    remaining = list(v3)
    deltas: list[float] = []
    unpaired_legacy = 0
    for transition in sorted(legacy, key=lambda t: t.at):
        candidates = [candidate for candidate in remaining
                      if candidate.direction == transition.direction
                      and candidate.to_severity == transition.to_severity]
        if not candidates:
            unpaired_legacy += 1
            continue
        nearest = min(candidates, key=lambda c: abs(c.at - transition.at))
        deltas.append(abs(nearest.at - transition.at))
        remaining.remove(nearest)

    ordered = tuple(sorted(deltas))
    return TransitionTiming(
        median_delta_sec=statistics.median(ordered) if ordered else None,
        p95_delta_sec=_percentile(ordered, 0.95) if ordered else None,
        unpaired_legacy=unpaired_legacy, unpaired_v3=len(remaining),
        deltas=ordered)


def _percentile(ordered: Sequence[float], fraction: float) -> float:
    """Nearest-rank percentile over an already-sorted sequence.

    `ceil(fraction * n)`, which is the nearest-rank definition. The
    previous `round(fraction * n + 0.5)` inherited Python's banker's
    rounding and was off by one in both directions that matter: at n=20 it
    made p95 the maximum (p100) and made p05 skip the single worst value.
    Both errors flatter the result, and these two statistics exist
    precisely to stop the report flattering itself — p95 bounds the
    transition lag, p05 surfaces the ticks where the evidence disagreed
    most.
    """
    if not ordered:
        raise DomainError(
            "percentile of an empty sequence: report None for "
            "'not measurable' rather than a number nothing supports")
    rank = max(1, min(len(ordered), math.ceil(fraction * len(ordered))))
    return ordered[rank - 1]


__all__ = [
    "Reading", "Contributor", "TickKey", "TickComparison", "compare_tick",
    "Transition", "TransitionTiming", "extract_transitions",
    "compare_transitions",
    "MATCH", "MISMATCH", "ONE_SIDE_MISSING", "PARTIAL",
    "INSENSITIVE", "SENSITIVE", "SIDE_LEGACY", "SIDE_V3",
    "THREAT_LEVEL", "PER_DOMAIN", "ATTACK_MODE", "TREND", "ANOMALY",
    "MAX_ONE_SIDE_MISSING_RATE", "ESCALATE", "DE_ESCALATE",
]
