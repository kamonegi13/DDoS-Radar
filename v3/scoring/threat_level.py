"""THE threat-level derivation. There is no second one.

The legacy system carries four copies of this ladder (D2 A-02 / F-14 /
G-09) across two formula families (P6 O-14), which is how a boundary can be
corrected in one place and stay wrong in three. Here it is a single
function, and every caller in v3 goes through it.

ADR-V3-004 freezes the formula for the duration of the parity period,
**including the part that looks wrong**: TL1 does not require a domain
count, while TL2 does — so the most severe conclusion asks for less
corroboration than the one below it (S1-scoring-core ACCIDENTAL A6, NP2
inversion). That is a live owner ruling, deferred until L5 firing
statistics exist after cutover. Changing it now would make every parity
difference uninterpretable: improvement and regression become
indistinguishable. So it is ported exactly, and the oddity is named here
rather than quietly repaired.

Hysteresis is a separate step (S1-SCORE-005) and lives below, because the
derivation answers "what does this tick say" and hysteresis answers "what
do we act on given what we said last time" — collapsing them is what makes
the raw value unrecoverable for the ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from v3.kernel import ThreatLevel
from v3.kernel.errors import DomainError
from v3.scoring.thresholds import (TL1_PHYSICAL_FLOOR, TL1_SCORE_FLOOR,
                                   TL2_MIN_DOMAINS, TL2_SCORE_FLOOR,
                                   TL3_SCORE_FLOOR, TL4_SCORE_FLOOR)

# The formula's identity, carried into every Provenance record so a stored
# conclusion can be matched to the expression that produced it (NP6).
FORMULA_REF = "v3.scoring.threat_level.derive_tl@S1-SCORE-004"


def derive_tl(score: float, active_domains: Sequence[str],
              physical_score: float) -> ThreatLevel:
    """S1-SCORE-004: the ladder, evaluated most-severe first.

    Each rung that fails its gate falls through to the next, so a score of
    10 with physical 2.9 lands on TL2, and a score of 7 in a single domain
    lands on TL3. Comparisons are `>=` throughout; the boundary values
    themselves (2.0 / 4.0 / 6.0 / 9.0) qualify.

    `active_domains` is only consulted by TL2. See the module docstring.
    """
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise DomainError(
            f"derive_tl needs a numeric score, got "
            f"{type(score).__name__} {score!r}")
    if isinstance(physical_score, bool) or \
            not isinstance(physical_score, (int, float)):
        raise DomainError(
            f"derive_tl needs a numeric physical_score, got "
            f"{type(physical_score).__name__} {physical_score!r}")
    if isinstance(active_domains, (str, bytes)):
        # "cyber" has five "domains" by len(); the mistake is silent and
        # would satisfy TL2's gate on a single domain.
        raise DomainError(
            f"active_domains must be a sequence of domain names, not the "
            f"string {active_domains!r}")
    domain_count = len(list(active_domains))

    if score >= TL1_SCORE_FLOOR and physical_score >= TL1_PHYSICAL_FLOOR:
        return ThreatLevel(1)
    if score >= TL2_SCORE_FLOOR and domain_count >= TL2_MIN_DOMAINS:
        return ThreatLevel(2)
    if score >= TL3_SCORE_FLOOR:
        return ThreatLevel(3)
    if score >= TL4_SCORE_FLOOR:
        return ThreatLevel(4)
    return ThreatLevel(5)


@dataclass(frozen=True, slots=True)
class HysteresisOutcome:
    """The acted-on level, the raw one, and whether the governor bit."""

    level: ThreatLevel
    raw: ThreatLevel
    held: bool


def apply_hysteresis(raw: ThreatLevel,
                     previous: Optional[ThreatLevel]) -> HysteresisOutcome:
    """S1-SCORE-005: fast toward danger, one step at a time away from it.

    Escalation (severity rising) applies immediately; de-escalation is
    capped at one level per tick. This is NP1 in arithmetic form — the cost
    of being slow to relax is a stale warning, and the cost of being slow
    to escalate is a missed war.

    Expressed entirely in severity (= 6 - TL), never in raw TL numbers:
    "de-escalation" means the TL integer *increases*, and writing that as
    a comparison on TL is how the scale got inverted in the 2026-08-02
    calibration incident.
    """
    if not isinstance(raw, ThreatLevel):
        raise DomainError(
            f"apply_hysteresis needs a kernel ThreatLevel, got "
            f"{type(raw).__name__}")
    if previous is None:
        # First observation: nothing to hold against.
        return HysteresisOutcome(level=raw, raw=raw, held=False)
    if not isinstance(previous, ThreatLevel):
        raise DomainError(
            f"previous threat level must be a kernel ThreatLevel or None, "
            f"got {type(previous).__name__}")

    if raw.severity() >= previous.severity():
        # Same or more severe — escalation is instant.
        return HysteresisOutcome(level=raw, raw=raw, held=False)

    # Less severe than last tick: step down by exactly one severity level.
    stepped = ThreatLevel(previous.value + 1)
    if stepped.severity() <= raw.severity():
        # The single step already reaches (or passes) the raw level, so
        # nothing is being held back.
        return HysteresisOutcome(level=raw, raw=raw, held=False)
    return HysteresisOutcome(level=stepped, raw=raw, held=True)


__all__ = ["derive_tl", "apply_hysteresis", "HysteresisOutcome", "FORMULA_REF"]
