"""Rolling many tick verdicts up into the numbers the cutover asks for.

The definitions are S5-VERIF-025 (agreement rate), 028 (contributing-set
agreement) and 029 (directional asymmetry), and each is written the way its
clause writes it rather than the way that would read best:

  * the agreement denominator is ticks present on BOTH sides, so a run
    riddled with one-side gaps cannot post a high score by shrinking what
    it counts (S5-VERIF-023 then voids the run outright above 5%);
  * mismatches are split by direction and the two halves are NOT summed.
    NP1 says a v3 that saw less is disqualifying and a v3 that saw more is
    a note, so a single "mismatch count" would average away the only
    distinction that matters;
  * contributor agreement is reported at the median and the 5th
    percentile. A TL that agrees while the evidence behind it does not is
    a coincidence, and NP6 does not accept coincidences as parity — the
    p05 is there to surface exactly those ticks.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Iterable, Optional

from v3.parity.compare import (INSENSITIVE, MATCH, MAX_ONE_SIDE_MISSING_RATE,
                               MISMATCH, ONE_SIDE_MISSING, PARTIAL, SENSITIVE,
                               SIDE_LEGACY, SIDE_V3, TickComparison,
                               TransitionTiming, _percentile)

#: How many worked examples a mismatch bucket carries into the report.
#: S5-VERIF-030 forbids reporting a rate without a route to the cause, and
#: a bounded sample keeps the report readable while staying actionable.
EXAMPLE_LIMIT = 10


@dataclass(frozen=True, slots=True)
class SeriesSummary:
    """Every number S5-VERIF-025..029 defines, over one comparison run."""

    total_keys: int
    both_present: int
    matched: int
    partial: int
    mismatched: int
    one_side_missing: int
    missing_legacy: int
    missing_v3: int
    insensitive: int
    sensitive: int
    jaccard_median: Optional[float]
    jaccard_p05: Optional[float]
    transitions: Optional[TransitionTiming] = None
    insensitive_examples: tuple[TickComparison, ...] = ()
    sensitive_examples: tuple[TickComparison, ...] = ()

    @property
    def agreement_rate(self) -> Optional[float]:
        """S5-VERIF-025: matched / present-on-both-sides.

        None when nothing was comparable — reporting 0.0 would read as
        total disagreement, and reporting 1.0 as perfect agreement. Both
        are claims the data cannot support.
        """
        if self.both_present == 0:
            return None
        return self.matched / self.both_present

    @property
    def one_side_missing_rate(self) -> float:
        if self.total_keys == 0:
            return 0.0
        return self.one_side_missing / self.total_keys

    @property
    def is_void(self) -> bool:
        """S5-VERIF-023: too many gaps and the comparison is meaningless."""
        return self.one_side_missing_rate > MAX_ONE_SIDE_MISSING_RATE

    @property
    def has_blocking_mismatch(self) -> bool:
        """NP1: any v3-quieter disagreement blocks, however rare."""
        return self.insensitive > 0

    def as_dict(self) -> dict:
        return {
            "total_keys": self.total_keys,
            "both_present": self.both_present,
            "matched": self.matched,
            "partial": self.partial,
            "mismatched": self.mismatched,
            "one_side_missing": self.one_side_missing,
            "missing_legacy": self.missing_legacy,
            "missing_v3": self.missing_v3,
            "one_side_missing_rate": self.one_side_missing_rate,
            "is_void": self.is_void,
            "agreement_rate": self.agreement_rate,
            "insensitive": self.insensitive,
            "sensitive": self.sensitive,
            "has_blocking_mismatch": self.has_blocking_mismatch,
            "jaccard_median": self.jaccard_median,
            "jaccard_p05": self.jaccard_p05,
            "transitions": (self.transitions.as_dict()
                            if self.transitions else None),
            "insensitive_examples": [c.as_dict()
                                     for c in self.insensitive_examples],
            "sensitive_examples": [c.as_dict()
                                   for c in self.sensitive_examples],
        }


def summarise(comparisons: Iterable[TickComparison], *,
              transitions: Optional[TransitionTiming] = None) -> SeriesSummary:
    """Fold tick verdicts into the reported statistics."""
    materialised = list(comparisons)

    matched = partial = mismatched = missing = 0
    missing_legacy = missing_v3 = 0
    insensitive: list[TickComparison] = []
    sensitive: list[TickComparison] = []
    jaccards: list[float] = []

    for comparison in materialised:
        if comparison.verdict == ONE_SIDE_MISSING:
            missing += 1
            if comparison.missing_side == SIDE_LEGACY:
                missing_legacy += 1
            elif comparison.missing_side == SIDE_V3:
                missing_v3 += 1
            # No jaccard: there is no second set to compare against, and
            # scoring it 0.0 would drag the p05 down with a fact about
            # absence rather than about evidence.
            continue

        if comparison.jaccard is not None:
            jaccards.append(comparison.jaccard)

        if comparison.verdict == MATCH:
            matched += 1
            continue
        if comparison.verdict == PARTIAL:
            partial += 1
        else:
            mismatched += 1
        if comparison.direction == INSENSITIVE:
            insensitive.append(comparison)
        elif comparison.direction == SENSITIVE:
            sensitive.append(comparison)

    both_present = len(materialised) - missing
    ordered = tuple(sorted(jaccards))
    return SeriesSummary(
        total_keys=len(materialised),
        both_present=both_present,
        matched=matched,
        partial=partial,
        mismatched=mismatched,
        one_side_missing=missing,
        missing_legacy=missing_legacy,
        missing_v3=missing_v3,
        insensitive=len(insensitive),
        sensitive=len(sensitive),
        jaccard_median=statistics.median(ordered) if ordered else None,
        jaccard_p05=_percentile(ordered, 0.05) if ordered else None,
        transitions=transitions,
        insensitive_examples=tuple(insensitive[:EXAMPLE_LIMIT]),
        sensitive_examples=tuple(sensitive[:EXAMPLE_LIMIT]))


__all__ = ["SeriesSummary", "summarise", "EXAMPLE_LIMIT"]
