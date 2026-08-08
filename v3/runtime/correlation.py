"""IDF-weighted origin overlap — production's fifth cyber entry.

§7-2 #122 registered this family as needing a NEW fetch. **It does not.**
The register read `compute_idf_weights`' docstring, which says "ASN keys",
and concluded that `correlations_idf_l3` is built from
`attacks/layer7/top/ases/origin` (`radar/scoring.py:742-754`). It is not.
The distributions that reach `compute_idf_weights` at `core.py:853-855`
are `origin_distributions*`, assembled at `core.py:785` and `:810` out of
`parse_origins` (`radar/scoring.py:659-668`), whose keys are **two-letter
ORIGIN COUNTRY codes**. The ASN histogram is fetched for exactly one
purpose — `state_asn_hits` at `core.py:751-754`, the `is_state_asn=`
decoration §7-2 #125(b) already registered — and never reaches an
overlap. So the whole family is arithmetic on numbers v3 has held since
WP-4.1d: `OriginSpike.origins[code]["l3_pct"]` IS
`normalized_dist_l3[code]` (`core.py:785`).

Three quantities, all pure, in the order production computes them:

  `idf_weights`     `radar/scoring.py:679-711`. How rare each origin is
                    across the compared countries, normalised so the
                    rarest weighs 1. A commodity origin present in every
                    country's distribution weighs ~0, which is the whole
                    point: raw histogram intersection saturated at
                    P50 ~= 53% and separated nothing (`core.py:910-914`).
  `overlap_idf`     `radar/scoring.py:713-736`. IDF-weighted histogram
                    intersection of two countries, 0-100.
  `pairwise_idf`    `core.py:856-861`. Every unordered pair, once.

and then two verdicts off the L3 map:

  `high_correlation`        `core.py:917-918`. The SYNC_DDOS half-gate.
  `botnet_overlap_verdict`  `core.py:1042-1062`. The 0-2 ladder.

**L3 only, deliberately.** Production computes three maps — combined, L3
and L7 — and reads exactly one of them for anything that moves a number:
`core.py:918` and `:1042` both take `correlations_idf_l3`. The other two
reach only the API payload (`core.py:2874`), for a frontend v3 does not
have. Computing them here would be three times the arithmetic for a
reader that does not exist; the choice is stated rather than left to be
rediscovered.

**The ladder's shape is a repair, and the comment above it says so.**
`core.py:1031-1041` records that a flat `score=1` at IDF>=1.5 fired 395
times in 24 h — about every other tick — contributing a constant cyber=1
that pushed threat_level L5->L4 spuriously, at a 47% false-positive rate
in `taiwan_contingency` analyst feedback. Two things are therefore
load-bearing and neither may be "simplified":

  * `MARGINAL_OVERLAP_SCORE` is 0 while the row still FIRES. Status and
    score disagree ON PURPOSE — the analyst keeps the visibility, the
    scenario score does not get the floor. Production's contribution path
    drops `rat.score <= 0` (`radar/scoring.py:83`), so zero is what keeps
    commodity co-occurrence out of scoring; `Observation.admits()` is v3's
    same test (`v3/scoring/inputs.py:249`).
  * FIRED-at-0 is also what still gates the chain. The sequence gate has
    no score condition (`core.py:997`, CLAUDE.md §5), so this row can
    open SYNC_DDOS while adding nothing numeric. `passes_gate()`'s own
    docstring names this row as the reason it is not `admits()`.

A 47% FP rate is the recall/precision trade NP1 normally decides in
recall's favour; it was decided the other way HERE, once, with measured
evidence, and the FIRED status is what preserves the recall half. Raising
`MARGINAL_OVERLAP_SCORE` off zero would re-open the 2026-05-10 defect;
lowering the row to OK would delete a chain link instead.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping

from v3.runtime.spike import DerivedVerdict

#: `radar/scoring.py:707` — the +1 in BOTH halves of `log(N/df)`. It keeps
#: a key present in every document at exactly 0 instead of at -inf, which
#: is what lets the normalisation below have a finite maximum.
IDF_SMOOTHING = 1
#: `radar/scoring.py:736` — `round(num * 100, 2)`. `num` is a weighted
#: histogram intersection in [0, 1]; the scale is what puts the answer on
#: the same 0-100 range the raw index used, so the thresholds below could
#: be recalibrated against a number analysts already read. The observed
#: range is far narrower than the scale suggests (`core.py:914`: P50~=0,
#: P95~=1.96, max~=5.43) because real distributions rarely concentrate on
#: rare origins.
OVERLAP_SCALE = 100.0
#: `radar/scoring.py:736` — and it is the ROUNDED value every threshold
#: below compares against, so the rounding is part of the arithmetic.
OVERLAP_ROUND_DIGITS = 2

#: `radar/routes/core.py:917` — `_HIGH_CORR_IDF_MIN`. Calibrated (A-1,
#: n=21) against a raw index whose P50 was 53%: the IDF index puts P95 at
#: 1.96, so 1.5 marks an outlier without costing recall.
HIGH_CORR_IDF_MIN = 1.5
#: `radar/routes/core.py:1043` — rare-ASN overlap, scored double.
STRONG_OVERLAP_IDF_MIN = 3.5
#: `radar/routes/core.py:1044`.
STRONG_OVERLAP_SCORE = 2.0
#: `radar/routes/core.py:1046` — the SCORING floor, which is not the
#: firing floor. The gap between this and `HIGH_CORR_IDF_MIN` is the
#: 2026-05-10 repair.
OVERLAP_IDF_MIN = 2.0
#: `radar/routes/core.py:1047`.
OVERLAP_SCORE = 1.0
#: `radar/routes/core.py:1050` — FIRED, and zero. See the module
#: docstring: this zero is the fix for a 47% false-positive rate, not an
#: oversight, and the row fires anyway so the chain link survives.
MARGINAL_OVERLAP_SCORE = 0.0

#: `radar/routes/core.py:858` — `f"{a}-{b}"`. Only `max()` and `any()`
#: read the values, and the index is symmetric in its two distributions
#: (`radar/scoring.py:729-732`), so the key is disclosure rather than
#: arithmetic; v3 sorts each pair where production takes them in the
#: focused scenario's participant order.
PAIR_SEPARATOR = "-"


def idf_weights(distributions: Mapping[str, Mapping[str, float]]
                ) -> dict[str, float]:
    """`radar/scoring.py:679-711`, transcribed.

    `distributions` is `{country: {origin: pct}}` — the SCOPED set, not
    every country the tick saw: production builds the weights from the
    countries it is about to compare (`core.py:846-855`) so that
    "ubiquitous" means ubiquitous among THEM. A country whose
    distribution is empty is not a document and does not raise `df`.

    The `max_w <= 0` arm production writes at `radar/scoring.py:709-710`
    is unreachable — `df[k] <= n_docs` by construction, so every raw
    weight is `log(x >= 1) >= 0` and `or 1.0` has already replaced a zero
    maximum. Transcribed as the same total function (all-zero weights)
    without the dead branch, and `tests/test_runtime_correlation.py`
    asserts the unreachability rather than leaving it as a claim.
    """
    if not distributions:
        return {}
    n_docs = sum(1 for values in distributions.values() if values)
    if n_docs <= 0:
        return {}
    document_frequency: dict[str, int] = {}
    for values in distributions.values():
        if not values:
            continue
        for key in values:
            document_frequency[key] = document_frequency.get(key, 0) + 1
    if not document_frequency:
        return {}
    raw = {key: math.log((n_docs + IDF_SMOOTHING) / (count + IDF_SMOOTHING))
           for key, count in document_frequency.items()}
    # `radar/scoring.py:708` — `or 1.0`, which is what an all-ubiquitous
    # scope reaches: every raw weight is 0, so every normalised weight is
    # 0 and the overlap is 0 however identical the two histograms are.
    max_weight = max(raw.values()) or 1.0
    return {key: max(0.0, weight / max_weight) for key, weight in raw.items()}


def overlap_idf(first: Mapping[str, float], second: Mapping[str, float],
                weights: Mapping[str, float]) -> float:
    """`radar/scoring.py:713-736`, transcribed. 0-100, symmetric.

    Each distribution is normalised to its own sum before the
    intersection, so two countries are compared on SHAPE rather than on
    how much traffic either received.

    Iteration is over a SORTED key set where production iterates a plain
    `set`. Float addition is not associative and CPython's `str` hash is
    per-process, so production's raw sum is not bit-reproducible even
    against itself across restarts; the difference lives far below
    `OVERLAP_ROUND_DIGITS` and the sweep in
    `tests/test_runtime_correlation.py` measures it rather than assuming
    it. A replay has to reproduce the number it is replaying, which is
    why the order is fixed here.
    """
    if not first or not second or not weights:
        return 0.0
    first_total = sum(first.values()) or 1.0
    second_total = sum(second.values()) or 1.0
    numerator = sum(
        min(float(first.get(key, 0.0)) / first_total,
            float(second.get(key, 0.0)) / second_total) * weights.get(key, 0.0)
        for key in sorted(set(first) | set(second)))
    return round(numerator * OVERLAP_SCALE, OVERLAP_ROUND_DIGITS)


@dataclass(frozen=True, slots=True)
class Correlations:
    """One layer's pairwise overlaps, with the weights that produced them.

    The weights travel beside the overlaps because they ARE the
    derivation: "TW-JP = 1.83" is not checkable, and "TW-JP = 1.83, and
    the origin they share weighed 1.0 because only those two reported it"
    is. Production keeps `_idf_w_l3` as a local and publishes only the
    overlaps (`core.py:2874`); NP6 asks for the other half, and computing
    it twice to get it would be the DRY violation the fold avoids by
    receiving both from one call.
    """

    weights: Mapping[str, float]
    overlaps: Mapping[str, float]

    @property
    def max_overlap(self) -> float:
        """`radar/routes/core.py:1042` — `max(..., default=0.0)`."""
        return max(self.overlaps.values(), default=0.0)


def pairwise_idf(distributions: Mapping[str, Mapping[str, float]]
                 ) -> Correlations:
    """`radar/routes/core.py:856-861` for one layer — every pair, once.

    One country makes no pair and the map is empty, which `max(...,
    default=0.0)` at `core.py:1042` then reads as 0.0. That is the honest
    answer: an overlap is a statement about two countries and there is no
    second one.
    """
    scoped = {country: dict(values or {})
              for country, values in distributions.items()}
    weights = idf_weights(scoped)
    ordered = sorted(scoped)
    overlaps: dict[str, float] = {}
    for index, left in enumerate(ordered):
        for right in ordered[index + 1:]:
            overlaps[f"{left}{PAIR_SEPARATOR}{right}"] = overlap_idf(
                scoped[left], scoped[right], weights)
    return Correlations(weights=weights, overlaps=overlaps)


def high_correlation(overlaps: Mapping[str, float]) -> bool:
    """`radar/routes/core.py:917-918` — the SYNC_DDOS half-gate.

    Production writes `any(v >= _HIGH_CORR_IDF_MIN ...)` here and
    `max(..., default=0.0)` at `:1042`, which are the same fact about the
    same dict. Kept as its own function because production keeps it as
    its own name, reads it in three places (`:918` -> the row's STATUS,
    `:1309` -> the chain gate, `:2839` -> the payload), and a future
    divergence between the two would otherwise be invisible;
    `tests/test_runtime_correlation.py` pins the equivalence.
    """
    return any(value >= HIGH_CORR_IDF_MIN for value in overlaps.values())


def botnet_overlap_verdict(max_overlap: float,
                           correlated: bool) -> DerivedVerdict:
    """`cf_botnet_overlap` — `radar/routes/core.py:1042-1062`, transcribed.

    The graduated ladder, with the property that made it a repair: the
    lowest rung FIRES and scores nothing. See the module docstring for
    the 395-fires-in-24h / 47%-FP history the production comment records.
    """
    if max_overlap >= STRONG_OVERLAP_IDF_MIN:
        score = STRONG_OVERLAP_SCORE
        reason = (f"Strong shared botnet IDF={max_overlap:.2f} "
                  f"(≥{STRONG_OVERLAP_IDF_MIN} — rare ASN overlap)")
    elif max_overlap >= OVERLAP_IDF_MIN:
        score = OVERLAP_SCORE
        reason = (f"Shared botnet IDF={max_overlap:.2f} "
                  f"(≥{OVERLAP_IDF_MIN})")
    elif correlated:
        score = MARGINAL_OVERLAP_SCORE
        reason = (f"Marginal shared botnet IDF={max_overlap:.2f} "
                  f"(≥{HIGH_CORR_IDF_MIN}; below scoring floor)")
    else:
        score = MARGINAL_OVERLAP_SCORE
        reason = ""
    return DerivedVerdict(fired=correlated, score=score,
                          value=f"{max_overlap:.2f} IDF overlap",
                          reason=reason)


__all__ = ["Correlations", "idf_weights", "overlap_idf", "pairwise_idf",
           "high_correlation",
           "botnet_overlap_verdict", "IDF_SMOOTHING", "OVERLAP_SCALE",
           "OVERLAP_ROUND_DIGITS", "HIGH_CORR_IDF_MIN",
           "STRONG_OVERLAP_IDF_MIN", "STRONG_OVERLAP_SCORE",
           "OVERLAP_IDF_MIN", "OVERLAP_SCORE", "MARGINAL_OVERLAP_SCORE",
           "PAIR_SEPARATOR"]
