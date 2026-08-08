"""The recall arithmetic. One implementation, by rule (S5-VERIF-035).

Production has three, and they disagree in ways nobody chose:

    scripts/report_recall_metrics.py   all types, deduped, `None` on a
                                       zero denominator
    radar/conclusions/calibration.py   threat_level only, 30-day window
    scripts/check_recall_post_autotune.py
                                       no dedup, no join

and a fourth expression inside the TL calibrator uses `tp / max(1, tp+fn)`,
which reports 0.0 — "measured, and terrible" — where the others report
`None` — "not measured". DP23 records both halves of that asymmetry.

So the functions here are deliberately tiny and deliberately the only
ones: `matrix.audit_recall_arithmetic_sites()` reads the package's AST and
fails the suite if a second site appears. Callers differ by the
PARAMETERS they pass (window, dedup, type filter), never by the formula.

`None` rather than 0.0 for an undefined denominator is not a style
choice — S1-CALIB-026 makes it the contract, and the downstream gate
treats `None` as a coverage loss rather than as a passing score.
"""
from __future__ import annotations

from fractions import Fraction
from typing import Optional

from v3.kernel.errors import DomainError


def _count(value, *, name: str) -> int:
    """A confusion-matrix count: a non-negative int, and not a bool.

    `bool` is an `int` in Python, so `tp=True` would silently mean 1. In a
    layer whose failures are silent by nature, that is not acceptable.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise DomainError(
            f"{name} must be a non-negative integer count, got "
            f"{type(value).__name__} {value!r}")
    if value < 0:
        raise DomainError(f"{name} must be non-negative, got {value}")
    return value


def recall(*, tp: int, fn: int) -> Optional[float]:
    """tp / (tp + fn), or None when no positive was ever observed."""
    numerator = _count(tp, name="tp")
    denominator = numerator + _count(fn, name="fn")
    if denominator == 0:
        return None
    return numerator / denominator


def precision(*, tp: int, fp: int) -> Optional[float]:
    """tp / (tp + fp), or None when nothing was ever alerted on."""
    numerator = _count(tp, name="tp")
    denominator = numerator + _count(fp, name="fp")
    if denominator == 0:
        return None
    return numerator / denominator


def recall_exact(*, tp: int, fn: int) -> Optional[Fraction]:
    """The same value as `recall`, before any float rounding.

    S5-VERIF-034 requires cell-level recall to be compared "as rationals,
    before rounding, with tolerance 0". It is not pedantry: at the Design
    W boundary, `1.0 - 0.95` is 0.050000000000000044 in IEEE754, so the
    clause's "equality is on the PASSING side" silently becomes a FAIL for
    exactly the pairs that sit on the line. Comparing rationals makes the
    boundary mean what the clause says it means.
    """
    numerator = _count(tp, name="tp")
    denominator = numerator + _count(fn, name="fn")
    if denominator == 0:
        return None
    return Fraction(numerator, denominator)


def drop_exceeds(*, baseline_tp: int, baseline_fn: int, current_tp: int,
                 current_fn: int, max_drop: float) -> bool:
    """Is the recall drop strictly greater than `max_drop`?

    Exact throughout: the tolerance is read as a decimal string so that
    0.05 means one twentieth rather than the nearest double, and the
    comparison is `>` so the boundary passes (S1-CALIB-029 branch 5).
    """
    before = recall_exact(tp=baseline_tp, fn=baseline_fn)
    after = recall_exact(tp=current_tp, fn=current_fn)
    if before is None or after is None:
        raise DomainError(
            "drop_exceeds needs a measurable recall on both sides; an "
            "undefined recall is a coverage question, not a drop question")
    if isinstance(max_drop, bool) or not isinstance(max_drop, (int, float)):
        raise DomainError(f"max_drop must be a number, got {max_drop!r}")
    return (before - after) > Fraction(str(max_drop))


def miss_rate(*, tp: int, fn: int) -> Optional[float]:
    """1 - recall. `None` propagates: an unmeasured miss rate is not 0."""
    value = recall(tp=tp, fn=fn)
    return None if value is None else 1.0 - value


__all__ = ["recall", "recall_exact", "precision", "miss_rate",
           "drop_exceeds"]
