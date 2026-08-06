"""ThreatLevel — a DEFCON-style scale whose ordering cannot be misread.

TL1 is CRITICAL and TL5 is NORMAL. Every ordinary reading of `a > b` is
therefore backwards, and in 2026-08-02 that inversion went into the
calibration path and stayed there: the expression looked right.

So this type does not carry a warning; it removes the operators. The only
number you can get out is `severity()` = 6 - TL, which increases with
danger the way a reader expects, and `int()` / `float()` are closed off so
the raw value cannot escape into a bare comparison either.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from v3.kernel.errors import DomainError, OrderingForbiddenError

MIN_LEVEL = 1   # CRITICAL
MAX_LEVEL = 5   # NORMAL
_SEVERITY_PIVOT = MAX_LEVEL + 1   # severity() = 6 - tl

_ORDERING_HELP = (
    "ThreatLevel refuses ordering comparisons: the scale is inverted "
    "(TL1 = CRITICAL, TL5 = NORMAL), so `<` and `>` mean the opposite of "
    "how they read. Use severity() (= 6 - TL, larger is worse) or "
    "is_more_severe_than(other)."
)


@dataclass(frozen=True, slots=True)
class ThreatLevel:
    """One threat level, 1..5, with ordering deliberately unavailable.

    `.value` is the raw 1..5 number and exists for display and storage
    ONLY. Comparing two `.value`s (`a.value > b.value`) reintroduces
    calibration incident #2 in full — it bypasses every guard on this
    type and reads as correct. To compare, use `severity()`; to sort, use
    `key=ThreatLevel.severity_key`. The kernel discipline gate flags
    `.value` comparisons on threat-level-named variables.
    """

    value: int

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "ThreatLevel is final: a subclass could re-enable the ordering "
            "operators this type removes on purpose (calibration incident "
            "#2 — TL1 is CRITICAL, so `<` means the opposite of how it "
            "reads).")

    def __post_init__(self) -> None:
        # bool first: it is a subclass of int, and True would quietly
        # become TL1 = CRITICAL.
        if isinstance(self.value, bool) or not isinstance(self.value, int):
            raise DomainError(
                f"ThreatLevel takes an int in 1..5, got "
                f"{type(self.value).__name__} {self.value!r}")
        if not MIN_LEVEL <= self.value <= MAX_LEVEL:
            raise DomainError(
                f"ThreatLevel must be in 1..5 (TL1 = CRITICAL, "
                f"TL5 = NORMAL), got {self.value}")

    # ── the only ordering surface ──────────────────────────────────────
    def severity(self) -> int:
        """6 - TL. Larger is worse — safe to compare, sort and threshold."""
        return _SEVERITY_PIVOT - self.value

    def is_more_severe_than(self, other: "ThreatLevel") -> bool:
        if not isinstance(other, ThreatLevel):
            raise TypeError(
                f"is_more_severe_than expects a ThreatLevel, got "
                f"{type(other).__name__}")
        return self.severity() > other.severity()

    @staticmethod
    def severity_key(level: "ThreatLevel") -> int:
        """THE sort key: `sorted(levels, key=ThreatLevel.severity_key)`.

        Ascending order puts the least severe first; add `reverse=True`
        for worst-first. Sorting is legitimate — the type only refuses to
        guess the direction, because guessing wrong is the incident.
        """
        if not isinstance(level, ThreatLevel):
            raise TypeError(
                f"severity_key expects a ThreatLevel, got "
                f"{type(level).__name__}")
        return level.severity()

    @classmethod
    def worst_of(cls, levels: Iterable["ThreatLevel"]) -> "ThreatLevel":
        """The most severe level in a sequence (i.e. the lowest number)."""
        materialised = list(levels)
        if not materialised:
            raise ValueError("worst_of() needs at least one ThreatLevel")
        for level in materialised:
            if not isinstance(level, ThreatLevel):
                raise TypeError(
                    f"worst_of expects ThreatLevel values, got "
                    f"{type(level).__name__}")
        # max() on severity rather than min() on value: the direction is
        # stated once, here, instead of at every call site.
        return max(materialised, key=lambda level: level.severity())

    # ── refusals ───────────────────────────────────────────────────────
    def __lt__(self, other):  # noqa: D105
        raise OrderingForbiddenError(_ORDERING_HELP)

    def __le__(self, other):  # noqa: D105
        raise OrderingForbiddenError(_ORDERING_HELP)

    def __gt__(self, other):  # noqa: D105
        raise OrderingForbiddenError(_ORDERING_HELP)

    def __ge__(self, other):  # noqa: D105
        raise OrderingForbiddenError(_ORDERING_HELP)

    def __int__(self):  # noqa: D105
        raise OrderingForbiddenError(
            "int(ThreatLevel) is refused: the bare number is what made the "
            "inversion invisible. Use .value for display or .severity() to "
            "compare.")

    def __float__(self):  # noqa: D105
        raise OrderingForbiddenError(
            "float(ThreatLevel) is refused — use .severity() to compare.")

    def __str__(self) -> str:
        return f"TL{self.value}"


__all__ = ["ThreatLevel", "MIN_LEVEL", "MAX_LEVEL"]
