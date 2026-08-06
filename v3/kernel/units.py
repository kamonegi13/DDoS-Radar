"""Ratio and Percentage — two units the language keeps apart.

F-08 was `jam_ratio >= GPS_JAM_THRESHOLD` where the left side was a
fraction in [0,1] and the right side was 3.0 on a percent scale. Both are
floats, so nothing objected, and the sensor detected nothing for its
entire life while reporting healthy.

Here the two scales are different types. Cross-unit operations raise
rather than returning a plausible-looking answer, comparison against a
bare float raises too (that is the same mistake with the unit erased),
and the only bridge is an explicit conversion a reviewer can grep for.
Same-unit comparison stays ordinary — comparing two ratios is what a
threshold check legitimately does.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import ClassVar

from v3.kernel.errors import DomainError, UnitMismatchError


def _validate(value, *, unit: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(
            f"{unit} takes a real number, got "
            f"{type(value).__name__} {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric):
        raise DomainError(f"{unit} cannot be {value!r}")
    if not low <= numeric <= high:
        raise DomainError(
            f"{unit} must be within [{low:g}, {high:g}], got {numeric:g}"
            + (f" — {numeric:g} looks like a percentage; "
               f"use Percentage({numeric:g}).to_ratio()"
               if unit == "Ratio" and numeric > 1 else ""))
    return numeric


class _Unit:
    """Shared operator discipline for the unit types.

    Not an inheritance escape hatch: it defines refusals only. Subclasses
    add no behaviour that could relax them, and both concrete types are
    frozen slotted dataclasses.
    """

    # Without this, every "frozen" unit instance silently carries a
    # __dict__ and object.__setattr__ smuggling succeeds.
    __slots__ = ()

    _UNIT_NAME: ClassVar[str] = "unit"

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.__module__ != _Unit.__module__:
            raise TypeError(
                f"{cls.__name__}: the kernel unit types are final. A "
                f"subclass could re-enable cross-unit comparison, which is "
                f"defect F-08.")

    def _require_same_unit(self, other, operation: str):
        if type(other) is type(self):
            return other
        raise UnitMismatchError(
            f"cannot {operation} {type(self).__name__} and "
            f"{type(other).__name__}: these are different units. "
            f"Convert explicitly (Ratio.to_percentage() / "
            f"Percentage.to_ratio()) so the conversion is visible in review."
            if isinstance(other, _Unit) else
            f"cannot {operation} {type(self).__name__} with a bare "
            f"{type(other).__name__}: a raw number carries no unit, which "
            f"is exactly how F-08 compared a ratio against a percentage. "
            f"Wrap it: {type(self).__name__}({other!r}).")

    def __eq__(self, other):
        self._require_same_unit(other, "compare")
        return self.value == other.value

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.value < self._require_same_unit(other, "compare").value

    def __le__(self, other):
        return self.value <= self._require_same_unit(other, "compare").value

    def __gt__(self, other):
        return self.value > self._require_same_unit(other, "compare").value

    def __ge__(self, other):
        return self.value >= self._require_same_unit(other, "compare").value

    def __add__(self, other):
        return type(self)(
            self.value + self._require_same_unit(other, "add").value)

    def __sub__(self, other):
        return type(self)(
            self.value - self._require_same_unit(other, "subtract").value)

    def __radd__(self, other):
        raise UnitMismatchError(self._reflected_message(other, "add"))

    def __rsub__(self, other):
        raise UnitMismatchError(self._reflected_message(other, "subtract"))

    def __rtruediv__(self, other):
        raise UnitMismatchError(self._reflected_message(other, "divide"))

    def _reflected_message(self, other, operation: str) -> str:
        # Operand order matters in the message: the caller wrote
        # `0.5 + ratio`, and being told about `Ratio + float` sends them
        # looking at the wrong line.
        return (f"cannot {operation} a bare {type(other).__name__} and a "
                f"{type(self).__name__}: a raw number carries no unit, "
                f"which is how F-08 compared a ratio against a percentage. "
                f"Wrap it: {type(self).__name__}({other!r}).")

    def __mul__(self, other):
        raise UnitMismatchError(
            f"multiplying a {type(self).__name__} is refused: the result's "
            f"unit is ambiguous. Do the arithmetic on plain numbers and "
            f"wrap the result once, where the unit is decided.")

    __rmul__ = __mul__

    def __truediv__(self, other):
        raise UnitMismatchError(
            f"dividing a {type(self).__name__} is refused: the result's "
            f"unit is ambiguous. Compute the quotient from plain numbers "
            f"and wrap it once.")

    def __hash__(self):
        return hash((type(self).__name__, self.value))


@dataclass(frozen=True, slots=True, eq=False)
class Ratio(_Unit):
    """A fraction in [0, 1]."""

    value: float
    _UNIT_NAME: ClassVar[str] = "ratio"

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "value", _validate(self.value, unit="Ratio",
                                     low=0.0, high=1.0))

    def to_percentage(self) -> "Percentage":
        return Percentage(self.value * 100.0)

    def __str__(self) -> str:
        return f"{self.value:g} (ratio)"


@dataclass(frozen=True, slots=True, eq=False)
class Percentage(_Unit):
    """A percentage in [0, 100]."""

    value: float
    _UNIT_NAME: ClassVar[str] = "percent"

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "value", _validate(self.value, unit="Percentage",
                                     low=0.0, high=100.0))

    def to_ratio(self) -> Ratio:
        return Ratio(self.value / 100.0)

    def __str__(self) -> str:
        return f"{self.value:g}%"


UNIT_TYPES: dict[str, type] = {"ratio": Ratio, "percent": Percentage}

__all__ = ["Ratio", "Percentage", "UNIT_TYPES"]
