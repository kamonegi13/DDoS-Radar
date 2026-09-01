"""Window — a retention window that cannot be confused with a sample count.

F-06: telegram declared a 30-day baseline and kept 30 *entries*. At a
900 s cadence that is 7.5 hours. Both quantities are the integer 30, so
nothing in the language, the review or the (false) docstring objected.

The cadence is therefore a required argument, never an assumption. The
sample count is derived, never supplied. And because the window is
immutable, a cap computed once at import cannot outlive a cadence change —
that combination is what the L5 window verifier was later built to detect,
and here it simply cannot arise.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from v3.kernel.errors import DomainError

DAY_SEC = 86400.0


def _positive_number(value, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(
            f"Window {name} must be a number, got "
            f"{type(value).__name__} {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric) or numeric <= 0:
        raise DomainError(f"Window {name} must be positive, got {value!r}")
    return numeric


@dataclass(frozen=True, slots=True, kw_only=True)
class Window:
    """A time window plus the cadence that fills it.

    Keyword-only on purpose: `Window(30, 900)` cannot be written, so the
    two numbers can never be swapped or misread positionally.
    """

    declared_days: float
    cadence_sec: float

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Window is final: a subclass could reintroduce a constructor "
            "that takes a bare sample count (defect F-06).")

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "declared_days",
            _positive_number(self.declared_days, name="declared_days"))
        object.__setattr__(
            self, "cadence_sec",
            _positive_number(self.cadence_sec, name="cadence_sec"))
        if self.cadence_sec > self.declared_days * DAY_SEC:
            raise DomainError(
                f"a {self.declared_days:g}-day window polled every "
                f"{self.cadence_sec:g}s cannot hold at least one sample; "
                f"the cadence is longer than the window")

    # ── constructors ───────────────────────────────────────────────────
    @classmethod
    def from_days(cls, days, *, cadence_sec) -> "Window":
        """The blessed constructor: a duration and the cadence filling it."""
        return cls(declared_days=days, cadence_sec=cadence_sec)

    @classmethod
    def from_samples(cls, samples, *args, **kwargs):
        """Always raises. A sample count alone does not describe a window."""
        raise DomainError(
            f"Window.from_samples({samples!r}) does not exist: a sample "
            f"count describes a window only together with the cadence that "
            f"produced it. This is defect F-06 — telegram kept 30 samples "
            f"believing it held 30 days, which at a 900s cadence was 7.5 "
            f"hours. Use Window.from_days(days, cadence_sec=...) and read "
            f".effective_samples.")

    # ── derived quantities ─────────────────────────────────────────────
    @property
    def effective_samples(self) -> int:
        """How many samples the window holds.

        Computed in one step from the total span. Deriving a per-day count
        first and multiplying floors twice: at a 5-day cadence that gave
        "1 per day x 30 days = 30 samples" for a window that really holds
        6 — the F-06 shape one level up.
        """
        return max(1, int(self.declared_days * DAY_SEC / self.cadence_sec))

    @property
    def effective_seconds(self) -> float:
        """The wall-clock span those samples actually cover."""
        return self.effective_samples * self.cadence_sec

    @property
    def effective_days(self) -> float:
        return self.effective_seconds / DAY_SEC

    # ── derivation ─────────────────────────────────────────────────────
    def with_cadence(self, cadence_sec) -> "Window":
        """A new Window at a different cadence, same declared duration."""
        return Window(declared_days=self.declared_days,
                      cadence_sec=cadence_sec)

    def __str__(self) -> str:
        return (f"{self.declared_days:g}d @ {self.cadence_sec:g}s "
                f"({self.effective_samples} samples)")


__all__ = ["Window", "DAY_SEC"]
