"""Evidence — an observation whose payload is behind a freshness check.

B-03: ground_osint received observations carrying a STALE marker and used
them anyway. The field was informational; reading it was optional; the
consuming code simply did not. That is an omission, and omissions do not
show up in review as anything at all.

Here the payload is not an attribute. `fresh()` is the only way to it and
it raises when the observation is past its horizon, so using stale data is
no longer something you can fail to prevent — it is something you would
have to write on purpose, via `assume_fresh(reason=...)`, which is
greppable and demands a justification. Replay legitimately needs that
hatch (S5 evaluates freshness at the replayed instant); nothing else
should use it.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from v3.kernel.errors import DomainError, StaleEvidenceError


def _positive_number(value, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(
            f"Evidence {name} must be a number, got "
            f"{type(value).__name__} {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric) or numeric <= 0:
        raise DomainError(f"Evidence {name} must be positive, got {value!r}")
    return numeric


@dataclass(frozen=True, slots=True)
class Evidence:
    """One observation, reachable only through a freshness check."""

    observed_at: float
    freshness_horizon_sec: float
    source: str
    _payload: Any = field(default=None, repr=False, compare=False)

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Evidence is final: a subclass could expose the payload without "
            "the freshness check (defect B-03).")

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "observed_at",
            _positive_number(self.observed_at, name="observed_at"))
        object.__setattr__(
            self, "freshness_horizon_sec",
            _positive_number(self.freshness_horizon_sec,
                             name="freshness_horizon_sec"))
        if not isinstance(self.source, str) or not self.source.strip():
            raise DomainError(
                f"Evidence source must name where the observation came "
                f"from, got {self.source!r}")
        object.__setattr__(self, "source", self.source.strip())

    @classmethod
    def observe(cls, payload: Any, *, observed_at: float,
                freshness_horizon_sec: float, source: str) -> "Evidence":
        """Record an observation together with how long it stays usable."""
        return cls(observed_at=observed_at,
                   freshness_horizon_sec=freshness_horizon_sec,
                   source=source, _payload=payload)

    # ── freshness ──────────────────────────────────────────────────────
    def age_seconds(self, now: Optional[float] = None) -> float:
        return (time.time() if now is None else now) - self.observed_at

    def is_fresh(self, now: Optional[float] = None) -> bool:
        """Answer the question without handing over the payload."""
        age = self.age_seconds(now)
        return 0 <= age <= self.freshness_horizon_sec

    def fresh(self, now: Optional[float] = None) -> Any:
        """The payload — if and only if it is still fresh."""
        age = self.age_seconds(now)
        if age < 0:
            raise StaleEvidenceError(
                f"{self.source} observation is {abs(age):.1f}s in the "
                f"future; refusing to treat clock skew as maximum freshness")
        if age > self.freshness_horizon_sec:
            raise StaleEvidenceError(
                f"{self.source} observation is {age:.0f}s old, past its "
                f"{self.freshness_horizon_sec:.0f}s freshness horizon "
                f"(that is {self.freshness_horizon_sec / 3600:.1f}h). This "
                f"is defect B-03: a stale observation used as if current.")
        return self._payload

    def assume_fresh(self, *, reason: str) -> Any:
        """Deliberate escape hatch. Requires a written justification."""
        if not isinstance(reason, str) or not reason.strip():
            raise DomainError(
                "assume_fresh() requires a reason: bypassing the freshness "
                "check is exactly defect B-03, so it must be justified at "
                "the call site and visible in review")
        return self._payload

    def __str__(self) -> str:
        return (f"Evidence<{self.source} @ {self.observed_at:.0f}, "
                f"horizon {self.freshness_horizon_sec:.0f}s>")


__all__ = ["Evidence"]
