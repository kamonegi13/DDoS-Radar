"""Per-adapter runtime state, as a value that outlives the process.

Two things live here and both used to be process-local, which is the same
defect twice:

  * `last_run_at` — F-01. Scheduling ran off an in-process counter that
    reset to zero on every restart, so a deploy cadence faster than the
    job cadence meant the later jobs never ran at all.
  * the breaker — the legacy breaker is an attribute on a sensor object,
    so every restart reset every breaker to CLOSED and re-hammered
    whatever was already failing.

Persisting them is not an optimisation; it is the difference between a
schedule and a coincidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from v3.fetch.breaker import BreakerState
from v3.kernel.errors import DomainError


@dataclass(frozen=True, slots=True)
class AdapterState:
    """One adapter's persisted state. Immutable; steps return successors."""

    adapter_id: str
    last_run_at: Optional[float] = None
    last_outcome: Optional[str] = None
    breaker: BreakerState = field(default_factory=BreakerState)

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, str) or not self.adapter_id:
            raise DomainError(
                f"AdapterState needs an adapter id, got {self.adapter_id!r}")
        if self.last_run_at is not None and self.last_run_at <= 0:
            raise DomainError(
                f"last_run_at must be a positive timestamp or None (never "
                f"run), got {self.last_run_at}")
        if not isinstance(self.breaker, BreakerState):
            raise DomainError(
                f"breaker must be a BreakerState, got "
                f"{type(self.breaker).__name__}")

    @property
    def has_run(self) -> bool:
        return self.last_run_at is not None

    def with_run(self, *, at: float, outcome: str,
                 breaker: BreakerState) -> "AdapterState":
        return AdapterState(adapter_id=self.adapter_id, last_run_at=at,
                            last_outcome=outcome, breaker=breaker)

    def with_breaker(self, breaker: BreakerState) -> "AdapterState":
        return AdapterState(adapter_id=self.adapter_id,
                            last_run_at=self.last_run_at,
                            last_outcome=self.last_outcome, breaker=breaker)

    def as_dict(self) -> dict:
        return {"adapter_id": self.adapter_id, "last_run_at": self.last_run_at,
                "last_outcome": self.last_outcome, **self.breaker.as_dict()}


__all__ = ["AdapterState"]
