"""The circuit breaker, as a pure state machine whose state is a value.

Design sheet §1-5: the breaker applies to every fetch path with no
exceptions, and its judgement happens exactly once per cycle. Both halves
matter and both come from measured defects.

B-01: `bg_observer` runs its own daemon thread and never calls
`cb_should_skip` / `cb_record_*`, so RSS failures there are never
suppressed — while its docstring claims breaker integration. The repair is
not to add the call; it is that `run_due` is the only thing that produces
work, and it consults the breaker before producing any.

S4-NF-003: the judgement must be made once per cycle, because asking twice
consumes two HALF_OPEN probe slots and a breaker that is meant to allow
one trial request allows two.

Making the state a value (rather than an attribute on a sensor object)
also survives restarts, which the legacy in-memory breaker did not: every
deploy reset every breaker to CLOSED and re-hammered whatever was down.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from v3.kernel.errors import DomainError
from v3.fetch.policy import (CB_FAILURE_THRESHOLD, CB_INITIAL_DELAY_SEC,
                             CB_MAX_DELAY_SEC)

CLOSED = "CLOSED"
OPEN = "OPEN"
HALF_OPEN = "HALF_OPEN"
_STATES = frozenset({CLOSED, OPEN, HALF_OPEN})

SUCCESS = "success"
FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class BreakerState:
    """One adapter's breaker. Immutable; `step` returns the successor."""

    state: str = CLOSED
    fail_count: int = 0
    opened_at: Optional[float] = None
    recovery_delay_sec: float = CB_INITIAL_DELAY_SEC

    def __post_init__(self) -> None:
        if self.state not in _STATES:
            raise DomainError(
                f"unknown breaker state {self.state!r}; expected one of "
                f"{sorted(_STATES)}")
        if self.fail_count < 0:
            raise DomainError(
                f"fail_count cannot be negative, got {self.fail_count}")
        if self.recovery_delay_sec <= 0:
            raise DomainError(
                f"recovery_delay_sec must be positive, got "
                f"{self.recovery_delay_sec}")
        if self.state == OPEN and self.opened_at is None:
            raise DomainError(
                "an OPEN breaker must record when it opened, or nothing can "
                "decide when to probe")

    def as_dict(self) -> dict:
        return {"state": self.state, "fail_count": self.fail_count,
                "opened_at": self.opened_at,
                "recovery_delay_sec": self.recovery_delay_sec}


def effective_state(state: BreakerState, now: float) -> BreakerState:
    """The state as of `now`, promoting OPEN to HALF_OPEN when due.

    Called ONCE per cycle by the runner (S4-NF-003). The promotion is
    expressed here rather than inside `should_skip` so that asking "may I
    fetch?" cannot itself consume a probe slot — that coupling is what
    makes a double call dangerous in the legacy code.
    """
    if state.state != OPEN:
        return state
    if state.opened_at is None:
        return state
    if now - state.opened_at >= state.recovery_delay_sec:
        return BreakerState(state=HALF_OPEN, fail_count=state.fail_count,
                            opened_at=state.opened_at,
                            recovery_delay_sec=state.recovery_delay_sec)
    return state


def should_skip(state: BreakerState) -> bool:
    """True while the breaker is holding the door shut.

    Takes an ALREADY-effective state (see `effective_state`), so it makes
    no time-based decision of its own.
    """
    return state.state == OPEN


def step(state: BreakerState, outcome: str, now: float) -> BreakerState:
    """Fold one fetch outcome into the breaker."""
    if outcome not in (SUCCESS, FAILURE):
        raise DomainError(
            f"breaker outcome must be {SUCCESS!r} or {FAILURE!r}, got "
            f"{outcome!r}")

    if outcome == SUCCESS:
        # Any success closes the breaker and resets the delay ladder —
        # including a success in CLOSED after intermittent failures, so a
        # flapping upstream does not accumulate its way to OPEN.
        return BreakerState(state=CLOSED, fail_count=0, opened_at=None,
                            recovery_delay_sec=CB_INITIAL_DELAY_SEC)

    if state.state == HALF_OPEN:
        # The probe failed: back to OPEN with the delay doubled, capped.
        return BreakerState(
            state=OPEN, fail_count=state.fail_count + 1, opened_at=now,
            recovery_delay_sec=min(state.recovery_delay_sec * 2,
                                   CB_MAX_DELAY_SEC))

    failures = state.fail_count + 1
    if failures >= CB_FAILURE_THRESHOLD:
        return BreakerState(state=OPEN, fail_count=failures, opened_at=now,
                            recovery_delay_sec=state.recovery_delay_sec)
    return BreakerState(state=CLOSED, fail_count=failures, opened_at=None,
                        recovery_delay_sec=state.recovery_delay_sec)


__all__ = ["BreakerState", "effective_state", "should_skip", "step",
           "CLOSED", "OPEN", "HALF_OPEN", "SUCCESS", "FAILURE"]
