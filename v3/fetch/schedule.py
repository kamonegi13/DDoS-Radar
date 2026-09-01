"""Due-ness, derived from a PERSISTED last run. Pure functions only.

Design sheet §1-3, repairing F-01. The legacy maintenance worker increments
a process-local `_cycle` every hour and assigns daily jobs by
`_cycle % 24 == N`. `_cycle` resets to zero on restart, so if the process
is restarted more often than every N hours, **offset N and above never
run at all**. Measured 2026-08-04: uptime 9h, `cycle=9`, offsets 10-12
unexecuted — and during the frequent restarts of 08-02/03 they had almost
certainly not run for days.

The repair is that due-ness is a function of `(now, last_run_at, cadence)`
where `last_run_at` comes from L1. A restart cannot shift a phase that is
not stored in the process.

The cadence is a kernel `Window`, never a bare number of seconds. F-06 was
a 30-"day" baseline that held 30 samples; the two quantities stay
distinguishable only when the type carries both.
"""
from __future__ import annotations

from typing import Optional

from v3.kernel import Window
from v3.kernel.errors import DomainError


def _validate(now: float, last_run_at: Optional[float],
              cadence: Window) -> None:
    if not isinstance(cadence, Window):
        raise DomainError(
            f"cadence must be a kernel Window, got {type(cadence).__name__}. "
            f"A bare number of seconds cannot say whether it means the poll "
            f"interval or the window it fills (F-06).")
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
    if last_run_at is not None and last_run_at <= 0:
        raise DomainError(
            f"last_run_at must be a positive timestamp or None (never run), "
            f"got {last_run_at}")


def is_due(now: float, last_run_at: Optional[float], cadence: Window) -> bool:
    """Whether this adapter should run at `now`.

    An adapter that has never run is due immediately — a fresh deploy
    must not wait a full cadence before its first observation, and
    `last_run_at is None` is the only honest way to say "never".

    A `last_run_at` in the future (clock skew, or a restored backup) is
    treated as not due rather than as an error: refusing to schedule is
    recoverable, and raising here would stop every other adapter in the
    cycle.
    """
    _validate(now, last_run_at, cadence)
    if last_run_at is None:
        return True
    return (now - last_run_at) >= cadence.cadence_sec


def next_run_at(now: float, last_run_at: Optional[float],
                cadence: Window) -> float:
    """When this adapter next becomes due. `now` if it already is."""
    _validate(now, last_run_at, cadence)
    if last_run_at is None:
        return now
    return max(now, last_run_at + cadence.cadence_sec)


def overdue_by(now: float, last_run_at: Optional[float],
               cadence: Window) -> float:
    """How long this adapter has been due. 0.0 when it is not.

    Reported rather than merely used: an adapter that is chronically
    overdue is a scheduling failure, and F-01 stayed invisible for months
    precisely because nothing measured lateness.
    """
    _validate(now, last_run_at, cadence)
    if last_run_at is None:
        return 0.0
    return max(0.0, (now - last_run_at) - cadence.cadence_sec)


def needs_refresh(now: float, stored_at: Optional[float],
                  refresh_after_sec: Optional[float]) -> bool:
    """Whether a request that declares `refresh_after_sec` should be sent.

    `radar/routes/core.py:739`, transcribed:
    `if not b_data or (current_time - b_data.get("time", 0) > 86400)`.
    Both arms matter and both are the sensitive direction — a request with
    no stored answer is sent, and the comparison is STRICTLY greater, so a
    snapshot exactly one day old is not yet stale.

    A request that declares nothing is always sent: this predicate can
    only ever WITHHOLD, so an adapter that never opts in cannot be quieted
    by a bug here.

    A `stored_at` in the future is treated as fresh, for the reason
    `is_due` treats a future `last_run_at` as not due: after a clock jump
    or a restored backup, refusing to send is recoverable and the stored
    answer is still the last real measurement.
    """
    if refresh_after_sec is None:
        return True
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
    if refresh_after_sec <= 0:
        raise DomainError(
            f"refresh_after_sec must be positive, got {refresh_after_sec}: "
            f"zero would mean 'never refresh'")
    if stored_at is None:
        return True
    return (now - float(stored_at)) > float(refresh_after_sec)


def refresh_due_at(stored_at: Optional[float],
                   refresh_after_sec: Optional[float]) -> Optional[float]:
    """When a withheld request becomes sendable again. For disclosure."""
    if stored_at is None or refresh_after_sec is None:
        return None
    return float(stored_at) + float(refresh_after_sec)


__all__ = ["is_due", "next_run_at", "overdue_by", "needs_refresh",
           "refresh_due_at"]
