"""Rate limiting keyed by GROUP, not by adapter.

Design sheet §1-5. The key is a `rate_limit_group` the adapter declares,
because the real constraint is frequently shared: OpenSky's quota is
consumed by three sensors (`opensky`, `isr_hotspot`, `mil_support_air`)
against one upstream account, and a per-adapter limiter would let them
collectively exceed a limit each of them individually respects (D1 §4 K01).

The courtesy delays are the same mechanism with a small interval rather
than a separate concept — RIPE Stat 0.3s, GDELT 0.5s, GreyNoise 0.5s,
PeeringDB 10s, OONI 0.5s (D1 §4 K15). Treating them as one parameter of
one mechanism is what stops five slightly different sleep calls from
drifting apart, which is A-02's shape.

Pure: state in, state out. Nothing sleeps here — `run_due` uses the answer
to decide whether to plan work, and the composition root decides what to
do with the wait.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Optional

from v3.kernel.errors import DomainError

#: Groups with no declared interval are unthrottled. Stated explicitly so
#: "no entry" cannot be mistaken for "zero by accident".
NO_INTERVAL = 0.0


@dataclass(frozen=True, slots=True)
class LimiterState:
    """Last-request time per group. Immutable; `record` returns a successor."""

    last_request_at: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        entries = dict(self.last_request_at)
        for group, stamp in entries.items():
            if not isinstance(group, str) or not group:
                raise DomainError(
                    f"rate limit group must be a non-empty string, got "
                    f"{group!r}")
            if stamp <= 0:
                raise DomainError(
                    f"last_request_at for {group!r} must be a positive "
                    f"timestamp, got {stamp}")
        object.__setattr__(self, "last_request_at", MappingProxyType(entries))

    # Hashability ruling (WP-2.5 review): value-equal, deliberately NOT
    # hashable. `frozen=True` normally advertises hashability, but this
    # type holds a mapping, so the generated __hash__ raises deep inside
    # itself. Setting it to None turns that into an immediate, legible
    # "unhashable type" at the call site. These are values to compare, not
    # dictionary keys.
    __hash__ = None

    def record(self, group: str, at: float) -> "LimiterState":
        merged = dict(self.last_request_at)
        merged[group] = at
        return LimiterState(last_request_at=merged)

    def as_dict(self) -> dict:
        return dict(self.last_request_at)


def earliest_allowed(state: LimiterState, group: str,
                     min_interval_sec: float) -> Optional[float]:
    """When this group may next be requested, or None if unconstrained."""
    if min_interval_sec <= 0:
        return None
    last = state.last_request_at.get(group)
    return None if last is None else last + min_interval_sec


def is_allowed(state: LimiterState, group: str, min_interval_sec: float,
               now: float) -> bool:
    """Whether a request for this group may be made at `now`."""
    allowed_at = earliest_allowed(state, group, min_interval_sec)
    return allowed_at is None or now >= allowed_at


def wait_seconds(state: LimiterState, group: str, min_interval_sec: float,
                 now: float) -> float:
    """How long until this group is allowed. 0.0 when it already is."""
    allowed_at = earliest_allowed(state, group, min_interval_sec)
    if allowed_at is None:
        return 0.0
    return max(0.0, allowed_at - now)


__all__ = ["LimiterState", "earliest_allowed", "is_allowed", "wait_seconds",
           "NO_INTERVAL"]
