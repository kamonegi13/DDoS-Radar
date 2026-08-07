"""Escalation chains: a state machine whose state is an argument.

S1-SCORE-021/022 and S1-PIPE-019 describe something inherently stateful —
events accumulate, dedupe against a 300 s window, expire out of a
retention window, and decay in value as they age. The legacy system keeps
that state in the database and reads it mid-computation, which is half of
why a tick cannot be replayed (F-05, S5-VERIF-020).

Here the chain is a value. `advance()` takes the previous events and
returns the next ones; `chain_bonus()` reads them and returns a number.
Nothing is stored, so the same tick evaluated twice gives the same answer,
and a parity run can start from any stated chain.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from v3.kernel.errors import DomainError
from v3.scoring.inputs import SequenceEvent
from v3.scoring.thresholds import (SEQUENCE_CHAIN_TYPES,
                                   SEQUENCE_DECAY_FLOOR,
                                   SEQUENCE_DECAY_HORIZON_H,
                                   SEQUENCE_DEDUP_WINDOW_S,
                                   SEQUENCE_FULL_CHAIN, SEQUENCE_MIN_BONUS,
                                   SEQUENCE_MIN_CHAIN,
                                   TEMPORAL_COHERENCE_BONUS,
                                   TEMPORAL_COHERENCE_WINDOW_S)

NO_EVENTS = "NO_EVENTS"
FULL_CHAIN = "FULL_CHAIN_CONFIRMED"
PARTIAL_CHAIN = "PARTIAL_CHAIN"
INSUFFICIENT_CHAIN = "INSUFFICIENT_CHAIN"

FORMULA_REF = "v3.scoring.sequence@S1-SCORE-021+022"

_SECONDS_PER_HOUR = 3600.0


@dataclass(frozen=True, slots=True)
class ChainOutcome:
    """A chain's bonus and the shape that produced it."""

    bonus: float
    status: str
    links: tuple[str, ...]
    decay: float
    timespan_hours: float


def advance(previous: Iterable[SequenceEvent],
            arriving: Iterable[SequenceEvent], *, now: float,
            retention_sec: float,
            admitted_sensors: Optional[frozenset] = None
            ) -> tuple[SequenceEvent, ...]:
    """The state step: keep, gate, dedupe, admit, expire — in that order.

    S1-SCORE-022 / S1-PIPE-019. An arriving event is dropped when one of
    the same (country, type) already sits within the 300 s dedup window,
    so a sensor polling faster than the window cannot manufacture a chain
    out of one event. Retention is applied last so an event admitted this
    tick is never expired by the same tick.

    S1-PIPE-013 / 014: when `admitted_sensors` is supplied, an event is
    admitted only if EVERY sensor in its `justified_by` cleared gating.
    "Every" rather than "any" is S1-PIPE-014 — a composite event asserts
    that several things were seen together, so one suppressed constituent
    falsifies the whole claim.
    """
    if retention_sec <= 0:
        raise DomainError(
            f"retention_sec must be positive, got {retention_sec!r}")
    kept: list[SequenceEvent] = []
    for event in previous:
        if not isinstance(event, SequenceEvent):
            raise DomainError(
                f"previous chain must hold SequenceEvent values, got "
                f"{type(event).__name__}")
        kept.append(event)

    for event in arriving:
        if not isinstance(event, SequenceEvent):
            raise DomainError(
                f"arriving events must be SequenceEvent values, got "
                f"{type(event).__name__}")
        if admitted_sensors is not None and event.justified_by and \
                not all(sensor in admitted_sensors
                        for sensor in event.justified_by):
            continue
        duplicate = any(
            existing.country == event.country
            and existing.event_type == event.event_type
            and abs(event.occurred_at - existing.occurred_at)
            <= SEQUENCE_DEDUP_WINDOW_S
            for existing in kept)
        if not duplicate:
            kept.append(event)

    cutoff = now - retention_sec
    return tuple(event for event in kept if event.occurred_at >= cutoff)


def chain_bonus(events: Iterable[SequenceEvent], country: str, *, now: float,
                full_bonus: float, partial_bonus: float,
                retention_sec: float) -> ChainOutcome:
    """S1-SCORE-021: chain completeness x recency.

    Only the four chain link types count, and only the most recent of each
    — a repeated link is corroboration of the same step, not progress
    along the chain. Each link's weight decays linearly to a floor of 0.3
    over 24 h, and the bonus scales by the mean of those weights.

    A qualifying chain never decays to nothing: the effective path floors
    the result at 1 (`radar/scoring.py:226,230`). S1-SCORE-021 does not
    describe that floor, nor the three-link partial tier; both are ported
    from the implementation because parity is measured against it.
    """
    wanted = country.upper()
    cutoff = now - retention_sec
    live = [event for event in events
            if event.country == wanted and event.occurred_at >= cutoff]
    if not live:
        return ChainOutcome(bonus=0.0, status=NO_EVENTS, links=(),
                            decay=1.0, timespan_hours=0.0)

    present = {event.event_type for event in live}
    links = tuple(name for name in SEQUENCE_CHAIN_TYPES if name in present)

    timestamps = [event.occurred_at for event in live]
    timespan_hours = round(
        (max(timestamps) - min(timestamps)) / _SECONDS_PER_HOUR, 1)

    weights = []
    for link in links:
        most_recent = max(event.occurred_at for event in live
                          if event.event_type == link)
        age_hours = (now - most_recent) / _SECONDS_PER_HOUR
        weights.append(max(SEQUENCE_DECAY_FLOOR,
                           1.0 - age_hours / SEQUENCE_DECAY_HORIZON_H))
    decay = sum(weights) / len(weights) if weights else 1.0

    found = len(links)
    if found >= SEQUENCE_FULL_CHAIN:
        raw, status = full_bonus, FULL_CHAIN
    elif found >= SEQUENCE_MIN_CHAIN:
        raw, status = partial_bonus, PARTIAL_CHAIN
    else:
        return ChainOutcome(bonus=0.0, status=INSUFFICIENT_CHAIN, links=links,
                            decay=decay, timespan_hours=timespan_hours)

    # round() is Python's banker's rounding, matching the effective path.
    bonus = max(SEQUENCE_MIN_BONUS, float(round(raw * decay)))
    return ChainOutcome(bonus=bonus, status=status, links=links, decay=decay,
                        timespan_hours=timespan_hours)


def temporal_coherence_bonus(events: Iterable[SequenceEvent], *,
                             now: float, retention_sec: float) -> float:
    """S1-SCORE-028: two countries' events within 10 s are synchronised.

    Simultaneity across separate theatres is evidence of coordination that
    neither theatre shows on its own — the one place where looking outside
    a scenario is the point rather than contamination.
    """
    cutoff = now - retention_sec
    live = sorted((event for event in events if event.occurred_at >= cutoff),
                  key=lambda event: event.occurred_at)
    for index, event in enumerate(live):
        for other in live[index + 1:]:
            if other.occurred_at - event.occurred_at > \
                    TEMPORAL_COHERENCE_WINDOW_S:
                break
            if other.country != event.country:
                return TEMPORAL_COHERENCE_BONUS
    return 0.0


__all__ = ["advance", "chain_bonus", "temporal_coherence_bonus",
           "ChainOutcome", "FORMULA_REF", "NO_EVENTS", "FULL_CHAIN",
           "PARTIAL_CHAIN", "INSUFFICIENT_CHAIN"]
