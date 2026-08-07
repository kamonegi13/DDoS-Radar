"""Derived views over the one TL stream (P6 O-16).

The current system grew four TL lanes and then three compensating
mechanisms, each fixing damage caused by the previous one: thinning broke
chronic detection, so a continuity ledger was added; that missed flapping,
so a duty-cycle correction was added. O-16 ends the chain by keeping one
unthinned stream and deriving everything else.

So every function here is a pure query. None of them writes, none of them
caches, and none of them needs a state machine — which is the property
that stops the compensation chain from starting again. A test asserts this
module holds no dict or list at module scope.
"""
from __future__ import annotations

import time
from typing import Optional

from v3.kernel import Window

DIRECTION_WORSENING = "worsening"
DIRECTION_IMPROVING = "improving"
DIRECTION_FLAT = "flat"
DIRECTION_INSUFFICIENT = "insufficient"


def _now(value: Optional[float]) -> float:
    return time.time() if value is None else value


def series_between(store, scenario_id: str, *, start: float,
                   end: float) -> list[dict]:
    """The raw stream slice. Every other view is built from this shape."""
    return store.tl_between(scenario_id, start, end)


def trend_over(store, scenario_id: str, *, window: Window,
               now: Optional[float] = None) -> dict:
    """Direction of travel across `window`, measured in SEVERITY.

    Severity, never TL: the scale is inverted, so a rising TL number is an
    improving situation. Comparing severities is the only reading that
    matches how a human describes the trend (calibration incident #2).
    """
    if not isinstance(window, Window):
        raise TypeError(
            f"trend_over needs a kernel Window, got {type(window).__name__}: "
            f"a bare duration cannot say what cadence it assumes (F-06)")
    ts = _now(now)
    rows = [row for row in
            series_between(store, scenario_id,
                           start=ts - window.effective_seconds, end=ts)
            if row["threat_level"] is not None]
    if not rows:
        return {"direction": DIRECTION_INSUFFICIENT, "samples": 0,
                "first_severity": None, "last_severity": None,
                "window_days": window.declared_days}

    first = rows[0]["threat_level"].severity()
    last = rows[-1]["threat_level"].severity()
    if last > first:
        direction = DIRECTION_WORSENING
    elif last < first:
        direction = DIRECTION_IMPROVING
    else:
        direction = DIRECTION_FLAT
    return {"direction": direction, "samples": len(rows),
            "first_severity": first, "last_severity": last,
            "window_days": window.declared_days}


def null_zone_spans(store, scenario_id: str, *,
                    since: Optional[float] = None,
                    now: Optional[float] = None) -> list[dict]:
    """Contiguous runs where no conclusion was available.

    Derived by scanning the stream, not maintained as a run-state machine
    — that machine is exactly what O-16 removes. `ongoing` marks a span
    still open at the end of the stream, which is the signal NP5+8 cares
    about (a transient null zone is fine; a permanent one is a design
    failure).
    """
    ts = _now(now)
    rows = series_between(store, scenario_id,
                          start=0.0 if since is None else since, end=ts)
    spans: list[dict] = []
    current: Optional[dict] = None
    for row in rows:
        if row["threat_level"] is None:
            if current is None:
                current = {"start": row["observed_at"],
                           "end": row["observed_at"], "ticks": 1}
            else:
                current["end"] = row["observed_at"]
                current["ticks"] += 1
        elif current is not None:
            # The outage ends when a conclusion returns, not at the last
            # null tick. Measuring only the null ticks understates the
            # span, and understating it is the direction that hides a
            # chronic null zone (NP5+8).
            spans.append({**current, "end": row["observed_at"],
                          "ongoing": False,
                          "length_sec": row["observed_at"] - current["start"]})
            current = None
    if current is not None:
        # Still open: it has lasted until now, not until its last tick.
        spans.append({**current, "end": ts, "ongoing": True,
                      "length_sec": max(0.0, ts - current["start"])})
    return spans


def chronic_null_zone(store, scenario_id: str, *, threshold_sec: float,
                      now: Optional[float] = None) -> dict:
    """Whether the null zone has become chronic (NP5+8).

    A transient inability to conclude is acceptable and expected; a
    permanent one is a design failure the tool must declare about itself.
    """
    spans = null_zone_spans(store, scenario_id, now=now)
    longest = max((span["length_sec"] for span in spans), default=0.0)
    return {"is_chronic": longest >= threshold_sec,
            "longest_span_sec": longest, "span_count": len(spans),
            "threshold_sec": threshold_sec,
            "ongoing": any(span["ongoing"] for span in spans)}


def transitions_only(store, scenario_id: str, *,
                     since: Optional[float] = None,
                     now: Optional[float] = None) -> list[dict]:
    """The thinned history the old lanes stored, projected from the stream.

    O-16's parity requirement: the change-gated view must be derivable, so
    that keeping it as a separate written lane is unnecessary. A return to
    a previous level is a transition (S5-VERIF-017's A->B->A rule), and
    the null zone counts as a state of its own.
    """
    ts = _now(now)
    rows = series_between(store, scenario_id,
                          start=0.0 if since is None else since, end=ts)
    transitions: list[dict] = []
    previous_marker: object = object()
    for row in rows:
        level = row["threat_level"]
        marker = None if level is None else level.value
        if marker != previous_marker:
            transitions.append(row)
            previous_marker = marker
    return transitions


__all__ = ["series_between", "trend_over", "null_zone_spans",
           "chronic_null_zone", "transitions_only", "DIRECTION_WORSENING",
           "DIRECTION_IMPROVING", "DIRECTION_FLAT", "DIRECTION_INSUFFICIENT"]
