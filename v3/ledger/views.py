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
from v3.kernel.window import DAY_SEC

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


def observed_span(store, scenario_id: str, *,
                  now: Optional[float] = None) -> dict:
    """How long this scenario has been observed at all.

    Read off the stream rather than kept as a per-scenario counter: a
    counter is state, and state is what O-16 removes. L3's
    `calibration_pending` guard asks this question — "has the tool watched
    long enough for its own thresholds to mean anything here" — and the
    answer has to be a projection so that a restart cannot reset it.
    """
    ts = _now(now)
    rows = series_between(store, scenario_id, start=0.0, end=ts)
    if not rows:
        return {"first_observed_at": None, "last_observed_at": None,
                "span_sec": 0.0, "samples": 0}
    first = rows[0]["observed_at"]
    last = rows[-1]["observed_at"]
    return {"first_observed_at": first, "last_observed_at": last,
            "span_sec": max(0.0, ts - first), "samples": len(rows)}


def severity_window_pair(store, scenario_id: str, *, window: Window,
                         now: Optional[float] = None) -> dict:
    """Mean SEVERITY over [now-W, now) and [now-2W, now-W), plus the delta.

    S1-CONC-016's window seam, as a query over the one TL stream. The
    conclusion layer classifies the delta; the arithmetic that turns rows
    into two means belongs with the rows.

    Severity is `6 - TL` (P6 O-15), not the `5 - TL` the legacy trend
    module used privately. The delta is identical — a constant shift
    cancels in a difference — but the reported means move by exactly 1.0,
    which is registered as an expected difference rather than left as a
    second severity scale in a project that has inverted this one twice.

    Half-open at both seams, matching production: a row exactly at
    `now - W` belongs to the current period, and a row at `now` is not yet
    in the window.
    """
    if not isinstance(window, Window):
        raise TypeError(
            f"severity_window_pair needs a kernel Window, got "
            f"{type(window).__name__}: a bare duration cannot say what "
            f"cadence it assumes (F-06)")
    ts = _now(now)
    # The DECLARED span, not `effective_seconds`. A trend window is a
    # wall-clock period, not a sample budget: `effective_seconds` floors
    # to a whole number of cadence steps, which at a 7000s cadence turns
    # a 1-day window into 84000s. A shorter window holds fewer rows, is
    # likelier to miss MIN_SAMPLES, and answers INSUFFICIENT — the
    # insensitive direction. `Window` is still required as the argument
    # type so a bare duration cannot be passed (F-06); it is the cadence
    # DECLARATION that matters here, not the derived sample count.
    span = window.declared_days * DAY_SEC
    current_start = ts - span
    rows = series_between(store, scenario_id, start=ts - 2 * span, end=ts)

    current: list[float] = []
    previous: list[float] = []
    for row in rows:
        level = row["threat_level"]
        if level is None or row["observed_at"] >= ts:
            continue
        target = current if row["observed_at"] >= current_start else previous
        target.append(float(level.severity()))

    current_mean = sum(current) / len(current) if current else None
    previous_mean = sum(previous) / len(previous) if previous else None
    delta = (None if current_mean is None or previous_mean is None
             else current_mean - previous_mean)
    return {"current_mean_severity": current_mean, "current_n": len(current),
            "previous_mean_severity": previous_mean,
            "previous_n": len(previous), "delta_severity": delta,
            "window_days": window.declared_days,
            "window_seconds": span}


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


__all__ = ["series_between", "trend_over", "observed_span",
           "severity_window_pair", "null_zone_spans", "chronic_null_zone",
           "transitions_only", "DIRECTION_WORSENING", "DIRECTION_IMPROVING",
           "DIRECTION_FLAT", "DIRECTION_INSUFFICIENT"]
