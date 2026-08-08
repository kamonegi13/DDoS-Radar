"""O-2: direction of travel. A view over the TL stream, not a machine.

P6 O-15 gives the trend to exactly one owner — this conclusion — and does
not port S1-SCORE-036's TL-transition state machine at all. P6 O-16 then
says the answer must be a query over L1's unthinned stream rather than a
lane of its own. So this module holds no state, keeps no run, caches
nothing, and reads through `v3.ledger.views.severity_window_pair`.

Severity is `6 - TL` here as everywhere (O-15). The legacy trend module
used a private `5 - TL`; the delta is unchanged by a constant shift, so
the classification is identical, but the reported means move by 1.0. In a
project that has inverted this scale twice, one scale with a registered
difference beats two scales with none.
"""
from __future__ import annotations


from v3.conclusions import availability as A
from v3.conclusions import conclusion as C
from v3.conclusions import thresholds as T
from v3.conclusions import vocabulary as V
from v3.conclusions.context import ScenarioContext
from v3.kernel import Provenance, Window

FORMULA_REF = "v3.conclusions.trend.derive@S1-CONC-015..018"

ESCALATING = "ESCALATING"
RISING = "RISING"
STABLE = "STABLE"
COOLING = "COOLING"
DEEPER_DECAY = "DEEPER_DECAY"
INSUFFICIENT = "INSUFFICIENT_DATA"

SHORT_TERM = "short_term"
MEDIUM_TERM = "medium_term"
LONG_TERM = "long_term"

# S1-CONC-015 fixes both the windows and their order; the packed state is
# positional, so a reordering here silently relabels stored history.
WINDOW_DAYS: tuple[tuple[str, float], ...] = (
    (SHORT_TERM, 1.0), (MEDIUM_TERM, 7.0), (LONG_TERM, 30.0))

# The states RISING and ESCALATING are the ones an analyst acts on.
_ALERTING_STATES = frozenset({RISING, ESCALATING})


def classify(delta: float) -> str:
    """S1-CONC-017, evaluated in the fixed order, boundaries inclusive."""
    if delta >= T.TREND_ESCALATE_DELTA:
        return ESCALATING
    if delta >= T.TREND_RISING_DELTA:
        return RISING
    if delta <= -T.TREND_ESCALATE_DELTA:
        return DEEPER_DECAY
    if delta <= -T.TREND_RISING_DELTA:
        return COOLING
    return STABLE


def pack(states: dict) -> str:
    """`short_term=X;medium_term=Y;long_term=Z`, order from WINDOW_DAYS."""
    return ";".join(f"{label}={states[label]}" for label, _ in WINDOW_DAYS)


def confidence_for(sample_counts: dict, *, any_unavailable: bool) -> float:
    """S1-CONC-018: density per window, capped, then penalised once."""
    total = 0.0
    for counts in sample_counts.values():
        n = min(counts["current_n"], counts["previous_n"])
        if n >= T.TREND_MIN_SAMPLES:
            total += min(T.TREND_CONFIDENCE_PER_WINDOW_CAP,
                         T.TREND_CONFIDENCE_PER_WINDOW_BASE
                         + n * T.TREND_CONFIDENCE_PER_SAMPLE)
    total = min(T.TREND_CONFIDENCE_CEILING, total)
    if any_unavailable:
        total = max(0.0, total - T.TREND_PARTIAL_PENALTY)
    return round(total, 3)


def evaluate_windows(store, scenario_id: str, *, now: float,
                     cadence_sec: float) -> dict:
    """The three windows, each a `severity_window_pair` read.

    `cadence_sec` is required rather than assumed: `Window` refuses to be
    built without it (F-06 — thirty samples is not thirty days), and the
    number of samples a window holds is what MIN_SAMPLES is compared
    against.
    """
    from v3.ledger import views

    windows: dict = {}
    for label, days in WINDOW_DAYS:
        pair = views.severity_window_pair(
            store, scenario_id,
            window=Window.from_days(days, cadence_sec=cadence_sec), now=now)
        enough = (pair["current_n"] >= T.TREND_MIN_SAMPLES
                  and pair["previous_n"] >= T.TREND_MIN_SAMPLES)
        windows[label] = {
            "state": classify(pair["delta_severity"]) if enough else None,
            "current_n": pair["current_n"],
            "previous_n": pair["previous_n"],
            "current_mean_severity": (
                None if pair["current_mean_severity"] is None
                else round(pair["current_mean_severity"], 3)),
            "previous_mean_severity": (
                None if pair["previous_mean_severity"] is None
                else round(pair["previous_mean_severity"], 3)),
            "delta_severity": (None if pair["delta_severity"] is None
                               else round(pair["delta_severity"], 3)),
            "window_days": days,
        }
    return windows


def derive(context: ScenarioContext, *, store,
           cadence_sec: float) -> C.Conclusion:
    """The TREND conclusion. One row, three windows packed into its state.

    S1-CONC-018: one usable window is enough to publish. All three
    unusable is the only path to unavailable, and it goes through the
    guard chain like every other — the reason is `insufficient_data` and
    the guard that produced it is named on the row.
    """
    windows = evaluate_windows(store, context.scenario_id, now=context.now,
                               cadence_sec=cadence_sec)
    states = {label: (windows[label]["state"] or INSUFFICIENT)
              for label, _ in WINDOW_DAYS}
    sample_counts = {label: {"current_n": windows[label]["current_n"],
                             "previous_n": windows[label]["previous_n"]}
                     for label, _ in WINDOW_DAYS}
    usable = [label for label, _ in WINDOW_DAYS
              if windows[label]["state"] is not None]

    if usable:
        candidate = A.Candidate(
            state=pack(states),
            calm=not any(states[label] in _ALERTING_STATES
                         for label in usable))
    else:
        candidate = A.Candidate(
            state=None, calm=True, derivable=False,
            detail=(f"no window reached {T.TREND_MIN_SAMPLES} samples in "
                    f"both its current and previous period; the TL stream "
                    f"is too short to say which way it is going"))

    verdict = A.evaluate(context.health, candidate)
    provenance = Provenance(
        formula_ref=FORMULA_REF, computed_at=context.now,
        inputs={"windows_usable": len(usable),
                "cadence_sec": float(cadence_sec),
                "severity_scale": "6-TL",
                "short_term_delta": windows[SHORT_TERM]["delta_severity"],
                "medium_term_delta": windows[MEDIUM_TERM]["delta_severity"],
                "long_term_delta": windows[LONG_TERM]["delta_severity"]},
        # S1-CONC-015: a trend is computed from the ledger, so it has no
        # primary sources of its own and must not borrow the sensors'.
        source_refs=())
    return C.build(
        scenario_id=context.scenario_id, conclusion_type=V.TREND,
        observed_at=context.now,
        confidence=confidence_for(sample_counts,
                                  any_unavailable=len(usable) < len(WINDOW_DAYS)),
        provenance=provenance, input_health=context.health,
        availability=verdict, state=candidate.state,
        threshold_ref={"rising_delta": T.TREND_RISING_DELTA,
                       "escalate_delta": T.TREND_ESCALATE_DELTA,
                       "min_samples": T.TREND_MIN_SAMPLES,
                       "window_days": [days for _, days in WINDOW_DAYS]},
        source_urls=(), calibration_status=context.calibration_status,
        metadata={"windows": windows, "sample_counts": sample_counts,
                  "severity_scale": "6-TL"})


__all__ = ["derive", "classify", "pack", "confidence_for",
           "evaluate_windows", "WINDOW_DAYS", "FORMULA_REF", "ESCALATING",
           "RISING", "STABLE", "COOLING", "DEEPER_DECAY", "INSUFFICIENT"]
