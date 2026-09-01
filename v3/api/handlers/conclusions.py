"""P7 R2 / R3 / R4 — what the tool concluded, over time, and why.

R2 is the analyst's primary read: the five conclusion types for one
scenario, in one envelope, with the NP7 sentence, plus the four ways a
conclusion can be unavailable.

**`?at=` is not a second endpoint and not a second code path.** P7's
derivation principle 4 says replay and live are the same projection, and
this module implements that literally: `_project` takes an instant, live
passes `context.now`, replay passes the parsed `at`. The only difference
in the response is that the envelope's `at` field is populated when the
caller asked for an instant — which is the field L3 already put on the
envelope for this purpose (S1-CONC-037's DP9). The legacy system had a
replay-only shape that had already diverged from the live one.

**The calibration_pending countdown.** The 2026-08-08 ruling kept the
30-day calibration window and required the API to say "calibration
pending, N days remaining" rather than merely returning no conclusion. A
new scenario is transiently silent on the calm side; silence without a
countdown is indistinguishable from a broken tool, which is the NP5+8
failure mode the ruling was guarding against.
"""
from __future__ import annotations

from typing import Optional

from v3.api import errors as E
from v3.api.envelope import ApiResponse, scenario_response
from v3.api.rehydrate import (UnreadableConclusionRow, from_row,
                              tl_point)
from v3.commands.state import labels_for
from v3.conclusions import (ANOMALY, CALIBRATION_PENDING, CONCLUSION_TYPES,
                            UNAVAILABLE_REASONS)
from v3.conclusions.persistence import BATCH_WINDOW_SEC
from v3.conclusions.thresholds import (CALIBRATION_MIN_HISTORY_DAYS,
                                       CALIBRATION_MIN_HISTORY_SEC)
from v3.kernel import Window
from v3.ledger import views

DAY_SEC = 86400.0
#: R3's default span. A window, not "everything": an unbounded history
#: read is the shape that made `/api/history/threat_levels` unusable at
#: scale, and the caller can widen it explicitly.
DEFAULT_HISTORY_SEC = 7 * DAY_SEC
MAX_HISTORY_SEC = 90 * DAY_SEC
#: NP5+8's line between "transient" and "a design failure". Seven days of
#: continuous inability to conclude is chronic; the number is the same one
#: the self-evaluation surface reports against, so the two cannot disagree.
CHRONIC_THRESHOLD_SEC = 7 * DAY_SEC
DEFAULT_CADENCE = 900.0


def _known_scenario(context, scenario_id: str):
    ref = context.scenario(scenario_id)
    if ref is None:
        raise E.not_found(f"シナリオ {scenario_id}",
                          scenario_id=scenario_id)
    return ref


def _instant(context, at) -> tuple[float, Optional[float]]:
    """(the instant to project, the value to echo as `at`).

    Live and replay differ here and nowhere else.
    """
    if at is None:
        return context.now, None
    try:
        parsed = float(at)
    except (TypeError, ValueError):
        raise E.bad_request("at は unix 時刻で指定します", at=str(at)) from None
    if parsed <= 0:
        raise E.bad_request("at は正の unix 時刻です", at=parsed)
    if parsed > context.now:
        raise E.bad_request(
            "at は未来を指せません（射影は台帳にある事実のみ）",
            at=parsed, now=context.now)
    return parsed, parsed


def _rows_for_type(context, scenario_id: str, conclusion_type: str,
                   at_ts: float) -> list:
    latest = context.ledger.latest_conclusion_at(
        at_ts, scenario_id=scenario_id, conclusion_type=conclusion_type)
    if latest is None:
        return []
    if conclusion_type != ANOMALY:
        return [latest]
    # S1-CONC-032: one tick emits several anomaly rows microseconds
    # apart, so the "latest" anomaly is a batch, not a row. Serving only
    # the newest row would drop every other anomaly of the same tick.
    newest = float(latest["observed_at"])
    return context.ledger.conclusions_between(
        scenario_id=scenario_id, conclusion_type=conclusion_type,
        start=newest - BATCH_WINDOW_SEC, end=newest)


def _calibration_countdown(conclusions) -> Optional[dict]:
    """The visible countdown the 2026-08-08 ruling requires."""
    pending = [item for item in conclusions
               if item.unavailable_reason == CALIBRATION_PENDING]
    if not pending:
        return None
    observed = max(item.input_health.history_span_sec for item in pending)
    remaining = max(0.0, CALIBRATION_MIN_HISTORY_SEC - observed)
    return {
        "reason": CALIBRATION_PENDING,
        "days_remaining": round(remaining / DAY_SEC, 2),
        "days_observed": round(observed / DAY_SEC, 2),
        "window_days": CALIBRATION_MIN_HISTORY_DAYS,
        "types": sorted({item.conclusion_type for item in pending}),
        "resolves_by": "観測履歴が較正窓に達した時点で自動的に解消します",
    }


def _project(context, scenario_id: str, at_ts: float,
             echo_at: Optional[float]) -> ApiResponse:
    rebuilt = []
    unreadable = []
    present = set()
    for conclusion_type in CONCLUSION_TYPES:
        for row in _rows_for_type(context, scenario_id, conclusion_type,
                                  at_ts):
            try:
                rebuilt.append(from_row(row))
            except UnreadableConclusionRow as exc:
                # Reported, never dropped: a row served as a thinner
                # conclusion is worse than a row reported as unreadable,
                # because the thinner one still looks like an answer.
                unreadable.append({"id": row.get("id"), "reason": str(exc)})
                continue
            present.add(conclusion_type)
    missing = sorted(set(CONCLUSION_TYPES) - present)
    extra = {
        "projection": {
            "at": at_ts,
            "types_present": sorted(present),
            "types_missing": missing,
            "unreadable_rows": unreadable,
            "unavailable_reasons": list(UNAVAILABLE_REASONS),
        },
    }
    countdown = _calibration_countdown(rebuilt)
    if countdown is not None:
        extra["calibration_pending"] = countdown
    return scenario_response(scenario_id, rebuilt, at=echo_at,
                             observed_at=at_ts if not rebuilt else None,
                             **extra)


def read_conclusions(context, *, scenario_id: str, at=None,
                     include=None) -> ApiResponse:
    """R2. Live and replay, one projection."""
    _known_scenario(context, scenario_id)
    at_ts, echo_at = _instant(context, at)
    if include:
        # AP2 narrative is a deterministic template engine (P7 §4). It is
        # not implemented yet and is registered as such; answering with a
        # silently narrative-free body would be the failure this project
        # keeps finding, so the caller is told.
        raise E.bad_request(
            "include=narrative は未実装です（P7 §4 の決定論テンプレート）",
            include=str(include), owner="WP-4.1c")
    return _project(context, scenario_id, at_ts, echo_at)


def read_history(context, *, scenario_id: str, window=None,
                 at=None) -> ApiResponse:
    """R3 — the derived view over L1's unthinned TL stream (P6 O-16).

    Trend, null-zone length and chronic detection are queries here, not
    state machines: that is what let WP-3.1 delete the thinning /
    continuity-ledger / duty-cycle chain rather than port it.
    """
    _known_scenario(context, scenario_id)
    at_ts, echo_at = _instant(context, at)
    span = DEFAULT_HISTORY_SEC if window is None else _span(window)
    start = at_ts - span
    series = [tl_point(row) for row
              in context.ledger.tl_between(scenario_id, start, at_ts)]
    null_spans = views.null_zone_spans(context.ledger, scenario_id,
                                       since=start, now=at_ts)
    chronic = views.chronic_null_zone(
        context.ledger, scenario_id, threshold_sec=CHRONIC_THRESHOLD_SEC,
        now=at_ts)
    windows = []
    for days in (1, 7):
        window_obj = Window(declared_days=days, cadence_sec=DEFAULT_CADENCE)
        pair = views.severity_window_pair(context.ledger, scenario_id,
                                          window=window_obj, now=at_ts)
        windows.append({"window_days": days, **pair})
    return scenario_response(
        scenario_id, (), at=echo_at, observed_at=at_ts,
        history={
            "start": start,
            "end": at_ts,
            "span_sec": span,
            "points": series,
            "point_count": len(series),
            "null_zone_spans": null_spans,
            "chronic_null_zone": chronic,
            "windows": windows,
        })


def _span(window) -> float:
    try:
        span = float(window)
    except (TypeError, ValueError):
        raise E.bad_request("window は秒数で指定します",
                            window=str(window)) from None
    if span <= 0 or span > MAX_HISTORY_SEC:
        raise E.bad_request(
            f"window は 0 より大きく {MAX_HISTORY_SEC:.0f} 秒以下です",
            window=span, maximum=MAX_HISTORY_SEC)
    return span


def read_conclusion(context, *, conclusion_id: str) -> ApiResponse:
    """R4 (the conclusion itself), with the labels posted against it.

    The labels are here because C2 has to have a reader. A feedback
    endpoint whose result no projection shows is G-15 in miniature: the
    analyst sees their label accepted and has no way to find out whether
    the tool kept it.
    """
    conclusion = _by_id(context, conclusion_id)
    return scenario_response(
        conclusion.scenario_id, (conclusion,),
        observed_at=conclusion.observed_at,
        analyst_labels=labels_for(context.ledger, conclusion_id,
                                  until=context.now))


def read_derivation(context, *, conclusion_id: str) -> ApiResponse:
    """R4 (the full derivation) — O-6, the NP6 surface.

    Formula, effective thresholds, source URLs, the LLM prompt digest and
    the guard verdicts that were evaluated but did not fire. The last of
    those is the part the legacy `score_breakdown` never had: a guard
    that stayed silent left no evidence it had been consulted.
    """
    conclusion = _by_id(context, conclusion_id)
    suppression = (None if conclusion.suppression is None
                   else conclusion.suppression.as_dict())
    return scenario_response(
        conclusion.scenario_id, (conclusion,),
        observed_at=conclusion.observed_at,
        derivation={
            "conclusion_id": conclusion.conclusion_id,
            "formula_ref": conclusion.provenance.formula_ref,
            "provenance": conclusion.provenance.as_dict(),
            "threshold_ref": dict(conclusion.threshold_ref),
            "source_urls": list(conclusion.source_urls),
            "llm_prompt_sha256": conclusion.llm_prompt_sha256,
            "input_health": conclusion.input_health.as_dict(),
            "calibration_status": dict(conclusion.calibration_status),
            "suppression": suppression,
            "guards_evaluated": ([] if suppression is None
                                 else suppression["evaluated"]),
        })


def _by_id(context, conclusion_id: str):
    if not isinstance(conclusion_id, str) or not conclusion_id.strip():
        raise E.bad_request("conclusion_id が空です")
    row = context.ledger.conclusion_by_id(conclusion_id)
    if row is None:
        raise E.not_found(f"結論 {conclusion_id}", conclusion_id=conclusion_id)
    try:
        return from_row(row)
    except UnreadableConclusionRow as exc:
        raise E.bad_request(
            "この結論行は再構成できません（導出開示が欠落しています）",
            conclusion_id=conclusion_id, reason=str(exc)) from exc


__all__ = ["read_conclusions", "read_history", "read_conclusion",
           "read_derivation"]
