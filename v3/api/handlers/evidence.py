"""P7 R5 — the indication matrix and the individual anomalous events.

Three legacy surfaces collapse here (`alert_timeline`, `sequence_chain`,
`history/sequence_events`), and the collapse is the point: the same event
was reachable in three shapes, and the three had drifted, so an analyst
who checked two of them saw two different pictures of one tick.

The suppressed rows are served WITH their reason. A signal that fired and
was excluded is not the same fact as a signal that did not fire, and the
legacy matrix rendered both as "OK" — which is the observation half of
E-17.
"""
from __future__ import annotations

from typing import Optional

from v3.api import errors as E
from v3.api.envelope import ApiResponse, scenario_response, tool_response

DAY_SEC = 86400.0
DEFAULT_WINDOW_SEC = DAY_SEC
MAX_WINDOW_SEC = 30 * DAY_SEC
FIRED = "FIRED"


def _window(value) -> float:
    if value is None:
        return DEFAULT_WINDOW_SEC
    try:
        span = float(value)
    except (TypeError, ValueError):
        raise E.bad_request("window は秒数で指定します",
                            window=str(value)) from None
    if span <= 0 or span > MAX_WINDOW_SEC:
        raise E.bad_request(
            f"window は 0 より大きく {MAX_WINDOW_SEC:.0f} 秒以下です",
            window=span, maximum=MAX_WINDOW_SEC)
    return span


def _row(observation: dict) -> dict:
    return {
        "tick_id": observation.get("tick_id"),
        "sensor": observation.get("sensor"),
        "signal_source": observation.get("signal_source"),
        "domain": observation.get("domain"),
        "country": observation.get("country"),
        "status": observation.get("status"),
        "raw_score": observation.get("raw_score"),
        "confidence": observation.get("confidence"),
        "observed_at": observation.get("observed_at"),
        "suppressed": bool(observation.get("suppressed")),
        "suppress_reason": observation.get("suppress_reason"),
        "evidence_url": observation.get("evidence_url"),
        "flags": observation.get("flags"),
    }


def read_evidence(context, *, scenario_id: str, at=None, domain=None,
                  sensor=None, window=None) -> ApiResponse:
    """R5. The matrix for one scenario's participants, at one instant."""
    ref = context.scenario(scenario_id)
    if ref is None:
        raise E.not_found(f"シナリオ {scenario_id}", scenario_id=scenario_id)
    at_ts = context.now if at is None else _at(context, at)
    span = _window(window)
    countries = set(ref.participants) | {"GLOBAL"}
    collected: list[dict] = []
    for country in sorted(countries):
        collected.extend(context.ledger.signals_between(
            at_ts - span, at_ts, sensor=sensor, country=country))
    rows = [_row(item) for item in collected]
    if domain is not None:
        rows = [row for row in rows if row["domain"] == domain]
    fired = [row for row in rows if row["status"] == FIRED
             and not row["suppressed"]]
    suppressed = [row for row in rows if row["suppressed"]]
    return scenario_response(
        scenario_id, (), at=None if at is None else at_ts,
        observed_at=at_ts,
        evidence={
            "at": at_ts,
            "window_sec": span,
            "countries": sorted(countries),
            "filters": {"domain": domain, "sensor": sensor},
            "matrix": rows,
            "fired": fired,
            "fired_count": len(fired),
            "suppressed": suppressed,
            "suppressed_count": len(suppressed),
            "observation_count": len(rows),
        })


def _at(context, value) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise E.bad_request("at は unix 時刻で指定します",
                            at=str(value)) from None
    if parsed <= 0 or parsed > context.now:
        raise E.bad_request("at は 0 より大きい過去の unix 時刻です",
                            at=parsed, now=context.now)
    return parsed


def read_observations(context, *, sensor_id: str, window=None,
                      country: Optional[str] = None) -> ApiResponse:
    """R8's second half — one sensor's observation series."""
    span = _window(window)
    rows = context.ledger.signals_between(context.now - span, context.now,
                                          sensor=sensor_id, country=country)
    if not rows:
        raise E.not_found(f"センサー {sensor_id} の観測", sensor=sensor_id,
                          window_sec=span)
    return tool_response(observed_at=context.now, sensor=sensor_id,
                         observations=[_row(item) for item in rows],
                         observation_count=len(rows), window_sec=span)


__all__ = ["read_evidence", "read_observations"]
