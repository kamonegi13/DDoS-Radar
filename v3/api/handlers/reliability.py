"""P7 R7 / R8 — how far to trust this tool right now, and per sensor.

AP3 in one number with its breakdown. Eight legacy surfaces
(`calibration/health`, `chronic_inconclusive`, `adaptive_zscore_status`,
`data_status`, `llm_preflight`, `intel/stats`, `llm_call_stats`,
`calibration/tier_governor`) said parts of this in seven shapes, none of
which composed, so "should I believe the tool today" required visiting
all of them and doing the arithmetic by eye.

Two properties are load-bearing:

* **each metric fails independently and none raises** (S1-CONC-038). A
  self-evaluation that 500s tells the analyst nothing, and "nothing" is
  read as "fine".
* **an unmeasurable metric is `None` with a reason, never `0.0`.** Zero
  drift reads as "no anomaly"; it is the opposite of "we cannot tell",
  and a self-referential metric that had gone identically zero reported
  no anomaly across 360,000 conclusions.

`ops_health` is the fifth block and it is ALWAYS served (WP-4.1g). Three
of its five monitors are answerable by v3 today (whether the tick loop is
producing, backup age from a marker beside the ledger, capacity from the
ledger file against the retention target); two are not, because v3 has no
L5 verification layer and no LLM health roll-up. All five appear with
their verdicts, so the composite is reserved for a NAMED reason rather
than for an absent field.

`tick_loop` joined that list after the shadow container reported HEALTHY
for its whole run with every tick failing. It is served from here AND from
`/healthz` — one measurement, two surfaces, which is the point: a health
probe with its own private notion of liveness is a second answer to the
question this block exists to answer.

Recall is `None` here today with a stated reason: the ground-truth label
ledger lands with WP-3.3, and pooling zero cells is not a measurement.
The aggregation path is L4's (`v3.calibration.status.self_evaluate`), not
a second one written here — S1-CONC-038 requires the chip and the CI gate
to be the same arithmetic, which is only checkable if there is one.
"""
from __future__ import annotations

from v3.api.envelope import ApiResponse, tool_response
from v3.calibration import status as S
from v3.calibration.epoch import CURRENT_EPOCH, EpochStamp
from v3.calibration.thresholds import CALIBRATION_WINDOW_SEC
from v3.ledger import views
from v3.runtime import ops_health as OPS

DAY_SEC = 86400.0
CHRONIC_THRESHOLD_SEC = 7 * DAY_SEC
#: How far back the sensor roll-up looks for "did this adapter report".
SENSOR_LOOKBACK_SEC = 2 * DAY_SEC


def _stamp(now: float) -> EpochStamp:
    """The declared window. F-16 is literally a null in this position."""
    since = max(float(CURRENT_EPOCH.started_at),
                now - CALIBRATION_WINDOW_SEC)
    return EpochStamp(epoch_id=CURRENT_EPOCH.epoch_id, since=since,
                      until=now, exclude_auto=False)


def _null_zone_block(context) -> dict:
    per_scenario = []
    chronic_any = False
    for ref in context.scenarios:
        chronic = views.chronic_null_zone(
            context.ledger, ref.scenario_id,
            threshold_sec=CHRONIC_THRESHOLD_SEC, now=context.now)
        span = views.observed_span(context.ledger, ref.scenario_id,
                                   now=context.now)
        chronic_any = chronic_any or chronic["is_chronic"]
        per_scenario.append({"scenario_id": ref.scenario_id,
                             **chronic, "observed": span})
    return {"any_chronic": chronic_any, "scenarios": per_scenario,
            "threshold_sec": CHRONIC_THRESHOLD_SEC}


def _freshness_block(context) -> dict:
    oldest = context.ledger.oldest_observed_at("signal_observation")
    horizon = context.ledger.max_freshness_horizon()
    recent = context.ledger.signals_between(
        context.now - SENSOR_LOOKBACK_SEC, context.now)
    latest = max((float(row["observed_at"]) for row in recent), default=None)
    return {
        "signal_count": context.ledger.count_signals(),
        "tl_count": context.ledger.count_tl(),
        "conclusion_count": context.ledger.count_conclusions(),
        "oldest_observation_at": oldest,
        "latest_observation_at": latest,
        "data_age_sec": None if latest is None else context.now - latest,
        "max_freshness_horizon_sec": horizon,
    }


def _sensor_rollup(context) -> list[dict]:
    """One shape for sensor health (P7 R8 replaces four legacy shapes)."""
    rows = context.ledger.signals_between(
        context.now - SENSOR_LOOKBACK_SEC, context.now)
    grouped: dict = {}
    for row in rows:
        entry = grouped.setdefault(row["sensor"], {
            "sensor": row["sensor"], "domain": row.get("domain"),
            "observation_count": 0, "fired_count": 0,
            "suppressed_count": 0, "countries": set(),
            "last_observed_at": None})
        entry["observation_count"] += 1
        if row.get("status") == "FIRED":
            entry["fired_count"] += 1
        if row.get("suppressed"):
            entry["suppressed_count"] += 1
        entry["countries"].add(row.get("country"))
        stamp = float(row["observed_at"])
        if entry["last_observed_at"] is None or \
                stamp > entry["last_observed_at"]:
            entry["last_observed_at"] = stamp
    summary = []
    for adapter_id in sorted(set(context.adapters) | set(grouped)):
        entry = grouped.get(adapter_id)
        if entry is None:
            # Declared but silent. NOT omitted: an adapter missing from
            # the roll-up is indistinguishable from a healthy one, and
            # that indistinguishability is G-17.
            summary.append({"sensor": adapter_id, "domain": None,
                            "observation_count": 0, "fired_count": 0,
                            "suppressed_count": 0, "countries": [],
                            "last_observed_at": None,
                            "silent_for_sec": None, "declared": True})
            continue
        summary.append({**entry,
                        "countries": sorted(c for c in entry["countries"]
                                            if c),
                        "silent_for_sec": (context.now
                                           - entry["last_observed_at"]),
                        "declared": adapter_id in context.adapters})
    return summary


def _ops_health_block(context) -> dict:
    """The operational axis (P8 §4's fifth fold input).

    Always present. WP-4.2's trust chip read amber because R7 had no such
    field at all, which meant the page could not distinguish "nothing is
    watching the backups" from "the server has not been taught to say".
    Now it says: an unprobed deployment gets every monitor, each carrying
    the reason it cannot answer, and the fold is still reserved — because
    green monitors beside unanswerable ones is not a green deployment
    (G-17).
    """
    return OPS.supplied_or_absent(getattr(context, "ops_health", None),
                                  now=context.now)


def read_self_eval(context) -> ApiResponse:
    """R7 — the composite reliability read (O-11)."""
    evaluation = S.self_evaluate((), stamp=_stamp(context.now))
    return tool_response(
        observed_at=context.now,
        self_eval={
            "calibration": evaluation.as_dict(),
            "calibration_note": (
                "recall は ground truth ラベル台帳（WP-3.3）が着地するまで "
                "measurable になりません。0.0 ではなく None を返します。"),
            "null_zone": _null_zone_block(context),
            "data": _freshness_block(context),
            "ops_health": _ops_health_block(context),
            "sensors": {"count": len(_sensor_rollup(context))},
            "epoch": {"epoch_id": CURRENT_EPOCH.epoch_id,
                      "window_sec": CALIBRATION_WINDOW_SEC},
        })


def read_sensors(context) -> ApiResponse:
    """R8 — sensor health, the single shape."""
    rollup = _sensor_rollup(context)
    return tool_response(observed_at=context.now, sensors=rollup,
                         sensor_count=len(rollup),
                         lookback_sec=SENSOR_LOOKBACK_SEC,
                         declared_adapters=list(context.adapters))


__all__ = ["read_self_eval", "read_sensors"]
