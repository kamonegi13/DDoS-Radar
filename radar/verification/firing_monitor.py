"""radar.verification.firing_monitor -- detection-flag liveness monitoring.

Answers the question the current health model cannot: "the sensor is
fetching fine, but has its *detection logic* been dead for months?"
`BaseSensor.health` is fetch liveness only, so a sensor whose thresholds
are unreachable (F-08 / gps_jamming) reports OK forever. `detection_health`
here is the second, independent axis required by S5-VERIF-004; the fetch
axis is left untouched because scoring confidence is calibrated against it.

Responsibilities:
    record_evaluation()      S5-VERIF-002 — persist per-flag fire history
    evaluate_silence()       S5-VERIF-003 — numeric long-silence verdicts
    detection_health()       S5-VERIF-004 — worst verdict per sensor
    run_daily_check_if_due() S5-VERIF-016 — one daily job on a *persistent*
                             schedule (the F-01 volatile-counter fix)
    snapshot()               AP3 self-evaluation surface

Everything here is exception-contained. record_evaluation() runs inside
BaseSensor.set_cache(); a monitoring failure must degrade to a log line,
never to a sensor outage (NP3). Read paths degrade to UNKNOWN rather than
to a green default — an unanswerable query is not a healthy one
(S5-VERIF-006 / NP5+8).
"""
from __future__ import annotations

import json
import logging
import time

from radar.verification import flag_catalog

log = logging.getLogger("radar")

JOB_ID = "firing_liveness_daily"
CHECK_ID = "firing_liveness"
JOB_INTERVAL_SEC = 86400.0
SUMMARY_TARGET = "__summary__"

# Worst-first. detection_health reports the first verdict present.
_VERDICT_ORDER = ("ANOMALY", "WARN", "INSUFFICIENT", "OK")

_DAY = 86400.0
_FIRE_COUNT_WINDOW_SEC = 30 * _DAY

# l5_check_result retention. Aligned with the conclusions-ledger horizon
# (ADR-V3-005): a verification finding must stay queryable for at least as
# long as the conclusions it casts doubt on.
CHECK_RESULT_RETENTION_DAYS = 365


def _db():
    """Lazy singleton accessor (also the seam tests bind to a temp DB)."""
    from radar.database import db
    return db


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def _is_enabled(sensor_name: str) -> bool:
    """Whether the registry considers this sensor enabled.

    Unknown sensors are treated as enabled on purpose: a catalog entry
    whose sensor vanished from the registry should surface as a finding,
    not disappear from monitoring (NP1 — a miss is worse than a false
    positive).
    """
    try:
        from radar import registry
        sensor = registry.get(sensor_name)
    except Exception as exc:  # noqa: BLE001 - registry import must not break checks
        log.warning("firing-monitor registry lookup failed for %s: %s",
                    sensor_name, exc)
        return True
    return True if sensor is None else bool(sensor.enabled)


# ── S5-VERIF-002: recording ────────────────────────────────────────────────
def record_evaluation(sensor_name: str, payload, now: float | None = None) -> None:
    """Evaluate every catalogued flag of a sensor and persist the outcome.

    Called from BaseSensor.set_cache() on every successful fetch. Cheap by
    construction: sensors with no catalog entry return before touching the
    DB, and each flag costs one upsert plus (only when fired) one append.
    """
    try:
        fired = flag_catalog.evaluate_flags(sensor_name, payload)
        if not fired:
            return
        _db().flag_record_evaluation(
            sensor_name,
            {flag_id: bool(is_fired) for flag_id, is_fired in fired.items()},
            ts=_now(now),
            ttl_sec=flag_catalog.FIRE_LOG_RETENTION_DAYS * _DAY,
        )
    except Exception as exc:  # noqa: BLE001 - NP3: never break a sensor fetch
        log.warning("firing-monitor record failed for %s: %s", sensor_name, exc)


# ── S5-VERIF-003: silence verdicts ─────────────────────────────────────────
def _verdict_for(spec, state: dict | None, now: float) -> tuple[str, str, float | None]:
    """(verdict, reason, silence_ratio) for one flag. Pure."""
    if state is None:
        return "INSUFFICIENT", "never_evaluated", None

    window = spec.expected_fire_interval_days * _DAY
    last_fired = state.get("last_fired_at")

    if last_fired is None:
        first_seen = state.get("first_observed_at")
        # Explicit None check: 0.0 is a real timestamp, and `or now` would
        # silently reclassify a decade of silence as a fresh observation.
        age = now - float(now if first_seen is None else first_seen)
        if age >= flag_catalog.NEVER_FIRED_GRACE_DAYS * _DAY:
            # The F-08 symptom: alive since day one, never once fired.
            return "ANOMALY", "never_fired", None
        return "INSUFFICIENT", "never_fired_within_grace", None

    ratio = (now - float(last_fired)) / window if window > 0 else 0.0
    if ratio >= flag_catalog.SILENCE_ANOMALY_RATIO:
        return "ANOMALY", "silent_too_long", ratio
    if ratio >= flag_catalog.SILENCE_WARN_RATIO:
        return "WARN", "silent_too_long", ratio
    return "OK", "recently_fired", ratio


def _evaluate(now: float) -> tuple[list[dict], list[str]]:
    """Evaluate the whole catalog. Returns (results, skipped_sensor_names)."""
    handle = _db()
    states = {(r["sensor"], r["flag_id"]): r for r in handle.flag_state_all()}
    fire_counts = handle.flag_fire_counts_since(now - _FIRE_COUNT_WINDOW_SEC)

    results: list[dict] = []
    skipped: list[str] = []
    enabled_cache: dict[str, bool] = {}

    for spec in flag_catalog.CATALOG:
        if spec.sensor not in enabled_cache:
            enabled_cache[spec.sensor] = _is_enabled(spec.sensor)
        if not enabled_cache[spec.sensor]:
            if spec.sensor not in skipped:
                skipped.append(spec.sensor)
            continue

        key = (spec.sensor, spec.flag_id)
        state = states.get(key)
        verdict, reason, ratio = _verdict_for(spec, state, now)
        results.append({
            "sensor": spec.sensor,
            "flag_id": spec.flag_id,
            "verdict": verdict,
            "reason": reason,
            "silence_ratio": None if ratio is None else round(ratio, 4),
            "last_fired_at": None if state is None else state.get("last_fired_at"),
            "first_observed_at": (
                None if state is None else state.get("first_observed_at")),
            "fire_count_30d": fire_counts.get(key, 0),
            "expected_fire_interval_days": spec.expected_fire_interval_days,
        })
    return results, skipped


def evaluate_silence(now: float | None = None) -> list[dict]:
    """Silence verdict for every catalogued flag of every enabled sensor."""
    return _evaluate(_now(now))[0]


# ── S5-VERIF-004: detection health axis ────────────────────────────────────
def detection_health(sensor_name: str, now: float | None = None) -> str:
    """Worst detection verdict for one sensor.

    Returns "NO_FLAGS" for sensors declared flagless, "UNKNOWN" when no
    state has been recorded yet or the lookup failed. Never returns "OK"
    on an error path — a query that could not be answered must not render
    as green (S5-VERIF-006).
    """
    if sensor_name in flag_catalog.NO_DETECTION_FLAGS:
        return "NO_FLAGS"
    specs = flag_catalog.specs_for(sensor_name)
    if not specs:
        return "UNKNOWN"
    try:
        states = {r["flag_id"]: r for r in _db().flag_state_for(sensor_name)}
    except Exception as exc:  # noqa: BLE001 - degrade to UNKNOWN, not to OK
        log.warning("firing-monitor detection_health failed for %s: %s",
                    sensor_name, exc)
        return "UNKNOWN"
    if not states:
        return "UNKNOWN"

    return _worst(specs, states, _now(now))


def _worst(specs, states: dict, ts: float) -> str:
    """Worst verdict across one sensor's specs, given its state rows."""
    verdicts = {_verdict_for(spec, states.get(spec.flag_id), ts)[0]
                for spec in specs}
    for verdict in _VERDICT_ORDER:
        if verdict in verdicts:
            return verdict
    return "UNKNOWN"


def detection_health_bulk(sensor_names=None, now: float | None = None) -> dict:
    """detection_health for many sensors from ONE state query.

    config_list() calls to_config_dict() per sensor, so a per-sensor SELECT
    there costs ~26 queries per /api/sensor_config request. Defaults to
    every sensor the catalog knows about plus the declared-flagless set.
    """
    if sensor_names is None:
        names = sorted({spec.sensor for spec in flag_catalog.CATALOG}
                       | set(flag_catalog.NO_DETECTION_FLAGS))
    else:
        names = list(sensor_names)

    flagless = {n: "NO_FLAGS" for n in names
                if n in flag_catalog.NO_DETECTION_FLAGS}
    pending = [n for n in names if n not in flagless]
    if not pending:
        return flagless

    try:
        rows = _db().flag_state_all()
    except Exception as exc:  # noqa: BLE001 - degrade to UNKNOWN, not to OK
        log.warning("firing-monitor detection_health_bulk failed: %s", exc)
        return {**flagless, **{n: "UNKNOWN" for n in pending}}

    by_sensor: dict[str, dict] = {}
    for row in rows:
        by_sensor.setdefault(row["sensor"], {})[row["flag_id"]] = row

    ts = _now(now)
    result = dict(flagless)
    for name in pending:
        specs = flag_catalog.specs_for(name)
        states = by_sensor.get(name)
        result[name] = _worst(specs, states, ts) if specs and states else "UNKNOWN"
    return result


# ── S5-VERIF-016: the daily job on a persistent schedule ───────────────────
def _append_result(handle, ts: float, target: str, verdict: str,
                   measured: dict, expected: dict) -> None:
    """Append one ledger row, carrying first_detected_at across runs.

    Carry-forward only continues an episode: it requires the *latest* row
    for this target to hold the same verdict. Recovery rows (below) are
    what make that correct — without them a fixed-then-broken-again target
    would inherit the first episode's start time and read as one long
    incident.
    """
    previous = handle.l5_check_last_for_target(CHECK_ID, target)
    if (previous and previous.get("verdict") == verdict
            and previous.get("first_detected_at") is not None):
        first_detected_at = previous["first_detected_at"]
    else:
        first_detected_at = ts
    handle.l5_check_append(
        ts=ts, check_id=CHECK_ID, target=target, verdict=verdict,
        measured_json=json.dumps(measured, sort_keys=True),
        expected_json=json.dumps(expected, sort_keys=True),
        first_detected_at=first_detected_at,
        ttl_sec=CHECK_RESULT_RETENTION_DAYS * _DAY,
    )


def _expected_block() -> dict:
    """The thresholds every verdict in this check was measured against."""
    return {
        "warn_ratio": flag_catalog.SILENCE_WARN_RATIO,
        "anomaly_ratio": flag_catalog.SILENCE_ANOMALY_RATIO,
        "never_fired_grace_days": flag_catalog.NEVER_FIRED_GRACE_DAYS,
    }


def _record_results(handle, ts: float, results: list[dict]) -> dict:
    """Append every non-OK result plus any OK recovery transition.

    Returns the verdict counts. OK targets are logged only when the
    previous ledger row for them was non-OK, so the ledger stays bounded
    (one row per transition) while still closing each episode.
    """
    counts = {"ANOMALY": 0, "WARN": 0, "INSUFFICIENT": 0, "OK": 0}
    for result in results:
        verdict = result["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        target = f"{result['sensor']}:{result['flag_id']}"

        if verdict == "OK":
            previous = handle.l5_check_last_for_target(CHECK_ID, target)
            if not previous or previous.get("verdict") == "OK":
                continue  # nothing to close — never append daily no-ops

        measured = {
            "reason": result["reason"],
            "silence_ratio": result["silence_ratio"],
            "last_fired_at": result["last_fired_at"],
            "first_observed_at": result["first_observed_at"],
            "fire_count_30d": result["fire_count_30d"],
        }
        expected = dict(_expected_block())
        expected["expected_fire_interval_days"] = \
            result["expected_fire_interval_days"]
        _append_result(handle, ts, target, verdict, measured, expected)
    return counts


def run_daily_check_if_due(now: float | None = None) -> bool:
    """Run the silence check if the persisted schedule says it is due.

    Returns True when the check actually ran. Driven by `next_run_at` in
    l5_job_state rather than an in-process counter, so an overdue job runs
    on the first tick after a restart instead of being skipped forever
    (defect F-01).
    """
    ts = _now(now)
    try:
        handle = _db()
        job = handle.l5_job_get(JOB_ID)
        if job and job.get("next_run_at") is not None and job["next_run_at"] > ts:
            return False

        results = evaluate_silence(now=ts)
        counts = _record_results(handle, ts, results)

        summary_verdict = ("ANOMALY" if counts["ANOMALY"]
                           else "WARN" if counts["WARN"] else "OK")
        _append_result(handle, ts, SUMMARY_TARGET, summary_verdict,
                       measured=counts,
                       expected={"flags_total": len(results)})
        handle.l5_job_set(JOB_ID, last_run_at=ts, next_run_at=ts + JOB_INTERVAL_SEC)
        if counts["ANOMALY"]:
            log.warning("[FiringLiveness] %d flag(s) ANOMALY, %d WARN",
                        counts["ANOMALY"], counts["WARN"])
        return True
    except Exception as exc:  # noqa: BLE001 - a failed check must not kill the worker
        log.warning("firing-monitor daily check failed: %s", exc)
        return False


# ── AP3 self-evaluation surface ────────────────────────────────────────────
def snapshot(now: float | None = None) -> dict:
    """Live firing-liveness summary for /api/v2/self_eval.

    Recomputed from state rather than read back from the ledger, so the
    surface reflects the current situation even between daily runs; the
    job timestamps say how fresh the *ledger* is.
    """
    ts = _now(now)
    results, skipped = _evaluate(ts)
    job = _db().l5_job_get(JOB_ID) or {}

    def _brief(result: dict) -> dict:
        return {k: result[k] for k in (
            "sensor", "flag_id", "reason", "silence_ratio", "last_fired_at",
            "expected_fire_interval_days")}

    never_evaluated = sorted({
        r["sensor"] for r in results if r["reason"] == "never_evaluated"})
    return {
        "job_id": JOB_ID,
        "job_last_run_at": job.get("last_run_at"),
        "job_next_run_at": job.get("next_run_at"),
        "flags_total": len(results),
        "anomalies": [_brief(r) for r in results if r["verdict"] == "ANOMALY"],
        "warns": [_brief(r) for r in results if r["verdict"] == "WARN"],
        "insufficient_count": sum(
            1 for r in results if r["verdict"] == "INSUFFICIENT"),
        "disabled_skipped": sorted(skipped),
        "never_evaluated": never_evaluated,
    }
