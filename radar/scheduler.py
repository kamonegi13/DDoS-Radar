"""radar.scheduler -- Background sensor scheduler and cache cleanup."""
from __future__ import annotations
import logging
import time
import threading
from radar.config import (
    DEFAULT_FOCUSED_SCENARIO,
    CF_HEADERS, OWM_API_KEY,
    GDELT_TONE_ALERT_THRESHOLD, GDELT_HISTORY_WINDOW,
    CACHE_EXPIRY, SEQUENCE_WINDOW,
)
from radar.sensors.base import BaseSensor
from radar.state import _cf_scoring_cache, _cf_cache_lock
from radar.database import db as _db
from radar.scoring import _asn_cache

log = logging.getLogger("radar")

def _build_default_context() -> dict:
    """Build sensor context from the focused scenario + all enabled scenarios
    (ADR-005). Per-country sensors target the focused scenario's participants;
    LLM sensors receive the union across all scorable scenarios.

    The "focused" set is the union of analyst-active focuses recorded in
    `radar.state._active_focus` (TTL-bounded) plus DEFAULT_FOCUSED_SCENARIO.
    This keeps FOCUSED_ONLY sensors in sync with the analyst's current view
    (scenario-refactor §8.1, P0-3)."""
    from radar.scenarios import (
        scenario_store, derive_country_context, derive_global_fetch_targets,
    )
    from radar.state import get_active_focus_ids

    # Collect the analyst-active focuses, falling back to the default.
    _focus_ids = list(get_active_focus_ids())
    if DEFAULT_FOCUSED_SCENARIO not in _focus_ids:
        _focus_ids.append(DEFAULT_FOCUSED_SCENARIO)

    focused_scenarios = [sc for sc in (scenario_store.get(sid) for sid in _focus_ids) if sc]
    if not focused_scenarios:
        _fallback = scenario_store.scorable()
        if _fallback:
            focused_scenarios = [_fallback[0]]

    if not focused_scenarios:
        # Store not yet loaded — return minimal context; scheduler will pick
        # up real targets on the next cycle.
        return {
            "all_targets": [], "strategic_theaters": [], "adversary_states": [],
            "all_participant_countries": [],
            "cf_headers": CF_HEADERS, "owm_api_key": OWM_API_KEY,
            "weather_conditions": {},
            "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD,
            "gdelt_history_window": GDELT_HISTORY_WINDOW,
        }

    # Union per-country targets across every active focus.
    strategic: set[str] = set()
    adversaries: set[str] = set()
    for sc in focused_scenarios:
        ctx = derive_country_context(sc)
        strategic |= set(ctx["strategic_theaters"])
        adversaries |= set(ctx["adversary_states"])

    global_targets = derive_global_fetch_targets()
    return {
        "all_targets":         sorted(strategic | adversaries),
        "strategic_theaters":  sorted(strategic),
        "adversary_states":    sorted(adversaries),
        "all_participant_countries": global_targets["all_participant_countries"],
        "cf_headers":          CF_HEADERS,
        "owm_api_key":         OWM_API_KEY,
        "weather_conditions":  {},
        "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD,
        "gdelt_history_window": GDELT_HISTORY_WINDOW,
    }

def _sensor_scheduler_worker(sensor: BaseSensor, registry=None,
                             initial_delay: float = 0.0):
    """Dedicated background fetch thread for a sensor.
    - Normal: periodic fetch every poll_interval
    - On failure: retry up to 3 times at shorter intervals [5min, 10min, 30min]
    - Emits sensor_status via WS on health changes
    - initial_delay: seconds to wait before first fetch (for staggering shared-API sensors)
    """
    from radar.ws import emit_sensor_status

    if not sensor.enabled:
        log.info(f"[Sensor/{sensor.name}] DISABLED — waiting for re-enablement")
        while not sensor.enabled:
            time.sleep(60)
        log.info(f"[Sensor/{sensor.name}] RE-ENABLED — starting scheduler")

    if initial_delay > 0:
        time.sleep(initial_delay)

    _last_health = sensor.health
    # Track whether a persistent-CIRCUIT_OPEN warning has been emitted so
    # we don't spam the log on every skip cycle.
    _cb_persistent_warned = False

    def _do_fetch() -> bool:
        ctx = _build_default_context()
        ctx["_registry"] = registry
        if sensor.name == "gdelt":
            owm = registry.get("openweather")
            if owm: ctx["weather_conditions"] = owm.get_cache().get("conditions", {})
        sensor.fetch(ctx)
        log_entries = sensor.get_fetch_log()
        return bool(log_entries and log_entries[-1].get("success"))

    def _check_health_change():
        nonlocal _last_health
        new_health = sensor.health
        if new_health != _last_health:
            log.info(f"[Sensor/{sensor.name}] Health: {_last_health} → {new_health}")
            emit_sensor_status(sensor.name, new_health)
            _last_health = new_health

    def _guarded_fetch() -> bool:
        """Fetch with circuit breaker integration."""
        nonlocal _cb_persistent_warned
        if sensor.cb_should_skip():
            # Emit a one-time warning when CB has failed 2+ probes
            # (recovery_delay > CB_INITIAL_DELAY means at least one probe already failed)
            with sensor._lock:
                delay = sensor._cb_recovery_delay
            if delay > sensor.CB_INITIAL_DELAY and not _cb_persistent_warned:
                log.error(
                    f"[CB/{sensor.name}] Sensor has been CIRCUIT_OPEN through multiple "
                    f"recovery probes (next retry in {delay:.0f}s) — "
                    f"check connectivity or API availability"
                )
                emit_sensor_status(sensor.name, "CIRCUIT_OPEN_PERSISTENT")
                _cb_persistent_warned = True
            return False
        try:
            ok = _do_fetch()
        except Exception as e:
            log.error(f"[Sensor/{sensor.name}] Fetch error: {e}")
            ok = False
        if ok:
            sensor.cb_record_success()
            _cb_persistent_warned = False  # Reset on recovery
        else:
            sensor.cb_record_failure()
        _check_health_change()
        return ok

    # Initial fetch: yield to event loop between attempts so HTTP requests
    # are not starved when many sensors start concurrently under gevent.
    _STARTUP_RETRY_DELAYS = [60, 300, 600]  # 1min, 5min, 10min
    time.sleep(0)  # yield to gevent event loop before first fetch
    if not _guarded_fetch():
        for delay in _STARTUP_RETRY_DELAYS:
            time.sleep(delay)
            if _guarded_fetch():
                break

    while True:
        time.sleep(sensor.poll_interval)
        _guarded_fetch()


# ── Cache cleanup worker ──
_CF_CACHE_MAX_SIZE = 1000  # Hard cap on _cf_scoring_cache entries


def _cache_cleanup_worker(registry=None):
    """Daemon thread: removes expired cache entries from all caches every hour.
    Also runs a full SQLite prune + WAL checkpoint once every 24 hours.
    """
    CLEANUP_INTERVAL  = 3600   # 1 hour
    DB_CLEANUP_EVERY  = 24     # cycles → once per day
    SEQ_LOG_WINDOW    = SEQUENCE_WINDOW  # 24h
    _cycle = 0

    while True:
        time.sleep(CLEANUP_INTERVAL)
        _cycle += 1
        try:
            now = time.time()

            # sequence_event_log: prune old events in SQLite
            _db.seq_cleanup(now - SEQ_LOG_WINDOW)

            # _cf_scoring_cache: sweep expired entries, then enforce MAX SIZE cap
            with _cf_cache_lock:
                for k in [k for k, v in list(_cf_scoring_cache.items())
                          if now - v["time"] > CACHE_EXPIRY * 3]:
                    _cf_scoring_cache.pop(k, None)
                # If still over cap after TTL eviction, drop oldest entries
                if len(_cf_scoring_cache) > _CF_CACHE_MAX_SIZE:
                    overflow = len(_cf_scoring_cache) - _CF_CACHE_MAX_SIZE
                    oldest = sorted(_cf_scoring_cache.items(), key=lambda x: x[1]["time"])
                    for k, _ in oldest[:overflow]:
                        _cf_scoring_cache.pop(k, None)

            # _asn_cache: sweep expired entries
            for k in [k for k, v in list(_asn_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _asn_cache.pop(k, None)

            # greynoise _ip_cache: remove entries older than TTL
            gn = registry.get("greynoise")
            if gn:
                with gn._ip_lock:
                    stale_ips = [k for k, v in list(gn._ip_cache.items())
                                 if now - v["fetched_at"] > gn.IP_CACHE_TTL]
                    for k in stale_ips:
                        gn._ip_cache.pop(k, None)

            log.info(f"[Cleanup] cycle={_cycle} baseline={_db.baseline_len()} "
                     f"seqlog={_db.seq_total()} "
                     f"cf_cache={len(_cf_scoring_cache)} asn_cache={len(_asn_cache)}")

            # Auto-reject stale pending intel items
            from radar.intel_queue import intel_queue as _iq
            _iq.auto_reject_stale()

            # Deterministic auto-judge recheck (Phase 4 commit 5).
            # Runs on the same cadence as auto_reject_stale; LLM-free, so
            # it works in air-gapped deployments. Decisions are tagged
            # analyst="auto:rule_*" for analyst-recall exclusion.
            try:
                from radar.intel_auto_judge import run_sweep as _aj_sweep
                _aj_summary = _aj_sweep(limit=200)
                if _aj_summary.get("confirm") or _aj_summary.get("reject"):
                    log.info(
                        "[AutoJudge] sweep evaluated=%d confirm=%d reject=%d pending=%d errors=%d",
                        _aj_summary.get("evaluated", 0),
                        _aj_summary.get("confirm", 0),
                        _aj_summary.get("reject", 0),
                        _aj_summary.get("pending", 0),
                        _aj_summary.get("errors", 0),
                    )
            except Exception as _aj_exc:
                log.warning("[AutoJudge] sweep failed: %s", _aj_exc)

            # Weekly observability: intel sensor audit + Layer 1 backtest.
            # Cadence-gated inside maybe_run() to once per
            # WEEKLY_DIAGNOSTICS_INTERVAL_HOURS (default 168h = 7d).
            # Read-only — no DB writes, no LLM calls (Phase 4 N3).
            try:
                from radar import diagnostics as _diag
                _diag.maybe_run()
            except Exception as _diag_exc:
                log.warning("[WeeklyDiag] maybe_run failed: %s", _diag_exc)

            # Phase B: per-scenario TL threshold calibrator (auto-tune).
            # Runs once per day on the cleanup_worker's hourly tick — a
            # separate cadence gate inside calibrate_all_scenarios is not
            # needed because the governor's cooldown (default 72h per key)
            # bounds the actual write rate. The recall_metrics CI gate +
            # bounded magnitude (10%) provide additional safety.
            # Phase B v1: emits proposals to threshold_history; actual
            # *application* in derive_tl is gated on a separate feature
            # flag (future commit) so the conclusion_diff_log 100% match
            # invariant is preserved during shadow rollout.
            if _cycle % 24 == 1:  # ~daily (cleanup_worker is hourly)
                try:
                    from radar.calibration.tl_threshold_calibrator import (
                        calibrate_all_scenarios,
                    )
                    cal_result = calibrate_all_scenarios()
                    accepted = sum(r.get("accepted", 0) for r in cal_result.values())
                    submitted = sum(r.get("submitted", 0) for r in cal_result.values())
                    if submitted:
                        log.info(
                            "[TLCalib] daily pass: %d scenarios, %d submitted, %d accepted",
                            len(cal_result), submitted, accepted,
                        )
                except Exception as _tlc_exc:
                    log.warning("[TLCalib] calibrate_all_scenarios failed: %s", _tlc_exc)

            # LLM pipeline health summary (hourly visibility)
            try:
                from radar.config import LLM_ENABLED
                stats = _iq.stats()
                llm_calls = _db.llm_call_stats(hours=1)
                total_calls = llm_calls.get("total", 0)
                log.info(
                    f"[LLM-Health] enabled={LLM_ENABLED} "
                    f"calls_1h={total_calls} "
                    f"intel(pending={stats.get('pending',0)} "
                    f"auto={stats.get('auto_confirmed',0)} "
                    f"confirmed={stats.get('confirmed',0)} "
                    f"total={stats.get('total',0)})"
                )
            except Exception:
                pass  # non-critical diagnostic

            # Hourly: WAL checkpoint (flush WAL to main DB file)
            _db.wal_checkpoint()

            # Hourly: persist legacy access telemetry (Safe Rename Pattern SR4).
            # Cheap UPSERT — runs after the WAL checkpoint so a crash here
            # at worst loses the increments since the last hour, never
            # data already on disk.
            try:
                from radar import legacy_telemetry as _lt
                flushed = _lt.flush_to_db(_db)
                if flushed:
                    log.info(f"[Cleanup] legacy_access flushed: {flushed} keys")
            except Exception as e:
                log.error(f"[Cleanup] legacy_access flush error: {e}")

            # v1 sunset observation hook removed 2026-04-29 alongside the
            # early ADR-V2-003 sunset. The summarize_v1_sunset helper that
            # used to live here was reading from radar.conclusions.v1_sunset,
            # which has been deleted.

            # Daily: prune SQLite tables
            if _cycle % DB_CLEANUP_EVERY == 0:
                _db.periodic_cleanup()

        except Exception as e:
            log.error(f"[Cleanup] Error: {e}")


# ── Cross-source corroboration worker ────────────────────────────────────────

def _corroboration_worker():
    """Daemon thread: runs the cross-source corroboration pass every 30 minutes.
    Looks for independent-source signals in the same theater+time window and
    synthesises them into a single 'corroborated' intel item via LLM.
    """
    CORR_INTERVAL = 1800  # 30 minutes
    # Stagger startup so the main sensor fetches have time to populate the DB
    time.sleep(300)  # 5-minute initial delay
    while True:
        try:
            from radar.intel_corroboration import corroboration_engine
            created = corroboration_engine.run_once()
            if created:
                log.info(f"[Corroboration] Worker: {created} new corroborated items")
        except Exception as e:
            log.error(f"[Corroboration] Worker error: {e}")
        time.sleep(CORR_INTERVAL)
