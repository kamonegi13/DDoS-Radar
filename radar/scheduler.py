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

            # Hourly: v1 sunset observation summary (ADR-V2-003).
            # Single-line digest of residual v1 route hits so the T+90d
            # removal decision is driven by observed evidence, not guesswork.
            # Always emit (even on zero) — sustained zero is the green light.
            try:
                from radar import legacy_telemetry as _lt2
                summary = _lt2.summarize_v1_sunset()
                if summary.total_hits == 0:
                    log.info(
                        f"[V1Sunset] residual=0 routes "
                        f"days_remaining={summary.days_remaining_until_sunset:.1f}"
                    )
                else:
                    top = ", ".join(
                        f"{label}={count}"
                        for label, count, _ in summary.per_route[:3]
                    )
                    log.info(
                        f"[V1Sunset] residual_routes={summary.total_routes} "
                        f"hits={summary.total_hits} "
                        f"last_seen_h_ago={summary.age_hours_since_last_seen:.1f} "
                        f"days_remaining={summary.days_remaining_until_sunset:.1f} "
                        f"top=[{top}]"
                    )
            except Exception as e:
                log.error(f"[Cleanup] v1 sunset summary error: {e}")

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
