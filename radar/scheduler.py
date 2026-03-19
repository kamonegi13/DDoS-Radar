"""radar.scheduler -- Background sensor scheduler and cache cleanup."""
from __future__ import annotations
import logging
import time
import threading
from radar.config import (
    DEFAULT_CORE, DEFAULT_CORRELATES, DEFAULT_ADVERSARIES, DEFAULT_PINS,
    CF_HEADERS, OWM_API_KEY,
    GDELT_TONE_ALERT_THRESHOLD, GDELT_HISTORY_WINDOW,
    CACHE_EXPIRY, SEQUENCE_WINDOW,
)
from radar.sensors.base import BaseSensor
from radar.state import _cf_scoring_cache
from radar.database import db as _db
from radar.scoring import _asn_cache

log = logging.getLogger("radar")

def _build_default_context() -> dict:
    """Build sensor context based on default config. Used by the background scheduler."""
    return {
        "all_targets":         sorted(set([DEFAULT_CORE] + DEFAULT_CORRELATES + DEFAULT_PINS)),
        "strategic_theaters":  sorted(set([DEFAULT_CORE] + DEFAULT_CORRELATES)),
        "adversary_states":    DEFAULT_ADVERSARIES,
        "cf_headers":          CF_HEADERS,
        "owm_api_key":         OWM_API_KEY,
        "weather_conditions":  {},
        "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD,
        "gdelt_history_window": GDELT_HISTORY_WINDOW,
    }

def _sensor_scheduler_worker(sensor: BaseSensor, registry=None):
    """Dedicated background fetch thread for a sensor.
    - Normal: periodic fetch every poll_interval
    - On failure: retry up to 3 times at shorter intervals [5min, 10min, 30min]
    - Emits sensor_status via WS on health changes
    """
    from radar.ws import emit_sensor_status

    _RETRY_DELAYS = [d for d in [300, 600, 1800] if d < sensor.poll_interval]
    _last_health = sensor.health

    def _do_fetch() -> bool:
        ctx = _build_default_context()
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

    try:
        success = _do_fetch()
    except Exception as e:
        log.error(f"[Sensor/{sensor.name}] Initial fetch error: {e}")
        success = False
    _check_health_change()

    while True:
        if not success and _RETRY_DELAYS:
            for delay in _RETRY_DELAYS:
                time.sleep(delay)
                try:
                    success = _do_fetch()
                    _check_health_change()
                    if success:
                        log.info(f"[Sensor/{sensor.name}] Retry succeeded after {delay}s")
                        break
                except Exception as e:
                    log.warning(f"[Sensor/{sensor.name}] Retry error (delay={delay}s): {e}")
                    _check_health_change()
        else:
            time.sleep(sensor.poll_interval)

        try:
            success = _do_fetch()
        except Exception as e:
            log.error(f"[Sensor/{sensor.name}] Scheduled fetch error: {e}")
            success = False
        _check_health_change()


# ── Cache cleanup worker ──
def _cache_cleanup_worker(registry=None):
    """Daemon thread: removes expired cache entries from all caches every hour."""
    CLEANUP_INTERVAL = 3600  # 1 hour
    SEQ_LOG_WINDOW   = SEQUENCE_WINDOW  # 24h
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            now = time.time()

            # sequence_event_log: prune old events in SQLite
            _db.seq_cleanup(now - SEQ_LOG_WINDOW)

            # _cf_scoring_cache / _asn_cache: sweep expired in-memory entries
            for k in [k for k, v in list(_cf_scoring_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _cf_scoring_cache.pop(k, None)
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

            log.info(f"[Cleanup] baseline={_db.baseline_len()} seqlog={_db.seq_total()} "
                  f"cf_cache={len(_cf_scoring_cache)} asn_cache={len(_asn_cache)}")
        except Exception as e:
            log.error(f"[Cleanup] Error: {e}")
