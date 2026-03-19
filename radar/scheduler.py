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
from radar.state import (
    baseline_cache, sequence_event_log, _cf_scoring_cache,
)
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
    """
    # Use only retry intervals shorter than poll_interval
    # (Short-cycle sensors like IODA=5min need no retry → results in empty list)
    _RETRY_DELAYS = [d for d in [300, 600, 1800] if d < sensor.poll_interval]

    def _do_fetch() -> bool:
        ctx = _build_default_context()
        if sensor.name == "gdelt":
            owm = registry.get("openweather")
            if owm: ctx["weather_conditions"] = owm.get_cache().get("conditions", {})
        sensor.fetch(ctx)
        log = sensor.get_fetch_log()
        return bool(log and log[-1].get("success"))

    # Fetch immediately at startup
    try:
        success = _do_fetch()
    except Exception as e:
        log.error(f"[Sensor/{sensor.name}] Initial fetch error: {e}")
        success = False

    while True:
        if not success and _RETRY_DELAYS:
            # On failure: retry at shorter intervals
            for delay in _RETRY_DELAYS:
                time.sleep(delay)
                try:
                    success = _do_fetch()
                    if success:
                        log.info(f"[Sensor/{sensor.name}] Retry succeeded after {delay}s")
                        break
                except Exception as e:
                    log.warning(f"[Sensor/{sensor.name}] Retry error (delay={delay}s): {e}")
            # After retries complete, resume normal poll_interval wait
        else:
            time.sleep(sensor.poll_interval)

        try:
            success = _do_fetch()
        except Exception as e:
            log.error(f"[Sensor/{sensor.name}] Scheduled fetch error: {e}")
            success = False


# ── Cache cleanup worker ──
def _cache_cleanup_worker(registry=None):
    """Daemon thread: removes expired cache entries from all caches every hour."""
    CLEANUP_INTERVAL = 3600  # 1 hour
    BASELINE_MAX_AGE = 86400 * 7   # baseline expires after 7 days
    SEQ_LOG_WINDOW   = SEQUENCE_WINDOW  # 24h
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            now = time.time()
            # baseline_cache: remove theaters not updated for 7+ days
            stale = [k for k, v in list(baseline_cache.items()) if now - v.get("time", 0) > BASELINE_MAX_AGE]
            for k in stale:
                baseline_cache.pop(k, None)

            # sequence_event_log: re-trim entries older than 24h per theater and remove empty theaters
            cutoff = now - SEQ_LOG_WINDOW
            for th in list(sequence_event_log.keys()):
                sequence_event_log[th] = [e for e in sequence_event_log[th] if e["ts"] >= cutoff]
                if not sequence_event_log[th]:
                    del sequence_event_log[th]

            # _cf_scoring_cache / _asn_cache: sweep all expired entries as a precaution
            for k in [k for k, v in list(_cf_scoring_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _cf_scoring_cache.pop(k, None)
            for k in [k for k, v in list(_asn_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _asn_cache.pop(k, None)

            # greynoise _ip_cache: remove entries older than 24h
            gn = registry.get("greynoise")
            if gn:
                with gn._ip_lock:
                    stale_ips = [k for k, v in list(gn._ip_cache.items())
                                 if now - v["fetched_at"] > gn.IP_CACHE_TTL]
                    for k in stale_ips:
                        gn._ip_cache.pop(k, None)

            log.info(f"[Cleanup] baseline_cache={len(baseline_cache)} seqlog={len(sequence_event_log)} "
                  f"cf_cache={len(_cf_scoring_cache)} asn_cache={len(_asn_cache)}")
        except Exception as e:
            log.error(f"[Cleanup] Error: {e}")


