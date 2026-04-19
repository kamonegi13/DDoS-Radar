"""radar.persistence -- SQLite-backed state persistence.

Replaces the original JSON flat-file persistence with SQLite (via radar.database).
Sensor caches are saved periodically to SQLite; all other state is written
directly by the modules that produce it (scoring, sensors, routes).
"""
from __future__ import annotations
import logging
import time
import threading
from radar.config import (
    PERSISTENCE_DIR, PERSISTENCE_STATE_FILE, PERSISTENCE_SAVE_INTERVAL,
)

log = logging.getLogger("radar")

# Track the cache_time of each sensor at the last successful save.
# Saves are skipped when no sensor cache has been updated since the last run.
_last_saved_cache_times: dict[str, float] = {}


def save_state() -> None:
    """Save per-sensor last-fetch caches to SQLite.

    All other state (HOD baselines, time series, alerts, sequence events)
    is written directly to SQLite by the producing modules, so only
    sensor snapshot caches need periodic saving.

    Skips sensors whose cache_time is unchanged since the last save to
    avoid redundant SQLite writes during periods of no new data.
    """
    try:
        from radar.database import db
        from radar import registry  # noqa: E402 — deferred to break circular import
        sc_count = 0
        with registry._lock:
            sensor_snapshot = list(registry._sensors.items())
        for name, sensor in sensor_snapshot:
            ct = sensor._cache_time
            if not ct:
                continue
            if ct == _last_saved_cache_times.get(name):
                continue  # Unchanged since last save
            cache = sensor.get_cache()
            if cache:
                db.sensor_cache_set(name, ct, cache)
                _last_saved_cache_times[name] = ct
                sc_count += 1
        if sc_count == 0:
            log.debug("[Persist] No sensor cache changes — save skipped")
            return
        log.info(
            f"[Persist] Saved sensor caches: {sc_count} sensors updated, "
            f"hod={db.hod_total_points('hod_baseline')}pts, "
            f"ch_hod={db.hod_total_points('checkhost_hod')}pts, "
            f"bgp_hod={db.hod_total_points('bgp_hod')}pts, "
            f"dow={db.gdelt_dow_total_points()}pts, "
            f"timeline={db.alert_count()}, "
            f"ts={db.ts_total_points()}pts"
        )
    except Exception as exc:
        log.error(f"[Persist] Save error: {exc}")


def restore_state() -> None:
    """Restore state from SQLite at startup.

    1. Run JSON→SQLite migration if needed (first run after upgrade).
    2. Restore sensor caches from SQLite into in-memory sensor objects.
    """
    from radar.database import db
    from radar.migration import migrate_json_to_sqlite

    # Attempt one-time migration from legacy JSON
    migrate_json_to_sqlite(PERSISTENCE_STATE_FILE)

    # Log current DB stats
    log.info(
        f"[Persist] SQLite state — "
        f"baseline={db.baseline_len()}, "
        f"airspace={db.airspace_len()}, "
        f"hod={db.hod_total_points('hod_baseline')}pts, "
        f"ch_hod={db.hod_total_points('checkhost_hod')}pts, "
        f"bgp_hod={db.hod_total_points('bgp_hod')}pts, "
        f"dow={db.gdelt_dow_total_points()}pts, "
        f"ts={db.ts_total_points()}pts, "
        f"timeline={db.alert_count()}, "
        f"seq={db.seq_total()}events"
    )

    # Restore sensor caches into memory
    from radar import registry as _reg  # noqa: E402
    sc_ok = sc_skip = 0
    for sname in list(_reg._sensors.keys()):
        sensor = _reg.get(sname)
        if sensor is None:
            continue
        cached = db.sensor_cache_get(sname)
        if not cached:
            continue
        cache_age = time.time() - cached["cache_time"]
        max_age = sensor.poll_interval * 3
        if cache_age <= max_age and cached["cache"]:
            sensor._cache = cached["cache"]
            sensor._cache_time = cached["cache_time"]
            sc_ok += 1
        else:
            sc_skip += 1
    log.info(f"[Persist] Sensor caches: {sc_ok} restored, {sc_skip} expired")

    # Reapply credibility bootstrap weights to existing llm_sources rows and
    # promote any pending items that now qualify for auto-confirm. Both
    # operations are idempotent: reseed only touches rows with no analyst
    # feedback, and promotion only affects pending items that already meet the
    # auto-confirm confidence floor. Run on every startup so pending items
    # created before a bootstrap change (or under a past bug) get promoted as
    # soon as the code catches up to the intended behavior.
    try:
        from radar.intel_queue import intel_queue
        reseeded = intel_queue.reseed_existing_credibility()
        if reseeded:
            log.info(f"[Persist] Credibility bootstrap: reseeded {reseeded} sources")
        promoted = intel_queue.promote_pending_after_reseed()
        if promoted:
            log.info(f"[Persist] Credibility bootstrap: promoted {promoted} pending items")
        floored = intel_queue.enforce_archetype_floor()
        if floored:
            log.info(f"[Persist] Archetype floor: raised {floored} sources to minimum credibility")
    except Exception as exc:
        log.warning(f"[Persist] Credibility reseed failed: {exc}")

    log.info("[Persist] Restore complete.")


def _persistence_worker() -> None:
    """Background thread: periodically save sensor caches."""
    while True:
        time.sleep(PERSISTENCE_SAVE_INTERVAL)
        save_state()
