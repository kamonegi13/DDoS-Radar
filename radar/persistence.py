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


def save_state() -> None:
    """Save per-sensor last-fetch caches to SQLite.

    All other state (HOD baselines, time series, alerts, sequence events)
    is written directly to SQLite by the producing modules, so only
    sensor snapshot caches need periodic saving.
    """
    try:
        from radar.database import db
        from radar import registry  # noqa: E402 — deferred to break circular import
        sc_count = 0
        for name, sensor in registry._sensors.items():
            cache = sensor.get_cache()
            if cache:
                db.sensor_cache_set(name, sensor._cache_time, cache)
                sc_count += 1
        log.info(
            f"[Persist] Saved sensor caches: {sc_count} sensors, "
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
    log.info("[Persist] Restore complete.")


def _persistence_worker() -> None:
    """Background thread: periodically save sensor caches."""
    while True:
        time.sleep(PERSISTENCE_SAVE_INTERVAL)
        save_state()
