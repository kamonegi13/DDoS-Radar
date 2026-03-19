"""radar.migration -- One-time JSON → SQLite migration."""
from __future__ import annotations
import json
import logging
import os
import time

log = logging.getLogger("radar")


def migrate_json_to_sqlite(json_path: str) -> bool:
    """Migrate state.json data into SQLite. Returns True if migration ran."""
    from radar.database import db

    if db.schema_version() >= 1:
        return False
    if not os.path.exists(json_path):
        db.set_schema_version(1)
        log.info("[Migration] No state.json found — starting fresh with SQLite.")
        return False

    log.info("[Migration] Migrating state.json → SQLite ...")
    t0 = time.time()

    with open(json_path, "r", encoding="utf-8") as f:
        state = json.load(f)

    # ── baseline_cache ──
    bc_count = 0
    for theater, data in state.get("baseline_cache", {}).items():
        ts = data.get("time", 0) if isinstance(data, dict) else 0
        db.baseline_set(theater, data, ts)
        bc_count += 1

    # ── airspace_baseline ──
    ab_count = 0
    for code, data in state.get("airspace_baseline", {}).items():
        db.airspace_set(code, data)
        ab_count += 1

    # ── hod_baseline_db ──
    hod_count = 0
    for theater, entries in state.get("hod_baseline_db", {}).items():
        pairs = [(int(float(ts)), float(v)) for ts, v in entries]
        if pairs:
            db.hod_record_many("hod_baseline", theater, pairs)
            hod_count += len(pairs)

    # ── checkhost_hod_db ──
    ch_count = 0
    for theater, entries in state.get("checkhost_hod_db", {}).items():
        pairs = [(int(float(ts)), float(v)) for ts, v in entries]
        if pairs:
            db.hod_record_many("checkhost_hod", theater, pairs)
            ch_count += len(pairs)

    # ── bgp_hod_db ──
    bgp_count = 0
    for theater, entries in state.get("bgp_hod_db", {}).items():
        pairs = [(int(float(ts)), float(v)) for ts, v in entries]
        if pairs:
            db.hod_record_many("bgp_hod", theater, pairs)
            bgp_count += len(pairs)

    # ── gdelt_dow_db ──
    dow_count = 0
    for theater, entries in state.get("gdelt_dow_db", {}).items():
        for d, w, t in entries:
            db.gdelt_dow_record(theater, int(float(d)), int(w), float(t))
            dow_count += 1

    # ── time_series_ts_db ──
    tsts_count = 0
    for theater, entries in state.get("time_series_ts_db", {}).items():
        for ts, val in entries:
            db.ts_append(theater, float(ts), float(val), max_entries=30)
            tsts_count += 1

    # ── time_series_db / l3 / l7 ──
    for db_name, series_type in [("time_series_db", "combined"),
                                  ("time_series_l3_db", "l3"),
                                  ("time_series_l7_db", "l7")]:
        for theater, values in state.get(db_name, {}).items():
            for v in list(values)[-15:]:
                db.series_append(theater, series_type, float(v), max_entries=15)

    # ── alert_timeline ──
    at_count = 0
    for entry in state.get("alert_timeline", []):
        db.alert_append(entry, max_entries=288)
        at_count += 1

    # ── sequence_event_log ──
    seq_count = 0
    for theater, events in state.get("sequence_event_log", {}).items():
        for e in events:
            db.seq_append(theater, float(e["ts"]), e["type"], e.get("meta", {}))
            seq_count += 1

    # ── sensor_caches ──
    sc_count = 0
    for sname, data in state.get("sensor_caches", {}).items():
        cache = data.get("cache")
        cache_time = float(data.get("cache_time", 0))
        if cache:
            db.sensor_cache_set(sname, cache_time, cache)
            sc_count += 1

    db.set_schema_version(1)

    # Rename original to backup
    backup = json_path + ".migrated"
    try:
        os.rename(json_path, backup)
        log.info(f"[Migration] Renamed {json_path} → {backup}")
    except OSError as e:
        log.warning(f"[Migration] Could not rename state.json: {e}")

    elapsed = time.time() - t0
    log.info(
        f"[Migration] Complete in {elapsed:.1f}s — "
        f"baseline={bc_count}, airspace={ab_count}, hod={hod_count}, "
        f"ch_hod={ch_count}, bgp_hod={bgp_count}, dow={dow_count}, "
        f"ts={tsts_count}, alerts={at_count}, seq={seq_count}, sensors={sc_count}"
    )
    return True
