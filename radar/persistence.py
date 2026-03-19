"""radar.persistence -- Periodic JSON state save / restore."""
from __future__ import annotations
import json
import logging
import os
import time
import threading
import atexit
from radar.config import (
    PERSISTENCE_DIR, PERSISTENCE_STATE_FILE, PERSISTENCE_SAVE_INTERVAL,
    HOD_BASELINE_DAYS, HOD_MAX_ENTRIES, SEQUENCE_WINDOW,
)
from radar.state import (
    baseline_cache, airspace_baseline, hod_baseline_db,
    checkhost_hod_db, bgp_hod_db, gdelt_dow_db,
    time_series_db, time_series_ts_db, time_series_l3_db, time_series_l7_db,
    alert_timeline, sequence_event_log,
)

log = logging.getLogger("radar")

_persist_lock = threading.Lock()


def save_state() -> None:
    """Atomically snapshot critical in-memory state to persistence/state.json.

    Called every PERSISTENCE_SAVE_INTERVAL seconds by background thread,
    and once on clean shutdown via atexit.  Uses .tmp → os.replace() to avoid
    partial writes on crash.
    """
    with _persist_lock:
        try:
            os.makedirs(PERSISTENCE_DIR, exist_ok=True)

            # Collect per-sensor last-fetch caches (lazy import to avoid circular)
            from radar import registry  # noqa: E402 — deferred to break circular import
            sensor_caches: dict = {}
            for name, sensor in registry._sensors.items():
                cache = sensor.get_cache()
                if cache:
                    sensor_caches[name] = {
                        "cache":      cache,
                        "cache_time": sensor._cache_time,
                    }

            state = {
                "version":   4,
                "saved_at":  time.time(),
                # ── Accumulated / long-lived (no expiry on restore) ──
                "baseline_cache":     dict(baseline_cache),
                "airspace_baseline":  dict(airspace_baseline),
                "hod_baseline_db":    {k: list(v)[-HOD_MAX_ENTRIES:] for k, v in hod_baseline_db.items()},
                "checkhost_hod_db":   {k: list(v)[-HOD_MAX_ENTRIES:] for k, v in checkhost_hod_db.items()},
                "bgp_hod_db":         {k: list(v)[-(HOD_BASELINE_DAYS * 24):] for k, v in bgp_hod_db.items()},
                "gdelt_dow_db":       {k: list(v)[-(20 * 7):] for k, v in gdelt_dow_db.items()},
                # ── Time-series: scored history for velocity/ambush ──
                # Trim to last 15 entries to cap file size (scoring only needs recent history)
                "time_series_ts_db":  {k: list(v)[-15:] for k, v in time_series_ts_db.items()},
                "time_series_db":     {k: list(v)[-15:] for k, v in time_series_db.items()},
                "time_series_l3_db":  {k: list(v)[-15:] for k, v in time_series_l3_db.items()},
                "time_series_l7_db":  {k: list(v)[-15:] for k, v in time_series_l7_db.items()},
                # ── Alert / event history ──
                "alert_timeline":     list(alert_timeline),
                "sequence_event_log": {k: list(v) for k, v in sequence_event_log.items()},
                # ── Sensor last-fetch snapshots ──
                "sensor_caches":      sensor_caches,
            }

            tmp = PERSISTENCE_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(state, f, default=str, ensure_ascii=False)
            os.replace(tmp, PERSISTENCE_STATE_FILE)   # atomic on POSIX; near-atomic on Windows

            hod_total  = sum(len(v) for v in hod_baseline_db.values())
            ch_total   = sum(len(v) for v in checkhost_hod_db.values())
            bgp_total  = sum(len(v) for v in bgp_hod_db.values())
            dow_total  = sum(len(v) for v in gdelt_dow_db.values())
            log.info(f"[Persist] Saved — baseline={len(baseline_cache)}, "
                  f"hod={hod_total}pts, ch_hod={ch_total}pts, bgp_hod={bgp_total}pts, "
                  f"dow={dow_total}pts, timeline={len(alert_timeline)}, sensors={len(sensor_caches)}")
        except Exception as exc:
            log.error(f"[Persist] Save error: {exc}")


def restore_state() -> None:
    """Restore state from persistence/state.json at startup.

    Restore policy per data type:
      baseline_cache    — always (no expiry; weeks to rebuild)
      airspace_baseline — always (no expiry; rolling average)
      time_series_*     — entries within 25 h (SEQUENCE_WINDOW + 1 h margin)
      alert_timeline    — all entries (deque maxlen evicts extras automatically)
      sequence_event_log— events within SEQUENCE_WINDOW (24 h)
      sensor._cache     — within 3 × poll_interval (snapshot only, not accumulated)
    """
    if not os.path.exists(PERSISTENCE_STATE_FILE):
        log.info("[Persist] No state file — starting fresh.")
        return

    with _persist_lock:
        try:
            with open(PERSISTENCE_STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)

            saved_at = float(state.get("saved_at", 0))
            age_h    = (time.time() - saved_at) / 3600
            log.info(f"[Persist] Restoring state from {age_h:.1f} h ago "
                  f"(version={state.get('version', 1)}) ...")

            # ── baseline_cache: no expiry ─────────────────────────────
            loaded = state.get("baseline_cache", {})
            baseline_cache.update(loaded)
            log.info(f"[Persist]   baseline_cache    : {len(loaded)} entries")

            # ── airspace_baseline: no expiry ──────────────────────────
            loaded = state.get("airspace_baseline", {})
            airspace_baseline.update(loaded)
            log.info(f"[Persist]   airspace_baseline : {len(loaded)} airports")

            # ── hod_baseline_db: no expiry (weeks to rebuild) ─────────
            hod_total = 0
            try:
                for theater, entries in state.get("hod_baseline_db", {}).items():
                    valid = [(float(ts), float(v)) for ts, v in entries][-HOD_MAX_ENTRIES:]
                    if valid:
                        hod_baseline_db[theater] = valid
                        hod_total += len(valid)
            except Exception as exc:
                log.warning(f"[Persist] hod_baseline_db: restore error — {exc}")
            log.info(f"[Persist]   hod_baseline_db   : {hod_total} hourly points")

            # ── checkhost_hod_db: no expiry ───────────────────────────
            ch_total = 0
            try:
                for theater, entries in state.get("checkhost_hod_db", {}).items():
                    valid = [(float(ts), float(v)) for ts, v in entries][-HOD_MAX_ENTRIES:]
                    if valid:
                        checkhost_hod_db[theater] = valid
                        ch_total += len(valid)
            except Exception as exc:
                log.warning(f"[Persist] checkhost_hod_db: restore error — {exc}")
            log.info(f"[Persist]   checkhost_hod_db  : {ch_total} hourly points")

            # ── bgp_hod_db: no expiry ─────────────────────────────────
            bgp_total = 0
            try:
                for theater, entries in state.get("bgp_hod_db", {}).items():
                    valid = [(float(ts), float(v)) for ts, v in entries][-(HOD_BASELINE_DAYS * 24):]
                    if valid:
                        bgp_hod_db[theater] = valid
                        bgp_total += len(valid)
            except Exception as exc:
                log.warning(f"[Persist] bgp_hod_db: restore error — {exc}")
            log.info(f"[Persist]   bgp_hod_db        : {bgp_total} hourly points")

            # ── gdelt_dow_db: no expiry ───────────────────────────────
            dow_total = 0
            try:
                for theater, entries in state.get("gdelt_dow_db", {}).items():
                    valid = [(float(d), int(w), float(t)) for d, w, t in entries][-(20 * 7):]
                    if valid:
                        gdelt_dow_db[theater] = valid
                        dow_total += len(valid)
            except Exception as exc:
                log.warning(f"[Persist] gdelt_dow_db: restore error — {exc}")
            log.info(f"[Persist]   gdelt_dow_db      : {dow_total} day-of-week points")

            # ── time_series_ts_db: prune entries older than 25 h ──────
            ts_cutoff = time.time() - (SEQUENCE_WINDOW + 3600)
            total_pts  = 0
            try:
                for theater, entries in state.get("time_series_ts_db", {}).items():
                    valid = [(float(ts), float(v)) for ts, v in entries if float(ts) >= ts_cutoff]
                    if valid:
                        time_series_ts_db[theater] = valid
                        total_pts += len(valid)
            except Exception as exc:
                log.warning(f"[Persist] time_series_ts_db: restore error — {exc}")
            log.info(f"[Persist]   time_series_ts_db : {total_pts} points")

            # ── plain time_series (value-only): bounded lists, restore trimmed to 15
            try:
                for db_name, db_obj in [
                    ("time_series_db",    time_series_db),
                    ("time_series_l3_db", time_series_l3_db),
                    ("time_series_l7_db", time_series_l7_db),
                ]:
                    for theater, entries in state.get(db_name, {}).items():
                        db_obj[theater] = list(entries)[-15:]
            except Exception as exc:
                log.warning(f"[Persist] time_series_db: restore error — {exc}")

            # ── alert_timeline: restore all; deque maxlen handles overflow
            saved_tl = state.get("alert_timeline", [])
            for entry in saved_tl:
                alert_timeline.append(entry)
            log.info(f"[Persist]   alert_timeline    : {len(saved_tl)} records")

            # ── sequence_event_log: only events within SEQUENCE_WINDOW ─
            seq_cutoff  = time.time() - SEQUENCE_WINDOW
            seq_total   = 0
            for theater, events in state.get("sequence_event_log", {}).items():
                valid = [e for e in events if float(e.get("ts", 0)) >= seq_cutoff]
                if valid:
                    sequence_event_log[theater] = valid
                    seq_total += len(valid)
            log.info(f"[Persist]   sequence_event_log: {seq_total} events")

            # ── sensor caches: within 3 × poll_interval ───────────────
            # Sensor._cache = last API snapshot (NOT accumulated).
            # If expired, let the sensor's next scheduled fetch refresh it.
            from radar import registry as _reg  # noqa: E402 — deferred to break circular import
            sc_ok = sc_skip = 0
            for sname, data in state.get("sensor_caches", {}).items():
                sensor = _reg.get(sname)
                if sensor is None:
                    continue
                cache_age = time.time() - float(data.get("cache_time", 0))
                max_age   = sensor.poll_interval * 3
                if cache_age <= max_age and data.get("cache"):
                    sensor._cache      = data["cache"]
                    sensor._cache_time = float(data["cache_time"])
                    sc_ok += 1
                else:
                    sc_skip += 1
            log.info(f"[Persist]   sensor_caches     : {sc_ok} restored, {sc_skip} expired")

            log.info("[Persist] Restore complete.")
        except Exception as exc:
            log.error(f"[Persist] Restore error: {exc} — continuing with empty state")


def _persistence_worker() -> None:
    """Background thread: auto-save every PERSISTENCE_SAVE_INTERVAL seconds."""
    while True:
        time.sleep(PERSISTENCE_SAVE_INTERVAL)
        save_state()


atexit.register(save_state)  # save on clean shutdown (Ctrl+C, SIGTERM)
_persistence_thread = threading.Thread(target=_persistence_worker, daemon=True, name="persistence")
_persistence_thread.start()
restore_state()              # restore before first scoring cycle
