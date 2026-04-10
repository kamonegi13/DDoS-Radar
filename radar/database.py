"""radar.database -- SQLite persistence layer.

Thread-safe SQLite backend replacing dict/deque state.
One connection per thread via threading.local(), WAL mode for concurrency.

Usage:
    from radar.database import db
    db.hod_record("hod_baseline", "TW", hour_bucket, avg_spike)
    same_hour = db.hod_same_hour("hod_baseline", "TW", target_hod, before_bucket)
"""
from __future__ import annotations
import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Optional

log = logging.getLogger("radar")

# ── Schema SQL ────────────────────────────────────────────────────────────────
_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA wal_autocheckpoint = 1000;

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER NOT NULL,
    migrated_at REAL NOT NULL
);

-- baseline_cache: {theater: {l3: {...}, l7: {...}}}
CREATE TABLE IF NOT EXISTS baseline_cache (
    theater    TEXT PRIMARY KEY,
    updated_at REAL NOT NULL,
    data_json  TEXT NOT NULL
);

-- airspace_baseline: {airport_code: {readings: [...], avg: float}}
CREATE TABLE IF NOT EXISTS airspace_baseline (
    airport_code TEXT PRIMARY KEY,
    data_json    TEXT NOT NULL
);

-- HOD baselines (CF spike, CheckHost, BGP) — identical structure
CREATE TABLE IF NOT EXISTS hod_baseline (
    theater     TEXT NOT NULL,
    hour_bucket INTEGER NOT NULL,
    avg_spike   REAL NOT NULL,
    PRIMARY KEY (theater, hour_bucket)
);

CREATE TABLE IF NOT EXISTS checkhost_hod (
    theater      TEXT NOT NULL,
    hour_bucket  INTEGER NOT NULL,
    success_rate REAL NOT NULL,
    PRIMARY KEY (theater, hour_bucket)
);

CREATE TABLE IF NOT EXISTS bgp_hod (
    theater      TEXT NOT NULL,
    hour_bucket  INTEGER NOT NULL,
    prefix_count REAL NOT NULL,
    PRIMARY KEY (theater, hour_bucket)
);

-- GDELT day-of-week tones
CREATE TABLE IF NOT EXISTS gdelt_dow (
    theater    TEXT NOT NULL,
    day_bucket INTEGER NOT NULL,
    weekday    INTEGER NOT NULL,
    tone       REAL NOT NULL,
    PRIMARY KEY (theater, day_bucket)
);
CREATE INDEX IF NOT EXISTS idx_gdelt_dow_weekday
    ON gdelt_dow (theater, weekday);

-- time_series_ts: timestamped scored history
CREATE TABLE IF NOT EXISTS time_series_ts (
    theater TEXT NOT NULL,
    ts      REAL NOT NULL,
    value   REAL NOT NULL,
    PRIMARY KEY (theater, ts)
);

-- time_series value-only (combined/l3/l7)
CREATE TABLE IF NOT EXISTS time_series (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    theater     TEXT NOT NULL,
    series_type TEXT NOT NULL,
    value       REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_time_series_theater
    ON time_series (theater, series_type, id);

-- alert_timeline (ring buffer, max 288)
CREATE TABLE IF NOT EXISTS alert_timeline (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_timeline_ts
    ON alert_timeline (ts);

-- sequence_event_log
CREATE TABLE IF NOT EXISTS sequence_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    theater    TEXT NOT NULL,
    ts         REAL NOT NULL,
    event_type TEXT NOT NULL,
    meta_json  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_seq_events_theater_ts
    ON sequence_events (theater, ts);

-- threat_history (ring buffer, max 20)
CREATE TABLE IF NOT EXISTS threat_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    threat_level INTEGER NOT NULL
);

-- sensor_caches: per-sensor last-fetch snapshot
CREATE TABLE IF NOT EXISTS sensor_caches (
    sensor_name TEXT PRIMARY KEY,
    cache_time  REAL NOT NULL,
    cache_json  TEXT NOT NULL
);

-- Phase 2: Adaptive Z-score per-sensor running statistics (Welford's algorithm)
CREATE TABLE IF NOT EXISTS sensor_zscore_stats (
    sensor_name  TEXT NOT NULL,
    theater      TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    mean         REAL NOT NULL DEFAULT 0.0,
    m2           REAL NOT NULL DEFAULT 0.0,
    last_updated REAL NOT NULL,
    PRIMARY KEY (sensor_name, theater)
);

-- Phase 3: Persistent sensor fetch log for reliability tracking
CREATE TABLE IF NOT EXISTS sensor_fetch_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_name  TEXT NOT NULL,
    ts           REAL NOT NULL,
    success      INTEGER NOT NULL DEFAULT 1,
    duration_ms  INTEGER DEFAULT 0,
    http_status  INTEGER DEFAULT 0,
    records      INTEGER DEFAULT 0,
    error        TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_fetch_log_sensor_ts ON sensor_fetch_log (sensor_name, ts);

-- llm_call_log: every LLM analysis attempt and its outcome.
-- Lets operators distinguish "sensor silent" from "LLM down" from "threshold too high".
-- caller    : sensor name (e.g. hacktivist_intel)
-- outcome   : ok | parse_failed | http_error | timeout | disabled | exception
-- verdict   : auto_confirmed | pending | discarded_low_conf | discarded_dedup | not_submitted
--             (verdict='' when call failed before reaching the queue)
CREATE TABLE IF NOT EXISTS llm_call_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    caller       TEXT NOT NULL,
    model        TEXT NOT NULL DEFAULT '',
    duration_ms  INTEGER DEFAULT 0,
    outcome      TEXT NOT NULL DEFAULT '',
    verdict      TEXT NOT NULL DEFAULT '',
    confidence   REAL DEFAULT 0,
    headline     TEXT DEFAULT '',
    error        TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_llm_call_log_ts     ON llm_call_log (ts);
CREATE INDEX IF NOT EXISTS idx_llm_call_log_caller ON llm_call_log (caller, ts);

-- CAC: Noise exclusion rules (analyst-defined)
CREATE TABLE IF NOT EXISTS noise_exclusion (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor      TEXT NOT NULL,
    theater     TEXT NOT NULL DEFAULT '',
    pattern     TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    created_at  REAL NOT NULL,
    created_by  TEXT NOT NULL DEFAULT '',
    expires_at  REAL DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_noise_excl_sensor ON noise_exclusion (sensor, theater);

-- CAC: Confirmed threat events (analyst classification)
CREATE TABLE IF NOT EXISTS confirmed_threats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    theater         TEXT NOT NULL,
    ts              REAL NOT NULL,
    classification  TEXT NOT NULL DEFAULT '',
    sensors_json    TEXT NOT NULL DEFAULT '[]',
    threat_level    INTEGER NOT NULL DEFAULT 5,
    notes           TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_confirmed_theater_ts ON confirmed_threats (theater, ts);

-- CAC: Daily summary snapshots for long-term trend analysis
CREATE TABLE IF NOT EXISTS daily_summary (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    theater       TEXT NOT NULL,
    day_bucket    INTEGER NOT NULL,
    avg_score     REAL NOT NULL DEFAULT 0.0,
    max_score     REAL NOT NULL DEFAULT 0.0,
    min_tl        INTEGER NOT NULL DEFAULT 5,
    max_tl        INTEGER NOT NULL DEFAULT 5,
    fired_sensors TEXT NOT NULL DEFAULT '[]',
    domain_scores TEXT NOT NULL DEFAULT '{}',
    context_alignment TEXT NOT NULL DEFAULT '{}',
    summary_json  TEXT NOT NULL DEFAULT '{}',
    UNIQUE(theater, day_bucket)
);
CREATE INDEX IF NOT EXISTS idx_daily_summary_theater ON daily_summary (theater, day_bucket);

-- CAC: Forecast log for prediction accuracy tracking
CREATE TABLE IF NOT EXISTS forecast_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    theater       TEXT NOT NULL,
    ts            REAL NOT NULL,
    forecast_type TEXT NOT NULL DEFAULT '',
    predicted     TEXT NOT NULL DEFAULT '',
    actual        TEXT DEFAULT NULL,
    resolved_at   REAL DEFAULT NULL,
    accuracy      REAL DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_forecast_theater_ts ON forecast_log (theater, ts);

-- CAC: Co-occurrence statistics for sensor pattern learning (sensitivity UP only)
CREATE TABLE IF NOT EXISTS cooccurrence_stats (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_a      TEXT NOT NULL,
    sensor_b      TEXT NOT NULL,
    theater       TEXT NOT NULL DEFAULT '',
    co_count      INTEGER NOT NULL DEFAULT 0,
    solo_a_count  INTEGER NOT NULL DEFAULT 0,
    solo_b_count  INTEGER NOT NULL DEFAULT 0,
    last_updated  REAL NOT NULL,
    UNIQUE(sensor_a, sensor_b, theater)
);
CREATE INDEX IF NOT EXISTS idx_cooccur_sensors ON cooccurrence_stats (sensor_a, sensor_b);

-- Climate Feed events (persistent)
CREATE TABLE IF NOT EXISTS climate_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    indicator  TEXT NOT NULL,
    axis       TEXT NOT NULL,
    headline   TEXT NOT NULL,
    detail     TEXT NOT NULL,
    severity   INTEGER NOT NULL DEFAULT 0,
    theater    TEXT NOT NULL DEFAULT '',
    meta_json  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_climate_events_ts ON climate_events (ts);
CREATE INDEX IF NOT EXISTS idx_climate_events_dedup ON climate_events (indicator, theater, ts);

-- Situation Wire items (persistent)
CREATE TABLE IF NOT EXISTS situation_wire (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    theater    TEXT NOT NULL,
    source     TEXT NOT NULL,
    text       TEXT NOT NULL,
    severity   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_situation_wire_ts ON situation_wire (ts);
CREATE INDEX IF NOT EXISTS idx_situation_wire_theater ON situation_wire (theater, ts);

-- LLM Intel: source credibility tracking
CREATE TABLE IF NOT EXISTS llm_sources (
    source_id            TEXT PRIMARY KEY,
    source_type          TEXT NOT NULL,
    credibility_weight   REAL NOT NULL DEFAULT 0.70,
    confirmed_count      INTEGER NOT NULL DEFAULT 0,
    false_positive_count INTEGER NOT NULL DEFAULT 0,
    last_updated         REAL NOT NULL
);

-- LLM Intel: queue of LLM-analyzed intelligence items
CREATE TABLE IF NOT EXISTS llm_intel (
    id            TEXT PRIMARY KEY,
    source_type   TEXT NOT NULL,
    source_id     TEXT NOT NULL DEFAULT '',
    theater       TEXT NOT NULL DEFAULT '',
    ts            REAL NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    confidence    REAL NOT NULL DEFAULT 0.0,
    raw_text      TEXT NOT NULL DEFAULT '',
    raw_url       TEXT NOT NULL DEFAULT '',
    headline      TEXT NOT NULL DEFAULT '',
    llm_fields    TEXT NOT NULL DEFAULT '{}',
    score_delta   REAL NOT NULL DEFAULT 0.0,
    domain        TEXT NOT NULL DEFAULT 'info',
    confirmed_by  TEXT DEFAULT NULL,
    confirmed_at  REAL DEFAULT NULL,
    override_at   REAL DEFAULT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_llm_intel_ts     ON llm_intel (ts DESC);
CREATE INDEX IF NOT EXISTS idx_llm_intel_status ON llm_intel (status, ts DESC);
CREATE INDEX IF NOT EXISTS idx_llm_intel_theater ON llm_intel (theater, ts DESC);

-- Auth: user accounts
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt        TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'viewer',
    created_at  REAL NOT NULL,
    last_login  REAL
);

-- Auth: per-user theater settings
CREATE TABLE IF NOT EXISTS user_settings (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id),
    core        TEXT NOT NULL DEFAULT 'TW',
    pins        TEXT NOT NULL DEFAULT '[]',
    correlates  TEXT NOT NULL DEFAULT '[]',
    adversaries TEXT NOT NULL DEFAULT '[]',
    muted       TEXT NOT NULL DEFAULT '[]',
    lang        TEXT NOT NULL DEFAULT 'en',
    updated_at  REAL NOT NULL
);

-- Auth: JWT revocation list
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    revoked_at  REAL NOT NULL
);
"""

# Column name mapping for parameterized HOD methods
_VALUE_COL = {
    "hod_baseline":  "avg_spike",
    "checkhost_hod": "success_rate",
    "bgp_hod":       "prefix_count",
}

_HOD_TABLES = set(_VALUE_COL.keys())


_WRITE_SQL_PREFIXES = ("INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP", "ALTER", "BEGIN", "PRAGMA")


class _CooperativeConn:
    """Thin proxy around sqlite3.Connection that serializes write operations.

    Under gevent, SQLite's C-level busy_timeout blocks the entire event loop
    when waiting for a write lock, creating a deadlock. This proxy acquires a
    cooperative threading.Lock (gevent-patched) before executing write SQL,
    and releases it on commit/rollback. Read SQL runs without the lock.

    All attribute access is forwarded to the underlying connection, so this
    object is a drop-in replacement for sqlite3.Connection.
    """
    __slots__ = ("_conn", "_wlock", "_holding")

    def __init__(self, conn: sqlite3.Connection, write_lock: threading.Lock):
        self._conn = conn
        self._wlock = write_lock
        self._holding = False

    def execute(self, sql: str, parameters=()):
        first_word = sql.lstrip().split(None, 1)[0].upper() if sql.lstrip() else ""
        if not self._holding and first_word in _WRITE_SQL_PREFIXES:
            self._wlock.acquire()
            self._holding = True
        try:
            return self._conn.execute(sql, parameters)
        except Exception:
            if self._holding:
                self._holding = False
                self._wlock.release()
            raise

    def executemany(self, sql: str, seq_of_parameters):
        if not self._holding:
            self._wlock.acquire()
            self._holding = True
        try:
            return self._conn.executemany(sql, seq_of_parameters)
        except Exception:
            if self._holding:
                self._holding = False
                self._wlock.release()
            raise

    def executescript(self, sql: str):
        if not self._holding:
            self._wlock.acquire()
            self._holding = True
        return self._conn.executescript(sql)

    def commit(self):
        try:
            self._conn.commit()
        finally:
            if self._holding:
                self._holding = False
                self._wlock.release()

    def rollback(self):
        try:
            self._conn.rollback()
        finally:
            if self._holding:
                self._holding = False
                self._wlock.release()

    def close(self):
        if self._holding:
            self._holding = False
            self._wlock.release()
        self._conn.close()

    @contextmanager
    def writing(self):
        """Context manager ensuring the write lock is released on exception."""
        try:
            yield
            self.commit()
        except Exception:
            self.rollback()
            raise

    def __getattr__(self, name):
        return getattr(self._conn, name)


class RadarDB:
    """Thread-safe SQLite state store. One connection per greenlet/thread.

    All connections are wrapped with _CooperativeConn, which serializes
    write operations via a cooperative lock. Under gevent, this prevents
    the C-level busy_timeout deadlock where sqlite3_sleep blocks the
    entire event loop. Read operations remain lock-free (WAL mode).
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._check_integrity_or_recreate()
        self._ensure_schema()

    def _check_integrity_or_recreate(self):
        """Run PRAGMA integrity_check on startup. If the DB is corrupted,
        rename it and let _ensure_schema create a fresh one.

        All persistent data in this system (baselines, caches, HOD stats)
        is ephemeral and will be rebuilt from upstream APIs within hours.
        A clean DB is always preferable to a corrupted one.
        """
        if not os.path.exists(self._db_path):
            return
        try:
            conn = sqlite3.connect(self._db_path, timeout=5)
            result = conn.execute("PRAGMA integrity_check").fetchone()
            conn.close()
            if result and result[0] == "ok":
                log.info("[DB] Startup integrity check: OK")
                # Also remove stale WAL/SHM files from previous unclean shutdowns
                return
            log.error(f"[DB] Integrity check FAILED: {result}")
        except Exception as e:
            log.error(f"[DB] Integrity check error: {e}")

        # Rename corrupted DB and WAL/SHM files
        ts = time.strftime("%Y%m%d%H%M%S")
        corrupt_name = f"{self._db_path}.corrupt.{ts}"
        os.rename(self._db_path, corrupt_name)
        for ext in ("-wal", "-shm"):
            f = self._db_path + ext
            if os.path.exists(f):
                os.rename(f, corrupt_name + ext)
        log.warning(f"[DB] Corrupted DB renamed to {corrupt_name} — creating fresh database")

    def _get_conn(self) -> _CooperativeConn:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            raw = sqlite3.connect(self._db_path, timeout=5)
            raw.execute("PRAGMA journal_mode = WAL")
            raw.execute("PRAGMA synchronous = FULL")
            raw.row_factory = sqlite3.Row
            conn = _CooperativeConn(raw, self._write_lock)
            self._local.conn = conn
        return conn

    def _ensure_schema(self):
        with self._init_lock:
            conn = self._get_conn()
            conn.executescript(_SCHEMA_SQL)
            conn.commit()
            self._run_migrations(conn)

    def schema_version(self) -> int:
        try:
            row = self._get_conn().execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            return row[0] if row and row[0] is not None else 0
        except sqlite3.OperationalError:
            return 0

    def set_schema_version(self, ver: int):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO schema_version (version, migrated_at) VALUES (?, ?)",
                (ver, time.time()),
            )

    # ── Auto-migration engine ─────────────────────────────────────────────
    # Each entry: (version_number, description, sql_or_callable)
    #   - sql_or_callable: str  → executed as conn.executescript()
    #                      callable(conn) → arbitrary Python migration
    #
    # To add a new migration:
    #   1. Append a tuple to _MIGRATIONS with the next version number
    #   2. Write the ALTER TABLE / INSERT / Python logic needed
    #   3. The engine auto-applies all pending migrations in order
    #
    # Example entries:
    #   (2, "Add priority column to alerts", "ALTER TABLE alert_timeline ADD COLUMN priority INTEGER DEFAULT 0;"),
    #   (3, "Backfill priorities", lambda conn: conn.execute("UPDATE alert_timeline SET priority=1 WHERE level='CRITICAL'")),

    _MIGRATIONS: list[tuple[int, str, str | callable]] = [
        # (1, "initial schema", "")  -- version 1 = current _SCHEMA_SQL baseline
        (2, "Add LLM intel tables (llm_intel, llm_sources)", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS llm_sources (
                source_id            TEXT PRIMARY KEY,
                source_type          TEXT NOT NULL,
                credibility_weight   REAL NOT NULL DEFAULT 0.70,
                confirmed_count      INTEGER NOT NULL DEFAULT 0,
                false_positive_count INTEGER NOT NULL DEFAULT 0,
                last_updated         REAL NOT NULL
            )"""),
            conn.execute("""CREATE TABLE IF NOT EXISTS llm_intel (
                id            TEXT PRIMARY KEY,
                source_type   TEXT NOT NULL,
                source_id     TEXT NOT NULL DEFAULT '',
                theater       TEXT NOT NULL DEFAULT '',
                ts            REAL NOT NULL,
                status        TEXT NOT NULL DEFAULT 'pending',
                confidence    REAL NOT NULL DEFAULT 0.0,
                raw_text      TEXT NOT NULL DEFAULT '',
                raw_url       TEXT NOT NULL DEFAULT '',
                headline      TEXT NOT NULL DEFAULT '',
                llm_fields    TEXT NOT NULL DEFAULT '{}',
                score_delta   REAL NOT NULL DEFAULT 0.0,
                domain        TEXT NOT NULL DEFAULT 'info',
                confirmed_by  TEXT DEFAULT NULL,
                confirmed_at  REAL DEFAULT NULL,
                override_at   REAL DEFAULT NULL,
                created_at    REAL NOT NULL
            )"""),
            conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_intel_ts      ON llm_intel (ts DESC)"),
            conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_intel_status  ON llm_intel (status, ts DESC)"),
            conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_intel_theater ON llm_intel (theater, ts DESC)"),
        ]),
    ]

    def _run_migrations(self, conn: sqlite3.Connection):
        """Apply any pending schema migrations in order."""
        current = self.schema_version()

        # If DB is brand new (no version record), mark as current baseline
        if current == 0:
            baseline = max((m[0] for m in self._MIGRATIONS), default=0)
            target = max(baseline, 1)
            self.set_schema_version(target)
            log.info("DB schema initialized at version %d", target)
            return

        pending = [m for m in self._MIGRATIONS if m[0] > current]
        if not pending:
            return

        pending.sort(key=lambda m: m[0])
        log.info("DB schema at v%d — %d migration(s) pending", current, len(pending))

        for ver, desc, action in pending:
            log.info("Applying migration v%d: %s", ver, desc)
            try:
                if callable(action):
                    action(conn)
                    conn.commit()
                elif action.strip():
                    conn.executescript(action)
                    conn.commit()
                self.set_schema_version(ver)
                log.info("Migration v%d applied successfully", ver)
            except Exception:
                log.exception("Migration v%d FAILED: %s", ver, desc)
                raise RuntimeError(
                    f"Database migration v{ver} failed: {desc}. "
                    f"Please check logs or restore from backup."
                )

    # ── baseline_cache ──────────────────────────────────────────────────────
    def baseline_get(self, theater: str) -> dict:
        row = self._get_conn().execute(
            "SELECT updated_at, data_json FROM baseline_cache WHERE theater=?",
            (theater,),
        ).fetchone()
        if not row:
            return {}
        data = json.loads(row["data_json"])
        data["time"] = row["updated_at"]
        return data

    def baseline_set(self, theater: str, data: dict, ts: float):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO baseline_cache (theater, updated_at, data_json) "
                "VALUES (?, ?, ?)",
                (theater, ts, json.dumps(data, default=str)),
            )

    def baseline_all(self) -> dict:
        rows = self._get_conn().execute(
            "SELECT theater, updated_at, data_json FROM baseline_cache"
        ).fetchall()
        result = {}
        for r in rows:
            d = json.loads(r["data_json"])
            d["time"] = r["updated_at"]
            result[r["theater"]] = d
        return result

    def baseline_len(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM baseline_cache").fetchone()
        return row[0] if row else 0

    # ── airspace_baseline ───────────────────────────────────────────────────
    def airspace_get(self, code: str) -> dict:
        row = self._get_conn().execute(
            "SELECT data_json FROM airspace_baseline WHERE airport_code=?",
            (code,),
        ).fetchone()
        return json.loads(row[0]) if row else {}

    def airspace_set(self, code: str, data: dict):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO airspace_baseline (airport_code, data_json) "
                "VALUES (?, ?)",
                (code, json.dumps(data, default=str)),
            )

    def airspace_all(self) -> dict:
        rows = self._get_conn().execute(
            "SELECT airport_code, data_json FROM airspace_baseline"
        ).fetchall()
        return {r[0]: json.loads(r[1]) for r in rows}

    def airspace_len(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM airspace_baseline").fetchone()
        return row[0] if row else 0

    # ── HOD baselines (parameterized by table name) ─────────────────────────
    def hod_record(self, table: str, theater: str, hour_bucket: int, value: float,
                   max_entries: int = 672):
        assert table in _HOD_TABLES, f"Invalid HOD table: {table}"
        col = _VALUE_COL[table]
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                f"INSERT OR REPLACE INTO {table} (theater, hour_bucket, {col}) "
                f"VALUES (?, ?, ?)",
                (theater, hour_bucket, value),
            )
            # Prune oldest beyond limit
            conn.execute(
                f"DELETE FROM {table} WHERE theater=? AND hour_bucket NOT IN "
                f"(SELECT hour_bucket FROM {table} WHERE theater=? "
                f"ORDER BY hour_bucket DESC LIMIT ?)",
                (theater, theater, max_entries),
            )

    def hod_record_many(self, table: str, theater: str,
                        entries: list[tuple[int, float]], max_entries: int = 672):
        """Bulk insert for migration. entries = [(hour_bucket, value), ...]"""
        assert table in _HOD_TABLES
        col = _VALUE_COL[table]
        conn = self._get_conn()
        with conn.writing():
            conn.executemany(
                f"INSERT OR REPLACE INTO {table} (theater, hour_bucket, {col}) "
                f"VALUES (?, ?, ?)",
                [(theater, hb, v) for hb, v in entries],
            )
            conn.execute(
                f"DELETE FROM {table} WHERE theater=? AND hour_bucket NOT IN "
                f"(SELECT hour_bucket FROM {table} WHERE theater=? "
                f"ORDER BY hour_bucket DESC LIMIT ?)",
                (theater, theater, max_entries),
            )

    def hod_same_hour(self, table: str, theater: str,
                      target_hod: int, before_bucket: int) -> list[float]:
        """Values where hour-of-day matches and bucket < before_bucket."""
        assert table in _HOD_TABLES
        col = _VALUE_COL[table]
        rows = self._get_conn().execute(
            f"SELECT {col} FROM {table} "
            f"WHERE theater=? AND (hour_bucket/3600)%24=? AND hour_bucket<?",
            (theater, target_hod, before_bucket),
        ).fetchall()
        return [r[0] for r in rows]

    def hod_last_bucket(self, table: str, theater: str) -> Optional[int]:
        assert table in _HOD_TABLES
        row = self._get_conn().execute(
            f"SELECT MAX(hour_bucket) FROM {table} WHERE theater=?",
            (theater,),
        ).fetchone()
        return row[0] if row and row[0] is not None else None

    def hod_all_entries(self, table: str, theater: str) -> list[tuple[int, float]]:
        """Return [(hour_bucket, value), ...] ordered by hour_bucket."""
        assert table in _HOD_TABLES
        col = _VALUE_COL[table]
        rows = self._get_conn().execute(
            f"SELECT hour_bucket, {col} FROM {table} "
            f"WHERE theater=? ORDER BY hour_bucket",
            (theater,),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def hod_existing_buckets(self, table: str, theater: str) -> set[int]:
        assert table in _HOD_TABLES
        rows = self._get_conn().execute(
            f"SELECT hour_bucket FROM {table} WHERE theater=?",
            (theater,),
        ).fetchall()
        return {r[0] for r in rows}

    def hod_distinct_hours(self, table: str, theater: str) -> int:
        assert table in _HOD_TABLES
        row = self._get_conn().execute(
            f"SELECT COUNT(DISTINCT (hour_bucket/3600)%24) FROM {table} WHERE theater=?",
            (theater,),
        ).fetchone()
        return row[0] if row else 0

    def hod_total_points(self, table: str) -> int:
        assert table in _HOD_TABLES
        row = self._get_conn().execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return row[0] if row else 0

    def hod_total_points_theater(self, table: str, theater: str) -> int:
        assert table in _HOD_TABLES
        row = self._get_conn().execute(
            f"SELECT COUNT(*) FROM {table} WHERE theater=?", (theater,)
        ).fetchone()
        return row[0] if row else 0

    # ── GDELT DoW ───────────────────────────────────────────────────────────
    def gdelt_dow_record(self, theater: str, day_bucket: int,
                         weekday: int, tone: float, max_entries: int = 140):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO gdelt_dow (theater, day_bucket, weekday, tone) "
                "VALUES (?, ?, ?, ?)",
                (theater, day_bucket, weekday, tone),
            )
            conn.execute(
                "DELETE FROM gdelt_dow WHERE theater=? AND day_bucket NOT IN "
                "(SELECT day_bucket FROM gdelt_dow WHERE theater=? "
                "ORDER BY day_bucket DESC LIMIT ?)",
                (theater, theater, max_entries),
            )

    def gdelt_dow_last_bucket(self, theater: str) -> Optional[int]:
        row = self._get_conn().execute(
            "SELECT MAX(day_bucket) FROM gdelt_dow WHERE theater=?",
            (theater,),
        ).fetchone()
        return row[0] if row and row[0] is not None else None

    def gdelt_dow_same_weekday(self, theater: str, weekday: int,
                               before_bucket: int) -> list[float]:
        rows = self._get_conn().execute(
            "SELECT tone FROM gdelt_dow WHERE theater=? AND weekday=? "
            "AND day_bucket<? ORDER BY day_bucket",
            (theater, weekday, before_bucket),
        ).fetchall()
        return [r[0] for r in rows]

    def gdelt_dow_total_points(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM gdelt_dow").fetchone()
        return row[0] if row else 0

    # ── time_series_ts (timestamped) ────────────────────────────────────────
    def ts_append(self, theater: str, ts: float, value: float, max_entries: int = 8064):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO time_series_ts (theater, ts, value) VALUES (?, ?, ?)",
                (theater, ts, value),
            )
            conn.execute(
                "DELETE FROM time_series_ts WHERE theater=? AND ts NOT IN "
                "(SELECT ts FROM time_series_ts WHERE theater=? "
                "ORDER BY ts DESC LIMIT ?)",
                (theater, theater, max_entries),
            )

    def ts_get(self, theater: str) -> list[tuple[float, float]]:
        rows = self._get_conn().execute(
            "SELECT ts, value FROM time_series_ts WHERE theater=? ORDER BY ts",
            (theater,),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def ts_get_since(self, theater: str, cutoff: float) -> list[tuple[float, float]]:
        rows = self._get_conn().execute(
            "SELECT ts, value FROM time_series_ts WHERE theater=? AND ts>=? ORDER BY ts",
            (theater, cutoff),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def ts_distinct_theaters(self) -> list[str]:
        rows = self._get_conn().execute(
            "SELECT DISTINCT theater FROM time_series_ts ORDER BY theater"
        ).fetchall()
        return [r[0] for r in rows]

    def ts_total_points(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM time_series_ts").fetchone()
        return row[0] if row else 0

    # ── time_series value-only (combined/l3/l7) ─────────────────────────────
    def series_append(self, theater: str, series_type: str,
                      value: float, max_entries: int = 8064):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO time_series (theater, series_type, value) VALUES (?, ?, ?)",
                (theater, series_type, value),
            )
            conn.execute(
                "DELETE FROM time_series WHERE theater=? AND series_type=? AND id NOT IN "
                "(SELECT id FROM time_series WHERE theater=? AND series_type=? "
                "ORDER BY id DESC LIMIT ?)",
                (theater, series_type, theater, series_type, max_entries),
            )

    def series_get(self, theater: str, series_type: str) -> list[float]:
        rows = self._get_conn().execute(
            "SELECT value FROM time_series WHERE theater=? AND series_type=? ORDER BY id",
            (theater, series_type),
        ).fetchall()
        return [r[0] for r in rows]

    # ── alert_timeline ──────────────────────────────────────────────────────
    def alert_append(self, alert_dict: dict, max_entries: int = 288):
        conn = self._get_conn()
        ts = alert_dict.get("ts", 0)
        with conn.writing():
            conn.execute(
                "INSERT INTO alert_timeline (ts, data_json) VALUES (?, ?)",
                (ts, json.dumps(alert_dict, default=str)),
            )
            conn.execute(
                "DELETE FROM alert_timeline WHERE id NOT IN "
                "(SELECT id FROM alert_timeline ORDER BY id DESC LIMIT ?)",
                (max_entries,),
            )

    def alert_list(self, limit: int = 288) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT data_json FROM alert_timeline ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [json.loads(r[0]) for r in reversed(rows)]

    def alert_count(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM alert_timeline").fetchone()
        return row[0] if row else 0

    def alert_clear(self):
        conn = self._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM alert_timeline")

    # ── sequence_event_log ──────────────────────────────────────────────────
    _SEQ_MAX = 500  # max sequence events per theater

    def seq_append(self, theater: str, ts: float, event_type: str, meta: dict):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO sequence_events (theater, ts, event_type, meta_json) "
                "VALUES (?, ?, ?, ?)",
                (theater, ts, event_type, json.dumps(meta, default=str)),
            )
            # Auto-prune oldest entries beyond limit
            conn.execute(
                "DELETE FROM sequence_events WHERE theater=? AND id NOT IN "
                "(SELECT id FROM sequence_events WHERE theater=? ORDER BY id DESC LIMIT ?)",
                (theater, theater, self._SEQ_MAX),
            )

    def seq_exists_since(self, theater: str, event_type: str, since: float) -> bool:
        row = self._get_conn().execute(
            "SELECT 1 FROM sequence_events "
            "WHERE theater=? AND event_type=? AND ts>=? LIMIT 1",
            (theater, event_type, since),
        ).fetchone()
        return row is not None

    def seq_events_since(self, theater: str, cutoff: float) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT ts, event_type, meta_json FROM sequence_events "
            "WHERE theater=? AND ts>=? ORDER BY ts",
            (theater, cutoff),
        ).fetchall()
        return [{"ts": r[0], "type": r[1], "meta": json.loads(r[2])} for r in rows]

    def seq_all_events(self, theater: str) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT ts, event_type, meta_json FROM sequence_events "
            "WHERE theater=? ORDER BY ts",
            (theater,),
        ).fetchall()
        return [{"ts": r[0], "type": r[1], "meta": json.loads(r[2])} for r in rows]

    def seq_cleanup(self, cutoff: float):
        conn = self._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM sequence_events WHERE ts<?", (cutoff,))

    def seq_total(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM sequence_events").fetchone()
        return row[0] if row else 0

    def seq_distinct_theaters(self) -> list[str]:
        rows = self._get_conn().execute(
            "SELECT DISTINCT theater FROM sequence_events"
        ).fetchall()
        return [r[0] for r in rows]

    def seq_clear(self):
        conn = self._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM sequence_events")

    # ── threat_history ──────────────────────────────────────────────────────
    def threat_append(self, ts: float, level: int, max_entries: int = 100):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO threat_history (ts, threat_level) VALUES (?, ?)",
                (ts, level),
            )
            conn.execute(
                "DELETE FROM threat_history WHERE id NOT IN "
                "(SELECT id FROM threat_history ORDER BY id DESC LIMIT ?)",
                (max_entries,),
            )

    def threat_list(self) -> list[tuple[float, int]]:
        rows = self._get_conn().execute(
            "SELECT ts, threat_level FROM threat_history ORDER BY id"
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def threat_last(self) -> Optional[tuple[float, int]]:
        row = self._get_conn().execute(
            "SELECT ts, threat_level FROM threat_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else None

    def threat_clear(self):
        conn = self._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM threat_history")

    # ── sensor_zscore_stats (Welford's online algorithm) ────────────────────
    def zscore_stats_get(self, sensor: str, theater: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT sample_count, mean, m2, last_updated "
            "FROM sensor_zscore_stats WHERE sensor_name=? AND theater=?",
            (sensor, theater),
        ).fetchone()
        if not row:
            return None
        n = row[0]
        return {
            "sample_count": n,
            "mean": row[1],
            "m2": row[2],
            "variance": row[2] / n if n > 1 else 0.0,
            "std": (row[2] / n) ** 0.5 if n > 1 and row[2] > 0 else 0.0,
            "last_updated": row[3],
        }

    def zscore_stats_update(self, sensor: str, theater: str, new_value: float):
        """Incrementally update running mean/variance using Welford's algorithm.

        Uses BEGIN IMMEDIATE to ensure atomic read-modify-write across threads.
        """
        import time as _time
        conn = self._get_conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT sample_count, mean, m2 "
                "FROM sensor_zscore_stats WHERE sensor_name=? AND theater=?",
                (sensor, theater),
            ).fetchone()
            if row:
                n, mean, m2 = row[0], row[1], row[2]
            else:
                n, mean, m2 = 0, 0.0, 0.0
            n += 1
            delta = new_value - mean
            mean += delta / n
            delta2 = new_value - mean
            m2 += delta * delta2
            conn.execute(
                "INSERT OR REPLACE INTO sensor_zscore_stats "
                "(sensor_name, theater, sample_count, mean, m2, last_updated) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (sensor, theater, n, mean, m2, _time.time()),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def zscore_stats_all(self) -> list:
        rows = self._get_conn().execute(
            "SELECT sensor_name, theater, sample_count, mean, m2, last_updated "
            "FROM sensor_zscore_stats ORDER BY sensor_name, theater"
        ).fetchall()
        result = []
        for r in rows:
            n = r[2]
            result.append({
                "sensor": r[0], "theater": r[1], "sample_count": n,
                "mean": r[3], "variance": r[4] / n if n > 1 else 0.0,
                "std": (r[4] / n) ** 0.5 if n > 1 and r[4] > 0 else 0.0,
                "last_updated": r[5],
            })
        return result

    # ── sensor_fetch_log ─────────────────────────────────────────────────────
    def fetch_log_append(self, sensor_name: str, ts: float, success: bool,
                         duration_ms: int = 0, http_status: int = 0,
                         records: int = 0, error: str = ""):
        """Persist a sensor fetch result. Auto-prunes entries older than 7 days."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO sensor_fetch_log (sensor_name, ts, success, duration_ms, http_status, records, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (sensor_name, ts, 1 if success else 0, duration_ms, http_status, records, error[:300]),
            )

    def fetch_log_reliability(self, sensor_name: str = None, hours: int = 24) -> list:
        """Per-sensor reliability aggregates over the given time window."""
        import time as _time
        cutoff = _time.time() - hours * 3600
        conn = self._get_conn()
        if sensor_name:
            rows = conn.execute(
                "SELECT sensor_name, COUNT(*) AS total, SUM(success) AS ok, "
                "AVG(duration_ms) AS avg_ms, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
                "FROM sensor_fetch_log WHERE sensor_name=? AND ts>=? GROUP BY sensor_name",
                (sensor_name, cutoff),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT sensor_name, COUNT(*) AS total, SUM(success) AS ok, "
                "AVG(duration_ms) AS avg_ms, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
                "FROM sensor_fetch_log WHERE ts>=? GROUP BY sensor_name ORDER BY sensor_name",
                (cutoff,),
            ).fetchall()
        return [
            {
                "sensor_name": r[0], "total_fetches": r[1],
                "success_rate": round(r[2] / r[1], 4) if r[1] else 0,
                "avg_duration_ms": round(r[3]) if r[3] else 0,
                "first_seen": r[4], "last_seen": r[5],
            }
            for r in rows
        ]

    # ── llm_call_log ─────────────────────────────────────────────────────────
    def llm_call_log_append(self, caller: str, model: str, duration_ms: int,
                            outcome: str, verdict: str = "",
                            confidence: float = 0.0, headline: str = "",
                            error: str = ""):
        """Persist a single LLM call attempt and its downstream queue verdict."""
        import time as _time
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO llm_call_log "
                "(ts, caller, model, duration_ms, outcome, verdict, confidence, headline, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_time.time(), caller, model[:80], duration_ms, outcome,
                 verdict, float(confidence), (headline or "")[:200], (error or "")[:300]),
            )

    def llm_call_stats(self, hours: int = 24) -> dict:
        """Aggregate stats per caller and overall verdict counts."""
        import time as _time
        cutoff = _time.time() - hours * 3600
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT caller, "
            "COUNT(*) AS total, "
            "SUM(CASE WHEN outcome='ok' THEN 1 ELSE 0 END) AS ok, "
            "SUM(CASE WHEN outcome='parse_failed' THEN 1 ELSE 0 END) AS parse_failed, "
            "SUM(CASE WHEN outcome='http_error' THEN 1 ELSE 0 END) AS http_error, "
            "SUM(CASE WHEN outcome='timeout' THEN 1 ELSE 0 END) AS timeout_, "
            "SUM(CASE WHEN outcome='exception' THEN 1 ELSE 0 END) AS exception_, "
            "SUM(CASE WHEN verdict='auto_confirmed' THEN 1 ELSE 0 END) AS auto_confirmed, "
            "SUM(CASE WHEN verdict='pending' THEN 1 ELSE 0 END) AS pending, "
            "SUM(CASE WHEN verdict='discarded_low_conf' THEN 1 ELSE 0 END) AS discarded_low, "
            "SUM(CASE WHEN verdict='discarded_dedup' THEN 1 ELSE 0 END) AS discarded_dedup, "
            "SUM(CASE WHEN verdict LIKE 'sensor_filtered:%' THEN 1 ELSE 0 END) AS sensor_filtered, "
            "SUM(CASE WHEN verdict='' THEN 1 ELSE 0 END) AS verdict_empty, "
            "AVG(duration_ms) AS avg_ms, "
            "AVG(confidence) AS avg_conf, "
            "MAX(ts) AS last_ts "
            "FROM llm_call_log WHERE ts>=? GROUP BY caller ORDER BY caller",
            (cutoff,),
        ).fetchall()
        per_caller = [
            {
                "caller": r[0], "total": r[1] or 0, "ok": r[2] or 0,
                "parse_failed": r[3] or 0, "http_error": r[4] or 0,
                "timeout": r[5] or 0, "exception": r[6] or 0,
                "auto_confirmed": r[7] or 0, "pending": r[8] or 0,
                "discarded_low_conf": r[9] or 0,
                "discarded_dedup": r[10] or 0,
                "sensor_filtered": r[11] or 0,
                "verdict_empty": r[12] or 0,
                "avg_duration_ms": round(r[13]) if r[13] else 0,
                "avg_confidence": round(r[14], 3) if r[14] else 0.0,
                "last_seen": r[15],
            }
            for r in rows
        ]
        totals_row = conn.execute(
            "SELECT COUNT(*), SUM(CASE WHEN outcome='ok' THEN 1 ELSE 0 END) "
            "FROM llm_call_log WHERE ts>=?",
            (cutoff,),
        ).fetchone()
        # Breakdown of sensor_filtered reasons (verdict = "sensor_filtered:<reason>")
        filter_rows = conn.execute(
            "SELECT caller, verdict, COUNT(*) FROM llm_call_log "
            "WHERE ts>=? AND verdict LIKE 'sensor_filtered:%' "
            "GROUP BY caller, verdict ORDER BY caller, verdict",
            (cutoff,),
        ).fetchall()
        sensor_filter_breakdown = [
            {"caller": r[0], "reason": r[1].split(":", 1)[1], "count": r[2]}
            for r in filter_rows
        ]
        return {
            "window_hours": hours,
            "total_calls": totals_row[0] or 0,
            "ok_calls": totals_row[1] or 0,
            "per_caller": per_caller,
            "sensor_filter_breakdown": sensor_filter_breakdown,
        }

    def llm_call_patch_verdict(self, callers: tuple, verdict: str,
                               window_sec: int = 60) -> bool:
        """Patch the most recent empty-verdict llm_call_log row for a caller set.

        Used by both intel_queue (for auto_confirmed/pending/discarded_*) and
        sensors (for sensor_filtered:<reason>). Best-effort, single-row update.
        Returns True if a row was updated.
        """
        if not callers or not verdict:
            return False
        import time as _time
        cutoff = _time.time() - window_sec
        conn = self._get_conn()
        placeholders = ",".join("?" * len(callers))
        try:
            with conn.writing():
                cur = conn.execute(
                    f"UPDATE llm_call_log SET verdict=? "
                    f"WHERE id = (SELECT id FROM llm_call_log "
                    f"WHERE caller IN ({placeholders}) AND ts >= ? "
                    f"AND verdict='' ORDER BY id DESC LIMIT 1)",
                    (verdict, *callers, cutoff),
                )
                return cur.rowcount > 0
        except Exception:
            return False

    def llm_call_recent(self, caller: str = "", limit: int = 50) -> list:
        """Most recent llm_call_log rows, optionally filtered by caller."""
        conn = self._get_conn()
        if caller:
            rows = conn.execute(
                "SELECT ts, caller, model, duration_ms, outcome, verdict, confidence, headline, error "
                "FROM llm_call_log WHERE caller=? ORDER BY ts DESC LIMIT ?",
                (caller, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT ts, caller, model, duration_ms, outcome, verdict, confidence, headline, error "
                "FROM llm_call_log ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "ts": r[0], "caller": r[1], "model": r[2], "duration_ms": r[3],
                "outcome": r[4], "verdict": r[5], "confidence": r[6],
                "headline": r[7], "error": r[8],
            }
            for r in rows
        ]

    # ── sensor_caches ───────────────────────────────────────────────────────
    def sensor_cache_set(self, sensor_name: str, cache_time: float, cache_data: dict):
        self._get_conn().execute(
            "INSERT OR REPLACE INTO sensor_caches (sensor_name, cache_time, cache_json) "
            "VALUES (?, ?, ?)",
            (sensor_name, cache_time, json.dumps(cache_data, default=str)),
        )
        self._get_conn().commit()

    def sensor_cache_get(self, sensor_name: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT cache_time, cache_json FROM sensor_caches WHERE sensor_name=?",
            (sensor_name,),
        ).fetchone()
        if not row:
            return None
        return {"cache_time": row[0], "cache": json.loads(row[1])}

    def sensor_cache_all(self) -> dict:
        rows = self._get_conn().execute(
            "SELECT sensor_name, cache_time, cache_json FROM sensor_caches"
        ).fetchall()
        return {
            r[0]: {"cache_time": r[1], "cache": json.loads(r[2])}
            for r in rows
        }

    def sensor_cache_count(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM sensor_caches").fetchone()
        return row[0] if row else 0

    # ── noise_exclusion ────────────────────────────────────────────────────
    def noise_excl_add(self, sensor: str, theater: str, pattern: str,
                       reason: str, created_by: str,
                       expires_at: float = None) -> int:
        import time as _time
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO noise_exclusion (sensor, theater, pattern, reason, "
                "created_at, created_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (sensor, theater, pattern, reason, _time.time(), created_by, expires_at),
            )
        return cur.lastrowid

    def noise_excl_remove(self, rule_id: int) -> bool:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute("DELETE FROM noise_exclusion WHERE id=?", (rule_id,))
        return cur.rowcount > 0

    def noise_excl_list(self, sensor: str = None, theater: str = None) -> list[dict]:
        import time as _time
        conn = self._get_conn()
        q = "SELECT id, sensor, theater, pattern, reason, created_at, created_by, expires_at FROM noise_exclusion WHERE 1=1"
        params = []
        if sensor:
            q += " AND sensor=?"
            params.append(sensor)
        if theater:
            q += " AND (theater=? OR theater='')"
            params.append(theater)
        # Exclude expired rules
        q += " AND (expires_at IS NULL OR expires_at > ?)"
        params.append(_time.time())
        rows = conn.execute(q, params).fetchall()
        return [{"id": r[0], "sensor": r[1], "theater": r[2], "pattern": r[3],
                 "reason": r[4], "created_at": r[5], "created_by": r[6],
                 "expires_at": r[7]} for r in rows]

    def noise_excl_match(self, sensor: str, theater: str, value: str) -> Optional[dict]:
        """Check if a signal matches any active noise exclusion rule."""
        rules = self.noise_excl_list(sensor=sensor, theater=theater)
        for rule in rules:
            pattern = rule.get("pattern", "")
            if pattern and pattern in value:
                return rule
        return None

    # ── confirmed_threats ──────────────────────────────────────────────────
    def confirmed_threat_add(self, theater: str, ts: float, classification: str,
                             sensors_active: list, threat_level: int,
                             notes: str, created_by: str) -> int:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO confirmed_threats (theater, ts, classification, sensors_json, "
                "threat_level, notes, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (theater, ts, classification, json.dumps(sensors_active),
                 threat_level, notes, created_by),
            )
        return cur.lastrowid

    def confirmed_threat_list(self, theater: str = None, limit: int = 100) -> list[dict]:
        conn = self._get_conn()
        if theater:
            rows = conn.execute(
                "SELECT id, theater, ts, classification, sensors_json, threat_level, "
                "notes, created_by FROM confirmed_threats WHERE theater=? "
                "ORDER BY ts DESC LIMIT ?", (theater, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, theater, ts, classification, sensors_json, threat_level, "
                "notes, created_by FROM confirmed_threats ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"id": r[0], "theater": r[1], "ts": r[2], "classification": r[3],
                 "sensors_active": json.loads(r[4]), "threat_level": r[5],
                 "notes": r[6], "created_by": r[7]} for r in rows]

    # ── daily_summary ──────────────────────────────────────────────────────
    def daily_summary_upsert(self, theater: str, day_bucket: int,
                             avg_score: float, max_score: float,
                             min_tl: int, max_tl: int,
                             fired_sensors: list, domain_scores: dict,
                             context_alignment: dict, summary: dict):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO daily_summary "
                "(theater, day_bucket, avg_score, max_score, min_tl, max_tl, "
                "fired_sensors, domain_scores, context_alignment, summary_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (theater, day_bucket, avg_score, max_score, min_tl, max_tl,
                 json.dumps(fired_sensors), json.dumps(domain_scores),
                 json.dumps(context_alignment), json.dumps(summary, default=str)),
            )

    def daily_summary_get(self, theater: str, days: int = 90) -> list[dict]:
        import time as _time
        cutoff = int(_time.time() // 86400) * 86400 - days * 86400
        rows = self._get_conn().execute(
            "SELECT theater, day_bucket, avg_score, max_score, min_tl, max_tl, "
            "fired_sensors, domain_scores, context_alignment, summary_json "
            "FROM daily_summary WHERE theater=? AND day_bucket>=? ORDER BY day_bucket",
            (theater, cutoff),
        ).fetchall()
        return [{"theater": r[0], "day_bucket": r[1], "avg_score": r[2],
                 "max_score": r[3], "min_tl": r[4], "max_tl": r[5],
                 "fired_sensors": json.loads(r[6]), "domain_scores": json.loads(r[7]),
                 "context_alignment": json.loads(r[8]),
                 "summary": json.loads(r[9])} for r in rows]

    # ── forecast_log ───────────────────────────────────────────────────────
    def forecast_log_add(self, theater: str, ts: float, forecast_type: str,
                         predicted: str) -> int:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO forecast_log (theater, ts, forecast_type, predicted) "
                "VALUES (?, ?, ?, ?)",
                (theater, ts, forecast_type, predicted),
            )
        return cur.lastrowid

    def forecast_log_resolve(self, forecast_id: int, actual: str, accuracy: float):
        import time as _time
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "UPDATE forecast_log SET actual=?, resolved_at=?, accuracy=? WHERE id=?",
                (actual, _time.time(), accuracy, forecast_id),
            )

    def forecast_log_get(self, theater: str = None, limit: int = 100) -> list[dict]:
        conn = self._get_conn()
        if theater:
            rows = conn.execute(
                "SELECT id, theater, ts, forecast_type, predicted, actual, "
                "resolved_at, accuracy FROM forecast_log WHERE theater=? "
                "ORDER BY ts DESC LIMIT ?", (theater, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, theater, ts, forecast_type, predicted, actual, "
                "resolved_at, accuracy FROM forecast_log ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{"id": r[0], "theater": r[1], "ts": r[2], "forecast_type": r[3],
                 "predicted": r[4], "actual": r[5], "resolved_at": r[6],
                 "accuracy": r[7]} for r in rows]

    def forecast_accuracy_summary(self, theater: str = None) -> dict:
        """Aggregate forecast accuracy for resolved forecasts."""
        conn = self._get_conn()
        if theater:
            row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN accuracy IS NOT NULL THEN 1 ELSE 0 END) AS resolved, "
                "AVG(accuracy) AS avg_accuracy "
                "FROM forecast_log WHERE theater=? AND resolved_at IS NOT NULL",
                (theater,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN accuracy IS NOT NULL THEN 1 ELSE 0 END) AS resolved, "
                "AVG(accuracy) AS avg_accuracy "
                "FROM forecast_log WHERE resolved_at IS NOT NULL",
            ).fetchone()
        return {
            "total_forecasts": row[0] if row else 0,
            "resolved": row[1] if row else 0,
            "avg_accuracy": round(row[2], 4) if row and row[2] is not None else None,
        }

    # ── cooccurrence_stats ─────────────────────────────────────────────────
    def cooccurrence_update(self, sensor_a: str, sensor_b: str, theater: str,
                            both_fired: bool):
        """Update co-occurrence counts. Only increases sensitivity (per design principle).

        Uses BEGIN IMMEDIATE to ensure atomic read-modify-write across threads.
        """
        import time as _time
        # Ensure consistent ordering (sensor_a < sensor_b alphabetically)
        if sensor_a > sensor_b:
            sensor_a, sensor_b = sensor_b, sensor_a
        conn = self._get_conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT co_count, solo_a_count, solo_b_count FROM cooccurrence_stats "
                "WHERE sensor_a=? AND sensor_b=? AND theater=?",
                (sensor_a, sensor_b, theater),
            ).fetchone()
            if row:
                co = row[0] + (1 if both_fired else 0)
                sa = row[1] + (1 if not both_fired else 0)
                sb = row[2]
                conn.execute(
                    "UPDATE cooccurrence_stats SET co_count=?, solo_a_count=?, "
                    "solo_b_count=?, last_updated=? "
                    "WHERE sensor_a=? AND sensor_b=? AND theater=?",
                    (co, sa, sb, _time.time(), sensor_a, sensor_b, theater),
                )
            else:
                conn.execute(
                    "INSERT INTO cooccurrence_stats "
                    "(sensor_a, sensor_b, theater, co_count, solo_a_count, "
                    "solo_b_count, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (sensor_a, sensor_b, theater,
                     1 if both_fired else 0,
                     1 if not both_fired else 0,
                     0, _time.time()),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def cooccurrence_get(self, theater: str = None) -> list[dict]:
        conn = self._get_conn()
        if theater:
            rows = conn.execute(
                "SELECT sensor_a, sensor_b, theater, co_count, solo_a_count, "
                "solo_b_count, last_updated FROM cooccurrence_stats WHERE theater=?",
                (theater,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT sensor_a, sensor_b, theater, co_count, solo_a_count, "
                "solo_b_count, last_updated FROM cooccurrence_stats",
            ).fetchall()
        return [{"sensor_a": r[0], "sensor_b": r[1], "theater": r[2],
                 "co_count": r[3], "solo_a_count": r[4], "solo_b_count": r[5],
                 "last_updated": r[6]} for r in rows]

    # ── Startup Cleanup ────────────────────────────────────────────────────
    def startup_cleanup(self):
        """Prune stale data on startup. Called once during app init."""
        self._prune_stale_rows()
        log.info("[DB] Startup cleanup complete")

    def shutdown(self):
        """Checkpoint WAL and close the current thread's connection.

        Called via atexit to ensure WAL data is flushed to the main DB
        file before the process exits. Without this, Docker Desktop for
        Mac volume mounts (VirtioFS/osxfs) may lose un-checkpointed WAL
        data on container stop, leading to corruption or data loss.
        """
        try:
            conn = getattr(self._local, "conn", None)
            if conn is not None:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                conn.commit()
                conn.close()
                self._local.conn = None
                log.info("[DB] Shutdown: WAL checkpointed and connection closed")
        except Exception as e:
            log.warning(f"[DB] Shutdown checkpoint failed: {e}")

    def wal_checkpoint(self):
        """Flush WAL to main DB file. Called hourly by cleanup worker."""
        try:
            conn = self._get_conn()
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
            log.debug("[DB] WAL checkpoint complete")
        except Exception as e:
            log.warning(f"[DB] WAL checkpoint failed: {e}")

    def periodic_cleanup(self):
        """Prune stale data during long-running operation. Called daily by the cleanup worker."""
        deleted = self._prune_stale_rows()
        self.wal_checkpoint()
        log.info(f"[DB] Periodic cleanup complete — deleted rows: {deleted}")

    def _prune_stale_rows(self) -> dict:
        """Execute all time-based DELETE statements. Returns counts of deleted rows."""
        import time as _time
        conn = self._get_conn()
        now = _time.time()
        cutoff_30d = now - 30 * 86400
        cutoff_7d  = now - 7 * 86400
        cutoff_48h = now - 48 * 3600

        deleted: dict[str, int] = {}

        # Commit after each DELETE to release the write lock between tables,
        # preventing long lock holds that would starve other greenlets.
        cur = conn.execute("DELETE FROM sequence_events WHERE ts < ?", (cutoff_30d,))
        deleted["sequence_events"] = cur.rowcount
        conn.commit()

        cur = conn.execute("DELETE FROM revoked_tokens WHERE revoked_at < ?", (cutoff_7d,))
        deleted["revoked_tokens"] = cur.rowcount
        conn.commit()

        cur = conn.execute("DELETE FROM sensor_fetch_log WHERE ts < ?", (cutoff_7d,))
        deleted["sensor_fetch_log"] = cur.rowcount
        conn.commit()

        cur = conn.execute("DELETE FROM llm_call_log WHERE ts < ?", (cutoff_7d,))
        deleted["llm_call_log"] = cur.rowcount
        conn.commit()

        cur = conn.execute(
            "DELETE FROM noise_exclusion WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        deleted["noise_exclusion"] = cur.rowcount
        conn.commit()

        cur = conn.execute("DELETE FROM climate_events WHERE ts < ?", (cutoff_48h,))
        deleted["climate_events"] = cur.rowcount
        conn.commit()

        cur = conn.execute("DELETE FROM situation_wire WHERE ts < ?", (cutoff_48h,))
        deleted["situation_wire"] = cur.rowcount
        conn.commit()

        # LLM intel: retain based on INTEL_RETENTION_DAYS config (default 7d)
        import os as _os
        cutoff_intel = now - int(_os.getenv("INTEL_RETENTION_DAYS", "7")) * 86400
        cur = conn.execute("DELETE FROM llm_intel WHERE created_at < ?", (cutoff_intel,))
        deleted["llm_intel"] = cur.rowcount
        conn.commit()

        return deleted

    # ── Climate Events ─────────────────────────────────────────────────────
    def climate_events_save(self, events: list[dict]):
        """Persist climate events. Replaces existing entries with same (indicator, theater, hour)."""
        if not events:
            return
        conn = self._get_conn()
        # Delete old entries matching same dedup key (indicator, theater, hour_bucket)
        for e in events:
            hour_bucket = int(e["ts"] // 3600)
            hour_start = hour_bucket * 3600
            hour_end = hour_start + 3600
            conn.execute(
                "DELETE FROM climate_events WHERE indicator=? AND theater=? AND ts>=? AND ts<?",
                (e["indicator"], e.get("theater", ""), hour_start, hour_end),
            )
        with conn.writing():
            conn.executemany(
                "INSERT INTO climate_events (ts, indicator, axis, headline, detail, severity, theater, meta_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [(e["ts"], e["indicator"], e["axis"], e["headline"], e["detail"],
                  e.get("severity", 0), e.get("theater", ""), json.dumps(e.get("meta", {})))
                 for e in events],
            )

    def climate_events_load(self, since_ts: float) -> list[dict]:
        """Load climate events since a given timestamp."""
        rows = self._get_conn().execute(
            "SELECT ts, indicator, axis, headline, detail, severity, theater, meta_json "
            "FROM climate_events WHERE ts > ? ORDER BY ts",
            (since_ts,),
        ).fetchall()
        result = []
        for r in rows:
            result.append({
                "ts": r["ts"], "indicator": r["indicator"], "axis": r["axis"],
                "headline": r["headline"], "detail": r["detail"],
                "severity": r["severity"], "theater": r["theater"],
                "meta": json.loads(r["meta_json"]) if r["meta_json"] else {},
            })
        return result

    def climate_events_prune(self, before_ts: float):
        """Remove climate events older than given timestamp."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM climate_events WHERE ts < ?", (before_ts,))

    # ── Situation Wire ───────────────────────────────────────────────────────
    def situation_wire_save(self, items: list[dict]):
        """Persist wire items. Replaces existing entries with same (theater, source, hour)."""
        if not items:
            return
        conn = self._get_conn()
        # Delete old entries matching same dedup key (theater, source, hour_bucket)
        for w in items:
            hour_bucket = int(w["ts"] // 3600)
            hour_start = hour_bucket * 3600
            hour_end = hour_start + 3600
            conn.execute(
                "DELETE FROM situation_wire WHERE theater=? AND source=? AND ts>=? AND ts<?",
                (w["theater"], w["source"], hour_start, hour_end),
            )
        with conn.writing():
            conn.executemany(
                "INSERT INTO situation_wire (ts, theater, source, text, severity) "
                "VALUES (?, ?, ?, ?, ?)",
                [(w["ts"], w["theater"], w["source"], w["text"], w.get("severity", 0))
                 for w in items],
            )

    def situation_wire_load(self, since_ts: float) -> list[dict]:
        """Load wire items since a given timestamp."""
        rows = self._get_conn().execute(
            "SELECT ts, theater, source, text, severity "
            "FROM situation_wire WHERE ts > ? ORDER BY ts",
            (since_ts,),
        ).fetchall()
        return [{"ts": r["ts"], "theater": r["theater"], "source": r["source"],
                 "text": r["text"], "severity": r["severity"]} for r in rows]

    def situation_wire_prune(self, before_ts: float):
        """Remove wire items older than given timestamp."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM situation_wire WHERE ts < ?", (before_ts,))

    # ── LLM Intel ───────────────────────────────────────────────────────────
    def intel_upsert(self, item: dict):
        """Insert or replace an LLM intel item."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO llm_intel "
                "(id, source_type, source_id, theater, ts, status, confidence, "
                "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
                "confirmed_by, confirmed_at, override_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item["id"], item["source_type"], item.get("source_id", ""),
                 item.get("theater", ""), item["ts"], item.get("status", "pending"),
                 item.get("confidence", 0.0), item.get("raw_text", ""),
                 item.get("raw_url", ""), item.get("headline", ""),
                 json.dumps(item.get("llm_fields", {})),
                 item.get("score_delta", 0.0), item.get("domain", "info"),
                 item.get("confirmed_by"), item.get("confirmed_at"),
                 item.get("override_at"), item.get("created_at", time.time())),
            )

    def intel_update_status(self, item_id: str, status: str,
                            confirmed_by: str = None, confirmed_at: float = None,
                            override_at: float = None):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "UPDATE llm_intel SET status=?, confirmed_by=?, confirmed_at=?, override_at=? "
                "WHERE id=?",
                (status, confirmed_by, confirmed_at, override_at, item_id),
            )

    def intel_get(self, item_id: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT id, source_type, source_id, theater, ts, status, confidence, "
            "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
            "confirmed_by, confirmed_at, override_at, created_at FROM llm_intel WHERE id=?",
            (item_id,),
        ).fetchone()
        return self._intel_row_to_dict(row) if row else None

    def intel_list(self, source_type: str = None, status: str = None,
                   theater: str = None, limit: int = 100,
                   since_ts: float = None, before_ts: float = None) -> list[dict]:
        q = ("SELECT id, source_type, source_id, theater, ts, status, confidence, "
             "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
             "confirmed_by, confirmed_at, override_at, created_at FROM llm_intel WHERE 1=1")
        params = []
        if source_type:
            q += " AND source_type=?"
            params.append(source_type)
        if status:
            q += " AND status=?"
            params.append(status)
        if theater:
            q += " AND theater=?"
            params.append(theater)
        if since_ts is not None:
            q += " AND ts >= ?"
            params.append(since_ts)
        if before_ts is not None:
            q += " AND created_at < ?"
            params.append(before_ts)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = self._get_conn().execute(q, params).fetchall()
        return [self._intel_row_to_dict(r) for r in rows]

    def intel_status_counts(self) -> dict[str, int]:
        """Return {status: count} for all intel items using GROUP BY."""
        rows = self._get_conn().execute(
            "SELECT status, COUNT(*) FROM llm_intel GROUP BY status"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def intel_update_llm_fields(self, item_id: str, llm_fields: dict):
        """Merge new key/value pairs into an existing item's llm_fields JSON blob.

        Uses BEGIN IMMEDIATE to ensure atomic read-modify-write across greenlets.
        """
        conn = self._get_conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT llm_fields FROM llm_intel WHERE id=?", (item_id,)
            ).fetchone()
            if not row:
                conn.rollback()
                return
            existing = json.loads(row[0]) if row[0] else {}
            existing.update(llm_fields)
            conn.execute(
                "UPDATE llm_intel SET llm_fields=? WHERE id=?",
                (json.dumps(existing), item_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def intel_update_core_fields(self, item_id: str, headline: str,
                                  confidence: float, score_delta: float,
                                  raw_text: str, raw_url: str):
        """Update headline, confidence, score_delta, raw_text, raw_url for an existing item."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "UPDATE llm_intel SET headline=?, confidence=?, score_delta=?, "
                "raw_text=?, raw_url=? WHERE id=?",
                (headline, confidence, score_delta, raw_text, raw_url, item_id),
            )

    def intel_active_in_window(self, since_ts: float) -> list[dict]:
        """Items that were auto_confirmed or confirmed in the given time window (for CLASSIFY THREAT linking)."""
        rows = self._get_conn().execute(
            "SELECT id, source_type, source_id, theater, ts, status, confidence, "
            "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
            "confirmed_by, confirmed_at, override_at, created_at FROM llm_intel "
            "WHERE status IN ('auto_confirmed', 'confirmed') AND ts >= ? "
            "ORDER BY ts DESC LIMIT 20",
            (since_ts,),
        ).fetchall()
        return [self._intel_row_to_dict(r) for r in rows]

    def _intel_row_to_dict(self, r) -> dict:
        return {
            "id": r[0], "source_type": r[1], "source_id": r[2],
            "theater": r[3], "ts": r[4], "status": r[5],
            "confidence": r[6], "raw_text": r[7], "raw_url": r[8],
            "headline": r[9], "llm_fields": json.loads(r[10]),
            "score_delta": r[11], "domain": r[12],
            "confirmed_by": r[13], "confirmed_at": r[14],
            "override_at": r[15], "created_at": r[16],
        }

    def intel_source_get(self, source_id: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT source_id, source_type, credibility_weight, confirmed_count, "
            "false_positive_count, last_updated FROM llm_sources WHERE source_id=?",
            (source_id,),
        ).fetchone()
        if not row:
            return None
        return {"source_id": row[0], "source_type": row[1],
                "credibility_weight": row[2], "confirmed_count": row[3],
                "false_positive_count": row[4], "last_updated": row[5]}

    def intel_source_upsert(self, source_id: str, source_type: str,
                            credibility_weight: float = 0.70):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR IGNORE INTO llm_sources "
                "(source_id, source_type, credibility_weight, last_updated) "
                "VALUES (?, ?, ?, ?)",
                (source_id, source_type, credibility_weight, time.time()),
            )

    def intel_source_update_credibility(self, source_id: str, delta: float):
        """Adjust credibility weight by delta, clamped to [0.30, 0.95]."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "UPDATE llm_sources SET "
                "credibility_weight = MAX(0.30, MIN(0.95, credibility_weight + ?)), "
                "last_updated = ? WHERE source_id=?",
                (delta, time.time(), source_id),
            )

    def intel_source_record_outcome(self, source_id: str, confirmed: bool):
        """Increment confirmed_count or false_positive_count and adjust credibility."""
        conn = self._get_conn()
        with conn.writing():
            if confirmed:
                conn.execute(
                    "UPDATE llm_sources SET confirmed_count = confirmed_count + 1, "
                    "credibility_weight = MAX(0.30, MIN(0.95, credibility_weight + 0.05)), "
                    "last_updated = ? WHERE source_id=?",
                    (time.time(), source_id),
                )
            else:
                conn.execute(
                    "UPDATE llm_sources SET false_positive_count = false_positive_count + 1, "
                    "credibility_weight = MAX(0.30, MIN(0.95, credibility_weight - 0.10)), "
                    "last_updated = ? WHERE source_id=?",
                    (time.time(), source_id),
                )

    def intel_source_list(self) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT source_id, source_type, credibility_weight, confirmed_count, "
            "false_positive_count, last_updated FROM llm_sources ORDER BY source_type, source_id"
        ).fetchall()
        return [{"source_id": r[0], "source_type": r[1], "credibility_weight": r[2],
                 "confirmed_count": r[3], "false_positive_count": r[4],
                 "last_updated": r[5]} for r in rows]

    # ── Auth ───────────────────────────────────────────────────────────────

    def user_count(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM users").fetchone()
        return row[0]

    def user_get(self, username: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT id, username, password_hash, salt, role, created_at, last_login "
            "FROM users WHERE username=?", (username,)
        ).fetchone()
        return dict(row) if row else None

    def user_get_role(self, username: str) -> Optional[str]:
        row = self._get_conn().execute(
            "SELECT role FROM users WHERE username=?", (username,)
        ).fetchone()
        return row[0] if row else None

    def user_create(self, username: str, password_hash: str, salt: str,
                    role: str, created_at: float) -> int:
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, salt, role, created_at),
            )
            user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        return user_id

    def user_exists(self, username: str) -> bool:
        row = self._get_conn().execute(
            "SELECT 1 FROM users WHERE username=?", (username,)
        ).fetchone()
        return row is not None

    def user_update_last_login(self, user_id: int, ts: float):
        conn = self._get_conn()
        with conn.writing():
            conn.execute("UPDATE users SET last_login=? WHERE id=?", (ts, user_id))

    def user_update_role(self, user_id: int, role: str):
        conn = self._get_conn()
        with conn.writing():
            conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))

    def user_update_password(self, user_id: int, password_hash: str, salt: str):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "UPDATE users SET password_hash=?, salt=? WHERE id=?",
                (password_hash, salt, user_id),
            )

    def user_delete(self, user_id: int):
        conn = self._get_conn()
        conn.execute("DELETE FROM user_settings WHERE user_id=?", (user_id,))
        with conn.writing():
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))

    def user_list(self) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT username, role, created_at, last_login FROM users ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    def user_settings_get(self, username: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT us.core, us.pins, us.correlates, us.adversaries, us.muted, us.lang "
            "FROM user_settings us JOIN users u ON us.user_id = u.id "
            "WHERE u.username=?", (username,)
        ).fetchone()
        return dict(row) if row else None

    def user_settings_create(self, user_id: int, core: str, pins: str,
                             correlates: str, adversaries: str,
                             muted: str, lang: str, updated_at: float):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO user_settings "
                "(user_id, core, pins, correlates, adversaries, muted, lang, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (user_id, core, pins, correlates, adversaries, muted, lang, updated_at),
            )

    def user_settings_update(self, user_id: int, updates: dict):
        conn = self._get_conn()
        set_clause = ", ".join(f"{k}=?" for k in updates)
        with conn.writing():
            conn.execute(
                f"UPDATE user_settings SET {set_clause} WHERE user_id=?",
                (*updates.values(), user_id),
            )

    def token_revoke(self, jti: str, revoked_at: float):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)",
                (jti, revoked_at),
            )

    def token_is_revoked(self, jti: str) -> bool:
        row = self._get_conn().execute(
            "SELECT 1 FROM revoked_tokens WHERE jti=?", (jti,)
        ).fetchone()
        return row is not None

    # ── Utility ─────────────────────────────────────────────────────────────
    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn:
            conn.close()
            self._local.conn = None


# ── Module-level singleton ──────────────────────────────────────────────────
from radar.config import PERSISTENCE_DIR  # noqa: E402

_DB_PATH = os.path.join(PERSISTENCE_DIR, "radar.db")
db = RadarDB(_DB_PATH)
