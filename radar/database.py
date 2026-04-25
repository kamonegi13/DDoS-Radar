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
PRAGMA synchronous = NORMAL;
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
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    caller          TEXT NOT NULL,
    model           TEXT NOT NULL DEFAULT '',
    duration_ms     INTEGER DEFAULT 0,
    outcome         TEXT NOT NULL DEFAULT '',
    verdict         TEXT NOT NULL DEFAULT '',
    confidence      REAL DEFAULT 0,
    headline        TEXT DEFAULT '',
    error           TEXT DEFAULT '',
    -- v2.0 ADR-V2-009: FK to llm_prompts.prompt_sha256 (NP6 disclosure).
    prompt_sha256   TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_call_log_ts     ON llm_call_log (ts);
CREATE INDEX IF NOT EXISTS idx_llm_call_log_caller ON llm_call_log (caller, ts);

-- v2.0 ADR-V2-009: sha256-deduplicated LLM prompt store.
-- Every llm_client invocation persists its prompt here; llm_call_log.prompt_sha256
-- references this table. Lets analysts retrieve the exact prompt text that
-- produced any conclusion (NP6 full disclosure).
CREATE TABLE IF NOT EXISTS llm_prompts (
    prompt_sha256  TEXT PRIMARY KEY,
    prompt_text    TEXT NOT NULL,
    model          TEXT NOT NULL,
    temperature    REAL,
    prompt_version TEXT,
    first_seen_at  REAL NOT NULL,
    last_seen_at   REAL NOT NULL,
    use_count      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_llm_prompts_last_seen ON llm_prompts (last_seen_at DESC);

-- v2.0 ADR-V2-001 + ADR-V2-008: append-only ledger for every Conclusion the tool emits.
-- Single output schema for all 5 domains (TL, trend, per_domain, anomaly, attack_mode).
-- Retention 365 days (configurable). Never UPDATE — historical truth.
CREATE TABLE IF NOT EXISTS conclusions (
    id                            TEXT PRIMARY KEY,
    scenario_id                   TEXT NOT NULL,
    conclusion_type               TEXT NOT NULL,
    state                         TEXT,
    confidence                    REAL NOT NULL,
    observed_at                   REAL NOT NULL,
    formula_ref                   TEXT NOT NULL,
    threshold_ref                 TEXT NOT NULL,
    source_urls                   TEXT NOT NULL,
    llm_prompt_sha256             TEXT,
    calibration_status            TEXT NOT NULL,
    conclusion_unavailable_reason TEXT,
    metadata                      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_conclusions_scenario_time
    ON conclusions (scenario_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_conclusions_type_time
    ON conclusions (conclusion_type, observed_at DESC);

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
    created_at    REAL NOT NULL,
    countries     TEXT NOT NULL DEFAULT '[]',
    country_weights TEXT NOT NULL DEFAULT '{}'
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

-- Auth: per-user scenario-centric settings (ADR-005)
CREATE TABLE IF NOT EXISTS user_settings (
    user_id           INTEGER PRIMARY KEY REFERENCES users(id),
    focused_scenario  TEXT,
    muted             TEXT NOT NULL DEFAULT '[]',
    lang              TEXT NOT NULL DEFAULT 'en',
    updated_at        REAL NOT NULL
);

-- Auth: JWT revocation list
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti         TEXT PRIMARY KEY,
    revoked_at  REAL NOT NULL
);

-- C-medium migration evaluation (§9.3.1) + shadow sampling (ADR-025)
-- Records every focused-scenario change (analyst-driven or shadow-synthesized)
-- so we can measure whether a switch was a "miss" by C-lite.
CREATE TABLE IF NOT EXISTS focus_switch_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id       TEXT NOT NULL,
    switched_at       REAL NOT NULL,
    lite_score        REAL NOT NULL,
    full_score        REAL NOT NULL,
    delta             REAL NOT NULL,
    is_miss           INTEGER NOT NULL DEFAULT 0,
    source            TEXT NOT NULL DEFAULT 'analyst',
    shadow_score_kind TEXT
);
CREATE INDEX IF NOT EXISTS idx_focus_switch_log_time
    ON focus_switch_log (switched_at DESC);
-- NOTE: idx_focus_switch_log_source_time is created in migration v13
-- (not here) because existing deployments may have a pre-v13
-- focus_switch_log without the `source` column, and this baseline runs
-- before migrations. Fresh DBs get the index via _post_baseline_indexes().

-- Round-robin state for ShadowSampler (ADR-025): least-recently-sampled
-- selection persists across restarts to avoid post-restart bias.
CREATE TABLE IF NOT EXISTS shadow_sampler_state (
    scenario_id      TEXT PRIMARY KEY,
    last_sampled_at  REAL NOT NULL,
    sample_count     INTEGER NOT NULL DEFAULT 0,
    last_lite_score  REAL,
    last_full_score  REAL,
    last_delta       REAL
);

-- Tier 1 calibration: shadow scoring log (ADR-015 dual-weight evaluation)
CREATE TABLE IF NOT EXISTS shadow_eval_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_at      REAL NOT NULL,
    scenario_id     TEXT NOT NULL,
    shadow_variant  TEXT NOT NULL,
    actual_score    REAL NOT NULL,
    actual_tl       INTEGER,
    shadow_score    REAL NOT NULL,
    shadow_tl       INTEGER,
    delta           REAL NOT NULL,
    active_countries TEXT NOT NULL DEFAULT '[]',
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_shadow_eval_log_sid
    ON shadow_eval_log (scenario_id, sampled_at DESC);
CREATE INDEX IF NOT EXISTS idx_shadow_eval_log_variant
    ON shadow_eval_log (shadow_variant, sampled_at DESC);

-- ADR-024 redesign: per-domain known-CA history for CT log anomaly detection
CREATE TABLE IF NOT EXISTS ct_log_known_ca_per_domain (
    domain          TEXT NOT NULL,
    ca_normalized   TEXT NOT NULL,
    ca_raw          TEXT NOT NULL,
    first_seen      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    cert_count      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (domain, ca_normalized)
);
CREATE INDEX IF NOT EXISTS idx_ct_known_ca_domain
    ON ct_log_known_ca_per_domain (domain);
CREATE TABLE IF NOT EXISTS ct_log_domain_first_observed (
    domain          TEXT PRIMARY KEY,
    first_observed  REAL NOT NULL
);
"""

# Column name mapping for parameterized HOD methods.
# SAFETY: table/col names used in f-string SQL interpolation are restricted
# to this allowlist — no user input reaches these identifiers.
_VALUE_COL: dict[str, str] = {
    "hod_baseline":  "avg_spike",
    "checkhost_hod": "success_rate",
    "bgp_hod":       "prefix_count",
}

_HOD_TABLES: frozenset[str] = frozenset(_VALUE_COL.keys())


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
        try:
            return self._conn.executescript(sql)
        except Exception:
            if self._holding:
                self._holding = False
                self._wlock.release()
            raise

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
            raw.execute("PRAGMA synchronous = NORMAL")
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
            self._post_baseline_indexes(conn)

    def _post_baseline_indexes(self, conn: "_CooperativeConn"):
        """Indexes that depend on migration-added columns. Created after
        baseline + migrations have both run, so columns are guaranteed
        present regardless of whether the DB is fresh or upgraded.
        """
        try:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_focus_switch_log_source_time "
                "ON focus_switch_log (source, switched_at DESC)"
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            log.warning("[DB] post-baseline index skipped: %s", e)

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
        (3, "Add scenario tables and sequence_events.scenario_id", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS scenarios (
                id              TEXT PRIMARY KEY,
                name_en         TEXT NOT NULL,
                name_ja         TEXT NOT NULL,
                description_en  TEXT,
                description_ja  TEXT,
                core_country    TEXT,
                state           TEXT NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'paused', 'archived')),
                enabled         INTEGER NOT NULL DEFAULT 1,
                tier            INTEGER NOT NULL DEFAULT 1,
                created_at      REAL NOT NULL,
                updated_at      REAL NOT NULL,
                updated_by      TEXT
            )"""),
            conn.execute("""CREATE TABLE IF NOT EXISTS scenario_participants (
                scenario_id TEXT NOT NULL,
                country     TEXT NOT NULL,
                weight      REAL NOT NULL CHECK (weight >= 0.0 AND weight <= 1.0),
                role        TEXT NOT NULL
                    CHECK (role IN (
                        'primary_target', 'principal_belligerent', 'adversary',
                        'primary_ally', 'forward_base', 'secondary_ally',
                        'extended_deterrence', 'strategic_observer',
                        'proxy_front', 'force_projection', 'secondary_party',
                        'spillover_risk', 'regional_power'
                    )),
                PRIMARY KEY (scenario_id, country),
                FOREIGN KEY (scenario_id) REFERENCES scenarios(id) ON DELETE CASCADE
            )"""),
            conn.execute("""CREATE TABLE IF NOT EXISTS scenario_change_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id TEXT NOT NULL,
                changed_at  REAL NOT NULL,
                changed_by  TEXT,
                change_type TEXT NOT NULL
                    CHECK (change_type IN (
                        'create', 'update', 'delete', 'archive',
                        'restore', 'purge', 'reset'
                    )),
                diff_json   TEXT
            )"""),
            conn.execute("""CREATE TABLE IF NOT EXISTS scenario_reserved_ids (
                id          TEXT PRIMARY KEY,
                reserved_at REAL NOT NULL,
                reserved_by TEXT,
                reason      TEXT
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_scenario_participants_sid
                ON scenario_participants (scenario_id)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_scenario_change_log_sid
                ON scenario_change_log (scenario_id, changed_at DESC)"""),
        ]),
        (4, "Add scenario_id column to sequence_events", lambda conn: [
            conn.execute("ALTER TABLE sequence_events ADD COLUMN scenario_id TEXT"),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_sequence_events_scenario
                ON sequence_events (scenario_id)"""),
        ]),
        (5, "Add scenario_tl_observation table for TL baseline calibration", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS scenario_tl_observation (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id  TEXT NOT NULL,
                observed_at  REAL NOT NULL,
                score        REAL NOT NULL,
                tl           INTEGER,
                cyber        REAL NOT NULL DEFAULT 0,
                physical     REAL NOT NULL DEFAULT 0,
                info         REAL NOT NULL DEFAULT 0,
                convergence_bonus REAL NOT NULL DEFAULT 0,
                scoring_mode TEXT NOT NULL DEFAULT 'full',
                active_countries TEXT NOT NULL DEFAULT '[]'
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_scenario_tl_obs_sid
                ON scenario_tl_observation (scenario_id, observed_at DESC)"""),
        ]),
        (6, "Add countries/country_weights to llm_intel, backfill from theater", lambda conn: [
            conn.execute("ALTER TABLE llm_intel ADD COLUMN countries TEXT NOT NULL DEFAULT '[]'"),
            conn.execute("ALTER TABLE llm_intel ADD COLUMN country_weights TEXT NOT NULL DEFAULT '{}'"),
            conn.execute("""
                UPDATE llm_intel
                SET countries = CASE
                    WHEN theater IS NOT NULL AND theater != '' THEN '["' || theater || '"]'
                    ELSE '[]'
                END,
                country_weights = CASE
                    WHEN theater IS NOT NULL AND theater != '' THEN '{"' || theater || '": 1.0}'
                    ELSE '{}'
                END
            """),
        ]),
        (7, "Add focus_switch_log table for C-medium migration metrics", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS focus_switch_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id  TEXT NOT NULL,
                switched_at  REAL NOT NULL,
                lite_score   REAL NOT NULL,
                full_score   REAL NOT NULL,
                delta        REAL NOT NULL,
                is_miss      INTEGER NOT NULL DEFAULT 0
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_focus_switch_log_time
                ON focus_switch_log (switched_at DESC)"""),
        ]),
        (8, "Replace user_settings country columns with focused_scenario (ADR-005)", lambda conn: [
            # Rebuild table to drop legacy country-centric columns
            # (core/pins/correlates/adversaries) in a single atomic step.
            # Preserves per-user muted/lang state; focused_scenario starts NULL
            # and callers fall back to DEFAULT_FOCUSED_SCENARIO.
            conn.execute("""CREATE TABLE user_settings_new (
                user_id          INTEGER PRIMARY KEY REFERENCES users(id),
                focused_scenario TEXT,
                muted            TEXT NOT NULL DEFAULT '[]',
                lang             TEXT NOT NULL DEFAULT 'en',
                updated_at       REAL NOT NULL
            )"""),
            conn.execute("""INSERT INTO user_settings_new
                (user_id, focused_scenario, muted, lang, updated_at)
                SELECT user_id, NULL, muted, lang, updated_at FROM user_settings"""),
            conn.execute("DROP TABLE user_settings"),
            conn.execute("ALTER TABLE user_settings_new RENAME TO user_settings"),
        ]),
        (9, "Add invalidate_tokens_before column to users for session revocation", lambda conn: [
            conn.execute("ALTER TABLE users ADD COLUMN invalidate_tokens_before REAL"),
        ]),
        (10, "Add shadow_eval_log for ADR-015 dual-weight evaluation (Tier 1)", lambda conn: [
            # Records side-by-side scoring: actual (current dual-weight formula)
            # vs shadow (variant under evaluation, e.g. flat country_weight = 1.0).
            # Used to quantify whether the LLM country_weight is over-fitting
            # (R10/R13) before deciding to keep, tune, or drop ADR-015.
            conn.execute("""CREATE TABLE IF NOT EXISTS shadow_eval_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                sampled_at      REAL NOT NULL,
                scenario_id     TEXT NOT NULL,
                shadow_variant  TEXT NOT NULL,
                actual_score    REAL NOT NULL,
                actual_tl       INTEGER,
                shadow_score    REAL NOT NULL,
                shadow_tl       INTEGER,
                delta           REAL NOT NULL,
                active_countries TEXT NOT NULL DEFAULT '[]',
                notes           TEXT
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_shadow_eval_log_sid
                ON shadow_eval_log (scenario_id, sampled_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_shadow_eval_log_variant
                ON shadow_eval_log (shadow_variant, sampled_at DESC)"""),
        ]),
        (11, "Add ct_log per-domain known-CA history (ADR-024 redesign)", lambda conn: [
            # Per-domain CA fingerprint history — the heart of the
            # signal-model redesign. Each row records that we have observed
            # the named domain being issued a cert by the named CA at least
            # once. The presence of a row means "this CA is known-good for
            # this domain" and silences future detections.
            #
            # The design choice to dedup-by-(domain, ca_normalized) rather
            # than store every cert is deliberate: we don't need per-cert
            # forensic detail, only the set of issuers per domain. crt.sh
            # is the durable source of truth for cert-level forensics.
            conn.execute("""CREATE TABLE IF NOT EXISTS ct_log_known_ca_per_domain (
                domain          TEXT NOT NULL,
                ca_normalized   TEXT NOT NULL,
                ca_raw          TEXT NOT NULL,
                first_seen      REAL NOT NULL,
                last_seen       REAL NOT NULL,
                cert_count      INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (domain, ca_normalized)
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_ct_known_ca_domain
                ON ct_log_known_ca_per_domain (domain)"""),
            # Per-domain first-observation timestamp — used to gate
            # warm-up. Without this we cannot distinguish "this CA is
            # genuinely new" from "we just started monitoring this domain
            # and have no history yet". Separate table from
            # ct_log_known_ca_per_domain because we want the warm-up
            # timestamp to be set on the very first poll regardless of
            # whether any CA was observed (e.g. crt.sh returned empty).
            conn.execute("""CREATE TABLE IF NOT EXISTS ct_log_domain_first_observed (
                domain          TEXT PRIMARY KEY,
                first_observed  REAL NOT NULL
            )"""),
        ]),
        (12, "Drop situation_wire table (Situation Board backend removed)", lambda conn: [
            conn.execute("DROP TABLE IF EXISTS situation_wire"),
        ]),
        (13, "Add shadow sampling support: source column + state table (ADR-025)", lambda conn: [
            # Distinguish analyst-initiated focus switches from synthesized
            # shadow samples. Existing rows backfill to 'analyst' via DEFAULT.
            conn.execute("ALTER TABLE focus_switch_log ADD COLUMN source TEXT NOT NULL DEFAULT 'analyst'"),
            # NULL for analyst rows; 'pre_bonus' for shadow rows (ADR-028).
            conn.execute("ALTER TABLE focus_switch_log ADD COLUMN shadow_score_kind TEXT"),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_focus_switch_log_source_time
                ON focus_switch_log (source, switched_at DESC)"""),
            # Round-robin state for ShadowSampler — least-recently-sampled
            # selection persists across restarts to avoid post-restart
            # alphabetical-stampede pattern.
            conn.execute("""CREATE TABLE IF NOT EXISTS shadow_sampler_state (
                scenario_id      TEXT PRIMARY KEY,
                last_sampled_at  REAL NOT NULL,
                sample_count     INTEGER NOT NULL DEFAULT 0,
                last_lite_score  REAL,
                last_full_score  REAL,
                last_delta       REAL
            )"""),
        ]),
        (14, "Phase B: noise/discard visibility log (F4 Hidden Negative Signals)", lambda conn: [
            # Records every signal/intel item that was filtered before reaching
            # the score so analysts can audit the "what got hidden" question.
            # Source events: noise_exclusion match, low-confidence intel discard,
            # dedup eviction, sensor circuit-breaker open.
            conn.execute("""CREATE TABLE IF NOT EXISTS hidden_signal_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                logged_at    REAL NOT NULL,
                scenario_id  TEXT,
                country      TEXT,
                sensor       TEXT NOT NULL,
                domain       TEXT NOT NULL DEFAULT '',
                hide_reason  TEXT NOT NULL,
                detail_json  TEXT NOT NULL DEFAULT '{}'
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_hidden_signal_log_time
                ON hidden_signal_log (logged_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_hidden_signal_log_scenario
                ON hidden_signal_log (scenario_id, logged_at DESC)"""),
        ]),
        (15, "Phase B: scenario sensor coverage + disconfirming evidence (F5/F6)", lambda conn: [
            # Per-scenario per-sensor health snapshot for coverage-gap UI.
            # Updated on each scoring cycle from sensor circuit-breaker state
            # and last-fetch timestamps.
            conn.execute("""CREATE TABLE IF NOT EXISTS scenario_sensor_coverage (
                scenario_id    TEXT NOT NULL,
                sensor         TEXT NOT NULL,
                domain         TEXT NOT NULL DEFAULT '',
                last_success   REAL,
                last_attempt   REAL,
                state          TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (state IN ('healthy', 'stale', 'failing', 'disabled', 'unknown')),
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                updated_at     REAL NOT NULL,
                PRIMARY KEY (scenario_id, sensor)
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_scenario_sensor_coverage_state
                ON scenario_sensor_coverage (state, scenario_id)"""),
            # Analyst-tagged disconfirming evidence — signals that contradict
            # the scenario's threat hypothesis. Stored separately from the
            # normal score path so it doesn't influence TL but stays visible.
            conn.execute("""CREATE TABLE IF NOT EXISTS disconfirming_evidence (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id  TEXT NOT NULL,
                tagged_at    REAL NOT NULL,
                tagged_by    TEXT NOT NULL,
                source_kind  TEXT NOT NULL
                    CHECK (source_kind IN ('intel_item', 'rationale', 'manual_note')),
                source_ref   TEXT,
                summary      TEXT NOT NULL,
                strength     INTEGER NOT NULL DEFAULT 2
                    CHECK (strength BETWEEN 1 AND 5),
                retracted_at REAL,
                retracted_by TEXT
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_disconf_evidence_sid
                ON disconfirming_evidence (scenario_id, tagged_at DESC)"""),
        ]),
        (16, "Phase C: ACH matrix + dissenting view (F8/F13)", lambda conn: [
            # Analysis of Competing Hypotheses (Heuer): N hypotheses x M evidence.
            # ach_matrices is the analyst-defined working matrix per scenario;
            # ach_hypotheses and ach_evidence are the rows/columns;
            # ach_scores is the cell consistency rating.
            conn.execute("""CREATE TABLE IF NOT EXISTS ach_matrices (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id  TEXT NOT NULL,
                title        TEXT NOT NULL,
                created_by   TEXT NOT NULL,
                created_at   REAL NOT NULL,
                updated_at   REAL NOT NULL,
                archived_at  REAL
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_ach_matrices_sid
                ON ach_matrices (scenario_id, updated_at DESC)"""),
            conn.execute("""CREATE TABLE IF NOT EXISTS ach_hypotheses (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                matrix_id    INTEGER NOT NULL REFERENCES ach_matrices(id) ON DELETE CASCADE,
                ord          INTEGER NOT NULL DEFAULT 0,
                text         TEXT NOT NULL,
                is_null_hypothesis INTEGER NOT NULL DEFAULT 0
            )"""),
            conn.execute("""CREATE TABLE IF NOT EXISTS ach_evidence (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                matrix_id    INTEGER NOT NULL REFERENCES ach_matrices(id) ON DELETE CASCADE,
                ord          INTEGER NOT NULL DEFAULT 0,
                text         TEXT NOT NULL,
                source_ref   TEXT,
                credibility  INTEGER NOT NULL DEFAULT 3
                    CHECK (credibility BETWEEN 1 AND 5),
                relevance    INTEGER NOT NULL DEFAULT 3
                    CHECK (relevance BETWEEN 1 AND 5)
            )"""),
            # consistency: -2=strongly inconsistent, -1=inconsistent, 0=neutral,
            # 1=consistent, 2=strongly consistent (Heuer scale)
            conn.execute("""CREATE TABLE IF NOT EXISTS ach_scores (
                hypothesis_id INTEGER NOT NULL REFERENCES ach_hypotheses(id) ON DELETE CASCADE,
                evidence_id   INTEGER NOT NULL REFERENCES ach_evidence(id) ON DELETE CASCADE,
                consistency   INTEGER NOT NULL DEFAULT 0
                    CHECK (consistency BETWEEN -2 AND 2),
                note          TEXT,
                PRIMARY KEY (hypothesis_id, evidence_id)
            )"""),
            # Dissenting views: structured devil's-advocate channel per scenario.
            # Kept separate from the consensus rationale path.
            conn.execute("""CREATE TABLE IF NOT EXISTS dissenting_views (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id     TEXT NOT NULL,
                created_at      REAL NOT NULL,
                created_by      TEXT NOT NULL,
                title           TEXT NOT NULL,
                body            TEXT NOT NULL,
                argues_for_tl   INTEGER,
                resolved_at     REAL,
                resolved_by     TEXT,
                resolution_note TEXT
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_dissenting_views_sid
                ON dissenting_views (scenario_id, created_at DESC)"""),
        ]),
        (17, "Phase D: assumptions + premortem + decision ledger (F10/F11/F14)", lambda conn: [
            # Key Assumptions Check (KAC): per-scenario list of hypotheses
            # the analysis depends on. is_locked=1 means admin has frozen
            # the assumption as "team consensus"; analysts can still add
            # new ones and dispute via dissenting_views.
            conn.execute("""CREATE TABLE IF NOT EXISTS key_assumptions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id     TEXT NOT NULL,
                created_at      REAL NOT NULL,
                created_by      TEXT NOT NULL,
                updated_at      REAL NOT NULL,
                updated_by      TEXT,
                statement       TEXT NOT NULL,
                rationale       TEXT,
                confidence      TEXT NOT NULL DEFAULT 'medium'
                    CHECK (confidence IN ('low', 'medium', 'high')),
                is_locked       INTEGER NOT NULL DEFAULT 0,
                locked_at       REAL,
                locked_by       TEXT,
                invalidated_at  REAL,
                invalidated_by  TEXT,
                invalidation_note TEXT
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_key_assumptions_sid
                ON key_assumptions (scenario_id, created_at DESC)"""),
            conn.execute("""CREATE TABLE IF NOT EXISTS key_assumption_change_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                assumption_id   INTEGER NOT NULL REFERENCES key_assumptions(id) ON DELETE CASCADE,
                changed_at      REAL NOT NULL,
                changed_by      TEXT NOT NULL,
                change_type     TEXT NOT NULL
                    CHECK (change_type IN ('create', 'edit', 'lock', 'unlock',
                                           'invalidate', 'reinstate', 'delete')),
                before_json     TEXT,
                after_json      TEXT,
                note            TEXT
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_assumption_change_log_aid
                ON key_assumption_change_log (assumption_id, changed_at DESC)"""),
            # Pre-mortem entries: "if this scenario assessment turned out to
            # be wrong six months from now, what would have caused that?"
            # (Klein 2007). Analysts capture failure modes proactively.
            conn.execute("""CREATE TABLE IF NOT EXISTS premortem_entries (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id     TEXT NOT NULL,
                created_at      REAL NOT NULL,
                created_by      TEXT NOT NULL,
                failure_mode    TEXT NOT NULL
                    CHECK (failure_mode IN ('false_positive', 'false_negative', 'cognitive_bias')),
                imagined_outcome TEXT NOT NULL,
                root_cause      TEXT NOT NULL,
                early_warning   TEXT,
                mitigation      TEXT,
                resolved_at     REAL,
                resolved_by     TEXT
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_premortem_sid
                ON premortem_entries (scenario_id, created_at DESC)"""),
            # Decision Ledger: per-tab session log of analyst judgments.
            # session_id is browser-tab UUID stored in sessionStorage (F14).
            conn.execute("""CREATE TABLE IF NOT EXISTS decision_ledger (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                logged_at       REAL NOT NULL,
                user_id         INTEGER REFERENCES users(id),
                username        TEXT NOT NULL DEFAULT '',
                session_id      TEXT NOT NULL,
                scenario_id     TEXT,
                decision_type   TEXT NOT NULL,
                summary         TEXT NOT NULL,
                detail_json     TEXT NOT NULL DEFAULT '{}'
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_decision_ledger_session
                ON decision_ledger (session_id, logged_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_decision_ledger_scenario
                ON decision_ledger (scenario_id, logged_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_decision_ledger_user
                ON decision_ledger (user_id, logged_at DESC)"""),
        ]),
        (18, "Add scenario_contribution_log for weight calibration advisory (Item 2.2)", lambda conn: [
            # Per-cycle per-(scenario, country) contribution snapshot.
            # Aggregated over a window to compute observed_share vs
            # configured_share for the weight_advisory endpoint. Append-only
            # — never updated, so no transactional contention with scoring.
            conn.execute("""CREATE TABLE IF NOT EXISTS scenario_contribution_log (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id      TEXT NOT NULL,
                country          TEXT NOT NULL,
                contribution_sum REAL NOT NULL,
                logged_at        REAL NOT NULL
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_scenario_contrib_sid_time
                ON scenario_contribution_log (scenario_id, logged_at DESC)"""),
        ]),
        # v2.0 Phase 0 scaffolding (ADR-V2-001, ADR-V2-008).
        # Append-only ledger of every Conclusion the tool emits.
        (19, "v2.0: conclusions append-only ledger", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS conclusions (
                id                            TEXT PRIMARY KEY,
                scenario_id                   TEXT NOT NULL,
                conclusion_type               TEXT NOT NULL,
                state                         TEXT,
                confidence                    REAL NOT NULL,
                observed_at                   REAL NOT NULL,
                formula_ref                   TEXT NOT NULL,
                threshold_ref                 TEXT NOT NULL,
                source_urls                   TEXT NOT NULL,
                llm_prompt_sha256             TEXT,
                calibration_status            TEXT NOT NULL,
                conclusion_unavailable_reason TEXT,
                metadata                      TEXT NOT NULL
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_conclusions_scenario_time
                ON conclusions (scenario_id, observed_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_conclusions_type_time
                ON conclusions (conclusion_type, observed_at DESC)"""),
        ]),
        # v2.0 Phase 0 scaffolding (ADR-V2-009).
        # sha256-deduplicated LLM prompt store + FK column on llm_call_log.
        # The ALTER TABLE is irreversible in SQLite — back up before applying.
        (20, "v2.0: llm_prompts sha256 store + llm_call_log FK", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS llm_prompts (
                prompt_sha256  TEXT PRIMARY KEY,
                prompt_text    TEXT NOT NULL,
                model          TEXT NOT NULL,
                temperature    REAL,
                prompt_version TEXT,
                first_seen_at  REAL NOT NULL,
                last_seen_at   REAL NOT NULL,
                use_count      INTEGER NOT NULL DEFAULT 1
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_llm_prompts_last_seen
                ON llm_prompts (last_seen_at DESC)"""),
            # Add FK column to existing llm_call_log. SQLite cannot enforce FK
            # via ALTER, so we skip REFERENCES (we enforce in app code).
            conn.execute("""ALTER TABLE llm_call_log
                ADD COLUMN prompt_sha256 TEXT"""),
        ]),
    ]

    def _run_migrations(self, conn: "_CooperativeConn"):
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
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
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
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
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
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
        col = _VALUE_COL[table]
        rows = self._get_conn().execute(
            f"SELECT {col} FROM {table} "
            f"WHERE theater=? AND (hour_bucket/3600)%24=? AND hour_bucket<?",
            (theater, target_hod, before_bucket),
        ).fetchall()
        return [r[0] for r in rows]

    def hod_last_bucket(self, table: str, theater: str) -> Optional[int]:
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
        row = self._get_conn().execute(
            f"SELECT MAX(hour_bucket) FROM {table} WHERE theater=?",
            (theater,),
        ).fetchone()
        return row[0] if row and row[0] is not None else None

    def hod_all_entries(self, table: str, theater: str) -> list[tuple[int, float]]:
        """Return [(hour_bucket, value), ...] ordered by hour_bucket."""
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
        col = _VALUE_COL[table]
        rows = self._get_conn().execute(
            f"SELECT hour_bucket, {col} FROM {table} "
            f"WHERE theater=? ORDER BY hour_bucket",
            (theater,),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def hod_existing_buckets(self, table: str, theater: str) -> set[int]:
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
        rows = self._get_conn().execute(
            f"SELECT hour_bucket FROM {table} WHERE theater=?",
            (theater,),
        ).fetchall()
        return {r[0] for r in rows}

    def hod_distinct_hours(self, table: str, theater: str) -> int:
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
        row = self._get_conn().execute(
            f"SELECT COUNT(DISTINCT (hour_bucket/3600)%24) FROM {table} WHERE theater=?",
            (theater,),
        ).fetchone()
        return row[0] if row else 0

    def hod_total_points(self, table: str) -> int:
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
        row = self._get_conn().execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return row[0] if row else 0

    def hod_total_points_theater(self, table: str, theater: str) -> int:
        if table not in _HOD_TABLES:
            raise ValueError(f"Invalid HOD table: {table!r}")
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

    def seq_append(self, theater: str, ts: float, event_type: str, meta: dict,
                   scenario_id: str | None = None):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO sequence_events (theater, ts, event_type, meta_json, scenario_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (theater, ts, event_type, json.dumps(meta, default=str), scenario_id),
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

    # ── scenario_tl_observation (Phase 2 baseline calibration) ──────────────
    def tl_observation_append(self, scenario_id: str, observed_at: float,
                              score: float, tl: int | None,
                              cyber: float, physical: float, info: float,
                              convergence_bonus: float, scoring_mode: str,
                              active_countries: list[str]):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO scenario_tl_observation "
                "(scenario_id, observed_at, score, tl, cyber, physical, info, "
                " convergence_bonus, scoring_mode, active_countries) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (scenario_id, observed_at, score, tl, cyber, physical, info,
                 convergence_bonus, scoring_mode,
                 json.dumps(active_countries)),
            )

    def scenario_history_start(self) -> float | None:
        """Return the earliest scenario_tl_observation timestamp, or None."""
        row = self._get_conn().execute(
            "SELECT MIN(observed_at) AS earliest FROM scenario_tl_observation"
        ).fetchone()
        return row["earliest"] if row and row["earliest"] else None

    # ── scenario_contribution_log (Item 2.2 weight advisory) ───────────────
    def scenario_contribution_append(self, scenario_id: str,
                                     contributions_by_country: dict[str, float],
                                     logged_at: float) -> None:
        """Persist this cycle's per-country contribution sums for a scenario.

        Empty contributions are intentionally still appended as a row with
        contribution_sum=0 so the aggregator can distinguish "no signal in
        the window" from "scenario was inactive in the window".
        """
        if not contributions_by_country:
            return
        conn = self._get_conn()
        with conn.writing():
            for country, total in contributions_by_country.items():
                conn.execute(
                    "INSERT INTO scenario_contribution_log "
                    "(scenario_id, country, contribution_sum, logged_at) "
                    "VALUES (?, ?, ?, ?)",
                    (scenario_id, country, float(total), logged_at),
                )

    def scenario_contributions_aggregate(self, scenario_id: str,
                                         hours: int = 168) -> dict[str, float]:
        """Sum per-country contributions for a scenario over a window.

        Returns ``{country: total_contribution}`` suitable for direct use
        as the ``contributions_by_country`` input to the weight_advisory
        helper after re-wrapping into ScenarioContribution objects.
        """
        cutoff = time.time() - hours * 3600
        rows = self._get_conn().execute(
            "SELECT country, SUM(contribution_sum) AS total "
            "FROM scenario_contribution_log "
            "WHERE scenario_id = ? AND logged_at > ? "
            "GROUP BY country",
            (scenario_id, cutoff),
        ).fetchall()
        return {r["country"]: float(r["total"] or 0.0) for r in rows}

    def scenario_contributions_rows(
        self, scenario_id: str, hours: int = 168,
    ) -> list[tuple[float, str, float]]:
        """Raw (logged_at, country, contribution_sum) rows for time-bucketed
        analysis. Used by the weight_advisory timeseries variant."""
        cutoff = time.time() - hours * 3600
        rows = self._get_conn().execute(
            "SELECT logged_at, country, contribution_sum "
            "FROM scenario_contribution_log "
            "WHERE scenario_id = ? AND logged_at > ? "
            "ORDER BY logged_at ASC",
            (scenario_id, cutoff),
        ).fetchall()
        return [
            (float(r["logged_at"]), r["country"], float(r["contribution_sum"] or 0.0))
            for r in rows
        ]

    # ── focus_switch_log (Section 9.3.1) ───────────────────────────────────
    def focus_switch_append(self, scenario_id: str, switched_at: float,
                            lite_score: float, full_score: float,
                            delta: float, is_miss: bool,
                            source: str = "analyst",
                            shadow_score_kind: str | None = None):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO focus_switch_log "
                "(scenario_id, switched_at, lite_score, full_score, delta, is_miss, "
                " source, shadow_score_kind) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scenario_id, switched_at, lite_score, full_score, delta,
                 1 if is_miss else 0, source, shadow_score_kind),
            )

    def focus_switch_stats(self, days: int = 28,
                           source: str | None = None) -> dict:
        """Return miss statistics for C-medium migration evaluation.

        source: when provided, restricts to rows with matching source
        ('analyst' or 'shadow_sampler'). None aggregates across all sources.
        """
        conn = self._get_conn()
        cutoff = time.time() - days * 86400
        if source is None:
            rows = conn.execute(
                "SELECT COUNT(*) AS total, "
                "  SUM(CASE WHEN is_miss = 1 THEN 1 ELSE 0 END) AS misses "
                "FROM focus_switch_log WHERE switched_at > ?",
                (cutoff,),
            ).fetchone()
        else:
            rows = conn.execute(
                "SELECT COUNT(*) AS total, "
                "  SUM(CASE WHEN is_miss = 1 THEN 1 ELSE 0 END) AS misses "
                "FROM focus_switch_log WHERE switched_at > ? AND source = ?",
                (cutoff, source),
            ).fetchone()
        return {
            "period_days": days,
            "source": source or "all",
            "total_switches": rows["total"] or 0,
            "misses": rows["misses"] or 0,
        }

    def focus_switch_detailed(self, days: int = 28,
                              source: str | None = None) -> dict:
        """Extended focus_switch_stats with delta distribution and per-scenario
        breakdown for the C-lite evaluation endpoint.

        source: when provided, restricts to rows with matching source.
        """
        conn = self._get_conn()
        cutoff = time.time() - days * 86400
        if source is None:
            rows = conn.execute(
                "SELECT scenario_id, switched_at, lite_score, full_score, "
                "  delta, is_miss, source, shadow_score_kind "
                "FROM focus_switch_log WHERE switched_at > ? "
                "ORDER BY switched_at DESC",
                (cutoff,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT scenario_id, switched_at, lite_score, full_score, "
                "  delta, is_miss, source, shadow_score_kind "
                "FROM focus_switch_log WHERE switched_at > ? AND source = ? "
                "ORDER BY switched_at DESC",
                (cutoff, source),
            ).fetchall()
        total = len(rows)
        misses = sum(1 for r in rows if r["is_miss"])
        deltas = [r["delta"] for r in rows]
        avg_delta = round(sum(deltas) / total, 2) if total else 0.0
        max_delta = round(max(deltas), 2) if deltas else 0.0
        miss_rate = round(misses / total, 3) if total else 0.0
        # Per-scenario breakdown
        by_scenario: dict[str, dict] = {}
        for r in rows:
            sid = r["scenario_id"]
            if sid not in by_scenario:
                by_scenario[sid] = {"switches": 0, "misses": 0,
                                    "deltas": []}
            by_scenario[sid]["switches"] += 1
            by_scenario[sid]["deltas"].append(r["delta"])
            if r["is_miss"]:
                by_scenario[sid]["misses"] += 1
        for v in by_scenario.values():
            v["avg_delta"] = round(sum(v["deltas"]) / len(v["deltas"]), 2)
            v["max_delta"] = round(max(v["deltas"]), 2)
            del v["deltas"]
        # Recommendation
        if total < 3:
            recommendation = "INSUFFICIENT_DATA"
        elif miss_rate > 0.15:
            recommendation = "CONSIDER_C_MEDIUM"
        else:
            recommendation = "LITE_SUFFICIENT"
        return {
            "period_days": days,
            "source": source or "all",
            "total_switches": total,
            "misses": misses,
            "miss_rate": miss_rate,
            "avg_delta": avg_delta,
            "max_delta": max_delta,
            "recommendation": recommendation,
            "by_scenario": by_scenario,
        }

    # ── shadow_sampler_state (ADR-025: background C-medium evaluation) ──────
    def shadow_sampler_state_get(self, scenario_id: str) -> dict | None:
        """Return the most recent shadow sampler state for a scenario, or None."""
        row = self._get_conn().execute(
            "SELECT scenario_id, last_sampled_at, sample_count, "
            "  last_lite_score, last_full_score, last_delta "
            "FROM shadow_sampler_state WHERE scenario_id = ?",
            (scenario_id,),
        ).fetchone()
        if not row:
            return None
        return {
            "scenario_id": row["scenario_id"],
            "last_sampled_at": row["last_sampled_at"],
            "sample_count": row["sample_count"],
            "last_lite_score": row["last_lite_score"],
            "last_full_score": row["last_full_score"],
            "last_delta": row["last_delta"],
        }

    def shadow_sampler_state_upsert(self, scenario_id: str,
                                    last_sampled_at: float,
                                    lite_score: float,
                                    full_score: float,
                                    delta: float) -> None:
        """Atomically upsert the shadow sampler state, incrementing sample_count."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO shadow_sampler_state "
                "(scenario_id, last_sampled_at, sample_count, "
                " last_lite_score, last_full_score, last_delta) "
                "VALUES (?, ?, 1, ?, ?, ?) "
                "ON CONFLICT(scenario_id) DO UPDATE SET "
                "  last_sampled_at = excluded.last_sampled_at, "
                "  sample_count = sample_count + 1, "
                "  last_lite_score = excluded.last_lite_score, "
                "  last_full_score = excluded.last_full_score, "
                "  last_delta = excluded.last_delta",
                (scenario_id, last_sampled_at,
                 round(lite_score, 4), round(full_score, 4), round(delta, 4)),
            )

    def shadow_sampler_least_recent_among(self, scenario_ids: list[str]) -> str | None:
        """Return the scenario_id from the candidate list that has the oldest
        last_sampled_at (or has never been sampled). Returns None if the input
        list is empty."""
        if not scenario_ids:
            return None
        conn = self._get_conn()
        placeholders = ",".join("?" * len(scenario_ids))
        rows = conn.execute(
            f"SELECT scenario_id, last_sampled_at "
            f"FROM shadow_sampler_state "
            f"WHERE scenario_id IN ({placeholders})",
            tuple(scenario_ids),
        ).fetchall()
        seen = {r["scenario_id"]: r["last_sampled_at"] for r in rows}
        # Never-sampled scenarios sort first (last_sampled_at = -inf)
        return min(scenario_ids,
                   key=lambda sid: seen.get(sid, float("-inf")))

    def shadow_sampler_daily_count(self, scenario_id: str | None = None) -> int:
        """Return the number of shadow_sampler entries in focus_switch_log
        within the last 24h. If scenario_id is None, counts globally."""
        conn = self._get_conn()
        cutoff = time.time() - 86400
        if scenario_id is None:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM focus_switch_log "
                "WHERE source = 'shadow_sampler' AND switched_at > ?",
                (cutoff,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM focus_switch_log "
                "WHERE source = 'shadow_sampler' AND scenario_id = ? "
                "  AND switched_at > ?",
                (scenario_id, cutoff),
            ).fetchone()
        return int(row["n"] or 0)

    def shadow_drift_stats(self, days: int = 28,
                           noise_band_pct: float = 25.0) -> dict:
        """Per-scenario lite-vs-full delta drift over the lookback window.

        Splits the window into early/recent halves and reports
        avg_delta + miss_rate per half plus a drift_direction signal
        (increasing / decreasing / stable / insufficient_data) and a
        signed magnitude_pct = (recent - early) / early * 100.

        Designed as an early-warning companion to cmedium_recommendation:
        flags scenarios where calibration is degrading well before the
        binary miss_rate threshold trips. Only shadow_sampler rows are
        counted — analyst rotations are sparse and event-driven, so
        their delta distribution is not a calibration signal.

        noise_band_pct: drift_direction is 'stable' when |magnitude| is
        within this band (default 25%) so analyst attention is not
        drawn to ordinary measurement noise.
        """
        now = time.time()
        cutoff = now - days * 86400
        midpoint = now - (days / 2.0) * 86400

        rows = self._get_conn().execute(
            "SELECT scenario_id, switched_at, delta, is_miss "
            "FROM focus_switch_log "
            "WHERE source = 'shadow_sampler' AND switched_at > ? "
            "ORDER BY scenario_id ASC, switched_at ASC",
            (cutoff,),
        ).fetchall()

        per_scenario: dict[str, dict] = {}
        for r in rows:
            sid = r["scenario_id"]
            bucket = "early" if r["switched_at"] < midpoint else "recent"
            slot = per_scenario.setdefault(sid, {
                "early_deltas": [], "recent_deltas": [],
                "early_misses": 0, "recent_misses": 0,
            })
            slot[f"{bucket}_deltas"].append(float(r["delta"]))
            if int(r["is_miss"] or 0):
                slot[f"{bucket}_misses"] += 1

        out: dict[str, dict] = {}
        for sid, s in per_scenario.items():
            early_n = len(s["early_deltas"])
            recent_n = len(s["recent_deltas"])
            early_avg = (sum(s["early_deltas"]) / early_n) if early_n else 0.0
            recent_avg = (sum(s["recent_deltas"]) / recent_n) if recent_n else 0.0
            early_miss_rate = (s["early_misses"] / early_n) if early_n else 0.0
            recent_miss_rate = (s["recent_misses"] / recent_n) if recent_n else 0.0

            if early_n == 0 or recent_n == 0:
                direction = "insufficient_data"
                magnitude_pct = 0.0
            elif early_avg <= 1e-6:
                # Avoid divide-by-zero; recent activity from a quiet baseline
                # is itself a drift signal — flag it without a magnitude pct.
                direction = "increasing" if recent_avg > 1e-3 else "stable"
                magnitude_pct = 0.0
            else:
                magnitude_pct = round(
                    (recent_avg - early_avg) / early_avg * 100.0, 1,
                )
                if abs(magnitude_pct) < noise_band_pct:
                    direction = "stable"
                elif magnitude_pct > 0:
                    direction = "increasing"
                else:
                    direction = "decreasing"

            out[sid] = {
                "sample_count": early_n + recent_n,
                "early_avg_delta": round(early_avg, 4),
                "recent_avg_delta": round(recent_avg, 4),
                "early_miss_rate": round(early_miss_rate, 3),
                "recent_miss_rate": round(recent_miss_rate, 3),
                "drift_direction": direction,
                "drift_magnitude_pct": magnitude_pct,
            }
        return {
            "period_days": days,
            "noise_band_pct": noise_band_pct,
            "by_scenario": out,
        }

    # ── shadow_eval_log (Tier 1: ADR-015 dual-weight evaluation) ───────────
    def shadow_eval_record(self, scenario_id: str, sampled_at: float,
                           shadow_variant: str,
                           actual_score: float, actual_tl: int | None,
                           shadow_score: float, shadow_tl: int | None,
                           active_countries: list[str],
                           notes: str | None = None) -> None:
        """Append a shadow evaluation sample.

        Records the divergence between the live (dual-weight) score and a
        shadow variant (e.g. flat country_weight = 1.0). The accumulated
        delta distribution is what the Tier 1 calibration endpoint reports
        on, and is the empirical basis for keeping or revising ADR-015.
        """
        delta = round(shadow_score - actual_score, 4)
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO shadow_eval_log "
                "(sampled_at, scenario_id, shadow_variant, actual_score, "
                " actual_tl, shadow_score, shadow_tl, delta, "
                " active_countries, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (sampled_at, scenario_id, shadow_variant,
                 round(actual_score, 4),
                 int(actual_tl) if actual_tl is not None else None,
                 round(shadow_score, 4),
                 int(shadow_tl) if shadow_tl is not None else None,
                 delta,
                 json.dumps(sorted(set(active_countries))),
                 notes),
            )

    def shadow_eval_summary(self, days: int = 14,
                            shadow_variant: str | None = None) -> dict:
        """Return aggregated shadow-eval statistics for the calibration endpoint.

        Output shape mirrors focus_switch_detailed() so the UI can reuse
        the same rendering primitives. Recommendation thresholds:
          - <30 samples → INSUFFICIENT_DATA
          - |avg_delta| > 1.5 OR tl_disagree_rate > 0.20 → REVIEW_DUAL_WEIGHT
          - otherwise → DUAL_WEIGHT_STABLE
        """
        conn = self._get_conn()
        cutoff = time.time() - days * 86400
        if shadow_variant:
            rows = conn.execute(
                "SELECT scenario_id, sampled_at, actual_score, actual_tl, "
                "  shadow_score, shadow_tl, delta, shadow_variant "
                "FROM shadow_eval_log "
                "WHERE sampled_at > ? AND shadow_variant = ? "
                "ORDER BY sampled_at DESC",
                (cutoff, shadow_variant),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT scenario_id, sampled_at, actual_score, actual_tl, "
                "  shadow_score, shadow_tl, delta, shadow_variant "
                "FROM shadow_eval_log "
                "WHERE sampled_at > ? "
                "ORDER BY sampled_at DESC",
                (cutoff,),
            ).fetchall()
        total = len(rows)
        if total == 0:
            return {
                "period_days": days,
                "shadow_variant": shadow_variant,
                "total_samples": 0,
                "recommendation": "INSUFFICIENT_DATA",
                "by_scenario": {},
            }
        deltas = [r["delta"] for r in rows]
        abs_deltas = [abs(d) for d in deltas]
        avg_delta = round(sum(deltas) / total, 3)
        avg_abs_delta = round(sum(abs_deltas) / total, 3)
        max_abs_delta = round(max(abs_deltas), 3)
        tl_disagree = sum(
            1 for r in rows
            if r["actual_tl"] is not None
            and r["shadow_tl"] is not None
            and r["actual_tl"] != r["shadow_tl"]
        )
        tl_disagree_rate = round(tl_disagree / total, 3)
        by_scenario: dict[str, dict] = {}
        for r in rows:
            sid = r["scenario_id"]
            slot = by_scenario.setdefault(sid, {
                "samples": 0,
                "tl_disagreements": 0,
                "_deltas": [],
            })
            slot["samples"] += 1
            slot["_deltas"].append(r["delta"])
            if (r["actual_tl"] is not None
                    and r["shadow_tl"] is not None
                    and r["actual_tl"] != r["shadow_tl"]):
                slot["tl_disagreements"] += 1
        for slot in by_scenario.values():
            d = slot.pop("_deltas")
            slot["avg_delta"] = round(sum(d) / len(d), 3)
            slot["avg_abs_delta"] = round(
                sum(abs(x) for x in d) / len(d), 3)
            slot["max_abs_delta"] = round(max(abs(x) for x in d), 3)
        if total < 30:
            recommendation = "INSUFFICIENT_DATA"
        elif avg_abs_delta > 1.5 or tl_disagree_rate > 0.20:
            recommendation = "REVIEW_DUAL_WEIGHT"
        else:
            recommendation = "DUAL_WEIGHT_STABLE"
        return {
            "period_days": days,
            "shadow_variant": shadow_variant,
            "total_samples": total,
            "avg_delta": avg_delta,
            "avg_abs_delta": avg_abs_delta,
            "max_abs_delta": max_abs_delta,
            "tl_disagreements": tl_disagree,
            "tl_disagree_rate": tl_disagree_rate,
            "recommendation": recommendation,
            "by_scenario": by_scenario,
        }

    def intel_count_24h_by_scenario(self, scenario_participants: dict[str, set[str]]) -> dict[str, int]:
        """Count LLM intel items (confirmed/auto_confirmed) in the last 24h per scenario.
        scenario_participants: {scenario_id: set_of_participant_country_codes}"""
        conn = self._get_conn()
        cutoff = time.time() - 86400
        rows = conn.execute(
            "SELECT countries FROM llm_intel "
            "WHERE ts > ? AND status IN ('confirmed', 'auto_confirmed')",
            (cutoff,),
        ).fetchall()
        counts: dict[str, int] = {sid: 0 for sid in scenario_participants}
        for row in rows:
            try:
                item_countries = set(json.loads(row["countries"]))
            except (json.JSONDecodeError, TypeError):
                continue
            for sid, participants in scenario_participants.items():
                if item_countries & participants:
                    counts[sid] += 1
        return counts

    def scenario_tl_last(self, scenario_id: str) -> int | None:
        """Return the most recent non-null TL observation for a scenario.
        Used for hysteresis: limits TL de-escalation to one step per cycle."""
        row = self._get_conn().execute(
            "SELECT tl FROM scenario_tl_observation "
            "WHERE scenario_id=? AND tl IS NOT NULL "
            "ORDER BY observed_at DESC LIMIT 1",
            (scenario_id,),
        ).fetchone()
        return row["tl"] if row else None

    def scenario_tl_duration_sec(self, scenario_id: str,
                                 current_tl: int | None) -> float | None:
        """Return seconds the scenario has been at current_tl, by walking
        scenario_tl_observation backwards from the latest until TL changes
        or the timeseries ends. Returns None if current_tl is None or no
        observations exist. Used to surface "TL3 for 4h12m" — combats
        normalcy bias by showing trajectory persistence."""
        if current_tl is None:
            return None
        rows = self._get_conn().execute(
            "SELECT observed_at, tl FROM scenario_tl_observation "
            "WHERE scenario_id=? "
            "ORDER BY observed_at DESC LIMIT 2000",
            (scenario_id,),
        ).fetchall()
        if not rows:
            return None
        latest_ts = rows[0]["observed_at"]
        earliest_same = latest_ts
        for r in rows:
            if r["tl"] == current_tl:
                earliest_same = r["observed_at"]
            else:
                break
        return max(0.0, latest_ts - earliest_same)

    def intel_count_for_scenario_window(self, participants: set[str],
                                        since_ts: float) -> int:
        """Count confirmed/auto_confirmed LLM intel touching any participant
        country since since_ts. Single-scenario variant of the bulk method
        intel_count_24h_by_scenario, suitable for arbitrary time windows."""
        if not participants:
            return 0
        rows = self._get_conn().execute(
            "SELECT countries FROM llm_intel "
            "WHERE ts > ? AND status IN ('confirmed', 'auto_confirmed')",
            (since_ts,),
        ).fetchall()
        n = 0
        for row in rows:
            try:
                if set(json.loads(row["countries"])) & participants:
                    n += 1
            except (json.JSONDecodeError, TypeError):
                continue
        return n

    def scenario_score_series(self, scenario_id: str,
                              limit: int = 20) -> list[tuple[float, float]]:
        """Return recent (observed_at, score) pairs for velocity computation.
        Ordered oldest-first for regression input."""
        rows = self._get_conn().execute(
            "SELECT observed_at, score FROM scenario_tl_observation "
            "WHERE scenario_id=? "
            "ORDER BY observed_at DESC LIMIT ?",
            (scenario_id, limit),
        ).fetchall()
        return [(r["observed_at"], r["score"]) for r in reversed(rows)]

    def scenario_score_at_or_before(self, scenario_id: str,
                                    target_ts: float) -> float | None:
        """Return the most recent observed score at or before target_ts.
        Used to compute background-scenario delta over a time window."""
        row = self._get_conn().execute(
            "SELECT score FROM scenario_tl_observation "
            "WHERE scenario_id=? AND observed_at <= ? "
            "ORDER BY observed_at DESC LIMIT 1",
            (scenario_id, target_ts),
        ).fetchone()
        return row["score"] if row else None

    def scenario_prev_lite_score(self, scenario_id: str,
                                 before_ts: float) -> float | None:
        """Return the most recent lite-mode score for a scenario strictly
        before before_ts. Used to compute focus-switch delta against the
        same scenario's pre-switch baseline (scenario-refactor §9.3.1)."""
        row = self._get_conn().execute(
            "SELECT score FROM scenario_tl_observation "
            "WHERE scenario_id=? AND scoring_mode='lite' "
            "  AND observed_at < ? "
            "ORDER BY observed_at DESC LIMIT 1",
            (scenario_id, before_ts),
        ).fetchone()
        return row["score"] if row else None

    def scenario_tl_timeseries(self, scenario_id: str, hours: int = 72,
                              limit: int = 500) -> list[dict]:
        """Return TL observation timeseries for a scenario."""
        conn = self._get_conn()
        cutoff = time.time() - hours * 3600
        rows = conn.execute(
            "SELECT observed_at, score, tl, cyber, physical, info, "
            "  convergence_bonus, scoring_mode, active_countries "
            "FROM scenario_tl_observation "
            "WHERE scenario_id=? AND observed_at>? "
            "ORDER BY observed_at DESC LIMIT ?",
            (scenario_id, cutoff, limit),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["active_countries"] = json.loads(d["active_countries"])
            except Exception:
                d["active_countries"] = []
            result.append(d)
        result.reverse()
        return result

    def scenario_country_timeseries(self, scenario_id: str, country: str,
                                     hours: int = 72) -> list[dict]:
        """Return TL observation timeseries filtered to entries where a specific
        country was active in the given scenario."""
        conn = self._get_conn()
        cutoff = time.time() - hours * 3600
        rows = conn.execute(
            "SELECT observed_at, score, tl, cyber, physical, info, "
            "  convergence_bonus, scoring_mode, active_countries "
            "FROM scenario_tl_observation "
            "WHERE scenario_id=? AND observed_at>? "
            "ORDER BY observed_at DESC LIMIT 500",
            (scenario_id, cutoff),
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                ac = json.loads(d["active_countries"])
            except Exception:
                ac = []
            if country in ac:
                d["active_countries"] = ac
                result.append(d)
        result.reverse()
        return result

    def tl_calibration_stats(self, scenario_id: str | None = None,
                             hours: int = 168) -> dict:
        """TL calibration monitoring data (Section 7.3.1).

        Returns per-TL distribution, score ranges per TL, and time-at-each-TL
        for recalibration analysis.  When scenario_id is None, aggregates
        across all scenarios.
        """
        conn = self._get_conn()
        cutoff = time.time() - hours * 3600
        if scenario_id:
            rows = conn.execute(
                "SELECT tl, score, observed_at FROM scenario_tl_observation "
                "WHERE scenario_id=? AND observed_at>? AND tl IS NOT NULL "
                "ORDER BY observed_at",
                (scenario_id, cutoff),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT tl, score, observed_at FROM scenario_tl_observation "
                "WHERE observed_at>? AND tl IS NOT NULL "
                "ORDER BY observed_at",
                (cutoff,),
            ).fetchall()

        tl_counts: dict[int, int] = {}
        tl_scores: dict[int, list[float]] = {}
        for r in rows:
            tl = r["tl"]
            tl_counts[tl] = tl_counts.get(tl, 0) + 1
            tl_scores.setdefault(tl, []).append(r["score"])

        total = sum(tl_counts.values())
        distribution = {}
        for tl in sorted(tl_counts.keys()):
            scores = tl_scores[tl]
            distribution[f"TL{tl}"] = {
                "count": tl_counts[tl],
                "pct": round(tl_counts[tl] / total * 100, 1) if total else 0,
                "score_min": round(min(scores), 2),
                "score_max": round(max(scores), 2),
                "score_avg": round(sum(scores) / len(scores), 2),
            }

        return {
            "hours": hours,
            "scenario_id": scenario_id,
            "total_observations": total,
            "distribution": distribution,
        }

    # ── scenario CRUD (Phase 4) ──────────────────────────────────────────────

    def scenario_get(self, scenario_id: str) -> dict | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
        if not row:
            return None
        result = dict(row)
        p_rows = conn.execute(
            "SELECT country, weight, role FROM scenario_participants WHERE scenario_id=?",
            (scenario_id,),
        ).fetchall()
        result["participants"] = {r["country"]: {"weight": r["weight"], "role": r["role"]} for r in p_rows}
        return result

    def scenario_list(self) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM scenarios ORDER BY tier, id").fetchall()
        result = []
        for row in rows:
            d = dict(row)
            p_rows = conn.execute(
                "SELECT country, weight, role FROM scenario_participants WHERE scenario_id=?",
                (row["id"],),
            ).fetchall()
            d["participants"] = {r["country"]: {"weight": r["weight"], "role": r["role"]} for r in p_rows}
            result.append(d)
        return result

    def scenario_upsert(self, scenario_id: str, data: dict, changed_by: str = "") -> None:
        conn = self._get_conn()
        now = time.time()
        existing = conn.execute("SELECT id FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
        change_type = "update" if existing else "create"

        with conn.writing():
            conn.execute(
                """INSERT INTO scenarios (id, name_en, name_ja, description_en, description_ja,
                   core_country, state, enabled, tier, created_at, updated_at, updated_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     name_en=excluded.name_en, name_ja=excluded.name_ja,
                     description_en=excluded.description_en, description_ja=excluded.description_ja,
                     core_country=excluded.core_country, state=excluded.state,
                     enabled=excluded.enabled, tier=excluded.tier,
                     updated_at=excluded.updated_at, updated_by=excluded.updated_by""",
                (scenario_id, data["name_en"], data["name_ja"],
                 data.get("description_en", ""), data.get("description_ja", ""),
                 data.get("core_country"), data.get("state", "active"),
                 1 if data.get("enabled", True) else 0,
                 data.get("tier", 1),
                 now, now, changed_by),
            )
            conn.execute("DELETE FROM scenario_participants WHERE scenario_id=?", (scenario_id,))
            for cc, pdata in data.get("participants", {}).items():
                conn.execute(
                    "INSERT INTO scenario_participants (scenario_id, country, weight, role) VALUES (?, ?, ?, ?)",
                    (scenario_id, cc, pdata["weight"], pdata["role"]),
                )
            conn.execute(
                "INSERT INTO scenario_change_log (scenario_id, changed_at, changed_by, change_type, diff_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (scenario_id, now, changed_by, change_type, json.dumps(data, ensure_ascii=False)),
            )

    # ADR-011 valid state transitions
    _STATE_TRANSITIONS: dict[str, dict[str, str]] = {
        # target_state: {required_current_state: change_type, ...}
        "paused":   {"active": "delete"},
        "archived": {"paused": "archive"},
        "active":   {"paused": "restore", "archived": "restore"},
    }

    def scenario_update_state(self, scenario_id: str, state: str, changed_by: str = "") -> tuple[bool, str]:
        """Returns (success, error_message). Error is empty on success."""
        conn = self._get_conn()
        row = conn.execute("SELECT id, state FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
        if not row:
            return False, "not_found"
        current_state = row["state"]
        allowed = self._STATE_TRANSITIONS.get(state)
        if not allowed or current_state not in allowed:
            return False, (
                f"Invalid transition: {current_state} -> {state}. "
                f"Allowed from {current_state}: "
                f"{[s for s, t in self._STATE_TRANSITIONS.items() if current_state in t]}"
            )
        change_type = allowed[current_state]
        now = time.time()
        with conn.writing():
            conn.execute(
                "UPDATE scenarios SET state=?, updated_at=?, updated_by=? WHERE id=?",
                (state, now, changed_by, scenario_id),
            )
            conn.execute(
                "INSERT INTO scenario_change_log (scenario_id, changed_at, changed_by, change_type, diff_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (scenario_id, now, changed_by, change_type, json.dumps({"state": state})),
            )
        return True, ""

    def scenario_set_enabled(self, scenario_id: str, enabled: bool, changed_by: str = "") -> bool:
        conn = self._get_conn()
        existing = conn.execute("SELECT id FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
        if not existing:
            return False
        now = time.time()
        with conn.writing():
            conn.execute(
                "UPDATE scenarios SET enabled=?, updated_at=?, updated_by=? WHERE id=?",
                (1 if enabled else 0, now, changed_by, scenario_id),
            )
            conn.execute(
                "INSERT INTO scenario_change_log (scenario_id, changed_at, changed_by, change_type, diff_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (scenario_id, now, changed_by, "update", json.dumps({"enabled": enabled})),
            )
        return True

    def scenario_delete(self, scenario_id: str, changed_by: str = "") -> tuple[bool, str]:
        """ADR-011: delete = active -> paused (semantic deletion, data retained)."""
        return self.scenario_update_state(scenario_id, "paused", changed_by)

    def scenario_purge(self, scenario_id: str, changed_by: str = "") -> tuple[bool, str]:
        """ADR-011: purge = archived -> permanent delete. Reserves the scenario_id."""
        conn = self._get_conn()
        row = conn.execute("SELECT id, state FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
        if not row:
            return False, "not_found"
        if row["state"] != "archived":
            return False, (
                f"Purge requires state=archived, current={row['state']}. "
                f"Transition: active -> paused (delete) -> archived (archive) -> purge"
            )
        now = time.time()
        with conn.writing():
            conn.execute("DELETE FROM scenarios WHERE id=?", (scenario_id,))
            conn.execute("DELETE FROM scenario_participants WHERE scenario_id=?", (scenario_id,))
            conn.execute("DELETE FROM scenario_tl_observation WHERE scenario_id=?", (scenario_id,))
            conn.execute(
                "INSERT INTO scenario_reserved_ids (id, reserved_at, reserved_by, reason) "
                "VALUES (?, ?, ?, ?)",
                (scenario_id, now, changed_by, "purged"),
            )
            conn.execute(
                "INSERT INTO scenario_change_log (scenario_id, changed_at, changed_by, change_type, diff_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (scenario_id, now, changed_by, "purge", None),
            )
        return True, ""

    def scenario_reset(self, scenario_id: str, changed_by: str = "") -> bool:
        conn = self._get_conn()
        with conn.writing():
            conn.execute("DELETE FROM scenarios WHERE id=?", (scenario_id,))
            conn.execute("DELETE FROM scenario_participants WHERE scenario_id=?", (scenario_id,))
            conn.execute(
                "INSERT INTO scenario_change_log (scenario_id, changed_at, changed_by, change_type, diff_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (scenario_id, time.time(), changed_by, "reset", None),
            )
        return True

    def scenario_change_log(self, scenario_id: str, limit: int = 50) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT * FROM scenario_change_log WHERE scenario_id=? ORDER BY changed_at DESC LIMIT ?",
            (scenario_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

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
                            error: str = "", prompt_sha256: str = ""):
        """Persist a single LLM call attempt and its downstream queue verdict.

        prompt_sha256: optional FK to llm_prompts (ADR-V2-009). Empty string
        when prompt persistence is disabled or persistence failed.
        """
        import time as _time
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO llm_call_log "
                "(ts, caller, model, duration_ms, outcome, verdict, confidence, headline, error, prompt_sha256) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_time.time(), caller, model[:80], duration_ms, outcome,
                 verdict, float(confidence), (headline or "")[:200], (error or "")[:300],
                 prompt_sha256 or None),
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
            "SUM(CASE WHEN outcome='pre_filter' THEN 1 ELSE 0 END) AS pre_filter, "
            "SUM(CASE WHEN verdict='auto_confirmed' THEN 1 ELSE 0 END) AS auto_confirmed, "
            "SUM(CASE WHEN verdict='pending' THEN 1 ELSE 0 END) AS pending, "
            "SUM(CASE WHEN verdict='discarded_low_conf' THEN 1 ELSE 0 END) AS discarded_low, "
            "SUM(CASE WHEN verdict='discarded_dedup' THEN 1 ELSE 0 END) AS discarded_dedup, "
            "SUM(CASE WHEN verdict LIKE 'sensor_filtered:%' THEN 1 ELSE 0 END) AS sensor_filtered, "
            "SUM(CASE WHEN verdict='' THEN 1 ELSE 0 END) AS verdict_empty, "
            "AVG(CASE WHEN outcome != 'pre_filter' THEN duration_ms END) AS avg_ms, "
            "AVG(CASE WHEN outcome = 'ok' THEN confidence END) AS avg_conf, "
            "MAX(ts) AS last_ts "
            "FROM llm_call_log WHERE ts>=? GROUP BY caller ORDER BY caller",
            (cutoff,),
        ).fetchall()
        per_caller = [
            {
                "caller": r[0], "total": r[1] or 0, "ok": r[2] or 0,
                "parse_failed": r[3] or 0, "http_error": r[4] or 0,
                "timeout": r[5] or 0, "exception": r[6] or 0,
                "pre_filter": r[7] or 0,
                "auto_confirmed": r[8] or 0, "pending": r[9] or 0,
                "discarded_low_conf": r[10] or 0,
                "discarded_dedup": r[11] or 0,
                "sensor_filtered": r[12] or 0,
                "verdict_empty": r[13] or 0,
                "avg_duration_ms": round(r[14]) if r[14] else 0,
                "avg_confidence": round(r[15], 3) if r[15] else 0.0,
                "last_seen": r[16],
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

    # ── CT Log per-domain known-CA history (ADR-024) ──────────────────────
    def ct_log_known_cas(self, domain: str) -> set[str]:
        """Return the set of normalized CA names previously observed for a domain.

        Empty set means we have no history for this domain (callers should
        check ct_log_first_observed() to distinguish "new domain" from
        "monitored but no CAs ever recorded").
        """
        if not domain:
            return set()
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT ca_normalized FROM ct_log_known_ca_per_domain WHERE domain=?",
            (domain,),
        ).fetchall()
        return {r[0] for r in rows}

    def ct_log_record_ca(self, domain: str, ca_normalized: str,
                         ca_raw: str, now: float) -> None:
        """Insert or refresh the (domain, ca) observation row.

        On first observation: inserts with first_seen=last_seen=now,
        cert_count=1. On repeat: bumps last_seen and cert_count. Treat as
        idempotent — caller can invoke for every observed cert without
        deduping.
        """
        if not domain or not ca_normalized:
            return
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO ct_log_known_ca_per_domain "
                "  (domain, ca_normalized, ca_raw, first_seen, last_seen, cert_count) "
                "VALUES (?, ?, ?, ?, ?, 1) "
                "ON CONFLICT(domain, ca_normalized) DO UPDATE SET "
                "  last_seen = excluded.last_seen, "
                "  cert_count = cert_count + 1",
                (domain, ca_normalized, ca_raw or ca_normalized, now, now),
            )

    def ct_log_first_observed(self, domain: str) -> float | None:
        """Return the timestamp at which we first started monitoring this domain.

        None means we have never recorded a first-observation marker; the
        sensor should set one immediately and treat the current poll as
        warm-up regardless of what CAs were observed.
        """
        if not domain:
            return None
        conn = self._get_conn()
        row = conn.execute(
            "SELECT first_observed FROM ct_log_domain_first_observed WHERE domain=?",
            (domain,),
        ).fetchone()
        return float(row[0]) if row else None

    def ct_log_set_first_observed(self, domain: str, now: float) -> None:
        """Mark a domain as monitored starting at `now`. No-op if already set."""
        if not domain:
            return
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR IGNORE INTO ct_log_domain_first_observed "
                "  (domain, first_observed) VALUES (?, ?)",
                (domain, now),
            )

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

        # LLM intel: retain based on INTEL_RETENTION_DAYS config (default 7d)
        import os as _os
        cutoff_intel = now - int(_os.getenv("INTEL_RETENTION_DAYS", "7")) * 86400
        cur = conn.execute("DELETE FROM llm_intel WHERE created_at < ?", (cutoff_intel,))
        deleted["llm_intel"] = cur.rowcount
        conn.commit()

        # scenario_tl_observation: highest-volume table (~1440 rows/day/scenario).
        # Real-time queries use at most 72h; 42 days covers two §7.3.1 calibration
        # cycles plus monthly TL2 frequency validation.
        _tl_obs_days = int(_os.getenv("TL_OBSERVATION_RETENTION_DAYS", "42"))
        cutoff_tl_obs = now - _tl_obs_days * 86400
        cur = conn.execute(
            "DELETE FROM scenario_tl_observation WHERE observed_at < ?",
            (cutoff_tl_obs,))
        deleted["scenario_tl_observation"] = cur.rowcount
        conn.commit()

        # focus_switch_log: C-medium migration evaluation (§9.3.1).
        # 180 days gives 6 months of operational context for permanent migration decision.
        _fsw_days = int(_os.getenv("FOCUS_SWITCH_RETENTION_DAYS", "180"))
        cutoff_fsw = now - _fsw_days * 86400
        cur = conn.execute(
            "DELETE FROM focus_switch_log WHERE switched_at < ?",
            (cutoff_fsw,))
        deleted["focus_switch_log"] = cur.rowcount
        conn.commit()

        # daily_summary: long-term analytical memory at 1 row/day/theater.
        # 730 days (2 years) enables year-over-year comparison at negligible cost.
        _ds_days = int(_os.getenv("DAILY_SUMMARY_RETENTION_DAYS", "730"))
        cutoff_ds = now - _ds_days * 86400
        cutoff_ds_bucket = int(cutoff_ds // 86400) * 86400
        cur = conn.execute(
            "DELETE FROM daily_summary WHERE day_bucket < ?",
            (cutoff_ds_bucket,))
        deleted["daily_summary"] = cur.rowcount
        conn.commit()

        # forecast_log: prediction accuracy tracking.
        # 365 days because forecast_accuracy_summary() aggregates all rows;
        # shorter retention silently converts overall accuracy into a rolling window.
        _fc_days = int(_os.getenv("FORECAST_RETENTION_DAYS", "365"))
        cutoff_fc = now - _fc_days * 86400
        cur = conn.execute("DELETE FROM forecast_log WHERE ts < ?", (cutoff_fc,))
        deleted["forecast_log"] = cur.rowcount
        conn.commit()

        # scenario_contribution_log: per-cycle per-country contribution
        # snapshots feeding the weight_advisory endpoint. ~1 row/country/
        # cycle (~30s), so a 4-participant scenario produces ~11.5k rows/day.
        # The endpoint queries at most 720h (30d); 90d gives a 60d margin
        # for trend analysis without unbounded growth.
        _ctb_days = int(_os.getenv("SCENARIO_CONTRIB_RETENTION_DAYS", "90"))
        cutoff_ctb = now - _ctb_days * 86400
        cur = conn.execute(
            "DELETE FROM scenario_contribution_log WHERE logged_at < ?",
            (cutoff_ctb,))
        deleted["scenario_contribution_log"] = cur.rowcount
        conn.commit()

        # NOTE: scenario_change_log and confirmed_threats are intentionally
        # excluded from automatic cleanup. scenario_change_log is an audit trail
        # (~4 MB/decade); confirmed_threats is human-generated ground truth
        # (~3 KB/year). Both have increasing analytical value over time.

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

    # ── LLM Intel ───────────────────────────────────────────────────────────
    def intel_upsert(self, item: dict):
        """Insert or replace an LLM intel item."""
        countries = item.get("countries", [])
        country_weights = item.get("country_weights", {})
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO llm_intel "
                "(id, source_type, source_id, theater, ts, status, confidence, "
                "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
                "confirmed_by, confirmed_at, override_at, created_at, "
                "countries, country_weights) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item["id"], item["source_type"], item.get("source_id", ""),
                 item.get("theater", ""), item["ts"], item.get("status", "pending"),
                 item.get("confidence", 0.0), item.get("raw_text", ""),
                 item.get("raw_url", ""), item.get("headline", ""),
                 json.dumps(item.get("llm_fields", {})),
                 item.get("score_delta", 0.0), item.get("domain", "info"),
                 item.get("confirmed_by"), item.get("confirmed_at"),
                 item.get("override_at"), item.get("created_at", time.time()),
                 json.dumps(countries), json.dumps(country_weights)),
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
            "confirmed_by, confirmed_at, override_at, created_at, "
            "countries, country_weights FROM llm_intel WHERE id=?",
            (item_id,),
        ).fetchone()
        return self._intel_row_to_dict(row) if row else None

    def intel_list(self, source_type: str = None, status: str = None,
                   theater: str = None, limit: int = 100,
                   since_ts: float = None, before_ts: float = None) -> list[dict]:
        q = ("SELECT id, source_type, source_id, theater, ts, status, confidence, "
             "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
             "confirmed_by, confirmed_at, override_at, created_at, "
             "countries, country_weights FROM llm_intel WHERE 1=1")
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

    def intel_find_by_raw_url(self, raw_url: str, since_ts: float = 0,
                              limit: int = 5) -> list[dict]:
        """Find intel items with matching raw_url across all source_types."""
        rows = self._get_conn().execute(
            "SELECT id, source_type, source_id, theater, ts, status, confidence, "
            "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
            "confirmed_by, confirmed_at, override_at, created_at, "
            "countries, country_weights FROM llm_intel "
            "WHERE raw_url=? AND ts >= ? ORDER BY ts DESC LIMIT ?",
            (raw_url, since_ts, limit),
        ).fetchall()
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
            "confirmed_by, confirmed_at, override_at, created_at, "
            "countries, country_weights FROM llm_intel "
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
            "countries": json.loads(r[17]) if r[17] else [],
            "country_weights": json.loads(r[18]) if r[18] else {},
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

    def intel_source_reset_credibility(self, source_id: str,
                                       credibility_weight: float) -> bool:
        """Reset credibility to an explicit value if the source has never been
        reviewed by an analyst (confirmed_count=0 AND false_positive_count=0).
        Returns True if updated, False if the row had learned state and was left
        alone. Used by startup to retroactively apply archetype bootstrap weights
        to sources that existed before bootstrapping was introduced.
        """
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "UPDATE llm_sources SET "
                "credibility_weight = ?, last_updated = ? "
                "WHERE source_id = ? "
                "AND confirmed_count = 0 AND false_positive_count = 0",
                (credibility_weight, time.time(), source_id),
            )
            return cur.rowcount > 0

    def intel_confidence_distribution(self, hours: int = 168) -> dict:
        """Confidence distribution of LLM intel items for pipeline tuning.

        Returns global histogram buckets (0.0-0.1 ... 0.9-1.0),
        per-status breakdown, auto_confirm threshold analysis, and a
        `by_source_type` map repeating the same shape per source_type
        so per-sensor calibration drift is visible without DB shell.
        """
        cutoff = time.time() - hours * 3600
        rows = self._get_conn().execute(
            "SELECT confidence, status, source_type FROM llm_intel WHERE ts > ?",
            (cutoff,),
        ).fetchall()

        def _bucket_label(conf: float) -> str:
            bucket_idx = min(int(conf * 10), 9)
            return f"{bucket_idx * 0.1:.1f}-{(bucket_idx + 1) * 0.1:.1f}"

        buckets: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        per_source: dict[str, dict] = {}
        auto_confirmable = 0
        total = 0
        for r in rows:
            conf = r["confidence"]
            st = r["status"]
            stype = r["source_type"] or "unknown"
            label = _bucket_label(conf)
            buckets[label] = buckets.get(label, 0) + 1
            status_counts[st] = status_counts.get(st, 0) + 1
            if conf >= 0.80:
                auto_confirmable += 1
            total += 1

            entry = per_source.setdefault(
                stype,
                {"total": 0, "buckets": {}, "status_counts": {},
                 "auto_confirmable": 0},
            )
            entry["total"] += 1
            entry["buckets"][label] = entry["buckets"].get(label, 0) + 1
            entry["status_counts"][st] = entry["status_counts"].get(st, 0) + 1
            if conf >= 0.80:
                entry["auto_confirmable"] += 1

        by_source_type = {
            stype: {
                "total": e["total"],
                "buckets": e["buckets"],
                "status_counts": e["status_counts"],
                "auto_confirmable_pct": (
                    round(e["auto_confirmable"] / e["total"] * 100, 1)
                    if e["total"] else 0
                ),
            }
            for stype, e in per_source.items()
        }

        return {
            "hours": hours,
            "total": total,
            "buckets": buckets,
            "status_counts": status_counts,
            "auto_confirmable_pct": round(auto_confirmable / total * 100, 1) if total else 0,
            "by_source_type": by_source_type,
        }

    def intel_country_weight_aggregate(self, hours: int = 168) -> dict:
        """Aggregate LLM-emitted country_weights across active intel items.

        Returns per-country mean / sd / low_weight_pct / samples for
        auto_confirmed+confirmed items within the window. Used by the
        dual-weight observability endpoint (ADR-015 / scenario-refactor
        §10.5) to compare LLM-derived weights against static scenario
        participant weights and to evaluate §10.5 rollback criteria
        (a) SD threshold and (b) low-weight contribution share.
        """
        cutoff = time.time() - hours * 3600
        rows = self._get_conn().execute(
            "SELECT country_weights FROM llm_intel "
            "WHERE status IN ('auto_confirmed', 'confirmed') AND ts > ? "
            "AND country_weights != '{}'",
            (cutoff,),
        ).fetchall()
        per_country: dict[str, list[float]] = {}
        for r in rows:
            try:
                cw = json.loads(r[0]) if r[0] else {}
            except (ValueError, TypeError):
                continue
            for cc, w in cw.items():
                try:
                    per_country.setdefault(cc.upper(), []).append(float(w))
                except (ValueError, TypeError):
                    continue
        out: dict[str, dict] = {}
        for cc, ws in per_country.items():
            n = len(ws)
            if n == 0:
                continue
            mean = sum(ws) / n
            var = sum((w - mean) ** 2 for w in ws) / n if n > 1 else 0.0
            sd = var ** 0.5
            low = sum(1 for w in ws if w < 0.5)
            out[cc] = {
                "samples": n,
                "mean": round(mean, 3),
                "sd": round(sd, 3),
                "min": round(min(ws), 3),
                "max": round(max(ws), 3),
                "low_weight_pct": round(low * 100.0 / n, 1),
            }
        return out

    # ── Auth ───────────────────────────────────────────────────────────────

    def user_count(self) -> int:
        row = self._get_conn().execute("SELECT COUNT(*) FROM users").fetchone()
        return row[0]

    def user_get(self, username: str) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT id, username, password_hash, salt, role, created_at, last_login, "
            "invalidate_tokens_before "
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
        now = time.time()
        with conn.writing():
            conn.execute(
                "UPDATE users SET password_hash=?, salt=?, invalidate_tokens_before=? WHERE id=?",
                (password_hash, salt, now, user_id),
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
            "SELECT us.focused_scenario, us.muted, us.lang "
            "FROM user_settings us JOIN users u ON us.user_id = u.id "
            "WHERE u.username=?", (username,)
        ).fetchone()
        return dict(row) if row else None

    def user_settings_create(self, user_id: int, focused_scenario: Optional[str],
                             muted: str, lang: str, updated_at: float):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO user_settings "
                "(user_id, focused_scenario, muted, lang, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, focused_scenario, muted, lang, updated_at),
            )

    # SAFETY: column names used in f-string SQL are restricted to this allowlist
    _USER_SETTINGS_COLS = frozenset({"focused_scenario", "muted", "lang", "updated_at"})

    def user_settings_update(self, user_id: int, updates: dict):
        bad = set(updates.keys()) - self._USER_SETTINGS_COLS
        if bad:
            raise ValueError(f"Disallowed user_settings columns: {bad}")
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

    def user_get_invalidate_ts(self, username: str) -> Optional[float]:
        """Return the invalidate_tokens_before timestamp for a user, or None."""
        row = self._get_conn().execute(
            "SELECT invalidate_tokens_before FROM users WHERE username=?",
            (username,),
        ).fetchone()
        if row and row[0] is not None:
            return float(row[0])
        return None

    # ── F4 Hidden Negative Signals ──────────────────────────────────────────
    def hidden_signal_log(
        self, scenario_id: Optional[str], country: Optional[str],
        sensor: str, domain: str, hide_reason: str,
        detail: Optional[dict] = None,
    ):
        import json as _json
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO hidden_signal_log "
                "(logged_at, scenario_id, country, sensor, domain, hide_reason, detail_json) "
                "VALUES (?,?,?,?,?,?,?)",
                (time.time(), scenario_id, country, sensor, domain,
                 hide_reason, _json.dumps(detail or {})),
            )

    def hidden_signal_list(
        self, scenario_id: Optional[str] = None,
        since: Optional[float] = None, limit: int = 100,
    ) -> list[dict]:
        import json as _json
        sql = ("SELECT id, logged_at, scenario_id, country, sensor, domain, "
               "hide_reason, detail_json FROM hidden_signal_log WHERE 1=1")
        params: list = []
        if scenario_id:
            sql += " AND scenario_id = ?"
            params.append(scenario_id)
        if since is not None:
            sql += " AND logged_at >= ?"
            params.append(since)
        sql += " ORDER BY logged_at DESC LIMIT ?"
        params.append(int(limit))
        rows = self._get_conn().execute(sql, params).fetchall()
        out = []
        for r in rows:
            try:
                detail = _json.loads(r["detail_json"] or "{}")
            except Exception:
                detail = {}
            out.append({
                "id": r["id"], "logged_at": r["logged_at"],
                "scenario_id": r["scenario_id"], "country": r["country"],
                "sensor": r["sensor"], "domain": r["domain"],
                "hide_reason": r["hide_reason"], "detail": detail,
            })
        return out

    # ── F5 Coverage Gap ─────────────────────────────────────────────────────
    def coverage_upsert(
        self, scenario_id: str, sensor: str, domain: str,
        last_success: Optional[float], last_attempt: Optional[float],
        state: str, consecutive_failures: int,
    ):
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO scenario_sensor_coverage "
                "(scenario_id, sensor, domain, last_success, last_attempt, state, "
                " consecutive_failures, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT (scenario_id, sensor) DO UPDATE SET "
                "domain=excluded.domain, last_success=excluded.last_success, "
                "last_attempt=excluded.last_attempt, state=excluded.state, "
                "consecutive_failures=excluded.consecutive_failures, "
                "updated_at=excluded.updated_at",
                (scenario_id, sensor, domain, last_success, last_attempt,
                 state, int(consecutive_failures), time.time()),
            )

    def coverage_list(self, scenario_id: str) -> list[dict]:
        rows = self._get_conn().execute(
            "SELECT sensor, domain, last_success, last_attempt, state, "
            "consecutive_failures, updated_at "
            "FROM scenario_sensor_coverage WHERE scenario_id=? "
            "ORDER BY state DESC, sensor ASC",
            (scenario_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── F6 Disconfirming Evidence ───────────────────────────────────────────
    def disconf_add(
        self, scenario_id: str, tagged_by: str, source_kind: str,
        source_ref: Optional[str], summary: str, strength: int,
    ) -> int:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO disconfirming_evidence "
                "(scenario_id, tagged_at, tagged_by, source_kind, source_ref, "
                " summary, strength) VALUES (?,?,?,?,?,?,?)",
                (scenario_id, time.time(), tagged_by, source_kind,
                 source_ref, summary, max(1, min(5, int(strength)))),
            )
            return int(cur.lastrowid or 0)

    def disconf_list(self, scenario_id: str, include_retracted: bool = False) -> list[dict]:
        sql = ("SELECT id, tagged_at, tagged_by, source_kind, source_ref, "
               "summary, strength, retracted_at, retracted_by "
               "FROM disconfirming_evidence WHERE scenario_id=?")
        if not include_retracted:
            sql += " AND retracted_at IS NULL"
        sql += " ORDER BY tagged_at DESC"
        rows = self._get_conn().execute(sql, (scenario_id,)).fetchall()
        return [dict(r) for r in rows]

    def disconf_retract(self, item_id: int, retracted_by: str) -> bool:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "UPDATE disconfirming_evidence SET retracted_at=?, retracted_by=? "
                "WHERE id=? AND retracted_at IS NULL",
                (time.time(), retracted_by, int(item_id)),
            )
            return cur.rowcount > 0

    # ── F8 ACH Matrix ───────────────────────────────────────────────────────
    def ach_matrix_create(self, scenario_id: str, title: str, created_by: str) -> int:
        now = time.time()
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO ach_matrices (scenario_id, title, created_by, "
                "created_at, updated_at) VALUES (?,?,?,?,?)",
                (scenario_id, title, created_by, now, now),
            )
            return int(cur.lastrowid or 0)

    def ach_matrix_list(self, scenario_id: str, include_archived: bool = False) -> list[dict]:
        sql = ("SELECT id, scenario_id, title, created_by, created_at, "
               "updated_at, archived_at FROM ach_matrices WHERE scenario_id=?")
        if not include_archived:
            sql += " AND archived_at IS NULL"
        sql += " ORDER BY updated_at DESC"
        rows = self._get_conn().execute(sql, (scenario_id,)).fetchall()
        return [dict(r) for r in rows]

    def ach_matrix_get(self, matrix_id: int) -> Optional[dict]:
        conn = self._get_conn()
        m = conn.execute(
            "SELECT id, scenario_id, title, created_by, created_at, "
            "updated_at, archived_at FROM ach_matrices WHERE id=?",
            (int(matrix_id),),
        ).fetchone()
        if not m:
            return None
        hyps = conn.execute(
            "SELECT id, ord, text, is_null_hypothesis FROM ach_hypotheses "
            "WHERE matrix_id=? ORDER BY ord ASC, id ASC",
            (int(matrix_id),),
        ).fetchall()
        evs = conn.execute(
            "SELECT id, ord, text, source_ref, credibility, relevance "
            "FROM ach_evidence WHERE matrix_id=? ORDER BY ord ASC, id ASC",
            (int(matrix_id),),
        ).fetchall()
        scores = conn.execute(
            "SELECT s.hypothesis_id, s.evidence_id, s.consistency, s.note "
            "FROM ach_scores s JOIN ach_hypotheses h ON h.id = s.hypothesis_id "
            "WHERE h.matrix_id=?",
            (int(matrix_id),),
        ).fetchall()
        return {
            **dict(m),
            "hypotheses": [dict(r) for r in hyps],
            "evidence": [dict(r) for r in evs],
            "scores": [dict(r) for r in scores],
        }

    def ach_hypothesis_add(self, matrix_id: int, text: str,
                           is_null: bool = False, ord_: int = 0) -> int:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO ach_hypotheses (matrix_id, ord, text, is_null_hypothesis) "
                "VALUES (?,?,?,?)",
                (int(matrix_id), int(ord_), text, 1 if is_null else 0),
            )
            conn.execute("UPDATE ach_matrices SET updated_at=? WHERE id=?",
                         (time.time(), int(matrix_id)))
            return int(cur.lastrowid or 0)

    def ach_evidence_add(self, matrix_id: int, text: str,
                         source_ref: Optional[str] = None,
                         credibility: int = 3, relevance: int = 3,
                         ord_: int = 0) -> int:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO ach_evidence (matrix_id, ord, text, source_ref, "
                "credibility, relevance) VALUES (?,?,?,?,?,?)",
                (int(matrix_id), int(ord_), text, source_ref,
                 max(1, min(5, int(credibility))),
                 max(1, min(5, int(relevance)))),
            )
            conn.execute("UPDATE ach_matrices SET updated_at=? WHERE id=?",
                         (time.time(), int(matrix_id)))
            return int(cur.lastrowid or 0)

    def ach_score_set(self, matrix_id: int, hypothesis_id: int,
                      evidence_id: int, consistency: int,
                      note: Optional[str] = None):
        c = max(-2, min(2, int(consistency)))
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO ach_scores (hypothesis_id, evidence_id, consistency, note) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT (hypothesis_id, evidence_id) DO UPDATE SET "
                "consistency=excluded.consistency, note=excluded.note",
                (int(hypothesis_id), int(evidence_id), c, note),
            )
            conn.execute("UPDATE ach_matrices SET updated_at=? WHERE id=?",
                         (time.time(), int(matrix_id)))

    # ── F13 Dissenting Views ────────────────────────────────────────────────
    def dissent_add(self, scenario_id: str, created_by: str, title: str,
                    body: str, argues_for_tl: Optional[int]) -> int:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO dissenting_views (scenario_id, created_at, created_by, "
                "title, body, argues_for_tl) VALUES (?,?,?,?,?,?)",
                (scenario_id, time.time(), created_by, title, body,
                 int(argues_for_tl) if argues_for_tl is not None else None),
            )
            return int(cur.lastrowid or 0)

    def dissent_list(self, scenario_id: str, include_resolved: bool = False) -> list[dict]:
        sql = ("SELECT id, created_at, created_by, title, body, argues_for_tl, "
               "resolved_at, resolved_by, resolution_note "
               "FROM dissenting_views WHERE scenario_id=?")
        if not include_resolved:
            sql += " AND resolved_at IS NULL"
        sql += " ORDER BY created_at DESC"
        rows = self._get_conn().execute(sql, (scenario_id,)).fetchall()
        return [dict(r) for r in rows]

    def dissent_resolve(self, view_id: int, resolved_by: str,
                        resolution_note: Optional[str]) -> bool:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "UPDATE dissenting_views SET resolved_at=?, resolved_by=?, "
                "resolution_note=? WHERE id=? AND resolved_at IS NULL",
                (time.time(), resolved_by, resolution_note, int(view_id)),
            )
            return cur.rowcount > 0

    # ── F10 Key Assumptions ─────────────────────────────────────────────────
    def assumption_add(self, scenario_id: str, created_by: str,
                       statement: str, rationale: Optional[str],
                       confidence: str) -> int:
        if confidence not in ("low", "medium", "high"):
            confidence = "medium"
        now = time.time()
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO key_assumptions (scenario_id, created_at, created_by, "
                "updated_at, updated_by, statement, rationale, confidence) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (scenario_id, now, created_by, now, created_by,
                 statement, rationale, confidence),
            )
            aid = int(cur.lastrowid or 0)
            self._assumption_log(conn, aid, created_by, "create", None, {
                "statement": statement, "rationale": rationale,
                "confidence": confidence,
            }, None)
            return aid

    def _assumption_log(self, conn, assumption_id: int, changed_by: str,
                        change_type: str, before: Optional[dict],
                        after: Optional[dict], note: Optional[str]):
        import json as _json
        conn.execute(
            "INSERT INTO key_assumption_change_log (assumption_id, changed_at, "
            "changed_by, change_type, before_json, after_json, note) "
            "VALUES (?,?,?,?,?,?,?)",
            (int(assumption_id), time.time(), changed_by, change_type,
             _json.dumps(before) if before is not None else None,
             _json.dumps(after) if after is not None else None,
             note),
        )

    def assumption_list(self, scenario_id: str,
                        include_invalidated: bool = True) -> list[dict]:
        sql = ("SELECT id, scenario_id, created_at, created_by, updated_at, "
               "updated_by, statement, rationale, confidence, is_locked, "
               "locked_at, locked_by, invalidated_at, invalidated_by, "
               "invalidation_note FROM key_assumptions WHERE scenario_id=?")
        if not include_invalidated:
            sql += " AND invalidated_at IS NULL"
        sql += " ORDER BY is_locked DESC, created_at DESC"
        rows = self._get_conn().execute(sql, (scenario_id,)).fetchall()
        return [dict(r) for r in rows]

    def assumption_get(self, assumption_id: int) -> Optional[dict]:
        row = self._get_conn().execute(
            "SELECT * FROM key_assumptions WHERE id=?", (int(assumption_id),),
        ).fetchone()
        return dict(row) if row else None

    def assumption_update(self, assumption_id: int, changed_by: str,
                          fields: dict, is_admin: bool) -> bool:
        a = self.assumption_get(assumption_id)
        if not a:
            return False
        if a.get("is_locked") and not is_admin:
            raise PermissionError("locked assumption — admin only")
        allowed = {"statement", "rationale", "confidence"}
        bad = set(fields.keys()) - allowed
        if bad:
            raise ValueError(f"disallowed assumption fields: {bad}")
        if "confidence" in fields and fields["confidence"] not in ("low", "medium", "high"):
            raise ValueError("confidence must be low|medium|high")
        before = {k: a.get(k) for k in allowed if k in fields}
        set_clause = ", ".join(f"{k}=?" for k in fields)
        params = [*fields.values(), time.time(), changed_by, int(assumption_id)]
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                f"UPDATE key_assumptions SET {set_clause}, updated_at=?, updated_by=? "
                f"WHERE id=?", params,
            )
            self._assumption_log(conn, assumption_id, changed_by, "edit",
                                 before, dict(fields), None)
            return cur.rowcount > 0

    def assumption_lock(self, assumption_id: int, locked_by: str,
                        is_admin: bool, lock: bool = True) -> bool:
        if not is_admin:
            raise PermissionError("lock/unlock requires admin")
        conn = self._get_conn()
        with conn.writing():
            if lock:
                cur = conn.execute(
                    "UPDATE key_assumptions SET is_locked=1, locked_at=?, locked_by=?, "
                    "updated_at=?, updated_by=? WHERE id=? AND is_locked=0",
                    (time.time(), locked_by, time.time(), locked_by, int(assumption_id)),
                )
                action = "lock"
            else:
                cur = conn.execute(
                    "UPDATE key_assumptions SET is_locked=0, locked_at=NULL, "
                    "locked_by=NULL, updated_at=?, updated_by=? WHERE id=? AND is_locked=1",
                    (time.time(), locked_by, int(assumption_id)),
                )
                action = "unlock"
            if cur.rowcount > 0:
                self._assumption_log(conn, assumption_id, locked_by, action,
                                     None, None, None)
            return cur.rowcount > 0

    def assumption_invalidate(self, assumption_id: int, by: str,
                              note: Optional[str]) -> bool:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "UPDATE key_assumptions SET invalidated_at=?, invalidated_by=?, "
                "invalidation_note=?, updated_at=?, updated_by=? "
                "WHERE id=? AND invalidated_at IS NULL",
                (time.time(), by, note, time.time(), by, int(assumption_id)),
            )
            if cur.rowcount > 0:
                self._assumption_log(conn, assumption_id, by, "invalidate",
                                     None, None, note)
            return cur.rowcount > 0

    def assumption_change_log(self, assumption_id: int) -> list[dict]:
        import json as _json
        rows = self._get_conn().execute(
            "SELECT id, changed_at, changed_by, change_type, before_json, "
            "after_json, note FROM key_assumption_change_log "
            "WHERE assumption_id=? ORDER BY changed_at DESC",
            (int(assumption_id),),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("before_json", "after_json"):
                try:
                    d[k.replace("_json", "")] = (
                        _json.loads(d.pop(k)) if d.get(k) else None)
                except Exception:
                    d[k.replace("_json", "")] = None
                    d.pop(k, None)
            out.append(d)
        return out

    # ── F11 Pre-Mortem ──────────────────────────────────────────────────────
    def premortem_add(self, scenario_id: str, created_by: str,
                      failure_mode: str, imagined_outcome: str,
                      root_cause: str, early_warning: Optional[str],
                      mitigation: Optional[str]) -> int:
        if failure_mode not in ("false_positive", "false_negative", "cognitive_bias"):
            raise ValueError("failure_mode must be false_positive|false_negative|cognitive_bias")
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO premortem_entries (scenario_id, created_at, created_by, "
                "failure_mode, imagined_outcome, root_cause, early_warning, mitigation) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (scenario_id, time.time(), created_by, failure_mode,
                 imagined_outcome, root_cause, early_warning, mitigation),
            )
            return int(cur.lastrowid or 0)

    def premortem_list(self, scenario_id: str,
                       include_resolved: bool = False) -> list[dict]:
        sql = ("SELECT id, scenario_id, created_at, created_by, failure_mode, "
               "imagined_outcome, root_cause, early_warning, mitigation, "
               "resolved_at, resolved_by FROM premortem_entries WHERE scenario_id=?")
        if not include_resolved:
            sql += " AND resolved_at IS NULL"
        sql += " ORDER BY created_at DESC"
        rows = self._get_conn().execute(sql, (scenario_id,)).fetchall()
        return [dict(r) for r in rows]

    def premortem_resolve(self, entry_id: int, resolved_by: str) -> bool:
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "UPDATE premortem_entries SET resolved_at=?, resolved_by=? "
                "WHERE id=? AND resolved_at IS NULL",
                (time.time(), resolved_by, int(entry_id)),
            )
            return cur.rowcount > 0

    # ── F14 Decision Ledger ─────────────────────────────────────────────────
    def decision_log(self, user_id: Optional[int], username: str,
                     session_id: str, scenario_id: Optional[str],
                     decision_type: str, summary: str,
                     detail: Optional[dict] = None) -> int:
        import json as _json
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO decision_ledger (logged_at, user_id, username, "
                "session_id, scenario_id, decision_type, summary, detail_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (time.time(), user_id, username or "", session_id,
                 scenario_id, decision_type, summary,
                 _json.dumps(detail or {})),
            )
            return int(cur.lastrowid or 0)

    def decision_list(self, session_id: Optional[str] = None,
                      scenario_id: Optional[str] = None,
                      user_id: Optional[int] = None,
                      since: Optional[float] = None,
                      limit: int = 200) -> list[dict]:
        import json as _json
        sql = ("SELECT id, logged_at, user_id, username, session_id, scenario_id, "
               "decision_type, summary, detail_json FROM decision_ledger WHERE 1=1")
        params: list = []
        if session_id:
            sql += " AND session_id=?"
            params.append(session_id)
        if scenario_id:
            sql += " AND scenario_id=?"
            params.append(scenario_id)
        if user_id is not None:
            sql += " AND user_id=?"
            params.append(int(user_id))
        if since is not None:
            sql += " AND logged_at >= ?"
            params.append(since)
        sql += " ORDER BY logged_at DESC LIMIT ?"
        params.append(int(limit))
        rows = self._get_conn().execute(sql, params).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["detail"] = _json.loads(d.pop("detail_json", "{}") or "{}")
            except Exception:
                d["detail"] = {}
                d.pop("detail_json", None)
            out.append(d)
        return out

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
