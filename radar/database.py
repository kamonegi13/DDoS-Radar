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


# ── A-4 generated-column migration (ADR-V2-006 Safe Rename Pattern) ───────────
# Tables that carry a legacy `theater` column. v24 adds a generated `country`
# mirror to each; SELECT sites can use either name interchangeably until A-5
# sunset renames the source column. Keep this list in sync with
# `RadarDB._A4_TABLES_WITH_THEATER` (single source of truth on the class).
_A4_THEATER_TABLES: tuple[str, ...] = (
    "baseline_cache",
    "hod_baseline",
    "checkhost_hod",
    "bgp_hod",
    "gdelt_dow",
    "time_series_ts",
    "time_series",
    "sequence_events",
    "sensor_zscore_stats",
    "noise_exclusion",
    "confirmed_threats",
    "daily_summary",
    "forecast_log",
    "cooccurrence_stats",
    "climate_events",
    "llm_intel",
)


def _migration_v40_schema_version_singleton(conn) -> None:
    """Phase 7.5h (audit DB L1) — collapse schema_version into a single
    row keyed by id=1.

    Pre-fix the table accumulated one row per migration (39 rows at
    v40 install time). Logically the table only ever describes "the
    current schema version", so a singleton with INSERT OR REPLACE
    semantics is the correct shape. Idempotent: detects whether the
    `id` column already exists (fresh DBs created from the v7.5h+
    baseline) and skips the rebuild.
    """
    cols = {r[1] for r in conn.execute(
        "PRAGMA table_info(schema_version)"
    ).fetchall()}
    if "id" in cols:
        return  # already migrated (fresh DB or re-run)
    # Capture the highest applied version before rebuild so we can
    # restore it as the single-row state.
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    current = int(row[0] or 0) if row else 0
    last_at = conn.execute(
        "SELECT migrated_at FROM schema_version WHERE version = ?",
        (current,),
    ).fetchone()
    last_at = float(last_at[0]) if last_at and last_at[0] is not None else 0.0
    conn.execute("ALTER TABLE schema_version RENAME TO schema_version_old_v39")
    conn.execute("""
        CREATE TABLE schema_version (
            id          INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            version     INTEGER NOT NULL,
            migrated_at REAL NOT NULL
        )
    """)
    # Use the v40 number itself rather than `current` because the
    # migration engine will call set_schema_version(40) after this
    # callable returns; pre-seeding with 40 keeps the row consistent
    # in the failure window if the post-migration write loses.
    conn.execute(
        "INSERT INTO schema_version (id, version, migrated_at) VALUES (1, ?, ?)",
        (max(current, 40), last_at or time.time()),
    )
    conn.execute("DROP TABLE schema_version_old_v39")


def _migration_v42_llm_routing_overrides(conn) -> None:
    """Phase 8 (LLM survey v10) — analyst-driven routing overrides.

    Two tables, mirroring the Feature Hub pattern (commit G):

      llm_routing_override          one row per (use_case, slot)
      llm_routing_override_history  append-only audit ledger

    Columns are NULLABLE so an analyst can override only the model
    while inheriting sampling from the env / code default. The hot-path
    resolver in radar.llm_routing._apply_db_layer walks every column and
    picks the row's value only when non-NULL.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS llm_routing_override (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            use_case          TEXT NOT NULL,
            slot              TEXT NOT NULL,
            model             TEXT,
            temperature       REAL,
            top_p             REAL,
            top_k             INTEGER,
            seed              INTEGER,
            num_predict       INTEGER,
            repeat_penalty    REAL,
            thinking_enabled  INTEGER,
            set_at            REAL NOT NULL,
            set_by            TEXT NOT NULL,
            reason            TEXT,
            UNIQUE (use_case, slot)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS llm_routing_override_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            use_case    TEXT NOT NULL,
            slot        TEXT NOT NULL,
            old_json    TEXT,
            new_json    TEXT,
            changed_at  REAL NOT NULL,
            changed_by  TEXT NOT NULL,
            reason      TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_llm_routing_override_hist_ts "
        "ON llm_routing_override_history (changed_at DESC)"
    )


def _migration_v41_llm_routing_v10(conn) -> None:
    """Phase 8 (LLM survey v10) — capture per-call thinking trace, the
    routing use-case bucket, and the model that v2 routing *would* have
    chosen when the feature is in SHADOW state.

    Adds three columns to ``llm_call_log``:

      - ``thinking_trace``      : reasoning text from <|think|> token
                                  (Gemma 4) or "Reasoning: high" (gpt-oss).
                                  NULL when thinking was OFF.
      - ``use_case``            : routing bucket (sensor_extract, verdict,
                                  conclusion, discovery, narrative). NULL
                                  for pre-Phase-8 rows + callers that
                                  didn't go through the routing layer.
      - ``shadow_model_choice`` : when model_routing_*=SHADOW, the model
                                  v10 routing would have picked but did
                                  not actually run.

    Plus an index on (use_case, ts) so the per-use-case AP3 self_eval
    rollups don't trigger a full table scan.
    """
    cols = {r[1] for r in conn.execute("PRAGMA table_info(llm_call_log)").fetchall()}
    if "thinking_trace" not in cols:
        conn.execute("ALTER TABLE llm_call_log ADD COLUMN thinking_trace TEXT")
    if "use_case" not in cols:
        conn.execute("ALTER TABLE llm_call_log ADD COLUMN use_case TEXT")
    if "shadow_model_choice" not in cols:
        conn.execute(
            "ALTER TABLE llm_call_log ADD COLUMN shadow_model_choice TEXT"
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_llm_call_log_usecase_ts "
        "ON llm_call_log (use_case, ts)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_llm_call_log_model_ts "
        "ON llm_call_log (model, ts)"
    )


def _migration_v37_decisions_revocation(conn) -> None:
    """Phase 5 (audit) — split revocation out of `superseded_by` so the FK
    constraint REFERENCES decisions(id) can be enforced.

    Pre-fix design wrote a synthetic ``"revoked:<by>:<unix_ts>"`` marker
    into superseded_by on revoke(), which is intentionally NOT a valid
    decisions(id) — that prevented turning PRAGMA foreign_keys = ON.

    This migration:
      1. Adds revoked_at / revoked_by columns.
      2. Backfills from existing 'revoked:%' markers (best-effort parse).
      3. Clears superseded_by on those rows so the FK becomes valid.

    Idempotent: ALTER ... ADD COLUMN IF NOT EXISTS not supported by SQLite,
    so we probe with PRAGMA table_info first.
    """
    cols = {r[1] for r in conn.execute("PRAGMA table_info(decisions)").fetchall()}
    if "revoked_at" not in cols:
        conn.execute("ALTER TABLE decisions ADD COLUMN revoked_at REAL")
    if "revoked_by" not in cols:
        conn.execute("ALTER TABLE decisions ADD COLUMN revoked_by TEXT")

    # Backfill: marker shape is `revoked:<by>:<unix_ts>` where <by> may
    # contain ':' itself in pathological cases — we split from the right
    # to extract the timestamp, then everything between the two colons.
    rows = conn.execute(
        "SELECT id, superseded_by FROM decisions "
        "WHERE superseded_by LIKE 'revoked:%'"
    ).fetchall()
    for row in rows:
        marker = row[1] or ""
        try:
            # Drop the leading 'revoked:'
            body = marker[len("revoked:"):]
            # Last ':' separates ts from by-name (by-name comes before).
            sep = body.rfind(":")
            if sep < 0:
                # Malformed marker — leave the timestamp NULL.
                by = body or "unknown"
                ts: float | None = None
            else:
                by = body[:sep] or "unknown"
                try:
                    ts = float(body[sep + 1:])
                except ValueError:
                    ts = None
        except Exception:
            by = "unknown"
            ts = None
        conn.execute(
            "UPDATE decisions SET revoked_at = ?, revoked_by = ?, "
            "                     superseded_by = NULL "
            "WHERE id = ?",
            (ts, by, row[0]),
        )

    # Rebuild the partial index to also exclude revoked rows from the
    # active-expiry scan (matches schema baseline above).
    conn.execute("DROP INDEX IF EXISTS idx_decisions_active_expiry")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_decisions_active_expiry "
        "ON decisions (decision_type, expires_at) "
        "WHERE superseded_by IS NULL AND revoked_at IS NULL"
    )


def _migration_v38_sensor_observation_ts_pk(conn) -> None:
    """Phase 5 (audit / DB H1) — give sensor_observation_ts a proper PK.

    The original baseline left the table without PRIMARY KEY or UNIQUE,
    so retried scoring-cycle inserts produced silent duplicate rows.

    Rebuild: rename, recreate with PRIMARY KEY (sensor, scope, ts),
    INSERT OR IGNORE (silently dropping duplicates), drop old, restore
    indexes. Idempotent via PRAGMA table_info probe.
    """
    cols = conn.execute("PRAGMA table_info(sensor_observation_ts)").fetchall()
    if not cols:
        # Fresh DB without the table — nothing to do; the baseline now
        # ships with PRIMARY KEY directly.
        return
    # Detect whether the PK is already in place.
    pk_cols = sorted(c[1] for c in cols if c[5])  # column 5 = pk
    if pk_cols == ["scope", "sensor", "ts"]:
        return  # already migrated
    conn.execute("ALTER TABLE sensor_observation_ts RENAME TO sensor_observation_ts_old_v37")
    conn.execute("""
        CREATE TABLE sensor_observation_ts (
            sensor    TEXT NOT NULL,
            scope     TEXT NOT NULL,
            ts        REAL NOT NULL,
            value     REAL,
            PRIMARY KEY (sensor, scope, ts)
        )
    """)
    conn.execute(
        "INSERT OR IGNORE INTO sensor_observation_ts (sensor, scope, ts, value) "
        "SELECT sensor, scope, ts, value FROM sensor_observation_ts_old_v37"
    )
    conn.execute("DROP TABLE sensor_observation_ts_old_v37")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sensor_obs_lookup "
        "ON sensor_observation_ts (sensor, scope, ts DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_sensor_obs_ttl "
        "ON sensor_observation_ts (ts)"
    )


def _migration_v39_scenario_tl_obs_mode_index(conn) -> None:
    """Phase 5 (audit / DB H3) — covering index for scenario_prev_lite_score.

    The hot query filters on (scenario_id, scoring_mode='lite', observed_at <
    cutoff). Existing index covers (scenario_id, observed_at DESC) only —
    SQLite has to post-filter every range row by scoring_mode. At 42-day
    retention (~60k rows / scenario / mode at 1-min ticks) this is
    measurable. Composite index makes the lookup index-only.
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tl_obs_sid_mode_ts "
        "ON scenario_tl_observation (scenario_id, scoring_mode, observed_at DESC)"
    )


def _migration_v36_bg_observer(conn) -> None:
    """ADR-V2-015 Phase 1+5: per-sensor contribution log + bg_observer cycle log.

    Idempotent — safe on fresh DB (no contribution_log baseline), upgraded
    DB (contribution_log from migration v18 needs ALTER), and re-run.
    Both tables use ``CREATE TABLE IF NOT EXISTS`` semantics so the
    migration is a no-op once both shapes are present.
    """
    # (1) scenario_contribution_log — ensure exists (v18 created it, but
    # fresh DBs that skip migrations need it created here) and ensure
    # the `sensor` column is present.
    cols = conn.execute(
        "PRAGMA table_info(scenario_contribution_log)"
    ).fetchall()
    if not cols:
        # Fresh DB path — table doesn't exist; create with v18 + v36 shape.
        conn.execute("""
            CREATE TABLE scenario_contribution_log (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scenario_id      TEXT NOT NULL,
                country          TEXT NOT NULL,
                contribution_sum REAL NOT NULL,
                logged_at        REAL NOT NULL,
                sensor           TEXT
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scenario_contrib_log "
            "ON scenario_contribution_log (scenario_id, logged_at DESC)"
        )
    else:
        col_names = {r[1] for r in cols}
        if "sensor" not in col_names:
            conn.execute(
                "ALTER TABLE scenario_contribution_log ADD COLUMN sensor TEXT"
            )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scenario_contribution_log_sensor "
        "ON scenario_contribution_log (sensor, logged_at DESC)"
    )

    # (2) bg_observer_cycle_log — per-cycle audit trail.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS bg_observer_cycle_log (
            cycle_id              INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at            REAL NOT NULL,
            duration_ms           INTEGER NOT NULL DEFAULT 0,
            feeds_attempted       INTEGER NOT NULL DEFAULT 0,
            feeds_failed          INTEGER NOT NULL DEFAULT 0,
            items_total           INTEGER NOT NULL DEFAULT 0,
            items_with_country    INTEGER NOT NULL DEFAULT 0,
            items_with_kinetic    INTEGER NOT NULL DEFAULT 0,
            items_with_fatalities INTEGER NOT NULL DEFAULT 0,
            matches_emitted       INTEGER NOT NULL DEFAULT 0,
            matches_by_country    TEXT NOT NULL DEFAULT '{}',
            alias_gap             TEXT NOT NULL DEFAULT '[]',
            scenarios_observed    TEXT NOT NULL DEFAULT '[]',
            drop_reason           TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bg_observer_cycle_log_ts "
        "ON bg_observer_cycle_log (started_at DESC)"
    )


def _migration_v24_generated_country(conn) -> None:
    """Add `country` GENERATED VIRTUAL column mirroring `theater` on each table.

    Idempotent: skips tables that already have a `country` column (e.g. a
    fresh DB created from a future _SCHEMA_SQL baseline that includes the
    column directly). Tables that lack a `theater` column are silently
    skipped — they were dropped or never created on this deployment.
    """
    for table in _A4_THEATER_TABLES:
        # NB: use table_xinfo, not table_info — table_info hides generated
        # columns, so the idempotency check would fail on a re-run and we'd
        # try to re-ALTER an existing column.
        cols = conn.execute(f"PRAGMA table_xinfo({table})").fetchall()
        col_names = {r[1] for r in cols}
        if not col_names:
            log.info("[migration v24] table %s does not exist — skip", table)
            continue
        if "country" in col_names:
            log.info("[migration v24] %s.country already present — skip", table)
            continue
        if "theater" not in col_names:
            log.info("[migration v24] %s has no theater column — skip", table)
            continue
        conn.execute(
            f'ALTER TABLE {table} ADD COLUMN country TEXT '
            f'GENERATED ALWAYS AS (theater) VIRTUAL'
        )
        log.info("[migration v24] %s.country generated column added", table)


# ── Schema SQL ────────────────────────────────────────────────────────────────
_SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA wal_autocheckpoint = 1000;

-- Phase 7.5h (audit DB L1) — schema_version is logically a single
-- "current schema" row. Pre-fix the table accumulated one row per
-- applied migration, so MAX(version) was needed at every read and
-- the table grew indefinitely. Fresh DBs ship with the single-row
-- shape (id PK, CHECK constraint); upgraded DBs converge via
-- migration v40.
CREATE TABLE IF NOT EXISTS schema_version (
    id          INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
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
-- scenario_id was added via migration v4. Mirrored here so fresh DBs
-- get the column without depending on the migration chain.
CREATE TABLE IF NOT EXISTS sequence_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    theater     TEXT NOT NULL,
    ts          REAL NOT NULL,
    event_type  TEXT NOT NULL,
    meta_json   TEXT NOT NULL DEFAULT '{}',
    scenario_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_seq_events_theater_ts
    ON sequence_events (theater, ts);
CREATE INDEX IF NOT EXISTS idx_sequence_events_scenario
    ON sequence_events (scenario_id);

-- threat_history — per-scenario TL series (migration v33 added
-- scenario_id; mirrored here for fresh DBs). The
-- idx_threat_history_scenario_ts index is created in
-- _post_baseline_indexes() so existing-DB upgrades (where the column
-- is added by migration v33) succeed without racing against the
-- baseline executescript.
CREATE TABLE IF NOT EXISTS threat_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           REAL NOT NULL,
    threat_level INTEGER NOT NULL,
    scenario_id  TEXT
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
    prompt_sha256   TEXT,
    -- Phase 8 (LLM survey v10) — routing telemetry. Migration v41 adds
    -- these via ALTER for upgraded DBs; the inline schema mirrors the
    -- ALTER so fresh DBs (which skip migrations) get them up-front.
    use_case            TEXT,
    shadow_model_choice TEXT,
    thinking_trace      TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_call_log_ts          ON llm_call_log (ts);
CREATE INDEX IF NOT EXISTS idx_llm_call_log_caller      ON llm_call_log (caller, ts);
-- Phase 8 indexes (use_case, model) are created in _post_baseline_indexes()
-- so they apply AFTER migration v41 has added the columns on upgraded DBs.

-- Phase 8 (LLM survey v10) — analyst-driven routing overrides. Mirrored
-- by migration v42 ALTERs for upgraded DBs; this inline form covers fresh
-- DBs (which skip migrations).
CREATE TABLE IF NOT EXISTS llm_routing_override (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    use_case          TEXT NOT NULL,
    slot              TEXT NOT NULL,
    model             TEXT,
    temperature       REAL,
    top_p             REAL,
    top_k             INTEGER,
    seed              INTEGER,
    num_predict       INTEGER,
    repeat_penalty    REAL,
    thinking_enabled  INTEGER,
    set_at            REAL NOT NULL,
    set_by            TEXT NOT NULL,
    reason            TEXT,
    UNIQUE (use_case, slot)
);
CREATE TABLE IF NOT EXISTS llm_routing_override_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    use_case    TEXT NOT NULL,
    slot        TEXT NOT NULL,
    old_json    TEXT,
    new_json    TEXT,
    changed_at  REAL NOT NULL,
    changed_by  TEXT NOT NULL,
    reason      TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_routing_override_hist_ts
    ON llm_routing_override_history (changed_at DESC);

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

-- v2.0 Phase 1 (ADR-V2-001 rollout monitoring).
-- Per-cycle diff between v1's in-memory TL and the v2 conclusions ledger.
-- Append-only; analysts review divergence stats before flipping the
-- default-on switch.
CREATE TABLE IF NOT EXISTS conclusion_diff_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sampled_at      REAL    NOT NULL,
    scenario_id     TEXT    NOT NULL,
    conclusion_type TEXT    NOT NULL,
    v1_state        TEXT,
    v2_state        TEXT,
    v2_conclusion_id TEXT,
    is_match        INTEGER NOT NULL,
    diff_kind       TEXT    NOT NULL,
    metadata        TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_conclusion_diff_time
    ON conclusion_diff_log (sampled_at DESC);
CREATE INDEX IF NOT EXISTS idx_conclusion_diff_kind_time
    ON conclusion_diff_log (diff_kind, sampled_at DESC);

-- v2.0 Phase 2 (ADR-V2-010): inconclusive_continuity_log.
-- Tracks consecutive cycles where a (scenario, conclusion_type) pair
-- inconclusive_continuity_log: defined below near line 636 with stricter
-- first_seen_at NOT NULL constraint (kept as the canonical schema).
CREATE INDEX IF NOT EXISTS idx_conclusions_scen_type_time
    ON conclusions (scenario_id, conclusion_type, observed_at DESC);

-- v2.0 priority 3 (Safe Rename Pattern SR4): legacy_access_log.
-- Records every observed access of a deprecated identifier so that the
-- 90-day sunset criterion (ADR-V2-002) can be evaluated on data, not guesswork.
CREATE TABLE IF NOT EXISTS legacy_access_log (
    key         TEXT    PRIMARY KEY,
    count       INTEGER NOT NULL DEFAULT 0,
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_legacy_access_last_seen
    ON legacy_access_log (last_seen DESC);

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
-- (idx_daily_summary_theater removed: exact duplicate of UNIQUE(theater, day_bucket))

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
-- (idx_cooccur_sensors removed: prefix-redundant with UNIQUE(sensor_a, sensor_b, theater);
--  SQLite uses the UNIQUE index for (sensor_a, sensor_b) equality lookups.)

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

-- v2.0 Phase 3: sensor_observation_ts for watchpane sparklines / drift watchdog.
CREATE TABLE IF NOT EXISTS sensor_observation_ts (
    sensor    TEXT NOT NULL,
    scope     TEXT NOT NULL,
    ts        REAL NOT NULL,
    score     REAL,
    baseline  REAL,
    status    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sensor_obs_lookup
    ON sensor_observation_ts (sensor, scope, ts DESC);
CREATE INDEX IF NOT EXISTS idx_sensor_obs_ttl
    ON sensor_observation_ts (ts);

-- v2.0 Phase 2: inconclusive_continuity_log (ADR-V2-010).
CREATE TABLE IF NOT EXISTS inconclusive_continuity_log (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at       REAL NOT NULL,
    scenario_id       TEXT NOT NULL,
    conclusion_type   TEXT NOT NULL,
    is_available      INTEGER NOT NULL DEFAULT 0,
    reason            TEXT,
    run_length_sec    REAL NOT NULL DEFAULT 0,
    first_seen_at     REAL NOT NULL,
    metadata          TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_inconclusive_continuity_scope
    ON inconclusive_continuity_log (scenario_id, conclusion_type, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_inconclusive_continuity_time
    ON inconclusive_continuity_log (observed_at DESC);

-- v2.0 Phase 3 (ADR-V2-011): analyst_feedback ledger.
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    conclusion_id        TEXT NOT NULL REFERENCES conclusions(id),
    label                TEXT NOT NULL
        CHECK (label IN ('TRUE_POSITIVE', 'FALSE_POSITIVE',
                         'TRUE_NEGATIVE', 'FALSE_NEGATIVE')),
    observed_outcome_url TEXT,
    analyst_id           TEXT NOT NULL,
    observed_at          REAL NOT NULL,
    notes                TEXT
);
CREATE INDEX IF NOT EXISTS idx_feedback_conclusion
    ON analyst_feedback (conclusion_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_analyst_time
    ON analyst_feedback (analyst_id, observed_at DESC);

-- Phase A foundation (2026-04-29): auto-tune ledgers.
CREATE TABLE IF NOT EXISTS threshold_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    emitted_at          REAL NOT NULL,
    key                 TEXT NOT NULL,
    value               TEXT NOT NULL,
    scope_scenario_id   TEXT,
    effective_from      REAL NOT NULL,
    effective_to        REAL,
    derived_from        TEXT NOT NULL,
    applied_by          TEXT NOT NULL,
    revertible_to_id    INTEGER REFERENCES threshold_history(id),
    sample_n            INTEGER NOT NULL DEFAULT 0,
    formula_ref         TEXT NOT NULL,
    evidence_json       TEXT NOT NULL DEFAULT '{}',
    magnitude_pct       REAL NOT NULL DEFAULT 0,
    state               TEXT NOT NULL DEFAULT 'active'
        CHECK (state IN ('active','reverted','superseded'))
);
CREATE INDEX IF NOT EXISTS idx_threshold_history_key_time
    ON threshold_history (key, effective_from DESC);
CREATE INDEX IF NOT EXISTS idx_threshold_history_scope_active
    ON threshold_history (scope_scenario_id, state, effective_from DESC);

CREATE TABLE IF NOT EXISTS scenario_drift_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    emitted_at          REAL NOT NULL,
    scenario_id         TEXT NOT NULL,
    drift_signal        TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN ('amber','red')),
    target_country      TEXT,
    evidence_json       TEXT NOT NULL DEFAULT '{}',
    formula_ref         TEXT NOT NULL,
    sample_n            INTEGER NOT NULL DEFAULT 0,
    why_string          TEXT,
    ack_state           TEXT NOT NULL DEFAULT 'unack'
        CHECK (ack_state IN ('unack','acknowledged','dismissed_as_false_positive')),
    ack_at              REAL,
    ack_by              TEXT,
    consecutive_runs    INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_scenario_drift_events_scenario
    ON scenario_drift_events (scenario_id, emitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_scenario_drift_events_unack
    ON scenario_drift_events (ack_state, severity, emitted_at DESC);

CREATE TABLE IF NOT EXISTS scenario_proposals (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    emitted_at          REAL NOT NULL,
    scenario_id         TEXT NOT NULL,
    proposal_type       TEXT NOT NULL,
    target_country      TEXT,
    suggested_value_json TEXT NOT NULL DEFAULT '{}',
    evidence_json       TEXT NOT NULL DEFAULT '{}',
    formula_ref         TEXT NOT NULL,
    sample_n            INTEGER NOT NULL DEFAULT 0,
    why_string          TEXT,
    evidence_strength   TEXT,    -- post-incident: 'strong'|'moderate'|'weak'|'insufficient'
    vitality_state      TEXT,    -- post-incident: 'active'|'dormant'|'data_gap'
    -- Phase D (2026-04-30): 'superseded' added so the discovery
    -- proposer can mark prior pendings inactive when a new run produces
    -- the same cluster fingerprint. Migration v35 extends existing DBs.
    state               TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','applied','dismissed','snoozed_30d','reverted','superseded')),
    state_changed_at    REAL,
    state_changed_by    TEXT,
    revertible_to_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_scenario_proposals_scenario
    ON scenario_proposals (scenario_id, emitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_scenario_proposals_pending
    ON scenario_proposals (state, emitted_at DESC);

-- Tier 3 (2026-04-29): G.2 + G.3a discovery foundation. Migration v29
-- creates these for upgraded DBs; mirrored here so fresh DBs get them.
CREATE TABLE IF NOT EXISTS cooccurrence_matrix_snapshot (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    emitted_at        REAL NOT NULL,
    window_days       INTEGER NOT NULL,
    bucket_hours      INTEGER NOT NULL DEFAULT 24,
    cell_count        INTEGER NOT NULL,
    matrix_json       TEXT NOT NULL,
    formula_ref       TEXT NOT NULL,
    evidence_json     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_cooccurrence_emitted_at
    ON cooccurrence_matrix_snapshot (emitted_at DESC);

CREATE TABLE IF NOT EXISTS scenario_discovery_run (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    emitted_at          REAL NOT NULL,
    matrix_snapshot_id  INTEGER NOT NULL
        REFERENCES cooccurrence_matrix_snapshot(id),
    algorithm           TEXT NOT NULL DEFAULT 'dbscan',
    eps                 REAL,
    min_samples         INTEGER,
    n_clusters          INTEGER NOT NULL DEFAULT 0,
    n_noise             INTEGER NOT NULL DEFAULT 0,
    formula_ref         TEXT NOT NULL,
    metadata_json       TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_discovery_run_emitted_at
    ON scenario_discovery_run (emitted_at DESC);

CREATE TABLE IF NOT EXISTS discovery_cluster (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id                INTEGER NOT NULL
        REFERENCES scenario_discovery_run(id),
    cluster_index         INTEGER NOT NULL,
    countries_json        TEXT NOT NULL,
    centroid_json         TEXT,
    annotation_json       TEXT,
    annotation_state      TEXT NOT NULL DEFAULT 'none'
        CHECK (annotation_state IN ('none','shadow','production')),
    suggested_scenario_id TEXT,
    formula_ref           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_discovery_cluster_run
    ON discovery_cluster (run_id);

-- LLM Feature Hub (migration v31, 2026-04-29). Mirrored here so fresh
-- DBs get the runtime control-plane tables without depending on the
-- migration chain.
CREATE TABLE IF NOT EXISTS llm_feature_state (
    feature_key   TEXT PRIMARY KEY,
    state         TEXT NOT NULL
        CHECK (state IN ('off','shadow','on')),
    set_at        REAL NOT NULL,
    set_by        TEXT NOT NULL,
    reason        TEXT
);
CREATE TABLE IF NOT EXISTS llm_feature_state_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    feature_key   TEXT NOT NULL,
    old_state     TEXT,
    new_state     TEXT NOT NULL,
    changed_at    REAL NOT NULL,
    changed_by    TEXT NOT NULL,
    reason        TEXT
);
CREATE INDEX IF NOT EXISTS idx_llm_feature_state_history_key
    ON llm_feature_state_history (feature_key, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_llm_feature_state_history_ts
    ON llm_feature_state_history (changed_at DESC);

-- ATTENTION rules engine (migration v32, 2026-04-29). Mirrored here so
-- fresh DBs include the snooze + adaptive-learning tables.
CREATE TABLE IF NOT EXISTS attention_snooze (
    rule_id        TEXT PRIMARY KEY,
    snooze_until   REAL NOT NULL,
    by             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attention_snooze_until
    ON attention_snooze (snooze_until DESC);

CREATE TABLE IF NOT EXISTS attention_metric_observation (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        TEXT NOT NULL,
    observed_at    REAL NOT NULL,
    observed_value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attention_metric_obs_rule_ts
    ON attention_metric_observation (rule_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS attention_metric_p95 (
    rule_id        TEXT PRIMARY KEY,
    p50            REAL NOT NULL,
    p95            REAL NOT NULL,
    p99            REAL,
    sample_count   INTEGER NOT NULL,
    computed_at    REAL NOT NULL,
    window_days    INTEGER NOT NULL DEFAULT 30
);

CREATE TABLE IF NOT EXISTS user_attention_thresholds (
    user_id        INTEGER NOT NULL,
    rule_id        TEXT NOT NULL,
    threshold      REAL NOT NULL,
    set_at         REAL NOT NULL,
    PRIMARY KEY (user_id, rule_id)
);

-- Decision Layer ledger (migration v34, 2026-04-30). Unified store for
-- analyst decisions on TRIAGE / calibration / threshold actions.
-- Columns and semantics documented in the v34 migration block.
CREATE TABLE IF NOT EXISTS decisions (
    id              TEXT PRIMARY KEY,
    decision_type   TEXT NOT NULL,
    target_kind     TEXT NOT NULL,
    target_id       TEXT,
    action          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    reason          TEXT,
    parameters      TEXT,
    decided_at      REAL NOT NULL,
    expires_at      REAL,
    superseded_by   TEXT,
    -- Phase 5 (audit) — revocation now has dedicated columns instead of
    -- abusing superseded_by with a synthetic 'revoked:<by>:<ts>' marker.
    -- The marker abuse violated the FK on superseded_by REFERENCES
    -- decisions(id) and prevented enabling PRAGMA foreign_keys = ON.
    revoked_at      REAL,
    revoked_by      TEXT,
    FOREIGN KEY (superseded_by) REFERENCES decisions (id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_target
    ON decisions (target_kind, target_id, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_type_ts
    ON decisions (decision_type, decided_at DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_active_expiry
    ON decisions (decision_type, expires_at)
    WHERE superseded_by IS NULL AND revoked_at IS NULL;

-- Phase 4 B2 (2026-04-29): auto-judge calibration ledger.
-- Mirrored in migration 27 for upgraded DBs; this ensures fresh DBs get
-- the table without depending on migration runs.
CREATE TABLE IF NOT EXISTS auto_judge_decisions (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                      REAL NOT NULL,
    item_id                 TEXT NOT NULL,
    action_proposed         TEXT NOT NULL
        CHECK (action_proposed IN ('confirm', 'reject', 'pending')),
    confidence              REAL NOT NULL DEFAULT 0,
    reason                  TEXT NOT NULL DEFAULT '',
    layer1_corroborators    INTEGER NOT NULL DEFAULT 0,
    layer1_satisfied        INTEGER NOT NULL DEFAULT 0,
    applied                 INTEGER NOT NULL DEFAULT 0,
    applied_at              REAL,
    analyst_overrode        INTEGER NOT NULL DEFAULT 0,
    analyst_override_action TEXT,
    analyst_override_at     REAL,
    analyst_id              TEXT
);
CREATE INDEX IF NOT EXISTS idx_auto_judge_decisions_ts
    ON auto_judge_decisions (ts);
CREATE INDEX IF NOT EXISTS idx_auto_judge_decisions_item
    ON auto_judge_decisions (item_id, ts);
CREATE INDEX IF NOT EXISTS idx_auto_judge_decisions_applied
    ON auto_judge_decisions (applied, ts);
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
        # Decision Layer ledger (migration v34, 2026-04-30). Lazy import
        # to avoid circular dependency with radar.decisions.
        from radar.decisions import DecisionLedger
        self.decisions = DecisionLedger(self)

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
            # Phase 5 (audit) — FK enforcement enabled. Three changes
            # together unblocked this:
            #   - decisions.record() now INSERTs the new row before
            #     UPDATEing prior rows' superseded_by, so the FK target
            #     row exists at constraint-check time.
            #   - decisions.revoke() writes revoked_at/revoked_by columns
            #     instead of stuffing a synthetic 'revoked:<by>:<ts>'
            #     marker into superseded_by — the marker abused the FK
            #     target since it is intentionally not a valid id.
            #   - decisions.superseded_by FK gained ON DELETE SET NULL.
            # See migration v37 for the data backfill.
            raw.execute("PRAGMA foreign_keys = ON")
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
        """Indexes and idempotent schema enhancements that must apply on
        BOTH fresh and upgraded DBs. Anything here MUST be idempotent.
        """
        try:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_focus_switch_log_source_time "
                "ON focus_switch_log (source, switched_at DESC)"
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            log.warning("[DB] post-baseline index skipped: %s", e)

        # threat_history.scenario_id index — runs AFTER migration v33
        # has added the column on upgraded DBs. Idempotent. (Fresh DBs
        # have the column from baseline _SCHEMA_SQL.)
        try:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_threat_history_scenario_ts "
                "ON threat_history (scenario_id, ts DESC)"
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            log.warning("[DB] threat_history index skipped: %s", e)

        # Phase 8 (LLM survey v10) — llm_call_log.use_case + .model indexes.
        # These columns are added by migration v41 on upgraded DBs and by
        # the inline schema on fresh DBs; the indexes are deferred here so
        # both paths converge. Idempotent.
        try:
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_llm_call_log_usecase_ts "
                "ON llm_call_log (use_case, ts)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_llm_call_log_model_ts "
                "ON llm_call_log (model, ts)"
            )
            conn.commit()
        except sqlite3.OperationalError as e:
            log.warning("[DB] llm_call_log Phase 8 indexes skipped: %s", e)

        # ADR-V2-006 A-4: ensure `country` generated column exists on every
        # table that carries `theater`, regardless of whether this DB was
        # created fresh from _SCHEMA_SQL (which doesn't contain the column)
        # or upgraded through migration v24. The helper is idempotent.
        try:
            with conn.writing():
                _migration_v24_generated_country(conn)
        except sqlite3.OperationalError as e:
            log.warning("[DB] A-4 generated column setup skipped: %s", e)

        # ADR-V2-015: ensure scenario_contribution_log carries `sensor` and
        # bg_observer_cycle_log exists. Fresh DBs skip migration v36
        # entirely (the migration engine sets schema_version to baseline
        # without running migrations on a brand-new DB), so the migration
        # helper is invoked here as well. Idempotent on upgraded DBs.
        try:
            with conn.writing():
                _migration_v36_bg_observer(conn)
        except sqlite3.OperationalError as e:
            log.warning("[DB] v36 bg_observer setup skipped: %s", e)

    def schema_version(self) -> int:
        try:
            row = self._get_conn().execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            return row[0] if row and row[0] is not None else 0
        except sqlite3.OperationalError:
            return 0

    def set_schema_version(self, ver: int):
        # Phase 7.5h (audit DB L1) — runtime shape detection. Old DBs
        # (pre-migration v40) have no `id` column and accumulate one
        # row per migration; new DBs have a single-row PK with a
        # CHECK(id = 1) constraint. We detect once per call (cheap)
        # and emit the right INSERT shape so the migration engine
        # works during the v40 transition itself.
        conn = self._get_conn()
        cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(schema_version)"
        ).fetchall()}
        with conn.writing():
            if "id" in cols:
                conn.execute(
                    "INSERT OR REPLACE INTO schema_version "
                    "(id, version, migrated_at) VALUES (1, ?, ?)",
                    (ver, time.time()),
                )
            else:
                conn.execute(
                    "INSERT INTO schema_version (version, migrated_at) "
                    "VALUES (?, ?)",
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
        # v2.0 Phase 1 priority 6: v1/v2 conclusion diff log.
        # Used during the shadow → opt-in rollout (ADR-V2-001) to measure
        # how often the v1 in-memory TL diverges from the v2 ledger row
        # before flipping default-on. Append-only; analyst review only.
        (21, "v2.0: conclusion_diff_log for v1/v2 rollout monitoring", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS conclusion_diff_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                sampled_at      REAL    NOT NULL,
                scenario_id     TEXT    NOT NULL,
                conclusion_type TEXT    NOT NULL,
                v1_state        TEXT,
                v2_state        TEXT,
                v2_conclusion_id TEXT,
                is_match        INTEGER NOT NULL,
                diff_kind       TEXT    NOT NULL,
                metadata        TEXT    NOT NULL DEFAULT '{}'
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_conclusion_diff_time
                ON conclusion_diff_log (sampled_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_conclusion_diff_kind_time
                ON conclusion_diff_log (diff_kind, sampled_at DESC)"""),
        ]),
        # v2.0 Phase 2 (ADR-V2-010): inconclusive_continuity_log.
        # Tracks consecutive cycles where a (scenario, conclusion_type) pair
        # produced an unavailable conclusion. NP5+8 enforces that transient
        # unavailable is acceptable but >= 7-day continuous unavailable is a
        # design failure that the scheduler must surface to analysts.
        # Append-only: each cycle inserts one row, even on transition.
        (22, "v2.0 Phase 2: inconclusive_continuity_log + per-conclusion-type index", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS inconclusive_continuity_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                observed_at     REAL    NOT NULL,
                scenario_id     TEXT    NOT NULL,
                conclusion_type TEXT    NOT NULL,
                is_available    INTEGER NOT NULL,
                reason          TEXT,
                run_length_sec  REAL    NOT NULL DEFAULT 0,
                first_seen_at   REAL,
                metadata        TEXT    NOT NULL DEFAULT '{}'
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_continuity_scen_type_time
                ON inconclusive_continuity_log (scenario_id, conclusion_type, observed_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_continuity_observed_at
                ON inconclusive_continuity_log (observed_at DESC)"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_conclusions_scen_type_time
                ON conclusions (scenario_id, conclusion_type, observed_at DESC)"""),
        ]),
        # v2.0 priority 3 (Safe Rename Pattern SR4): legacy_access_log records
        # every observed access of a deprecated identifier / dict key / API param.
        # Used by ADR-V2-002 sunset criterion "30 consecutive days of count=0".
        # See docs/design/safe-rename-pattern.md and radar/legacy_telemetry.py.
        (23, "v2.0 priority 3: legacy_access_log for SR4 telemetry", lambda conn: [
            conn.execute("""CREATE TABLE IF NOT EXISTS legacy_access_log (
                key         TEXT    PRIMARY KEY,
                count       INTEGER NOT NULL DEFAULT 0,
                first_seen  REAL    NOT NULL,
                last_seen   REAL    NOT NULL
            )"""),
            conn.execute("""CREATE INDEX IF NOT EXISTS idx_legacy_access_last_seen
                ON legacy_access_log (last_seen DESC)"""),
        ]),
        # v2.0 priority 3 (Safe Rename Pattern A-4): generated `country` column
        # mirroring legacy `theater` on every table that carries the legacy
        # field. Lets all SELECT sites use either name interchangeably while
        # the source column is still `theater`. At A-5 sunset we will swap
        # the source: drop the generated column, rename `theater` -> `country`.
        # SQLite ≥ 3.31 (project on 3.52.0) supports VIRTUAL generated columns
        # via ALTER TABLE; STORED is not allowed via ALTER. VIRTUAL is fine
        # here because it has zero storage cost and is computed on read.
        # Tables without a `theater` column (pure rename targets) are skipped.
        (24, "v2.0 A-4: generated country column mirroring theater (17 tables)", _migration_v24_generated_country),
        # Phase 3 Layer 3: per-sensor observation time-series so the Sensor
        # Watchpane (v2-ui.md §6.2 / §7.1) can render real 1h sparklines
        # instead of the degraded single-point rendering. Written by the
        # scoring tick after cache swap; read by /api/v2/sensors/<n>/observations.
        # 24h retention is enough for the planned 1h–6h windows; cleanup runs
        # opportunistically via DELETE WHERE ts < now()-86400.
        (25, "Phase 3: sensor_observation_ts for watchpane sparklines", """
            CREATE TABLE IF NOT EXISTS sensor_observation_ts (
                sensor   TEXT NOT NULL,
                scope    TEXT NOT NULL,
                ts       REAL NOT NULL,
                score    REAL NOT NULL,
                baseline REAL,
                status   TEXT,
                PRIMARY KEY (sensor, scope, ts)
            );
            CREATE INDEX IF NOT EXISTS idx_sensor_obs_lookup
                ON sensor_observation_ts (sensor, scope, ts DESC);
            CREATE INDEX IF NOT EXISTS idx_sensor_obs_ttl
                ON sensor_observation_ts (ts);
        """),
        # v2.0 Phase 3 (ADR-V2-011): analyst feedback ledger. Stores ground
        # truth labels per conclusion for Design W recall calibration and
        # attack-mode estimator validation. Permanent retention — feedback
        # is the project's only ground-truth signal, and aggregate metrics
        # are downstream of the raw rows. Multiple analysts may label the
        # same conclusion; aggregation is a read-side concern.
        (26, "v2.0 Phase 3: analyst_feedback ledger (ADR-V2-011)", """
            CREATE TABLE IF NOT EXISTS analyst_feedback (
                id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                conclusion_id        TEXT NOT NULL REFERENCES conclusions(id),
                label                TEXT NOT NULL
                    CHECK (label IN ('TRUE_POSITIVE', 'FALSE_POSITIVE',
                                     'TRUE_NEGATIVE', 'FALSE_NEGATIVE')),
                observed_outcome_url TEXT,
                analyst_id           TEXT NOT NULL,
                observed_at          REAL NOT NULL,
                notes                TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_feedback_conclusion
                ON analyst_feedback (conclusion_id, observed_at DESC);
            CREATE INDEX IF NOT EXISTS idx_feedback_analyst_time
                ON analyst_feedback (analyst_id, observed_at DESC);
        """),

        (27, "Phase 4 N3+B2: auto_judge_decisions calibration ledger", """
            -- LLM second-pass calibration ledger. Every LLM recheck
            -- invocation writes one row, regardless of shadow vs apply
            -- mode and regardless of whether the verdict was applied.
            -- Lets us compute ECE = |predicted_confidence - actual_outcome|
            -- once enough analyst overrides accumulate (≥30, per the
            -- (a)-only ECE rule discussed during design).
            CREATE TABLE IF NOT EXISTS auto_judge_decisions (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts                     REAL NOT NULL,
                item_id                TEXT NOT NULL,
                action_proposed        TEXT NOT NULL
                    CHECK (action_proposed IN ('confirm', 'reject', 'pending')),
                confidence             REAL NOT NULL DEFAULT 0,
                reason                 TEXT NOT NULL DEFAULT '',
                layer1_corroborators   INTEGER NOT NULL DEFAULT 0,
                layer1_satisfied       INTEGER NOT NULL DEFAULT 0,
                applied                INTEGER NOT NULL DEFAULT 0,
                applied_at             REAL,
                analyst_overrode       INTEGER NOT NULL DEFAULT 0,
                analyst_override_action TEXT,
                analyst_override_at    REAL,
                analyst_id             TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_auto_judge_decisions_ts
                ON auto_judge_decisions (ts);
            CREATE INDEX IF NOT EXISTS idx_auto_judge_decisions_item
                ON auto_judge_decisions (item_id, ts);
            CREATE INDEX IF NOT EXISTS idx_auto_judge_decisions_applied
                ON auto_judge_decisions (applied, ts);
        """),

        (28, "Phase A: threshold_history ledger + scenario_drift_events + scenario_proposals (auto-tune foundation)", """
            -- Phase A foundation (2026-04-29): every auto-tune decision is
            -- recorded as a ledger row so the conclusion's threshold_ref
            -- resolves at-decision-time (not from a mutable global). This
            -- is the load-bearing piece for NP6 transparency under
            -- automated tuning. See docs/design/v2-migration.md Phase F.
            CREATE TABLE IF NOT EXISTS threshold_history (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                emitted_at          REAL NOT NULL,
                key                 TEXT NOT NULL,
                value               TEXT NOT NULL,
                scope_scenario_id   TEXT,
                effective_from      REAL NOT NULL,
                effective_to        REAL,
                derived_from        TEXT NOT NULL,
                applied_by          TEXT NOT NULL,
                revertible_to_id    INTEGER REFERENCES threshold_history(id),
                sample_n            INTEGER NOT NULL DEFAULT 0,
                formula_ref         TEXT NOT NULL,
                evidence_json       TEXT NOT NULL DEFAULT '{}',
                magnitude_pct       REAL NOT NULL DEFAULT 0,
                state               TEXT NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'reverted', 'superseded'))
            );
            CREATE INDEX IF NOT EXISTS idx_threshold_history_key_time
                ON threshold_history (key, effective_from DESC);
            CREATE INDEX IF NOT EXISTS idx_threshold_history_scope_active
                ON threshold_history (scope_scenario_id, state, effective_from DESC);

            -- F3 drift watchdog ledger (sibling to threshold_history).
            CREATE TABLE IF NOT EXISTS scenario_drift_events (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                emitted_at          REAL NOT NULL,
                scenario_id         TEXT NOT NULL,
                drift_signal        TEXT NOT NULL,
                severity            TEXT NOT NULL CHECK (severity IN ('amber','red')),
                target_country      TEXT,
                evidence_json       TEXT NOT NULL DEFAULT '{}',
                formula_ref         TEXT NOT NULL,
                sample_n            INTEGER NOT NULL DEFAULT 0,
                why_string          TEXT,
                ack_state           TEXT NOT NULL DEFAULT 'unack'
                    CHECK (ack_state IN ('unack','acknowledged','dismissed_as_false_positive')),
                ack_at              REAL,
                ack_by              TEXT,
                consecutive_runs    INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_scenario_drift_events_scenario
                ON scenario_drift_events (scenario_id, emitted_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scenario_drift_events_unack
                ON scenario_drift_events (ack_state, severity, emitted_at DESC);

            -- F1 improvement proposals ledger (used in next phase, schema
            -- defined here so the migration is atomic).
            CREATE TABLE IF NOT EXISTS scenario_proposals (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                emitted_at          REAL NOT NULL,
                scenario_id         TEXT NOT NULL,
                proposal_type       TEXT NOT NULL,
                target_country      TEXT,
                suggested_value_json TEXT NOT NULL DEFAULT '{}',
                evidence_json       TEXT NOT NULL DEFAULT '{}',
                formula_ref         TEXT NOT NULL,
                sample_n            INTEGER NOT NULL DEFAULT 0,
                why_string          TEXT,
                state               TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','applied','dismissed','snoozed_30d','reverted')),
                state_changed_at    REAL,
                state_changed_by    TEXT,
                revertible_to_json  TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scenario_proposals_scenario
                ON scenario_proposals (scenario_id, emitted_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scenario_proposals_pending
                ON scenario_proposals (state, emitted_at DESC);
        """),

        (29, "Tier 3: cooccurrence_matrix_snapshot + scenario_discovery_run + discovery_cluster (G.2 + G.3a foundation)", """
            -- G.2: Co-occurrence matrix snapshots. Each row captures one
            -- ETL run's pairwise country co-occurrence over a time window.
            -- matrix_json shape: {countries: [...], pairs: [{a, b, count, share}]}
            -- cell_count caps the matrix size — refuse > 5000 to avoid bloat.
            CREATE TABLE IF NOT EXISTS cooccurrence_matrix_snapshot (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                emitted_at        REAL NOT NULL,
                window_days       INTEGER NOT NULL,
                bucket_hours      INTEGER NOT NULL DEFAULT 24,
                cell_count        INTEGER NOT NULL,
                matrix_json       TEXT NOT NULL,
                formula_ref       TEXT NOT NULL,
                evidence_json     TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_cooccurrence_emitted_at
                ON cooccurrence_matrix_snapshot (emitted_at DESC);

            -- G.3a: DBSCAN run records. One row per discovery pass.
            CREATE TABLE IF NOT EXISTS scenario_discovery_run (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                emitted_at          REAL NOT NULL,
                matrix_snapshot_id  INTEGER NOT NULL
                    REFERENCES cooccurrence_matrix_snapshot(id),
                algorithm           TEXT NOT NULL DEFAULT 'dbscan',
                eps                 REAL,
                min_samples         INTEGER,
                n_clusters          INTEGER NOT NULL DEFAULT 0,
                n_noise             INTEGER NOT NULL DEFAULT 0,
                formula_ref         TEXT NOT NULL,
                metadata_json       TEXT NOT NULL DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_run_emitted_at
                ON scenario_discovery_run (emitted_at DESC);

            -- One row per cluster found in a discovery_run. annotation_json
            -- is filled in commit 12 (G.3b LLM annotator) when shadow opt-in.
            CREATE TABLE IF NOT EXISTS discovery_cluster (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id                INTEGER NOT NULL
                    REFERENCES scenario_discovery_run(id),
                cluster_index         INTEGER NOT NULL,
                countries_json        TEXT NOT NULL,
                centroid_json         TEXT,
                annotation_json       TEXT,
                annotation_state      TEXT NOT NULL DEFAULT 'none'
                    CHECK (annotation_state IN ('none','shadow','production')),
                suggested_scenario_id TEXT,
                formula_ref           TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_discovery_cluster_run
                ON discovery_cluster (run_id);
        """),

        (30, "Post-incident redesign: scenario_proposals.evidence_strength + vitality_state for guard-aware emission", """
            -- Post-incident redesign (2026-04-29 Wizard incident).
            -- Each emitted proposal records the evidence_strength + scenario
            -- vitality_state so the UI can route it to the right tab
            -- (Recall+ / Structure / Recall- / Diagnostic) and color it
            -- correctly. Both columns are nullable for back-compat with
            -- pre-redesign rows.
            ALTER TABLE scenario_proposals ADD COLUMN evidence_strength TEXT;
            ALTER TABLE scenario_proposals ADD COLUMN vitality_state TEXT;
        """),

        (33, "Threat history scenario_id column for per-scenario sparkline (HUD divergence fix 2026-04-29)", """
            -- Pre-fix: threat_history was a single global stream. The HUD
            -- sparkline rendered "whatever scenario was focused at the
            -- time" rather than "this scenario's history", causing the
            -- HUD-Row-1 / sparkline / FOCUS-card divergence.
            -- The accompanying idx_threat_history_scenario_ts index is
            -- created by _post_baseline_indexes() (idempotent), which
            -- runs AFTER all migrations so the column exists on both
            -- fresh and upgraded DBs.
            ALTER TABLE threat_history ADD COLUMN scenario_id TEXT;
        """),

        (35, "scenario_proposals.state allows 'superseded' (Phase D autotune fix 2026-04-30)", """
            -- Phase D of the autotune audit fix (2026-04-30 PM).
            -- Adds 'superseded' to the allowed states so the discovery
            -- proposer can mark prior pendings inactive when a new
            -- calibration run emits the same countries cluster.
            -- SQLite doesn't support modifying CHECK constraints, so we
            -- recreate the table with the new constraint and migrate
            -- the data. Indexes are recreated below.
            -- NOTE: CREATE TABLE without IF NOT EXISTS is intentional here.
            -- The preceding ALTER TABLE ... RENAME guarantees the original
            -- name is free; if a partial migration left the original in place
            -- we want this to fail loudly rather than silently skip the rebuild.
            ALTER TABLE scenario_proposals RENAME TO scenario_proposals_old_v34;
            CREATE TABLE scenario_proposals (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                emitted_at          REAL NOT NULL,
                scenario_id         TEXT NOT NULL,
                proposal_type       TEXT NOT NULL,
                target_country      TEXT,
                suggested_value_json TEXT NOT NULL DEFAULT '{}',
                evidence_json       TEXT NOT NULL DEFAULT '{}',
                formula_ref         TEXT NOT NULL,
                sample_n            INTEGER NOT NULL DEFAULT 0,
                why_string          TEXT,
                evidence_strength   TEXT,
                vitality_state      TEXT,
                state               TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','applied','dismissed',
                                     'snoozed_30d','reverted','superseded')),
                state_changed_at    REAL,
                state_changed_by    TEXT,
                revertible_to_json  TEXT
            );
            INSERT INTO scenario_proposals
                (id, emitted_at, scenario_id, proposal_type, target_country,
                 suggested_value_json, evidence_json, formula_ref, sample_n,
                 why_string, evidence_strength, vitality_state, state,
                 state_changed_at, state_changed_by, revertible_to_json)
            SELECT
                id, emitted_at, scenario_id, proposal_type, target_country,
                suggested_value_json, evidence_json, formula_ref, sample_n,
                why_string, evidence_strength, vitality_state, state,
                state_changed_at, state_changed_by, revertible_to_json
            FROM scenario_proposals_old_v34;
            DROP TABLE scenario_proposals_old_v34;
            CREATE INDEX IF NOT EXISTS idx_scenario_proposals_scenario
                ON scenario_proposals (scenario_id, emitted_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scenario_proposals_pending
                ON scenario_proposals (state, emitted_at DESC);
        """),

        (34, "Decision Layer ledger (operations + governance + AP4 trail) — 2026-04-30", """
            -- Unified ledger for analyst decisions across triage, calibration,
            -- and threshold operations. Sits beside (not above) existing
            -- distributed implementations like attention_snooze and
            -- scenario_proposals.state_changed_by — Decision History UI
            -- merges this and the legacy stores into one timeline (AP4).
            --
            -- decision_type values currently in use:
            --   'triage_snooze'         — TRIAGE Lane mute (max 24h)
            --   'triage_visibility'     — always-visible toggle
            --   'triage_dismiss'        — hide until next fire
            --   'tl_recal_accept'       — accept current TL thresholds
            --   'tl_recal_extend'       — extend TL recal deadline
            --   'tl_recal_raise'        — apply RAISE_THRESHOLDS
            --   'dual_weight_accept'    — accept dual-weight result
            --   'dual_weight_extend'    — extend dual-weight evaluation
            --   'dual_weight_rollback'  — rollback to single-weight (NP7)
            --   'triage_threshold_override' — per-user dormant/critical set
            --
            -- target_kind: 'global' | 'scenario' | 'conclusion' | 'user'
            -- action:      'accept' | 'extend' | 'raise' | 'rollback'
            --              | 'snooze' | 'dismiss' | 'set' | 'apply'
            -- expires_at:  unix seconds; NULL = no expiry; past = inactive
            -- superseded_by: decision_id of the next decision on the same
            --                (decision_type, target_kind, target_id);
            --                NULL = current
            CREATE TABLE IF NOT EXISTS decisions (
                id              TEXT PRIMARY KEY,
                decision_type   TEXT NOT NULL,
                target_kind     TEXT NOT NULL,
                target_id       TEXT,
                action          TEXT NOT NULL,
                actor           TEXT NOT NULL,
                reason          TEXT,
                parameters      TEXT,
                decided_at      REAL NOT NULL,
                expires_at      REAL,
                superseded_by   TEXT,
                FOREIGN KEY (superseded_by) REFERENCES decisions (id)
            );
            CREATE INDEX IF NOT EXISTS idx_decisions_target
                ON decisions (target_kind, target_id, decided_at DESC);
            CREATE INDEX IF NOT EXISTS idx_decisions_type_ts
                ON decisions (decision_type, decided_at DESC);
            CREATE INDEX IF NOT EXISTS idx_decisions_active_expiry
                ON decisions (decision_type, expires_at)
                WHERE superseded_by IS NULL;
        """),

        (32, "ATTENTION snooze + adaptive learning observation tables (CONTROLS redesign 2026-04-29)", """
            -- Snooze surface for ATTENTION rules (commit M).
            CREATE TABLE IF NOT EXISTS attention_snooze (
                rule_id        TEXT PRIMARY KEY,
                snooze_until   REAL NOT NULL,
                by             TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_attention_snooze_until
                ON attention_snooze (snooze_until DESC);

            -- Adaptive learning observations (commit O). One row per
            -- 5-minute polling tick × rule. Retention 30d.
            CREATE TABLE IF NOT EXISTS attention_metric_observation (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id        TEXT NOT NULL,
                observed_at    REAL NOT NULL,
                observed_value REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_attention_metric_obs_rule_ts
                ON attention_metric_observation (rule_id, observed_at DESC);

            -- Aggregated per-rule p50/p95 statistics (computed nightly).
            CREATE TABLE IF NOT EXISTS attention_metric_p95 (
                rule_id        TEXT PRIMARY KEY,
                p50            REAL NOT NULL,
                p95            REAL NOT NULL,
                p99            REAL,
                sample_count   INTEGER NOT NULL,
                computed_at    REAL NOT NULL,
                window_days    INTEGER NOT NULL DEFAULT 30
            );

            -- Per-user threshold overrides (commit O).
            CREATE TABLE IF NOT EXISTS user_attention_thresholds (
                user_id        INTEGER NOT NULL,
                rule_id        TEXT NOT NULL,
                threshold      REAL NOT NULL,
                set_at         REAL NOT NULL,
                PRIMARY KEY (user_id, rule_id)
            );
        """),

        (31, "LLM Feature Hub: feature_state runtime control plane + audit history", """
            -- LLM Feature Hub registry (radar/llm_features.py). The
            -- runtime state of every LLM-driven capability is owned
            -- by these two tables. Migration is non-destructive — the
            -- existing env flags continue to work as defaults; rows
            -- here override env when present.
            CREATE TABLE IF NOT EXISTS llm_feature_state (
                feature_key   TEXT PRIMARY KEY,
                state         TEXT NOT NULL
                    CHECK (state IN ('off','shadow','on')),
                set_at        REAL NOT NULL,
                set_by        TEXT NOT NULL,
                reason        TEXT
            );

            -- Append-only audit trail (NP6). Every state flip records
            -- old/new state + actor + reason. Pair with the API audit
            -- endpoint for forensic readout.
            CREATE TABLE IF NOT EXISTS llm_feature_state_history (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                feature_key   TEXT NOT NULL,
                old_state     TEXT,
                new_state     TEXT NOT NULL,
                changed_at    REAL NOT NULL,
                changed_by    TEXT NOT NULL,
                reason        TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_llm_feature_state_history_key
                ON llm_feature_state_history (feature_key, changed_at DESC);
            CREATE INDEX IF NOT EXISTS idx_llm_feature_state_history_ts
                ON llm_feature_state_history (changed_at DESC);
        """),

        (36, "bg_observer phase 6: sensor column on contribution_log + cycle_log table (ADR-V2-015)",
         _migration_v36_bg_observer),

        (37, "decisions: revoked_at/revoked_by columns + backfill (Phase 5 audit fix)",
         _migration_v37_decisions_revocation),

        (38, "sensor_observation_ts: rebuild with PRIMARY KEY (sensor, scope, ts) (DB H1)",
         _migration_v38_sensor_observation_ts_pk),

        (39, "scenario_tl_observation: composite index incl scoring_mode (DB H3)",
         _migration_v39_scenario_tl_obs_mode_index),

        (40, "schema_version: collapse to singleton row (DB L1)",
         _migration_v40_schema_version_singleton),

        (41, "llm_call_log: thinking_trace + use_case + shadow_model_choice (Phase 8 LLM survey v10)",
         _migration_v41_llm_routing_v10),

        (42, "llm_routing_override + history (Phase 8 analyst override surface)",
         _migration_v42_llm_routing_overrides),
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

    # ── sensor_observation_ts (Phase 3 watchpane sparklines) ────────────────
    # Per-sensor per-scope observation series. Written from the scoring tick
    # after cache swap; read by /api/v2/sensors/<n>/observations to render
    # real 1h sparklines. 24h TTL is enough for the planned 1h–6h windows.
    def sensor_obs_record(
        self, sensor: str, scope: str, ts: float, score: float,
        baseline: float | None = None, status: str | None = None,
        ttl_sec: float = 86400.0,
    ) -> None:
        """Insert one observation point and opportunistically prune > ttl_sec."""
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT OR REPLACE INTO sensor_observation_ts "
                "(sensor, scope, ts, score, baseline, status) VALUES (?, ?, ?, ?, ?, ?)",
                (sensor, scope, ts, float(score), baseline, status),
            )
            cutoff = ts - ttl_sec
            conn.execute(
                "DELETE FROM sensor_observation_ts WHERE ts < ?",
                (cutoff,),
            )

    def sensor_obs_recent(
        self, sensor: str, scope: str, since_ts: float,
    ) -> list[tuple[float, float, float | None, str | None]]:
        """Return [(ts, score, baseline, status), ...] for a sensor/scope since cutoff."""
        rows = self._get_conn().execute(
            "SELECT ts, score, baseline, status FROM sensor_observation_ts "
            "WHERE sensor=? AND scope=? AND ts>=? ORDER BY ts",
            (sensor, scope, since_ts),
        ).fetchall()
        return [(r[0], r[1], r[2], r[3]) for r in rows]

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
                                     logged_at: float,
                                     sensor: Optional[str] = None,
                                     contributions_by_country_sensor: Optional[
                                         dict[tuple[str, str], float]
                                     ] = None) -> None:
        """Persist this cycle's per-country contribution sums for a scenario.

        Two call shapes are supported (one per call):

        - ``contributions_by_country={'IL': 0.42}`` + optional ``sensor='bg_observer_rss'``:
          all entries share the same sensor (back-compat behaviour when no
          sensor is supplied: persisted with sensor=NULL = 'legacy').
        - ``contributions_by_country_sensor={('IL','bg_observer_rss'): 0.42, ...}``:
          per-(country, sensor) breakdown for callers that have already
          partitioned by sensor (ADR-V2-015 Phase 1).

        Empty contributions are intentionally still appended as a row with
        contribution_sum=0 so the aggregator can distinguish "no signal in
        the window" from "scenario was inactive in the window".
        """
        if not contributions_by_country and not contributions_by_country_sensor:
            return
        # Phase 5 (audit / DB H2): batch inserts via executemany. The
        # previous per-row execute() loop held the cooperative write
        # lock for the full loop duration on every 30-second scoring
        # tick, producing ~11,520 lock-protected calls per day for a
        # 4-country scenario. executemany serialises into a single
        # parameterised statement, dropping the lock-held window
        # significantly under load.
        if contributions_by_country_sensor:
            rows = [
                (scenario_id, country, float(total), logged_at, snr)
                for (country, snr), total in contributions_by_country_sensor.items()
            ]
        else:
            rows = [
                (scenario_id, country, float(total), logged_at, sensor)
                for country, total in contributions_by_country.items()
            ]
        if not rows:
            return
        conn = self._get_conn()
        with conn.writing():
            conn.executemany(
                "INSERT INTO scenario_contribution_log "
                "(scenario_id, country, contribution_sum, logged_at, sensor) "
                "VALUES (?, ?, ?, ?, ?)",
                rows,
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

    def scenario_signal_volume(
        self, scenario_id: str, hours: int = 24,
    ) -> dict:
        """Per-scenario signal-volume report for the AP3 OBS chip.

        Returns a dict with:
          - row_count: distinct (logged_at, country) rows with non-zero
                       per-country contribution in the window
          - distinct_countries: count of distinct participant countries
                                that contributed
          - last_at: most recent logged_at (None if no rows)
          - top_countries: list of (country, total_contribution) tuples,
                           top 5 desc

        Queries the scenario_contribution_log, which excludes GLOBAL
        signals by construction. So the figure measures genuine per-
        country observation, not noise from global sources like
        cf_botnet_overlap.

        Used to identify scenarios whose lite-mode score is being driven
        only by global signals (chronic blind-spot per NP5+8).

        Phase 6 (ADR-V2-015): also returns ``by_sensor`` so the AP3 OBS
        chip can disaggregate bg_observer / llm_intel / per-country
        sensors. Legacy rows without a sensor value are bucketed under
        'legacy'.
        """
        cutoff = time.time() - hours * 3600
        conn = self._get_conn()
        agg = conn.execute(
            "SELECT COUNT(*) AS n, "
            "       COUNT(DISTINCT country) AS n_countries, "
            "       MAX(logged_at) AS last_at "
            "FROM scenario_contribution_log "
            "WHERE scenario_id = ? AND logged_at > ? "
            "  AND contribution_sum > 0",
            (scenario_id, cutoff),
        ).fetchone()
        top = conn.execute(
            "SELECT country, SUM(contribution_sum) AS total "
            "FROM scenario_contribution_log "
            "WHERE scenario_id = ? AND logged_at > ? "
            "  AND contribution_sum > 0 "
            "GROUP BY country ORDER BY total DESC LIMIT 5",
            (scenario_id, cutoff),
        ).fetchall()
        by_sensor_rows = conn.execute(
            "SELECT COALESCE(sensor, 'legacy') AS s, "
            "       COUNT(*) AS n, "
            "       SUM(contribution_sum) AS total, "
            "       COUNT(DISTINCT country) AS n_countries "
            "FROM scenario_contribution_log "
            "WHERE scenario_id = ? AND logged_at > ? "
            "  AND contribution_sum > 0 "
            "GROUP BY COALESCE(sensor, 'legacy')",
            (scenario_id, cutoff),
        ).fetchall()
        return {
            "row_count": int(agg["n"] or 0) if agg else 0,
            "distinct_countries": int(agg["n_countries"] or 0) if agg else 0,
            "last_at": float(agg["last_at"]) if agg and agg["last_at"] else None,
            "top_countries": [
                (r["country"], float(r["total"] or 0.0)) for r in top
            ],
            "by_sensor": {
                r["s"]: {
                    "row_count": int(r["n"] or 0),
                    "total": float(r["total"] or 0.0),
                    "distinct_countries": int(r["n_countries"] or 0),
                }
                for r in by_sensor_rows
            },
        }

    # ── bg_observer cycle_log (ADR-V2-015 Phase 5) ─────────────────────────
    def bg_observer_cycle_append(self, row: dict) -> None:
        """Persist one bg_observer cycle audit row.

        ``row`` must contain the columns of bg_observer_cycle_log. JSON
        fields (matches_by_country, alias_gap, scenarios_observed) may be
        passed as Python objects and will be serialised here.
        """
        import json as _json
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO bg_observer_cycle_log "
                "(started_at, duration_ms, feeds_attempted, feeds_failed, "
                " items_total, items_with_country, items_with_kinetic, "
                " items_with_fatalities, matches_emitted, matches_by_country, "
                " alias_gap, scenarios_observed, drop_reason) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    float(row.get("started_at", time.time())),
                    int(row.get("duration_ms", 0)),
                    int(row.get("feeds_attempted", 0)),
                    int(row.get("feeds_failed", 0)),
                    int(row.get("items_total", 0)),
                    int(row.get("items_with_country", 0)),
                    int(row.get("items_with_kinetic", 0)),
                    int(row.get("items_with_fatalities", 0)),
                    int(row.get("matches_emitted", 0)),
                    _json.dumps(row.get("matches_by_country", {})),
                    _json.dumps(row.get("alias_gap", [])),
                    _json.dumps(row.get("scenarios_observed", [])),
                    row.get("drop_reason"),
                ),
            )

    def bg_observer_cycle_summary(self, hours: int = 24) -> dict:
        """Aggregate stats for the AP3 self-eval HUD chip.

        Returns counts of cycles, empty-cycle ratio, median matches per
        cycle, and the most recent alias_gap observation.
        """
        cutoff = time.time() - hours * 3600
        conn = self._get_conn()
        agg = conn.execute(
            "SELECT COUNT(*) AS n, "
            "       SUM(CASE WHEN matches_emitted = 0 THEN 1 ELSE 0 END) AS n_empty, "
            "       SUM(matches_emitted) AS sum_matches, "
            "       MAX(started_at) AS last_at "
            "FROM bg_observer_cycle_log "
            "WHERE started_at > ?",
            (cutoff,),
        ).fetchone()
        last_gap_row = conn.execute(
            "SELECT alias_gap FROM bg_observer_cycle_log "
            "WHERE started_at > ? "
            "ORDER BY started_at DESC LIMIT 1",
            (cutoff,),
        ).fetchone()
        n = int(agg["n"] or 0) if agg else 0
        n_empty = int(agg["n_empty"] or 0) if agg else 0
        sum_m = int(agg["sum_matches"] or 0) if agg else 0
        import json as _json
        try:
            alias_gap = _json.loads(last_gap_row["alias_gap"]) if last_gap_row else []
        except Exception:
            alias_gap = []
        return {
            "cycles": n,
            "empty_cycles": n_empty,
            "empty_rate": round(n_empty / n, 3) if n else None,
            "matches_total": sum_m,
            "matches_per_cycle_avg": round(sum_m / n, 2) if n else None,
            "last_at": float(agg["last_at"]) if agg and agg["last_at"] else None,
            "alias_gap": alias_gap,
        }

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
    # Post-redesign 2026-04-29: scenario_id column added (migration v33) so
    # the HUD sparkline can pull per-scenario history rather than the
    # old "currently-focused TL across any scenario" mishmash that caused
    # the HUD/sparkline/FOCUS-card divergence.
    #
    # `threat_append(ts, level)` retains the legacy unscoped semantics
    # (used by paths that still don't track scenario context); new callers
    # should use `threat_append_scoped(ts, level, scenario_id)`.

    def threat_append(self, ts: float, level: int, max_entries: int = 100):
        """Legacy unscoped append. scenario_id stored as NULL.

        Kept for any caller that doesn't have scenario_id available (e.g.
        sunset-era v1 paths). Per-scenario sparkline ignores NULL rows.
        """
        return self.threat_append_scoped(ts, level, None,
                                         max_entries=max_entries)

    def threat_append_scoped(self, ts: float, level: int,
                             scenario_id: Optional[str],
                             max_entries: int = 1000):
        """Append a (ts, level, scenario_id) row.

        max_entries default raised from 100 → 1000 because we now have
        N scenarios × ticks each, not a single global stream.
        """
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "INSERT INTO threat_history (ts, threat_level, scenario_id) "
                "VALUES (?, ?, ?)",
                (ts, level, scenario_id),
            )
            # Per-scenario retention: keep last `max_entries` per scenario.
            # NULL scenario_id rows are kept under their own bucket.
            conn.execute(
                "DELETE FROM threat_history WHERE id IN ("
                "  SELECT id FROM threat_history th "
                "  WHERE (th.scenario_id IS ? OR th.scenario_id = ?) "
                "  AND id NOT IN ("
                "    SELECT id FROM threat_history "
                "    WHERE (scenario_id IS ? OR scenario_id = ?) "
                "    ORDER BY id DESC LIMIT ?"
                "  )"
                ")",
                (scenario_id, scenario_id,
                 scenario_id, scenario_id, max_entries),
            )

    def threat_list(self) -> list[tuple[float, int]]:
        """Legacy unscoped list — returns ALL rows regardless of scenario.

        Used by the legacy /api/threat_data response. New consumers
        should call `threat_list_scoped(scenario_id)`.
        """
        rows = self._get_conn().execute(
            "SELECT ts, threat_level FROM threat_history ORDER BY id"
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def threat_list_scoped(self, scenario_id: str,
                           since_ts: Optional[float] = None,
                           limit: int = 1000) -> list[tuple[float, int]]:
        """Return (ts, level) rows for a single scenario, optionally
        filtered to since_ts (unix seconds). Ordered ascending by id.
        """
        if since_ts is not None:
            rows = self._get_conn().execute(
                "SELECT ts, threat_level FROM threat_history "
                "WHERE scenario_id=? AND ts >= ? "
                "ORDER BY id LIMIT ?",
                (scenario_id, since_ts, limit),
            ).fetchall()
        else:
            rows = self._get_conn().execute(
                "SELECT ts, threat_level FROM threat_history "
                "WHERE scenario_id=? ORDER BY id DESC LIMIT ?",
                (scenario_id, limit),
            ).fetchall()
            rows = list(reversed(rows))
        return [(r[0], r[1]) for r in rows]

    def threat_last(self) -> Optional[tuple[float, int]]:
        row = self._get_conn().execute(
            "SELECT ts, threat_level FROM threat_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else None

    def threat_last_scoped(self, scenario_id: str) -> Optional[tuple[float, int]]:
        row = self._get_conn().execute(
            "SELECT ts, threat_level FROM threat_history "
            "WHERE scenario_id=? ORDER BY id DESC LIMIT 1",
            (scenario_id,),
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
                            error: str = "", prompt_sha256: str = "",
                            use_case: "str | None" = None,
                            shadow_model_choice: "str | None" = None,
                            thinking_trace: "str | None" = None):
        """Persist a single LLM call attempt and its downstream queue verdict.

        prompt_sha256        : optional FK to llm_prompts (ADR-V2-009). Empty
                               string when prompt persistence is disabled.
        use_case             : Phase 8 routing bucket. None for legacy callers.
        shadow_model_choice  : when v10 routing is in SHADOW state, the model
                               that would have been picked. None otherwise.
        thinking_trace       : reasoning text captured from <|think|> /
                               Reasoning: high modes. None when thinking OFF.
        """
        import time as _time
        conn = self._get_conn()
        # Capped at generous bounds so a runaway model can't blow the row.
        trace = (thinking_trace or "")[:4000] or None
        sm_choice = (shadow_model_choice or "")[:80] or None
        uc = (use_case or "")[:32] or None
        with conn.writing():
            conn.execute(
                "INSERT INTO llm_call_log "
                "(ts, caller, model, duration_ms, outcome, verdict, "
                " confidence, headline, error, prompt_sha256, "
                " use_case, shadow_model_choice, thinking_trace) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (_time.time(), caller, model[:80], duration_ms, outcome,
                 verdict, float(confidence), (headline or "")[:200],
                 (error or "")[:300], prompt_sha256 or None,
                 uc, sm_choice, trace),
            )

    def auto_judge_decision_log(self, item_id: str, action_proposed: str,
                                 confidence: float, reason: str,
                                 layer1_corroborators: int,
                                 layer1_satisfied: bool,
                                 applied: bool) -> int:
        """Append a row to auto_judge_decisions and return its rowid.

        One row per LLM second-pass invocation (shadow + apply), regardless
        of whether the verdict was actually applied. Used by ECE
        calibration once analyst overrides accumulate.
        """
        import time as _time
        conn = self._get_conn()
        now = _time.time()
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO auto_judge_decisions "
                "(ts, item_id, action_proposed, confidence, reason, "
                " layer1_corroborators, layer1_satisfied, applied, applied_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now, item_id, action_proposed, float(confidence),
                 (reason or "")[:200], int(layer1_corroborators),
                 1 if layer1_satisfied else 0,
                 1 if applied else 0,
                 now if applied else None),
            )
            return cur.lastrowid

    def auto_judge_decision_mark_applied(self, item_id: str) -> None:
        """Promote the most recent decision row for an item to applied=1."""
        import time as _time
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "UPDATE auto_judge_decisions SET applied=1, applied_at=? "
                "WHERE rowid=(SELECT rowid FROM auto_judge_decisions "
                "             WHERE item_id=? ORDER BY ts DESC LIMIT 1)",
                (_time.time(), item_id),
            )

    def auto_judge_decision_mark_overridden(self, item_id: str,
                                             override_action: str,
                                             analyst_id: str) -> None:
        """Mark the most recent applied decision for `item_id` as overridden
        by an analyst. Called from intel_queue.confirm/reject when the
        analyst's marker is NOT auto:rule_* / auto:llm_recheck_*.
        """
        import time as _time
        conn = self._get_conn()
        with conn.writing():
            conn.execute(
                "UPDATE auto_judge_decisions "
                "SET analyst_overrode=1, analyst_override_action=?, "
                "    analyst_override_at=?, analyst_id=? "
                "WHERE rowid=(SELECT rowid FROM auto_judge_decisions "
                "             WHERE item_id=? AND applied=1 "
                "             ORDER BY ts DESC LIMIT 1)",
                (override_action, _time.time(), analyst_id, item_id),
            )

    def auto_judge_decisions_recent(self, hours: int = 168) -> list[dict]:
        """Return decisions from the last `hours` for ECE calibration.
        Default 168h = 1 week.
        """
        import time as _time
        cutoff = _time.time() - hours * 3600
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT id, ts, item_id, action_proposed, confidence, reason, "
            "layer1_corroborators, layer1_satisfied, applied, applied_at, "
            "analyst_overrode, analyst_override_action, analyst_override_at, "
            "analyst_id FROM auto_judge_decisions WHERE ts >= ? "
            "ORDER BY ts DESC",
            (cutoff,),
        ).fetchall()
        return [
            {"id": r[0], "ts": r[1], "item_id": r[2], "action_proposed": r[3],
             "confidence": r[4], "reason": r[5], "layer1_corroborators": r[6],
             "layer1_satisfied": bool(r[7]), "applied": bool(r[8]),
             "applied_at": r[9], "analyst_overrode": bool(r[10]),
             "analyst_override_action": r[11], "analyst_override_at": r[12],
             "analyst_id": r[13]}
            for r in rows
        ]

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
        # Lifecycle summary — counts intel items in the same window by
        # eventual status × confirmer kind. Distinguishes auto-judge
        # background applies from ingest-time auto-confirms and analyst
        # actions, so the Diagnostics panel can show what actually
        # happened to items after submission (which the per-caller
        # 'auto_confirmed' verdict column does NOT capture for items
        # that were initially pending and later auto-judged).
        lc_row = conn.execute(
            "SELECT "
            "  SUM(CASE WHEN status='auto_confirmed' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status='confirmed' AND confirmed_by LIKE 'auto:%' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status='confirmed' AND (confirmed_by NOT LIKE 'auto:%' OR confirmed_by IS NULL) THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status='review_needed' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status='rejected' AND confirmed_by LIKE 'auto:%' THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status='rejected' AND (confirmed_by NOT LIKE 'auto:%' OR confirmed_by IS NULL) THEN 1 ELSE 0 END), "
            "  SUM(CASE WHEN status='overridden' THEN 1 ELSE 0 END) "
            "FROM llm_intel WHERE ts >= ?",
            (cutoff,),
        ).fetchone()
        lifecycle = {
            "ingest_auto_confirmed":  int(lc_row[0] or 0),
            "auto_judge_confirmed":   int(lc_row[1] or 0),
            "manual_confirmed":       int(lc_row[2] or 0),
            "pending":                int(lc_row[3] or 0),
            "review_needed":          int(lc_row[4] or 0),
            "auto_judge_rejected":    int(lc_row[5] or 0),
            "manual_rejected":        int(lc_row[6] or 0),
            "overridden":             int(lc_row[7] or 0),
        }
        return {
            "window_hours": hours,
            "total_calls": totals_row[0] or 0,
            "ok_calls": totals_row[1] or 0,
            "per_caller": per_caller,
            "sensor_filter_breakdown": sensor_filter_breakdown,
            "lifecycle": lifecycle,
        }

    def llm_routing_stats(self, hours: int = 24) -> dict:
        """Phase 8 (LLM survey v10) — per-model + per-use_case rollups.

        Conclusion-level recall isn't directly attributable to a single LLM
        model (calls feed deterministic scoring), so this surfaces the
        operational metrics that *are* per-model:

          - call counts, ok / parse_failed / timeout / http_error rates
          - avg confidence (proxy for model self-assessed signal strength)
          - avg duration_ms (latency)
          - auto_confirmed share of verdicts (proxy for analyst-acceptable
            output)
          - shadow agreement: fraction of SHADOW rows where the active
            (legacy) model and the v10 candidate would have been the same
            family (gemma vs mistral vs gpt-oss).

        AP3 reads this to render per-model trust chips.
        """
        import time as _time
        cutoff = _time.time() - hours * 3600
        conn = self._get_conn()

        # Per-model aggregates.
        model_rows = conn.execute(
            "SELECT model, "
            "       COUNT(*) AS total, "
            "       SUM(CASE WHEN outcome='ok' THEN 1 ELSE 0 END) AS ok, "
            "       SUM(CASE WHEN outcome='parse_failed' THEN 1 ELSE 0 END) AS parse_failed, "
            "       SUM(CASE WHEN outcome='timeout' THEN 1 ELSE 0 END) AS timeout_, "
            "       SUM(CASE WHEN outcome='http_error' THEN 1 ELSE 0 END) AS http_error, "
            "       SUM(CASE WHEN outcome='exception' THEN 1 ELSE 0 END) AS exception_, "
            "       SUM(CASE WHEN verdict='auto_confirmed' THEN 1 ELSE 0 END) AS auto_confirmed, "
            "       AVG(CASE WHEN outcome='ok' THEN duration_ms END) AS avg_ms, "
            "       AVG(CASE WHEN outcome='ok' THEN confidence END) AS avg_conf "
            "FROM llm_call_log "
            "WHERE ts>=? AND model<>'' "
            "GROUP BY model ORDER BY total DESC",
            (cutoff,),
        ).fetchall()
        # Map model → use_cases observed (so the chip can show what bucket
        # this model was used for).
        usecase_rows = conn.execute(
            "SELECT model, use_case FROM llm_call_log "
            "WHERE ts>=? AND model<>'' AND use_case IS NOT NULL "
            "GROUP BY model, use_case",
            (cutoff,),
        ).fetchall()
        model_to_usecases: dict[str, list[str]] = {}
        for r in usecase_rows:
            model_to_usecases.setdefault(r[0], []).append(r[1])
        by_model: dict[str, dict] = {}
        for r in model_rows:
            total = r[1] or 0
            ok = r[2] or 0
            by_model[r[0]] = {
                "n": total,
                "ok_rate": round(ok / total, 3) if total else None,
                "parse_failed": r[3] or 0,
                "timeout": r[4] or 0,
                "http_error": r[5] or 0,
                "exception": r[6] or 0,
                "auto_confirmed_rate": (
                    round((r[7] or 0) / ok, 3) if ok else None
                ),
                "avg_duration_ms": round(r[8]) if r[8] else 0,
                "avg_confidence": round(r[9], 3) if r[9] else None,
                "use_cases": sorted(model_to_usecases.get(r[0], [])),
            }

        # Per-use_case aggregates (cuts across models, useful when v10 is
        # SHADOW so v1 model dominates calls but use_case routing is recorded).
        uc_rows = conn.execute(
            "SELECT use_case, "
            "       COUNT(*) AS total, "
            "       SUM(CASE WHEN outcome='ok' THEN 1 ELSE 0 END) AS ok, "
            "       SUM(CASE WHEN verdict='auto_confirmed' THEN 1 ELSE 0 END) AS auto_confirmed, "
            "       AVG(CASE WHEN outcome='ok' THEN confidence END) AS avg_conf "
            "FROM llm_call_log "
            "WHERE ts>=? AND use_case IS NOT NULL "
            "GROUP BY use_case ORDER BY total DESC",
            (cutoff,),
        ).fetchall()
        # For each use_case find the most-used model (effective primary).
        uc_primary_rows = conn.execute(
            "SELECT use_case, model, COUNT(*) AS n FROM llm_call_log "
            "WHERE ts>=? AND use_case IS NOT NULL AND model<>'' "
            "GROUP BY use_case, model",
            (cutoff,),
        ).fetchall()
        uc_primary: dict[str, tuple[str, int]] = {}
        for r in uc_primary_rows:
            uc, model_name, n = r[0], r[1], r[2]
            cur = uc_primary.get(uc)
            if cur is None or n > cur[1]:
                uc_primary[uc] = (model_name, n)
        by_use_case: dict[str, dict] = {}
        for r in uc_rows:
            total = r[1] or 0
            ok = r[2] or 0
            primary = uc_primary.get(r[0], (None, 0))[0]
            by_use_case[r[0]] = {
                "n": total,
                "ok_rate": round(ok / total, 3) if total else None,
                "auto_confirmed_rate": (
                    round((r[3] or 0) / ok, 3) if ok else None
                ),
                "avg_confidence": round(r[4], 3) if r[4] else None,
                "primary_model": primary,
            }

        # Shadow agreement — for rows where shadow_model_choice is set
        # (v10 is in SHADOW for that use_case), how often did the active
        # legacy model belong to the same model-family as the v10 pick?
        shadow_rows = conn.execute(
            "SELECT use_case, model, shadow_model_choice "
            "FROM llm_call_log "
            "WHERE ts>=? AND shadow_model_choice IS NOT NULL "
            "  AND use_case IS NOT NULL",
            (cutoff,),
        ).fetchall()
        shadow_agg: dict[str, dict] = {}
        for r in shadow_rows:
            uc = r[0]
            v1 = (r[1] or "").split(":", 1)[0]
            v2 = (r[2] or "").split(":", 1)[0]
            entry = shadow_agg.setdefault(
                uc, {"n": 0, "same_family": 0, "v2_model": r[2]},
            )
            entry["n"] += 1
            if v1 and v2 and v1 == v2:
                entry["same_family"] += 1
        shadow_diff: dict[str, dict] = {}
        for uc, agg in shadow_agg.items():
            n = agg["n"]
            shadow_diff[uc] = {
                "n": n,
                "same_family_rate": (
                    round(agg["same_family"] / n, 3) if n else None
                ),
                "v2_model": agg["v2_model"],
            }

        return {
            "window_hours": hours,
            "by_model": by_model,
            "by_use_case": by_use_case,
            "shadow_diff": shadow_diff,
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
        import os as _os
        import time as _time
        conn = self._get_conn()
        now = _time.time()
        cutoff_30d = now - 30 * 86400
        cutoff_7d  = now - 7 * 86400
        cutoff_48h = now - 48 * 3600

        # Phase 7.5h (audit Security L4) — revoked_tokens retention must
        # cover the full lifetime of any token that could replay. The
        # blocklist only matters until the token expires on its own; any
        # row older than max(access_ttl, refresh_ttl) is dead weight, but
        # any row younger than that MUST be kept or a revoked-but-not-
        # yet-expired token would be re-accepted. Use the JWT refresh
        # TTL (longest of the two) plus a 1h grace window.
        try:
            _refresh_ttl = int(_os.getenv("JWT_REFRESH_EXPIRES", "86400"))
        except (TypeError, ValueError):
            _refresh_ttl = 86400
        cutoff_revoked = now - max(_refresh_ttl + 3600, 86400)

        deleted: dict[str, int] = {}

        # Commit after each DELETE to release the write lock between tables,
        # preventing long lock holds that would starve other greenlets.
        cur = conn.execute("DELETE FROM sequence_events WHERE ts < ?", (cutoff_30d,))
        deleted["sequence_events"] = cur.rowcount
        conn.commit()

        cur = conn.execute(
            "DELETE FROM revoked_tokens WHERE revoked_at < ?",
            (cutoff_revoked,),
        )
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

        # bg_observer_cycle_log: per-cycle audit (ADR-V2-015 Phase 5).
        # ~1 row per BG_OBSERVER_INTERVAL_SEC (default 300s) = ~288/day.
        # 30d retention = ~8.6k rows is plenty for AP3/AP4 introspection.
        _bgo_days = int(_os.getenv("BG_OBSERVER_CYCLE_LOG_RETENTION_DAYS", "30"))
        cutoff_bgo = now - _bgo_days * 86400
        cur = conn.execute(
            "DELETE FROM bg_observer_cycle_log WHERE started_at < ?",
            (cutoff_bgo,))
        deleted["bg_observer_cycle_log"] = cur.rowcount
        conn.commit()

        # NOTE: scenario_change_log and confirmed_threats are intentionally
        # excluded from automatic cleanup. scenario_change_log is an audit trail
        # (~4 MB/decade); confirmed_threats is human-generated ground truth
        # (~3 KB/year). Both have increasing analytical value over time.

        # ── Phase D retention additions (2026-04-30) ──────────────────────
        # Tables added between Phase 0 and Phase 5 that lacked retention.
        # Defaults are conservative; override via env vars below.

        # conclusions: highest-volume ledger (~1700 rows/day pre-fix). NP6
        # transparency requires audit trail, but unbounded growth threatens
        # query performance. 90d covers two calibration cycles + monthly
        # cross-scenario validation.
        _conc_days = int(_os.getenv("CONCLUSIONS_RETENTION_DAYS", "90"))
        cutoff_conc = now - _conc_days * 86400
        cur = conn.execute(
            "DELETE FROM conclusions WHERE observed_at < ?",
            (cutoff_conc,))
        deleted["conclusions"] = cur.rowcount
        conn.commit()

        # llm_call_log: per-call ledger (~1500 rows/day). 30d sufficient
        # for the LLM Feature Hub audit + caller-level α/β classification
        # (which uses last 7d). NP6 audit retained for 30d.
        _lcl_days = int(_os.getenv("LLM_CALL_LOG_RETENTION_DAYS", "30"))
        cutoff_lcl = now - _lcl_days * 86400
        cur = conn.execute(
            "DELETE FROM llm_call_log WHERE ts < ?",
            (cutoff_lcl,))
        deleted["llm_call_log"] = cur.rowcount
        conn.commit()

        # analyst_feedback: ground-truth labels (FALSE_NEGATIVE /
        # TRUE_POSITIVE / FALSE_POSITIVE). Used by recall calibration over
        # 30d windows; 180d gives 6 months of forensic context.
        _af_days = int(_os.getenv("ANALYST_FEEDBACK_RETENTION_DAYS", "180"))
        cutoff_af = now - _af_days * 86400
        cur = conn.execute(
            "DELETE FROM analyst_feedback WHERE observed_at < ?",
            (cutoff_af,))
        deleted["analyst_feedback"] = cur.rowcount
        conn.commit()

        # inconclusive_continuity_log: tracks how long a (scenario, type)
        # has been stuck at insufficient_data. NP5+8 governance metric.
        # 60d covers two months of continuity context.
        _icl_days = int(_os.getenv("INCONCLUSIVE_LOG_RETENTION_DAYS", "60"))
        cutoff_icl = now - _icl_days * 86400
        cur = conn.execute(
            "DELETE FROM inconclusive_continuity_log WHERE observed_at < ?",
            (cutoff_icl,))
        deleted["inconclusive_continuity_log"] = cur.rowcount
        conn.commit()

        # decisions (Decision Layer, migration v34): superseded rows lose
        # operational meaning after the next decision overwrites them. We
        # keep current decisions indefinitely; superseded ones for 90d for
        # forensic timeline (AP4 Decision Trail).
        _dec_days = int(_os.getenv("DECISIONS_SUPERSEDED_RETENTION_DAYS", "90"))
        cutoff_dec = now - _dec_days * 86400
        cur = conn.execute(
            "DELETE FROM decisions WHERE superseded_by IS NOT NULL "
            "AND decided_at < ?",
            (cutoff_dec,))
        deleted["decisions_superseded"] = cur.rowcount
        conn.commit()

        # legacy_access_log: v1 sunset telemetry. 90d covers post-sunset
        # observation period; older rows have no operational value.
        _lal_days = int(_os.getenv("LEGACY_ACCESS_LOG_RETENTION_DAYS", "90"))
        cutoff_lal = now - _lal_days * 86400
        cur = conn.execute(
            "DELETE FROM legacy_access_log WHERE last_seen < ?",
            (cutoff_lal,))
        deleted["legacy_access_log"] = cur.rowcount
        conn.commit()

        # Phase 1 fix (2026-04-30 PM, problem 48): see
        # _revive_expired_snoozed_proposals() for details. Extracted
        # so unit tests can target the sweep without exercising every
        # other DELETE in this method.
        deleted["proposals_snooze_revived"] = (
            self._revive_expired_snoozed_proposals(now=now)
        )

        return deleted

    def _revive_expired_snoozed_proposals(self, *, now: float = None) -> int:
        """Phase 1 fix (problem 48): scenario_proposals rows in
        'snoozed_30d' state must auto-revive to 'pending' after
        PROPOSAL_SNOOZE_DAYS days. Pre-fix the state had no sweep, so
        analyst's "Defer 30 days" was effectively "Defer forever".

        Returns the number of revived rows.
        """
        import os as _os
        import time as _time
        if now is None:
            now = _time.time()
        snooze_days = int(_os.getenv("PROPOSAL_SNOOZE_DAYS", "30"))
        cutoff = now - snooze_days * 86400
        conn = self._get_conn()
        with conn.writing():
            cur = conn.execute(
                "UPDATE scenario_proposals "
                "SET state='pending', state_changed_at=?, "
                "    state_changed_by='auto:snooze_expired' "
                "WHERE state='snoozed_30d' AND state_changed_at < ?",
                (now, cutoff),
            )
            return cur.rowcount

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
        """Return {status: count} for all intel items using GROUP BY.

        Plus extra synthetic keys that split 'confirmed' by author kind:
            confirmed_auto    — confirmed_by starts with 'auto:'
                                (auto-judge background apply or other
                                automated marker)
            confirmed_manual  — confirmed_by is a human (not auto:* and
                                not None)
        These let the UI report "AUTO" and "MANUAL" tallies without
        losing back-compat for the legacy 'auto_confirmed' status.
        """
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) FROM llm_intel GROUP BY status"
        ).fetchall()
        out = {row[0]: row[1] for row in rows}
        # Split status='confirmed' into auto vs manual based on confirmed_by.
        rows2 = conn.execute(
            "SELECT CASE "
            "  WHEN confirmed_by LIKE 'auto:%' THEN 'confirmed_auto' "
            "  WHEN confirmed_by IS NULL OR confirmed_by='' THEN 'confirmed_unknown' "
            "  ELSE 'confirmed_manual' END AS kind, COUNT(*) "
            "FROM llm_intel WHERE status='confirmed' GROUP BY kind"
        ).fetchall()
        for kind, n in rows2:
            out[kind] = int(n or 0)
        return out

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
        # ADR-V2-006 A-2: dual-write `country` (single-string mirror of legacy
        # `theater`) so the UI can read `item.country ?? item.theater`. The
        # multi-country list lives in `countries` (Phase 3); `country` is the
        # rename pair for the legacy scalar field.
        return {
            "id": r[0], "source_type": r[1], "source_id": r[2],
            "theater": r[3], "country": r[3], "ts": r[4], "status": r[5],
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

    # Phase 5 (audit / DB H4) — explicit per-column SQL fragments. Replaces
    # the previous f"{k}=?" interpolation. The runtime allowlist guard is
    # still useful as a defence-in-depth check for unknown keys, but the
    # SQL itself no longer contains any caller-supplied identifier text,
    # so a future regression that drops the guard cannot create an
    # injection surface.
    _USER_SETTINGS_COL_SQL: dict[str, str] = {
        "focused_scenario": "focused_scenario = ?",
        "muted":            "muted = ?",
        "lang":             "lang = ?",
        "updated_at":       "updated_at = ?",
    }

    def user_settings_update(self, user_id: int, updates: dict):
        bad = set(updates.keys()) - self._USER_SETTINGS_COLS
        if bad:
            raise ValueError(f"Disallowed user_settings columns: {bad}")
        if not updates:
            return
        # Build the SET clause from the static SQL map keyed by allowlist
        # membership; iterate in dict-insertion order so the parameter
        # tuple lines up with the fragments.
        set_fragments = [self._USER_SETTINGS_COL_SQL[k] for k in updates]
        set_clause = ", ".join(set_fragments)
        conn = self._get_conn()
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

# Hydrate Safe Rename Pattern SR4 telemetry from disk so counters survive
# restarts. Best-effort: if migration v23 has not yet run, the call is a no-op
# and will succeed on the next module import (after migrations complete).
try:
    from radar import legacy_telemetry as _lt
    _lt.hydrate_from_db(db)
except Exception as _e:
    log.warning("legacy_telemetry hydrate skipped: %s", _e)
