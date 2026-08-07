"""L1 schema: tables, retention registry, and the store's own versioning.

Shapes follow S3-data-migration.md §2.2 so that WP-2.3's ETL fills these
tables directly, with two deliberate departures documented below.

Retention is a **declarative registry**, not a list of hand-written
DELETEs (S3-DATA-040). The current system's twenty inline DELETE
statements are what let a hardcoded 7-day prune sit next to a live config
key for months, silently making the key dead code; a registry makes the
policy for every table readable in one place, and S3-DATA-044 requires
every table to declare one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

SCHEMA_VERSION = 3

# ADR-V3-005 / P1 §5: the signal horizon is derived from the parity
# requirement (30-day replay window x 2), not chosen for convenience.
SIGNAL_RETENTION_DAYS = 60
CONCLUSION_RETENTION_DAYS = 365
# WP-2.5 §1-6: raw bodies are opt-in and short-lived. Keeping 60 days of
# every body for 34 adapters is a capacity decision outside S3's estimate
# and nobody has approved it; `body_sha256` proves identity without it.
RAW_BODY_RETENTION_DAYS = 7


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """One table's retention rule. `retention_days=None` means permanent.

    Table and column names are validated as Python identifiers because the
    prune job interpolates them into SQL (they are registry constants, not
    user input, but "not user input today" is not a property that survives
    refactoring). This validation is what makes the job's `# noqa: S608`
    checkable rather than a promise.
    """

    table: str
    time_column: Optional[str]
    retention_days: Optional[float]
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.table, str) or not self.table.isidentifier():
            raise ValueError(
                f"retention table must be a plain identifier, got "
                f"{self.table!r}: the prune job interpolates it into SQL")
        if self.time_column is not None and (
                not isinstance(self.time_column, str)
                or not self.time_column.isidentifier()):
            raise ValueError(
                f"retention time_column must be a plain identifier, got "
                f"{self.time_column!r}")
        if self.retention_days is not None and self.retention_days <= 0:
            raise ValueError(
                f"retention_days must be positive or None (permanent), "
                f"got {self.retention_days!r}")

    @property
    def is_permanent(self) -> bool:
        return self.retention_days is None


RETENTION_POLICIES: tuple[RetentionPolicy, ...] = (
    RetentionPolicy(
        table="signal_observation", time_column="observed_at",
        retention_days=SIGNAL_RETENTION_DAYS,
        rationale="ADR-V3-005 / S5-VERIF-018: 30-day parity replay window "
                  "x2 so a window can be compared against its predecessor."),
    RetentionPolicy(
        table="tl_observation", time_column="observed_at",
        retention_days=CONCLUSION_RETENTION_DAYS,
        rationale="P6 O-16: the TL stream backs the conclusions-side views "
                  "(trend, chronic, null-zone), so it follows the "
                  "conclusion horizon rather than the signal one."),
    RetentionPolicy(
        table="conclusion", time_column="observed_at",
        retention_days=CONCLUSION_RETENTION_DAYS,
        rationale="ADR-V3-005 / S3-DATA-041: calibration series comparison "
                  "and after-the-fact verification."),
    RetentionPolicy(
        table="baseline_stat", time_column=None, retention_days=None,
        rationale="P1 §5: baselines are permanent (generation-managed). "
                  "Three of them cannot be backfilled at all, so age is "
                  "not a reason to discard one."),
    RetentionPolicy(
        table="schema_meta", time_column=None, retention_days=None,
        rationale="Store metadata."),
    # ── schema v2 (WP-2.5, L0) ──────────────────────────────────────────
    RetentionPolicy(
        table="fetch_log", time_column="requested_at",
        retention_days=SIGNAL_RETENTION_DAYS,
        rationale="WP-2.5 §1-6: every fetch is recorded. Follows the signal "
                  "horizon because a fetch record explains the observation "
                  "it did or did not produce, and the two must stay "
                  "co-resident to be readable together."),
    RetentionPolicy(
        table="llm_call", time_column="called_at",
        retention_days=CONCLUSION_RETENTION_DAYS,
        rationale="S5-VERIF-022: parity must replay recorded LLM responses "
                  "by prompt_sha256 rather than calling a model. The record "
                  "has to outlive the conclusion it justifies, so it follows "
                  "the conclusion horizon."),
    RetentionPolicy(
        table="fetch_body", time_column="recorded_at",
        retention_days=RAW_BODY_RETENTION_DAYS,
        rationale="WP-2.5 §1-6: opt-in raw bodies, short-lived. Identity is "
                  "proved by fetch_log.body_sha256; the body itself is a "
                  "debugging convenience, not evidence."),
    RetentionPolicy(
        table="fetch_schedule", time_column=None, retention_days=None,
        rationale="Current per-adapter state (last run, breaker). Not a "
                  "history — one row per adapter, updated in place."),
)

PERSISTED_TABLES: tuple[str, ...] = (
    "signal_observation", "tl_observation", "conclusion", "baseline_stat",
    "schema_meta", "fetch_schedule", "fetch_log", "llm_call", "fetch_body",
)

# ── DDL ─────────────────────────────────────────────────────────────────
#
# Append-only is enforced by the database itself, not by convention: the
# two triggers below reject UPDATE and DELETE on the observation tables.
# The retention job disables them for the duration of a prune, which is
# the single sanctioned exception (and the only writer that ever deletes).
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- The signal-level input ledger S5-VERIF-018 requires. Column set is that
-- clause's row shape verbatim; `tick_id` is added for idempotence and
-- `recorded_at` separates "when we stored it" from "when it happened".
CREATE TABLE IF NOT EXISTS signal_observation (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    tick_id         TEXT NOT NULL,
    sensor          TEXT NOT NULL,
    signal_source   TEXT NOT NULL,
    domain          TEXT NOT NULL,
    country         TEXT NOT NULL,
    observed_at     REAL NOT NULL,
    recorded_at     REAL NOT NULL,
    raw_score       REAL,
    status          TEXT NOT NULL,
    flags           TEXT NOT NULL DEFAULT '{}',
    confidence      REAL,
    suppressed      INTEGER NOT NULL DEFAULT 0,
    suppress_reason TEXT,
    evidence_url    TEXT,
    payload         TEXT,
    freshness_horizon_sec REAL NOT NULL,
    UNIQUE (tick_id, sensor, signal_source, country)
);
CREATE INDEX IF NOT EXISTS idx_signal_obs_lookup
    ON signal_observation (sensor, country, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_signal_obs_time
    ON signal_observation (observed_at DESC);

-- P6 O-16: ONE unthinned TL stream. Every tick is appended, including
-- repeats and null-zone ticks; trend / chronic / null-zone / history are
-- queries over this table and nothing else.
CREATE TABLE IF NOT EXISTS tl_observation (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tick_id           TEXT NOT NULL,
    scenario_id       TEXT NOT NULL,
    observed_at       REAL NOT NULL,
    tl                INTEGER,          -- NULL = INSUFFICIENT (null-zone)
    score             REAL NOT NULL,
    cyber             REAL NOT NULL DEFAULT 0,
    physical          REAL NOT NULL DEFAULT 0,
    info              REAL NOT NULL DEFAULT 0,
    convergence_bonus REAL NOT NULL DEFAULT 0,
    scoring_mode      TEXT NOT NULL DEFAULT 'full',
    active_countries  TEXT NOT NULL DEFAULT '[]',
    UNIQUE (tick_id, scenario_id)
);
CREATE INDEX IF NOT EXISTS idx_tl_obs_scenario_time
    ON tl_observation (scenario_id, observed_at DESC);

-- S3-DATA-010's conclusions shape. L1 owns storage and retention only;
-- L3 (WP-3.1) owns the semantics.
CREATE TABLE IF NOT EXISTS conclusion (
    id                            TEXT PRIMARY KEY,
    scenario_id                   TEXT NOT NULL,
    conclusion_type               TEXT NOT NULL,
    state                         TEXT,
    confidence                    REAL NOT NULL,
    observed_at                   REAL NOT NULL,
    formula_ref                   TEXT NOT NULL DEFAULT '',
    threshold_ref                 TEXT NOT NULL DEFAULT '',
    source_urls                   TEXT NOT NULL DEFAULT '[]',
    llm_prompt_sha256             TEXT,
    calibration_status            TEXT NOT NULL DEFAULT '',
    conclusion_unavailable_reason TEXT,
    metadata                      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_conclusion_scen_type_time
    ON conclusion (scenario_id, conclusion_type, observed_at DESC);

-- The only table that is updated in place, and only by the explicit
-- baseline job. A-03: these used to live in process memory and vanish on
-- restart, which made every restart a silent baseline reset.
CREATE TABLE IF NOT EXISTS baseline_stat (
    baseline_id  TEXT NOT NULL,
    sensor       TEXT NOT NULL,
    country      TEXT NOT NULL,
    bucket       INTEGER NOT NULL DEFAULT 0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    mean         REAL NOT NULL DEFAULT 0.0,
    m2           REAL NOT NULL DEFAULT 0.0,
    window_days  REAL,
    cadence_sec  REAL,
    updated_at   REAL NOT NULL,
    PRIMARY KEY (baseline_id, sensor, country, bucket)
);

CREATE TRIGGER IF NOT EXISTS signal_observation_no_update
BEFORE UPDATE ON signal_observation
BEGIN
    SELECT RAISE(ABORT,
        'signal_observation is append-only: records are facts, not drafts');
END;

CREATE TRIGGER IF NOT EXISTS signal_observation_no_delete
BEFORE DELETE ON signal_observation
WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'signal_observation rows are removed only by the retention job');
END;

CREATE TRIGGER IF NOT EXISTS tl_observation_no_update
BEFORE UPDATE ON tl_observation
BEGIN
    SELECT RAISE(ABORT, 'tl_observation is append-only (P6 O-16)');
END;

CREATE TRIGGER IF NOT EXISTS tl_observation_no_delete
BEFORE DELETE ON tl_observation
WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'tl_observation rows are removed only by the retention job');
END;

CREATE TRIGGER IF NOT EXISTS conclusion_no_delete
BEFORE DELETE ON conclusion
WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
BEGIN
    SELECT RAISE(ABORT,
        'conclusion rows are removed only by the retention job');
END;
"""


# ── migrations ──────────────────────────────────────────────────────────
#
# The minimal mechanism WP-2.2's completion note promised, implemented by
# the extension that first needed it (ruling 3). Deliberately minimal: a
# numbered list of statements, applied in order, above whatever version
# the store records. No downgrades — a store that has run a newer version
# is not something this list can reason about.
#
# `SCHEMA_SQL` stays the v1 baseline. New tables arrive as migrations even
# though `CREATE TABLE IF NOT EXISTS` would also work on a fresh store,
# because the point of the list is that the UPGRADE path is exercised on
# every run rather than only in the one deployment that happens to be old.


@dataclass(frozen=True)
class Migration:
    """One schema step. `statements` run individually, in order."""

    version: int
    statements: tuple[str, ...]
    rationale: str

    def __post_init__(self) -> None:
        if self.version < 2:
            raise ValueError(
                f"migration versions start at 2 (1 is SCHEMA_SQL's "
                f"baseline), got {self.version}")
        if not self.statements:
            raise ValueError(f"migration {self.version} has no statements")


_MIGRATION_2 = Migration(
    version=2,
    rationale="WP-2.5: L0's three tables. A-09 keeps them here rather than "
              "in a second store owned by the fetch layer.",
    statements=(
        # Per-adapter current state: when it last ran, and its breaker.
        # One row per adapter, updated in place — F-01's repair is that
        # scheduling reads a PERSISTED last_run_at instead of a process
        # counter that resets to zero on restart.
        """
        CREATE TABLE IF NOT EXISTS fetch_schedule (
            adapter_id              TEXT PRIMARY KEY,
            last_run_at             REAL,
            last_outcome            TEXT,
            breaker_state           TEXT NOT NULL DEFAULT 'CLOSED',
            breaker_fail_count      INTEGER NOT NULL DEFAULT 0,
            breaker_opened_at       REAL,
            breaker_recovery_delay_sec REAL NOT NULL DEFAULT 300.0,
            updated_at              REAL NOT NULL
        )
        """,
        # Every fetch, always. `outcome` carries the feed death-cause
        # classification (§1-7) so a dead feed stays visible instead of
        # looking like an absence.
        """
        CREATE TABLE IF NOT EXISTS fetch_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            adapter_id    TEXT NOT NULL,
            requested_at  REAL NOT NULL,
            url_sha256    TEXT NOT NULL,
            http_status   INTEGER,
            latency_ms    REAL,
            outcome       TEXT NOT NULL,
            body_sha256   TEXT,
            breaker_state TEXT NOT NULL DEFAULT 'CLOSED',
            detail        TEXT NOT NULL DEFAULT ''
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_fetch_log_adapter_time "
        "ON fetch_log (adapter_id, requested_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_fetch_log_time "
        "ON fetch_log (requested_at DESC)",
        # S5-VERIF-022's precondition. Every field here is required for
        # replay; a row missing one of them makes its conclusion type
        # non-replayable, which the clause says must then be excluded from
        # parity and the exclusion stated.
        """
        CREATE TABLE IF NOT EXISTS llm_call (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            adapter_id    TEXT NOT NULL,
            called_at     REAL NOT NULL,
            prompt        TEXT NOT NULL,
            prompt_sha256 TEXT NOT NULL,
            response      TEXT NOT NULL,
            model_id      TEXT NOT NULL,
            temperature   REAL NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_llm_call_prompt "
        "ON llm_call (prompt_sha256, called_at DESC)",
        # Opt-in, short-lived. Keyed by content hash so an unchanged body
        # fetched a hundred times is stored once.
        """
        CREATE TABLE IF NOT EXISTS fetch_body (
            body_sha256 TEXT PRIMARY KEY,
            adapter_id  TEXT NOT NULL,
            recorded_at REAL NOT NULL,
            body        BLOB NOT NULL
        )
        """,
        # fetch_log is a record of what happened; a record that can be
        # edited afterwards is not one.
        """
        CREATE TRIGGER IF NOT EXISTS fetch_log_no_update
        BEFORE UPDATE ON fetch_log
        BEGIN
            SELECT RAISE(ABORT, 'fetch_log is append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS llm_call_no_update
        BEFORE UPDATE ON llm_call
        BEGIN
            -- One line: SQLite does not concatenate adjacent string
            -- literals the way Python does.
            SELECT RAISE(ABORT, 'llm_call is append-only (S5-VERIF-022)');
        END
        """,
    ))

_MIGRATION_3 = Migration(
    version=3,
    rationale="WP-2.5 review: the v2 tables were append-only by convention "
              "only. llm_call in particular is S5-VERIF-022's replay "
              "substrate — a deleted row is a conclusion that can never be "
              "reproduced, and nothing stopped a DELETE.",
    statements=(
        # Guarded by the same pruning flag the v1 tables use, so the
        # retention job remains the single sanctioned deleter.
        """
        CREATE TRIGGER IF NOT EXISTS fetch_log_no_delete
        BEFORE DELETE ON fetch_log
        WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
        BEGIN
            SELECT RAISE(ABORT,
                'fetch_log rows are removed only by the retention job');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS llm_call_no_delete
        BEFORE DELETE ON llm_call
        WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
        BEGIN
            SELECT RAISE(ABORT,
                'llm_call rows are removed only by the retention job');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS fetch_body_no_delete
        BEFORE DELETE ON fetch_body
        WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
        BEGIN
            SELECT RAISE(ABORT,
                'fetch_body rows are removed only by the retention job');
        END
        """,
    ))

MIGRATIONS: tuple[Migration, ...] = (_MIGRATION_2, _MIGRATION_3)

if MIGRATIONS and MIGRATIONS[-1].version != SCHEMA_VERSION:
    raise RuntimeError(
        f"SCHEMA_VERSION is {SCHEMA_VERSION} but the last migration is "
        f"{MIGRATIONS[-1].version}: a store would report a version it had "
        f"not actually reached")

__all__ = ["SCHEMA_SQL", "SCHEMA_VERSION", "RETENTION_POLICIES",
           "RetentionPolicy", "PERSISTED_TABLES", "SIGNAL_RETENTION_DAYS",
           "CONCLUSION_RETENTION_DAYS", "RAW_BODY_RETENTION_DAYS",
           "Migration", "MIGRATIONS"]
