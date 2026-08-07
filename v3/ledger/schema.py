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

SCHEMA_VERSION = 1

# ADR-V3-005 / P1 §5: the signal horizon is derived from the parity
# requirement (30-day replay window x 2), not chosen for convenience.
SIGNAL_RETENTION_DAYS = 60
CONCLUSION_RETENTION_DAYS = 365


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
)

PERSISTED_TABLES: tuple[str, ...] = (
    "signal_observation", "tl_observation", "conclusion", "baseline_stat",
    "schema_meta",
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

__all__ = ["SCHEMA_SQL", "SCHEMA_VERSION", "RETENTION_POLICIES",
           "RetentionPolicy", "PERSISTED_TABLES", "SIGNAL_RETENTION_DAYS",
           "CONCLUSION_RETENTION_DAYS"]
