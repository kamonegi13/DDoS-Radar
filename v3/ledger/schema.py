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

from v3.ledger.migrations import LATEST_VERSION, MIGRATIONS, Migration

SCHEMA_VERSION = 7

# ADR-V3-005 / P1 §5: the signal horizon is derived from the parity
# requirement (30-day replay window x 2), not chosen for convenience.
SIGNAL_RETENTION_DAYS = 60
CONCLUSION_RETENTION_DAYS = 365
# WP-2.5 §1-6: raw bodies are opt-in and short-lived. Keeping 60 days of
# every body for 34 adapters is a capacity decision outside S3's estimate
# and nobody has approved it; `body_sha256` proves identity without it.
RAW_BODY_RETENTION_DAYS = 7
# WP-4.1b ruling 2: the per-entity series horizon. Decided by the longest
# lookback any consumer actually has — `NARRATIVE_BASELINE_DAYS` (30,
# `radar/config.py:360`), the narrative/telegram frequency baselines.
# Everything else reading this table looks back less (check_host keeps 12
# samples and evicts a URL after 24h of no poll, `checkhost.py:143,180-185`;
# `ais_maritime` keeps one snapshot per MMSI with a 24h TTL,
# `ais_maritime.py:143-152`), and those tighter bounds are enforced on the
# write as counts, the way production enforces them.
ENTITY_SERIES_RETENTION_DAYS = 30


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
        rationale="P1 §5: baselines are permanent AS FAR AS THE PRUNE JOB "
                  "is concerned — three of them cannot be backfilled at "
                  "all, so age is not a reason to discard one. The "
                  "hour-of-day series carry their own window on the WRITE "
                  "side instead (`record_bucket_sample`, transcribing "
                  "`hod_record`'s newest-N-buckets cap), because that is "
                  "where production's window is; a second, time-based "
                  "window here would silently be the narrower of the two."),
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
    # ── schema v4 (WP-4.1b ruling 2, L1) ────────────────────────────────
    RetentionPolicy(
        table="entity_observation", time_column="observed_at",
        retention_days=ENTITY_SERIES_RETENTION_DAYS,
        rationale="WP-4.1b ruling 2: per-entity series (URL latency, MMSI "
                  "position, keyword frequency). Bound taken from the "
                  "longest consumer lookback that exists — the 30-day "
                  "narrative frequency window — rather than chosen; the "
                  "tighter per-series counts are enforced on the write, "
                  "as production enforces them."),
    RetentionPolicy(
        table="entity_marker", time_column=None, retention_days=None,
        rationale="WP-4.1b ruling 2: first-seen and set membership. "
                  "PERMANENT because `first_seen` is what ends a warm-up "
                  "(`ct_log.py:273-275`): expiring it restarts the warm-up "
                  "and re-silences a detection that had already graduated, "
                  "which is an insensitive difference (C-02/C-03). A "
                  "first-seen also cannot be backfilled — the same reason "
                  "baseline_stat is permanent. Production has never pruned "
                  "either of its two equivalents."),
    # ── schema v5 (WP-4.1c, L6 command surface) ─────────────────────────
    RetentionPolicy(
        table="command_record", time_column=None, retention_days=None,
        rationale="WP-4.1c: the command log IS the state it records — the "
                  "effective focus, label, override or ground-truth entry is "
                  "the fold of these rows, not a copy kept elsewhere. So "
                  "pruning a row would silently REVERT the change it "
                  "describes, which is the failure this table exists to make "
                  "impossible (G-15: an audit row that records a change "
                  "nothing reads). Permanent is also what AP4 means by a "
                  "decision trail: a trail with a horizon cannot answer "
                  "'what did the tool believe when this was decided'."),
    # ── schema v6 (WP-3.3, L4 storage) ──────────────────────────────────
    RetentionPolicy(
        table="calibration_label", time_column=None, retention_days=None,
        rationale="WP-3.3: a label is the EVIDENCE a recall number was "
                  "computed from. Pruning one silently changes a published "
                  "measurement's denominator, and the three calibration "
                  "disasters were all discovered by re-reading old labels — "
                  "a horizon here would have hidden every one of them. "
                  "Growth is bounded by analyst effort, not by tick rate."),
    RetentionPolicy(
        table="calibration_proposal", time_column=None, retention_days=None,
        rationale="WP-3.3: the proposal is the subject of its adjudication "
                  "commands, which are permanent (command_record). A pruned "
                  "proposal would leave an 'applied' decision with nothing "
                  "it applied to — the mirror of the dangling audit row "
                  "G-15 describes."),
    # ── schema v7 (WP-4.1f, S8 attention ledger) ────────────────────────
    RetentionPolicy(
        table="attention_rank", time_column="computed_at",
        retention_days=CONCLUSION_RETENTION_DAYS,
        rationale="WP-4.1f / P5 O-8: the ranking an analyst was shown, "
                  "with the components that produced it. G-03 was that this "
                  "rank existed ONLY in the browser, so AP4's 'past "
                  "automated judgments can be audited' had a hole exactly "
                  "where AP1 sits. Follows the CONCLUSION horizon because "
                  "the ranked subject IS a conclusion: a rank outliving its "
                  "subject points at nothing, and one expiring before it "
                  "would leave an ack whose target cannot be explained."),
)

PERSISTED_TABLES: tuple[str, ...] = (
    "signal_observation", "tl_observation", "conclusion", "baseline_stat",
    "schema_meta", "fetch_schedule", "fetch_log", "llm_call", "fetch_body",
    "entity_observation", "entity_marker", "command_record",
    "calibration_label", "calibration_proposal", "attention_rank",
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


# ── migrations ─────────────────────────────────────────────────────────
#
# The list itself lives in `v3/ledger/migrations.py` (the 800-line house
# limit). Re-exported here because `LedgerStore` reads
# `schema_module.MIGRATIONS`, and moving that name would have been a
# silent change to what the store applies at open.

if MIGRATIONS and LATEST_VERSION != SCHEMA_VERSION:
    raise RuntimeError(
        f"SCHEMA_VERSION is {SCHEMA_VERSION} but the last migration is "
        f"{LATEST_VERSION}: a store would report a version it had "
        f"not actually reached")

__all__ = ["SCHEMA_SQL", "SCHEMA_VERSION", "RETENTION_POLICIES",
           "RetentionPolicy", "PERSISTED_TABLES", "SIGNAL_RETENTION_DAYS",
           "CONCLUSION_RETENTION_DAYS", "RAW_BODY_RETENTION_DAYS",
           "ENTITY_SERIES_RETENTION_DAYS", "Migration", "MIGRATIONS"]
