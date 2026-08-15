"""L1's schema migrations — the numbered upgrade path, in order.

Split out of `v3/ledger/schema.py` when WP-4.1f's `attention_rank` pushed
that file past the 800-line house limit. The split is along the seam the
module already had: `schema.py` states what the store IS (the v1 baseline
DDL, the retention registry, the version), and this file states how a
store that predates the current version GETS there.

Deliberately minimal, as WP-2.2's completion note promised: a numbered
list of statements applied in order above whatever version the store
records, and no downgrades — a store that has run a newer version is not
something this list can reason about.

New tables arrive as migrations even though `CREATE TABLE IF NOT EXISTS`
would also work on a fresh store, because the point of the list is that
the UPGRADE path is exercised on every run rather than only in the one
deployment that happens to be old.
"""
from __future__ import annotations

from dataclasses import dataclass

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

_MIGRATION_4 = Migration(
    version=4,
    rationale="WP-4.1b ruling 2: state keyed by an entity that is not a "
              "country — a domain, a URL, an MMSI, a keyword. Overloading "
              "baseline_stat's `country` column with those would make the "
              "schema say one thing and hold another.",
    statements=(
        # A per-entity SERIES. Observational, so it gets the same
        # append-only treatment as its siblings.
        """
        CREATE TABLE IF NOT EXISTS entity_observation (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            series      TEXT NOT NULL,
            sensor      TEXT NOT NULL,
            entity      TEXT NOT NULL,
            observed_at REAL NOT NULL,
            recorded_at REAL NOT NULL,
            value       REAL,
            payload     TEXT NOT NULL DEFAULT '{}'
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_entity_obs_series "
        "ON entity_observation (series, sensor, entity, observed_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_entity_obs_time "
        "ON entity_observation (observed_at DESC)",
        """
        CREATE TRIGGER IF NOT EXISTS entity_observation_no_update
        BEFORE UPDATE ON entity_observation
        BEGIN
            SELECT RAISE(ABORT, 'entity_observation is append-only');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS entity_observation_no_delete
        BEFORE DELETE ON entity_observation
        WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
        BEGIN
            SELECT RAISE(ABORT,
                'entity_observation rows are removed only by the retention job');
        END
        """,
        # First-seen and set membership. Updated in place like
        # baseline_stat, so no append-only trigger — but the ONE field
        # whose movement would silently restart a warm-up is nailed down.
        """
        CREATE TABLE IF NOT EXISTS entity_marker (
            series            TEXT NOT NULL,
            sensor            TEXT NOT NULL,
            entity            TEXT NOT NULL,
            member            TEXT NOT NULL DEFAULT '',
            first_seen        REAL NOT NULL,
            last_seen         REAL NOT NULL,
            observation_count INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (series, sensor, entity, member)
        )
        """,
        """
        CREATE TRIGGER IF NOT EXISTS entity_marker_first_seen_immutable
        BEFORE UPDATE ON entity_marker
        WHEN NEW.first_seen <> OLD.first_seen
        BEGIN
            SELECT RAISE(ABORT,
                'entity_marker.first_seen never moves: it is what ends a warm-up');
        END
        """,
    ))

_MIGRATION_5 = Migration(
    version=5,
    rationale="WP-4.1c: the command log. S2-PROP-019 is 'one change, one "
              "audit row'; this table is how that becomes structural rather "
              "than procedural, because the row is not a NOTE ABOUT the "
              "change — the effective state is the fold of these rows, so "
              "there is no change without one.",
    statements=(
        # Append-only, like the observation tables, and for a stronger
        # reason: an UPDATE here would rewrite history that the current
        # state is derived from, so the row and the state would disagree
        # with no way to tell which was edited.
        """
        CREATE TABLE IF NOT EXISTS command_record (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id   TEXT NOT NULL UNIQUE,
            action       TEXT NOT NULL,
            target_kind  TEXT NOT NULL,
            target_id    TEXT NOT NULL,
            actor_id     TEXT NOT NULL,
            actor_role   TEXT NOT NULL,
            issued_at    REAL NOT NULL,
            recorded_at  REAL NOT NULL,
            before_json  TEXT NOT NULL,
            after_json   TEXT NOT NULL,
            reason       TEXT,
            payload      TEXT NOT NULL DEFAULT '{}'
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_command_target "
        "ON command_record (action, target_kind, target_id, issued_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_command_time "
        "ON command_record (issued_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_command_actor "
        "ON command_record (actor_id, issued_at DESC)",
        """
        CREATE TRIGGER IF NOT EXISTS command_record_no_update
        BEFORE UPDATE ON command_record
        BEGIN
            SELECT RAISE(ABORT,
                'command_record is append-only: the current state is the fold of these rows');
        END
        """,
        # No prune-flag escape hatch, unlike entity_observation. The
        # retention registry declares this table permanent, so a DELETE
        # can only be someone reaching around the registry — and the row
        # they would delete is the change itself.
        """
        CREATE TRIGGER IF NOT EXISTS command_record_no_delete
        BEFORE DELETE ON command_record
        BEGIN
            SELECT RAISE(ABORT,
                'a command record is never deleted: deleting it would revert the change it records');
        END
        """,
    ))

_MIGRATION_6 = Migration(
    version=6,
    rationale="WP-3.3: the label ledger and the proposal queue. Both are "
              "storage the calibration layer has needed since WP-3.2 built "
              "its type system: an epoch-stamped label cannot be compared "
              "with another epoch's, and a proposal cannot be adjudicated, "
              "without somewhere to put them. The four provenance columns "
              "are NOT NULL because S5-VERIF-032 makes them the identity of "
              "the label population, and F-16 is what a nullable one costs.",
    statements=(
        # The v3 form of `analyst_feedback`. Append-only: a relabel is a
        # NEW row and the fold takes the latest per (conclusion_id,
        # analyst_id) (S1-CALIB-026). An UPDATE would erase the analyst's
        # earlier judgement, which is the one thing the decision trail is
        # for — and all three calibration disasters were label
        # contamination, so the ability to see what a label USED to say is
        # the forensic record.
        """
        CREATE TABLE IF NOT EXISTS calibration_label (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            label_id             TEXT NOT NULL UNIQUE,
            conclusion_id        TEXT NOT NULL,
            scenario_id          TEXT NOT NULL,
            conclusion_type      TEXT NOT NULL,
            label                TEXT NOT NULL,
            analyst_id           TEXT NOT NULL,
            observed_at          REAL NOT NULL,
            labelled_at          REAL NOT NULL,
            recorded_at          REAL NOT NULL,
            generator_id         TEXT NOT NULL,
            generator_version    TEXT NOT NULL,
            rule_id              TEXT NOT NULL,
            epoch_id             TEXT NOT NULL,
            is_automated         INTEGER NOT NULL DEFAULT 0,
            observed_outcome_url TEXT,
            reason               TEXT,
            CHECK (length(trim(epoch_id)) > 0),
            CHECK (length(trim(generator_id)) > 0),
            CHECK (length(trim(generator_version)) > 0),
            CHECK (length(trim(rule_id)) > 0),
            CHECK (is_automated IN (0, 1))
        )
        """,
        # The cell aggregation reads (epoch, window, scenario, type); the
        # epoch leads because it is the partition key. A query that could
        # scan across epochs cheaply is a query somebody will write.
        "CREATE INDEX IF NOT EXISTS idx_calibration_label_epoch_window "
        "ON calibration_label (epoch_id, observed_at)",
        "CREATE INDEX IF NOT EXISTS idx_calibration_label_subject "
        "ON calibration_label (conclusion_id, analyst_id, labelled_at DESC)",
        """
        CREATE TRIGGER IF NOT EXISTS calibration_label_no_update
        BEFORE UPDATE ON calibration_label
        BEGIN
            SELECT RAISE(ABORT,
                'calibration_label is append-only: a relabel is a new row, and the fold takes the latest per (conclusion_id, analyst_id)');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS calibration_label_no_delete
        BEFORE DELETE ON calibration_label
        BEGIN
            SELECT RAISE(ABORT,
                'a label is never deleted: it is the evidence a recall number was computed from');
        END
        """,
        # The proposal QUEUE. One row per emitted proposal, append-only —
        # the STATE is not a column here, it is the fold of the
        # adjudication commands in `command_record` (WP-4.1c's seam). That
        # is the shape S1-CALIB-041 asks for and production does not have:
        # a refusal leaves no row there, so "why was nothing proposed" is
        # unanswerable. Here the emission and every adjudication are both
        # rows, and neither can exist without the other being visible.
        """
        CREATE TABLE IF NOT EXISTS calibration_proposal (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            proposal_id       TEXT NOT NULL UNIQUE,
            proposal_type     TEXT NOT NULL,
            scenario_id       TEXT NOT NULL,
            target_country    TEXT NOT NULL DEFAULT '',
            proposal_key      TEXT NOT NULL,
            prior_value       REAL,
            proposed_value    REAL,
            direction         TEXT NOT NULL DEFAULT '',
            impact            TEXT NOT NULL,
            sample_n          INTEGER NOT NULL DEFAULT 0,
            emitted_at        REAL NOT NULL,
            recorded_at       REAL NOT NULL,
            epoch_id          TEXT NOT NULL,
            formula_ref       TEXT NOT NULL,
            evidence_json     TEXT NOT NULL DEFAULT '{}',
            payload_json      TEXT NOT NULL DEFAULT '{}',
            CHECK (length(trim(epoch_id)) > 0),
            CHECK (length(trim(impact)) > 0)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_calibration_proposal_queue "
        "ON calibration_proposal (scenario_id, proposal_type, emitted_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_calibration_proposal_time "
        "ON calibration_proposal (emitted_at DESC)",
        """
        CREATE TRIGGER IF NOT EXISTS calibration_proposal_no_update
        BEFORE UPDATE ON calibration_proposal
        BEGIN
            SELECT RAISE(ABORT,
                'calibration_proposal is append-only: a proposal state is the fold of its adjudication commands, not a column edited in place');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS calibration_proposal_no_delete
        BEFORE DELETE ON calibration_proposal
        BEGIN
            SELECT RAISE(ABORT,
                'a proposal is never deleted: dismissing one is an adjudication, and an erased proposal is an adjudication with no subject');
        END
        """,
    ))

_MIGRATION_7 = Migration(
    version=7,
    rationale="WP-4.1f: the S8 attention ledger. P5 O-8 put AP1's ranking in "
              "the backend and required it to land in a ledger; G-03's "
              "finding was that `attention_score` existed only in "
              "`triage_score.js`, so the rank an analyst acted on left no "
              "trace and AP4 could not replay it. One row per ranked item "
              "per snapshot, carrying its three components — the score "
              "without its components is a number nobody can argue with "
              "(NP6).",
    statements=(
        """
        CREATE TABLE IF NOT EXISTS attention_rank (
            id                     INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id            TEXT NOT NULL,
            computed_at            REAL NOT NULL,
            recorded_at            REAL NOT NULL,
            scenario_id            TEXT NOT NULL,
            item_kind              TEXT NOT NULL,
            item_id                TEXT NOT NULL,
            rank_position          INTEGER NOT NULL,
            score                  REAL NOT NULL,
            novelty                REAL NOT NULL,
            confidence_delta       REAL NOT NULL,
            analyst_blindness      REAL NOT NULL,
            formula_ref            TEXT NOT NULL,
            narrative_template_ref TEXT NOT NULL,
            narrative              TEXT NOT NULL,
            components_json        TEXT NOT NULL,
            UNIQUE (snapshot_id, item_kind, item_id),
            CHECK (length(trim(snapshot_id)) > 0),
            CHECK (length(trim(scenario_id)) > 0),
            CHECK (length(trim(item_kind)) > 0),
            CHECK (length(trim(item_id)) > 0),
            CHECK (length(trim(formula_ref)) > 0),
            CHECK (length(trim(narrative_template_ref)) > 0),
            CHECK (rank_position >= 1),
            CHECK (score >= 0.0 AND score <= 1.0),
            CHECK (novelty >= 0.0 AND novelty <= 1.0),
            CHECK (confidence_delta >= 0.0 AND confidence_delta <= 1.0),
            CHECK (analyst_blindness >= 0.0 AND analyst_blindness <= 1.0)
        )
        """,
        # The projection asks two questions and there is one index for
        # each: "the snapshot as of T" and "this scenario's rank history".
        "CREATE INDEX IF NOT EXISTS idx_attention_rank_snapshot "
        "ON attention_rank (computed_at DESC, rank_position)",
        "CREATE INDEX IF NOT EXISTS idx_attention_rank_item "
        "ON attention_rank (item_kind, item_id, computed_at DESC)",
        """
        CREATE TRIGGER IF NOT EXISTS attention_rank_no_update
        BEFORE UPDATE ON attention_rank
        BEGIN
            SELECT RAISE(ABORT,
                'attention_rank is append-only: a rank an analyst was shown cannot be edited after the fact, or the decision trail describes a screen nobody saw');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS attention_rank_no_delete
        BEFORE DELETE ON attention_rank
        WHEN (SELECT value FROM schema_meta WHERE key = 'pruning') IS NULL
        BEGIN
            SELECT RAISE(ABORT,
                'attention_rank rows are removed only by the retention job');
        END
        """,
    ))


_MIGRATION_8 = Migration(
    version=8,
    rationale="WP-0.4 v2 (ADR-V3-012): the FN draft ledger and the S9 run "
              "record. A single-source FALSE_NEGATIVE candidate is not yet "
              "a label — Tier 1 confirms only multi-source convergence, and "
              "the remainder must wait for the LLM second reader or a human "
              "WITHOUT blocking the pipeline. The draft table is where they "
              "wait in the open: every pending row widens the published "
              "recall interval, so an unattended queue degrades the stated "
              "precision instead of silently overstating recall. The run "
              "table is S9's own heartbeat — a persisted last-run instant "
              "(the F-01 lesson: never a process counter) and the AP4 "
              "record of what each cycle did.",
    statements=(
        """
        CREATE TABLE IF NOT EXISTS calibration_fn_draft (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            draft_id             TEXT NOT NULL UNIQUE,
            created_at           REAL NOT NULL,
            scenario_id          TEXT NOT NULL,
            conclusion_type      TEXT NOT NULL,
            conclusion_id        TEXT NOT NULL,
            label                TEXT NOT NULL,
            reason               TEXT NOT NULL,
            proposed_analyst_id  TEXT NOT NULL,
            generator_id         TEXT NOT NULL,
            generator_version    TEXT NOT NULL,
            rule_id              TEXT NOT NULL,
            epoch_id             TEXT NOT NULL,
            observed_at          REAL NOT NULL,
            labelled_at          REAL NOT NULL,
            sources_json         TEXT NOT NULL,
            evidence_url         TEXT,
            CHECK (label = 'FALSE_NEGATIVE'),
            CHECK (length(trim(draft_id)) > 0),
            CHECK (length(trim(scenario_id)) > 0),
            CHECK (length(trim(conclusion_type)) > 0),
            CHECK (length(trim(conclusion_id)) > 0),
            CHECK (length(trim(epoch_id)) > 0),
            CHECK (length(trim(generator_id)) > 0),
            CHECK (length(trim(generator_version)) > 0),
            CHECK (length(trim(rule_id)) > 0)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_calibration_fn_draft_cell "
        "ON calibration_fn_draft (epoch_id, scenario_id, conclusion_type)",
        "CREATE INDEX IF NOT EXISTS idx_calibration_fn_draft_subject "
        "ON calibration_fn_draft (conclusion_id)",
        """
        CREATE TRIGGER IF NOT EXISTS calibration_fn_draft_no_update
        BEFORE UPDATE ON calibration_fn_draft
        BEGIN
            SELECT RAISE(ABORT,
                'calibration_fn_draft is append-only: adjudication is a command fold, never an edit of the candidate');
        END
        """,
        """
        CREATE TRIGGER IF NOT EXISTS calibration_fn_draft_no_delete
        BEFORE DELETE ON calibration_fn_draft
        BEGIN
            SELECT RAISE(ABORT,
                'a draft is never deleted: dropping an unadjudicated FN candidate is how a recall number silently inflates (NP1)');
        END
        """,
        """
        CREATE TABLE IF NOT EXISTS calibration_run (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ran_at       REAL NOT NULL,
            window_start REAL NOT NULL,
            window_end   REAL NOT NULL,
            outcome      TEXT NOT NULL,
            report_json  TEXT NOT NULL,
            CHECK (length(trim(outcome)) > 0),
            CHECK (window_start <= window_end)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_calibration_run_ran_at "
        "ON calibration_run (ran_at DESC)",
        """
        CREATE TRIGGER IF NOT EXISTS calibration_run_no_update
        BEFORE UPDATE ON calibration_run
        BEGIN
            SELECT RAISE(ABORT,
                'calibration_run is append-only: it is the AP4 record of what S9 actually did');
        END
        """,
    ))


MIGRATIONS: tuple[Migration, ...] = (_MIGRATION_2, _MIGRATION_3, _MIGRATION_4,
                                     _MIGRATION_5, _MIGRATION_6, _MIGRATION_7,
                                     _MIGRATION_8)

#: The version a store reaches by applying every migration above.
#: `schema.py` asserts `SCHEMA_VERSION` equals this at import, so a
#: migration added without bumping the version is a failing import rather
#: than a store reporting a version it had not actually reached.
LATEST_VERSION = MIGRATIONS[-1].version

__all__ = ["Migration", "MIGRATIONS", "LATEST_VERSION"]
