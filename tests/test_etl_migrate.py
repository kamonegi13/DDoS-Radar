"""WP-2.3 — migration ETL from the v1 store into the v3 ledger.

The ETL is where v1's stringly-typed rows meet records.py's validation,
so it is also where every piece of dirty data in five years of production
arrives at once. S3's rules are explicit about the shapes to expect
(`theater` vocabulary, text booleans, JSON payloads carrying the old key)
and about the discipline: a row that cannot be migrated is never dropped
silently — it goes to a quarantine report with its identity and reason
(S5-VERIF-006's rule applied to migration).

The source is opened read-only. S3-DATA-023 makes that a MUST for a
reason: the production database lives in a docker volume with WAL, and a
writing connection from outside the container corrupts it.
"""
import json
import sqlite3

import pytest

from v3.etl import ETLReport, migrate
from v3.etl.mapping import MIGRATABLE, NOT_YET_MIGRATABLE
from v3.ledger import LedgerStore

NOW = 1_786_000_000.0
DAY = 86400.0

# Minimal v1 schema — only the tables the ETL touches, lifted from S3 §2.2.
V1_SCHEMA = """
CREATE TABLE conclusions (
  id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, conclusion_type TEXT NOT NULL,
  state TEXT, confidence REAL NOT NULL, observed_at REAL NOT NULL,
  formula_ref TEXT NOT NULL, threshold_ref TEXT NOT NULL,
  source_urls TEXT NOT NULL, llm_prompt_sha256 TEXT,
  calibration_status TEXT NOT NULL, conclusion_unavailable_reason TEXT,
  metadata TEXT NOT NULL );
CREATE TABLE scenario_tl_observation (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scenario_id TEXT NOT NULL,
  observed_at REAL NOT NULL, score REAL NOT NULL, tl INTEGER,
  cyber REAL NOT NULL DEFAULT 0, physical REAL NOT NULL DEFAULT 0,
  info REAL NOT NULL DEFAULT 0, convergence_bonus REAL NOT NULL DEFAULT 0,
  scoring_mode TEXT NOT NULL DEFAULT 'full',
  active_countries TEXT NOT NULL DEFAULT '[]' );
CREATE TABLE hod_baseline (
  theater TEXT NOT NULL, hour_bucket INTEGER NOT NULL,
  avg_spike REAL NOT NULL, PRIMARY KEY (theater, hour_bucket) );
CREATE TABLE checkhost_hod (
  theater TEXT NOT NULL, hour_bucket INTEGER NOT NULL,
  success_rate REAL NOT NULL, PRIMARY KEY (theater, hour_bucket) );
CREATE TABLE bgp_hod (
  theater TEXT NOT NULL, hour_bucket INTEGER NOT NULL,
  prefix_count REAL NOT NULL, PRIMARY KEY (theater, hour_bucket) );
CREATE TABLE gdelt_dow (
  theater TEXT NOT NULL, day_bucket INTEGER NOT NULL, weekday INTEGER NOT NULL,
  tone REAL NOT NULL, PRIMARY KEY (theater, day_bucket) );
CREATE TABLE analyst_feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT, conclusion_id TEXT NOT NULL,
  label TEXT NOT NULL, observed_outcome_url TEXT, analyst_id TEXT NOT NULL,
  observed_at REAL NOT NULL, notes TEXT );
CREATE TABLE llm_prompts (
  prompt_sha256 TEXT PRIMARY KEY, prompt_text TEXT NOT NULL, model TEXT NOT NULL,
  temperature REAL, prompt_version TEXT, first_seen_at REAL NOT NULL,
  last_seen_at REAL NOT NULL, use_count INTEGER NOT NULL DEFAULT 1 );
"""


@pytest.fixture
def v1(tmp_path):
    """A miniature v1 database."""
    path = tmp_path / "v1.db"
    connection = sqlite3.connect(str(path))
    connection.executescript(V1_SCHEMA)
    connection.commit()
    connection.close()
    return str(path)


@pytest.fixture
def target(tmp_path):
    store = LedgerStore(str(tmp_path / "v3.db"))
    yield store
    store.close()


def _write(v1_path, sql, rows):
    connection = sqlite3.connect(v1_path)
    connection.executemany(sql, rows)
    connection.commit()
    connection.close()


def _conclusion_rows(count=3, start=NOW):
    return [(f"c{i}", "taiwan", "threat_level", "ACTIVE", 0.9,
             start + i, "S1-X", "T1", '["https://example.test"]',
             None, "calibrated", None, "{}") for i in range(count)]


def _seed_conclusions(v1_path, rows=None):
    _write(v1_path,
           "INSERT INTO conclusions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
           rows if rows is not None else _conclusion_rows())


def _seed_tl(v1_path, series=(5, 4, 3)):
    _write(v1_path,
           "INSERT INTO scenario_tl_observation "
           "(scenario_id, observed_at, score, tl, cyber, physical, info, "
           " convergence_bonus, scoring_mode, active_countries) "
           "VALUES (?,?,?,?,?,?,?,?,?,?)",
           [("taiwan", NOW + i, float(i), tl, 0, 0, 0, 0, "full", "[]")
            for i, tl in enumerate(series)])


class TestSourceIsReadOnly:
    """S3-DATA-023: the source is opened read-only, always."""

    def test_the_source_connection_refuses_writes(self, v1):
        from v3.etl.source import V1Source
        source = V1Source(v1)
        try:
            with pytest.raises(sqlite3.OperationalError):
                source.connection().execute("DELETE FROM conclusions")
        finally:
            source.close()

    def test_migration_leaves_the_source_byte_identical(self, v1, target):
        import hashlib
        _seed_conclusions(v1)
        before = hashlib.sha256(open(v1, "rb").read()).hexdigest()
        migrate(v1, target)
        assert hashlib.sha256(open(v1, "rb").read()).hexdigest() == before

    def test_an_awkward_source_path_still_opens(self, tmp_path, target):
        directory = tmp_path / "with#hash"
        directory.mkdir()
        path = str(directory / "v1.db")
        connection = sqlite3.connect(path)
        connection.executescript(V1_SCHEMA)
        connection.commit()
        connection.close()
        _seed_conclusions(path)
        report = migrate(path, target)
        assert report.migrated["conclusions"] == 3

    def test_a_missing_source_fails_loudly(self, tmp_path, target):
        with pytest.raises(Exception):
            migrate(str(tmp_path / "absent.db"), target)


class TestConclusionMigration:
    def test_rows_are_copied(self, v1, target):
        _seed_conclusions(v1)
        report = migrate(v1, target)
        assert report.migrated["conclusions"] == 3
        assert target.count_conclusions() == 3

    def test_fields_survive(self, v1, target):
        _seed_conclusions(v1)
        migrate(v1, target)
        row = target.latest_conclusion_at(NOW + 10, scenario_id="taiwan",
                                          conclusion_type="threat_level")
        assert row["confidence"] == 0.9
        assert row["formula_ref"] == "S1-X"
        assert "example.test" in row["source_urls"]

    def test_chunked_copy_handles_more_than_one_chunk(self, v1, target):
        _seed_conclusions(v1, _conclusion_rows(count=250))
        report = migrate(v1, target, chunk_size=100)
        assert report.migrated["conclusions"] == 250
        assert target.count_conclusions() == 250


class TestTlMigration:
    def test_rows_are_copied_with_kernel_types(self, v1, target):
        _seed_tl(v1)
        report = migrate(v1, target)
        assert report.migrated["scenario_tl_observation"] == 3
        row = target.latest_tl_at(NOW + 10, scenario_id="taiwan")
        assert row["threat_level"].value == 3

    def test_a_null_tl_survives_as_the_null_zone(self, v1, target):
        _seed_tl(v1, series=(5, None))
        migrate(v1, target)
        assert target.latest_tl_at(NOW + 10,
                                   scenario_id="taiwan")["threat_level"] is None

    def test_an_out_of_range_tl_is_quarantined_not_dropped(self, v1, target):
        _seed_tl(v1, series=(5, 9))
        report = migrate(v1, target)
        assert target.count_tl() == 1
        assert len(report.quarantined) == 1
        entry = report.quarantined[0]
        assert entry["table"] == "scenario_tl_observation"
        assert "9" in entry["reason"] or "1..5" in entry["reason"]
        assert entry["identity"]


class TestBaselineMigration:
    """S3-DATA-011: these cannot be backfilled — losing them costs weeks."""

    def test_theater_becomes_country_without_value_change(self, v1, target):
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)",
               [("TW", 3, 1.5), ("UA", 4, 2.5)])
        report = migrate(v1, target)
        assert report.migrated["hod_baseline"] == 2
        stat = target.read_baseline("hod", sensor="hod_baseline",
                                    country="TW", bucket=3)
        assert stat["mean"] == 1.5

    def test_all_four_baseline_tables_migrate(self, v1, target):
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)", [("TW", 1, 1.0)])
        _write(v1, "INSERT INTO checkhost_hod VALUES (?,?,?)",
               [("TW", 1, 0.99)])
        _write(v1, "INSERT INTO bgp_hod VALUES (?,?,?)", [("TW", 1, 500.0)])
        _write(v1, "INSERT INTO gdelt_dow VALUES (?,?,?,?)",
               [("TW", 20000, 3, -2.5)])
        report = migrate(v1, target)
        for table in ("hod_baseline", "checkhost_hod", "bgp_hod", "gdelt_dow"):
            assert report.migrated[table] == 1, table

    def test_the_unknown_sample_count_is_recorded_as_zero(self, v1, target):
        # v1 stored only the aggregate; the moment count never existed, and
        # inventing 1 would claim a sample size the source never had.
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)", [("TW", 3, 1.5)])
        migrate(v1, target)
        stat = target.read_baseline("hod", sensor="hod_baseline",
                                    country="TW", bucket=3)
        assert stat["sample_count"] == 0


class TestDirtyData:
    """S3's named hazards, each arriving as a real v1 row."""

    def test_a_nan_cannot_even_reach_the_etl(self, v1):
        # Finding, pinned: SQLite converts NaN to NULL on insert, and every
        # numeric column S3 declares here is NOT NULL. So the dirty-data
        # hazard for these columns is NULL, never NaN — the ETL's guard is
        # the record validation, and this is why it never fires on NaN.
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:4] + (float("nan"),) + rows[0][5:]
        with pytest.raises(sqlite3.IntegrityError):
            _seed_conclusions(v1, rows)

    def test_malformed_json_metadata_is_quarantined(self, v1, target):
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:12] + ("{not json",)
        _seed_conclusions(v1, rows)
        report = migrate(v1, target)
        assert target.count_conclusions() == 0
        assert report.quarantined[0]["reason"]

    def test_a_non_positive_timestamp_is_quarantined(self, v1, target):
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:5] + (0.0,) + rows[0][6:]
        _seed_conclusions(v1, rows)
        report = migrate(v1, target)
        assert target.count_conclusions() == 0
        assert len(report.quarantined) == 1

    def test_a_theater_key_in_json_payload_fails_the_migration(self, v1,
                                                               target):
        # S3-DATA-022 (追加): a surviving "theater" key inside a JSON column
        # must fail the ETL, not pass silently.
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:12] + ('{"theater": "TW"}',)
        _seed_conclusions(v1, rows)
        report = migrate(v1, target)
        assert report.quarantined
        assert any("theater" in entry["reason"]
                   for entry in report.quarantined)

    def test_an_empty_identifier_is_quarantined(self, v1, target):
        rows = _conclusion_rows(count=1)
        rows[0] = (rows[0][0], "", *rows[0][2:])
        _seed_conclusions(v1, rows)
        report = migrate(v1, target)
        assert target.count_conclusions() == 0
        assert len(report.quarantined) == 1

    def test_good_rows_still_migrate_alongside_bad_ones(self, v1, target):
        rows = _conclusion_rows(count=3)
        rows[1] = rows[1][:12] + ("{not json",)
        _seed_conclusions(v1, rows)
        report = migrate(v1, target)
        assert target.count_conclusions() == 2
        assert len(report.quarantined) == 1

    def test_quarantine_entries_carry_row_identity(self, v1, target):
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:12] + ("{not json",)
        _seed_conclusions(v1, rows)
        report = migrate(v1, target)
        assert report.quarantined[0]["identity"] == {"id": "c0"}

    def test_the_report_is_json_serializable(self, v1, target):
        import json
        _seed_conclusions(v1)
        json.dumps(migrate(v1, target).as_dict())


class TestIdempotenceAndResume:
    """S3-DATA-030 prescribes wipe-then-copy as the norm; both that and a
    mid-table resume must converge to the same target state."""

    def test_a_second_run_converges_on_the_same_state(self, v1, target):
        _seed_conclusions(v1)
        _seed_tl(v1)
        migrate(v1, target, wipe=False)
        second = migrate(v1, target, wipe=False)
        # Convergence is about the TARGET STATE, not about the counters: a
        # resumed run legitimately copies nothing because the checkpoint
        # says everything is already there.
        assert target.count_conclusions() == 3
        assert target.count_tl() == 3
        assert second.migrated["conclusions"] == 0

    def test_a_wiped_rerun_reproduces_the_same_state(self, v1, target):
        _seed_conclusions(v1)
        _seed_tl(v1)
        first = migrate(v1, target)
        again = migrate(v1, target, wipe=True)
        assert again.migrated == first.migrated
        assert target.count_conclusions() == 3

    def test_a_resume_after_a_partial_run_converges(self, v1, target):
        _seed_conclusions(v1, _conclusion_rows(count=10))
        migrate(v1, target, limit=4, wipe=False)   # simulated interruption
        assert target.count_conclusions() == 4
        migrate(v1, target, wipe=False)            # resume
        assert target.count_conclusions() == 10

    def test_checkpoints_live_in_the_target_never_the_source(self, v1, target):
        _seed_conclusions(v1)
        migrate(v1, target, wipe=False)
        source = sqlite3.connect(f"file:{v1}?mode=ro", uri=True)
        try:
            tables = {row[0] for row in source.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            source.close()
        assert "schema_meta" not in tables
        assert target.checkpoint("conclusions") is not None

    def test_wipe_mode_empties_the_target_first(self, v1, target):
        _seed_conclusions(v1)
        migrate(v1, target)
        _seed_conclusions(v1, [("extra", "taiwan", "threat_level", None, 0.5,
                                NOW + 99, "f", "t", "[]", None, "c", None,
                                "{}")])
        report = migrate(v1, target, wipe=True)
        assert report.migrated["conclusions"] == 4
        assert target.count_conclusions() == 4


class TestScopeReporting:
    def test_migratable_tables_are_declared(self):
        assert "conclusions" in MIGRATABLE
        assert "scenario_tl_observation" in MIGRATABLE

    def test_not_yet_migratable_tables_carry_a_reason_and_a_wp(self):
        assert NOT_YET_MIGRATABLE
        for table, entry in NOT_YET_MIGRATABLE.items():
            assert entry["reason"], table
            assert entry["target_wp"], table

    def test_the_two_registries_do_not_overlap(self):
        assert set(MIGRATABLE) & set(NOT_YET_MIGRATABLE) == set()

    def test_the_report_lists_what_it_could_not_migrate(self, v1, target):
        report = migrate(v1, target)
        assert "analyst_feedback" in report.not_yet_migratable
        assert report.not_yet_migratable["analyst_feedback"]["target_wp"]

    def test_the_report_is_an_etl_report(self, v1, target):
        assert isinstance(migrate(v1, target), ETLReport)


class TestTieGroupsAreNotLost:
    """A keyset cursor on a NON-UNIQUE column loses rows.

    `observed_at` is shared by every row of a tick, and the baselines'
    bucket by every country. With a bare scalar cursor, a tie group split
    by a chunk boundary drops every row after the split — no exception, no
    quarantine, just fewer rows. The cursor must be the composite
    (order_by, rowid), which is total.
    """

    def _tied_conclusions(self, count, at=NOW):
        return [(f"c{i}", "taiwan", "threat_level", "ACTIVE", 0.9, at,
                 "S1-X", "T1", "[]", None, "calibrated", None, "{}")
                for i in range(count)]

    def test_a_tie_group_split_by_a_chunk_boundary_survives(self, v1, target):
        # 10 rows sharing one observed_at, chunked at 3: the boundary falls
        # inside the tie group.
        _seed_conclusions(v1, self._tied_conclusions(10))
        report = migrate(v1, target, chunk_size=3)
        assert target.count_conclusions() == 10, "rows lost inside a tie group"
        assert report.migrated["conclusions"] == 10

    def test_an_all_ties_table_migrates_completely(self, v1, target):
        _seed_conclusions(v1, self._tied_conclusions(25))
        migrate(v1, target, chunk_size=5)
        assert target.count_conclusions() == 25

    def test_ties_in_the_tl_stream_survive(self, v1, target):
        _write(v1, "INSERT INTO scenario_tl_observation "
                   "(scenario_id, observed_at, score, tl) VALUES (?,?,?,?)",
               [(f"s{i}", NOW, 1.0, 3) for i in range(10)])
        migrate(v1, target, chunk_size=3)
        assert target.count_tl() == 10

    def test_baseline_buckets_sharing_a_value_survive(self, v1, target):
        # Every country shares hour_bucket=1: one tie group of 10.
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)",
               [(f"C{i}", 1, float(i)) for i in range(10)])
        report = migrate(v1, target, chunk_size=3)
        assert report.migrated["hod_baseline"] == 10

    def test_a_resume_inside_a_tie_group_finishes_the_group(self, v1, target):
        _seed_conclusions(v1, self._tied_conclusions(10))
        migrate(v1, target, limit=4, wipe=False)
        assert target.count_conclusions() == 4
        migrate(v1, target, wipe=False)
        assert target.count_conclusions() == 10, \
            "resume skipped the rest of the tie group"

    def test_the_checkpoint_is_a_composite_pair(self, v1, target):
        _seed_conclusions(v1, self._tied_conclusions(4))
        migrate(v1, target, wipe=False)
        checkpoint = target.checkpoint("conclusions")
        assert isinstance(checkpoint, tuple) and len(checkpoint) == 2


class TestGeneratedColumnHandling:
    """S3-DATA-022 warns about the v24 GENERATED VIRTUAL `country` column.

    The stated reason was wrong: a VIRTUAL generated column DOES appear in
    `SELECT *` (only HIDDEN ones are excluded). The real protection is that
    every migrator reads columns by NAME, so an extra column changes
    nothing — pinned here so a future positional rewrite fails.
    """

    def test_a_generated_country_column_does_not_break_migration(self,
                                                                 tmp_path,
                                                                 target):
        path = str(tmp_path / "v24.db")
        connection = sqlite3.connect(path)
        connection.executescript("""
            CREATE TABLE hod_baseline (
              theater TEXT NOT NULL, hour_bucket INTEGER NOT NULL,
              avg_spike REAL NOT NULL,
              country TEXT GENERATED ALWAYS AS (theater) VIRTUAL,
              PRIMARY KEY (theater, hour_bucket) );
        """)
        connection.execute("INSERT INTO hod_baseline (theater, hour_bucket, "
                           "avg_spike) VALUES ('TW', 3, 1.5)")
        connection.commit()
        connection.close()
        report = migrate(path, target)
        assert report.migrated["hod_baseline"] == 1
        assert target.read_baseline("hod", sensor="hod_baseline",
                                    country="TW", bucket=3)["mean"] == 1.5

    def test_the_generated_column_is_visible_in_select_star(self, tmp_path):
        # The empirical fact the old comment got backwards.
        path = str(tmp_path / "v24.db")
        connection = sqlite3.connect(path)
        connection.executescript("""
            CREATE TABLE probe (theater TEXT,
              country TEXT GENERATED ALWAYS AS (theater) VIRTUAL);
        """)
        connection.execute("INSERT INTO probe (theater) VALUES ('TW')")
        columns = [d[0] for d in
                   connection.execute("SELECT * FROM probe").description]
        connection.close()
        assert "country" in columns


class TestBaselineValidation:
    def test_an_empty_country_is_quarantined_like_other_tables(self, v1,
                                                               target):
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)",
               [("", 1, 1.0), ("TW", 2, 2.0)])
        report = migrate(v1, target)
        assert report.migrated["hod_baseline"] == 1
        assert len(report.quarantined) == 1
        assert report.quarantined[0]["table"] == "hod_baseline"


class TestQuarantineIsBounded:
    def test_records_are_written_to_a_side_file(self, v1, target, tmp_path):
        rows = _conclusion_rows(count=3)
        rows[0] = rows[0][:12] + ("{not json",)
        _seed_conclusions(v1, rows)
        side_file = tmp_path / "quarantine.jsonl"
        report = migrate(v1, target, quarantine_path=str(side_file))
        assert side_file.exists()
        lines = [json.loads(line) for line in
                 side_file.read_text(encoding="utf-8").splitlines()]
        assert lines[0]["table"] == "conclusions"
        assert report.quarantined_count == 1

    def test_memory_keeps_only_a_bounded_sample(self, v1, target, monkeypatch):
        # importlib, not `import v3.etl.migrate`: the package re-exports a
        # FUNCTION named migrate, which shadows the submodule attribute.
        import importlib
        migrate_module = importlib.import_module("v3.etl.migrate")
        monkeypatch.setattr(migrate_module, "QUARANTINE_EXAMPLE_LIMIT", 2)
        rows = [r[:12] + ("{not json",) for r in _conclusion_rows(count=10)]
        _seed_conclusions(v1, rows)
        report = migrate(v1, target)
        assert report.quarantined_count == 10
        assert len(report.quarantined) == 2, "in-memory examples must be capped"


class TestRegistryCompleteness:
    """`scenarios` went missing from both registries and nothing noticed.

    It holds the analyst's Layer-2 scenario overrides, so silent loss means
    every scenario reverts to its preset at cutover with no signal. This
    test makes any future drift from S3's canonical list fail loudly.
    """

    def test_the_two_registries_exactly_cover_s3s_thirty_five(self):
        from v3.etl.mapping import S3_MIGRATE_35
        covered = set(MIGRATABLE) | set(NOT_YET_MIGRATABLE)
        assert covered - S3_MIGRATE_35 == set(), "table not in S3's list"
        assert S3_MIGRATE_35 - covered == set(), "S3 table with no accounting"

    def test_the_canonical_list_has_thirty_five_entries(self):
        from v3.etl.mapping import S3_MIGRATE_35
        assert len(S3_MIGRATE_35) == 35

    def test_scenario_tables_are_accounted_for(self):
        assert "scenarios" in NOT_YET_MIGRATABLE
        assert "scenario_reserved_ids" in NOT_YET_MIGRATABLE
        assert "revert" in NOT_YET_MIGRATABLE["scenarios"]["reason"].lower()

    def test_regenerate_only_tables_are_not_migration_backlog(self):
        from v3.etl.mapping import REGENERATE_ONLY, S3_MIGRATE_35
        # S3-DATA-050 says MUST NOT migrate these; listing one as pending
        # would misrepresent the remaining work.
        assert "attention_metric_p95" in REGENERATE_ONLY
        assert "attention_metric_p95" not in NOT_YET_MIGRATABLE
        assert REGENERATE_ONLY & S3_MIGRATE_35 == set()

    def test_regenerate_only_matches_s3s_count(self):
        from v3.etl.mapping import REGENERATE_ONLY
        # 31 listed by S3-DATA-050, minus focus_switch_log which
        # S3-DATA-061 discards outright.
        assert len(REGENERATE_ONLY) == 30
        assert "focus_switch_log" not in REGENERATE_ONLY
