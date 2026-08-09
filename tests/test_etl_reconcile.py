"""WP-2.3 — S3's five acceptance criteria as an executable gate.

S3-DATA-025 says one mismatched table aborts cutover; the other four have
the same weight. So the harness must be as honest about what it could NOT
check as about what passed. Three criteria depend on tables whose v3
destination lands in a later WP, and those report BLOCKED with the
blocking table named — never PASS.
"""
import json
import sqlite3

import pytest

from v3.etl import migrate, reconcile
from v3.etl.reconcile import BLOCKED, FAIL, PASS, SAMPLE_SIZE
from v3.ledger import LedgerStore

from tests.test_etl_migrate import (V1_SCHEMA, _conclusion_rows,
                                    _seed_conclusions, _seed_tl, _write)

NOW = 1_786_000_000.0
DAY = 86400.0


def _write_schema(v1_path, statement):
    """Add a table the snapshot has and the registries have not heard of."""
    connection = sqlite3.connect(v1_path)
    connection.execute(statement)
    connection.commit()
    connection.close()


@pytest.fixture
def v1(tmp_path):
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


class TestCriterion1RowCounts:
    def test_a_complete_migration_passes(self, v1, target):
        _seed_conclusions(v1)
        _seed_tl(v1)
        migrate(v1, target)
        report = reconcile(v1, target)
        assert report.criteria["1_row_counts"]["verdict"] == PASS

    def test_a_missing_row_fails(self, v1, target):
        _seed_conclusions(v1, _conclusion_rows(count=5))
        migrate(v1, target, limit=3)
        report = reconcile(v1, target)
        criterion = report.criteria["1_row_counts"]
        assert criterion["verdict"] == FAIL
        assert criterion["mismatches"]["conclusions"] == {"source": 5,
                                                          "target": 3}

    def test_a_quarantined_row_shows_up_as_a_count_mismatch(self, v1, target):
        rows = _conclusion_rows(count=2)
        rows[1] = rows[1][:12] + ("{not json",)
        _seed_conclusions(v1, rows)
        migrate(v1, target)
        assert reconcile(v1, target).criteria["1_row_counts"]["verdict"] == FAIL

    def test_baseline_tables_are_counted(self, v1, target):
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)",
               [("TW", 1, 1.0), ("UA", 2, 2.0)])
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["1_row_counts"]
        assert criterion["tables"]["hod_baseline"] == {"source": 2,
                                                       "target": 2}

    def test_the_not_yet_migratable_list_travels_with_the_verdict(self, v1,
                                                                  target):
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["1_row_counts"]
        assert "analyst_feedback" in criterion["not_yet_migratable"]


class TestCriterion2SampleHashes:
    def test_a_faithful_copy_hashes_equal(self, v1, target):
        _seed_conclusions(v1, _conclusion_rows(count=20))
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["2_sample_hashes"]
        assert criterion["verdict"] == PASS
        assert criterion["hashes"]["conclusions"]["source"] == \
            criterion["hashes"]["conclusions"]["target"]

    def test_the_hash_is_stable_across_runs(self, v1, target):
        _seed_conclusions(v1, _conclusion_rows(count=20))
        migrate(v1, target)
        first = reconcile(v1, target).criteria["2_sample_hashes"]["hashes"]
        second = reconcile(v1, target).criteria["2_sample_hashes"]["hashes"]
        assert first == second, "the sample rule must be deterministic"

    def test_a_divergent_value_fails(self, v1, target):
        _seed_conclusions(v1, _conclusion_rows(count=5))
        migrate(v1, target)
        with target.transaction() as connection:
            connection.execute(
                "UPDATE conclusion SET confidence = 0.1 WHERE id = 'c0'")
        assert reconcile(v1, target).criteria["2_sample_hashes"]["verdict"] \
            == FAIL

    def test_reshaped_baselines_are_hashed_by_value(self, v1, target):
        # The column layout differs (aggregate -> baseline_stat) but the
        # composite key and the value are stable across both sides, so the
        # payload is comparable and skipping would understate coverage.
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)",
               [("TW", 1, 1.0), ("UA", 2, 2.0)])
        migrate(v1, target)
        entry = reconcile(v1, target).criteria["2_sample_hashes"][
            "hashes"]["hod_baseline"]
        assert entry["source"] == entry["target"]
        assert entry["sampled"] == 2

    def test_a_corrupted_baseline_value_fails(self, v1, target):
        _write(v1, "INSERT INTO hod_baseline VALUES (?,?,?)", [("TW", 1, 1.0)])
        migrate(v1, target)
        with target.transaction() as connection:
            connection.execute("UPDATE baseline_stat SET mean = 9.9")
        assert reconcile(v1, target).criteria["2_sample_hashes"]["verdict"] \
            == FAIL


class TestCriterion2CrossSideComparability:
    """The hash must be able to PASS on a faithful migration. Surrogate ids
    and JSON encoding differences made that structurally impossible."""

    def test_the_tl_stream_hashes_equal_after_a_faithful_migration(self, v1,
                                                                   target):
        _seed_tl(v1, series=(5, 4, 3, None, 1))
        migrate(v1, target)
        entry = reconcile(v1, target).criteria["2_sample_hashes"][
            "hashes"]["scenario_tl_observation"]
        assert entry["source"] == entry["target"], \
            "uncorrelated surrogate ids must not enter the hash"

    def test_japanese_metadata_hashes_equal(self, v1, target):
        # v1 wrote JSON with ensure_ascii=True (\uXXXX escapes), v3 writes
        # with False. Identical data, different bytes.
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:12] + ('{"note": "\\u53f0\\u6e7e\\u6709\\u4e8b"}',)
        _seed_conclusions(v1, rows)
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["2_sample_hashes"]
        assert criterion["verdict"] == PASS

    def test_a_genuinely_mutated_json_value_still_fails(self, v1, target):
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:12] + ('{"note": "original"}',)
        _seed_conclusions(v1, rows)
        migrate(v1, target)
        with target.transaction() as connection:
            connection.execute(
                "UPDATE conclusion SET metadata = '{\"note\": \"tampered\"}'")
        assert reconcile(v1, target).criteria["2_sample_hashes"]["verdict"] \
            == FAIL

    def test_a_reordered_json_key_set_still_hashes_equal(self, v1, target):
        rows = _conclusion_rows(count=1)
        rows[0] = rows[0][:12] + ('{"b": 2, "a": 1}',)
        _seed_conclusions(v1, rows)
        migrate(v1, target)
        assert reconcile(v1, target).criteria["2_sample_hashes"]["verdict"] \
            == PASS


def _seed_history_covering_both_windows(v1_path):
    """History old enough that criterion 4's two RUNNABLE sub-checks pass.

    Without this the criterion has a genuine failure to report, and after
    the verdict fix that is a FAIL — so a test about BLOCKED has to supply
    the history it is claiming to have.
    """
    import time
    now = time.time()
    _write(v1_path,
           "INSERT INTO conclusions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
           [("old", "taiwan", "threat_level", "ACTIVE", 0.9,
             now - 400 * DAY, "S1-X", "T1", '["https://example.test"]',
             None, "calibrated", None, "{}")])
    _write(v1_path, "INSERT INTO scenario_tl_observation "
                    "(scenario_id, observed_at, score, tl) VALUES (?,?,?,?)",
           [("taiwan", now - 60 * DAY, 1.0, 3)])


class TestCriterion1SourceTableAccounting:
    """A table nobody classified is a table nobody counts (R1).

    The completeness test compares the registries against S3's transcribed
    list, so it can only see tables someone already wrote down. Production
    grew five tables after S3 was written — L5 verification state and
    sensor-flag first-observation timestamps — and every registry-vs-list
    check in the suite stayed green while they went unmigrated.
    """

    def test_a_table_in_no_registry_fails_the_accounting(self, v1, target):
        _write_schema(v1, "CREATE TABLE sensor_flag_state (sensor TEXT, "
                          "flag_id TEXT, first_observed_at REAL)")
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["1_row_counts"]
        assert criterion["verdict"] == FAIL
        assert "sensor_flag_state" in criterion["unaccounted_source_tables"]

    def test_the_unaccounted_table_is_named_with_its_row_count(self, v1,
                                                               target):
        _write_schema(v1, "CREATE TABLE l5_check_result (id INTEGER, ts REAL)")
        _write(v1, "INSERT INTO l5_check_result VALUES (?,?)",
               [(1, NOW), (2, NOW)])
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["1_row_counts"]
        assert criterion["unaccounted_row_counts"]["l5_check_result"] == 2

    def test_a_fully_classified_snapshot_still_passes(self, v1, target):
        _seed_conclusions(v1)
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["1_row_counts"]
        assert criterion["unaccounted_source_tables"] == []
        assert criterion["verdict"] == PASS

    def test_sqlite_internal_tables_are_not_unaccounted(self, v1, target):
        # sqlite_sequence appears because a table uses AUTOINCREMENT, not
        # because anyone decided anything; flagging it would train the
        # reader to ignore this list.
        _seed_tl(v1)
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["1_row_counts"]
        assert criterion["unaccounted_source_tables"] == []

    def test_a_discarded_table_is_accounted_not_unaccounted(self, v1, target):
        _write_schema(v1,
                      "CREATE TABLE focus_switch_log (id INTEGER, ts REAL)")
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["1_row_counts"]
        assert criterion["unaccounted_source_tables"] == []
        assert criterion["source_table_accounting"]["discarded"] == 1


class TestCriterion4VerdictHonesty:
    """A sub-check that RAN and was violated is a FAIL.

    Criterion 4 computed a `failures` list and then reported BLOCKED
    regardless — so a calibration window that demonstrably did not survive
    was indistinguishable from one nobody could measure. Harmless only
    while criteria 3 and 5 are also BLOCKED; the moment L3 lands, this is
    the only thing between a truncated history and cutover.
    """

    def test_a_violated_window_is_a_failure_not_a_block(self, v1, target):
        _seed_tl(v1)           # seconds old: the 42-day window is not covered
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["4_calibration_window"]
        assert criterion["verdict"] == FAIL
        assert "tl_history_covers_window" in criterion["failures"]

    def test_it_blocks_only_when_every_runnable_check_passed(self, v1, target):
        _seed_history_covering_both_windows(v1)
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["4_calibration_window"]
        assert criterion["failures"] == []
        assert criterion["verdict"] == BLOCKED
        assert criterion["checks"]["continuity_run_length_monotonic"][
            "blocked_by"] == "inconclusive_continuity_log"

    def test_the_source_side_travels_with_the_verdict(self, v1, target):
        # "the window is short" has two causes and only one is the ETL's.
        _seed_tl(v1)
        migrate(v1, target)
        check = reconcile(v1, target).criteria["4_calibration_window"][
            "checks"]["tl_history_covers_window"]
        assert check["source_oldest_observed_at"] == \
            check["oldest_observed_at"], \
            "a faithful copy must show the same oldest row on both sides"
        assert check["window_days"] == 42

    def test_a_migration_that_truncated_history_is_named_as_such(self, v1,
                                                                 target):
        # The realistic way a window shortens: the OLDEST row is the one
        # that fails validation, so quarantine eats the far end of the
        # history and every surviving row still hashes perfectly.
        import time
        now = time.time()
        _write(v1, "INSERT INTO scenario_tl_observation "
                   "(scenario_id, observed_at, score, tl) VALUES (?,?,?,?)",
               [("taiwan", now - 60 * DAY, 1.0, 9),      # tl=9: quarantined
                ("taiwan", now - 10 * DAY, 1.0, 3)])
        report = migrate(v1, target)
        assert report.quarantined_count == 1
        criterion = reconcile(v1, target).criteria["4_calibration_window"]
        check = criterion["checks"]["tl_history_covers_window"]
        assert check["truncated_by_migration"] is True
        assert check["source_oldest_observed_at"] < check["oldest_observed_at"]
        assert "tl_history_covers_window:truncated_by_migration" in \
            criterion["failures"]
        assert criterion["verdict"] == FAIL

    def test_a_source_limited_window_is_not_blamed_on_the_migration(self, v1,
                                                                    target):
        # v1 prunes conclusions at 90d, so ADR-V3-005's 365d window cannot
        # be satisfied out of any v1 snapshot. That is still a FAIL — the
        # ledger really does not hold the window — but not a lost row.
        _seed_conclusions(v1)
        migrate(v1, target)
        check = reconcile(v1, target).criteria["4_calibration_window"][
            "checks"]["conclusion_history_covers_retention"]
        assert check["ok"] is False
        assert check["truncated_by_migration"] is False


class TestSampleFetchIsOnePass:
    """The verifier must not cost more than the migration it verifies.

    Neither side indexes the reconciliation's ordering columns, so
    `ORDER BY … LIMIT 1 OFFSET n` sorts the whole table once per sample
    row. Against production's 1,047,286 conclusions that measured 1.7 s
    per offset — a 60-second migration followed by a 17-minute check,
    inside the write-stop window S3-DATA-031 budgets at "a few minutes".
    """

    def test_it_returns_exactly_what_per_offset_queries_returned(self, v1):
        import sqlite3 as _sqlite3

        from v3.etl.reconcile import _fetch_offsets
        _seed_conclusions(v1, _conclusion_rows(count=40))
        connection = _sqlite3.connect(v1)
        connection.row_factory = _sqlite3.Row
        offsets = [0, 3, 7, 39, 40, 99]
        walked = _fetch_offsets(connection, "conclusions",
                                ("observed_at", "id"), offsets)
        naive = []
        for offset in offsets:
            row = connection.execute(
                'SELECT * FROM conclusions ORDER BY "observed_at" ASC, '
                '"id" ASC LIMIT 1 OFFSET ?', (offset,)).fetchone()
            if row is not None:
                naive.append(row)
        connection.close()
        assert [tuple(row) for row in walked] == [tuple(r) for r in naive]

    def test_offsets_past_the_end_are_dropped_not_faked(self, v1):
        import sqlite3 as _sqlite3

        from v3.etl.reconcile import _fetch_offsets
        _seed_conclusions(v1, _conclusion_rows(count=2))
        connection = _sqlite3.connect(v1)
        connection.row_factory = _sqlite3.Row
        rows = _fetch_offsets(connection, "conclusions",
                              ("observed_at", "id"), [0, 1, 2, 500])
        connection.close()
        assert len(rows) == 2

    def test_rows_come_back_in_the_order_the_offsets_were_asked_for(self):
        from v3.ledger.store_migration import take_offsets
        assert take_offsets(iter("abcdef"), [4, 1, 0]) == ["e", "b", "a"]

    def test_the_hash_still_passes_on_a_table_past_the_sample_threshold(
            self, v1, target):
        # 3*SAMPLE_SIZE is where _sample_offsets stops returning every row
        # and starts taking head/middle/tail, which is where a one-pass
        # walk could diverge from a per-offset query.
        _seed_conclusions(v1, _conclusion_rows(count=SAMPLE_SIZE * 3 + 50))
        migrate(v1, target)
        entry = reconcile(v1, target).criteria["2_sample_hashes"][
            "hashes"]["conclusions"]
        assert entry["sampled"] == SAMPLE_SIZE * 3
        assert entry["source"] == entry["target"]


class TestBlockedCriteria:
    """PASS would be a lie; BLOCKED with a named cause is the truth."""

    def test_recall_is_blocked_on_analyst_feedback(self, v1, target):
        criterion = reconcile(v1, target).criteria["3_recall_precision"]
        assert criterion["verdict"] == BLOCKED
        assert "analyst_feedback" in criterion["blocked_by"]
        assert criterion["target_wp"]

    def test_recall_names_both_required_series(self, v1, target):
        criterion = reconcile(v1, target).criteria["3_recall_precision"]
        assert set(criterion["series_required"]) == {"human_only", "all_rows"}

    def test_np6_is_blocked_on_the_prompt_store(self, v1, target):
        criterion = reconcile(v1, target).criteria["5_np6_resolution"]
        assert criterion["verdict"] == BLOCKED
        assert "llm_prompts" in criterion["blocked_by"]

    def test_np6_reports_how_many_references_are_waiting(self, v1, target):
        rows = _conclusion_rows(count=2)
        rows[0] = rows[0][:9] + ("abc123",) + rows[0][10:]
        _seed_conclusions(v1, rows)
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["5_np6_resolution"]
        assert criterion["conclusions_with_prompt_ref"] == 1

    def test_calibration_window_is_blocked_on_continuity(self, v1, target):
        # Seeded history: with the windows unmet the criterion has a real
        # failure to report, and after the verdict fix that is a FAIL.
        _seed_history_covering_both_windows(v1)
        migrate(v1, target)
        criterion = reconcile(v1, target).criteria["4_calibration_window"]
        assert criterion["verdict"] == BLOCKED
        assert criterion["checks"]["continuity_run_length_monotonic"][
            "blocked_by"] == "inconclusive_continuity_log"

    def test_the_checkable_half_of_criterion_4_still_runs(self, v1, target):
        _seed_tl(v1)
        migrate(v1, target)
        checks = reconcile(v1, target).criteria["4_calibration_window"][
            "checks"]
        # Fixture history is only seconds old, so the 42-day window is not
        # covered — and the harness says so rather than glossing over it.
        assert checks["tl_history_covers_window"]["ok"] is False
        assert checks["tl_history_covers_window"]["oldest_observed_at"]

    def test_a_long_enough_history_satisfies_the_tl_window(self, v1, target):
        import time
        _write(v1, "INSERT INTO scenario_tl_observation "
                   "(scenario_id, observed_at, score, tl) VALUES (?,?,?,?)",
               [("taiwan", time.time() - 60 * DAY, 1.0, 3)])
        migrate(v1, target)
        checks = reconcile(v1, target).criteria["4_calibration_window"][
            "checks"]
        assert checks["tl_history_covers_window"]["ok"] is True


class TestOverallVerdict:
    def test_any_failure_dominates(self, v1, target):
        _seed_conclusions(v1, _conclusion_rows(count=5))
        migrate(v1, target, limit=2)
        assert reconcile(v1, target).verdict == FAIL

    def test_blocked_dominates_pass(self, v1, target):
        _seed_history_covering_both_windows(v1)
        migrate(v1, target)
        # Criteria 3/4/5 are BLOCKED, so the run is not a green light.
        assert reconcile(v1, target).verdict == BLOCKED

    def test_the_report_is_machine_readable(self, v1, target):
        _seed_conclusions(v1)
        migrate(v1, target)
        payload = json.loads(json.dumps(reconcile(v1, target).as_dict()))
        assert set(payload["criteria"]) == {
            "1_row_counts", "2_sample_hashes", "3_recall_precision",
            "4_calibration_window", "5_np6_resolution"}
        assert payload["verdict"] in (PASS, FAIL, BLOCKED)

    def test_reconciliation_does_not_write_to_the_source(self, v1, target):
        import hashlib
        _seed_conclusions(v1)
        migrate(v1, target)
        before = hashlib.sha256(open(v1, "rb").read()).hexdigest()
        reconcile(v1, target)
        assert hashlib.sha256(open(v1, "rb").read()).hexdigest() == before
