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
from v3.etl.reconcile import BLOCKED, FAIL, PASS
from v3.ledger import LedgerStore

from tests.test_etl_migrate import (V1_SCHEMA, _conclusion_rows,
                                    _seed_conclusions, _seed_tl, _write)

NOW = 1_786_000_000.0
DAY = 86400.0


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
        _seed_conclusions(v1)
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
