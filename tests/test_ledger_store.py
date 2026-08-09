"""WP-2.2 L1 — the observation ledger (append-only, single-jurisdiction).

Five obligations, each traceable to a defect the diagnosis found:

  append-only        the ledger records what a sensor said, and nothing
                     later rewrites it. Replay depends on that (AP4).
  explicit stats     reading never updates a statistic. F-05 was
                     `compute_adaptive_zscore` writing running stats on
                     every read, which makes a scoring tick non-idempotent
                     and therefore makes parity unprovable (S5-VERIF-019).
  persistent         no in-memory baselines. A-03 lost them on restart.
  retention          60d signals / 365d conclusions (ADR-V3-005), pruned
                     only by an explicit job, from a declarative registry
                     (S3-DATA-040 — the hand-written DELETE list is what
                     hid a hardcoded 7d prune behind a live config key).
  latest-row-at-T    the one read primitive replay uses (S5-VERIF-017).
"""
import sqlite3
import threading

import gevent
import pytest

from v3.kernel import Evidence, ThreatLevel, Window
from v3.kernel.errors import DomainError, StaleEvidenceError
from v3.ledger import (ConclusionRecord, LedgerStore, SignalObservation,
                       TLObservation)

NOW = 1_786_000_000.0
DAY = 86400.0
HOUR = 3600.0


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "v3.db"))
    yield instance
    instance.close()


def _signal(tick_id="t1", sensor="gps_jamming", country="TW",
            observed_at=NOW, payload=None, **overrides):
    fields = {
        "tick_id": tick_id,
        "sensor": sensor,
        "signal_source": "gpsjam",
        "domain": "physical",
        "country": country,
        "evidence": Evidence.observe(
            payload if payload is not None else {"ratio": 0.08},
            observed_at=observed_at, freshness_horizon_sec=6 * HOUR,
            source=sensor),
        "status": "FIRED",
        "raw_score": 0.08,
        "confidence": 0.9,
    }
    fields.update(overrides)
    return SignalObservation(**fields)


def _tl(tick_id="t1", scenario_id="taiwan", observed_at=NOW, tl=3):
    return TLObservation(
        tick_id=tick_id, scenario_id=scenario_id, observed_at=observed_at,
        threat_level=None if tl is None else ThreatLevel(tl), score=42.0)


class TestSchema:
    def test_the_store_creates_its_own_file(self, tmp_path):
        path = tmp_path / "fresh.db"
        instance = LedgerStore(str(path))
        assert path.exists()
        instance.close()

    def test_the_path_is_injected_never_defaulted(self):
        with pytest.raises(TypeError):
            LedgerStore()

    def test_schema_version_is_recorded(self, store):
        assert store.schema_version() >= 1

    def test_reopening_does_not_re_migrate(self, tmp_path):
        path = str(tmp_path / "v3.db")
        first = LedgerStore(path)
        version = first.schema_version()
        first.close()
        second = LedgerStore(path)
        assert second.schema_version() == version
        second.close()

    def test_every_table_declares_a_retention_policy(self):
        from v3.ledger import schema
        declared = {policy.table for policy in schema.RETENTION_POLICIES}
        assert declared >= set(schema.PERSISTED_TABLES), \
            "S3-DATA-044: no table may exist without a retention declaration"


class TestAppendOnlySignals:
    def test_a_signal_is_recorded(self, store):
        assert store.append_signal(_signal(), now=NOW) is True
        assert store.count_signals() == 1

    def test_the_evidence_payload_is_persisted(self, store):
        store.append_signal(_signal(payload={"ratio": 0.08}), now=NOW)
        row = store.latest_signal_at(NOW, sensor="gps_jamming", country="TW")
        assert row["raw_score"] == 0.08

    def test_a_stale_observation_is_refused_at_ingest(self, store):
        # Freshness is checked when it enters the ledger, so a stale row
        # cannot become a "fact" that later reads trust (B-03).
        stale = _signal(observed_at=NOW - 48 * HOUR)
        with pytest.raises(StaleEvidenceError):
            store.append_signal(stale, now=NOW)
        assert store.count_signals() == 0

    def test_raw_dicts_are_refused_at_the_boundary(self, store):
        with pytest.raises(TypeError):
            store.append_signal({"sensor": "x"}, now=NOW)

    def test_a_bare_payload_instead_of_evidence_is_refused(self, store):
        with pytest.raises(DomainError):
            SignalObservation(
                tick_id="t", sensor="s", signal_source="src",
                domain="physical", country="TW",
                evidence={"ratio": 0.08},   # not kernel Evidence
                status="FIRED")

    def test_every_in_place_writer_is_individually_sanctioned(self, store):
        # Nothing may revise an observation. Three APIs write in place, and
        # each is allowed for a stated reason:
        #   update_baselines      the explicit baseline job (A-03 / F-05)
        #   upsert_baseline_value the ETL's aggregate-baseline import
        #   set_checkpoint        ETL progress in schema_meta — metadata
        #                         about the migration, not ledger content
        public = {name for name in dir(store) if not name.startswith("_")}
        mutators = {name for name in public
                    if name.startswith(("update_", "edit_", "modify_",
                                        "set_", "revise_", "upsert_"))}
        assert mutators == {"update_baselines", "upsert_baseline_value",
                            "set_checkpoint"}, \
            "the ledger records facts; every in-place writer needs a reason"

    def test_there_is_no_delete_api_besides_the_retention_job(self, store):
        public = {name for name in dir(store) if not name.startswith("_")}
        deleters = {name for name in public
                    if name.startswith(("delete_", "remove_", "purge_"))}
        assert deleters <= {"prune_expired"}

    def test_a_direct_update_is_rejected_by_the_database(self, store):
        store.append_signal(_signal(), now=NOW)
        with pytest.raises(sqlite3.DatabaseError):
            store._connection().execute(  # noqa: SLF001
                "UPDATE signal_observation SET raw_score = 9.9")

    def test_a_direct_delete_is_rejected_by_the_database(self, store):
        store.append_signal(_signal(), now=NOW)
        with pytest.raises(sqlite3.DatabaseError):
            store._connection().execute(  # noqa: SLF001
                "DELETE FROM signal_observation")


class TestIdempotence:
    """S5-VERIF-019: replaying the same tick must not corrupt the ledger."""

    def test_recording_the_same_tick_twice_inserts_once(self, store):
        assert store.append_signal(_signal(tick_id="t1"), now=NOW) is True
        assert store.append_signal(_signal(tick_id="t1"), now=NOW) is False
        assert store.count_signals() == 1

    def test_different_ticks_are_both_recorded(self, store):
        store.append_signal(_signal(tick_id="t1"), now=NOW)
        store.append_signal(_signal(tick_id="t2", observed_at=NOW + 60),
                            now=NOW + 60)
        assert store.count_signals() == 2

    def test_the_same_tick_for_a_different_country_is_a_distinct_row(self, store):
        store.append_signal(_signal(tick_id="t1", country="TW"), now=NOW)
        store.append_signal(_signal(tick_id="t1", country="UA"), now=NOW)
        assert store.count_signals() == 2

    def test_queries_are_unaffected_by_a_double_record(self, store):
        store.append_signal(_signal(tick_id="t1"), now=NOW)
        before = store.latest_signal_at(NOW, sensor="gps_jamming",
                                        country="TW")
        store.append_signal(_signal(tick_id="t1"), now=NOW)
        assert store.latest_signal_at(NOW, sensor="gps_jamming",
                                      country="TW") == before

    def test_tl_ticks_are_idempotent_too(self, store):
        assert store.append_tl(_tl(tick_id="t1")) is True
        assert store.append_tl(_tl(tick_id="t1")) is False
        assert store.count_tl() == 1


class TestLatestRowAtT:
    """S5-VERIF-017: `observed_at <= T ORDER BY observed_at DESC LIMIT 1`
    must return what an analyst saw at T."""

    def _seed(self, store):
        for index, offset in enumerate([0, HOUR, 2 * HOUR]):
            store.append_signal(
                _signal(tick_id=f"t{index}", observed_at=NOW + offset,
                        raw_score=float(index)),
                now=NOW + offset)

    def test_returns_the_row_in_force_at_t(self, store):
        self._seed(store)
        row = store.latest_signal_at(NOW + HOUR + 1, sensor="gps_jamming",
                                     country="TW")
        assert row["raw_score"] == 1.0

    def test_the_boundary_instant_is_included(self, store):
        self._seed(store)
        row = store.latest_signal_at(NOW + HOUR, sensor="gps_jamming",
                                     country="TW")
        assert row["raw_score"] == 1.0

    def test_before_the_first_row_returns_nothing(self, store):
        self._seed(store)
        assert store.latest_signal_at(NOW - 1, sensor="gps_jamming",
                                      country="TW") is None

    def test_after_the_last_row_returns_the_last(self, store):
        self._seed(store)
        row = store.latest_signal_at(NOW + 10 * HOUR, sensor="gps_jamming",
                                     country="TW")
        assert row["raw_score"] == 2.0

    def test_out_of_order_inserts_still_answer_by_observed_at(self, store):
        # Arrival order must not decide the answer; observation time must.
        store.append_signal(_signal(tick_id="late", observed_at=NOW + 2 * HOUR,
                                    raw_score=2.0), now=NOW + 2 * HOUR)
        store.append_signal(_signal(tick_id="early", observed_at=NOW,
                                    raw_score=0.0), now=NOW + 2 * HOUR)
        row = store.latest_signal_at(NOW + HOUR, sensor="gps_jamming",
                                     country="TW")
        assert row["raw_score"] == 0.0

    def test_a_b_a_recovery_is_three_rows(self, store):
        # S5-VERIF-017 names this explicitly: the return to A must be
        # recorded, not collapsed into the earlier A.
        for index, (offset, status) in enumerate(
                [(0, "OK"), (HOUR, "FIRED"), (2 * HOUR, "OK")]):
            store.append_signal(
                _signal(tick_id=f"s{index}", observed_at=NOW + offset,
                        status=status), now=NOW + offset)
        assert store.count_signals() == 3
        assert store.latest_signal_at(NOW + 2 * HOUR, sensor="gps_jamming",
                                      country="TW")["status"] == "OK"

    def test_scoping_by_sensor_and_country(self, store):
        store.append_signal(_signal(tick_id="a", sensor="gps_jamming"),
                            now=NOW)
        store.append_signal(_signal(tick_id="b", sensor="telegram_mirror"),
                            now=NOW)
        row = store.latest_signal_at(NOW, sensor="telegram_mirror",
                                     country="TW")
        assert row["sensor"] == "telegram_mirror"


class TestReadsHaveNoSideEffects:
    """S5-VERIF-019 / F-05: a read must never write."""

    def _fingerprint(self, store):
        return (store.count_signals(), store.count_tl(),
                store._connection().execute(  # noqa: SLF001
                    "SELECT COUNT(*) FROM baseline_stat").fetchone()[0])

    def test_latest_row_query_changes_nothing(self, store):
        store.append_signal(_signal(), now=NOW)
        before = self._fingerprint(store)
        for _ in range(5):
            store.latest_signal_at(NOW, sensor="gps_jamming", country="TW")
        assert self._fingerprint(store) == before

    def test_baseline_reads_change_nothing(self, store):
        store.update_baselines([_signal()], baseline_id="zscore", now=NOW)
        before = self._fingerprint(store)
        for _ in range(5):
            store.read_baseline("zscore", sensor="gps_jamming", country="TW")
        assert self._fingerprint(store) == before

    def test_the_read_connection_is_read_only(self, store):
        with pytest.raises(sqlite3.OperationalError):
            store._read_connection().execute(  # noqa: SLF001
                "INSERT INTO baseline_stat "
                "(baseline_id, sensor, country, bucket, sample_count, mean, "
                " m2, updated_at) VALUES ('x','y','z',0,1,0,0,0)")

    def test_reading_a_missing_baseline_does_not_create_it(self, store):
        assert store.read_baseline("zscore", sensor="nope",
                                   country="ZZ") is None
        assert self._fingerprint(store)[2] == 0


class TestBaselinesArePersistentAndExplicit:
    """A-03: baselines lived in process memory and died on restart."""

    def test_an_update_job_folds_observations_in(self, store):
        store.update_baselines([_signal(raw_score=1.0),
                                _signal(tick_id="t2", raw_score=3.0)],
                               baseline_id="zscore", now=NOW)
        stat = store.read_baseline("zscore", sensor="gps_jamming",
                                   country="TW")
        assert stat["sample_count"] == 2
        assert stat["mean"] == pytest.approx(2.0)

    def test_the_baseline_survives_close_and_reopen(self, tmp_path):
        path = str(tmp_path / "v3.db")
        first = LedgerStore(path)
        first.update_baselines([_signal(raw_score=1.0)], baseline_id="zscore",
                               now=NOW)
        first.close()

        second = LedgerStore(path)
        stat = second.read_baseline("zscore", sensor="gps_jamming",
                                    country="TW")
        assert stat["sample_count"] == 1
        second.close()

    def test_updates_accumulate_across_jobs(self, store):
        store.update_baselines([_signal(raw_score=1.0)], baseline_id="zscore",
                               now=NOW)
        store.update_baselines([_signal(tick_id="t2", raw_score=3.0)],
                               baseline_id="zscore", now=NOW + 60)
        stat = store.read_baseline("zscore", sensor="gps_jamming",
                                   country="TW")
        assert stat["sample_count"] == 2

    def test_the_update_records_the_window_it_was_built_for(self, store):
        window = Window.from_days(30, cadence_sec=1800)
        store.update_baselines([_signal(raw_score=1.0)], baseline_id="zscore",
                               window=window, now=NOW)
        stat = store.read_baseline("zscore", sensor="gps_jamming",
                                   country="TW")
        assert stat["window_days"] == 30
        assert stat["cadence_sec"] == 1800

    def test_a_raw_window_is_refused(self, store):
        with pytest.raises(TypeError):
            store.update_baselines([_signal()], baseline_id="zscore",
                                   window=30, now=NOW)

    def test_no_module_level_baseline_cache_exists(self):
        from v3.ledger import baselines
        caches = [name for name, value in vars(baselines).items()
                  if isinstance(value, dict) and not name.startswith("__")]
        assert caches == [], f"in-memory baseline state found: {caches}"


class TestRetention:
    """ADR-V3-005, enforced by an explicit job over a declarative registry."""

    def test_signals_older_than_sixty_days_are_pruned(self, store):
        store.append_signal(_signal(tick_id="old", observed_at=NOW - 61 * DAY),
                            now=NOW - 61 * DAY)
        store.append_signal(_signal(tick_id="new", observed_at=NOW), now=NOW)
        pruned = store.prune_expired(now=NOW)
        assert pruned["signal_observation"] == 1
        assert store.count_signals() == 1

    def test_a_signal_inside_sixty_days_survives(self, store):
        store.append_signal(_signal(tick_id="keep", observed_at=NOW - 59 * DAY),
                            now=NOW - 59 * DAY)
        store.prune_expired(now=NOW)
        assert store.count_signals() == 1

    def test_the_boundary_day_is_kept(self, store):
        store.append_signal(_signal(tick_id="edge", observed_at=NOW - 60 * DAY),
                            now=NOW - 60 * DAY)
        store.prune_expired(now=NOW)
        assert store.count_signals() == 1

    def test_conclusions_are_kept_for_a_year(self, store):
        store.append_conclusion(ConclusionRecord(
            conclusion_id="c1", scenario_id="taiwan",
            conclusion_type="threat_level", observed_at=NOW - 364 * DAY,
            confidence=0.9))
        store.append_conclusion(ConclusionRecord(
            conclusion_id="c2", scenario_id="taiwan",
            conclusion_type="threat_level", observed_at=NOW - 366 * DAY,
            confidence=0.9))
        pruned = store.prune_expired(now=NOW)
        assert pruned["conclusion"] == 1
        assert store.count_conclusions() == 1

    def test_nothing_is_pruned_without_the_explicit_job(self, store):
        store.append_signal(_signal(tick_id="old", observed_at=NOW - 400 * DAY),
                            now=NOW - 400 * DAY)
        for _ in range(3):
            store.latest_signal_at(NOW, sensor="gps_jamming", country="TW")
        assert store.count_signals() == 1, \
            "retention must never be a side effect of a read"

    def test_baselines_are_never_pruned_by_age(self, store):
        store.update_baselines([_signal(raw_score=1.0)], baseline_id="zscore",
                               now=NOW - 400 * DAY)
        store.prune_expired(now=NOW)
        assert store.read_baseline("zscore", sensor="gps_jamming",
                                   country="TW") is not None

    def test_the_registry_declares_the_two_mandated_horizons(self):
        from v3.ledger import schema
        by_table = {policy.table: policy for policy in schema.RETENTION_POLICIES}
        assert by_table["signal_observation"].retention_days == 60
        assert by_table["conclusion"].retention_days == 365


class TestPruneIsAtomic:
    """The retention job opens the append-only gate. If it can leave that
    gate open, the ledger silently stops being append-only — and nothing
    reports it, because the triggers just stop firing."""

    def test_a_failure_mid_prune_deletes_nothing(self, store, monkeypatch):
        from v3.ledger import retention, schema
        store.append_signal(_signal(tick_id="old",
                                    observed_at=NOW - 400 * DAY),
                            now=NOW - 400 * DAY)
        broken = schema.RETENTION_POLICIES + (
            schema.RetentionPolicy(table="no_such_table",
                                   time_column="observed_at",
                                   retention_days=1, rationale="probe"),)
        monkeypatch.setattr(retention, "RETENTION_POLICIES", broken)
        with pytest.raises(Exception):
            store.prune_expired(now=NOW)
        assert store.count_signals() == 1, \
            "a partial prune must roll back entirely"

    def test_a_failed_prune_leaves_the_gate_closed(self, store, monkeypatch):
        from v3.ledger import retention, schema
        store.append_signal(_signal(tick_id="a"), now=NOW)
        broken = schema.RETENTION_POLICIES + (
            schema.RetentionPolicy(table="no_such_table",
                                   time_column="observed_at",
                                   retention_days=1, rationale="probe"),)
        monkeypatch.setattr(retention, "RETENTION_POLICIES", broken)
        with pytest.raises(Exception):
            store.prune_expired(now=NOW)
        with pytest.raises(sqlite3.DatabaseError):
            store._connection().execute(  # noqa: SLF001
                "DELETE FROM signal_observation")

    def test_a_stuck_flag_from_a_crash_is_cleared_on_reopen(self, tmp_path):
        # Defence in depth: if a durable pruning flag somehow exists at
        # construction, it can only mean a previous process died holding
        # the gate open. Reopening must close it.
        path = str(tmp_path / "v3.db")
        first = LedgerStore(path)
        first._connection().execute(  # noqa: SLF001
            "INSERT INTO schema_meta (key, value) VALUES ('pruning', '1') "
            "ON CONFLICT (key) DO UPDATE SET value = '1'")
        first._connection().commit()  # noqa: SLF001
        first.close()

        second = LedgerStore(path)
        try:
            second.append_signal(_signal(), now=NOW)
            with pytest.raises(sqlite3.DatabaseError):
                second._connection().execute(  # noqa: SLF001
                    "DELETE FROM signal_observation")
        finally:
            second.close()

    def test_a_successful_prune_closes_the_gate(self, store):
        store.append_signal(_signal(tick_id="old",
                                    observed_at=NOW - 400 * DAY),
                            now=NOW - 400 * DAY)
        # A surviving row is required for the check to mean anything: the
        # trigger is per-row, so a DELETE matching nothing never fires it.
        store.append_signal(_signal(tick_id="fresh"), now=NOW)
        assert store.prune_expired(now=NOW)["signal_observation"] == 1
        with pytest.raises(sqlite3.DatabaseError):
            store._connection().execute(  # noqa: SLF001
                "DELETE FROM signal_observation")
        assert store.count_signals() == 1


class TestAwkwardPaths:
    """A '#' or '?' in the path silently truncates a sqlite URI: writes
    keep working through the normal connection while every read returns
    empty. Third time this lesson has appeared in this codebase."""

    @pytest.mark.parametrize("directory", ["with#hash", "with?query",
                                           "with space", "with%pct"])
    def test_reads_and_writes_agree_on_awkward_paths(self, tmp_path,
                                                     directory):
        target = tmp_path / directory
        target.mkdir()
        instance = LedgerStore(str(target / "v3.db"))
        try:
            assert instance.append_signal(_signal(), now=NOW) is True
            assert instance.count_signals() == 1, \
                "the read connection is looking at a different file"
            assert instance.latest_signal_at(NOW, sensor="gps_jamming",
                                             country="TW") is not None
        finally:
            instance.close()


class TestTickDivergence:
    """S5-VERIF-019 says a replayed tick must be a no-op. A same-key row
    with DIFFERENT content is not a replay — it is evidence that the
    caller is not deterministic, which is the thing parity depends on."""

    def test_an_identical_replay_is_a_quiet_no_op(self, store):
        store.append_signal(_signal(tick_id="t1"), now=NOW)
        assert store.append_signal(_signal(tick_id="t1"), now=NOW) is False
        assert store.count_signals() == 1

    def test_a_divergent_raw_score_raises(self, store):
        store.append_signal(_signal(tick_id="t1", raw_score=0.08), now=NOW)
        with pytest.raises(DomainError) as exc:
            store.append_signal(_signal(tick_id="t1", raw_score=0.99),
                                now=NOW)
        assert "0.08" in str(exc.value) and "0.99" in str(exc.value)

    def test_a_divergent_status_raises(self, store):
        store.append_signal(_signal(tick_id="t1", status="FIRED"), now=NOW)
        with pytest.raises(DomainError):
            store.append_signal(_signal(tick_id="t1", status="OK"), now=NOW)

    def test_a_divergent_observed_at_raises(self, store):
        store.append_signal(_signal(tick_id="t1", observed_at=NOW), now=NOW)
        with pytest.raises(DomainError):
            store.append_signal(_signal(tick_id="t1", observed_at=NOW + 30),
                                now=NOW + 30)

    def test_a_divergent_tl_raises(self, store):
        store.append_tl(_tl(tick_id="t1", tl=3))
        with pytest.raises(DomainError):
            store.append_tl(_tl(tick_id="t1", tl=1))

    def test_an_identical_tl_replay_is_a_no_op(self, store):
        store.append_tl(_tl(tick_id="t1", tl=3))
        assert store.append_tl(_tl(tick_id="t1", tl=3)) is False


class TestConclusionRecord:
    def _record(self, **overrides):
        from v3.ledger import ConclusionRecord
        fields = {"conclusion_id": "c1", "scenario_id": "taiwan",
                  "conclusion_type": "threat_level", "observed_at": NOW,
                  "confidence": 0.9}
        fields.update(overrides)
        return ConclusionRecord(**fields)

    def test_a_valid_record_appends(self, store):
        assert store.append_conclusion(self._record()) is True

    def test_a_raw_kwargs_bag_is_refused(self, store):
        with pytest.raises(TypeError):
            store.append_conclusion(conclusion_id="c1", scenario_id="s",
                                    conclusion_type="t", observed_at=NOW,
                                    confidence=0.5)

    def test_an_unknown_field_is_refused(self):
        with pytest.raises(TypeError):
            self._record(typo_field="x")

    @pytest.mark.parametrize("value", ["", "  ", None])
    def test_empty_identifiers_are_refused(self, value):
        with pytest.raises(DomainError):
            self._record(scenario_id=value)

    @pytest.mark.parametrize("value", [float("nan"), float("inf")])
    def test_non_finite_confidence_is_refused(self, value):
        with pytest.raises(DomainError):
            self._record(confidence=value)

    def test_missing_confidence_is_refused(self):
        with pytest.raises(DomainError):
            self._record(confidence=None)

    def test_latest_conclusion_is_deterministic_on_ties(self, store):
        for index in range(3):
            store.append_conclusion(self._record(
                conclusion_id=f"c{index}", observed_at=NOW))
        first = store.latest_conclusion_at(NOW, scenario_id="taiwan",
                                           conclusion_type="threat_level")
        for _ in range(5):
            assert store.latest_conclusion_at(
                NOW, scenario_id="taiwan",
                conclusion_type="threat_level") == first


class TestRecordValidation:
    def test_tl_score_is_required(self):
        with pytest.raises(DomainError):
            TLObservation(tick_id="t", scenario_id="s", observed_at=NOW,
                          threat_level=ThreatLevel(3), score=None)

    def test_a_zero_score_is_legitimate(self):
        record = TLObservation(tick_id="t", scenario_id="s", observed_at=NOW,
                               threat_level=ThreatLevel(3), score=0.0)
        assert record.score == 0.0

    @pytest.mark.parametrize("value", ["false", "0", 1, None])
    def test_suppressed_must_be_a_real_bool(self, value):
        with pytest.raises(DomainError):
            _signal(suppressed=value)

    def test_suppressed_accepts_booleans(self):
        assert _signal(suppressed=True).suppressed is True

    def test_flags_are_immutable(self):
        observation = _signal(flags={"a": 1})
        with pytest.raises(TypeError):
            observation.flags["a"] = 2

    def test_a_retention_policy_rejects_a_non_identifier_table(self):
        from v3.ledger.schema import RetentionPolicy
        with pytest.raises(Exception):
            RetentionPolicy(table="signal; DROP TABLE x",
                            time_column="observed_at", retention_days=1,
                            rationale="probe")

    def test_a_retention_policy_rejects_a_non_identifier_column(self):
        from v3.ledger.schema import RetentionPolicy
        with pytest.raises(Exception):
            RetentionPolicy(table="signal_observation",
                            time_column="observed_at; DROP TABLE x",
                            retention_days=1, rationale="probe")


class TestTheReadConnectionIsThreadLocal:
    """A single cached `_read_conn` raised

        sqlite3.ProgrammingError: SQLite objects created in a thread can
        only be used in that same thread.

    the moment a second thread reached it — sqlite3 defaults to
    `check_same_thread=True`, and v3's composition root runs a tick
    thread alongside HTTP request threads, so this was not hypothetical:
    it fired on the first request after the tick thread had opened the
    read connection first (or vice versa). Every test in this class
    raises that ProgrammingError against the single-shared-handle
    implementation and passes once each thread gets its own handle.

    Every cross-thread test here spawns on `gevent.get_hub().threadpool`
    rather than `threading.Thread`, and that is load-bearing, not a
    style choice. This repo's root `conftest.py` runs
    `gevent.monkey.patch_all()` for the whole pytest session (legacy v1
    compatibility). That patches `threading.Thread` to spawn a
    cooperative GREENLET, not a real OS thread — every greenlet shares
    the ONE real OS thread the interpreter started with, so
    `threading.get_ident()` differs per greenlet while the identity
    SQLite's `check_same_thread` actually compares
    (`PyThread_get_thread_ident()`, a C-level call the monkey-patch does
    not touch) does not. A version of these tests written with plain
    `threading.Thread` was tried first and PASSED both before and after
    the fix in this test process — proving nothing, exactly the "not
    evidence" trap the task called out. v3's real deployment does not
    monkey-patch gevent at all (`Dockerfile.v3` runs plain gunicorn `-k
    gthread`), so its tick thread (`v3/runtime/loop.py`) and its HTTP
    worker threads ARE genuine, distinct OS threads, which is why the
    defect fired there. `gevent.get_hub().threadpool` is gevent's own
    supported escape hatch for running Python code on a real OS thread
    despite the monkey-patch, so spawning on it is what makes these
    tests faithful to the PRODUCTION concurrency shape rather than to
    pytest's.

    Only reads cross threads in these tests, never writes. The write
    connection had the IDENTICAL defect and it is covered by
    `TestTheWriteConnectionIsThreadLocal` below — scoping this class to
    reads was the original error: the traceback showed a read, so the fix
    was made to read, and the shadow container went on failing every tick
    on the write path for exactly the same reason.
    """

    @staticmethod
    def _run_on_a_real_os_thread(target):
        """See `_on_a_real_os_thread`; kept as the name these tests read."""
        return _on_a_real_os_thread(target)

    def test_a_read_from_another_thread_returns_the_same_rows(self, store):
        # THE regression test for the defect. Confirmed by running this
        # exact test (with the store fix reverted via `git stash`)
        # before writing the fix: it raised sqlite3.ProgrammingError.
        # With the fix, `_read_connection()` hands each thread its own
        # handle and this passes.
        store.append_signal(_signal(), now=NOW)
        main_thread_row = store.latest_signal_at(
            NOW, sensor="gps_jamming", country="TW")
        assert main_thread_row is not None

        other_thread_row = self._run_on_a_real_os_thread(
            lambda: store.latest_signal_at(NOW, sensor="gps_jamming",
                                           country="TW"))

        assert other_thread_row == main_thread_row

    def test_the_main_thread_can_still_read_after_a_worker_thread_read_first(
            self, store):
        # Order matters for the single-shared-connection bug: whichever
        # thread calls `_read_connection()` FIRST "owns" the cached
        # handle, and it is the OTHER thread that then raises. The test
        # above has the main thread go first; this one reverses it, so
        # both orderings of the race are covered.
        store.append_signal(_signal(), now=NOW)

        worker_row = self._run_on_a_real_os_thread(
            lambda: store.latest_signal_at(NOW, sensor="gps_jamming",
                                           country="TW"))
        assert worker_row is not None

        main_thread_row = store.latest_signal_at(
            NOW, sensor="gps_jamming", country="TW")
        assert main_thread_row == worker_row

    def test_two_threads_reading_concurrently_both_get_correct_results(
            self, store):
        # `check_same_thread=False` would have "fixed" the
        # ProgrammingError by handing every thread the SAME connection
        # object with no serialisation between them — a silent data
        # race instead of a loud error. This proves the actual fix (one
        # connection per thread) instead: two REAL OS threads hammering
        # different countries at the same time each see only their own
        # country's row, never a mix-up or a crash. The barrier forces
        # both tasks onto the thread pool at once, rather than letting
        # the pool serialise them onto one reused worker thread and
        # accidentally hide the race.
        for index, country in enumerate(("TW", "US")):
            store.append_signal(
                _signal(tick_id=f"concurrent-{index}", country=country),
                now=NOW)

        pool = gevent.get_hub().threadpool
        barrier = threading.Barrier(2, timeout=10)

        def _hammer(country):
            barrier.wait()
            mismatches = []
            for _ in range(200):
                row = store.latest_signal_at(
                    NOW, sensor="gps_jamming", country=country)
                if row is None or row["country"] != country:
                    mismatches.append((country, row))
            return mismatches

        first = pool.spawn(_hammer, "TW")
        second = pool.spawn(_hammer, "US")
        tw_mismatches = first.get(timeout=15)
        us_mismatches = second.get(timeout=15)

        assert not tw_mismatches, tw_mismatches
        assert not us_mismatches, us_mismatches

    def test_close_still_works_after_a_read_from_another_thread(
            self, tmp_path):
        # `close()` used to close ONE cached connection. With one handle
        # per thread, it must still close cleanly: the calling thread's
        # own handle directly, and the other thread's handle by dropping
        # this store's reference to it (see the docstring on `close()`
        # for why that is the honest option rather than a leak or a
        # lie). Either way, `close()` itself must not raise, and the
        # underlying file must not be left locked for the next open.
        path = str(tmp_path / "v3.db")
        instance = LedgerStore(path)
        instance.append_signal(_signal(), now=NOW)

        def _read_from_other_thread():
            return instance.latest_signal_at(NOW, sensor="gps_jamming",
                                             country="TW")

        assert self._run_on_a_real_os_thread(_read_from_other_thread) \
            is not None

        instance.close()  # must not raise

        # The file must not be left locked by an un-closed handle from
        # the other thread.
        reopened = LedgerStore(path)
        try:
            assert reopened.count_signals() == 1
        finally:
            reopened.close()


def _on_a_real_os_thread(target, *args):
    """Run `target` on a real OS thread via gevent's thread pool.

    Shared by both thread-affinity classes for the reason the read class
    documents at length: the root `conftest.py` monkey-patches gevent over
    the whole session, so `threading.Thread` spawns a GREENLET and every
    greenlet shares ONE real OS thread. A cross-thread test written with
    `threading.Thread` passes before AND after the fix, which is the false
    negative that already happened here once. `gevent.get_hub().threadpool`
    is gevent's supported way to reach a genuine OS thread despite the
    patch, and it matches the deployment shape: `Dockerfile.v3` runs plain
    gunicorn `-k gthread` with no patching at all.
    """
    return gevent.get_hub().threadpool.spawn(target, *args).get(timeout=20)


class TestTheWriteConnectionIsThreadLocal:
    """The write handle had the identical defect the read handle had.

    e973d31 made `_read_connection()` per-thread and scoped the fix to
    reads because the traceback showed a read. The shadow container then
    logged, once per tick, forever:

        tick failed: ProgrammingError: SQLite objects created in a thread
        can only be used in that same thread.

    `LedgerStore` is constructed on the gunicorn worker's thread and
    `v3/runtime/loop.py` runs the tick on a thread of its own — and the
    tick WRITES. One cached `self._conn` is one thread's property, so
    every tick died at its first append and `tl_observation` stayed empty
    for the whole run.

    **Writes are not reads, so the fix is not a copy.** Two write handles
    to one SQLite file are not automatically safe; what makes them safe
    here is that they were never what serialised writes in the first
    place. `transaction()` holds `self._lock` for a whole BEGIN
    IMMEDIATE..COMMIT, so at most one write transaction exists in this
    process at any instant no matter how many handles do. These tests
    check both halves: that a write from another thread WORKS, and that
    the properties the single handle used to carry — one serialised
    transaction, the append-only triggers, the prune gate's single
    transaction — still hold once there are several.
    """

    def test_a_write_from_another_thread_succeeds(self, store):
        # THE regression test. Against a single shared write connection
        # this raises sqlite3.ProgrammingError — the exact line the
        # shadow container logged once a minute, forever.
        _on_a_real_os_thread(
            lambda: store.append_signal(_signal(tick_id="from-worker"),
                                        now=NOW))

        assert store.count_signals() == 1

    def test_the_deployment_shape_writes_on_one_thread_reads_on_another(
            self, store):
        # The container's actual shape: the tick thread appends, an HTTP
        # worker thread projects. Both directions of the handoff have to
        # work, and the row the reader sees has to be the row the writer
        # wrote — a per-thread handle that saw a stale snapshot would be
        # a quieter version of the same defect.
        _on_a_real_os_thread(
            lambda: store.append_tl(_tl(tick_id="tick-thread"), ))

        row = store.latest_tl_at(NOW, scenario_id="taiwan")
        assert row is not None and row["tick_id"] == "tick-thread"

        store.append_signal(_signal(tick_id="main-thread"), now=NOW)
        worker_row = _on_a_real_os_thread(
            lambda: store.latest_signal_at(NOW, sensor="gps_jamming",
                                           country="TW"))
        assert worker_row is not None
        assert worker_row["tick_id"] == "main-thread"

    def test_two_real_threads_writing_at_once_lose_nothing(self, store):
        # What a per-thread WRITE handle has to earn that a per-thread
        # read handle did not: two handles can hold two write
        # transactions on one file, and SQLite answers that with
        # SQLITE_BUSY, not with a merge. The lock is what forbids it —
        # `transaction()` holds it across BEGIN IMMEDIATE..COMMIT — so
        # both threads' rows must ALL land, with no busy error and no
        # loss. The barrier forces genuine overlap rather than letting
        # the pool serialise the two tasks by accident.
        pool = gevent.get_hub().threadpool
        barrier = threading.Barrier(2, timeout=20)
        per_thread = 40

        def _write(prefix):
            barrier.wait()
            for index in range(per_thread):
                store.append_signal(
                    _signal(tick_id=f"{prefix}-{index}"), now=NOW)
            return prefix

        first = pool.spawn(_write, "alpha")
        second = pool.spawn(_write, "beta")
        assert first.get(timeout=30) == "alpha"
        assert second.get(timeout=30) == "beta"

        assert store.count_signals() == 2 * per_thread

    def test_the_append_only_triggers_still_bite_on_a_second_handle(
            self, store):
        # A new write connection is a new chance to be exempt from the
        # discipline. It must not be: the triggers are schema objects, so
        # every handle to the file is subject to them, and a handle that
        # could UPDATE would make "append-only" a property of which
        # thread you happened to be on.
        store.append_signal(_signal(), now=NOW)

        def _try_to_rewrite_history():
            with pytest.raises(sqlite3.IntegrityError):
                store._connection().execute(       # noqa: SLF001
                    "UPDATE signal_observation SET raw_score = 0.99")
            with pytest.raises(sqlite3.IntegrityError):
                store._connection().execute(       # noqa: SLF001
                    "DELETE FROM signal_observation")
            return True

        assert _on_a_real_os_thread(_try_to_rewrite_history)
        assert store.latest_signal_at(
            NOW, sensor="gps_jamming", country="TW")["raw_score"] == 0.08

    def test_a_prune_from_another_thread_is_still_one_transaction(self, store):
        # The prune gate opens and closes inside ONE `BEGIN IMMEDIATE`.
        # Run from a thread that has to open its own write handle first,
        # that invariant has to survive: the flag must be gone afterwards
        # (the gate closed) and the rows must actually be deleted (the
        # deletes and the flag were the same transaction).
        store.append_signal(_signal(tick_id="old", observed_at=NOW - 90 * DAY),
                            now=NOW - 90 * DAY)
        store.append_signal(_signal(tick_id="new"), now=NOW)

        deleted = _on_a_real_os_thread(lambda: store.prune_expired(now=NOW))

        assert deleted["signal_observation"] == 1
        assert store.count_signals() == 1
        flag = store._connection().execute(        # noqa: SLF001
            "SELECT value FROM schema_meta WHERE key = 'pruning'").fetchone()
        assert flag is None, \
            "the gate was left open, so the ledger is no longer append-only"

    def test_close_still_works_after_a_write_from_another_thread(
            self, tmp_path):
        # Same decision as the read handle's `close()`, and it has to be
        # made again rather than assumed: `sqlite3.Connection.close()` is
        # itself thread-gated, so closing another thread's handle raises.
        # `close()` must not raise, and must not leave the file locked.
        path = str(tmp_path / "v3.db")
        instance = LedgerStore(path)

        _on_a_real_os_thread(
            lambda: instance.append_signal(_signal(tick_id="worker"),
                                           now=NOW))

        instance.close()  # must not raise

        reopened = LedgerStore(path)
        try:
            assert reopened.count_signals() == 1
            reopened.append_signal(_signal(tick_id="after-reopen"), now=NOW)
            assert reopened.count_signals() == 2
        finally:
            reopened.close()
