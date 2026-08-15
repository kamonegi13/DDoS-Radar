"""WP-0.4 v2 — the S9 runner against a real store.

The load-bearing claims:

* a convergent FALSE_NEGATIVE (rss + gdelt) is CONFIRMED by Tier 1 and
  lands in `calibration_label` under the automated actor;
* a single-source FALSE_NEGATIVE waits as a pending draft — no label,
  and the pending count is exactly what widens the recall interval;
* a draft is resolved by a LATER label, never by touching the draft row;
* TP / FP / TN flow straight from the classifier;
* the whole cycle is idempotent — a re-run writes nothing new;
* `maybe_run` is a persisted daily schedule (F-01), not a process
  counter: due-ness survives what a restart would forget.
"""
from __future__ import annotations

import dataclasses

import pytest

from tests.conclusions_fixtures import healthy, provenance
from v3.calibration import human as HUMAN
from v3.calibration import runner as RUNNER
from v3.calibration import thresholds as T
from v3.calibration.epoch import CURRENT_EPOCH
from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
from v3.ledger import LedgerStore
from v3.ledger.records import Evidence, SignalObservation

NOW = 1_786_000_000.0
HOUR = 3600.0
DAY = 86400.0
EPOCH = CURRENT_EPOCH.epoch_id
SCENARIO = "taiwan_contingency"


@dataclasses.dataclass(frozen=True)
class _Ref:
    scenario_id: str
    roles: dict


REFS = (_Ref(scenario_id=SCENARIO,
             roles={"TW": "primary_target", "CN": "adversary",
                    "US": "primary_ally"}),)


def _conclusion(store, *, observed_at, state="TL5", confidence=0.5):
    record = to_record(Conclusion(
        scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
        observed_at=observed_at, confidence=confidence,
        provenance=provenance("tl@S1-CONC-001"), input_health=healthy(),
        state=state, threshold_ref={}, source_urls=(),
        calibration_status={}))
    store.append_conclusion(record)
    return record


def _signal(store, *, at, source="bg_observer_rss", country="TW",
            fatalities=12):
    flags = ({"fatalities": fatalities, "extractor_confidence": 0.9}
             if source == "bg_observer_rss" else {})
    store.append_signal(SignalObservation(
        tick_id=f"tick-{at:.0f}-{source}-{country}", sensor=source,
        signal_source=source, domain="info", country=country,
        evidence=Evidence.observe({}, source=source, observed_at=at,
                                  freshness_horizon_sec=30 * DAY),
        status="FIRED", raw_score=6.0, confidence=0.7, flags=flags,
        evidence_url=f"https://example.invalid/{source}"), at)


@pytest.fixture()
def store(tmp_path):
    handle = LedgerStore(str(tmp_path / "s9.db"))
    yield handle
    handle.close()


class TestTier1Convergence:
    def test_a_convergent_fn_is_confirmed_automatically(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        _signal(store, at=NOW - HOUR, source="gdelt")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new.get("FALSE_NEGATIVE") == 1
        assert report.drafts_new == 0
        rows = store.labels_in_epoch(epoch_id=EPOCH, since=NOW - DAY,
                                     until=NOW)
        assert len(rows) == 1
        row = rows[0]
        assert row["label"] == "FALSE_NEGATIVE"
        assert row["is_automated"] is True
        assert row["analyst_id"] == "auto:ground_truth_etl"
        assert row["epoch_id"] == EPOCH

    def test_the_human_only_series_stays_clean(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        _signal(store, at=NOW - HOUR, source="gdelt")
        RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert store.labels_in_epoch(epoch_id=EPOCH, since=NOW - DAY,
                                     until=NOW, exclude_auto=True) == []

    def test_a_single_source_fn_waits_as_a_pending_draft(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new == {}
        assert report.drafts_new == 1
        assert report.pending_total == 1
        assert store.labels_in_epoch(epoch_id=EPOCH, since=NOW - DAY,
                                     until=NOW) == []
        drafts = store.fn_drafts(epoch_id=EPOCH)
        assert len(drafts) == 1
        assert drafts[0]["sources"] == ["rss"]
        assert drafts[0]["proposed_analyst_id"] == "auto:rss"

    def test_a_draft_is_resolved_by_a_later_label_not_an_edit(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert HUMAN.pending_draft_counts(store, now=NOW) == {
            (SCENARIO, "threat_level"): 1}
        # The second source arrives a day later; Tier 1 now converges.
        _signal(store, at=NOW + HOUR, source="gdelt")
        report = RUNNER.s9_cycle(store, now=NOW + DAY, scenarios=REFS)
        assert report.labels_new.get("FALSE_NEGATIVE") == 1
        # The draft row survives (append-only), but it is no longer
        # pending — the label's existence is the resolution.
        assert HUMAN.pending_draft_counts(store, now=NOW) == {}
        assert len(store.fn_drafts(epoch_id=EPOCH)) == 1


class TestTheClassifierLabelsFlowThrough:
    def test_an_alert_with_an_event_is_a_true_positive(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL2")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new.get("TRUE_POSITIVE") == 1

    def test_absence_labels_wait_for_the_horizon(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new == {}
        assert report.unlabelled.get("horizon_not_elapsed") == 1

    def test_a_calm_call_with_no_event_becomes_tn_after_the_horizon(
            self, store):
        _conclusion(store, observed_at=NOW - 8 * DAY, state="TL5")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new.get("TRUE_NEGATIVE") == 1

    def test_an_alert_with_no_event_becomes_fp_after_the_horizon(
            self, store):
        _conclusion(store, observed_at=NOW - 8 * DAY, state="TL2")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new.get("FALSE_POSITIVE") == 1

    def test_an_unavailable_conclusion_is_skipped_not_scored(self, store):
        from v3.conclusions import Suppression
        store.append_conclusion(to_record(Conclusion(
            scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
            observed_at=NOW - 8 * DAY, confidence=0.0,
            provenance=provenance("tl@S1-CONC-001"),
            input_health=healthy(),
            unavailable_reason="calibration_pending",
            suppression=Suppression(
                guard_id="calibration_window",
                reason="calibration_pending", detail="窓未充足",
                overridden=False))))
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new == {}
        assert report.unlabelled.get("position_unscorable") == 1


class TestTheCycleConverges:
    def test_a_rerun_writes_nothing_new(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        _signal(store, at=NOW - HOUR, source="gdelt")
        first = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        second = RUNNER.s9_cycle(store, now=NOW + HOUR, scenarios=REFS)
        assert first.labels_new.get("FALSE_NEGATIVE") == 1
        assert second.labels_new == {}
        assert second.labels_existing == 1
        assert store.count_labels() == 1

    def test_a_draft_rerun_converges_too(self, store):
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        second = RUNNER.s9_cycle(store, now=NOW + HOUR, scenarios=REFS)
        assert second.drafts_new == 0
        assert second.drafts_existing == 1
        assert len(store.fn_drafts(epoch_id=EPOCH)) == 1


class TestMaybeRunIsAPersistedSchedule:
    def test_the_first_wake_runs_immediately(self, store):
        report = RUNNER.maybe_run(store, now=NOW, scenarios=REFS)
        assert report is not None
        assert store.latest_s9_run_at() == pytest.approx(NOW)

    def test_within_the_interval_nothing_runs(self, store):
        RUNNER.maybe_run(store, now=NOW, scenarios=REFS)
        assert RUNNER.maybe_run(store, now=NOW + HOUR,
                                scenarios=REFS) is None

    def test_after_the_interval_it_runs_again(self, store):
        RUNNER.maybe_run(store, now=NOW, scenarios=REFS)
        report = RUNNER.maybe_run(
            store, now=NOW + T.S9_RUN_INTERVAL_SEC + 1, scenarios=REFS)
        assert report is not None

    def test_the_run_record_is_append_only(self, store):
        import sqlite3
        RUNNER.maybe_run(store, now=NOW, scenarios=REFS)
        with pytest.raises(sqlite3.DatabaseError):
            with store.transaction() as conn:
                conn.execute("UPDATE calibration_run SET outcome='edited'")


class TestTheMigrationPathReplays:
    """v10 was the first ALTER-TABLE migration here and it broke the
    replay the suite performs (a version rewind re-runs the whole list;
    `CREATE TABLE IF NOT EXISTS` survives that, `ADD COLUMN` does not).
    Rebuilt as an idempotent table copy — pinned, because the next
    column will be tempted down the same path."""

    def test_replaying_every_migration_preserves_the_drafts(self, store,
                                                            tmp_path):
        import sqlite3
        from v3.ledger.schema import SCHEMA_VERSION
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert len(store.fn_drafts(epoch_id=EPOCH)) == 1
        path = store._path if hasattr(store, "_path") else None
        store.close()
        assert path, "the fixture's store must know its own path"

        # Rewind and re-run the whole list, exactly as the ledger suite
        # does for the entity tables.
        conn = sqlite3.connect(path)
        conn.execute("UPDATE schema_meta SET value = '7' WHERE key = 'version'")
        conn.commit()
        conn.close()

        again = LedgerStore(path)
        try:
            assert again.schema_version() == SCHEMA_VERSION
            drafts = again.fn_drafts(epoch_id=EPOCH)
            assert len(drafts) == 1, "the replay must not lose a draft"
            assert "evidence_note" in drafts[0]
        finally:
            again.close()


class TestTheDraftLedgerIsAppendOnly:
    def test_an_update_is_refused(self, store):
        import sqlite3
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        with pytest.raises(sqlite3.DatabaseError):
            with store.transaction() as conn:
                conn.execute(
                    "UPDATE calibration_fn_draft SET reason='edited'")

    def test_a_delete_is_refused(self, store):
        import sqlite3
        _conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        with pytest.raises(sqlite3.DatabaseError):
            with store.transaction() as conn:
                conn.execute("DELETE FROM calibration_fn_draft")
