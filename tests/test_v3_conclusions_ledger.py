"""WP-3.1 condition 6 — derived views, and a ledger that may be thinned.

P6 O-16 removed the compensation chain (thinning broke chronic detection
-> continuity ledger -> that missed flapping -> duty cycle) by keeping one
unthinned TL stream and deriving everything from it. The tests here are
the proof that the chain cannot restart: chronic detection, null-zone
length and trend are computed from the TL stream, so suppressing every
duplicate conclusion write changes none of them.

DP6 is satisfied at the same time (the ledger's write unit is a state
change), which is only possible because of the sentence above.

Named `test_v3_*` because `test_conclusions_persistence.py` is the v1
suite for `radar/conclusions/persistence.py` and both must keep running
until cutover.
"""
import json

import pytest

from tests.conclusions_fixtures import (LONG_HISTORY as LONG, NOW,
                                        contribution, context,
                                        scoring_result, store_with_tl)
from v3.conclusions import InputHealth
from v3.conclusions import vocabulary as V
from v3.conclusions.derive import derive_all
from v3.conclusions.persistence import persist, to_record
from v3.ledger import views

HOUR = 3600.0
DAY = 86400.0


@pytest.fixture
def store(tmp_path):
    instance = store_with_tl(tmp_path, "taiwan_contingency", [])
    yield instance
    instance.close()


class TestWriteRule:
    def test_the_first_tick_writes_every_type(self, store):
        report = persist(store, derive_all(context(), store=store))
        assert report["produced"] == len(report["written"])

    def test_an_unchanged_type_is_not_written_twice(self, store):
        persist(store, derive_all(context(), store=store))
        report = persist(store, derive_all(context(now=NOW + 300),
                                           store=store))
        assert report["written"] == []
        assert {entry["reason"] for entry in report["skipped"]} == {
            "unchanged_since_latest_row", "identical_batch_signature"}

    def test_a_state_change_writes_again(self, store):
        persist(store, derive_all(context(), store=store))
        changed = context(now=NOW + 300,
                          result=scoring_result(tl=2, score=7.0))
        report = persist(store, derive_all(changed, store=store))
        assert report["written"]

    def test_becoming_unavailable_is_a_change(self, store):
        persist(store, derive_all(context(), store=store))
        dead = context(now=NOW + 300, result=None,
                       health=InputHealth(sources_failed=("a",)))
        report = persist(store, derive_all(dead, store=store))
        assert report["written"]

    def test_a_flap_writes_every_transition(self, store):
        persist(store, derive_all(context(), store=store))
        persist(store, derive_all(
            context(now=NOW + 300, result=scoring_result(tl=2, score=7.0)),
            store=store))
        report = persist(store, derive_all(
            context(now=NOW + 600, result=scoring_result(tl=4, score=2.5)),
            store=store))
        # A -> B -> A: the third write must happen, or any reconstruction
        # between the second and third tick reports B forever.
        assert report["written"]

    def test_write_all_bypasses_the_comparison(self, store):
        persist(store, derive_all(context(), store=store))
        report = persist(store, derive_all(context(now=NOW + 300),
                                           store=store), write_all=True)
        assert report["skipped"] == []

    def test_the_skip_decision_is_returned_not_swallowed(self, store):
        persist(store, derive_all(context(), store=store))
        report = persist(store, derive_all(context(now=NOW + 300),
                                           store=store))
        assert report["skipped"]

    def test_an_anomaly_batch_is_compared_as_a_set(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"), contribution(signal_source="b"))))
        persist(store, derive_all(ctx, store=store))
        again = context(now=NOW + 1.0, result=scoring_result(contributions=(
            contribution(signal_source="b"), contribution(signal_source="a"))))
        report = persist(store, derive_all(again, store=store))
        assert any(entry["reason"] == "identical_batch_signature"
                   for entry in report["skipped"])

    def test_a_jittered_previous_batch_is_still_recognised(self, store):
        # S1-CONC-032: rows of one batch may land microseconds apart. v3
        # stamps them all with context.now, but the comparison must not
        # depend on that — a caller that varies them slightly still has
        # one batch, not several.
        from v3.conclusions.persistence import to_record
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"), contribution(signal_source="b"))))
        rows = [item for item in derive_all(ctx, store=store)
                if item.conclusion_type == V.ANOMALY]
        for offset, item in enumerate(rows):
            record = to_record(item)
            store.append_conclusion(type(record)(
                **{**{f: getattr(record, f) for f in
                      ("conclusion_id", "scenario_id", "conclusion_type",
                       "confidence", "state", "formula_ref", "threshold_ref",
                       "source_urls", "llm_prompt_sha256",
                       "calibration_status", "conclusion_unavailable_reason",
                       "metadata")},
                   "observed_at": record.observed_at + offset * 0.000_1}))
        again = context(now=NOW + 300, result=scoring_result(contributions=(
            contribution(signal_source="a"), contribution(signal_source="b"))))
        report = persist(store, derive_all(again, store=store))
        assert any(entry["reason"] == "identical_batch_signature"
                   for entry in report["skipped"])

    def test_two_ticks_inside_the_jitter_window_do_not_merge(self, store):
        # M-5: with a pure 5s window, ticks less than BATCH_WINDOW_SEC
        # apart (replay, backfill) merged into one "previous batch" and a
        # genuine change read as unchanged. `metadata.batch_at` makes the
        # previous batch an exact grouping instead of a neighbourhood.
        persist(store, derive_all(context(result=scoring_result(
            contributions=(contribution(signal_source="a"),))), store=store))
        persist(store, derive_all(context(
            now=NOW + 1.0, result=scoring_result(
                contributions=(contribution(signal_source="b"),))),
            store=store))
        report = persist(store, derive_all(context(
            now=NOW + 2.0, result=scoring_result(contributions=(
                contribution(signal_source="a"),
                contribution(signal_source="b")))), store=store))
        assert report["written"], \
            "'a and b were simultaneously present' is a new fact"

    def test_a_changed_anomaly_set_rewrites_the_whole_batch(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"),)))
        persist(store, derive_all(ctx, store=store))
        changed = context(now=NOW + 1.0, result=scoring_result(contributions=(
            contribution(signal_source="a"),
            contribution(signal_source="c", sensor="ioda"))))
        persist(store, derive_all(changed, store=store))
        anomalies = store.conclusions_between(
            scenario_id="taiwan_contingency", conclusion_type=V.ANOMALY,
            start=0.0, end=NOW + 10)
        assert len(anomalies) == 3


class TestHealthCollapseIsAlwaysWritten:
    """The write identity includes WHICH GUARD spoke, not only the state.

    Found in review: with `(state, reason)` alone, a tick where every
    source died but the level held was "unchanged" and was not written —
    so the ledger's most recent threat-level row went on asserting four
    healthy sources while the pipeline was dead, with no marker anywhere.
    G-17 one layer down, and worst in the NP1 case the override exists
    for: an ALERTING conclusion republished from broken inputs looked, in
    the ledger, exactly like the healthy tick before it.
    """

    def _alerting(self, when, health):
        return context(now=when, health=health,
                       result=scoring_result(tl=2, score=7.0))

    def test_a_pipeline_collapse_under_an_unchanged_level_is_written(
            self, store):
        healthy_health = InputHealth(
            sources_ok=("a", "b", "c", "d"), history_span_sec=LONG)
        dead_health = InputHealth(
            sources_failed=("a", "b", "c", "d"), history_span_sec=LONG)

        persist(store, derive_all(self._alerting(NOW, healthy_health),
                                  store=store))
        report = persist(store, derive_all(
            self._alerting(NOW + 300, dead_health), store=store))

        assert report["written"], \
            "the level held but every source died; that is a new fact"
        row = store.latest_conclusion_at(
            NOW + 400, scenario_id="taiwan_contingency",
            conclusion_type=V.THREAT_LEVEL)
        metadata = json.loads(row["metadata"])
        assert metadata["input_health"]["sources_failed"] == \
            ["a", "b", "c", "d"]
        assert metadata["suppression"]["reason"] == V.UPSTREAM_FAILURE
        assert metadata["suppression"]["overridden"] is True

    def test_recovery_is_written_too(self, store):
        healthy_health = InputHealth(sources_ok=("a", "b"),
                                     history_span_sec=LONG)
        dead_health = InputHealth(sources_failed=("a", "b"),
                                  history_span_sec=LONG)
        persist(store, derive_all(self._alerting(NOW, dead_health),
                                  store=store))
        report = persist(store, derive_all(
            self._alerting(NOW + 300, healthy_health), store=store))
        assert report["written"]
        row = store.latest_conclusion_at(
            NOW + 400, scenario_id="taiwan_contingency",
            conclusion_type=V.THREAT_LEVEL)
        assert "suppression" not in json.loads(row["metadata"])

    def test_a_steady_degraded_state_is_still_deduplicated(self, store):
        dead_health = InputHealth(sources_failed=("a", "b"),
                                  history_span_sec=LONG)
        persist(store, derive_all(self._alerting(NOW, dead_health),
                                  store=store))
        report = persist(store, derive_all(
            self._alerting(NOW + 300, dead_health), store=store))
        # The marker is part of the identity, not a heartbeat: an
        # unchanging outage still writes once.
        assert report["written"] == []

    def test_the_anomaly_batch_notices_a_health_collapse_too(self, store):
        healthy_health = InputHealth(sources_ok=("a", "b"),
                                     history_span_sec=LONG)
        dead_health = InputHealth(sources_failed=("a", "b"),
                                  history_span_sec=LONG)
        first = context(health=healthy_health, result=scoring_result(
            contributions=(contribution(signal_source="a"),)))
        persist(store, derive_all(first, store=store))
        second = context(now=NOW + 300, health=dead_health,
                         result=scoring_result(contributions=(
                             contribution(signal_source="a"),)))
        report = persist(store, derive_all(second, store=store))
        assert report["written"]


class TestImportanceIsNotMultiplicity:
    def test_a_twelvefold_importance_change_is_written(self, store):
        small = context(result=scoring_result(contributions=(
            contribution(signal_source="bgp", raw_score=0.1),)))
        persist(store, derive_all(small, store=store))
        large = context(now=NOW + 300, result=scoring_result(contributions=(
            contribution(signal_source="bgp", raw_score=9.0),)))
        report = persist(store, derive_all(large, store=store))
        assert report["written"], \
            "importance 8 -> 100 is the row's whole content, not multiplicity"
        row = store.latest_conclusion_at(
            NOW + 400, scenario_id="taiwan_contingency",
            conclusion_type=V.ANOMALY)
        assert json.loads(row["metadata"])["importance_score"] > 50

    def test_recency_drift_within_a_band_does_not_rewrite(self, store):
        # S1-CONC-032's actual concern: a signature that moves every tick
        # is a gate that never closes. Recency decay is about 2% per 900s
        # tick at tau=12h, which must stay inside one band.
        # raw 0.9 x participant 0.8 = importance 72, comfortably inside
        # band 7. A value sitting exactly on a band edge does rewrite once
        # as it crosses — bounded and acceptable, unlike a signature that
        # moves on every tick regardless.
        first = context(result=scoring_result(contributions=(
            contribution(signal_source="bgp", raw_score=0.9),)))
        persist(store, derive_all(first, store=store))
        later = context(now=NOW + 900, observation_times={"bgp": NOW},
                        result=scoring_result(contributions=(
                            contribution(signal_source="bgp", raw_score=0.9),)))
        report = persist(store, derive_all(later, store=store))
        assert any(entry["reason"] == "identical_batch_signature"
                   for entry in report["skipped"])


class TestScenariosDoNotCollapseIntoEachOther:
    def test_a_second_scenarios_first_anomaly_is_not_lost(self, store):
        shared = (contribution(signal_source="bgp"),)
        persist(store, derive_all(
            context(scenario_id="A", result=scoring_result(
                scenario_id="A", contributions=shared)), store=store))
        mixed = list(derive_all(
            context(scenario_id="A", now=NOW + 300, result=scoring_result(
                scenario_id="A", contributions=shared)), store=store))
        mixed += list(derive_all(
            context(scenario_id="B", now=NOW + 300, result=scoring_result(
                scenario_id="B", contributions=shared)), store=store))
        persist(store, mixed)

        rows_b = store.conclusions_between(
            scenario_id="B", conclusion_type=V.ANOMALY, start=0.0,
            end=NOW + 1000)
        assert rows_b, \
            "B's identical anomaly collapsed onto A's set element and was " \
            "reported as an unchanged batch for a scenario with no rows"

    def test_each_scenarios_skip_reason_names_its_scenario(self, store):
        shared = (contribution(signal_source="bgp"),)
        produced = list(derive_all(
            context(scenario_id="A", result=scoring_result(
                scenario_id="A", contributions=shared)), store=store))
        persist(store, produced)
        report = persist(store, list(derive_all(
            context(scenario_id="A", now=NOW + 300, result=scoring_result(
                scenario_id="A", contributions=shared)), store=store)))
        assert all("scenario_id" in entry for entry in report["skipped"])


class TestTheLedgerRow:
    def test_the_suppression_survives_into_the_row(self, store):
        dead = context(result=None,
                       health=InputHealth(sources_failed=("a",)))
        persist(store, derive_all(dead, store=store))
        row = store.latest_conclusion_at(
            NOW + 1, scenario_id="taiwan_contingency",
            conclusion_type=V.THREAT_LEVEL)
        metadata = json.loads(row["metadata"])
        assert metadata["suppression"]["reason"] == V.UPSTREAM_FAILURE
        assert row["conclusion_unavailable_reason"] == V.UPSTREAM_FAILURE

    def test_the_input_health_survives_into_the_row(self, store):
        persist(store, derive_all(context(), store=store))
        row = store.latest_conclusion_at(
            NOW + 1, scenario_id="taiwan_contingency",
            conclusion_type=V.THREAT_LEVEL)
        assert json.loads(row["metadata"])["input_health"]["consulted"] == 4

    def test_the_provenance_survives_into_the_row(self, store):
        persist(store, derive_all(context(), store=store))
        row = store.latest_conclusion_at(
            NOW + 1, scenario_id="taiwan_contingency",
            conclusion_type=V.THREAT_LEVEL)
        assert row["formula_ref"].startswith("v3.conclusions.threat_level")
        assert json.loads(row["metadata"])["provenance"]["formula_ref"]

    def test_json_fields_are_key_sorted(self, store):
        record = to_record(derive_all(context(), store=store)[0])
        assert record.threshold_ref.index("tl1_physical") < \
            record.threshold_ref.index("tl1_total")

    def test_the_row_round_trips_through_the_ledger(self, store):
        conclusion = derive_all(context(), store=store)[0]
        store.append_conclusion(to_record(conclusion))
        row = store.latest_conclusion_at(
            NOW + 1, scenario_id="taiwan_contingency",
            conclusion_type=V.THREAT_LEVEL)
        assert row["id"] == conclusion.conclusion_id
        assert row["state"] == conclusion.state
        assert row["confidence"] == conclusion.confidence


class TestThinningCannotBreakDetection:
    """The property that makes O-16's ruling and DP6's norm compatible."""

    def _outage_stream(self, tmp_path):
        series = [(NOW - 10 * DAY + i * HOUR, None) for i in range(240)]
        return store_with_tl(tmp_path, "taiwan_contingency", series)

    def test_chronic_null_zone_reads_the_tl_stream_not_the_ledger(
            self, tmp_path):
        store = self._outage_stream(tmp_path)
        try:
            assert store.count_conclusions() == 0
            verdict = views.chronic_null_zone(
                store, "taiwan_contingency", threshold_sec=7 * DAY, now=NOW)
        finally:
            store.close()
        assert verdict["is_chronic"] is True

    def test_it_is_unchanged_when_every_duplicate_write_is_suppressed(
            self, tmp_path):
        store = self._outage_stream(tmp_path)
        try:
            for tick in range(5):
                persist(store, derive_all(
                    context(now=NOW + tick, result=None,
                            health=InputHealth(sources_failed=("a",))),
                    store=store))
            dense = views.chronic_null_zone(
                store, "taiwan_contingency", threshold_sec=7 * DAY, now=NOW)
            written = store.count_conclusions()
        finally:
            store.close()
        # Five ticks of identical unavailability wrote once, and the
        # chronic verdict is the same as with no conclusion rows at all.
        assert dense["is_chronic"] is True
        assert written == 5   # one per type, written once

    def test_null_zone_length_comes_from_the_stream(self, tmp_path):
        store = self._outage_stream(tmp_path)
        try:
            spans = views.null_zone_spans(store, "taiwan_contingency",
                                          now=NOW)
        finally:
            store.close()
        assert len(spans) == 1 and spans[0]["ongoing"] is True

    def test_observed_span_is_derived_not_counted(self, tmp_path):
        store = store_with_tl(tmp_path, "s",
                              [(NOW - 5 * DAY, 4), (NOW - DAY, 4)])
        try:
            span = views.observed_span(store, "s", now=NOW)
        finally:
            store.close()
        assert span["span_sec"] == pytest.approx(5 * DAY)
        assert span["samples"] == 2

    def test_observed_span_of_an_unseen_scenario_is_zero(self, store):
        assert views.observed_span(store, "never_seen", now=NOW) == {
            "first_observed_at": None, "last_observed_at": None,
            "span_sec": 0.0, "samples": 0}

    def test_a_young_stream_drives_the_calibration_pending_guard(self,
                                                                tmp_path):
        store = store_with_tl(tmp_path, "s", [(NOW - HOUR, 5)])
        try:
            span = views.observed_span(store, "s", now=NOW)
            health = InputHealth(sources_ok=("a",),
                                 history_span_sec=span["span_sec"])
            produced = derive_all(
                context(scenario_id="s", now=NOW, health=health,
                        result=scoring_result(scenario_id="s", tl=5,
                                              score=0.0)),
                store=store)
        finally:
            store.close()
        threat = next(item for item in produced
                      if item.conclusion_type == V.THREAT_LEVEL)
        assert threat.unavailable_reason == V.CALIBRATION_PENDING


class TestSeverityWindowPair:
    def test_it_refuses_a_bare_duration(self, store):
        with pytest.raises(TypeError, match="F-06"):
            views.severity_window_pair(store, "s", window=86400.0, now=NOW)

    def test_the_seam_puts_a_row_at_the_boundary_in_the_current_period(
            self, tmp_path):
        from v3.kernel import Window
        store = store_with_tl(tmp_path, "s",
                              [(NOW - DAY, 2), (NOW - DAY - 1, 5)])
        try:
            pair = views.severity_window_pair(
                store, "s", window=Window.from_days(1.0, cadence_sec=DAY),
                now=NOW)
        finally:
            store.close()
        assert pair["current_n"] == 1 and pair["previous_n"] == 1
        assert pair["current_mean_severity"] == 4.0

    def test_a_row_at_exactly_now_is_not_yet_in_the_window(self, tmp_path):
        # L-5: the half-open upper seam. Deleting the `observed_at >= ts`
        # filter would not have failed any test.
        from v3.kernel import Window
        store = store_with_tl(tmp_path, "s", [(NOW, 1), (NOW - HOUR, 5)])
        try:
            pair = views.severity_window_pair(
                store, "s", window=Window.from_days(1.0, cadence_sec=HOUR),
                now=NOW)
        finally:
            store.close()
        assert pair["current_n"] == 1
        assert pair["current_mean_severity"] == 1.0   # TL5 only, not TL1

    def test_the_span_is_the_declared_window_not_a_floored_sample_count(
            self, tmp_path):
        # L-1: `effective_seconds` floors to whole cadence steps, which at
        # a 7000s cadence turns one day into 84000s — a shorter window,
        # fewer samples, likelier INSUFFICIENT, insensitive direction.
        from v3.kernel import Window
        store = store_with_tl(tmp_path, "s", [(NOW - 85000.0, 2)])
        try:
            pair = views.severity_window_pair(
                store, "s", window=Window.from_days(1.0, cadence_sec=7000.0),
                now=NOW)
        finally:
            store.close()
        assert pair["window_seconds"] == DAY
        assert pair["current_n"] == 1

    def test_the_delta_is_none_when_either_period_is_empty(self, tmp_path):
        from v3.kernel import Window
        store = store_with_tl(tmp_path, "s", [(NOW - HOUR, 2)])
        try:
            pair = views.severity_window_pair(
                store, "s", window=Window.from_days(1.0, cadence_sec=HOUR),
                now=NOW)
        finally:
            store.close()
        assert pair["delta_severity"] is None

    def test_a_constant_shift_leaves_the_delta_unchanged(self, tmp_path):
        # P6 O-15's parity argument, checked rather than asserted in prose:
        # 6-TL and 5-TL differ by 1.0 in the means and by 0.0 in the delta.
        from v3.kernel import Window
        store = store_with_tl(
            tmp_path, "s",
            [(NOW - 40 * HOUR + i * HOUR, 5) for i in range(4)]
            + [(NOW - 4 * HOUR + i * HOUR, 2) for i in range(4)])
        try:
            pair = views.severity_window_pair(
                store, "s", window=Window.from_days(1.0, cadence_sec=HOUR),
                now=NOW)
        finally:
            store.close()
        legacy_delta = ((5 - 2) - (5 - 5))     # the old 5-TL scale
        assert pair["delta_severity"] == legacy_delta
        assert pair["current_mean_severity"] == (5 - 2) + 1
