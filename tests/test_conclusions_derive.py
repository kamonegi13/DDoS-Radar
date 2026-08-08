"""WP-3.1 — the five derivations (S1-CONC-009 through 026).

Numeric thresholds are pinned DIRECTLY here, not compared against the
module constants. S1-conclusions §7 GAP-01/02 records that the entire
production suite is constant-relative: `CYBER_DDOS_FLOOR = 0.1` passes all
26 of its tests, so the classifier's sensitivity could change without a
single failure. These assertions are the missing pins.
"""
import math

import pytest

from tests.conclusions_fixtures import (NOW, contribution, context, healthy,
                                        scoring_result, store_with_tl)
from v3.conclusions import InputHealth, ScenarioContext
from v3.conclusions import anomaly, attack_mode, per_domain, threat_level
from v3.conclusions import trend as trend_module
from v3.conclusions import vocabulary as V
from v3.conclusions.derive import derive_all, latest_of_each_type


@pytest.fixture
def store(tmp_path):
    instance = store_with_tl(tmp_path, "taiwan_contingency", [])
    yield instance
    instance.close()


# ── THREAT_LEVEL ─────────────────────────────────────────────────────────

class TestThreatLevel:
    def test_state_is_the_tl_integer_as_a_string(self):
        conclusion = threat_level.derive(
            context(result=scoring_result(tl=3, score=5.0)))
        assert conclusion.state == "3"

    def test_severity_decides_alertness_not_the_raw_number(self):
        alert = threat_level.derive(context(
            result=scoring_result(tl=3, score=5.0),
            health=InputHealth(sources_ok=("a",), history_span_sec=0.0)))
        # TL3 is severity 3 = alerting, so the young-scenario guard is
        # overridden rather than allowed to withhold it (NP1).
        assert alert.is_available and alert.suppression.overridden is True

    def test_a_calm_tl_is_suppressed_by_the_same_health(self):
        calm = threat_level.derive(context(
            result=scoring_result(tl=5, score=0.0),
            health=InputHealth(sources_ok=("a",), history_span_sec=0.0)))
        assert calm.unavailable_reason == V.CALIBRATION_PENDING

    def test_confidence_is_the_clamped_linear_map(self):
        conclusion = threat_level.derive(
            context(result=scoring_result(tl=3, score=6.0)))
        assert conclusion.confidence == 0.5

    def test_confidence_clamps_at_one(self):
        conclusion = threat_level.derive(
            context(result=scoring_result(tl=1, score=40.0)))
        assert conclusion.confidence == 1.0

    def test_the_denominator_is_twelve(self):
        from v3.conclusions import thresholds as T
        assert T.TL_CONFIDENCE_DENOM == 12.0

    def test_lite_mode_discounts_confidence_by_zero_point_six(self):
        conclusion = threat_level.derive(context(
            result=scoring_result(tl=3, score=6.0, scoring_mode="lite")))
        assert conclusion.confidence == 0.3

    def test_lite_mode_does_not_change_the_level(self):
        conclusion = threat_level.derive(context(
            result=scoring_result(tl=3, score=6.0, scoring_mode="lite")))
        assert conclusion.state == "3"

    def test_lite_mode_carries_the_note_and_full_mode_does_not(self):
        lite = threat_level.derive(context(
            result=scoring_result(tl=3, score=6.0, scoring_mode="lite")))
        full = threat_level.derive(context(result=scoring_result(tl=3)))
        assert "lite_tl_note" in lite.metadata
        assert "lite_tl_note" not in full.metadata

    def test_threshold_ref_publishes_the_six_keys(self):
        conclusion = threat_level.derive(context())
        assert set(conclusion.threshold_ref) == {
            "tl1_total", "tl1_physical", "tl2_total",
            "tl2_active_domains_min", "tl3_total", "tl4_total"}

    def test_threshold_ref_matches_the_single_tl_implementation(self):
        # DP1: the disclosure is read off the constants derive_tl compares
        # against, so a floor cannot move in one place and not the other.
        from v3.scoring import thresholds as S
        published = threat_level.threshold_ref()
        assert published["tl1_total"] == S.TL1_SCORE_FLOOR == 9.0
        assert published["tl1_physical"] == S.TL1_PHYSICAL_FLOOR == 3.0
        assert published["tl2_total"] == S.TL2_SCORE_FLOOR == 6.0
        assert published["tl2_active_domains_min"] == S.TL2_MIN_DOMAINS == 2
        assert published["tl3_total"] == S.TL3_SCORE_FLOOR == 4.0
        assert published["tl4_total"] == S.TL4_SCORE_FLOOR == 2.0

    def test_the_rationale_matrix_sorts_by_absolute_contribution(self):
        conclusion = threat_level.derive(context(
            result=scoring_result(contributions=(
                contribution(signal_source="small", score=0.4),
                contribution(signal_source="big", score=-3.2),
                contribution(signal_source="mid", score=1.1)))))
        order = [row["signal_source"]
                 for row in conclusion.metadata["rationale_matrix"]]
        assert order == ["big", "mid", "small"]

    def test_the_matrix_is_an_empty_list_when_nothing_contributed(self):
        conclusion = threat_level.derive(context())
        assert conclusion.metadata["rationale_matrix"] == []

    def test_the_matrix_is_present_on_an_unavailable_row(self):
        conclusion = threat_level.derive(context(
            result=None,
            health=healthy(),
        ))
        assert conclusion.unavailable_reason == V.INSUFFICIENT_DATA
        assert "rationale_matrix" in conclusion.metadata

    def test_a_scenario_that_did_not_score_still_yields_a_row(self):
        conclusion = threat_level.derive(context(result=None))
        assert conclusion.conclusion_type == V.THREAT_LEVEL

    def test_source_urls_are_a_sorted_unique_set(self):
        ctx = context(
            result=scoring_result(contributions=(
                contribution(signal_source="b"),
                contribution(signal_source="a"),
                contribution(signal_source="b"))),
            evidence_urls={"a": "https://z.example", "b": "https://a.example"})
        conclusion = threat_level.derive(ctx)
        assert conclusion.source_urls == ("https://a.example",
                                          "https://z.example")

    def test_the_provenance_names_the_clause_range(self):
        conclusion = threat_level.derive(context())
        assert conclusion.provenance.formula_ref.endswith("S1-CONC-009..013")

    def test_the_provenance_carries_the_source_urls(self):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"),)),
            evidence_urls={"a": "https://a.example"})
        assert threat_level.derive(ctx).provenance.source_refs == \
            ("https://a.example",)


# ── TREND ────────────────────────────────────────────────────────────────

class TestTrendClassification:
    @pytest.mark.parametrize("delta,expected", [
        (1.5, "ESCALATING"), (1.49, "RISING"), (0.5, "RISING"),
        (0.49, "STABLE"), (0.0, "STABLE"), (-0.49, "STABLE"),
        (-0.5, "COOLING"), (-1.49, "COOLING"), (-1.5, "DEEPER_DECAY"),
    ])
    def test_the_bands_are_pinned_at_their_numbers(self, delta, expected):
        assert trend_module.classify(delta) == expected

    def test_the_state_string_packs_three_windows_in_order(self):
        packed = trend_module.pack({"short_term": "RISING",
                                    "medium_term": "STABLE",
                                    "long_term": "COOLING"})
        assert packed == ("short_term=RISING;medium_term=STABLE;"
                          "long_term=COOLING")

    def test_the_windows_are_one_seven_and_thirty_days(self):
        assert trend_module.WINDOW_DAYS == (("short_term", 1.0),
                                            ("medium_term", 7.0),
                                            ("long_term", 30.0))

    def test_min_samples_is_three(self):
        from v3.conclusions import thresholds as T
        assert T.TREND_MIN_SAMPLES == 3

    def test_confidence_rewards_density_and_caps(self):
        counts = {label: {"current_n": 100, "previous_n": 100}
                  for label, _ in trend_module.WINDOW_DAYS}
        assert trend_module.confidence_for(
            counts, any_unavailable=False) == 0.9

    def test_confidence_is_penalised_once_for_partial_availability(self):
        counts = {"short_term": {"current_n": 5, "previous_n": 5},
                  "medium_term": {"current_n": 0, "previous_n": 0},
                  "long_term": {"current_n": 0, "previous_n": 0}}
        assert trend_module.confidence_for(counts, any_unavailable=True) == \
            round(min(0.30, 0.15 + 5 * 0.01) - 0.15, 3)

    def test_confidence_is_zero_when_no_window_qualifies(self):
        counts = {label: {"current_n": 1, "previous_n": 1}
                  for label, _ in trend_module.WINDOW_DAYS}
        assert trend_module.confidence_for(counts, any_unavailable=True) == 0.0


class TestTrendIsADerivedView:
    """Condition 6: the trend is a query over L1's stream, not a lane."""

    def _worsening(self, tmp_path):
        # Previous 24h at TL5 (severity 1), current 24h at TL2 (severity 4).
        hour = 3600.0
        series = ([(NOW - 47 * hour + i * hour, 5) for i in range(6)]
                  + [(NOW - 20 * hour + i * hour, 2) for i in range(6)])
        return store_with_tl(tmp_path, "taiwan_contingency", series)

    def test_it_reads_the_tl_stream_and_classifies_the_delta(self, tmp_path):
        store = self._worsening(tmp_path)
        try:
            windows = trend_module.evaluate_windows(
                store, "taiwan_contingency", now=NOW, cadence_sec=3600.0)
        finally:
            store.close()
        assert windows["short_term"]["state"] == "ESCALATING"
        assert windows["short_term"]["delta_severity"] == 3.0

    def test_severity_is_six_minus_tl_everywhere(self, tmp_path):
        store = store_with_tl(tmp_path, "s",
                              [(NOW - 3600 * (6 - i), 5) for i in range(3)]
                              + [(NOW - 1800, 5)])
        try:
            windows = trend_module.evaluate_windows(
                store, "s", now=NOW, cadence_sec=1800.0)
        finally:
            store.close()
        # TL5 under 6-TL is severity 1, not 0 (the legacy private scale).
        assert windows["short_term"]["current_mean_severity"] == 1.0

    def test_other_scenarios_are_not_mixed_in(self, tmp_path):
        store = self._worsening(tmp_path)
        try:
            windows = trend_module.evaluate_windows(
                store, "other_scenario", now=NOW, cadence_sec=3600.0)
        finally:
            store.close()
        assert windows["short_term"]["state"] is None

    def test_null_zone_rows_are_excluded_from_the_means(self, tmp_path):
        hour = 3600.0
        series = ([(NOW - 47 * hour + i * hour, None) for i in range(6)]
                  + [(NOW - 20 * hour + i * hour, 2) for i in range(6)])
        store = store_with_tl(tmp_path, "s", series)
        try:
            windows = trend_module.evaluate_windows(
                store, "s", now=NOW, cadence_sec=3600.0)
        finally:
            store.close()
        assert windows["short_term"]["previous_n"] == 0
        assert windows["short_term"]["state"] is None

    def test_all_windows_short_yields_insufficient_data(self, store):
        conclusion = trend_module.derive(context(), store=store,
                                         cadence_sec=3600.0)
        assert conclusion.unavailable_reason == V.INSUFFICIENT_DATA
        assert conclusion.suppression.guard_id == "derivation_produced_nothing"

    def test_one_usable_window_is_enough_to_publish(self, tmp_path):
        store = self._worsening(tmp_path)
        try:
            conclusion = trend_module.derive(
                context(), store=store, cadence_sec=3600.0)
        finally:
            store.close()
        assert conclusion.is_available
        assert conclusion.state.startswith("short_term=ESCALATING")

    def test_it_never_reports_source_urls(self, tmp_path):
        store = self._worsening(tmp_path)
        try:
            conclusion = trend_module.derive(
                context(), store=store, cadence_sec=3600.0)
        finally:
            store.close()
        assert conclusion.source_urls == ()
        assert conclusion.provenance.source_refs == ()

    def test_sample_counts_are_always_disclosed(self, store):
        conclusion = trend_module.derive(context(), store=store,
                                         cadence_sec=3600.0)
        assert set(conclusion.metadata["sample_counts"]) == {
            "short_term", "medium_term", "long_term"}

    def test_the_module_keeps_no_state_between_calls(self, tmp_path):
        store = self._worsening(tmp_path)
        try:
            first = trend_module.derive(context(), store=store,
                                        cadence_sec=3600.0)
            second = trend_module.derive(context(), store=store,
                                         cadence_sec=3600.0)
        finally:
            store.close()
        assert first.state == second.state


# ── PER_DOMAIN ───────────────────────────────────────────────────────────

class TestPerDomain:
    @pytest.mark.parametrize("current,prior,expected", [
        (0.0, None, "INSUFFICIENT_SIGNAL"),
        (-1.0, None, "INSUFFICIENT_SIGNAL"),
        (2.5, None, "ACTIVE"),
        (2.49, None, "ELEVATED"),
        (1.5, None, "ELEVATED"),
        (1.49, None, "STABLE"),
        (2.0, 3.0, "DEGRADING"),
        (2.0, 2.9, "ELEVATED"),
        (2.5, 5.0, "ACTIVE"),
    ])
    def test_the_ladder_is_pinned_at_its_numbers(self, current, prior,
                                                 expected):
        assert per_domain.classify(current, prior) == expected

    def test_degrading_outranks_elevated_as_production_does(self):
        # ACCIDENTAL A6, preserved on purpose: 4.0 -> 2.0 reads DEGRADING
        # and the absolute level vanishes from the state.
        assert per_domain.classify(2.0, 4.0) == "DEGRADING"

    def test_no_prior_means_degrading_cannot_fire(self):
        assert per_domain.classify(2.0, None) == "ELEVATED"

    def test_the_state_packs_three_domains_in_canonical_order(self):
        conclusion = per_domain.derive(context(result=scoring_result(
            domains={"cyber": 3.0, "physical": 0.0, "info": 1.6})))
        assert conclusion.state == ("cyber=ACTIVE;physical=INSUFFICIENT_SIGNAL;"
                                    "info=ELEVATED")

    def test_confidence_is_half_breadth_half_magnitude(self):
        conclusion = per_domain.derive(context(result=scoring_result(
            domains={"cyber": 3.0, "physical": 3.0, "info": 0.0})))
        # breadth 2/3, magnitude 6/12
        assert conclusion.confidence == round(0.5 * (2 / 3) + 0.5 * 0.5, 3)

    def test_all_domains_silent_yields_insufficient_data(self):
        conclusion = per_domain.derive(context(result=scoring_result(
            domains={"cyber": 0.0, "physical": 0.0, "info": 0.0})))
        assert conclusion.unavailable_reason == V.INSUFFICIENT_DATA

    def test_one_signalled_domain_is_enough(self):
        conclusion = per_domain.derive(context(result=scoring_result(
            domains={"cyber": 0.2, "physical": 0.0, "info": 0.0})))
        assert conclusion.is_available

    def test_source_urls_only_cover_the_three_known_domains(self):
        ctx = context(
            result=scoring_result(contributions=(
                contribution(signal_source="known", domain="cyber"),
                contribution(signal_source="odd", domain="weather"))),
            evidence_urls={"known": "https://k.example",
                           "odd": "https://o.example"})
        assert per_domain.derive(ctx).source_urls == ("https://k.example",)

    def test_prior_scores_are_disclosed_on_the_row(self):
        conclusion = per_domain.derive(context(
            result=scoring_result(domains={"cyber": 2.0, "physical": 0.0,
                                           "info": 0.0}),
            prior_domain_scores={"cyber": 4.0}))
        assert conclusion.metadata["prior_domain_scores"] == {"cyber": 4.0}
        assert conclusion.metadata["domain_states"]["cyber"] == "DEGRADING"

    def test_a_degrading_but_elevated_domain_is_still_alerting(self):
        # A6 labels 3.5 -> 2.4 as DEGRADING, which reads calm. Reading the
        # LABEL to decide alertness would let a degraded-input guard
        # suppress a domain well above the elevated floor — the
        # insensitive direction NP1 forbids. Alertness comes from the
        # score.
        conclusion = per_domain.derive(ScenarioContext(
            scenario_id="s", now=NOW,
            health=InputHealth(sources_failed=("a", "b")),
            result=scoring_result(scenario_id="s",
                                  domains={"cyber": 2.4, "physical": 0.0,
                                           "info": 0.0}),
            prior_domain_scores={"cyber": 3.5}))
        assert conclusion.metadata["domain_states"]["cyber"] == "DEGRADING"
        assert conclusion.is_available
        assert conclusion.suppression.overridden is True

    def test_a_genuinely_quiet_domain_set_stays_suppressible(self):
        conclusion = per_domain.derive(ScenarioContext(
            scenario_id="s", now=NOW,
            health=InputHealth(sources_failed=("a", "b")),
            result=scoring_result(scenario_id="s",
                                  domains={"cyber": 0.4, "physical": 0.0,
                                           "info": 0.0})))
        assert conclusion.unavailable_reason == V.UPSTREAM_FAILURE

    def test_an_active_domain_is_alerting_so_health_cannot_hide_it(self):
        conclusion = per_domain.derive(ScenarioContext(
            scenario_id="s", now=NOW,
            health=InputHealth(sources_failed=("a",), history_span_sec=0.0),
            result=scoring_result(scenario_id="s",
                                  domains={"cyber": 3.0, "physical": 0.0,
                                           "info": 0.0})))
        assert conclusion.is_available
        assert conclusion.suppression.overridden is True


# ── ANOMALY ──────────────────────────────────────────────────────────────

class TestAnomaly:
    def test_recency_is_a_one_over_e_time_constant_at_twelve_hours(self):
        assert anomaly.recency_decay(12.0) == pytest.approx(1 / math.e)

    def test_future_timestamps_do_not_amplify(self):
        assert anomaly.recency_decay(-5.0) == 1.0

    def test_novelty_drops_with_repetition_and_floors_at_zero_point_three(self):
        assert anomaly.novelty_factor(0) == 1.0
        assert anomaly.novelty_factor(5) == 0.5
        assert anomaly.novelty_factor(50) == 0.3

    def test_importance_is_the_product_of_four_factors_times_100(self):
        assert anomaly.importance_for(raw_score=2.0, decay=0.5,
                                      relevance=0.5, novelty=1.0) == 50.0

    def test_importance_is_clamped_at_one_hundred(self):
        assert anomaly.importance_for(raw_score=90.0, decay=1.0,
                                      relevance=1.0, novelty=1.0) == 100.0

    def test_global_relevance_uses_the_participant_weight_only(self):
        item = contribution(country="GLOBAL", llm_country_weight=0.2,
                            participant_weight=0.4)
        assert anomaly.scenario_relevance(item) == 0.4

    def test_country_relevance_multiplies_both_weights(self):
        item = contribution(llm_country_weight=0.5, participant_weight=0.4)
        assert anomaly.scenario_relevance(item) == pytest.approx(0.2)

    def test_it_returns_one_row_per_positive_contribution(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"), contribution(signal_source="b"))))
        rows = anomaly.derive(ctx, store=store)
        assert len(rows) == 2

    def test_non_positive_contributions_are_excluded(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a", raw_score=0.0),
            contribution(signal_source="b", raw_score=-1.0))))
        rows = anomaly.derive(ctx, store=store)
        assert len(rows) == 1 and rows[0].unavailable_reason == \
            V.INSUFFICIENT_DATA

    def test_no_contributions_yields_exactly_one_unavailable_row(self, store):
        rows = anomaly.derive(context(), store=store)
        assert len(rows) == 1
        assert rows[0].unavailable_reason == V.INSUFFICIENT_DATA

    def test_it_never_returns_an_empty_tuple(self, store):
        assert anomaly.derive(context(result=None), store=store)

    def test_the_state_is_the_signal_source_alone(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="cf_botnet_overlap"),)))
        rows = anomaly.derive(ctx, store=store)
        assert rows[0].state == "cf_botnet_overlap"

    def test_the_free_text_lives_in_metadata_not_in_the_state(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="cf_botnet_overlap"),)))
        rows = anomaly.derive(ctx, store=store)
        assert rows[0].metadata["value_display"]
        assert rows[0].metadata["value_display"] != rows[0].state

    def test_rows_are_ranked_by_importance(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="small", raw_score=0.5),
            contribution(signal_source="large", raw_score=5.0))))
        rows = anomaly.derive(ctx, store=store)
        assert [row.state for row in rows] == ["large", "small"]

    def test_the_default_limit_is_ten_and_is_actually_applied(self, store):
        # L-4: the only surviving mutant. `test_the_limit_truncates`
        # passes anomaly_limit=3 explicitly, so the DEFAULT could be set
        # to 1 with the whole behavioural suite green.
        ctx = context(result=scoring_result(contributions=tuple(
            contribution(signal_source=f"s{i}", raw_score=float(i + 1))
            for i in range(14))))
        assert len(anomaly.derive(ctx, store=store)) == 10

    def test_the_limit_truncates(self, store):
        ctx = context(
            result=scoring_result(contributions=tuple(
                contribution(signal_source=f"s{i}", raw_score=float(i + 1))
                for i in range(12))),
            anomaly_limit=3)
        assert len(anomaly.derive(ctx, store=store)) == 3

    def test_every_factor_is_disclosed_on_the_row(self, store):
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"),)))
        metadata = anomaly.derive(ctx, store=store)[0].metadata
        assert {"raw_score", "recency_decay", "scenario_relevance",
                "novelty_factor", "novelty_similar_count", "elapsed_hours",
                "importance_score", "novelty_source"} <= set(metadata)

    def test_novelty_counts_come_from_the_unthinned_signal_stream(
            self, tmp_path):
        from v3.kernel import Evidence
        from v3.ledger import LedgerStore, SignalObservation
        store = LedgerStore(str(tmp_path / "v3.db"))
        try:
            for index in range(4):
                store.append_signal(SignalObservation(
                    tick_id=f"t{index}", sensor="ripe_bgp",
                    signal_source="bgp", domain="cyber", country="TW",
                    evidence=Evidence.observe(
                        {"n": index}, observed_at=NOW - 600 * index,
                        source="https://x.example",
                        freshness_horizon_sec=86400.0),
                    status="FIRED"), NOW)
            ctx = context(
                result=scoring_result(contributions=(
                    contribution(signal_source="bgp"),)),
                participants=("TW",))
            rows = anomaly.derive(ctx, store=store)
        finally:
            store.close()
        assert rows[0].metadata["novelty_similar_count"] == 4
        assert rows[0].metadata["novelty_factor"] == 0.6
        assert rows[0].metadata["novelty_source"] == "signal_stream_fired_24h"

    def test_polls_do_not_count_as_repetitions(self, tmp_path):
        # C-2: signal_observation holds one row per POLL. Counting the
        # table made a healthy quiet sensor look like ~96 repetitions a
        # day, saturating novelty at its 0.3 floor for every source and
        # deflating published importance and confidence by more than 3x
        # behind a label that still read healthy.
        from v3.kernel import Evidence
        from v3.ledger import LedgerStore, SignalObservation
        store = LedgerStore(str(tmp_path / "v3.db"))
        try:
            for index in range(40):
                store.append_signal(SignalObservation(
                    tick_id=f"t{index}", sensor="ripe_bgp",
                    signal_source="bgp", domain="cyber", country="TW",
                    evidence=Evidence.observe(
                        {"n": index}, observed_at=NOW - 600 * index,
                        source="https://x.example",
                        freshness_horizon_sec=86400.0),
                    status="OK"), NOW)
            ctx = context(
                result=scoring_result(contributions=(
                    contribution(signal_source="bgp"),)),
                participants=("TW",))
            rows = anomaly.derive(ctx, store=store)
        finally:
            store.close()
        assert rows[0].metadata["novelty_similar_count"] == 0
        assert rows[0].metadata["novelty_factor"] == 1.0

    def test_a_saturating_number_of_firings_still_reaches_the_floor(
            self, tmp_path):
        from v3.kernel import Evidence
        from v3.ledger import LedgerStore, SignalObservation
        store = LedgerStore(str(tmp_path / "v3.db"))
        try:
            for index in range(12):
                store.append_signal(SignalObservation(
                    tick_id=f"t{index}", sensor="ripe_bgp",
                    signal_source="bgp", domain="cyber", country="TW",
                    evidence=Evidence.observe(
                        {"n": index}, observed_at=NOW - 600 * index,
                        source="https://x.example",
                        freshness_horizon_sec=86400.0),
                    status="FIRED"), NOW)
            ctx = context(
                result=scoring_result(contributions=(
                    contribution(signal_source="bgp"),)),
                participants=("TW",))
            rows = anomaly.derive(ctx, store=store)
        finally:
            store.close()
        # Twelve firings in a day IS repetitive; the floor is correct here
        # and only here.
        assert rows[0].metadata["novelty_similar_count"] == 12
        assert rows[0].metadata["novelty_factor"] == 0.3

    def test_the_lookback_window_is_twenty_four_hours(self, tmp_path):
        # The last surviving mutant: every other novelty test placed its
        # firings within a couple of hours, so the window could shrink to
        # ~9h with the suite green. One firing just inside the horizon and
        # one just outside pins it.
        from v3.kernel import Evidence
        from v3.ledger import LedgerStore, SignalObservation
        store = LedgerStore(str(tmp_path / "v3.db"))
        try:
            for index, age_hours in enumerate((1.0, 23.0, 25.0, 40.0)):
                store.append_signal(SignalObservation(
                    tick_id=f"t{index}", sensor="ripe_bgp",
                    signal_source="bgp", domain="cyber", country="TW",
                    evidence=Evidence.observe(
                        {"n": index}, observed_at=NOW - age_hours * 3600.0,
                        source="https://x.example",
                        freshness_horizon_sec=200000.0),
                    status="FIRED"), NOW)
            ctx = context(
                result=scoring_result(contributions=(
                    contribution(signal_source="bgp"),)),
                participants=("TW",))
            rows = anomaly.derive(ctx, store=store)
        finally:
            store.close()
        # 1h and 23h are inside the 24h horizon; 25h and 40h are not.
        assert rows[0].metadata["novelty_similar_count"] == 2
        from v3.conclusions import thresholds as T
        assert T.ANOMALY_NOVELTY_LOOKBACK_SEC == 86400.0

    def test_an_unscoped_count_says_so(self, store):
        # M-6: with no participants the count is scoped to GLOBAL alone,
        # which under-counts, which raises importance — the safe
        # direction, but silent unless labelled.
        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"),)))
        rows = anomaly.derive(ctx, store=store)
        assert rows[0].metadata["novelty_source"] == \
            "signal_stream_fired_24h_unscoped"

    def test_a_read_failure_degrades_every_source_together(self):
        # H-4: a per-source fallback gives the failed source novelty 1.0
        # while its neighbours keep their real factor, reordering the
        # ranking and letting a fallback row displace a higher-scoring
        # real one out of the anomaly_limit window — a miss caused by a
        # read error. Uniform degradation preserves the order.
        class FlakyOnce:
            def __init__(self):
                self.calls = 0

            def count_signal_source_observations(self, *, signal_source,
                                                 **_):
                self.calls += 1
                if signal_source == "flaky":
                    raise RuntimeError("timeout")
                return 9

        ctx = context(
            result=scoring_result(contributions=(
                contribution(signal_source="real", raw_score=3.0),
                contribution(signal_source="flaky", raw_score=1.0))),
            anomaly_limit=1, participants=("TW",))
        rows = anomaly.derive(ctx, store=FlakyOnce())
        assert rows[0].state == "real"
        assert all(row.metadata["novelty_factor"] == 1.0 for row in rows)

    def test_a_ledger_read_failure_falls_back_to_full_novelty(self):
        class Broken:
            def count_signal_source_observations(self, **_):
                raise RuntimeError("db gone")

        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"),)))
        rows = anomaly.derive(ctx, store=Broken())
        assert rows[0].metadata["novelty_factor"] == 1.0
        assert rows[0].metadata["novelty_source"].startswith(
            "signal_stream_fired_24h_fallback_empty")

    def test_the_degraded_path_is_labelled_not_silent(self):
        class Broken:
            def count_signal_source_observations(self, **_):
                raise RuntimeError("db gone")

        ctx = context(result=scoring_result(contributions=(
            contribution(signal_source="a"),)))
        rows = anomaly.derive(ctx, store=Broken())
        # The exception CLASS travels with the label: a broad catch
        # that says only "degraded" cannot distinguish a dead database
        # from a store-API signature drift, and the second one degrades
        # every anomaly at once with nothing to grep for.
        assert rows[0].provenance.inputs["novelty_source"] == \
            "signal_stream_fired_24h_fallback_empty:RuntimeError"

    def test_each_row_carries_only_its_own_evidence_url(self, store):
        ctx = context(
            result=scoring_result(contributions=(
                contribution(signal_source="a"),
                contribution(signal_source="b"))),
            evidence_urls={"a": "https://a.example", "b": "https://b.example"})
        rows = anomaly.derive(ctx, store=store)
        assert {row.state: row.source_urls for row in rows} == {
            "a": ("https://a.example",), "b": ("https://b.example",)}


# ── ATTACK_MODE ──────────────────────────────────────────────────────────

class TestAttackMode:
    def test_ddos_precursor_fires_at_its_floors(self):
        matches = attack_mode.apply_rules(
            {"cyber": 1.2, "physical": 0.0, "info": 0.8}, ())
        assert [m.mode for m in matches] == ["DDOS_PRECURSOR"]
        assert matches[0].confidence == 0.55

    def test_ddos_precursor_does_not_fire_below_the_cyber_floor(self):
        matches = attack_mode.apply_rules(
            {"cyber": 1.19, "physical": 0.0, "info": 0.8}, ())
        assert not any(m.mode == "DDOS_PRECURSOR" for m in matches)

    def test_the_cyber_floor_is_one_point_two_not_five(self):
        from v3.conclusions import thresholds as T
        assert T.ATTACK_CYBER_DDOS_FLOOR == 1.2

    def test_the_info_narrative_floor_gates_ddos_precursor(self):
        # Found by mutation: with only the cyber floor pinned, dropping
        # INFO_NARRATIVE_FLOOR from 0.8 to 0.05 passed every behavioural
        # test. That is GAP-01's exact shape reproduced in a new suite, so
        # the info side gets its own boundary pair.
        assert not attack_mode.apply_rules(
            {"cyber": 3.0, "physical": 0.0, "info": 0.79}, ())
        assert [m.mode for m in attack_mode.apply_rules(
            {"cyber": 3.0, "physical": 0.0, "info": 0.8}, ())] == \
            ["DDOS_PRECURSOR"]

    def test_the_info_narrative_floor_gates_info_ops_dominant(self):
        assert not attack_mode.apply_rules(
            {"cyber": 0.0, "physical": 0.0, "info": 0.79}, ())
        assert [m.mode for m in attack_mode.apply_rules(
            {"cyber": 0.0, "physical": 0.0, "info": 0.8}, ())] == \
            ["INFO_OPS_DOMINANT"]

    def test_the_info_narrative_floor_is_zero_point_eight(self):
        from v3.conclusions import thresholds as T
        assert T.ATTACK_INFO_NARRATIVE_FLOOR == 0.8

    def test_the_hybrid_floor_gates_each_domain_independently(self):
        for low in ("cyber", "physical", "info"):
            scores = {"cyber": 0.8, "physical": 0.8, "info": 0.8}
            scores[low] = 0.79
            assert not any(m.mode == "HYBRID_PRESSURE"
                           for m in attack_mode.apply_rules(
                               scores, ("A", "B", "C", "D"))), low

    def test_kinetic_preparation_fires_at_its_floor(self):
        matches = attack_mode.apply_rules(
            {"cyber": 0.0, "physical": 1.0, "info": 0.0}, ())
        assert [m.mode for m in matches] == ["KINETIC_PREPARATION"]
        assert matches[0].confidence == 0.55

    def test_kinetic_confidence_saturates_at_the_ceiling(self):
        matches = attack_mode.apply_rules(
            {"cyber": 0.0, "physical": 9.0, "info": 0.0}, ())
        assert matches[0].confidence == 0.95

    def test_the_margin_denominator_is_max_floor_one(self):
        # physical 1.5 with floor 1.0: margin = 0.5, conf = 0.55 + 0.2
        matches = attack_mode.apply_rules(
            {"cyber": 0.0, "physical": 1.5, "info": 0.0}, ())
        assert matches[0].confidence == 0.75

    def test_hybrid_pressure_needs_all_three_domains_and_a_cluster(self):
        scores = {"cyber": 0.8, "physical": 0.8, "info": 0.8}
        assert not any(m.mode == "HYBRID_PRESSURE"
                       for m in attack_mode.apply_rules(scores, ("A", "B", "C")))
        assert any(m.mode == "HYBRID_PRESSURE"
                   for m in attack_mode.apply_rules(
                       scores, ("A", "B", "C", "D")))

    def test_hybrid_confidence_uses_the_cluster_and_domain_sum(self):
        matches = [m for m in attack_mode.apply_rules(
            {"cyber": 1.0, "physical": 1.0, "info": 1.0},
            ("A", "B", "C", "D")) if m.mode == "HYBRID_PRESSURE"]
        assert matches[0].confidence == round(0.50 + 0.05 * 4 + 0.02 * 3.0, 3)

    def test_info_ops_dominant_needs_the_dominance_ratio(self):
        assert not any(m.mode == "INFO_OPS_DOMINANT"
                       for m in attack_mode.apply_rules(
                           {"cyber": 1.0, "physical": 0.0, "info": 1.4}, ()))
        assert any(m.mode == "INFO_OPS_DOMINANT"
                   for m in attack_mode.apply_rules(
                       {"cyber": 1.0, "physical": 0.0, "info": 1.5}, ()))

    def test_the_dominance_confidence_divides_by_the_other_domain_max(self):
        # The predicate divides by a bare `other_max` gated on > 0; the
        # confidence divides by max(other_max, 0.1). Pinning the ordinary
        # case (other_max >= 0.1, so the epsilon is transparent) is what
        # kills a mutated epsilon — found by mutation, which showed 0.1
        # could be raised to 2.0 with the whole suite still green.
        matches = [m for m in attack_mode.apply_rules(
            {"cyber": 1.0, "physical": 0.0, "info": 3.0}, ())
            if m.mode == "INFO_OPS_DOMINANT"]
        assert matches[0].confidence == round(0.55 + 0.10 * 3.0, 3)

    def test_the_epsilon_itself_is_unreachable_at_its_pinned_value(self):
        # A recorded fact, not an assertion of intent: the rule needs
        # info >= 0.8, so whenever other_max < 0.1 the quotient is at
        # least 8 and 0.55 + 0.8 exceeds the 0.95 ceiling. At 0.1 the
        # floor therefore changes no published number. It is transcribed
        # because production has it, and this test says why nothing
        # observes it — so a later reader does not "simplify" it away and
        # find out the hard way that a smaller info floor would.
        from v3.conclusions import thresholds as T
        assert T.ATTACK_INFO_DOMINANCE_EPSILON == 0.1
        capped = [m for m in attack_mode.apply_rules(
            {"cyber": 0.05, "physical": 0.0, "info": 0.8}, ())
            if m.mode == "INFO_OPS_DOMINANT"]
        assert capped[0].confidence == T.ATTACK_CONFIDENCE_CEILING

    def test_pure_info_takes_the_fixed_confidence(self):
        matches = attack_mode.apply_rules(
            {"cyber": 0.0, "physical": 0.0, "info": 0.8}, ())
        assert [(m.mode, m.confidence) for m in matches] == \
            [("INFO_OPS_DOMINANT", 0.65)]

    def test_rules_are_not_exclusive(self):
        matches = attack_mode.apply_rules(
            {"cyber": 2.0, "physical": 2.0, "info": 3.5},
            ("A", "B", "C", "D"))
        assert len(matches) == 4

    def test_the_top_mode_becomes_the_state_and_all_are_ranked(self):
        conclusion = attack_mode.derive(context(result=scoring_result(
            domains={"cyber": 2.0, "physical": 2.0, "info": 3.5},
            active_countries=("A", "B", "C", "D"))))
        ranked = conclusion.metadata["ranked_modes"]
        assert conclusion.state == ranked[0]["mode"]
        assert [entry["confidence"] for entry in ranked] == \
            sorted((entry["confidence"] for entry in ranked), reverse=True)

    def test_every_ranked_entry_explains_its_rule(self):
        conclusion = attack_mode.derive(context(result=scoring_result(
            domains={"cyber": 2.0, "physical": 2.0, "info": 3.5},
            active_countries=("A", "B", "C", "D"))))
        assert all(entry["rule"].strip()
                   for entry in conclusion.metadata["ranked_modes"])

    def test_a_low_confidence_top_mode_is_flagged_tentative(self):
        conclusion = attack_mode.derive(context(result=scoring_result(
            domains={"cyber": 0.0, "physical": 0.0, "info": 0.8})))
        assert conclusion.metadata["is_tentative"] is False
        low = attack_mode.derive(context(result=scoring_result(
            domains={"cyber": 1.2, "physical": 0.0, "info": 0.8})))
        assert low.metadata["is_tentative"] is True

    def test_no_rule_matching_is_unavailable_not_an_all_clear(self):
        conclusion = attack_mode.derive(context(result=scoring_result(
            domains={"cyber": 0.0, "physical": 0.0, "info": 0.0})))
        assert conclusion.unavailable_reason == V.INSUFFICIENT_DATA
        assert conclusion.state is None
        assert "NOT a finding" in conclusion.metadata["reason_detail"]

    def test_the_unavailable_row_keeps_the_domain_scores_it_looked_at(self):
        conclusion = attack_mode.derive(context(result=scoring_result(
            domains={"cyber": 0.1, "physical": 0.0, "info": 0.0})))
        assert conclusion.metadata["domain_scores"]["cyber"] == 0.1
        assert conclusion.metadata["active_countries_n"] == 1

    def test_a_fired_mode_is_alerting_and_survives_degraded_inputs(self):
        conclusion = attack_mode.derive(ScenarioContext(
            scenario_id="s", now=NOW,
            health=InputHealth(sources_ok=("a",), sources_stale=("b", "c"),
                               history_span_sec=0.0),
            result=scoring_result(scenario_id="s",
                                  domains={"cyber": 0.0, "physical": 3.0,
                                           "info": 0.0})))
        assert conclusion.state == "KINETIC_PREPARATION"
        assert conclusion.suppression.overridden is True


# ── the orchestrator ─────────────────────────────────────────────────────

class TestDeriveAll:
    def test_every_type_appears_for_a_healthy_tick(self, store):
        produced = derive_all(context(), store=store)
        assert {item.conclusion_type for item in produced} == \
            set(V.CONCLUSION_TYPES)

    def test_every_type_appears_when_nothing_scored(self, store):
        produced = derive_all(context(result=None), store=store)
        assert {item.conclusion_type for item in produced} == \
            set(V.CONCLUSION_TYPES)

    def test_every_type_appears_when_the_pipeline_is_dead(self, store):
        produced = derive_all(
            context(result=None,
                    health=InputHealth(sources_failed=("a", "b"))),
            store=store)
        assert {item.conclusion_type for item in produced} == \
            set(V.CONCLUSION_TYPES)
        assert all(item.unavailable_reason == V.UPSTREAM_FAILURE
                   for item in produced)

    def test_a_type_is_never_silently_dropped(self, store):
        for result in (None, scoring_result(), scoring_result(tl=1, score=9.0)):
            produced = derive_all(context(result=result), store=store)
            assert len(set(item.conclusion_type for item in produced)) == 5

    def test_the_bundle_takes_the_newest_row_per_type(self, store):
        produced = derive_all(context(), store=store)
        newest = latest_of_each_type(produced)
        assert set(newest) == set(V.CONCLUSION_TYPES)

    def test_all_five_carry_the_np7_disclaimer(self, store):
        produced = derive_all(context(), store=store)
        assert all(item.disclaimer == V.NP7_DISCLAIMER for item in produced)

    def test_all_five_carry_a_provenance(self, store):
        from v3.kernel import Provenance
        produced = derive_all(context(), store=store)
        assert all(isinstance(item.provenance, Provenance)
                   for item in produced)

    def test_all_five_carry_the_input_health(self, store):
        produced = derive_all(context(), store=store)
        assert all(item.input_health.consulted == 4 for item in produced)
