"""WP-2.4 — the L2 scoring kernel, clause by clause.

Every test class here is named in `v3.scoring.registry.IMPLEMENTED`, and
`tests/test_scoring_registry.py` fails if a claimed class stops existing.
The numbers are taken from the S1 books and, where the two disagree, from
the effective production path — the S1 clauses were themselves derived
from tests/test_engine.py and tests/test_scenario_scoring.py, which pin
the same boundaries.
"""
import pytest

from v3.kernel import Ratio, ThreatLevel
from v3.kernel.errors import DomainError, OrderingForbiddenError
from v3.scoring import (CountryWeight, NoiseRule, Observation, Participant,
                        PatternFlags, PriorState, Scenario, ScoringInputs,
                        ScoringSettings, SequenceEvent, apply_hysteresis,
                        convergence_bonus, convergence_level, derive_tl, gate,
                        score_tick)
from v3.scoring import contributions as contrib
from v3.scoring import convergence, sequence, trend
from v3.scoring.gating import (REASON_ANALYST_MUTE, REASON_NOISE_RULE,
                               apply_confidence_penalty)

NOW = 1_700_000_000.0
CYBER, PHYSICAL, INFO = "cyber", "physical", "info"


# ── helpers ───────────────────────────────────────────────────────────────

def taiwan() -> Scenario:
    """The S1 books' worked example, weights included."""
    return Scenario(
        scenario_id="taiwan_contingency", core_country="TW",
        participants=(
            Participant("TW", Ratio(1.0), "primary_target"),
            Participant("US", Ratio(0.8), "primary_ally"),
            Participant("JP", Ratio(0.8), "forward_base"),
            Participant("CN", Ratio(0.7), "adversary"),
        ))


def obs(sensor="cf", domain=CYBER, score=3.0, country="TW", *,
        status="FIRED", source="", suppressed=False, weights=None,
        origin="sensor", value="", observed_at=None) -> Observation:
    if weights is not None:
        countries = tuple(CountryWeight(c, Ratio(w)) for c, w in weights)
    elif country:
        countries = (CountryWeight(country, Ratio(1.0)),)
    else:
        countries = ()
    # WP-2.4 addendum: llm_intel must carry a timestamp. Defaulted to NOW
    # here so the age term is exactly 1.0 and every figure pinned in this
    # file keeps the value it was pinned at; the term itself is exercised
    # in tests/test_scoring_intel_decay.py.
    if observed_at is None and origin == "llm_intel":
        observed_at = NOW
    return Observation(sensor=sensor, domain=domain, status=status,
                       score=score, signal_source=source, countries=countries,
                       suppressed=suppressed, origin=origin, value=value,
                       observed_at=observed_at)


def settings(**overrides) -> ScoringSettings:
    return ScoringSettings(**overrides)


def tick_inputs(observations=(), scenarios=None, *, focused="taiwan_contingency",
                prior=None, arriving=(), series=None, flags=None, chains=None,
                **setting_overrides) -> ScoringInputs:
    return ScoringInputs(
        now=NOW,
        observations=tuple(observations),
        scenarios=tuple(scenarios if scenarios is not None else (taiwan(),)),
        settings=settings(**setting_overrides),
        focused_scenario_id=focused,
        prior=prior or PriorState(),
        arriving_events=tuple(arriving),
        score_series=series or {},
        pattern_flags=flags or {},
        chain_countries=chains or {})


# ── S1-SCORE-004 ──────────────────────────────────────────────────────────

class TestDeriveTL:
    """The single ladder. ADR-V3-004 freezes every boundary here."""

    @pytest.mark.parametrize("score,domains,physical,expected", [
        (10.0, [CYBER, PHYSICAL, INFO], 3.5, 1),
        (10.0, [CYBER, PHYSICAL, INFO], 2.9, 2),   # physical gate missed
        (6.5, [CYBER, INFO], 0.0, 2),
        (7.0, [CYBER], 0.0, 3),                     # domain gate missed
        (4.5, [CYBER], 0.0, 3),
        (2.5, [INFO], 0.0, 4),
        (1.5, [INFO], 0.0, 5),
    ])
    def test_the_pinned_ladder(self, score, domains, physical, expected):
        assert derive_tl(score, domains, physical).value == expected

    @pytest.mark.parametrize("score,domains,physical,expected", [
        (9.0, [CYBER, PHYSICAL], 3.0, 1),   # both TL1 boundaries exactly
        (8.999, [CYBER, PHYSICAL], 3.0, 2),
        (6.0, [CYBER, INFO], 0.0, 2),
        (4.0, [CYBER], 0.0, 3),
        (2.0, [CYBER], 0.0, 4),
        (1.999, [CYBER], 0.0, 5),
    ])
    def test_boundaries_are_inclusive(self, score, domains, physical, expected):
        """GAP-03: S1 left `>=` vs `>` at the boundaries unverified."""
        assert derive_tl(score, domains, physical).value == expected

    def test_tl1_does_not_require_a_domain_count(self):
        """ADR-V3-004 / ACCIDENTAL A6: the deliberate NP2 inversion.

        TL2 demands two domains; TL1, above it, demands none. Ported as-is
        because changing it mid-parity makes every difference
        uninterpretable. Owner ruling deferred to post-cutover L5 stats.
        """
        assert derive_tl(9.0, [PHYSICAL], 3.0).value == 1

    def test_a_string_of_domains_is_refused(self):
        # len("cyber") == 5 would satisfy TL2's gate on one domain.
        with pytest.raises(DomainError):
            derive_tl(7.0, "cyber", 0.0)

    def test_the_result_is_a_kernel_threat_level(self):
        level = derive_tl(10.0, [CYBER, PHYSICAL], 3.5)
        assert isinstance(level, ThreatLevel)
        assert level.severity() == 5

    def test_severity_is_the_only_comparison(self):
        worse = derive_tl(10.0, [CYBER, PHYSICAL], 3.5)
        milder = derive_tl(1.0, [], 0.0)
        assert worse.is_more_severe_than(milder)
        with pytest.raises(OrderingForbiddenError):
            _ = worse < milder


# ── S1-SCORE-005 / S1-PIPE-027 ────────────────────────────────────────────

class TestHysteresis:
    """Fast toward danger, one step at a time away from it (NP1)."""

    def test_first_observation_passes_through(self):
        outcome = apply_hysteresis(ThreatLevel(3), None)
        assert outcome.level.value == 3 and outcome.held is False

    def test_escalation_is_instant(self):
        outcome = apply_hysteresis(ThreatLevel(2), ThreatLevel(5))
        assert outcome.level.value == 2 and outcome.held is False

    def test_de_escalation_is_capped_at_one_step(self):
        outcome = apply_hysteresis(ThreatLevel(5), ThreatLevel(2))
        assert outcome.level.value == 3 and outcome.held is True
        assert outcome.raw.value == 5

    def test_a_single_step_down_is_not_held(self):
        outcome = apply_hysteresis(ThreatLevel(3), ThreatLevel(2))
        assert outcome.level.value == 3 and outcome.held is False

    def test_an_unchanged_level_is_not_held(self):
        outcome = apply_hysteresis(ThreatLevel(3), ThreatLevel(3))
        assert outcome.level.value == 3 and outcome.held is False

    def test_a_raw_int_is_refused(self):
        with pytest.raises(DomainError):
            apply_hysteresis(3, None)

    def test_the_tick_applies_it_to_background_too(self):
        """S1-PIPE-027: the governor is not focused-only."""
        background = Scenario(scenario_id="korea", core_country="KR",
                              participants=(Participant("KR", Ratio(1.0)),))
        inputs = tick_inputs(
            observations=(),
            scenarios=(taiwan(), background),
            prior=PriorState(previous_tl={"korea": ThreatLevel(2)}))
        result = score_tick(inputs).results["korea"]
        assert result.scoring_mode == "lite"
        assert result.raw_threat_level.value == 5
        assert result.threat_level.value == 3 and result.hysteresis_held


# ── S1-SCORE-001 / 015 / 018 ──────────────────────────────────────────────

class TestAdmissionAndDomainTotals:
    def test_only_fired_unsuppressed_positive_readings_score(self):
        admitted = obs(score=3.0)
        assert admitted.admits()
        assert not obs(status="CLEAR").admits()
        assert not obs(suppressed=True).admits()
        assert not obs(score=0.0).admits()

    def test_a_negative_score_is_not_admitted(self):
        """Effective path uses `score <= 0`; S1-SCORE-018 says `== 0`."""
        assert not obs(score=-1.0).admits()

    def test_domain_totals_sum_only_admitted_contributions(self):
        built = contrib.build_contributions(
            (obs(sensor="a", source="s1", score=2.0),
             obs(sensor="b", source="s2", score=3.0),
             obs(sensor="c", source="s3", score=9.0, suppressed=True),
             obs(sensor="d", source="s4", score=9.0, status="CLEAR")),
            taiwan(), settings=settings(), now=NOW)
        totals = contrib.domain_totals(built, domain_cap=6.0)
        assert totals[CYBER] == pytest.approx(5.0)

    def test_the_domain_cap_clips_before_anything_else(self):
        built = contrib.build_contributions(
            (obs(sensor="a", source="s1", score=10.0),), taiwan(),
            settings=settings(), now=NOW)
        assert contrib.domain_totals(built, domain_cap=6.0)[CYBER] == 6.0

    def test_every_domain_is_reported_even_at_zero(self):
        totals = contrib.domain_totals((), domain_cap=6.0)
        assert set(totals) == {CYBER, PHYSICAL, INFO}
        assert all(value == 0.0 for value in totals.values())

    def test_an_empty_signal_source_falls_back_to_the_sensor_name(self):
        assert obs(sensor="ripe_bgp", source="").signal_source == "ripe_bgp"

    def test_a_zero_domain_cap_is_refused(self):
        with pytest.raises(DomainError):
            contrib.domain_totals((), domain_cap=0.0)


# ── S1-SCORE-003 ──────────────────────────────────────────────────────────

class TestConvergenceLevel:
    @pytest.mark.parametrize("count,expected", [
        (0, convergence.NONE),
        (1, convergence.SINGLE_DOMAIN),
        (2, convergence.DUAL_DOMAIN),
        (3, convergence.FULL_CONVERGENCE),
    ])
    def test_the_vocabulary(self, count, expected):
        assert convergence_level(count) == expected

    def test_a_negative_count_is_refused(self):
        with pytest.raises(DomainError):
            convergence_level(-1)


# ── S1-SCORE-007 ──────────────────────────────────────────────────────────

class TestConvergenceBonus:
    def test_three_domains_earn_the_full_bonus(self):
        assert convergence_bonus(3, 2, scenario_specific=False) == 2.0

    def test_two_domains_earn_the_dual_bonus(self):
        assert convergence_bonus(2, 2, scenario_specific=False) == 1.0

    def test_one_domain_earns_nothing(self):
        assert convergence_bonus(1, 1, scenario_specific=False) == 0.0

    def test_a_single_participant_is_downgraded_when_the_gate_is_on(self):
        """NP2: one country flooding three pipes is not convergence."""
        assert convergence_bonus(3, 1, scenario_specific=True) == 1.0

    def test_the_gate_off_keeps_legacy_behaviour(self):
        assert convergence_bonus(3, 1, scenario_specific=False) == 2.0

    def test_the_dual_tier_ignores_the_participant_count(self):
        assert convergence_bonus(2, 1, scenario_specific=True) == 1.0


# ── S1-SCORE-008 ──────────────────────────────────────────────────────────

class TestDedup:
    def test_same_source_same_country_keeps_the_maximum(self):
        built = contrib.build_contributions(
            (obs(sensor="ioda_bgp", source="bgp", score=2.0),
             obs(sensor="ripe_bgp", source="bgp", score=3.0)),
            taiwan(), settings=settings(), now=NOW)
        deduped = contrib.dedup_max(built)
        assert len(deduped) == 1
        assert deduped[0].score == pytest.approx(3.0)

    def test_different_country_is_kept_separately(self):
        built = contrib.build_contributions(
            (obs(sensor="ioda_bgp", source="bgp", score=2.0, country="TW"),
             obs(sensor="ripe_bgp", source="bgp", score=2.0, country="JP")),
            taiwan(), settings=settings(), now=NOW)
        assert len(contrib.dedup_max(built)) == 2

    def test_different_source_same_country_is_kept_separately(self):
        built = contrib.build_contributions(
            (obs(sensor="ioda", source="bgp", score=2.0),
             obs(sensor="cf", source="cloudflare", score=1.5)),
            taiwan(), settings=settings(), now=NOW)
        assert len(contrib.dedup_max(built)) == 2

    def test_a_tie_keeps_the_first_seen(self):
        built = contrib.build_contributions(
            (obs(sensor="first", source="bgp", score=2.0),
             obs(sensor="second", source="bgp", score=2.0)),
            taiwan(), settings=settings(), now=NOW)
        deduped = contrib.dedup_max(built)
        assert len(deduped) == 1 and deduped[0].sensor == "first"


# ── S1-SCORE-009 ──────────────────────────────────────────────────────────

class TestContributionFormula:
    def test_score_is_raw_times_llm_weight_times_participant_weight(self):
        built = contrib.build_contributions(
            (obs(score=3.0, country="US"),), taiwan(), settings=settings(), now=NOW)
        assert built[0].score == pytest.approx(3.0 * 1.0 * 0.8)

    def test_the_trace_records_every_factor(self):
        built = contrib.build_contributions(
            (obs(score=3.0, country="US"),), taiwan(), settings=settings(), now=NOW)
        assert built[0].trace == (
            "3.00 (raw) × 1.00 (llm:US) × 0.80 (participant:US) = 2.40")

    def test_a_non_llm_signal_carries_weight_one(self):
        built = contrib.build_contributions(
            (obs(score=2.0, country="TW"),), taiwan(), settings=settings(), now=NOW)
        assert built[0].llm_country_weight == 1.0


# ── S1-SCORE-010 / 011 / 044 ──────────────────────────────────────────────

class TestParticipantMembership:
    def test_a_non_participant_country_contributes_nothing(self):
        built = contrib.build_contributions(
            (obs(score=5.0, country="FR"),), taiwan(), settings=settings(), now=NOW)
        assert built == ()

    def test_the_adversary_contributes_with_its_own_weight(self):
        built = contrib.build_contributions(
            (obs(score=3.0, country="CN"),), taiwan(), settings=settings(), now=NOW)
        assert built[0].score == pytest.approx(3.0 * 0.7)
        assert built[0].role == "adversary"

    def test_the_adversary_counts_among_active_countries(self):
        built = contrib.build_contributions(
            (obs(score=3.0, country="CN"),), taiwan(), settings=settings(), now=NOW)
        assert contrib.active_countries(built) == ("CN",)


# ── S1-SCORE-012 / 013 ────────────────────────────────────────────────────

class TestGlobalSignals:
    def test_countryless_signals_are_decoupled_by_default(self):
        built = contrib.build_contributions(
            (obs(score=5.0, country=""),), taiwan(), settings=settings(), now=NOW)
        assert built == ()

    def test_they_cannot_light_a_domain_and_satisfy_the_tl2_gate(self):
        """The Phase 9 regression this default exists to prevent."""
        result = score_tick(tick_inputs(observations=(
            obs(sensor="a", source="s1", domain=CYBER, score=5.0, country=""),
            obs(sensor="b", source="s2", domain=INFO, score=5.0, country=""),
        ))).results["taiwan_contingency"]
        assert result.active_domains == ()
        assert result.threat_level.value == 5

    def test_the_legacy_path_weights_them_when_coupling_is_on(self):
        built = contrib.build_contributions(
            (obs(score=4.0, country=""),), taiwan(),
            settings=settings(global_signals_decoupled=False), now=NOW)
        assert built[0].country == "GLOBAL"
        assert built[0].score == pytest.approx(2.0)
        assert built[0].trace == "4.00 (raw) × 0.50 (global) = 2.00"

    def test_global_is_excluded_from_the_participant_count(self):
        built = contrib.build_contributions(
            (obs(score=4.0, country=""),), taiwan(),
            settings=settings(global_signals_decoupled=False), now=NOW)
        assert contrib.active_countries(built) == ()

    def test_the_global_envelope_aggregates_them_separately(self):
        envelope = contrib.global_threat(
            (obs(sensor="a", source="s1", score=4.0, country=""),
             obs(sensor="b", source="s2", domain=INFO, score=2.0, country=""),
             obs(sensor="c", source="s3", score=9.0, country="TW")),
            global_signal_weight=Ratio(0.5), now=NOW)
        assert envelope["score"] == pytest.approx(3.0)
        assert envelope["domains"][CYBER] == pytest.approx(2.0)
        assert set(envelope["sources"]) == {"s1", "s2"}

    def test_the_envelope_is_empty_without_global_signals(self):
        envelope = contrib.global_threat(
            (obs(score=9.0, country="TW"),), global_signal_weight=Ratio(0.5), now=NOW)
        assert envelope["score"] == 0.0 and envelope["sources"] == ()


# ── S1-SCORE-014 ──────────────────────────────────────────────────────────

class TestLlmPrimaryCountry:
    def test_a_secondary_country_below_the_ratio_is_dropped(self):
        built = contrib.build_contributions(
            (obs(score=3.0, weights=(("US", 1.0), ("TW", 0.5)),
                 origin="llm_intel"),), taiwan(), settings=settings(), now=NOW)
        assert {c.country for c in built} == {"US"}

    def test_the_boundary_ratio_is_kept(self):
        """`>=`, so exactly 0.8 survives."""
        built = contrib.build_contributions(
            (obs(score=3.0, weights=(("US", 1.0), ("TW", 0.8)),
                 origin="llm_intel"),), taiwan(), settings=settings(), now=NOW)
        assert {c.country for c in built} == {"US", "TW"}

    def test_just_below_the_boundary_is_dropped(self):
        built = contrib.build_contributions(
            (obs(score=3.0, weights=(("US", 1.0), ("TW", 0.79)),
                 origin="llm_intel"),), taiwan(), settings=settings(), now=NOW)
        assert {c.country for c in built} == {"US"}

    def test_an_override_raises_the_bar(self):
        built = contrib.build_contributions(
            (obs(score=3.0, weights=(("US", 1.0), ("TW", 0.9)),
                 origin="llm_intel"),), taiwan(),
            settings=settings(llm_primary_threshold=Ratio(0.95)), now=NOW)
        assert {c.country for c in built} == {"US"}

    def test_the_flag_off_lets_every_tag_bleed_through(self):
        built = contrib.build_contributions(
            (obs(score=3.0, weights=(("US", 1.0), ("TW", 0.2)),
                 origin="llm_intel"),), taiwan(),
            settings=settings(llm_primary_country_only=False), now=NOW)
        assert {c.country for c in built} == {"US", "TW"}

    def test_a_single_country_sensor_signal_always_passes(self):
        built = contrib.build_contributions(
            (obs(score=3.0, weights=(("TW", 0.1),)),), taiwan(),
            settings=settings(), now=NOW)
        assert {c.country for c in built} == {"TW"}


# ── S1-SCORE-016 / S1-PIPE-025 ────────────────────────────────────────────

class TestFullAndLiteModes:
    def test_one_tick_scores_every_scorable_scenario(self):
        korea = Scenario(scenario_id="korea", core_country="KR",
                         participants=(Participant("KR", Ratio(1.0)),))
        result = score_tick(tick_inputs(
            observations=(obs(score=3.0, country="TW"),),
            scenarios=(taiwan(), korea)))
        assert set(result.results) == {"taiwan_contingency", "korea"}

    def test_focused_is_full_and_the_rest_are_lite(self):
        korea = Scenario(scenario_id="korea", core_country="KR",
                         participants=(Participant("KR", Ratio(1.0)),))
        results = score_tick(tick_inputs(
            scenarios=(taiwan(), korea))).results
        assert results["taiwan_contingency"].scoring_mode == "full"
        assert results["korea"].scoring_mode == "lite"

    def test_background_derives_a_threat_level_with_the_same_ladder(self):
        """NP4: withholding it left 3 of 4 scenarios conclusion-less."""
        korea = Scenario(scenario_id="korea", core_country="KR",
                         participants=(Participant("KR", Ratio(1.0)),))
        results = score_tick(tick_inputs(
            observations=(obs(sensor="a", source="s1", domain=CYBER,
                              score=6.0, country="KR"),
                          obs(sensor="b", source="s2", domain=INFO,
                              score=1.0, country="KR")),
            scenarios=(taiwan(), korea))).results
        assert results["korea"].threat_level.value == 2

    def test_all_scenarios_share_one_observation_set(self):
        korea = Scenario(scenario_id="korea", core_country="KR",
                         participants=(Participant("TW", Ratio(1.0)),))
        results = score_tick(tick_inputs(
            observations=(obs(score=3.0, country="TW"),),
            scenarios=(taiwan(), korea))).results
        assert results["korea"].active_countries == ("TW",)


# ── S1-SCORE-021 / 022 / S1-PIPE-019 ──────────────────────────────────────

class TestSequenceChain:
    def _chain(self, ages_hours, country="TW"):
        types = ("NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY")
        return tuple(
            SequenceEvent(country, name, NOW - hours * 3600.0)
            for name, hours in zip(types, ages_hours))

    def test_a_fresh_full_chain_earns_the_full_bonus(self):
        outcome = sequence.chain_bonus(
            self._chain([0.001] * 4), "TW", now=NOW, full_bonus=3.0,
            partial_bonus=2.0, retention_sec=86400.0)
        assert outcome.bonus == 3.0 and outcome.status == sequence.FULL_CHAIN

    def test_an_eight_hour_old_chain_decays_to_two(self):
        outcome = sequence.chain_bonus(
            self._chain([8.0] * 4), "TW", now=NOW, full_bonus=3.0,
            partial_bonus=2.0, retention_sec=86400.0)
        assert outcome.decay == pytest.approx(2 / 3, abs=1e-6)
        assert outcome.bonus == 2.0

    def test_the_decay_floor_holds_at_point_three(self):
        outcome = sequence.chain_bonus(
            self._chain([20.0] * 4), "TW", now=NOW, full_bonus=3.0,
            partial_bonus=2.0, retention_sec=86400.0)
        assert outcome.decay == pytest.approx(0.3)
        assert outcome.bonus == 1.0

    def test_fewer_than_three_links_earn_nothing(self):
        outcome = sequence.chain_bonus(
            self._chain([0.001, 0.001]), "TW", now=NOW, full_bonus=3.0,
            partial_bonus=2.0, retention_sec=86400.0)
        assert outcome.bonus == 0.0
        assert outcome.status == sequence.INSUFFICIENT_CHAIN

    def test_three_links_earn_the_partial_bonus(self):
        outcome = sequence.chain_bonus(
            self._chain([0.001] * 3), "TW", now=NOW, full_bonus=3.0,
            partial_bonus=2.0, retention_sec=86400.0)
        assert outcome.bonus == 2.0
        assert outcome.status == sequence.PARTIAL_CHAIN

    def test_an_empty_chain_reports_no_events(self):
        outcome = sequence.chain_bonus(
            (), "TW", now=NOW, full_bonus=3.0, partial_bonus=2.0,
            retention_sec=86400.0)
        assert outcome.bonus == 0.0 and outcome.status == sequence.NO_EVENTS

    def test_another_countrys_chain_is_not_borrowed(self):
        outcome = sequence.chain_bonus(
            self._chain([0.001] * 4, country="JP"), "TW", now=NOW,
            full_bonus=3.0, partial_bonus=2.0, retention_sec=86400.0)
        assert outcome.status == sequence.NO_EVENTS

    def test_duplicates_inside_the_window_are_folded(self):
        first = SequenceEvent("TW", "ISR_SURGE", NOW - 10.0)
        second = SequenceEvent("TW", "ISR_SURGE", NOW - 5.0)
        chain = sequence.advance((first,), (second,), now=NOW,
                                 retention_sec=86400.0)
        assert len(chain) == 1

    def test_a_repeat_beyond_the_dedup_window_is_a_new_event(self):
        first = SequenceEvent("TW", "ISR_SURGE", NOW - 400.0)
        second = SequenceEvent("TW", "ISR_SURGE", NOW - 5.0)
        chain = sequence.advance((first,), (second,), now=NOW,
                                 retention_sec=86400.0)
        assert len(chain) == 2

    def test_events_beyond_retention_are_dropped(self):
        stale = SequenceEvent("TW", "ISR_SURGE", NOW - 90000.0)
        chain = sequence.advance((stale,), (), now=NOW, retention_sec=86400.0)
        assert chain == ()

    def test_advance_returns_a_new_chain_and_mutates_nothing(self):
        previous = (SequenceEvent("TW", "ISR_SURGE", NOW - 10.0),)
        chain = sequence.advance(
            previous, (SequenceEvent("TW", "SYNC_DDOS", NOW - 5.0),),
            now=NOW, retention_sec=86400.0)
        assert len(previous) == 1 and len(chain) == 2


# ── S1-PIPE-013 / 014 / 017 ───────────────────────────────────────────────

class TestSequenceGating:
    def test_an_event_from_a_suppressed_sensor_never_enters_the_chain(self):
        event = SequenceEvent("TW", "ISR_SURGE", NOW - 5.0,
                              justified_by=("isr",))
        chain = sequence.advance((), (event,), now=NOW, retention_sec=86400.0,
                                 admitted_sensors=frozenset())
        assert chain == ()

    def test_an_event_from_an_admitted_sensor_enters(self):
        event = SequenceEvent("TW", "ISR_SURGE", NOW - 5.0,
                              justified_by=("isr",))
        chain = sequence.advance((), (event,), now=NOW, retention_sec=86400.0,
                                 admitted_sensors=frozenset({"isr"}))
        assert len(chain) == 1

    def test_a_composite_event_requires_every_constituent(self):
        """S1-PIPE-014: all, not any — the event asserts co-occurrence."""
        event = SequenceEvent("TW", "SYNC_DDOS", NOW - 5.0,
                              justified_by=("coordination", "botnet"))
        chain = sequence.advance((), (event,), now=NOW, retention_sec=86400.0,
                                 admitted_sensors=frozenset({"coordination"}))
        assert chain == ()

    def test_the_tick_gates_arriving_events_on_admitted_observations(self):
        event = SequenceEvent("TW", "ISR_SURGE", NOW - 5.0,
                              justified_by=("isr",))
        suppressed = score_tick(tick_inputs(
            observations=(obs(sensor="isr", suppressed=True),),
            arriving=(event,)))
        assert suppressed.next_sequence_events == ()
        admitted = score_tick(tick_inputs(
            observations=(obs(sensor="isr"),), arriving=(event,)))
        assert len(admitted.next_sequence_events) == 1

    def test_an_event_without_a_country_cannot_be_built(self):
        """S1-PIPE-017, enforced by the type rather than by a check."""
        with pytest.raises(DomainError):
            SequenceEvent("", "ISR_SURGE", NOW)

    def test_a_fired_zero_score_reading_still_gates_its_link(self):
        """The gate has NO score term (core.py:997, CLAUDE.md §5).

        cf_botnet_overlap fires with score 0 in the marginal IDF band: it
        contributes nothing numerically and still gates SYNC_DDOS. Folding
        the score test into the gate would silently delete those links.
        """
        marginal = obs(sensor="cf_botnet_overlap", score=0.0)
        assert marginal.passes_gate() is True
        assert marginal.admits() is False

        event = SequenceEvent("TW", "SYNC_DDOS", NOW - 5.0,
                              justified_by=("cf_botnet_overlap",))
        result = score_tick(tick_inputs(observations=(marginal,),
                                        arriving=(event,)))
        assert len(result.next_sequence_events) == 1
        assert result.results["taiwan_contingency"].contributions == ()

    def test_a_suppressed_zero_score_reading_gates_nothing(self):
        marginal = obs(sensor="cf_botnet_overlap", score=0.0, suppressed=True)
        assert marginal.passes_gate() is False
        event = SequenceEvent("TW", "SYNC_DDOS", NOW - 5.0,
                              justified_by=("cf_botnet_overlap",))
        result = score_tick(tick_inputs(observations=(marginal,),
                                        arriving=(event,)))
        assert result.next_sequence_events == ()

    def test_an_unfired_reading_gates_nothing(self):
        assert obs(status="CLEAR").passes_gate() is False


class TestChainCountry:
    """S1-PIPE-016: the chain owner is supplied, never guessed."""

    def _middle_east(self) -> Scenario:
        return Scenario(
            scenario_id="middle_east", core_country=None,
            participants=(Participant("IL", Ratio(1.0), "principal_belligerent"),
                          Participant("IR", Ratio(1.0), "principal_belligerent")))

    def _chain_for(self, country):
        types = ("NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY")
        return tuple(SequenceEvent(country, name, NOW - 1.0) for name in types)

    def test_a_single_core_scenario_needs_nothing_supplied(self):
        inputs = tick_inputs()
        assert inputs.chain_country_for(taiwan()) == "TW"

    def test_a_supplied_owner_overrides_the_core_country(self):
        inputs = tick_inputs(chains={"taiwan_contingency": "JP"})
        assert inputs.chain_country_for(taiwan()) == "JP"

    def test_a_dual_core_scenario_without_an_owner_raises(self):
        """Production picks primary_ec by LIVE spike; a static rule would
        pick IL forever, since IL and IR both weigh 1.0."""
        inputs = tick_inputs(scenarios=(self._middle_east(),),
                             focused="middle_east")
        with pytest.raises(DomainError, match="no core_country"):
            score_tick(inputs)

    def test_a_dual_core_scenario_scores_against_the_supplied_owner(self):
        result = score_tick(tick_inputs(
            observations=(obs(score=3.0, country="IR"),),
            scenarios=(self._middle_east(),), focused="middle_east",
            prior=PriorState(sequence_events=self._chain_for("IR")),
            chains={"middle_east": "IR"})).results["middle_east"]
        assert result.bonuses.sequence == 3.0

    def test_the_owner_choice_actually_changes_the_bonus(self):
        """IL is alphabetically first; the escalating side is IR."""
        result = score_tick(tick_inputs(
            observations=(obs(score=3.0, country="IR"),),
            scenarios=(self._middle_east(),), focused="middle_east",
            prior=PriorState(sequence_events=self._chain_for("IR")),
            chains={"middle_east": "IL"})).results["middle_east"]
        assert result.bonuses.sequence == 0.0

    def test_a_background_dual_core_scenario_needs_no_owner(self):
        """Only the focused scenario folds bonuses, so only it needs one."""
        result = score_tick(tick_inputs(
            observations=(obs(score=3.0, country="IR"),),
            scenarios=(taiwan(), self._middle_east())))
        assert result.results["middle_east"].bonuses.total == 0.0


# ── S1-SCORE-024 ──────────────────────────────────────────────────────────

class TestTrendDerivatives:
    def test_slope_of_a_rising_series(self):
        assert trend.linear_regression_slope(
            [0, 1, 2, 3, 4], [1, 2, 3, 4, 5]) == pytest.approx(1.0)

    def test_slope_of_a_flat_series(self):
        assert trend.linear_regression_slope(
            [0, 1, 2, 3], [5, 5, 5, 5]) == pytest.approx(0.0)

    def test_slope_of_a_falling_series(self):
        assert trend.linear_regression_slope(
            [0, 1, 2, 3, 4], [5, 4, 3, 2, 1]) == pytest.approx(-1.0)

    @pytest.mark.parametrize("xs,ys", [([], []), ([1.0], [2.0])])
    def test_too_few_points_have_no_slope(self, xs, ys):
        assert trend.linear_regression_slope(xs, ys) == 0.0

    def test_identical_x_values_have_no_slope(self):
        assert trend.linear_regression_slope([3, 3, 3], [1, 2, 3]) == 0.0

    def test_a_static_series_has_no_velocity(self):
        series = [(NOW + index * 60, 5.0) for index in range(10)]
        assert abs(trend.velocity(series)) < 1e-6

    def test_a_rising_series_has_positive_velocity(self):
        series = [(NOW + index * 60, float(index)) for index in range(10)]
        assert trend.velocity(series) > 0

    def test_too_few_observations_give_zero_velocity(self):
        assert trend.velocity([(NOW, 1.0), (NOW + 60, 5.0)]) == 0.0

    def test_constant_velocity_has_no_acceleration(self):
        series = [(NOW + index * 60, float(index)) for index in range(12)]
        assert abs(trend.acceleration(series)) < 1e-4

    def test_the_velocity_bonus_is_capped_both_ways(self):
        assert trend.velocity_bonus(10.0, 0.0)[0] == 1.5
        assert trend.velocity_bonus(-10.0, 0.0)[0] == -1.5

    def test_a_negligible_velocity_earns_no_bonus(self):
        assert trend.velocity_bonus(0.00001, 0.0) == (0.0, 0.0)

    def test_deceleration_never_earns_a_bonus(self):
        """NP1: a slowing escalation is not evidence of safety."""
        assert trend.velocity_bonus(0.0, -5.0)[1] == 0.0


# ── S1-SCORE-028 ──────────────────────────────────────────────────────────

class TestTemporalCoherence:
    def test_no_events_means_no_bonus(self):
        assert sequence.temporal_coherence_bonus(
            (), now=NOW, retention_sec=86400.0) == 0.0

    def test_two_theatres_within_ten_seconds_are_synchronised(self):
        events = (SequenceEvent("TW", "SYNC_DDOS", NOW - 100.0),
                  SequenceEvent("JP", "SYNC_DDOS", NOW - 95.0))
        assert sequence.temporal_coherence_bonus(
            events, now=NOW, retention_sec=86400.0) == 2.0

    def test_the_same_theatre_twice_is_not_synchronisation(self):
        events = (SequenceEvent("TW", "SYNC_DDOS", NOW - 100.0),
                  SequenceEvent("TW", "ISR_SURGE", NOW - 95.0))
        assert sequence.temporal_coherence_bonus(
            events, now=NOW, retention_sec=86400.0) == 0.0

    def test_events_further_apart_are_not_synchronised(self):
        events = (SequenceEvent("TW", "SYNC_DDOS", NOW - 100.0),
                  SequenceEvent("JP", "SYNC_DDOS", NOW - 80.0))
        assert sequence.temporal_coherence_bonus(
            events, now=NOW, retention_sec=86400.0) == 0.0


# ── S1-PIPE-022 / 026 ─────────────────────────────────────────────────────

class TestBonusFold:
    def _full_chain(self):
        types = ("NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY")
        return tuple(SequenceEvent("TW", name, NOW - 1.0) for name in types)

    def test_the_focused_scenario_folds_its_bonuses_in(self):
        result = score_tick(tick_inputs(
            observations=(obs(score=3.0, country="TW"),),
            prior=PriorState(sequence_events=self._full_chain())),
        ).results["taiwan_contingency"]
        assert result.bonuses.sequence == 3.0
        assert result.score == pytest.approx(result.base_score + 3.0)

    def test_background_scenarios_get_no_bonus_fold(self):
        """ACCIDENTAL A8, ported rather than repaired."""
        korea = Scenario(scenario_id="korea", core_country="TW",
                         participants=(Participant("TW", Ratio(1.0)),))
        results = score_tick(tick_inputs(
            observations=(obs(score=3.0, country="TW"),),
            scenarios=(taiwan(), korea),
            prior=PriorState(sequence_events=self._full_chain()))).results
        assert results["korea"].bonuses.total == 0.0

    def test_the_total_is_not_capped(self):
        """S1-PIPE-022's cap of 15 belongs to the engine family.

        The served scenario score is floored at 0 and never clipped above
        (radar/routes/core.py:2201-2202 are the only two mutations of
        _state.score). Capping here would suppress TL1 on exactly the
        ticks that earn it.
        """
        chain = self._full_chain() + (
            SequenceEvent("JP", "SYNC_DDOS", NOW - 1.0),)
        result = score_tick(tick_inputs(
            observations=(
                obs(sensor="a", source="s1", domain=CYBER, score=6.0),
                obs(sensor="b", source="s2", domain=PHYSICAL, score=6.0),
                obs(sensor="c", source="s3", domain=INFO, score=6.0)),
            prior=PriorState(sequence_events=chain),
            flags={"taiwan_contingency": PatternFlags(True, True)}),
        ).results["taiwan_contingency"]
        # 6+6+6 capped per-domain, +2 convergence = 20 base; chain 3 +
        # temporal 2 + silent 0.5 + context 0.5 = 6 more.
        assert result.base_score == pytest.approx(20.0)
        assert result.score == pytest.approx(26.0)
        assert result.score > 15.0
        assert result.threat_level.value == 1

    def test_the_score_is_floored_at_zero(self):
        series = [(NOW - (20 - index) * 3600, 10.0 - index)
                  for index in range(20)]
        result = score_tick(tick_inputs(
            observations=(obs(score=0.5, country="TW"),),
            series={"taiwan_contingency": tuple(series)}),
        ).results["taiwan_contingency"]
        assert result.score >= 0.0

    def test_the_pattern_flags_add_their_pinned_bonuses(self):
        result = score_tick(tick_inputs(
            observations=(obs(score=1.0, country="TW"),),
            flags={"taiwan_contingency": PatternFlags(
                silent_divergence=True, context_alignment=True)}),
        ).results["taiwan_contingency"]
        assert result.bonuses.silent_divergence == 0.5
        assert result.bonuses.context_alignment == 0.5

    def test_provenance_itemises_every_bonus_component(self):
        """NP6: "why did the bonus move" must be answerable from the
        disclosure record alone, without re-running the tick."""
        result = score_tick(tick_inputs(
            observations=(obs(score=1.0, country="TW"),),
            prior=PriorState(sequence_events=self._full_chain()),
            flags={"taiwan_contingency": PatternFlags(True, False)}),
        ).results["taiwan_contingency"]
        disclosed = result.provenance.inputs
        for component in ("sequence", "temporal_coherence", "velocity",
                          "acceleration", "silent_divergence",
                          "context_alignment"):
            assert f"bonus_{component}" in disclosed
        assert disclosed["bonus_sequence"] == 3.0
        assert disclosed["bonus_silent_divergence"] == 0.5
        assert disclosed["bonus_context_alignment"] == 0.0
        assert sum(value for key, value in disclosed.items()
                   if key.startswith("bonus_") and key != "bonus_total") == \
            pytest.approx(disclosed["bonus_total"])

    def test_the_threat_level_is_derived_after_the_fold(self):
        result = score_tick(tick_inputs(
            observations=(obs(sensor="a", source="s1", domain=CYBER,
                              score=3.0),
                          obs(sensor="b", source="s2", domain=INFO,
                              score=2.0)),
            prior=PriorState(sequence_events=self._full_chain())),
        ).results["taiwan_contingency"]
        # 3.0 + 2.0 + dual bonus 1.0 = 6.0 base, + 3.0 chain = 9.0
        assert result.base_score == pytest.approx(6.0)
        assert result.score == pytest.approx(9.0)
        assert result.threat_level.value == 2   # no physical, so not TL1


# ── S1-SCORE-042 / 044 ────────────────────────────────────────────────────

class TestScenarioSelection:
    def test_a_disabled_scenario_is_not_scored(self):
        disabled = Scenario(scenario_id="scs", enabled=False,
                            participants=(Participant("TW", Ratio(1.0)),))
        result = score_tick(tick_inputs(scenarios=(taiwan(), disabled)))
        assert "scs" not in result.results
        assert result.skipped == ("scs",)

    def test_skipping_is_reported_rather_than_silent(self):
        disabled = Scenario(scenario_id="scs", enabled=False)
        assert score_tick(tick_inputs(
            scenarios=(taiwan(), disabled))).skipped == ("scs",)

    def test_a_scenario_without_a_core_country_scores_symmetrically(self):
        middle_east = Scenario(
            scenario_id="middle_east", core_country=None,
            participants=(Participant("IL", Ratio(1.0), "principal_belligerent"),
                          Participant("IR", Ratio(1.0), "principal_belligerent")))
        built = contrib.build_contributions(
            (obs(sensor="a", source="s1", score=3.0, country="IL"),
             obs(sensor="b", source="s2", score=3.0, country="IR")),
            middle_east, settings=settings(), now=NOW)
        assert [c.score for c in built] == [3.0, 3.0]

    def test_duplicate_participants_are_refused(self):
        with pytest.raises(DomainError):
            Scenario(scenario_id="x",
                     participants=(Participant("TW", Ratio(1.0)),
                                   Participant("TW", Ratio(0.5))))


# ── S1-SCORE-043 ──────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_a_scenario_with_no_signals_floors_at_tl5(self):
        result = score_tick(tick_inputs()).results["taiwan_contingency"]
        assert result.score == 0.0
        assert result.threat_level.value == 5
        assert result.contributions == ()

    def test_a_scenario_with_only_suppressed_signals_floors_at_tl5(self):
        result = score_tick(tick_inputs(observations=(
            obs(score=9.0, suppressed=True),))).results["taiwan_contingency"]
        assert result.threat_level.value == 5

    def test_the_result_carries_provenance_naming_its_clauses(self):
        result = score_tick(tick_inputs(observations=(
            obs(score=3.0),))).results["taiwan_contingency"]
        assert "S1-SCORE-004" in result.provenance.formula_ref
        assert result.provenance.inputs["score"] == result.score
        assert result.provenance.computed_at == NOW

    def test_provenance_discloses_the_effective_settings(self):
        result = score_tick(tick_inputs(
            observations=(obs(score=3.0),),
            domain_cap=4.0)).results["taiwan_contingency"]
        assert result.provenance.inputs["domain_cap"] == 4.0

    def test_severity_is_six_minus_tl(self):
        result = score_tick(tick_inputs()).results["taiwan_contingency"]
        assert result.severity() == 1 == 6 - result.threat_level.value


# ── S1-PIPE-009 ───────────────────────────────────────────────────────────

class TestGatingTruthTable:
    """All eight rows. S1-PIPE §6 GAP-01: none of this was tested before."""

    def test_row1_clean_fired_observation_is_admitted(self):
        decision = gate(obs(), now=NOW)
        assert decision.admitted is True
        assert decision.suppressed is False and decision.reason is None
        assert decision.hidden_signal is False

    def test_row2_noise_rule_suppresses_and_is_recorded(self):
        rule = NoiseRule("r1", "cf", "maintenance")
        decision = gate(obs(value="scheduled maintenance"),
                        noise_rules=(rule,), now=NOW)
        assert decision.admitted is False and decision.suppressed is True
        assert decision.reason == REASON_NOISE_RULE
        assert decision.noise_rule_id == "r1"
        assert decision.noise_rule_applied is True
        assert decision.hidden_signal is True

    def test_row3_caller_suppression_keeps_its_own_reason(self):
        decision = gate(obs(), caller_suppressed=True,
                        caller_reason="weather", now=NOW)
        assert decision.reason == "weather"
        assert decision.noise_rule_applied is False
        assert decision.hidden_signal is True

    def test_row4_an_already_suppressed_reading_does_not_adopt_noise(self):
        rule = NoiseRule("r1", "cf", "maintenance")
        decision = gate(obs(value="scheduled maintenance"),
                        caller_suppressed=True, caller_reason="weather",
                        noise_rules=(rule,), now=NOW)
        assert decision.reason == "weather"
        assert decision.noise_rule_applied is False
        assert decision.noise_rule_id is None

    def test_row5_analyst_mute_outranks_everything(self):
        rule = NoiseRule("r1", "cf", "maintenance")
        decision = gate(obs(value="scheduled maintenance"), muted=True,
                        caller_suppressed=True, caller_reason="weather",
                        noise_rules=(rule,), now=NOW)
        assert decision.reason == REASON_ANALYST_MUTE
        assert decision.noise_rule_applied is False
        assert decision.hidden_signal is True

    def test_row6_an_unfired_clean_observation_is_not_suppressed(self):
        decision = gate(obs(status="CLEAR"), now=NOW)
        assert decision.admitted is False and decision.suppressed is False
        assert decision.hidden_signal is False

    def test_row7_a_noise_rule_still_applies_to_an_unfired_reading(self):
        """ACCIDENTAL A3, ported: the rule matches and is counted."""
        rule = NoiseRule("r1", "cf", "maintenance")
        decision = gate(obs(status="CLEAR", value="scheduled maintenance"),
                        noise_rules=(rule,), now=NOW)
        assert decision.suppressed is True
        assert decision.noise_rule_applied is True
        assert decision.hidden_signal is False   # never fired

    def test_row8_a_disabled_sensor_is_never_admitted(self):
        decision = gate(obs(status="DISABLED"), now=NOW)
        assert decision.admitted is False

    def test_a_suppressed_observation_keeps_its_score(self):
        """Step 6: suppression sets a flag, it does not zero evidence."""
        from v3.scoring.gating import apply_gate
        decision = gate(obs(score=7.0), caller_suppressed=True,
                        caller_reason="weather", now=NOW)
        carried = apply_gate(decision)
        assert carried.score == 7.0
        assert carried.suppressed is True
        assert carried.suppress_reason == "weather"
        assert carried.admits() is False


# ── S1-PIPE-010 ───────────────────────────────────────────────────────────

class TestNoiseRules:
    def test_the_sensor_must_match_exactly(self):
        rule = NoiseRule("r1", "cf", "noise")
        assert not rule.matches(obs(sensor="cf_other", value="noise"), "TW",
                                now=NOW)

    def test_an_empty_country_is_a_wildcard(self):
        rule = NoiseRule("r1", "cf", "noise", country="")
        assert rule.matches(obs(value="noise"), "JP", now=NOW)

    def test_a_named_country_must_match(self):
        rule = NoiseRule("r1", "cf", "noise", country="TW")
        assert rule.matches(obs(value="noise"), "TW", now=NOW)
        assert not rule.matches(obs(value="noise"), "JP", now=NOW)

    def test_an_expired_rule_does_not_match(self):
        rule = NoiseRule("r1", "cf", "noise", expires_at=NOW - 1)
        assert not rule.matches(obs(value="noise"), "TW", now=NOW)

    def test_a_future_expiry_still_matches(self):
        rule = NoiseRule("r1", "cf", "noise", expires_at=NOW + 1000)
        assert rule.matches(obs(value="noise"), "TW", now=NOW)

    def test_the_pattern_is_a_substring_of_the_structured_value(self):
        rule = NoiseRule("r1", "cf", "maint")
        assert rule.matches(obs(value="scheduled maintenance"), "TW", now=NOW)
        assert not rule.matches(obs(value="attack surge"), "TW", now=NOW)

    def test_the_first_matching_rule_wins(self):
        rules = (NoiseRule("first", "cf", "noise"),
                 NoiseRule("second", "cf", "noise"))
        assert gate(obs(value="noise"), noise_rules=rules,
                    now=NOW).noise_rule_id == "first"

    def test_matching_ignores_the_display_label(self):
        """DP4 repaired: rules bind to `value`, not to rendered text."""
        rule = NoiseRule("r1", "cf", "maintenance")
        assert not rule.matches(obs(value="", sensor="cf"), "TW", now=NOW)


# ── S1-PIPE-011 ───────────────────────────────────────────────────────────

class TestConfidencePenalty:
    def test_a_weak_claim_loses_one_point(self):
        assert apply_confidence_penalty(3.0, 0.2, minimum=0.5) == 2.0

    def test_a_strong_claim_is_untouched(self):
        assert apply_confidence_penalty(3.0, 0.9, minimum=0.5) == 3.0

    def test_the_boundary_counts_as_strong(self):
        assert apply_confidence_penalty(3.0, 0.5, minimum=0.5) == 3.0

    def test_the_penalty_floors_at_zero(self):
        assert apply_confidence_penalty(0.5, 0.1, minimum=0.5) == 0.0


# ── WP-2.4 completion condition 1 ─────────────────────────────────────────

class TestPurityAndIdempotence:
    """The kernel reads nothing, so a tick can be replayed (F-05)."""

    def _busy_inputs(self):
        chain = tuple(
            SequenceEvent("TW", name, NOW - 3600.0)
            for name in ("NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS"))
        return tick_inputs(
            observations=(
                obs(sensor="a", source="bgp", domain=CYBER, score=4.0),
                obs(sensor="b", source="bgp", domain=CYBER, score=2.0),
                obs(sensor="c", source="isr", domain=PHYSICAL, score=3.5,
                    country="JP"),
                obs(sensor="d", source="rss", domain=INFO, score=2.0,
                    weights=(("US", 1.0), ("TW", 0.9)), origin="llm_intel"),
                obs(sensor="e", source="glob", domain=INFO, score=5.0,
                    country=""),
                obs(sensor="f", source="mute", domain=INFO, score=9.0,
                    suppressed=True)),
            prior=PriorState(previous_tl={"taiwan_contingency": ThreatLevel(2)},
                             sequence_events=chain),
            series={"taiwan_contingency": tuple(
                (NOW - (10 - i) * 3600, float(i)) for i in range(10))},
            flags={"taiwan_contingency": PatternFlags(True, False)})

    def test_the_same_input_produces_the_same_output_twice(self):
        inputs = self._busy_inputs()
        assert score_tick(inputs).results["taiwan_contingency"].as_dict() == \
            score_tick(inputs).results["taiwan_contingency"].as_dict()

    def test_results_compare_equal_not_merely_similar(self):
        inputs = self._busy_inputs()
        assert score_tick(inputs).results["taiwan_contingency"] == \
            score_tick(inputs).results["taiwan_contingency"]

    def test_scoring_never_resolves_a_threshold(self):
        """Break resolution outright; scoring must not notice.

        The kernel has no default resolver any more (§7-2 #115 sweep), so
        the way to break resolution is to break the only remaining path:
        `Threshold.resolve` itself. If any formula reached for a
        registry-backed value at tick time, this would raise.
        """
        import v3.kernel.threshold as threshold_module

        def explode(self, resolver=None):
            raise AssertionError(
                f"score_tick resolved {self.key or self.provenance_ref!r} — "
                f"the kernel must read no configuration at tick time")

        original = threshold_module.Threshold.resolve
        threshold_module.Threshold.resolve = explode
        try:
            result = score_tick(self._busy_inputs())
        finally:
            threshold_module.Threshold.resolve = original
        assert result.results["taiwan_contingency"].threat_level is not None

    def test_the_input_is_not_mutated(self):
        inputs = self._busy_inputs()
        before = (len(inputs.observations), len(inputs.prior.sequence_events))
        score_tick(inputs)
        assert (len(inputs.observations),
                len(inputs.prior.sequence_events)) == before

    def test_the_clock_is_an_argument_not_a_reading(self):
        earlier = score_tick(self._busy_inputs())
        assert earlier.now == NOW
        assert earlier.results["taiwan_contingency"].provenance.computed_at \
            == NOW

    def test_the_successor_state_feeds_the_next_tick(self):
        result = score_tick(self._busy_inputs())
        successor = result.next_prior_state()
        assert successor.tl_for("taiwan_contingency") is not None
        assert successor.sequence_events == result.next_sequence_events

    def test_a_wrong_input_type_is_refused_rather_than_guessed(self):
        with pytest.raises(TypeError):
            score_tick({"now": NOW})


class TestValuesSurviveTransport:
    """Parity replay ships these objects between processes.

    Every frozen type here exposes a mappingproxy, which pickle and
    deepcopy both refuse. `__reduce__` rebuilds through the constructor,
    so a restored value is a re-validated value rather than a snapshot of
    whatever the sender's memory happened to hold — the pattern Provenance
    already established.
    """

    def _inputs(self):
        return tick_inputs(
            observations=(obs(score=3.0),),
            prior=PriorState(previous_tl={"taiwan_contingency": ThreatLevel(3)},
                             sequence_events=(SequenceEvent(
                                 "TW", "ISR_SURGE", NOW - 10.0),)),
            series={"taiwan_contingency": ((NOW - 60, 1.0), (NOW, 2.0))},
            flags={"taiwan_contingency": PatternFlags(True, False)},
            chains={"taiwan_contingency": "TW"})

    @pytest.mark.parametrize("build", [
        lambda self: self._inputs(),
        lambda self: self._inputs().prior,
        lambda self: score_tick(self._inputs()),
        lambda self: score_tick(self._inputs()).results["taiwan_contingency"],
    ])
    def test_pickle_round_trips(self, build):
        import pickle
        original = build(self)
        assert pickle.loads(pickle.dumps(original)) == original

    @pytest.mark.parametrize("build", [
        lambda self: self._inputs(),
        lambda self: self._inputs().prior,
        lambda self: score_tick(self._inputs()),
        lambda self: score_tick(self._inputs()).results["taiwan_contingency"],
    ])
    def test_deepcopy_round_trips(self, build):
        import copy
        original = build(self)
        assert copy.deepcopy(original) == original

    def test_a_restored_tick_scores_identically(self):
        import pickle
        inputs = self._inputs()
        restored = pickle.loads(pickle.dumps(inputs))
        assert score_tick(restored).results["taiwan_contingency"] == \
            score_tick(inputs).results["taiwan_contingency"]

    def test_restoring_re_runs_validation(self):
        import pickle
        restored = pickle.loads(pickle.dumps(self._inputs()))
        assert restored.prior.tl_for("taiwan_contingency").value == 3
        assert restored.chain_countries["taiwan_contingency"] == "TW"


class TestPublishedFiguresCannotBeEdited:
    def test_the_global_envelope_is_frozen_all_the_way_down(self):
        result = score_tick(tick_inputs(observations=(
            obs(score=4.0, country=""),),
            global_signals_decoupled=False))
        with pytest.raises(TypeError):
            result.global_threat["score"] = 99.0
        with pytest.raises(TypeError):
            result.global_threat["domains"][CYBER] = 99.0

    def test_the_envelope_from_contributions_is_frozen_too(self):
        envelope = contrib.global_threat(
            (obs(score=4.0, country=""),), global_signal_weight=Ratio(0.5), now=NOW)
        with pytest.raises(TypeError):
            envelope["domains"][CYBER] = 99.0

    def test_domain_scores_on_a_result_are_read_only(self):
        result = score_tick(tick_inputs(observations=(
            obs(score=3.0),))).results["taiwan_contingency"]
        with pytest.raises(TypeError):
            result.domain_scores[CYBER] = 99.0


class TestScoreSeriesIsValidated:
    """A NaN here is the F-08 shape: it survives the arithmetic and then
    compares False in the epsilon guard, so the bonus reads zero."""

    @pytest.mark.parametrize("point", [
        (float("nan"), 1.0),
        (1.0, float("nan")),
        (float("inf"), 1.0),
        (1.0, float("inf")),
        (0.0, 1.0),
        (-1.0, 1.0),
    ])
    def test_a_non_finite_point_is_refused(self, point):
        with pytest.raises(DomainError):
            tick_inputs(series={"taiwan_contingency": (point,)})

    @pytest.mark.parametrize("point", [(NOW,), (NOW, 1.0, 2.0), NOW, "x"])
    def test_a_malformed_point_is_refused(self, point):
        with pytest.raises(DomainError):
            tick_inputs(series={"taiwan_contingency": (point,)})

    def test_a_well_formed_series_is_accepted(self):
        inputs = tick_inputs(
            series={"taiwan_contingency": ((NOW - 60, 1.0), (NOW, 2.0))})
        assert len(inputs.score_series_for("taiwan_contingency")) == 2

    def test_a_nan_can_no_longer_reach_the_velocity_bonus(self):
        series = tuple((NOW - (10 - i) * 60, float(i)) for i in range(9))
        with pytest.raises(DomainError):
            tick_inputs(series={
                "taiwan_contingency": series + ((NOW, float("nan")),)})
