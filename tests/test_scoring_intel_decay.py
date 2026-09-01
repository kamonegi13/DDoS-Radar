"""WP-2.4 ADDENDUM (landed in WP-2.7) — the LLM intel age-decay term.

Design sheet §9 ruling 1: `Observation` gains `observed_at` and L2 gains
ONE pinned decay term, held to the scoring kernel's discipline. This file
is the clause-mapped half of that discipline.

The traced effective path, verified with `ast` rather than by reading the
S1 citation (the WP-2.4 lesson — a cited line is a lead, not evidence):

    radar/intel_queue.py:1001-1003   weight = _age_weight(age_sec, source_type)
                                     decayed = float(item["score_delta"]) * weight
    radar/intel_queue.py:88-106      _age_weight = exp(-max(0, age) / (tau_h * 3600))
    radar/intel_queue.py:1026        the DECAYED value is published as "score"
    radar/routes/core.py:2068-2078   raw_score=float(_lr["score"])   <- decayed
                                     observed_at=current_time        <- the TICK,
                                                                        not the item
    radar/routes/core.py:1925        add_rat(..., _llm_entry["score"], ...) — the
                                     5th positional parameter of add_rat is
                                     `score` (core.py:930), so the focused path
                                     receives the decayed number too.

So production pre-decays in L0/L3 and hands L2 a number whose age is
already spent — and then stamps the observation with the tick's clock, so
the age is unrecoverable downstream. v3 inverts that: the adapter emits
the UNDECAYED score together with the item's own `observed_at`, and this
term is the only place the exponential is applied (O-17: no second
decay mechanism).
"""
import math

import pytest

from v3.kernel import Ratio
from v3.kernel.errors import DomainError
from v3.scoring import (CountryWeight, Observation, Participant, Scenario,
                        ScoringSettings)
from v3.scoring import contributions as contrib
from v3.scoring import decay
from v3.scoring.thresholds import (INTEL_AGE_DECAY_TAU_H,
                                   INTEL_AGE_DECAY_TAU_SEC, pinned_threshold)

NOW = 1_700_000_000.0
TAU = INTEL_AGE_DECAY_TAU_SEC


def taiwan() -> Scenario:
    return Scenario(
        scenario_id="taiwan_contingency", core_country="TW",
        participants=(Participant("TW", Ratio(1.0), "primary_target"),
                      Participant("US", Ratio(0.8), "primary_ally")))


def intel(score=3.0, *, age_sec=0.0, country="TW", weights=None,
          domain="info") -> Observation:
    if weights is not None:
        countries = tuple(CountryWeight(c, Ratio(w)) for c, w in weights)
    elif country:
        countries = (CountryWeight(country, Ratio(1.0)),)
    else:
        countries = ()
    return Observation(sensor="llm_intel", domain=domain, status="FIRED",
                       score=score, signal_source="llm_intel",
                       countries=countries, origin="llm_intel",
                       observed_at=NOW - age_sec)


# ── S1-INTEL-020: the weight itself ───────────────────────────────────────

class TestIntelAgeWeight:
    """`exp(-max(0, age_sec) / (tau_hours * 3600))`, value for value."""

    def test_a_fresh_item_keeps_its_whole_score(self):
        assert decay.intel_age_weight(NOW, NOW) == 1.0

    def test_one_tau_costs_one_e_fold(self):
        assert decay.intel_age_weight(NOW - TAU, NOW) == pytest.approx(1 / math.e)
        assert decay.intel_age_weight(NOW - TAU, NOW) == pytest.approx(0.3679,
                                                                      abs=1e-4)

    def test_two_taus_cost_two(self):
        assert decay.intel_age_weight(NOW - 2 * TAU, NOW) == pytest.approx(
            math.exp(-2))
        assert decay.intel_age_weight(NOW - 2 * TAU, NOW) == pytest.approx(
            0.1353, abs=1e-4)

    def test_a_negative_age_is_clamped_to_zero_not_amplified(self):
        """S1-INTEL-020's clamp. Without it a clock-skewed future timestamp
        makes exp(+x) > 1 and an item scores ABOVE its declared delta."""
        assert decay.intel_age_weight(NOW + 86400.0, NOW) == 1.0

    def test_the_weight_never_reaches_zero(self):
        """Production keeps the 48h TTL as a hard floor precisely because
        this term alone never deletes an item."""
        assert decay.intel_age_weight(NOW - 30 * 86400.0, NOW) > 0.0

    def test_a_non_positive_tau_is_refused_rather_than_disabling_decay(self):
        """Production's env escape hatch (`tau_hours <= 0 -> 1.0`,
        intel_queue.py:103) silently turns the term off. v3 pins tau, so the
        branch is unreachable; asked for it directly, it raises."""
        with pytest.raises(DomainError):
            decay.intel_age_weight(NOW - TAU, NOW, tau_sec=0.0)

    def test_the_tau_matches_the_deployed_configuration(self):
        assert INTEL_AGE_DECAY_TAU_H == 12.0
        assert INTEL_AGE_DECAY_TAU_SEC == 12.0 * 3600.0

    def test_the_tau_is_pinned_and_discloses_its_source(self):
        threshold = pinned_threshold("INTEL_AGE_DECAY_TAU_H")
        assert not threshold.is_registry_backed
        assert "intel_queue" in threshold.provenance_ref
        assert "S1-INTEL-020" in threshold.provenance_ref


class TestOnlyIntelDecays:
    """A sensor reading has no age term — production applies the weight in
    `get_active_rationale` alone, which no sensor passes through."""

    def test_a_sensor_observation_is_untouched_however_old(self):
        reading = Observation(sensor="cf", domain="cyber", status="FIRED",
                              score=3.0,
                              countries=(CountryWeight("TW", Ratio(1.0)),),
                              observed_at=NOW - 10 * TAU)
        assert decay.age_weight_for(reading, now=NOW) == 1.0

    def test_an_intel_observation_decays(self):
        assert decay.age_weight_for(intel(age_sec=TAU), now=NOW) == \
            pytest.approx(1 / math.e)


# ── the field ─────────────────────────────────────────────────────────────

class TestObservedAt:
    def test_an_intel_observation_without_a_timestamp_is_refused(self):
        """Defaulting to `now` would read every stale item as fresh, and
        defaulting to the epoch would read every item as spent. Both are
        guesses about the one quantity the term exists to use."""
        with pytest.raises(DomainError):
            Observation(sensor="llm_intel", domain="info", status="FIRED",
                        score=3.0, origin="llm_intel",
                        countries=(CountryWeight("TW", Ratio(1.0)),))

    def test_a_sensor_observation_may_omit_it(self):
        reading = Observation(sensor="cf", domain="cyber", status="FIRED",
                              score=3.0)
        assert reading.observed_at is None

    def test_a_zero_timestamp_is_refused(self):
        with pytest.raises(DomainError):
            Observation(sensor="llm_intel", domain="info", status="FIRED",
                        score=3.0, origin="llm_intel", observed_at=0.0)

    def test_the_timestamp_survives_a_round_trip(self):
        import copy
        item = intel(age_sec=3600.0)
        assert copy.deepcopy(item).observed_at == item.observed_at


# ── where the term lands ──────────────────────────────────────────────────

class TestDecayReachesTheContribution:
    def test_the_contribution_score_carries_the_weight(self):
        built = contrib.build_contributions(
            (intel(score=4.0, age_sec=TAU),), taiwan(),
            settings=ScoringSettings(), now=NOW)
        assert len(built) == 1
        assert built[0].score == pytest.approx(4.0 * (1 / math.e) * 1.0)

    def test_the_raw_score_stays_undecayed_so_both_numbers_are_visible(self):
        """Production publishes `score` and `score_raw` side by side
        (intel_queue.py:1026-1027). NP6 needs the same pair here."""
        built = contrib.build_contributions(
            (intel(score=4.0, age_sec=TAU),), taiwan(),
            settings=ScoringSettings(), now=NOW)
        assert built[0].raw_score == 4.0
        assert built[0].age_weight == pytest.approx(1 / math.e)

    def test_the_decay_multiplies_before_the_two_country_weights(self):
        built = contrib.build_contributions(
            (intel(score=4.0, age_sec=TAU, weights=(("US", 1.0),)),),
            taiwan(), settings=ScoringSettings(), now=NOW)
        assert built[0].score == pytest.approx(4.0 * (1 / math.e) * 1.0 * 0.8)

    def test_a_sensor_contribution_keeps_its_pinned_trace_byte_for_byte(self):
        """S1-SCORE-009's trace format is pinned. The decay factor appears
        only where a decay happened."""
        reading = Observation(sensor="cf", domain="cyber", status="FIRED",
                              score=3.0,
                              countries=(CountryWeight("TW", Ratio(1.0)),))
        built = contrib.build_contributions((reading,), taiwan(),
                                            settings=ScoringSettings(), now=NOW)
        assert built[0].trace == ("3.00 (raw) × 1.00 (llm:TW) "
                                  "× 1.00 (participant:TW) = 3.00")
        assert built[0].age_weight == 1.0

    def test_a_decayed_contribution_discloses_the_factor_in_its_trace(self):
        built = contrib.build_contributions(
            (intel(score=4.0, age_sec=TAU),), taiwan(),
            settings=ScoringSettings(), now=NOW)
        assert "0.37 (decay:12.0h)" in built[0].trace

    def test_the_global_envelope_decays_too(self):
        envelope = contrib.global_threat(
            (intel(score=4.0, age_sec=TAU, country=""),),
            global_signal_weight=Ratio(0.5), now=NOW)
        assert envelope["score"] == pytest.approx(4.0 * (1 / math.e) * 0.5)

    def test_dedup_ranks_on_the_decayed_score(self):
        """A stale high-delta item must lose to a fresh smaller one — the
        stated intent of ranking on the decayed value
        (intel_queue.py:1016)."""
        stale = intel(score=5.0, age_sec=4 * TAU)
        fresh = intel(score=2.0, age_sec=0.0)
        kept = contrib.dedup_max(contrib.build_contributions(
            (stale, fresh), taiwan(), settings=ScoringSettings(), now=NOW))
        assert len(kept) == 1
        assert kept[0].raw_score == 2.0


class TestDecayReachesTheTick:
    def _inputs(self, age_sec):
        from v3.scoring import ScoringInputs
        return ScoringInputs(
            now=NOW, observations=(intel(score=6.0, age_sec=age_sec),),
            scenarios=(taiwan(),), settings=ScoringSettings(),
            arriving_events=(), focused_scenario_id=None)

    def test_an_aged_item_scores_below_a_fresh_one(self):
        from v3.scoring import score_tick
        fresh = score_tick(self._inputs(0.0)).results["taiwan_contingency"]
        aged = score_tick(self._inputs(2 * TAU)).results["taiwan_contingency"]
        assert fresh.score > aged.score
        assert aged.score == pytest.approx(6.0 * math.exp(-2))

    def test_score_tick_stays_pure_across_the_new_term(self):
        """The age is a function of two existing inputs — the observation's
        own timestamp and the tick's `now` — so no clock is read."""
        from v3.scoring import score_tick
        inputs = self._inputs(TAU)
        first = score_tick(inputs)
        second = score_tick(inputs)
        assert first.results["taiwan_contingency"].score == \
            second.results["taiwan_contingency"].score

    def test_the_tau_is_disclosed_in_the_provenance(self):
        from v3.scoring import score_tick
        record = score_tick(self._inputs(TAU)).results[
            "taiwan_contingency"].provenance
        assert record.inputs["intel_age_decay_tau_h"] == 12.0


class TestTheParityProjectionCarriesTheAge:
    """S5-VERIF-031's single input adapter has to carry what the term uses.

    The L1 table has no `origin` column, so the projection recovers it from
    `signal_source` — which S1-INTEL-020 pins to the literal `llm_intel`.
    Dropping either field would make every intel row score at full weight
    on the v3 side of a parity run, silently.
    """

    def _row(self, **over):
        row = {"sensor": "llm_intel", "signal_source": "llm_intel",
               "domain": "info", "country": "TW", "observed_at": NOW - TAU,
               "raw_score": 4.0, "status": "FIRED", "confidence": 1.0,
               "suppressed": 0, "suppress_reason": None, "payload": ""}
        row.update(over)
        return row

    def test_an_intel_row_is_projected_as_intel(self):
        from v3.parity.adapter import to_v3_observations
        projected = to_v3_observations([self._row()])[0]
        assert projected.is_llm_intel
        assert projected.observed_at == NOW - TAU

    def test_a_sensor_row_keeps_the_sensor_origin_and_its_timestamp(self):
        from v3.parity.adapter import to_v3_observations
        projected = to_v3_observations(
            [self._row(sensor="cf", signal_source="cf_l7", domain="cyber")])[0]
        assert not projected.is_llm_intel
        assert projected.observed_at == NOW - TAU

    def test_the_projected_intel_row_actually_decays(self):
        from v3.parity.adapter import to_v3_observations
        built = contrib.build_contributions(
            to_v3_observations([self._row()]), taiwan(),
            settings=ScoringSettings(), now=NOW)
        assert built[0].score == pytest.approx(4.0 * (1 / math.e))


# ── the clause registry ───────────────────────────────────────────────────

class TestTheAddendumIsRegistered:
    def test_the_decay_clause_is_recorded_as_implemented(self):
        from v3.scoring.registry import ADDENDUM_IMPLEMENTED
        entry = ADDENDUM_IMPLEMENTED["S1-INTEL-020"]
        assert entry.test_class == "TestIntelAgeWeight"
        assert "decay" in entry.where

    def test_the_addendum_stays_a_named_exception_not_a_second_universe(self):
        """S1-intel.md is L3's book. Exactly one of its clauses reaches
        this kernel; anything else claimed here needs its own ruling."""
        from v3.scoring.registry import (ADDENDUM_IMPLEMENTED,
                                         INTEL_ADDENDUM_CLAUSES)
        assert set(ADDENDUM_IMPLEMENTED) == set(INTEL_ADDENDUM_CLAUSES)
        assert INTEL_ADDENDUM_CLAUSES == ("S1-INTEL-020",)

    def test_the_addendum_does_not_leak_into_the_scoring_universe(self):
        from v3.scoring.registry import (ADDENDUM_IMPLEMENTED,
                                         S1_SCORING_CLAUSES, unaccounted)
        assert set(ADDENDUM_IMPLEMENTED) & S1_SCORING_CLAUSES == set()
        assert unaccounted() == frozenset()

    def test_the_pipe_023_exclusion_no_longer_claims_the_whole_clause(self):
        """S1-PIPE-023 clause (4) says intel is injected ALREADY DECAYED.
        With the term here, that half is no longer the adapter's."""
        from v3.scoring.registry import EXCLUDED
        assert "S1-INTEL-020" in EXCLUDED["S1-PIPE-023"].evidence

    def test_the_addendum_clause_names_a_living_test_class(self):
        import inspect

        import tests.test_scoring_intel_decay as suite
        from v3.scoring.registry import ADDENDUM_IMPLEMENTED
        present = {name for name, _ in inspect.getmembers(suite, inspect.isclass)
                   if name.startswith("Test")}
        for entry in ADDENDUM_IMPLEMENTED.values():
            assert entry.test_class in present
