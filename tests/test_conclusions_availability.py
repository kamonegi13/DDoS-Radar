"""WP-3.1 condition 2 / cutover C-08 — every reason has a live path.

F-12: three of the four `ConclusionUnavailableReason` values were emitted
by nothing at all, so `insufficient_data` was the only answer the tool
could give to "why can't you tell me?". C-08 makes the repair a cutover
condition with override forbidden, which means this file is the gate:
a reachable path per reason, a test that reaches it, and a registry that
is read rather than hand-kept.
"""
import pytest

from tests.conclusions_fixtures import NOW, healthy, provenance
from v3.conclusions import (GUARDS, InputHealth, build,
                            reasons_with_a_generation_path,
                            registry_disclosure)
from v3.conclusions import thresholds as T
from v3.conclusions import vocabulary as V
from v3.conclusions.availability import Candidate, evaluate
from v3.kernel.errors import DomainError

CALM = Candidate(state="5", calm=True)
ALERT = Candidate(state="1", calm=False)
UNDERIVABLE = Candidate(state=None, calm=True, derivable=False,
                        detail="no window held enough samples")

OLD_ENOUGH = T.CALIBRATION_MIN_HISTORY_SEC + 1.0


class TestEveryReasonHasAGenerationPath:
    """C-08. Override forbidden — do not weaken these four."""

    def test_the_registry_covers_all_four_reasons(self):
        assert reasons_with_a_generation_path() == set(V.UNAVAILABLE_REASONS)

    def test_removing_a_guard_removes_its_reason(self):
        # The previous version of this test asserted
        # `reasons_with_a_generation_path() == {g.reason for g in GUARDS}`,
        # which is verbatim the function body and cannot fail for any
        # value of GUARDS. What matters is that the set is DERIVED: drop
        # the only guard for a reason and that reason must disappear, so
        # the C-08 check above starts failing instead of a hand-kept list
        # continuing to claim coverage.
        from v3.conclusions import availability as module
        survivors = tuple(g for g in GUARDS
                          if g.reason != V.UPSTREAM_FAILURE)
        original = module.GUARDS
        module.GUARDS = survivors
        try:
            assert V.UPSTREAM_FAILURE not in \
                module.reasons_with_a_generation_path()
        finally:
            module.GUARDS = original
        assert V.UPSTREAM_FAILURE in reasons_with_a_generation_path()

    def test_every_guard_declares_the_condition_it_checks(self):
        for entry in registry_disclosure():
            assert entry["condition"].strip()
            assert entry["guard_id"].strip()

    @pytest.mark.parametrize("reason", V.UNAVAILABLE_REASONS)
    def test_each_reason_is_actually_reachable(self, reason):
        """The anti-F-12 test: reach every value through real inputs."""
        health = {
            V.UPSTREAM_FAILURE: InputHealth(sources_failed=("a", "b"),
                                            history_span_sec=OLD_ENOUGH),
            V.SENSOR_DEGRADED: InputHealth(sources_ok=("a", "b"),
                                           sources_stale=("c", "d"),
                                           history_span_sec=OLD_ENOUGH),
            V.INSUFFICIENT_DATA: InputHealth(history_span_sec=OLD_ENOUGH),
            V.CALIBRATION_PENDING: InputHealth(sources_ok=("a", "b"),
                                               history_span_sec=0.0),
        }[reason]
        verdict = evaluate(health, CALM)
        assert verdict.available is False
        assert verdict.reason == reason

    def test_no_reason_collapses_into_insufficient_data(self):
        reached = {
            evaluate(InputHealth(sources_failed=("a",),
                                 history_span_sec=OLD_ENOUGH), CALM).reason,
            evaluate(InputHealth(sources_ok=("a",), sources_stale=("b",),
                                 history_span_sec=OLD_ENOUGH), CALM).reason,
            evaluate(InputHealth(history_span_sec=OLD_ENOUGH), CALM).reason,
            evaluate(InputHealth(sources_ok=("a",),
                                 history_span_sec=0.0), CALM).reason,
        }
        assert reached == set(V.UNAVAILABLE_REASONS)

    def test_a_reason_added_without_a_guard_would_fail_this_gate(self):
        # The guard against F-12 returning under new names: the vocabulary
        # and the registry are compared, not maintained in parallel.
        assert set(V.UNAVAILABLE_REASONS) <= reasons_with_a_generation_path()


class TestUpstreamFailure:
    def test_it_needs_total_loss_not_partial(self):
        health = InputHealth(sources_ok=("a",), sources_failed=("b",),
                             history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).reason != V.UPSTREAM_FAILURE

    def test_every_source_failing_fires_it(self):
        health = InputHealth(sources_failed=("a", "b", "c"),
                             history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).reason == V.UPSTREAM_FAILURE

    def test_the_detail_names_the_failed_sources(self):
        health = InputHealth(sources_failed=("ripe_bgp", "ioda"),
                             history_span_sec=OLD_ENOUGH)
        detail = evaluate(health, CALM).suppression.detail
        assert "ripe_bgp" in detail and "ioda" in detail

    def test_it_outranks_sensor_degraded(self):
        # Total loss also satisfies the degraded majority; the more
        # specific answer has to win or the reason is never seen.
        health = InputHealth(sources_failed=("a", "b"),
                             history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).reason == V.UPSTREAM_FAILURE

    def test_the_floor_is_pinned_at_total_loss(self):
        assert T.UPSTREAM_FAILURE_RATIO == 1.0


class TestSensorDegraded:
    def test_a_majority_stale_fires_it(self):
        health = InputHealth(sources_ok=("a", "b"),
                             sources_stale=("c", "d"),
                             history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).reason == V.SENSOR_DEGRADED

    def test_the_boundary_is_inclusive(self):
        health = InputHealth(sources_ok=("a", "b"), sources_stale=("c", "d"),
                             history_span_sec=OLD_ENOUGH)
        assert health.degraded_ratio == T.SENSOR_DEGRADED_RATIO
        assert evaluate(health, CALM).available is False

    def test_a_minority_degraded_still_concludes(self):
        health = InputHealth(sources_ok=("a", "b", "c"),
                             sources_stale=("d",),
                             history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).available is True

    def test_failed_and_stale_both_count_as_unusable(self):
        health = InputHealth(sources_ok=("a", "b"), sources_failed=("c",),
                             sources_stale=("d",),
                             history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).reason == V.SENSOR_DEGRADED

    def test_the_detail_says_a_quiet_reading_describes_the_sensors(self):
        health = InputHealth(sources_ok=("a",), sources_stale=("b",),
                             history_span_sec=OLD_ENOUGH)
        assert "sensors" in evaluate(health, CALM).suppression.detail


class TestInsufficientData:
    def test_no_source_consulted_at_all_fires_it(self):
        health = InputHealth(history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).reason == V.INSUFFICIENT_DATA

    def test_the_detail_names_the_g17_reports(self):
        health = InputHealth(history_span_sec=OLD_ENOUGH)
        assert "G-17" in evaluate(health, CALM).suppression.detail

    def test_an_underivable_candidate_also_fires_it(self):
        health = healthy()
        verdict = evaluate(health, UNDERIVABLE)
        assert verdict.reason == V.INSUFFICIENT_DATA
        assert verdict.suppression.guard_id == "derivation_produced_nothing"

    def test_the_two_paths_are_distinguishable_by_guard_id(self):
        empty = evaluate(InputHealth(history_span_sec=OLD_ENOUGH), CALM)
        underivable = evaluate(healthy(), UNDERIVABLE)
        assert empty.reason == underivable.reason == V.INSUFFICIENT_DATA
        assert empty.suppression.guard_id != underivable.suppression.guard_id

    def test_the_derivations_detail_is_carried_verbatim(self):
        verdict = evaluate(healthy(), UNDERIVABLE)
        assert verdict.suppression.detail == "no window held enough samples"


class TestCalibrationPending:
    def test_a_young_scenario_cannot_report_calm(self):
        health = InputHealth(sources_ok=("a", "b"), history_span_sec=3600.0)
        assert evaluate(health, CALM).reason == V.CALIBRATION_PENDING

    def test_it_resolves_once_the_window_is_full(self):
        health = InputHealth(sources_ok=("a", "b"),
                             history_span_sec=OLD_ENOUGH)
        assert evaluate(health, CALM).available is True

    def test_the_boundary_is_inclusive_of_a_full_window(self):
        health = InputHealth(sources_ok=("a",),
                             history_span_sec=T.CALIBRATION_MIN_HISTORY_SEC)
        assert evaluate(health, CALM).available is True

    def test_the_detail_says_it_is_self_resolving(self):
        health = InputHealth(sources_ok=("a",), history_span_sec=0.0)
        assert "fills" in evaluate(health, CALM).suppression.detail

    def test_the_window_matches_the_calibration_window(self):
        assert T.CALIBRATION_MIN_HISTORY_DAYS == 30.0


class TestNP1Asymmetry:
    """A guard may quiet a calm verdict. It may never withhold an alarm."""

    @pytest.mark.parametrize("health", [
        InputHealth(sources_failed=("a", "b"), history_span_sec=OLD_ENOUGH),
        InputHealth(sources_ok=("a",), sources_stale=("b",),
                    history_span_sec=OLD_ENOUGH),
        InputHealth(sources_ok=("a",), history_span_sec=0.0),
    ])
    def test_an_alerting_candidate_is_always_published(self, health):
        verdict = evaluate(health, ALERT)
        assert verdict.available is True
        assert verdict.reason is None

    def test_the_near_miss_is_recorded_as_an_overridden_suppression(self):
        health = InputHealth(sources_failed=("a",),
                             history_span_sec=OLD_ENOUGH)
        verdict = evaluate(health, ALERT)
        assert verdict.suppression.overridden is True
        assert verdict.suppression.reason == V.UPSTREAM_FAILURE
        assert "NP1" in verdict.suppression.detail

    def test_an_alerting_candidate_with_no_basis_is_not_overridden(self):
        # The override's one limit. NP1 says publish an alarm from
        # PARTIAL evidence; with NO source consulted there is nothing for
        # the alarm to be about. Overriding here would produce a state
        # that `Conclusion` refuses (G-17), the DomainError would
        # propagate out of derive_all, and the tick would lose all five
        # conclusions — for exactly the alerting scenarios, while calm
        # ones recorded cleanly. Silence about the loudest scenario is
        # the worst available reading of NP1.
        health = InputHealth(history_span_sec=OLD_ENOUGH)
        verdict = evaluate(health, ALERT)
        assert verdict.available is False
        assert verdict.reason == V.INSUFFICIENT_DATA
        assert verdict.suppression.overridden is False
        assert "no evidence for an alarm" in verdict.suppression.detail

    def test_that_alerting_scenario_still_produces_a_conclusion(self):
        health = InputHealth(history_span_sec=OLD_ENOUGH)
        conclusion = build(
            scenario_id="s", conclusion_type=V.THREAT_LEVEL,
            observed_at=NOW, confidence=0.9, provenance=provenance(),
            input_health=health, availability=evaluate(health, ALERT))
        assert conclusion.unavailable_reason == V.INSUFFICIENT_DATA
        assert conclusion.state is None

    def test_the_type_still_refuses_a_state_built_from_nothing(self):
        # Belt and braces: even if a caller hand-assembled an Availability
        # that said "publish", the Conclusion type refuses the verdict.
        health = InputHealth(history_span_sec=OLD_ENOUGH)
        forged = evaluate(healthy(), ALERT)
        with pytest.raises(DomainError, match="G-17"):
            build(scenario_id="s", conclusion_type=V.THREAT_LEVEL,
                  observed_at=NOW, confidence=0.9, provenance=provenance(),
                  input_health=health, availability=forged, state="1")

    def test_an_underivable_candidate_cannot_claim_to_be_alerting(self):
        with pytest.raises(DomainError, match="asymmetry runs one way"):
            Candidate(state=None, calm=False, derivable=False, detail="x")


class TestGuardChainDisclosure:
    def test_every_guard_is_evaluated_even_after_one_fires(self):
        health = InputHealth(sources_failed=("a",), history_span_sec=0.0)
        verdict = evaluate(health, CALM)
        assert len(verdict.suppression.evaluated) == len(GUARDS)

    def test_the_losing_guards_are_visible_with_their_verdicts(self):
        health = InputHealth(sources_failed=("a",), history_span_sec=0.0)
        verdict = evaluate(health, CALM)
        fired = {item.guard_id for item in verdict.suppression.evaluated
                 if item.fired}
        assert fired == {"upstream_total_loss", "sensor_coverage_degraded",
                         "history_below_calibration_window"}

    def test_the_first_firing_guard_owns_the_outcome(self):
        health = InputHealth(sources_failed=("a",), history_span_sec=0.0)
        verdict = evaluate(health, CALM)
        assert verdict.reason == V.UPSTREAM_FAILURE

    def test_a_guard_that_did_not_fire_still_says_so(self):
        verdict = evaluate(InputHealth(sources_failed=("a",),
                                       history_span_sec=OLD_ENOUGH), CALM)
        quiet = [item for item in verdict.suppression.evaluated
                 if not item.fired]
        assert quiet and all(item.detail for item in quiet)

    def test_a_healthy_tick_produces_no_suppression_at_all(self):
        verdict = evaluate(healthy(), CALM)
        assert verdict.available and verdict.suppression is None

    def test_evaluate_refuses_a_bare_dict_for_health(self):
        with pytest.raises(TypeError, match="G-17"):
            evaluate({"sources_ok": ["a"]}, CALM)

    def test_evaluate_refuses_a_bare_string_candidate(self):
        with pytest.raises(TypeError):
            evaluate(healthy(), "5")


class TestInputHealthArithmetic:
    def test_ratios_are_zero_when_nothing_was_consulted(self):
        health = InputHealth()
        assert health.failure_ratio == 0.0 and health.degraded_ratio == 0.0

    def test_has_no_basis_only_when_truly_empty(self):
        assert InputHealth().has_no_basis is True
        assert InputHealth(sources_failed=("a",)).has_no_basis is False

    def test_a_negative_history_span_is_refused(self):
        with pytest.raises(DomainError, match="non-negative"):
            InputHealth(history_span_sec=-1.0)

    def test_it_is_immutable(self):
        health = healthy()
        with pytest.raises(Exception):
            health.sources_ok = ()
