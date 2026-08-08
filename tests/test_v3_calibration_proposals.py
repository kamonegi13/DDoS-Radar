"""S1-CALIB-015/018/019/056 — proposal generation, pure and disclosed."""
from __future__ import annotations

import pytest

from v3.calibration import authority as A
from v3.calibration import epoch as E
from v3.calibration import guards as G
from v3.calibration import matrix as M
from v3.calibration import proposals as P
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError
from v3.kernel.provenance import Provenance


def _cell(**kw):
    base = dict(scenario_id="korean_peninsula",
                conclusion_type="threat_level", tp=6, fp=4, tn=5, fn=5,
                distinct_analysts=3, epoch_id="e2026_08_02")
    base.update(kw)
    return M.ConfusionCell(**base)


def _stamp():
    started = E.epoch("e2026_08_02").started_at
    return E.EpochStamp(epoch_id="e2026_08_02", since=started + 1.0,
                        until=started + 30 * 86400.0, exclude_auto=False)


def _evidence(cell=None):
    return M.CalibrationEvidence.from_cells((cell or _cell(),),
                                            stamp=_stamp())


class TestDirectionDecision:
    """S1-CALIB-015's four branches, in the module's own order."""

    def test_recall_below_the_floor_loosens(self):
        # recall 6/11 = 0.545
        assert P.decide_direction(_cell()).direction == "looser"

    def test_the_recall_floor_boundary_does_not_fire(self):
        # recall exactly 0.80 -> not looser.
        cell = _cell(tp=8, fn=2, tn=5, fp=90)
        assert P.decide_direction(cell).direction != "looser"

    def test_recall_is_checked_before_precision(self):
        # Low recall AND low precision: the recall branch owns it.
        cell = _cell(tp=1, fn=9, fp=99, tn=5)
        assert P.decide_direction(cell).direction == "looser"

    def test_the_degenerate_guard_refuses_to_tighten(self):
        cell = _cell(tp=167, fp=497, tn=0, fn=0)
        decision = P.decide_direction(cell)
        assert decision.direction is None
        assert decision.reason == "degenerate_data_guard"

    def test_high_recall_and_low_precision_tightens(self):
        cell = _cell(tp=100, fn=0, fp=300, tn=5)
        assert P.decide_direction(cell).direction == "tighter"

    def test_the_precision_ceiling_boundary_does_not_fire(self):
        # precision exactly 0.30 -> no tighten.
        cell = _cell(tp=30, fn=0, fp=70, tn=5)
        assert cell.precision == 0.30
        assert P.decide_direction(cell).direction is None

    def test_healthy_metrics_produce_no_action(self):
        cell = _cell(tp=90, fn=5, fp=5, tn=20)
        assert P.decide_direction(cell).reason == "no_action_needed"

    def test_an_unmeasurable_recall_never_loosens(self):
        # DP23: production's max(1, tp+fn) reports 0.0 here and would
        # loosen on a measurement that does not exist.
        cell = _cell(tp=0, fn=0, tn=5, fp=5)
        decision = P.decide_direction(cell)
        assert decision.direction is None
        assert decision.reason == "recall_or_precision_unmeasurable"

    def test_the_degenerate_precision_bound_matches_production(self):
        assert T.CALIBRATOR_PRECISION_MIN_FLOOR \
            + T.CALIBRATOR_DEGENERATE_PRECISION_MARGIN == \
            pytest.approx(T.CALIBRATOR_PRECISION_CEILING)


class TestStep:
    """S1-CALIB-018 with DP22's absolute bounds."""

    def test_loosening_is_five_percent_down_rounded_to_three(self):
        assert P.stepped_value(9.0, direction="looser",
                               band_default=9.0) == 8.55

    def test_tightening_is_five_percent_up(self):
        assert P.stepped_value(9.0, direction="tighter",
                               band_default=9.0) == 9.45

    def test_repeated_loosening_stops_at_an_absolute_floor(self):
        # DP22: production has no bound, so 0.95^n converges to zero. The
        # Middle East band took twelve consecutive loosenings.
        value = 9.0
        for _ in range(30):
            value = P.stepped_value(value, direction="looser",
                                    band_default=9.0)
        assert value == 9.0 * P.ABSOLUTE_FLOOR_FRACTION

    def test_repeated_tightening_stops_at_an_absolute_ceiling(self):
        value = 9.0
        for _ in range(60):
            value = P.stepped_value(value, direction="tighter",
                                    band_default=9.0)
        assert value == 9.0 * P.ABSOLUTE_CEILING_FRACTION

    def test_the_five_bands_and_their_defaults_match_production(self):
        assert P.DEFAULT_TL_THRESHOLDS == {
            "tl1_total": 9.0, "tl1_physical": 3.0, "tl2_total": 6.0,
            "tl3_total": 4.0, "tl4_total": 2.0}

    def test_an_unknown_direction_is_refused(self):
        with pytest.raises(DomainError):
            P.stepped_value(9.0, direction="sideways", band_default=9.0)


class TestImpact:
    """S1-CALIB-056's norm."""

    def test_raising_recall_is_low_impact(self):
        assert P.impact_of("looser") == "low"

    def test_reducing_recall_is_high_impact(self):
        assert P.impact_of("tighter") == "high"


class TestGeneration:

    def test_every_band_gets_a_proposal(self):
        result = P.generate(_evidence(), scenario_id="korean_peninsula",
                            current_values={}, computed_at=1000.0)
        assert {p.band for p in result} == set(P.DEFAULT_TL_THRESHOLDS)

    def test_generation_is_pure_and_repeatable(self):
        args = dict(scenario_id="korean_peninsula", current_values={},
                    computed_at=1000.0)
        first = P.generate(_evidence(), **args)
        second = P.generate(_evidence(), **args)
        assert [p.as_dict() for p in first] == [p.as_dict() for p in second]

    def test_no_direction_means_no_proposals(self):
        healthy = _cell(tp=90, fn=5, fp=5, tn=20)
        assert P.generate(_evidence(healthy),
                          scenario_id="korean_peninsula",
                          current_values={}, computed_at=1000.0) == ()

    def test_a_scenario_with_no_threat_level_cell_yields_nothing(self):
        cell = _cell(conclusion_type="attack_mode")
        assert P.generate(_evidence(cell), scenario_id="korean_peninsula",
                          current_values={}, computed_at=1000.0) == ()

    def test_a_raw_cell_list_is_refused(self):
        with pytest.raises(DomainError, match="CalibrationEvidence"):
            P.generate((_cell(),), scenario_id="korean_peninsula",
                       current_values={}, computed_at=1000.0)

    def test_degenerate_evidence_cannot_reach_generation_at_all(self):
        with pytest.raises(M.DegenerateEvidenceError):
            P.generate(M.CalibrationEvidence.from_cells(
                (_cell(tp=5, fp=10, tn=0, fn=0),), stamp=_stamp()),
                scenario_id="korean_peninsula", current_values={},
                computed_at=1000.0)

    def test_every_proposal_carries_provenance(self):
        result = P.generate(_evidence(), scenario_id="korean_peninsula",
                            current_values={}, computed_at=1000.0)
        assert all(isinstance(p.provenance, Provenance) for p in result)

    def test_the_provenance_records_the_freshness_inputs(self):
        # DP2: production's evidence omits these, so the ledger cannot
        # say which false negative justified the change.
        result = P.generate(_evidence(), scenario_id="korean_peninsula",
                            current_values={}, computed_at=1000.0,
                            motivating_at=900.0, last_applied_at=500.0)
        inputs = result[0].provenance.inputs
        assert inputs["motivating_at"] == 900.0
        assert inputs["last_applied_at"] == 500.0

    def test_the_provenance_records_the_epoch_and_window(self):
        result = P.generate(_evidence(), scenario_id="korean_peninsula",
                            current_values={}, computed_at=1000.0)
        assert result[0].provenance.inputs["epoch_id"] == "e2026_08_02"
        assert "window_since" in result[0].provenance.inputs

    def test_the_formula_ref_names_the_band_and_direction(self):
        result = P.generate(_evidence(), scenario_id="korean_peninsula",
                            current_values={}, computed_at=1000.0)
        band = next(p for p in result if p.band == "tl1_total")
        assert band.formula_ref.endswith("#tl1_total_looser")

    def test_a_proposal_that_changes_nothing_is_not_issued(self):
        at_floor = {b: v * P.ABSOLUTE_FLOOR_FRACTION
                    for b, v in P.DEFAULT_TL_THRESHOLDS.items()}
        assert P.generate(_evidence(), scenario_id="korean_peninsula",
                          current_values=at_floor, computed_at=1000.0) == ()

    def test_a_proposal_cannot_be_built_without_provenance(self):
        with pytest.raises(DomainError, match="Provenance"):
            P.Proposal(key="k", scope_scenario_id="s", band="tl1_total",
                       prior_value=9.0, proposed_value=8.55,
                       direction="looser", impact="low", sample_n=30,
                       formula_ref="f", provenance=None)


class TestApplicationNeedsThePermit:
    """The structural half of condition 1, on the write side."""

    def _proposal(self):
        issued = P.generate(_evidence(), scenario_id="korean_peninsula",
                            current_values={}, computed_at=1000.0)
        return next(p for p in issued if p.band == "tl1_total")

    def _permit(self):
        actor = A.Actor.analyst("a.tanaka")
        request = G.GuardRequest(
            phase=G.PHASE_APPLICATION,
            authorisation=A.authorize(actor, "apply_proposal"),
            draft=G.ProposalDraft(
                proposal_type="tl_threshold", scenario_id="korean_peninsula",
                target_country=None, direction="looser", impact="low",
                prior_value=9.0, proposed_value=8.55),
            evidence=M.CalibrationEvidence.from_cells(
                (_cell(tp=10, fp=6, tn=8, fn=8),), stamp=_stamp()),
            state=G.SystemState(
                now=2000.0, tier=3, last_applied_at=None,
                motivating_at=1500.0, high_applied_at=None,
                recall_status=M.OK, target_role="strategic_observer",
                threshold_key="tl_thresholds.korean_peninsula.tl1_total",
                scope_scenario_id="korean_peninsula"))
        return G.evaluate(request).permit()

    def test_a_permit_turns_a_proposal_into_a_ledger_row(self):
        row = P.apply_to_ledger_row(
            self._proposal(), permit=self._permit(), effective_from=3000.0,
            row_id="r1", revertible_to_id=None, applied_by="a.tanaka")
        assert row.value == 8.55
        assert row.state == "active"

    def test_application_without_a_permit_is_refused(self):
        with pytest.raises(DomainError, match="Permit"):
            P.apply_to_ledger_row(
                self._proposal(), permit=None, effective_from=3000.0,
                row_id="r1", revertible_to_id=None, applied_by="x")

    def test_a_generation_permit_is_refused_at_the_application_door(self):
        actor = A.Actor.analyst("a.tanaka")
        request = G.GuardRequest(
            phase=G.PHASE_GENERATION,
            authorisation=A.authorize(actor, "generate_proposal"),
            draft=G.ProposalDraft(
                proposal_type="tl_threshold", scenario_id="korean_peninsula",
                target_country=None, direction="looser", impact="low",
                prior_value=9.0, proposed_value=8.55),
            evidence=M.CalibrationEvidence.from_cells(
                (_cell(tp=10, fp=6, tn=8, fn=8),), stamp=_stamp()),
            state=G.SystemState(
                now=2000.0, tier=3, last_applied_at=None,
                motivating_at=1500.0, high_applied_at=None,
                recall_status=M.OK, target_role="strategic_observer",
                threshold_key="k", scope_scenario_id="korean_peninsula"))
        with pytest.raises(G.GuardRefusedError):
            P.apply_to_ledger_row(
                self._proposal(), permit=G.evaluate(request).permit(),
                effective_from=3000.0, row_id="r1", revertible_to_id=None,
                applied_by="a.tanaka")

    def test_the_row_carries_the_proposals_disclosure(self):
        row = P.apply_to_ledger_row(
            self._proposal(), permit=self._permit(), effective_from=3000.0,
            row_id="r1", revertible_to_id=None, applied_by="a.tanaka")
        assert "recall" in row.evidence
        assert "motivating_at" in row.evidence
