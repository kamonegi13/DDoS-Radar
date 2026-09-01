"""S1-CONC-029/030/038 and the Design W gate (S1-CALIB-029 / S5-VERIF-038).

Three of the ten clauses WP-3.1 deferred to WP-3.2, plus the gate that
consumes them. The gate tests are where F-16's repair is visible from the
outside: there is no way to call the comparison with two snapshots.
"""
from __future__ import annotations

import inspect

import pytest

from v3.calibration import epoch as E
from v3.calibration import matrix as M
from v3.calibration import status as S
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError


def _cell(**kw):
    base = dict(scenario_id="taiwan_contingency",
                conclusion_type="threat_level", tp=8, fp=2, tn=4, fn=2,
                distinct_analysts=3, epoch_id="e2026_08_02")
    base.update(kw)
    return M.ConfusionCell(**base)


def _stamp(exclude_auto=False):
    started = E.epoch("e2026_08_02").started_at
    return E.EpochStamp(epoch_id="e2026_08_02", since=started + 1.0,
                        until=started + 30 * 86400.0,
                        exclude_auto=exclude_auto)


def _pair():
    return E.AlignedPair(baseline=_stamp(), current=_stamp())


class TestCalibrationStatus:
    """S1-CONC-029 / 030."""

    def test_the_source_is_the_ground_truth_matrix(self):
        assert S.status_for(_cell()).source == "ground_truth"

    def test_the_three_values(self):
        assert S.status_for(_cell(tp=8, fn=2)).status == "OK"
        assert S.status_for(_cell(tp=2, fn=8)).status == "DEGRADED"
        assert S.status_for(_cell(tp=1, fn=1, tn=9)).status == \
            "INSUFFICIENT_DATA"

    def test_a_missing_cell_is_insufficient_never_an_error(self):
        assert S.status_for(None).status == "INSUFFICIENT_DATA"

    def test_true_negatives_alone_never_reach_ok(self):
        # recall is undefined without an observed positive.
        assert S.status_for(_cell(tp=0, fn=0, tn=40, fp=0)).status == \
            "INSUFFICIENT_DATA"
        assert S.status_for(_cell(tp=0, fn=0, tn=40, fp=3)).recall is None

    def test_the_recall_denominator_decides_not_the_label_total(self):
        assert S.status_for(_cell(tp=2, fn=2, tn=100, fp=100)).status == \
            "INSUFFICIENT_DATA"

    def test_the_denominator_boundary_of_five_is_sufficient(self):
        assert S.status_for(_cell(tp=4, fn=1, tn=3)).status != \
            "INSUFFICIENT_DATA"

    def test_the_degraded_boundary_is_on_the_ok_side(self):
        # recall == 0.70 is OK.
        assert S.status_for(_cell(tp=7, fn=3, tn=2)).recall == 0.7
        assert S.status_for(_cell(tp=7, fn=3, tn=2)).status == "OK"

    def test_precision_is_reported_but_never_decides(self):
        st = S.status_for(_cell(tp=8, fp=100, fn=2, tn=4))
        assert st.precision is not None and st.status == "OK"

    def test_the_window_is_the_pinned_thirty_days(self):
        assert S.status_for(_cell()).window_days == T.CALIBRATION_WINDOW_D
        assert T.CALIBRATION_WINDOW_D == 30.0

    def test_the_status_carries_the_epoch_it_was_measured_under(self):
        assert S.status_for(_cell()).epoch_id == "e2026_08_02"


class TestSelfEvaluation:
    """S1-CONC-038."""

    def test_recall_pools_every_cell(self):
        ev = S.self_evaluate((_cell(tp=3, fn=1),
                              _cell(tp=1, fn=1, conclusion_type="attack_mode")),
                             stamp=_stamp())
        assert ev.recall == pytest.approx(4 / 6)

    def test_recall_uses_the_calibration_window(self):
        ev = S.self_evaluate((_cell(),), stamp=_stamp())
        assert ev.recall_meta["window_days"] == pytest.approx(30.0)

    def test_the_human_and_automatic_label_split_is_disclosed(self):
        ev = S.self_evaluate((_cell(),), stamp=_stamp(), labels_human=0,
                             labels_auto=120)
        assert ev.recall_meta["labels_human"] == 0
        assert ev.recall_meta["labels_auto"] == 120

    def test_a_fully_self_marked_recall_is_visible_in_the_metadata(self):
        # labels_human == 0 means the tool is grading its own homework.
        ev = S.self_evaluate((_cell(),), stamp=_stamp(), labels_auto=50)
        assert ev.recall_meta["labels_human"] == 0

    def test_drift_is_the_mean_miss_rate(self):
        ev = S.self_evaluate((_cell(tp=8, fn=2),
                              _cell(tp=6, fn=4,
                                    conclusion_type="attack_mode")),
                             stamp=_stamp())
        assert ev.drift == pytest.approx((0.2 + 0.4) / 2)

    def test_drift_over_nothing_measurable_is_none_with_a_reason(self):
        # 0.0 would read as "no anomaly", which is the opposite of the
        # truth.
        ev = S.self_evaluate((_cell(tp=0, fn=0, tn=0, fp=5),),
                             stamp=_stamp())
        assert ev.drift is None
        assert ev.drift_error

    def test_drift_excludes_insufficient_cells(self):
        ev = S.self_evaluate((_cell(tp=8, fn=2),
                              _cell(tp=1, fn=1, tn=3,
                                    conclusion_type="attack_mode")),
                             stamp=_stamp())
        assert ev.drift_meta["cells_considered"] == 1

    def test_drift_names_the_worst_cell(self):
        ev = S.self_evaluate((_cell(tp=8, fn=2),
                              _cell(tp=6, fn=4, scenario_id="korean_peninsula")),
                             stamp=_stamp())
        assert ev.drift_meta["worst_cell"] == "korean_peninsula/threat_level"

    def test_degenerate_cells_are_named_in_the_recall_metadata(self):
        ev = S.self_evaluate((_cell(tp=8, fn=2),
                              _cell(tp=5, fn=0, tn=0,
                                    conclusion_type="attack_mode")),
                             stamp=_stamp())
        assert ev.recall_meta["degenerate_cells"] == \
            ["taiwan_contingency/attack_mode"]

    def test_the_metrics_fail_independently(self):
        ev = S.self_evaluate((), stamp=_stamp())
        assert ev.recall is None and ev.recall_error
        assert ev.drift is None and ev.drift_error

    def test_self_evaluation_never_raises(self):
        assert S.self_evaluate((), stamp=_stamp()) is not None


class TestDesignWGate:
    """S1-CALIB-029's six branches + S5-VERIF-037/038."""

    def test_it_takes_only_an_aligned_pair(self):
        params = list(inspect.signature(S.design_w_gate).parameters)
        assert params[0] == "pair"
        # No parameter would accept two loose snapshots; a cross-epoch
        # comparison is not expressible (F-16).
        assert "baseline" not in params and "current" not in params

    def test_a_loose_snapshot_pair_is_refused(self):
        with pytest.raises(DomainError, match="AlignedPair"):
            S.design_w_gate(_stamp(), baseline_cells=(), current_cells=(),
                            max_drop=0.05)

    def test_branch_one_absent_now_is_a_warning_not_a_failure(self):
        result = S.design_w_gate(_pair(), baseline_cells=(_cell(),),
                                 current_cells=(), max_drop=0.05)
        assert result.passed is True
        assert any("absent now" in m for m in result.messages)

    def test_branch_two_a_baseline_without_recall_is_skipped(self):
        base = _cell(tp=0, fn=0, tn=3, fp=2)
        result = S.design_w_gate(_pair(), baseline_cells=(base,),
                                 current_cells=(base,), max_drop=0.05)
        assert result.passed is True
        assert any("no baseline recall" in m or "DEGENERATE" in m
                   for m in result.messages)

    def test_branch_three_coverage_loss_fails(self):
        base = _cell(tp=8, fn=2, tn=3)
        now = _cell(tp=0, fn=0, tn=3, fp=1)
        result = S.design_w_gate(_pair(), baseline_cells=(base,),
                                 current_cells=(now,), max_drop=0.05)
        assert result.passed is False

    def test_branch_four_a_drop_beyond_tolerance_fails(self):
        result = S.design_w_gate(
            _pair(), baseline_cells=(_cell(tp=9, fn=1, tn=3),),
            current_cells=(_cell(tp=5, fn=5, tn=3),), max_drop=0.05)
        assert result.passed is False
        assert any(m.startswith("FAIL") for m in result.messages)

    def test_branch_five_the_tolerance_boundary_passes(self):
        # drop == max_drop is on the PASSING side.
        base = _cell(tp=20, fn=0, tn=3)      # recall 1.00
        now = _cell(tp=19, fn=1, tn=3)       # recall 0.95, drop 0.05
        result = S.design_w_gate(_pair(), baseline_cells=(base,),
                                 current_cells=(now,), max_drop=0.05)
        assert result.passed is True

    def test_a_drop_one_ulp_past_the_boundary_fails(self):
        base = _cell(tp=20, fn=0, tn=3)
        now = _cell(tp=18, fn=2, tn=3)       # recall 0.90, drop 0.10
        result = S.design_w_gate(_pair(), baseline_cells=(base,),
                                 current_cells=(now,), max_drop=0.05)
        assert result.passed is False

    def test_branch_six_a_new_cell_is_informational(self):
        result = S.design_w_gate(_pair(), baseline_cells=(),
                                 current_cells=(_cell(),), max_drop=0.05)
        assert result.passed is True
        assert any("new cell" in m for m in result.messages)

    def test_a_degenerate_baseline_cell_cannot_carry_a_verdict(self):
        # S5-VERIF-037. Five of the live baseline's eight cells are here.
        base = _cell(tp=5, fp=10, tn=0, fn=0)
        result = S.design_w_gate(_pair(), baseline_cells=(base,),
                                 current_cells=(base,), max_drop=0.05)
        assert any("DEGENERATE" in m for m in result.messages)
        assert result.passed is True

    def test_a_cell_that_becomes_degenerate_fails(self):
        # Recall would read 1.0 and look like an improvement.
        base = _cell(tp=8, fn=2, tn=3)
        now = _cell(tp=8, fn=0, tn=0)
        result = S.design_w_gate(_pair(), baseline_cells=(base,),
                                 current_cells=(now,), max_drop=0.05)
        assert result.passed is False
        assert any("became DEGENERATE" in m for m in result.messages)

    def test_the_result_records_the_epoch_it_ran_under(self):
        assert S.design_w_gate(_pair(), baseline_cells=(),
                               current_cells=(), max_drop=0.05
                               ).epoch_id == "e2026_08_02"

    def test_the_tolerance_is_an_explicit_argument(self):
        # S5-VERIF-038 objects to check_ci.sh calling the gate with no
        # arguments and depending on a default.
        params = inspect.signature(S.design_w_gate).parameters
        assert "max_drop" in params
        assert params["max_drop"].default == T.DESIGN_W_MAX_DROP
