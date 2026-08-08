"""S5-VERIF-037 / S5-VERIF-035 — a degenerate cell cannot be evidence, and
the recall arithmetic exists once.

Incident #1 (2026-05-29): the RSS ETL labelled every match TRUE_POSITIVE,
so FN was identically 0 and recall was pinned at 1.0. The gate kept
passing. It was guarding a number that could not move.

The live baseline still has the shape: 5 of its 8 cells are fn=0 ∧ tn=0.
S5-VERIF-037 is explicit that detection must be by PREDICATE, not by
count — the spec itself carried the wrong count (4) until a 2026-08-06
file check corrected it to 5, which is exactly the failure mode a count
invites.
"""
from __future__ import annotations

import pytest

from v3.calibration import epoch as E
from v3.calibration import matrix as M
from v3.calibration import recall as R
from v3.kernel.errors import DomainError


def cell(**kw):
    base = dict(scenario_id="taiwan_contingency", conclusion_type="threat_level",
                tp=10, fp=2, tn=3, fn=4, distinct_analysts=2,
                epoch_id="e2026_08_02")
    base.update(kw)
    return M.ConfusionCell(**base)


class TestRecallArithmetic:
    """S1-CALIB-026 / S1-CONC-030, ported by value."""

    def test_recall_is_tp_over_tp_plus_fn(self):
        assert R.recall(tp=3, fn=1) == 0.75

    def test_precision_is_tp_over_tp_plus_fp(self):
        assert R.precision(tp=3, fp=1) == 0.75

    def test_a_zero_denominator_is_none_not_zero(self):
        # DP23: the calibrator's max(1, ·) reads 0.0, the aggregation layer
        # reads None. 0.0 says "measured, and terrible"; None says "not
        # measured". Only one of those is true.
        assert R.recall(tp=0, fn=0) is None
        assert R.precision(tp=0, fp=0) is None

    def test_miss_rate_is_one_minus_recall_and_none_propagates(self):
        assert R.miss_rate(tp=3, fn=1) == 0.25
        assert R.miss_rate(tp=0, fn=0) is None

    def test_negative_counts_are_refused(self):
        with pytest.raises(DomainError):
            R.recall(tp=-1, fn=1)

    def test_non_integer_counts_are_refused(self):
        with pytest.raises(DomainError):
            R.recall(tp=1.5, fn=1)

    def test_booleans_are_not_counts(self):
        with pytest.raises(DomainError):
            R.recall(tp=True, fn=1)


class TestThereIsExactlyOneRecallImplementation:
    """S5-VERIF-035, enforced by reading the package, not by convention.

    Production has three implementations with different windows, dedup
    rules and type filters. A fourth would be invisible here without this
    check.
    """

    def test_no_module_outside_recall_py_divides_tp_by_a_denominator(self):
        offenders = M.audit_recall_arithmetic_sites()
        assert offenders == (), (
            f"recall arithmetic outside v3/calibration/recall.py: "
            f"{offenders}")

    def test_the_cell_delegates_rather_than_recomputing(self):
        c = cell(tp=3, fn=1)
        assert c.recall == R.recall(tp=3, fn=1)


class TestDegenerateCells:
    """The predicate, and what it refuses."""

    def test_a_cell_with_no_negatives_at_all_is_degenerate(self):
        assert cell(fn=0, tn=0).is_degenerate is True

    def test_one_true_negative_is_enough_to_be_non_degenerate(self):
        # middle_east/threat_level in the live baseline: tn=1, so it is
        # NOT degenerate. This boundary is why a count is the wrong test.
        assert cell(fn=0, tn=1).is_degenerate is False

    def test_one_false_negative_is_enough_to_be_non_degenerate(self):
        assert cell(fn=1, tn=0).is_degenerate is False

    def test_a_degenerate_cell_reports_recall_one_which_is_the_trap(self):
        c = cell(tp=5, fn=0, tn=0, fp=10)
        assert c.recall == 1.0
        assert c.is_degenerate is True

    def test_an_empty_cell_is_degenerate_and_has_no_recall(self):
        c = cell(tp=0, fp=0, tn=0, fn=0)
        assert c.is_degenerate is True
        assert c.recall is None

    def test_the_status_of_a_degenerate_cell_is_its_own_value(self):
        assert cell(fn=0, tn=0).status == M.DEGENERATE

    def test_thin_positive_evidence_is_insufficient_not_ok(self):
        # S5-VERIF-037: tp + fn < 5.
        assert cell(tp=2, fn=1, tn=4).status == M.INSUFFICIENT_DATA
        assert cell(tp=4, fn=1, tn=4).status == M.OK

    def test_the_denominator_boundary_of_five_is_sufficient(self):
        assert cell(tp=4, fn=1, tn=2).status != M.INSUFFICIENT_DATA

    def test_degenerate_wins_over_insufficient(self):
        # A cell can be both; the degenerate label is the more specific
        # and the more dangerous, so it must be the one reported.
        assert cell(tp=1, fp=0, tn=0, fn=0).status == M.DEGENERATE


class TestDegenerateCellsCannotBecomeEvidence:
    """The type-level refusal condition 4 and S5-VERIF-037 ask for."""

    def test_a_healthy_cell_becomes_evidence(self):
        ev = M.CalibrationEvidence.from_cells(
            (cell(),), stamp=_stamp())
        assert ev.cell_count == 1

    def test_a_degenerate_cell_is_refused_at_construction(self):
        with pytest.raises(M.DegenerateEvidenceError) as exc:
            M.CalibrationEvidence.from_cells(
                (cell(fn=0, tn=0),), stamp=_stamp())
        assert "recall is 1.0 by construction" in str(exc.value)

    def test_one_degenerate_cell_poisons_the_whole_evidence_set(self):
        # Not "filtered out quietly": the caller has to say what it wants.
        # Silently dropping is how a set of 8 cells reports on 3 while
        # looking like it reported on 8.
        with pytest.raises(M.DegenerateEvidenceError):
            M.CalibrationEvidence.from_cells(
                (cell(), cell(fn=0, tn=0, conclusion_type="attack_mode")),
                stamp=_stamp())

    def test_dropping_degenerate_cells_is_explicit_and_recorded(self):
        ev = M.CalibrationEvidence.from_cells(
            (cell(), cell(fn=0, tn=0, conclusion_type="attack_mode")),
            stamp=_stamp(), drop_degenerate=True)
        assert ev.cell_count == 1
        assert ev.degenerate_dropped == ("taiwan_contingency/attack_mode",)

    def test_evidence_of_nothing_but_degenerate_cells_is_still_refused(self):
        with pytest.raises(M.DegenerateEvidenceError, match="every cell"):
            M.CalibrationEvidence.from_cells(
                (cell(fn=0, tn=0),), stamp=_stamp(), drop_degenerate=True)

    def test_evidence_cells_must_share_the_stamp_epoch(self):
        with pytest.raises(E.EpochMismatchError):
            M.CalibrationEvidence.from_cells(
                (cell(epoch_id="e2026_07_04"),), stamp=_stamp())

    def test_evidence_is_frozen(self):
        ev = M.CalibrationEvidence.from_cells((cell(),), stamp=_stamp())
        with pytest.raises((AttributeError, DomainError)):
            ev.cells = ()

    def test_a_relaxing_subclass_is_refused(self):
        with pytest.raises(TypeError, match="final"):
            class Loose(M.CalibrationEvidence):
                pass

    def test_evidence_cannot_be_built_by_the_bare_constructor(self):
        # from_cells is the validating door. If the dataclass constructor
        # were usable directly, the refusal would be optional.
        with pytest.raises(DomainError, match="from_cells"):
            M.CalibrationEvidence(cells=(cell(fn=0, tn=0),),
                                  stamp=_stamp(), degenerate_dropped=(),
                                  _token=None)

    def test_pooled_recall_uses_the_one_implementation(self):
        ev = M.CalibrationEvidence.from_cells(
            (cell(tp=3, fn=1), cell(tp=1, fn=1, conclusion_type="attack_mode")),
            stamp=_stamp())
        assert ev.pooled_recall == R.recall(tp=4, fn=2)


class TestDegenerateAuditOverASnapshot:
    """WP-1.4's L5 signature, as a predicate over any snapshot."""

    def test_it_names_the_degenerate_cells_rather_than_counting_them(self):
        cells = (cell(), cell(fn=0, tn=0, conclusion_type="attack_mode"),
                 cell(fn=0, tn=0, scenario_id="korean_peninsula",
                      conclusion_type="attack_mode"))
        report = M.degenerate_audit(cells)
        assert report["degenerate"] == ("korean_peninsula/attack_mode",
                                        "taiwan_contingency/attack_mode")
        assert report["non_degenerate"] == ("taiwan_contingency/threat_level",)

    def test_an_all_degenerate_snapshot_is_flagged_as_no_evidence(self):
        report = M.degenerate_audit((cell(fn=0, tn=0),))
        assert report["has_any_evidence"] is False

    def test_the_audit_never_reports_a_hardcoded_expected_count(self):
        # The spec's own count was wrong once (4 vs the actual 5). Any
        # constant in this position would be wrong again at the next
        # re-baseline.
        import inspect
        src = inspect.getsource(M.degenerate_audit)
        assert " 5" not in src and " 4" not in src


def _stamp():
    started = E.epoch("e2026_08_02").started_at
    return E.EpochStamp(epoch_id="e2026_08_02", since=started + 1.0,
                        until=started + 1000.0, exclude_auto=False)
