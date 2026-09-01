"""S1-CALIB-022/023/024/025 + 063 — the threshold ledger and revert.

Clause 023 is one of the twelve incident-derived guards: it is the path
the 2026-07-03 and 2026-08-02 remediations used to roll the Korean and
Middle Eastern thresholds back after the calibrator had walked them down
by -5%, twelve times and four times respectively.
"""
from __future__ import annotations

import pytest

from v3.calibration import authority as A
from v3.calibration import history as H
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError


def _row(row_id="r1", value=9.0, scope="korean_peninsula",
         effective_from=1000.0, state=H.STATE_ACTIVE, revertible_to=None,
         key="tl_thresholds.korean_peninsula.tl1_total"):
    return H.ThresholdRow(
        row_id=row_id, key=key, value=value, scope_scenario_id=scope,
        effective_from=effective_from, effective_to=None, state=state,
        applied_by="auto:tl_calibrator", derived_from=None,
        revertible_to_id=revertible_to, sample_n=42,
        formula_ref="tl_threshold_calibrator/v1#tl1_total_looser",
        evidence={"recall": 0.6}, magnitude_pct=-5.0)


def _permit(action):
    return A.authorize(A.Actor.analyst("a.tanaka"), action)


class TestAppendOnlyLedger:

    def test_a_new_row_supersedes_the_prior_active_row(self):
        rows = H.record_change((_row(),), new_row=_row(
            row_id="r2", value=8.55, effective_from=2000.0),
            authorisation=_permit("record_threshold_change"))
        prior = next(r for r in rows if r.row_id == "r1")
        assert prior.state == H.STATE_SUPERSEDED
        assert prior.effective_to == 2000.0

    def test_the_windows_are_contiguous_and_the_new_row_wins_the_boundary(self):
        rows = H.record_change((_row(),), new_row=_row(
            row_id="r2", value=8.55, effective_from=2000.0),
            authorisation=_permit("record_threshold_change"))
        assert H.value_at(rows, key=_row().key, at=2000.0,
                          scenario_id="korean_peninsula").row_id == "r2"
        assert H.value_at(rows, key=_row().key, at=1999.9,
                          scenario_id="korean_peninsula").row_id == "r1"

    def test_a_point_in_time_query_is_not_filtered_by_state(self):
        # A row that later became superseded was genuinely in force then.
        rows = H.record_change((_row(),), new_row=_row(
            row_id="r2", effective_from=2000.0),
            authorisation=_permit("record_threshold_change"))
        assert H.value_at(rows, key=_row().key, at=1500.0,
                          scenario_id="korean_peninsula").state == \
            H.STATE_SUPERSEDED

    def test_the_current_query_sees_only_the_active_row(self):
        rows = H.record_change((_row(),), new_row=_row(
            row_id="r2", value=8.55, effective_from=2000.0),
            authorisation=_permit("record_threshold_change"))
        assert H.current(rows, key=_row().key,
                         scenario_id="korean_peninsula").value == 8.55

    def test_scope_resolution_prefers_the_scenario_over_the_global(self):
        rows = (_row(row_id="g", value=9.0, scope=None),
                _row(row_id="s", value=4.0, scope="korean_peninsula"))
        assert H.current(rows, key=_row().key,
                         scenario_id="korean_peninsula").value == 4.0

    def test_scope_resolution_falls_back_to_the_global_row(self):
        rows = (_row(row_id="g", value=9.0, scope=None),)
        assert H.current(rows, key=_row().key,
                         scenario_id="korean_peninsula").value == 9.0

    def test_an_undefined_key_resolves_to_nothing(self):
        assert H.current((), key="nope", scenario_id="x") is None

    def test_reusing_a_row_id_is_refused(self):
        with pytest.raises(DomainError, match="append-only"):
            H.record_change((_row(),), new_row=_row(),
                            authorisation=_permit("record_threshold_change"))

    def test_recording_requires_authorisation(self):
        with pytest.raises(A.UnauthorizedError):
            H.record_change((), new_row=_row(),
                            authorisation=_permit("apply_proposal"))

    def test_the_input_rows_are_not_mutated(self):
        original = _row()
        H.record_change((original,), new_row=_row(row_id="r2",
                                                  effective_from=2000.0),
                        authorisation=_permit("record_threshold_change"))
        assert original.state == H.STATE_ACTIVE
        assert original.effective_to is None


class TestRevert:
    """S1-CALIB-023's four preconditions, incident #2/#3's repair path."""

    def _walked_down(self):
        return (_row(row_id="r1", value=9.0, effective_from=1000.0,
                     state=H.STATE_SUPERSEDED),
                _row(row_id="r2", value=8.55, effective_from=2000.0,
                     revertible_to="r1"))

    def test_a_revert_restores_the_predecessors_value_as_a_new_row(self):
        rows = H.revert(self._walked_down(), row_id="r2", at=3000.0,
                        new_row_id="r3",
                        authorisation=_permit("revert_threshold_change"))
        restored = next(r for r in rows if r.row_id == "r3")
        assert restored.value == 9.0
        assert restored.state == H.STATE_ACTIVE

    def test_the_reverted_row_is_marked_not_deleted(self):
        rows = H.revert(self._walked_down(), row_id="r2", at=3000.0,
                        new_row_id="r3",
                        authorisation=_permit("revert_threshold_change"))
        assert next(r for r in rows if r.row_id == "r2").state == \
            H.STATE_REVERTED

    def test_the_new_row_records_what_it_undid(self):
        rows = H.revert(self._walked_down(), row_id="r2", at=3000.0,
                        new_row_id="r3",
                        authorisation=_permit("revert_threshold_change"))
        restored = next(r for r in rows if r.row_id == "r3")
        assert restored.derived_from == "revert_of:r2"
        assert restored.formula_ref == "threshold_history#revert"
        assert restored.evidence == {"reverted_row_id": "r2",
                                     "restored_from_row_id": "r1"}

    def test_a_missing_target_is_refused(self):
        with pytest.raises(H.RevertRefusedError, match="does not exist"):
            H.revert(self._walked_down(), row_id="nope", at=3000.0,
                     new_row_id="r3",
                     authorisation=_permit("revert_threshold_change"))

    def test_a_non_active_target_is_refused(self):
        with pytest.raises(H.RevertRefusedError, match="not active"):
            H.revert(self._walked_down(), row_id="r1", at=3000.0,
                     new_row_id="r3",
                     authorisation=_permit("revert_threshold_change"))

    def test_a_target_with_no_predecessor_is_refused(self):
        with pytest.raises(H.RevertRefusedError, match="no predecessor"):
            H.revert((_row(row_id="r1"),), row_id="r1", at=3000.0,
                     new_row_id="r3",
                     authorisation=_permit("revert_threshold_change"))

    def test_a_dangling_predecessor_reference_is_refused(self):
        rows = (_row(row_id="r2", revertible_to="ghost"),)
        with pytest.raises(H.RevertRefusedError, match="not in the ledger"):
            H.revert(rows, row_id="r2", at=3000.0, new_row_id="r3",
                     authorisation=_permit("revert_threshold_change"))

    def test_revert_requires_authorisation(self):
        with pytest.raises(A.UnauthorizedError):
            H.revert(self._walked_down(), row_id="r2", at=3000.0,
                     new_row_id="r3",
                     authorisation=_permit("apply_proposal"))

    def test_a_walk_of_four_loosenings_can_be_undone_one_step_at_a_time(self):
        # The Korean shape: -5% four times off the same frozen FNs.
        rows: tuple = (_row(row_id="r0", value=9.0, effective_from=0.0,
                            state=H.STATE_SUPERSEDED),)
        prior = "r0"
        value = 9.0
        for i in range(1, 5):
            value = round(value * T.CALIBRATOR_LOOSER_FACTOR, 3)
            rows = rows + (_row(row_id=f"r{i}", value=value,
                                effective_from=float(i * 1000),
                                state=H.STATE_SUPERSEDED
                                if i < 4 else H.STATE_ACTIVE,
                                revertible_to=prior),)
            prior = f"r{i}"
        assert rows[-1].value == pytest.approx(7.331, abs=1e-3)
        rows = H.revert(rows, row_id="r4", at=9000.0, new_row_id="undo",
                        authorisation=_permit("revert_threshold_change"))
        assert H.current(rows, key=_row().key,
                         scenario_id="korean_peninsula").value == \
            pytest.approx(7.717, abs=1e-3)


class TestLineage:
    """S1-CALIB-024/025 — read-only, capped, and honest about truncation."""

    def _chain(self, n=4):
        rows = [_row(row_id="r0", effective_from=0.0)]
        for i in range(1, n):
            rows.append(_row(row_id=f"r{i}", effective_from=float(i),
                             revertible_to=f"r{i-1}"))
        return tuple(rows)

    def test_it_walks_ancestors(self):
        result = H.lineage(self._chain(), row_id="r3")
        assert [r.row_id for r in result.ancestors] == ["r2", "r1", "r0"]

    def test_it_walks_descendants(self):
        result = H.lineage(self._chain(), row_id="r0")
        assert [r.row_id for r in result.descendants] == ["r1", "r2", "r3"]

    def test_a_complete_walk_says_so(self):
        assert H.lineage(self._chain(), row_id="r3").complete is True

    def test_a_missing_predecessor_makes_the_walk_incomplete(self):
        # DP20: production returns the partial graph and says nothing.
        rows = (_row(row_id="r2", revertible_to="ghost"),)
        result = H.lineage(rows, row_id="r2")
        assert result.complete is False
        assert "missing" in result.truncated_because

    def test_the_depth_cap_is_disclosed_rather_than_silent(self):
        result = H.lineage(self._chain(10), row_id="r9", max_depth=3)
        assert result.complete is False
        assert "depth cap" in result.truncated_because

    def test_the_default_depth_cap_is_fifty(self):
        assert H.MAX_LINEAGE_DEPTH == 50

    def test_a_cycle_is_detected_and_disclosed(self):
        rows = (_row(row_id="a", revertible_to="b"),
                _row(row_id="b", revertible_to="a"))
        result = H.lineage(rows, row_id="a")
        assert result.complete is False
        assert "cycle" in result.truncated_because

    def test_an_unknown_row_is_an_incomplete_walk_not_an_exception(self):
        result = H.lineage((), row_id="nope")
        assert result.complete is False

    def test_lineage_writes_nothing(self):
        rows = self._chain()
        H.lineage(rows, row_id="r3")
        assert all(r.state == H.STATE_ACTIVE for r in rows)


class TestMagnitudeClamp:
    """S1-CALIB-063 — clamps, never rejects, edges intact."""

    def test_a_change_inside_the_budget_passes_through(self):
        value, pct = H.clamp_magnitude(prior=100.0, proposed=105.0,
                                       max_pct=10.0)
        assert (value, pct) == (105.0, 5.0)

    def test_an_excessive_change_is_clamped_to_the_budget(self):
        value, pct = H.clamp_magnitude(prior=100.0, proposed=200.0,
                                       max_pct=10.0)
        assert (value, pct) == (110.0, 10.0)

    def test_the_ledger_records_the_clamped_value_not_the_request(self):
        value, _ = H.clamp_magnitude(prior=100.0, proposed=200.0,
                                     max_pct=10.0)
        assert value != 200.0

    def test_the_clamp_is_symmetric_downward(self):
        value, _ = H.clamp_magnitude(prior=100.0, proposed=10.0,
                                     max_pct=10.0)
        assert value == 90.0

    def test_the_boundary_is_not_clamped(self):
        value, pct = H.clamp_magnitude(prior=100.0, proposed=110.0,
                                       max_pct=10.0)
        assert (value, pct) == (110.0, 10.0)

    def test_a_zero_prior_is_outside_the_budget_entirely(self):
        # ACCIDENTAL A13, preserved: prior == 0 returns the proposal
        # unclamped at magnitude 100.
        assert H.clamp_magnitude(prior=0.0, proposed=99.0,
                                 max_pct=10.0) == (99.0, 100.0)

    def test_a_first_seen_key_commits_verbatim_at_zero_magnitude(self):
        assert H.clamp_magnitude(prior=None, proposed=42.0,
                                 max_pct=10.0) == (42.0, 0.0)

    def test_a_non_numeric_prior_reports_the_maximum_magnitude(self):
        assert H.clamp_magnitude(prior=True, proposed=1.0,
                                 max_pct=10.0)[1] == 100.0

    def test_the_calibrators_own_step_never_reaches_the_budget(self):
        # ACCIDENTAL A3: +-5% against a 10% budget, so the clamp is inert
        # for the one producer that runs every tick.
        _, pct = H.clamp_magnitude(prior=9.0,
                                   proposed=round(9.0 * T.CALIBRATOR_LOOSER_FACTOR,
                                                  3),
                                   max_pct=T.AUTOTUNE_MAX_MAGNITUDE_PCT)
        assert pct < T.AUTOTUNE_MAX_MAGNITUDE_PCT
