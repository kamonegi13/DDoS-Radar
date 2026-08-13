"""WP-5.1 — P2 §5's SEVENTEEN cutover conditions, after ADR-V3-011.

The 2026-08-09 revision rewrote what the gate measures: parity is the
attribution of differences, not their absence. `v3/parity/conditions.py`
implemented the superseded fourteen until this package, which is the debt
P2 §5 records against itself ("ハーネス側の未追随").

These tests hold the four properties the revision turns on:

  * the condition TABLE is the single source — seventeen rows, the groups
    P2 §5 assigns them, and an override-forbidden set of exactly four;
  * refusal is DIRECTION-AWARE — C-03 is owner-overridable in general and
    refuses the moment its evidence carries an unregistered insensitive
    disagreement, because that half is what NP1 is written about;
  * an empty denominator is NOT_MEASURED — the shape WP-2.3 measured as a
    false green (`llm_prompt_sha256` NULL on all 1,047,286 rows);
  * VOID exclusions appear BY NAME, and V-1 is time-limited, so the
    repair of H-05 restores the reference point instead of retiring it
    forever.

The end-to-end harness tests live in `test_parity_harness.py`; nothing
here spawns the legacy subprocess.
"""
import dataclasses

import pytest

from v3.kernel.errors import DomainError
from v3.parity.compare import TransitionTiming
from v3.parity.conditions import (BLOCKED, BY_ID, CONDITIONS,
                                  CUTOVER_BLOCKING_DEFECTS, FAIL,
                                  MAX_TRANSITION_LAG_TICKS, MIN_VALID_CELLS,
                                  NOT_MEASURED, PASS, BlockingDefect,
                                  ConditionVerdict)
from v3.parity.judges import evaluate
from v3.parity.report import ParityContext, ParityReport
from v3.parity.summary import SeriesSummary
from v3.parity.void import (VOID_BY_ID, VOID_REGISTER, VOID_TIME_BOUNDED,
                            classify_cell)

TICK = 120.0
DAY = 86_400.0
#: The 2026-08-09 both-systems BGP repair (P2 §5-0 V-1, §7-2 #136). A
#: fixture constant, not a wall clock: the boundary is context-supplied.
REPAIR_AT = 1_754_700_000.0


# ── helpers ──────────────────────────────────────────────────────────────

def _context(**kwargs) -> ParityContext:
    base = {"tick_interval_sec": TICK}
    base.update(kwargs)
    return ParityContext(**base)


def _verdict(condition_id: str, **kwargs) -> ConditionVerdict:
    verdicts = {v.condition_id: v for v in evaluate(_context(**kwargs))}
    return verdicts[condition_id]


def _summary(*, total=100, matched=100, mismatched=0, partial=0, missing=0,
             insensitive=0, sensitive=0, missing_v3=0,
             transitions=None) -> SeriesSummary:
    return SeriesSummary(
        total_keys=total, both_present=total - missing, matched=matched,
        partial=partial, mismatched=mismatched, one_side_missing=missing,
        missing_legacy=0, missing_v3=missing_v3, insensitive=insensitive,
        sensitive=sensitive, jaccard_median=1.0, jaccard_p05=1.0,
        transitions=transitions)


def _cell(cell_id, *, tp=10, fn=2, tn=5, recall_legacy=0.8, recall_v3=0.9,
          void_refs=(), window_start=None) -> dict:
    cell = {"cell_id": cell_id, "tp": tp, "fn": fn, "tn": tn,
            "recall_legacy": recall_legacy, "recall_v3": recall_v3,
            "void_refs": list(void_refs)}
    if window_start is not None:
        cell["window_start"] = window_start
    return cell


def _healthy_running_evidence(**overrides) -> dict:
    evidence = {
        "ticks_total": 21_600,
        "tick_reports": 21_600,
        "tl_observation_rows": 21_600,
        "failed_ticks": 4,
        "failed_ticks_with_reason": 4,
        "healthz_states_exercised": ["healthy", "degraded", "starting",
                                     "unhealthy"],
        "degraded_when_unproductive": True,
        "unhandled_exceptions": 3,
        "observed_until": REPAIR_AT + 31 * DAY,
    }
    evidence.update(overrides)
    return evidence


# ── the table itself ─────────────────────────────────────────────────────

class TestTheConditionTable:
    def test_there_are_seventeen_conditions(self):
        assert len(CONDITIONS) == 17

    def test_the_ids_are_c01_through_c17(self):
        assert {c.condition_id for c in CONDITIONS} == \
            {f"C-{n:02d}" for n in range(1, 18)}

    def test_the_groups_are_the_ones_p2_section_5_assigns(self):
        """A / B / C / D, with C-15 in group A beside C-01."""
        by_group = {}
        for condition in CONDITIONS:
            by_group.setdefault(condition.group[0], set()).add(
                condition.condition_id)
        assert by_group["A"] == {"C-01", "C-02", "C-03", "C-04", "C-15"}
        assert by_group["B"] == {"C-05", "C-06", "C-07", "C-08", "C-09"}
        assert by_group["C"] == {"C-10", "C-11", "C-12", "C-13", "C-14"}
        assert by_group["D"] == {"C-16", "C-17"}

    def test_every_condition_states_a_criterion_and_a_text(self):
        for condition in CONDITIONS:
            assert condition.text.strip()
            assert condition.criterion.strip()

    def test_c15_carries_the_undocumented_threshold_note(self):
        """P2 §5 records 4 as a magic number and forbids losing that."""
        c15 = BY_ID["C-15"]
        assert str(MIN_VALID_CELLS) in c15.criterion
        assert "deriv" in (c15.text + c15.criterion).lower()

    def test_every_condition_is_answered_exactly_once(self):
        verdicts = evaluate(_context())
        assert [v.condition_id for v in verdicts] == \
            [c.condition_id for c in CONDITIONS]

    def test_no_condition_silently_passes_on_an_empty_context(self):
        """An empty run answers nothing; PASS anywhere would be a lie."""
        for verdict in evaluate(_context()):
            assert verdict.status in (BLOCKED, NOT_MEASURED, FAIL), \
                verdict.condition_id

    def test_the_table_does_not_import_the_judges(self):
        """The dependency runs one way, so the table reads as a spec.

        `judges` imports `conditions`; the reverse would make the
        condition rows unreadable without the arithmetic and would need a
        deferred import to load at all.
        """
        import ast
        from pathlib import Path
        source = (Path(__file__).resolve().parent.parent / "v3" / "parity" /
                  "conditions.py").read_text(encoding="utf-8")
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        assert "v3.parity.judges" not in imported
        assert "v3.parity.void" not in imported


# ── override discipline ──────────────────────────────────────────────────

class TestOverrideForbidden:
    def _failed(self, condition_id, evidence=None):
        return ConditionVerdict(condition_id, FAIL, "for the test",
                                evidence or {})

    def test_the_forbidden_set_is_exactly_the_four_p2_names(self):
        assert {c.condition_id for c in CONDITIONS if not c.override_ok} == \
            {"C-02", "C-08", "C-14", "C-17"}

    @pytest.mark.parametrize("condition_id",
                             ["C-02", "C-08", "C-14", "C-17"])
    def test_the_forbidden_four_cannot_be_waived(self, condition_id):
        with pytest.raises(DomainError, match="override-forbidden"):
            self._failed(condition_id).waive(reason="we accept the risk")

    def test_c03_is_waivable_when_nothing_insensitive_is_unregistered(self):
        waived = self._failed(
            "C-03", {"unregistered_insensitive": 0}).waive(
                reason="registered neutral difference, §7-2 #61")
        assert waived.waived is True and waived.status == FAIL

    def test_c03_refuses_a_waiver_while_insensitive_remains_unregistered(self):
        """P2 §5 group A adds 'the insensitive side of C-03' to the
        forbidden set — the direction, not the whole condition."""
        verdict = self._failed("C-03", {"unregistered_insensitive": 1})
        with pytest.raises(DomainError, match="override-forbidden"):
            verdict.waive(reason="we accept the risk")

    def test_the_refusal_names_the_direction(self):
        verdict = self._failed("C-03", {"unregistered_insensitive": 2})
        with pytest.raises(DomainError, match="insensitive"):
            verdict.waive(reason="we accept the risk")

    def test_a_sensitive_only_disagreement_stays_waivable(self):
        """NP1's asymmetry: a LOUDER v3 never blocks."""
        waived = self._failed(
            "C-03", {"unregistered_insensitive": 0, "sensitive": 40}).waive(
                reason="v3 sees more; §7-2 batch approval")
        assert waived.waived is True

    def test_a_waiver_still_requires_a_written_reason(self):
        with pytest.raises(DomainError, match="written reason"):
            self._failed("C-03").waive(reason="  ")

    def test_a_not_measured_verdict_cannot_be_waived(self):
        """Waiving means accepting a known failure, not an unknown."""
        with pytest.raises(DomainError, match="nothing to waive"):
            ConditionVerdict("C-03", NOT_MEASURED, "no denominator").waive(
                reason="looks fine")


# ── §5-0, the VOID register ──────────────────────────────────────────────

class TestVoidRegister:
    def test_the_register_holds_v1_through_v7(self):
        assert [v.void_id for v in VOID_REGISTER] == \
            [f"V-{n}" for n in range(1, 8)]

    def test_every_entry_names_the_defect_that_invalidates_it(self):
        for entry in VOID_REGISTER:
            assert entry.invalidating_defect.startswith("H-")
            assert entry.reference_point.strip()
            assert entry.comparison_treatment.strip()
            assert entry.v3_treatment.strip()

    def test_only_v1_is_time_bounded(self):
        bounded = [v.void_id for v in VOID_REGISTER if v.is_time_bounded]
        assert bounded == ["V-1"]
        assert VOID_BY_ID["V-1"].scope == VOID_TIME_BOUNDED

    def test_v1_names_the_context_field_that_carries_its_boundary(self):
        """P2 §5-0 discipline 3: a time-limited VOID states its period.

        The period is the 2026-08-09 both-systems repair (§7-2 #136) and
        arrives from the context — the module never reads a clock.
        """
        assert VOID_BY_ID["V-1"].boundary_context_field == "bgp_repair_at"
        assert VOID_BY_ID["V-1"].invalidating_defect == "H-05"

    def test_permanent_entries_carry_no_boundary_field(self):
        for entry in VOID_REGISTER:
            if not entry.is_time_bounded:
                assert entry.boundary_context_field is None

    def test_the_register_entries_are_frozen(self):
        with pytest.raises(dataclasses.FrozenInstanceError):
            VOID_REGISTER[0].void_id = "V-9"


# ── the valid-cell predicate (C-01 / C-15) ───────────────────────────────

class TestValidCellPredicate:
    def test_a_non_degenerate_well_populated_cell_is_valid(self):
        assert classify_cell(_cell("taiwan/tl")).is_valid is True

    def test_a_degenerate_cell_is_excluded(self):
        """fn+tn == 0 makes recall 1.0 by construction — an empty
        condition, not a passing one (P2 §5 group A, C-01)."""
        result = classify_cell(_cell("mid_east/tl", fn=0, tn=0, tp=33))
        assert result.is_valid is False
        assert "degenerate" in result.reasons

    def test_too_few_positives_is_excluded(self):
        result = classify_cell(_cell("korea/tl", tp=2, fn=2))
        assert result.is_valid is False
        assert "insufficient_positives" in result.reasons

    def test_a_permanent_void_dependency_excludes_the_cell(self):
        result = classify_cell(_cell("taiwan/tl", void_refs=["V-2"]))
        assert result.is_valid is False
        assert "void_dependent" in result.reasons
        assert result.void_refs == ("V-2",)

    def test_a_v1_cell_before_the_repair_is_excluded(self):
        result = classify_cell(
            _cell("taiwan/tl", void_refs=["V-1"],
                  window_start=REPAIR_AT - DAY),
            bgp_repair_at=REPAIR_AT)
        assert result.is_valid is False
        assert result.void_refs == ("V-1",)

    def test_a_v1_cell_after_the_repair_is_valid_again(self):
        """V-1 is TIME-LIMITED. Writing it as permanent would mean never
        measuring BGP again, which is the failure §5-0 discipline 3
        names."""
        result = classify_cell(
            _cell("taiwan/tl", void_refs=["V-1"],
                  window_start=REPAIR_AT + DAY),
            bgp_repair_at=REPAIR_AT)
        assert result.is_valid is True

    def test_a_v1_cell_without_a_supplied_boundary_is_excluded_by_name(self):
        result = classify_cell(
            _cell("taiwan/tl", void_refs=["V-1"],
                  window_start=REPAIR_AT + DAY))
        assert result.is_valid is False
        assert "void_boundary_unknown" in result.reasons
        assert "bgp_repair_at" in result.detail

    def test_a_v1_cell_without_a_window_is_excluded_by_name(self):
        result = classify_cell(_cell("taiwan/tl", void_refs=["V-1"]),
                               bgp_repair_at=REPAIR_AT)
        assert result.is_valid is False
        assert "void_boundary_unknown" in result.reasons

    def test_an_unregistered_void_id_is_refused(self):
        """§5-0 discipline 3: VOIDs may not be invented to pass a gate."""
        with pytest.raises(DomainError, match="V-99"):
            classify_cell(_cell("taiwan/tl", void_refs=["V-99"]))

    def test_all_the_reasons_a_cell_fails_are_reported_together(self):
        result = classify_cell(
            _cell("x", tp=1, fn=0, tn=0, void_refs=["V-4"]))
        assert set(result.reasons) == {"degenerate", "insufficient_positives",
                                       "void_dependent"}


# ── C-01 / C-15 ──────────────────────────────────────────────────────────

class TestC01RecallDoesNotDegrade:
    def test_it_blocks_on_l4_when_no_cells_are_supplied(self):
        verdict = _verdict("C-01")
        assert verdict.status == BLOCKED
        assert "WP-" in verdict.evidence["blocked_on"]

    def test_every_valid_cell_improving_passes(self):
        verdict = _verdict("C-01", calibration_cells=[
            _cell("a", recall_legacy=0.8, recall_v3=0.9),
            _cell("b", recall_legacy=0.5, recall_v3=0.5)])
        assert verdict.status == PASS

    def test_one_degrading_cell_fails(self):
        verdict = _verdict("C-01", calibration_cells=[
            _cell("a", recall_legacy=0.8, recall_v3=0.9),
            _cell("b", recall_legacy=0.60, recall_v3=0.59)])
        assert verdict.status == FAIL
        assert "b" in verdict.detail

    def test_the_delta_is_judged_before_rounding(self):
        """P2 §5 says 丸め前 — a 1e-9 regression is a regression."""
        verdict = _verdict("C-01", calibration_cells=[
            _cell("a", recall_legacy=0.8, recall_v3=0.8 - 1e-9)])
        assert verdict.status == FAIL

    def test_a_void_dependent_regression_does_not_fail_the_condition(self):
        """Measuring degradation against a dead detector measures zero."""
        verdict = _verdict(
            "C-01",
            bgp_repair_at=REPAIR_AT,
            calibration_cells=[
                _cell("live", recall_legacy=0.5, recall_v3=0.6),
                _cell("dead", recall_legacy=0.9, recall_v3=0.1,
                      void_refs=["V-1"], window_start=REPAIR_AT - DAY)])
        assert verdict.status == PASS
        assert "dead" in verdict.evidence["excluded_cells"]

    def test_the_exclusions_are_named_in_the_evidence(self):
        verdict = _verdict("C-01", calibration_cells=[
            _cell("live"), _cell("dead", void_refs=["V-5"])])
        excluded = verdict.evidence["excluded_cells"]
        assert excluded["dead"]["void_refs"] == ["V-5"]

    def test_no_valid_cell_is_not_measured_never_pass(self):
        verdict = _verdict("C-01", calibration_cells=[
            _cell("dead", void_refs=["V-2"])])
        assert verdict.status == NOT_MEASURED

    def test_a_valid_cell_missing_a_recall_is_not_measured(self):
        cell = _cell("a")
        cell.pop("recall_v3")
        verdict = _verdict("C-01", calibration_cells=[cell])
        assert verdict.status == NOT_MEASURED


class TestC15EnoughGroundToStandOn:
    def test_it_blocks_on_l4_when_no_cells_are_supplied(self):
        assert _verdict("C-15").status == BLOCKED

    def test_an_empty_cell_list_is_not_measured(self):
        assert _verdict("C-15", calibration_cells=[]).status == NOT_MEASURED

    def test_three_valid_cells_fail(self):
        """The measured 2026-08-07 position, under the OLD predicate."""
        verdict = _verdict("C-15", calibration_cells=[
            _cell("a"), _cell("b"), _cell("c")])
        assert verdict.status == FAIL
        assert verdict.evidence["valid_cell_count"] == 3

    def test_four_valid_cells_pass(self):
        verdict = _verdict("C-15", calibration_cells=[
            _cell(name) for name in "abcd"])
        assert verdict.status == PASS

    def test_void_dependent_cells_do_not_count_toward_the_four(self):
        verdict = _verdict("C-15", calibration_cells=[
            _cell("a"), _cell("b"), _cell("c"),
            _cell("d", void_refs=["V-6"])])
        assert verdict.status == FAIL
        assert verdict.evidence["valid_cell_count"] == 3
        assert "d" in verdict.evidence["excluded_cells"]


# ── C-03 / C-04 / C-09 ───────────────────────────────────────────────────

class TestC03AttributionNotIdentity:
    def test_no_summaries_is_not_measured(self):
        assert _verdict("C-03").status == NOT_MEASURED

    def test_an_unattributed_disagreement_fails_however_high_the_rate(self):
        verdict = _verdict("C-03", scenario_summaries={
            "taiwan": _summary(total=1000, matched=999, mismatched=1,
                               sensitive=1)})
        assert verdict.status == FAIL
        assert verdict.evidence["unregistered_total"] == 1

    def test_a_low_rate_passes_when_every_difference_is_registered(self):
        """The 5% ceiling is gone. Attribution replaces it, and a fully
        attributed 0.60 is a better position than an unexplained 0.96."""
        verdict = _verdict(
            "C-03",
            scenario_summaries={"taiwan": _summary(
                total=100, matched=60, mismatched=40, sensitive=40)},
            difference_attribution={"taiwan": {
                "unregistered": 0, "insensitive_unjustified": 0}})
        assert verdict.status == PASS
        assert verdict.evidence["per_scenario_agreement"]["taiwan"] == \
            pytest.approx(0.60)

    def test_an_unjustified_insensitive_disagreement_fails(self):
        verdict = _verdict(
            "C-03",
            scenario_summaries={"taiwan": _summary(
                total=1000, matched=999, mismatched=1, insensitive=1)},
            difference_attribution={"taiwan": {"unregistered": 0}})
        assert verdict.status == FAIL
        assert verdict.evidence["unregistered_insensitive"] == 1

    def test_that_failure_cannot_then_be_waived(self):
        verdict = _verdict(
            "C-03",
            scenario_summaries={"taiwan": _summary(
                total=1000, matched=999, mismatched=1, insensitive=1)},
            difference_attribution={"taiwan": {"unregistered": 0}})
        with pytest.raises(DomainError, match="override-forbidden"):
            verdict.waive(reason="we accept the risk")

    def test_a_justified_insensitive_disagreement_passes(self):
        verdict = _verdict(
            "C-03",
            scenario_summaries={"taiwan": _summary(
                total=1000, matched=999, mismatched=1, insensitive=1)},
            difference_attribution={"taiwan": {
                "unregistered": 0, "insensitive_unjustified": 0}})
        assert verdict.status == PASS

    def test_a_scenario_with_nothing_comparable_is_not_measured(self):
        verdict = _verdict("C-03", scenario_summaries={
            "taiwan": _summary(total=0, matched=0)})
        assert verdict.status == NOT_MEASURED

    def test_a_run_riddled_with_one_side_gaps_is_still_void(self):
        """S5-VERIF-023 outranks the empty-denominator reading: above the
        5% ceiling the run does not describe the two systems at all."""
        verdict = _verdict("C-03", scenario_summaries={
            "taiwan": _summary(total=10, matched=0, missing=10)})
        assert verdict.status == FAIL
        assert "void" in verdict.detail

    def test_the_rate_is_disclosed_for_every_scenario(self):
        verdict = _verdict(
            "C-03",
            scenario_summaries={"taiwan": _summary(), "korea": _summary()},
            difference_attribution={})
        assert set(verdict.evidence["per_scenario_agreement"]) == \
            {"taiwan", "korea"}


class TestC04DirectionSplitTiming:
    def _summaries(self, p95_sec):
        return {"taiwan": _summary(transitions=TransitionTiming(
            median_delta_sec=0.0, p95_delta_sec=p95_sec,
            unpaired_legacy=0, unpaired_v3=0, deltas=(p95_sec,)))}

    def test_no_transitions_is_not_measured(self):
        verdict = _verdict("C-04", scenario_summaries={
            "taiwan": _summary(transitions=None)})
        assert verdict.status == NOT_MEASURED

    def test_a_mixed_p95_over_the_allowance_fails(self):
        verdict = _verdict("C-04",
                           scenario_summaries=self._summaries(3 * TICK))
        assert verdict.status == FAIL

    def test_a_mixed_p95_within_the_allowance_still_needs_the_split(self):
        """A p95 that mixes early and late lets lateness be offset by
        earliness — the reason ADR-V3-011 split the distribution."""
        verdict = _verdict("C-04",
                           scenario_summaries=self._summaries(0.5 * TICK))
        assert verdict.status == NOT_MEASURED
        assert "insensitive" in verdict.detail

    def test_a_late_only_p95_over_the_allowance_fails(self):
        verdict = _verdict(
            "C-04", scenario_summaries=self._summaries(0.5 * TICK),
            insensitive_transition_p95_sec={"taiwan": 4 * TICK})
        assert verdict.status == FAIL

    def test_both_within_the_allowance_passes(self):
        verdict = _verdict(
            "C-04", scenario_summaries=self._summaries(0.5 * TICK),
            insensitive_transition_p95_sec={"taiwan": 0.5 * TICK})
        assert verdict.status == PASS
        assert verdict.evidence["allowance_sec"] == \
            MAX_TRANSITION_LAG_TICKS * TICK


class TestC09AbsoluteNullZone:
    def test_no_measurement_is_not_measured(self):
        assert _verdict("C-09").status == NOT_MEASURED

    def test_a_null_zone_over_seven_days_fails(self):
        verdict = _verdict("C-09", null_zone={
            "taiwan/threat_level": {"v3_longest_sec": 8 * DAY}})
        assert verdict.status == FAIL
        assert "taiwan/threat_level" in verdict.detail

    def test_a_chronic_flag_fails_even_under_seven_days(self):
        verdict = _verdict("C-09", null_zone={
            "taiwan/threat_level": {"v3_longest_sec": DAY, "chronic": 1}})
        assert verdict.status == FAIL

    def test_it_no_longer_compares_against_the_legacy_baseline(self):
        """P2 §5 drops 「旧系と同等以下」: v1's null zone is the artefact
        of F-12 (one unavailable reason), so it is not a baseline."""
        verdict = _verdict("C-09", null_zone={
            "taiwan/threat_level": {"legacy_longest_sec": 100.0,
                                    "v3_longest_sec": 1000.0}})
        assert verdict.status == PASS

    def test_unregistered_v3_only_unavailability_fails(self):
        verdict = _verdict(
            "C-09",
            null_zone={"taiwan": {"v3_longest_sec": 0.0}},
            scenario_summaries={"taiwan": _summary(
                total=100, matched=98, missing=2, missing_v3=2)})
        assert verdict.status == FAIL
        assert verdict.evidence["unregistered_insensitive"] == 2

    def test_registered_v3_only_unavailability_passes(self):
        verdict = _verdict(
            "C-09",
            null_zone={"taiwan": {"v3_longest_sec": 0.0}},
            scenario_summaries={"taiwan": _summary(
                total=100, matched=98, missing=2, missing_v3=2)},
            difference_attribution={"taiwan": {
                "v3_only_unavailable_registered": 2}})
        assert verdict.status == PASS

    def test_a_missing_v3_measurement_is_not_measured(self):
        verdict = _verdict("C-09", null_zone={
            "taiwan": {"legacy_longest_sec": 1.0}})
        assert verdict.status == NOT_MEASURED


# ── C-10 / C-11 ──────────────────────────────────────────────────────────

class TestC10AndC11:
    def test_both_block_without_a_reconciliation_report(self):
        for condition_id in ("C-10", "C-11"):
            verdict = _verdict(condition_id)
            assert verdict.status == BLOCKED
            assert "reconcil" in verdict.detail.lower()
            assert "blocked_on" not in verdict.evidence

    def test_c10_is_not_measured_when_the_report_omits_unclassified(self):
        """A table count fixed by transcription cannot see the five tables
        v3 itself added (WP-2.3 F-1)."""
        verdict = _verdict("C-10", migration={
            "row_count_mismatches": [], "tables_compared": 35})
        assert verdict.status == NOT_MEASURED

    def test_c10_fails_on_an_unclassified_table(self):
        verdict = _verdict("C-10", migration={
            "row_count_mismatches": [], "tables_compared": 35,
            "unclassified_tables": ["l5_check_result"]})
        assert verdict.status == FAIL
        assert "l5_check_result" in verdict.detail

    def test_c10_fails_on_a_row_count_mismatch(self):
        verdict = _verdict("C-10", migration={
            "row_count_mismatches": ["conclusions"], "tables_compared": 40,
            "unclassified_tables": []})
        assert verdict.status == FAIL

    def test_c10_passes_when_all_classified_and_matching(self):
        verdict = _verdict("C-10", migration={
            "row_count_mismatches": [], "tables_compared": 40,
            "unclassified_tables": []})
        assert verdict.status == PASS

    def test_c10_is_not_measured_on_an_empty_table_set(self):
        verdict = _verdict("C-10", migration={
            "row_count_mismatches": [], "tables_compared": 0,
            "unclassified_tables": []})
        assert verdict.status == NOT_MEASURED

    def test_c11_is_not_measured_when_only_a_sample_was_taken(self):
        verdict = _verdict("C-11", migration={"sample_hash_mismatches": []})
        assert verdict.status == NOT_MEASURED
        assert "census" in verdict.detail.lower()

    def test_c11_is_not_measured_on_a_zero_row_census(self):
        verdict = _verdict("C-11", migration={
            "census_rows_compared": 0, "census_mismatches": []})
        assert verdict.status == NOT_MEASURED

    def test_c11_passes_on_a_clean_full_census(self):
        verdict = _verdict("C-11", migration={
            "census_rows_compared": 1_691, "census_mismatches": []})
        assert verdict.status == PASS

    def test_c11_fails_on_a_census_mismatch(self):
        verdict = _verdict("C-11", migration={
            "census_rows_compared": 1_691,
            "census_mismatches": ["baseline_stat"]})
        assert verdict.status == FAIL


# ── C-16, the layer parity does not cover ────────────────────────────────

class TestC16ThirtyDaysOfRunning:
    def test_no_evidence_is_not_measured(self):
        assert _verdict("C-16").status == NOT_MEASURED

    def test_the_three_inadmissible_proofs_are_refused_by_name(self):
        """All three were simultaneously true in a system that had
        completed zero ticks (P2 §5-D)."""
        verdict = _verdict("C-16", running_evidence={
            "container_up": True, "tests_green": True, "parity_pass": True})
        assert verdict.status == NOT_MEASURED
        for token in ("container_up", "tests_green", "parity_pass"):
            assert token in verdict.detail

    def test_it_is_not_measured_without_the_tick_path_change_instant(self):
        verdict = _verdict("C-16",
                           running_evidence=_healthy_running_evidence())
        assert verdict.status == NOT_MEASURED
        assert "last_tick_path_change_at" in verdict.detail

    def test_it_is_not_measured_on_a_zero_tick_window(self):
        verdict = _verdict(
            "C-16", last_tick_path_change_at=REPAIR_AT,
            running_evidence=_healthy_running_evidence(ticks_total=0))
        assert verdict.status == NOT_MEASURED

    def test_a_short_run_fails(self):
        verdict = _verdict(
            "C-16", last_tick_path_change_at=REPAIR_AT,
            running_evidence=_healthy_running_evidence(
                observed_until=REPAIR_AT + 12 * DAY))
        assert verdict.status == FAIL
        assert "12.0" in verdict.detail or "30" in verdict.detail

    def test_a_silent_failure_fails(self):
        verdict = _verdict(
            "C-16", last_tick_path_change_at=REPAIR_AT,
            running_evidence=_healthy_running_evidence(
                failed_ticks=9, failed_ticks_with_reason=4))
        assert verdict.status == FAIL
        assert "silent" in verdict.detail.lower()

    def test_a_tick_without_a_tl_observation_fails(self):
        verdict = _verdict(
            "C-16", last_tick_path_change_at=REPAIR_AT,
            running_evidence=_healthy_running_evidence(
                tl_observation_rows=21_000))
        assert verdict.status == FAIL

    def test_a_healthz_that_never_reports_degraded_fails(self):
        verdict = _verdict(
            "C-16", last_tick_path_change_at=REPAIR_AT,
            running_evidence=_healthy_running_evidence(
                degraded_when_unproductive=False))
        assert verdict.status == FAIL
        assert "healthz" in verdict.detail.lower()

    def test_an_exception_rate_over_the_budget_fails(self):
        verdict = _verdict(
            "C-16", last_tick_path_change_at=REPAIR_AT,
            running_evidence=_healthy_running_evidence(
                unhandled_exceptions=100))
        assert verdict.status == FAIL

    def test_a_clean_thirty_days_passes(self):
        verdict = _verdict(
            "C-16", last_tick_path_change_at=REPAIR_AT,
            running_evidence=_healthy_running_evidence())
        assert verdict.status == PASS


# ── C-17, the blocker register ───────────────────────────────────────────

class TestC17BlockingDefects:
    def test_the_module_register_holds_v3_sec_01_unresolved(self):
        by_id = {d.defect_id: d for d in CUTOVER_BLOCKING_DEFECTS}
        defect = by_id["V3-SEC-01"]
        assert defect.resolved is False
        assert defect.severity == "CRITICAL"
        assert len(defect.resolution_requirements) == 3

    def test_the_three_requirements_are_the_ones_p3_records(self):
        defect = {d.defect_id: d for d in CUTOVER_BLOCKING_DEFECTS}[
            "V3-SEC-01"]
        joined = " ".join(defect.resolution_requirements).lower()
        assert "plaintext" in joined
        assert "sweep" in joined or "storage" in joined
        assert "rotat" in joined

    def test_it_fails_today(self):
        verdict = _verdict("C-17")
        assert verdict.status == FAIL
        assert "V3-SEC-01" in verdict.detail

    def test_that_failure_cannot_be_waived(self):
        with pytest.raises(DomainError, match="override-forbidden"):
            _verdict("C-17").waive(reason="shadow is loopback-bound")

    def test_the_context_can_supply_its_own_register(self):
        verdict = _verdict("C-17", cutover_blocking_defects=[
            BlockingDefect("V3-SEC-01", "CRITICAL", "plaintext admin secret",
                           ("(1)", "(2)", "(3)"), resolved=True)])
        assert verdict.status == PASS

    def test_an_open_defect_in_a_supplied_register_still_fails(self):
        verdict = _verdict("C-17", cutover_blocking_defects=[
            BlockingDefect("V3-NEW-01", "CRITICAL", "something", ("(1)",))])
        assert verdict.status == FAIL
        assert "V3-NEW-01" in verdict.detail

    def test_the_verdict_carries_the_resolution_requirements(self):
        verdict = _verdict("C-17")
        assert verdict.evidence["open"]["V3-SEC-01"][
            "resolution_requirements"]

    def test_a_register_of_the_wrong_type_is_refused(self):
        with pytest.raises(DomainError, match="BlockingDefect"):
            _verdict("C-17", cutover_blocking_defects=[
                {"defect_id": "V3-SEC-01", "resolved": True}])


# ── readiness aggregation ────────────────────────────────────────────────

class TestCutoverReadiness:
    def _report(self, overrides=None) -> ParityReport:
        overrides = overrides or {}
        verdicts = tuple(
            ConditionVerdict(c.condition_id,
                             overrides.get(c.condition_id, PASS), "synthetic")
            for c in CONDITIONS)
        return ParityReport(verdicts=verdicts, context=_context())

    def test_all_seventeen_passing_is_ready(self):
        assert self._report().is_cutover_ready is True

    def test_a_blocked_condition_is_not_ready(self):
        assert self._report({"C-05": BLOCKED}).is_cutover_ready is False

    def test_a_not_measured_condition_is_not_ready(self):
        """The false-green shape WP-2.3 measured: an empty denominator is
        not a pass, and must not aggregate into one."""
        report = self._report({"C-14": NOT_MEASURED})
        assert report.is_cutover_ready is False
        assert report.not_measured == ("C-14",)

    def test_an_open_c17_is_never_ready(self):
        report = self._report({"C-17": FAIL})
        assert report.is_cutover_ready is False
        assert "C-17" in report.unmet_override_forbidden

    def test_a_waived_failure_does_not_buy_readiness(self):
        waived = ConditionVerdict("C-03", FAIL, "d").waive(reason="§7-2 #61")
        verdicts = tuple(
            waived if c.condition_id == "C-03"
            else ConditionVerdict(c.condition_id, PASS, "synthetic")
            for c in CONDITIONS)
        report = ParityReport(verdicts=verdicts, context=_context())
        assert report.is_cutover_ready is False

    def test_a_short_verdict_list_is_never_ready(self):
        """A report missing rows cannot be complete, whatever it holds."""
        report = ParityReport(
            verdicts=(ConditionVerdict("C-01", PASS, "d"),),
            context=_context())
        assert report.is_cutover_ready is False

    def test_the_serialised_report_names_every_bucket(self):
        payload = self._report({"C-14": NOT_MEASURED, "C-17": FAIL}).as_dict()
        assert len(payload["conditions"]) == 17
        assert payload["not_measured"] == ["C-14"]
        # C-14 is override-forbidden too, so an unmeasured C-14 belongs in
        # this list: "nobody can waive it" is about the row, not the
        # status it happens to hold.
        assert payload["unmet_override_forbidden"] == ["C-14", "C-17"]
        assert payload["cutover_ready"] is False
