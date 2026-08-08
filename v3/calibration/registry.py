"""The clause ledger for S1-calibration's 68 clauses.

Same shape and same reason as `v3.conclusions.registry`: a completion
condition that says "the clauses are implemented" is satisfiable by
implementing all of them, including the ones that belong to another work
package. So the partition is code — every clause is either realised here
with a named test class, deferred to a named work package, or excluded
with a rationale — and the suite fails if the three stop covering the
universe.

The twelve clauses S1-calibration marks "由来: インシデント #1/#2/#3" are
listed separately in `INCIDENT_DERIVED`, and a test asserts that every one
of them is in IMPLEMENTED. That is WP-3.2's completion condition 4 made
mechanical: the twelve cannot drift into DEFERRED without the suite
saying so.
"""
from __future__ import annotations

from dataclasses import dataclass

CALIB_CLAUSES: tuple[str, ...] = tuple(
    f"S1-CALIB-{n:03d}" for n in range(1, 69))
S1_CALIBRATION_CLAUSES: frozenset = frozenset(CALIB_CLAUSES)

#: The twelve guards the three calibration disasters left behind. Read off
#: S1-calibration's "由来: インシデント #n" annotations, not paraphrased.
INCIDENT_DERIVED: tuple[str, ...] = (
    "S1-CALIB-001", "S1-CALIB-002", "S1-CALIB-004", "S1-CALIB-005",
    "S1-CALIB-006", "S1-CALIB-009", "S1-CALIB-010", "S1-CALIB-011",
    "S1-CALIB-013", "S1-CALIB-016", "S1-CALIB-023", "S1-CALIB-028")


class Rationale:
    """Why a clause is not implemented here. A closed vocabulary."""

    #: The defect is not preserved because the shape that caused it is
    #: unrepresentable in v3 — there is nothing left to preserve.
    DEFECT_UNREPRESENTABLE = "defect shape is unrepresentable in v3"
    #: Storage and retention belong to L1.
    OWNED_BY_L1 = "L1 ledger (WP-2.2)"


class Owner:
    """Which work package owes a deferred clause."""

    L4_PROPOSALS = "WP-3.3 (L4: the scenario-proposal family)"
    L4_LLM = "WP-3.3 (L4: LLM calibration)"
    L6_API = "WP-4.1 (L6 public API / scheduling surface)"


@dataclass(frozen=True, slots=True)
class Implemented:
    clause: str
    where: str
    test_class: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class Deferred:
    clause: str
    owner: str
    note: str


@dataclass(frozen=True, slots=True)
class Excluded:
    clause: str
    rationale: str
    evidence: str


IMPLEMENTED: dict = {entry.clause: entry for entry in (
    Implemented("S1-CALIB-001", "ground_truth.severity_of + kernel "
                "ThreatLevel", "TestSeveritySpace",
                "6-TL, and the kernel type has no ordering operators, so "
                "incident #2's inverted comparison does not type-check."),
    Implemented("S1-CALIB-002", "ground_truth.may_attribute / "
                "attributable_countries", "TestConflictPartyAttribution",
                "Attribution is conflict-party only; may_sense keeps the "
                "wide net (NP1)."),
    Implemented("S1-CALIB-003", "ground_truth.RULE_ORDER + classify",
                "TestRuleOrder",
                "No rule matching returns label=None with a reason, never "
                "a TRUE_NEGATIVE."),
    Implemented("S1-CALIB-004", "ground_truth.classify", "TestFalseNegative",
                "Both production paths ported: the ACLED tripwire and the "
                "graded floor. llm_intel / sequence_events can corroborate "
                "a hit and can never evidence a miss."),
    Implemented("S1-CALIB-005", "ground_truth.is_alert + in_forward_window",
                "TestTruePositive",
                "TREND and PER_DOMAIN are unscorable; the window is closed "
                "at both ends."),
    Implemented("S1-CALIB-006", "ground_truth.classify + "
                "ABSENCE_ANALYST_ID", "TestHorizonAndTheAbsenceClaim",
                "An absence claim is signed auto:horizon because no source "
                "corroborates it (incident #1)."),
    Implemented("S1-CALIB-007", "ground_truth.analyst_id_for",
                "TestAutomatedIdentityIsOneVote"),
    Implemented("S1-CALIB-008", "ground_truth.expected_severity_floor",
                "TestFalseNegative",
                "The one place a TL/severity comparison happens in the "
                "rule set."),
    Implemented("S1-CALIB-009", "ground_truth.classify_tier + "
                "confidence_for", "TestKineticTier",
                "A bare weapon noun is posture. Fatalities are never "
                "fabricated."),
    Implemented("S1-CALIB-010", "ground_truth.is_relevant + "
                "mentions_country", "TestRelevanceLadder",
                "Three rungs; the alias boundary is (?!\\w), not \\b."),
    Implemented("S1-CALIB-011", "ground_truth.episode_key / anchor_country "
                "/ merge_episode_evidence", "TestEpisodeGranularity"),
    Implemented("S1-CALIB-012", "ground_truth.episode_scoring_passes + "
                "merge_episode_evidence", "TestEpisodeGranularity",
                "Heaviest floor sets the expectation, earliest report "
                "anchors the window."),
    Implemented("S1-CALIB-013", "ground_truth.IDEMPOTENCY_KEYS / "
                "episode_note / day_cap_key", "TestIdempotency"),
    Implemented("S1-CALIB-014", "guards._guard_insufficient_feedback",
                "TestEvidenceGuards",
                "DP23 corrected: the window is explicit (EpochStamp) and "
                "an unmeasurable recall is None, not 0.0. Registered as "
                "§7-2 #65."),
    Implemented("S1-CALIB-015", "proposals.decide_direction",
                "TestDirectionDecision",
                "Four branches in the module's own order, verified by "
                "reading tl_threshold_calibrator.py:215-239."),
    Implemented("S1-CALIB-016", "guards._guard_no_motivating_evidence + "
                "_guard_no_new_evidence", "TestFreshnessGuard",
                "Direction-keyed; the equality boundary refuses. DP21's "
                "two-clock comparison is unrepresentable — both "
                "timestamps are parameters of one SystemState."),
    Implemented("S1-CALIB-018", "proposals.stepped_value", "TestStep",
                "DP22 corrected: absolute bounds as a fraction of the "
                "band default, so repeated loosening cannot converge to "
                "zero. Registered as §7-2 #66."),
    Implemented("S1-CALIB-019", "proposals.Proposal + generate",
                "TestGeneration",
                "DP2 corrected: the freshness-gate inputs are in the "
                "Provenance, so the ledger can say which false negative "
                "justified the change. Registered as §7-2 #67."),
    Implemented("S1-CALIB-022", "history.record_change / value_at / current",
                "TestAppendOnlyLedger",
                "Point-in-time is not state-filtered; current is."),
    Implemented("S1-CALIB-023", "history.revert", "TestRevert",
                "Four preconditions; the repair path of incidents #2/#3."),
    Implemented("S1-CALIB-024", "history.lineage", "TestLineage"),
    Implemented("S1-CALIB-025", "history.Lineage.complete", "TestLineage",
                "DP20 corrected: a truncated walk says so. Registered as "
                "§7-2 #68."),
    Implemented("S1-CALIB-026", "matrix.ConfusionCell + recall",
                "TestRecallArithmetic",
                "Zero denominator is None. One implementation, enforced by "
                "audit_recall_arithmetic_sites()."),
    Implemented("S1-CALIB-027", "status.status_for", "TestCalibrationStatus",
                "Three values decided by the recall denominator; never "
                "raises."),
    Implemented("S1-CALIB-028", "status.self_evaluate",
                "TestSelfEvaluation",
                "One window, one arithmetic, human/auto split disclosed."),
    Implemented("S1-CALIB-029", "status.design_w_gate", "TestDesignWGate",
                "Six branches preserved; the boundary is compared as "
                "rationals so the clause's equality case actually passes "
                "(§7-2 #64). Degenerate cells cannot carry a verdict."),
    Implemented("S1-CALIB-030", "epoch (the whole module)",
                "TestCrossEpochComparisonIsUnrepresentable",
                "DP19 closed: the series break is enforced by the type, "
                "not by procedure. This is condition 2."),
    Implemented("S1-CALIB-031", "guards._guard_recall_degraded",
                "TestGuardsFailClosed",
                "DP18 / G-07 closed: the gate exists, is executed by a "
                "test, and denies on anything but OK."),
    Implemented("S1-CALIB-035", "guards._guard_protected_role",
                "TestProtectedRoleGuard",
                "PROTECTED_ROLES compared against production by AST."),
    Implemented("S1-CALIB-041", "guards.Ruling.as_record",
                "TestRefusalsAreRecorded",
                "DP9 / E-05 closed: a refusal produces a persistable "
                "record naming every guard evaluated."),
    Implemented("S1-CALIB-042", "guards.evaluate + Permit",
                "TestThereIsOneGuardEvaluator",
                "DP7 / E-03 closed: one evaluator, and the permit it "
                "mints is the only way into a write. This is condition 1."),
    Implemented("S1-CALIB-056", "guards._guard_tier_gate + "
                "proposals.impact_of", "TestTierAndCooldownGuards",
                "Raising recall is low, reducing it is high; an unknown "
                "impact is refused rather than defaulted (DP15)."),
    Implemented("S1-CALIB-061", "guards._guard_high_cooldown",
                "TestTierAndCooldownGuards",
                "Holds low and med for 24h; HIGH is exempt from its own "
                "cooldown. The circuit-breaker and kill-switch halves are "
                "WP-3.3's."),
    Implemented("S1-CALIB-062", "guards.evaluate (GUARDS order)",
                "TestThereIsOneGuardEvaluator",
                "Fixed evaluation order, first firing guard owns the "
                "outcome, and EVERY guard fails closed — the inverse of "
                "production's fail-open recall gate."),
    Implemented("S1-CALIB-063", "history.clamp_magnitude",
                "TestMagnitudeClamp",
                "Clamps rather than rejects; prior==0 and first-seen edges "
                "preserved. The recorded magnitude at prior==0 differs "
                "(§7-2 #63)."),
)}


DEFERRED: dict = {entry.clause: entry for entry in (
    Deferred("S1-CALIB-017", Owner.L4_PROPOSALS,
             "The SQL that resolves 'last applied at'. v3's evaluator "
             "takes it as a parameter, so DP21's two-clock comparison "
             "cannot be written here; what remains is the query that "
             "supplies it, which arrives with persistence."),
    Deferred("S1-CALIB-020", Owner.L6_API,
             "Whether calibrated thresholds are consumed by scoring. "
             "Production's dormancy (DP3) is why incidents #2/#3 never "
             "reached live TL; wiring it is a scoring-surface decision, "
             "and S1-calibration §7 item 3 reserves it for the owner."),
    Deferred("S1-CALIB-021", Owner.L4_PROPOSALS,
             "Per-scenario failure isolation in the batch runner. Needs "
             "the runner; the pure functions here cannot fail per "
             "scenario because they do not iterate scenarios."),
    Deferred("S1-CALIB-032", Owner.L6_API,
             "Post-autotune recall regression, two-stage. S5-VERIF-038 "
             "additionally requires it to be strict rather than warn-only."),
    Deferred("S1-CALIB-033", Owner.L4_PROPOSALS,
             "The nine proposal types and the five with an apply "
             "primitive."),
    Deferred("S1-CALIB-034", Owner.L4_PROPOSALS, "weight_too_low."),
    Deferred("S1-CALIB-036", Owner.L4_PROPOSALS,
             "Five-source triangulation and the six-rung evidence ladder."),
    Deferred("S1-CALIB-037", Owner.L4_PROPOSALS,
             "DP26: the unscoped FN aggregation. ACCIDENTAL A5 asks "
             "whether the global scope is intended before it is ported."),
    Deferred("S1-CALIB-038", Owner.L4_PROPOSALS, "Scenario vitality."),
    Deferred("S1-CALIB-039", Owner.L4_PROPOSALS, "missing_participant."),
    Deferred("S1-CALIB-040", Owner.L4_PROPOSALS,
             "dedup / cap / insert. ACCIDENTAL A6 (fail-open counting) "
             "must be settled first — ADR-V3-006 says fail closed."),
    Deferred("S1-CALIB-043", Owner.L4_PROPOSALS, "The auto-apply tree."),
    Deferred("S1-CALIB-044", Owner.L4_PROPOSALS,
             "DP8: role_reclassify's unreachable auto-apply."),
    Deferred("S1-CALIB-045", Owner.L4_PROPOSALS,
             "The seven-stage apply primitive; needs the scenario store."),
    Deferred("S1-CALIB-046", Owner.L4_PROPOSALS,
             "DP16: the partial-failure window. Needs one transaction "
             "boundary across the scenario store and the ledger."),
    Deferred("S1-CALIB-047", Owner.L4_PROPOSALS, "Structure proposer."),
    Deferred("S1-CALIB-048", Owner.L4_PROPOSALS,
             "DP17: scenario discovery bypasses the common issue path."),
    Deferred("S1-CALIB-049", Owner.L6_API, "Drift watchdog, seven signals."),
    Deferred("S1-CALIB-050", Owner.L4_PROPOSALS, "Sensor-disable proposals."),
    Deferred("S1-CALIB-051", Owner.L4_PROPOSALS,
             "DP10: the dry-run escalation that writes `applied`."),
    Deferred("S1-CALIB-052", Owner.L4_PROPOSALS, "Proposal state machine."),
    Deferred("S1-CALIB-053", Owner.L4_PROPOSALS, "Three auto-dismiss hooks."),
    Deferred("S1-CALIB-054", Owner.L4_PROPOSALS,
             "DP6 (HIGH): Defer is structurally broken in production and "
             "needs fixing there too."),
    Deferred("S1-CALIB-055", Owner.L4_PROPOSALS, "Supersede, two families."),
    Deferred("S1-CALIB-057", Owner.L4_PROPOSALS,
             "DP15: unknown applied_by. The authority module already "
             "refuses an undeclared action; the impact table is WP-3.3's."),
    Deferred("S1-CALIB-058", Owner.L4_PROPOSALS, "Tier promotion/demotion."),
    Deferred("S1-CALIB-059", Owner.L4_PROPOSALS, "DP13: revert rate."),
    Deferred("S1-CALIB-060", Owner.L4_PROPOSALS,
             "DP14: dwell time, and the snapshot read that writes."),
    Deferred("S1-CALIB-064", Owner.L4_LLM, "LLM annotation states."),
    Deferred("S1-CALIB-065", Owner.L4_LLM,
             "DP11: the soft cap and the missing prompt hash."),
    Deferred("S1-CALIB-066", Owner.L4_LLM,
             "DP12: the non-convergent confidence heuristic."),
    Deferred("S1-CALIB-067", Owner.L6_API,
             "The auto-feedback ETL gate. GAP-01: no dedicated test "
             "exists in production for the pipeline's ignition point."),
    Deferred("S1-CALIB-068", Owner.L6_API, "The eight-phase manual run."),
)}


EXCLUDED: dict = {}


def accounted_for() -> frozenset:
    return frozenset(IMPLEMENTED) | frozenset(DEFERRED) | frozenset(EXCLUDED)


def unaccounted() -> frozenset:
    """Clauses in no partition — always empty, or the suite fails."""
    return S1_CALIBRATION_CLAUSES - accounted_for()


def incident_derived_not_implemented() -> frozenset:
    """WP-3.2 condition 4, as a predicate. Always empty."""
    return frozenset(INCIDENT_DERIVED) - frozenset(IMPLEMENTED)


def deferrals_by_owner() -> dict:
    grouped: dict = {}
    for entry in DEFERRED.values():
        grouped.setdefault(entry.owner, []).append(entry.clause)
    return {owner: sorted(clauses) for owner, clauses in grouped.items()}


__all__ = ["S1_CALIBRATION_CLAUSES", "CALIB_CLAUSES", "INCIDENT_DERIVED",
           "IMPLEMENTED", "DEFERRED", "EXCLUDED", "Implemented", "Deferred",
           "Excluded", "Rationale", "Owner", "accounted_for", "unaccounted",
           "incident_derived_not_implemented", "deferrals_by_owner"]
