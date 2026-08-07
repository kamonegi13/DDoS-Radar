"""The clause ledger: what this kernel implements, and what it refuses to.

P6 O-14 rules that v3 gets ONE scoring kernel, covering the clauses on the
path that actually reaches a served threat level, and that every other
clause appears in an explicit exclusion list with its reason. Without that
list, WP-2.4's completion condition ("S1-scoring-core's clauses are
implemented") rebuilds both formula families faithfully — which is the
outcome the ruling exists to prevent.

So the accounting is code, not prose. `S1_SCORING_CLAUSES` transcribes the
full clause universe from both S1 books; `IMPLEMENTED` and `EXCLUDED`
partition it; and the suite fails if the three ever disagree. That is the
same shape as the ETL's `S3_MIGRATE_35` registry, and for the same reason:
`scenarios` went missing from the migration precisely because nothing
compared the plan against the spec.

Each implemented clause names the test class that holds it, and a
meta-test checks those classes exist — a clause claimed as implemented
whose test was renamed away stops being a claim and starts being a lie.
"""
from __future__ import annotations

from dataclasses import dataclass

# ── the clause universe, transcribed from the two S1 books ────────────────
# S1-scoring-core.md    §2, S1-SCORE-001 .. 044 (44 clauses, no gaps)
# S1-scoring-pipeline.md §2, S1-PIPE-001 .. 047 (47 clauses, no gaps)
SCORE_CLAUSES: tuple[str, ...] = tuple(
    f"S1-SCORE-{n:03d}" for n in range(1, 45))
PIPE_CLAUSES: tuple[str, ...] = tuple(
    f"S1-PIPE-{n:03d}" for n in range(1, 48))
S1_SCORING_CLAUSES: frozenset = frozenset(SCORE_CLAUSES + PIPE_CLAUSES)


# ── exclusion rationale vocabulary ────────────────────────────────────────

class Rationale:
    """Why a clause is not in this kernel. A closed vocabulary, so that
    "excluded" always answers a further question."""

    #: P6 O-14 — belongs to the engine formula family, which does not
    #: reach the served TL; or is dead code; or has zero numeric effect.
    NON_EFFECTIVE = "non-effective (O-14)"
    #: Produces observations out of sensor-specific fields. The kernel
    #: scores the resulting observation; implementing the detector here
    #: would require L2 to know what a CheckHost blackout is.
    DERIVED_OBSERVATION = "derived-observation producer"
    #: Owned by another layer of the v3 architecture (P1 §4-§10).
    MOVED_TO_L0 = "L0 fetch kernel (WP-2.5)"
    MOVED_TO_L1 = "L1 observation ledger (WP-2.2)"
    MOVED_TO_L3 = "L3 conclusion layer (WP-3.1)"
    MOVED_TO_L6 = "L6 public API (WP-4.1)"
    MOVED_TO_ADAPTER = "L0/L2 sensor adapter (WP-2.6/2.7)"
    #: Tick sequencing, focus resolution, request handling — the caller's
    #: job, and mostly obsolete once scoring is scheduler-driven.
    ORCHESTRATION = "tick orchestration, not the formula"
    #: The condition cannot arise in the v3 structure.
    STRUCTURALLY_MOOT = "structurally moot in v3"
    #: A second route to a decision this kernel makes once.
    DUPLICATE_MECHANISM = "duplicate of an implemented mechanism"
    #: Not a scoring concern at all.
    OUT_OF_LAYER = "outside the scoring layer"
    #: P6 O-15 — the trend computation is L3's, and the consumer survey
    #: found nothing to migrate.
    NOT_PORTED_O15 = "not ported (O-15 ruling)"


@dataclass(frozen=True, slots=True)
class Implemented:
    """A clause this kernel realises, and where its behaviour is proved."""

    clause: str
    where: str
    test_class: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class Excluded:
    """A clause this kernel deliberately does not implement."""

    clause: str
    rationale: str
    evidence: str


# ── implemented ───────────────────────────────────────────────────────────

IMPLEMENTED: dict[str, Implemented] = {entry.clause: entry for entry in (
    Implemented(
        "S1-SCORE-001", "contributions.build_contributions + domain_totals",
        "TestAdmissionAndDomainTotals",
        "The FIRED-and-unsuppressed predicate lives once, on Observation."),
    Implemented(
        "S1-SCORE-003", "convergence.convergence_level",
        "TestConvergenceLevel"),
    Implemented(
        "S1-SCORE-004", "threat_level.derive_tl", "TestDeriveTL",
        "The single copy. ADR-V3-004 freezes it, TL1's missing domain "
        "gate included."),
    Implemented(
        "S1-SCORE-005", "threat_level.apply_hysteresis", "TestHysteresis"),
    Implemented(
        "S1-SCORE-007", "convergence.convergence_bonus",
        "TestConvergenceBonus",
        "The effective tier table; the engine's confidence-gated variant "
        "(S1-SCORE-006) is excluded."),
    Implemented("S1-SCORE-008", "contributions.dedup_max", "TestDedup"),
    Implemented(
        "S1-SCORE-009", "contributions.build_contributions",
        "TestContributionFormula", "Includes the pinned trace format."),
    Implemented(
        "S1-SCORE-010", "contributions.build_contributions",
        "TestParticipantMembership"),
    Implemented(
        "S1-SCORE-011", "contributions.build_contributions + active_countries",
        "TestParticipantMembership"),
    Implemented(
        "S1-SCORE-012", "contributions.build_contributions",
        "TestGlobalSignals"),
    Implemented("S1-SCORE-013", "contributions.global_threat",
                "TestGlobalSignals"),
    Implemented("S1-SCORE-014", "contributions._passes_primary_filter",
                "TestLlmPrimaryCountry"),
    Implemented("S1-SCORE-015", "contributions.domain_totals",
                "TestAdmissionAndDomainTotals"),
    Implemented("S1-SCORE-016", "kernel.score_tick", "TestFullAndLiteModes"),
    Implemented(
        "S1-SCORE-018", "inputs.Observation.admits + __post_init__",
        "TestAdmissionAndDomainTotals",
        "The conversion itself is moot (one representation); the "
        "admission predicate and signal_source fallback survive."),
    Implemented("S1-SCORE-021", "sequence.chain_bonus", "TestSequenceChain"),
    Implemented("S1-SCORE-022", "sequence.advance", "TestSequenceChain"),
    Implemented(
        "S1-SCORE-024",
        "trend.linear_regression_slope / velocity / acceleration",
        "TestTrendDerivatives",
        "One implementation, resolving DEFECT-PRESERVE DP1 / D2 A-02."),
    Implemented("S1-SCORE-028", "sequence.temporal_coherence_bonus",
                "TestTemporalCoherence"),
    Implemented("S1-SCORE-042", "inputs.Scenario.is_scorable + score_tick",
                "TestScenarioSelection"),
    Implemented("S1-SCORE-043", "kernel.score_scenario", "TestEdgeCases"),
    Implemented("S1-SCORE-044", "contributions.build_contributions",
                "TestScenarioSelection",
                "Symmetric belligerents fall out of per-participant "
                "weighting; no core_country special case exists."),

    Implemented("S1-PIPE-009", "gating.gate — ORCHESTRATOR-INVOKED",
                "TestGatingTruthTable",
                "All eight rows of the truth table, previously GAP-01. "
                "Run by the caller BEFORE score_tick, like resolve_settings: "
                "its output sets Observation.suppressed and, through "
                "passes_gate(), the sequence-gate set. score_tick does not "
                "call it — do not add a second gate inside the kernel."),
    Implemented("S1-PIPE-010", "gating.NoiseRule.matches — ORCHESTRATOR",
                "TestNoiseRules",
                "Matches the structured value, fixing DP4. Consulted by "
                "gate(), which the orchestrator runs."),
    Implemented("S1-PIPE-011", "gating.apply_confidence_penalty — ORCHESTRATOR",
                "TestConfidencePenalty",
                "Adjusts an observation's score before it reaches the "
                "kernel; deliberately not suppression."),
    Implemented("S1-PIPE-016", "inputs.ScoringInputs.chain_country_for",
                "TestChainCountry",
                "The chain owner is an explicit caller-supplied input. "
                "Production selects a dual-core primary_ec by LIVE average "
                "spike (radar/routes/core.py:878-881); that SELECTION is "
                "the orchestrator's step, because the kernel cannot see "
                "spike data. A dual-core scenario with no supplied owner "
                "raises rather than guessing."),
    Implemented("S1-PIPE-013", "sequence.advance(admitted_sensors=...)",
                "TestSequenceGating"),
    Implemented("S1-PIPE-014", "sequence.advance(admitted_sensors=...)",
                "TestSequenceGating",
                "All constituents must be admitted, not merely one."),
    Implemented("S1-PIPE-017", "inputs.SequenceEvent", "TestSequenceGating",
                "Enforced by the type: an empty country cannot be built."),
    Implemented("S1-PIPE-019", "sequence.advance", "TestSequenceChain"),
    Implemented("S1-PIPE-025", "kernel.score_tick", "TestFullAndLiteModes"),
    Implemented("S1-PIPE-026", "kernel._bonus_fold", "TestBonusFold"),
    Implemented("S1-PIPE-027", "kernel.score_scenario", "TestHysteresis"),
    Implemented("S1-PIPE-035", "kernel.score_tick", "TestPurityAndIdempotence",
                "The idempotence half. Baseline updates are L1's and are "
                "absent here by construction, which is the other half."),
)}


# ── excluded ──────────────────────────────────────────────────────────────

EXCLUDED: dict[str, Excluded] = {entry.clause: entry for entry in (
    # --- O-14: the engine formula family does not reach the served TL ---
    Excluded(
        "S1-SCORE-002", Rationale.NON_EFFECTIVE,
        "Domain cap 10 and DOMAIN_WEIGHT_* are applied only in "
        "engine.compute_convergence_score (radar/engine.py:109). The served "
        "path sums UNWEIGHTED domain totals under DOMAIN_CAP=6.0 "
        "(radar/scoring.py:1521,1546). S1-SCORE-015 is the effective cap."),
    Excluded(
        "S1-SCORE-006", Rationale.NON_EFFECTIVE,
        "engine.apply_convergence_bonus's min-domain-confidence gate feeds "
        "score_with_bonus, which reaches alert_history and daily_summary "
        "only, never ScenarioState.tl. S1-SCORE-007 is the effective bonus."),
    Excluded(
        "S1-SCORE-019", Rationale.NON_EFFECTIVE,
        "The effective conversion takes raw_score=float(rat.score) "
        "(radar/scoring.py:87) and never multiplies by confidence. "
        "Confidence weighting exists only in the engine's diagnostic lane."),
    Excluded(
        "S1-SCORE-020", Rationale.NON_EFFECTIVE,
        "Per-domain confidence averages exist solely to gate the engine's "
        "convergence bonus (S1-SCORE-006), which is itself non-effective."),
    Excluded(
        "S1-SCORE-026", Rationale.NON_EFFECTIVE,
        "Feint detection injects a rationale entry with score=0 "
        "(radar/routes/core.py:1959-1963): informational, zero numeric "
        "effect on any threat level."),
    Excluded(
        "S1-SCORE-027", Rationale.NON_EFFECTIVE,
        "engine.compute_sync_score has no production caller — referenced "
        "only by tests/test_engine.py. Dead on arrival."),
    Excluded(
        "S1-SCORE-031", Rationale.NON_EFFECTIVE,
        "Origin entropy is computed for display "
        "(radar/routes/core.py:828-831) and never passed to add_rat()."),
    Excluded(
        "S1-SCORE-032", Rationale.NON_EFFECTIVE,
        "Entropy CONCENTRATING/DISPERSING classification is display-only, "
        "on the same path as S1-SCORE-031."),
    Excluded(
        "S1-SCORE-033", Rationale.NON_EFFECTIVE,
        "The WITHDRAWING/GROWING label feeds narrative text only "
        "(radar/routes/core.py:1139-1147); the numeric BGP contribution "
        "comes from core_bgp['is_anomaly'], computed independently of the "
        "trend label."),
    Excluded(
        "S1-SCORE-035", Rationale.NON_EFFECTIVE,
        "compute_confidence's HIGH/MEDIUM/LOW feeds the combined_sources "
        "display dict (radar/routes/core.py:804) and no score."),
    Excluded(
        "S1-PIPE-022", Rationale.NON_EFFECTIVE,
        "The cap of 15 clips `score_with_bonus` "
        "(radar/routes/core.py:2003), the engine family's number, which "
        "reaches alert_history / daily_summary / What-If. The served "
        "scenario score is floored at 0 and never clipped above "
        "(radar/routes/core.py:2201-2202 — the only two mutations of "
        "_state.score). Porting the cap would have suppressed TL1 on the "
        "highest-scoring ticks."),
    Excluded(
        "S1-PIPE-020", Rationale.NON_EFFECTIVE,
        "The eight-step ordering describes the engine family's sequence "
        "(radar/routes/core.py:1937-1991). The effective ordering is "
        "S1-PIPE-023..027, implemented in kernel.score_scenario."),

    # --- detectors that manufacture observations from sensor internals ---
    Excluded(
        "S1-SCORE-025", Rationale.DERIVED_OBSERVATION,
        "Ambush detection reads raw DDoS time series and emits a score-2 "
        "rationale entry (core.py:1457-1461). Its output enters this kernel "
        "as an ordinary observation. S1-SCORE-025 also carries GAP-01: its "
        "firing thresholds are pinned by no test."),
    Excluded(
        "S1-SCORE-029", Rationale.DERIVED_OBSERVATION,
        "Blockade Index composes CheckHost/DDoS/RIPE sensor fields, which "
        "this kernel has no vocabulary for, and emits a score-1 entry when "
        "BI >= 7.0 (core.py:1466-1475)."),
    Excluded(
        "S1-SCORE-030", Rationale.DERIVED_OBSERVATION,
        "Maskirovka composes narrative-burst and CheckHost blackout state "
        "(core.py:1440-1453); GAP-02 records that its 'core degradation' "
        "condition is unspecified."),
    Excluded(
        "S1-SCORE-034", Rationale.MOVED_TO_ADAPTER,
        "IDF-weighted ASN overlap produces a sensor's score component "
        "(core.py:1042-1044) before any scenario exists to score."),

    # --- other layers ---
    Excluded(
        "S1-SCORE-017", Rationale.MOVED_TO_L3,
        "Conclusion confidence and the lite_tl_note belong to the "
        "conclusion envelope. P1 §6: L2 produces numbers, L3 produces "
        "judgements. The kernel supplies scoring_mode for L3 to discount."),
    Excluded(
        "S1-SCORE-023", Rationale.MOVED_TO_L1,
        "Hour-of-day baselines are L1 statistics. P1 §5 requires baseline "
        "writes to be an explicit job; scoring computing them mid-tick is "
        "exactly the non-idempotence F-05 names."),
    Excluded(
        "S1-SCORE-037", Rationale.MOVED_TO_L3,
        "TL proximity is computed after the threat level is fixed "
        "(core.py:2572) and annotates a conclusion rather than producing "
        "one."),
    Excluded(
        "S1-SCORE-038", Rationale.MOVED_TO_L0,
        "The circuit breaker is fetch-side resilience (NP3). WP-2.5 owns "
        "it; its effect reaches here as a DISABLED observation."),
    Excluded(
        "S1-SCORE-039", Rationale.OUT_OF_LAYER,
        "Secret masking is a configuration-surface security control (S4), "
        "with no scoring content."),
    Excluded(
        "S1-SCORE-040", Rationale.MOVED_TO_L0,
        "Sensor registry enumeration is L0's inventory contract."),
    Excluded(
        "S1-SCORE-041", Rationale.MOVED_TO_L1,
        "Coverage upsert is a persistence guard. This kernel writes "
        "nothing, and Scenario refuses an empty scenario_id at "
        "construction."),

    # --- O-15 ---
    Excluded(
        "S1-SCORE-036", Rationale.NOT_PORTED_O15,
        "P6 O-15 gives trend to L3's TREND conclusion alone. The required "
        "consumer survey found NO consumer: compute_escalation_progress is "
        "emitted at strategic_alert.analytics.escalation but no frontend "
        "code reads it (grep of radar.js / tradecraft.js / index.html / "
        "i18n.js for .escalation, escalation_velocity, tl_transitions, "
        "predicted_next_tl — zero hits), it is absent from the INTEL GUIDE "
        "API chapter, and its forecast half was recorded degenerate at "
        "~3% accuracy when forecast_log was retired 2026-05-05 "
        "(radar/engine.py:829-834). Nothing to supply from TREND."),

    # --- pipeline: orchestration, other layers, moot ---
    Excluded(
        "S1-PIPE-001", Rationale.ORCHESTRATION,
        "Tick-driven scoring is the caller's structure (DEFECT-PRESERVE "
        "DP1/A-01). The kernel is a function, so it cannot be driven by a "
        "GET even if the caller tried."),
    Excluded("S1-PIPE-002", Rationale.ORCHESTRATION,
             "Focus resolution precedes scoring; the kernel receives "
             "focused_scenario_id already settled."),
    Excluded("S1-PIPE-003", Rationale.ORCHESTRATION,
             "The active-focus registry with its TTL is transient request "
             "state, and drives fetch targeting rather than arithmetic."),
    Excluded("S1-PIPE-004", Rationale.ORCHESTRATION,
             "Role-gated weight overlays are an authorisation concern; the "
             "kernel receives whatever participant weights survived it."),
    Excluded("S1-PIPE-005", Rationale.ORCHESTRATION,
             "Re-scoring triggers are cache policy, and S1-PIPE-001 "
             "removes two of the three conditions outright."),
    Excluded("S1-PIPE-006", Rationale.MOVED_TO_L0,
             "Force-fetch states, role limits and the allow-list (whose "
             "DP3 identifier bug WP-0.2 fixed) are all fetch-side."),
    Excluded("S1-PIPE-007", Rationale.MOVED_TO_L1,
             "Cache collection purity is L1's read contract. The kernel "
             "receives the observation set as an argument."),
    Excluded("S1-PIPE-008", Rationale.MOVED_TO_L0,
             "Emitting DISABLED observations is the fetch layer's duty; "
             "this kernel carries the DISABLED status through."),
    Excluded("S1-PIPE-012", Rationale.MOVED_TO_L0,
             "Sensor confidence (health x samples x baseline coverage) is "
             "computed where health is known. It arrives as "
             "Observation.confidence."),
    Excluded("S1-PIPE-015", Rationale.DUPLICATE_MECHANISM,
             "A second route to the same verdict as S1-PIPE-013, required "
             "by the clause itself to agree with it. One admission "
             "predicate means one route."),
    Excluded("S1-PIPE-018", Rationale.MOVED_TO_ADAPTER,
             "Secondary-belligerent registration, ACCIDENTAL A6 (it gates "
             "on the primary's observation). Event production, not "
             "scoring."),
    Excluded("S1-PIPE-021", Rationale.STRUCTURALLY_MOOT,
             "Derived observations arrive in the observation set before "
             "aggregation, so there is no post-hoc re-aggregation to "
             "forget. ACCIDENTAL A7 cannot arise."),
    Excluded("S1-PIPE-023", Rationale.MOVED_TO_ADAPTER,
             "Signal-set construction decides which observations exist. "
             "The kernel scores the set it is handed."),
    Excluded("S1-PIPE-024", Rationale.MOVED_TO_L1,
             "Injection and drain failures are ledger-side, and the "
             "kernel performs no destructive reads to fail at."),
    Excluded("S1-PIPE-028", Rationale.MOVED_TO_L6,
             "SHOW_BACKGROUND_TL is response filtering. NP4 requires the "
             "derivation, which S1-SCORE-016 provides; hiding it is a "
             "presentation ruling (ACCIDENTAL A9)."),
    Excluded("S1-PIPE-029", Rationale.MOVED_TO_L3,
             "Null TL on failure is the null zone, an L3 concept (P1 §7). "
             "The kernel's half is that it raises rather than returning "
             "TL5 — it has no code path that invents a level."),
    Excluded("S1-PIPE-030", Rationale.MOVED_TO_L3,
             "Which TL the ledger records is L3's. The kernel supplies "
             "both the held and raw levels so L3 can obey the clause."),
    Excluded("S1-PIPE-031", Rationale.MOVED_TO_L3,
             "Conclusion ordering (threat level then trend) is L3's, and "
             "O-15 puts trend there exclusively."),
    Excluded("S1-PIPE-032", Rationale.MOVED_TO_L3,
             "Conclusion-write failure isolation is L3's. This kernel "
             "writes nothing."),
    Excluded("S1-PIPE-033", Rationale.MOVED_TO_L3,
             "Single-stage conclusion derivation is L3's (DEFECT-PRESERVE "
             "DP6). No conclusion is derived here."),
    Excluded("S1-PIPE-034", Rationale.MOVED_TO_L1,
             "The nine persistence targets and their failure policy are "
             "L1's (ACCIDENTAL A10)."),
    Excluded("S1-PIPE-036", Rationale.MOVED_TO_L6,
             "Response cache replacement and diffing are serving concerns."),
    Excluded("S1-PIPE-037", Rationale.MOVED_TO_L6,
             "Transient-state ownership (DEFECT-PRESERVE DP7 / B-04) is "
             "moot for a function that holds no state."),
    Excluded("S1-PIPE-038", Rationale.MOVED_TO_L6,
             "WebSocket emission conditions and rooms are L6's."),
    Excluded("S1-PIPE-039", Rationale.MOVED_TO_L6,
             "Single-source TL-change notification is L6's."),
    Excluded("S1-PIPE-040", Rationale.MOVED_TO_L6,
             "Assembling responses from a cache snapshot is L6's."),
    Excluded("S1-PIPE-041", Rationale.MOVED_TO_L0,
             "The fetch loop and its circuit-breaker coupling are L0's."),
    Excluded("S1-PIPE-042", Rationale.MOVED_TO_L0,
             "Startup retry ladder and sensor stagger are L0's."),
    Excluded("S1-PIPE-043", Rationale.MOVED_TO_L0,
             "Waiting for a disabled sensor to be re-enabled is L0's "
             "(DEFECT-PRESERVE DP9 / B-01)."),
    Excluded("S1-PIPE-044", Rationale.MOVED_TO_L0,
             "Periodic job scheduling (DEFECT-PRESERVE DP8: restart-reset "
             "counters) is the scheduler's."),
    Excluded("S1-PIPE-045", Rationale.MOVED_TO_L0,
             "Deriving fetch context from the active focus set is L0's."),
    Excluded("S1-PIPE-046", Rationale.ORCHESTRATION,
             "The HTTP-self-call background scoring worker (DEFECT-PRESERVE "
             "DP2) is exactly what S1-PIPE-001 deletes."),
    Excluded("S1-PIPE-047", Rationale.MOVED_TO_L1,
             "Sensor cache persistence cadence is L1's."),
)}


def accounted_for() -> frozenset:
    return frozenset(IMPLEMENTED) | frozenset(EXCLUDED)


def unaccounted() -> frozenset:
    """Clauses in neither registry — always empty, or the suite fails."""
    return S1_SCORING_CLAUSES - accounted_for()


def exclusions_by_rationale() -> dict:
    grouped: dict = {}
    for entry in EXCLUDED.values():
        grouped.setdefault(entry.rationale, []).append(entry.clause)
    return {reason: sorted(clauses) for reason, clauses in grouped.items()}


__all__ = ["S1_SCORING_CLAUSES", "SCORE_CLAUSES", "PIPE_CLAUSES",
           "IMPLEMENTED", "EXCLUDED", "Implemented", "Excluded", "Rationale",
           "accounted_for", "unaccounted", "exclusions_by_rationale"]
