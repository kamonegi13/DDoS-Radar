"""The clause ledger for S1-conclusions' 45 clauses.

Same shape and same reason as `v3.scoring.registry`: a completion
condition that says "the clauses are implemented" is satisfiable by
implementing all of them, including the ones a ruling removed and the ones
that belong to another layer. So the partition is code — every clause is
either realised here with a named test class, deferred to a named work
package, or excluded with a rationale — and the suite fails if the three
ever stop covering the universe.

DEFERRED is a third partition on purpose. `v3.scoring.registry` needed only
two because O-14 settled every scoring clause; S1-conclusions spans four
layers (L3 derives, L4 calibrates, L6 serves), so "not here, not never"
needs somewhere to live that is not the exclusion list. A clause parked in
DEFERRED names the WP that owes it.
"""
from __future__ import annotations

from dataclasses import dataclass

CONC_CLAUSES: tuple[str, ...] = tuple(
    f"S1-CONC-{n:03d}" for n in range(1, 46))
S1_CONCLUSION_CLAUSES: frozenset = frozenset(CONC_CLAUSES)


class Rationale:
    """Why a clause is not implemented here. A closed vocabulary."""

    #: P6 O-16 — replaced by a derived view over the unthinned TL stream.
    #: The clause's OUTPUT is reproduced; its mechanism is not rebuilt.
    DERIVED_VIEW_O16 = "superseded by a derived view (O-16)"
    #: Migration scaffolding that must not reach v3 (D2 C-03).
    SCAFFOLD = "v1->v2 migration scaffold, not carried"
    #: Storage and retention are L1's; L3 owns semantics only.
    OWNED_BY_L1 = "L1 ledger (WP-2.2)"
    #: Not a conclusion-layer concern.
    OUT_OF_LAYER = "outside the conclusion layer"


class Owner:
    """Which work package owes a deferred clause."""

    L4_CALIBRATION = "WP-3.2 (L4 calibration)"
    L6_API = "WP-4.1 (L6 public API)"
    L6_REPORTING = "WP-4.1 (L6: markdown export / audit trace)"


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


IMPLEMENTED: dict[str, Implemented] = {entry.clause: entry for entry in (
    Implemented(
        "S1-CONC-001", "conclusion.Conclusion.__post_init__",
        "TestSchemaInvariants",
        "Five types, unique id, state/reason exclusivity, confidence "
        "domain, NP7 disclaimer. Refused, never clamped."),
    Implemented(
        "S1-CONC-002", "conclusion.Conclusion (frozen) + as_dict/__reduce__",
        "TestSchemaInvariants",
        "Immutable, key-sorted serialisation, revalidating round trip. The "
        "disclaimer is a pinned constant rather than a config value "
        "injected at read time, so the v2 re-injection step (GAP-06) has "
        "nothing to do."),
    Implemented(
        "S1-CONC-003", "availability.GUARDS + vocabulary.UNAVAILABLE_REASONS",
        "TestEveryReasonHasAGenerationPath",
        "F-12 closed: all four reasons have a live guard and a test that "
        "reaches it (cutover C-08)."),
    Implemented(
        "S1-CONC-004", "conclusion.build",
        "TestUnavailableAssertsNothing",
        "asserts_absence / is_transient / reason_detail on every "
        "unavailable row."),
    Implemented(
        "S1-CONC-005", "envelope.ConclusionEnvelope",
        "TestConditionFiveOneEnvelopeWithTheDisclaimer",
        "One shape for success and error alike; api_version is 3.0 "
        "(P7 §1). The v2 kill-switch flag is scaffolding (C-03)."),
    Implemented(
        "S1-CONC-006", "envelope.ConclusionEnvelope + derive.derive_all",
        "TestDeriveAll",
        "'Nothing yet' is a Conclusion object, not a hand-built dict — "
        "ACCIDENTAL A2 closed at the type."),
    Implemented(
        "S1-CONC-007", "derive.latest_of_each_type", "TestDeriveAll",
        "The per-type independence rule. HTTP status mapping is WP-4.1's."),
    Implemented(
        "S1-CONC-009", "threat_level.derive", "TestThreatLevel",
        "state is str(tl). Every comparison goes through severity() — the "
        "kernel type has no ordering operators at all."),
    Implemented(
        "S1-CONC-010", "threat_level.derive", "TestThreatLevel",
        "A scenario that did not score still emits a row."),
    Implemented(
        "S1-CONC-011", "threat_level.confidence_for", "TestThreatLevel",
        "Sequential rounding preserved (clamp -> round -> discount -> "
        "round)."),
    Implemented(
        "S1-CONC-012", "threat_level.threshold_ref", "TestThreatLevel",
        "Read off v3.scoring.thresholds, so DP1's three-way copy cannot "
        "form."),
    Implemented(
        "S1-CONC-013", "threat_level.rationale_matrix + source_urls",
        "TestThreatLevel",
        "evidence_url comes from the context map: L2's Contribution "
        "carries no URL, value_display or suppress_reason (§7-2 CONC-04)."),
    Implemented(
        "S1-CONC-015", "trend.derive + trend.pack", "TestTrendIsADerivedView",
        "One row, three packed windows, no source_urls ever."),
    Implemented(
        "S1-CONC-016", "ledger.views.severity_window_pair",
        "TestSeverityWindowPair",
        "The window seam as a query over the one TL stream. severity is "
        "6-TL (O-15); the delta is unchanged, the means shift by 1.0."),
    Implemented("S1-CONC-017", "trend.classify", "TestTrendClassification",
                "Numbers pinned directly, closing GAP-02 for TREND."),
    Implemented(
        "S1-CONC-018", "trend.derive + trend.confidence_for",
        "TestTrendClassification",
        "One usable window publishes; three unusable is the only "
        "unavailable path."),
    Implemented(
        "S1-CONC-019", "per_domain.derive + confidence_for + source_urls",
        "TestPerDomain"),
    Implemented("S1-CONC-020", "per_domain.classify", "TestPerDomain",
                "Order preserved including A6 (DEGRADING before ELEVATED). "
                "Numbers pinned directly, closing GAP-02 for PER_DOMAIN."),
    Implemented(
        "S1-CONC-021", "anomaly.derive", "TestAnomaly",
        "Several rows, ranked, capped; never an empty tuple; state is the "
        "signal_source alone."),
    Implemented("S1-CONC-022", "anomaly.importance_for + recency_decay",
                "TestAnomaly", "Four factors, all disclosed."),
    Implemented(
        "S1-CONC-023", "anomaly.novelty_factor + novelty_counts",
        "TestAnomaly",
        "Counted over L1's signal stream rather than anomaly ledger rows "
        "(§7-2 CONC-03), which is the redefinition ACCIDENTAL A8 asked "
        "for. The fallback is labelled, never silent."),
    Implemented("S1-CONC-024", "attack_mode.derive", "TestAttackMode",
                "Non-exclusive rules, ranked, each with its rule string; "
                "tentative flag below 0.6."),
    Implemented("S1-CONC-025", "attack_mode.apply_rules", "TestAttackMode",
                "Numbers pinned directly, closing GAP-01."),
    Implemented("S1-CONC-026", "attack_mode.derive", "TestAttackMode",
                "No match is a refusal to judge, with the domain scores "
                "kept on the unavailable row."),
    Implemented(
        "S1-CONC-031", "persistence.persist", "TestWriteRule",
        "Append-only, compared against the LATEST row of the type (not "
        "the latest matching row), so A->B->A writes three times. No "
        "heartbeat: chronic detection no longer reads this ledger. The "
        "write identity includes WHICH GUARD spoke, so a pipeline "
        "collapse under an unchanged level is still written (§7-2 #61)."),
    Implemented(
        "S1-CONC-032", "persistence._anomaly_signature", "TestWriteRule",
        "Set signature without multiplicity — but WITH scenario_id, the "
        "suppression marker and a 10-point importance band, because "
        "magnitude is not multiplicity. The previous batch is an exact "
        "grouping on metadata.batch_at, not a time neighbourhood."),
)}


DEFERRED: dict[str, Deferred] = {entry.clause: entry for entry in (
    Deferred("S1-CONC-008", Owner.L6_REPORTING,
             "Audit-trace endpoint: full disclosure plus LLM prompt "
             "resolution. The disclosure fields all exist on Conclusion "
             "(provenance / threshold_ref / source_urls / metadata); what "
             "is missing is the endpoint and the prompt ledger join."),
    Deferred("S1-CONC-014", Owner.L6_REPORTING,
             "Falsification report. Deliberately not written as a second "
             "TL ladder: DP1 requires it to be computed by re-running "
             "v3.scoring.threat_level.derive_tl over hypothetical inputs, "
             "which needs L2's re-scoring seam. Sized as its own task."),
    Deferred("S1-CONC-027", Owner.L6_API,
             "Scenario-specific extension modes, declared in scenario "
             "presets. Needs the v3 scenario configuration surface, which "
             "WP-4.1 owns."),
    Deferred("S1-CONC-028", Owner.L6_API,
             "LLM augmentation of ATTACK_MODE. The prompt sha256 slot "
             "exists on Conclusion; the call path is L0's LLM adapter plus "
             "an L6 feature flag."),
    Deferred("S1-CONC-029", Owner.L4_CALIBRATION,
             "calibration_status content. L3 carries the slot on all five "
             "types (P7 R2 requires five, production had two); L4 fills "
             "it from the ground-truth confusion matrix."),
    Deferred("S1-CONC-030", Owner.L4_CALIBRATION,
             "recall/precision arithmetic and the three-value status."),
    Deferred("S1-CONC-036", Owner.L4_CALIBRATION,
             "Retention windows. L1 already declares 365 days for the "
             "conclusion table (ADR-V3-005); the prompt-ledger floor "
             "(conclusions + 30d) arrives with the prompt ledger."),
    Deferred("S1-CONC-037", Owner.L6_API,
             "Replay endpoint. The semantics are already available — "
             "store.latest_conclusion_at is as-of by construction and the "
             "envelope's `at` field makes replay and live the same shape "
             "(DP9). What remains is the route and its authorisation."),
    Deferred("S1-CONC-038", Owner.L4_CALIBRATION,
             "self_eval metrics. null_zone_days is already a view "
             "(views.null_zone_spans); recall and drift are L4's."),
    Deferred("S1-CONC-039", Owner.L6_REPORTING, "Markdown export."),
    Deferred("S1-CONC-040", Owner.L4_CALIBRATION, "Analyst feedback ledger."),
    Deferred("S1-CONC-041", Owner.L4_CALIBRATION, "Feedback aggregation."),
    Deferred("S1-CONC-042", Owner.L4_CALIBRATION, "Ground-truth ledger."),
    Deferred("S1-CONC-043", Owner.L4_CALIBRATION, "Weekly human anchor queue."),
    Deferred("S1-CONC-044", Owner.L4_CALIBRATION,
             "The single natural-language question and its stance mapping. "
             "The severity threshold it uses is already pinned here as "
             "vocabulary.ALERT_MIN_SEVERITY, so L4 inherits one number."),
    Deferred("S1-CONC-045", Owner.L4_CALIBRATION, "External research links."),
)}


EXCLUDED: dict[str, Excluded] = {entry.clause: entry for entry in (
    Excluded("S1-CONC-033", Rationale.DERIVED_VIEW_O16,
             "The continuity ledger and its run state machine. O-16: null "
             "zones are spans found by scanning the unthinned TL stream "
             "(views.null_zone_spans), so there is no run to open, extend "
             "or close, and a thinned conclusion write cannot break it."),
    Excluded("S1-CONC-034", Rationale.DERIVED_VIEW_O16,
             "Chronic detection's two criteria. views.chronic_null_zone "
             "measures the longest span directly, which subsumes both the "
             "consecutive-days test and the duty-cycle correction that was "
             "added because the first missed flapping. DP3 (the duty "
             "parameters being unreachable from the registry) disappears "
             "with the mechanism."),
    Excluded("S1-CONC-035", Rationale.DERIVED_VIEW_O16,
             "The chronic snapshot's chronic/transient/duty merge and the "
             "null_run_minutes stamping. Both are projections of "
             "views.null_zone_spans; presenting them is L6's."),
)}


def accounted_for() -> frozenset:
    return frozenset(IMPLEMENTED) | frozenset(DEFERRED) | frozenset(EXCLUDED)


def unaccounted() -> frozenset:
    """Clauses in no partition — always empty, or the suite fails."""
    return S1_CONCLUSION_CLAUSES - accounted_for()


def deferrals_by_owner() -> dict:
    grouped: dict = {}
    for entry in DEFERRED.values():
        grouped.setdefault(entry.owner, []).append(entry.clause)
    return {owner: sorted(clauses) for owner, clauses in grouped.items()}


__all__ = ["S1_CONCLUSION_CLAUSES", "CONC_CLAUSES", "IMPLEMENTED",
           "DEFERRED", "EXCLUDED", "Implemented", "Deferred", "Excluded",
           "Rationale", "Owner", "accounted_for", "unaccounted",
           "deferrals_by_owner"]
