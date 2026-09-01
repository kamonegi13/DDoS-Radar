"""P2 §5's seventeen cutover conditions, as code that can answer for itself.

Each condition carries its criterion, the evaluator that applies it, and —
where the condition depends on a layer that does not exist yet — the
specific dependency, so the report says BLOCKED-on-what instead of quietly
omitting a row. An unmet precondition is a stated result.

**ADR-V3-011 (2026-08-09) rewrote what this gate measures.** The old
fourteen asked for numerical identity against v1. v1 is measurably wrong —
D2 §H names seven defects found by reading it during the port (H-05's BGP
detector reading a key RIPE never returns, so all 5,398 rows are 0.0;
H-01's direction confidence that changes across restarts; H-02's dual-core
attribution the docstring forbids; H-03's 27 families excluded from
anomalies; H-06's ISO2 sweep whose misattribution a test fixture froze as
expected; H-07's Defer that is really Dismiss; H-04's non-associative IDF
sum) — and a gate demanding agreement with that is the wrong SHAPE, not
merely a strict one.

So the gate now asks: is every difference ATTRIBUTED, is every
*insensitive* difference (v1 saw it, v3 did not) individually justified,
is the comparison standing on a valid reference point, and is the layer
this harness does not cover covered by something else.

Four properties exist because of specific defects:

  * **Direction is asymmetric.** A louder v3 is a note; a quieter v3
    blocks. NP1 written as an acceptance condition.
  * **NOT_MEASURED is a status.** WP-2.3 measured the false green: 100%
    NP6 resolution over an empty set (`llm_prompt_sha256` NULL on all
    1,047,286 rows). An empty denominator is never a PASS (§5-D rule 3).
  * **VOID exclusions are named.** §5-0 registers the reference points a
    v1 defect invalidated. They leave the denominator BY NAME, never
    silently, and V-1 is time-limited so H-05's repair restores it.
  * **The type refuses forbidden waives.** C-02, C-08, C-14 and C-17 are
    override-forbidden outright; C-03 is overridable EXCEPT on its
    insensitive side, which the verdict enforces from its own evidence.

This module is the DECLARATIVE half: statuses, the two types, the
seventeen rows and C-17's blocker register. `judges` holds the evaluators
and `evaluate`; `void` holds §5-0's register and the valid-cell
predicate. The split is so that the table reads as a specification
without the arithmetic interleaved, and it runs one way — `judges`
imports this module, never the reverse.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional

from v3.kernel.errors import DomainError

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"
#: The criterion RAN and had nothing to run on. Distinct from BLOCKED (a
#: layer is missing) and from PASS (nothing contradicted it) — §5-D rule 3.
NOT_MEASURED = "NOT_MEASURED"

# ── the layers that do not exist yet, named once ──────────────────────────
L0_ADAPTERS = "WP-2.5/2.6/2.7 (L0 fetch kernel and sensor adapters)"
L3_CONCLUSIONS = "WP-3.1 (L3 conclusion layer)"
L4_CALIBRATION = "WP-3.2 (L4 calibration layer)"
L5_VERIFICATION = "WP-1.x rebuilt against v3 (L5 self-verification)"

# ── numeric criteria (P2 §5, as revised 2026-08-09) ──────────────────────
#: No longer a gate. C-03 discloses the per-scenario severity agreement
#: rate without a threshold; a sudden drop below this level is a SYMPTOM
#: of unregistered differences, not the finding itself.
SEVERITY_AGREEMENT_WATCH_LEVEL = 0.95
MAX_TRANSITION_LAG_TICKS = 1.0
#: C-15. P2 §5 keeps 4 from S5 CUT-07 and records that its derivation was
#: never written down; carrying an underived threshold is the shape G-18
#: (the climate freeze) already forbade, so the note travels in the text.
MIN_VALID_CELLS = 4
#: C-09(a), NP5+8's design-failure line (CHRONIC_INCONCLUSIVE_THRESHOLD_DAYS).
MAX_NULL_ZONE_DAYS = 7
#: C-16(e). Counted from the last change to the tick path, not from boot.
REQUIRED_RUNNING_DAYS = 30
#: C-16(d), absorbing the old CUT-14.
MAX_UNHANDLED_EXCEPTIONS_PER_TICK = 0.001
#: C-16(c): starting / healthy / degraded / unhealthy.
REQUIRED_HEALTHZ_STATES = 4
SECONDS_PER_DAY = 86_400.0

#: C-16's explicitly inadmissible evidence. All three were simultaneously
#: TRUE in a system that had not completed a single tick (P2 §5-D).
INADMISSIBLE_RUNNING_EVIDENCE: tuple[str, ...] = (
    "container_up", "tests_green", "parity_pass")

#: The evidence key that makes a verdict unwaivable regardless of which
#: condition it belongs to. P2 §5 group A adds "C-03's insensitive
#: disagreements" to S5-VERIF-043's override-forbidden set; C-09(b) is the
#: same clause about a different series, so the rule is written about the
#: DIRECTION rather than about one condition id.
UNREGISTERED_INSENSITIVE = "unregistered_insensitive"


# ── C-17's register: v3 defects that block the cutover ───────────────────

@dataclass(frozen=True, slots=True)
class BlockingDefect:
    """One entry of P3's 「cutover 阻害」 table, which is the single source."""

    defect_id: str
    severity: str
    summary: str
    resolution_requirements: tuple[str, ...]
    resolved: bool = False

    def as_dict(self) -> dict:
        return {"defect_id": self.defect_id, "severity": self.severity,
                "summary": self.summary,
                "resolution_requirements": list(self.resolution_requirements),
                "resolved": self.resolved}


CUTOVER_BLOCKING_DEFECTS: tuple[BlockingDefect, ...] = (
    BlockingDefect(
        "V3-SEC-01", "CRITICAL",
        "the plaintext administrator password is stored forever in the "
        "append-only ledger: user.register's command payload holds "
        "{\"password\": \"<plaintext>\", \"role\": \"admin\"}, byte-equal to "
        "NOROSHI_V3_BOOTSTRAP_PASSWORD, and L1's triggers refuse UPDATE and "
        "DELETE. The shape is the defect: v3's sweep asserted that no "
        "plaintext appears anywhere, and that claim was true of the "
        "PROJECTION and false of the STORAGE — the check tested the surface "
        "adjacent to its own claim (D2 F-13's family)",
        ("(1) eliminate the plaintext at write time (argon2 hash only, "
         "keeping the projection-side redaction)",
         "(2) re-aim the sweep test at the storage surface",
         "(3) discard the existing ledger — it cannot be amended — and "
         "rotate the keys"),
        # RESOLVED 2026-08-13, all three parts, each with evidence:
        # (1)+(2) commit 1b2da77 — producers derive, the fold refuses a
        # plaintext key, and TestNoPlaintextReachesTheStorageFace reads
        # the raw stored bytes of every table; (3) the shadow's
        # command_record was dropped and rebuilt empty
        # (scripts/v3_discard_command_ledger.py), the bootstrap password
        # rotated, and a live sweep of the rebuilt ledger found the
        # rotated plaintext in NO table while the stored register payload
        # begins {"credential": {"algorithm": "argon2id", ...}}. The entry
        # STAYS in the register: C-17's audit trail is that a blocker was
        # found, named, and closed — deleting it would leave the next
        # reader unable to tell "never had one" from "had one and fixed
        # it".
        resolved=True),
)


# ── the condition and verdict types ──────────────────────────────────────

@dataclass(frozen=True, slots=True)
class Condition:
    """One cutover condition: what it asks, and what would answer it."""

    condition_id: str
    group: str
    text: str
    criterion: str
    override_ok: bool = True
    blocked_on: Optional[str] = None


@dataclass(frozen=True, slots=True)
class ConditionVerdict:
    condition_id: str
    status: str
    detail: str
    evidence: Mapping = field(default_factory=dict)
    waived: bool = False
    waiver_reason: Optional[str] = None

    @property
    def unregistered_insensitive(self) -> int:
        """How many v1-saw-it/v3-did-not differences carry no justification."""
        if not self.evidence:
            return 0
        return int(self.evidence.get(UNREGISTERED_INSENSITIVE) or 0)

    @property
    def is_override_forbidden(self) -> bool:
        condition = BY_ID.get(self.condition_id)
        if condition is not None and not condition.override_ok:
            return True
        return self.unregistered_insensitive > 0

    def as_dict(self) -> dict:
        return {"condition_id": self.condition_id, "status": self.status,
                "detail": self.detail, "evidence": dict(self.evidence),
                "waived": self.waived, "waiver_reason": self.waiver_reason,
                "override_forbidden": self.is_override_forbidden}

    def waive(self, *, reason: str) -> "ConditionVerdict":
        """Accept a FAIL deliberately, where P2 §5 permits it.

        Four conditions may never be waived: C-02 (a v3-only miss), C-08
        (an unreachable unavailable-reason), C-14 (a broken NP6 trail) and
        C-17 (a registered cutover-blocking defect). Each is a recurrence
        of something that already shipped, so the type refuses rather than
        trusting the operator to remember which is which.

        A fifth refusal is DIRECTIONAL rather than per-condition: any
        verdict whose evidence records unregistered insensitive
        differences is unwaivable, whatever its id. P2 §5 adds "C-03's
        insensitive disagreements" to the forbidden set, and C-09(b) is
        the same clause about the null zone — writing the rule about the
        direction keeps it true when a third series appears.

        A waiver never becomes a PASS. It stays FAIL and carries its
        reason, so a report can show what was overridden and by what
        argument — an override nobody can find later is indistinguishable
        from a condition that passed.
        """
        condition = BY_ID.get(self.condition_id)
        if condition is not None and not condition.override_ok:
            raise DomainError(
                f"{self.condition_id} cannot be waived: P2 §5 marks it "
                f"override-forbidden. {condition.text}")
        if self.unregistered_insensitive > 0:
            raise DomainError(
                f"{self.condition_id} cannot be waived: it carries "
                f"{self.unregistered_insensitive} unregistered insensitive "
                f"difference(s) — v1 concluded and v3 did not. P2 §5 marks "
                f"the insensitive direction override-forbidden (NP1); "
                f"register and justify each one in §7-2 instead")
        if not isinstance(reason, str) or not reason.strip():
            raise DomainError(
                f"waiving {self.condition_id} requires a written reason: an "
                f"override without an argument is not a decision anyone can "
                f"review")
        if self.status != FAIL:
            raise DomainError(
                f"{self.condition_id} is {self.status}, not FAIL — there is "
                f"nothing to waive")
        return ConditionVerdict(
            self.condition_id, self.status, self.detail, self.evidence,
            waived=True, waiver_reason=reason.strip())


# ── the table (P2 §5, revised rows) ──────────────────────────────────────
GROUP_A = "A. detection"
GROUP_B = "B. health"
GROUP_C = "C. continuity"
GROUP_D = "D. running system"

CONDITIONS: tuple[Condition, ...] = (
    Condition(
        "C-01", GROUP_A,
        "recall_v3 - recall_legacy >= 0, unrounded, on EVERY valid cell. "
        "Valid cell = non-degenerate (fn+tn > 0) AND tp+fn >= 5 "
        "(S5-VERIF-037) AND not dependent on a §5-0 VOID reference point. "
        "The direction (zero degradation) is unchanged from the original; "
        "only the population is.",
        "per-valid-cell recall delta >= 0, compared before rounding",
        blocked_on=L4_CALIBRATION),
    Condition(
        "C-02", GROUP_A,
        "Zero cases where a miss (false negative) occurred only in v3.",
        "v3-only FN count == 0",
        override_ok=False, blocked_on=L4_CALIBRATION),
    Condition(
        "C-03", GROUP_A,
        "Every TL-series disagreement maps to a registered §7-2 entry, and "
        "unregistered disagreements number zero. Insensitive disagreements "
        "(v1 saw it, v3 did not) each carry an individual justification — a "
        "retire condition, or evidence that the v1-side quantity is not a "
        "measurement. The per-scenario severity agreement rate is disclosed "
        "with NO threshold: it is a symptom, not the finding.",
        "unregistered disagreements == 0 AND unjustified insensitive == 0; "
        "agreement rate disclosed, not gating"),
    Condition(
        "C-04", GROUP_A,
        "TL transition timing differs by at most one scoring tick at p95 — "
        "AND at most one tick at p95 on the distribution restricted to "
        "v3-late (insensitive) transitions alone. A p95 that mixes early "
        "and late lets lateness be paid for with earliness, which is not a "
        "measurement of NP1.",
        f"mixed p95 <= {MAX_TRANSITION_LAG_TICKS} tick AND insensitive-only "
        f"p95 <= {MAX_TRANSITION_LAG_TICKS} tick"),
    Condition(
        "C-15", GROUP_A,
        "At least four valid cells exist, by C-01's predicate — a gate that "
        "compares recall must first prove there is ground to compare on. "
        "Successor to S5 CUT-07, which measured the right property with the "
        "wrong predicate (it never asked whether the cell's detector was "
        "alive).",
        f"valid cell count >= {MIN_VALID_CELLS}. P2 §5 records this "
        f"threshold as an UNDERIVED magic number carried over from "
        f"S5-VERIF-042: it must be derived, or replaced by a derived "
        f"number, before the cutover call",
        blocked_on=L4_CALIBRATION),

    # ── B. health ────────────────────────────────────────────────────────
    Condition(
        "C-05", GROUP_B,
        "L5's five checks run AGAINST v3's operating ledger, each holds a "
        "record of having executed and returned a judgement within its "
        "expected interval, and unresolved ANOMALY is zero. A check with no "
        "execution record is not green (G-07: a permanently open gate kept "
        "answering 'not red').",
        "5/5 executed inside their expected interval AND unresolved "
        "ANOMALY == 0",
        blocked_on=L5_VERIFICATION),
    Condition(
        "C-06", GROUP_B,
        "For every flag, age / expected_fire_interval is below 1x (WARN) "
        "and 3x (ANOMALY); under 30 days of observation the flag is "
        "INSUFFICIENT rather than anomalous (ADR-V3-010's ratio semantics). "
        "Additionally, where v1 is permanently silent on a family and v3 "
        "fires, that difference is registered in §7-2 as sensitive — a "
        "detector v3 brought back to life must not pass as 'it fired, so "
        "it is healthy'.",
        "per-flag age ratio < 3x AND every revived family registered",
        blocked_on=L0_ADAPTERS),
    Condition(
        "C-07", GROUP_B,
        "Registry-registered keys reach 100% three-layer resolution, AND "
        "direct environment reads outside the registry number zero, AND the "
        "registered key count is disclosed beside the fixed-constant count. "
        "The substance is on the direct-read side (S5 CUT-10 folded in "
        "here); the count is disclosed so that 'only nine keys' reads as "
        "the rule's consequence rather than as effort not spent.",
        "resolution reachability == 1.0 AND direct env reads == 0 AND both "
        "counts disclosed",
        blocked_on=L0_ADAPTERS),
    Condition(
        "C-08", GROUP_B,
        "All four conclusion-unavailable reasons have generation paths and "
        "are reachable by test (F-12 recurrence guard).",
        "4/4 reasons reachable",
        override_ok=False, blocked_on=L3_CONCLUSIONS),
    Condition(
        "C-09", GROUP_B,
        "(a) Absolute: the longest UNAVAILABLE run is at most seven days "
        "for every (scenario x conclusion_type), and chronic is zero "
        "(NP5+8's design-failure line). (b) Relative: every tick where v1 "
        "concluded and v3 did not is registered in §7-2 as an insensitive "
        "difference with an individual justification. v1's own null zone is "
        "not a baseline — it is the artefact of having one unavailable "
        "reason (F-12).",
        f"max UNAVAILABLE <= {MAX_NULL_ZONE_DAYS} days AND chronic == 0 AND "
        f"unregistered v3-only unavailability == 0"),

    # ── C. data continuity ───────────────────────────────────────────────
    # This group keeps IDENTITY as its measure on purpose: R1 is data
    # continuity, and ETL fidelity has no passing grade other than "not one
    # row lost, not one value changed". The revision tightens it against
    # false greens rather than relaxing it.
    Condition(
        "C-10", GROUP_C,
        "Every CLASSIFIED table matches on row count, and the number of "
        "unclassified tables is zero. '35 tables' was a transcription of "
        "the 2026-08-03 state and is structurally blind to the five tables "
        "v3's own WP-0.3/1.1/1.2/1.3 added to production (WP-2.3 F-1): a "
        "condition that fixes the count cannot see a table that appeared.",
        "row-count delta == 0 on all classified tables AND unclassified "
        "table count == 0"),
    Condition(
        "C-11", GROUP_C,
        "Full-census comparison — not a sample — with zero mismatches and "
        "matching deterministic hashes. WP-2.3 already reached this on real "
        "data (1,515 + 176 cells, four baseline tables, 500 extracted ids "
        "byte-equal across all columns), so the condition is raised to the "
        "level already achieved.",
        "census mismatches == 0 over a non-empty census"),
    Condition(
        "C-12", GROUP_C,
        "recall/precision RECOMPUTED FROM THE MIGRATED LEDGER, over the "
        "same label set and the same window, match the legacy baseline per "
        "cell (human-only and all-labels series). This is a condition about "
        "ETL fidelity, not about detection: read as 'v3's recall equals "
        "v1's' it would contradict C-01, and the only way to satisfy both "
        "would be to forbid improvement.",
        "per-cell equality of the recomputed baseline",
        blocked_on=L4_CALIBRATION),
    Condition(
        "C-13", GROUP_C,
        "Calibration-window continuity: every discontinuity carries an "
        "epoch stamp (EpochStamp) and unstamped discontinuities number "
        "zero. 'No discontinuity' is already false — H-05's repair discards "
        "bgp_hod's 5,398 rows, and that is the correct operation, because "
        "0.0 was the absence of a key rather than a measurement (F-16).",
        "unstamped discontinuities == 0, judged over the window the "
        "migration can actually satisfy (conclusion history spans 90.96 "
        "days; ADR-V3-005's 365-day window is unreachable from a v1 "
        "snapshot)",
        blocked_on=L4_CALIBRATION),
    Condition(
        "C-14", GROUP_C,
        "NP6 traceability resolves 100% — formula, thresholds, primary "
        "sources, prompts — AND the resolved set is not empty. A face with "
        "a zero denominator is NOT_MEASURED, never PASS: WP-2.3 measured "
        "that false green (llm_prompt_sha256 NULL on all 1,047,286 rows; "
        "source_urls='[]' on 294,324 = 28.1%). The reading applies to every "
        "condition here, not only this one (§5-D rule 3).",
        "traceability == 1.0 over a NON-EMPTY resolution set",
        override_ok=False, blocked_on=L3_CONCLUSIONS),

    # ── D. the running system (2026-08-09, new) ──────────────────────────
    # Groups A/B/C compare stored rows projected into the kernel. They
    # never cross the fold, the tick loop, or the container — which is how
    # 13/13 fixture agreement and 7,403 green tests coexisted with a system
    # that could not complete one tick.
    Condition(
        "C-16", GROUP_D,
        "v3 has run for thirty continuous days with zero unexplained tick "
        "failures. (a) every tick leaves a TickReport and a tl_observation "
        "row; (b) failed ticks are recorded WITH A REASON (zero silent "
        "failures); (c) /healthz's four states work and a running but "
        "unproductive system reads degraded/503; (d) unhandled exceptions "
        f"<= {MAX_UNHANDLED_EXCEPTIONS_PER_TICK}/tick (absorbing CUT-14); "
        "(e) the thirty days are counted from the last change to the tick "
        "path. 'The container is Up', 'the tests are green' and 'parity "
        "PASSed' are NOT evidence for this condition — all three were true "
        "at once in a system that had completed zero ticks.",
        f"{REQUIRED_RUNNING_DAYS} continuous days since the last tick-path "
        f"change, with (a)-(d) all holding"),
    Condition(
        "C-17", GROUP_D,
        "Zero v3-side defects are registered as cutover-blocking; P3's "
        "「cutover 阻害」 table is the single source. Currently open: "
        "V3-SEC-01. Without this row a script judging §5 could return "
        "is_cutover_ready = True while holding a CRITICAL blocker, because "
        "the owner's ruling lived only in P3.",
        "open cutover-blocking defects == 0",
        override_ok=False),
)

BY_ID: Mapping[str, Condition] = {c.condition_id: c for c in CONDITIONS}

OVERRIDE_FORBIDDEN: frozenset[str] = frozenset(
    c.condition_id for c in CONDITIONS if not c.override_ok)



__all__ = ["Condition", "ConditionVerdict", "CONDITIONS", "BY_ID",
           "OVERRIDE_FORBIDDEN", "UNREGISTERED_INSENSITIVE",
           "PASS", "FAIL", "BLOCKED", "NOT_MEASURED",
           "BlockingDefect", "CUTOVER_BLOCKING_DEFECTS",
           "SEVERITY_AGREEMENT_WATCH_LEVEL", "MAX_TRANSITION_LAG_TICKS",
           "MIN_VALID_CELLS", "MAX_NULL_ZONE_DAYS", "REQUIRED_RUNNING_DAYS",
           "MAX_UNHANDLED_EXCEPTIONS_PER_TICK", "REQUIRED_HEALTHZ_STATES",
           "SECONDS_PER_DAY", "INADMISSIBLE_RUNNING_EVIDENCE",
           "GROUP_A", "GROUP_B", "GROUP_C", "GROUP_D",
           "L0_ADAPTERS", "L3_CONCLUSIONS", "L4_CALIBRATION",
           "L5_VERIFICATION"]
