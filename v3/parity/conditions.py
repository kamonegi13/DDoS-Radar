"""P2 §5's fourteen cutover conditions, as code that can answer for itself.

WP-2.8's fourth completion condition is that these become mechanically
judgeable. That means more than "a human can check them": each condition
carries its numeric criterion, the evaluator that applies it, and — where
the condition depends on a layer that does not exist yet — the specific
dependency, so the report says BLOCKED-on-what instead of quietly omitting
a row.

That distinction matters because WP-2.8 has been pulled ahead of WP-2.5,
2.6, 2.7, 3.1 and 3.2. Nine of the fourteen conditions ask about layers
those packages will build. A harness that reported those as PASS because
nothing contradicted them would be worse than useless at exactly the
moment somebody is deciding whether to cut over. The same reasoning as the
ETL's acceptance criteria: an unmet precondition is a stated result.

Three conditions are marked override-forbidden in P2 §5 (C-02, C-08,
C-14). The type refuses to let those be waived — `Condition.override_ok`
is False and `ConditionVerdict.waive()` raises for them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping, Optional

from v3.kernel.errors import DomainError

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"

# ── the layers that do not exist yet, named once ──────────────────────────
L0_ADAPTERS = "WP-2.5/2.6/2.7 (L0 fetch kernel and sensor adapters)"
L3_CONCLUSIONS = "WP-3.1 (L3 conclusion layer)"
L4_CALIBRATION = "WP-3.2 (L4 calibration layer)"
L5_VERIFICATION = "WP-1.x rebuilt against v3 (L5 self-verification)"

# ── numeric criteria (P2 §5) ─────────────────────────────────────────────
MIN_SEVERITY_AGREEMENT = 0.95
MAX_TRANSITION_LAG_TICKS = 1.0


@dataclass(frozen=True, slots=True)
class Condition:
    """One cutover condition: what it asks, and what would answer it."""

    condition_id: str
    group: str
    text: str
    criterion: str
    override_ok: bool = True
    blocked_on: Optional[str] = None

    @property
    def is_judgeable_now(self) -> bool:
        return self.blocked_on is None


@dataclass(frozen=True, slots=True)
class ConditionVerdict:
    condition_id: str
    status: str
    detail: str
    evidence: Mapping = field(default_factory=dict)
    waived: bool = False
    waiver_reason: Optional[str] = None

    def as_dict(self) -> dict:
        return {"condition_id": self.condition_id, "status": self.status,
                "detail": self.detail, "evidence": dict(self.evidence),
                "waived": self.waived, "waiver_reason": self.waiver_reason}

    def waive(self, *, reason: str) -> "ConditionVerdict":
        """Accept a FAIL deliberately, where P2 §5 permits it.

        Three conditions may never be waived: C-02 (a v3-only miss), C-08
        (an unreachable unavailable-reason) and C-14 (a broken NP6 trail)
        are marked override-forbidden because each one is a recurrence of
        a defect that already shipped. The type refuses rather than
        trusting the operator to remember which is which.

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


# ── A. detection capability (NP1 — highest priority) ─────────────────────
CONDITIONS: tuple[Condition, ...] = (
    Condition(
        "C-01", "A. detection",
        "recall_v3 >= recall_legacy across the 30-day replay window, for "
        "every cell. Not one cell may degrade.",
        "per-cell recall delta >= 0",
        blocked_on=L4_CALIBRATION),
    Condition(
        "C-02", "A. detection",
        "Zero cases where a miss (false negative) occurred only in v3.",
        "v3-only FN count == 0",
        override_ok=False, blocked_on=L4_CALIBRATION),
    Condition(
        "C-03", "A. detection",
        "TL series severity agreement >= 0.95 per scenario over the 30-day "
        "window; the remaining 5% must be explicable as registered "
        "intentional differences.",
        f"agreement_rate >= {MIN_SEVERITY_AGREEMENT}"),
    Condition(
        "C-04", "A. detection",
        "TL transition timing differs by at most one scoring tick, measured "
        "at the 95th percentile of disagreements.",
        f"transition p95 <= {MAX_TRANSITION_LAG_TICKS} tick"),

    # ── B. health ────────────────────────────────────────────────────────
    Condition(
        "C-05", "B. health",
        "v3's silent-failure detection (L5's five monitors) is green on "
        "every item.",
        "5/5 monitors green",
        blocked_on=L5_VERIFICATION),
    Condition(
        "C-06", "B. health",
        "Every v3 sensor fires at least once inside the 30-day window — no "
        "sensor sits at zero (F-08 recurrence guard).",
        "min per-sensor firing count >= 1",
        blocked_on=L0_ADAPTERS),
    Condition(
        "C-07", "B. health",
        "Registry-registered keys reach 100% three-layer resolution (G-15 "
        "recurrence guard).",
        "resolution reachability == 1.0",
        blocked_on=L0_ADAPTERS),
    Condition(
        "C-08", "B. health",
        "All four conclusion-unavailable reasons have generation paths and "
        "are reachable by test (F-12 recurrence guard).",
        "4/4 reasons reachable",
        override_ok=False, blocked_on=L3_CONCLUSIONS),
    Condition(
        "C-09", "B. health",
        "v3's null zone (consecutive days without a conclusion) is no worse "
        "than the legacy system's.",
        "v3 null-zone duration <= legacy"),

    # ── C. data continuity ───────────────────────────────────────────────
    Condition(
        "C-10", "C. continuity",
        "The 35 migrated tables match on row count exactly.",
        "row count delta == 0 for all 35"),
    Condition(
        "C-11", "C. continuity",
        "Deterministic sample hashes match.",
        "sample hash equality"),
    Condition(
        "C-12", "C. continuity",
        "recall/precision match exactly per cell, on both the human-only "
        "and the all-labels series.",
        "per-cell equality",
        blocked_on=L4_CALIBRATION),
    Condition(
        "C-13", "C. continuity",
        "Calibration window continuity holds — the series identity is not "
        "broken.",
        "no epoch discontinuity",
        blocked_on=L4_CALIBRATION),
    Condition(
        "C-14", "C. continuity",
        "NP6 traceability resolves 100%: formula, thresholds, primary "
        "sources and prompts.",
        "traceability == 1.0",
        override_ok=False, blocked_on=L3_CONCLUSIONS),
)

BY_ID: Mapping[str, Condition] = {c.condition_id: c for c in CONDITIONS}


def _blocked(condition: Condition) -> ConditionVerdict:
    return ConditionVerdict(
        condition.condition_id, BLOCKED,
        f"needs {condition.blocked_on}, which does not exist yet",
        {"blocked_on": condition.blocked_on, "criterion": condition.criterion})


# ── evaluators for the conditions this harness CAN answer ────────────────

def _judge_c03(context) -> ConditionVerdict:
    """Every scenario must clear the bar, not the pool.

    Pooling lets a healthy scenario carry a sick one: a scenario at 0.75
    agreement disappears inside a big one at 0.99. P2 §5 says "per
    scenario" and this is what that means.
    """
    per_scenario = context.scenario_summaries or {}
    if not per_scenario:
        return ConditionVerdict(
            "C-03", BLOCKED,
            "no per-scenario summaries: the run produced no key present on "
            "both sides", {"criterion": f">= {MIN_SEVERITY_AGREEMENT}"})

    rates = {}
    void = []
    below = []
    insensitive = {}
    for scenario_id, summary in sorted(per_scenario.items()):
        rates[scenario_id] = summary.agreement_rate
        if summary.is_void:
            void.append(scenario_id)
        if summary.agreement_rate is None or \
                summary.agreement_rate < MIN_SEVERITY_AGREEMENT:
            below.append(scenario_id)
        if summary.insensitive:
            insensitive[scenario_id] = summary.insensitive

    evidence = {"per_scenario_agreement": rates,
                "per_scenario_insensitive": insensitive,
                "void_scenarios": void,
                "criterion": f">= {MIN_SEVERITY_AGREEMENT} on EVERY scenario"}
    if void:
        return ConditionVerdict(
            "C-03", FAIL,
            f"run is void for {void}: the one-side-missing rate exceeds the "
            f"5% ceiling (S5-VERIF-023), so the agreement rate does not "
            f"describe the two systems", evidence)
    if below:
        return ConditionVerdict(
            "C-03", FAIL,
            f"below {MIN_SEVERITY_AGREEMENT} on {below} "
            f"(rates: {{{', '.join(f'{k}={v:.4f}' for k, v in rates.items() if v is not None)}}})",
            evidence)
    if insensitive:
        # NP1 outranks the rate: a v3 that saw less is disqualifying even
        # at perfect agreement everywhere else.
        return ConditionVerdict(
            "C-03", FAIL,
            f"agreement meets {MIN_SEVERITY_AGREEMENT} everywhere, but "
            f"{sum(insensitive.values())} insensitive disagreement(s) remain "
            f"in {sorted(insensitive)} — v3 reported a lower severity than "
            f"legacy, which NP1 treats as blocking regardless of the rate",
            evidence)
    return ConditionVerdict(
        "C-03", PASS,
        f"every scenario meets {MIN_SEVERITY_AGREEMENT} with no insensitive "
        f"disagreement ({len(rates)} scenario(s))", evidence)


def _judge_c04(context) -> ConditionVerdict:
    """Transition lag, per scenario — the same dilution applies here."""
    per_scenario = context.scenario_summaries or {}
    allowance = MAX_TRANSITION_LAG_TICKS * context.tick_interval_sec
    measured = {
        scenario_id: summary.transitions.p95_delta_sec
        for scenario_id, summary in sorted(per_scenario.items())
        if summary.transitions is not None
        and summary.transitions.p95_delta_sec is not None}
    if not measured:
        return ConditionVerdict(
            "C-04", BLOCKED,
            "no transition pairs in the window; timing cannot be measured",
            {"criterion": f"<= {MAX_TRANSITION_LAG_TICKS} tick"})
    unpaired = {
        scenario_id: {"legacy_only": summary.transitions.unpaired_legacy,
                      "v3_only": summary.transitions.unpaired_v3}
        for scenario_id, summary in sorted(per_scenario.items())
        if summary.transitions is not None}
    over = sorted(k for k, v in measured.items() if v > allowance)
    evidence = {"per_scenario_p95_sec": measured, "allowance_sec": allowance,
                "unpaired": unpaired}
    if over:
        return ConditionVerdict(
            "C-04", FAIL,
            f"transition timing p95 exceeds {allowance:.1f}s on {over}",
            evidence)
    return ConditionVerdict(
        "C-04", PASS,
        f"transition timing p95 within {allowance:.1f}s on every scenario "
        f"({MAX_TRANSITION_LAG_TICKS} x {context.tick_interval_sec:.0f}s tick)",
        evidence)


def _judge_c09(context) -> ConditionVerdict:
    """Null zone compared WITHIN each scenario.

    Taking the max of each side across scenarios lets a 10x-worse v3 null
    zone on one scenario hide behind a different scenario's long legacy
    one. The pairing has to happen per scenario or it is not a comparison.
    """
    measured = context.null_zone or {}
    if not measured:
        return ConditionVerdict(
            "C-09", BLOCKED,
            "null-zone durations were not measured for this run",
            {"criterion": "v3 <= legacy, per scenario"})
    worse = []
    for scenario_id, sides in sorted(measured.items()):
        legacy_sec = sides.get("legacy_longest_sec")
        v3_sec = sides.get("v3_longest_sec")
        if legacy_sec is None or v3_sec is None:
            return ConditionVerdict(
                "C-09", BLOCKED,
                f"{scenario_id} reported no null-zone measurement on one "
                f"side", {"per_scenario": dict(measured)})
        if v3_sec > legacy_sec:
            worse.append(scenario_id)
    evidence = {"per_scenario": {k: dict(v) for k, v in measured.items()},
                "criterion": "v3 <= legacy, per scenario"}
    if worse:
        return ConditionVerdict(
            "C-09", FAIL,
            f"v3's null zone is longer than legacy's on {worse}", evidence)
    return ConditionVerdict(
        "C-09", PASS,
        f"v3's null zone is no longer than legacy's on every scenario "
        f"({len(measured)} scenario(s))", evidence)


def _judge_c10(context) -> ConditionVerdict:
    report = context.migration
    if report is None:
        return ConditionVerdict(
            "C-10", BLOCKED,
            "no ETL reconciliation report supplied; run v3.etl.reconcile "
            "against the migrated store", {"criterion": "row delta == 0"})
    mismatched = sorted(report.get("row_count_mismatches", ()))
    status = PASS if not mismatched else FAIL
    return ConditionVerdict(
        "C-10", status,
        "all migrated tables match on row count" if status == PASS
        else f"row count differs for: {mismatched}",
        {"mismatched_tables": mismatched})


def _judge_c11(context) -> ConditionVerdict:
    report = context.migration
    if report is None:
        return ConditionVerdict(
            "C-11", BLOCKED,
            "no ETL reconciliation report supplied", {})
    mismatched = sorted(report.get("sample_hash_mismatches", ()))
    status = PASS if not mismatched else FAIL
    return ConditionVerdict(
        "C-11", status,
        "deterministic sample hashes agree" if status == PASS
        else f"sample hash differs for: {mismatched}",
        {"mismatched_tables": mismatched})


_EVALUATORS: Mapping[str, Callable] = {
    "C-03": _judge_c03,
    "C-04": _judge_c04,
    "C-09": _judge_c09,
    "C-10": _judge_c10,
    "C-11": _judge_c11,
}


def evaluate(context) -> tuple[ConditionVerdict, ...]:
    """Judge all fourteen conditions against one parity run.

    `context` is a `ParityContext` (see `report`): the summaries this
    harness produced plus any external reports handed in. Conditions whose
    layer does not exist return BLOCKED naming it — never PASS by default.
    """
    verdicts = []
    for condition in CONDITIONS:
        if not condition.is_judgeable_now:
            verdicts.append(_blocked(condition))
            continue
        evaluator = _EVALUATORS.get(condition.condition_id)
        if evaluator is None:
            raise RuntimeError(
                f"{condition.condition_id} is declared judgeable but has no "
                f"evaluator; a condition that cannot be judged must declare "
                f"blocked_on rather than silently passing")
        verdicts.append(evaluator(context))
    return tuple(verdicts)


__all__ = ["Condition", "ConditionVerdict", "CONDITIONS", "BY_ID", "evaluate",
           "PASS", "FAIL", "BLOCKED", "MIN_SEVERITY_AGREEMENT",
           "MAX_TRANSITION_LAG_TICKS", "L0_ADAPTERS", "L3_CONCLUSIONS",
           "L4_CALIBRATION", "L5_VERIFICATION"]
