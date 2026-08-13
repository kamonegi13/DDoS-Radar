"""The evaluators behind P2 §5's condition table, and `evaluate`.

`conditions` holds the declarative side: what each condition asks, which
layer it waits on, and whether it can be overridden. This module holds
the side that answers, so that the table can be read as a spec without
reading the arithmetic, and the arithmetic can be changed without
touching the spec.

Every judge here obeys the same three rules, which come from defects:

  * **A missing layer is BLOCKED, naming the work package.** WP-2.8 was
    pulled ahead of the packages eight of these conditions ask about, and
    a harness that reported them PASS because nothing contradicted them
    would be worst at exactly the moment somebody is deciding to cut over.
  * **An empty denominator is NOT_MEASURED.** WP-2.3 measured the false
    green: 100% NP6 resolution over zero rows. §5-D rule 3 makes the
    reading general, so it is applied in every judge whose denominator
    can be empty, not only in C-14.
  * **Exclusions are disclosed by name.** VOID-dependent cells and
    registered differences both leave the arithmetic, and both appear in
    the verdict's evidence with their ids.
"""
from __future__ import annotations

from typing import Callable, Mapping, Optional

from v3.kernel.errors import DomainError
from v3.parity.conditions import (BLOCKED, BY_ID, CONDITIONS,
                                  CUTOVER_BLOCKING_DEFECTS, FAIL,
                                  INADMISSIBLE_RUNNING_EVIDENCE,
                                  MAX_NULL_ZONE_DAYS,
                                  MAX_TRANSITION_LAG_TICKS,
                                  MAX_UNHANDLED_EXCEPTIONS_PER_TICK,
                                  MIN_VALID_CELLS, NOT_MEASURED, PASS,
                                  REQUIRED_HEALTHZ_STATES,
                                  REQUIRED_RUNNING_DAYS, SECONDS_PER_DAY,
                                  SEVERITY_AGREEMENT_WATCH_LEVEL,
                                  UNREGISTERED_INSENSITIVE, BlockingDefect,
                                  Condition, ConditionVerdict)
from v3.parity.void import cell_identity, classify_cells


def _blocked(condition: Condition) -> ConditionVerdict:
    return ConditionVerdict(
        condition.condition_id, BLOCKED,
        f"needs {condition.blocked_on}, which does not exist yet",
        {"blocked_on": condition.blocked_on, "criterion": condition.criterion})


def _not_measured(condition_id: str, detail: str,
                  evidence: Optional[Mapping] = None) -> ConditionVerdict:
    """§5-D rule 3: the criterion ran and had nothing to run on.

    Reported apart from PASS because "nothing contradicted it" and "it
    holds" are different claims, and apart from BLOCKED because no layer
    is missing — the measurement is.
    """
    return ConditionVerdict(condition_id, NOT_MEASURED, detail,
                            dict(evidence or {}))


# ── A. detection ─────────────────────────────────────────────────────────

def _classified(context):
    return classify_cells(context.calibration_cells or (),
                          bgp_repair_at=context.bgp_repair_at)


def _excluded_evidence(classified) -> dict:
    return {c.cell_id: {"reasons": list(c.reasons),
                        "void_refs": list(c.void_refs),
                        "detail": c.detail}
            for c in classified if not c.is_valid}


def _recall_deltas(cells, valid_ids) -> tuple[dict, list]:
    """Unrounded per-cell deltas, plus the cells that cannot form one.

    P2 §5 says 丸め前: a 1e-9 regression is a regression. Rounding first
    is how a degradation becomes a tie.
    """
    by_id = {cell_identity(cell): cell for cell in cells}
    deltas, unmeasurable = {}, []
    for cell_id in valid_ids:
        cell = by_id[cell_id]
        legacy, v3 = cell.get("recall_legacy"), cell.get("recall_v3")
        if legacy is None or v3 is None:
            unmeasurable.append(cell_id)
            continue
        deltas[cell_id] = float(v3) - float(legacy)
    return deltas, unmeasurable


def _judge_c01(context) -> ConditionVerdict:
    """Zero degradation, on the cells where degradation means something.

    A VOID-dependent cell is excluded BY NAME rather than dropped: a
    recall drop measured against a detector that returned 0.0 on all
    5,398 rows (H-05) is a fact about the repair, not about v3.
    """
    if context.calibration_cells is None:
        return _blocked(BY_ID["C-01"])
    classified = _classified(context)
    excluded = _excluded_evidence(classified)
    valid_ids = [c.cell_id for c in classified if c.is_valid]
    evidence = {"valid_cells": valid_ids, "excluded_cells": excluded,
                "criterion": BY_ID["C-01"].criterion}
    if not valid_ids:
        return _not_measured(
            "C-01",
            f"no valid cell survived the predicate ({len(excluded)} "
            f"excluded, see evidence): there is nothing to measure "
            f"degradation on, which is not the same as no degradation",
            evidence)

    deltas, unmeasurable = _recall_deltas(context.calibration_cells, valid_ids)
    evidence["recall_deltas"] = deltas
    if unmeasurable:
        return _not_measured(
            "C-01",
            f"valid cells {sorted(unmeasurable)} carry no recall on one "
            f"side; the delta cannot be formed", evidence)

    degraded = sorted(k for k, v in deltas.items() if v < 0)
    if degraded:
        return ConditionVerdict(
            "C-01", FAIL,
            f"recall degrades on {degraded} "
            f"({', '.join(f'{k}={deltas[k]:+.6f}' for k in degraded)})",
            evidence)
    return ConditionVerdict(
        "C-01", PASS,
        f"recall holds or improves on all {len(valid_ids)} valid cell(s); "
        f"{len(excluded)} excluded by the §5-0 / degeneracy predicate",
        evidence)


def _judge_c15(context) -> ConditionVerdict:
    """Prove there is ground before comparing recall on it."""
    if context.calibration_cells is None:
        return _blocked(BY_ID["C-15"])
    classified = _classified(context)
    if not classified:
        return _not_measured(
            "C-15", "no calibration cells were supplied at all; a count of "
                    "zero over an empty input is not a measurement",
            {"criterion": BY_ID["C-15"].criterion})
    valid = [c.cell_id for c in classified if c.is_valid]
    evidence = {"valid_cell_count": len(valid), "valid_cells": valid,
                "excluded_cells": _excluded_evidence(classified),
                "threshold": MIN_VALID_CELLS,
                "threshold_derivation": "NOT RECORDED (P2 §5, S5-VERIF-042)",
                "criterion": BY_ID["C-15"].criterion}
    if len(valid) < MIN_VALID_CELLS:
        return ConditionVerdict(
            "C-15", FAIL,
            f"{len(valid)} valid cell(s) < {MIN_VALID_CELLS}; "
            f"{len(classified) - len(valid)} excluded by the predicate",
            evidence)
    return ConditionVerdict(
        "C-15", PASS,
        f"{len(valid)} valid cell(s) >= {MIN_VALID_CELLS}", evidence)


def _c03_tally(per_scenario, attribution) -> dict:
    """Per-scenario disagreement counts, after §7-2 attribution.

    An absent attribution entry counts as no registration. The other
    reading — "unattributed means unknown, so withhold judgement" — is
    exactly how a difference stays silently in the tree, and §5-C rule 1
    says the only two options are reverting it or registering it.
    """
    rates, disagreements, unregistered, unjustified = {}, {}, {}, {}
    void, empty = [], []
    for scenario_id, summary in sorted(per_scenario.items()):
        rates[scenario_id] = summary.agreement_rate
        if summary.is_void:
            void.append(scenario_id)
        if summary.both_present == 0:
            empty.append(scenario_id)
            continue
        count = summary.mismatched + summary.partial
        disagreements[scenario_id] = count
        entry = attribution.get(scenario_id) or {}
        open_count = int(entry.get("unregistered", count))
        open_insensitive = int(
            entry.get("insensitive_unjustified", summary.insensitive))
        if open_count:
            unregistered[scenario_id] = open_count
        if open_insensitive:
            unjustified[scenario_id] = open_insensitive
    return {"rates": rates, "disagreements": disagreements, "void": void,
            "empty": empty, "unregistered": unregistered,
            "unjustified": unjustified}


def _c03_problems(unregistered, unjustified) -> list[str]:
    """Both halves of C-03's failure, reported together rather than first."""
    problems = []
    if unregistered:
        problems.append(
            f"{sum(unregistered.values())} unregistered disagreement(s) in "
            f"{sorted(unregistered)} — every difference must be reverted to "
            f"match production or registered in §7-2; leaving it silently "
            f"is not one of the two options")
    if unjustified:
        problems.append(
            f"{sum(unjustified.values())} insensitive disagreement(s) in "
            f"{sorted(unjustified)} carry no individual justification — v1 "
            f"saw it and v3 did not (NP1)")
    return problems


def _judge_c03(context) -> ConditionVerdict:
    """Attribution, not identity — and per scenario, never pooled.

    Pooling lets a healthy scenario carry a sick one. The rate itself no
    longer decides anything (ADR-V3-011): what decides is whether every
    disagreement maps to a §7-2 entry, and whether the insensitive ones
    are justified one at a time.
    """
    per_scenario = context.scenario_summaries or {}
    if not per_scenario:
        return _not_measured(
            "C-03", "no per-scenario summaries: the run produced no key "
                    "present on both sides",
            {"criterion": BY_ID["C-03"].criterion})

    tally = _c03_tally(per_scenario, context.difference_attribution or {})
    unregistered, unjustified = tally["unregistered"], tally["unjustified"]
    evidence = {
        "per_scenario_agreement": tally["rates"],
        "per_scenario_disagreements": tally["disagreements"],
        "unregistered_by_scenario": unregistered,
        "unregistered_total": sum(unregistered.values()),
        UNREGISTERED_INSENSITIVE: sum(unjustified.values()),
        "unregistered_insensitive_by_scenario": unjustified,
        "agreement_watch_level": SEVERITY_AGREEMENT_WATCH_LEVEL,
        "criterion": BY_ID["C-03"].criterion}

    if tally["void"]:
        return ConditionVerdict(
            "C-03", FAIL,
            f"run is void for {tally['void']}: the one-side-missing rate "
            f"exceeds the 5% ceiling (S5-VERIF-023), so the agreement rate "
            f"does not describe the two systems", evidence)
    if tally["empty"]:
        return _not_measured(
            "C-03",
            f"{tally['empty']} had no tick present on both sides; the "
            f"attribution denominator is empty and an empty denominator is "
            f"not a pass", evidence)

    problems = _c03_problems(unregistered, unjustified)
    if problems:
        return ConditionVerdict("C-03", FAIL, "; ".join(problems), evidence)

    watched = sorted(k for k, v in tally["rates"].items()
                     if v is not None and v < SEVERITY_AGREEMENT_WATCH_LEVEL)
    note = (f" (agreement below {SEVERITY_AGREEMENT_WATCH_LEVEL} on "
            f"{watched}, disclosed but not gating)" if watched else "")
    return ConditionVerdict(
        "C-03", PASS,
        f"every disagreement across {len(tally['rates'])} scenario(s) is "
        f"registered and every insensitive one is justified{note}", evidence)


def _judge_c04(context) -> ConditionVerdict:
    """Timing, per scenario, and with the late half measured on its own.

    The mixed p95 answers a weaker question than the condition asks: a
    run that is two ticks late half the time and two ticks early the
    other half posts the same number as one that is on time. The
    direction-split figure is supplied by the caller because the
    comparison engine records absolute deltas only.
    """
    per_scenario = context.scenario_summaries or {}
    allowance = MAX_TRANSITION_LAG_TICKS * context.tick_interval_sec
    measured = {
        scenario_id: summary.transitions.p95_delta_sec
        for scenario_id, summary in sorted(per_scenario.items())
        if summary.transitions is not None
        and summary.transitions.p95_delta_sec is not None}
    evidence = {"per_scenario_p95_sec": measured, "allowance_sec": allowance,
                "criterion": BY_ID["C-04"].criterion}
    if not measured:
        return _not_measured(
            "C-04", "no transition pairs in the window; timing cannot be "
                    "measured", evidence)
    evidence["unpaired"] = {
        scenario_id: {"legacy_only": summary.transitions.unpaired_legacy,
                      "v3_only": summary.transitions.unpaired_v3}
        for scenario_id, summary in sorted(per_scenario.items())
        if summary.transitions is not None}

    over = sorted(k for k, v in measured.items() if v > allowance)
    if over:
        return ConditionVerdict(
            "C-04", FAIL,
            f"transition timing p95 exceeds {allowance:.1f}s on {over}",
            evidence)
    return _judge_c04_late_half(context, measured, allowance, evidence)


def _judge_c04_late_half(context, measured, allowance,
                         evidence) -> ConditionVerdict:
    """C-04's second clause: the v3-late distribution, alone."""
    late = context.insensitive_transition_p95_sec
    if late is None:
        return _not_measured(
            "C-04",
            f"the mixed p95 is within {allowance:.1f}s on every scenario, "
            f"but the insensitive-only (v3-late) distribution was not "
            f"supplied; a mixed p95 lets lateness be offset by earliness, "
            f"so the second half of the condition is unmeasured", evidence)
    evidence["per_scenario_insensitive_p95_sec"] = dict(late)
    missing = sorted(set(measured) - set(late))
    if missing:
        return _not_measured(
            "C-04", f"no insensitive-only p95 supplied for {missing}",
            evidence)
    late_over = sorted(k for k, v in late.items()
                       if v is not None and v > allowance)
    if late_over:
        return ConditionVerdict(
            "C-04", FAIL,
            f"v3-late transition p95 exceeds {allowance:.1f}s on "
            f"{late_over}, though the mixed p95 does not — the lateness was "
            f"being paid for with earliness", evidence)
    return ConditionVerdict(
        "C-04", PASS,
        f"mixed and v3-late transition p95 both within {allowance:.1f}s on "
        f"every scenario ({MAX_TRANSITION_LAG_TICKS} x "
        f"{context.tick_interval_sec:.0f}s tick)", evidence)


# ── B. health ────────────────────────────────────────────────────────────

def _c09_unregistered_v3_only(context) -> tuple[dict, int]:
    """C-09(b): ticks where v1 concluded and v3 did not, less registrations."""
    attribution = context.difference_attribution or {}
    open_by_scenario, registered_total = {}, 0
    for scenario_id, summary in sorted(
            (context.scenario_summaries or {}).items()):
        registered = int((attribution.get(scenario_id) or {}).get(
            "v3_only_unavailable_registered", 0))
        registered_total += registered
        open_count = max(0, summary.missing_v3 - registered)
        if open_count:
            open_by_scenario[scenario_id] = open_count
    return open_by_scenario, registered_total


def _c09_problems(too_long, chronic, v3_only) -> list[str]:
    """The absolute bar, the chronic flag and the relative clause, together."""
    problems = []
    if too_long:
        problems.append(
            f"UNAVAILABLE runs longer than {MAX_NULL_ZONE_DAYS} days on "
            f"{too_long}")
    if chronic:
        problems.append(f"chronic inconclusive on {chronic} (NP5+8 calls a "
                        f"persistent null zone a design failure)")
    if v3_only:
        problems.append(
            f"{sum(v3_only.values())} tick(s) in {sorted(v3_only)} where v1 "
            f"concluded and v3 did not, with no §7-2 registration")
    return problems


def _judge_c09(context) -> ConditionVerdict:
    """An absolute null-zone bar, plus registered exceptions.

    The old condition compared v3's null zone against v1's. v1's is the
    product of having ONE unavailable reason (F-12), so matching it is
    not a health property — it is agreement with a defect.
    """
    measured = context.null_zone or {}
    criterion = BY_ID["C-09"].criterion
    limit = MAX_NULL_ZONE_DAYS * SECONDS_PER_DAY
    if not measured:
        return _not_measured(
            "C-09", "null-zone durations were not measured for this run",
            {"criterion": criterion})

    too_long, chronic, unmeasured = [], [], []
    for key, sides in sorted(measured.items()):
        longest = sides.get("v3_longest_sec")
        if longest is None:
            unmeasured.append(key)
            continue
        if longest > limit:
            too_long.append(key)
        if int(sides.get("chronic") or 0) > 0:
            chronic.append(key)

    v3_only, registered_total = _c09_unregistered_v3_only(context)
    evidence = {"per_series": {k: dict(v) for k, v in measured.items()},
                "limit_sec": limit, "chronic_series": chronic,
                "v3_only_unavailable_registered": registered_total,
                UNREGISTERED_INSENSITIVE: sum(v3_only.values()),
                "unregistered_insensitive_by_scenario": v3_only,
                "criterion": criterion}
    if unmeasured:
        return _not_measured(
            "C-09", f"{unmeasured} reported no v3 null-zone measurement",
            evidence)

    problems = _c09_problems(too_long, chronic, v3_only)
    if problems:
        return ConditionVerdict("C-09", FAIL, "; ".join(problems), evidence)
    return ConditionVerdict(
        "C-09", PASS,
        f"every series stays under {MAX_NULL_ZONE_DAYS} days with no "
        f"chronic run and no unregistered v3-only unavailability "
        f"({len(measured)} series)", evidence)


# ── C. data continuity ───────────────────────────────────────────────────

def _judge_c10(context) -> ConditionVerdict:
    report = context.migration
    if report is None:
        return ConditionVerdict(
            "C-10", BLOCKED,
            "no ETL reconciliation report supplied; run v3.etl.reconcile "
            "against the migrated store", {"criterion": "row delta == 0"})
    unclassified = report.get("unclassified_tables")
    compared = report.get("tables_compared")
    mismatched = sorted(report.get("row_count_mismatches", ()))
    evidence = {"mismatched_tables": mismatched,
                "unclassified_tables": (sorted(unclassified)
                                        if unclassified is not None else None),
                "tables_compared": compared,
                "criterion": BY_ID["C-10"].criterion}
    if unclassified is None:
        return _not_measured(
            "C-10",
            "the report does not state how many source tables were "
            "unclassified. A fixed table count is blind to tables added "
            "after it was written (WP-2.3 F-1: five tables v3 itself "
            "created), so 'all 35 match' cannot answer this condition",
            evidence)
    if not compared:
        return _not_measured(
            "C-10",
            "zero tables were compared; an empty denominator is not a pass",
            evidence)
    problems = []
    if mismatched:
        problems.append(f"row count differs for: {mismatched}")
    if unclassified:
        problems.append(f"unclassified tables: {sorted(unclassified)}")
    if problems:
        return ConditionVerdict("C-10", FAIL, "; ".join(problems), evidence)
    return ConditionVerdict(
        "C-10", PASS,
        f"all {compared} classified tables match on row count and no table "
        f"is unclassified", evidence)


def _judge_c11(context) -> ConditionVerdict:
    report = context.migration
    if report is None:
        return ConditionVerdict(
            "C-11", BLOCKED,
            "no ETL reconciliation report supplied; run v3.etl.reconcile "
            "against the migrated store", {})
    rows = report.get("census_rows_compared")
    mismatched = sorted(report.get("census_mismatches", ()))
    evidence = {"mismatched_tables": mismatched, "census_rows_compared": rows,
                "criterion": BY_ID["C-11"].criterion}
    if rows is None:
        return _not_measured(
            "C-11",
            "the report carries no census; ADR-V3-011 raised this condition "
            "from sample hashing to a full census, which WP-2.3 had already "
            "reached on real data, so a sample no longer answers it",
            evidence)
    if not rows:
        return _not_measured(
            "C-11",
            "the census compared zero rows; an empty denominator is not a "
            "pass", evidence)
    if mismatched:
        return ConditionVerdict(
            "C-11", FAIL, f"census mismatch for: {mismatched}", evidence)
    return ConditionVerdict(
        "C-11", PASS,
        f"full census over {rows} rows agrees with no mismatch", evidence)


# ── D. the running system ────────────────────────────────────────────────

def _c16_inadmissible(context) -> Optional[ConditionVerdict]:
    """The evidence P2 §5-D refuses, and the inputs it requires.

    Returns a NOT_MEASURED verdict when the condition cannot be judged,
    or None when it can. The three refusals are not pedantry: on
    2026-08-09 the container was Up, 7,403 tests were green and the
    parity fixtures agreed 13/13, while the system had completed zero
    ticks and was holding six defects.
    """
    evidence_in = dict(context.running_evidence or {})
    offered = set(evidence_in)
    inadmissible = sorted(offered & set(INADMISSIBLE_RUNNING_EVIDENCE))
    base = {"offered": sorted(offered), "inadmissible": inadmissible,
            "criterion": BY_ID["C-16"].criterion}
    if not offered:
        return _not_measured(
            "C-16", "no running evidence supplied; this condition covers "
                    "the layer parity does not reach and cannot be inferred "
                    "from a parity result", base)
    if not offered - set(INADMISSIBLE_RUNNING_EVIDENCE):
        return _not_measured(
            "C-16",
            f"the only evidence offered is {inadmissible}. P2 §5-D refuses "
            f"all three by name — container_up, tests_green and parity_pass "
            f"were simultaneously true in a system that had completed zero "
            f"ticks", base)
    full = {**base, **evidence_in}
    if not evidence_in.get("ticks_total"):
        return _not_measured(
            "C-16", "ticks_total is zero or absent; there is no denominator "
                    "for the failure and exception rates", full)
    if context.last_tick_path_change_at is None:
        return _not_measured(
            "C-16",
            "the thirty days run from the last change to the tick path and "
            "the context supplied no last_tick_path_change_at; counting "
            "from boot would credit the run with days that predate the fix",
            full)
    if evidence_in.get("observed_until") is None:
        return _not_measured(
            "C-16", "the evidence states no observed_until, so the elapsed "
                    "window cannot be formed", full)
    return None


def _c16_problems(evidence_in, ticks, elapsed_days,
                  exception_rate) -> list[str]:
    """Clauses (a)-(e) of C-16, each reported rather than short-circuited."""
    problems = []
    if elapsed_days < REQUIRED_RUNNING_DAYS:
        problems.append(
            f"only {elapsed_days:.1f} of {REQUIRED_RUNNING_DAYS} days have "
            f"elapsed since the tick path last changed")
    reports = int(evidence_in.get("tick_reports") or 0)
    observations = int(evidence_in.get("tl_observation_rows") or 0)
    if reports < ticks or observations < ticks:
        problems.append(
            f"(a) {ticks - reports} tick(s) left no TickReport and "
            f"{ticks - observations} left no tl_observation row")
    failed = int(evidence_in.get("failed_ticks") or 0)
    explained = int(evidence_in.get("failed_ticks_with_reason") or 0)
    if explained < failed:
        problems.append(
            f"(b) {failed - explained} silent tick failure(s): a failure "
            f"with no reason in the ledger is the state L5 exists to catch")
    states = set(evidence_in.get("healthz_states_exercised") or ())
    if len(states) < REQUIRED_HEALTHZ_STATES or \
            not evidence_in.get("degraded_when_unproductive"):
        problems.append(
            f"(c) /healthz exercised {len(states)} of "
            f"{REQUIRED_HEALTHZ_STATES} states and reported "
            f"degraded-while-unproductive="
            f"{bool(evidence_in.get('degraded_when_unproductive'))}")
    if exception_rate > MAX_UNHANDLED_EXCEPTIONS_PER_TICK:
        problems.append(
            f"(d) unhandled exceptions at {exception_rate:.5f}/tick exceed "
            f"{MAX_UNHANDLED_EXCEPTIONS_PER_TICK}")
    return problems


def _judge_c16(context) -> ConditionVerdict:
    """Thirty days of running, judged only on evidence of running."""
    refusal = _c16_inadmissible(context)
    if refusal is not None:
        return refusal

    evidence_in = dict(context.running_evidence or {})
    ticks = int(evidence_in["ticks_total"])
    last_change = float(context.last_tick_path_change_at)
    elapsed_days = (float(evidence_in["observed_until"]) - last_change) / \
        SECONDS_PER_DAY
    exception_rate = float(evidence_in.get("unhandled_exceptions") or 0) / \
        float(ticks)
    evidence = {**evidence_in, "criterion": BY_ID["C-16"].criterion,
                "last_tick_path_change_at": last_change,
                "elapsed_days": elapsed_days,
                "unhandled_exception_rate": exception_rate,
                "required_days": REQUIRED_RUNNING_DAYS}

    problems = _c16_problems(evidence_in, ticks, elapsed_days, exception_rate)
    if problems:
        return ConditionVerdict("C-16", FAIL, "; ".join(problems), evidence)
    return ConditionVerdict(
        "C-16", PASS,
        f"{elapsed_days:.1f} continuous days over {ticks} ticks with every "
        f"failure explained, /healthz complete, and "
        f"{exception_rate:.5f} unhandled exceptions per tick", evidence)


def _judge_c17(context) -> ConditionVerdict:
    """P3's blocker table, read as a condition rather than as a footnote."""
    register = context.cutover_blocking_defects
    if register is None:
        register = CUTOVER_BLOCKING_DEFECTS
    entries = tuple(register)
    for entry in entries:
        if not isinstance(entry, BlockingDefect):
            raise DomainError(
                f"C-17's register takes BlockingDefect entries, got "
                f"{type(entry).__name__}: the register is the single source "
                f"for what blocks a cutover and cannot be a loose mapping "
                f"whose 'resolved' key might simply be absent")
    open_defects = [entry for entry in entries if not entry.resolved]
    evidence = {"register_size": len(entries),
                "source": "P3-work-packages.md 「cutover 阻害」",
                "open": {entry.defect_id: entry.as_dict()
                         for entry in open_defects},
                "criterion": BY_ID["C-17"].criterion}
    if open_defects:
        return ConditionVerdict(
            "C-17", FAIL,
            f"{len(open_defects)} cutover-blocking defect(s) open: "
            f"{', '.join(entry.defect_id for entry in open_defects)}",
            evidence)
    return ConditionVerdict(
        "C-17", PASS,
        f"no cutover-blocking defect is open ({len(entries)} entr(y/ies) in "
        f"the register)", evidence)


EVALUATORS: Mapping[str, Callable] = {
    "C-01": _judge_c01,
    "C-03": _judge_c03,
    "C-04": _judge_c04,
    "C-09": _judge_c09,
    "C-10": _judge_c10,
    "C-11": _judge_c11,
    "C-15": _judge_c15,
    "C-16": _judge_c16,
    "C-17": _judge_c17,
}


def evaluate(context) -> tuple[ConditionVerdict, ...]:
    """Judge all seventeen conditions against one parity run.

    `context` is a `ParityContext` (see `report`): the summaries this
    harness produced plus any external reports handed in. A condition
    whose layer is absent returns BLOCKED naming it; a condition whose
    denominator is empty returns NOT_MEASURED. Neither is a PASS.

    A condition may declare `blocked_on` AND own an evaluator: the layer
    is missing today, but the context can carry the measurement in from
    outside, and the evaluator reports BLOCKED itself when it does not.
    """
    verdicts = []
    for condition in CONDITIONS:
        evaluator = EVALUATORS.get(condition.condition_id)
        if evaluator is not None:
            verdicts.append(evaluator(context))
            continue
        if condition.blocked_on is None:
            raise RuntimeError(
                f"{condition.condition_id} has no evaluator and declares no "
                f"blocked_on; a condition that cannot be judged must name "
                f"its dependency rather than silently passing")
        verdicts.append(_blocked(condition))
    return tuple(verdicts)


__all__ = ["evaluate", "EVALUATORS"]
