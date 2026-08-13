"""The machine-readable verdict: seventeen conditions, one answer each.

Modelled on the ETL's reconciliation report, including the part that
matters most — a criterion whose precondition is absent reports BLOCKED
with the missing dependency named, never PASS. WP-2.8 runs ahead of the
layers eight of these conditions ask about, so a report that could only
say PASS or FAIL would be forced to lie eight times. ADR-V3-011 adds a
fourth answer, NOT_MEASURED, for the criterion that ran against an empty
denominator — the false green WP-2.3 measured.

`ParityContext` is the bundle of measurements the conditions are judged
against. Assembling it is explicit so that a condition can never reach
past it into live state to find an answer. The fields added by ADR-V3-011
carry measurements this harness structurally cannot make: it projects
stored L1 rows into the kernel, so it never crosses the fold, the tick
loop or the container (P2 §5-D).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

from v3.parity.conditions import (BLOCKED, CONDITIONS, FAIL, NOT_MEASURED,
                                  PASS, ConditionVerdict)
from v3.parity.judges import evaluate
from v3.parity.summary import SeriesSummary


@dataclass(frozen=True, slots=True)
class ParityContext:
    """Everything the seventeen conditions are allowed to consult."""

    tick_interval_sec: float
    #: The pooled summary, for the report headline only. No condition is
    #: judged on it — pooling hides a sick scenario inside a healthy one.
    threat_level_summary: Optional[SeriesSummary] = None
    #: scenario_id -> SeriesSummary. This is what the conditions read.
    scenario_summaries: Mapping[str, SeriesSummary] = field(
        default_factory=dict)
    #: series key -> {"v3_longest_sec": ..., "chronic": ...}. C-09 is now
    #: an absolute bar, so "legacy_longest_sec" is disclosed but not used.
    null_zone: Optional[Mapping] = None
    migration: Optional[Mapping] = None
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    parity_run_id: Optional[str] = None

    # ── ADR-V3-011 inputs ────────────────────────────────────────────────
    #: C-01 / C-15. Each cell: cell_id, tp, fn, tn, recall_legacy,
    #: recall_v3, void_refs, window_start. None means L4 has supplied
    #: nothing and both conditions report BLOCKED rather than passing.
    calibration_cells: Optional[Sequence[Mapping]] = None
    #: §5-0 V-1's boundary: the instant of the 2026-08-09 both-systems BGP
    #: repair (§7-2 #136). Supplied, never read from a clock, so a replay
    #: of an old window classifies its cells the way that window's
    #: analyst would have.
    bgp_repair_at: Optional[float] = None
    #: C-03 / C-09(b). scenario_id -> {"unregistered": int,
    #: "insensitive_unjustified": int, "v3_only_unavailable_registered":
    #: int}. Absent means nothing was registered, which is the fail-closed
    #: reading: §5-C rule 1 leaves only "revert it" or "register it".
    difference_attribution: Optional[Mapping] = None
    #: C-04's second half. scenario_id -> p95 seconds over the v3-LATE
    #: transitions alone; `compare_transitions` records absolute deltas,
    #: so the signed split comes from outside.
    insensitive_transition_p95_sec: Optional[Mapping] = None
    #: C-16's evidence about the running system. See the condition text
    #: for the keys, and for the three that are inadmissible.
    running_evidence: Optional[Mapping] = None
    #: C-16(e). The thirty days are counted from here, not from boot.
    last_tick_path_change_at: Optional[float] = None
    #: C-17. None uses the module register (P3's blocker table).
    cutover_blocking_defects: Optional[Sequence] = None


@dataclass(frozen=True, slots=True)
class ParityReport:
    """The seventeen verdicts plus the measurements behind them."""

    verdicts: tuple[ConditionVerdict, ...]
    context: ParityContext
    summary: Optional[SeriesSummary] = None
    notes: tuple[str, ...] = ()

    @property
    def passed(self) -> tuple[str, ...]:
        return tuple(v.condition_id for v in self.verdicts if v.status == PASS)

    @property
    def failed(self) -> tuple[str, ...]:
        return tuple(v.condition_id for v in self.verdicts if v.status == FAIL)

    @property
    def blocked(self) -> tuple[str, ...]:
        return tuple(v.condition_id for v in self.verdicts
                     if v.status == BLOCKED)

    @property
    def not_measured(self) -> tuple[str, ...]:
        return tuple(v.condition_id for v in self.verdicts
                     if v.status == NOT_MEASURED)

    @property
    def waived(self) -> tuple[str, ...]:
        return tuple(v.condition_id for v in self.verdicts if v.waived)

    @property
    def unmet_override_forbidden(self) -> tuple[str, ...]:
        """The conditions no argument can buy off, that are not PASS.

        Named separately from `failed` because these are the rows where a
        waiver is refused by the type, and a reader deciding a cutover
        should see them without reconciling two lists.
        """
        return tuple(v.condition_id for v in self.verdicts
                     if v.status != PASS and v.is_override_forbidden)

    @property
    def is_cutover_ready(self) -> bool:
        """P2 §5: every condition must hold SIMULTANEOUSLY.

        BLOCKED is not passed and NOT_MEASURED is not passed, so this
        stays False until the missing layers exist, answer, and answer
        against a non-empty denominator. That is the intended reading —
        the alternative is a harness that green-lights a cutover on the
        strength of the conditions it happened to be able to check.

        The override-forbidden check below is deliberately redundant with
        the all-PASS check. It exists because C-17 was added precisely
        because a script judging §5 could return True while holding a
        CRITICAL blocker, and a rule stated once in an aggregate is a rule
        that a future refactor removes without noticing.
        """
        by_id = {v.condition_id: v for v in self.verdicts}
        if set(by_id) != {c.condition_id for c in CONDITIONS}:
            return False
        if self.unmet_override_forbidden:
            return False
        return all(verdict.status == PASS for verdict in by_id.values())

    def verdict_for(self, condition_id: str) -> ConditionVerdict:
        for verdict in self.verdicts:
            if verdict.condition_id == condition_id:
                return verdict
        raise KeyError(condition_id)

    def as_dict(self) -> dict:
        return {
            "cutover_ready": self.is_cutover_ready,
            "passed": list(self.passed),
            "failed": list(self.failed),
            "blocked": list(self.blocked),
            "not_measured": list(self.not_measured),
            "waived": list(self.waived),
            "unmet_override_forbidden": list(self.unmet_override_forbidden),
            "per_scenario_summaries": {
                scenario_id: summary.as_dict() for scenario_id, summary
                in self.context.scenario_summaries.items()},
            "window": {"start": self.context.window_start,
                       "end": self.context.window_end,
                       "tick_interval_sec": self.context.tick_interval_sec},
            "parity_run_id": self.context.parity_run_id,
            "conditions": [v.as_dict() for v in self.verdicts],
            "summary": self.summary.as_dict() if self.summary else None,
            "notes": list(self.notes),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, sort_keys=True,
                          allow_nan=False, ensure_ascii=False, default=str)


def build_report(context: ParityContext, *, notes=()) -> ParityReport:
    return ParityReport(verdicts=evaluate(context), context=context,
                        summary=context.threat_level_summary,
                        notes=tuple(notes))


__all__ = ["ParityContext", "ParityReport", "build_report"]
