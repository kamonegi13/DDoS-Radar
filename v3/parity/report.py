"""The machine-readable verdict: fourteen conditions, one answer each.

Modelled on the ETL's reconciliation report, including the part that
matters most — a criterion whose precondition is absent reports BLOCKED
with the missing dependency named, never PASS. WP-2.8 runs ahead of the
layers nine of these conditions ask about, so a report that could only say
PASS or FAIL would be forced to lie nine times.

`ParityContext` is the bundle of measurements the conditions are judged
against. Assembling it is explicit so that a condition can never reach
past it into live state to find an answer.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Mapping, Optional

from v3.parity.conditions import (BLOCKED, CONDITIONS, FAIL, PASS,
                                  ConditionVerdict, evaluate)
from v3.parity.summary import SeriesSummary


@dataclass(frozen=True, slots=True)
class ParityContext:
    """Everything the fourteen conditions are allowed to consult."""

    tick_interval_sec: float
    #: The pooled summary, for the report headline only. No condition is
    #: judged on it — pooling hides a sick scenario inside a healthy one.
    threat_level_summary: Optional[SeriesSummary] = None
    #: scenario_id -> SeriesSummary. This is what the conditions read.
    scenario_summaries: Mapping[str, SeriesSummary] = field(
        default_factory=dict)
    #: scenario_id -> {"legacy_longest_sec": ..., "v3_longest_sec": ...}
    null_zone: Optional[Mapping] = None
    migration: Optional[Mapping] = None
    window_start: Optional[float] = None
    window_end: Optional[float] = None
    parity_run_id: Optional[str] = None


@dataclass(frozen=True, slots=True)
class ParityReport:
    """The fourteen verdicts plus the measurements behind them."""

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
    def waived(self) -> tuple[str, ...]:
        return tuple(v.condition_id for v in self.verdicts if v.waived)

    @property
    def is_cutover_ready(self) -> bool:
        """P2 §5: every condition must hold SIMULTANEOUSLY.

        A blocked condition is not a passed one, so this stays False until
        the missing layers exist and answer. That is the intended reading —
        the alternative is a harness that green-lights a cutover on the
        strength of the conditions it happened to be able to check.
        """
        return len(self.passed) == len(CONDITIONS)

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
            "waived": list(self.waived),
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
