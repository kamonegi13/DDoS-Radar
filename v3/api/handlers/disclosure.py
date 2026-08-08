"""P7 R10 / R12 / R15 — thresholds, the one report, and infrastructure.

**R10.** O-18 split thresholds in two — operator-variable keys and
provenance-carrying constants — and ruled that BOTH are disclosed. A
constant that only exists in a Python module is not disclosed; NP6 says a
conclusion must be traceable to its effective threshold, and "effective"
includes the ones nobody can change.

**R12.** The only report output. `salute_report`, `weather_brief`,
`sitrep` and `daily_summary` are dropped (P7 §5): two of them answered
ROUTINE/CLEAR from an empty cache, which is G-17 — a fabricated
conclusion, not a missing one — and the structure that made it possible
goes with them.

**R15.** `/healthz` is the one public route on the surface. That is a
decision, stated in the route table: a liveness probe that requires a
token cannot be used by the thing that restarts the process.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, scenario_response, tool_response
from v3.api.rehydrate import UnreadableConclusionRow, from_row
from v3.calibration import thresholds as calibration_thresholds
from v3.conclusions import CONCLUSION_TYPES, NP7_DISCLAIMER
from v3.conclusions import thresholds as conclusion_thresholds
from v3.conclusions.availability import registry_disclosure


def read_thresholds(context) -> ApiResponse:
    """R10 — the registry's current values with their provenance."""
    return tool_response(
        observed_at=context.now,
        thresholds={
            "conclusions": conclusion_thresholds.disclosure(),
            "calibration": calibration_thresholds.disclosure(),
        },
        unavailable_reason_registry=registry_disclosure())


def read_app_config(context) -> ApiResponse:
    """R15 — start-up configuration, as the composition root supplied it."""
    return tool_response(observed_at=context.now,
                         app_config=dict(context.app_config))


def read_health(context) -> ApiResponse:
    """R15 — the liveness probe. Public, deliberately."""
    return tool_response(observed_at=context.now,
                         health={"status": "ok", "ledger_reachable": True})


def _line(label: str, value) -> str:
    return f"- **{label}**: {value}"


def read_report(context, *, scenario_id: str, at=None) -> ApiResponse:
    """R12 — the conclusion report, Markdown, one system.

    Built from the same rows R2 serves, so a report and the screen it was
    taken from cannot disagree. The NP7 sentence is in the document as
    well as in the envelope (P7 O-8: "permanently present in the report
    too").
    """
    ref = context.scenario(scenario_id)
    if ref is None:
        raise E.not_found(f"シナリオ {scenario_id}", scenario_id=scenario_id)
    at_ts = context.now if at is None else float(at)
    lines = [f"# {scenario_id} — 結論レポート", "",
             _line("観測時刻", at_ts), _line("参加国",
                                          ", ".join(sorted(ref.participants))
                                          or "（未設定）"), ""]
    for conclusion_type in CONCLUSION_TYPES:
        row = context.ledger.latest_conclusion_at(
            at_ts, scenario_id=scenario_id, conclusion_type=conclusion_type)
        lines.append(f"## {conclusion_type}")
        if row is None:
            lines.append("結論行がありません（この型はまだ記録されていません）。")
            lines.append("")
            continue
        try:
            conclusion = from_row(row)
        except UnreadableConclusionRow as exc:
            lines.extend(["この結論行は再構成できません（導出開示の欠落）。",
                          f"理由: {exc}", ""])
            continue
        lines.extend([
            _line("state", conclusion.state if conclusion.state is not None
                  else f"結論不可（{conclusion.unavailable_reason}）"),
            _line("confidence", f"{conclusion.confidence:.3f}"),
            _line("formula_ref", conclusion.provenance.formula_ref),
            _line("observed_at", conclusion.observed_at), ""])
    lines.extend(["---", "", NP7_DISCLAIMER, ""])
    return scenario_response(scenario_id, (), observed_at=at_ts,
                             at=None if at is None else at_ts,
                             report={"format": "markdown",
                                     "markdown": "\n".join(lines)})


__all__ = ["read_thresholds", "read_app_config", "read_health",
           "read_report"]
