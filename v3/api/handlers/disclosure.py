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

**And it used to be a lie.** `read_health` returned the literals
`{"status": "ok", "ledger_reachable": True}`, so the shadow container
answered 200 OK for its whole run while every tick failed and
`tl_observation` stayed empty — G-17 at the container layer, in the system built to make
G-17 unrepresentable. It now reports the `tick_loop` monitor
(`v3/runtime/ops_health.py`), which is the same measurement `GET
/api/v3/self_eval` serves, and the HTTP code says which of four states
the deployment is in. See `HEALTH_HTTP` for why none of them is 500.
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, scenario_response, tool_response
from v3.api.rehydrate import UnreadableConclusionRow, from_row
from v3.calibration import thresholds as calibration_thresholds
from v3.conclusions import CONCLUSION_TYPES, NP7_DISCLAIMER
from v3.conclusions import thresholds as conclusion_thresholds
from v3.conclusions.availability import registry_disclosure
from v3.config import registry as config_registry
from v3.runtime import ops_health as OPS

#: The four answers `/healthz` can give. Four, not two, because an
#: orchestrator does something different with each.
HEALTH_OK = "ok"              # up AND producing
HEALTH_STARTING = "starting"  # up, no tick has finished yet, still in budget
HEALTH_UNKNOWN = "unknown"    # the endpoint answered; nobody wired the probe
HEALTH_DEGRADED = "degraded"  # up and NOT producing

#: Verdict → status. The mapping is the whole contract, so it is a table
#: rather than a chain of ifs: `INSUFFICIENT` (measured, not yet
#: determinable) and `UNSUPPLIED` (not measured at all) are NP5+8's two
#: distinct inconclusive states, and collapsing them is how "nobody is
#: watching" comes to read as "nothing is wrong".
HEALTH_STATUS: dict = {
    OPS.OK: HEALTH_OK,
    OPS.INSUFFICIENT: HEALTH_STARTING,
    OPS.UNSUPPLIED: HEALTH_UNKNOWN,
    OPS.WARN: HEALTH_DEGRADED,
    OPS.ANOMALY: HEALTH_DEGRADED,
}

#: Status → HTTP code, and each one is a decision about what a restarter
#: should do:
#:
#:   200 ok        route to it, believe it.
#:   200 starting  do NOT restart. Killing a container for being
#:                 mid-first-tick restarts the thing that is starting;
#:                 compose's `start_period` covers the same window from
#:                 the other side. It is not `ok`, so a probe that asserts
#:                 the loop still refuses it.
#:   200 unknown   the endpoint worked and this deployment wired no loop
#:                 probe. A wiring gap is not a service failure, and it is
#:                 not health either.
#:   503 degraded  alive, not producing. 503 and never 500: 500 means the
#:                 probe itself could not answer, which is a DIFFERENT
#:                 fact, and the two have to stay distinguishable — the
#:                 whole defect here was two states sharing one answer.
HEALTH_HTTP: dict = {HEALTH_OK: 200, HEALTH_STARTING: 200,
                     HEALTH_UNKNOWN: 200, HEALTH_DEGRADED: 503}

#: A single-row lookup on `schema_meta`'s primary key: it touches the file
#: without scanning it, so the probe cannot become the load it reports on.
_REACHABILITY_PROBE_TABLE = "signal_observation"


def read_thresholds(context) -> ApiResponse:
    """R10 — the registry's current values with their provenance.

    BOTH halves of O-18, which is what P7 R10 asks for. The pinned
    catalogues carry the constants; `variable` is the group-(a) set with
    its declared reader, so a threshold nobody can change and a dial an
    analyst can turn are distinguishable from one document rather than by
    knowing which endpoint to ask. The variable keys' CURRENT values, with
    the layer that answered, are R14's — this is the declaration, that is
    the resolution.
    """
    return tool_response(
        observed_at=context.now,
        thresholds={
            "conclusions": conclusion_thresholds.disclosure(),
            "calibration": calibration_thresholds.disclosure(),
            "scoring_pinned": {
                name: body for name, body in
                config_registry.pinned_disclosure().items()
                if body.get("catalogue") == "scoring"},
            "variable": config_registry.variable_disclosure(),
        },
        unavailable_reason_registry=registry_disclosure())


def read_app_config(context) -> ApiResponse:
    """R15 — start-up configuration, as the composition root supplied it."""
    return tool_response(observed_at=context.now,
                         app_config=dict(context.app_config))


def _ledger_reachable(context) -> bool:
    """Can this process actually read its ledger? Asked, not asserted.

    Broad except on purpose, and it is the same ruling S1-CONC-038 made
    for the self-evaluation: a probe that raises takes the health surface
    down, and a health surface that is down is read as a health surface
    that is fine.
    """
    try:
        context.ledger.checkpoint(_REACHABILITY_PROBE_TABLE)
    except BaseException:                     # noqa: BLE001
        return False
    return True


def read_health(context) -> ApiResponse:
    """R15 — is the process up, AND is the loop producing? Public.

    Two questions, because they had one answer and that is what let a
    container report healthy over a tool that had concluded nothing. The
    loop's verdict comes from `ops_health`, so this endpoint and the AP3
    self-evaluation are reading the same measurement rather than two.

    The whole ops fold is NOT republished here: `/healthz` is
    unauthenticated, so it carries the loop (which is what a probe needs)
    and a pointer to the composite. The monitor bodies stay behind
    `GET /api/v3/self_eval`.
    """
    folded = OPS.supplied_or_absent(getattr(context, "ops_health", None),
                                    now=context.now)
    loop = OPS.monitor_named(folded, OPS.MONITOR_LOOP)
    status = HEALTH_STATUS.get(loop["verdict"], HEALTH_DEGRADED)
    reason = loop["reason"]

    reachable = _ledger_reachable(context)
    if not reachable:
        # A tool that cannot read its own ledger cannot conclude anything,
        # whatever the loop believes about itself.
        status, reason = HEALTH_DEGRADED, "ledger_unreachable"

    return tool_response(
        observed_at=context.now, status=HEALTH_HTTP[status],
        health={
            "status": status,
            "reason": reason,
            "ledger_reachable": reachable,
            "tick_loop": loop,
            "ops_health": {
                "worst_verdict": folded.get("worst_verdict"),
                "worst_monitor": folded.get("worst_monitor"),
                "worst_reason": folded.get("worst_reason"),
                "worst_band": folded.get("worst_band"),
                "failing_count": folded.get("failing_count"),
                "monitor_count": folded.get("monitor_count"),
            },
        })


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
           "read_report", "HEALTH_OK", "HEALTH_STARTING", "HEALTH_UNKNOWN",
           "HEALTH_DEGRADED", "HEALTH_STATUS", "HEALTH_HTTP"]
