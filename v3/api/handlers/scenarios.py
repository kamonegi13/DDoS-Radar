"""P7 R1 — the scenario ledger, and the lightweight bar over it.

The scenario bar polls this; the focused scenario's detail comes from R2
and R5. That two-stage shape is what replaces `/api/threat_data`, the
god-endpoint whose 13 top-level keys and ~40 analytics sub-objects were
recomputed on every poll — and whose recomputation was A-01.

`compare` is deliberately absent (P7 R1): comparing two scenarios is this
projection read twice and differenced on the client. A server-side
compare endpoint is a second place the same numbers are produced, which
is defect A-02's shape.
"""
from __future__ import annotations

from v3.api.envelope import ApiResponse, tool_response
from v3.api.rehydrate import tl_point
from v3.commands.state import focus_state

DAY_SEC = 86400.0


def _tl_summary(ledger, scenario_id: str, now: float) -> dict:
    """Current TL plus the 24h change, in the tool's own vocabulary.

    `threat_level = None` is the null zone: a state, not a missing value
    (NP5+8). It is reported as such rather than defaulted to 5/NORMAL —
    defaulting is exactly how the empty cache returned CLEAR (G-17).
    """
    raw_latest = ledger.latest_tl_at(now, scenario_id=scenario_id)
    raw_earlier = ledger.latest_tl_at(now - DAY_SEC, scenario_id=scenario_id)
    latest = None if raw_latest is None else tl_point(raw_latest)
    earlier = None if raw_earlier is None else tl_point(raw_earlier)
    current = None if latest is None else latest.get("threat_level")
    previous = None if earlier is None else earlier.get("threat_level")
    delta = None
    if current is not None and previous is not None:
        # Severity space (6 - TL), never TL space: the scale is inverted
        # and comparing TL numbers directly is calibration incident #2.
        delta = (6 - current) - (6 - previous)
    return {
        "threat_level": current,
        "threat_level_24h_ago": previous,
        "severity_delta_24h": delta,
        "observed_at": None if latest is None else latest.get("observed_at"),
        "score": None if latest is None else latest.get("score"),
        "scoring_mode": None if latest is None else latest.get("scoring_mode"),
        "in_null_zone": latest is not None and current is None,
        "never_observed": latest is None,
    }


def read_scenarios(context) -> ApiResponse:
    """R1. One row per configured scenario, focus state included.

    Focus is read from the command log, not from the deployment's
    bootstrap value, whenever a command has ever set it. That is what
    makes C1 a real change rather than a recorded one: if this projection
    kept its own copy, the two would be free to disagree, and G-15 is the
    name for what happens when they do. The deployment default survives
    only as the state before the first command.
    """
    focused = focus_state(context.ledger, until=context.now)
    rows = []
    for ref in context.scenarios:
        row = {**ref.as_dict(),
               **_tl_summary(context.ledger, ref.scenario_id, context.now)}
        if focused is not None:
            row["focused"] = ref.scenario_id == focused
        rows.append(row)
    return tool_response(observed_at=context.now, scenarios=rows,
                         scenario_count=len(rows),
                         focused_scenario=focused,
                         focus_source=("command_log" if focused is not None
                                       else "deployment_default"))


__all__ = ["read_scenarios"]
