"""Falsification / sensitivity analysis for THREAT_LEVEL conclusions.

NP6 transparency extension: given the current ScenarioState's score
breakdown and the published THRESHOLD_REF, compute a deterministic
"what would change this" report so the AP2 narrative can show the
analyst the fragility of the current TL judgment.

All numbers are derivable from radar.scoring.derive_tl + the existing
rationale_matrix attached to the conclusion. No LLM calls, no learned
weights, no scenario-specific tuning. Deterministic + idempotent.

Output schema (attached to conclusion.metadata['falsification']):

    {
        "threshold_distance": {
            "to_higher_tl": {
                "target_tl": int | None,         # one step higher than current
                                                  # (lower TL number = more severe).
                "conditions": [
                    {"field": "score", "current": 4.2, "target": 6.0, "gap": 1.8},
                    {"field": "active_domain_count", "current": 1, "target": 2, "gap": 1},
                    ...
                ],
                "all_satisfied": false,           # any single unmet condition blocks
                                                  # the rise to higher severity.
            },
            "to_lower_tl": {
                "target_tl": int | None,          # one step lower than current.
                "conditions": [
                    {"field": "score", "current": 4.2, "trigger_below": 4.0, "gap": 0.2},
                    ...
                ],
            },
        },
        "signal_sensitivity": [
            {
                "sensor": "ct_log",
                "domain": "cyber",
                "current_contribution": 1.4,
                "hypothetical_tl_if_drops_to_zero": 4,    # current=3 → 4 (less severe)
                "moves_tl_by": 1,
            },
            ... (top N by current_contribution)
        ],
    }

Read by ``self_explanation.js#narrateTL`` to render the
"What would change this" section in the drill-down.
"""

from __future__ import annotations

from typing import Optional


# Threshold ladder mirror. Kept in lockstep with
# radar.conclusions.threat_level.THRESHOLD_REF — a unit test asserts
# they are identical so no drift is possible.
_TL_RUNGS: list[tuple[int, dict]] = [
    # tl, requirements
    (1, {"score_min": 9.0, "physical_min": 3.0}),
    (2, {"score_min": 6.0, "active_domains_min": 2}),
    (3, {"score_min": 4.0}),
    (4, {"score_min": 2.0}),
    (5, {}),  # default
]


def _derive_tl_from_components(
    score: float,
    active_domain_count: int,
    physical_score: float,
) -> int:
    """Pure mirror of radar.scoring.derive_tl that operates on numeric
    inputs without a ScenarioState. Identical predicate ordering; if
    the production formula moves, both must move together.
    """
    if score >= 9.0 and physical_score >= 3.0:
        return 1
    if score >= 6.0 and active_domain_count >= 2:
        return 2
    if score >= 4.0:
        return 3
    if score >= 2.0:
        return 4
    return 5


def _conditions_for_tl(tl: int, score: float, active_domain_count: int,
                       physical_score: float) -> list[dict]:
    """Render the gap conditions for reaching ``tl`` from current state.

    Severity-rising direction (current TL → lower TL number). Returns
    one row per requirement that isn't already satisfied. An empty list
    means "already meets all requirements for this rung".
    """
    rung = next((r for t, r in _TL_RUNGS if t == tl), None)
    if rung is None:
        return []
    out: list[dict] = []
    if "score_min" in rung and score < rung["score_min"]:
        out.append({
            "field": "score",
            "current": round(score, 3),
            "target": rung["score_min"],
            "gap": round(rung["score_min"] - score, 3),
        })
    if "physical_min" in rung and physical_score < rung["physical_min"]:
        out.append({
            "field": "physical_score",
            "current": round(physical_score, 3),
            "target": rung["physical_min"],
            "gap": round(rung["physical_min"] - physical_score, 3),
        })
    if "active_domains_min" in rung and active_domain_count < rung["active_domains_min"]:
        out.append({
            "field": "active_domain_count",
            "current": active_domain_count,
            "target": rung["active_domains_min"],
            "gap": rung["active_domains_min"] - active_domain_count,
        })
    return out


def _compute_to_higher_tl(
    current_tl: int, score: float, active_domain_count: int,
    physical_score: float,
) -> dict:
    """Find one rung up (lower number = more severe) and report conditions.

    Returns a dict with ``target_tl=None`` if already at the most severe
    rung (TL=1), so the narrative can render "Already at TL1 — no higher
    severity defined".
    """
    target = current_tl - 1 if current_tl > 1 else None
    if target is None:
        return {"target_tl": None, "conditions": [], "all_satisfied": False}
    conditions = _conditions_for_tl(target, score, active_domain_count, physical_score)
    return {
        "target_tl": target,
        "conditions": conditions,
        "all_satisfied": len(conditions) == 0,
    }


def _compute_to_lower_tl(
    current_tl: int, score: float, active_domain_count: int,
    physical_score: float,
) -> dict:
    """Find one rung down (higher number = less severe) and report
    triggers — i.e. what numeric change would cause the rung to fall.

    For each requirement the CURRENT rung satisfies, surface the
    threshold that, if breached downward, would drop us out of this
    rung. The first one to break is what causes the drop.
    """
    if current_tl >= 5:
        return {"target_tl": None, "conditions": [], "any_triggered": False}
    target = current_tl + 1
    rung = next((r for t, r in _TL_RUNGS if t == current_tl), None)
    if rung is None:
        return {"target_tl": target, "conditions": [], "any_triggered": False}

    triggers: list[dict] = []
    if "score_min" in rung:
        triggers.append({
            "field": "score",
            "current": round(score, 3),
            "trigger_below": rung["score_min"],
            "gap": round(score - rung["score_min"], 3),
        })
    if "physical_min" in rung:
        triggers.append({
            "field": "physical_score",
            "current": round(physical_score, 3),
            "trigger_below": rung["physical_min"],
            "gap": round(physical_score - rung["physical_min"], 3),
        })
    if "active_domains_min" in rung:
        triggers.append({
            "field": "active_domain_count",
            "current": active_domain_count,
            "trigger_below": rung["active_domains_min"],
            "gap": active_domain_count - rung["active_domains_min"],
        })
    return {
        "target_tl": target,
        "conditions": triggers,
        "any_triggered": False,  # by definition: we are at current_tl
    }


def _compute_signal_sensitivity(
    rationale_matrix: list[dict],
    current_score: float,
    current_active_domain_count: int,
    current_physical_score: float,
    current_convergence_bonus: float,
    domain_cap: float = 6.0,
    top_n: int = 3,
) -> list[dict]:
    """For each top contributing signal, simulate dropping its
    contribution to zero and report the hypothetical TL.

    Pure recompute against the existing rationale_matrix — this is
    just arithmetic, never re-runs scoring. The simulation uses the
    same convergence_bonus on the assumption that the active-domain
    count is preserved (signal removal in a still-active domain) or
    reduced (signal removal that empties its domain).

    Returns rows for the top ``top_n`` contributors by absolute
    final_contribution (positive only — suppressed/zero rows excluded).
    Each row indicates how many TL steps would shift if this signal
    dropped out.
    """
    contribs = [
        r for r in (rationale_matrix or [])
        if isinstance(r, dict)
        and r.get("contributing_country") not in (None, "GLOBAL")
        and isinstance(r.get("final_contribution"), (int, float))
        and float(r["final_contribution"]) > 0
        and not r.get("suppress_reason")
    ]
    contribs.sort(key=lambda r: float(r["final_contribution"]), reverse=True)
    top = contribs[:max(0, int(top_n))]
    if not top:
        return []

    # Reconstruct per-domain totals from rationale_matrix so we can
    # subtract a single signal cleanly. Cap at domain_cap to mirror
    # production scoring (radar/scoring.py:1389).
    raw_by_domain: dict[str, float] = {}
    for r in contribs:
        d = r.get("domain")
        if not d:
            continue
        raw_by_domain[d] = raw_by_domain.get(d, 0.0) + float(r["final_contribution"])
    capped_by_domain = {d: min(v, domain_cap) for d, v in raw_by_domain.items()}

    current_tl = _derive_tl_from_components(
        current_score, current_active_domain_count, current_physical_score,
    )

    out: list[dict] = []
    for r in top:
        d = r.get("domain") or ""
        # Hypothetical: drop this signal's contribution. Recompute
        # capped sums for the affected domain, then total.
        hypo_raw = max(0.0, raw_by_domain.get(d, 0.0) - float(r["final_contribution"]))
        hypo_capped = {**capped_by_domain, d: min(hypo_raw, domain_cap)}
        hypo_active_count = sum(1 for v in hypo_capped.values() if v > 0)
        # Convergence bonus is recomputed on active_domain_count.
        hypo_conv = (
            2.0 if hypo_active_count >= 3
            else 1.0 if hypo_active_count == 2
            else 0.0
        )
        hypo_score = sum(hypo_capped.values()) + hypo_conv
        hypo_physical = (
            hypo_capped.get("physical", 0.0) if d == "physical"
            else current_physical_score
        )
        hypo_tl = _derive_tl_from_components(
            hypo_score, hypo_active_count, hypo_physical,
        )
        out.append({
            "sensor": r.get("sensor"),
            "domain": d,
            "current_contribution": round(float(r["final_contribution"]), 3),
            "hypothetical_tl_if_drops_to_zero": hypo_tl,
            "moves_tl_by": hypo_tl - current_tl,
        })
    return out


def compute_falsification(
    *,
    score: float,
    active_domain_count: int,
    physical_score: float,
    convergence_bonus: float,
    rationale_matrix: list[dict],
    current_tl: Optional[int],
    domain_cap: float = 6.0,
    top_n: int = 3,
) -> dict:
    """Top-level entry: build the falsification report attached to
    the THREAT_LEVEL conclusion's metadata.

    Returns ``{}`` for the INSUFFICIENT_DATA case (current_tl is None);
    the narrative renderer then skips the section gracefully.
    """
    if current_tl is None:
        return {}
    return {
        "threshold_distance": {
            "to_higher_tl": _compute_to_higher_tl(
                current_tl, score, active_domain_count, physical_score,
            ),
            "to_lower_tl": _compute_to_lower_tl(
                current_tl, score, active_domain_count, physical_score,
            ),
        },
        "signal_sensitivity": _compute_signal_sensitivity(
            rationale_matrix or [],
            score,
            active_domain_count,
            physical_score,
            convergence_bonus,
            domain_cap=domain_cap,
            top_n=top_n,
        ),
    }
