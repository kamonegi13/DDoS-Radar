"""Scenario structure proposer (Phase F2-a).

Extends Phase F1 with structure-level suggestions: role mismatch
detection and dormant-participant detection. F1 covered weight tweaks
and missing-participant additions; F2-a covers the case where a
participant *is* in the scenario but their configured role no longer
matches observed signal patterns.

Phase F2-a v1 scope: 2 rules.

  1. role_reclassify  — participant whose dominant signal mix over the
                        last 30d implies a different role than the one
                        configured. Suggests change with full evidence.
  2. dormant_participant — participant with weight ≥ 0.30 but zero
                        contributing signals over the last 30d. F1's
                        weight_too_high uses analyst-FN as a guard;
                        this rule fires earlier and proposes a softer
                        action (review for relevance) before the
                        weight rule kicks in.

Both rules write to the existing scenario_proposals table with new
proposal_type values. Dedup, per-scenario active cap, and
is_recall_reducing flagging are inherited from scenario_improver via
shared private helpers.

NP integrity:
  NP1 — role_reclassify could shift signal weighting; UI should require
        confirmation before apply (is_recall_reducing flag handles this).
  NP3 — graceful degradation: if llm_intel is empty (warm-up period)
        the rules become no-ops rather than crashing.
  NP6 — every proposal carries formula_ref, sample_n, and a structured
        evidence dict containing the per-signal-type counts that drove
        the inference.
  NP7 — proposals only; analyst confirms via Wizard (commit 14).
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

from radar.calibration.scenario_improver import (
    ProposalEvent,
    _emit as _emit_raw,
)
from radar.database import db


def _emit_proposal(event: ProposalEvent) -> Optional[int]:
    """Guard-aware wrapper: stamp evidence_strength + vitality_state from
    the event's evidence dict when the rule populated them."""
    strength = event.evidence.get("evidence_strength") if isinstance(
        event.evidence, dict) else None
    vitality_state = event.evidence.get("vitality_state") if isinstance(
        event.evidence, dict) else None
    return _emit_raw(
        event,
        evidence_strength=strength,
        vitality_state=vitality_state,
    )

log = logging.getLogger("radar.calibration.scenario_structure_proposer")


PROPOSER_VERSION = "scenario_structure_proposer/v1"
APPLIED_BY = "auto:scenario_structure"


# Mapping from llm_intel.source_type → role implied by dominant signal.
# Conservative: each source_type maps to a single role, and only the
# most-fired source_type per country is used. Any source_type not listed
# here is treated as "ambiguous" and skipped.
_SOURCE_TYPE_TO_ROLE: dict[str, str] = {
    "apt_intel": "adversary",
    "hacktivist": "adversary",
    "hacktivist_intel": "adversary",
    "hacktivist_news": "adversary",
    "military_exercise": "forward_base",
    "diplomatic": "primary_ally",
    "ground_osint": "forward_base",
    "narrative": "strategic_observer",
    "rss_narrative": "strategic_observer",
    "geopolitical_news": "strategic_observer",
}


def _min_dominant_count() -> int:
    """Minimum fire count for the dominant source_type before the rule
    will propose. Prevents firing on a single anecdotal signal."""
    return int(os.getenv("STRUCTURE_PROPOSER_MIN_DOMINANT", "5"))


def _dominant_share_threshold() -> float:
    """Dominant source_type must account for at least this fraction of
    the country's total signals before role_reclassify proposes."""
    return float(os.getenv("STRUCTURE_PROPOSER_MIN_SHARE", "0.50"))


def _dormant_weight_floor() -> float:
    """Participants with weight ≥ this threshold are eligible for the
    dormant_participant rule. Below this, the participant is already a
    low-priority observer and dormancy is unsurprising."""
    return float(os.getenv("STRUCTURE_PROPOSER_DORMANT_WEIGHT", "0.30"))


def _lookback_days() -> float:
    return float(os.getenv("STRUCTURE_PROPOSER_LOOKBACK_DAYS", "30"))


# ── Data helpers ─────────────────────────────────────────────────────────────


def _read_signal_mix(scenario) -> dict[str, dict[str, int]]:
    """Return {country_iso2: {source_type: count}} for the scenario's
    participants over the lookback window.

    `llm_intel.theater` holds a country code (post A-3 rename, mirrored
    by the `country` generated column from migration v24). We query for
    rows whose theater matches any of the scenario's participants and
    aggregate per (country, source_type).

    NP3: if llm_intel is empty, the participant list is empty, or the
    query fails, returns {} so the rules become no-ops.
    """
    countries = list(getattr(scenario, "participants", {}) or {})
    if not countries:
        return {}
    cutoff = time.time() - _lookback_days() * 86400
    placeholders = ",".join("?" * len(countries))
    sql = (
        f"SELECT theater, source_type, COUNT(*) FROM llm_intel "
        f"WHERE theater IN ({placeholders}) AND ts > ? "
        f"GROUP BY theater, source_type"
    )
    try:
        conn = db._get_conn()  # noqa: SLF001
        rows = conn.execute(sql, (*countries, cutoff)).fetchall()
    except Exception as exc:
        log.debug("read_signal_mix(%s) failed: %s",
                  getattr(scenario, "id", "?"), exc)
        return {}
    out: dict[str, dict[str, int]] = {}
    for country, source_type, n in rows:
        if not country:
            continue
        out.setdefault(country, {})[source_type or "unknown"] = int(n or 0)
    return out


def _dominant_signal(per_country: dict[str, int]) -> Optional[tuple[str, int, float]]:
    """Return (source_type, count, share) for the dominant signal, or
    None if no source_type meets the count + share floors."""
    if not per_country:
        return None
    total = sum(per_country.values())
    if total == 0:
        return None
    top_type, top_count = max(per_country.items(), key=lambda kv: kv[1])
    if top_count < _min_dominant_count():
        return None
    share = top_count / total
    if share < _dominant_share_threshold():
        return None
    return top_type, top_count, share


# ── Rule: role_reclassify ────────────────────────────────────────────────────


def _rule_role_reclassify(scenario) -> list[ProposalEvent]:
    """Detect participants whose dominant signal mix implies a different
    role than their configured one."""
    mix = _read_signal_mix(scenario)
    out: list[ProposalEvent] = []
    for country_iso, participant in scenario.participants.items():
        per = mix.get(country_iso) or mix.get(country_iso.upper())
        if not per:
            continue
        dominant = _dominant_signal(per)
        if dominant is None:
            continue
        top_type, top_count, share = dominant
        inferred_role = _SOURCE_TYPE_TO_ROLE.get(top_type)
        if inferred_role is None:
            continue
        try:
            current_role_value = participant.role.value
        except AttributeError:
            current_role_value = str(participant.role)
        if current_role_value == inferred_role:
            continue
        out.append(ProposalEvent(
            scenario_id=scenario.id,
            proposal_type="role_reclassify",
            target_country=country_iso,
            suggested_value={
                "role_from": current_role_value,
                "role_to": inferred_role,
                "weight": getattr(participant, "weight", None),
            },
            evidence={
                "dominant_source_type": top_type,
                "dominant_count": top_count,
                "dominant_share": round(share, 3),
                "lookback_days": _lookback_days(),
                "signal_mix": per,
            },
            formula_ref=f"{PROPOSER_VERSION}#role_reclassify",
            sample_n=sum(per.values()),
            why_string=(
                f"Country {country_iso} signal mix is dominated by "
                f"{top_type} ({top_count}/{sum(per.values())} = "
                f"{share:.0%}) over {_lookback_days():.0f}d. Configured "
                f"role={current_role_value}; observed mix implies "
                f"{inferred_role}. Review before applying — role change "
                f"can shift recall/precision."
            ),
        ))
    return out


# ── Rule: dormant_participant ────────────────────────────────────────────────


def _rule_dormant_participant(scenario) -> list[ProposalEvent]:
    """Recall-reducing rule — strict guards per post-incident redesign.

    Mirrors F1's _rule_weight_too_high logic: emits dormant_participant
    ONLY for non-protected roles in active scenarios with strong
    multi-source dormancy evidence. data_gap / dormant scenarios skip
    this rule entirely (commit D emits scenario-level diagnostics
    instead).
    """
    from radar.calibration import _proposal_guards as _guards

    vitality = _guards.scenario_vitality(scenario, days=int(_lookback_days()))
    if vitality.state != "active":
        return []

    floor = _dormant_weight_floor()
    out: list[ProposalEvent] = []
    for country_iso, participant in scenario.participants.items():
        weight = getattr(participant, "weight", 0.0) or 0.0
        if weight < floor:
            continue
        if _guards.is_role_protected(participant):
            continue
        signals = _guards.collect_multi_source_signals(
            country_iso, days=int(_lookback_days()),
        )
        strength = _guards.evidence_strength(signals, role_protected=False)
        if strength != "strong":
            continue
        try:
            current_role_value = participant.role.value
        except AttributeError:
            current_role_value = str(participant.role)
        out.append(ProposalEvent(
            scenario_id=scenario.id,
            proposal_type="dormant_participant",
            target_country=country_iso,
            suggested_value={
                "weight_from": weight,
                "weight_to": max(0.10, weight - 0.20),
                "action_hint": "review_relevance",
            },
            evidence={
                "weight": weight,
                "role": current_role_value,
                "signals": signals,
                "evidence_strength": strength,
                "vitality_state": vitality.state,
                "lookback_days": _lookback_days(),
            },
            formula_ref=f"{PROPOSER_VERSION}#dormant_participant",
            sample_n=sum(int(v or 0) for v in signals.values()),
            why_string=(
                f"Country {country_iso} (weight={weight:.2f}, "
                f"role={current_role_value}) is dormant across "
                f"{_guards.zero_source_count(signals)}/5 data sources "
                f"over {_lookback_days():.0f}d. Evidence strength: "
                f"{strength}, scenario vitality: {vitality.state}. "
                f"Recall-reducing — requires NP7 confirmation."
            ),
        ))
    return out


# ── Driver ───────────────────────────────────────────────────────────────────


def run_once() -> dict:
    """Iterate registered scenarios + apply all F2-a rules. Returns
    per-scenario, per-rule counts of new proposals emitted."""
    out: dict[str, dict[str, int]] = {}
    try:
        from radar.scenarios import scenario_store
        scenarios = list(scenario_store._scenarios.values())  # noqa: SLF001
    except Exception as exc:
        log.warning("structure_proposer: failed to enumerate scenarios: %s", exc)
        return out
    rules = [
        ("role_reclassify", _rule_role_reclassify),
        ("dormant_participant", _rule_dormant_participant),
    ]
    for scenario in scenarios:
        per_rule: dict[str, int] = {}
        for rule_name, rule_fn in rules:
            try:
                events = rule_fn(scenario)
            except Exception as exc:
                log.warning("rule %s failed for %s: %s",
                            rule_name, scenario.id, exc)
                events = []
            n_emitted = 0
            for ev in events:
                if _emit_proposal(ev) is not None:
                    n_emitted += 1
            per_rule[rule_name] = n_emitted
        out[scenario.id] = per_rule
    return out


__all__ = [
    "ProposalEvent",
    "run_once",
]
