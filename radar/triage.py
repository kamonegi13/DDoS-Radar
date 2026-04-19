"""radar.triage -- pure functions for analyst triage prioritization.

Single source of truth for the priority formula and gate ladder shared by
/api/intel/pending/triage and /api/intel/stats (triage_pulse). Keeping the
constants and the math here prevents the two endpoints from drifting apart
silently — which would surface as "the pulse fires but the triage list is
empty" or vice versa.

All functions are pure: no DB, no Flask, no globals. Test-target.
"""
from __future__ import annotations

import math
from typing import Iterable

# ── Tunable constants ─────────────────────────────────────────────────────
# 12h half-life-ish decay constant. Items aged 12h are weighted ~37% of fresh.
PRIORITY_AGE_TAU_SEC: float = 12.0 * 3600.0

# Items whose countries match no scenario participant get a small non-zero
# floor so they don't drop to the bottom forever — analyst should still see
# unmatched items, just below scenario-relevant ones.
PRIORITY_UNMATCHED_COUPLING_FLOOR: float = 0.30

# Minimum source credibility required for auto-confirm. Mirrors the
# intel_queue gate so the triage UI can explain "why is this still pending".
CREDIBILITY_FLOOR: float = 0.75

# Ecosystems trusted enough to be auto-confirmed when other gates pass.
# Anything else (state media, hacktivist, unclassified) requires manual review.
ALLOWED_AUTO_CONFIRM_ECOSYSTEMS: frozenset[str] = frozenset(
    {"independent", "cert", "us_gov"}
)


def derive_countries(item: dict) -> list[str]:
    """Return the list of country codes for an intel item.

    Falls back to splitting `theater` on '-' (e.g. "TW-CN" -> ["TW","CN"])
    when explicit `countries` is empty. Single-country theaters become a
    one-element list. Always uppercase.
    """
    countries = item.get("countries") or []
    if countries:
        return [c.upper() for c in countries if c]
    theater = item.get("theater") or ""
    if not theater:
        return []
    if "-" in theater:
        return [c.strip().upper() for c in theater.split("-") if c.strip()]
    return [theater.upper()]


def compute_priority(
    confidence: float,
    max_coupling: float,
    age_sec: float,
) -> float:
    """priority = confidence × coupling_factor × age_decay.

    coupling_factor uses the unmatched floor when no scenario matches, so an
    important item with no scenario coupling still gets some priority instead
    of dropping to zero.
    """
    coupling = max_coupling if max_coupling > 0 else PRIORITY_UNMATCHED_COUPLING_FLOOR
    age_decay = math.exp(-max(0.0, age_sec) / PRIORITY_AGE_TAU_SEC)
    return float(confidence) * coupling * age_decay


def max_scenario_coupling(
    countries: Iterable[str],
    scenarios: Iterable,
) -> tuple[float, dict | None, list[dict]]:
    """Return (max_weight, top_scenario_dict_or_None, all_matches).

    `scenarios` is an iterable of Scenario dataclasses with .participants
    (dict[str, Participant]). A Participant has `.weight` and `.role.value`.
    """
    max_coupling = 0.0
    top_scenario: dict | None = None
    matches: list[dict] = []
    countries_list = list(countries)
    for sc in scenarios:
        for cc in countries_list:
            p = sc.participants.get(cc)
            if not p:
                continue
            matches.append({
                "country": cc,
                "scenario_id": sc.id,
                "weight": p.weight,
                "role": p.role.value,
            })
            if p.weight > max_coupling:
                max_coupling = p.weight
                top_scenario = {
                    "id": sc.id,
                    "name_en": sc.name_en,
                    "name_ja": sc.name_ja,
                    "coupling": p.weight,
                    "country": cc,
                    "role": p.role.value,
                }
    return max_coupling, top_scenario, matches


def classify_gate(
    confidence: float,
    credibility: float,
    ecosystem: str,
    auto_confirm_threshold: float,
) -> str:
    """Return the gate reason explaining why an item is still pending.

    Order matters: we report the first gate that fails, in the order the
    intel_queue evaluates them. "manual_review" means all gates passed but
    something else (operator config, review_needed flag) blocked auto-confirm.
    """
    if confidence < auto_confirm_threshold:
        return "low_confidence"
    if credibility < CREDIBILITY_FLOOR:
        return "low_source_credibility"
    if ecosystem and ecosystem not in ALLOWED_AUTO_CONFIRM_ECOSYSTEMS:
        return f"ecosystem_blocked:{ecosystem}"
    if not ecosystem:
        return "ecosystem_unclassified"
    return "manual_review"


def enrich_pending(
    items: Iterable[dict],
    sources: dict,
    scenarios: Iterable,
    *,
    now: float,
    auto_confirm_threshold: float,
    classify_ecosystem,
) -> list[dict]:
    """Enrich pending items with priority/gate/scenario context, sorted desc.

    `sources` maps source_id -> source dict (with `credibility_weight`).
    `classify_ecosystem` is injected to keep this module DB-free.
    """
    enriched: list[dict] = []
    for it in items:
        countries = derive_countries(it)
        max_coupling, top_scenario, matched = max_scenario_coupling(countries, scenarios)
        confidence = float(it.get("confidence") or 0.0)
        ts = float(it.get("ts") or it.get("created_at") or now)
        age_sec = max(0.0, now - ts)
        priority = compute_priority(confidence, max_coupling, age_sec)

        source_id = it.get("source_id", "")
        cred = sources.get(source_id, {}).get("credibility_weight", 0.70)
        eco = classify_ecosystem(source_id)
        gate = classify_gate(confidence, cred, eco, auto_confirm_threshold)

        llm_fields = it.get("llm_fields") or {}
        corroborators = llm_fields.get("corroborating_sources") or []
        corr_eco = llm_fields.get("corroborating_ecosystems") or []

        enriched.append({
            **it,
            "priority": round(priority, 4),
            "gate_reason": gate,
            "source_credibility": round(cred, 3),
            "ecosystem": eco,
            "corroboration_count": len(corroborators),
            "corroborating_sources": corroborators,
            "corroborating_ecosystems": corr_eco,
            "top_scenario": top_scenario,
            "matched_scenarios": matched,
            "age_hours": round(age_sec / 3600.0, 2),
            "age_decay": round(math.exp(-age_sec / PRIORITY_AGE_TAU_SEC), 4),
            "max_scenario_coupling": round(max_coupling, 3),
        })
    enriched.sort(key=lambda x: x["priority"], reverse=True)
    return enriched


def compute_pulse(
    items: Iterable[dict],
    scenarios: Iterable,
    *,
    now: float,
    threshold: float,
    min_age_sec: float,
) -> dict:
    """Count high-priority stale pending items for the HUD pulse indicator.

    Pulse fires when count > 0. min_age_sec gates against fresh items so the
    pulse doesn't blink on every newly arriving high-confidence item — it
    surfaces only items the analyst *should already have looked at*.
    """
    pulse_count = 0
    max_priority = 0.0
    oldest_age_h = 0.0
    for it in items:
        countries = derive_countries(it)
        max_coupling, _, _ = max_scenario_coupling(countries, scenarios)
        confidence = float(it.get("confidence") or 0.0)
        ts = float(it.get("ts") or it.get("created_at") or now)
        age_sec = max(0.0, now - ts)
        priority = compute_priority(confidence, max_coupling, age_sec)
        if priority > max_priority:
            max_priority = priority
        if priority >= threshold and age_sec >= min_age_sec:
            pulse_count += 1
            age_h = age_sec / 3600.0
            if age_h > oldest_age_h:
                oldest_age_h = age_h
    return {
        "count": pulse_count,
        "max_priority": round(max_priority, 4),
        "oldest_stale_hours": round(oldest_age_h, 2),
    }
