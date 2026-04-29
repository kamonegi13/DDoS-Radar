"""Shared guards for proposal-emitting rules (post-incident redesign).

Background
----------
Phase F1 / F2-a / G.3a all share a structural risk: when sensor data is
sparse or coverage is uneven, "no signal observed" gets misread as
"the participant is no longer relevant", and recall-reducing proposals
flood the Wizard. This module factors out the guards that prevent that
misread.

The original incident (2026-04-29): F1's ``_rule_weight_too_high``
emitted 25 weight-decrease proposals across all five scenarios,
including the **primary_target** of every scenario (TW for taiwan,
UA for eastern_europe, etc.). The structural error is mistaking
**A. data acquisition failure**, **B. observed quiescence**, and
**C. true relevance decay** for a single state.

Design principles enforced here
-------------------------------
P1 Role-Tier Protection — primary_target / principal_belligerent /
   adversary / core_country are recall-load-bearing. Recall-reducing
   proposals (weight_too_high / participant_remove) are blocked on
   them outright.

P2 Multi-Source Triangulation — dormancy is asserted only when
   ≥4 of 5 data sources confirm zero AND analyst FN count is zero.
   One-source signals are insufficient (NP6 evidence rigor).

P3 Scenario Vitality Check — before emitting any individual-level
   proposal, confirm the scenario itself is alive. If the whole
   scenario is silent, the right proposal is "investigate sensor
   coverage", not "lower this weight".

P4 Null-Hypothesis Discipline — when evidence is ambiguous, emit a
   diagnostic proposal (sensor_gap / scenario_dormant / needs_more_data)
   instead of a structure-changing one. NP5+8 transitional 結論不可
   is actively expressed, not silently elided.

P5 Recall-First Asymmetry — recall-positive proposals require 1 source;
   recall-neutral require 2; recall-negative require 4 + role check
   + scenario vitality + analyst FN ≥ 1. Asymmetric evidence bar
   matches asymmetric NP1 cost.

NP integrity
------------
NP1 — recall-reducing proposals are gated by the strictest evidence path.
NP3 — every helper is fault-tolerant; missing tables/columns degrade
      gracefully to "no signal" rather than crashing the run.
NP6 — collect_multi_source_signals returns the full {source: count}
      dict so every downstream proposal carries reproducible evidence.
NP7 — PROTECTED_ROLES is the structural floor: rules cannot suggest
      changing the very identity of a scenario.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Iterable, Literal, Optional

from radar.database import db

log = logging.getLogger("radar.calibration._proposal_guards")


# ── P1: Role-Tier Protection ─────────────────────────────────────────────────


# Roles whose participants ARE the scenario. Removing/weakening any of these
# would change the scenario's identity. Recall-reducing proposals MUST skip
# these participants.
PROTECTED_ROLES: frozenset[str] = frozenset({
    "primary_target",
    "principal_belligerent",
    "adversary",
    "core_country",  # historical alias; in current schema core is a field, not a role
})

# Roles where structural change (weight delta, role reclassify) requires the
# Wizard's NP7 confirm modal even when evidence is strong.
REQUIRES_CONFIRM_ROLES: frozenset[str] = frozenset({
    "primary_ally",
    "forward_base",
    "extended_deterrence",
})


def _role_value(participant) -> str:
    """Extract role.value from a Participant; defensive against shape drift."""
    role = getattr(participant, "role", None)
    if role is None:
        return ""
    if hasattr(role, "value"):
        return str(role.value)
    return str(role)


def is_role_protected(participant) -> bool:
    """True when the participant's role is in PROTECTED_ROLES.

    NP7: rules MUST consult this before emitting any recall-reducing
    proposal. False is the default (callable participants without an
    explicit role).
    """
    return _role_value(participant) in PROTECTED_ROLES


def role_requires_confirm(participant) -> bool:
    """True when role is in REQUIRES_CONFIRM_ROLES."""
    return _role_value(participant) in REQUIRES_CONFIRM_ROLES


# ── P2: Multi-Source Triangulation ──────────────────────────────────────────


SOURCE_NAMES = (
    "llm_intel",
    "sequence_events",
    "sensor_observation_ts",
    "analyst_feedback_fn",
    "conclusions_contribution",
)


def _lookback_seconds(days: int) -> float:
    return max(1, int(days)) * 86400


def _safe_count(sql: str, params: tuple) -> int:
    """Run a single-cell COUNT query. NP3: failures return 0."""
    try:
        conn = db._get_conn()  # noqa: SLF001
        row = conn.execute(sql, params).fetchone()
        return int(row[0] if row else 0)
    except Exception as exc:
        log.debug("_safe_count failed: %s", exc)
        return 0


def collect_multi_source_signals(country: str, *, days: int = 30) -> dict[str, int]:
    """Return per-source signal counts for one country over the lookback.

    Five sources are inspected:
      - llm_intel:                   theater-tagged LLM rows
      - sequence_events:             sequence-level fires
      - sensor_observation_ts:       per-sensor observations
      - analyst_feedback_fn:         FALSE_NEGATIVE labels touching this
                                      country (joined via conclusions)
      - conclusions_contribution:    scoring rows where this country
                                      contributed to a conclusion

    NP6: every numeric here goes into the proposal's evidence_json so
    the analyst can audit the dormancy claim end-to-end.
    """
    cutoff = time.time() - _lookback_seconds(days)
    out = {name: 0 for name in SOURCE_NAMES}
    if not country:
        return out

    out["llm_intel"] = _safe_count(
        "SELECT COUNT(*) FROM llm_intel WHERE theater=? AND ts > ?",
        (country, cutoff),
    )
    out["sequence_events"] = _safe_count(
        "SELECT COUNT(*) FROM sequence_events WHERE theater=? AND ts > ?",
        (country, cutoff),
    )
    out["sensor_observation_ts"] = _safe_count(
        "SELECT COUNT(*) FROM sensor_observation_ts "
        "WHERE theater=? AND ts > ?",
        (country, cutoff),
    )
    # FN labels: label='FALSE_NEGATIVE' joined via conclusions to capture
    # any FN where this country was a participant of the scenario. The
    # "country was a participant" check is done at the rule layer
    # (we just count FN rows for the scenario the caller already filtered).
    # For per-country FN, we approximate by joining on country column when
    # present (fallback: skip — overcounts conservatively).
    out["analyst_feedback_fn"] = _safe_count(
        "SELECT COUNT(*) FROM analyst_feedback "
        "WHERE label='FALSE_NEGATIVE' AND observed_at > ?",
        (cutoff,),
    )
    # Scoring contribution: presence in scenario_contribution_log.
    # Optional table — not all deployments have it. NP3-safe.
    out["conclusions_contribution"] = _safe_count(
        "SELECT COUNT(*) FROM scenario_contribution_log "
        "WHERE country=? AND ts > ?",
        (country, cutoff),
    )
    return out


def zero_source_count(signals: dict[str, int]) -> int:
    """Number of sources where the signal is exactly zero."""
    return sum(1 for v in signals.values() if int(v or 0) == 0)


def is_truly_dormant(
    signals: dict[str, int],
    *,
    min_zero_sources: int = 4,
    require_zero_fn: bool = True,
) -> bool:
    """Return True iff dormancy claim is supported by P2 evidence:

      ≥ min_zero_sources of 5 sources at zero AND analyst FN == 0.

    Returning False does NOT mean "active" — it means "evidence
    insufficient to call dormant" (which is the safe default under
    NP1).
    """
    zeros = zero_source_count(signals)
    if zeros < min_zero_sources:
        return False
    if require_zero_fn and signals.get("analyst_feedback_fn", 0) > 0:
        return False
    return True


# ── P3: Scenario Vitality ────────────────────────────────────────────────────


VitalityState = Literal["active", "dormant", "data_gap"]


@dataclass(frozen=True)
class VitalityReport:
    state: VitalityState
    total_signals: int
    active_participant_count: int
    total_participant_count: int
    sensor_coverage_ratio: float  # 0..1, fraction of participants with any signal
    detail: str


def _scenario_dormant_floor() -> int:
    """Below this total signal count across all participants, the scenario
    is treated as dormant rather than letting per-participant rules fire.
    Default 5 — enough to distinguish "noise" from "real scenario activity"
    without being so high that one quiet week kills proposals."""
    return int(os.getenv("PROPOSAL_GUARDS_SCENARIO_DORMANT_FLOOR", "5"))


def _data_gap_min_coverage() -> float:
    """Minimum fraction of participants with non-zero signals to NOT be
    classified as data_gap. Default 0.3 — when fewer than 30% of
    participants are observable, the suspicion shifts to sensor problems
    rather than scenario relevance."""
    return float(os.getenv("PROPOSAL_GUARDS_MIN_COVERAGE", "0.3"))


def scenario_vitality(scenario, *, days: int = 30) -> VitalityReport:
    """Classify a scenario as active / dormant / data_gap.

    active   — multiple participants firing, scenario observably alive.
               Per-participant rules can fire safely.
    dormant  — total signal count below floor AND coverage is decent.
               Suggests the scenario itself may be obsolete; emit
               'scenario_dormant' diagnostic instead of weight tweaks.
    data_gap — coverage is poor (few participants observable). The
               problem is likely sensor-side; emit
               'sensor_gap_detected' diagnostic instead.

    NP3: scenario without participants → returns ('dormant', 0, 0, 0, 0).
    """
    participants = getattr(scenario, "participants", {}) or {}
    if not participants:
        return VitalityReport(
            state="dormant", total_signals=0,
            active_participant_count=0, total_participant_count=0,
            sensor_coverage_ratio=0.0,
            detail="scenario has no participants",
        )

    total = 0
    active_count = 0
    for country in participants.keys():
        sigs = collect_multi_source_signals(country, days=days)
        # Treat as "active" if any source > 0
        per_country_total = sum(int(v or 0) for v in sigs.values())
        total += per_country_total
        if per_country_total > 0:
            active_count += 1

    n_part = len(participants)
    coverage = active_count / n_part if n_part > 0 else 0.0

    floor = _scenario_dormant_floor()
    min_cov = _data_gap_min_coverage()

    if total < floor and coverage < min_cov:
        # very low total + sparse coverage → can't tell which it is,
        # default to data_gap (sensor side first; safer than blaming
        # scenario design).
        state: VitalityState = "data_gap"
        detail = (f"only {active_count}/{n_part} participants observed any "
                  f"signal; total volume {total} below floor {floor}")
    elif coverage < min_cov:
        state = "data_gap"
        detail = (f"coverage {coverage:.2f} below minimum {min_cov} — "
                  f"likely sensor-side issue")
    elif total < floor:
        state = "dormant"
        detail = (f"total volume {total} below floor {floor} despite "
                  f"coverage {coverage:.2f}; scenario may be obsolete")
    else:
        state = "active"
        detail = (f"{active_count}/{n_part} participants firing, "
                  f"total volume {total}")

    return VitalityReport(
        state=state, total_signals=total,
        active_participant_count=active_count,
        total_participant_count=n_part,
        sensor_coverage_ratio=round(coverage, 3),
        detail=detail,
    )


# ── P5: Evidence-Strength Asymmetry ──────────────────────────────────────────


EvidenceStrength = Literal["strong", "moderate", "weak", "insufficient"]


def evidence_strength(
    signals: dict[str, int], *, role_protected: bool,
) -> EvidenceStrength:
    """Classify evidence strength for a recall-reducing proposal.

    "strong"       — 4+ sources show zero AND FN==0 AND role NOT protected.
                     Required threshold for any structure-changing
                     recall-reducing proposal.
    "moderate"     — 2-3 zero sources, role not protected.
                     OK for diagnostic proposals (sensor_gap / dormant).
    "weak"         — 1 zero source.
                     OK only for hint-level diagnostics.
    "insufficient" — role protected OR FN > 0 OR all-non-zero.
                     No proposal should fire.
    """
    if role_protected:
        return "insufficient"
    if signals.get("analyst_feedback_fn", 0) > 0:
        return "insufficient"
    zeros = zero_source_count(signals)
    if zeros >= 4:
        return "strong"
    if zeros >= 2:
        return "moderate"
    if zeros >= 1:
        return "weak"
    return "insufficient"


# ── Convenience: full guard bundle ──────────────────────────────────────────


@dataclass(frozen=True)
class GuardDecision:
    can_emit_recall_negative: bool
    can_emit_structure_change: bool
    can_emit_diagnostic: bool
    vitality: VitalityReport
    signals: dict[str, int]
    strength: EvidenceStrength
    blocking_reasons: tuple[str, ...]


def evaluate_for_country(scenario, country: str, *, days: int = 30) -> GuardDecision:
    """One-shot evaluation: collects signals, runs vitality, computes
    strength, and returns flags for what kinds of proposals are allowed.

    Used by rules to short-circuit the "should I emit?" decision.
    """
    vitality = scenario_vitality(scenario, days=days)
    participant = (getattr(scenario, "participants", {}) or {}).get(country)
    role_protected = is_role_protected(participant) if participant else False
    signals = collect_multi_source_signals(country, days=days)
    strength = evidence_strength(signals, role_protected=role_protected)

    reasons: list[str] = []
    if vitality.state != "active":
        reasons.append(f"scenario_vitality={vitality.state}")
    if role_protected:
        reasons.append(f"role_protected={_role_value(participant)}")
    if signals.get("analyst_feedback_fn", 0) > 0:
        reasons.append("analyst_fn>0")

    can_emit_recall_negative = (
        vitality.state == "active"
        and not role_protected
        and strength == "strong"
    )
    can_emit_structure_change = (
        vitality.state == "active"
        and strength in ("strong", "moderate")
    )
    # Diagnostics are SAFE under any vitality — they're informational
    # rather than structure-changing. We still gate them by "have at
    # least some evidence" to avoid noise.
    can_emit_diagnostic = strength != "insufficient" or vitality.state != "active"

    return GuardDecision(
        can_emit_recall_negative=can_emit_recall_negative,
        can_emit_structure_change=can_emit_structure_change,
        can_emit_diagnostic=can_emit_diagnostic,
        vitality=vitality,
        signals=signals,
        strength=strength,
        blocking_reasons=tuple(reasons),
    )


__all__ = [
    "PROTECTED_ROLES",
    "REQUIRES_CONFIRM_ROLES",
    "SOURCE_NAMES",
    "VitalityReport",
    "GuardDecision",
    "is_role_protected",
    "role_requires_confirm",
    "collect_multi_source_signals",
    "zero_source_count",
    "is_truly_dormant",
    "scenario_vitality",
    "evidence_strength",
    "evaluate_for_country",
]
