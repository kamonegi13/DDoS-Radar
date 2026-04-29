"""Guard-aware proposal writer (post-incident redesign).

Single chokepoint for emitting scenario_proposals rows. Wraps the existing
scenario_improver._emit logic with:

  - automatic stamping of evidence_strength + vitality_state (migration v30)
  - separation of "structural" (apply changes config) vs "diagnostic"
    (informational only) proposal kinds
  - taxonomy enforcement: every emitted row has a `proposal_kind`
    that places it in exactly one Wizard tab (commit E)

Proposal kinds (all stored under proposal_type column for API back-compat):

  RECALL_POSITIVE — increases recall coverage; safe to apply
                    types: weight_too_low, missing_participant
  STRUCTURE       — neither + nor - on recall; needs analyst review
                    types: role_reclassify
  RECALL_NEGATIVE — decreases recall coverage; strict evidence + NP7
                    types: weight_too_high, dormant_participant,
                           participant_remove
  DIAGNOSTIC      — informational, no apply path
                    types: sensor_gap_detected, scenario_dormant,
                           needs_more_data
  DISCOVERY       — G.3a clusters
                    types: scenario_discovery
  SENSOR          — Phase D auto-disable
                    types: sensor_disable

NP integrity:
  NP1 — RECALL_NEGATIVE emit path is gated by guards.evaluate_for_country
        before this module is even called (rules check first).
  NP3 — emit returns None on dedup/cap/insert failure rather than raising.
  NP6 — every row carries evidence_strength + vitality_state; combined
        with formula_ref these are sufficient to reproduce the decision.
  NP7 — DIAGNOSTIC kind has no API apply endpoint; it's surfaced for
        analyst awareness but cannot mutate scenario state.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from radar.calibration import _proposal_guards as guards
from radar.calibration.scenario_improver import (
    ProposalEvent,
    _has_recent_pending_for,
    _active_proposal_count,
    _max_active_per_scenario,
)
from radar.database import db

log = logging.getLogger("radar.calibration._proposal_writer")


class ProposalKind(str, Enum):
    RECALL_POSITIVE = "recall_positive"
    STRUCTURE = "structure"
    RECALL_NEGATIVE = "recall_negative"
    DIAGNOSTIC = "diagnostic"
    DISCOVERY = "discovery"
    SENSOR = "sensor"


# Mapping from proposal_type → ProposalKind. Used by the Wizard to assign
# each row to a tab. Kept here (not in guards) so the writer is the single
# source of truth.
TYPE_TO_KIND: dict[str, ProposalKind] = {
    # F1 (existing)
    "weight_too_low":         ProposalKind.RECALL_POSITIVE,
    "weight_too_high":        ProposalKind.RECALL_NEGATIVE,
    "missing_participant":    ProposalKind.RECALL_POSITIVE,
    # F2-a (existing)
    "role_reclassify":        ProposalKind.STRUCTURE,
    "dormant_participant":    ProposalKind.RECALL_NEGATIVE,
    # G.3a (existing)
    "scenario_discovery":     ProposalKind.DISCOVERY,
    # Phase D (existing)
    "sensor_disable":         ProposalKind.SENSOR,
    # Diagnostic (post-incident new)
    "sensor_gap_detected":    ProposalKind.DIAGNOSTIC,
    "scenario_dormant":       ProposalKind.DIAGNOSTIC,
    "needs_more_data":        ProposalKind.DIAGNOSTIC,
}


# Diagnostic types — listed for callers that need to filter by kind without
# importing ProposalKind directly.
DIAGNOSTIC_TYPES = frozenset({
    "sensor_gap_detected", "scenario_dormant", "needs_more_data",
})


def kind_of(proposal_type: str) -> ProposalKind:
    """Resolve a proposal_type string to its ProposalKind. Unknown types
    default to STRUCTURE (safe default — UI puts them in the analyst-review
    tab rather than the safe-apply tab)."""
    return TYPE_TO_KIND.get(proposal_type, ProposalKind.STRUCTURE)


# ── Writer ───────────────────────────────────────────────────────────────────


def emit(
    event: ProposalEvent,
    *,
    evidence_strength: Optional[str] = None,
    vitality_state: Optional[str] = None,
) -> Optional[int]:
    """Insert a scenario_proposals row, stamping the new evidence_strength
    + vitality_state columns (migration v30).

    Honors the existing dedup window + per-scenario active cap.
    Returns the new row id, or None on dedup/cap/error.
    """
    if _has_recent_pending_for(
            event.scenario_id, event.proposal_type, event.target_country):
        return None
    if _active_proposal_count(event.scenario_id) >= _max_active_per_scenario():
        log.debug(
            "[writer] %s active cap hit, skipping %s",
            event.scenario_id, event.proposal_type,
        )
        return None
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO scenario_proposals "
                "(emitted_at, scenario_id, proposal_type, target_country, "
                " suggested_value_json, evidence_json, formula_ref, sample_n, "
                " why_string, evidence_strength, vitality_state, state) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
                (time.time(), event.scenario_id, event.proposal_type,
                 event.target_country,
                 json.dumps(event.suggested_value, sort_keys=True),
                 json.dumps(event.evidence, sort_keys=True),
                 event.formula_ref, int(event.sample_n), event.why_string,
                 evidence_strength, vitality_state),
            )
            return cur.lastrowid
    except Exception as exc:
        log.warning("[writer] insert failed: %s", exc)
        return None


def emit_with_decision(
    event: ProposalEvent, decision: guards.GuardDecision,
) -> Optional[int]:
    """Convenience wrapper: stamp evidence_strength + vitality_state from
    a guards.GuardDecision."""
    return emit(
        event,
        evidence_strength=decision.strength,
        vitality_state=decision.vitality.state,
    )


# ── Diagnostic builders ─────────────────────────────────────────────────────


def build_scenario_dormant_event(
    scenario, vitality: guards.VitalityReport,
) -> ProposalEvent:
    """Build a 'scenario_dormant' diagnostic proposal — emit when scenario
    vitality is 'dormant' (low total signals despite reasonable coverage).
    Suggests scenario obsolescence or analyst review."""
    return ProposalEvent(
        scenario_id=scenario.id,
        proposal_type="scenario_dormant",
        target_country=None,
        suggested_value={
            "total_signals_30d": vitality.total_signals,
            "active_participant_count": vitality.active_participant_count,
            "total_participant_count": vitality.total_participant_count,
            "action_hint": "review_relevance",
        },
        evidence={
            "vitality_state": vitality.state,
            "sensor_coverage_ratio": vitality.sensor_coverage_ratio,
            "detail": vitality.detail,
        },
        formula_ref="proposal_guards/v1#scenario_dormant",
        sample_n=vitality.total_signals,
        why_string=(
            f"Scenario {scenario.id} appears dormant: only "
            f"{vitality.active_participant_count}/{vitality.total_participant_count} "
            f"participants showed any signal over 30d, total volume "
            f"{vitality.total_signals}. {vitality.detail}. Consider "
            f"reviewing scenario relevance or expanding sensor coverage. "
            f"This is informational — no automatic action."
        ),
    )


def build_sensor_gap_event(
    scenario, vitality: guards.VitalityReport,
) -> ProposalEvent:
    """Build a 'sensor_gap_detected' diagnostic — emit when scenario
    vitality is 'data_gap' (low coverage suggests sensor-side problem).
    Points the analyst at the sensor stack rather than scenario config."""
    return ProposalEvent(
        scenario_id=scenario.id,
        proposal_type="sensor_gap_detected",
        target_country=None,
        suggested_value={
            "active_participant_count": vitality.active_participant_count,
            "total_participant_count": vitality.total_participant_count,
            "sensor_coverage_ratio": vitality.sensor_coverage_ratio,
            "action_hint": "investigate_sensors",
        },
        evidence={
            "vitality_state": vitality.state,
            "total_signals_30d": vitality.total_signals,
            "detail": vitality.detail,
        },
        formula_ref="proposal_guards/v1#sensor_gap_detected",
        sample_n=vitality.active_participant_count,
        why_string=(
            f"Scenario {scenario.id} has sensor coverage "
            f"{vitality.sensor_coverage_ratio:.0%} "
            f"({vitality.active_participant_count}/{vitality.total_participant_count} "
            f"participants observable). {vitality.detail}. This usually "
            f"indicates sensor-side issues rather than scenario config — "
            f"check /api/v2/proposals/sensor_disable and "
            f"/api/sensor_config before adjusting scenario weights."
        ),
    )


def build_needs_more_data_event(
    scenario, country: str, signals: dict, decision: guards.GuardDecision,
) -> ProposalEvent:
    """Build a 'needs_more_data' diagnostic — emit when a participant is
    suggestive of dormancy but evidence is below 'strong' threshold.
    NP5+8 transitional 結論不可 made explicit."""
    return ProposalEvent(
        scenario_id=scenario.id,
        proposal_type="needs_more_data",
        target_country=country,
        suggested_value={
            "current_evidence_strength": decision.strength,
            "needed_strength": "strong",
            "action_hint": "wait_for_accumulation",
        },
        evidence={
            "signals": signals,
            "blocking_reasons": list(decision.blocking_reasons),
            "vitality_state": decision.vitality.state,
        },
        formula_ref="proposal_guards/v1#needs_more_data",
        sample_n=sum(int(v or 0) for v in signals.values()),
        why_string=(
            f"Participant {country} shows partial dormancy signals "
            f"(evidence={decision.strength}) but the threshold for a "
            f"recall-reducing proposal is 'strong'. Awaiting more data "
            f"accumulation or analyst FN labels. NP5+8 transitional "
            f"resolved-unavailable; no action proposed."
        ),
    )


__all__ = [
    "ProposalKind",
    "TYPE_TO_KIND",
    "DIAGNOSTIC_TYPES",
    "kind_of",
    "emit",
    "emit_with_decision",
    "build_scenario_dormant_event",
    "build_sensor_gap_event",
    "build_needs_more_data_event",
]
