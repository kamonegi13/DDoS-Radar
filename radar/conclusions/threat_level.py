"""Threat-level conclusion deriver — wraps `radar.scoring.derive_tl()` output
in the v2.0 Conclusion schema.

The v1 derive_tl() returns an int 1..5 (1 = most severe). This builder lifts
that scalar into a full Conclusion(THREAT_LEVEL) row with NP6 disclosure
(formula_ref + threshold_ref + source_urls), NP5+8 calibration metadata,
and NP7 disclaimer.

The actual threshold table is duplicated here from `derive_tl()` so the
conclusion can publish the constants it used. If `derive_tl()` thresholds
change, bump DERIVE_TL_FORMULA_REF in scoring.py AND mirror the new values
into THRESHOLD_REF below — `test_threat_level_derive` enforces parity.

NP1: even an INSUFFICIENT_DATA TL=None still emits a Conclusion (with
unavailable_reason set), so chronic gaps are visible to continuity tracking
rather than silently dropped.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Optional

from radar import config
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    new_conclusion_id,
)
from radar.conclusions.calibration import calibration_status_for
from radar.conclusions.sensitivity import compute_falsification

if TYPE_CHECKING:
    from radar.database import RadarDB
    from radar.scoring import ScenarioState


# Mirror of radar.scoring.DERIVE_TL_FORMULA_REF — re-exported here so the
# Conclusion is self-describing without importing scoring.py at module level
# (avoids the circular import risk that scoring.py → conclusions has today).
FORMULA_REF = "radar/scoring.py#derive_tl@v2.0.1"

# Frozen copy of the thresholds derive_tl() applies. Kept in lockstep via
# test_threat_level_derive.test_threshold_ref_matches_derive_tl().
THRESHOLD_REF: dict = {
    "tl1_total": 9.0,
    "tl1_physical": 3.0,
    "tl2_total": 6.0,
    "tl2_active_domains_min": 2,
    "tl3_total": 4.0,
    "tl4_total": 2.0,
}

# Score / 12.0 maps an upper-bound score (≈ DOMAIN_CAP × 2) to confidence 1.0
# under v1 scoring. This is a placeholder calibration; ADR-V2-010 calls for
# isotonic regression once analyst feedback accumulates.
_CONFIDENCE_DENOM = 12.0


def derive_threat_level(
    db: "RadarDB",
    state: "ScenarioState",
    *,
    now: Optional[float] = None,
) -> Conclusion:
    """Build the THREAT_LEVEL Conclusion for a scenario's current ScenarioState.

    Caller is responsible for persisting via `save_conclusion(db, c)`. This
    function is pure (no DB writes); the only DB read is the calibration
    snapshot for `calibration_status`.

    `state.tl is None` is mapped to an INSUFFICIENT_DATA Conclusion rather
    than dropped silently — NP5+8 + NP1 (visibility of gaps).
    """
    if now is None:
        now = time.time()

    source_urls = tuple(sorted({
        c.signal.evidence_url
        for c in state.contributions
        if c.signal.evidence_url
    }))

    # NP6 — surface every contributing signal so the drill-down can show the
    # full derivation path (mirrors v1 strategic_alert.rationale_matrix). Sorted
    # by absolute final_contribution descending so the largest movers come first.
    rationale_matrix = [
        {
            "sensor": c.signal.sensor,
            "domain": c.signal.domain,
            "signal_source": c.signal.signal_source,
            "value_display": c.signal.value_display,
            "raw_score": round(float(c.signal.raw_score), 3),
            "contributing_country": c.contributing_country,
            "participant_role": c.participant_role,
            "final_contribution": round(float(c.final_contribution), 3),
            "formula_trace": c.formula_trace,
            "evidence_url": c.signal.evidence_url,
            "suppress_reason": c.suppress_reason,
        }
        for c in sorted(
            state.contributions,
            key=lambda c: abs(float(c.final_contribution)),
            reverse=True,
        )
    ]

    if state.tl is None:
        return Conclusion(
            id=new_conclusion_id(),
            scenario_id=state.scenario_id,
            conclusion_type=ConclusionType.THREAT_LEVEL,
            state=None,
            confidence=0.0,
            observed_at=now,
            formula_ref=FORMULA_REF,
            threshold_ref=dict(THRESHOLD_REF),
            source_urls=source_urls,
            calibration_status=calibration_status_for(db, state.scenario_id),
            final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
            conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
            metadata={
                "score": round(float(state.score), 3),
                "active_countries": list(state.active_countries),
                "convergence_bonus": round(float(state.convergence_bonus), 3),
                "scoring_mode": state.scoring_mode,
                "is_transient": True,
                "reason_detail": "derive_tl returned None (no scorable signal)",
                "rationale_matrix": rationale_matrix,
            },
        )

    confidence = round(min(1.0, max(0.0, float(state.score) / _CONFIDENCE_DENOM)), 3)

    active_domain_count = sum(1 for v in state.domains.values() if v > 0)
    physical_score = float(state.domains.get("physical", 0.0))

    # NP6 — falsification report: deterministic "what would change this"
    # analysis (ADR-V2-016). Pure arithmetic against the rationale_matrix
    # + threshold ladder; no LLM, no learned weights.
    falsification = compute_falsification(
        score=float(state.score),
        active_domain_count=active_domain_count,
        physical_score=physical_score,
        convergence_bonus=float(state.convergence_bonus),
        rationale_matrix=rationale_matrix,
        current_tl=state.tl,
    )

    return Conclusion(
        id=new_conclusion_id(),
        scenario_id=state.scenario_id,
        conclusion_type=ConclusionType.THREAT_LEVEL,
        state=str(state.tl),
        confidence=confidence,
        observed_at=now,
        formula_ref=FORMULA_REF,
        threshold_ref=dict(THRESHOLD_REF),
        source_urls=source_urls,
        calibration_status=calibration_status_for(db, state.scenario_id),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        metadata={
            "score": round(float(state.score), 3),
            "active_countries": list(state.active_countries),
            "convergence_bonus": round(float(state.convergence_bonus), 3),
            "scoring_mode": state.scoring_mode,
            "active_domain_count": active_domain_count,
            "physical_score": round(physical_score, 3),
            "rationale_matrix": rationale_matrix,
            "falsification": falsification,
        },
    )
