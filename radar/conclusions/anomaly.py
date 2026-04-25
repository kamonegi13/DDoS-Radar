"""Anomaly conclusion deriver — emits one Conclusion(ANOMALY) per
notable signal contribution in the current ScenarioState, ranked by
importance and capped at top N.

Importance formula (v2-migration.md §6.4):

    importance = raw × recency_decay × scenario_relevance × novelty_factor × 100

where
  recency_decay      = exp(-elapsed_hours / 12)              # τ = 12h (1/e ≈ 37% at 12h)
  scenario_relevance = llm_country_weight × participant_weight (per contribution)
  novelty_factor     = 1.0 − (similar_24h_count / 10), clamped [0.3, 1.0]

The spec text in v2-migration.md §6.4 calls the 12h constant a "half-life",
but the literal formula `exp(-h/12)` is a 1/e time constant — half-life is
actually ≈ 8.32h (12·ln 2). We follow the formula literally rather than the
label; the misnomer is tracked for a doc fix.

NP1 stance: Phase 1 has no historical anomaly ledger to query, so
`similar_24h_count` is approximated by the count of same-`signal_source`
contributions *within the current scoring tick*. This biases novelty
toward 1.0 (more anomalies surfaced) which is acceptable under NP1
(sensitivity > precision). A follow-up will tighten the proxy once the
`conclusions` table accumulates ANOMALY rows we can count over 24h —
the source of the count is recorded in `metadata["novelty_source"]` so
analysts can tell which definition any given row used.

NP5+8: when the scoring tick has no scorable contribution we still emit
a single INSUFFICIENT_DATA Conclusion rather than dropping the row, so
chronic gaps are visible in continuity tracking.
"""

from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING, List, Optional

from radar import config
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    new_conclusion_id,
)
from radar.conclusions.calibration import calibration_status_for

if TYPE_CHECKING:
    from radar.database import RadarDB
    from radar.scoring import ScenarioContribution, ScenarioState


FORMULA_REF = "radar/conclusions/anomaly.py#derive_anomaly@v2.0.0"

THRESHOLD_REF: dict = {
    "recency_time_constant_hours": 12.0,
    "novelty_floor": 0.3,
    "novelty_window_count": 10,
    "default_limit": 10,
    "max_importance": 100.0,
}

DEFAULT_LIMIT = 10

_RECENCY_TIME_CONSTANT_HOURS = 12.0
_NOVELTY_WINDOW = 10
_NOVELTY_FLOOR = 0.3
_MAX_IMPORTANCE = 100.0


def _recency_decay(observed_at: float, now: float) -> float:
    elapsed_h = max(0.0, (now - observed_at) / 3600.0)
    return math.exp(-elapsed_h / _RECENCY_TIME_CONSTANT_HOURS)


def _novelty_factor(similar_count: int) -> float:
    f = 1.0 - (similar_count / _NOVELTY_WINDOW)
    return max(_NOVELTY_FLOOR, min(1.0, f))


def _scenario_relevance(contribution: "ScenarioContribution") -> float:
    """Per-country: llm_country_weight × participant_weight.

    GLOBAL contributions already absorb global_signal_weight into
    participant_weight, so we use that scalar directly.
    """
    if contribution.contributing_country == "GLOBAL":
        return float(contribution.participant_weight)
    return float(contribution.llm_country_weight) * float(
        contribution.participant_weight
    )


def _state_summary(contribution: "ScenarioContribution") -> str:
    sig = contribution.signal
    if sig.value_display:
        return f"{sig.signal_source}: {sig.value_display.strip()}"
    return sig.signal_source


def _unavailable(db: "RadarDB", state: "ScenarioState", now: float) -> Conclusion:
    return Conclusion(
        id=new_conclusion_id(),
        scenario_id=state.scenario_id,
        conclusion_type=ConclusionType.ANOMALY,
        state=None,
        confidence=0.0,
        observed_at=now,
        formula_ref=FORMULA_REF,
        threshold_ref=dict(THRESHOLD_REF),
        source_urls=(),
        calibration_status=calibration_status_for(db, state.scenario_id),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
        metadata={
            "is_transient": True,
            "reason_detail": (
                "no scorable signal contributions in this scoring tick"
            ),
        },
    )


def derive_anomaly(
    db: "RadarDB",
    state: "ScenarioState",
    *,
    now: Optional[float] = None,
    limit: int = DEFAULT_LIMIT,
) -> List[Conclusion]:
    """Build the list of Conclusion(ANOMALY) rows for this scenario tick.

    Returns the top-`limit` most important anomalies. If no scorable
    contribution is available, returns a single INSUFFICIENT_DATA
    Conclusion (NP5+8 + NP1).

    Caller persists each row via `save_conclusion`. Pure: the only DB
    reads are `calibration_status_for` per emitted row.
    """
    if now is None:
        now = time.time()

    if not state.contributions:
        return [_unavailable(db, state, now)]

    src_counts: dict[str, int] = {}
    for c in state.contributions:
        src_counts[c.signal.signal_source] = (
            src_counts.get(c.signal.signal_source, 0) + 1
        )

    cal = calibration_status_for(db, state.scenario_id)
    disclaimer = config.V2_NP7_DISCLAIMER

    ranked: list[tuple[float, Conclusion]] = []
    for c in state.contributions:
        sig = c.signal
        raw = float(sig.raw_score)
        if raw <= 0:
            continue
        decay = _recency_decay(float(sig.observed_at), now)
        relevance = _scenario_relevance(c)
        # similar_count excludes the contribution itself
        similar = max(0, src_counts.get(sig.signal_source, 1) - 1)
        novelty = _novelty_factor(similar)
        importance = raw * decay * relevance * novelty * 100.0
        importance = max(0.0, min(_MAX_IMPORTANCE, importance))
        confidence = round(importance / _MAX_IMPORTANCE, 3)
        elapsed_h = max(0.0, (now - float(sig.observed_at)) / 3600.0)

        conc = Conclusion(
            id=new_conclusion_id(),
            scenario_id=state.scenario_id,
            conclusion_type=ConclusionType.ANOMALY,
            state=_state_summary(c),
            confidence=confidence,
            observed_at=now,
            formula_ref=FORMULA_REF,
            threshold_ref=dict(THRESHOLD_REF),
            source_urls=(sig.evidence_url,) if sig.evidence_url else (),
            calibration_status=cal,
            final_judgment_disclaimer=disclaimer,
            metadata={
                "importance_score": round(importance, 2),
                "raw_score": round(raw, 3),
                "recency_decay": round(decay, 3),
                "scenario_relevance": round(relevance, 3),
                "novelty_factor": round(novelty, 3),
                "elapsed_hours": round(elapsed_h, 2),
                "domain": sig.domain,
                "contributing_country": c.contributing_country,
                "signal_source": sig.signal_source,
                "sensor": sig.sensor,
                "novelty_source": "current_tick_proxy",
            },
        )
        ranked.append((importance, conc))

    if not ranked:
        return [_unavailable(db, state, now)]

    ranked.sort(key=lambda pair: pair[0], reverse=True)
    return [c for _, c in ranked[:limit]]
