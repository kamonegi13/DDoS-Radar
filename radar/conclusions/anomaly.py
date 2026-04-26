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

Novelty source: this builder counts prior ANOMALY rows in the conclusions
ledger over the past `_NOVELTY_LOOKBACK_SEC` window (default 24h) for the
same scenario_id and same signal_source. Empty / unavailable ledger reads
return 0, which keeps novelty=1.0 — strictly NP1 (no false suppression
when history is missing). The source of the count is recorded in
`metadata["novelty_source"]` (`"ledger_24h"` for the live path,
`"ledger_24h_fallback_empty"` if the SQL query failed) so analysts can
trace which definition a historical row used.

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


FORMULA_REF = "radar/conclusions/anomaly.py#derive_anomaly@v2.1.0"

THRESHOLD_REF: dict = {
    "recency_time_constant_hours": 12.0,
    "novelty_floor": 0.3,
    "novelty_window_count": 10,
    "novelty_lookback_sec": 24 * 3600,
    "default_limit": 10,
    "max_importance": 100.0,
}

DEFAULT_LIMIT = 10

_RECENCY_TIME_CONSTANT_HOURS = 12.0
_NOVELTY_WINDOW = 10
_NOVELTY_FLOOR = 0.3
_NOVELTY_LOOKBACK_SEC = 24 * 3600
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


def _ledger_similar_count(db: "RadarDB", scenario_id: str,
                          signal_source: str, now: float) -> tuple[int, str]:
    """Count prior ANOMALY conclusions for (scenario, signal_source) in the
    last `_NOVELTY_LOOKBACK_SEC` seconds.

    Returns (count, source_label). On any read failure we fall back to 0
    (novelty=1.0) and label the source so analysts can distinguish a real
    "no prior history" from a degraded path that returned 0 by accident.
    NP1: never under-count silently in a way that would suppress importance.
    """
    cutoff = now - _NOVELTY_LOOKBACK_SEC
    try:
        row = db._get_conn().execute(  # noqa: SLF001 — established internal pattern
            "SELECT COUNT(*) AS n FROM conclusions "
            "WHERE scenario_id = ? "
            "  AND conclusion_type = ? "
            "  AND observed_at >= ? AND observed_at < ? "
            "  AND json_extract(metadata, '$.signal_source') = ?",
            (scenario_id, ConclusionType.ANOMALY.value,
             cutoff, now, signal_source),
        ).fetchone()
        if row is None:
            return 0, "ledger_24h"
        return int(row["n"] or 0), "ledger_24h"
    except Exception:
        return 0, "ledger_24h_fallback_empty"


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

    Caller persists each row via `save_conclusion`. The only DB reads
    are `calibration_status_for` and one `_ledger_similar_count` per
    emitted row.
    """
    if now is None:
        now = time.time()

    if not state.contributions:
        return [_unavailable(db, state, now)]

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
        similar, novelty_source = _ledger_similar_count(
            db, state.scenario_id, sig.signal_source, now,
        )
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
                "novelty_similar_count": similar,
                "elapsed_hours": round(elapsed_h, 2),
                "domain": sig.domain,
                "contributing_country": c.contributing_country,
                "signal_source": sig.signal_source,
                "sensor": sig.sensor,
                "novelty_source": novelty_source,
            },
        )
        ranked.append((importance, conc))

    if not ranked:
        return [_unavailable(db, state, now)]

    ranked.sort(key=lambda pair: pair[0], reverse=True)
    return [c for _, c in ranked[:limit]]
