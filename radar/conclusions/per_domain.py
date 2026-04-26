"""Per-domain conclusion deriver — ADR-V2-004 (5 states per cyber/physical/info).

For each domain we map current contribution score + 24h delta to one of:

  ACTIVE              — score >= ACTIVE_FLOOR
  ELEVATED            — score >= ELEVATED_FLOOR
  STABLE              — score below ELEVATED_FLOOR but signals present
  DEGRADING           — score dropped >= DEGRADE_DELTA from prior 24h baseline
  INSUFFICIENT_SIGNAL — domain produced 0 signal contributions this cycle

The deriver writes ONE Conclusion(PER_DOMAIN) row per scenario per cycle,
encoding all 3 domain states in the `state` string for compact storage.

NP6: per-domain scores + sources are persisted in metadata.
NP5+8: a domain reporting INSUFFICIENT_SIGNAL is treated as transient
unavailable for that domain only — the parent conclusion is still
available as long as ≥1 domain produced signal.
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
from radar.conclusions.persistence import latest_conclusion

if TYPE_CHECKING:
    from radar.database import RadarDB
    from radar.scoring import ScenarioState


FORMULA_REF = "radar/conclusions/per_domain.py#derive_per_domain@v2.0.1"

DOMAINS = ("cyber", "physical", "info")

# Threshold calibration (Phase 1.3, scripts/calibrate_thresholds.py over
# 4437 backfilled rows): cyber score p95=2.5/max=3.5, physical p95=2.70/
# max=4.29. ACTIVE_FLOOR=3.0 fired in <1% of positive observations; lower
# to 2.5 to capture the p95-p99 band without flooding with false ACTIVE.
# DEGRADE_DELTA=1.5 sat at exactly cyber drop p95 (i.e. only the most
# extreme tail triggered DEGRADING); lower to 1.0 to cover p75-p90 of
# real drops. NP1 (sensitivity) dictates picking thresholds that fire on
# the meaningful portion of the empirical distribution, not just outliers.
ACTIVE_FLOOR = 2.5       # domain score considered ACTIVE
ELEVATED_FLOOR = 1.5     # domain score considered ELEVATED (unchanged: covers ~p75)
DEGRADE_DELTA = 1.0      # absolute drop from prior PER_DOMAIN snapshot to call DEGRADING


def derive_per_domain(db: "RadarDB", state: "ScenarioState", *,
                      now: Optional[float] = None) -> Conclusion:
    """Build the per-domain Conclusion from the in-flight ScenarioState.

    Reads the most recent persisted PER_DOMAIN row to detect DEGRADING.
    Caller persists via save_conclusion.
    """
    if now is None:
        now = time.time()

    prior = latest_conclusion(db, state.scenario_id, ConclusionType.PER_DOMAIN)
    prior_scores = _extract_prior_scores(prior)

    domain_states: dict[str, str] = {}
    domain_scores: dict[str, float] = {}
    sources_by_domain: dict[str, list[str]] = {d: [] for d in DOMAINS}

    for c in state.contributions:
        d = c.signal.domain
        if d in sources_by_domain and c.signal.evidence_url:
            sources_by_domain[d].append(c.signal.evidence_url)

    for d in DOMAINS:
        cur = float(state.domains.get(d, 0.0))
        domain_scores[d] = round(cur, 3)
        domain_states[d] = _classify(d, cur, prior_scores.get(d))

    available_domains = [d for d, s in domain_states.items()
                         if s != "INSUFFICIENT_SIGNAL"]
    threshold_ref = {
        "active_floor": ACTIVE_FLOOR,
        "elevated_floor": ELEVATED_FLOOR,
        "degrade_delta": DEGRADE_DELTA,
    }
    source_urls = tuple(sorted({
        url for urls in sources_by_domain.values() for url in urls
    }))

    if not available_domains:
        return Conclusion(
            id=new_conclusion_id(),
            scenario_id=state.scenario_id,
            conclusion_type=ConclusionType.PER_DOMAIN,
            state=None,
            confidence=0.0,
            observed_at=now,
            formula_ref=FORMULA_REF,
            threshold_ref=threshold_ref,
            source_urls=source_urls,
            final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
            conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
            metadata={
                "domain_scores": domain_scores,
                "domain_states": domain_states,
                "is_transient": True,
                "reason_detail": "all 3 domains report INSUFFICIENT_SIGNAL",
            },
        )

    confidence = _confidence(domain_scores, available_domains)

    return Conclusion(
        id=new_conclusion_id(),
        scenario_id=state.scenario_id,
        conclusion_type=ConclusionType.PER_DOMAIN,
        state=_serialize(domain_states),
        confidence=confidence,
        observed_at=now,
        formula_ref=FORMULA_REF,
        threshold_ref=threshold_ref,
        source_urls=source_urls,
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        metadata={
            "domain_scores": domain_scores,
            "domain_states": domain_states,
            "domain_source_counts": {d: len(sources_by_domain[d]) for d in DOMAINS},
        },
    )


def _classify(domain: str, cur: float, prior: Optional[float]) -> str:
    if cur <= 0.0:
        return "INSUFFICIENT_SIGNAL"
    if cur >= ACTIVE_FLOOR:
        return "ACTIVE"
    if prior is not None and prior - cur >= DEGRADE_DELTA:
        return "DEGRADING"
    if cur >= ELEVATED_FLOOR:
        return "ELEVATED"
    return "STABLE"


def _serialize(domain_states: dict[str, str]) -> str:
    return ";".join(f"{d}={domain_states[d]}" for d in DOMAINS)


def _extract_prior_scores(prior: Optional[Conclusion]) -> dict[str, float]:
    if prior is None or not prior.metadata:
        return {}
    raw = prior.metadata.get("domain_scores", {}) or {}
    out: dict[str, float] = {}
    for d, v in raw.items():
        try:
            out[d] = float(v)
        except (TypeError, ValueError):
            continue
    return out


def _confidence(domain_scores: dict[str, float], available: list[str]) -> float:
    """3 active domains → high confidence; 1 active + 2 silent → low.

    Confidence reflects breadth of signal, not magnitude. NP1 still
    requires that even single-domain ACTIVE produces a usable conclusion.
    """
    breadth = len(available) / float(len(DOMAINS))
    magnitude = min(1.0, sum(domain_scores.values()) / 12.0)
    return round(0.5 * breadth + 0.5 * magnitude, 3)
