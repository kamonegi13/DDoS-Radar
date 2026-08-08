"""O-1: the scenario's threat level, with every contributing signal shown.

S1-CONC-009 through S1-CONC-013. Two things this module deliberately does
NOT do:

  * it does not re-derive the ladder. DP1 records the TL formula living in
    three places, kept in step by tests alone, with the third copy already
    structurally different from the other two. `threshold_ref` here is
    read off `v3.scoring.thresholds`, the constants the single
    implementation actually compares against, so a floor cannot move in
    the formula and stay still in the disclosure.
  * it does not compare TL numbers. `severity()` decides whether the
    verdict is calm, because TL1 is CRITICAL and every ordinary reading of
    `tl <= 3` is one refactor away from meaning its opposite (2026-08-02).
"""
from __future__ import annotations


from v3.conclusions import availability as A
from v3.conclusions import conclusion as C
from v3.conclusions import thresholds as T
from v3.conclusions import vocabulary as V
from v3.conclusions.context import ScenarioContext
from v3.kernel import Provenance
from v3.scoring import thresholds as S

FORMULA_REF = "v3.conclusions.threat_level.derive@S1-CONC-009..013"

# The disclosure, read off the constants the one derivation compares
# against (DP1). Written as a function rather than a module dict so that a
# reader cannot mistake it for a second source of the numbers.


def threshold_ref() -> dict:
    """S1-CONC-012's six keys, sourced from the single TL implementation."""
    return {
        "tl1_total": S.TL1_SCORE_FLOOR,
        "tl1_physical": S.TL1_PHYSICAL_FLOOR,
        "tl2_total": S.TL2_SCORE_FLOOR,
        "tl2_active_domains_min": S.TL2_MIN_DOMAINS,
        "tl3_total": S.TL3_SCORE_FLOOR,
        "tl4_total": S.TL4_SCORE_FLOOR,
    }


def rationale_matrix(context: ScenarioContext) -> list[dict]:
    """S1-CONC-013: one row per contributing signal, biggest mover first.

    Sorted by |final_contribution| descending. Ties keep the scorer's
    order, which is itself deterministic (L2 preserves insertion order
    through dedup), so the matrix is reproducible from the same inputs —
    the property that lets an analyst re-run the argument.

    The key is present and empty when nothing contributed. An absent key
    and an empty list read the same to a careless consumer, and only one
    of them means "we looked".
    """
    rows = []
    for item in sorted(context.contributions,
                       key=lambda c: abs(float(c.score)), reverse=True):
        rows.append({
            "sensor": item.sensor,
            "domain": item.domain,
            "signal_source": item.signal_source,
            "raw_score": round(float(item.raw_score), 3),
            "contributing_country": item.country,
            "participant_role": item.role,
            "final_contribution": round(float(item.score), 3),
            "formula_trace": item.trace,
            "age_weight": round(float(item.age_weight), 3),
            "evidence_url": context.url_for(item.signal_source),
        })
    return rows


def source_urls(context: ScenarioContext) -> tuple[str, ...]:
    """S1-CONC-013: the contributing evidence, de-duplicated and sorted."""
    return tuple(sorted({
        url for url in (context.url_for(item.signal_source)
                        for item in context.contributions) if url}))


def confidence_for(score: float, *, scoring_mode: str) -> float:
    """S1-CONC-011: clamp(score / 12, 0, 1), discounted for lite mode.

    The two roundings are sequential, not combined: production rounds the
    clamped quotient to three places and then rounds the discounted value
    again (`threat_level.py:138-146`). Folding them into one round()
    changes the third decimal on some inputs, which is a parity difference
    for no benefit.
    """
    confidence = round(min(1.0, max(0.0, score / T.TL_CONFIDENCE_DENOM)), 3)
    if scoring_mode == "lite":
        confidence = round(confidence * T.TL_LITE_CONFIDENCE_FACTOR, 3)
    return confidence


def derive(context: ScenarioContext) -> C.Conclusion:
    """The THREAT_LEVEL conclusion — available or not, always exactly one."""
    matrix = rationale_matrix(context)
    urls = source_urls(context)
    result = context.result

    if result is None:
        candidate = A.Candidate(
            state=None, calm=True, derivable=False,
            detail="scoring produced no threat level for this scenario "
                   "(derive_tl had nothing to rank)")
        metadata: dict = {"rationale_matrix": matrix}
        score = 0.0
        scoring_mode = "unknown"
    else:
        level = result.threat_level
        score = float(result.score)
        scoring_mode = result.scoring_mode
        candidate = A.Candidate(
            state=str(level.value),
            calm=level.severity() < V.ALERT_MIN_SEVERITY)
        metadata = {
            "score": round(score, 3),
            "raw_tl": result.raw_threat_level.value,
            "severity": level.severity(),
            "hysteresis_held": result.hysteresis_held,
            "active_countries": list(result.active_countries),
            "active_domain_count": len(result.active_domains),
            "physical_score": round(result.physical_score, 3),
            "convergence": result.convergence,
            "convergence_bonus": round(float(result.convergence_bonus), 3),
            "scoring_mode": scoring_mode,
            "rationale_matrix": matrix,
        }
        if scoring_mode == "lite":
            metadata["lite_tl_note"] = (
                "background scenario (C-lite): TL derived from global + "
                "LLM-intel signals only; confidence discounted x"
                f"{T.TL_LITE_CONFIDENCE_FACTOR}")

    verdict = A.evaluate(context.health, candidate)
    provenance = Provenance(
        formula_ref=FORMULA_REF, computed_at=context.now,
        inputs={"score": round(score, 6), "scoring_mode": scoring_mode,
                "contributions": len(matrix),
                "sources_consulted": context.health.consulted,
                "sources_unusable": context.health.unusable},
        source_refs=urls)
    return C.build(
        scenario_id=context.scenario_id, conclusion_type=V.THREAT_LEVEL,
        observed_at=context.now,
        confidence=confidence_for(score, scoring_mode=scoring_mode),
        provenance=provenance, input_health=context.health,
        availability=verdict, state=candidate.state,
        threshold_ref=threshold_ref(), source_urls=urls,
        calibration_status=context.calibration_status, metadata=metadata)


__all__ = ["derive", "threshold_ref", "rationale_matrix", "source_urls",
           "confidence_for", "FORMULA_REF"]
