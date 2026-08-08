"""O-4: individual anomalous events, ranked, with every factor shown.

S1-CONC-021 through S1-CONC-023. The one type that emits several rows per
tick, and the one whose `state` is a controlled vocabulary — Phase G
(2026-04-30) replaced a free-text summary with the bare `signal_source`,
because a state unique to each row cannot be counted, and counting is what
turns anomalies into a pattern.

Novelty (S1-CONC-023) is measured over L1's signal-observation stream
rather than over anomaly rows in the conclusion ledger. Two reasons:

  * S1-conclusions A8 recorded the interaction the old shape created —
    the 2026-07-04 change gate cut ledger rows, `similar_count` fell, and
    importance drifted upward with nobody measuring it. Counting the
    unthinned stream removes the coupling instead of compensating for it
    (P6 O-16), and it is the redefinition A8 itself proposed.
  * whether the conclusion ledger thins is then a storage decision with no
    effect on a published number.

The count is scoped to the scenario's participants, so two scenarios
watching different countries stay isolated. Scenarios sharing a
participant now share that country's observations, which is a registered
difference from the strict per-scenario isolation of the ledger count.
"""
from __future__ import annotations

import math

from v3.conclusions import availability as A
from v3.conclusions import conclusion as C
from v3.conclusions import thresholds as T
from v3.conclusions import vocabulary as V
from v3.conclusions.context import ScenarioContext
from v3.kernel import Provenance

FORMULA_REF = "v3.conclusions.anomaly.derive@S1-CONC-021..023"

GLOBAL_COUNTRY = "GLOBAL"
STATUS_FIRED = "FIRED"
NOVELTY_SOURCE_STREAM = "signal_stream_fired_24h"
NOVELTY_SOURCE_UNSCOPED = "signal_stream_fired_24h_unscoped"
NOVELTY_SOURCE_FALLBACK = "signal_stream_fired_24h_fallback_empty"


def recency_decay(elapsed_hours: float) -> float:
    """exp(-h / 12). A 1/e time constant, not a half-life (A7)."""
    return math.exp(-max(0.0, elapsed_hours) / T.ANOMALY_RECENCY_TIME_CONSTANT_H)


def novelty_factor(similar_count: int) -> float:
    """clamp(1 - n/10, 0.3, 1.0). Repetition dulls, it never silences."""
    return max(T.ANOMALY_NOVELTY_FLOOR,
               min(1.0, 1.0 - similar_count / T.ANOMALY_NOVELTY_WINDOW_COUNT))


def scenario_relevance(contribution) -> float:
    """llm_country_weight x participant_weight, except for GLOBAL.

    A GLOBAL contribution already has the global weight folded into its
    participant slot by L2, so multiplying both would count it twice.
    """
    if contribution.country == GLOBAL_COUNTRY:
        return float(contribution.participant_weight)
    return (float(contribution.llm_country_weight)
            * float(contribution.participant_weight))


def importance_for(*, raw_score: float, decay: float, relevance: float,
                   novelty: float) -> float:
    """S1-CONC-022: the four factors, times 100, clamped to [0, 100]."""
    product = raw_score * decay * relevance * novelty * T.ANOMALY_MAX_IMPORTANCE
    return max(0.0, min(T.ANOMALY_MAX_IMPORTANCE, product))


def novelty_counts(store, context: ScenarioContext) -> dict:
    """How often each contributing source FIRED in the last 24h.

    Fired, not polled. `signal_observation` holds one row per poll per
    source whatever the status, so counting the table would count a
    healthy quiet sensor as ninety-six repetitions a day, saturate
    `novelty_factor` at its 0.3 floor for every source, and deflate the
    published importance and confidence of a genuinely novel event by
    more than 3x — behind a label that still reads healthy. "How often
    has this fired" is what novelty means and what production's ledger
    count approximated.

    Degradation is UNIFORM: if any read fails, every source in the tick
    falls back together. A per-source fallback would give the failed
    source novelty 1.0 while its neighbours kept their real factor,
    reordering the ranking and letting a fallback row displace a
    higher-scoring real one out of the `anomaly_limit` window — a miss
    caused by a read error. Falling back everywhere preserves the order,
    which raw_score x decay x relevance then determines.

    The fallback direction is zero occurrences (novelty 1.0, highest
    importance): NP1 forbids a missing history from quietening a signal.
    It is stamped on the row (`novelty_source`, plus `novelty_error` with
    the exception class) because a degraded path that looks identical to
    a healthy one is defect D-01.
    """
    scoped = tuple(sorted(set(context.participants) | {GLOBAL_COUNTRY}))
    # An unpopulated participant list scopes the count to GLOBAL alone,
    # which under-counts, which raises importance — the safe direction,
    # but silent. Label it so an inflated ranking can be explained.
    label = (NOVELTY_SOURCE_STREAM if context.participants
             else NOVELTY_SOURCE_UNSCOPED)
    start = context.now - T.ANOMALY_NOVELTY_LOOKBACK_SEC
    counts: dict = {}
    for item in context.contributions:
        source = item.signal_source
        if source in counts:
            continue
        try:
            counts[source] = (store.count_signal_source_observations(
                signal_source=source, start=start, end=context.now,
                countries=scoped, status=STATUS_FIRED), label)
        except Exception as exc:  # noqa: BLE001 - degraded, never silent
            detail = f"{NOVELTY_SOURCE_FALLBACK}:{type(exc).__name__}"
            return {item.signal_source: (0, detail)
                    for item in context.contributions}
    return counts


def _threshold_ref() -> dict:
    return {
        "recency_time_constant_hours": T.ANOMALY_RECENCY_TIME_CONSTANT_H,
        "novelty_floor": T.ANOMALY_NOVELTY_FLOOR,
        "novelty_window_count": T.ANOMALY_NOVELTY_WINDOW_COUNT,
        "novelty_lookback_sec": T.ANOMALY_NOVELTY_LOOKBACK_SEC,
        "max_importance": T.ANOMALY_MAX_IMPORTANCE,
    }


def derive(context: ScenarioContext, *, store) -> tuple[C.Conclusion, ...]:
    """Every scorable anomaly this tick, ranked, capped at `anomaly_limit`.

    Never an empty tuple. A tick with nothing to report returns exactly
    one unavailable conclusion, because the chronic-null-zone view reads a
    per-tick observation series and an empty list is a hole in it
    (S1-CONC-021).
    """
    counts = novelty_counts(store, context)
    ranked: list[tuple[float, C.Conclusion]] = []

    for item in context.contributions:
        raw = float(item.raw_score)
        if raw <= 0:
            # S1-CONC-022: a non-positive contribution is not an anomaly.
            continue
        observed_at = context.observation_times.get(
            item.signal_source, context.now)
        elapsed_hours = max(0.0, (context.now - observed_at) / 3600.0)
        decay = recency_decay(elapsed_hours)
        relevance = scenario_relevance(item)
        similar, novelty_source = counts.get(
            item.signal_source, (0, NOVELTY_SOURCE_FALLBACK))
        novelty = novelty_factor(similar)
        importance = importance_for(raw_score=raw, decay=decay,
                                    relevance=relevance, novelty=novelty)
        url = context.url_for(item.signal_source)
        urls = (url,) if url else ()

        candidate = A.Candidate(state=item.signal_source, calm=False)
        verdict = A.evaluate(context.health, candidate)
        provenance = Provenance(
            formula_ref=FORMULA_REF, computed_at=context.now,
            inputs={"raw_score": round(raw, 6),
                    "recency_decay": round(decay, 6),
                    "scenario_relevance": round(relevance, 6),
                    "novelty_factor": round(novelty, 6),
                    "novelty_similar_count": similar,
                    "elapsed_hours": round(elapsed_hours, 4),
                    "novelty_source": novelty_source},
            source_refs=urls)
        ranked.append((importance, C.build(
            scenario_id=context.scenario_id, conclusion_type=V.ANOMALY,
            observed_at=context.now,
            confidence=round(importance / T.ANOMALY_MAX_IMPORTANCE, 3),
            provenance=provenance, input_health=context.health,
            availability=verdict, state=item.signal_source,
            threshold_ref=_threshold_ref(), source_urls=urls,
            calibration_status=context.calibration_status,
            metadata={"importance_score": round(importance, 2),
                      "raw_score": round(raw, 3),
                      "recency_decay": round(decay, 3),
                      "scenario_relevance": round(relevance, 3),
                      "novelty_factor": round(novelty, 3),
                      "novelty_similar_count": similar,
                      "novelty_source": novelty_source,
                      "elapsed_hours": round(elapsed_hours, 2),
                      "domain": item.domain,
                      "contributing_country": item.country,
                      "signal_source": item.signal_source,
                      "sensor": item.sensor,
                      "batch_at": context.now,
                      "value_display": item.trace})))

    if not ranked:
        candidate = A.Candidate(
            state=None, calm=True, derivable=False,
            detail="no contribution carried a positive score, so there is "
                   "no individual event to rank. This asserts nothing about "
                   "whether anomalies occurred.")
        verdict = A.evaluate(context.health, candidate)
        provenance = Provenance(
            formula_ref=FORMULA_REF, computed_at=context.now,
            inputs={"contributions": len(context.contributions),
                    "positive_contributions": 0})
        return (C.build(
            scenario_id=context.scenario_id, conclusion_type=V.ANOMALY,
            observed_at=context.now, confidence=0.0, provenance=provenance,
            input_health=context.health, availability=verdict,
            threshold_ref=_threshold_ref(),
            calibration_status=context.calibration_status,
            metadata={"contributions": len(context.contributions),
                      "batch_at": context.now}),)

    # Descending importance; Python's sort is stable, so equal importance
    # keeps the scorer's deterministic order and the ranking is
    # reproducible from the same inputs.
    ranked.sort(key=lambda pair: pair[0], reverse=True)
    return tuple(item for _, item in ranked[:context.anomaly_limit])


__all__ = ["derive", "recency_decay", "novelty_factor", "scenario_relevance",
           "importance_for", "novelty_counts", "FORMULA_REF",
           "NOVELTY_SOURCE_STREAM", "NOVELTY_SOURCE_FALLBACK"]
