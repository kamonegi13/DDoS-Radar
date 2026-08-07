"""`score_tick` — the one entry point, and the order the clauses run in.

S1-PIPE-020 and S1-PIPE-023..027 describe a sequence. Reproduced here in
one readable function rather than spread across a 3,000-line request
handler, because the ordering IS the specification: S1-PIPE-030 exists
only because the legacy system wrote a threat-level conclusion before
hysteresis had run, so the ledger and the screen disagreed for two months.

The whole function reads nothing. Every value it uses came in through
`ScoringInputs`, including the clock. Running it twice on the same input
produces two equal results — checked by the suite, and the precondition
for parity replay (F-05).

Two steps happen BEFORE this function, in the caller: `resolve_settings()`
turns threshold keys into numbers, and `gating.gate()` turns raw readings
into observations carrying their suppression verdict. Both are outside the
kernel so that it stays pure. In particular, do not re-derive gating in
here — `Observation.passes_gate()` reads the verdict that already exists.
"""
from __future__ import annotations

from v3.kernel import Provenance
from v3.scoring import contributions as contrib
from v3.scoring import convergence, sequence, trend
from v3.scoring.inputs import (MODE_FULL, Scenario, ScoringInputs,
                               SequenceEvent)
from v3.scoring.registry import IMPLEMENTED
from v3.scoring.result import BonusBreakdown, ScoringResult, TickResult
from v3.scoring.threat_level import apply_hysteresis, derive_tl
from v3.scoring.thresholds import (CONTEXT_ALIGNMENT_BONUS,
                                   SILENT_DIVERGENCE_BONUS)

# Derived from the clause registry rather than restated, so the disclosure
# cannot drift from what is actually implemented. Full clause IDs, not a
# compressed range: NP6 means a reader can grep "S1-SCORE-004" and find
# every conclusion it produced.
FORMULA_REF = "v3.scoring.kernel.score_tick@" + ",".join(
    sorted(IMPLEMENTED))


def _bonus_fold(scenario: Scenario, inputs: ScoringInputs,
                chain_events: tuple[SequenceEvent, ...]) -> BonusBreakdown:
    """S1-PIPE-026: the focused-only additions, itemised.

    Applied to the focused scenario only, faithfully to the effective
    path. S1-scoring-pipeline ACCIDENTAL A8 records that this makes
    focused and background scores incommensurable — a real problem, and an
    owner ruling, not something to silently repair while porting.
    """
    country = inputs.chain_country_for(scenario)

    chain = sequence.chain_bonus(
        chain_events, country, now=inputs.now,
        full_bonus=inputs.settings.sequence_full_bonus,
        partial_bonus=inputs.settings.sequence_partial_bonus,
        retention_sec=inputs.settings.sequence_window_sec)
    temporal = sequence.temporal_coherence_bonus(
        chain_events, now=inputs.now,
        retention_sec=inputs.settings.sequence_window_sec)

    series = inputs.score_series_for(scenario.scenario_id)
    rate = trend.velocity(series)
    accel = trend.acceleration(series)
    rate_bonus, accel_bonus = trend.velocity_bonus(rate, accel)

    flags = inputs.pattern_flags_for(scenario.scenario_id)
    return BonusBreakdown(
        sequence=chain.bonus,
        temporal_coherence=temporal,
        velocity=rate_bonus,
        acceleration=accel_bonus,
        silent_divergence=(SILENT_DIVERGENCE_BONUS
                           if flags.silent_divergence else 0.0),
        context_alignment=(CONTEXT_ALIGNMENT_BONUS
                           if flags.context_alignment else 0.0))


def score_scenario(scenario: Scenario, inputs: ScoringInputs,
                   chain_events: tuple[SequenceEvent, ...]) -> ScoringResult:
    """One scenario, start to finish, in the order S1-PIPE-020 fixes."""
    settings = inputs.settings
    mode = inputs.mode_for(scenario)

    # (1) contributions, (2) dedup, (3) per-domain totals under the cap
    built = contrib.build_contributions(inputs.observations, scenario,
                                        settings=settings)
    deduped = contrib.dedup_max(built)
    domains = contrib.domain_totals(deduped, domain_cap=settings.domain_cap)
    active_domains = contrib.active_domains(domains)
    active_countries = contrib.active_countries(deduped)

    # (4) convergence, from the domain count and the participant count
    bonus = convergence.convergence_bonus(
        len(active_domains), len(active_countries),
        scenario_specific=settings.convergence_scenario_specific)
    level = convergence.convergence_level(len(active_domains))

    # S1-SCORE-043: no admitted signal means score 0.0 and TL5, reached
    # here by ordinary arithmetic rather than a special case — a separate
    # branch for "nothing happened" is a branch that can disagree.
    base_score = sum(domains.values()) + bonus

    # (5) S1-PIPE-026: focused-only bonus fold, floored at 0 — and NOT
    #     capped. S1-PIPE-022's ceiling of 15 belongs to the engine
    #     family's `score_with_bonus` (radar/routes/core.py:2003), which
    #     feeds alert_history / daily_summary / What-If. The served
    #     scenario score has a floor and no upper clip
    #     (radar/routes/core.py:2201-2202), so applying the cap here would
    #     hold TL1 down on exactly the ticks that most warrant it.
    if mode == MODE_FULL:
        breakdown = _bonus_fold(scenario, inputs, chain_events)
    else:
        breakdown = BonusBreakdown()
    score = max(0.0, base_score + breakdown.total)

    # (6) S1-SCORE-004 / S1-SCORE-016: the same ladder for full and lite
    raw_level = derive_tl(score, active_domains, domains.get("physical", 0.0))

    # (7) S1-SCORE-005 / S1-PIPE-027: hysteresis, for background too
    outcome = apply_hysteresis(raw_level, inputs.prior.tl_for(
        scenario.scenario_id))

    provenance = Provenance(
        formula_ref=FORMULA_REF,
        computed_at=inputs.now,
        inputs={
            "scenario_id": scenario.scenario_id,
            "scoring_mode": mode,
            "base_score": base_score,
            "bonus_total": breakdown.total,
            "score": score,
            "cyber": domains.get("cyber", 0.0),
            "physical": domains.get("physical", 0.0),
            "info": domains.get("info", 0.0),
            "convergence": level,
            "convergence_bonus": bonus,
            "active_domain_count": len(active_domains),
            "active_participant_count": len(active_countries),
            "contribution_count": len(deduped),
            "raw_tl": raw_level.value,
            "tl": outcome.level.value,
            "severity": outcome.level.severity(),
            "hysteresis_held": outcome.held,
            # Itemised, not just totalled: "the bonus was 3" and "a chain
            # completed" are different disclosures, and only the second
            # one can be argued with (NP6).
            **{f"bonus_{name}": value
               for name, value in breakdown.as_dict().items()
               if name != "total"},
            **settings.disclosed(),
        },
        source_refs=tuple(sorted({c.signal_source for c in deduped})))

    return ScoringResult(
        scenario_id=scenario.scenario_id,
        scoring_mode=mode,
        threat_level=outcome.level,
        raw_threat_level=outcome.raw,
        hysteresis_held=outcome.held,
        score=score,
        base_score=base_score,
        domain_scores=domains,
        convergence=level,
        convergence_bonus=bonus,
        bonuses=breakdown,
        active_domains=active_domains,
        active_countries=active_countries,
        contributions=deduped,
        provenance=provenance)


def score_tick(inputs: ScoringInputs) -> TickResult:
    """Score every scorable scenario from one observation set.

    S1-PIPE-025: one snapshot, all scenarios. Re-collecting observations
    per scenario is how focused and background came to be scored against
    different moments in the legacy system.

    S1-SCORE-042: a disabled scenario is not scored, and is reported in
    `skipped` rather than silently vanishing — "not scored" and "scored
    NORMAL" must never look alike (NP5+8).
    """
    if not isinstance(inputs, ScoringInputs):
        raise TypeError(
            f"score_tick takes a ScoringInputs, got {type(inputs).__name__}")

    # S1-PIPE-013/014: only observations that cleared gating may justify a
    # chain link. The predicate is `passes_gate()` — FIRED and not
    # suppressed — and NOT `admits()`: the sequence gate has no score
    # condition (radar/routes/core.py:997, CLAUDE.md §5). A sensor may
    # fire with score 0 and still gate its chain link, which
    # cf_botnet_overlap does by design in the marginal IDF band.
    gated_sensors = frozenset(
        observation.sensor for observation in inputs.observations
        if observation.passes_gate())
    chain_events = sequence.advance(
        inputs.prior.sequence_events, inputs.arriving_events,
        now=inputs.now, retention_sec=inputs.settings.sequence_window_sec,
        admitted_sensors=gated_sensors)

    results = {}
    skipped = []
    for scenario in inputs.scenarios:
        if not scenario.is_scorable:
            skipped.append(scenario.scenario_id)
            continue
        results[scenario.scenario_id] = score_scenario(
            scenario, inputs, chain_events)

    return TickResult(
        now=inputs.now,
        results=results,
        global_threat=contrib.global_threat(
            inputs.observations,
            global_signal_weight=inputs.settings.global_signal_weight),
        next_sequence_events=chain_events,
        skipped=tuple(skipped))


__all__ = ["score_tick", "score_scenario", "FORMULA_REF"]
