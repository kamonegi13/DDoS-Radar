"""One parity run, end to end.

Drives both systems from the same window of the same ledger, compares in
severity space, records every verdict to the isolated parity ledger, and
judges P2 §5's fourteen conditions.

The v3 side is driven with NO focused scenario. That is deliberate and it
is the harness's main scope limitation: the legacy focused-only bonus fold
lives inside the GET handler (`radar/routes/core.py:2156-2213`) and cannot
be called without the HTTP layer, so running v3 with the fold while legacy
runs without it would compare two different computations and attribute the
difference to the rewrite. Both sides therefore compute the scoring core
only. `SCOPE_NOTES` says so in the report, because a limitation that is
not in the output is a limitation nobody accounts for.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from v3.kernel import Provenance
from v3.kernel.errors import DomainError
from v3.parity import driver_v2, driver_v3
from v3.parity.adapter import LedgerInputAdapter
from v3.parity.compare import (compare_tick, compare_transitions,
                               extract_transitions)
from v3.parity.conditions import MIN_SEVERITY_AGREEMENT
from v3.parity.ledger import MismatchEvidence, ParityLedger, RunIdentity
from v3.parity.report import ParityContext, ParityReport, build_report
from v3.parity.summary import summarise
from v3.ledger import LedgerStore
from v3.scoring import Scenario, ScoringSettings

SCOPE_NOTES: tuple[str, ...] = (
    "Comparison covers the scoring CORE only: contributions, dedup, "
    "per-domain totals under the cap, convergence bonus, derive_tl and "
    "hysteresis. The focused-only bonus fold (S1-PIPE-026) is excluded "
    "because on the legacy side it lives inside the GET handler "
    "(radar/routes/core.py:2156-2213) and is not callable without the HTTP "
    "layer; reproducing it in the harness is forbidden by S5-VERIF-031. It "
    "becomes comparable once D2 A-01's decomposition extracts that block.",
    "Conclusion-level parity (per_domain / attack_mode / trend / anomaly) "
    "is not exercised: v3 L3 does not exist yet (WP-3.1). The comparison "
    "engine implements S5-VERIF-027's rules for all five types, but only "
    "threat_level has both sides to compare.",
    "No LLM is invoked anywhere in this harness. LLM-derived signals are "
    "already recorded observations in the L1 ledger and both sides consume "
    "the same rows, so S5-VERIF-022's determinism requirement is met "
    "structurally at this level. Replay of recorded LLM RESPONSES by "
    "prompt_sha256 is an L3 concern and is reported BLOCKED.",
)


@dataclass(frozen=True, slots=True)
class ParityRun:
    """The completed run: report, ledger id, and both sides' raw output."""

    report: ParityReport
    parity_run_id: str
    v3_result: driver_v3.ReplayResult
    legacy_result: driver_v2.LegacyReplayResult

    @property
    def sandbox(self):
        return self.legacy_result.sandbox


#: v3 ScoringSettings field -> the radar.config name the legacy scoring
#: path reads for the same quantity.
_CONFIG_MIRROR: Mapping[str, str] = {
    "global_signals_decoupled": "GLOBAL_SIGNALS_DECOUPLED",
    "llm_primary_country_only": "LLM_INTEL_PRIMARY_COUNTRY_ONLY",
    "convergence_scenario_specific": "CONVERGENCE_SCENARIO_SPECIFIC",
}


def _legacy_config_overrides(settings: ScoringSettings) -> dict:
    """The shared settings, in the names radar.config uses."""
    overrides = {legacy_name: getattr(settings, field)
                 for field, legacy_name in _CONFIG_MIRROR.items()}
    overrides["LLM_INTEL_PRIMARY_THRESHOLD"] = \
        settings.llm_primary_threshold.value
    return overrides


def _contributors(reading) -> tuple:
    if reading is None:
        return ()
    return tuple(sorted(c.as_tuple() for c in reading.contributing))


def _evidence(key, v3_result, legacy_result) -> MismatchEvidence:
    """S5-VERIF-030's per-disagreement disclosure, for ONE key.

    Built per comparison, from the two sides' own readings. A single
    shared object would name the formulas and then leave every
    contribution list empty — which is a rate with no route to the cause,
    the exact output the clause forbids.
    """
    legacy = legacy_result.readings.get(key)
    v3 = v3_result.readings.get(key)
    return MismatchEvidence(
        legacy_contributions=_contributors(legacy),
        v3_contributions=_contributors(v3),
        legacy_formula_ref=legacy_result.formula_ref,
        v3_formula_ref=v3_result.formula_ref,
        effective_thresholds={**dict(legacy_result.thresholds),
                              **dict(v3_result.thresholds)},
        config_keys=tuple(sorted(v3_result.thresholds)),
        source_urls=tuple(sorted(
            {url for reading in (legacy, v3) if reading is not None
             for url in getattr(reading, "source_urls", ())})))


def run_parity(*, store: LedgerStore, parity_ledger: ParityLedger,
               scenarios: Sequence[Scenario],
               start: float, end: float, tick_interval_sec: float,
               settings: Optional[ScoringSettings] = None,
               legacy_code_version: str = "unknown",
               v3_code_version: str = "unknown",
               migration_report: Optional[Mapping] = None,
               now: Optional[float] = None,
               timeout_sec: int = driver_v2.DEFAULT_TIMEOUT_SEC) -> ParityRun:
    """Drive both systems over one window and judge the result."""
    if not isinstance(parity_ledger, ParityLedger):
        raise DomainError(
            f"parity results go to a ParityLedger, got "
            f"{type(parity_ledger).__name__}: S5-VERIF-021 requires an "
            f"isolated comparison store")
    effective = settings or ScoringSettings()
    sampled_at = time.time() if now is None else now
    adapter = LedgerInputAdapter(store, tick_interval_sec=tick_interval_sec)

    # ── both sides, from the same adapter over the same window ──────────
    v3_result = driver_v3.replay(
        store, scenarios, start=start, end=end,
        tick_interval_sec=tick_interval_sec, settings=effective,
        focused_scenario_id=None)
    legacy_result = driver_v2.replay(
        store, scenarios, start=start, end=end,
        tick_interval_sec=tick_interval_sec,
        domain_cap=effective.domain_cap,
        global_signal_weight=effective.global_signal_weight.value,
        # S5-VERIF-031's spirit: ONE set of settings drives both sides.
        # The legacy path reads these off radar.config at call time, so
        # they must be mirrored or a settings difference would be read as
        # an implementation difference.
        config_overrides=_legacy_config_overrides(effective),
        timeout_sec=timeout_sec)

    # ── compare every key either side produced (S5-VERIF-023) ───────────
    keys = sorted(set(v3_result.readings) | set(legacy_result.readings),
                  key=lambda k: (k.scenario_id, k.conclusion_type, k.tick_ts))
    comparisons = [
        compare_tick(key, legacy_result.readings.get(key),
                     v3_result.readings.get(key))
        for key in keys]

    # ── per-scenario summaries; NOTHING is judged on the pool ───────────
    scenario_summaries = {}
    for scenario in scenarios:
        scenario_id = scenario.scenario_id
        subset = [c for c in comparisons if c.key.scenario_id == scenario_id]
        timing = compare_transitions(
            extract_transitions(legacy_result.series_for(scenario_id)),
            extract_transitions(v3_result.series_for(scenario_id)))
        scenario_summaries[scenario_id] = summarise(subset,
                                                    transitions=timing)

    # The pooled summary is the report headline only (see ParityContext).
    pooled_timing = compare_transitions(
        [t for scenario in scenarios for t in extract_transitions(
            legacy_result.series_for(scenario.scenario_id))],
        [t for scenario in scenarios for t in extract_transitions(
            v3_result.series_for(scenario.scenario_id))])
    summary = summarise(comparisons, transitions=pooled_timing)

    # ── record every verdict, append-only, in ONE transaction ───────────
    identity = RunIdentity(
        window_start=start, window_end=end,
        tick_interval_sec=tick_interval_sec,
        input_snapshot_id=adapter.snapshot_id(start, end),
        legacy_code_version=legacy_code_version,
        v3_code_version=v3_code_version)
    disclosure = Provenance(
        formula_ref=f"legacy={legacy_result.formula_ref}; "
                    f"v3={v3_result.formula_ref}",
        computed_at=sampled_at,
        inputs={"tick_interval_sec": tick_interval_sec,
                "scenarios": len(scenarios),
                "ticks": len(adapter.tick_timestamps(start, end)),
                "min_agreement_required": MIN_SEVERITY_AGREEMENT})
    run_id = parity_ledger.open_run(identity, started_at=sampled_at,
                                    provenance=disclosure)
    parity_ledger.record_comparisons(
        run_id,
        ((comparison, _evidence(comparison.key, v3_result, legacy_result))
         for comparison in comparisons),
        sampled_at=sampled_at)

    # ── null zone, PER SCENARIO (C-09 pairs within a scenario) ──────────
    null_zone = {
        scenario.scenario_id: {
            "legacy_longest_sec": driver_v3.null_zone_seconds(
                legacy_result.series_for(scenario.scenario_id),
                tick_interval_sec=tick_interval_sec),
            "v3_longest_sec": driver_v3.null_zone_seconds(
                v3_result.series_for(scenario.scenario_id),
                tick_interval_sec=tick_interval_sec),
        }
        for scenario in scenarios}

    context = ParityContext(
        tick_interval_sec=tick_interval_sec,
        threat_level_summary=summary,
        scenario_summaries=scenario_summaries,
        null_zone=null_zone,
        migration=migration_report,
        window_start=start, window_end=end, parity_run_id=run_id)
    return ParityRun(
        report=build_report(context, notes=SCOPE_NOTES),
        parity_run_id=run_id,
        v3_result=v3_result,
        legacy_result=legacy_result)


__all__ = ["run_parity", "ParityRun", "SCOPE_NOTES"]
