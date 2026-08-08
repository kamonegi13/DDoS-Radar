"""Assembling one tick's scoring input — and resolving its settings first.

This module is the edge WP-4.1d left unbuilt. `ConfigResolver` landed, R14
served the layer, C7 wrote the override and `resolve_settings` could read
it — but no caller under `v3/runtime/` ever ran that resolution, so a
scored tick still terminated in legacy `radar.config_layered`. A value an
operator changes, the ledger records and the screen shows, which the
formula does not read, is defect G-15 one layer up. `settings_for` is the
one call that closes it, and `tests/test_runtime_scoring_wiring.py` proves
the closure by moving a number and reading the score that came out.

Four steps, in the order the caller must run them (S1-PIPE-020's split
between the impure caller and the pure kernel):

    settings_for(...)   resolve every variable key through v3's own chain
    prior_state(...)    read the previous tick's levels out of L1
    assemble(...)       one `ScoringInputs`, from ledger rows
    score(inputs)       the pure kernel, which reads nothing

The split is why `assemble` exists as a public function rather than as
lines inside `run_tick`. WP-4.1c deferred C6 (counterfactual) naming
exactly this: "a dry-run needs a whole ScoringInput assembled outside the
scoring tick, and that path exists only inside v3/runtime/tick.py". It now
exists here, takes its settings as an argument, and writes nothing — so a
counterfactual is `assemble(..., settings=<other>)` followed by `score`.

**The observations come through `LedgerInputAdapter`, not a second
reader.** S5-VERIF-031 requires one adapter, never two readers that agree
today; the parity harness measures what production scores only if the
in-force projection is literally the same code. That module's home is
`v3/parity/` because parity is where it was first needed, and moving it
would be a rename with no behaviour attached to it.
"""
from __future__ import annotations

from typing import Optional, Sequence

from v3.kernel.errors import DomainError
from v3.ledger.records import TLObservation
from v3.parity.adapter import LedgerInputAdapter, to_v3_observations
from v3.runtime import chain
from v3.runtime.geo import Geography
from v3.scoring import (Participant, PriorState, Scenario, ScoringInputs,
                        ScoringSettings, TickResult, score_tick)
from v3.scoring.settings import resolve_settings

#: The cadence `LedgerInputAdapter` is told about. It bounds nothing here —
#: one instant is requested, so no second tick timestamp is generated — but
#: the adapter refuses a non-positive interval and F-06's lesson is that a
#: window and a sample count stay distinguishable only when the cadence is
#: stated at the call site.
DEFAULT_TICK_INTERVAL_SEC = 60.0


def settings_for(ledger, *, config, at: Optional[float] = None
                 ) -> ScoringSettings:
    """Every variable key, resolved through v3's three layers. NOT PURE.

    `config` is the composition root's `ConfigResolver`; `ledger` is the
    command ledger the override layer folds. `at` bounds that fold, so
    replaying an old tick resolves the override that was in force THEN
    rather than the one in force now — the same projection live and in
    replay (P7 derivation principle 4).

    Left to `Threshold.resolve` (i.e. called without this function) the
    registry-backed branch still ends in legacy `radar.config_layered`.
    That is the fallback this module exists to stop being the live path.
    """
    if config is None:
        raise DomainError(
            "settings_for needs the composition root's ConfigResolver: "
            "without it resolution falls through to legacy "
            "radar.config_layered and a C7 override reaches the ledger, the "
            "audit row and the screen but not the formula (G-15)")
    # `config`, not `resolver`: the kernel's own `resolver=` seam is
    # licensed to v3/config/resolution.py alone, and two differently-scoped
    # things sharing a name is how a licence gets inherited by accident
    # (the reason `resolve_settings` named its parameter `resolve_threshold`).
    return resolve_settings(
        config.settings_resolver(ledger=ledger, at=at))


def scenarios_for(geography: Geography, scenario_ids: Sequence[str]
                  ) -> tuple[Scenario, ...]:
    """The kernel's view of the declared scenarios.

    `core_country` is READ from the geography, exactly as production reads
    it (`radar/scenarios.py::derive_country_context`, `core = focused.
    core_country`). That is a declaration, not a derivation — the thing
    the ruling forbids deriving is the dual-core scenario's OWNER, which
    `core_country: null` deliberately leaves unstated and which
    `v3/runtime/chain.py` measures per tick from that tick's observations.
    """
    built = []
    for scenario_id in scenario_ids:
        declared = geography.scenarios.get(scenario_id)
        if declared is None:
            raise DomainError(
                f"unknown scenario {scenario_id!r}; declared scenarios are "
                f"{sorted(geography.scenarios)}")
        participants = declared.get("participants", {}) or {}
        core = declared.get("core_country")
        built.append(Scenario(
            scenario_id=scenario_id,
            participants=tuple(
                Participant(country=str(code).upper(),
                            weight=float(row.get("weight", 0.0)),
                            role=str(row.get("role", "")))
                for code, row in sorted(
                    participants.items(),
                    key=lambda item: (-float(item[1].get("weight", 0.0)),
                                      item[0]))),
            enabled=bool(declared.get("enabled", True)),
            core_country=str(core).upper() if core else None))
    return tuple(built)


def observations_at(store, *, now: float,
                    tick_interval_sec: float = DEFAULT_TICK_INTERVAL_SEC):
    """Every row in force at `now`, as kernel observations.

    Latest-row-at-T with each row's own freshness horizon applied, which is
    B-03's repair: without the horizon a sensor that died on day 3 keeps
    contributing for the rest of the window.
    """
    from v3.intel import adjudication as intel

    adapter = LedgerInputAdapter(store, tick_interval_sec=tick_interval_sec)
    # THE reader for P7 C3's adjudication. Applied here because this is the
    # one place the ledger becomes kernel input, so "unadjudicated intel
    # does not score" is a single edge rather than a rule every caller
    # keeps. Rows are not deleted — L1 is append-only and R11 still shows
    # every item with its state, which is what "an analyst has not looked
    # at this yet" has to look like from the queue.
    for tick_input in adapter.ticks(now, now):
        return to_v3_observations(
            intel.scoreable_rows(store, tick_input.rows, until=now))
    return ()


def prior_state(store, *, now: float, scenario_ids: Sequence[str],
                sequence_events: tuple = ()) -> PriorState:
    """The previous tick's levels, read from L1 rather than from memory.

    Hysteresis is path-dependent (S1-SCORE-005), so a restart that forgot
    the previous level would release every held level at once — a step
    change in the published TL caused by a deployment, which reads exactly
    like a de-escalation.

    Rows at or after `now` are excluded, and that is not defensive: this
    tick writes its own TL row AT `now`, so a re-run of the same instant
    would otherwise read its own output as its own input, produce a
    different result and make `append_tl` refuse the idempotent replay.
    """
    levels = {}
    for scenario_id in scenario_ids:
        row = store.latest_tl_at(now, scenario_id=scenario_id)
        if row is None or float(row["observed_at"]) >= now:
            continue
        levels[scenario_id] = row["threat_level"]
    return PriorState(previous_tl=levels, sequence_events=sequence_events)


def assemble(*, now: float, store, geography: Optional[Geography] = None,
             scenario_ids: Sequence[str] = (),
             settings: ScoringSettings,
             focused_scenario_id: Optional[str] = None,
             prior: Optional[PriorState] = None,
             tick_interval_sec: float = DEFAULT_TICK_INTERVAL_SEC,
             scenarios: Optional[Sequence[Scenario]] = None
             ) -> ScoringInputs:
    """One tick's complete scoring input. Reads L1; writes nothing.

    The seam C6 is built on. Everything impure happens here, so `score`
    below is a pure function of the value this returns and a counterfactual
    is this call with different `settings` or different `scenarios`.

    `scenarios` is the counterfactual door and it is deliberately the ONLY
    one. C6 varies coupling weights, and the alternative — letting the
    caller pass a mutated `Geography` — would make the deployment's own
    scenario definitions a thing a request could rewrite. Supplied here,
    the substitution is confined to one call and `geography` is not
    consulted at all, so a what-if cannot leak into the tick's view of the
    world.

    **The sequence chain's owner is chosen HERE, from these observations.**
    It is not a parameter, and that is the point: production picks the
    owner by live spike, so anything a caller could pass — an operator's
    environment variable most of all — would be a constant standing in
    for a measurement. `v3/runtime/chain.py` transcribes production's
    rule; this is the layer that holds the data it needs.
    """
    if not isinstance(settings, ScoringSettings):
        raise DomainError(
            f"assemble needs resolved settings, got "
            f"{type(settings).__name__}. Resolution is the caller's step "
            f"(settings_for); assembling one here would put a configuration "
            f"read inside the path that must be replayable.")
    if scenarios is None:
        if geography is None:
            raise DomainError(
                "assemble needs either a Geography (the tick's path) or an "
                "explicit `scenarios` tuple (C6's counterfactual path); with "
                "neither there is nothing to score and an empty result would "
                "read as a quiet world")
        scenarios = scenarios_for(geography, scenario_ids)
    else:
        scenarios = tuple(scenarios)
        if not all(isinstance(item, Scenario) for item in scenarios):
            raise DomainError(
                "assemble's `scenarios` are kernel Scenario values; a dict "
                "here would skip the weight and country validation the "
                "kernel does at construction")
    if focused_scenario_id is not None and \
            focused_scenario_id not in {s.scenario_id for s in scenarios}:
        raise DomainError(
            f"focused scenario {focused_scenario_id!r} is not among the "
            f"scenarios being scored {sorted(s.scenario_id for s in scenarios)}"
            f": a focus nothing scores is a focus that silently means lite")
    observations = observations_at(store, now=now,
                                   tick_interval_sec=tick_interval_sec)
    return ScoringInputs(
        now=now,
        observations=observations,
        scenarios=scenarios,
        settings=settings,
        focused_scenario_id=focused_scenario_id,
        prior=prior if prior is not None else prior_state(
            store, now=now, scenario_ids=[s.scenario_id for s in scenarios]),
        chain_countries=chain.chain_owners(scenarios, observations))


def score(inputs: ScoringInputs) -> TickResult:
    """The pure kernel. Named here so a caller needs one import, not two."""
    return score_tick(inputs)


def persist_tl(store, result: TickResult, *, tick_id: str) -> int:
    """Write this tick's levels to L1's TL stream.

    Every tick, including repeats and the null zone — unlike the
    conclusion ledger, which is written on state change only (DP6). R3's
    series, the trend window and the null-zone measure all read THIS
    table, so thinning it would change the measurements that decide
    whether the tool is concluding at all.
    """
    written = 0
    for scenario_id, scored in result.results.items():
        if store.append_tl(TLObservation(
                tick_id=tick_id, scenario_id=scenario_id,
                observed_at=result.now,
                threat_level=scored.threat_level,
                score=scored.score,
                cyber=scored.domain_scores.get("cyber", 0.0),
                physical=scored.domain_scores.get("physical", 0.0),
                info=scored.domain_scores.get("info", 0.0),
                convergence_bonus=scored.convergence_bonus,
                scoring_mode=scored.scoring_mode,
                active_countries=scored.active_countries)):
            written += 1
    return written


__all__ = ["settings_for", "scenarios_for", "observations_at", "prior_state",
           "assemble", "score", "persist_tl", "DEFAULT_TICK_INTERVAL_SEC"]
