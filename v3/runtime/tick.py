"""One tick: fetch -> observations -> score -> conclusions -> ledger.

The eleven processing steps of P4, sequenced. Everything below is
assembled from parts that already existed and were deliberately left
unconnected, because connecting them requires a clock, a credential store
and a database handle, and no other package under `v3/` is allowed all
three.

Order, and why each step is where it is:

  1. read the persisted schedule (`fetch_schedule`) — F-01's repair. No
     process counter decides due-ness, so a restart cannot skip a job
     forever the way the hourly maintenance worker did.
  2. read the previous cycle's scalars BEFORE writing this one, or every
     "compared with last tick" verdict compares a value with itself.
  3. plan (`run_due`, pure) and reorder so suppression PRODUCERS run
     first: `space_weather` cannot mute RIPE Atlas in a cycle where it
     has not been fetched yet.
  4. execute, with the composition root's four hooks — reduction,
     feed-death classification, UA rotation, credential annotation.
  5. score, conclude, persist.

Idempotence (S5-VERIF-019) is the ledger's, not a flag kept here: a
re-run with the same `tick_id` and the same content is a no-op, and with
different content it raises. `run_tick` therefore derives `tick_id` from
the tick instant rather than from a counter, so replaying a recorded
cycle lands on the same key.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

from v3.conclusions.availability import InputHealth
from v3.conclusions.context import ScenarioContext
from v3.conclusions.derive import derive_all
from v3.conclusions.persistence import persist
from v3.fetch import recorder
from v3.fetch.runner import CycleHooks, FetchPlan, execute_plan, run_due
from v3.kernel.errors import DomainError
from v3.runtime import attention as attention_module
from v3.runtime import baselines as baselines_module
from v3.runtime import expansion as expansion_module
from v3.runtime import health as health_module
from v3.runtime import record as record_module
from v3.runtime import reduce as reduce_module
from v3.runtime import scoring as scoring_module
from v3.runtime import suppression as suppression_module
from v3.runtime.geo import Geography, adversaries_of, participants_of
from v3.runtime.secrets import CredentialPlan

#: Producers of cross-adapter suppression, fetched before their targets.
PRODUCER_ORDER: tuple[str, ...] = (suppression_module.SPACE_WEATHER,
                                   suppression_module.OPENWEATHER)


def tick_id_for(now: float) -> str:
    """Derived from the instant, so a replay lands on the same ledger key."""
    return f"t{int(now)}"


def order_producers_first(plan: FetchPlan) -> FetchPlan:
    """Reorder a plan so suppressors run before what they suppress.

    A reordering, never a filter: every planned adapter still runs, and
    the plan's `skipped` list is untouched. Concurrency and ordering are
    explicitly the composition root's to decide (§1-2); what it may not do
    is decide that something is not fetched.
    """
    rank = {name: index for index, name in enumerate(PRODUCER_ORDER)}
    ordered = sorted(plan.planned,
                     key=lambda item: rank.get(item.adapter_id.value,
                                               len(rank)))
    if len(ordered) != len(plan.planned):   # pragma: no cover - defensive
        raise DomainError("reordering changed the plan's size")
    return FetchPlan(now=plan.now, planned=tuple(ordered),
                     skipped=plan.skipped,
                     breaker_states=plan.breaker_states)


@dataclass
class _CycleState:
    """The suppressors accumulated as the cycle runs.

    Mutable, and the only mutable thing in the pipeline. It exists because
    suppression is a join across adapters and the adapters are executed in
    sequence; the ordering above is what makes reading it safe.
    """

    suppressors: suppression_module.Suppressors = field(
        default_factory=suppression_module.Suppressors)
    produced: dict = field(default_factory=dict)


def build_hooks(state: _CycleState, *, baselines: Mapping, now: float,
                credentials: Optional[CredentialPlan] = None) -> CycleHooks:
    """The four functions the kernel is lent for this cycle."""
    from v3.adapters.info.bg_observer_rss import classify_feed
    from v3.adapters.info.telegram_mirror import USER_AGENT_POOL

    def fold(adapter_id: str, drafts):
        reduced = reduce_module.reduce_drafts(adapter_id, drafts,
                                              baselines=baselines, now=now)
        if adapter_id in PRODUCER_ORDER:
            state.produced[adapter_id] = reduced
            state.suppressors = suppression_module.read_suppressors(
                state.produced)
        return suppression_module.apply(adapter_id, reduced,
                                        suppressors=state.suppressors)

    def rotate(index: int) -> Mapping[str, str]:
        # Deterministic where production uses `random.choice`
        # (`telegram.py:97`). Rotation is what defeats a per-UA throttle;
        # randomness additionally makes the request stream unreplayable,
        # and NP6 asks that a recorded cycle reproduce.
        return {"User-Agent": USER_AGENT_POOL[index % len(USER_AGENT_POOL)]}

    notes = {}
    if credentials is not None:
        for posture in credentials.anonymous:
            notes[posture.adapter_id] = f"anonymous: no {posture.key_id}"
    return CycleHooks(
        reduce=fold,
        classify_outcome={"bg_observer_rss": classify_feed},
        request_headers={"telegram_mirror": rotate},
        credential_notes=notes)


@dataclass(frozen=True, slots=True)
class TickReport:
    """What one tick did, as a value the caller can log or serve."""

    tick_id: str
    now: float
    scenario_ids: tuple[str, ...]
    planned: tuple[str, ...]
    skipped: tuple[tuple, ...]
    observations_written: int
    health: Mapping[str, dict]
    conclusions: Mapping[str, dict]
    credentials: Mapping
    suppressors: Mapping
    coverage: Mapping
    #: scenario_id -> `ScoringResult.as_dict()`. Empty when the tick ran
    #: acquisition-only, which is a different fact from "scored, nothing
    #: found" and must not look like it (NP5+8).
    scoring: Mapping[str, dict] = field(default_factory=dict)
    #: The resolved settings this tick computed with, and the layer each
    #: value came from. Disclosed on the report because a published score
    #: whose thresholds are not stated is not reproducible (NP6).
    settings: Mapping[str, object] = field(default_factory=dict)
    #: Step S8's result: the attention ranking, and whether it moved.
    #: On the report because `attention_update` is published from it —
    #: a websocket event whose payload is not also in the tick's own
    #: record is an event nobody can check afterwards (AP4).
    attention: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"tick_id": self.tick_id, "now": self.now,
                "scenarios": list(self.scenario_ids),
                "planned": list(self.planned),
                "skipped": [list(row) for row in self.skipped],
                "observations_written": self.observations_written,
                "health": dict(self.health),
                "conclusions": dict(self.conclusions),
                "credentials": dict(self.credentials),
                "suppressors": dict(self.suppressors),
                "coverage": dict(self.coverage),
                "scoring": dict(self.scoring),
                "settings": dict(self.settings),
                "attention": dict(self.attention)}


def fetch_cycle(*, now: float, registry, store, client,
                geography: Geography, countries: Sequence[str],
                credentials: Optional[CredentialPlan] = None,
                tick_id: Optional[str] = None):
    """Steps 1-4: schedule, expand, plan, execute. Returns a CycleResult."""
    states = recorder.load_states(store)
    baselines = baselines_module.for_cycle(store, now=now,
                                           countries=countries)
    expansions = expansion_module.for_cycle(
        geography, countries, now=now,
        carried=baselines_module.carried_values(store, now=now))
    plan = order_producers_first(
        run_due(now, registry.enabled(), states, None, expansions))
    state = _CycleState()
    cycle = execute_plan(
        plan, registry, client=client, store=store,
        tick_id=tick_id or tick_id_for(now), countries=countries,
        context_for=lambda adapter: expansion_module.context_for(
            adapter, geography, countries, now=now),
        hooks=build_hooks(state, baselines=baselines, now=now,
                          credentials=credentials))
    # Step 4b: advance the baselines, from what was just written. A stage
    # of its own (F-05) and strictly AFTER the read at the top, so no
    # reading is ever compared against itself.
    record_module.record_cycle(store, now=now, countries=countries)
    return cycle, state


def conclude(*, now: float, store, scenario_id: str, health: InputHealth,
             result=None, participants: Sequence[str] = ()) -> dict:
    """Steps 5-7 for one scenario: context -> five conclusions -> ledger.

    Every type is derived and persisted, including the ones that come back
    unavailable: S1-CONC-010 says a row that cannot be derived is not a
    row that may be dropped, because the chronic-null-zone view reads the
    gaps and a missing row is invisible to it.
    """
    context = ScenarioContext(scenario_id=scenario_id, now=now,
                              health=health, result=result,
                              participants=tuple(participants))
    conclusions = derive_all(context, store=store)
    return persist(store, conclusions)


def score_cycle(*, now: float, store, geography: Geography,
                scenario_ids: Sequence[str], config, tick_id: str,
                focused_scenario_id: Optional[str] = None,
                chain_countries: Optional[Mapping[str, str]] = None):
    """Steps 5a-5c: resolve, assemble, score, write the TL stream.

    The three impure steps and the one pure one, in the order S1-PIPE-020
    fixes. Resolution is bounded at `now` so a replayed tick computes with
    the override that was in force then.

    Returns `(TickResult, ScoringSettings)`. The settings come back because
    the report discloses them: a score whose thresholds are not published
    with it cannot be argued with (NP6).
    """
    settings = scoring_module.settings_for(store, config=config, at=now)
    result = scoring_module.score(scoring_module.assemble(
        now=now, store=store, geography=geography,
        scenario_ids=scenario_ids, settings=settings,
        focused_scenario_id=focused_scenario_id,
        chain_countries=chain_countries))
    scoring_module.persist_tl(store, result, tick_id=tick_id)
    return result, settings


def run_tick(*, now: float, registry, store, client, geography: Geography,
             scenario_ids: Sequence[str],
             credentials: Optional[CredentialPlan] = None,
             config=None, focused_scenario_id: Optional[str] = None,
             chain_countries: Optional[Mapping[str, str]] = None,
             score=None) -> TickReport:
    """One whole tick. The composition root's single unit of work.

    `config` is the composition root's `ConfigResolver`. Supplying it is
    what makes the tick SCORE: the settings are resolved through v3's own
    three layers (`v3/runtime/scoring.py::settings_for`) and handed to the
    kernel, so a C7 override reaches the formula rather than stopping at
    the settings screen. Omitting it runs the acquisition half alone —
    which is what a shadow deployment does, and what the parity harness
    needs when it replays observations through a scoring build it is
    comparing.

    `score` is the other way in, and it exists for a caller that has its
    own scoring build (the parity harness comparing two of them). It takes
    `(now, cycle)` and returns `{scenario_id: ScoringResult}` — the WHOLE
    tick, not one scenario, because S1-PIPE-025 requires every scenario to
    be scored from one observation set and a per-scenario callable invites
    the re-collection that made focused and background incommensurable.

    The two are mutually exclusive, and the refusal is deliberate: two
    scoring paths in one tick is the state where "which number did the
    ledger get" has no answer.
    """
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
    if config is not None and score is not None:
        raise DomainError(
            "a tick has one scoring path: supply `config` (v3's own "
            "resolution chain) or `score` (a caller's own build), never "
            "both. Two paths is the state where nobody can say which "
            "settings produced the row that was written.")
    scenarios = tuple(scenario_ids)
    if not scenarios:
        raise DomainError(
            "a tick with no scenarios would fetch, write observations and "
            "conclude nothing, which reads downstream as a quiet world")
    countries = tuple(dict.fromkeys(
        country for scenario_id in scenarios
        for country in participants_of(geography, scenario_id)))

    identity = tick_id_for(now)
    cycle, state = fetch_cycle(
        now=now, registry=registry, store=store, client=client,
        geography=geography, countries=countries, credentials=credentials,
        tick_id=identity)

    # Step 5: score. AFTER the observations are written, because the
    # scoring input is the ledger's in-force projection at `now` — the
    # same reader the parity harness uses, so what parity measures is
    # what production scored (S5-VERIF-031).
    settings_disclosure: Mapping[str, object] = {}
    if config is not None:
        result, settings = score_cycle(
            now=now, store=store, geography=geography,
            scenario_ids=scenarios, config=config, tick_id=identity,
            focused_scenario_id=focused_scenario_id,
            chain_countries=chain_countries)
        results_by_scenario = dict(result.results)
        settings_disclosure = settings.disclosed()
    else:
        results_by_scenario = dict(score(now, cycle) or {}) \
            if score is not None else {}

    outcomes = health_module.outcomes_for_cycle(cycle,
                                                credentials=credentials)
    stale = health_module.stale_sources(store, now=now,
                                        adapters=registry.enabled(),
                                        countries=countries)
    health_by_scenario, conclusions_by_scenario = {}, {}
    for scenario_id in scenarios:
        health = health_module.build(
            outcomes, stale=stale,
            history_span=health_module.history_span_sec(store, scenario_id,
                                                        now=now))
        health_by_scenario[scenario_id] = health.as_dict()
        conclusions_by_scenario[scenario_id] = conclude(
            now=now, store=store, scenario_id=scenario_id, health=health,
            result=results_by_scenario.get(scenario_id),
            participants=participants_of(geography, scenario_id))

    # Step S8: rank what was just concluded. AFTER the conclusions are
    # written, because the ranker's novelty and confidence_delta read the
    # conclusion stream — ranking first would order this tick's findings
    # by last tick's numbers.
    ranking = attention_module.rank_cycle(
        now=now, store=store, scenario_ids=scenarios)

    return TickReport(
        tick_id=identity, now=now, scenario_ids=scenarios,
        planned=cycle.plan.planned_ids,
        skipped=tuple((s.adapter_id.value, s.reason)
                      for s in cycle.plan.skipped),
        observations_written=cycle.observations_written,
        health=health_by_scenario,
        conclusions=conclusions_by_scenario,
        credentials=credentials.as_dict() if credentials else {},
        suppressors=state.suppressors.as_dict(),
        coverage=expansion_module.coverage_report(geography, countries),
        scoring={scenario_id: scored.as_dict()
                 for scenario_id, scored in results_by_scenario.items()},
        settings=settings_disclosure,
        attention=ranking.as_dict())


__all__ = ["run_tick", "fetch_cycle", "score_cycle", "conclude",
           "build_hooks", "order_producers_first", "tick_id_for",
           "TickReport", "PRODUCER_ORDER"]
