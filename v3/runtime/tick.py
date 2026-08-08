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
from v3.runtime import baselines as baselines_module
from v3.runtime import expansion as expansion_module
from v3.runtime import health as health_module
from v3.runtime import reduce as reduce_module
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


def build_hooks(state: _CycleState, *, baselines: Mapping,
                credentials: Optional[CredentialPlan] = None) -> CycleHooks:
    """The four functions the kernel is lent for this cycle."""
    from v3.adapters.info.bg_observer_rss import classify_feed
    from v3.adapters.info.telegram_mirror import USER_AGENT_POOL

    def fold(adapter_id: str, drafts):
        reduced = reduce_module.reduce_drafts(adapter_id, drafts,
                                              baselines=baselines)
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
                "coverage": dict(self.coverage)}


def fetch_cycle(*, now: float, registry, store, client,
                geography: Geography, countries: Sequence[str],
                credentials: Optional[CredentialPlan] = None,
                tick_id: Optional[str] = None):
    """Steps 1-4: schedule, expand, plan, execute. Returns a CycleResult."""
    states = recorder.load_states(store)
    baselines = baselines_module.previous_cycle(store, now=now,
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
        hooks=build_hooks(state, baselines=baselines,
                          credentials=credentials))
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


def run_tick(*, now: float, registry, store, client, geography: Geography,
             scenario_ids: Sequence[str],
             credentials: Optional[CredentialPlan] = None,
             score=None) -> TickReport:
    """One whole tick. The composition root's single unit of work.

    `score` is injected rather than imported so a caller can run the
    acquisition half alone — which is what a shadow deployment does, and
    what the parity harness needs when it replays observations through a
    scoring build it is comparing.
    """
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
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
        result = score(scenario_id, cycle) if score is not None else None
        conclusions_by_scenario[scenario_id] = conclude(
            now=now, store=store, scenario_id=scenario_id, health=health,
            result=result,
            participants=participants_of(geography, scenario_id))

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
        coverage=expansion_module.coverage_report(geography, countries))


__all__ = ["run_tick", "fetch_cycle", "conclude", "build_hooks",
           "order_producers_first", "tick_id_for", "TickReport",
           "PRODUCER_ORDER"]
