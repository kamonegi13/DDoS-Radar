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
from v3.fetch import policy as fetch_policy
from v3.fetch import recorder
from v3.fetch.runner import (CycleHooks, FetchPlan, apply_budget, execute_plan,
                             run_due)
from v3.kernel.errors import DomainError
from v3.runtime import attention as attention_module
from v3.runtime import attribution as attribution_module
from v3.runtime import baselines as baselines_module
from v3.runtime import chain as chain_module
from v3.runtime import expansion as expansion_module
from v3.runtime import health as health_module
from v3.runtime import llm_stage as llm_stage_module
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
    #: adapter_id -> the RAW drafts that arrived carrying an article still
    #: waiting for a model. Captured here because the fold that follows
    #: flattens per-article provenance into a row-level feed list
    #: (`v3/runtime/reduce_common.py:180-186`), and `source_id` on the
    #: intel envelope is exactly that provenance (S1-INGEST-019). See
    #: `v3/runtime/llm_stage.py::collect` for why this point and not L1.
    awaiting_llm: dict = field(default_factory=dict)


def build_hooks(state: _CycleState, *, baselines: Mapping, now: float,
                credentials: Optional[CredentialPlan] = None) -> CycleHooks:
    """The four functions the kernel is lent for this cycle."""
    from v3.adapters.info.bg_observer_rss import classify_feed
    from v3.adapters.info.telegram_mirror import USER_AGENT_POOL

    def fold(adapter_id: str, drafts):
        # BEFORE the fold, and only what says it is waiting. The hook runs
        # inside the transaction that writes (`runner.py:619-626`), so
        # what is captured here is what L1 receives — which is the
        # property that makes the LLM stage's input honest rather than a
        # guess about what was written.
        pending = tuple(
            draft for draft in drafts
            if str((draft.flags or {}).get("awaiting") or "").startswith(
                llm_stage_module.AWAITING))
        if pending:
            state.awaiting_llm[adapter_id] = \
                state.awaiting_llm.get(adapter_id, ()) + pending
        reduced = reduce_module.reduce_drafts(adapter_id, drafts,
                                              baselines=baselines, now=now)
        if adapter_id in PRODUCER_ORDER:
            state.produced[adapter_id] = reduced
            state.suppressors = suppression_module.read_suppressors(
                state.produced)
        # §7-2 #127. AFTER suppression, never before: `apply` decides per
        # country (`_fires` reads `severe_weather.get(draft.country)`) and
        # GDELT's weather-noise join is exactly that shape, so a row that
        # went countryless first would look up `""` and stop being
        # suppressed without a word. Collapsing here copies the primary
        # core's already-decided suppression, which is production's own
        # order (`radar/sensors/gdelt.py:58` decides, `core.py:1132`
        # files).
        return attribution_module.collapse(
            adapter_id,
            suppression_module.apply(adapter_id, reduced,
                                     suppressors=state.suppressors),
            cores=baselines.get(baselines_module.EFFECTIVE_CORES) or ())

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
    #: adapter -> the requests it did NOT send because a stored answer is
    #: still inside its declared refresh window (§7-2 #117). Published
    #: because "asked and got nothing" and "did not ask" are the two
    #: things this programme refuses to let look alike.
    withheld: Mapping[str, tuple]
    observations_written: int
    health: Mapping[str, dict]
    conclusions: Mapping[str, dict]
    credentials: Mapping
    suppressors: Mapping
    coverage: Mapping
    #: G-19's disclosure: how much of what this tick MEANT to fetch it
    #: fetched, and how much of what it deferred L1 has never heard from.
    #: On the report because a partial sweep that reads like a complete one
    #: is this programme's signature defect, and the budget makes partial
    #: sweeps a normal state rather than an exceptional one.
    #:
    #: Defaults EMPTY, not complete, and `ops_health.sweep_monitor` reads an
    #: empty mapping as UNSUPPLIED for that reason: a report that says
    #: nothing about its sweep has not told us the sweep was whole.
    sweep: Mapping[str, object] = field(default_factory=dict)
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
    #: scenario_id -> the belligerent whose escalation chain the focused
    #: bonus read this tick. Measured, never configured (§7-2 #115): a
    #: dual-core scenario's owner moves with the evidence, so which one it
    #: was IS part of what the tick concluded.
    chain_owners: Mapping[str, str] = field(default_factory=dict)
    #: scenario_id -> `{owner, basis, values, production_ref}`. The same
    #: selection with the QUANTITY that made it: production's `avg_spike`
    #: when the origin distribution was measured this tick, the
    #: admitted-evidence fallback when no core had one (§7-2 #116). NP6
    #: applies to the ranking too — an owner is not a derivation.
    chain_ranking: Mapping[str, dict] = field(default_factory=dict)
    #: The escalation-chain links live after this tick, plus which of the
    #: four chain types v3 can supply at all. Both halves are needed to
    #: read the first: two of four are supplied today (§7-2 #123), so a
    #: chain that never reaches its three-link tier is the EXPECTED state
    #: rather than a quiet day, and a report showing only "0 links" would
    #: be indistinguishable from "nothing is escalating".
    chain_events: Mapping[str, object] = field(default_factory=dict)
    #: The LLM extraction stage's own account of itself
    #: (`v3/runtime/llm_stage.py`). Never empty on a tick that ran: a
    #: deployment with no egress reports `llm_not_wired` and a tick that
    #: found the model down reports how many articles it therefore did not
    #: ask about. `ops_health`'s LLM rollup has nothing else to read, and
    #: an absent stage that looked like a quiet one is exactly the shape
    #: C12 was filed against.
    llm: Mapping[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"tick_id": self.tick_id, "now": self.now,
                "scenarios": list(self.scenario_ids),
                "planned": list(self.planned),
                "skipped": [list(row) for row in self.skipped],
                "withheld": {adapter: [list(row) for row in rows]
                             for adapter, rows in self.withheld.items()},
                "observations_written": self.observations_written,
                "sweep": dict(self.sweep),
                "health": dict(self.health),
                "conclusions": dict(self.conclusions),
                "credentials": dict(self.credentials),
                "suppressors": dict(self.suppressors),
                "coverage": dict(self.coverage),
                "scoring": dict(self.scoring),
                "settings": dict(self.settings),
                "attention": dict(self.attention),
                "chain_owners": dict(self.chain_owners),
                "chain_ranking": {scenario_id: dict(row) for scenario_id, row
                                  in self.chain_ranking.items()},
                "chain_events": dict(self.chain_events),
                "llm": dict(self.llm)}


def fetch_cycle(*, now: float, registry, store, client,
                geography: Geography, countries: Sequence[str],
                article_countries: Sequence[str],
                credentials: Optional[CredentialPlan] = None,
                tick_id: Optional[str] = None,
                adversaries: Sequence[str] = (),
                cores: Sequence[str] = (),
                fetch_budget: Optional[int] = None):
    """Steps 1-4: schedule, expand, plan, execute. Returns a CycleResult.

    `countries` is the SWEEP scope and `article_countries` the union over
    every scored scenario. Two sets rather than one because production
    keeps two (`radar/scheduler.py:56-69`): the per-country sensors run on
    the focused scenario's participants, and five article sensors receive
    every scenario's. One set for both is what made the shadow expand
    ripe_atlas to 108 serial steps and ct_log to 162 against a 30/hr quota.
    `expansion.context_for` chooses per adapter; everything else here —
    the baselines, the recorded scalars, the expansion itself — is about
    what was actually fetched, so it takes the sweep scope.

    `adversaries` reaches the cloudflare fold, where an origin country's
    declared role decides the floor its spike is measured against — 0.5%
    for an adversary and 3.0%/2.0% for anyone else (`core.py:775-777`).
    Production reads the FOCUSED scenario's list; a cycle here fetches for
    every scored scenario at once, so the union is what is supplied.

    `cores` reaches the same fold for the same reason: `cf_vector_shift`
    fires on whether an EFFECTIVE CORE shifted (`core.py:877`/`:886`), and
    an origin distribution cannot answer that on its own.

    `fetch_budget` overrides G-19's per-tick request bound. An argument
    rather than a read of `policy` at the call site so a test can make the
    budget bite with three adapters instead of thirty-four, and so the
    parity harness — which replays recorded payloads and has no wall clock
    to protect — can lift it.
    """
    states = recorder.load_states(store)
    baselines = baselines_module.for_cycle(store, now=now,
                                           countries=countries,
                                           adversaries=adversaries,
                                           cores=cores)
    expansions = expansion_module.for_cycle(
        geography, countries, now=now,
        carried=baselines_module.carried_values(store, now=now))
    # §7-2 #117: production refetches the 28-day origin baseline only when
    # its stored snapshot is over a day old (`core.py:738-742`). The age
    # is in the snapshot this cycle already read, so the gate is data the
    # planner is handed rather than a second schedule to keep.
    #
    # G-19: then bound it. A cold `fetch_schedule` makes every adapter due
    # at once — 772 expanded steps against the deployed geography — and a
    # sweep that cannot finish is a deployment that never reaches its first
    # conclusion. `apply_budget` is pure and runs BEFORE the reordering, so
    # the reordering still sees the whole admitted set; the producers are
    # exempt from the budget for the same reason they are reordered, which
    # is that a cycle missing its suppressor reads noise as signal.
    plan = order_producers_first(apply_budget(
        run_due(now, registry.enabled(), states, None, expansions,
                freshness=baselines_module.refresh_state(baselines)),
        max_requests=fetch_budget or fetch_policy.FETCH_BUDGET_REQUESTS,
        always_admit=PRODUCER_ORDER))
    state = _CycleState()
    cycle = execute_plan(
        plan, registry, client=client, store=store,
        tick_id=tick_id or tick_id_for(now), countries=countries,
        context_for=lambda adapter: expansion_module.context_for(
            adapter, geography, countries, now=now,
            adversaries=adversaries, article_countries=article_countries),
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
                focused_scenario_id: Optional[str] = None):
    """Steps 5a-5c: resolve, assemble, score, write the TL stream.

    The three impure steps and the one pure one, in the order S1-PIPE-020
    fixes. Resolution is bounded at `now` so a replayed tick computes with
    the override that was in force then.

    Returns `(TickResult, ScoringSettings, chain_ranking)`. The settings
    come back because the report discloses them — a score whose thresholds
    are not published with it cannot be argued with (NP6) — and the chain
    ranking for the same reason: the focused bonus is computed against ONE
    belligerent's escalation chain, chosen from this tick's observations
    (`v3/runtime/chain.py`), and a bonus whose owner nobody can name
    afterwards is a bonus nobody can check.

    The ranking carries the QUANTITY as well as the winner. Production's
    `avg_spike` and v3's admitted-evidence fallback pick the same shape of
    answer from different measurements (§7-2 #116), so an owner published
    without its basis is two different claims wearing one label.
    """
    settings = scoring_module.settings_for(store, config=config, at=now)
    inputs = scoring_module.assemble(
        now=now, store=store, geography=geography,
        scenario_ids=scenario_ids, settings=settings,
        focused_scenario_id=focused_scenario_id)
    result = scoring_module.score(inputs)
    scoring_module.persist_tl(store, result, tick_id=tick_id)
    return result, settings, scoring_module.chain_rankings(
        store, now=now, scenarios=inputs.scenarios,
        observations=inputs.observations)


def run_tick(*, now: float, registry, store, client, geography: Geography,
             scenario_ids: Sequence[str],
             credentials: Optional[CredentialPlan] = None,
             config=None, focused_scenario_id: Optional[str] = None,
             default_focused_scenario_id: Optional[str] = None,
             score=None, fetch_budget: Optional[int] = None,
             llm=None) -> TickReport:
    """One whole tick. The composition root's single unit of work.

    `default_focused_scenario_id` is v1's `DEFAULT_FOCUSED_SCENARIO`
    (`radar/config.py:741-756`), and with `focused_scenario_id` it decides
    what the per-country sensors SWEEP: focus if an analyst set one, the
    default otherwise, exactly one scenario either way. Production's
    reason is quoted rather than restated — "running every sensor on every
    scenario every cycle would saturate upstreams" — and the shadow proved
    it: ct_log sent 162 requests an hour into a 30/hr quota and ripe_atlas
    took 25 minutes to walk 108 serial steps.

    This is the one country set in the tick that MAY be omitted, and the
    asymmetry is deliberate. Omitting it sweeps every scored scenario's
    participants, which is what v3 did until now: wider, slower, and never
    less sensitive. `article_countries` and `adversaries` have no such
    default because forgetting THOSE narrows what is watched.

    Two v1 mechanics are deliberately NOT ported here, and are registered
    rather than left as a silent difference:

      * v1 sweeps the UNION of up to four TTL-bounded active focuses
        (`radar/state.py:23-34`, ACTIVE_FOCUS_TTL_SEC=1800,
        ACTIVE_FOCUS_MAX=4), each touched by a `/api/threat_data` view.
        v3 has no such expiry: `focus_state` is a fold over the C1
        command log and returns one scenario, forever, until another
        command replaces it. Porting the TTL means a fold over
        `command_record` bounded at `now` — `v3/commands/state.py` — and
        nothing else; it is not this layer's to invent, because a
        composition root holding its own focus set would be the second
        source that disagrees with the record (G-15).
      * the sweep scenario does not become the SCORING focus.
        `focused_scenario_id` still reaches `score_cycle` untouched, so a
        deployment nobody has focused scores every scenario as background
        — which is what it did before this change. v1 keeps the same
        split (`radar/scheduler.py:56-68` unions for the sensors,
        `core.py:590` reads the single focused scenario for the score).

    `llm` is the dedicated LLM egress (`v3/runtime/llm_stage.LlmEgress`),
    supplied by the composition root and by nothing else. `None` runs the
    tick without an extraction stage — which is what the parity harness
    does, and what a deployment with no model does — and the report says
    so rather than omitting the stage.

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
    # The union over every scored scenario: production's
    # `all_participant_countries`, and the only country set the five
    # ARTICLE_SCOPED adapters ever see.
    article_countries = tuple(dict.fromkeys(
        country for scenario_id in scenarios
        for country in participants_of(geography, scenario_id)))
    # ... and the sweep scope: production's `strategic_theaters`. An
    # unknown id raises here rather than expanding to nothing, which is
    # what `scoring.assemble` already does with the same value — a focus
    # nobody can resolve must not present as a scenario nobody watched.
    sweep_scenario_id = focused_scenario_id or default_focused_scenario_id
    countries = (participants_of(geography, sweep_scenario_id)
                 if sweep_scenario_id else article_countries)

    identity = tick_id_for(now)
    # The union of the scored scenarios' effective cores, read through the
    # same transcription of `derive_country_context` the chain ranking
    # uses (`v3/runtime/chain.py`) rather than a second reading of the
    # geography that could disagree with it.
    declared = scoring_module.scenarios_for(geography, scenarios)
    cores = tuple(dict.fromkeys(
        core for scenario in declared
        for core in chain_module.effective_cores(scenario)))
    cycle, state = fetch_cycle(
        now=now, registry=registry, store=store, client=client,
        geography=geography, countries=countries,
        article_countries=article_countries, credentials=credentials,
        tick_id=identity, cores=cores, fetch_budget=fetch_budget,
        adversaries=tuple(dict.fromkeys(
            country for scenario_id in scenarios
            for country in adversaries_of(geography, scenario_id))))

    # Step 4c: extract. AFTER the cycle wrote its rows and BEFORE scoring,
    # so an item this tick pulled out of an article is scored by this tick
    # — L2 reads L1's in-force projection at `now`, and running the stage
    # after the score would make every intel item exactly one tick late
    # with nothing saying why (WP-2.7 / C12).
    #
    # The UNION, not the sweep scope. `countries` is the extraction
    # prompt's `theaters` fallback for a candidate whose article names
    # none, and `hacktivist_news` — the family that fallback exists for —
    # is one of the five production feeds `all_participant_countries`
    # (`radar/sensors/hacktivist_news_sensor.py:236`). Handing it the
    # focused participants would tell the model to attribute a Ukrainian
    # claim to Taiwan's list.
    llm_report = llm_stage_module.run(
        egress=llm, store=store, registry=registry,
        awaiting=state.awaiting_llm, now=now, countries=article_countries,
        tick_id=identity)

    # Step 5: score. AFTER the observations are written, because the
    # scoring input is the ledger's in-force projection at `now` — the
    # same reader the parity harness uses, so what parity measures is
    # what production scored (S5-VERIF-031).
    settings_disclosure: Mapping[str, object] = {}
    chain_ranking: Mapping[str, dict] = {}
    chain_events: Mapping[str, object] = {}
    if config is not None:
        result, settings, chain_ranking = score_cycle(
            now=now, store=store, geography=geography,
            scenario_ids=scenarios, config=config, tick_id=identity,
            focused_scenario_id=focused_scenario_id)
        results_by_scenario = dict(result.results)
        settings_disclosure = settings.disclosed()
        chain_events = _chain_event_disclosure(result.next_sequence_events)
    else:
        results_by_scenario = dict(score(now, cycle) or {}) \
            if score is not None else {}

    # G-19: resolved against the ledger BEFORE the outcomes are built,
    # because a budget deferral means opposite things depending on whether
    # the source has ever spoken — free when its last reading is still in
    # force, total darkness when there is no reading at all.
    unobserved = health_module.never_observed(store, now=now,
                                              adapters=registry.enabled(),
                                              countries=countries)
    outcomes = health_module.outcomes_for_cycle(cycle,
                                                credentials=credentials,
                                                unobserved=unobserved)
    sweep = health_module.sweep_coverage(cycle, unobserved=unobserved)
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
        withheld=cycle.plan.withheld,
        observations_written=(cycle.observations_written
                              + llm_report.observations_written),
        health=health_by_scenario,
        conclusions=conclusions_by_scenario,
        credentials=credentials.as_dict() if credentials else {},
        suppressors=state.suppressors.as_dict(),
        coverage=expansion_module.coverage_report(geography, countries),
        sweep=sweep,
        scoring={scenario_id: scored.as_dict()
                 for scenario_id, scored in results_by_scenario.items()},
        settings=settings_disclosure,
        attention=ranking.as_dict(),
        chain_owners={scenario_id: row["owner"]
                      for scenario_id, row in chain_ranking.items()},
        chain_ranking=dict(chain_ranking),
        chain_events=dict(chain_events),
        llm=llm_report.as_dict())


def _chain_event_disclosure(events) -> dict:
    """The chain's live links, with what CAN be supplied beside them.

    NP6 reaches the sequence bonus the same way it reaches the score: a
    bonus of 0 has two readings — "no escalation" and "the link that
    would have shown it is not implemented" — and only one of them is a
    conclusion about the world.
    """
    from v3.runtime import events as events_module

    by_country: dict = {}
    for event in events:
        by_country.setdefault(event.country, []).append(event.event_type)
    return {"live": {country: sorted(set(types))
                     for country, types in sorted(by_country.items())},
            "count": len(tuple(events)),
            "coverage": events_module.chain_coverage()}


__all__ = ["run_tick", "fetch_cycle", "score_cycle", "conclude",
           "build_hooks", "order_producers_first", "tick_id_for",
           "TickReport", "PRODUCER_ORDER"]
