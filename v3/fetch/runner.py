"""One fetch cycle, split into a pure decision and an impure execution.

Design sheet §1-2. `run_due` is a **function that returns work as values**.
It starts no thread, opens no socket and touches no database; you can call
it in a test with a dictionary of states and read the plan it produces.
Executing that plan is `execute_plan`, which is the only impure half.

The split exists because the alternative was measured. `radar/__init__.py`
spawns ~40 threads at import, which (a) pointed the test suite at the
production database, (b) forced WP-2.8's parity driver into subprocess
isolation, and (c) allowed B-01 — `bg_observer` running its own daemon
thread straight past the circuit breaker while its docstring claimed
otherwise. With `run_due` as the only producer of work, there is nowhere
for a private thread to obtain any.

S4-NF-003's "exactly once per cycle" is structural here: the breaker's
effective state is computed in `run_due` and carried in the plan, so
`execute_plan` cannot consume a second HALF_OPEN probe slot by asking
again. The probe is one STEP for the same structural reason: `run_due`
truncates a HALF_OPEN plan to its first step, so the executor cannot
spend an adapter's whole sweep on what the breaker meant as one trial
request. Measured before the truncation existed (shadow, 2026-08-13):
ct_log's "probe" was its full 162-step expansion — 319 requests in ten
minutes, all against an exhausted 30-requests/hour anonymous quota.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Mapping, Optional, Sequence

from v3.adapters.types import (FALLBACK_ON_FAILURE_OR_EMPTY, AdapterId,
                               NormalizeContext, RequestSpec, SourceAdapter)
from v3.fetch import breaker as breaker_module
from v3.fetch import client as client_module
from v3.fetch import expand as expand_module
from v3.fetch import recorder, schedule
from v3.fetch.breaker import BreakerState
from v3.fetch.expand import ExpansionInput, ResolvedStep
from v3.fetch.limiter import LimiterState, is_allowed, wait_seconds
from v3.fetch.state import AdapterState
from v3.kernel import Evidence
from v3.kernel.errors import DomainError
from v3.ledger.records import SignalObservation

# ── why an adapter was not planned ──────────────────────────────────────
NOT_DUE = "not_due"
BREAKER_OPEN = "breaker_open"
RATE_LIMITED = "rate_limited"
DISABLED = "disabled"
#: The caller supplied no value for a placeholder the adapter declares.
#: Recorded rather than raised: one misconfigured adapter must not take a
#: cycle down. Recorded rather than SENT, because `{country}` on the wire
#: is an error that answers HTTP 200 with nothing in it (K02).
UNRESOLVED = "unresolved_placeholder"
#: Every request the adapter would have sent still has a stored answer
#: younger than its declared `refresh_after_sec` (§7-2 #117).
FRESH_ENOUGH = "answer_still_fresh"
#: This tick's request budget was already spent on adapters that had been
#: waiting longer (G-19). NOT a failure and NOT "not due": the adapter is
#: due, nothing is wrong with it, and it will be planned first next tick.
#: Its own reason code because the three are different operational facts
#: and `v3/runtime/health.py` has to be able to tell them apart — folding
#: a deferral into `NOT_DUE` is how "we swept 40% of our sources" would
#: come to render as an ordinary quiet tick.
BUDGET_DEFERRED = "fetch_budget_deferred"

#: Where a draft's `reason` lands in the observation's flags.
#:
#: L1's `signal_observation` has no `fired_reason` column and the schema is
#: committed (WP-2.4); promoting it to one is 裁定要求 3's business. Until
#: then the runner writes it under ONE canonical key, in ONE place — which
#: is the difference between a convention and `check_host` inventing
#: `flags["reason"]` for itself.
FIRED_REASON_FLAG = "fired_reason"


@dataclass(frozen=True, slots=True)
class PlannedFetch:
    """Work to do, with the breaker decision already made and carried.

    `steps` are CONCRETE — placeholders already expanded — so the plan
    shows exactly what will reach the wire, and `execute_plan` has no
    decision left to make about addressing.
    """

    adapter_id: AdapterId
    steps: tuple[ResolvedStep, ...]
    breaker: BreakerState
    overdue_by_sec: float = 0.0
    #: When this adapter last ran, or `None` for never. Carried because
    #: `apply_budget` orders by it: `overdue_by_sec` is 0.0 for an adapter
    #: that has NEVER run (`schedule.overdue_by`), so on a cold ledger every
    #: candidate ties at zero and lateness cannot break the tie. "Longest
    #: since it last spoke" can, and it is starvation-free by construction.
    last_run_at: Optional[float] = None
    #: `(label, scope_key, due_at)` for each step this plan did NOT send
    #: because its stored answer is still fresh (§7-2 #117). Carried rather
    #: than dropped: a plan that quietly sends fewer requests than the
    #: adapter declares is indistinguishable from one whose expansion
    #: broke, and that is the failure this layer exists to make visible.
    withheld: tuple[tuple, ...] = ()
    #: How many due steps were held back because this plan is a HALF_OPEN
    #: probe (S4-NF-003: one trial request, so `steps` was cut to its
    #: first). Disclosed for the same reason `withheld` is — a truncated
    #: plan must never read like a completed sweep (G-17). The step keeps
    #: its fallback chain: the chain is the same question asked of another
    #: host, and the probe's question is "can this adapter answer again".
    probe_deferred: int = 0

    @property
    def is_probe(self) -> bool:
        """A HALF_OPEN probe — one trial request, not a resumption."""
        return self.breaker.state == breaker_module.HALF_OPEN

    @property
    def requests(self) -> tuple[RequestSpec, ...]:
        """Every concrete spec in the plan, chains flattened.

        For inspection. A chain's later alternatives are only reached when
        the earlier ones do not answer, so this is what MIGHT be fetched,
        not what will be.
        """
        return tuple(spec for step in self.steps for spec in step.alternatives)


@dataclass(frozen=True, slots=True)
class SkippedFetch:
    adapter_id: AdapterId
    reason: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class FetchPlan:
    """A cycle's decisions, as values. Produced without any I/O."""

    now: float
    planned: tuple[PlannedFetch, ...] = ()
    skipped: tuple[SkippedFetch, ...] = ()
    breaker_states: Mapping[str, BreakerState] = field(default_factory=dict)

    @property
    def planned_ids(self) -> tuple[str, ...]:
        return tuple(item.adapter_id.value for item in self.planned)

    def skipped_for(self, reason: str) -> tuple[SkippedFetch, ...]:
        return tuple(item for item in self.skipped if item.reason == reason)

    @property
    def withheld(self) -> Mapping[str, tuple]:
        """`{adapter: ((label, scope_key, due_at), ...)}`. NP6 disclosure."""
        return {item.adapter_id.value: item.withheld
                for item in self.planned if item.withheld}


def _withhold_fresh(steps: Sequence[ResolvedStep], *, now: float,
                    stored: Mapping[tuple, float]) -> tuple[tuple, tuple]:
    """Split expanded steps into `(to send, withheld)`. PURE.

    A step is withheld only if its PRIMARY spec declares
    `refresh_after_sec` and a stored answer for `(label, scope_key)` is
    younger than it. The primary alone decides because a chain's later
    alternatives are the same question asked of another host — if the
    question does not need re-asking, none of them does.
    """
    sending: list[ResolvedStep] = []
    withheld: list[tuple] = []
    for step in steps:
        spec = step.primary
        window = spec.refresh_after_sec
        key = (spec.label, step.scope_key)
        stored_at = stored.get(key)
        if schedule.needs_refresh(now, stored_at, window):
            sending.append(step)
            continue
        withheld.append((spec.label, step.scope_key,
                         schedule.refresh_due_at(stored_at, window)))
    return tuple(sending), tuple(withheld)


def run_due(now: float, adapters: Sequence[SourceAdapter],
            states: Mapping[str, AdapterState],
            limiter_state: Optional[LimiterState] = None,
            expansions: Optional[Mapping[str, ExpansionInput]] = None,
            freshness: Optional[Mapping[str, Mapping[tuple, float]]] = None
            ) -> FetchPlan:
    """Decide what to fetch. PURE — no clock, no socket, no database.

    Order of the three gates is deliberate: due-ness, then the breaker,
    then the rate limiter. An adapter that is not due should not consume a
    HALF_OPEN probe slot, and an adapter the breaker is holding shut
    should not consume a rate-limit slot on behalf of the group it shares.

    `expansions` maps an adapter name to the placeholder values for THIS
    run — countries, coordinates, chokepoints, ISR zones, time bounds.
    Expansion happens here rather than at fetch time so the plan carries
    concrete requests: a plan you can read is a plan you can check before
    it reaches anything (NP6), and it is where an unresolved `{country}`
    is caught while it is still a value.

    `freshness` is `{adapter: {(label, scope_key): stored_at}}` and is the
    only input a per-REQUEST cadence needs (§7-2 #117). It arrives as data
    for the same reason expansions do: the age lives in L1, this function
    opens nothing, and a request the caller says nothing about is sent.
    The filter runs AFTER expansion because the cadence is per target —
    `cloudflare_radar` refreshes TW's 28-day baseline window and JP's on
    different days.
    """
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
    limits = limiter_state or LimiterState()
    inputs = dict(expansions or {})
    ages = dict(freshness or {})

    planned: list[PlannedFetch] = []
    skipped: list[SkippedFetch] = []
    effective: dict[str, BreakerState] = {}
    # Group slots claimed earlier in THIS cycle, so two adapters sharing a
    # quota cannot both be planned into the same instant (K01).
    claimed: set[str] = set()

    for adapter in adapters:
        name = adapter.adapter_id.value
        state = states.get(name) or AdapterState(adapter_id=name)

        if not adapter.enabled:
            skipped.append(SkippedFetch(adapter.adapter_id, DISABLED,
                                        adapter.disabled_reason))
            effective[name] = state.breaker
            continue

        if not schedule.is_due(now, state.last_run_at, adapter.cadence):
            skipped.append(SkippedFetch(
                adapter.adapter_id, NOT_DUE,
                f"next due at "
                f"{schedule.next_run_at(now, state.last_run_at, adapter.cadence):.0f}"))
            effective[name] = state.breaker
            continue

        # S4-NF-003: computed ONCE, here, and carried in the plan.
        current = breaker_module.effective_state(state.breaker, now)
        effective[name] = current
        if breaker_module.should_skip(current):
            skipped.append(SkippedFetch(
                adapter.adapter_id, BREAKER_OPEN,
                f"open since {current.opened_at}, retry in "
                f"{current.recovery_delay_sec:.0f}s"))
            continue

        group = adapter.rate_limit_group
        if group in claimed or not is_allowed(
                limits, group, adapter.min_interval_sec, now):
            skipped.append(SkippedFetch(
                adapter.adapter_id, RATE_LIMITED,
                f"group {group!r} available in "
                f"{wait_seconds(limits, group, adapter.min_interval_sec, now):.1f}s"
                if group not in claimed else
                f"group {group!r} already claimed this cycle"))
            continue

        try:
            steps = expand_module.expand_requests(
                adapter.requests, inputs.get(name) or ExpansionInput())
        except DomainError as unresolved:
            # Not raised: an adapter the caller under-supplied must not
            # take the other 21 with it. Not sent either — this is the
            # defect the expander exists to make impossible.
            skipped.append(SkippedFetch(adapter.adapter_id, UNRESOLVED,
                                        str(unresolved)))
            continue

        steps, withheld = _withhold_fresh(steps, now=now,
                                          stored=ages.get(name) or {})
        if withheld and not steps:
            # Nothing left to ask. Skipped rather than planned-and-empty so
            # that `last_run_at` does not advance on a cycle that sent no
            # request — an adapter whose whole declaration is on a daily
            # refresh must still come back tomorrow.
            skipped.append(SkippedFetch(
                adapter.adapter_id, FRESH_ENOUGH,
                f"{len(withheld)} request(s) still answered by a stored "
                f"value"))
            continue

        probe_deferred = 0
        if current.state == breaker_module.HALF_OPEN and len(steps) > 1:
            # One trial request, not a resumption (S4-NF-003). The rest of
            # the sweep runs when the probe's success has closed the
            # breaker and the adapter comes due again.
            probe_deferred = len(steps) - 1
            steps = steps[:1]

        if adapter.min_interval_sec > 0:
            claimed.add(group)
        planned.append(PlannedFetch(
            adapter_id=adapter.adapter_id, steps=steps, breaker=current,
            overdue_by_sec=schedule.overdue_by(now, state.last_run_at,
                                               adapter.cadence),
            last_run_at=state.last_run_at,
            withheld=withheld,
            probe_deferred=probe_deferred))

    return FetchPlan(now=now, planned=tuple(planned), skipped=tuple(skipped),
                     breaker_states=effective)


def _request_cost(item: PlannedFetch) -> int:
    """What this adapter will cost the budget, counted in resolved steps.

    STEPS rather than `requests`: a chain's later alternatives are only
    reached when the earlier ones do not answer, so counting them would
    charge every adapter for the failure it is hoping to avoid, and
    `ct_log`'s 162 steps would price as 324.
    """
    return len(item.steps)


def apply_budget(plan: FetchPlan, *, max_requests: int,
                 always_admit: Sequence[str] = ()) -> FetchPlan:
    """Bound ONE tick's fetch stage. PURE — a plan in, a plan out.

    G-19. `is_due` answers True for every adapter that has never run, which
    is correct and is also why a cold ledger plans the entire catalogue in
    one tick: 772 expanded steps against the deployed geography, which two
    shadow runs failed to finish in twenty-five minutes. A deployment that
    cannot complete its first sweep cannot reach its first conclusion, and
    the schedule never advances, so the next tick plans the same 772 again.

    **The unit is the ADAPTER, and it is atomic.** An adapter is admitted
    whole or deferred whole, even when it alone exceeds the budget
    (`ct_log` does). Half-fetching is the one thing this must not do:
    `reduce` folds across an adapter's payloads, so a ct_log that fetched
    80 of its 162 domains would fold a verdict that looks exactly like a
    complete one — G-17's shape, manufactured by the fix for G-19.

    **Order is "longest since it last spoke", never registry order.** A
    fixed order would be starvation-free here by accident (every cadence is
    at least 300s and the loop ticks every 60s, so an adapter that runs
    leaves the due set for at least five ticks) — but only by accident, and
    the first adapter declared with a 30s cadence would silently monopolise
    the budget. Ordering by `last_run_at` ascending, never-run first, is
    starvation-free by construction: running an adapter makes it the most
    recently run, which sorts it last.

    `always_admit` is the composition root's list of suppression PRODUCERS.
    They are exempt because deferring one changes how the adapters that DO
    run are read: `space_weather` and `openweather` mute other families per
    country, and a cycle missing its suppressor reports noise as signal.
    They still spend the budget, so what follows them gets what is left.

    At least one adapter is always admitted. A budget that could admit
    nothing is a loop that fetches nothing forever, which is the livelock
    this function exists to end wearing different clothes.
    """
    if max_requests <= 0:
        raise DomainError(
            f"max_requests must be positive, got {max_requests}: a "
            f"non-positive budget defers every adapter forever, which is "
            f"the livelock this bound exists to end")
    exempt = frozenset(str(name) for name in always_admit)
    admitted: list[PlannedFetch] = []
    deferred: list[SkippedFetch] = []
    spent = 0

    def take(item: PlannedFetch) -> None:
        nonlocal spent
        admitted.append(item)
        spent += _request_cost(item)

    reserved = [item for item in plan.planned
                if item.adapter_id.value in exempt]
    for item in reserved:
        take(item)

    # `last_run_at is None` (never run) sorts first; the adapter id is the
    # final tie-break so two adapters that last ran in the same instant
    # order reproducibly (NP6 — a plan has to replay).
    candidates = sorted(
        (item for item in plan.planned if item.adapter_id.value not in exempt),
        key=lambda item: (item.last_run_at is not None,
                          item.last_run_at or 0.0, item.adapter_id.value))
    for item in candidates:
        cost = _request_cost(item)
        if admitted and spent + cost > max_requests:
            waited = "never run" if item.last_run_at is None \
                else f"last ran at {item.last_run_at:.0f}"
            deferred.append(SkippedFetch(
                item.adapter_id, BUDGET_DEFERRED,
                f"{cost} request(s) would take this tick to "
                f"{spent + cost} of a {max_requests} budget; {waited}, so it "
                f"is planned before the adapters admitted here next tick"))
            continue
        take(item)

    if not deferred:
        return plan
    # The admitted set is returned in the PLAN's original order, not the
    # priority order: `order_producers_first` and the executor read this
    # sequence, and re-ordering here would move a decision about execution
    # into a function about admission.
    keep = {item.adapter_id.value for item in admitted}
    return FetchPlan(
        now=plan.now,
        planned=tuple(item for item in plan.planned
                      if item.adapter_id.value in keep),
        skipped=plan.skipped + tuple(deferred),
        breaker_states=plan.breaker_states)


# ── the impure half ─────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class CycleHooks:
    """What the composition root lends the kernel for one cycle.

    Four things the kernel must DO but must not DECIDE. Each is a function
    supplied by `v3/runtime/`, defaulting to "no change", so the kernel
    keeps working unhooked and every hook is visible at one call site
    instead of spread across the adapters.

    Passing functions rather than handles is deliberate and is the design
    sheet's wording (§7-2 #45): giving `bg_observer_rss` a ledger handle
    would let an adapter write, and asking the adapter to classify its own
    feed after the kernel already parsed it would parse the same bytes
    twice.
    """

    #: `(adapter_id, drafts) -> drafts`. The N-to-one fold, §7-2 #11.
    #: Runs before anything is written, so the collision it prevents never
    #: reaches the ledger's UNIQUE constraint.
    reduce: Optional[object] = None
    #: `{adapter_id: payload -> outcome}`. Turns "HTTP 200 with HTML in
    #: it" into `returns_html` in `fetch_log.outcome` rather than `ok`
    #: (§7-2 #45 / A10: "returned zero items" and "has been serving HTML
    #: since June" stop being one counter).
    classify_outcome: Mapping[str, object] = field(default_factory=dict)
    #: `{adapter_id: attempt_index -> headers}`. Per-request header
    #: selection, which a fixed `RequestSpec.headers` cannot express —
    #: §7-2 #50's UA pool.
    request_headers: Mapping[str, object] = field(default_factory=dict)
    #: `{adapter_id: note}` recorded alongside every fetch that adapter
    #: makes, so "ran anonymously" is a fact in the ledger and not only in
    #: a start-up message nobody re-reads.
    credential_notes: Mapping[str, str] = field(default_factory=dict)

    def folded(self, adapter_id: str, drafts):
        return tuple(self.reduce(adapter_id, drafts)) if self.reduce \
            else tuple(drafts)

    def outcome_for(self, adapter_id: str, outcome):
        """Reclassify a SUCCESSFUL fetch, never a failed one.

        A classifier that could overwrite `timeout` would be a second
        opinion on whether the request happened at all; what it may say is
        what the bytes turned out to be.
        """
        classifier = self.classify_outcome.get(adapter_id)
        if classifier is None or not outcome.succeeded \
                or outcome.payload is None:
            return outcome.outcome
        return str(classifier(outcome.payload)) or outcome.outcome

    def headers_for(self, adapter_id: str, index: int):
        chooser = self.request_headers.get(adapter_id)
        return dict(chooser(index)) if chooser else {}

    def note_for(self, adapter_id: str) -> str:
        return str(self.credential_notes.get(adapter_id, ""))


def _annotated(detail: str, note: str) -> str:
    if not note:
        return detail
    return f"{note}; {detail}" if detail else note


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """What executing one adapter produced."""

    adapter_id: AdapterId
    outcome: str
    observations: int = 0
    state: Optional[AdapterState] = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CycleResult:
    plan: FetchPlan
    results: tuple[AdapterResult, ...] = ()
    limiter_state: LimiterState = field(default_factory=LimiterState)

    @property
    def observations_written(self) -> int:
        return sum(result.observations for result in self.results)


def execute_plan(plan: FetchPlan, registry, *, client, store,
                 tick_id: str, credentials_present: bool = True,
                 limiter_state: Optional[LimiterState] = None,
                 countries: Sequence[str] = (),
                 context_for=None,
                 hooks: Optional[CycleHooks] = None) -> CycleResult:
    """Carry out a plan. The ONLY impure entry point in this module.

    Adapters do not write to L1 (§2-2): `normalize` returns drafts and
    THIS function wraps them in kernel `Evidence` and appends them. That
    keeps the freshness horizon set in exactly one place, which is the
    entrance B-03 came through.
    """
    limits = limiter_state or LimiterState()
    lent = hooks or CycleHooks()
    results: list[AdapterResult] = []

    for item in plan.planned:
        adapter = registry.get(item.adapter_id)
        drafts = []
        fetched: list = []
        outcome_name = client_module.OK
        detail = ""
        attempt_index = 0
        classified: dict = {}

        # ── I/O first, OUTSIDE the transaction ──────────────────────────
        # Network calls are slow and can hang; holding SQLite's write lock
        # across them would block every other writer for the duration of a
        # remote timeout.
        unanswered: list = []
        for step in item.steps:
            # A chain's later alternatives run ONLY when the earlier ones
            # do not answer. Fetching them all unconditionally is what let
            # a Cloudflare anomaly override IODA's OK (K19): both payloads
            # reached `normalize`, and the FIRED one won.
            satisfied = False
            last_failure = None
            for spec in step.alternatives:
                # §7-2 #50: a per-request header the declaration cannot
                # hold. The spec is REPLACED, not mutated — a shared
                # declaration edited in place is edited for every later
                # cycle too.
                chosen = lent.headers_for(adapter.name, attempt_index)
                attempt_index += 1
                if chosen:
                    spec = replace(spec,
                                   headers={**dict(spec.headers), **chosen})
                outcome = client.fetch(spec, now=plan.now, auth=adapter.auth)
                limits = limits.record(adapter.rate_limit_group, plan.now)
                fetched.append(outcome)
                classified[id(outcome)] = lent.outcome_for(adapter.name,
                                                           outcome)
                if not _answers(outcome, step.advance_on):
                    last_failure = outcome
                    continue
                context = (context_for(adapter) if context_for is not None
                           else NormalizeContext(
                               adapter_id=adapter.adapter_id, now=plan.now,
                               countries=tuple(countries)))
                drafts.extend(adapter.normalize(outcome.payload, context))
                # "A then B(A)": the second request only becomes
                # addressable now, from the answer just received. It runs
                # on SUCCESS, which is the whole difference from a chain.
                if step.continuation is not None:
                    followed = _continue(client, step, outcome, adapter,
                                         now=plan.now)
                    if followed is not None:
                        limits = limits.record(adapter.rate_limit_group,
                                               plan.now)
                        fetched.append(followed)
                        if followed.succeeded and followed.payload is not None:
                            drafts.extend(adapter.normalize(followed.payload,
                                                            context))
                        else:
                            last_failure = followed
                            break
                satisfied = True
                break
            # A step a fallback rescued is a step that answered. The
            # primary's failure is still in fetch_log, which is where it
            # belongs — visible, without calling the cycle a failure.
            if not satisfied and last_failure is not None:
                unanswered.append(last_failure)

        if unanswered:
            outcome_name = unanswered[-1].outcome
            detail = unanswered[-1].detail

        succeeded = outcome_name == client_module.OK
        stepped = breaker_module.step(
            item.breaker,
            breaker_module.SUCCESS if succeeded else breaker_module.FAILURE,
            plan.now)
        state = AdapterState(adapter_id=adapter.name).with_run(
            at=plan.now, outcome=outcome_name, breaker=stepped)

        # ── then ONE transaction for the whole cycle ────────────────────
        # fetch_log + body + observations + schedule state commit together
        # or not at all. Separately-committed writes leave a crash window
        # where the log records a fetch whose breaker step was lost, and
        # the next cycle then reasons from a state that never existed.
        written = 0
        note = lent.note_for(adapter.name)
        with store.transaction() as conn:
            for outcome in fetched:
                recorder.record_fetch(
                    store, adapter.name, requested_at=plan.now,
                    url_sha256=outcome.url_sha256,
                    outcome=classified.get(id(outcome), outcome.outcome),
                    http_status=outcome.status, latency_ms=outcome.latency_ms,
                    body_sha256=outcome.body_sha256,
                    breaker_state=item.breaker.state,
                    detail=_annotated(outcome.detail, note),
                    connection=conn)
                if (adapter.record_body and outcome.succeeded
                        and outcome.payload is not None):
                    recorder.record_body(store, adapter.name,
                                         body=outcome.payload.body,
                                         recorded_at=plan.now, connection=conn)
            if succeeded:
                # The fold runs INSIDE the transaction that writes, so a
                # reduction failure aborts the write rather than leaving
                # half a cycle recorded.
                written = append_drafts(store, adapter,
                                        lent.folded(adapter.name, drafts),
                                        tick_id=tick_id, now=plan.now,
                                        connection=conn)
            recorder.save_state(store, state, updated_at=plan.now,
                                connection=conn)

        results.append(AdapterResult(
            adapter_id=adapter.adapter_id, outcome=outcome_name,
            observations=written, state=state, detail=detail))

    return CycleResult(plan=plan, results=tuple(results), limiter_state=limits)


def _decoded(payload):
    """The first response as a document, or None if it is not one."""
    if payload is None:
        return None
    try:
        return payload.json()
    except Exception:            # noqa: BLE001 - any decode failure is "not a document"
        return None


def _continue(client, step: ResolvedStep, outcome, adapter: SourceAdapter, *,
              now: float):
    """Fetch the second half of "A then B(A)", or say why it could not be.

    Returns a `FetchOutcome` either way, so the attempt is in `fetch_log`
    whichever happened. A continuation that silently does not happen is
    the adapter reporting "measured, nothing there" about a measurement it
    never took — the shape NP1 exists to forbid, and the shape this whole
    type was added to remove.
    """
    continuation = step.continuation
    values, missing = expand_module.carried_values(continuation,
                                                   _decoded(outcome.payload))
    if missing:
        return client_module.FetchOutcome(
            outcome=client_module.CONTINUATION_UNRESOLVED,
            url=continuation.spec.url, requested_at=now, latency_ms=0.0,
            detail=f"the first response carried no "
                   f"{', '.join(sorted(missing))}; "
                   f"{continuation.reason}")
    client.pause(continuation.delay_sec)
    return client.fetch(expand_module.continue_with(continuation, values),
                        now=now, auth=adapter.auth)


def _answers(outcome, advance_on: str) -> bool:
    """Did this alternative answer, or should the chain move on?

    The kernel judges what it can see. "No bytes" it can see; "no useful
    content" it cannot, because that needs a parse, and the parse is
    `normalize`'s — which runs after the chain is already resolved.
    """
    if not outcome.succeeded:
        return False
    if advance_on == FALLBACK_ON_FAILURE_OR_EMPTY:
        return bool(outcome.payload is not None and outcome.payload.body)
    return True


def append_drafts(store, adapter: SourceAdapter, drafts, *, tick_id: str,
                  now: float, connection=None) -> int:
    """Wrap drafts in kernel Evidence and append. Adapters never do this.

    PUBLIC since WP-2.7's stage landed. It was `_append_drafts` while the
    runner was its only caller; `v3/runtime/llm_stage.py` is the second,
    and a private name there would have invited a copy — which is how the
    freshness horizon comes to be set in two places and B-03 comes back.
    One seam, two callers, one horizon.
    """
    written = 0
    for draft in drafts:
        flags = dict(draft.flags)
        if draft.reason:
            flags[FIRED_REASON_FLAG] = draft.reason
        observation = SignalObservation(
            tick_id=tick_id,
            sensor=adapter.name,
            signal_source=draft.signal_source,
            domain=draft.domain,
            country=draft.country or "GLOBAL",
            evidence=Evidence.observe(
                draft.value, observed_at=now,
                freshness_horizon_sec=adapter.freshness_horizon_sec,
                source=adapter.name),
            status=draft.status,
            raw_score=draft.raw_score,
            confidence=draft.confidence,
            flags=flags,
            suppressed=draft.suppressed,
            suppress_reason=draft.suppress_reason,
            evidence_url=draft.evidence_url)
        if store.append_signal(observation, now=now, connection=connection):
            written += 1
    return written


__all__ = ["run_due", "apply_budget", "execute_plan", "append_drafts",
           "FetchPlan",
           "PlannedFetch", "CycleHooks",
           "SkippedFetch", "CycleResult", "AdapterResult",
           "NOT_DUE", "BREAKER_OPEN", "RATE_LIMITED", "DISABLED",
           "UNRESOLVED", "FRESH_ENOUGH", "BUDGET_DEFERRED",
           "FIRED_REASON_FLAG"]
