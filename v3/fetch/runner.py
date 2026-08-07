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
again.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional, Sequence

from v3.adapters.types import (AdapterId, NormalizeContext, RequestSpec,
                               SourceAdapter)
from v3.fetch import breaker as breaker_module
from v3.fetch import client as client_module
from v3.fetch import recorder, schedule
from v3.fetch.breaker import BreakerState
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


@dataclass(frozen=True, slots=True)
class PlannedFetch:
    """Work to do, with the breaker decision already made and carried."""

    adapter_id: AdapterId
    requests: tuple[RequestSpec, ...]
    breaker: BreakerState
    overdue_by_sec: float = 0.0

    @property
    def is_probe(self) -> bool:
        """A HALF_OPEN probe — one trial request, not a resumption."""
        return self.breaker.state == breaker_module.HALF_OPEN


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


def run_due(now: float, adapters: Sequence[SourceAdapter],
            states: Mapping[str, AdapterState],
            limiter_state: Optional[LimiterState] = None) -> FetchPlan:
    """Decide what to fetch. PURE — no clock, no socket, no database.

    Order of the three gates is deliberate: due-ness, then the breaker,
    then the rate limiter. An adapter that is not due should not consume a
    HALF_OPEN probe slot, and an adapter the breaker is holding shut
    should not consume a rate-limit slot on behalf of the group it shares.
    """
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
    limits = limiter_state or LimiterState()

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

        if adapter.min_interval_sec > 0:
            claimed.add(group)
        planned.append(PlannedFetch(
            adapter_id=adapter.adapter_id, requests=adapter.requests,
            breaker=current,
            overdue_by_sec=schedule.overdue_by(now, state.last_run_at,
                                               adapter.cadence)))

    return FetchPlan(now=now, planned=tuple(planned), skipped=tuple(skipped),
                     breaker_states=effective)


# ── the impure half ─────────────────────────────────────────────────────

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
                 countries: Sequence[str] = ()) -> CycleResult:
    """Carry out a plan. The ONLY impure entry point in this module.

    Adapters do not write to L1 (§2-2): `normalize` returns drafts and
    THIS function wraps them in kernel `Evidence` and appends them. That
    keeps the freshness horizon set in exactly one place, which is the
    entrance B-03 came through.
    """
    limits = limiter_state or LimiterState()
    results: list[AdapterResult] = []

    for item in plan.planned:
        adapter = registry.get(item.adapter_id)
        drafts = []
        fetched: list = []
        outcome_name = client_module.OK
        detail = ""

        # ── I/O first, OUTSIDE the transaction ──────────────────────────
        # Network calls are slow and can hang; holding SQLite's write lock
        # across them would block every other writer for the duration of a
        # remote timeout.
        for spec in item.requests:
            outcome = client.fetch(spec, now=plan.now, auth=adapter.auth)
            limits = limits.record(adapter.rate_limit_group, plan.now)
            fetched.append(outcome)
            if not outcome.succeeded:
                outcome_name = outcome.outcome
                detail = outcome.detail
                continue
            context = NormalizeContext(adapter_id=adapter.adapter_id,
                                       now=plan.now, countries=tuple(countries))
            drafts.extend(adapter.normalize(outcome.payload, context))

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
        with store.transaction() as conn:
            for outcome in fetched:
                recorder.record_fetch(
                    store, adapter.name, requested_at=plan.now,
                    url_sha256=outcome.url_sha256, outcome=outcome.outcome,
                    http_status=outcome.status, latency_ms=outcome.latency_ms,
                    body_sha256=outcome.body_sha256,
                    breaker_state=item.breaker.state, detail=outcome.detail,
                    connection=conn)
                if (adapter.record_body and outcome.succeeded
                        and outcome.payload is not None):
                    recorder.record_body(store, adapter.name,
                                         body=outcome.payload.body,
                                         recorded_at=plan.now, connection=conn)
            if succeeded:
                written = _append_drafts(store, adapter, drafts,
                                         tick_id=tick_id, now=plan.now,
                                         connection=conn)
            recorder.save_state(store, state, updated_at=plan.now,
                                connection=conn)

        results.append(AdapterResult(
            adapter_id=adapter.adapter_id, outcome=outcome_name,
            observations=written, state=state, detail=detail))

    return CycleResult(plan=plan, results=tuple(results), limiter_state=limits)


def _append_drafts(store, adapter: SourceAdapter, drafts, *, tick_id: str,
                   now: float, connection=None) -> int:
    """Wrap drafts in kernel Evidence and append. Adapters never do this."""
    written = 0
    for draft in drafts:
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
            flags=dict(draft.flags),
            suppressed=draft.suppressed,
            suppress_reason=draft.suppress_reason,
            evidence_url=draft.evidence_url)
        if store.append_signal(observation, now=now, connection=connection):
            written += 1
    return written


__all__ = ["run_due", "execute_plan", "FetchPlan", "PlannedFetch",
           "SkippedFetch", "CycleResult", "AdapterResult",
           "NOT_DUE", "BREAKER_OPEN", "RATE_LIMITED", "DISABLED"]
