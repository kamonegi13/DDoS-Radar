"""What the tick actually had to work with, built from what happened.

L3's guards take `InputHealth` and nothing builds one — which is the
remaining half of G-17. In the legacy system a dead pipeline and a quiet
world were the same absence in the cache, so a tick where every source
failed published the same calm verdict as a tick where every source
answered "nothing here". The type that distinguishes them exists
(`v3/conclusions/availability.py`); this is where it gets its numbers.

Three counters, and the boundaries between them are the whole design:

    sources_ok      answered, and the answer is inside its freshness
                    horizon
    sources_failed  did not answer — HTTP error, timeout, breaker open,
                    a required credential that was never supplied
    sources_stale   answered at some point, but the newest observation is
                    older than the adapter's declared horizon

Staleness is separated from failure deliberately. A feed that has been
serving a cached body for six hours is failing in a way an HTTP status
cannot show, and folding it into `sources_ok` is exactly how B-03 read old
data as current. `Evidence` already refuses to be read past its horizon;
this counts the refusals rather than discovering them one at a time.

**WP-3.1's finding is the reason this must be truthful and not
convenient**: a tick where every source died but the threat level held
still has to WRITE, because the guard identity is part of the write
identity. If health is padded — if a skipped adapter quietly does not
count — the guard does not fire, the row is written as a normal
conclusion, and the outage becomes indistinguishable from calm in the
ledger that calibration later reads.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from v3.conclusions.availability import InputHealth
from v3.fetch import client as client_module
from v3.fetch import runner as runner_module
from v3.kernel.errors import DomainError
from v3.ledger import views

#: A skip reason that means the adapter produced nothing this tick and
#: SHOULD count against health. `NOT_DUE` is absent on purpose: a source
#: on a four-hour cadence is not a broken source at minute thirty, and
#: counting it would make every tick look degraded and every guard fire —
#: NP5+8's "permanent inability to conclude is a design failure".
COUNTED_SKIPS: frozenset = frozenset({
    runner_module.BREAKER_OPEN,
    runner_module.RATE_LIMITED,
    runner_module.UNRESOLVED,
})

#: Skips that mean "this source was never in scope for this tick".
UNCOUNTED_SKIPS: frozenset = frozenset({
    runner_module.NOT_DUE,
    runner_module.DISABLED,
})

#: G-19's skip, and it belongs in NEITHER set above without a second fact.
#:
#: A budget deferral costs the tick nothing WHEN the adapter already has an
#: observation inside its freshness horizon: scoring reads L1's in-force
#: projection at `now` (`v3/runtime/scoring.py::assemble`), not this tick's
#: rows, so a source deferred for one tick is still being scored from what
#: it said last time. Counting that as a failure would fire the coverage
#: guards on a healthy deployment and name working sources as broken.
#:
#: On a COLD ledger the same skip means the opposite. An adapter that has
#: never been fetched has nothing in the projection, contributes nothing,
#: and `stale_sources` cannot see it either — it only ages rows that EXIST
#: (`if newest is not None`). Left in `NOT_CONSULTED`, a first tick that
#: swept 40% of its sources would produce exactly the conclusions of one
#: that swept all of them. That is G-17's shape, so the deferral is
#: resolved against the ledger rather than assumed either way.
DEFERRED_SKIPS: frozenset = frozenset({runner_module.BUDGET_DEFERRED})


@dataclass(frozen=True, slots=True)
class SourceOutcome:
    """One adapter's contribution to the tick's health, with its reason.

    The reason is kept, not just the bucket. "cyber coverage degraded" is
    a verdict an analyst has to be able to open, and a set of adapter
    names with no causes attached is a verdict that cannot be opened.
    """

    adapter_id: str
    bucket: str
    detail: str = ""

    OK = "ok"
    FAILED = "failed"
    STALE = "stale"
    NOT_CONSULTED = "not_consulted"

    def __post_init__(self) -> None:
        if self.bucket not in (self.OK, self.FAILED, self.STALE,
                               self.NOT_CONSULTED):
            raise DomainError(f"unknown health bucket {self.bucket!r}")

    def as_dict(self) -> dict:
        return {"adapter_id": self.adapter_id, "bucket": self.bucket,
                "detail": self.detail}


def outcomes_for_cycle(cycle, *, credentials=None,
                       unobserved: Sequence[str] = ()
                       ) -> tuple[SourceOutcome, ...]:
    """Read one `CycleResult` into per-source verdicts.

    Both halves of the cycle are read. The results say what the adapters
    that RAN produced; the plan's `skipped` list says what did not run and
    why, and a source held shut by its own circuit breaker is a source
    that answered nothing — the fact B-01 made invisible by fetching
    around the breaker entirely.

    `unobserved` is the set of adapters L1 holds NO observation for at all
    (`never_observed`). It decides the one skip reason whose meaning
    depends on the ledger: a budget deferral (G-19) is free when the
    adapter's last reading is still in force and is total darkness when it
    has never had one. Supplied rather than looked up, because this
    function is otherwise a pure read of one cycle.
    """
    dark = frozenset(str(name) for name in unobserved)
    outcomes: list[SourceOutcome] = []
    for result in getattr(cycle, "results", ()):
        adapter_id = result.adapter_id.value
        if result.outcome == client_module.OK:
            outcomes.append(SourceOutcome(adapter_id, SourceOutcome.OK))
        else:
            outcomes.append(SourceOutcome(
                adapter_id, SourceOutcome.FAILED,
                result.detail or result.outcome))

    plan = getattr(cycle, "plan", None)
    for skipped in getattr(plan, "skipped", ()):
        adapter_id = skipped.adapter_id.value
        detail = f"{skipped.reason}: {skipped.detail}"
        if skipped.reason in DEFERRED_SKIPS:
            if adapter_id in dark:
                bucket = SourceOutcome.FAILED
                detail = (f"{detail} — and L1 holds no observation from this "
                          f"source at all, so nothing of it is in force")
            else:
                bucket = SourceOutcome.NOT_CONSULTED
                detail = (f"{detail} — its last reading is still in force, "
                          f"so this tick scored from it anyway")
        elif skipped.reason in COUNTED_SKIPS:
            bucket = SourceOutcome.FAILED
        else:
            bucket = SourceOutcome.NOT_CONSULTED
        outcomes.append(SourceOutcome(adapter_id, bucket, detail))

    if credentials is not None:
        # An adapter whose REQUIRED credential is missing never reaches a
        # socket, so it appears in neither list. Silence here would be the
        # tick reporting full health while a source is structurally dark.
        running = {o.adapter_id for o in outcomes}
        for posture in credentials.unsatisfied:
            if posture.adapter_id not in running:
                outcomes.append(SourceOutcome(
                    posture.adapter_id, SourceOutcome.FAILED,
                    f"required credential {posture.key_id} not supplied"))
    return tuple(outcomes)


def stale_sources(store, *, now: float, adapters: Iterable,
                  countries: Sequence[str] = ()) -> tuple[str, ...]:
    """Adapters whose newest observation is past its freshness horizon.

    Asked of the ledger rather than of the fetch results, because the two
    answer different questions. A fetch that succeeded five minutes ago
    proves the endpoint is up; whether the DATA it returned is current is
    the adapter's declared `freshness_horizon_sec`, and B-03 is what
    happens when a live endpoint serving a stale cache is counted as
    healthy.
    """
    stale: list[str] = []
    scope = tuple(countries) or ("GLOBAL",)
    for adapter in adapters:
        horizon = float(adapter.freshness_horizon_sec)
        newest: Optional[float] = None
        for country in scope:
            row = store.latest_signal_at(now, sensor=adapter.name,
                                         country=country)
            if row is None:
                continue
            observed = float(row["observed_at"])
            newest = observed if newest is None else max(newest, observed)
        if newest is not None and (now - newest) > horizon:
            stale.append(adapter.name)
    return tuple(sorted(set(stale)))


def never_observed(store, *, now: float, adapters: Iterable,
                   countries: Sequence[str] = ()) -> tuple[str, ...]:
    """Adapters L1 holds no observation from AT ALL. G-19's other half.

    `stale_sources` cannot answer this: it ages rows that exist and skips
    an adapter with none (`if newest is not None`), which is right for its
    own question and is exactly why a source that has never spoken is
    invisible to it. On a cold ledger that describes most of the catalogue,
    and a first tick that swept 40% of its sources would otherwise conclude
    with the same input health as one that swept all of them.

    The scope is this tick's participants **and GLOBAL**, not one or the
    other. `stale_sources` writes `tuple(countries) or ("GLOBAL",)`, so
    whenever a tick has participants — which is every real tick — it never
    looks at GLOBAL at all, and a countryless family (`apt_intel`,
    `cf_bgp_hijack`, every §7-2 #127 row) can never be reported stale.
    That is a real gap in the OTHER function and it is left alone here
    deliberately: closing it makes more sources unusable, which is a
    sensitivity change with its own direction and its own registration.
    Reproducing it here would have been worse than either — it would mark
    every countryless adapter permanently dark and fire the coverage guard
    on a healthy deployment forever.

    Each probe is an index seek on `idx_signal_obs_lookup`'s
    `(sensor, country)` prefix and `any()` stops at the first hit, so a
    warm ledger costs about one seek per adapter; the full 31 x 28 only
    happens while the ledger is genuinely empty.
    """
    dark: list[str] = []
    scope = tuple(countries) + ("GLOBAL",)
    for adapter in adapters:
        seen = any(store.latest_signal_at(now, sensor=adapter.name,
                                          country=country) is not None
                   for country in scope)
        if not seen:
            dark.append(adapter.name)
    return tuple(sorted(set(dark)))


def history_span_sec(store, scenario_id: str, *, now: float) -> float:
    """How long this scenario has been observed AT ALL.

    Derived from L1's TL stream rather than counted in a field somewhere
    (P6 O-16): a counter can be reset, and the calibration-window guard
    reads this number to decide whether it has enough history to conclude.
    """
    span = views.observed_span(store, scenario_id, now=now)
    return max(float(span.get("span_sec", 0.0) or 0.0), 0.0)


def build(outcomes: Sequence[SourceOutcome], *, stale: Sequence[str] = (),
          history_span: float = 0.0) -> InputHealth:
    """Assemble the record L3 reads. Pure.

    `stale` wins over `ok`: a source that answered with data older than
    its horizon answered, and what it said cannot be used. Reporting it in
    both places would inflate the healthy denominator, which `InputHealth`
    refuses outright — the direction that hides an outage.
    """
    stale_names = {str(name) for name in stale}
    ok, failed = [], []
    for outcome in outcomes:
        if outcome.bucket == SourceOutcome.NOT_CONSULTED:
            continue
        if outcome.adapter_id in stale_names:
            continue
        if outcome.bucket == SourceOutcome.OK:
            ok.append(outcome.adapter_id)
        else:
            failed.append(outcome.adapter_id)
    # A source cannot be healthy AND failed in the same tick. When both
    # appear (a chain whose fallback rescued one request and not another)
    # the unhealthy reading governs — NP1's asymmetry runs one way.
    ok = [name for name in ok if name not in set(failed)]
    return InputHealth(sources_ok=tuple(sorted(set(ok))),
                       sources_failed=tuple(sorted(set(failed))),
                       sources_stale=tuple(sorted(stale_names)),
                       history_span_sec=history_span)


def for_scenario(cycle, *, store, scenario_id: str, now: float,
                 adapters: Iterable, countries: Sequence[str] = (),
                 credentials=None) -> InputHealth:
    """The whole supply, in one call. The impure entry point."""
    adapters = tuple(adapters)
    return build(
        outcomes_for_cycle(
            cycle, credentials=credentials,
            unobserved=never_observed(store, now=now, adapters=adapters,
                                      countries=countries)),
        stale=stale_sources(store, now=now, adapters=adapters,
                            countries=countries),
        history_span=history_span_sec(store, scenario_id, now=now))


def sweep_coverage(cycle, *, unobserved: Sequence[str] = ()) -> dict:
    """How much of what this tick MEANT to fetch it actually fetched.

    G-19's disclosure. The budget makes a partial sweep a normal, expected
    state; what must never be normal is a partial sweep that reads like a
    complete one. `deferred` is what the budget held back and `dark` is the
    subset of those that L1 has never heard from at all — the second number
    is the one that says whether the tool is concluding from a sample of
    the world or from a sample of its own schedule.

    Counted over the adapters that were DUE, not over the whole catalogue:
    an adapter on a four-hour cadence is not missing from a sweep at minute
    thirty, and counting it would report every steady-state tick as
    partial, which is how a real alarm comes to be ignored.
    """
    plan = getattr(cycle, "plan", None)
    executed = tuple(getattr(cycle, "results", ()))
    deferred = tuple(item for item in getattr(plan, "skipped", ())
                     if item.reason in DEFERRED_SKIPS)
    dark = frozenset(str(name) for name in unobserved)
    deferred_ids = sorted(item.adapter_id.value for item in deferred)
    dark_ids = sorted(name for name in deferred_ids if name in dark)
    due = len(executed) + len(deferred_ids)
    return {
        "due": due,
        "fetched": len(executed),
        "deferred": deferred_ids,
        "deferred_never_observed": dark_ids,
        "complete": not deferred_ids,
        "coverage": 1.0 if not due else round(len(executed) / due, 3),
    }


def disclosure(outcomes: Sequence[SourceOutcome]) -> list[dict]:
    """Every source and why it counted as it did (NP6/AP2)."""
    return [outcome.as_dict() for outcome in outcomes]


__all__ = ["SourceOutcome", "COUNTED_SKIPS", "UNCOUNTED_SKIPS",
           "DEFERRED_SKIPS",
           "outcomes_for_cycle", "stale_sources", "never_observed",
           "history_span_sec", "build", "for_scenario", "disclosure",
           "sweep_coverage"]
