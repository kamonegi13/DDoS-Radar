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


def outcomes_for_cycle(cycle, *, credentials=None) -> tuple[SourceOutcome, ...]:
    """Read one `CycleResult` into per-source verdicts.

    Both halves of the cycle are read. The results say what the adapters
    that RAN produced; the plan's `skipped` list says what did not run and
    why, and a source held shut by its own circuit breaker is a source
    that answered nothing — the fact B-01 made invisible by fetching
    around the breaker entirely.
    """
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
        bucket = SourceOutcome.FAILED if skipped.reason in COUNTED_SKIPS \
            else SourceOutcome.NOT_CONSULTED
        outcomes.append(SourceOutcome(
            adapter_id, bucket, f"{skipped.reason}: {skipped.detail}"))

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
        outcomes_for_cycle(cycle, credentials=credentials),
        stale=stale_sources(store, now=now, adapters=adapters,
                            countries=countries),
        history_span=history_span_sec(store, scenario_id, now=now))


def disclosure(outcomes: Sequence[SourceOutcome]) -> list[dict]:
    """Every source and why it counted as it did (NP6/AP2)."""
    return [outcome.as_dict() for outcome in outcomes]


__all__ = ["SourceOutcome", "COUNTED_SKIPS", "UNCOUNTED_SKIPS",
           "outcomes_for_cycle", "stale_sources", "history_span_sec",
           "build", "for_scenario", "disclosure"]
