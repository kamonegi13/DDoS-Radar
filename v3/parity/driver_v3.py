"""Replaying the v3 side: ledger rows through the real scoring kernel.

Entirely in-process, because the v3 kernel is pure — no database handle, no
clock, no configuration read at tick time (WP-2.4). Replaying it is
therefore just calling it, which is the property the whole parity exercise
depends on: S5-VERIF-019 requires a tick to be idempotent, and here that
is structural rather than aspirational.

Path-dependent state (hysteresis, the sequence chain) is threaded forward
explicitly via `TickResult.next_prior_state()`, satisfying S5-VERIF-020 —
the run starts from a stated point and never consults live production
state.

Nothing is written. The store is read through `LedgerStore`'s read-only
connection, and results are returned as values (S5-VERIF-021).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from v3.intel import adjudication as INTEL
from v3.ledger import LedgerStore
from v3.runtime import chain as CHAIN
from v3.parity.adapter import LedgerInputAdapter, to_v3_observations
from v3.parity.compare import THREAT_LEVEL, Contributor, Reading, TickKey
from v3.scoring import (PriorState, Scenario, ScoringInputs, ScoringSettings,
                        score_tick)
from v3.scoring.kernel import FORMULA_REF as V3_FORMULA_REF


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """One side's full output over a window."""

    readings: Mapping[TickKey, Reading]
    tl_series: Mapping[str, tuple]
    formula_ref: str
    thresholds: Mapping[str, object]

    def series_for(self, scenario_id: str) -> tuple:
        return self.tl_series.get(scenario_id, ())


def replay(store: LedgerStore, scenarios: Sequence[Scenario], *,
           start: float, end: float,
           tick_interval_sec: float,
           settings: Optional[ScoringSettings] = None,
           focused_scenario_id: Optional[str] = None,
           initial_prior: Optional[PriorState] = None) -> ReplayResult:
    """Score every tick in the window and collect the readings.

    `settings` is passed in rather than resolved, so a replay cannot be
    perturbed by a registry change between runs — the same reason the
    kernel takes them as an argument at all (P6 O-18).

    The sequence chain's owner is the one thing that must NOT be pinned
    per run: production selects it from each tick's own spike, so a
    replay that carried one country for the whole window would measure a
    system nobody runs. It is recomputed per tick from that tick's rows,
    through the same rule the live tick uses (§7-2 #115).
    """
    effective = settings or ScoringSettings()
    adapter = LedgerInputAdapter(store, tick_interval_sec=tick_interval_sec)
    focused = focused_scenario_id or (
        scenarios[0].scenario_id if scenarios else None)

    readings: dict[TickKey, Reading] = {}
    series: dict[str, list] = {s.scenario_id: [] for s in scenarios}
    prior = initial_prior or PriorState()

    for tick in adapter.ticks(start, end):
        # The SAME predicate the live tick applies (§7-2 #105): intel
        # scores only in an adjudicated state. A parity run that admitted
        # rows the tick would not would be measuring agreement for a system
        # nobody runs, and the extra rows would sit in the disagreement
        # column making the differences that matter harder to see.
        observations = to_v3_observations(
            INTEL.scoreable_rows(store, tick.rows, until=tick.tick_ts))
        result = score_tick(ScoringInputs(
            now=tick.tick_ts,
            observations=observations,
            scenarios=tuple(scenarios),
            settings=effective,
            focused_scenario_id=focused,
            prior=prior,
            chain_countries=CHAIN.chain_owners(scenarios, observations),
        ))
        for scenario_id, scored in result.results.items():
            reading = Reading(
                threat_level=scored.threat_level,
                state=f"TL{scored.threat_level.value}",
                contributing=tuple(
                    Contributor(c.sensor, c.signal_source, c.country)
                    for c in scored.contributions))
            readings[TickKey(scenario_id, THREAT_LEVEL, tick.tick_ts)] = reading
            series.setdefault(scenario_id, []).append(
                (tick.tick_ts, reading))
        prior = result.next_prior_state()

    return ReplayResult(
        readings=readings,
        tl_series={key: tuple(value) for key, value in series.items()},
        formula_ref=V3_FORMULA_REF,
        thresholds=effective.disclosed())


def null_zone_seconds(series: Iterable[tuple], *,
                      tick_interval_sec: float) -> float:
    """Longest run of ticks with no conclusion (C-09).

    Measured in wall time rather than tick count so the two systems stay
    comparable if they are ever replayed at different cadences.
    """
    longest = 0.0
    current = 0.0
    for _, reading in sorted(series, key=lambda pair: pair[0]):
        if reading.threat_level is None:
            current += tick_interval_sec
            longest = max(longest, current)
        else:
            current = 0.0
    return longest


__all__ = ["replay", "ReplayResult", "null_zone_seconds"]
