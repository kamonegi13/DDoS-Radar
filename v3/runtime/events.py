"""Which observations become escalation-chain events. Production's table.

`v3/scoring/sequence.py` is a complete state machine that had no input:
`ScoringInputs.arriving_events` defaulted to `()` and nothing ever set it,
so the chain could not advance, the chain bonus was structurally 0 and
`temporal_coherence_bonus` could never fire — with every test green,
because the kernel's own tests supply events directly (§7-2 #123). This
module is the supply, and it exists as a named layer so the omission
cannot recur silently: `ScoringInputs` now REQUIRES the field, so a caller
must decide what the arriving events are rather than inherit a default.

**CLAUDE.md §5 is the law transcribed here.** A sensor may not register a
sequence event; the scoring layer registers one only when `add_rat()`
returned True — FIRED and not muted / suppressed / noise-excluded
(`radar/routes/core.py:997`). `Observation.passes_gate()` IS that return
value, and it is deliberately not `admits()`: the gate has no score
condition, which is how `cf_botnet_overlap` gates a link while scoring 0.

**Who the event belongs to.** Production calls `_seq_fire(core_theater,
...)` (`core.py:573-588`), which resolves targets through
`resolve_seq_fire_targets(_original_core_theater, effective_cores, ...)`
(`radar/scoring.py:94-127`). For a scenario that declares `core_country`
the effective cores ARE `[core_country]`, and for a dual-core scenario
`_original_core_theater` is empty, so the third branch returns every
effective core: in both shapes the answer is the scenario's effective
cores. v3 reads them through `v3/runtime/chain.py::effective_cores`,
which transcribes the same `derive_country_context` rule.

**Which country's reading decides.** v3 registers an event for country C
from C's OWN observation — production's per-secondary blocks
(`select_secondary_ec_hits`, `core.py:1297-1304` and siblings) do exactly
this, and the primary block does it for the primary. What v3 does NOT
reproduce is production's spill: in a dual-core scenario the primary's
reading also registers against the secondary, because the guard that was
written to prevent it (`resolve_seq_fire_targets`' docstring: "Registering
for secondary would attach a false-provenance event to a chain whose
underlying sensor data was never inspected") is bypassed by its own
`if core_theater:` test, which is false in precisely the dual-core case.
Reproducing that would attach an event to a chain whose sensor data was
never inspected — the cross-attribution shape of the 2026-08-02
calibration failure. Registered as a difference rather than copied.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from v3.runtime import chain
from v3.scoring import Observation, Scenario
from v3.scoring.inputs import SequenceEvent


@dataclass(frozen=True, slots=True)
class Registration:
    """One row of production's registration table.

    `min_score` is how a ladder rung becomes a gate. OONI is the only
    case: the row FIRES at `is_censoring` (`core.py:1707`) but the event
    is registered on `_ooni_heavy` (`core.py:1710`), and heavy is exactly
    the rung that scores 2 in both systems (`core.py:1700` /
    `v3/adapters/cyber/ooni_censorship.py:123`). Reading the rung keeps
    the condition inside the Observation the kernel already has, instead
    of asking the event layer to re-open a payload.
    """

    event_type: str
    signal_source: str
    production_ref: str
    min_score: float = 0.0

    def admits(self, observation: Observation) -> bool:
        return (observation.passes_gate()
                and observation.score >= self.min_score)


@dataclass(frozen=True, slots=True)
class Absence:
    """An event type production registers and v3 cannot yet. Stated, not
    omitted: an absent link is invisible in a chain that scores by
    completeness, so the gap has to be readable from the code that has it.
    """

    event_type: str
    production_ref: str
    reason: str
    direction: str
    register_ref: str


#: The types the chain itself is made of (`radar/scoring.py:201`,
#: mirrored by `v3/scoring/thresholds.py::SEQUENCE_CHAIN_TYPES`). Named
#: here so `chain_coverage()` can say which of THEM are supplied — the
#: other event types reach only `temporal_coherence_bonus`.
NARRATIVE_BURST = "NARRATIVE_BURST"
ISR_SURGE = "ISR_SURGE"
SYNC_DDOS = "SYNC_DDOS"
FIRMS_ANOMALY = "FIRMS_ANOMALY"

REGISTRATIONS: tuple[Registration, ...] = (
    Registration(
        event_type=ISR_SURGE, signal_source="isr_hotspot",
        production_ref="radar/routes/core.py:1229-1232"),
    Registration(
        event_type=FIRMS_ANOMALY, signal_source="nasa_eonet",
        production_ref="radar/routes/core.py:1285-1288"),
    Registration(
        event_type="AIS_DARK_GAP", signal_source="ais_maritime",
        production_ref="radar/routes/core.py:1260-1263"),
    Registration(
        event_type="MIL_AIR_SURGE", signal_source="mil_support_air",
        production_ref="radar/routes/core.py:1780-1783"),
    Registration(
        event_type="GPS_JAMMING", signal_source="gps_jamming",
        production_ref="radar/routes/core.py:1819-1822"),
    Registration(
        event_type="CENSORSHIP_DETECTED", signal_source="ooni_censorship",
        production_ref="radar/routes/core.py:1710-1713", min_score=2.0),
)

ABSENCES: tuple[Absence, ...] = (
    Absence(
        event_type=NARRATIVE_BURST,
        production_ref="radar/routes/core.py:1214-1216 (rss_narrative), "
                       ":1360-1364 (telegram_mirror)",
        reason="both folds land OBSERVED — the burst z-score needs a "
               "30-day keyword-frequency baseline L1 does not yet hold "
               "(v3/runtime/reduce_info.py::_fold_named_sources), so no "
               "row ever passes the gate",
        direction="insensitive",
        register_ref="§7-2 #123 (residual), §7-2 #9/#11 family"),
    Absence(
        event_type=SYNC_DDOS,
        production_ref="radar/routes/core.py:1309-1319",
        reason="the gate is `is_coordinated and high_correlation and "
               "_coord_active and _overlap_active`; v3 emits "
               "cf_coordinated but has no cf_botnet_overlap and no IDF "
               "correlation at all",
        direction="insensitive",
        register_ref="§7-2 #122"),
    Absence(
        event_type="CENSORSHIP_DETECTED",
        production_ref="radar/routes/core.py:1602-1607 (tor_metrics + "
                       "ihr_disco)",
        reason="the composite needs ihr_health, which is disabled on BOTH "
               "sides (chronic HTTP 400 since 2026-Q1), so the link is "
               "absent from production too",
        direction="neutral",
        register_ref="parity-neutral: absent on both sides"),
    Absence(
        event_type="NOTAM_SURGE",
        production_ref="radar/routes/core.py:1644-1647",
        reason="the notam adapter is disabled on BOTH sides (upstream API "
               "withdrawn)",
        direction="neutral",
        register_ref="parity-neutral: absent on both sides"),
)

_BY_SOURCE: Mapping[str, Registration] = {
    entry.signal_source: entry for entry in REGISTRATIONS}

#: The only row names that can become an event. Exported so a caller
#: reading a whole retention window can drop the rest BEFORE projecting
#: them — a day of L1 is tens of thousands of rows and all but a handful
#: are irrelevant here.
SUPPLIED_SOURCES: frozenset = frozenset(_BY_SOURCE)


def eligible_countries(scenarios: Sequence[Scenario]) -> frozenset:
    """The countries a chain can be anchored to this tick.

    Production's `resolve_seq_fire_targets` answers the scenario's
    effective cores in every branch (see the module docstring), and
    `register_sequence_event` refuses an empty theatre outright
    (`radar/scoring.py:169-174`) rather than writing a row nothing can
    correlate later. A scenario that is not scorable contributes nothing,
    for the reason `score_tick` skips it.
    """
    return frozenset(
        country
        for scenario in scenarios if scenario.is_scorable
        for country in chain.effective_cores(scenario))


def arriving_from(observations: Sequence[Observation],
                  scenarios: Sequence[Scenario], *,
                  now: Optional[float] = None) -> tuple[SequenceEvent, ...]:
    """This tick's chain events. A pure function of what the tick saw.

    `occurred_at` is the OBSERVATION's own timestamp, not `now`. A row
    still in force across four ticks would otherwise mint a fresh event
    each time, and the chain's decay term reads exactly that timestamp —
    a stale reading would present as perpetually current and a 24 h chain
    would never age out. With the row's own stamp the repeats are
    identical values and `sequence.advance()`'s 300 s dedup collapses
    them, which is what production's `dedup_window` does for the same
    reason (`radar/scoring.py:160-168`).

    `now` is the fallback for a projection that carried no timestamp; it
    is required only in that case, and asking for it here keeps the
    decision at the caller rather than defaulting to a wall clock inside
    a function that must replay identically.
    """
    eligible = eligible_countries(scenarios)
    if not eligible:
        return ()
    events: list[SequenceEvent] = []
    for observation in observations:
        registration = _BY_SOURCE.get(observation.signal_source)
        if registration is None or not registration.admits(observation):
            continue
        occurred_at = observation.observed_at
        if occurred_at is None:
            if now is None:
                continue
            occurred_at = now
        for entry in observation.countries:
            if entry.country not in eligible:
                continue
            events.append(SequenceEvent(
                country=entry.country,
                event_type=registration.event_type,
                occurred_at=float(occurred_at),
                # The adapter id, because that is what the kernel's
                # `admitted_sensors` set is keyed by (`kernel.py:198-200`).
                justified_by=(observation.sensor,)))
    # Sorted so the dedup inside `advance()` sees a stable order: it keeps
    # the FIRST of a duplicate pair, and an unordered input would make
    # which one survives depend on the ledger's row order.
    return tuple(sorted(events, key=lambda event: (
        event.occurred_at, event.country, event.event_type)))


def chain_coverage() -> dict:
    """Which of the four chain links v3 can currently supply (AP3/NP6).

    Reported rather than assumed: with two of four supplied, `chain_bonus`
    cannot reach even its three-link partial tier, so the chain bonus
    stays 0 and only `temporal_coherence_bonus` becomes live. A fix that
    left this unsaid would read as "the chain works now".
    """
    from v3.scoring.thresholds import (SEQUENCE_CHAIN_TYPES,
                                       SEQUENCE_MIN_CHAIN)
    supplied = {entry.event_type for entry in REGISTRATIONS}
    present = tuple(name for name in SEQUENCE_CHAIN_TYPES if name in supplied)
    return {"chain_types": list(SEQUENCE_CHAIN_TYPES),
            "supplied": list(present),
            "missing": [name for name in SEQUENCE_CHAIN_TYPES
                        if name not in supplied],
            "minimum_for_a_bonus": SEQUENCE_MIN_CHAIN,
            "chain_bonus_reachable": len(present) >= SEQUENCE_MIN_CHAIN,
            "absences": [{"event_type": item.event_type,
                          "reason": item.reason,
                          "direction": item.direction,
                          "register_ref": item.register_ref,
                          "production_ref": item.production_ref}
                         for item in ABSENCES]}


__all__ = ["Registration", "Absence", "REGISTRATIONS", "ABSENCES",
           "SUPPLIED_SOURCES", "arriving_from", "eligible_countries",
           "chain_coverage",
           "NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY"]
