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

**Two shapes, because production has two.** Most registrations read ONE
row and anchor the event to the country that row is about. `SYNC_DDOS`
does not: its gate is a CONJUNCTION of two countryless verdicts
(`core.py:1309` — `is_coordinated and high_correlation and _coord_active
and _overlap_active`, which is `cf_coordinated` and `cf_botnet_overlap`
each having fired unmuted, since `_overlap_active` already implies
`high_correlation` and `_coord_active` implies `is_coordinated`), and it
fires `scenario_wide=True` so `resolve_seq_fire_targets` returns every
effective core rather than one country (`radar/scoring.py:117-124`). A
countryless row anchors nothing through the per-country path — it has no
`countries` at all — so transcribing this link as a `Registration` would
have produced a rule that is present, tested, and permanently silent.

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
from typing import Container, Mapping, Optional, Sequence

from v3.runtime import attribution, chain
from v3.runtime.reduce_cyber import (BOTNET_OVERLAP_SIGNAL,
                                     COORDINATED_SIGNAL)
from v3.scoring import Observation, Scenario
from v3.scoring.inputs import SequenceEvent


@dataclass(frozen=True, slots=True)
class Registration:
    """One row of production's registration table.

    `min_score` is how a ladder rung becomes a gate, and no registration
    uses it any more. OONI was the one case — the row FIRES at
    `is_censoring` (`core.py:1707`) while the event is registered on
    `_ooni_heavy` (`core.py:1710`), the rung that scores 2 — and §7-2 #127
    moved that score off the per-country row onto the countryless one
    (`v3/runtime/attribution.py`), which left the rung unreadable here:
    `Observation` carries no `flags`. The rung is now a row of its own
    (`attribution.OONI_HEAVY`), FIRED with score 0, emitted only where the
    reading was heavy AND the source row passed the gate — production's
    two conditions, restated where the kernel can see them. `min_score`
    stays on this type because the next graded registration will need it
    and deleting it would hide that the question exists.
    """

    event_type: str
    signal_source: str
    production_ref: str
    min_score: float = 0.0

    def admits(self, observation: Observation) -> bool:
        return (observation.passes_gate()
                and observation.score >= self.min_score)


@dataclass(frozen=True, slots=True)
class Conjunction:
    """An event production registers from SEVERAL rows at once.

    `signal_sources` are all required, all in the SAME tick, and each on
    the same predicate a `Registration` uses — `passes_gate()`, which is
    `add_rat`'s return value (`radar/routes/core.py:997`). Nothing here
    reads a score: `cf_botnet_overlap` scores 0 across the whole marginal
    IDF band and still opens this link, which is precisely the property
    `admits()` would have deleted.

    The event is anchored to every eligible country rather than to one,
    because production fires it `scenario_wide=True`
    (`radar/routes/core.py:1319`) and `resolve_seq_fire_targets` then
    returns every effective core: coordinated cross-theatre DDoS is a
    statement about the theatre, not about one belligerent.
    """

    event_type: str
    signal_sources: tuple[str, ...]
    production_ref: str
    gate_ref: str

    def admits(self, passing: Container[str]) -> bool:
        return all(name in passing for name in self.signal_sources)


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
        event_type="CENSORSHIP_DETECTED",
        signal_source=attribution.OONI_HEAVY,
        production_ref="radar/routes/core.py:1710-1713"),
)

#: §7-2 #122. The gate at `core.py:1309` has four conjuncts and reduces
#: to two: `_overlap_active` is `add_rat("cf_botnet_overlap", ...,
#: "FIRED" if high_correlation else "OK", ...)`'s return, so it already
#: carries `high_correlation`, and `_coord_active` likewise carries
#: `is_coordinated`. Both are the gate-passing facts of the two rows the
#: cloudflare fold now emits, so the two-source form is the four-conjunct
#: form, not an approximation of it.
CONJUNCTIONS: tuple[Conjunction, ...] = (
    Conjunction(
        event_type=SYNC_DDOS,
        signal_sources=(COORDINATED_SIGNAL, BOTNET_OVERLAP_SIGNAL),
        production_ref="radar/routes/core.py:1308-1319",
        gate_ref="radar/routes/core.py:1309"),
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

#: Every name a conjunction reads. Derived from `CONJUNCTIONS` rather than
#: listed, so adding a conjunction cannot leave its inputs filtered out of
#: `sequence_history` — which would make the link work live and vanish on
#: the next tick, the hardest shape of this defect to see.
_CONJUNCTION_SOURCES: frozenset = frozenset(
    name for entry in CONJUNCTIONS for name in entry.signal_sources)

#: The only row names that can become an event. Exported so a caller
#: reading a whole retention window can drop the rest BEFORE projecting
#: them — a day of L1 is tens of thousands of rows and all but a handful
#: are irrelevant here.
SUPPLIED_SOURCES: frozenset = frozenset(_BY_SOURCE) | _CONJUNCTION_SOURCES


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
        occurred_at = _stamp(observation, now)
        if occurred_at is None:
            continue
        for entry in observation.countries:
            if entry.country not in eligible:
                continue
            events.append(SequenceEvent(
                country=entry.country,
                event_type=registration.event_type,
                occurred_at=occurred_at,
                # The adapter id, because that is what the kernel's
                # `admitted_sensors` set is keyed by (`kernel.py:198-200`).
                justified_by=(observation.sensor,)))
    events.extend(_conjunction_events(observations, eligible, now))
    # Sorted so the dedup inside `advance()` sees a stable order: it keeps
    # the FIRST of a duplicate pair, and an unordered input would make
    # which one survives depend on the ledger's row order.
    return tuple(sorted(events, key=lambda event: (
        event.occurred_at, event.country, event.event_type)))


def _stamp(observation: Observation, now: Optional[float]) -> Optional[float]:
    """The observation's own timestamp, or `now` if it carried none."""
    if observation.observed_at is not None:
        return float(observation.observed_at)
    return None if now is None else float(now)


def _conjunction_events(observations: Sequence[Observation],
                        eligible: frozenset,
                        now: Optional[float]) -> list[SequenceEvent]:
    """Events whose gate reads several rows of the SAME tick.

    **Grouped by `observed_at`, and that is not a heuristic.** Every draft
    a cycle writes is stamped with the one `now` the cycle started from
    (`v3/fetch/runner.py:562`), so rows of one tick share the value
    exactly and rows of different ticks never do. Without the grouping,
    `sequence_history` — which hands a whole retention window to this
    function in one call — would conjoin a `cf_coordinated` from Monday
    with a `cf_botnet_overlap` from Tuesday and mint a SYNC_DDOS
    production never fired. That is the sensitive direction, which is
    exactly why it has to be refused: an invented link is indistinguishable
    from an observed one once it is in the chain.

    The anchor set is every eligible country, not one. Production's is the
    FOCUSED scenario's effective cores; v3 has no focused scenario and
    scores every scorable one from a single acquisition, so the union is
    what exists — the §7-2 #124 widening, in the sensitive direction, and
    consistent with the rows themselves being computed over the union.
    """
    if not CONJUNCTIONS:
        return []
    by_tick: dict[float, dict[str, str]] = {}
    for observation in observations:
        if observation.signal_source not in _CONJUNCTION_SOURCES:
            continue
        if not observation.passes_gate():
            continue
        occurred_at = _stamp(observation, now)
        if occurred_at is None:
            continue
        by_tick.setdefault(occurred_at, {}).setdefault(
            observation.signal_source, observation.sensor)
    events: list[SequenceEvent] = []
    for occurred_at, passing in by_tick.items():
        for conjunction in CONJUNCTIONS:
            if not conjunction.admits(passing):
                continue
            justified = tuple(sorted({passing[name] for name
                                      in conjunction.signal_sources}))
            for country in sorted(eligible):
                events.append(SequenceEvent(
                    country=country, event_type=conjunction.event_type,
                    occurred_at=occurred_at, justified_by=justified))
    return events


def chain_coverage() -> dict:
    """Which of the four chain links v3 can currently supply (AP3/NP6).

    Reported rather than assumed. With §7-2 #122 landed this reaches
    THREE of four, which is `SEQUENCE_MIN_CHAIN`, so `chain_bonus` becomes
    structurally reachable for the first time — a change of kind, not of
    degree, and one a reader must be able to see without diffing this
    module. The remaining absence (`NARRATIVE_BURST`) is what still keeps
    the FULL tier out of reach, and it is still stated.
    """
    from v3.scoring.thresholds import (SEQUENCE_CHAIN_TYPES,
                                       SEQUENCE_MIN_CHAIN)
    supplied = ({entry.event_type for entry in REGISTRATIONS}
                | {entry.event_type for entry in CONJUNCTIONS})
    present = tuple(name for name in SEQUENCE_CHAIN_TYPES if name in supplied)
    return {"chain_types": list(SEQUENCE_CHAIN_TYPES),
            "supplied": list(present),
            "missing": [name for name in SEQUENCE_CHAIN_TYPES
                        if name not in supplied],
            "minimum_for_a_bonus": SEQUENCE_MIN_CHAIN,
            "chain_bonus_reachable": len(present) >= SEQUENCE_MIN_CHAIN,
            "conjunctions": [{"event_type": item.event_type,
                              "signal_sources": list(item.signal_sources),
                              "gate_ref": item.gate_ref,
                              "production_ref": item.production_ref}
                             for item in CONJUNCTIONS],
            "absences": [{"event_type": item.event_type,
                          "reason": item.reason,
                          "direction": item.direction,
                          "register_ref": item.register_ref,
                          "production_ref": item.production_ref}
                         for item in ABSENCES]}


__all__ = ["Registration", "Conjunction", "Absence", "REGISTRATIONS",
           "CONJUNCTIONS", "ABSENCES",
           "SUPPLIED_SOURCES", "arriving_from", "eligible_countries",
           "chain_coverage",
           "NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY"]
