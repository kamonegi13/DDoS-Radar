"""Who owns a scenario's escalation chain THIS tick. Production's own rule.

`ScoringInputs.chain_country_for` is supplied, never derived, and the
reason is in its docstring: production picks a dual-core scenario's chain
owner by LIVE spike — "whichever belligerent is currently escalating" —
so any static rule picks the same country forever, which is wrong for
exactly the scenario that motivates the field (middle_east has IL and IR
both at weight 1.0).

WP-4.4 wired the tick, hit the raise, and registered an environment
constant (`NOROSHI_V3_CHAIN_COUNTRIES`) as the mitigation. **That was the
same defect with an operator's name on it.** A configured constant is
static; substituting one for a live measurement reproduces precisely the
failure the ruling forbade. This module is the repair: the orchestrator
holds the tick's observations, so the orchestrator performs production's
selection and hands the answer to the kernel. The kernel stays pure.

Two steps, transcribed from two places, AST-verified in
`tests/test_runtime_chain_owner.py`:

  1. **the core list is static and IS derivable** — `radar/scenarios.py::
     derive_country_context` (:585-593). A declared `core_country` is the
     whole list; otherwise the PRINCIPAL_BELLIGERENT participants at or
     above weight 0.9, SORTED. This is a declaration being read, not the
     owner being guessed.
  2. **the owner is the live maximum** — `radar/routes/core.py:878-881`,
     `max(effective_cores, key=avg_spike)`. `max` returns the FIRST
     maximal element, and production's list is alphabetically sorted, so
     a tie resolves alphabetically. Reproduced exactly, because a tie is
     the ordinary state of a quiet tick.

**The ordering quantity is production's now, and where it is not, the row
says so.** Production ranks by `avg_spike` (`core.py:817`), computed from
the per-target ATTACK ORIGIN distribution (`core.py:748-749`) against a
baseline-window distribution (`core.py:740-741`; the window is
`BASELINE_DATE_RANGE` = 28 days, not the 90 the register recorded). §7-2
#116 registered that v3 ranked by something else, and the obstacle it
named was not derivation but ACQUISITION: `CLOUDFLARE_RADAR_ADAPTER`
declared four requests and none was the origin endpoint. It declares
them now, `v3/runtime/spike.py` computes the ratio, and the composition
root reads the resulting `cf_spike_target` rows and hands them here. That
row rather than `cf_spike_core`: the entry is countryless since §7-2
#118's retirement, exactly as production's is, so the per-country
quantity lives on the measurement face that mirrors `target_details`.

**The stand-in survives, narrowed, for the tick where the measurement does
not exist** — a fresh deployment, or a cycle where every core's fetch
failed. It is the sum of this tick's ADMITTED evidence naming the
country, using the kernel's own `admits()` predicate rather than a new
one, and unweighted by coupling weight because `avg_spike` is unweighted
too. Production's own answer in that situation is degenerate (every core
defaults to 0 and `max` returns the alphabetically first), so the
fallback is chosen for NP1: more evidence beats alphabetical order.

**Which quantity ranked which scenario is published** (`rankings`). NP6
is about the derivation, and "IR owns the chain" derived from a measured
spike and derived from a warm-up fallback are two different claims that
must not print the same.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from v3.kernel import Ratio
from v3.scoring import Observation, Scenario

#: `radar/scenarios.py:589` — `p.role == Role.PRINCIPAL_BELLIGERENT`. The
#: string, not an enum: v3 reads roles out of `geo_data.json`, which is
#: where production's enum gets its values from too.
PRINCIPAL_BELLIGERENT = "principal_belligerent"
#: `radar/scenarios.py:590` — `p.weight >= 0.9`.
CORE_WEIGHT_FLOOR = 0.9

#: The two quantities a ranking can be made of, and where each comes from.
BASIS_AVG_SPIKE = "avg_spike"
BASIS_ADMITTED_EVIDENCE = "admitted_evidence"
BASIS_PRODUCTION_REF: Mapping[str, str] = {
    BASIS_AVG_SPIKE: ("radar/routes/core.py:817 (avg_spike) / :878-881 "
                      "(max over effective_cores)"),
    BASIS_ADMITTED_EVIDENCE: ("§7-2 #116 — v3 stand-in: the sum of this "
                              "tick's admitted evidence naming the country, "
                              "used only when no core has a measured "
                              "avg_spike"),
}


@dataclass(frozen=True, slots=True)
class ChainRanking:
    """Who owns the chain, by what quantity, with every candidate's value.

    The values are carried, not just the winner: a ranking that publishes
    only its answer cannot be argued with, and the focused bonus reads a
    different escalation chain depending on this one string.
    """

    scenario_id: str
    owner: str
    basis: str
    values: Mapping[str, float]

    def as_dict(self) -> dict:
        return {"owner": self.owner, "basis": self.basis,
                "values": dict(self.values),
                "production_ref": BASIS_PRODUCTION_REF[self.basis]}


def effective_cores(scenario: Scenario) -> tuple[str, ...]:
    """The scenario's scoring cores. `derive_country_context`, transcribed.

    Sorted, because production sorts — and because the sort order IS the
    tie-break that `max` then applies.
    """
    if scenario.core_country:
        return (scenario.core_country,)
    floor = Ratio(CORE_WEIGHT_FLOOR)
    return tuple(sorted(
        participant.country for participant in scenario.participants
        if participant.role == PRINCIPAL_BELLIGERENT
        and participant.weight >= floor))


def admitted_evidence(observations: Sequence[Observation],
                      country: str) -> float:
    """The fallback quantity: this tick's admitted score naming a country.

    `admits()` is the kernel's own "does this reading contribute score"
    predicate — reusing it means the ranking cannot admit evidence the
    score itself would refuse.
    """
    wanted = country.upper()
    return sum(observation.score for observation in observations
               if observation.admits()
               and any(entry.country == wanted
                       for entry in observation.countries))


def escalation_intensity(observations: Sequence[Observation], country: str, *,
                         spikes: Optional[Mapping[str, float]] = None
                         ) -> float:
    """How hard this country is being hit, by whichever quantity applies.

    A supplied, non-empty `spikes` mapping IS the quantity — production's
    `avg_spike`, measured this tick. A country missing from it scores 0.0,
    which is production's own default for the same lookup
    (`target_details.get(ec, {}).get('avg_spike', 0)`), NOT a silent
    switch to the other quantity: mixing a spike ratio with a score sum
    inside one comparison would rank two countries on different scales.
    """
    if spikes:
        return float(spikes.get(country.upper(), 0.0))
    return admitted_evidence(observations, country)


def ranking_for(scenario: Scenario, observations: Sequence[Observation],
                spikes: Optional[Mapping[str, float]] = None
                ) -> Optional[ChainRanking]:
    """This scenario's ranking, or None when it has no candidate at all.

    The basis is decided per SCENARIO, over its own cores: a spike
    mapping that happens to hold some other scenario's country says
    nothing about this one, and using it would rank every core here at
    production's 0.0 default — which resolves alphabetically and is
    exactly the static answer the WP-4.4 ruling forbade.
    """
    cores = effective_cores(scenario)
    if not cores:
        return None
    measured = {core: float(spikes[core]) for core in cores
                if spikes and core in spikes}
    basis = BASIS_AVG_SPIKE if measured else BASIS_ADMITTED_EVIDENCE
    if measured:
        values = {core: measured.get(core, 0.0) for core in cores}
    else:
        values = {core: admitted_evidence(observations, core)
                  for core in cores}
    # `max` returns the FIRST maximal element and `cores` is sorted, so a
    # tie resolves alphabetically — production's rule, and a tie is the
    # ordinary state of a quiet tick.
    return ChainRanking(scenario_id=scenario.scenario_id,
                        owner=max(cores, key=lambda core: values[core]),
                        basis=basis, values=values)


def chain_owner(scenario: Scenario, observations: Sequence[Observation],
                spikes: Optional[Mapping[str, float]] = None) -> str:
    """`primary_ec`, for this scenario, at this tick. `""` when undecidable.

    Empty means the scenario declares no core country AND has no
    principal belligerent at the weight floor — a structural gap in the
    geography, not a missing measurement, so it is announced at
    composition rather than papered over here.
    """
    ranking = ranking_for(scenario, observations, spikes)
    return ranking.owner if ranking else ""


def chain_owners(scenarios: Sequence[Scenario],
                 observations: Sequence[Observation],
                 spikes: Optional[Mapping[str, float]] = None
                 ) -> dict[str, str]:
    """One owner per scenario that has one. THE mapping the kernel wants.

    Scenarios with no decidable owner are ABSENT rather than empty:
    `chain_country_for` raises for them with a message that says why, and
    an empty string smuggled in as an owner would make the bonus fold
    read a chain nobody owns.
    """
    return {scenario_id: row["owner"] for scenario_id, row
            in rankings(scenarios, observations, spikes).items()}


def rankings(scenarios: Sequence[Scenario],
             observations: Sequence[Observation],
             spikes: Optional[Mapping[str, float]] = None) -> dict[str, dict]:
    """Every decidable scenario's ranking, WITH the quantity used (NP6)."""
    disclosed: dict[str, dict] = {}
    for scenario in scenarios:
        ranking = ranking_for(scenario, observations, spikes)
        if ranking is not None and ranking.owner:
            disclosed[scenario.scenario_id] = ranking.as_dict()
    return disclosed


def scenarios_without_cores(scenarios: Sequence[Scenario]) -> tuple[str, ...]:
    """Scenarios no measurement can give an owner. For the announcement."""
    return tuple(scenario.scenario_id for scenario in scenarios
                 if not effective_cores(scenario))


__all__ = ["effective_cores", "escalation_intensity", "admitted_evidence",
           "ranking_for", "rankings", "chain_owner", "chain_owners",
           "scenarios_without_cores", "ChainRanking",
           "PRINCIPAL_BELLIGERENT", "CORE_WEIGHT_FLOOR", "BASIS_AVG_SPIKE",
           "BASIS_ADMITTED_EVIDENCE", "BASIS_PRODUCTION_REF"]
