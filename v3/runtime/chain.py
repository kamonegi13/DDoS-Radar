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

**The registered difference is the ordering quantity, and it is forced.**
Production ranks by `avg_spike` (`core.py:817`), computed from the
per-target ATTACK ORIGIN distribution (`core.py:747-748`) against a
90-day origin baseline (`core.py:741-742`). v3 does not compute it — §7-2
#9 records that, and S1-SCORE-025/029/030 are excluded from L2 as
derived-observation producers — but the harder fact is that v3 never
FETCHES it: `CLOUDFLARE_RADAR_ADAPTER` declares four requests and none is
`attacks/layer{3,7}/top/locations/origin`. So this is not a wiring gap L1
could close; the input is not in the ledger at all.

The stand-in is the smallest honest thing that is still a live
measurement: **the sum of this tick's ADMITTED evidence naming the
country**, using the kernel's own `admits()` predicate rather than a new
one, and unweighted by coupling weight because `avg_spike` is unweighted
too. Direction of the difference: v3 reads all three domains where
production reads a cyber DDoS spike, so v3 can select a belligerent
production would not when the escalation is visible outside cyber. That
direction favours recall (NP1) and it is registered in §7-2 as #116.
"""
from __future__ import annotations

from typing import Sequence

from v3.kernel import Ratio
from v3.scoring import Observation, Scenario

#: `radar/scenarios.py:589` — `p.role == Role.PRINCIPAL_BELLIGERENT`. The
#: string, not an enum: v3 reads roles out of `geo_data.json`, which is
#: where production's enum gets its values from too.
PRINCIPAL_BELLIGERENT = "principal_belligerent"
#: `radar/scenarios.py:590` — `p.weight >= 0.9`.
CORE_WEIGHT_FLOOR = 0.9


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


def escalation_intensity(observations: Sequence[Observation],
                         country: str) -> float:
    """How hard this country is being hit, from THIS tick's readings.

    The stand-in for `avg_spike` (see the module docstring for why one is
    needed and what the difference costs). `admits()` is the kernel's own
    "does this reading contribute score" predicate — reusing it means the
    ranking cannot admit evidence the score itself would refuse.

    A country with no reading scores 0.0, which is production's default
    for the same lookup (`target_details.get(ec, {}).get('avg_spike', 0)`).
    """
    wanted = country.upper()
    return sum(observation.score for observation in observations
               if observation.admits()
               and any(entry.country == wanted
                       for entry in observation.countries))


def chain_owner(scenario: Scenario,
                observations: Sequence[Observation]) -> str:
    """`primary_ec`, for this scenario, at this tick. `""` when undecidable.

    Empty means the scenario declares no core country AND has no
    principal belligerent at the weight floor — a structural gap in the
    geography, not a missing measurement, so it is announced at
    composition rather than papered over here.
    """
    cores = effective_cores(scenario)
    if not cores:
        return ""
    return max(cores, key=lambda core: escalation_intensity(observations,
                                                            core))


def chain_owners(scenarios: Sequence[Scenario],
                 observations: Sequence[Observation]) -> dict[str, str]:
    """One owner per scenario that has one. THE mapping the kernel wants.

    Scenarios with no decidable owner are ABSENT rather than empty:
    `chain_country_for` raises for them with a message that says why, and
    an empty string smuggled in as an owner would make the bonus fold
    read a chain nobody owns.
    """
    owners: dict[str, str] = {}
    for scenario in scenarios:
        owner = chain_owner(scenario, observations)
        if owner:
            owners[scenario.scenario_id] = owner
    return owners


def scenarios_without_cores(scenarios: Sequence[Scenario]) -> tuple[str, ...]:
    """Scenarios no measurement can give an owner. For the announcement."""
    return tuple(scenario.scenario_id for scenario in scenarios
                 if not effective_cores(scenario))


__all__ = ["effective_cores", "escalation_intensity", "chain_owner",
           "chain_owners", "scenarios_without_cores",
           "PRINCIPAL_BELLIGERENT", "CORE_WEIGHT_FLOOR"]
