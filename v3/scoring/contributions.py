"""From observations to the weighted contributions a scenario is scored on.

This is the effective path P6 O-14 selected: the scenario formula family
(`radar/scoring.py:1446-1533`). Each admitted observation is projected onto
the scenario's participants, weighted twice, de-duplicated per
(signal_source, country), and summed per domain under a cap.

The two weights are separate on purpose (S1-SCORE-009):

    llm_country_weight    how strongly the source attributed the event to
                          this country. 1.0 for an ordinary sensor.
    participant_weight    how strongly this country couples to the
                          scenario.

Multiplying them in one step would make a diluted attribution and a weakly
coupled participant indistinguishable in the trace, and the trace is what
NP6 publishes.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping

from v3.kernel import Ratio
from v3.kernel.errors import DomainError
from v3.scoring.inputs import (DOMAINS, Observation, Scenario)

GLOBAL_COUNTRY = "GLOBAL"
GLOBAL_ROLE = "global"


@dataclass(frozen=True, slots=True)
class Contribution:
    """One observation's weighted contribution to one scenario.

    `trace` is the human-auditable derivation NP6 requires at its smallest
    unit — the exact string S1-SCORE-009 pins, two decimals throughout.
    """

    sensor: str
    signal_source: str
    domain: str
    country: str
    role: str
    raw_score: float
    llm_country_weight: float
    participant_weight: float
    score: float
    trace: str

    @property
    def dedup_key(self) -> tuple[str, str]:
        """S1-SCORE-008 folds on (signal_source, country)."""
        return (self.signal_source, self.country)

    def as_dict(self) -> dict:
        return {
            "sensor": self.sensor,
            "signal_source": self.signal_source,
            "domain": self.domain,
            "country": self.country,
            "role": self.role,
            "raw_score": self.raw_score,
            "llm_country_weight": self.llm_country_weight,
            "participant_weight": self.participant_weight,
            "score": self.score,
            "trace": self.trace,
        }


def _trace(raw: float, llm_weight: float, participant_weight: float,
           country: str, final: float) -> str:
    return (f"{raw:.2f} (raw) "
            f"× {llm_weight:.2f} (llm:{country}) "
            f"× {participant_weight:.2f} (participant:{country}) "
            f"= {final:.2f}")


def _global_trace(raw: float, weight: float, final: float) -> str:
    return (f"{raw:.2f} (raw) × {weight:.2f} (global) = {final:.2f}")


def _passes_primary_filter(llm_weight: float, max_weight: float,
                           *, enabled: bool, threshold: Ratio) -> bool:
    """S1-SCORE-014: keep only countries at or above the primary ratio.

    The comparison is `>=`, so a country sitting exactly on the threshold
    is kept — pinned by
    tests/test_scenario_scoring.py::TestLlmIntelPrimaryCountry.

    A single-country sensor signal has llm_weight == max_weight, so the
    ratio is 1.0 and the filter is transparent to it.

    The quotient is wrapped as a `Ratio` before comparing, so the check is
    Ratio-against-Ratio rather than float-against-float. `max_weight` is
    the maximum, so the quotient is always within [0, 1] and the wrap
    cannot fail — it is there to keep the comparison unit-safe, which is
    the F-08 defence the kernel discipline gate enforces.
    """
    if not enabled or max_weight <= 0:
        return True
    return Ratio(llm_weight / max_weight) >= threshold


def build_contributions(observations: Iterable[Observation],
                        scenario: Scenario,
                        *, settings) -> tuple[Contribution, ...]:
    """Project admitted observations onto one scenario's participants.

    Clauses realised here:
      S1-SCORE-009  score = raw x llm_country_weight x participant_weight
      S1-SCORE-010  a non-participant country contributes nothing
      S1-SCORE-011  the adversary role contributes like any other
      S1-SCORE-012  countryless signals are decoupled by default
      S1-SCORE-014  LLM multi-country tags filtered by primary ratio
      S1-SCORE-018  admission predicate and the empty-field fallbacks
    """
    built: list[Contribution] = []
    for observation in observations:
        if not observation.admits():
            continue

        if observation.is_global:
            # S1-SCORE-012. Decoupled is the default because a global
            # signal lighting a domain satisfies TL2's two-domain gate on
            # nothing that happened anywhere in particular.
            if settings.global_signals_decoupled:
                continue
            weight = settings.global_signal_weight.value
            final = observation.score * weight
            built.append(Contribution(
                sensor=observation.sensor,
                signal_source=observation.signal_source,
                domain=observation.domain,
                country=GLOBAL_COUNTRY,
                role=GLOBAL_ROLE,
                raw_score=observation.score,
                llm_country_weight=1.0,
                participant_weight=weight,
                score=final,
                trace=_global_trace(observation.score, weight, final)))
            continue

        weights = [entry.weight.value for entry in observation.countries]
        max_weight = max(weights) if weights else 1.0
        for entry in observation.countries:
            participant = scenario.participant_for(entry.country)
            if participant is None:
                # S1-SCORE-010: not in this scenario, contributes nothing.
                continue
            llm_weight = entry.weight.value
            if not _passes_primary_filter(
                    llm_weight, max_weight,
                    enabled=settings.llm_primary_country_only,
                    threshold=settings.llm_primary_threshold):
                continue
            participant_weight = participant.weight.value
            final = observation.score * llm_weight * participant_weight
            built.append(Contribution(
                sensor=observation.sensor,
                signal_source=observation.signal_source,
                domain=observation.domain,
                country=entry.country,
                role=participant.role,
                raw_score=observation.score,
                llm_country_weight=llm_weight,
                participant_weight=participant_weight,
                score=final,
                trace=_trace(observation.score, llm_weight,
                             participant_weight, entry.country, final)))
    return tuple(built)


def dedup_max(contributions: Iterable[Contribution]) -> tuple[Contribution, ...]:
    """S1-SCORE-008: one contribution per (signal_source, country), the max.

    Two sensors can report the same physical event under one
    `signal_source` — `ioda_bgp` and `ripe_bgp` both emit `bgp` — and
    summing them would count one outage twice, inflating a domain toward
    the convergence gates on a single fact. This is NP2's core defence.

    Ties keep the first seen (`>`, not `>=`), and insertion order is
    preserved, so the result is a deterministic function of the input
    order — which is what lets provenance be reproduced.
    """
    best: dict[tuple[str, str], Contribution] = {}
    for contribution in contributions:
        key = contribution.dedup_key
        current = best.get(key)
        if current is None or contribution.score > current.score:
            best[key] = contribution
    return tuple(best.values())


def domain_totals(contributions: Iterable[Contribution],
                  *, domain_cap: float) -> Mapping[str, float]:
    """S1-SCORE-001 / S1-SCORE-015: sum per domain, then clip at the cap.

    Every domain appears in the result, including at 0.0 — "this domain
    saw nothing" and "this domain was never asked" must not be the same
    absence (NP5+8).
    """
    if domain_cap <= 0:
        raise DomainError(
            f"domain_cap must be positive, got {domain_cap!r}: a cap of 0 "
            f"silently zeroes every domain and the scenario reads NORMAL")
    totals = {domain: 0.0 for domain in DOMAINS}
    for contribution in contributions:
        if contribution.domain in totals:
            totals[contribution.domain] += contribution.score
    return {domain: min(total, domain_cap)
            for domain, total in totals.items()}


def active_domains(totals: Mapping[str, float]) -> tuple[str, ...]:
    """Domains carrying any score at all. Order follows `DOMAINS`."""
    return tuple(domain for domain in DOMAINS if totals.get(domain, 0.0) > 0)


def active_countries(contributions: Iterable[Contribution]) -> tuple[str, ...]:
    """The participants actually firing, sorted, excluding GLOBAL.

    S1-SCORE-011: an adversary counts here like any other participant
    (ADR-014). GLOBAL is not a participant and must not inflate the
    distinct-participant count that S1-SCORE-007's downgrade gate reads.
    """
    return tuple(sorted({c.country for c in contributions
                         if c.country != GLOBAL_COUNTRY}))


def global_threat(observations: Iterable[Observation], *,
                  global_signal_weight: Ratio) -> dict:
    """S1-SCORE-013: countryless signals, aggregated in their own envelope.

    Separate from every scenario score by construction, so that
    decoupling them (S1-SCORE-012) loses no information — the signal is
    still reported, just not attributed to a conflict it has no evidence
    about.
    """
    weight = global_signal_weight.value
    totals = {domain: 0.0 for domain in DOMAINS}
    sources: list[str] = []
    score = 0.0
    for observation in observations:
        if not observation.admits() or not observation.is_global:
            continue
        weighted = observation.score * weight
        score += weighted
        if observation.domain in totals:
            totals[observation.domain] += weighted
        if observation.signal_source not in sources:
            sources.append(observation.signal_source)
    # The nested mapping is frozen too. A read-only outer dict wrapping a
    # mutable inner one is not immutable — anyone holding
    # global_threat["domains"] could edit a published figure after the
    # fact, which is the mutation Provenance was built to prevent.
    return MappingProxyType({
        "score": score,
        "domains": MappingProxyType(dict(totals)),
        "sources": tuple(sources),
        "weight": weight,
    })


__all__ = ["Contribution", "build_contributions", "dedup_max",
           "domain_totals", "active_domains", "active_countries",
           "global_threat", "GLOBAL_COUNTRY"]
