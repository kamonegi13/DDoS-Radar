"""O-3: cyber / physical / info, three states packed into one row.

S1-CONC-019 and S1-CONC-020. The classification order is load-bearing and
is preserved exactly, including the part S1-conclusions flags as
ACCIDENTAL A6: DEGRADING is tested before ELEVATED, so a domain falling
from 4.0 to 2.0 reads DEGRADING and its absolute level disappears from the
state. That is a live owner question, not a bug to fix mid-port —
changing it here would make every parity difference in this conclusion
type uninterpretable.

`prior` comes from the preceding row of L1's TL stream (which carries the
three domain columns), not from the previous PER_DOMAIN conclusion. Same
number, one fewer lane, and it keeps working when the conclusion ledger
thins — P6 O-16 applied to a comparison that used to depend on what was
last written.
"""
from __future__ import annotations

from typing import Mapping, Optional

from v3.conclusions import availability as A
from v3.conclusions import conclusion as C
from v3.conclusions import thresholds as T
from v3.conclusions import vocabulary as V
from v3.conclusions.context import ScenarioContext
from v3.kernel import Provenance

FORMULA_REF = "v3.conclusions.per_domain.derive@S1-CONC-019..020"

DOMAINS: tuple[str, ...] = ("cyber", "physical", "info")

ACTIVE = "ACTIVE"
DEGRADING = "DEGRADING"
ELEVATED = "ELEVATED"
STABLE = "STABLE"
INSUFFICIENT_SIGNAL = "INSUFFICIENT_SIGNAL"


def classify(current: float, prior: Optional[float]) -> str:
    """S1-CONC-020's ladder, in order, boundaries inclusive.

    A non-positive score is INSUFFICIENT_SIGNAL, negatives included: a
    domain cannot be less than silent, and treating a negative as STABLE
    would let a suppression artefact read as a healthy quiet domain.
    """
    if current <= 0.0:
        return INSUFFICIENT_SIGNAL
    if current >= T.DOMAIN_ACTIVE_FLOOR:
        return ACTIVE
    if prior is not None and prior - current >= T.DOMAIN_DEGRADE_DELTA:
        return DEGRADING
    if current >= T.DOMAIN_ELEVATED_FLOOR:
        return ELEVATED
    return STABLE


def pack(states: Mapping[str, str]) -> str:
    return ";".join(f"{domain}={states[domain]}" for domain in DOMAINS)


def confidence_for(domain_scores: Mapping[str, float],
                   signalled: list) -> float:
    """S1-CONC-019: half breadth, half magnitude, three decimals.

    The magnitude term is clamped at BOTH ends. Production clamps only
    the top (`radar/conclusions/per_domain.py:172`), and `classify` in
    this same module documents that negative domain scores occur — so a
    strongly negative domain drives the sum below zero, the confidence
    below zero, and `Conclusion` (correctly) refuses to be built. In v3
    that refusal propagates out of `derive_all` and deletes all five
    conclusions for the tick, which every downstream view reads as a
    healthy tick. The lower clamp is a registered difference from
    production, on an input where production is also wrong.
    """
    breadth = len(signalled) / float(len(DOMAINS))
    magnitude = max(0.0, min(1.0, sum(domain_scores.values())
                             / T.DOMAIN_MAGNITUDE_DENOM))
    return round(0.5 * breadth + 0.5 * magnitude, 3)


def source_urls(context: ScenarioContext) -> tuple[str, ...]:
    """S1-CONC-019: only evidence belonging to the three known domains."""
    return tuple(sorted({
        url for url in (context.url_for(item.signal_source)
                        for item in context.contributions
                        if item.domain in DOMAINS) if url}))


def derive(context: ScenarioContext) -> C.Conclusion:
    """The PER_DOMAIN conclusion. One row; one signalled domain is enough."""
    scores = {domain: float(context.domain_scores.get(domain, 0.0))
              for domain in DOMAINS}
    states = {domain: classify(scores[domain],
                               context.prior_domain_scores.get(domain))
              for domain in DOMAINS}
    signalled = [domain for domain in DOMAINS
                 if states[domain] != INSUFFICIENT_SIGNAL]
    counts = {domain: sum(1 for item in context.contributions
                          if item.domain == domain)
              for domain in DOMAINS}
    urls = source_urls(context)

    if signalled:
        # Calmness is read off the SCORES, not off the state labels. A6's
        # ordering puts DEGRADING ahead of ELEVATED, so a domain falling
        # from 3.5 to 2.4 is labelled DEGRADING — and reading the label
        # would call that calm, letting a degraded-input guard suppress a
        # domain sitting well above the elevated floor. That is the
        # insensitive direction, which NP1 forbids. The label keeps A6's
        # quirk (it is the published state and parity depends on it); the
        # alerting decision does not inherit it.
        candidate = A.Candidate(
            state=pack(states),
            calm=not any(scores[domain] >= T.DOMAIN_ELEVATED_FLOOR
                         for domain in DOMAINS))
    else:
        # S1-CONC-019: all three silent is the only unavailable path (NP1).
        candidate = A.Candidate(
            state=None, calm=True, derivable=False,
            detail="every domain scored at or below zero, so there is no "
                   "domain-level picture to publish")

    verdict = A.evaluate(context.health, candidate)
    provenance = Provenance(
        formula_ref=FORMULA_REF, computed_at=context.now,
        inputs={"cyber": round(scores["cyber"], 6),
                "physical": round(scores["physical"], 6),
                "info": round(scores["info"], 6),
                "signalled_domains": len(signalled),
                "had_prior": bool(context.prior_domain_scores)},
        source_refs=urls)
    return C.build(
        scenario_id=context.scenario_id, conclusion_type=V.PER_DOMAIN,
        observed_at=context.now,
        confidence=confidence_for(scores, signalled), provenance=provenance,
        input_health=context.health, availability=verdict,
        state=candidate.state,
        threshold_ref={"active_floor": T.DOMAIN_ACTIVE_FLOOR,
                       "elevated_floor": T.DOMAIN_ELEVATED_FLOOR,
                       "degrade_delta": T.DOMAIN_DEGRADE_DELTA,
                       "magnitude_denom": T.DOMAIN_MAGNITUDE_DENOM},
        source_urls=urls, calibration_status=context.calibration_status,
        metadata={"domain_scores": {d: round(s, 3)
                                    for d, s in scores.items()},
                  "domain_states": dict(states),
                  "domain_source_counts": counts,
                  "prior_domain_scores": {
                      d: round(float(v), 3)
                      for d, v in context.prior_domain_scores.items()}})


__all__ = ["derive", "classify", "pack", "confidence_for", "source_urls",
           "DOMAINS", "FORMULA_REF", "ACTIVE", "DEGRADING", "ELEVATED",
           "STABLE", "INSUFFICIENT_SIGNAL"]
