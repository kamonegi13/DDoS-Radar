"""O-5: which attack pattern the signal mix looks like. Not "whether".

S1-CONC-024 through S1-CONC-026. The rules are not exclusive: every one
that fires is recorded, the most confident becomes the state, and each
entry carries the plain-text rule that fired it (NP6 — a mode name without
its trigger is a label, not a conclusion).

S1-CONC-026 is the clause that matters most here. No rule matching does
NOT mean "no attack"; it means the rule set declined to judge. That is why
this type's empty case is an unavailable conclusion carrying
`asserts_absence: false` and the domain scores it looked at, rather than a
row saying NONE — and why `metadata` survives on the unavailable row.

Confidence formulas are transcribed from `attack_mode.py:_apply_rules` by
AST extraction, including the two places where the code and S1's rendering
differ in form: the margin denominator is `max(floor, 1.0)`, not the floor
itself (identical while every floor is >= 1.0, which DDOS's 1.2 and
KINETIC's 1.0 both are), and INFO_OPS_DOMINANT's predicate divides by a
bare `other_max` gated on `> 0` while its confidence divides by
`max(other_max, 0.1)`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from v3.conclusions import availability as A
from v3.conclusions import conclusion as C
from v3.conclusions import thresholds as T
from v3.conclusions import vocabulary as V
from v3.conclusions.context import ScenarioContext
from v3.kernel import Provenance
from v3.kernel.errors import DomainError

FORMULA_REF = "v3.conclusions.attack_mode.derive@S1-CONC-024..026"

DDOS_PRECURSOR = "DDOS_PRECURSOR"
KINETIC_PREPARATION = "KINETIC_PREPARATION"
HYBRID_PRESSURE = "HYBRID_PRESSURE"
INFO_OPS_DOMINANT = "INFO_OPS_DOMINANT"

BASE_MODES: tuple[str, ...] = (DDOS_PRECURSOR, KINETIC_PREPARATION,
                               HYBRID_PRESSURE, INFO_OPS_DOMINANT)


@dataclass(frozen=True, slots=True)
class ModeMatch:
    mode: str
    confidence: float
    rule: str

    def as_dict(self) -> dict:
        return {"mode": self.mode, "confidence": self.confidence,
                "rule": self.rule}


def _margin_confidence(value: float, floor: float) -> float:
    """0.55 + 0.4 * min(1, (value - floor) / max(floor, 1.0)), capped.

    `max(floor, 1.0)` is the production denominator. Writing it as the
    floor itself — which is how S1-CONC-025's table renders it — agrees
    for every current floor and diverges the moment one drops below 1.0,
    which is the direction these floors have moved twice (A10).
    """
    if value < floor:
        raise DomainError(
            f"_margin_confidence({value}, {floor}) is below the floor: every "
            f"call site is gated on `value >= floor`, so this is a caller "
            f"bug, and the unclamped expression would return a negative "
            f"confidence that Conclusion then refuses — turning a logic "
            f"error into a lost tick rather than a visible one")
    margin = (value - floor) / max(floor, 1.0)
    return round(min(T.ATTACK_CONFIDENCE_CEILING,
                     T.ATTACK_MARGIN_BASE_CONFIDENCE
                     + T.ATTACK_MARGIN_SPAN * min(1.0, margin)), 3)


def apply_rules(domain_scores: Mapping[str, float],
                active_countries: tuple) -> tuple[ModeMatch, ...]:
    """S1-CONC-025's four rules, evaluated independently."""
    cyber = float(domain_scores.get("cyber", 0.0))
    physical = float(domain_scores.get("physical", 0.0))
    info = float(domain_scores.get("info", 0.0))
    active_n = len(active_countries)
    matches: list[ModeMatch] = []

    if cyber >= T.ATTACK_CYBER_DDOS_FLOOR and \
            info >= T.ATTACK_INFO_NARRATIVE_FLOOR:
        matches.append(ModeMatch(
            DDOS_PRECURSOR,
            _margin_confidence(cyber, T.ATTACK_CYBER_DDOS_FLOOR),
            f"cyber={cyber:.1f}>={T.ATTACK_CYBER_DDOS_FLOOR} & "
            f"info>={T.ATTACK_INFO_NARRATIVE_FLOOR}"))

    if physical >= T.ATTACK_PHYSICAL_KINETIC_FLOOR:
        matches.append(ModeMatch(
            KINETIC_PREPARATION,
            _margin_confidence(physical, T.ATTACK_PHYSICAL_KINETIC_FLOOR),
            f"physical={physical:.1f}>="
            f"{T.ATTACK_PHYSICAL_KINETIC_FLOOR}"))

    floor = T.ATTACK_ALL_DOMAIN_HYBRID_FLOOR
    if (cyber >= floor and physical >= floor and info >= floor
            and active_n >= T.ATTACK_HYBRID_CLUSTER_MIN):
        summed = cyber + physical + info
        matches.append(ModeMatch(
            HYBRID_PRESSURE,
            round(min(T.ATTACK_CONFIDENCE_CEILING,
                      T.ATTACK_HYBRID_BASE_CONFIDENCE
                      + T.ATTACK_HYBRID_PER_COUNTRY * active_n
                      + T.ATTACK_HYBRID_PER_DOMAIN_SUM * summed), 3),
            f"all 3 domains >= {floor} & active_n={active_n}"))

    other_max = max(cyber, physical)
    if (info >= T.ATTACK_INFO_NARRATIVE_FLOOR and other_max > 0
            and info / other_max >= T.ATTACK_INFO_DOMINANCE_RATIO):
        matches.append(ModeMatch(
            INFO_OPS_DOMINANT,
            round(min(T.ATTACK_CONFIDENCE_CEILING,
                      T.ATTACK_MARGIN_BASE_CONFIDENCE
                      + T.ATTACK_INFO_DOMINANCE_SCALE
                      * (info / max(other_max,
                                    T.ATTACK_INFO_DOMINANCE_EPSILON))), 3),
            f"info/max(other)={info / other_max:.2f}>="
            f"{T.ATTACK_INFO_DOMINANCE_RATIO}"))
    elif info >= T.ATTACK_INFO_NARRATIVE_FLOOR and cyber == 0 \
            and physical == 0:
        matches.append(ModeMatch(INFO_OPS_DOMINANT,
                                 T.ATTACK_PURE_INFO_CONFIDENCE,
                                 "info-only signal mix"))

    return tuple(matches)


def _threshold_ref() -> dict:
    return {
        "cyber_ddos_floor": T.ATTACK_CYBER_DDOS_FLOOR,
        "info_narrative_floor": T.ATTACK_INFO_NARRATIVE_FLOOR,
        "physical_kinetic_floor": T.ATTACK_PHYSICAL_KINETIC_FLOOR,
        "all_domain_hybrid_floor": T.ATTACK_ALL_DOMAIN_HYBRID_FLOOR,
        "hybrid_cluster_min": T.ATTACK_HYBRID_CLUSTER_MIN,
        "info_dominance_ratio": T.ATTACK_INFO_DOMINANCE_RATIO,
        "tentative_below": T.ATTACK_TENTATIVE_CONFIDENCE,
    }


def derive(context: ScenarioContext) -> C.Conclusion:
    """The ATTACK_MODE conclusion. Silence is a refusal, never an all-clear."""
    scores = {domain: float(context.domain_scores.get(domain, 0.0))
              for domain in ("cyber", "physical", "info")}
    active = () if context.result is None else context.result.active_countries
    matches = sorted(apply_rules(scores, active),
                     key=lambda match: match.confidence, reverse=True)

    metadata: dict = {
        "domain_scores": {d: round(s, 3) for d, s in scores.items()},
        "active_countries_n": len(active),
        "ranked_modes": [match.as_dict() for match in matches],
    }

    if matches:
        top = matches[0]
        metadata["is_tentative"] = top.confidence < T.ATTACK_TENTATIVE_CONFIDENCE
        # Any recognised attack pattern is an alerting verdict — the guard
        # chain may flag the inputs but may not withhold it (NP1).
        candidate = A.Candidate(state=top.mode, calm=False)
        confidence = top.confidence
    else:
        candidate = A.Candidate(
            state=None, calm=True, derivable=False,
            detail="no rule matched the current signal mix. This is the "
                   "rule set declining to judge, NOT a finding that no "
                   "attack is under way (S1-CONC-026).")
        confidence = 0.0

    verdict = A.evaluate(context.health, candidate)
    provenance = Provenance(
        formula_ref=FORMULA_REF, computed_at=context.now,
        inputs={"cyber": round(scores["cyber"], 6),
                "physical": round(scores["physical"], 6),
                "info": round(scores["info"], 6),
                "active_countries_n": len(active),
                "modes_fired": len(matches)})
    return C.build(
        scenario_id=context.scenario_id, conclusion_type=V.ATTACK_MODE,
        observed_at=context.now, confidence=confidence, provenance=provenance,
        input_health=context.health, availability=verdict,
        state=candidate.state, threshold_ref=_threshold_ref(),
        calibration_status=context.calibration_status, metadata=metadata)


__all__ = ["derive", "apply_rules", "ModeMatch", "BASE_MODES",
           "DDOS_PRECURSOR", "KINETIC_PREPARATION", "HYBRID_PRESSURE",
           "INFO_OPS_DOMINANT", "FORMULA_REF"]
