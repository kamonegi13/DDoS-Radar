"""Attack mode conclusion deriver — ADR-V2-005 (rule-based, Phase 2 initial).

Maps the in-flight ScenarioState into one or more of the 5 base attack modes:

  DDOS_PRECURSOR       — cyber-heavy with narrative buildup
  KINETIC_PREPARATION  — physical convergence (ISR + military + diplomatic)
  HYBRID_PRESSURE      — all 3 domains active with multi-source intel cluster
  INFO_OPS_DOMINANT    — info domain ACTIVE, others STABLE-or-below
  INSUFFICIENT_SIGNAL  — no rule matches; transient unavailable

Multiple modes can fire simultaneously (e.g., HYBRID_PRESSURE +
INFO_OPS_DOMINANT). The conclusion records the top mode in `state` and
the full ranked list in metadata so downstream UI can show top N.

scenario_extensions (per geo_data.json scenarios.<id>.attack_mode_extensions)
are evaluated by `radar/conclusions/attack_mode_extensions.py` and merged
into the ranked list. Extensions are config-only — declared in geo_data.json
per scenario, never as Python branches.

LLM augmentation is deferred to Phase 2 後半 (per design doc §6.5).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from radar import config
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    new_conclusion_id,
)

if TYPE_CHECKING:
    from radar.scoring import ScenarioState


FORMULA_REF = "radar/conclusions/attack_mode.py#derive_attack_mode@v2.0.0"

# Thresholds — recalibrated 2026-05-10 against 24h × 4 scenario observed
# distribution. Original values (5.0/3.0/1.5) sat 2-3x above the all-time
# observed maxima (cyber max=1.5, physical=0.0, info p95<2 except
# middle_east) producing 100% NULL attack_mode in 3/4 scenarios — a direct
# NP5+8 violation ("恒常的結論不可"). New floors recover NP1 sensitivity
# while INFO_OPS_DOMINANT in middle_east continues to fire (the only mode
# that worked under old thresholds).
CYBER_DDOS_FLOOR = 1.2      # cyber domain — barely above 1.0 baseline
INFO_NARRATIVE_FLOOR = 0.8  # info domain — fires with 1+ info source
PHYSICAL_KINETIC_FLOOR = 1.0  # physical domain — any FIRED tripwire qualifies
ALL_DOMAIN_HYBRID_FLOOR = 0.8  # per-domain min for HYBRID — aligned with info floor
HYBRID_INTEL_CLUSTER_MIN = 4  # active_countries — kept; needs cluster size
INFO_DOMINANCE_RATIO = 1.5    # info / max(other) — kept; works for middle_east


@dataclass(frozen=True)
class _ModeMatch:
    mode: str
    confidence: float
    rule: str  # which threshold rule matched


def derive_attack_mode(state: "ScenarioState", *,
                       now: Optional[float] = None) -> Conclusion:
    """Classify ScenarioState into ranked attack modes."""
    if now is None:
        now = time.time()

    from radar.conclusions.attack_mode_extensions import evaluate_extensions
    base_matches = list(_apply_rules(state))
    extension_matches = [
        _ModeMatch(mode=m.mode, confidence=m.confidence, rule=m.rule)
        for m in evaluate_extensions(state)
    ]
    matches = base_matches + extension_matches
    matches.sort(key=lambda m: m.confidence, reverse=True)

    threshold_ref = {
        "cyber_ddos_floor": CYBER_DDOS_FLOOR,
        "info_narrative_floor": INFO_NARRATIVE_FLOOR,
        "physical_kinetic_floor": PHYSICAL_KINETIC_FLOOR,
        "all_domain_hybrid_floor": ALL_DOMAIN_HYBRID_FLOOR,
        "hybrid_intel_cluster_min": HYBRID_INTEL_CLUSTER_MIN,
        "info_dominance_ratio": INFO_DOMINANCE_RATIO,
    }
    source_urls = tuple(sorted({
        c.signal.evidence_url for c in state.contributions
        if c.signal.evidence_url
    }))

    if not matches:
        # NP5+8: no rule matched is a transient unavailable, NOT a "no
        # attack" claim. The deriver cannot prove a negative.
        return Conclusion(
            id=new_conclusion_id(),
            scenario_id=state.scenario_id,
            conclusion_type=ConclusionType.ATTACK_MODE,
            state=None,
            confidence=0.0,
            observed_at=now,
            formula_ref=FORMULA_REF,
            threshold_ref=threshold_ref,
            source_urls=source_urls,
            final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
            conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
            metadata={
                "domain_scores": dict(state.domains),
                "active_countries_n": len(state.active_countries),
                "is_transient": True,
                "reason_detail": "no rule-based mode matched current signal mix",
            },
        )

    top = matches[0]
    return Conclusion(
        id=new_conclusion_id(),
        scenario_id=state.scenario_id,
        conclusion_type=ConclusionType.ATTACK_MODE,
        state=top.mode,
        confidence=top.confidence,
        observed_at=now,
        formula_ref=FORMULA_REF,
        threshold_ref=threshold_ref,
        source_urls=source_urls,
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        metadata={
            "ranked_modes": [
                {"mode": m.mode, "confidence": m.confidence, "rule": m.rule}
                for m in matches
            ],
            "domain_scores": {d: round(v, 3) for d, v in state.domains.items()},
            "active_countries_n": len(state.active_countries),
            "is_tentative": top.confidence < 0.6,
        },
    )


def _apply_rules(state: "ScenarioState") -> list[_ModeMatch]:
    """Yield every mode whose rule fires. Confidence reflects rule margin."""
    cyber = float(state.domains.get("cyber", 0.0))
    physical = float(state.domains.get("physical", 0.0))
    info = float(state.domains.get("info", 0.0))
    active_n = len(state.active_countries)

    matches: list[_ModeMatch] = []

    # DDOS_PRECURSOR — cyber dominant + info narrative buildup
    if cyber >= CYBER_DDOS_FLOOR and info >= INFO_NARRATIVE_FLOOR:
        margin = (cyber - CYBER_DDOS_FLOOR) / max(CYBER_DDOS_FLOOR, 1.0)
        conf = min(0.95, 0.55 + 0.4 * min(1.0, margin))
        matches.append(_ModeMatch("DDOS_PRECURSOR", round(conf, 3),
                                  f"cyber={cyber:.1f}>={CYBER_DDOS_FLOOR} & info>={INFO_NARRATIVE_FLOOR}"))

    # KINETIC_PREPARATION — physical convergence
    if physical >= PHYSICAL_KINETIC_FLOOR:
        margin = (physical - PHYSICAL_KINETIC_FLOOR) / max(PHYSICAL_KINETIC_FLOOR, 1.0)
        conf = min(0.95, 0.55 + 0.4 * min(1.0, margin))
        matches.append(_ModeMatch("KINETIC_PREPARATION", round(conf, 3),
                                  f"physical={physical:.1f}>={PHYSICAL_KINETIC_FLOOR}"))

    # HYBRID_PRESSURE — all 3 domains + cluster size
    if (cyber >= ALL_DOMAIN_HYBRID_FLOOR
            and physical >= ALL_DOMAIN_HYBRID_FLOOR
            and info >= ALL_DOMAIN_HYBRID_FLOOR
            and active_n >= HYBRID_INTEL_CLUSTER_MIN):
        sum_d = cyber + physical + info
        conf = min(0.95, 0.50 + 0.05 * active_n + 0.02 * sum_d)
        matches.append(_ModeMatch("HYBRID_PRESSURE", round(conf, 3),
                                  f"all 3 domains >= {ALL_DOMAIN_HYBRID_FLOOR} & active_n={active_n}"))

    # INFO_OPS_DOMINANT — info dominance over kinetic dimensions
    other_max = max(cyber, physical)
    if info >= INFO_NARRATIVE_FLOOR and other_max > 0 and info / other_max >= INFO_DOMINANCE_RATIO:
        conf = min(0.95, 0.55 + 0.10 * (info / max(other_max, 0.1)))
        matches.append(_ModeMatch("INFO_OPS_DOMINANT", round(conf, 3),
                                  f"info/max(other)={info / other_max:.2f}>={INFO_DOMINANCE_RATIO}"))
    elif info >= INFO_NARRATIVE_FLOOR and cyber == 0 and physical == 0:
        # Pure info case
        matches.append(_ModeMatch("INFO_OPS_DOMINANT", 0.65,
                                  "info-only signal mix"))

    return matches
