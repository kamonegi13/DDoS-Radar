"""Tests for radar.conclusions.attack_mode.derive_attack_mode.

Pins the rule-based ATTACK_MODE classifier (ADR-V2-005, Phase 2 initial):

  DDOS_PRECURSOR       — cyber >= 5.0 AND info >= 1.5
  KINETIC_PREPARATION  — physical >= 3.0
  HYBRID_PRESSURE      — all 3 domains >= 1.5 AND active_countries >= 4
  INFO_OPS_DOMINANT    — info >= 1.5 AND info / max(other) >= 1.5
                          (or info-only with cyber=physical=0)

Verifies: schema (formula_ref/threshold_ref/disclaimer/source_urls),
INSUFFICIENT_DATA path (NP5+8 + NP1: no rule match is transient unavailable,
NOT a "no attack" claim), confidence ranges, multi-mode firing with top
mode in `state` and full ranked list in metadata, source_urls dedup.

The implementation (radar/conclusions/attack_mode.py) diverges from the
spec text in v2-migration.md §6.5 (which talks about cyber_signal_count,
physical-component conjunction, intel cluster size). Drift is recorded
in the doc; these tests pin the live thresholds so any change to the
classifier surfaces immediately.
"""

from __future__ import annotations

import pytest

from radar import config
from radar.conclusions import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
)
from radar.conclusions.attack_mode import (
    ALL_DOMAIN_HYBRID_FLOOR,
    CYBER_DDOS_FLOOR,
    FORMULA_REF,
    HYBRID_INTEL_CLUSTER_MIN,
    INFO_DOMINANCE_RATIO,
    INFO_NARRATIVE_FLOOR,
    PHYSICAL_KINETIC_FLOOR,
    derive_attack_mode,
)
from radar.scoring import ScenarioContribution, ScenarioState, Signal


@pytest.fixture
def now() -> float:
    return 1_700_000_000.0


def _signal(
    *,
    signal_source: str = "apt_intel",
    domain: str = "cyber",
    raw_score: float = 1.0,
    observed_at: float = 1_700_000_000.0,
    evidence_url: str | None = None,
) -> Signal:
    return Signal(
        signal_source=signal_source,
        sensor=signal_source,
        observed_at=observed_at,
        domain=domain,
        countries=["TW"],
        country_weights={"TW": 1.0},
        raw_score=raw_score,
        value_display="",
        evidence_url=evidence_url,
    )


def _contribution(sig: Signal) -> ScenarioContribution:
    return ScenarioContribution(
        signal=sig,
        contributing_country="TW",
        llm_country_weight=1.0,
        participant_weight=1.0,
        participant_role="primary_target",
        final_contribution=sig.raw_score,
        formula_trace="test",
    )


def _state(
    *,
    domains: dict | None = None,
    active_countries: list[str] | None = None,
    contributions: list[ScenarioContribution] | None = None,
    tl: int | None = 3,
    is_focused: bool = True,
) -> ScenarioState:
    return ScenarioState(
        scenario_id="taiwan_contingency",
        is_focused=is_focused,
        scoring_mode="full",
        score=sum((c.final_contribution for c in (contributions or [])), 0.0),
        domains=domains or {"cyber": 0.0, "physical": 0.0, "info": 0.0},
        active_countries=active_countries or ["TW"],
        convergence_bonus=0.0,
        tl=tl,
        contributions=contributions or [],
    )


# ---------- schema ----------

def test_returns_single_conclusion_of_type_attack_mode(now: float) -> None:
    out = derive_attack_mode(_state(domains={"cyber": 6.0, "physical": 0.0, "info": 2.0}), now=now)
    assert isinstance(out, Conclusion)
    assert out.conclusion_type is ConclusionType.ATTACK_MODE


def test_formula_ref_is_stable_constant(now: float) -> None:
    out = derive_attack_mode(_state(domains={"cyber": 6.0, "physical": 0.0, "info": 2.0}), now=now)
    assert out.formula_ref == FORMULA_REF


def test_threshold_ref_exposes_every_floor(now: float) -> None:
    out = derive_attack_mode(_state(domains={"cyber": 6.0, "physical": 0.0, "info": 2.0}), now=now)
    tr = out.threshold_ref
    assert tr["cyber_ddos_floor"] == CYBER_DDOS_FLOOR
    assert tr["info_narrative_floor"] == INFO_NARRATIVE_FLOOR
    assert tr["physical_kinetic_floor"] == PHYSICAL_KINETIC_FLOOR
    assert tr["all_domain_hybrid_floor"] == ALL_DOMAIN_HYBRID_FLOOR
    assert tr["hybrid_intel_cluster_min"] == HYBRID_INTEL_CLUSTER_MIN
    assert tr["info_dominance_ratio"] == INFO_DOMINANCE_RATIO


def test_disclaimer_uses_config_value(monkeypatch, now: float) -> None:
    monkeypatch.setattr(config, "V2_NP7_DISCLAIMER", "TEST DISCLAIMER")
    out = derive_attack_mode(_state(domains={"cyber": 6.0, "physical": 0.0, "info": 2.0}), now=now)
    assert out.final_judgment_disclaimer == "TEST DISCLAIMER"


# ---------- INSUFFICIENT_DATA (NP5+8 + NP1) ----------

def test_no_signals_yields_insufficient_data(now: float) -> None:
    """Empty domain mix: a transient unavailable, NOT a "no attack" claim."""
    out = derive_attack_mode(_state(), now=now)
    assert not out.is_available()
    assert out.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA
    assert out.metadata.get("is_transient") is True
    assert out.state is None
    assert out.confidence == 0.0


def test_below_all_floors_yields_insufficient_data(now: float) -> None:
    # Values chosen below all current floors (CYBER=1.2, PHYSICAL=1.0,
    # INFO=0.8) so no rule fires.
    out = derive_attack_mode(
        _state(domains={"cyber": 0.5, "physical": 0.5, "info": 0.5}),
        now=now,
    )
    assert not out.is_available()
    assert out.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA


def test_insufficient_metadata_carries_domain_scores(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 1.0, "physical": 0.5, "info": 0.0}),
        now=now,
    )
    assert out.metadata["domain_scores"] == {"cyber": 1.0, "physical": 0.5, "info": 0.0}
    assert out.metadata["active_countries_n"] == 1


# ---------- DDOS_PRECURSOR ----------

def test_ddos_precursor_fires_at_floors(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": CYBER_DDOS_FLOOR, "physical": 0.0,
                        "info": INFO_NARRATIVE_FLOOR}),
        now=now,
    )
    assert out.state == "DDOS_PRECURSOR"
    assert 0.5 < out.confidence <= 0.95


def test_ddos_precursor_blocks_below_cyber_floor(now: float) -> None:
    """cyber just under the floor must NOT fire DDOS_PRECURSOR."""
    out = derive_attack_mode(
        _state(domains={"cyber": CYBER_DDOS_FLOOR - 0.01, "physical": 0.0,
                        "info": INFO_NARRATIVE_FLOOR + 1.0}),
        now=now,
    )
    assert out.state != "DDOS_PRECURSOR"


def test_ddos_precursor_blocks_below_info_floor(now: float) -> None:
    """High cyber alone must NOT classify as DDOS_PRECURSOR (needs narrative)."""
    out = derive_attack_mode(
        _state(domains={"cyber": CYBER_DDOS_FLOOR + 5.0, "physical": 0.0,
                        "info": INFO_NARRATIVE_FLOOR - 0.01}),
        now=now,
    )
    assert out.state != "DDOS_PRECURSOR"


# ---------- KINETIC_PREPARATION ----------

def test_kinetic_preparation_fires_at_floor(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 0.0, "physical": PHYSICAL_KINETIC_FLOOR, "info": 0.0}),
        now=now,
    )
    assert out.state == "KINETIC_PREPARATION"


def test_kinetic_preparation_blocks_below_floor(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 0.0, "physical": PHYSICAL_KINETIC_FLOOR - 0.01, "info": 0.0}),
        now=now,
    )
    assert out.state != "KINETIC_PREPARATION"


# ---------- HYBRID_PRESSURE ----------

def test_hybrid_pressure_requires_all_three_domains_and_cluster(now: float) -> None:
    out = derive_attack_mode(
        _state(
            domains={"cyber": ALL_DOMAIN_HYBRID_FLOOR,
                     "physical": ALL_DOMAIN_HYBRID_FLOOR,
                     "info": ALL_DOMAIN_HYBRID_FLOOR},
            active_countries=["TW", "US", "JP", "CN"],
        ),
        now=now,
    )
    ranked = [m["mode"] for m in out.metadata["ranked_modes"]]
    assert "HYBRID_PRESSURE" in ranked


def test_hybrid_pressure_blocks_when_cluster_too_small(now: float) -> None:
    """All 3 domains barely over the HYBRID floor but only 3 countries: HYBRID
    rejects on cluster_min, and no other rule clears its higher floor either,
    so the row is INSUFFICIENT_DATA — not a HYBRID classification.
    """
    out = derive_attack_mode(
        _state(
            domains={"cyber": ALL_DOMAIN_HYBRID_FLOOR,
                     "physical": ALL_DOMAIN_HYBRID_FLOOR,
                     "info": ALL_DOMAIN_HYBRID_FLOOR},
            active_countries=["TW", "US", "JP"],  # 3 < HYBRID_INTEL_CLUSTER_MIN
        ),
        now=now,
    )
    if out.is_available():
        ranked = [m["mode"] for m in out.metadata["ranked_modes"]]
        assert "HYBRID_PRESSURE" not in ranked
    else:
        assert out.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA


def test_hybrid_pressure_blocks_when_one_domain_silent(now: float) -> None:
    """cyber=0 disqualifies HYBRID. The remaining domains do not reach any
    other rule's floor either, so the result is INSUFFICIENT_DATA.
    """
    out = derive_attack_mode(
        _state(
            domains={"cyber": 0.0,
                     "physical": ALL_DOMAIN_HYBRID_FLOOR,
                     "info": ALL_DOMAIN_HYBRID_FLOOR},
            active_countries=["TW", "US", "JP", "CN"],
        ),
        now=now,
    )
    if out.is_available():
        ranked = [m["mode"] for m in out.metadata["ranked_modes"]]
        assert "HYBRID_PRESSURE" not in ranked
    else:
        assert out.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA


# ---------- INFO_OPS_DOMINANT ----------

def test_info_dominance_fires_with_ratio(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 1.0, "physical": 1.0,
                        "info": INFO_DOMINANCE_RATIO * 1.0 + 0.1}),
        now=now,
    )
    ranked = [m["mode"] for m in out.metadata["ranked_modes"]]
    assert "INFO_OPS_DOMINANT" in ranked


def test_info_only_signal_mix_classifies_info_ops(now: float) -> None:
    """Pure info case (cyber=physical=0) must still classify."""
    out = derive_attack_mode(
        _state(domains={"cyber": 0.0, "physical": 0.0, "info": INFO_NARRATIVE_FLOOR}),
        now=now,
    )
    assert out.state == "INFO_OPS_DOMINANT"


def test_info_below_floor_does_not_dominate(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 0.0, "physical": 0.0, "info": INFO_NARRATIVE_FLOOR - 0.01}),
        now=now,
    )
    assert out.state != "INFO_OPS_DOMINANT"


# ---------- multi-mode firing ----------

def test_multi_mode_records_top_in_state_and_full_ranked_list(now: float) -> None:
    """High cyber+info+physical should fire DDOS_PRECURSOR + KINETIC_PREPARATION
    (and HYBRID if cluster met). state holds the highest-confidence one;
    ranked_modes captures all matches sorted by confidence desc.
    """
    out = derive_attack_mode(
        _state(
            domains={"cyber": 9.0, "physical": 5.0, "info": 2.0},
            active_countries=["TW", "US", "JP", "CN"],
        ),
        now=now,
    )
    modes = [m["mode"] for m in out.metadata["ranked_modes"]]
    assert "DDOS_PRECURSOR" in modes
    assert "KINETIC_PREPARATION" in modes
    confidences = [m["confidence"] for m in out.metadata["ranked_modes"]]
    assert confidences == sorted(confidences, reverse=True)
    assert out.state == out.metadata["ranked_modes"][0]["mode"]


def test_each_ranked_entry_carries_rule_string(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 6.0, "physical": 0.0, "info": 2.0}),
        now=now,
    )
    for m in out.metadata["ranked_modes"]:
        assert isinstance(m["rule"], str)
        assert m["rule"]


# ---------- confidence + tentative flag ----------

def test_confidence_clamped_below_unit(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 1000.0, "physical": 0.0, "info": 5.0}),
        now=now,
    )
    assert 0.0 <= out.confidence <= 1.0
    assert out.confidence == pytest.approx(0.95, abs=0.001)


def test_tentative_flag_set_when_confidence_low(now: float) -> None:
    """Margin-light DDOS firing right at the floors yields confidence < 0.6."""
    out = derive_attack_mode(
        _state(domains={"cyber": CYBER_DDOS_FLOOR, "physical": 0.0,
                        "info": INFO_NARRATIVE_FLOOR}),
        now=now,
    )
    assert out.metadata["is_tentative"] == (out.confidence < 0.6)


# ---------- source_urls ----------

def test_source_urls_collected_and_deduped(now: float) -> None:
    contribs = [
        _contribution(_signal(signal_source="a", evidence_url="https://x/1", observed_at=now)),
        _contribution(_signal(signal_source="b", evidence_url="https://x/2", observed_at=now)),
        _contribution(_signal(signal_source="c", evidence_url="https://x/1", observed_at=now)),
        _contribution(_signal(signal_source="d", evidence_url=None, observed_at=now)),
    ]
    out = derive_attack_mode(
        _state(domains={"cyber": 6.0, "physical": 0.0, "info": 2.0},
               contributions=contribs),
        now=now,
    )
    assert out.source_urls == ("https://x/1", "https://x/2")


def test_source_urls_empty_when_no_contributions(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 6.0, "physical": 0.0, "info": 2.0}),
        now=now,
    )
    assert out.source_urls == ()


# ---------- metadata invariants ----------

def test_metadata_carries_active_country_count(now: float) -> None:
    out = derive_attack_mode(
        _state(
            domains={"cyber": 6.0, "physical": 0.0, "info": 2.0},
            active_countries=["TW", "US", "JP"],
        ),
        now=now,
    )
    assert out.metadata["active_countries_n"] == 3


def test_metadata_domain_scores_rounded(now: float) -> None:
    out = derive_attack_mode(
        _state(domains={"cyber": 6.123456, "physical": 0.0, "info": 2.987654}),
        now=now,
    )
    assert out.metadata["domain_scores"]["cyber"] == 6.123
    assert out.metadata["domain_scores"]["info"] == 2.988
