"""Tests for radar.conclusions.threat_level.derive_threat_level builder.

Validates the v2.0 THREAT_LEVEL Conclusion produced from a ScenarioState:
- Output schema (formula_ref, threshold_ref, source_urls, disclaimer)
- INSUFFICIENT_DATA path when state.tl is None (NP5+8 + NP1)
- Confidence bounded to [0.0, 1.0]
- Threshold table parity with derive_tl() (catches drift if either changes)
- Source URLs are deduplicated and sorted (deterministic ordering)
- Metadata captures the score/active_countries/scoring_mode for replay
"""

from __future__ import annotations

import pytest

from radar import config, scoring
from radar.conclusions import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    derive_threat_level,
)
from radar.conclusions.threat_level import FORMULA_REF, THRESHOLD_REF
from radar.database import RadarDB


@pytest.fixture
def db(tmp_path) -> RadarDB:
    return RadarDB(str(tmp_path / "tl_derive.db"))


def _state(**overrides) -> "scoring.ScenarioState":
    base = dict(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=5.0,
        domains={"cyber": 3.0, "physical": 2.0, "info": 0.0},
        active_countries=["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=[],
    )
    base.update(overrides)
    return scoring.ScenarioState(**base)


def test_returns_conclusion_with_threat_level_type(db: RadarDB) -> None:
    c = derive_threat_level(db, _state())
    assert isinstance(c, Conclusion)
    assert c.conclusion_type is ConclusionType.THREAT_LEVEL


def test_state_is_string_of_tl_int(db: RadarDB) -> None:
    c = derive_threat_level(db, _state(tl=2))
    assert c.state == "2"


def test_formula_ref_matches_derive_tl_version(db: RadarDB) -> None:
    """Builder must publish the same formula_ref as scoring.DERIVE_TL_FORMULA_REF."""
    c = derive_threat_level(db, _state())
    assert c.formula_ref == scoring.DERIVE_TL_FORMULA_REF
    assert c.formula_ref == FORMULA_REF


def test_threshold_ref_matches_derive_tl(db: RadarDB) -> None:
    """Drift guard: every threshold derive_tl() applies must appear here."""
    # Probe the boundaries: any change to derive_tl thresholds should make
    # at least one of these fail.
    assert scoring.derive_tl(9.0, ["cyber", "physical"], 3.0) == 1
    # Physical floor matters: 2 domains keep us at TL2, but losing the
    # physical>=3.0 floor should drop us out of TL1.
    assert scoring.derive_tl(9.0, ["cyber", "physical"], 2.99) == 2
    assert scoring.derive_tl(6.0, ["cyber", "physical"], 0.0) == 2
    assert scoring.derive_tl(4.0, ["cyber"], 0.0) == 3
    assert scoring.derive_tl(2.0, ["cyber"], 0.0) == 4
    assert scoring.derive_tl(1.99, [], 0.0) == 5

    c = derive_threat_level(db, _state())
    assert c.threshold_ref["tl1_total"] == 9.0
    assert c.threshold_ref["tl1_physical"] == 3.0
    assert c.threshold_ref["tl2_total"] == 6.0
    assert c.threshold_ref["tl2_active_domains_min"] == 2
    assert c.threshold_ref["tl3_total"] == 4.0
    assert c.threshold_ref["tl4_total"] == 2.0


def test_tl_none_yields_insufficient_data(db: RadarDB) -> None:
    """NP5+8 + NP1: missing TL is an explicit unavailable Conclusion."""
    c = derive_threat_level(db, _state(tl=None, score=0.0))
    assert c.state is None
    assert c.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA
    assert not c.is_available()
    assert c.metadata.get("is_transient") is True


def test_confidence_clamped_to_unit_interval(db: RadarDB) -> None:
    """Score / 12.0 may exceed 1.0 with stacked signals — must clamp."""
    c_high = derive_threat_level(db, _state(score=20.0, tl=1))
    c_zero = derive_threat_level(db, _state(score=-1.0, tl=5))
    assert 0.0 <= c_high.confidence <= 1.0
    assert c_high.confidence == 1.0
    assert c_zero.confidence == 0.0


def test_source_urls_are_deduplicated_and_sorted(db: RadarDB) -> None:
    """Caller may emit the same evidence_url twice — output must be unique sorted."""
    from radar.scoring import ScenarioContribution, Signal

    sig_a = Signal(
        signal_source="apt_intel", sensor="apt_intel", observed_at=0.0,
        domain="cyber", countries=["TW"], country_weights={"TW": 1.0},
        raw_score=1.0, evidence_url="https://example.com/b",
    )
    sig_b = Signal(
        signal_source="mil_ex", sensor="military_exercise", observed_at=0.0,
        domain="physical", countries=["TW"], country_weights={"TW": 1.0},
        raw_score=1.0, evidence_url="https://example.com/a",
    )
    sig_dup = Signal(
        signal_source="rss", sensor="rss_narrative", observed_at=0.0,
        domain="info", countries=["TW"], country_weights={"TW": 1.0},
        raw_score=1.0, evidence_url="https://example.com/a",
    )
    contributions = [
        ScenarioContribution(
            signal=sig, contributing_country="TW",
            llm_country_weight=1.0, participant_weight=1.0,
            participant_role="primary_target", final_contribution=1.0,
            formula_trace="test",
        )
        for sig in (sig_a, sig_b, sig_dup)
    ]
    c = derive_threat_level(db, _state(contributions=contributions))
    assert c.source_urls == ("https://example.com/a", "https://example.com/b")


def test_metadata_captures_replay_fields(db: RadarDB) -> None:
    c = derive_threat_level(
        db,
        _state(
            score=4.5,
            domains={"cyber": 3.0, "physical": 1.5, "info": 0.0},
            active_countries=["TW", "US"],
            convergence_bonus=0.5,
            scoring_mode="full",
            tl=3,
        ),
    )
    assert c.metadata["score"] == 4.5
    assert c.metadata["active_countries"] == ["TW", "US"]
    assert c.metadata["convergence_bonus"] == 0.5
    assert c.metadata["scoring_mode"] == "full"
    assert c.metadata["active_domain_count"] == 2  # cyber + physical


def test_disclaimer_uses_config_value(db: RadarDB, monkeypatch) -> None:
    """NP7: disclaimer is sourced from config at build time."""
    monkeypatch.setattr(config, "V2_NP7_DISCLAIMER", "TEST DISCLAIMER VALUE")
    c = derive_threat_level(db, _state())
    assert c.final_judgment_disclaimer == "TEST DISCLAIMER VALUE"


def test_calibration_status_is_attached(db: RadarDB) -> None:
    """calibration_status_for() output must be embedded for NP5+8 traceability."""
    c = derive_threat_level(db, _state())
    assert isinstance(c.calibration_status, dict)
    # calibration_status_for returns a dict even when no analyst feedback yet
