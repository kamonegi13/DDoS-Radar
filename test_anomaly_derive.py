"""Tests for radar.conclusions.anomaly.derive_anomaly builder.

Validates the v2.0 ANOMALY Conclusion list produced from a ScenarioState:
- Output schema (formula_ref, threshold_ref, source_urls, disclaimer)
- INSUFFICIENT_DATA path when no scorable contribution exists (NP5+8 + NP1)
- Importance formula components (recency_decay, scenario_relevance, novelty)
- Ranking by importance + top-N truncation
- Confidence bounded to [0.0, 1.0] (since importance is clamped to [0, 100])
- GLOBAL contributions use participant_weight only (not multiplied by llm_cw)
- Metadata captures every formula component for replay
"""

from __future__ import annotations

import math
import time

import pytest

from radar import config
from radar.conclusions import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    derive_anomaly,
)
from radar.conclusions.anomaly import (
    DEFAULT_LIMIT,
    FORMULA_REF,
    THRESHOLD_REF,
    _RECENCY_TIME_CONSTANT_HOURS,
)
from radar.database import RadarDB
from radar.scoring import ScenarioContribution, ScenarioState, Signal


@pytest.fixture
def db(tmp_path) -> RadarDB:
    return RadarDB(str(tmp_path / "anomaly_derive.db"))


@pytest.fixture
def now() -> float:
    return 1_700_000_000.0


def _signal(
    *,
    signal_source: str = "apt_intel",
    sensor: str = "apt_intel",
    domain: str = "cyber",
    countries: list[str] | None = None,
    raw_score: float = 1.0,
    observed_at: float = 1_700_000_000.0,
    value_display: str = "",
    evidence_url: str | None = None,
) -> Signal:
    return Signal(
        signal_source=signal_source,
        sensor=sensor,
        observed_at=observed_at,
        domain=domain,
        countries=countries if countries is not None else ["TW"],
        country_weights={c: 1.0 for c in (countries or ["TW"])},
        raw_score=raw_score,
        value_display=value_display,
        evidence_url=evidence_url,
    )


def _contribution(
    sig: Signal,
    *,
    country: str = "TW",
    llm_country_weight: float = 1.0,
    participant_weight: float = 1.0,
    role: str = "primary_target",
    final_contribution: float | None = None,
) -> ScenarioContribution:
    fc = (
        final_contribution
        if final_contribution is not None
        else sig.raw_score * llm_country_weight * participant_weight
    )
    return ScenarioContribution(
        signal=sig,
        contributing_country=country,
        llm_country_weight=llm_country_weight,
        participant_weight=participant_weight,
        participant_role=role,
        final_contribution=fc,
        formula_trace="test",
    )


def _state(contributions: list[ScenarioContribution], **overrides) -> ScenarioState:
    base = dict(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=sum(c.final_contribution for c in contributions),
        domains={"cyber": 0.0, "physical": 0.0, "info": 0.0},
        active_countries=["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=contributions,
    )
    base.update(overrides)
    return ScenarioState(**base)


def test_returns_list_of_anomaly_conclusions(db: RadarDB, now: float) -> None:
    state = _state([_contribution(_signal(observed_at=now))])
    out = derive_anomaly(db, state, now=now)
    assert isinstance(out, list)
    assert all(isinstance(c, Conclusion) for c in out)
    assert all(c.conclusion_type is ConclusionType.ANOMALY for c in out)


def test_state_summary_includes_signal_source_and_value(db: RadarDB, now: float) -> None:
    sig = _signal(value_display="BGP withdrawal surge from AS4134", observed_at=now)
    out = derive_anomaly(db, _state([_contribution(sig)]), now=now)
    assert out[0].state == "apt_intel: BGP withdrawal surge from AS4134"


def test_state_summary_falls_back_to_signal_source_when_no_value(
    db: RadarDB, now: float
) -> None:
    sig = _signal(value_display="", observed_at=now)
    out = derive_anomaly(db, _state([_contribution(sig)]), now=now)
    assert out[0].state == "apt_intel"


def test_no_contributions_yields_single_insufficient_data(
    db: RadarDB, now: float
) -> None:
    """NP5+8 + NP1: empty tick must still emit a visible Conclusion."""
    state = _state([])
    out = derive_anomaly(db, state, now=now)
    assert len(out) == 1
    c = out[0]
    assert not c.is_available()
    assert c.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA
    assert c.metadata.get("is_transient") is True


def test_zero_raw_score_contributions_filtered(db: RadarDB, now: float) -> None:
    """Signals with raw_score=0 contribute nothing — they must not surface."""
    contributions = [
        _contribution(_signal(raw_score=0.0, observed_at=now)),
        _contribution(_signal(raw_score=0.0, observed_at=now)),
    ]
    out = derive_anomaly(db, _state(contributions), now=now)
    assert len(out) == 1
    assert not out[0].is_available()


def test_recency_decay_at_one_time_constant(db: RadarDB, now: float) -> None:
    """At τ = 12h elapsed, decay = e^-1 ≈ 0.368.

    Note: §6.4 calls this a "half-life" but the literal formula is a 1/e
    time constant; the actual half-life is 12·ln 2 ≈ 8.32h. This test pins
    the formula's behavior, not the misnomer.
    """
    sig = _signal(raw_score=1.0, observed_at=now - 12 * 3600)
    out = derive_anomaly(db, _state([_contribution(sig)]), now=now)
    decay = out[0].metadata["recency_decay"]
    assert math.isclose(decay, math.exp(-1.0), abs_tol=0.01)


def test_recency_decay_at_actual_half_life(db: RadarDB, now: float) -> None:
    """Sanity check: actual 50% point is τ·ln 2 hours after observation."""
    half_life_h = 12.0 * math.log(2)
    sig = _signal(raw_score=1.0, observed_at=now - half_life_h * 3600)
    out = derive_anomaly(db, _state([_contribution(sig)]), now=now)
    assert math.isclose(out[0].metadata["recency_decay"], 0.5, abs_tol=0.01)


def test_recency_decay_at_zero_elapsed_is_one(db: RadarDB, now: float) -> None:
    sig = _signal(raw_score=1.0, observed_at=now)
    out = derive_anomaly(db, _state([_contribution(sig)]), now=now)
    assert out[0].metadata["recency_decay"] == 1.0


def test_older_signal_has_lower_importance(db: RadarDB, now: float) -> None:
    fresh = _contribution(_signal(signal_source="fresh", observed_at=now))
    old = _contribution(
        _signal(signal_source="old", observed_at=now - 24 * 3600)
    )
    out = derive_anomaly(db, _state([old, fresh]), now=now)
    # fresh ranks first
    assert out[0].metadata["signal_source"] == "fresh"
    assert out[1].metadata["signal_source"] == "old"
    assert (
        out[0].metadata["importance_score"]
        > out[1].metadata["importance_score"]
    )


def test_top_n_limit_truncates(db: RadarDB, now: float) -> None:
    contributions = [
        _contribution(_signal(signal_source=f"src{i}", observed_at=now))
        for i in range(20)
    ]
    out = derive_anomaly(db, _state(contributions), now=now, limit=5)
    assert len(out) == 5


def test_default_limit_is_documented_constant(db: RadarDB, now: float) -> None:
    assert DEFAULT_LIMIT == THRESHOLD_REF["default_limit"]
    # And derive_anomaly without limit kwarg uses it
    contributions = [
        _contribution(_signal(signal_source=f"src{i}", observed_at=now))
        for i in range(DEFAULT_LIMIT + 5)
    ]
    out = derive_anomaly(db, _state(contributions), now=now)
    assert len(out) == DEFAULT_LIMIT


def test_novelty_factor_drops_for_repeated_signal_source(
    db: RadarDB, now: float
) -> None:
    """11 contributions sharing one signal_source → novelty floors at 0.3."""
    contributions = [
        _contribution(_signal(signal_source="repeated", observed_at=now))
        for _ in range(11)
    ]
    out = derive_anomaly(db, _state(contributions), now=now, limit=1)
    assert out[0].metadata["novelty_factor"] == pytest.approx(0.3, abs=0.01)


def test_novelty_factor_one_for_singleton_source(db: RadarDB, now: float) -> None:
    out = derive_anomaly(
        db, _state([_contribution(_signal(observed_at=now))]), now=now
    )
    assert out[0].metadata["novelty_factor"] == 1.0


def test_global_contribution_relevance_uses_participant_weight_only(
    db: RadarDB, now: float
) -> None:
    """GLOBAL signals have participant_weight = global_signal_weight already."""
    sig = _signal(countries=[], observed_at=now)
    c = _contribution(
        sig,
        country="GLOBAL",
        llm_country_weight=1.0,
        participant_weight=0.5,
        role="global",
        final_contribution=0.5,
    )
    out = derive_anomaly(db, _state([c]), now=now)
    assert out[0].metadata["scenario_relevance"] == pytest.approx(0.5)


def test_per_country_relevance_multiplies_llm_cw_and_participant_weight(
    db: RadarDB, now: float
) -> None:
    sig = _signal(observed_at=now)
    c = _contribution(sig, llm_country_weight=0.8, participant_weight=0.5)
    out = derive_anomaly(db, _state([c]), now=now)
    assert out[0].metadata["scenario_relevance"] == pytest.approx(0.4, abs=0.001)


def test_importance_clamped_to_unit_confidence(db: RadarDB, now: float) -> None:
    """Even with very large raw_score, confidence must stay in [0, 1]."""
    sig = _signal(raw_score=1000.0, observed_at=now)
    c = _contribution(sig, llm_country_weight=1.0, participant_weight=1.0)
    out = derive_anomaly(db, _state([c]), now=now)
    assert 0.0 <= out[0].confidence <= 1.0
    assert out[0].metadata["importance_score"] == 100.0


def test_source_urls_emitted_when_evidence_present(db: RadarDB, now: float) -> None:
    sig = _signal(evidence_url="https://example.com/evidence", observed_at=now)
    out = derive_anomaly(db, _state([_contribution(sig)]), now=now)
    assert out[0].source_urls == ("https://example.com/evidence",)


def test_source_urls_empty_when_no_evidence(db: RadarDB, now: float) -> None:
    sig = _signal(evidence_url=None, observed_at=now)
    out = derive_anomaly(db, _state([_contribution(sig)]), now=now)
    assert out[0].source_urls == ()


def test_metadata_captures_every_formula_component(db: RadarDB, now: float) -> None:
    sig = _signal(
        signal_source="apt_intel",
        sensor="apt_intel",
        domain="cyber",
        raw_score=2.0,
        observed_at=now - 6 * 3600,
    )
    c = _contribution(sig, country="TW", llm_country_weight=0.9, participant_weight=1.0)
    out = derive_anomaly(db, _state([c]), now=now)
    md = out[0].metadata
    for key in (
        "importance_score", "raw_score", "recency_decay", "scenario_relevance",
        "novelty_factor", "elapsed_hours", "domain", "contributing_country",
        "signal_source", "sensor", "novelty_source",
    ):
        assert key in md, f"metadata missing {key}"
    assert md["domain"] == "cyber"
    assert md["contributing_country"] == "TW"
    assert md["novelty_source"] == "current_tick_proxy"


def test_formula_ref_is_stable_constant(db: RadarDB, now: float) -> None:
    out = derive_anomaly(db, _state([_contribution(_signal(observed_at=now))]), now=now)
    assert out[0].formula_ref == FORMULA_REF


def test_threshold_ref_constants_match_implementation(db: RadarDB, now: float) -> None:
    """Drift guard: anyone changing the half-life or floor must update THRESHOLD_REF."""
    assert THRESHOLD_REF["recency_time_constant_hours"] == _RECENCY_TIME_CONSTANT_HOURS
    out = derive_anomaly(db, _state([_contribution(_signal(observed_at=now))]), now=now)
    assert out[0].threshold_ref["recency_time_constant_hours"] == _RECENCY_TIME_CONSTANT_HOURS
    assert out[0].threshold_ref["novelty_floor"] == 0.3
    assert out[0].threshold_ref["max_importance"] == 100.0


def test_disclaimer_uses_config_value(db: RadarDB, monkeypatch, now: float) -> None:
    """NP7: disclaimer is sourced from config at build time."""
    monkeypatch.setattr(config, "V2_NP7_DISCLAIMER", "TEST DISCLAIMER")
    out = derive_anomaly(db, _state([_contribution(_signal(observed_at=now))]), now=now)
    assert out[0].final_judgment_disclaimer == "TEST DISCLAIMER"


def test_calibration_status_attached_to_each_row(db: RadarDB, now: float) -> None:
    contributions = [
        _contribution(_signal(signal_source=f"src{i}", observed_at=now))
        for i in range(3)
    ]
    out = derive_anomaly(db, _state(contributions), now=now)
    assert all(isinstance(c.calibration_status, dict) for c in out)


def test_results_sorted_by_importance_descending(db: RadarDB, now: float) -> None:
    contributions = [
        _contribution(
            _signal(signal_source=f"src{i}", raw_score=float(i + 1), observed_at=now)
        )
        for i in range(5)
    ]
    out = derive_anomaly(db, _state(contributions), now=now)
    importances = [c.metadata["importance_score"] for c in out]
    assert importances == sorted(importances, reverse=True)
