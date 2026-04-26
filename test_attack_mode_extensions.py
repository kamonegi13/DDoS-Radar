"""Tests for radar/conclusions/attack_mode_extensions.py (Phase 2.5 hook).

Pins the scenario_extensions evaluation contract:

  - Extensions are read from `radar.config._raw_geo["SCENARIOS"][sid][...]`
  - Each extension fires when ALL declared conditions hold:
      * domain_floors (per-domain min score)
      * active_n_min (count of active_countries)
      * requires_participant (ISO-2 codes — all must be in active_countries)
  - Confidence is clamped to [0.55, 0.95]; margin above floor adds up to +0.30
  - Reserved base mode names are dropped (never override base classifier)
  - Bad config (missing `mode`, malformed lists) is silently dropped
  - Missing geo_data → returns [] (NP3 — deriver still classifies base modes)

Also pins the integration into derive_attack_mode():
  - Base + extension matches are merged and re-sorted by confidence
  - top mode in `state` may be a scenario_extensions mode when its
    confidence exceeds all base matches
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

from radar import config
from radar.conclusions.attack_mode import derive_attack_mode
from radar.conclusions.attack_mode_extensions import (
    ExtensionMatch,
    evaluate_extensions,
)
from radar.scoring import ScenarioContribution, ScenarioState, Signal


_NOW = 1_700_000_000.0


def _state(
    *,
    scenario_id: str = "taiwan_contingency",
    cyber: float = 0.0,
    physical: float = 0.0,
    info: float = 0.0,
    active_countries: list[str] | None = None,
) -> ScenarioState:
    return ScenarioState(
        scenario_id=scenario_id,
        is_focused=True,
        scoring_mode="full",
        score=cyber + physical + info,
        domains={"cyber": cyber, "physical": physical, "info": info},
        active_countries=active_countries or ["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=[],
    )


@pytest.fixture
def patched_geo(monkeypatch):
    """Replace _raw_geo with a controlled SCENARIOS map for these tests.

    Avoids depending on the live geo_data.json content (which can drift)
    while still exercising the same code path used in production.
    """
    def _inject(scenarios: dict) -> None:
        monkeypatch.setattr(config, "_raw_geo", {"SCENARIOS": scenarios})
    return _inject


# ---------- evaluate_extensions: empty / missing config ----------

def test_returns_empty_when_scenario_has_no_extensions(patched_geo):
    patched_geo({"taiwan_contingency": {"participants": {}}})
    assert evaluate_extensions(_state()) == []


def test_returns_empty_when_scenario_id_unknown(patched_geo):
    patched_geo({"other_scenario": {"attack_mode_extensions": [
        {"mode": "X", "domain_floors": {"cyber": 1.0}, "base_confidence": 0.6},
    ]}})
    assert evaluate_extensions(_state(scenario_id="taiwan_contingency")) == []


def test_returns_empty_when_geo_data_missing(monkeypatch):
    """NP3 — no geo_data must NOT crash the deriver."""
    monkeypatch.setattr(config, "_raw_geo", {})
    assert evaluate_extensions(_state()) == []


def test_returns_empty_when_extensions_block_is_not_a_list(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": "not-a-list"}})
    assert evaluate_extensions(_state()) == []


# ---------- evaluate_extensions: rule firing ----------

def test_extension_fires_when_all_floors_and_countries_match(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "NAVAL_BLOCKADE_PRECURSOR",
            "domain_floors": {"physical": 4.0, "info": 1.0},
            "active_n_min": 3,
            "requires_participant": ["CN"],
            "base_confidence": 0.6,
            "rule_summary": "naval blockade",
        }
    ]}})
    out = evaluate_extensions(_state(
        physical=5.0, info=1.5,
        active_countries=["TW", "JP", "CN"],
    ))
    assert len(out) == 1
    assert out[0].mode == "NAVAL_BLOCKADE_PRECURSOR"
    assert 0.55 <= out[0].confidence <= 0.95
    assert out[0].rule == "naval blockade"


def test_extension_does_not_fire_when_required_country_absent(patched_geo):
    """requires_participant is a hard gate — missing CN means no match."""
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "NAVAL_BLOCKADE_PRECURSOR",
            "domain_floors": {"physical": 4.0},
            "requires_participant": ["CN"],
            "base_confidence": 0.6,
        }
    ]}})
    out = evaluate_extensions(_state(
        physical=10.0,
        active_countries=["TW", "JP", "US"],
    ))
    assert out == []


def test_extension_does_not_fire_when_one_floor_unmet(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "X",
            "domain_floors": {"physical": 4.0, "info": 1.0},
            "base_confidence": 0.6,
        }
    ]}})
    # physical OK, info too low
    assert evaluate_extensions(_state(physical=5.0, info=0.5)) == []
    # info OK, physical too low
    assert evaluate_extensions(_state(physical=2.0, info=2.0)) == []


def test_extension_does_not_fire_when_active_n_below_min(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "X",
            "domain_floors": {"physical": 1.0},
            "active_n_min": 5,
            "base_confidence": 0.6,
        }
    ]}})
    assert evaluate_extensions(_state(
        physical=2.0, active_countries=["TW", "JP"],
    )) == []


# ---------- evaluate_extensions: confidence math ----------

def test_confidence_floor_and_ceiling_applied(patched_geo):
    """base_confidence outside [0.55, 0.85] gets clamped before margin."""
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {"mode": "TOO_LOW", "domain_floors": {"physical": 1.0}, "base_confidence": 0.1},
        {"mode": "TOO_HIGH", "domain_floors": {"physical": 1.0}, "base_confidence": 5.0},
    ]}})
    out = evaluate_extensions(_state(physical=1.0))  # zero margin
    by_mode = {m.mode: m for m in out}
    assert by_mode["TOO_LOW"].confidence == 0.55  # floor
    assert by_mode["TOO_HIGH"].confidence == 0.85  # ceiling-of-base + 0 margin


def test_strong_margin_increases_confidence_but_caps_at_0_95(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "X",
            "domain_floors": {"physical": 2.0},
            "base_confidence": 0.85,
        }
    ]}})
    out = evaluate_extensions(_state(physical=200.0))  # huge margin
    assert out[0].confidence == 0.95  # ceiling


def test_zero_margin_returns_base_confidence(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "X",
            "domain_floors": {"physical": 3.0},
            "base_confidence": 0.7,
        }
    ]}})
    out = evaluate_extensions(_state(physical=3.0))  # exactly at floor
    assert out[0].confidence == 0.7


# ---------- evaluate_extensions: malformed config ----------

def test_extension_without_mode_is_silently_dropped(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {"domain_floors": {"physical": 1.0}, "base_confidence": 0.6},  # no mode
        {"mode": "OK", "domain_floors": {"physical": 1.0}, "base_confidence": 0.6},
    ]}})
    out = evaluate_extensions(_state(physical=2.0))
    assert [m.mode for m in out] == ["OK"]


def test_extension_using_reserved_base_mode_is_dropped(patched_geo):
    """Extensions cannot shadow base classifier modes."""
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "DDOS_PRECURSOR",  # reserved
            "domain_floors": {"physical": 1.0},
            "base_confidence": 0.9,
        }
    ]}})
    assert evaluate_extensions(_state(physical=5.0)) == []


def test_duplicate_mode_only_first_wins(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {"mode": "DUP", "domain_floors": {"physical": 1.0}, "base_confidence": 0.6,
         "rule_summary": "first"},
        {"mode": "DUP", "domain_floors": {"physical": 1.0}, "base_confidence": 0.85,
         "rule_summary": "second"},
    ]}})
    out = evaluate_extensions(_state(physical=2.0))
    assert len(out) == 1
    assert out[0].rule == "first"


def test_non_dict_extension_entries_ignored(patched_geo):
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        "garbage",
        42,
        None,
        {"mode": "OK", "domain_floors": {"physical": 1.0}, "base_confidence": 0.6},
    ]}})
    out = evaluate_extensions(_state(physical=2.0))
    assert [m.mode for m in out] == ["OK"]


# ---------- integration with derive_attack_mode ----------

def test_extension_appears_in_ranked_modes_metadata(patched_geo):
    """Extensions merge with base matches and surface in ranked_modes."""
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "NAVAL_BLOCKADE_PRECURSOR",
            "domain_floors": {"physical": 4.0},
            "base_confidence": 0.85,
        }
    ]}})
    # physical=5 fires both KINETIC_PREPARATION (base) and NAVAL_BLOCKADE (ext)
    state = _state(physical=5.0)
    out = derive_attack_mode(state, now=_NOW)
    ranked = [r["mode"] for r in out.metadata["ranked_modes"]]
    assert "KINETIC_PREPARATION" in ranked
    assert "NAVAL_BLOCKADE_PRECURSOR" in ranked


def test_extension_can_become_top_mode_when_confidence_dominates(patched_geo):
    """If extension confidence > all base, it lands in `state` (top slot).

    physical=3.5 puts the base KINETIC_PREPARATION rule barely over its
    floor (conf ≈ 0.62), while a high-base_confidence extension lands
    at ≈0.90 — so the extension dominates the ranked list.
    """
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "PLA_AIR_INCURSION_SURGE",
            "domain_floors": {"physical": 3.0},
            "requires_participant": ["TW", "CN"],
            "base_confidence": 0.85,
        }
    ]}})
    state = _state(physical=3.5, active_countries=["TW", "CN"])
    out = derive_attack_mode(state, now=_NOW)
    assert out.state == "PLA_AIR_INCURSION_SURGE"


def test_no_extensions_means_pure_base_behavior(patched_geo):
    """Backward-compat: scenarios without extensions classify exactly as before."""
    patched_geo({"taiwan_contingency": {}})  # no extensions block
    state = _state(physical=5.0)
    out = derive_attack_mode(state, now=_NOW)
    # Only the base KINETIC_PREPARATION fires
    ranked = [r["mode"] for r in out.metadata["ranked_modes"]]
    assert ranked == ["KINETIC_PREPARATION"]


def test_extension_does_not_rescue_insufficient_signal_when_base_is_empty(patched_geo):
    """If neither base nor extensions match, INSUFFICIENT_SIGNAL still fires.

    This guards against a misconfigured floor=0 extension that would
    otherwise mask data scarcity.
    """
    patched_geo({"taiwan_contingency": {"attack_mode_extensions": [
        {
            "mode": "X",
            "domain_floors": {"physical": 100.0},  # unreachable
            "base_confidence": 0.6,
        }
    ]}})
    state = _state()  # all zeros
    out = derive_attack_mode(state, now=_NOW)
    assert out.state is None
    from radar.conclusions.base import ConclusionUnavailableReason
    assert out.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA


def test_extension_match_dataclass_is_immutable():
    """Frozen dataclass guards against accidental mutation downstream."""
    m = ExtensionMatch(mode="X", confidence=0.7, rule="r")
    with pytest.raises(Exception):
        m.confidence = 0.9  # type: ignore[misc]
