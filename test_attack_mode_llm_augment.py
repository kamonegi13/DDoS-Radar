"""Tests for radar.conclusions.attack_mode_llm.augment_attack_mode_with_llm.

Pins the LLM-augmentation contract for ATTACK_MODE conclusions (ADR-V2-005,
Phase 2 後半):

  1. Feature flag gating — disabled by default, no LLM call when off.
  2. NP3 — LLM unreachable returns the rule conclusion unchanged (plus an
     `attempted/ok=False` audit row in metadata when LLM was offline at
     llm_available time? No — we short-circuit BEFORE that branch and so
     return the original).
  3. NP4/NP1 — INSUFFICIENT_DATA rule rows are NEVER augmented (LLM cannot
     invent a mode the rules abstained on).
  4. Confidence nudge is clamped to ±0.10.
  5. State (the rule mode) is never overwritten by LLM agreement/disagree.
  6. llm_prompt_sha256 is stamped on the augmented row.
  7. Suggested alternative outside the known-mode set collapses to None.
  8. Agreement enum unknown values collapse to "unknown".
  9. JSON parse failure / HTTP error path records `attempted=True, ok=False`
     in metadata and preserves rule confidence.
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
    CYBER_DDOS_FLOOR,
    INFO_NARRATIVE_FLOOR,
    derive_attack_mode,
)
from radar.conclusions import attack_mode_llm as augm
from radar.scoring import ScenarioContribution, ScenarioState, Signal


@pytest.fixture(autouse=True)
def _enable_llm_augment(monkeypatch):
    """All tests in this module default to flag ON; individual tests flip off
    when they need to verify the gate.

    The augmentation path now consults the LLM Feature Hub
    (``radar.llm_features.is_enabled``) before falling back to the legacy
    config flag, so the Hub must also be force-enabled here. Without the
    Hub mock the registry returns its DB-backed default (False at test
    time), short-circuiting the augmentation and producing the original
    rule conclusion — which the contract assertions reject with
    KeyError('llm_augmentation') / identity mismatches.
    """
    monkeypatch.setattr(config, "V2_ATTACK_MODE_LLM_AUGMENT_ENABLED", True)
    # The augmentation path imports is_enabled lazily inside the function
    # body (`from radar.llm_features import is_enabled`), so we have to
    # patch the source module rather than the consumer.
    monkeypatch.setattr(
        "radar.llm_features.is_enabled",
        lambda _key: True,
    )


@pytest.fixture
def now() -> float:
    return 1_700_000_000.0


def _state(*, domains, active_countries=None) -> ScenarioState:
    return ScenarioState(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=sum(domains.values()),
        domains=domains,
        active_countries=active_countries or ["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=[],
    )


def _ddos_state() -> ScenarioState:
    return _state(domains={"cyber": CYBER_DDOS_FLOOR + 2.0,
                           "physical": 0.0,
                           "info": INFO_NARRATIVE_FLOOR + 0.5})


def _patch_llm(monkeypatch, *, available=True, ok=True, data=None,
               error="boom"):
    monkeypatch.setattr("radar.llm_client.llm_available", lambda: available)
    if ok:
        monkeypatch.setattr(
            "radar.llm_client.llm_analyze_json",
            lambda **_: {"ok": True, "data": dict(data or {})},
        )
    else:
        monkeypatch.setattr(
            "radar.llm_client.llm_analyze_json",
            lambda **_: {"ok": False, "data": {}, "error": error},
        )


# ---------- gating ----------

def test_disabled_flag_returns_original_unchanged(monkeypatch, now):
    # Both gates must be off: the LLM Feature Hub is checked first, then
    # the legacy config flag is consulted only if the Hub raised an
    # ImportError (NP3 fallback). The autouse fixture forces both ON, so
    # this test reverses both.
    monkeypatch.setattr(config, "V2_ATTACK_MODE_LLM_AUGMENT_ENABLED", False)
    monkeypatch.setattr("radar.llm_features.is_enabled", lambda _key: False)
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out is rule  # identity: no copy made


def test_llm_unavailable_returns_original_unchanged(monkeypatch, now):
    _patch_llm(monkeypatch, available=False)
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out is rule


def test_insufficient_data_rule_passes_through(monkeypatch, now):
    """NP4 + NP1: the LLM is never asked when rules abstained."""
    state = _state(domains={"cyber": 0.0, "physical": 0.0, "info": 0.0})
    rule = derive_attack_mode(state, now=now)
    assert rule.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA

    called = {"n": 0}

    def _spy(**_):
        called["n"] += 1
        return {"ok": True, "data": {"agreement": "agree"}}

    monkeypatch.setattr("radar.llm_client.llm_available", lambda: True)
    monkeypatch.setattr("radar.llm_client.llm_analyze_json", _spy)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert called["n"] == 0
    assert out is rule


# ---------- happy path ----------

def test_augmented_row_carries_state_and_narrative(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "agree",
        "suggested_alternative_mode": "DDOS_PRECURSOR",
        "narrative": "cyber surge with narrative buildup consistent with ddos precursor",
        "key_evidence": ["cyber spike", "info narrative cluster"],
        "confidence_adjustment": 0.05,
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)

    assert out.state == rule.state == "DDOS_PRECURSOR"
    aug = out.metadata["llm_augmentation"]
    assert aug["ok"] is True
    assert aug["agreement"] == "agree"
    assert aug["suggested_alternative_mode"] == "DDOS_PRECURSOR"
    assert "ddos precursor" in aug["narrative"]
    assert aug["key_evidence"] == ["cyber spike", "info narrative cluster"]
    assert aug["confidence_adjustment_applied"] == 0.05


def test_confidence_nudge_clamped_at_positive_max(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "agree",
        "confidence_adjustment": 5.0,  # absurd
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out.confidence <= rule.confidence + 0.10 + 1e-9


def test_confidence_nudge_clamped_at_negative_max(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "disagree",
        "confidence_adjustment": -5.0,
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out.confidence >= rule.confidence - 0.10 - 1e-9
    assert out.confidence >= 0.0


def test_state_never_overwritten_by_llm_disagreement(monkeypatch, now):
    """LLM may disagree, but rule mode remains the authority for `state`."""
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "disagree",
        "suggested_alternative_mode": "INFO_OPS_DOMINANT",
        "narrative": "I think info ops fits better",
        "confidence_adjustment": -0.05,
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out.state == "DDOS_PRECURSOR"
    assert out.metadata["llm_augmentation"]["suggested_alternative_mode"] == "INFO_OPS_DOMINANT"


def test_prompt_sha256_stamped_on_augmented_row(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={"agreement": "agree"})
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out.llm_prompt_sha256 and len(out.llm_prompt_sha256) == 64


# ---------- defensive parsing ----------

def test_unknown_alternative_mode_collapses_to_none(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "agree",
        "suggested_alternative_mode": "MADE_UP_MODE",
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out.metadata["llm_augmentation"]["suggested_alternative_mode"] is None


def test_unknown_agreement_collapses_to_unknown(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={"agreement": "lol"})
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert out.metadata["llm_augmentation"]["agreement"] == "unknown"


def test_evidence_capped_to_four_items_and_120_chars(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "agree",
        "key_evidence": [
            "x" * 200, "b", "c", "d", "e", "f",
        ],
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    ev = out.metadata["llm_augmentation"]["key_evidence"]
    assert len(ev) == 4
    assert len(ev[0]) == 120


def test_narrative_truncated_at_240_chars(monkeypatch, now):
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "agree",
        "narrative": "x" * 1000,
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert len(out.metadata["llm_augmentation"]["narrative"]) == 240


def test_llm_call_failure_records_attempt_and_preserves_confidence(monkeypatch, now):
    _patch_llm(monkeypatch, ok=False, error="timeout")
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    out = augm.augment_attack_mode_with_llm(rule, state)
    aug = out.metadata["llm_augmentation"]
    assert aug["attempted"] is True
    assert aug["ok"] is False
    assert aug["error"] == "timeout"
    assert out.confidence == rule.confidence
    assert out.state == rule.state


def test_rule_conclusion_is_not_mutated(monkeypatch, now):
    """frozen dataclass guarantee — augmentation must produce a new instance."""
    _patch_llm(monkeypatch, ok=True, data={
        "agreement": "agree",
        "confidence_adjustment": 0.05,
    })
    state = _ddos_state()
    rule = derive_attack_mode(state, now=now)
    rule_meta_before = dict(rule.metadata)
    rule_conf_before = rule.confidence
    out = augm.augment_attack_mode_with_llm(rule, state)
    assert rule.metadata == rule_meta_before
    assert rule.confidence == rule_conf_before
    assert out is not rule
