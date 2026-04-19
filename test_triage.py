"""Tests for radar.triage — pure functions powering analyst prioritization.

These tests pin the priority formula, gate ladder, and pulse aggregation that
are shared between /api/intel/pending/triage and /api/intel/stats. If these
two endpoints ever silently disagree on what counts as "high-priority and
overdue", the HUD's pulse indicator will fire on items the triage list does
not surface — so the contract is worth locking down.
"""
from __future__ import annotations

import math

import pytest

from radar.scenarios import Participant, Role, Scenario
from radar.triage import (
    ALLOWED_AUTO_CONFIRM_ECOSYSTEMS,
    CREDIBILITY_FLOOR,
    PRIORITY_AGE_TAU_SEC,
    PRIORITY_UNMATCHED_COUPLING_FLOOR,
    classify_gate,
    compute_priority,
    compute_pulse,
    derive_countries,
    enrich_pending,
    max_scenario_coupling,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_scenario(scenario_id: str, participants: dict[str, tuple[float, Role]]) -> Scenario:
    return Scenario(
        id=scenario_id,
        name_en=scenario_id,
        name_ja=scenario_id,
        description_en="",
        description_ja="",
        core_country=None,
        state="active",
        enabled=True,
        tier=1,
        participants={
            cc: Participant(country=cc, weight=w, role=role)
            for cc, (w, role) in participants.items()
        },
    )


def _stub_classify(eco_map: dict[str, str]):
    """Build a classify_ecosystem stub from a {source_id: ecosystem} map."""
    return lambda sid: eco_map.get(sid, "")


# ── derive_countries ────────────────────────────────────────────────────────

class TestDeriveCountries:
    def test_explicit_countries_win(self):
        assert derive_countries({"countries": ["tw", "us"], "theater": "JP-CN"}) == ["TW", "US"]

    def test_falls_back_to_dashed_theater(self):
        assert derive_countries({"countries": [], "theater": "TW-CN"}) == ["TW", "CN"]

    def test_single_country_theater(self):
        assert derive_countries({"theater": "JP"}) == ["JP"]

    def test_empty_returns_empty_list(self):
        assert derive_countries({}) == []
        assert derive_countries({"countries": [], "theater": ""}) == []

    def test_filters_empty_strings_in_countries(self):
        assert derive_countries({"countries": ["", "TW", None]}) == ["TW"]

    def test_strips_whitespace_in_theater_split(self):
        assert derive_countries({"theater": " TW - CN "}) == ["TW", "CN"]


# ── compute_priority ────────────────────────────────────────────────────────

class TestComputePriority:
    def test_fresh_high_confidence_full_coupling(self):
        # confidence=1, coupling=1, age=0 → priority=1
        assert compute_priority(1.0, 1.0, 0.0) == pytest.approx(1.0)

    def test_age_decay_at_tau(self):
        # At one tau (12h), age_decay = 1/e ≈ 0.3679
        p = compute_priority(1.0, 1.0, PRIORITY_AGE_TAU_SEC)
        assert p == pytest.approx(math.e ** -1, rel=1e-6)

    def test_unmatched_uses_floor(self):
        # coupling=0 → floor (0.30) kicks in instead of zeroing priority
        p = compute_priority(1.0, 0.0, 0.0)
        assert p == pytest.approx(PRIORITY_UNMATCHED_COUPLING_FLOOR)

    def test_negative_age_clamped_to_zero(self):
        # Future-dated items shouldn't get exp(positive) blow-up
        p = compute_priority(0.5, 0.5, -3600.0)
        assert p == pytest.approx(0.25)

    def test_low_confidence_dampens_priority(self):
        p = compute_priority(0.10, 1.0, 0.0)
        assert p == pytest.approx(0.10)


# ── max_scenario_coupling ───────────────────────────────────────────────────

class TestMaxScenarioCoupling:
    def test_no_match_returns_zero(self):
        sc = _make_scenario("sc1", {"TW": (0.9, Role.PRIMARY_TARGET)})
        max_w, top, matches = max_scenario_coupling(["JP"], [sc])
        assert max_w == 0.0
        assert top is None
        assert matches == []

    def test_picks_max_weight_across_scenarios(self):
        a = _make_scenario("a", {"TW": (0.5, Role.PRIMARY_TARGET)})
        b = _make_scenario("b", {"TW": (0.9, Role.PRIMARY_TARGET)})
        max_w, top, matches = max_scenario_coupling(["TW"], [a, b])
        assert max_w == 0.9
        assert top["id"] == "b"
        assert {m["scenario_id"] for m in matches} == {"a", "b"}

    def test_top_scenario_includes_role_and_country(self):
        sc = _make_scenario("sc", {"US": (0.8, Role.FORWARD_BASE)})
        _, top, _ = max_scenario_coupling(["US"], [sc])
        assert top["country"] == "US"
        assert top["role"] == "forward_base"
        assert top["coupling"] == 0.8

    def test_records_all_matches_for_drill_down(self):
        sc = _make_scenario("sc", {
            "TW": (0.9, Role.PRIMARY_TARGET),
            "US": (0.7, Role.PRIMARY_ALLY),
        })
        _, _, matches = max_scenario_coupling(["TW", "US"], [sc])
        assert len(matches) == 2


# ── classify_gate ───────────────────────────────────────────────────────────

class TestClassifyGate:
    def test_low_confidence_first(self):
        # Even with perfect credibility/ecosystem, low confidence dominates
        assert classify_gate(0.5, 0.99, "cert", 0.80) == "low_confidence"

    def test_low_credibility_after_confidence_passes(self):
        assert classify_gate(0.9, 0.50, "cert", 0.80) == "low_source_credibility"

    def test_credibility_floor_constant(self):
        # Right at the floor passes
        assert classify_gate(0.9, CREDIBILITY_FLOOR, "cert", 0.80) != "low_source_credibility"
        # One epsilon below fails
        assert classify_gate(0.9, CREDIBILITY_FLOOR - 0.01, "cert", 0.80) == "low_source_credibility"

    def test_ecosystem_blocked_returns_labeled_reason(self):
        assert classify_gate(0.9, 0.9, "state_media", 0.80) == "ecosystem_blocked:state_media"

    def test_ecosystem_unclassified(self):
        assert classify_gate(0.9, 0.9, "", 0.80) == "ecosystem_unclassified"

    def test_all_pass_yields_manual_review(self):
        # Hit every allowed ecosystem to make sure none accidentally block
        for eco in ALLOWED_AUTO_CONFIRM_ECOSYSTEMS:
            assert classify_gate(0.9, 0.9, eco, 0.80) == "manual_review"


# ── enrich_pending ──────────────────────────────────────────────────────────

class TestEnrichPending:
    def test_sorted_by_priority_desc(self):
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        items = [
            {"id": "low", "confidence": 0.3, "ts": 0, "countries": ["TW"], "source_id": "s1"},
            {"id": "high", "confidence": 0.95, "ts": 0, "countries": ["TW"], "source_id": "s1"},
            {"id": "mid", "confidence": 0.6, "ts": 0, "countries": ["TW"], "source_id": "s1"},
        ]
        sources = {"s1": {"credibility_weight": 0.8}}
        out = enrich_pending(
            items, sources, [sc],
            now=0.0,
            auto_confirm_threshold=0.80,
            classify_ecosystem=_stub_classify({"s1": "cert"}),
        )
        assert [e["id"] for e in out] == ["high", "mid", "low"]

    def test_unknown_source_uses_default_credibility(self):
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        items = [{"id": "i", "confidence": 0.9, "ts": 0, "countries": ["TW"], "source_id": "unknown"}]
        out = enrich_pending(
            items, sources={}, scenarios=[sc],
            now=0.0,
            auto_confirm_threshold=0.80,
            classify_ecosystem=_stub_classify({}),
        )
        # Default credibility 0.70 < CREDIBILITY_FLOOR (0.75)
        assert out[0]["source_credibility"] == 0.70
        assert out[0]["gate_reason"] == "low_source_credibility"

    def test_emits_corroboration_fields(self):
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        items = [{
            "id": "i", "confidence": 0.9, "ts": 0,
            "countries": ["TW"], "source_id": "s1",
            "llm_fields": {
                "corroborating_sources": ["s2", "s3"],
                "corroborating_ecosystems": ["cert", "independent"],
            },
        }]
        out = enrich_pending(
            items, sources={"s1": {"credibility_weight": 0.8}}, scenarios=[sc],
            now=0.0,
            auto_confirm_threshold=0.80,
            classify_ecosystem=_stub_classify({"s1": "cert"}),
        )
        assert out[0]["corroboration_count"] == 2
        assert out[0]["corroborating_ecosystems"] == ["cert", "independent"]

    def test_age_hours_and_decay_present(self):
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        # 12h old (one tau) → decay ≈ 0.3679, age_hours ≈ 12.0
        # Use ts=1.0 (not 0.0) because `it.get("ts") or now` treats 0.0 as
        # "missing" and falls back to now, masking the age calculation.
        items = [{
            "id": "i", "confidence": 0.9,
            "ts": 1.0, "countries": ["TW"], "source_id": "s1",
        }]
        out = enrich_pending(
            items, sources={"s1": {"credibility_weight": 0.8}}, scenarios=[sc],
            now=1.0 + PRIORITY_AGE_TAU_SEC,
            auto_confirm_threshold=0.80,
            classify_ecosystem=_stub_classify({"s1": "cert"}),
        )
        assert out[0]["age_hours"] == pytest.approx(12.0, abs=0.01)
        assert out[0]["age_decay"] == pytest.approx(math.e ** -1, abs=1e-3)


# ── compute_pulse ───────────────────────────────────────────────────────────

class TestComputePulse:
    def test_fresh_items_do_not_pulse(self):
        # Items younger than min_age_sec are excluded even if priority is high
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        items = [{"confidence": 0.95, "ts": 100.0, "countries": ["TW"]}]
        pulse = compute_pulse(items, [sc], now=200.0, threshold=0.5, min_age_sec=3600.0)
        assert pulse["count"] == 0

    def test_aged_high_priority_pulses(self):
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        # 5h old, 0.95 confidence → priority well above 0.5
        items = [{"confidence": 0.95, "ts": 1.0, "countries": ["TW"]}]
        pulse = compute_pulse(items, [sc], now=1.0 + 5 * 3600.0, threshold=0.5, min_age_sec=4 * 3600.0)
        assert pulse["count"] == 1
        assert pulse["oldest_stale_hours"] == pytest.approx(5.0, abs=0.01)

    def test_low_priority_excluded_even_when_aged(self):
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        # 0.10 confidence × 1.0 coupling × decay → well under threshold
        items = [{"confidence": 0.10, "ts": 1.0, "countries": ["TW"]}]
        pulse = compute_pulse(items, [sc], now=1.0 + 8 * 3600.0, threshold=0.5, min_age_sec=4 * 3600.0)
        assert pulse["count"] == 0

    def test_max_priority_tracked_independent_of_count(self):
        # Even items below the count gate contribute to max_priority
        sc = _make_scenario("sc", {"TW": (1.0, Role.PRIMARY_TARGET)})
        items = [{"confidence": 0.99, "ts": 100.0, "countries": ["TW"]}]
        pulse = compute_pulse(items, [sc], now=200.0, threshold=0.5, min_age_sec=3600.0)
        assert pulse["count"] == 0
        assert pulse["max_priority"] > 0.5
