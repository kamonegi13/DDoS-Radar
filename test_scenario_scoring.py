"""Tests for scenario scoring engine (Phase 2).

Covers: compute_scenario_score, dedup, convergence bonus, TL derivation,
dual-weight contribution, adversary contribution, edge cases.
"""
import pytest
import time

from radar.scenarios import (
    Role, Scenario, Participant, _parse_scenario_json,
    load_layer1,
)
from radar.scoring import (
    Signal, ScenarioContribution, ScenarioState,
    compute_scenario_score, dedup_by_source_country_max,
    compute_convergence_bonus_scenario, derive_tl,
    rationale_to_signal,
)
from radar.models import RationaleEntry


# ── Helpers ─────────────────────────────────────────────────────────────────

def _taiwan_scenario() -> Scenario:
    return _parse_scenario_json("taiwan_contingency", {
        "name_en": "Taiwan Contingency",
        "name_ja": "台湾有事",
        "core_country": "TW",
        "participants": {
            "TW": {"weight": 1.0, "role": "primary_target"},
            "US": {"weight": 0.8, "role": "primary_ally"},
            "JP": {"weight": 0.8, "role": "forward_base"},
            "CN": {"weight": 0.7, "role": "adversary"},
        },
    })


def _middle_east_scenario() -> Scenario:
    return _parse_scenario_json("middle_east", {
        "name_en": "Middle East",
        "name_ja": "中東紛争",
        "core_country": None,
        "participants": {
            "IL": {"weight": 1.0, "role": "principal_belligerent"},
            "IR": {"weight": 1.0, "role": "principal_belligerent"},
            "LB": {"weight": 0.7, "role": "proxy_front"},
            "US": {"weight": 0.6, "role": "force_projection"},
        },
    })


def _scs_disabled_scenario() -> Scenario:
    return _parse_scenario_json("south_china_sea", {
        "name_en": "South China Sea",
        "name_ja": "南シナ海",
        "core_country": "PH",
        "enabled": False,
        "participants": {
            "PH": {"weight": 1.0, "role": "primary_target"},
            "CN": {"weight": 0.7, "role": "adversary"},
        },
    })


def _signal(source: str, sensor: str, domain: str, countries: list,
            raw_score: float = 1.0, country_weights: dict = None) -> Signal:
    return Signal(
        signal_source=source,
        sensor=sensor,
        observed_at=time.time(),
        domain=domain,
        countries=countries,
        country_weights=country_weights or {},
        raw_score=raw_score,
        value_display=f"test:{source}",
    )


# ── Convergence bonus ──────────────────────────────────────────────────────

class TestConvergenceBonus:
    def test_three_domains(self):
        assert compute_convergence_bonus_scenario(["cyber", "physical", "info"]) == 2.0

    def test_two_domains(self):
        assert compute_convergence_bonus_scenario(["cyber", "physical"]) == 1.0

    def test_one_domain(self):
        assert compute_convergence_bonus_scenario(["cyber"]) == 0.0

    def test_empty(self):
        assert compute_convergence_bonus_scenario([]) == 0.0


# ── TL derivation ──────────────────────────────────────────────────────────

class TestDeriveTL:
    def test_tl1(self):
        assert derive_tl(10.0, ["cyber", "physical", "info"], 3.5) == 1

    def test_tl1_needs_physical(self):
        assert derive_tl(10.0, ["cyber", "physical", "info"], 2.9) == 2

    def test_tl2(self):
        assert derive_tl(6.5, ["cyber", "info"], 0.0) == 2

    def test_tl2_needs_two_domains(self):
        assert derive_tl(7.0, ["cyber"], 0.0) == 3

    def test_tl3(self):
        assert derive_tl(4.5, ["cyber"], 0.0) == 3

    def test_tl4(self):
        assert derive_tl(2.5, ["info"], 0.0) == 4

    def test_tl5(self):
        assert derive_tl(1.5, ["info"], 0.0) == 5


# ── Dedup ───────────────────────────────────────────────────────────────────

class TestDedup:
    def test_same_source_same_country_keeps_max(self):
        sig = _signal("bgp", "ioda_bgp", "cyber", ["TW"])
        c1 = ScenarioContribution(signal=sig, contributing_country="TW",
                                  llm_country_weight=1.0, participant_weight=1.0,
                                  participant_role="primary_target",
                                  final_contribution=2.0, formula_trace="")
        c2 = ScenarioContribution(signal=sig, contributing_country="TW",
                                  llm_country_weight=1.0, participant_weight=1.0,
                                  participant_role="primary_target",
                                  final_contribution=3.0, formula_trace="")
        result = dedup_by_source_country_max([c1, c2])
        assert len(result) == 1
        assert result[0].final_contribution == 3.0

    def test_same_source_different_country_both_kept(self):
        sig_tw = _signal("bgp", "ioda_bgp", "cyber", ["TW"])
        sig_jp = _signal("bgp", "ripe_bgp", "cyber", ["JP"])
        c1 = ScenarioContribution(signal=sig_tw, contributing_country="TW",
                                  llm_country_weight=1.0, participant_weight=1.0,
                                  participant_role="primary_target",
                                  final_contribution=2.0, formula_trace="")
        c2 = ScenarioContribution(signal=sig_jp, contributing_country="JP",
                                  llm_country_weight=1.0, participant_weight=0.8,
                                  participant_role="forward_base",
                                  final_contribution=1.6, formula_trace="")
        result = dedup_by_source_country_max([c1, c2])
        assert len(result) == 2

    def test_different_source_same_country_both_kept(self):
        sig1 = _signal("bgp", "ioda_bgp", "cyber", ["TW"])
        sig2 = _signal("cloudflare", "cloudflare_radar", "cyber", ["TW"])
        c1 = ScenarioContribution(signal=sig1, contributing_country="TW",
                                  llm_country_weight=1.0, participant_weight=1.0,
                                  participant_role="primary_target",
                                  final_contribution=2.0, formula_trace="")
        c2 = ScenarioContribution(signal=sig2, contributing_country="TW",
                                  llm_country_weight=1.0, participant_weight=1.0,
                                  participant_role="primary_target",
                                  final_contribution=1.5, formula_trace="")
        result = dedup_by_source_country_max([c1, c2])
        assert len(result) == 2


# ── compute_scenario_score ─────────────────────────────────────────────────

class TestComputeScenarioScore:
    def test_basic_focused(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=3.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        assert state.scenario_id == "taiwan_contingency"
        assert state.is_focused is True
        assert state.scoring_mode == "full"
        assert state.tl is not None
        assert state.score == 3.0  # 3.0 * 1.0(llm) * 1.0(pw) = 3.0, no convergence
        assert state.domains["cyber"] == 3.0
        assert len(state.contributions) == 1

    def test_background_no_tl(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=3.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=False)
        assert state.tl is None
        assert state.scoring_mode == "lite"

    def test_global_signal(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("greynoise", "greynoise", "cyber", [], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True,
                                       global_signal_weight=0.5)
        assert state.score == 1.0  # 2.0 * 0.5 = 1.0
        assert len(state.contributions) == 1
        assert state.contributions[0].contributing_country == "GLOBAL"

    def test_signal_countries_not_in_scenario_ignored(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["FR"], raw_score=3.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        assert state.score == 0.0
        assert len(state.contributions) == 0

    def test_domain_cap(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=10.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True,
                                       domain_cap=6.0)
        assert state.domains["cyber"] == 6.0
        assert state.score == 6.0

    def test_convergence_bonus_full(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=2.0),
            _signal("opensky", "opensky", "physical", ["TW"], raw_score=2.0),
            _signal("gdelt", "gdelt", "info", ["TW"], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        assert state.convergence_bonus == 2.0
        assert state.score == 2.0 + 2.0 + 2.0 + 2.0

    def test_convergence_bonus_dual(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=2.0),
            _signal("gdelt", "gdelt", "info", ["TW"], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        assert state.convergence_bonus == 1.0

    def test_to_dict(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=3.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        d = state.to_dict()
        assert d["id"] == "taiwan_contingency"
        assert d["tl"] is not None
        assert isinstance(d["contributions"], list)


# ── Dual-weight contribution (ADR-015) ─────────────────────────────────────

class TestDualWeight:
    def test_llm_signal_dual_country(self):
        """LLM signal countries=["US","TW"] with country_weights generates
        two contributions that both contribute to the scenario score."""
        sc = _taiwan_scenario()
        signals = [
            _signal("apt_intel", "apt_intel", "cyber", ["US", "TW"],
                    raw_score=3.0,
                    country_weights={"US": 1.0, "TW": 0.6}),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)

        assert len(state.contributions) == 2

        us_contrib = next(c for c in state.contributions if c.contributing_country == "US")
        tw_contrib = next(c for c in state.contributions if c.contributing_country == "TW")

        # US: 3.0 * 1.0 (llm) * 0.8 (participant) = 2.4
        assert abs(us_contrib.final_contribution - 2.4) < 0.001
        assert us_contrib.participant_role == "primary_ally"

        # TW: 3.0 * 0.6 (llm) * 1.0 (participant) = 1.8
        assert abs(tw_contrib.final_contribution - 1.8) < 0.001
        assert tw_contrib.participant_role == "primary_target"

        # Both should be in cyber domain total
        assert abs(state.domains["cyber"] - (2.4 + 1.8)) < 0.001

    def test_formula_trace_format(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("apt_intel", "apt_intel", "cyber", ["US"],
                    raw_score=3.0,
                    country_weights={"US": 1.0}),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        c = state.contributions[0]
        assert "3.00 (raw)" in c.formula_trace
        assert "1.00 (llm:US)" in c.formula_trace
        assert "0.80 (participant:US)" in c.formula_trace
        assert "2.40" in c.formula_trace


# ── Adversary contribution (ADR-014) ───────────────────────────────────────

class TestAdversaryContribution:
    def test_cn_threatfox_contributes(self):
        """CN signal with role=adversary, weight=0.7 contributes to Taiwan scenario."""
        sc = _taiwan_scenario()
        signals = [
            _signal("threatfox", "threatfox", "cyber", ["CN"], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        assert len(state.contributions) == 1
        c = state.contributions[0]
        assert c.contributing_country == "CN"
        assert c.participant_role == "adversary"
        # 2.0 * 1.0 (no llm cw) * 0.7 (adversary weight) = 1.4
        assert abs(c.final_contribution - 1.4) < 0.001

    def test_adversary_counted_in_active_countries(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("threatfox", "threatfox", "cyber", ["CN"], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        assert "CN" in state.active_countries


# ── Middle East (core_country=null, symmetric) ─────────────────────────────

class TestMiddleEast:
    def test_symmetric_belligerents(self):
        sc = _middle_east_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["IL"], raw_score=2.0),
            _signal("bgp", "ripe_bgp", "cyber", ["IR"], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        il = next(c for c in state.contributions if c.contributing_country == "IL")
        ir = next(c for c in state.contributions if c.contributing_country == "IR")
        # Both have weight 1.0
        assert abs(il.final_contribution - 2.0) < 0.001
        assert abs(ir.final_contribution - 2.0) < 0.001
        assert state.score == 2.0 + 2.0  # no convergence (single domain)


# ── SCS disabled ────────────────────────────────────────────────────────────

class TestDisabledScenario:
    def test_disabled_not_scorable(self):
        sc = _scs_disabled_scenario()
        assert sc.is_scorable is False


# ── Edge cases ──────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_no_signals(self):
        sc = _taiwan_scenario()
        state = compute_scenario_score(sc, [], is_focused=True)
        assert state.score == 0.0
        assert state.tl == 5
        assert state.contributions == []

    def test_empty_countries_not_scored_per_country(self):
        """Signal with empty countries treated as global."""
        sc = _taiwan_scenario()
        signals = [
            _signal("greynoise", "greynoise", "cyber", [], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True,
                                       global_signal_weight=0.5)
        assert len(state.contributions) == 1
        assert state.contributions[0].contributing_country == "GLOBAL"

    def test_dedup_across_multiple_sensors_same_source(self):
        """IODA and BGPRouting both use signal_source='bgp' for TW => MAX."""
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=2.0),
            _signal("bgp", "ripe_bgp", "cyber", ["TW"], raw_score=3.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True)
        assert len(state.contributions) == 1
        assert state.contributions[0].final_contribution == 3.0

    def test_mixed_global_and_per_country(self):
        sc = _taiwan_scenario()
        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=2.0),
            _signal("greynoise", "greynoise", "cyber", [], raw_score=2.0),
        ]
        state = compute_scenario_score(sc, signals, is_focused=True,
                                       global_signal_weight=0.5)
        # bgp:TW = 2.0, greynoise:GLOBAL = 1.0
        assert abs(state.domains["cyber"] - 3.0) < 0.001


# ── rationale_to_signal adapter ─────────────────────────────────────────────

class TestRationaleToSignal:
    def test_fired_converts(self):
        rat = RationaleEntry(sensor="ioda_bgp", domain="cyber", status="FIRED",
                             value="45%", score=2, signal_source="bgp")
        sig = rationale_to_signal(rat, source_country="TW")
        assert sig is not None
        assert sig.signal_source == "bgp"
        assert sig.countries == ["TW"]
        assert sig.raw_score == 2.0

    def test_suppressed_skipped(self):
        rat = RationaleEntry(sensor="ioda_bgp", domain="cyber", status="FIRED",
                             value="45%", score=2, signal_source="bgp",
                             suppressed=True)
        assert rationale_to_signal(rat) is None

    def test_ok_status_skipped(self):
        rat = RationaleEntry(sensor="ioda_bgp", domain="cyber", status="OK",
                             value="normal", score=0, signal_source="bgp")
        assert rationale_to_signal(rat) is None

    def test_zero_score_skipped(self):
        rat = RationaleEntry(sensor="gdelt", domain="info", status="FIRED",
                             value="tone=-20", score=0, signal_source="gdelt")
        assert rationale_to_signal(rat) is None

    def test_global_sensor_empty_country(self):
        rat = RationaleEntry(sensor="greynoise", domain="cyber", status="FIRED",
                             value="spike", score=1, signal_source="greynoise")
        sig = rationale_to_signal(rat, source_country="")
        assert sig is not None
        assert sig.countries == []

    def test_fallback_signal_source(self):
        rat = RationaleEntry(sensor="some_sensor", domain="cyber", status="FIRED",
                             value="x", score=1, signal_source="")
        sig = rationale_to_signal(rat, source_country="TW")
        assert sig.signal_source == "some_sensor"


# ── Full scenario scoring with real geo_data ────────────────────────────────

class TestRealGeoData:
    def test_load_and_score_all_scenarios(self):
        import json
        with open("geo_data.json", "r", encoding="utf-8") as f:
            geo = json.load(f)
        scenarios = load_layer1(geo)
        scorable = [s for s in scenarios.values() if s.is_scorable]
        assert len(scorable) == 4  # SCS is disabled

        signals = [
            _signal("bgp", "ioda_bgp", "cyber", ["TW"], raw_score=2.0),
            _signal("opensky", "opensky", "physical", ["TW"], raw_score=1.0),
            _signal("gdelt", "gdelt", "info", ["TW"], raw_score=1.0),
            _signal("apt_intel", "apt_intel", "cyber", ["CN"], raw_score=2.0),
            _signal("greynoise", "greynoise", "cyber", [], raw_score=1.0),
        ]

        for sc in scorable:
            state = compute_scenario_score(sc, signals, is_focused=(sc.id == "taiwan_contingency"))
            assert state.scenario_id == sc.id
            if sc.id == "taiwan_contingency":
                assert state.tl is not None
                assert state.score > 0
                # TW, CN both participants => should have contributions
                tw_contribs = [c for c in state.contributions if c.contributing_country == "TW"]
                cn_contribs = [c for c in state.contributions if c.contributing_country == "CN"]
                global_contribs = [c for c in state.contributions if c.contributing_country == "GLOBAL"]
                assert len(tw_contribs) > 0
                assert len(cn_contribs) > 0
                assert len(global_contribs) > 0
            else:
                assert state.tl is None
