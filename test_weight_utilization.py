"""Tests for Phase 4 / Item 2.2: weight calibration advisory.

Background:
  Scenario participants have a static `weight` (Layer 2 / Layer 3
  override). This weight encodes the analyst's prior expectation of
  how much each country should contribute to scenario score. After
  weeks of operation, observed contribution shares may diverge from
  configured shares — meaning the static weight is mis-calibrated.

P5 / NP4 / NP6 alignment:
  This is REPORTING, not auto-mutation. The endpoint surfaces
  divergence and flags ADVISORY_REVIEW_NEEDED for analyst review.
  The static weight is never changed by the system — only the
  analyst can edit it via the existing scenario admin UI.

Item 2.2 introduces:
  - compute_weight_utilization(scenario, contributions, threshold)
    pure helper returning per-participant rows with:
      configured_weight, configured_share, observed_share,
      utilization_pct, flag, reason
  - Underperformance triggers ADVISORY_REVIEW_NEEDED
    (utilization < 1 - threshold/100 and configured_weight >= 0.3)
  - Overperformance is informational only (utilization > 1 + ...);
    no flag, but `note` field is set
  - Empty contributions or zero participants → empty list (graceful)
"""
from dataclasses import dataclass

import pytest

from radar.scenarios import Participant, Role, Scenario


@dataclass
class _StubSignal:
    domain: str = "info"
    sensor: str = "stub"
    signal_source: str = "stub_source"
    countries: list = None
    country_weights: dict = None
    raw_score: float = 1.0

    def __post_init__(self):
        self.countries = self.countries or []
        self.country_weights = self.country_weights or {}

    def to_dict(self):
        return {"sensor": self.sensor, "domain": self.domain}


def _scenario(participants: dict[str, float]) -> Scenario:
    return Scenario(
        id="test_sc",
        name_en="Test", name_ja="テスト",
        description_en="", description_ja="",
        core_country=list(participants.keys())[0] if participants else None,
        state="active", enabled=True, tier=1,
        participants={
            cc: Participant(country=cc, weight=w,
                            role=Role.PRIMARY_TARGET)
            for cc, w in participants.items()
        },
    )


def _contrib(country: str, final: float):
    from radar.scoring import ScenarioContribution
    return ScenarioContribution(
        signal=_StubSignal(countries=[country]),
        contributing_country=country,
        llm_country_weight=1.0,
        participant_weight=1.0,
        participant_role="primary_target",
        final_contribution=final,
        formula_trace="stub",
    )


# ── Pure helper: compute_weight_utilization ──────────────────────────────────


class TestComputeWeightUtilization:
    def test_returns_one_row_per_participant(self):
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"TW": 1.0, "US": 0.7, "JP": 0.4})
        contribs = [_contrib("TW", 5.0), _contrib("US", 3.0)]
        out = compute_weight_utilization(sc, contribs)
        countries = {r["country"] for r in out}
        assert countries == {"TW", "US", "JP"}

    def test_underperforming_participant_flagged(self):
        """YE configured weight 0.6 (= 0.6 / 1.0 = 60% of scenario);
        observed 5% (0.5 / 10.0). utilization = 5/60 = ~8% → flag."""
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"IL": 0.4, "YE": 0.6})
        contribs = [_contrib("IL", 9.5), _contrib("YE", 0.5)]
        out = compute_weight_utilization(sc, contribs, divergence_threshold_pct=30)
        ye = next(r for r in out if r["country"] == "YE")
        assert ye["flag"] == "ADVISORY_REVIEW_NEEDED", \
            f"YE should be flagged, got {ye!r}"
        assert ye["utilization_pct"] < 70

    def test_overperformer_not_flagged(self):
        """Over-performance is informational, not a flag.
        IL configured 0.4 (40%), observed 95% → utilization_pct ~237%
        → flag stays normal, but `note` is set so UI can hint at it."""
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"IL": 0.4, "YE": 0.6})
        contribs = [_contrib("IL", 9.5), _contrib("YE", 0.5)]
        out = compute_weight_utilization(sc, contribs, divergence_threshold_pct=30)
        il = next(r for r in out if r["country"] == "IL")
        assert il["flag"] == "normal", \
            f"IL over-performance should not flag, got {il!r}"
        assert il["utilization_pct"] > 130
        assert il.get("note") == "overperforming"

    def test_within_threshold_normal(self):
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"TW": 1.0, "US": 0.5})
        # configured shares: TW=66.7%, US=33.3%
        # observed:          TW=60%,   US=40%
        contribs = [_contrib("TW", 6.0), _contrib("US", 4.0)]
        out = compute_weight_utilization(sc, contribs, divergence_threshold_pct=30)
        for row in out:
            assert row["flag"] == "normal", \
                f"{row['country']} within threshold should be normal: {row!r}"

    def test_low_weight_participant_not_flagged_when_silent(self):
        """A participant with configured_weight < 0.3 (e.g. observer)
        should not flag even with 0 contribution — observers are
        expected to contribute little. Avoid alarm fatigue."""
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"TW": 1.0, "US": 0.7, "AU": 0.2})
        contribs = [_contrib("TW", 5.0), _contrib("US", 3.0)]
        out = compute_weight_utilization(sc, contribs)
        au = next(r for r in out if r["country"] == "AU")
        assert au["flag"] == "normal", \
            f"low-weight observer should not flag silent, got {au!r}"

    def test_no_contributions_returns_normal_for_all(self):
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"TW": 1.0, "US": 0.5})
        out = compute_weight_utilization(sc, [])
        assert len(out) == 2
        # Without observations there is no signal to flag — must be silent
        # so empty windows do not generate alerts
        for row in out:
            assert row["flag"] == "normal"
            assert row["observed_share"] == 0.0

    def test_empty_scenario_returns_empty(self):
        from radar.scoring import compute_weight_utilization
        sc = _scenario({})
        out = compute_weight_utilization(sc, [])
        assert out == []

    def test_global_contributions_excluded(self):
        """GLOBAL contributions (signals without country) must not
        skew the per-participant share computation."""
        from radar.scoring import compute_weight_utilization, ScenarioContribution
        sc = _scenario({"TW": 1.0, "US": 0.5})
        global_c = ScenarioContribution(
            signal=_StubSignal(),
            contributing_country="GLOBAL",
            llm_country_weight=1.0,
            participant_weight=0.5,
            participant_role="global",
            final_contribution=8.0,
            formula_trace="global",
        )
        contribs = [_contrib("TW", 6.0), _contrib("US", 4.0), global_c]
        out = compute_weight_utilization(sc, contribs)
        # Only TW (60%) + US (40%) count for shares, not GLOBAL
        tw = next(r for r in out if r["country"] == "TW")
        us = next(r for r in out if r["country"] == "US")
        assert abs(tw["observed_share"] - 0.6) < 0.01
        assert abs(us["observed_share"] - 0.4) < 0.01

    def test_flag_string_has_advisory_prefix(self):
        """ADR / NP7 audit: any flag the system raises must use the
        ADVISORY_ prefix so analysts can grep / filter for tool-side
        recommendations vs system-detected facts."""
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"IL": 0.4, "YE": 0.6})
        contribs = [_contrib("IL", 9.5), _contrib("YE", 0.5)]
        out = compute_weight_utilization(sc, contribs)
        flagged = [r for r in out if r["flag"] != "normal"]
        for r in flagged:
            assert r["flag"].startswith("ADVISORY_"), \
                f"flag {r['flag']!r} must use ADVISORY_ prefix"

    def test_reason_string_present_when_flagged(self):
        from radar.scoring import compute_weight_utilization
        sc = _scenario({"IL": 0.4, "YE": 0.6})
        contribs = [_contrib("IL", 9.5), _contrib("YE", 0.5)]
        out = compute_weight_utilization(sc, contribs)
        ye = next(r for r in out if r["country"] == "YE")
        assert ye.get("reason"), \
            f"flagged participant must include human-readable reason"
