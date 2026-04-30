"""Tests for radar/conclusions/sensitivity.py — falsification report (ADR-V2-016).

Pins:
  - threshold_distance to_higher_tl reports the right gap conditions
  - threshold_distance to_lower_tl reports the right triggers
  - signal_sensitivity computes hypothetical TL after a contribution drop
  - INSUFFICIENT_DATA case (current_tl=None) returns empty dict
  - boundary cases (TL1 = no higher, TL5 = no lower)
  - lockstep with radar.conclusions.threat_level.THRESHOLD_REF
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

from radar.conclusions.sensitivity import (
    compute_falsification,
    _derive_tl_from_components,
    _TL_RUNGS,
)
from radar.conclusions.threat_level import THRESHOLD_REF


# ── Lockstep with production threshold ladder ──────────────────────────────


def test_tl_rungs_match_threshold_ref():
    """If THRESHOLD_REF moves, _TL_RUNGS must move in lockstep — otherwise
    the falsification report disagrees with the actual derive_tl output."""
    rungs = {tl: req for tl, req in _TL_RUNGS}
    assert rungs[1]["score_min"] == THRESHOLD_REF["tl1_total"]
    assert rungs[1]["physical_min"] == THRESHOLD_REF["tl1_physical"]
    assert rungs[2]["score_min"] == THRESHOLD_REF["tl2_total"]
    assert rungs[2]["active_domains_min"] == THRESHOLD_REF["tl2_active_domains_min"]
    assert rungs[3]["score_min"] == THRESHOLD_REF["tl3_total"]
    assert rungs[4]["score_min"] == THRESHOLD_REF["tl4_total"]


def test_derive_tl_mirror_matches_production():
    """The pure-numeric mirror must agree with the production derive_tl
    on representative inputs."""
    from radar.scoring import derive_tl
    cases = [
        (10.0, ["physical", "cyber"], 4.0, 1),
        (7.0, ["cyber", "info"], 0.0, 2),
        (5.0, ["cyber"], 0.0, 3),
        (3.0, ["info"], 0.0, 4),
        (1.5, [], 0.0, 5),
        (8.5, ["cyber"], 5.0, 3),  # score<9 even though physical>=3
    ]
    for total, doms, phys, expected in cases:
        prod = derive_tl(total, doms, phys)
        mirror = _derive_tl_from_components(total, len(doms), phys)
        assert mirror == prod == expected, (total, doms, phys)


# ── threshold_distance.to_higher_tl ────────────────────────────────────────


def test_to_higher_tl_at_tl3_reports_score_gap_to_tl2():
    out = compute_falsification(
        score=4.2, active_domain_count=1, physical_score=0.0,
        convergence_bonus=0.0, rationale_matrix=[], current_tl=3,
    )
    higher = out["threshold_distance"]["to_higher_tl"]
    assert higher["target_tl"] == 2
    assert higher["all_satisfied"] is False
    fields = {c["field"] for c in higher["conditions"]}
    assert "score" in fields  # 4.2 < 6.0
    assert "active_domain_count" in fields  # 1 < 2
    score_cond = next(c for c in higher["conditions"] if c["field"] == "score")
    assert score_cond["gap"] == pytest.approx(1.8, abs=0.01)


def test_to_higher_tl_at_tl1_returns_none_target():
    out = compute_falsification(
        score=12.0, active_domain_count=3, physical_score=5.0,
        convergence_bonus=2.0, rationale_matrix=[], current_tl=1,
    )
    higher = out["threshold_distance"]["to_higher_tl"]
    assert higher["target_tl"] is None
    assert higher["all_satisfied"] is False


def test_to_higher_tl_all_conditions_met():
    """Edge case: current state already meets a higher rung — flag it
    so the analyst sees the discrepancy (e.g. hysteresis dwell or
    suppressed escalation)."""
    out = compute_falsification(
        score=10.0, active_domain_count=2, physical_score=4.0,
        convergence_bonus=1.0, rationale_matrix=[], current_tl=2,
    )
    higher = out["threshold_distance"]["to_higher_tl"]
    assert higher["target_tl"] == 1
    assert higher["all_satisfied"] is True
    assert higher["conditions"] == []


# ── threshold_distance.to_lower_tl ─────────────────────────────────────────


def test_to_lower_tl_reports_trigger_below_score():
    out = compute_falsification(
        score=4.5, active_domain_count=1, physical_score=0.0,
        convergence_bonus=0.0, rationale_matrix=[], current_tl=3,
    )
    lower = out["threshold_distance"]["to_lower_tl"]
    assert lower["target_tl"] == 4
    score_cond = next(c for c in lower["conditions"] if c["field"] == "score")
    assert score_cond["trigger_below"] == 4.0  # tl3_total
    assert score_cond["gap"] == pytest.approx(0.5, abs=0.01)


def test_to_lower_tl_at_tl5_returns_none():
    out = compute_falsification(
        score=1.0, active_domain_count=1, physical_score=0.0,
        convergence_bonus=0.0, rationale_matrix=[], current_tl=5,
    )
    lower = out["threshold_distance"]["to_lower_tl"]
    assert lower["target_tl"] is None
    assert lower["conditions"] == []


# ── signal_sensitivity ─────────────────────────────────────────────────────


def test_signal_sensitivity_top_n_sorted_descending():
    rm = [
        {"sensor": "a", "domain": "cyber", "contributing_country": "US",
         "final_contribution": 1.4, "suppress_reason": None},
        {"sensor": "b", "domain": "cyber", "contributing_country": "US",
         "final_contribution": 0.9, "suppress_reason": None},
        {"sensor": "c", "domain": "info", "contributing_country": "US",
         "final_contribution": 2.1, "suppress_reason": None},
    ]
    out = compute_falsification(
        score=4.4, active_domain_count=2, physical_score=0.0,
        convergence_bonus=1.0, rationale_matrix=rm, current_tl=3, top_n=3,
    )
    sigs = out["signal_sensitivity"]
    assert [s["sensor"] for s in sigs] == ["c", "a", "b"]


def test_signal_sensitivity_excludes_suppressed_and_global():
    rm = [
        {"sensor": "kept", "domain": "cyber", "contributing_country": "US",
         "final_contribution": 1.0, "suppress_reason": None},
        {"sensor": "supp", "domain": "cyber", "contributing_country": "US",
         "final_contribution": 5.0, "suppress_reason": "muted"},
        {"sensor": "glob", "domain": "info", "contributing_country": "GLOBAL",
         "final_contribution": 3.0, "suppress_reason": None},
    ]
    out = compute_falsification(
        score=2.0, active_domain_count=1, physical_score=0.0,
        convergence_bonus=0.0, rationale_matrix=rm, current_tl=4,
    )
    assert [s["sensor"] for s in out["signal_sensitivity"]] == ["kept"]


def test_signal_sensitivity_predicts_tl_drop_when_signal_zeroes():
    """Removing a signal that empties its only domain should drop TL."""
    rm = [
        {"sensor": "lone", "domain": "cyber", "contributing_country": "US",
         "final_contribution": 4.5, "suppress_reason": None},
    ]
    out = compute_falsification(
        score=4.5, active_domain_count=1, physical_score=0.0,
        convergence_bonus=0.0, rationale_matrix=rm, current_tl=3,
    )
    sigs = out["signal_sensitivity"]
    assert len(sigs) == 1
    # After removal: cyber=0, total=0, active=0 → TL=5 (less severe)
    assert sigs[0]["hypothetical_tl_if_drops_to_zero"] == 5
    assert sigs[0]["moves_tl_by"] == 2  # 3 → 5


# ── INSUFFICIENT_DATA + edge cases ─────────────────────────────────────────


def test_insufficient_data_returns_empty_dict():
    out = compute_falsification(
        score=0.0, active_domain_count=0, physical_score=0.0,
        convergence_bonus=0.0, rationale_matrix=[], current_tl=None,
    )
    assert out == {}


def test_no_rationale_matrix_returns_empty_signal_sensitivity():
    out = compute_falsification(
        score=4.5, active_domain_count=1, physical_score=0.0,
        convergence_bonus=0.0, rationale_matrix=[], current_tl=3,
    )
    assert out["signal_sensitivity"] == []
    # threshold_distance still populated
    assert out["threshold_distance"]["to_higher_tl"]["target_tl"] == 2
    assert out["threshold_distance"]["to_lower_tl"]["target_tl"] == 4
