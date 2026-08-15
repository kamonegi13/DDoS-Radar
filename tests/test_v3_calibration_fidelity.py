"""Every pinned calibration number, held by a test that will notice.

Two nets, because they catch different things:

1. `TestThresholdCatalogue` pins each value literally. Changing a
   calibration number then requires changing it in two places on purpose,
   which is the whole point of a value that no longer has a runtime dial.
   Without this, the first mutation run over `_PINNED` left 27 of 51
   mutants alive — numbers pinned, disclosed, and constrained by nothing.

2. `TestProductionFidelity` executes the AST gate in-process. S5-VERIF-039
   asks for a test per gate proving the gate was called and returned a
   verdict, precisely because G-07's gate called a function that did not
   exist and nobody noticed for months. A gate that only runs in CI is a
   gate whose failure mode is "CI was skipped".
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from v3.calibration import thresholds as T

REPO_ROOT = Path(__file__).resolve().parent.parent

#: name -> value. Regenerate deliberately, never by copying the module.
CATALOGUE: dict = {
    "AUTOTUNE_COOLDOWN_H": 72.0,
    "AUTOTUNE_MAX_MAGNITUDE_PCT": 10.0,
    "AUTOTUNE_MIN_SAMPLE_N": 30.0,
    "CALIBRATION_CACHE_TTL_SEC": 300.0,
    "CALIBRATION_WINDOW_D": 30.0,
    "CONFIDENCE_KINETIC": 0.6,
    "CONFIDENCE_POSTURE": 0.4,
    "CONFIDENCE_WITH_FATALITIES": 0.85,
    "DEGRADED_RECALL_FLOOR": 0.7,
    "DESIGN_W_MAX_DROP": 0.05,
    "GLOBAL_MIN_SIGNALS": 50.0,
    "GT_ALERT_SEVERITY_MIN": 3.0,
    "GT_FN_FATALITIES": 10.0,
    "GT_FORWARD_WINDOW_H": 72.0,
    "GT_FP_TN_HORIZON_D": 7.0,
    "GT_KINETIC_CONFIDENCE_FLOOR": 0.6,
    "GT_NOTE_TRUNCATE": 240.0,
    "HIGH_COOLDOWN_HOURS": 24.0,
    "MIN_RECALL_DENOM": 5.0,
    "MISSING_PARTICIPANT_EVENT_N": 3.0,
    "PROPOSAL_DEDUP_WINDOW_D": 7.0,
    "PROPOSAL_MAX_PENDING": 5.0,
    "PROPOSAL_WINDOW_D": 30.0,
    "RELEVANCE_MIN_RECOGNISED_COUNTRIES": 2.0,
    "SEVERITY_FLOOR_ESCALATION": 2.0,
    "SEVERITY_FLOOR_KINETIC": 3.0,
    "S9_POSITION_LOOKBACK_D": 9.0,
    "S9_RUN_INTERVAL_H": 24.0,
    "S9_TIER1_MIN_DISTINCT_SOURCES": 2.0,
    "S9_TIER2_DRAFTS_PER_CYCLE": 20.0,
    "S9_TIER2_MAX_TOKENS": 400.0,
    "SEVERITY_FLOOR_MASS_CASUALTY": 4.0,
    "TIER_CAP": 3.0,
    "TIER_CONSECUTIVE_FAILURE_LIMIT": 3.0,
    "TIER_DEMOTE_REVERT_RATE_24H": 0.2,
    "TIER_PROMOTE_0_TO_1_ROWS": 100.0,
    "TIER_PROMOTE_1_TO_2_DAYS": 7.0,
    "TIER_PROMOTE_2_TO_3_DAYS": 14.0,
    "TIER_PROMOTE_MAX_REVERT_RATE": 0.05,
    "TL_CALIB_DEGENERATE_PRECISION_MARGIN": 0.2,
    "TL_CALIB_LOOSER_FACTOR": 0.95,
    "TL_CALIB_MIN_FEEDBACK": 30.0,
    "TL_CALIB_PRECISION_CEILING": 0.3,
    "TL_CALIB_PRECISION_MIN_FLOOR": 0.1,
    "TL_CALIB_RECALL_FLOOR": 0.8,
    "TL_CALIB_ROUND_DIGITS": 3.0,
    "TL_CALIB_TIGHTEN_RECALL_FLOOR": 0.99,
    "TL_CALIB_TIGHTER_FACTOR": 1.05,
    "VITALITY_MIN_COVERAGE": 0.3,
    "VITALITY_SIGNAL_FLOOR": 5.0,
    "WEIGHT_CEILING": 0.95,
    "WEIGHT_FLOOR": 0.1,
    "WEIGHT_STEP_IMPROVER": 0.15,
    "WEIGHT_STEP_STRUCTURE_PROPOSER": 0.2,
    "ZERO_SOURCES_FOR_MODERATE": 3.0,
    "ZERO_SOURCES_FOR_STRONG": 5.0,
}


class TestThresholdCatalogue:

    @pytest.mark.parametrize("name", sorted(CATALOGUE))
    def test_each_pinned_value(self, name):
        assert T.disclosure()[name]["value"] == pytest.approx(
            CATALOGUE[name], abs=1e-12)

    def test_the_catalogue_covers_every_pinned_threshold(self):
        # A threshold added without a catalogue entry is a threshold no
        # test holds.
        assert set(T.disclosure()) == set(CATALOGUE)

    def test_every_pinned_threshold_discloses_its_provenance(self):
        for name, entry in T.disclosure().items():
            assert entry["provenance_ref"].strip(), name

    def test_every_provenance_cites_a_clause_or_a_module(self):
        for name, entry in T.disclosure().items():
            ref = entry["provenance_ref"]
            assert ("S1-CALIB-" in ref or "S1-CONC-" in ref
                    or "S5-VERIF-" in ref or ".py" in ref), name


class TestProductionFidelity:
    """S5-VERIF-039: the gate is executed, and returns a verdict."""

    def test_the_ast_gate_reports_no_unregistered_difference(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_calibration_thresholds.py"],
            capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert result.returncode == 0, (
            f"calibration thresholds drifted from production:\n"
            f"{result.stdout}\n{result.stderr}")

    def test_the_gate_actually_compared_something(self):
        # "0 differences" over 0 comparisons is what a silently broken
        # gate reports.
        result = subprocess.run(
            [sys.executable, "scripts/check_calibration_thresholds.py"],
            capture_output=True, text=True, cwd=str(REPO_ROOT))
        assert "compared against production by AST" in result.stdout
        count = int(result.stdout.split()[2])
        assert count >= 30, f"only {count} thresholds compared"
