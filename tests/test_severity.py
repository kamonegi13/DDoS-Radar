"""TL severity-direction sentinels.

The threat-level scale is DEFCON-style: TL1 = CRITICAL (most severe) …
TL5 = NORMAL (calm) — defined by ``radar.scoring.derive_tl``. Everyone's
intuition says "bigger number = worse", and inverting the scale in the
ground-truth classifier silently turned the entire calibration layer into
a reversed teacher signal (rewarding calm calls during real escalations)
— discovered 2026-07-03 after 30k contaminated labels.

These tests exist so that ANY future re-inversion fails CI immediately.
Do not weaken them; if the TL scale itself ever changes direction, that
is a v3-level breaking change and every consumer must be revisited.
"""

from __future__ import annotations

import pytest

from radar.conclusions.severity import (
    TL_CRITICAL,
    TL_ELEVATED,
    TL_HIGH,
    TL_NORMAL,
    TL_SEVERE,
    severity_of,
)
from radar.conclusions.ground_truth_etl import (
    EXPECTED_SEVERITY_ESCALATION,
    EXPECTED_SEVERITY_KINETIC,
    EXPECTED_SEVERITY_MASS_CASUALTY,
    expected_severity_floor,
    label_for_threat_level,
)
from radar.conclusions.feedback import FeedbackLabel
from radar.scoring import derive_tl


# ── scale direction ──────────────────────────────────────────────────────


def test_tl_constants_are_defcon_style():
    # Arrange / Act / Assert — the named levels pin the direction.
    assert TL_CRITICAL == 1
    assert TL_SEVERE == 2
    assert TL_HIGH == 3
    assert TL_ELEVATED == 4
    assert TL_NORMAL == 5


def test_severity_of_is_monotonically_decreasing_in_tl():
    # TL1 (CRITICAL) must map to the HIGHEST severity.
    sevs = [severity_of(tl) for tl in (1, 2, 3, 4, 5)]
    assert sevs == [5, 4, 3, 2, 1]


def test_severity_of_rejects_out_of_range_tl():
    for bad in (0, 6, -1, 99):
        with pytest.raises(ValueError):
            severity_of(bad)


def test_derive_tl_agrees_with_severity_direction():
    """The scoring engine's own mapping: max score → TL1, min score → TL5.
    If derive_tl ever flips, this fails before any classifier does."""
    worst = derive_tl(12.0, ["cyber", "physical"], 5.0)
    calm = derive_tl(0.0, [], 0.0)
    assert worst == TL_CRITICAL
    assert calm == TL_NORMAL
    assert severity_of(worst) > severity_of(calm)


# ── inversion sentinels for the graded ground-truth classifier ──────────
#
# These four are THE regression tests for the 2026-07-03 incident. A tool
# showing CRITICAL during a mass-casualty event is a success (TP); a tool
# showing NORMAL is the NP1-critical miss (FN). The broken classifier
# asserted the exact opposite.


def test_critical_tool_during_mass_casualty_is_true_positive():
    floor = expected_severity_floor(fatalities=25, confidence=0.85)
    label = label_for_threat_level(
        tool_tl=TL_CRITICAL, expected_severity_floor=floor,
    )
    assert label is FeedbackLabel.TRUE_POSITIVE


def test_normal_tool_during_mass_casualty_is_false_negative():
    floor = expected_severity_floor(fatalities=25, confidence=0.85)
    label = label_for_threat_level(
        tool_tl=TL_NORMAL, expected_severity_floor=floor,
    )
    assert label is FeedbackLabel.FALSE_NEGATIVE


def test_more_alarmed_tool_never_scores_worse_than_calmer_tool():
    """Monotonicity: for any event floor, if TL=x earns TP then every
    more-severe TL must also earn TP. The inverted classifier violated
    this for every floor."""
    for floor in (
        EXPECTED_SEVERITY_ESCALATION,
        EXPECTED_SEVERITY_KINETIC,
        EXPECTED_SEVERITY_MASS_CASUALTY,
    ):
        labels = [
            label_for_threat_level(tool_tl=tl, expected_severity_floor=floor)
            for tl in (1, 2, 3, 4, 5)  # CRITICAL → NORMAL
        ]
        # Once the labels turn FN going calmer, they must never turn back.
        seen_fn = False
        for lab in labels:
            if lab is FeedbackLabel.FALSE_NEGATIVE:
                seen_fn = True
            else:
                assert not seen_fn, (
                    f"non-monotonic grading at floor={floor}: {labels}"
                )
        # And the extremes are fixed: CRITICAL is never an under-rating,
        # NORMAL never satisfies a kinetic/mass-casualty floor.
        assert labels[0] is FeedbackLabel.TRUE_POSITIVE
        if floor >= EXPECTED_SEVERITY_KINETIC:
            assert labels[-1] is FeedbackLabel.FALSE_NEGATIVE


def test_expected_severity_floor_ladder():
    """Mass casualty demands ≥SEVERE, armed violence ≥HIGH, a bare
    escalation signal ≥ELEVATED — expressed in severity space."""
    mass = expected_severity_floor(fatalities=25, confidence=0.85)
    kinetic = expected_severity_floor(fatalities=2, confidence=0.60)
    escalation = expected_severity_floor(fatalities=0, confidence=0.40)
    assert mass == EXPECTED_SEVERITY_MASS_CASUALTY == severity_of(TL_SEVERE)
    assert kinetic == EXPECTED_SEVERITY_KINETIC == severity_of(TL_HIGH)
    assert escalation == EXPECTED_SEVERITY_ESCALATION == severity_of(TL_ELEVATED)
    assert mass > kinetic > escalation
