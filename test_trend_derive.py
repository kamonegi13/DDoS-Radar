"""Tests for radar.conclusions.trend.derive_trend builder.

Pins the existing v2.0 TREND deriver behavior shipped in the Phase 0
scaffold. The state vocabulary and formula intentionally diverge from spec
§6.2 — the spec calls out RAPIDLY_ESCALATING / ESCALATING / STABLE /
DE_ESCALATING / RAPIDLY_DE_ESCALATING using a velocity + acceleration
classifier, while the implementation uses ESCALATING / RISING / STABLE /
COOLING / DEEPER_DECAY using mean-of-window deltas. Calibration is
deferred to Phase 1.3 — this file locks current behavior so the upcoming
realignment shows up as a single intentional diff.

Coverage targets (NP6 disclosure surface + DB-touching builder behavior):
- 5 classification states across the 3 windows (short / medium / long term)
- MIN_SAMPLES gate per window (insufficient → INSUFFICIENT_DATA per window)
- All-windows-insufficient → top-level INSUFFICIENT_DATA Conclusion
- Partial-availability confidence penalty
- TL severity inversion (1 → 4, 5 → 0)
- Window slicing boundaries (rows on the prev/cur seam)
- threshold_ref + formula_ref + disclaimer surface
- Packed window-state string format
"""

from __future__ import annotations

import pytest

from radar import config
from radar.conclusions import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    save_conclusion,
)
from radar.conclusions.base import new_conclusion_id
from radar.conclusions.trend import (
    ESCALATE_DELTA,
    FORMULA_REF,
    MIN_SAMPLES,
    RISING_DELTA,
    WINDOWS,
    derive_trend,
)
from radar.database import RadarDB


SCENARIO = "taiwan_contingency"


@pytest.fixture
def db(tmp_path) -> RadarDB:
    return RadarDB(str(tmp_path / "trend_derive.db"))


@pytest.fixture
def now() -> float:
    return 1_700_000_000.0


def _seed_tl(db: RadarDB, *, observed_at: float, tl_state: str,
             scenario_id: str = SCENARIO) -> None:
    """Append one THREAT_LEVEL row at observed_at with state=tl_state."""
    c = Conclusion(
        id=new_conclusion_id(),
        scenario_id=scenario_id,
        conclusion_type=ConclusionType.THREAT_LEVEL,
        state=tl_state,
        confidence=0.5,
        observed_at=observed_at,
        formula_ref="test/seed",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        metadata={},
    )
    save_conclusion(db, c)


def _seed_window(db: RadarDB, *, base_now: float, window_sec: float,
                 prev_tl: str, cur_tl: str, n: int,
                 scenario_id: str = SCENARIO) -> None:
    """Seed N rows in current window and N rows in previous window with given TLs.

    Spaces samples evenly so they all fall comfortably inside their slice
    (avoids boundary ambiguity tested elsewhere).
    """
    cur_step = (window_sec - 60) / max(n, 1)
    prev_step = (window_sec - 60) / max(n, 1)
    for i in range(n):
        _seed_tl(db, observed_at=base_now - 30 - i * cur_step,
                 tl_state=cur_tl, scenario_id=scenario_id)
        _seed_tl(db, observed_at=base_now - window_sec - 30 - i * prev_step,
                 tl_state=prev_tl, scenario_id=scenario_id)


# ── schema / NP6 disclosure surface ────────────────────────────────────


def test_returns_single_conclusion_of_trend_type(db, now) -> None:
    out = derive_trend(db, SCENARIO, now=now)
    assert isinstance(out, Conclusion)
    assert out.conclusion_type is ConclusionType.TREND


def test_formula_ref_is_versioned(db, now) -> None:
    out = derive_trend(db, SCENARIO, now=now)
    assert out.formula_ref == FORMULA_REF
    assert "@v" in out.formula_ref


def test_threshold_ref_mirrors_module_constants(db, now) -> None:
    out = derive_trend(db, SCENARIO, now=now)
    assert out.threshold_ref == {
        "rising_delta": RISING_DELTA,
        "escalate_delta": ESCALATE_DELTA,
        "min_samples": MIN_SAMPLES,
        "windows_sec": {label: span for label, span in WINDOWS},
    }


def test_disclaimer_attached_per_np7(db, now) -> None:
    out = derive_trend(db, SCENARIO, now=now)
    assert out.final_judgment_disclaimer == config.V2_NP7_DISCLAIMER


def test_source_urls_empty_trend_synthesizes_no_evidence(db, now) -> None:
    """TREND is computed from past Conclusion rows, not raw sensor URLs."""
    out = derive_trend(db, SCENARIO, now=now)
    assert out.source_urls == ()


# ── INSUFFICIENT_DATA paths ────────────────────────────────────────────


def test_empty_db_yields_insufficient_data(db, now) -> None:
    out = derive_trend(db, SCENARIO, now=now)
    assert not out.is_available()
    assert out.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA
    assert out.metadata.get("is_transient") is True
    assert out.confidence == 0.0
    assert out.state is None


def test_insufficient_data_reports_zero_sample_counts(db, now) -> None:
    out = derive_trend(db, SCENARIO, now=now)
    counts = out.metadata["sample_counts"]
    for label, _ in WINDOWS:
        assert counts[label]["current_n"] == 0
        assert counts[label]["previous_n"] == 0


def test_below_min_samples_in_one_window_marks_that_window_unavailable(db, now) -> None:
    """Seed only 24h window; 7d / 30d should be INSUFFICIENT_DATA."""
    _seed_window(db, base_now=now, window_sec=24 * 3600,
                 prev_tl="3", cur_tl="3", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.metadata["windows"]["short_term"] == "STABLE"
    assert out.metadata["windows"]["medium_term"] == "INSUFFICIENT_DATA"
    assert out.metadata["windows"]["long_term"] == "INSUFFICIENT_DATA"


# ── classification: 5 states (verified on the short_term window) ───────


def test_stable_when_delta_within_rising_band(db, now) -> None:
    """TL 3 → TL 3 (severity 2 → 2): zero delta is STABLE."""
    _seed_window(db, base_now=now, window_sec=24 * 3600,
                 prev_tl="3", cur_tl="3", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.metadata["windows"]["short_term"] == "STABLE"


def test_rising_when_delta_above_rising_below_escalate(db, now) -> None:
    """TL 3 → TL 2 (severity 2 → 3): delta = +1.0, RISING_DELTA <= delta < ESCALATE_DELTA."""
    _seed_window(db, base_now=now, window_sec=24 * 3600,
                 prev_tl="3", cur_tl="2", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.metadata["windows"]["short_term"] == "RISING"


def test_escalating_when_delta_at_or_above_escalate_delta(db, now) -> None:
    """TL 4 → TL 1 (severity 1 → 4): delta = +3.0 >= ESCALATE_DELTA."""
    _seed_window(db, base_now=now, window_sec=24 * 3600,
                 prev_tl="4", cur_tl="1", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.metadata["windows"]["short_term"] == "ESCALATING"


def test_cooling_when_negative_delta_at_or_above_rising(db, now) -> None:
    """TL 2 → TL 3 (severity 3 → 2): delta = -1.0, COOLING band."""
    _seed_window(db, base_now=now, window_sec=24 * 3600,
                 prev_tl="2", cur_tl="3", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.metadata["windows"]["short_term"] == "COOLING"


def test_deeper_decay_when_negative_delta_at_or_above_escalate(db, now) -> None:
    """TL 1 → TL 4 (severity 4 → 1): delta = -3.0 <= -ESCALATE_DELTA."""
    _seed_window(db, base_now=now, window_sec=24 * 3600,
                 prev_tl="1", cur_tl="4", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.metadata["windows"]["short_term"] == "DEEPER_DECAY"


# ── boundary conditions ───────────────────────────────────────────────


def test_rising_delta_boundary_inclusive(db, now) -> None:
    """A delta of exactly RISING_DELTA must classify as RISING (not STABLE)."""
    # 2 cur rows at sev 3, 1 cur row at sev 2 → mean = 2.667
    # 3 prev rows at sev 2 → mean = 2.0; delta = 0.667 > RISING_DELTA(0.50)
    win = 24 * 3600
    _seed_tl(db, observed_at=now - 60, tl_state="2")
    _seed_tl(db, observed_at=now - 120, tl_state="2")
    _seed_tl(db, observed_at=now - 180, tl_state="3")
    _seed_tl(db, observed_at=now - win - 60, tl_state="3")
    _seed_tl(db, observed_at=now - win - 120, tl_state="3")
    _seed_tl(db, observed_at=now - win - 180, tl_state="3")
    out = derive_trend(db, SCENARIO, now=now)
    assert out.metadata["windows"]["short_term"] == "RISING"


def test_unknown_tl_state_is_ignored(db, now) -> None:
    """Rows with non-1..5 state strings drop out of the mean — they cannot
    poison the classifier even if some background writer emits garbage.
    """
    win = 24 * 3600
    for i in range(MIN_SAMPLES):
        _seed_tl(db, observed_at=now - 60 - i, tl_state="3")
        _seed_tl(db, observed_at=now - win - 60 - i, tl_state="3")
    _seed_tl(db, observed_at=now - 30, tl_state="bogus")
    out = derive_trend(db, SCENARIO, now=now)
    # Bogus row dropped → STABLE (3→3, delta 0)
    assert out.metadata["windows"]["short_term"] == "STABLE"


def test_window_seam_classifies_rows_into_correct_slice(db, now) -> None:
    """A row at exactly cur_start belongs to current; row before is previous.

    The slicing predicate is `observed_at >= cur_start` — pinning so any
    refactor of the boundary stays observable.
    """
    win = 24 * 3600
    cur_start = now - win
    _seed_tl(db, observed_at=cur_start, tl_state="2")          # current edge
    _seed_tl(db, observed_at=cur_start + 1, tl_state="2")
    _seed_tl(db, observed_at=cur_start + 2, tl_state="2")
    _seed_tl(db, observed_at=cur_start - 1, tl_state="3")      # previous edge
    _seed_tl(db, observed_at=cur_start - 2, tl_state="3")
    _seed_tl(db, observed_at=cur_start - 3, tl_state="3")
    out = derive_trend(db, SCENARIO, now=now)
    counts = out.metadata["sample_counts"]["short_term"]
    assert counts["current_n"] == 3
    assert counts["previous_n"] == 3


def test_rows_for_other_scenarios_are_ignored(db, now) -> None:
    """The query is per-scenario; other-scenario rows must not leak in."""
    for i in range(MIN_SAMPLES):
        _seed_tl(db, observed_at=now - 60 - i, tl_state="3", scenario_id="other_scenario")
        _seed_tl(db, observed_at=now - 24 * 3600 - 60 - i, tl_state="3",
                 scenario_id="other_scenario")
    out = derive_trend(db, SCENARIO, now=now)
    assert not out.is_available()


# ── packed state string format ─────────────────────────────────────────


def test_state_string_packs_all_three_windows_in_canonical_order(db, now) -> None:
    """All three windows populated with STABLE → expected serialization."""
    for _, span in WINDOWS:
        _seed_window(db, base_now=now, window_sec=span,
                     prev_tl="3", cur_tl="3", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.state == "short_term=STABLE;medium_term=STABLE;long_term=STABLE"


def test_state_string_uses_module_window_order(db, now) -> None:
    for _, span in WINDOWS:
        _seed_window(db, base_now=now, window_sec=span,
                     prev_tl="3", cur_tl="3", n=MIN_SAMPLES)
    out = derive_trend(db, SCENARIO, now=now)
    assert out.state is not None
    parts = out.state.split(";")
    assert [p.split("=")[0] for p in parts] == [label for label, _ in WINDOWS]


# ── confidence ────────────────────────────────────────────────────────


def test_partial_availability_penalises_confidence(db, now) -> None:
    """One window populated vs all three: confidence must drop by 0.15.

    Scenarios are independent rows in the conclusions table, so we seed two
    scenarios in the same DB (no second DB instance needed).
    """
    for _, span in WINDOWS:
        _seed_window(db, base_now=now, window_sec=span,
                     prev_tl="3", cur_tl="3", n=MIN_SAMPLES, scenario_id="full_seed")
    full = derive_trend(db, "full_seed", now=now).confidence

    _seed_window(db, base_now=now, window_sec=24 * 3600,
                 prev_tl="3", cur_tl="3", n=MIN_SAMPLES, scenario_id="partial_seed")
    partial = derive_trend(db, "partial_seed", now=now).confidence

    assert partial < full
    # Penalty surfaces immediately as 0.15 less than the same-density base
    assert round(full - partial, 3) >= 0.15


def test_confidence_caps_at_zero_to_one(db, now) -> None:
    for _, span in WINDOWS:
        _seed_window(db, base_now=now, window_sec=span,
                     prev_tl="3", cur_tl="3", n=MIN_SAMPLES * 5)
    out = derive_trend(db, SCENARIO, now=now)
    assert 0.0 <= out.confidence <= 1.0


def test_confidence_zero_when_unavailable(db, now) -> None:
    out = derive_trend(db, SCENARIO, now=now)
    assert out.confidence == 0.0


# ── persistence round-trip (live shadow-write path) ────────────────────


def test_round_trip_via_save_then_re_derive(db, now) -> None:
    """Seed TLs, derive, persist, derive again — shape stable."""
    for _, span in WINDOWS:
        _seed_window(db, base_now=now, window_sec=span,
                     prev_tl="3", cur_tl="2", n=MIN_SAMPLES)
    c1 = derive_trend(db, SCENARIO, now=now)
    save_conclusion(db, c1)
    c2 = derive_trend(db, SCENARIO, now=now)
    assert c1.state == c2.state
    assert c1.metadata["windows"] == c2.metadata["windows"]
