"""Every number L4 uses, pinned with the clause that holds its value.

Same discipline as `v3/conclusions/thresholds.py`, and the same reason:
WP-2.6's sweep found 97 transcription infidelities in values that looked
correctly copied, and WP-3.1 found more inside code shipped earlier in its
own package. An S1 citation line is a LEAD; the production module constant
is the source, and the only reliable way to read it is to parse it.

`scripts/check_calibration_thresholds.py` re-runs that comparison as a CI
gate. Names it cannot reach — production keeps many of these as inline
`os.getenv(...)` defaults inside function bodies rather than as module
constants — are declared there as unreachable-with-a-reason, because a
gate that reports "N checked" and says nothing about the rest reads as
coverage it does not have.

S1-calibration §3 records that the calibration thresholds have **no** DB
override implemented anywhere: the only runtime-variable calibration
values are the proposal-applied ones, which travel through the threshold
ledger. So every entry here is `Threshold.pinned` (P6 O-18), and changing
one is a code change that forces review.
"""
from __future__ import annotations

from typing import Any

from v3.kernel import Threshold

_PINNED: dict[str, Threshold] = {
    # ── ground truth ETL (S1-CALIB-004/005/006/008) ────────────────────
    "GT_FORWARD_WINDOW_H": Threshold.pinned(
        72.0, unit="h",
        provenance_ref="S1-CALIB-005; radar/config.py "
                       "GROUND_TRUTH_WINDOW_HOURS default 72. The window "
                       "[observed_at, observed_at+72h] is CLOSED at both "
                       "ends"),
    "GT_FP_TN_HORIZON_D": Threshold.pinned(
        7.0, unit="d",
        provenance_ref="S1-CALIB-006; radar/config.py "
                       "GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS default 7. "
                       "Before it elapses neither FP nor TN may be "
                       "declared — a claim about an ABSENCE that no source "
                       "corroborates (incident #1: `auto:acled` was "
                       "claimed with ACLED unconfigured)"),
    "GT_FN_FATALITIES": Threshold.pinned(
        10.0, unit="count",
        provenance_ref="S1-CALIB-004; radar/config.py "
                       "GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES default 10"),
    "GT_ALERT_SEVERITY_MIN": Threshold.pinned(
        3.0, unit="index",
        provenance_ref="S1-CALIB-005; ground_truth_etl.py "
                       "_ALERT_SEVERITY_MIN. severity >= 3 means TL <= 3. "
                       "Incident #2's old form was `int(state) >= 3`, "
                       "which EXCLUDED CRITICAL and SEVERE"),
    "GT_NOTE_TRUNCATE": Threshold.pinned(
        240.0, unit="count",
        provenance_ref="S1-CALIB-007; ground_truth_etl.py _NOTE_TRUNCATE"),
    "SEVERITY_FLOOR_MASS_CASUALTY": Threshold.pinned(
        4.0, unit="index",
        provenance_ref="S1-CALIB-008; ground_truth_etl.py "
                       "EXPECTED_SEVERITY_MASS_CASUALTY (fatalities >= 10)"),
    "SEVERITY_FLOOR_KINETIC": Threshold.pinned(
        3.0, unit="index",
        provenance_ref="S1-CALIB-008; ground_truth_etl.py "
                       "EXPECTED_SEVERITY_KINETIC (fatalities >= 1 or "
                       "confidence >= 0.60)"),
    "SEVERITY_FLOOR_ESCALATION": Threshold.pinned(
        2.0, unit="index",
        provenance_ref="S1-CALIB-008; ground_truth_etl.py "
                       "EXPECTED_SEVERITY_ESCALATION (the posture floor a "
                       "bare weapon noun falls back to — incident #3)"),
    "GT_KINETIC_CONFIDENCE_FLOOR": Threshold.pinned(
        0.60, unit="ratio",
        provenance_ref="S1-CALIB-008/009; the confidence at which a "
                       "fatality-free kinetic match still earns the "
                       "kinetic severity floor"),
    "CONFIDENCE_WITH_FATALITIES": Threshold.pinned(
        0.85, unit="ratio",
        provenance_ref="S1-CALIB-009; rss_extractor confidence ladder, "
                       "fatality-bearing match"),
    "CONFIDENCE_KINETIC": Threshold.pinned(
        0.60, unit="ratio",
        provenance_ref="S1-CALIB-009; rss_extractor confidence ladder, "
                       "kinetic tier"),
    "CONFIDENCE_POSTURE": Threshold.pinned(
        0.40, unit="ratio",
        provenance_ref="S1-CALIB-009; rss_extractor confidence ladder, "
                       "posture tier — where a bare weapon noun lands"),
    "RELEVANCE_MIN_RECOGNISED_COUNTRIES": Threshold.pinned(
        2.0, unit="count",
        provenance_ref="S1-CALIB-010 rung 2; a weak kinetic verb qualifies "
                       "only with a military actor noun or >= 2 recognised "
                       "countries. Incident #2's follow-up: a bear-spray "
                       "incident and a typhoon were evidence for a Taiwan "
                       "contingency"),

    # ── recall metrics and calibration status ──────────────────────────
    "CALIBRATION_WINDOW_D": Threshold.pinned(
        30.0, unit="d",
        provenance_ref="S1-CALIB-027/028; radar/conclusions/calibration.py "
                       "_WINDOW_DAYS. DP4 records that CALIBRATION_WINDOW_"
                       "DAYS is registered nowhere, so the getattr default "
                       "of 30 always wins — here it is pinned rather than "
                       "pretend-configurable"),
    "MIN_RECALL_DENOM": Threshold.pinned(
        5.0, unit="count",
        provenance_ref="S1-CALIB-027 / S1-CONC-030; calibration.py "
                       "_MIN_RECALL_SAMPLES. tp+fn below this is "
                       "INSUFFICIENT_DATA, and `== 5` is sufficient"),
    "DEGRADED_RECALL_FLOOR": Threshold.pinned(
        0.70, unit="ratio",
        provenance_ref="S1-CALIB-027 / S1-CONC-030; calibration.py "
                       "_DEGRADED_RECALL_THRESHOLD. `recall == 0.70` is OK"),
    "CALIBRATION_CACHE_TTL_SEC": Threshold.pinned(
        300.0, unit="s",
        provenance_ref="S1-CONC-029; calibration.py _CACHE_TTL_SEC"),
    "DESIGN_W_MAX_DROP": Threshold.pinned(
        0.05, unit="ratio",
        provenance_ref="S1-CALIB-029 / S5-VERIF-038; "
                       "scripts/check_recall_baseline.py compare(max_drop). "
                       "`drop == max_drop` is on the PASSING side"),

    # ── TL threshold calibrator (S1-CALIB-014/015/018) ─────────────────
    "TL_CALIB_MIN_FEEDBACK": Threshold.pinned(
        30.0, unit="count",
        provenance_ref="S1-CALIB-014; tl_threshold_calibrator.py "
                       "TL_CALIB_MIN_FEEDBACK_PER_CELL default 30. `== 30` "
                       "passes"),
    "TL_CALIB_RECALL_FLOOR": Threshold.pinned(
        0.80, unit="ratio",
        provenance_ref="S1-CALIB-015 branch 1; CALIBRATOR_RECALL_FLOOR "
                       "default 0.80. `recall == 0.80` does NOT fire"),
    "TL_CALIB_PRECISION_CEILING": Threshold.pinned(
        0.30, unit="ratio",
        provenance_ref="S1-CALIB-015 branch 3; CALIBRATOR_PRECISION_CEILING "
                       "default 0.30. `precision == 0.30` does NOT fire"),
    "TL_CALIB_PRECISION_MIN_FLOOR": Threshold.pinned(
        0.10, unit="ratio",
        provenance_ref="S1-CALIB-015 branch 2; CALIBRATOR_PRECISION_MIN_FLOOR "
                       "default 0.10"),
    "TL_CALIB_DEGENERATE_PRECISION_MARGIN": Threshold.pinned(
        0.20, unit="ratio",
        provenance_ref="S1-CALIB-015 branch 2; the literal +0.20 in "
                       "`precision < PRECISION_MIN_FLOOR + 0.20`. "
                       "ACCIDENTAL A2: 0.10+0.20 lands exactly on the "
                       "tighten ceiling, so on a degenerate cell tighten "
                       "is unreachable whether the guard fires or not"),
    "TL_CALIB_TIGHTEN_RECALL_FLOOR": Threshold.pinned(
        0.99, unit="ratio",
        provenance_ref="S1-CALIB-015 branch 3; the literal 0.99 in "
                       "`recall >= 0.99 and precision < ceiling`"),
    "TL_CALIB_LOOSER_FACTOR": Threshold.pinned(
        0.95, unit="multiplier",
        provenance_ref="S1-CALIB-018; round(current * 0.95, 3)"),
    "TL_CALIB_TIGHTER_FACTOR": Threshold.pinned(
        1.05, unit="multiplier",
        provenance_ref="S1-CALIB-018; round(current * 1.05, 3)"),
    "TL_CALIB_ROUND_DIGITS": Threshold.pinned(
        3.0, unit="count",
        provenance_ref="S1-CALIB-018; the 3 in round(current*factor, 3)"),

    # ── S9 runner + Tier 1 convergence (WP-0.4 v2 / ADR-V3-012) ────────
    "S9_RUN_INTERVAL_H": Threshold.pinned(
        24.0, unit="h",
        provenance_ref="P4 S9 / v3/calibration/runner.py maybe_run: "
                       "前向きの流れとは別の遅い周期（日次〜週次）. Daily, "
                       "the fast end of that range — NP1 prefers labels "
                       "arriving a day early to a week late"),
    "S9_POSITION_LOOKBACK_D": Threshold.pinned(
        9.0, unit="d",
        provenance_ref="WP-0.4 v2, v3/calibration/runner.py s9_cycle: "
                       "GT_FP_TN_HORIZON_D (7d) + one daily cadence + one "
                       "day of slack. Positions younger than the horizon "
                       "classify to None and are re-visited on later runs; "
                       "the idempotent label/draft ids make the re-scan "
                       "converge instead of double-counting",),
    "S9_TIER1_MIN_DISTINCT_SOURCES": Threshold.pinned(
        2.0, unit="count",
        provenance_ref="WP-0.4 v2 Tier 1, v3/calibration/etl.py "
                       "tier1_decision (NP2: 単一ソース依存禁止): an FN "
                       "auto-confirms only when >=2 distinct non-circular "
                       "sources converge; a single-source candidate waits "
                       "as a pending draft and widens the recall interval "
                       "instead of entering the denominator unaudited"),

    # ── auto-tune governor (S1-CALIB-062/063) ──────────────────────────
    "AUTOTUNE_MIN_SAMPLE_N": Threshold.pinned(
        30.0, unit="count",
        provenance_ref="S1-CALIB-062 rule 1; AUTO_TUNE min sample default "
                       "30, `== 30` passes"),
    "AUTOTUNE_COOLDOWN_H": Threshold.pinned(
        72.0, unit="h",
        provenance_ref="S1-CALIB-062 rule 4; per (key, scope), "
                       "`elapsed == cooldown` passes"),
    "AUTOTUNE_MAX_MAGNITUDE_PCT": Threshold.pinned(
        10.0, unit="percent",
        provenance_ref="S1-CALIB-063; exceeding it CLAMPS rather than "
                       "rejects, and the ledger records the clamped value. "
                       "ACCIDENTAL A3: the calibrator's own +-5% never "
                       "reaches this budget"),

    # ── tier governor (S1-CALIB-056/058/061) ───────────────────────────
    "TIER_PROMOTE_0_TO_1_ROWS": Threshold.pinned(
        100.0, unit="count",
        provenance_ref="S1-CALIB-058; auto_apply_tier_governor.py "
                       "PROMOTE_TIER0_TO_TIER1['min_auto_feedback_rows']"),
    "TIER_PROMOTE_1_TO_2_DAYS": Threshold.pinned(
        7.0, unit="d",
        provenance_ref="S1-CALIB-058; PROMOTE_TIER1_TO_TIER2"
                       "['min_days_at_tier']"),
    "TIER_PROMOTE_2_TO_3_DAYS": Threshold.pinned(
        14.0, unit="d",
        provenance_ref="S1-CALIB-058; PROMOTE_TIER2_TO_TIER3"
                       "['min_days_at_tier']"),
    "TIER_PROMOTE_MAX_REVERT_RATE": Threshold.pinned(
        0.05, unit="ratio",
        provenance_ref="S1-CALIB-058; PROMOTE_TIER*['max_revert_rate'], "
                       "the same 0.05 for both promotions"),
    "TIER_DEMOTE_REVERT_RATE_24H": Threshold.pinned(
        0.20, unit="ratio",
        provenance_ref="S1-CALIB-058; DEMOTE_TIER*_TO_*"
                       "['max_revert_rate_24h'], identical for all three. "
                       "The hysteresis is 0.05 over 7/14d against 0.20 "
                       "over 24h"),
    "TIER_CONSECUTIVE_FAILURE_LIMIT": Threshold.pinned(
        3.0, unit="count",
        provenance_ref="S1-CALIB-061; auto_apply_tier_governor.py "
                       "CONSECUTIVE_FAILURE_LIMIT — the circuit breaker"),
    "HIGH_COOLDOWN_HOURS": Threshold.pinned(
        24.0, unit="h",
        provenance_ref="S1-CALIB-061; auto_apply_tier_governor.py "
                       "HIGH_COOLDOWN_HOURS_DEFAULT. Holds low and med; "
                       "HIGH itself is exempt"),
    "TIER_CAP": Threshold.pinned(
        3.0, unit="index",
        provenance_ref="S1-CALIB-061; auto_apply_tier_governor.py "
                       "TIER_FULL is the ceiling. ACCIDENTAL A12: "
                       "production falls back to this maximum on a bad "
                       "AUTO_CALIBRATION_TIER_CAP value, which empties the "
                       "kill switch"),

    # ── proposal issue path (S1-CALIB-034/035/039/040/047) ─────────────
    "PROPOSAL_DEDUP_WINDOW_D": Threshold.pinned(
        7.0, unit="d",
        provenance_ref="S1-CALIB-040; SCENARIO_IMPROVER_DEDUP_DAYS "
                       "default 7, over state IN ('pending','applied')"),
    "PROPOSAL_MAX_PENDING": Threshold.pinned(
        5.0, unit="count",
        provenance_ref="S1-CALIB-040; SCENARIO_IMPROVER_MAX_ACTIVE "
                       "default 5"),
    "WEIGHT_STEP_IMPROVER": Threshold.pinned(
        0.15, unit="score",
        provenance_ref="S1-CALIB-034; SCENARIO_IMPROVER_WEIGHT_STEP "
                       "default 0.15"),
    "WEIGHT_STEP_STRUCTURE_PROPOSER": Threshold.pinned(
        0.20, unit="score",
        provenance_ref="S1-CALIB-047; the structure proposer's hardcoded "
                       "0.20. ACCIDENTAL A8: different from the "
                       "improver's 0.15 with no stated reason"),
    "WEIGHT_CEILING": Threshold.pinned(
        0.95, unit="ratio",
        provenance_ref="S1-CALIB-034; round(min(0.95, w + step), 2)"),
    "WEIGHT_FLOOR": Threshold.pinned(
        0.10, unit="ratio",
        provenance_ref="S1-CALIB-035/047; round(max(0.10, w - step), 2)"),
    "MISSING_PARTICIPANT_EVENT_N": Threshold.pinned(
        3.0, unit="count",
        provenance_ref="S1-CALIB-039; SCENARIO_IMPROVER_MISSING_EVENT_N "
                       "default 3, scoped by scenario_id (the 2026-04-29 "
                       "secondary accident: UA proposed to all 5 "
                       "scenarios)"),
    "PROPOSAL_WINDOW_D": Threshold.pinned(
        30.0, unit="d",
        provenance_ref="S1-CALIB-034/039/047; the 30-day contribution "
                       "window, hardcoded in production"),
    "VITALITY_SIGNAL_FLOOR": Threshold.pinned(
        5.0, unit="count",
        provenance_ref="S1-CALIB-038; the scenario vitality floor"),
    "VITALITY_MIN_COVERAGE": Threshold.pinned(
        0.30, unit="ratio",
        provenance_ref="S1-CALIB-038; minimum sensor coverage before a "
                       "scenario is called data_gap rather than dormant"),
    "GLOBAL_MIN_SIGNALS": Threshold.pinned(
        50.0, unit="count",
        provenance_ref="S1-CALIB-038; the global signal floor below which "
                       "recall-reducing proposals are suppressed "
                       "scenario-wide. Derived from the upstream-outage "
                       "accident where 5/5 zero sources read as `strong` "
                       "evidence of dormancy for every participant"),
    "ZERO_SOURCES_FOR_STRONG": Threshold.pinned(
        5.0, unit="count",
        provenance_ref="S1-CALIB-036; ALL five sources must be zero for "
                       "`strong`. The docstring says >= 4 — DP1"),
    "ZERO_SOURCES_FOR_MODERATE": Threshold.pinned(
        3.0, unit="count",
        provenance_ref="S1-CALIB-036; >= 3 zero sources is `moderate`"),
}


def _pinned_number(name: str) -> float:
    resolved = _PINNED[name].resolve().value
    return float(getattr(resolved, "value", resolved))


def disclosure() -> dict[str, Any]:
    """Every pinned calibration threshold with its value and provenance."""
    return {name: {"value": _pinned_number(name), "unit": threshold.unit,
                   "provenance_ref": threshold.provenance_ref}
            for name, threshold in sorted(_PINNED.items())}


GT_FORWARD_WINDOW_H = _pinned_number("GT_FORWARD_WINDOW_H")
GT_FORWARD_WINDOW_SEC = GT_FORWARD_WINDOW_H * 3600.0
GT_FP_TN_HORIZON_D = _pinned_number("GT_FP_TN_HORIZON_D")
GT_FP_TN_HORIZON_SEC = GT_FP_TN_HORIZON_D * 86400.0
GT_FN_FATALITIES = int(_pinned_number("GT_FN_FATALITIES"))
GT_ALERT_SEVERITY_MIN = int(_pinned_number("GT_ALERT_SEVERITY_MIN"))
GT_NOTE_TRUNCATE = int(_pinned_number("GT_NOTE_TRUNCATE"))
SEVERITY_FLOOR_MASS_CASUALTY = int(_pinned_number(
    "SEVERITY_FLOOR_MASS_CASUALTY"))
SEVERITY_FLOOR_KINETIC = int(_pinned_number("SEVERITY_FLOOR_KINETIC"))
SEVERITY_FLOOR_ESCALATION = int(_pinned_number("SEVERITY_FLOOR_ESCALATION"))
GT_KINETIC_CONFIDENCE_FLOOR = _pinned_number("GT_KINETIC_CONFIDENCE_FLOOR")
CONFIDENCE_WITH_FATALITIES = _pinned_number("CONFIDENCE_WITH_FATALITIES")
CONFIDENCE_KINETIC = _pinned_number("CONFIDENCE_KINETIC")
CONFIDENCE_POSTURE = _pinned_number("CONFIDENCE_POSTURE")
RELEVANCE_MIN_RECOGNISED_COUNTRIES = int(_pinned_number(
    "RELEVANCE_MIN_RECOGNISED_COUNTRIES"))

CALIBRATION_WINDOW_D = _pinned_number("CALIBRATION_WINDOW_D")
CALIBRATION_WINDOW_SEC = CALIBRATION_WINDOW_D * 86400.0
MIN_RECALL_DENOM = int(_pinned_number("MIN_RECALL_DENOM"))
DEGRADED_RECALL_FLOOR = _pinned_number("DEGRADED_RECALL_FLOOR")
CALIBRATION_CACHE_TTL_SEC = _pinned_number("CALIBRATION_CACHE_TTL_SEC")
DESIGN_W_MAX_DROP = _pinned_number("DESIGN_W_MAX_DROP")

CALIBRATOR_MIN_FEEDBACK = int(_pinned_number("TL_CALIB_MIN_FEEDBACK"))
CALIBRATOR_RECALL_FLOOR = _pinned_number("TL_CALIB_RECALL_FLOOR")
CALIBRATOR_PRECISION_CEILING = _pinned_number("TL_CALIB_PRECISION_CEILING")
CALIBRATOR_PRECISION_MIN_FLOOR = _pinned_number("TL_CALIB_PRECISION_MIN_FLOOR")
CALIBRATOR_DEGENERATE_PRECISION_MARGIN = _pinned_number(
    "TL_CALIB_DEGENERATE_PRECISION_MARGIN")
CALIBRATOR_TIGHTEN_RECALL_FLOOR = _pinned_number("TL_CALIB_TIGHTEN_RECALL_FLOOR")
CALIBRATOR_LOOSER_FACTOR = _pinned_number("TL_CALIB_LOOSER_FACTOR")
CALIBRATOR_TIGHTER_FACTOR = _pinned_number("TL_CALIB_TIGHTER_FACTOR")
CALIBRATOR_ROUND_DIGITS = int(_pinned_number("TL_CALIB_ROUND_DIGITS"))

S9_RUN_INTERVAL_H = _pinned_number("S9_RUN_INTERVAL_H")
S9_RUN_INTERVAL_SEC = S9_RUN_INTERVAL_H * 3600.0
S9_POSITION_LOOKBACK_D = _pinned_number("S9_POSITION_LOOKBACK_D")
S9_POSITION_LOOKBACK_SEC = S9_POSITION_LOOKBACK_D * 86400.0
S9_TIER1_MIN_DISTINCT_SOURCES = int(_pinned_number(
    "S9_TIER1_MIN_DISTINCT_SOURCES"))

AUTOTUNE_MIN_SAMPLE_N = int(_pinned_number("AUTOTUNE_MIN_SAMPLE_N"))
AUTOTUNE_COOLDOWN_H = _pinned_number("AUTOTUNE_COOLDOWN_H")
AUTOTUNE_MAX_MAGNITUDE_PCT = _pinned_number("AUTOTUNE_MAX_MAGNITUDE_PCT")

TIER_PROMOTE_0_TO_1_ROWS = int(_pinned_number("TIER_PROMOTE_0_TO_1_ROWS"))
TIER_PROMOTE_1_TO_2_DAYS = _pinned_number("TIER_PROMOTE_1_TO_2_DAYS")
TIER_PROMOTE_2_TO_3_DAYS = _pinned_number("TIER_PROMOTE_2_TO_3_DAYS")
TIER_PROMOTE_MAX_REVERT_RATE = _pinned_number("TIER_PROMOTE_MAX_REVERT_RATE")
TIER_DEMOTE_REVERT_RATE_24H = _pinned_number("TIER_DEMOTE_REVERT_RATE_24H")
TIER_CONSECUTIVE_FAILURE_LIMIT = int(_pinned_number(
    "TIER_CONSECUTIVE_FAILURE_LIMIT"))
HIGH_COOLDOWN_HOURS = _pinned_number("HIGH_COOLDOWN_HOURS")
TIER_CAP = int(_pinned_number("TIER_CAP"))

PROPOSAL_DEDUP_WINDOW_D = _pinned_number("PROPOSAL_DEDUP_WINDOW_D")
PROPOSAL_MAX_PENDING = int(_pinned_number("PROPOSAL_MAX_PENDING"))
WEIGHT_STEP_IMPROVER = _pinned_number("WEIGHT_STEP_IMPROVER")
WEIGHT_STEP_STRUCTURE_PROPOSER = _pinned_number(
    "WEIGHT_STEP_STRUCTURE_PROPOSER")
WEIGHT_CEILING = _pinned_number("WEIGHT_CEILING")
WEIGHT_FLOOR = _pinned_number("WEIGHT_FLOOR")
MISSING_PARTICIPANT_EVENT_N = int(_pinned_number(
    "MISSING_PARTICIPANT_EVENT_N"))
PROPOSAL_WINDOW_D = _pinned_number("PROPOSAL_WINDOW_D")
VITALITY_SIGNAL_FLOOR = int(_pinned_number("VITALITY_SIGNAL_FLOOR"))
VITALITY_MIN_COVERAGE = _pinned_number("VITALITY_MIN_COVERAGE")
GLOBAL_MIN_SIGNALS = int(_pinned_number("GLOBAL_MIN_SIGNALS"))
ZERO_SOURCES_FOR_STRONG = int(_pinned_number("ZERO_SOURCES_FOR_STRONG"))
ZERO_SOURCES_FOR_MODERATE = int(_pinned_number("ZERO_SOURCES_FOR_MODERATE"))

__all__ = ["disclosure"] + sorted(_PINNED) + [
    "GT_FORWARD_WINDOW_SEC", "GT_FP_TN_HORIZON_SEC", "CALIBRATION_WINDOW_SEC"]
