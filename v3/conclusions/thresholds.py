"""Every number L3 uses, pinned with the clause that holds its value.

P6 O-18 splits thresholds into an operationally variable group and a
disclosed-constant group, and measured evidence (G-15: 95 of 98 registered
keys unread for months) says the second group is almost all of them. None
of the conclusion thresholds is a dial an analyst turns between ticks —
S1-conclusions §3 lists thirty of them and records that exactly one is
DB-overridable — so all of them are pinned here, each carrying the clause,
the production line, or the incident that fixes its value.

Values were taken from the production modules by AST extraction, not by
reading the S1 citation lines: WP-2.6's sweep found 97 transcription
infidelities in values that looked correctly copied, so a citation is a
lead and the module constant is the source. `scripts/check_conclusion_
thresholds.py` re-runs that comparison as a gate.
"""
from __future__ import annotations

from typing import Any

from v3.kernel import Threshold

_PINNED: dict[str, Threshold] = {
    # ── THREAT_LEVEL (S1-CONC-011) ────────────────────────────────────
    "TL_CONFIDENCE_DENOM": Threshold.pinned(
        12.0, unit="score",
        provenance_ref="S1-CONC-011; radar/conclusions/threat_level.py "
                       "_CONFIDENCE_DENOM. S1-conclusions A3 records this as "
                       "an explicit interim value (isotonic calibration was "
                       "planned in ADR-V2-010 and never started)"),
    "TL_LITE_CONFIDENCE_FACTOR": Threshold.pinned(
        0.6, unit="multiplier",
        provenance_ref="S1-CONC-011; radar/conclusions/threat_level.py "
                       "_LITE_CONFIDENCE_FACTOR (2026-07-04)"),

    # ── TREND (S1-CONC-017, S1-CONC-018) ──────────────────────────────
    "TREND_RISING_DELTA": Threshold.pinned(
        0.5, unit="score",
        provenance_ref="S1-CONC-017; radar/conclusions/trend.py "
                       "RISING_DELTA. S1 §7 GAP-02: no production test pins "
                       "this number, only constant-relative boundaries"),
    "TREND_ESCALATE_DELTA": Threshold.pinned(
        1.5, unit="score",
        provenance_ref="S1-CONC-017; radar/conclusions/trend.py "
                       "ESCALATE_DELTA (GAP-02)"),
    "TREND_MIN_SAMPLES": Threshold.pinned(
        3.0, unit="count",
        provenance_ref="S1-CONC-018; radar/conclusions/trend.py MIN_SAMPLES"),
    "TREND_CONFIDENCE_CEILING": Threshold.pinned(
        0.95, unit="ratio",
        provenance_ref="S1-CONC-018; trend.py _confidence_from_samples caps "
                       "the sum at 0.95"),
    "TREND_CONFIDENCE_PER_WINDOW_CAP": Threshold.pinned(
        0.30, unit="ratio",
        provenance_ref="S1-CONC-018; min(0.30, 0.15 + n*0.01) per window"),
    "TREND_CONFIDENCE_PER_WINDOW_BASE": Threshold.pinned(
        0.15, unit="ratio",
        provenance_ref="S1-CONC-018; the 0.15 in min(0.30, 0.15 + n*0.01)"),
    "TREND_CONFIDENCE_PER_SAMPLE": Threshold.pinned(
        0.01, unit="ratio",
        provenance_ref="S1-CONC-018; the 0.01 in min(0.30, 0.15 + n*0.01)"),
    "TREND_PARTIAL_PENALTY": Threshold.pinned(
        0.15, unit="ratio",
        provenance_ref="S1-CONC-018; one unavailable window costs 0.15"),

    # ── PER_DOMAIN (S1-CONC-019, S1-CONC-020) ─────────────────────────
    "DOMAIN_ACTIVE_FLOOR": Threshold.pinned(
        2.5, unit="score",
        provenance_ref="S1-CONC-020; radar/conclusions/per_domain.py "
                       "ACTIVE_FLOOR (2026-04-26 recalibration to the "
                       "observed distribution). D5 §3-7 still records the "
                       "pre-recalibration 3.0 — the module is the source"),
    "DOMAIN_ELEVATED_FLOOR": Threshold.pinned(
        1.5, unit="score",
        provenance_ref="S1-CONC-020; per_domain.py ELEVATED_FLOOR"),
    "DOMAIN_DEGRADE_DELTA": Threshold.pinned(
        1.0, unit="score",
        provenance_ref="S1-CONC-020; per_domain.py DEGRADE_DELTA. D5 records "
                       "1.5; the module says 1.0"),
    "DOMAIN_MAGNITUDE_DENOM": Threshold.pinned(
        12.0, unit="score",
        provenance_ref="S1-CONC-019; per_domain.py _confidence divides the "
                       "domain-score sum by 12.0"),

    # ── ANOMALY (S1-CONC-021, S1-CONC-022, S1-CONC-023) ───────────────
    "ANOMALY_DEFAULT_LIMIT": Threshold.pinned(
        10.0, unit="count",
        provenance_ref="S1-CONC-021; radar/conclusions/anomaly.py "
                       "DEFAULT_LIMIT"),
    "ANOMALY_MAX_IMPORTANCE": Threshold.pinned(
        100.0, unit="index",
        provenance_ref="S1-CONC-022; anomaly.py _MAX_IMPORTANCE"),
    "ANOMALY_RECENCY_TIME_CONSTANT_H": Threshold.pinned(
        12.0, unit="h",
        provenance_ref="S1-CONC-022; anomaly.py "
                       "_RECENCY_TIME_CONSTANT_HOURS. It is a 1/e time "
                       "constant, NOT a half-life — the design document's "
                       "'half-life' wording is ACCIDENTAL A7; the real "
                       "half-life is 12*ln2 = 8.32h"),
    "ANOMALY_NOVELTY_WINDOW_COUNT": Threshold.pinned(
        10.0, unit="count",
        provenance_ref="S1-CONC-023; anomaly.py _NOVELTY_WINDOW"),
    "ANOMALY_NOVELTY_FLOOR": Threshold.pinned(
        0.3, unit="ratio",
        provenance_ref="S1-CONC-023; anomaly.py _NOVELTY_FLOOR"),
    "ANOMALY_NOVELTY_LOOKBACK_SEC": Threshold.pinned(
        86400.0, unit="s",
        provenance_ref="S1-CONC-023; anomaly.py _NOVELTY_LOOKBACK_SEC "
                       "(24 * 3600)"),

    # ── ATTACK_MODE (S1-CONC-024, S1-CONC-025) ────────────────────────
    "ATTACK_CYBER_DDOS_FLOOR": Threshold.pinned(
        1.2, unit="score",
        provenance_ref="S1-CONC-025; radar/conclusions/attack_mode.py "
                       "CYBER_DDOS_FLOOR (2026-05-10 recalibration). "
                       "v2-migration §6.5 still says 5.0 — ACCIDENTAL A10"),
    "ATTACK_INFO_NARRATIVE_FLOOR": Threshold.pinned(
        0.8, unit="score",
        provenance_ref="S1-CONC-025; attack_mode.py INFO_NARRATIVE_FLOOR"),
    "ATTACK_PHYSICAL_KINETIC_FLOOR": Threshold.pinned(
        1.0, unit="score",
        provenance_ref="S1-CONC-025; attack_mode.py PHYSICAL_KINETIC_FLOOR"),
    "ATTACK_ALL_DOMAIN_HYBRID_FLOOR": Threshold.pinned(
        0.8, unit="score",
        provenance_ref="S1-CONC-025; attack_mode.py "
                       "ALL_DOMAIN_HYBRID_FLOOR"),
    "ATTACK_HYBRID_CLUSTER_MIN": Threshold.pinned(
        4.0, unit="count",
        provenance_ref="S1-CONC-025; attack_mode.py "
                       "HYBRID_INTEL_CLUSTER_MIN"),
    # unit="multiplier", not "ratio": this is info/max(other), which is
    # unbounded above. A kernel Ratio refuses anything over 1.0, and that
    # refusal is correct — the name is the misleading part (F-08's shape).
    "ATTACK_INFO_DOMINANCE_RATIO": Threshold.pinned(
        1.5, unit="multiplier",
        provenance_ref="S1-CONC-025; attack_mode.py INFO_DOMINANCE_RATIO"),
    "ATTACK_TENTATIVE_CONFIDENCE": Threshold.pinned(
        0.6, unit="ratio",
        provenance_ref="S1-CONC-024; a top mode below 0.6 is flagged "
                       "tentative"),
    "ATTACK_CONFIDENCE_CEILING": Threshold.pinned(
        0.95, unit="ratio",
        provenance_ref="S1-CONC-025; every rule's min(0.95, ...) ceiling"),
    "ATTACK_MARGIN_BASE_CONFIDENCE": Threshold.pinned(
        0.55, unit="ratio",
        provenance_ref="S1-CONC-025; the 0.55 in 0.55 + 0.4*margin, shared "
                       "by DDOS_PRECURSOR / KINETIC_PREPARATION / "
                       "INFO_OPS_DOMINANT"),
    "ATTACK_MARGIN_SPAN": Threshold.pinned(
        0.4, unit="ratio",
        provenance_ref="S1-CONC-025; the 0.4 multiplying the clamped margin"),
    "ATTACK_HYBRID_BASE_CONFIDENCE": Threshold.pinned(
        0.50, unit="ratio",
        provenance_ref="S1-CONC-025; HYBRID_PRESSURE starts at 0.50"),
    "ATTACK_HYBRID_PER_COUNTRY": Threshold.pinned(
        0.05, unit="ratio",
        provenance_ref="S1-CONC-025; +0.05 per active country"),
    "ATTACK_HYBRID_PER_DOMAIN_SUM": Threshold.pinned(
        0.02, unit="ratio",
        provenance_ref="S1-CONC-025; +0.02 per point of summed domain score"),
    "ATTACK_INFO_DOMINANCE_SCALE": Threshold.pinned(
        0.10, unit="ratio",
        provenance_ref="S1-CONC-025; 0.55 + 0.10 * info/max(other, 0.1)"),
    "ATTACK_INFO_DOMINANCE_EPSILON": Threshold.pinned(
        0.1, unit="score",
        provenance_ref="S1-CONC-025; the max(other, 0.1) floor guarding the "
                       "confidence quotient. NOTE the rule predicate uses a "
                       "different denominator (bare other_max, gated on "
                       "> 0) — attack_mode.py:_apply_rules"),
    "ATTACK_PURE_INFO_CONFIDENCE": Threshold.pinned(
        0.65, unit="ratio",
        provenance_ref="S1-CONC-025; the fixed 0.65 for the info-only mix"),

    # ── availability guards (S1-CONC-003 / F-12) ──────────────────────
    "UPSTREAM_FAILURE_RATIO": Threshold.pinned(
        1.0, unit="ratio",
        provenance_ref="F-12 generation path for `upstream_failure`. Set at "
                       "1.0 — EVERY consulted source must have hard-failed. "
                       "Below total loss the tool still has an observation "
                       "of the world, however partial, and calling that an "
                       "upstream failure would make the reason unfalsifiable"),
    "SENSOR_DEGRADED_RATIO": Threshold.pinned(
        0.5, unit="ratio",
        provenance_ref="F-12 generation path for `sensor_degraded`. A "
                       "majority of consulted sources unusable (hard failure "
                       "or past its freshness horizon) means the quiet "
                       "reading is a reading of the sensors, not of the "
                       "world — G-17's exact confusion"),
    "CALIBRATION_MIN_HISTORY_DAYS": Threshold.pinned(
        30.0, unit="d",
        provenance_ref="F-12 generation path for `calibration_pending`. "
                       "Matches the 30-day calibration window of "
                       "S1-CONC-029/030: a calm verdict from a scenario "
                       "observed for less than one calibration window rests "
                       "on thresholds never checked against that scenario's "
                       "own distribution. Transient by construction — it "
                       "resolves as the stream fills (NP5+8)"),
}


def _pinned_number(name: str) -> float:
    resolved = _PINNED[name].resolve().value
    return float(getattr(resolved, "value", resolved))


def disclosure() -> dict[str, Any]:
    """Every pinned threshold with its value and provenance (NP6 / R10).

    The published catalogue: O-18 requires constants to be disclosed even
    though they are not runtime-variable, and a conclusion's
    `threshold_ref` is a projection of this mapping.
    """
    return {name: {"value": _pinned_number(name),
                   "unit": threshold.unit,
                   "provenance_ref": threshold.provenance_ref}
            for name, threshold in sorted(_PINNED.items())}


TL_CONFIDENCE_DENOM = _pinned_number("TL_CONFIDENCE_DENOM")
TL_LITE_CONFIDENCE_FACTOR = _pinned_number("TL_LITE_CONFIDENCE_FACTOR")

TREND_RISING_DELTA = _pinned_number("TREND_RISING_DELTA")
TREND_ESCALATE_DELTA = _pinned_number("TREND_ESCALATE_DELTA")
TREND_MIN_SAMPLES = int(_pinned_number("TREND_MIN_SAMPLES"))
TREND_CONFIDENCE_CEILING = _pinned_number("TREND_CONFIDENCE_CEILING")
TREND_CONFIDENCE_PER_WINDOW_CAP = _pinned_number(
    "TREND_CONFIDENCE_PER_WINDOW_CAP")
TREND_CONFIDENCE_PER_WINDOW_BASE = _pinned_number(
    "TREND_CONFIDENCE_PER_WINDOW_BASE")
TREND_CONFIDENCE_PER_SAMPLE = _pinned_number("TREND_CONFIDENCE_PER_SAMPLE")
TREND_PARTIAL_PENALTY = _pinned_number("TREND_PARTIAL_PENALTY")

DOMAIN_ACTIVE_FLOOR = _pinned_number("DOMAIN_ACTIVE_FLOOR")
DOMAIN_ELEVATED_FLOOR = _pinned_number("DOMAIN_ELEVATED_FLOOR")
DOMAIN_DEGRADE_DELTA = _pinned_number("DOMAIN_DEGRADE_DELTA")
DOMAIN_MAGNITUDE_DENOM = _pinned_number("DOMAIN_MAGNITUDE_DENOM")

ANOMALY_DEFAULT_LIMIT = int(_pinned_number("ANOMALY_DEFAULT_LIMIT"))
ANOMALY_MAX_IMPORTANCE = _pinned_number("ANOMALY_MAX_IMPORTANCE")
ANOMALY_RECENCY_TIME_CONSTANT_H = _pinned_number(
    "ANOMALY_RECENCY_TIME_CONSTANT_H")
ANOMALY_NOVELTY_WINDOW_COUNT = _pinned_number("ANOMALY_NOVELTY_WINDOW_COUNT")
ANOMALY_NOVELTY_FLOOR = _pinned_number("ANOMALY_NOVELTY_FLOOR")
ANOMALY_NOVELTY_LOOKBACK_SEC = _pinned_number("ANOMALY_NOVELTY_LOOKBACK_SEC")

ATTACK_CYBER_DDOS_FLOOR = _pinned_number("ATTACK_CYBER_DDOS_FLOOR")
ATTACK_INFO_NARRATIVE_FLOOR = _pinned_number("ATTACK_INFO_NARRATIVE_FLOOR")
ATTACK_PHYSICAL_KINETIC_FLOOR = _pinned_number("ATTACK_PHYSICAL_KINETIC_FLOOR")
ATTACK_ALL_DOMAIN_HYBRID_FLOOR = _pinned_number(
    "ATTACK_ALL_DOMAIN_HYBRID_FLOOR")
ATTACK_HYBRID_CLUSTER_MIN = int(_pinned_number("ATTACK_HYBRID_CLUSTER_MIN"))
ATTACK_INFO_DOMINANCE_RATIO = _pinned_number("ATTACK_INFO_DOMINANCE_RATIO")
ATTACK_TENTATIVE_CONFIDENCE = _pinned_number("ATTACK_TENTATIVE_CONFIDENCE")
ATTACK_CONFIDENCE_CEILING = _pinned_number("ATTACK_CONFIDENCE_CEILING")
ATTACK_MARGIN_BASE_CONFIDENCE = _pinned_number("ATTACK_MARGIN_BASE_CONFIDENCE")
ATTACK_MARGIN_SPAN = _pinned_number("ATTACK_MARGIN_SPAN")
ATTACK_HYBRID_BASE_CONFIDENCE = _pinned_number("ATTACK_HYBRID_BASE_CONFIDENCE")
ATTACK_HYBRID_PER_COUNTRY = _pinned_number("ATTACK_HYBRID_PER_COUNTRY")
ATTACK_HYBRID_PER_DOMAIN_SUM = _pinned_number("ATTACK_HYBRID_PER_DOMAIN_SUM")
ATTACK_INFO_DOMINANCE_SCALE = _pinned_number("ATTACK_INFO_DOMINANCE_SCALE")
ATTACK_INFO_DOMINANCE_EPSILON = _pinned_number("ATTACK_INFO_DOMINANCE_EPSILON")
ATTACK_PURE_INFO_CONFIDENCE = _pinned_number("ATTACK_PURE_INFO_CONFIDENCE")

UPSTREAM_FAILURE_RATIO = _pinned_number("UPSTREAM_FAILURE_RATIO")
SENSOR_DEGRADED_RATIO = _pinned_number("SENSOR_DEGRADED_RATIO")
CALIBRATION_MIN_HISTORY_DAYS = _pinned_number("CALIBRATION_MIN_HISTORY_DAYS")
CALIBRATION_MIN_HISTORY_SEC = CALIBRATION_MIN_HISTORY_DAYS * 86400.0

__all__ = ["disclosure"] + sorted(_PINNED) + ["CALIBRATION_MIN_HISTORY_SEC"]
