"""Per-sensor LLM_CONFIDENCE_MIN calibrator (Phase C).

Currently `LLM_CONFIDENCE_MIN` is a single global value (default 0.35) —
items below it are silently discarded across all sensors. Different
sensors have different LLM-output quality distributions, so a single
threshold under- or over-filters depending on sensor.

This calibrator computes per-sensor optimal confidence floors from
analyst_feedback observations:

  - Reads (TP, FP) by sensor → `intel_queue` hits → `analyst_feedback`
  - For each sensor, finds the confidence threshold that:
    * Maximizes precision while keeping recall ≥ recall_floor
    * Is bounded between [global_min - 0.10, global_min + 0.20]
  - Submits a Proposal to the governor for each sensor whose proposed
    floor differs from the current floor by ≥ 0.02

Per-sensor keys produced:

  llm_confidence_min.<sensor_name>   (default = global LLM_CONFIDENCE_MIN)

Pattern intentionally mirrors tl_threshold_calibrator (Phase B) so the
same governor enforces sample_n / cooldown / magnitude / recall gate.

Phase C v1 scope: emits proposals to threshold_history. Actual
*application* in intel_queue.submit() reads via threshold_history
(future opt-in commit, gated on V2_AUTO_TUNE_LLM_CONFIDENCE=true).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

from radar.calibration import auto_tune_governor as gov
from radar.calibration.auto_tune_governor import Proposal
from radar.database import db

log = logging.getLogger("radar.calibration.llm_confidence_calibrator")


CALIBRATOR_VERSION = "llm_confidence_calibrator/v1"
APPLIED_BY = "auto:llm_confidence"

# Sensors that submit through intel_queue and are LLM-confidence-gated.
# Update if a new contributor is added (pattern: same as
# scripts/audit_intel_sensors.py INTEL_SENSORS).
LLM_GATED_SENSORS: tuple[str, ...] = (
    "apt_intel",
    "diplomatic",
    "military_exercise",
    "rss_narrative",
    "ground_osint",
    "hacktivist_intel",
    "hacktivist_news",
)


def _min_feedback_per_sensor() -> int:
    return int(os.getenv("LLM_CONF_CALIB_MIN_FEEDBACK", "30"))


def _recall_floor() -> float:
    return float(os.getenv("LLM_CONF_CALIB_RECALL_FLOOR", "0.85"))


def _global_default() -> float:
    return float(os.getenv("LLM_CONFIDENCE_MIN", "0.35"))


@dataclass(frozen=True)
class CalibrationResult:
    sensor_name: str
    proposed: bool
    accepted: bool
    rejection_reason: Optional[str]
    proposed_floor: Optional[float]
    sample_n: int


def _read_sensor_metrics(sensor_name: str) -> Optional[dict]:
    """Compute (TP, FP) for items submitted by `sensor_name` and joined
    with analyst_feedback. Returns None if sample size is below threshold.

    NP3: any DB error returns None — calibrator becomes a silent no-op
    rather than risk a wrong tune.
    """
    try:
        conn = db._get_conn()  # noqa: SLF001
        # llm_intel.source_type maps to sensor name for most sensors;
        # rss_narrative uses 'narrative', hacktivist_news uses 'hacktivist'.
        source_type = {
            "rss_narrative": "narrative",
            "hacktivist_news": "hacktivist",
            "hacktivist_intel": "hacktivist",
        }.get(sensor_name, sensor_name)
        rows = conn.execute(
            "SELECT af.label, COUNT(*) FROM analyst_feedback af "
            "JOIN conclusions c ON af.conclusion_id = c.id "
            "JOIN llm_intel li ON li.theater = c.scenario_id "
            "WHERE li.source_type = ? "
            "GROUP BY af.label",
            (source_type,),
        ).fetchall()
    except Exception as exc:
        log.debug("llm_conf_calibrator: read failed for %s: %s", sensor_name, exc)
        return None
    counts = {row[0]: row[1] for row in rows}
    tp = counts.get("TRUE_POSITIVE", 0)
    fp = counts.get("FALSE_POSITIVE", 0)
    fn = counts.get("FALSE_NEGATIVE", 0)
    total = tp + fp + fn
    if total < _min_feedback_per_sensor():
        return None
    recall = tp / max(1, tp + fn)
    precision = tp / max(1, tp + fp)
    return {"tp": tp, "fp": fp, "fn": fn, "total": total,
            "recall": recall, "precision": precision}


def _propose_floor(sensor_name: str, metrics: dict) -> Optional[float]:
    """Return the suggested floor, or None if no change is needed.

    Logic (conservative):
      - If precision < 0.5 (lots of FP) AND recall ≥ floor + 0.10 →
        raise floor by 0.05 (tighten)
      - If recall < floor (missing TPs) → lower floor by 0.05 (loosen)
      - Otherwise no change
    Floor stays bounded to [global_min - 0.10, global_min + 0.20].
    """
    global_min = _global_default()
    floor_lo = max(0.10, global_min - 0.10)
    floor_hi = min(0.95, global_min + 0.20)

    if metrics["recall"] < _recall_floor():
        new_floor = max(floor_lo, global_min - 0.05)
        if abs(new_floor - global_min) < 0.02:
            return None
        return round(new_floor, 3)

    if metrics["precision"] < 0.5 and metrics["recall"] >= _recall_floor() + 0.10:
        new_floor = min(floor_hi, global_min + 0.05)
        if abs(new_floor - global_min) < 0.02:
            return None
        return round(new_floor, 3)

    return None


def calibrate_sensor(sensor_name: str) -> CalibrationResult:
    """Run one calibration pass on a single sensor. Returns a
    structured outcome that the scheduler can log."""
    metrics = _read_sensor_metrics(sensor_name)
    if metrics is None:
        return CalibrationResult(
            sensor_name=sensor_name, proposed=False, accepted=False,
            rejection_reason="insufficient_feedback",
            proposed_floor=None, sample_n=0,
        )
    new_floor = _propose_floor(sensor_name, metrics)
    if new_floor is None:
        return CalibrationResult(
            sensor_name=sensor_name, proposed=False, accepted=False,
            rejection_reason="no_action_needed",
            proposed_floor=None, sample_n=metrics["total"],
        )
    proposal = Proposal(
        key=f"llm_confidence_min.{sensor_name}",
        new_value=new_floor,
        scope_scenario_id=None,
        derived_from=f"{CALIBRATOR_VERSION}#derive_from_feedback",
        applied_by=APPLIED_BY,
        sample_n=metrics["total"],
        formula_ref=f"{CALIBRATOR_VERSION}#{sensor_name}",
        evidence={
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "recall": metrics["recall"],
            "precision": metrics["precision"],
            "global_default": _global_default(),
        },
    )
    outcome = gov.commit(proposal)
    return CalibrationResult(
        sensor_name=sensor_name,
        proposed=True,
        accepted=outcome.accepted,
        rejection_reason=None if outcome.accepted else outcome.reason,
        proposed_floor=new_floor,
        sample_n=metrics["total"],
    )


def calibrate_all_sensors() -> dict:
    """Iterate across all LLM-gated sensors and run the calibrator on
    each. Returns a dict keyed by sensor_name."""
    out: dict[str, dict] = {}
    for s in LLM_GATED_SENSORS:
        try:
            result = calibrate_sensor(s)
            out[s] = {
                "proposed": result.proposed,
                "accepted": result.accepted,
                "proposed_floor": result.proposed_floor,
                "rejection_reason": result.rejection_reason,
                "sample_n": result.sample_n,
            }
        except Exception as exc:
            log.warning("llm_conf_calibrator: sensor %s failed: %s", s, exc)
            out[s] = {"error": str(exc)[:200]}
    return out


__all__ = ["LLM_GATED_SENSORS", "calibrate_sensor", "calibrate_all_sensors"]
