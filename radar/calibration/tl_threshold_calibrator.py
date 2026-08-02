"""Per-scenario threat-level threshold calibrator (Phase B).

Reads `analyst_feedback` per (scenario, conclusion_type=THREAT_LEVEL)
and proposes adjusted TL thresholds when:

  - recall is low and a looser threshold would lift TP without
    flipping confirmed FN cases (NP1 — sensitivity-preserving)
  - precision is low and a tighter threshold would drop FP without
    losing existing TP

The calibrator does NOT mutate scoring directly. It submits a Proposal
to auto_tune_governor.commit(). The governor enforces sample size,
cooldown, magnitude budget, and the recall gate. If accepted, the new
threshold is recorded in threshold_history; downstream consumers
(future opt-in derive_tl wrapper) read from there.

Per-scenario keys produced:

  tl_thresholds.<scenario_id>.tl1_total       (default 9.0)
  tl_thresholds.<scenario_id>.tl1_physical    (default 3.0)
  tl_thresholds.<scenario_id>.tl2_total       (default 6.0)
  tl_thresholds.<scenario_id>.tl3_total       (default 4.0)
  tl_thresholds.<scenario_id>.tl4_total       (default 2.0)

Phase B v1 scope: produces proposals; governor is the only writer to
threshold_history. Actual *application* of these thresholds in
derive_tl is gated on a future feature flag and only after analyst
review of the ledger via the AP3 reliability scoreboard.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

from radar.calibration import auto_tune_governor as gov
from radar.calibration.auto_tune_governor import Proposal
from radar.database import db

log = logging.getLogger("radar.calibration.tl_threshold_calibrator")


CALIBRATOR_VERSION = "tl_threshold_calibrator/v1"
APPLIED_BY = "auto:tl_calibrator"
DEFAULT_TL_THRESHOLDS = {
    "tl1_total": 9.0,
    "tl1_physical": 3.0,
    "tl2_total": 6.0,
    "tl3_total": 4.0,
    "tl4_total": 2.0,
}

# Calibrator gating thresholds (tunable via env so operations can adjust
# without code change).
def _min_feedback_per_cell() -> int:
    return int(os.getenv("TL_CALIB_MIN_FEEDBACK_PER_CELL", "30"))


def _recall_floor() -> float:
    """If observed recall is below this, propose loosening thresholds."""
    return float(os.getenv("TL_CALIB_RECALL_FLOOR", "0.80"))


def _precision_ceiling_for_tighten() -> float:
    """If observed precision is below this AND recall is at 1.0, propose
    tightening thresholds. 0.30 default is conservative — most cells
    today are above 0.50."""
    return float(os.getenv("TL_CALIB_PRECISION_CEILING", "0.30"))


@dataclass(frozen=True)
class CalibrationResult:
    scenario_id: str
    proposals_submitted: int
    proposals_accepted: int
    proposals_rejected: int
    rejection_reasons: dict


def _read_recall_for_scenario(scenario_id: str) -> Optional[dict]:
    """Compute (TP, FP, TN, FN) for THREAT_LEVEL conclusions of this
    scenario from analyst_feedback. Returns None if sample size is
    below threshold (NP3: skip rather than tune wrongly)."""
    conn = db._get_conn()  # noqa: SLF001
    rows = conn.execute(
        "SELECT af.label, COUNT(*), MAX(af.observed_at) "
        "FROM analyst_feedback af "
        "JOIN conclusions c ON af.conclusion_id = c.id "
        "WHERE c.scenario_id = ? AND c.conclusion_type = 'threat_level' "
        "GROUP BY af.label",
        (scenario_id,),
    ).fetchall()
    counts = {row[0]: row[1] for row in rows}
    latest = {row[0]: row[2] for row in rows}
    tp = counts.get("TRUE_POSITIVE", 0)
    fp = counts.get("FALSE_POSITIVE", 0)
    fn = counts.get("FALSE_NEGATIVE", 0)
    tn = counts.get("TRUE_NEGATIVE", 0)
    total = tp + fp + fn + tn
    if total < _min_feedback_per_cell():
        log.debug(
            "tl_calibrator: %s feedback_total=%d < min=%d, skipping",
            scenario_id, total, _min_feedback_per_cell(),
        )
        return None
    recall = tp / max(1, tp + fn)
    precision = tp / max(1, tp + fp)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "total": total, "recall": recall, "precision": precision,
        "last_label_at": max(
            (v for v in latest.values() if v is not None), default=None,
        ),
        # Per-class recency for the direction-keyed freshness gate:
        # 'looser' must be motivated by a NEW miss, 'tighter' by a NEW
        # false alarm — arrivals of other label classes must not reopen
        # the gate (2026-08-02 korea loosening incident).
        "last_fn_at": latest.get("FALSE_NEGATIVE"),
        "last_fp_at": latest.get("FALSE_POSITIVE"),
    }


def _last_applied_at(scenario_id: str) -> Optional[float]:
    """Timestamp of this calibrator's most recent threshold change for the
    scenario (any state), or None if it never changed anything."""
    conn = db._get_conn()  # noqa: SLF001
    row = conn.execute(
        "SELECT MAX(emitted_at) FROM threshold_history "
        "WHERE scope_scenario_id = ? AND applied_by = ?",
        (scenario_id, APPLIED_BY),
    ).fetchone()
    return row[0] if row and row[0] is not None else None


def _propose_for_band(
    scenario_id: str,
    band_key: str,
    current_value: float,
    direction: str,  # 'looser' (lower threshold) or 'tighter' (higher)
    metrics: dict,
) -> Proposal:
    """Build a single Proposal for one TL band's threshold."""
    # Conservative step: 5% nudge in the requested direction.
    if direction == "looser":
        new_value = round(current_value * 0.95, 3)
    else:  # tighter
        new_value = round(current_value * 1.05, 3)
    full_key = f"tl_thresholds.{scenario_id}.{band_key}"
    return Proposal(
        key=full_key,
        new_value=new_value,
        scope_scenario_id=scenario_id,
        derived_from=f"{CALIBRATOR_VERSION}#derive_from_recall",
        applied_by=APPLIED_BY,
        sample_n=metrics["total"],
        formula_ref=f"{CALIBRATOR_VERSION}#{band_key}_{direction}",
        evidence={
            "recall": metrics["recall"],
            "precision": metrics["precision"],
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "fn": metrics["fn"],
            "tn": metrics["tn"],
            "direction": direction,
            "prior_value": current_value,
        },
    )


def calibrate_scenario(scenario_id: str) -> CalibrationResult:
    """Run one calibration pass on a single scenario. Returns a
    structured outcome that the scheduler can log. NP3: any failure in
    sub-steps becomes a no-op rather than crashing the worker thread.
    """
    rejection_reasons: dict[str, int] = {}
    submitted = 0
    accepted = 0
    rejected = 0

    try:
        metrics = _read_recall_for_scenario(scenario_id)
    except Exception as exc:
        log.warning(
            "tl_calibrator: failed to read recall for %s: %s",
            scenario_id, exc,
        )
        return CalibrationResult(
            scenario_id=scenario_id, proposals_submitted=0,
            proposals_accepted=0, proposals_rejected=0,
            rejection_reasons={"read_error": 1},
        )
    if metrics is None:
        return CalibrationResult(
            scenario_id=scenario_id, proposals_submitted=0,
            proposals_accepted=0, proposals_rejected=0,
            rejection_reasons={"insufficient_feedback": 1},
        )

    direction: Optional[str]
    # Phase 2 fix (2026-04-30 PM, problem 50): track WHY direction is
    # None so analysts can distinguish "genuinely no action" from
    # "Phase H guard blocked tighten on degenerate data".
    no_action_reason: str = "no_action_needed"

    # Phase H guard (2026-04-30): degenerate-data protection.
    # If TN=0 and FP is large compared to TP, the precision metric is
    # measured against a population where no negative was ever
    # confirmed. Tightening based on that biases the system toward
    # under-firing. Phase 5 audit observed precision=25%, fp=497,
    # tp=167, fn=0, tn=0 — calibrator tightened 5 bands. With this
    # guard, that case now skips the tightening and waits for
    # negative-class feedback.
    PRECISION_MIN_FLOOR = float(os.getenv("TL_CALIB_PRECISION_MIN_FLOOR", "0.10"))
    is_degenerate = (
        metrics["tn"] == 0
        and metrics["fn"] == 0
        and metrics["precision"] < PRECISION_MIN_FLOOR + 0.20
    )

    if metrics["recall"] < _recall_floor():
        direction = "looser"
    elif is_degenerate:
        # Refuse to tighten on degenerate data.
        log.warning(
            "tl_calibrator: %s degenerate-data guard fired "
            "(recall=%.3f precision=%.3f tn=%d fn=%d) — refuse to tighten",
            scenario_id, metrics["recall"], metrics["precision"],
            metrics["tn"], metrics["fn"],
        )
        direction = None
        no_action_reason = "degenerate_data_guard"
    elif (metrics["recall"] >= 0.99
            and metrics["precision"] < _precision_ceiling_for_tighten()):
        direction = "tighter"
    else:
        # Recall OK and precision OK → no action.
        direction = None

    if direction is None:
        log.info(
            "tl_calibrator: %s recall=%.3f precision=%.3f → %s",
            scenario_id, metrics["recall"], metrics["precision"],
            no_action_reason,
        )
        return CalibrationResult(
            scenario_id=scenario_id, proposals_submitted=0,
            proposals_accepted=0, proposals_rejected=0,
            rejection_reasons={no_action_reason: 1},
        )

    # Evidence-freshness gate, keyed to the direction's motivating label
    # class. History of this gate:
    #   * 2026-07-04 (runaway-loop fix): 12 consecutive -5% loosenings on
    #     middle_east were justified by the SAME frozen label set — the
    #     gate then required ANY label newer than the last applied change.
    #   * 2026-08-02 (korea loosening incident): that any-label form kept
    #     reopening because TRUE_POSITIVEs arrive weekly while the
    #     motivating FALSE_NEGATIVE set stayed frozen — four more -5%
    #     loosenings from the same contaminated FNs. The gate now demands
    #     a new label OF THE CLASS that motivates the move: a new miss to
    #     loosen, a new false alarm to tighten. One motivating-evidence
    #     state may justify at most one adjustment.
    motivating_at = (
        metrics.get("last_fn_at") if direction == "looser"
        else metrics.get("last_fp_at")
    )
    if motivating_at is None:
        log.info(
            "tl_calibrator: %s direction=%s but no %s labels exist — "
            "refusing an evidence-free adjustment",
            scenario_id, direction,
            "FALSE_NEGATIVE" if direction == "looser" else "FALSE_POSITIVE",
        )
        return CalibrationResult(
            scenario_id=scenario_id, proposals_submitted=0,
            proposals_accepted=0, proposals_rejected=0,
            rejection_reasons={"no_motivating_evidence": 1},
        )
    last_applied = _last_applied_at(scenario_id)
    if last_applied is not None and motivating_at <= last_applied:
        log.info(
            "tl_calibrator: %s direction=%s but newest motivating label "
            "(%.0f) predates the last applied change (%.0f) — refusing "
            "to re-apply the same evidence",
            scenario_id, direction, motivating_at, last_applied,
        )
        return CalibrationResult(
            scenario_id=scenario_id, proposals_submitted=0,
            proposals_accepted=0, proposals_rejected=0,
            rejection_reasons={"no_new_evidence": 1},
        )

    # Read current threshold values from threshold_history (or fall
    # back to defaults). Propose for each band.
    from radar.calibration import threshold_history
    for band_key, default_val in DEFAULT_TL_THRESHOLDS.items():
        full_key = f"tl_thresholds.{scenario_id}.{band_key}"
        rec = threshold_history.latest(full_key, scope_scenario_id=scenario_id)
        current_value = rec.value if rec else default_val
        proposal = _propose_for_band(
            scenario_id, band_key, current_value, direction, metrics,
        )
        submitted += 1
        outcome = gov.commit(proposal)
        if outcome.accepted:
            accepted += 1
            log.info(
                "tl_calibrator: %s/%s accepted (reason=%s, magnitude=%.2f%%)",
                scenario_id, band_key, outcome.reason,
                outcome.actual_magnitude_pct,
            )
        else:
            rejected += 1
            rejection_reasons[outcome.reason] = (
                rejection_reasons.get(outcome.reason, 0) + 1
            )

    return CalibrationResult(
        scenario_id=scenario_id,
        proposals_submitted=submitted,
        proposals_accepted=accepted,
        proposals_rejected=rejected,
        rejection_reasons=rejection_reasons,
    )


def calibrate_all_scenarios() -> dict:
    """Iterate across all registered scenarios and run the calibrator
    on each. Returns a dict keyed by scenario_id with the
    CalibrationResult for each. NP3: a single scenario's failure does
    not break the others."""
    out: dict[str, dict] = {}
    try:
        from radar.scenarios import scenario_store
        scenarios = list(scenario_store._scenarios.keys())  # noqa: SLF001
    except Exception as exc:
        log.warning("tl_calibrator: failed to enumerate scenarios: %s", exc)
        return out
    for sid in scenarios:
        try:
            result = calibrate_scenario(sid)
            out[sid] = {
                "submitted": result.proposals_submitted,
                "accepted": result.proposals_accepted,
                "rejected": result.proposals_rejected,
                "rejection_reasons": result.rejection_reasons,
            }
        except Exception as exc:
            log.warning(
                "tl_calibrator: scenario %s failed: %s", sid, exc,
            )
            out[sid] = {"error": str(exc)[:200]}
    return out


__all__ = [
    "CalibrationResult",
    "DEFAULT_TL_THRESHOLDS",
    "calibrate_scenario",
    "calibrate_all_scenarios",
]
