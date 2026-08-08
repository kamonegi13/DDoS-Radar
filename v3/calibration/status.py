"""calibration_status, the self-evaluation metrics, and the Design W gate.

Three of the ten clauses WP-3.1 deferred here (S1-CONC-029 / 030 / 038)
plus the gate they feed (S1-CALIB-027 / 029, S5-VERIF-038). They share a
module because they must share arithmetic: S1-CONC-038 requires the AP3
recall chip and the CI gate to be "the same aggregation path", which is
only checkable if there is one path to be the same as.

The gate's comparison takes an `AlignedPair` and nothing else. That is
F-16's repair: there is no signature here that accepts a loose baseline
and a loose current snapshot, so a comparison across the 2026-07-04 or
2026-08-02 series break cannot be written, only refused at the point the
pair is formed.

Two deliberate departures from production, both registered:

* the gate is STRICT. S5-VERIF-038 requires detection-related gates to be
  strict at cutover, and `check_recall_post_autotune.py` is warn-only with
  `check_ci.sh` never passing `--strict` — structurally unable to fail.
* `drift` over zero eligible scenarios is `None` with a reason, never
  0.0. S1-CONC-038 is explicit: 0.0 reads as "no anomaly".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from v3.calibration import matrix as M
from v3.calibration import recall as R
from v3.calibration import thresholds as T
from v3.calibration.epoch import AlignedPair, EpochStamp
from v3.kernel.errors import DomainError

#: S1-CONC-029: the only admissible source. A self-referential metric
#: (the lite/full score delta) went identically zero once the score paths
#: merged and reported "no anomaly" across 360,000 conclusions.
SOURCE_GROUND_TRUTH = "ground_truth"

VERDICT_PASS = "PASS"
VERDICT_FAIL = "FAIL"
VERDICT_WARN = "warn"
VERDICT_SKIP = "skip"
VERDICT_INFO = "info"


@dataclass(frozen=True, slots=True)
class CalibrationStatus:
    """What S1-CONC-029 attaches to every conclusion."""

    source: str
    status: str
    recall: Optional[float]
    precision: Optional[float]
    tp: int
    fp: int
    tn: int
    fn: int
    sample_n: int
    window_days: float
    last_label_at: Optional[float]
    epoch_id: Optional[str]

    def as_dict(self) -> dict:
        return {"source": self.source, "status": self.status,
                "recall": self.recall, "precision": self.precision,
                "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "sample_n": self.sample_n, "window_days": self.window_days,
                "last_label_at": self.last_label_at,
                "epoch_id": self.epoch_id}


INSUFFICIENT = CalibrationStatus(
    source=SOURCE_GROUND_TRUTH, status=M.INSUFFICIENT_DATA, recall=None,
    precision=None, tp=0, fp=0, tn=0, fn=0, sample_n=0,
    window_days=T.CALIBRATION_WINDOW_D, last_label_at=None, epoch_id=None)


def status_for(cell: Optional[M.ConfusionCell], *,
               last_label_at: Optional[float] = None) -> CalibrationStatus:
    """S1-CONC-030: three values, decided by the recall DENOMINATOR.

    Not by the total label count: a scenario with nothing but true
    negatives and false positives stays INSUFFICIENT_DATA, because recall
    is undefined without an observed positive. Precision is reported and
    never used to decide.

    Never raises (NP3). A missing cell is INSUFFICIENT_DATA, not an error.
    """
    if cell is None:
        return INSUFFICIENT
    if not isinstance(cell, M.ConfusionCell):
        raise DomainError(
            f"status_for needs a ConfusionCell or None, got "
            f"{type(cell).__name__}")
    if cell.total == 0:
        return INSUFFICIENT
    value = cell.recall
    return CalibrationStatus(
        source=SOURCE_GROUND_TRUTH, status=cell.status, recall=value,
        precision=cell.precision, tp=cell.tp, fp=cell.fp, tn=cell.tn,
        fn=cell.fn, sample_n=cell.total,
        window_days=T.CALIBRATION_WINDOW_D, last_label_at=last_label_at,
        epoch_id=cell.epoch_id)


@dataclass(frozen=True, slots=True)
class SelfEvaluation:
    """S1-CONC-038 — each metric fails independently, none raises."""

    recall: Optional[float]
    recall_error: Optional[str]
    recall_meta: dict
    drift: Optional[float]
    drift_error: Optional[str]
    drift_meta: dict

    def as_dict(self) -> dict:
        return {"recall": self.recall, "recall_error": self.recall_error,
                "recall_meta": dict(self.recall_meta), "drift": self.drift,
                "drift_error": self.drift_error,
                "drift_meta": dict(self.drift_meta)}


def self_evaluate(cells: Iterable[M.ConfusionCell], *, stamp: EpochStamp,
                  labels_human: int = 0, labels_auto: int = 0
                  ) -> SelfEvaluation:
    """The AP3 metrics, over the same window and the same arithmetic.

    `recall` pools every cell — the same aggregation the gate uses, which
    is what "the chip and the gate cannot report different numbers" means
    in practice.

    `drift` is the mean miss rate over scenarios whose calibration status
    is neither INSUFFICIENT_DATA nor degenerate. Zero eligible scenarios
    yields None plus a reason: 0.0 would read as "no drift", which is the
    opposite of "we cannot tell".
    """
    materialised = tuple(cells)
    window_days = (stamp.until - stamp.since) / 86400.0

    recall_value: Optional[float] = None
    recall_error: Optional[str] = None
    try:
        recall_value = R.recall(tp=sum(c.tp for c in materialised),
                                fn=sum(c.fn for c in materialised))
        if recall_value is None:
            recall_error = "no observed positive in the window"
    except Exception as exc:  # noqa: BLE001 — disclosed, never 5xx (NP3)
        recall_error = f"{type(exc).__name__}: {exc}"

    eligible = [c for c in materialised
                if c.status in M.OK_STATUSES and c.recall is not None]
    drift_value: Optional[float] = None
    drift_error: Optional[str] = None
    worst: Optional[str] = None
    if eligible:
        misses = [R.miss_rate(tp=c.tp, fn=c.fn) for c in eligible]
        drift_value = sum(misses) / len(misses)
        worst = max(eligible, key=lambda c: R.miss_rate(tp=c.tp,
                                                        fn=c.fn)).key
    else:
        drift_error = ("no scenario has a measurable recall in this "
                       "window; reporting 0.0 would read as 'no drift'")

    degenerate = M.degenerate_audit(materialised)
    return SelfEvaluation(
        recall=recall_value, recall_error=recall_error,
        recall_meta={"window_days": window_days,
                     "epoch_id": stamp.epoch_id,
                     "labels_total": labels_human + labels_auto,
                     "labels_human": labels_human,
                     "labels_auto": labels_auto,
                     "source": SOURCE_GROUND_TRUTH,
                     "degenerate_cells": list(degenerate["degenerate"])},
        drift=drift_value, drift_error=drift_error,
        drift_meta={"method": "mean(1 - recall) over measurable cells",
                    "cells_considered": len(eligible),
                    "worst_cell": worst,
                    "window_days": window_days,
                    "epoch_id": stamp.epoch_id})


@dataclass(frozen=True, slots=True)
class GateResult:
    passed: bool
    messages: tuple
    epoch_id: str

    def as_dict(self) -> dict:
        return {"passed": self.passed, "messages": list(self.messages),
                "epoch_id": self.epoch_id}


def design_w_gate(pair: AlignedPair, *, baseline_cells: Iterable,
                  current_cells: Iterable,
                  max_drop: float = T.DESIGN_W_MAX_DROP) -> GateResult:
    """S1-CALIB-029's six branches, preserved, over an aligned pair.

    1. in baseline, absent now          -> warn (does not fail)
    2. baseline recall is None          -> skip
    3. baseline had a number, now None  -> FAIL (coverage loss)
    4. drop > max_drop                  -> FAIL
    5. 0 < drop <= max_drop             -> info (the boundary PASSES)
    6. only in current                  -> info

    Plus one addition S5-VERIF-037 requires: a degenerate cell is reported
    and never used as the basis of a verdict. Its recall is 1.0 by
    construction, so comparing it measures nothing — and it is the shape
    incident #1 left in five of the live baseline's eight cells.

    `max_drop` is an explicit argument at every call site (S5-VERIF-038
    objects to the CI gate depending on a default), and the window and
    `exclude_auto` come from the pair rather than from either side alone.
    """
    if not isinstance(pair, AlignedPair):
        raise DomainError(
            f"design_w_gate needs an AlignedPair, got "
            f"{type(pair).__name__}: the pair is the proof that both "
            f"sides measure the same label population (F-16). There is "
            f"deliberately no two-snapshot form of this call")
    base_idx = {(c.scenario_id, c.conclusion_type): c
                for c in baseline_cells}
    cur_idx = {(c.scenario_id, c.conclusion_type): c for c in current_cells}

    messages: list = []
    failed = False

    for key, base_cell in sorted(base_idx.items()):
        name = f"{key[0]}/{key[1]}"
        if base_cell.is_degenerate:
            messages.append(
                f"{VERDICT_WARN}: {name} is DEGENERATE in the baseline "
                f"(fn=0 and tn=0, so recall is 1.0 by construction); it "
                f"cannot support a verdict (S5-VERIF-037)")
            continue
        cur_cell = cur_idx.get(key)
        if cur_cell is None:
            messages.append(
                f"{VERDICT_WARN}: {name} present in baseline but absent now")
            continue
        base_recall = base_cell.recall
        if base_recall is None:
            messages.append(f"{VERDICT_SKIP}: {name} had no baseline recall")
            continue
        if cur_cell.is_degenerate:
            failed = True
            messages.append(
                f"{VERDICT_FAIL}: {name} became DEGENERATE (fn=0 and "
                f"tn=0); its recall is no longer a measurement")
            continue
        cur_recall = cur_cell.recall
        if cur_recall is None:
            failed = True
            messages.append(
                f"{VERDICT_FAIL}: {name} recall went from "
                f"{base_recall:.3f} to None (coverage loss)")
            continue
        # Exact, not float: at the boundary `1.0 - 0.95` is
        # 0.050000000000000044, which would turn the clause's "equality
        # passes" into a FAIL for precisely the cells on the line
        # (S5-VERIF-034 asks for rationals before rounding).
        drop = base_recall - cur_recall
        if R.drop_exceeds(baseline_tp=base_cell.tp, baseline_fn=base_cell.fn,
                          current_tp=cur_cell.tp, current_fn=cur_cell.fn,
                          max_drop=max_drop):
            failed = True
            messages.append(
                f"{VERDICT_FAIL}: {name} recall dropped {base_recall:.3f} "
                f"-> {cur_recall:.3f} (delta {drop:+.3f}, threshold "
                f"{max_drop:+.3f})")
        elif drop > 0:
            messages.append(
                f"{VERDICT_INFO}: {name} recall slipped {base_recall:.3f} "
                f"-> {cur_recall:.3f} (delta {drop:+.3f})")

    for key in sorted(set(cur_idx) - set(base_idx)):
        messages.append(
            f"{VERDICT_INFO}: new cell {key[0]}/{key[1]} (not in baseline)")

    return GateResult(passed=not failed, messages=tuple(messages),
                      epoch_id=pair.epoch.epoch_id)


__all__ = ["CalibrationStatus", "INSUFFICIENT", "status_for",
           "SelfEvaluation", "self_evaluate", "GateResult", "design_w_gate",
           "SOURCE_GROUND_TRUTH", "VERDICT_PASS", "VERDICT_FAIL",
           "VERDICT_WARN", "VERDICT_SKIP", "VERDICT_INFO"]
