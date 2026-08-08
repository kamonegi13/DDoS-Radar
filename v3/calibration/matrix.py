"""Confusion cells, and the shape that must never be evidence.

Incident #1 (2026-05-29): the RSS ETL wrote TRUE_POSITIVE for every match.
FN became identically zero, recall became 1.0, and the Design W gate went
on passing for weeks while guarding a number that could not move. The
signature is arithmetic, not statistical:

    fn == 0 and tn == 0  ⇒  recall = tp/(tp+0) = 1.0, unconditionally

WP-1.4 built the audit that detects it (5 of the live baseline's 8 cells
still have the shape). This module makes the shape unusable rather than
merely visible: `CalibrationEvidence` — the only thing a proposal or a
gate verdict may rest on — refuses to contain a degenerate cell.

Two deliberate choices:

* the test is a PREDICATE (`fn == 0 and tn == 0`), never a count.
  S5-VERIF-037 says so because the spec's own count was wrong: it said 4
  degenerate cells until a 2026-08-06 file check found 5. A constant in
  this position is wrong again at the next re-baseline.
* dropping degenerate cells is possible but never implicit. Silently
  filtering them would let a set of 8 cells report on 3 while presenting
  itself as a report on 8 — the same category of lie as the blanket-TP.
"""
from __future__ import annotations

import ast
import pathlib
from dataclasses import dataclass, field
from typing import Iterable, Optional

from v3.calibration import recall as _recall
from v3.calibration import thresholds as _thresholds
from v3.calibration.epoch import EpochMismatchError, EpochStamp, epoch
from v3.kernel.errors import DomainError

#: Cell statuses. `DEGENERATE` is more specific than `INSUFFICIENT_DATA`
#: and strictly more dangerous, so it wins when a cell is both.
DEGENERATE = "DEGENERATE"
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
DEGRADED = "DEGRADED"
OK = "OK"
OK_STATUSES: tuple[str, ...] = (OK, DEGRADED)

#: S5-VERIF-037: a recall denominator below this is not yet a measurement.
#: S1-CONC-030 / S1-CALIB-027: below DEGRADED_RECALL_FLOOR the tool is
#: demonstrably missing real escalations. Both come from the pinned
#: registry rather than being retyped here — DP4 is exactly the defect of
#: a threshold that exists in two places and is registered in neither.
MIN_RECALL_DENOM = _thresholds.MIN_RECALL_DENOM
DEGRADED_RECALL_FLOOR = _thresholds.DEGRADED_RECALL_FLOOR


class DegenerateEvidenceError(DomainError):
    """A cell whose recall is 1.0 by construction was offered as proof."""


def _text(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(f"{name} must be a non-empty string, got {value!r}")
    return value.strip()


@dataclass(frozen=True, slots=True)
class ConfusionCell:
    """One (scenario, conclusion_type) cell, stamped with its epoch."""

    scenario_id: str
    conclusion_type: str
    tp: int
    fp: int
    tn: int
    fn: int
    distinct_analysts: int
    epoch_id: str

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "ConfusionCell is final: a subclass could override "
            "is_degenerate, which is the one predicate incident #1 turns "
            "on.")

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id",
                           _text(self.scenario_id, name="scenario_id"))
        # Case matters: S1-CALIB-029 matches conclusion_type by exact
        # string, so normalising it here would silently merge cells.
        object.__setattr__(self, "conclusion_type",
                           _text(self.conclusion_type,
                                 name="conclusion_type"))
        for name in ("tp", "fp", "tn", "fn", "distinct_analysts"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) \
                    or value < 0:
                raise DomainError(
                    f"ConfusionCell {name} must be a non-negative integer, "
                    f"got {value!r}")
        epoch(_text(self.epoch_id, name="epoch_id"))

    @property
    def key(self) -> str:
        return f"{self.scenario_id}/{self.conclusion_type}"

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def recall_denominator(self) -> int:
        return self.tp + self.fn

    @property
    def recall(self) -> Optional[float]:
        return _recall.recall(tp=self.tp, fn=self.fn)

    @property
    def precision(self) -> Optional[float]:
        return _recall.precision(tp=self.tp, fp=self.fp)

    @property
    def is_degenerate(self) -> bool:
        """No negative of either kind was ever observed.

        Then `recall = tp/(tp+0)` is 1.0 whenever tp > 0 and undefined
        otherwise: in neither case is it a measurement of detection.
        """
        return self.fn == 0 and self.tn == 0

    @property
    def status(self) -> str:
        if self.is_degenerate:
            return DEGENERATE
        value = self.recall
        if value is None or self.recall_denominator < MIN_RECALL_DENOM:
            return INSUFFICIENT_DATA
        return DEGRADED if value < DEGRADED_RECALL_FLOOR else OK

    def as_dict(self) -> dict:
        return {"scenario_id": self.scenario_id,
                "conclusion_type": self.conclusion_type,
                "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                "total": self.total, "recall": self.recall,
                "precision": self.precision,
                "distinct_analysts": self.distinct_analysts,
                "epoch_id": self.epoch_id, "status": self.status,
                "is_degenerate": self.is_degenerate}


_EVIDENCE_TOKEN = object()


@dataclass(frozen=True, slots=True)
class CalibrationEvidence:
    """The only thing a calibration decision is allowed to rest on.

    Constructed exclusively through `from_cells`, which is where the
    degenerate refusal and the epoch check live. The bare dataclass
    constructor is closed off with a token so that "build the evidence
    without the checks" is not a two-character shortcut.
    """

    cells: tuple
    stamp: EpochStamp
    degenerate_dropped: tuple
    _token: object = field(default=None, repr=False, compare=False)

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "CalibrationEvidence is final: a subclass could accept the "
            "degenerate cells this type exists to refuse.")

    def __post_init__(self) -> None:
        if self._token is not _EVIDENCE_TOKEN:
            raise DomainError(
                "CalibrationEvidence must be built with from_cells(): the "
                "degenerate-cell refusal and the epoch check live there, "
                "and a second door would make them optional (incident #1).")

    @classmethod
    def from_cells(cls, cells: Iterable[ConfusionCell], *,
                   stamp: EpochStamp,
                   drop_degenerate: bool = False) -> "CalibrationEvidence":
        if not isinstance(stamp, EpochStamp):
            raise DomainError(
                f"evidence needs an EpochStamp, got {type(stamp).__name__}: "
                f"without one there is no record of which label population "
                f"it measured (F-16)")
        materialised = tuple(cells)
        for entry in materialised:
            if not isinstance(entry, ConfusionCell):
                raise DomainError(
                    f"evidence cells must be ConfusionCell, got "
                    f"{type(entry).__name__}")
            if entry.epoch_id != stamp.epoch_id:
                raise EpochMismatchError(
                    f"cell {entry.key} was labelled under epoch "
                    f"{entry.epoch_id} but the snapshot is stamped "
                    f"{stamp.epoch_id}; the two are different label "
                    f"populations and pooling them re-creates F-16 inside "
                    f"a single snapshot")

        degenerate = tuple(sorted(c.key for c in materialised
                                  if c.is_degenerate))
        usable = tuple(c for c in materialised if not c.is_degenerate)

        if degenerate and not drop_degenerate:
            raise DegenerateEvidenceError(
                f"cells {list(degenerate)} have fn == 0 and tn == 0, so "
                f"their recall is 1.0 by construction rather than by "
                f"detection — that is the exact shape incident #1 left "
                f"behind (2026-05-29 blanket-TP), and 5 of the 8 cells in "
                f"the live baseline still have it. Pass "
                f"drop_degenerate=True to proceed on the remaining cells; "
                f"the drop is then recorded on the evidence rather than "
                f"applied silently.")
        if not usable:
            raise DegenerateEvidenceError(
                "every cell offered is degenerate (fn == 0 and tn == 0); "
                "there is no evidence of detection here at all, only "
                "evidence that nothing has been labelled as a negative. "
                "A calibration decision on this input would be a decision "
                "on an artefact.")

        return cls(cells=usable, stamp=stamp,
                   degenerate_dropped=degenerate, _token=_EVIDENCE_TOKEN)

    @property
    def cell_count(self) -> int:
        return len(self.cells)

    @property
    def pooled_recall(self) -> Optional[float]:
        return _recall.recall(tp=sum(c.tp for c in self.cells),
                              fn=sum(c.fn for c in self.cells))

    @property
    def pooled_precision(self) -> Optional[float]:
        return _recall.precision(tp=sum(c.tp for c in self.cells),
                                 fp=sum(c.fp for c in self.cells))

    @property
    def sample_n(self) -> int:
        return sum(c.total for c in self.cells)

    @property
    def has_conclusive_cell(self) -> bool:
        """At least one cell whose recall is actually measurable."""
        return any(c.status in OK_STATUSES for c in self.cells)

    def cell_for(self, scenario_id: str,
                 conclusion_type: str) -> Optional[ConfusionCell]:
        for entry in self.cells:
            if entry.scenario_id == scenario_id \
                    and entry.conclusion_type == conclusion_type:
                return entry
        return None

    def as_dict(self) -> dict:
        return {"epoch_id": self.stamp.epoch_id,
                "window": [self.stamp.since, self.stamp.until],
                "exclude_auto": self.stamp.exclude_auto,
                "cells": [c.as_dict() for c in self.cells],
                "degenerate_dropped": list(self.degenerate_dropped),
                "pooled_recall": self.pooled_recall,
                "pooled_precision": self.pooled_precision,
                "sample_n": self.sample_n}


def degenerate_audit(cells: Iterable[ConfusionCell]) -> dict:
    """Name the degenerate cells in a snapshot. Never count-based.

    WP-1.4's L5 signature, expressed over any cell collection: which cells
    cannot testify, which can, and whether anything is left.
    """
    materialised = tuple(cells)
    degenerate = tuple(sorted(c.key for c in materialised if c.is_degenerate))
    healthy = tuple(sorted(c.key for c in materialised
                           if not c.is_degenerate))
    return {"degenerate": degenerate, "non_degenerate": healthy,
            "has_any_evidence": bool(healthy),
            "conclusive": tuple(sorted(c.key for c in materialised
                                       if c.status in OK_STATUSES))}


# ── S5-VERIF-035 enforcement ────────────────────────────────────────────

_PACKAGE_DIR = pathlib.Path(__file__).resolve().parent
_ARITHMETIC_HOME = "recall.py"


def audit_recall_arithmetic_sites() -> tuple:
    """Modules in this package that compute recall themselves.

    Production drifted into three implementations because nothing looked
    at the set of them. This reads the package's own AST for a division
    whose numerator mentions a `tp`-ish name, and reports every site
    outside `recall.py`.
    """
    offenders: list[str] = []
    for path in sorted(_PACKAGE_DIR.glob("*.py")):
        if path.name == _ARITHMETIC_HOME:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) \
                    or not isinstance(node.op, ast.Div):
                continue
            names = {n.id.lower() for n in ast.walk(node.left)
                     if isinstance(n, ast.Name)}
            names |= {n.attr.lower() for n in ast.walk(node.left)
                      if isinstance(n, ast.Attribute)}
            if names & {"tp", "true_positive", "true_positives"}:
                offenders.append(f"{path.name}:{node.lineno}")
    return tuple(offenders)


__all__ = ["ConfusionCell", "CalibrationEvidence", "DegenerateEvidenceError",
           "degenerate_audit", "audit_recall_arithmetic_sites",
           "DEGENERATE", "INSUFFICIENT_DATA", "DEGRADED", "OK",
           "OK_STATUSES", "MIN_RECALL_DENOM", "DEGRADED_RECALL_FLOOR"]
