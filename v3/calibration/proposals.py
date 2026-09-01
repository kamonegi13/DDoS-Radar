"""Proposal generation: pure, disclosed, and gated by the one evaluator.

`(labels, current thresholds) -> proposals with Provenance`. No queries,
no writes, no clock: the same evidence always produces the same proposal,
which is what makes the differential sweep against production meaningful.

Application is a separate step and needs a `Permit`, which only
`guards.evaluate()` mints. Generation needs one too — S1-CALIB-019 says a
calibrator "hands to the ledger and has no side effect on scoring", and
the way to keep that true is for the proposal to be a value rather than
an action.

Three corrections to production, each registered:

* DP2 — production's `evidence` omits the freshness-gate inputs, so the
  ledger cannot answer "which false negative justified this change".
  Every input the decision consulted is in `Provenance.inputs` here.
* DP22 — the ±5% step has no absolute bounds in production, so repeated
  loosening converges geometrically toward zero (the Middle East band
  took twelve of them). An absolute floor and ceiling are applied and
  disclosed.
* DP23 — the calibrator's `tp / max(1, tp+fn)` reports 0.0 for an
  unmeasurable recall while every other path reports None. There is one
  recall implementation here and it returns None.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from v3.calibration import matrix as M
from v3.calibration import thresholds as T
from v3.calibration.guards import IMPACT_HIGH, IMPACT_LOW, Permit
from v3.kernel.errors import DomainError
from v3.kernel.provenance import Provenance

DIRECTION_LOOSER = "looser"
DIRECTION_TIGHTER = "tighter"

#: S1-CALIB-018's five bands and their defaults, read from
#: `tl_threshold_calibrator.DEFAULT_TL_THRESHOLDS` by AST.
DEFAULT_TL_THRESHOLDS: dict = {
    "tl1_total": 9.0, "tl1_physical": 3.0, "tl2_total": 6.0,
    "tl3_total": 4.0, "tl4_total": 2.0}

#: DP22's repair. Production has no absolute bound, so a band that is
#: loosened every cycle approaches zero — 0.95^12 is 0.54, and the Middle
#: East band took exactly twelve. The bounds are a fraction of the band's
#: own default rather than one global number, because the bands differ by
#: 4.5x.
ABSOLUTE_FLOOR_FRACTION = 0.50
ABSOLUTE_CEILING_FRACTION = 2.00

_NO_ACTION = "no_action_needed"
_DEGENERATE_GUARD = "degenerate_data_guard"


@dataclass(frozen=True, slots=True)
class Direction:
    """Which way to move, or why not to move at all."""

    direction: Optional[str]
    reason: str

    @property
    def acts(self) -> bool:
        return self.direction is not None


def decide_direction(cell: M.ConfusionCell) -> Direction:
    """S1-CALIB-015's four branches, in the order the code evaluates them.

    Read off `tl_threshold_calibrator.py:215-239`, not off the clause
    text: the clause numbers the degenerate guard second and the module
    agrees, but only reading the module proves it.

    1. recall < 0.80                     -> looser (0.80 does NOT fire)
    2. tn == 0 and fn == 0 and precision < floor + 0.20  -> no action
    3. recall >= 0.99 and precision < 0.30 -> tighter (0.30 does NOT fire)
    4. otherwise                         -> no action

    Recall is checked first, so a recall shortfall never waits on
    precision. That ordering is NP1 in one line.
    """
    if not isinstance(cell, M.ConfusionCell):
        raise DomainError(
            f"decide_direction needs a ConfusionCell, got "
            f"{type(cell).__name__}")
    recall = cell.recall
    precision = cell.precision
    if recall is None or precision is None:
        # DP23: production's max(1, ·) would report 0.0 here and loosen on
        # a measurement that does not exist.
        return Direction(None, "recall_or_precision_unmeasurable")

    if recall < T.CALIBRATOR_RECALL_FLOOR:
        return Direction(DIRECTION_LOOSER, "recall_below_floor")

    is_degenerate = (
        cell.tn == 0 and cell.fn == 0
        and precision < T.CALIBRATOR_PRECISION_MIN_FLOOR
        + T.CALIBRATOR_DEGENERATE_PRECISION_MARGIN)
    if is_degenerate:
        return Direction(None, _DEGENERATE_GUARD)

    if recall >= T.CALIBRATOR_TIGHTEN_RECALL_FLOOR \
            and precision < T.CALIBRATOR_PRECISION_CEILING:
        return Direction(DIRECTION_TIGHTER, "precision_below_ceiling")

    return Direction(None, _NO_ACTION)


def stepped_value(current: float, *, direction: str,
                  band_default: float) -> float:
    """S1-CALIB-018's ±5%, with the absolute bounds DP22 asks for."""
    if direction == DIRECTION_LOOSER:
        factor = T.CALIBRATOR_LOOSER_FACTOR
    elif direction == DIRECTION_TIGHTER:
        factor = T.CALIBRATOR_TIGHTER_FACTOR
    else:
        raise DomainError(f"unknown direction {direction!r}")
    stepped = round(current * factor, T.CALIBRATOR_ROUND_DIGITS)
    floor = band_default * ABSOLUTE_FLOOR_FRACTION
    ceiling = band_default * ABSOLUTE_CEILING_FRACTION
    return min(max(stepped, floor), ceiling)


def impact_of(direction: str) -> str:
    """S1-CALIB-056's norm: raising recall is low, reducing it is high.

    Withholding a conclusion is itself a reduction in recall, which is why
    the asymmetry is not arbitrary (NP1).
    """
    if direction == DIRECTION_LOOSER:
        return IMPACT_LOW
    if direction == DIRECTION_TIGHTER:
        return IMPACT_HIGH
    raise DomainError(f"unknown direction {direction!r}")


@dataclass(frozen=True, slots=True)
class Proposal:
    """A change, its justification, and everything that produced it."""

    key: str
    scope_scenario_id: str
    band: str
    prior_value: float
    proposed_value: float
    direction: str
    impact: str
    sample_n: int
    formula_ref: str
    provenance: Provenance

    def __post_init__(self) -> None:
        if not isinstance(self.provenance, Provenance):
            raise DomainError(
                "a proposal without Provenance is not disclosable (NP6); "
                "DP2 is exactly this omission — the ledger cannot say "
                "which false negative justified the change")

    def as_dict(self) -> dict:
        return {"key": self.key, "scope_scenario_id": self.scope_scenario_id,
                "band": self.band, "prior_value": self.prior_value,
                "proposed_value": self.proposed_value,
                "direction": self.direction, "impact": self.impact,
                "sample_n": self.sample_n, "formula_ref": self.formula_ref,
                "provenance": self.provenance.as_dict()}


CALIBRATOR_VERSION = "v3.calibration.proposals/v1"


def generate(evidence: M.CalibrationEvidence, *, scenario_id: str,
             current_values: dict, computed_at: float,
             motivating_at: Optional[float] = None,
             last_applied_at: Optional[float] = None) -> tuple:
    """Every band's proposal for one scenario. Pure.

    Returns an empty tuple when the direction says no action — the same
    "all five bands or none" shape production has, because the direction
    is decided once per scenario from the threat_level cell.
    """
    if not isinstance(evidence, M.CalibrationEvidence):
        raise DomainError(
            f"generate needs CalibrationEvidence, got "
            f"{type(evidence).__name__}: a raw cell list would bypass the "
            f"degenerate refusal (S5-VERIF-037)")
    cell = evidence.cell_for(scenario_id, "threat_level")
    if cell is None:
        return ()
    decision = decide_direction(cell)
    if not decision.acts:
        return ()

    impact = impact_of(decision.direction)
    proposals: list = []
    for band, default in sorted(DEFAULT_TL_THRESHOLDS.items()):
        prior = current_values.get(band, default)
        proposed = stepped_value(prior, direction=decision.direction,
                                 band_default=default)
        if proposed == prior:
            # S1-CALIB-018: an unchanged value is not a proposal.
            continue
        provenance = Provenance(
            formula_ref=f"{CALIBRATOR_VERSION}#{band}_{decision.direction}",
            computed_at=computed_at,
            inputs={"recall": cell.recall, "precision": cell.precision,
                    "tp": cell.tp, "fp": cell.fp, "fn": cell.fn,
                    "tn": cell.tn, "direction": decision.direction,
                    "reason": decision.reason, "prior_value": prior,
                    "band_default": default,
                    "epoch_id": evidence.stamp.epoch_id,
                    "window_since": evidence.stamp.since,
                    "window_until": evidence.stamp.until,
                    "exclude_auto": evidence.stamp.exclude_auto,
                    # DP2: production omits these two, so the ledger
                    # cannot reconstruct which evidence justified the move.
                    "motivating_at": motivating_at,
                    "last_applied_at": last_applied_at},
            source_refs=(f"cell:{cell.key}",))
        proposals.append(Proposal(
            key=f"tl_thresholds.{scenario_id}.{band}",
            scope_scenario_id=scenario_id, band=band, prior_value=prior,
            proposed_value=proposed, direction=decision.direction,
            impact=impact, sample_n=cell.total,
            formula_ref=provenance.formula_ref, provenance=provenance))
    return tuple(proposals)


def apply_to_ledger_row(proposal: Proposal, *, permit: Permit,
                        effective_from: float, row_id: str,
                        revertible_to_id: Optional[str],
                        applied_by: str):
    """Turn an approved proposal into a ledger row.

    Takes a `Permit`, which only `guards.evaluate()` produces. That is the
    single-path requirement made structural: there is no argument list
    that reaches this function without the evaluator having spoken (E-03).
    """
    from v3.calibration.history import STATE_ACTIVE, ThresholdRow
    if not isinstance(permit, Permit):
        raise DomainError(
            f"apply_to_ledger_row needs a Permit from guards.evaluate(), "
            f"got {type(permit).__name__}")
    from v3.calibration.guards import PHASE_APPLICATION
    permit.require(PHASE_APPLICATION)
    return ThresholdRow(
        row_id=row_id, key=proposal.key, value=proposal.proposed_value,
        scope_scenario_id=proposal.scope_scenario_id,
        effective_from=effective_from, effective_to=None,
        state=STATE_ACTIVE, applied_by=applied_by,
        derived_from=None, revertible_to_id=revertible_to_id,
        sample_n=proposal.sample_n, formula_ref=proposal.formula_ref,
        evidence=dict(proposal.provenance.inputs), magnitude_pct=0.0)


__all__ = ["DIRECTION_LOOSER", "DIRECTION_TIGHTER", "DEFAULT_TL_THRESHOLDS",
           "ABSOLUTE_FLOOR_FRACTION", "ABSOLUTE_CEILING_FRACTION",
           "Direction", "decide_direction", "stepped_value", "impact_of",
           "Proposal", "CALIBRATOR_VERSION", "generate",
           "apply_to_ledger_row"]
