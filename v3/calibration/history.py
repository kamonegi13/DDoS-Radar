"""The threshold ledger: what a threshold was, when, and why.

S1-CALIB-022/023/024/025. NP6's precondition — reproducing a past
conclusion requires knowing the thresholds that were in force when it was
drawn — and, on 2026-07-03 and 2026-08-02, the mechanism the remediation
actually used: `revert` rolled the Korean and Middle East thresholds back
after the calibrator had walked them down by -5% twelve and four times.

Pure record algebra. Every operation takes the rows and returns new rows;
nothing is mutated, so "what did this look like before" is always
answerable, and a caller cannot accidentally rewrite history by holding a
reference. Persistence is L1's; the semantics are here.

Two corrections to production behaviour, both registered:

* DP20 — a lineage walk that hits a missing row returns a partial graph
  with no indication that it is partial. Here `Lineage.complete` says so.
* S1-CALIB-025 — nothing records which thresholds a conclusion was drawn
  under; it is recomputed by timestamp at read time. `value_at` keeps that
  as-of semantics, and the completeness flag makes a failed resolution
  visible rather than silent.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Optional

from v3.calibration.authority import Authorisation
from v3.kernel.errors import DomainError

STATE_ACTIVE = "active"
STATE_SUPERSEDED = "superseded"
STATE_REVERTED = "reverted"
STATES: tuple[str, ...] = (STATE_ACTIVE, STATE_SUPERSEDED, STATE_REVERTED)

#: S1-CALIB-024: the lineage walk's depth cap.
MAX_LINEAGE_DEPTH = 50


def _text(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(f"{name} must be a non-empty string, got {value!r}")
    return value.strip()


@dataclass(frozen=True, slots=True)
class ThresholdRow:
    """One append-only row of the threshold ledger."""

    row_id: str
    key: str
    value: float
    scope_scenario_id: Optional[str]
    effective_from: float
    effective_to: Optional[float]
    state: str
    applied_by: str
    derived_from: Optional[str]
    revertible_to_id: Optional[str]
    sample_n: int
    formula_ref: str
    evidence: dict
    magnitude_pct: float

    def __post_init__(self) -> None:
        _text(self.row_id, name="row_id")
        _text(self.key, name="key")
        _text(self.applied_by, name="applied_by")
        _text(self.formula_ref, name="formula_ref")
        if self.state not in STATES:
            raise DomainError(
                f"unknown ledger state {self.state!r}; expected one of "
                f"{list(STATES)}")
        if self.effective_to is not None \
                and self.effective_to < self.effective_from:
            raise DomainError("effective_to precedes effective_from")

    @property
    def scope_key(self) -> tuple:
        return (self.key, self.scope_scenario_id)

    def as_dict(self) -> dict:
        return {"row_id": self.row_id, "key": self.key, "value": self.value,
                "scope_scenario_id": self.scope_scenario_id,
                "effective_from": self.effective_from,
                "effective_to": self.effective_to, "state": self.state,
                "applied_by": self.applied_by,
                "derived_from": self.derived_from,
                "revertible_to_id": self.revertible_to_id,
                "sample_n": self.sample_n,
                "formula_ref": self.formula_ref,
                "evidence": dict(self.evidence),
                "magnitude_pct": self.magnitude_pct}


def record_change(rows: Iterable[ThresholdRow], *, new_row: ThresholdRow,
                  authorisation: Authorisation) -> tuple:
    """Append `new_row`, closing the prior active row in the same step.

    S1-CALIB-022: the supersede and the insert are one transaction, the
    windows are half-open and contiguous, and at the boundary instant the
    NEW row wins. Doing them separately is how a ledger acquires two
    simultaneously-active rows for one key.
    """
    authorisation.require("record_threshold_change")
    if not isinstance(new_row, ThresholdRow):
        raise DomainError("record_change needs a ThresholdRow")
    if new_row.state != STATE_ACTIVE:
        raise DomainError(
            f"a newly recorded row is {STATE_ACTIVE!r}, not "
            f"{new_row.state!r}")
    materialised = tuple(rows)
    if any(r.row_id == new_row.row_id for r in materialised):
        raise DomainError(f"row_id {new_row.row_id!r} already exists; the "
                          f"ledger is append-only, not upsert")
    closed = tuple(
        replace(row, state=STATE_SUPERSEDED,
                effective_to=new_row.effective_from)
        if (row.scope_key == new_row.scope_key
            and row.state == STATE_ACTIVE)
        else row
        for row in materialised)
    return closed + (new_row,)


def value_at(rows: Iterable[ThresholdRow], *, key: str, at: float,
             scenario_id: Optional[str] = None) -> Optional[ThresholdRow]:
    """What was in force at `at`. NOT filtered by state.

    S1-CALIB-022: a row that later became superseded or reverted was
    genuinely in force at the time, and a point-in-time query that hides
    it cannot reproduce the conclusion it produced.

    Scope resolution is scenario -> global (scope IS NULL) -> undefined.
    """
    materialised = tuple(rows)
    for scope in (scenario_id, None) if scenario_id is not None else (None,):
        candidates = [r for r in materialised
                      if r.key == key and r.scope_scenario_id == scope
                      and r.effective_from <= at
                      and (r.effective_to is None or at < r.effective_to)]
        if candidates:
            # The boundary instant belongs to the newest row.
            return max(candidates, key=lambda r: r.effective_from)
    return None


def current(rows: Iterable[ThresholdRow], *, key: str,
            scenario_id: Optional[str] = None) -> Optional[ThresholdRow]:
    """The value in force now: `state == 'active'` only."""
    materialised = tuple(rows)
    for scope in (scenario_id, None) if scenario_id is not None else (None,):
        candidates = [r for r in materialised
                      if r.key == key and r.scope_scenario_id == scope
                      and r.state == STATE_ACTIVE]
        if candidates:
            return max(candidates, key=lambda r: r.effective_from)
    return None


class RevertRefusedError(DomainError):
    """One of revert's four preconditions did not hold."""


def revert(rows: Iterable[ThresholdRow], *, row_id: str, at: float,
           new_row_id: str, authorisation: Authorisation) -> tuple:
    """S1-CALIB-023: restore the predecessor's value as a NEW row.

    The repair path of incidents #2 and #3. Four preconditions, all
    required: the target exists, it is active, it names a predecessor, and
    that predecessor exists. Rolling back by editing the row in place
    would erase the evidence of the walk that had to be undone.
    """
    authorisation.require("revert_threshold_change")
    materialised = tuple(rows)
    by_id = {r.row_id: r for r in materialised}

    target = by_id.get(row_id)
    if target is None:
        raise RevertRefusedError(f"row {row_id!r} does not exist")
    if target.state != STATE_ACTIVE:
        raise RevertRefusedError(
            f"row {row_id!r} is {target.state!r}, not active; only the row "
            f"currently in force can be reverted")
    if target.revertible_to_id is None:
        raise RevertRefusedError(
            f"row {row_id!r} names no predecessor, so there is no value to "
            f"restore")
    predecessor = by_id.get(target.revertible_to_id)
    if predecessor is None:
        raise RevertRefusedError(
            f"row {row_id!r} names predecessor "
            f"{target.revertible_to_id!r}, which is not in the ledger")

    restored = ThresholdRow(
        row_id=new_row_id, key=target.key, value=predecessor.value,
        scope_scenario_id=target.scope_scenario_id, effective_from=at,
        effective_to=None, state=STATE_ACTIVE,
        applied_by=authorisation.actor.actor_id,
        derived_from=f"revert_of:{row_id}",
        revertible_to_id=predecessor.row_id, sample_n=0,
        formula_ref="threshold_history#revert",
        evidence={"reverted_row_id": row_id,
                  "restored_from_row_id": predecessor.row_id},
        magnitude_pct=0.0)

    marked = tuple(replace(row, state=STATE_REVERTED, effective_to=at)
                   if row.row_id == row_id else row
                   for row in materialised)
    return marked + (restored,)


@dataclass(frozen=True, slots=True)
class Lineage:
    """A derivation walk, with an honest completeness flag.

    DP20: production returns a partial graph on a missing row or a DB
    error and says nothing about it, so a truncated lineage and a short
    one are indistinguishable. `complete` and `truncated_because` make
    the difference visible.
    """

    ancestors: tuple
    descendants: tuple
    complete: bool
    truncated_because: Optional[str]

    def as_dict(self) -> dict:
        return {"ancestors": [r.as_dict() for r in self.ancestors],
                "descendants": [r.as_dict() for r in self.descendants],
                "complete": self.complete,
                "truncated_because": self.truncated_because}


def lineage(rows: Iterable[ThresholdRow], *, row_id: str,
            max_depth: int = MAX_LINEAGE_DEPTH) -> Lineage:
    """Walk the predecessor edge both ways. Reads only, writes never."""
    materialised = tuple(rows)
    by_id = {r.row_id: r for r in materialised}
    if row_id not in by_id:
        return Lineage((), (), False, f"row {row_id!r} not found")

    ancestors: list = []
    seen = {row_id}
    cursor = by_id[row_id]
    reason: Optional[str] = None
    complete = True
    while cursor.revertible_to_id is not None:
        if len(ancestors) >= max_depth:
            complete, reason = False, f"depth cap {max_depth} reached"
            break
        if cursor.revertible_to_id in seen:
            complete, reason = False, (
                f"cycle at {cursor.revertible_to_id!r}")
            break
        parent = by_id.get(cursor.revertible_to_id)
        if parent is None:
            complete, reason = False, (
                f"predecessor {cursor.revertible_to_id!r} is missing")
            break
        ancestors.append(parent)
        seen.add(parent.row_id)
        cursor = parent

    children: dict = {}
    for row in materialised:
        if row.revertible_to_id:
            children.setdefault(row.revertible_to_id, []).append(row)

    descendants: list = []
    frontier = [row_id]
    visited = {row_id}
    depth = 0
    while frontier:
        if depth >= max_depth:
            complete, reason = False, f"depth cap {max_depth} reached"
            break
        following: list = []
        for parent_id in frontier:
            for child in sorted(children.get(parent_id, []),
                                key=lambda r: r.effective_from):
                if child.row_id in visited:
                    complete, reason = False, f"cycle at {child.row_id!r}"
                    continue
                visited.add(child.row_id)
                descendants.append(child)
                following.append(child.row_id)
        frontier = following
        depth += 1

    return Lineage(tuple(ancestors), tuple(descendants), complete, reason)


def clamp_magnitude(*, prior: Optional[float], proposed: float,
                    max_pct: float) -> tuple:
    """S1-CALIB-063: exceeding the budget CLAMPS, it does not reject.

    Ported with its edges intact, because they are where the behaviour
    lives: `prior == 0` is outside the budget entirely, a first-seen key
    commits verbatim at magnitude 0.0, and the direction is unconstrained
    (the absolute value ignores the sign — the only directional constraint
    anywhere is the impact classification).
    """
    if prior is None:
        return proposed, 0.0
    if isinstance(prior, bool) or isinstance(proposed, bool) \
            or not isinstance(prior, (int, float)) \
            or not isinstance(proposed, (int, float)):
        return proposed, 100.0
    if prior == 0:
        return (proposed, 100.0 if proposed != 0 else 0.0)
    delta = proposed - prior
    magnitude = abs(delta / prior) * 100.0
    if magnitude <= max_pct:
        return proposed, magnitude
    sign = 1.0 if delta > 0 else -1.0
    clamped = prior + sign * abs(prior) * (max_pct / 100.0)
    return clamped, max_pct


__all__ = ["ThresholdRow", "STATES", "STATE_ACTIVE", "STATE_SUPERSEDED",
           "STATE_REVERTED", "MAX_LINEAGE_DEPTH", "record_change",
           "value_at", "current", "revert", "RevertRefusedError", "Lineage",
           "lineage", "clamp_magnitude"]
