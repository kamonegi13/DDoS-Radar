"""P2 §5-0 — the reference points where comparison measures nothing.

D2 §H names seven defects in v1 whose effect is that the v1-side quantity
is not a measurement. Agreeing with a detector that returned 0.0 on all
5,398 rows because it read a key RIPE never sends (H-05) measures zero;
disagreeing with it measures the repair. Either way the comparison says
nothing about detection capability, so the cell leaves the denominator.

Two disciplines are structural here rather than remembered:

  * **Exclusions are named.** `classify_cell` returns a classification
    for every cell it is given, carrying the VOID ids and the reasons, so
    a report can list what left the denominator and why. §5-0 rule 1
    forbids dropping them quietly.
  * **V-1 carries a period.** H-05 was repaired in both systems on
    2026-08-09 (§7-2 #136) and real history was backfilled, so the
    reference point is valid again after that instant. Writing it as
    permanent — the easy choice — would mean never measuring BGP again,
    which §5-0 rule 3 names as the failure to avoid. The boundary is
    supplied by the caller; this module reads no clock.

The register may not be extended to make a gate pass. §5-0 rule 3 asks
for a D2 defect id and measured evidence that the v1-side quantity is not
a measurement, and `_void_exclusion` refuses an unregistered id outright.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from v3.kernel.errors import DomainError

VOID_PERMANENT = "PERMANENT"
VOID_TIME_BOUNDED = "TIME_BOUNDED"

#: S5-VERIF-037: below this many positives a cell's recall is a statement
#: about the label collection rather than about the detector.
MIN_CELL_POSITIVES = 5

CELL_DEGENERATE = "degenerate"
CELL_INSUFFICIENT_POSITIVES = "insufficient_positives"
CELL_VOID_DEPENDENT = "void_dependent"
CELL_VOID_BOUNDARY_UNKNOWN = "void_boundary_unknown"


@dataclass(frozen=True, slots=True)
class VoidReference:
    """One reference point a v1 defect emptied of meaning (§5-0)."""

    void_id: str
    reference_point: str
    invalidating_defect: str
    scope: str
    v3_treatment: str
    comparison_treatment: str
    #: TIME_BOUNDED entries only: the `ParityContext` field carrying the
    #: instant after which the reference point is valid again.
    boundary_context_field: Optional[str] = None

    @property
    def is_time_bounded(self) -> bool:
        return self.scope == VOID_TIME_BOUNDED

    def as_dict(self) -> dict:
        return {"void_id": self.void_id,
                "reference_point": self.reference_point,
                "invalidating_defect": self.invalidating_defect,
                "scope": self.scope, "v3_treatment": self.v3_treatment,
                "comparison_treatment": self.comparison_treatment,
                "boundary_context_field": self.boundary_context_field}


VOID_REGISTER: tuple[VoidReference, ...] = (
    VoidReference(
        "V-1",
        "ripe_bgp's BGP anomaly (Z / drop_ratio / trend, bgp_hod)",
        "H-05",
        VOID_TIME_BOUNDED,
        "both systems repaired together and backfilled from real history; "
        "the old series is discarded — a deliberate epoch",
        "ticks before the repair are not comparable; where a window "
        "straddles it, BGP-derived disagreements leave the denominator and "
        "are disclosed as VOID",
        boundary_context_field="bgp_repair_at"),
    VoidReference(
        "V-2",
        "cf_adversary_strike's direction confidence (0.7 / 0.9)",
        "H-01",
        VOID_PERMANENT,
        "not ported (§7-2 #125)",
        "excluded from the agreement denominator: a quantity v1 does not "
        "reproduce against ITSELF across restarts cannot be compared"),
    VoidReference(
        "V-3",
        "bit-equality of the raw IDF index",
        "H-04",
        VOID_PERMANENT,
        "deterministic via sorted() (§7-2 #133)",
        "the index compares at abs=0.01 and the VERDICT compares exactly; "
        "bit equality is not a condition"),
    VoidReference(
        "V-4",
        "sequence-event attribution on dual-core scenarios",
        "H-02",
        VOID_PERMANENT,
        "not reproduced (§7-2 #128)",
        "disagreement is not counted as v3 degradation; it is disclosed as "
        "a record that v1 is wrong — the same shape as the 2026-08-02 "
        "calibration incident"),
    VoidReference(
        "V-5",
        "Cloudflare attack-origin country attribution (ISO2 sweep)",
        "H-06",
        VOID_PERMANENT,
        "targetCountryAlpha2 takes priority over the sweep",
        "attribution differences are not counted as v3 errors: the v1 "
        "winner was decided by dict iteration order, and a test fixture "
        "froze that misattribution as the expected value"),
    VoidReference(
        "V-6",
        "anomaly family coverage (27 families)",
        "H-03",
        VOID_PERMANENT,
        "aligned with production (§7-2 #127 / #132)",
        "the comparison is VALID and does agree, but agreement on this "
        "surface is not cited as evidence of detection capability"),
    VoidReference(
        "V-7",
        "survival of Defer in the proposal queue",
        "H-07",
        VOID_PERMANENT,
        "ported and proven (§7-2 #82)",
        "the two sides agree, and what they agree on is a defect; repaired "
        "in both at the same time as the production ruling"),
)

VOID_BY_ID: Mapping[str, VoidReference] = {
    entry.void_id: entry for entry in VOID_REGISTER}


@dataclass(frozen=True, slots=True)
class CellClassification:
    """Why one calibration cell is, or is not, ground to stand on."""

    cell_id: str
    is_valid: bool
    reasons: tuple[str, ...] = ()
    void_refs: tuple[str, ...] = ()
    detail: str = ""

    def as_dict(self) -> dict:
        return {"cell_id": self.cell_id, "is_valid": self.is_valid,
                "reasons": list(self.reasons),
                "void_refs": list(self.void_refs), "detail": self.detail}


def cell_identity(cell: Mapping) -> str:
    """The cell's own id, or the (scenario, conclusion_type) pair."""
    return str(cell.get("cell_id") or
               f"{cell.get('scenario')}/{cell.get('conclusion_type')}")


def _void_exclusion(void_refs: Iterable[str],
                    window_start: Optional[float],
                    boundaries: Mapping[str, Optional[float]]
                    ) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    """Which registered VOIDs still invalidate this cell, and why.

    Returns (blocking_ids, reasons, detail). A time-bounded VOID stops
    blocking once the cell's window opens at or after its boundary — the
    whole point of writing V-1 with a period instead of as permanent.
    """
    blocking: list[str] = []
    reasons: set[str] = set()
    notes: list[str] = []
    for void_id in void_refs:
        entry = VOID_BY_ID.get(void_id)
        if entry is None:
            raise DomainError(
                f"{void_id} is not in the §5-0 VOID register: an exclusion "
                f"that is not registered is how a gate gets passed by "
                f"inventing exemptions. Add it to VOID_REGISTER with the D2 "
                f"defect id and the evidence that the v1-side quantity is "
                f"not a measurement.")
        if not entry.is_time_bounded:
            blocking.append(void_id)
            reasons.add(CELL_VOID_DEPENDENT)
            continue
        boundary = boundaries.get(entry.boundary_context_field or "")
        if boundary is None:
            blocking.append(void_id)
            reasons.add(CELL_VOID_BOUNDARY_UNKNOWN)
            notes.append(
                f"{void_id} is time-limited and the context supplied no "
                f"{entry.boundary_context_field}")
        elif window_start is None:
            blocking.append(void_id)
            reasons.add(CELL_VOID_BOUNDARY_UNKNOWN)
            notes.append(
                f"{void_id} is time-limited and the cell states no "
                f"window_start, so which side of the boundary it sits on is "
                f"unknown")
        elif window_start < boundary:
            blocking.append(void_id)
            reasons.add(CELL_VOID_DEPENDENT)
            notes.append(f"{void_id} window opens before its boundary")
    return tuple(blocking), tuple(sorted(reasons)), "; ".join(notes)


def classify_cell(cell: Mapping, *,
                  bgp_repair_at: Optional[float] = None
                  ) -> CellClassification:
    """P2 §5 group A's 有効 cell predicate, with every reason reported.

    Valid = non-degenerate (`fn+tn > 0`) AND `tp+fn >= 5` (S5-VERIF-037)
    AND not dependent on a §5-0 VOID reference point. All three are
    evaluated, because a cell that fails two of them fails for two
    reasons and the report should say so.
    """
    reasons: set[str] = set()

    tp = float(cell.get("tp") or 0)
    fn = float(cell.get("fn") or 0)
    tn = float(cell.get("tn") or 0)
    if fn + tn <= 0:
        # recall is 1.0 by construction here, so the condition is empty
        # rather than satisfied.
        reasons.add(CELL_DEGENERATE)
    if tp + fn < MIN_CELL_POSITIVES:
        reasons.add(CELL_INSUFFICIENT_POSITIVES)

    blocking, void_reasons, detail = _void_exclusion(
        cell.get("void_refs") or (), cell.get("window_start"),
        {"bgp_repair_at": bgp_repair_at})
    reasons.update(void_reasons)

    return CellClassification(
        cell_id=cell_identity(cell), is_valid=not reasons,
        reasons=tuple(sorted(reasons)), void_refs=blocking, detail=detail)


def classify_cells(cells: Iterable[Mapping], *,
                   bgp_repair_at: Optional[float] = None
                   ) -> tuple[CellClassification, ...]:
    return tuple(classify_cell(cell, bgp_repair_at=bgp_repair_at)
                 for cell in cells)


__all__ = ["VoidReference", "VOID_REGISTER", "VOID_BY_ID", "VOID_PERMANENT",
           "VOID_TIME_BOUNDED", "CellClassification", "classify_cell",
           "classify_cells", "cell_identity", "MIN_CELL_POSITIVES",
           "CELL_DEGENERATE", "CELL_INSUFFICIENT_POSITIVES",
           "CELL_VOID_DEPENDENT", "CELL_VOID_BOUNDARY_UNKNOWN"]
