"""The label ledger's L4 half: the one door in, and the cells out.

WP-3.2 built the type system for comparing labels — `LabelProvenance`,
`EpochStamp`, `ConfusionCell`, `CalibrationEvidence` — and none of it had
anywhere to read from. This module is the two edges that were missing:

    record(...)      an Actor + a LabelProvenance -> a stored LabelRecord
    cells_for(...)   stored rows -> ConfusionCells -> CalibrationEvidence

**Why the write door is here and not on the store.** L1 enforces that the
four provenance columns are PRESENT (NOT NULL, non-empty, and
`LabelRecord` refuses a blank). It cannot enforce that they are COHERENT —
that `rss_etl:4` is actually declared against `e2026_08_02` — because that
is `v3/calibration/epoch.py`'s table and L1 may not import L4. So the
coherence check lives on this side, in the only module allowed to build a
`LabelRecord`, and `audit_label_construction_sites()` proves by AST that
no second module does. That is the same shape as
`matrix.audit_recall_arithmetic_sites()`, and it exists for the same
reason: a rule that holds because everyone remembers it is a rule that
held right up until the incident.

**Authority.** A label is an input to the recall chain, so writing one
takes an `Authorisation` for `submit_label` — analyst or above (G-01).
Automated labels are not exempt: an ETL presents an automated `Actor`,
which carries its generator identity, and `Actor.automated` refuses an
`actor_id` that does not begin `auto:` — so "who labelled this" and "was
it a human" are the same fact rather than two that can disagree.

**Cross-epoch comparison stays unrepresentable.** `cells_for` takes an
`EpochStamp` and passes its `epoch_id` to the store, which has no
cross-epoch reader at all. Every cell it returns therefore carries the
stamp's epoch by construction, and `CalibrationEvidence.from_cells`
re-checks it — two independent refusals of the same mistake, because F-16
survived one.
"""
from __future__ import annotations

import ast
import hashlib
import pathlib
from typing import Iterable, Mapping, Optional, Sequence

from v3.calibration import matrix as M
from v3.calibration.authority import Actor, Authorisation
from v3.calibration.epoch import EpochStamp, LabelProvenance
from v3.calibration.ground_truth import RULE_ORDER
from v3.kernel.errors import DomainError
from v3.ledger.records import LabelRecord

#: The action `authority.ACTIONS` gates a label write behind.
SUBMIT_LABEL = "submit_label"

#: The four values a confusion cell counts. A label outside them is kept
#: (the analyst wrote it) but counted only in `distinct_analysts`, which
#: is S1-CALIB-026's rule verbatim — dropping the row entirely would make
#: an analyst's participation invisible, and counting it in a cell would
#: widen the matrix by a value nothing knows how to score.
COUNTED_LABELS: frozenset = frozenset(RULE_ORDER)

_COUNTER_FOR: Mapping[str, str] = {
    "TRUE_POSITIVE": "tp", "FALSE_POSITIVE": "fp",
    "TRUE_NEGATIVE": "tn", "FALSE_NEGATIVE": "fn",
}


def label_id_for(*, conclusion_id: str, analyst_id: str,
                 labelled_at: float) -> str:
    """A deterministic identity for one label event.

    Deterministic so a re-run of an ETL over the same rows converges
    instead of doubling the denominator of every recall number it feeds.
    `labelled_at` is IN the key: an analyst who relabels later has made a
    new judgement and both rows must survive (the fold picks the latest),
    whereas the same judgement replayed lands on the same id.
    """
    material = f"{conclusion_id}\x1f{analyst_id}\x1f{labelled_at!r}"
    return "lbl_" + hashlib.sha256(material.encode()).hexdigest()[:24]


def record(*, authorisation: Authorisation, provenance: LabelProvenance,
           conclusion_id: str, scenario_id: str, conclusion_type: str,
           label: str, observed_at: float, labelled_at: float,
           observed_outcome_url: Optional[str] = None,
           reason: Optional[str] = None) -> LabelRecord:
    """Build the one stored label. THE only construction site.

    Takes the `Authorisation` rather than the `Actor` so the permit cannot
    be skipped by passing a well-formed actor: `authorize()` is the only
    minter and `require()` refuses a permit issued for a cheaper action.
    """
    if not isinstance(authorisation, Authorisation):
        raise DomainError(
            f"recording a label needs an Authorisation from "
            f"authority.authorize(), got {type(authorisation).__name__}. A "
            f"label is an input to the recall chain and every calibration "
            f"disaster so far began with a contaminated input (G-01).")
    authorisation.require(SUBMIT_LABEL)
    if not isinstance(provenance, LabelProvenance):
        raise DomainError(
            f"a label needs LabelProvenance, got "
            f"{type(provenance).__name__}: without the generator, its "
            f"version and the epoch, this row cannot be compared with any "
            f"other row (S5-VERIF-032, F-16)")
    if label not in COUNTED_LABELS:
        raise DomainError(
            f"unknown label {label!r}; the calibration vocabulary is "
            f"{sorted(COUNTED_LABELS)}. A fifth value would either be "
            f"dropped by the consumer — a contribution the analyst believes "
            f"they made and nothing counts — or widen the matrix by a cell "
            f"the recall arithmetic has no definition for.")
    actor: Actor = authorisation.actor
    if actor.is_automated and \
            actor.generator_id != provenance.generator_id:
        raise DomainError(
            f"the automated actor identifies as {actor.generator_id!r} but "
            f"the label's provenance says {provenance.generator_id!r}. Two "
            f"answers to 'which generator wrote this' is the state where "
            f"an epoch advance can miss a population.")
    return LabelRecord(
        label_id=label_id_for(conclusion_id=conclusion_id,
                              analyst_id=actor.actor_id,
                              labelled_at=labelled_at),
        conclusion_id=conclusion_id, scenario_id=scenario_id,
        conclusion_type=conclusion_type, label=label,
        analyst_id=actor.actor_id, observed_at=observed_at,
        labelled_at=labelled_at,
        generator_id=provenance.generator_id,
        generator_version=provenance.generator_version,
        rule_id=provenance.rule_id, epoch_id=provenance.epoch_id,
        is_automated=actor.is_automated,
        observed_outcome_url=observed_outcome_url, reason=reason)


def submit(store, *, authorisation: Authorisation,
           provenance: LabelProvenance, now: Optional[float] = None,
           **fields) -> LabelRecord:
    """`record()` then `append_label()`. The whole write, one call."""
    built = record(authorisation=authorisation, provenance=provenance,
                   **fields)
    store.append_label(built, now=now)
    return built


# ── the read: rows -> cells -> evidence ─────────────────────────────────
def latest_per_subject(rows: Iterable[Mapping]) -> tuple:
    """One row per (conclusion_id, analyst_id) — the latest wins.

    S1-CALIB-026's rule, and NOT an optimisation. An analyst who relabels
    has changed their mind; counting both would double their weight in the
    denominator of a recall number, and an analyst whose second thought
    disagrees with their first is exactly the case where the doubling
    lands on both sides of the matrix at once.

    The tie-break is the row's insert order (`id`), so two labels written
    at the same instant still have one answer rather than an order that
    depends on how SQLite felt.
    """
    newest: dict = {}
    for row in rows:
        key = (row["conclusion_id"], row["analyst_id"])
        current = newest.get(key)
        rank = (float(row["labelled_at"]), int(row.get("id") or 0))
        if current is None or rank > current[0]:
            newest[key] = (rank, row)
    return tuple(row for _, row in sorted(
        newest.values(), key=lambda pair: pair[0]))


def cells_from_rows(rows: Iterable[Mapping], *, epoch_id: str) -> tuple:
    """`ConfusionCell` per (scenario_id, conclusion_type).

    Every cell carries `epoch_id`, taken from the argument rather than
    from the rows: the store cannot return a mixed-epoch list, so reading
    it off the rows would be a check that can never fire, and a check that
    can never fire is one nobody notices when the query changes.
    """
    counters: dict = {}
    for row in latest_per_subject(rows):
        if row["epoch_id"] != epoch_id:      # pragma: no cover - defensive
            raise M.EpochMismatchError(
                f"row {row.get('label_id')!r} is epoch {row['epoch_id']!r} "
                f"but the aggregation is for {epoch_id!r}")
        key = (row["scenario_id"], row["conclusion_type"])
        cell = counters.setdefault(
            key, {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "analysts": set()})
        cell["analysts"].add(row["analyst_id"])
        counter = _COUNTER_FOR.get(row["label"])
        if counter is not None:
            cell[counter] += 1
    return tuple(
        M.ConfusionCell(scenario_id=scenario_id, conclusion_type=kind,
                        tp=values["tp"], fp=values["fp"], tn=values["tn"],
                        fn=values["fn"],
                        distinct_analysts=len(values["analysts"]),
                        epoch_id=epoch_id)
        for (scenario_id, kind), values in sorted(counters.items()))


def cells_for(store, *, stamp: EpochStamp,
              scenario_id: Optional[str] = None) -> tuple:
    """The stamp's window, read out of L1 as cells. One epoch, always."""
    if not isinstance(stamp, EpochStamp):
        raise DomainError(
            f"cells_for needs an EpochStamp, got {type(stamp).__name__}: "
            f"without one there is no record of which label population was "
            f"measured, which is F-16 exactly")
    rows = store.labels_in_epoch(
        epoch_id=stamp.epoch_id, since=stamp.since, until=stamp.until,
        exclude_auto=stamp.exclude_auto, scenario_id=scenario_id)
    return cells_from_rows(rows, epoch_id=stamp.epoch_id)


def evidence_for(store, *, stamp: EpochStamp,
                 scenario_id: Optional[str] = None,
                 drop_degenerate: bool = False) -> M.CalibrationEvidence:
    """The proposal family's only admissible input, built from L1.

    Goes through `CalibrationEvidence.from_cells`, which is the door that
    refuses degenerate cells. There is deliberately no path from rows to a
    proposal that skips it: `proposals.generate` takes evidence, not a
    cell list, so the 2026-05-29 blanket-TP shape cannot reach a proposal
    even if this function were called wrongly.
    """
    return M.CalibrationEvidence.from_cells(
        cells_for(store, stamp=stamp, scenario_id=scenario_id),
        stamp=stamp, drop_degenerate=drop_degenerate)


# ── the AST audit ───────────────────────────────────────────────────────
_PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CONSTRUCTION_HOME = "calibration/labels.py"


def audit_label_construction_sites(root: Optional[pathlib.Path] = None
                                   ) -> tuple:
    """Every module under `v3/` that constructs a `LabelRecord`.

    Must be exactly this one. `LabelRecord` enforces that the provenance
    fields are non-empty, not that they are declared — the declaration
    check is `LabelProvenance`'s, and it is only unavoidable while this
    module is the only builder. A second construction site is a second
    door into the label population, which is the mechanism, not the
    symptom, of all three incidents.
    """
    base = pathlib.Path(root) if root is not None else _PACKAGE_ROOT
    found: list = []
    for path in sorted(base.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and \
                    isinstance(node.func, ast.Name) and \
                    node.func.id == "LabelRecord":
                found.append(f"{path.relative_to(base.parent)}:{node.lineno}")
    return tuple(found)


def unexpected_construction_sites(root: Optional[pathlib.Path] = None
                                  ) -> tuple:
    return tuple(site for site in audit_label_construction_sites(root)
                 if _CONSTRUCTION_HOME not in site)


def counted_labels() -> Sequence[str]:
    return tuple(sorted(COUNTED_LABELS))


__all__ = ["SUBMIT_LABEL", "COUNTED_LABELS", "label_id_for", "record",
           "submit", "latest_per_subject", "cells_from_rows", "cells_for",
           "evidence_for", "audit_label_construction_sites",
           "unexpected_construction_sites", "counted_labels"]
