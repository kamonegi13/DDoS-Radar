"""The label ledger and the proposal queue — `LedgerStore`'s L4 half.

A third module on the store's base chain, for the 800-line house limit and
under the same rule the other two follow: `v3/api/store_source.py` resolves
`LedgerStore`'s bases from the source, so the methods here are audited by
`readonly.py` and `writeonly.py` exactly as if they had stayed in
`store.py`. A method hidden from that chain is a method both seams stop
checking WITHOUT failing, which is why the resolver raises on a base it
cannot follow.

Two tables, and neither of them holds a state that is edited:

    calibration_label     the v3 form of `analyst_feedback`. Append-only;
                          a relabel is a new row and the fold takes the
                          latest per (conclusion_id, analyst_id).
    calibration_proposal  the emitted proposal. Append-only; its state is
                          the fold of its adjudication commands in
                          `command_record`, not a column.

**The epoch is a query parameter, not a filter a caller may forget.**
`labels_in_epoch` requires an `epoch_id` and there is no method that
returns labels across epochs. That is the storage-level half of WP-3.2's
type-level rule: `CalibrationEvidence.from_cells` refuses cells whose
epoch disagrees with the stamp, and here the rows cannot be fetched
together in the first place. Two populations that cannot be loaded into
one list cannot be pooled by accident (F-16).
"""
from __future__ import annotations

import json
import time
from typing import Optional

from v3.kernel.errors import DomainError
from v3.ledger.records import LabelRecord, ProposalRecord


def _label_row(row) -> dict:
    record = dict(row)
    record["is_automated"] = bool(record["is_automated"])
    return record


def _proposal_row(row) -> dict:
    record = dict(row)
    for column in ("evidence_json", "payload_json"):
        record[column[:-5]] = json.loads(record.pop(column) or "{}")
    return record


class CalibrationLedgerMixin:
    """`LedgerStore`'s calibration half (WP-3.3)."""

    # ── labels ──────────────────────────────────────────────────────────
    def append_label(self, record: LabelRecord, *, now: Optional[float] = None,
                     connection=None) -> bool:
        """Record one label. True if it was stored, False if already present.

        `INSERT OR IGNORE` on `label_id`, then a content check — the same
        idempotence shape the observation tables use, and for the same
        reason: an ETL re-run must be a no-op, and a re-run that produced a
        DIFFERENT label under the same identity is a generator change that
        must be loud (S5-VERIF-032 makes that an epoch advance).
        """
        if not isinstance(record, LabelRecord):
            raise TypeError(
                f"append_label expects a LabelRecord, got "
                f"{type(record).__name__}: a kwargs bag would let a caller "
                f"omit the epoch, and an unstamped label cannot be compared "
                f"with any other (F-16)")
        stamped = time.time() if now is None else float(now)
        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO calibration_label "
                "(label_id, conclusion_id, scenario_id, conclusion_type, "
                " label, analyst_id, observed_at, labelled_at, recorded_at, "
                " generator_id, generator_version, rule_id, epoch_id, "
                " is_automated, observed_outcome_url, reason) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.label_id, record.conclusion_id, record.scenario_id,
                 record.conclusion_type, record.label, record.analyst_id,
                 record.observed_at, record.labelled_at, stamped,
                 record.generator_id, record.generator_version,
                 record.rule_id, record.epoch_id,
                 1 if record.is_automated else 0,
                 record.observed_outcome_url, record.reason))
            if cursor.rowcount > 0:
                return True
            stored = conn.execute(
                "SELECT label, epoch_id, analyst_id FROM calibration_label "
                "WHERE label_id = ?", (record.label_id,)).fetchone()
            existing = dict(stored) if stored else {}
            expected = {"label": record.label, "epoch_id": record.epoch_id,
                        "analyst_id": record.analyst_id}
            if existing != expected:
                raise DomainError(
                    f"label {record.label_id!r} already exists holding "
                    f"{existing}, and this write carries {expected}. Two "
                    f"different judgements under one identity is the "
                    f"contamination shape all three calibration incidents "
                    f"had; the fold cannot choose between them, so the "
                    f"write is refused rather than silently ignored.")
        return False

    def labels_in_epoch(self, *, epoch_id: str, since: float, until: float,
                        exclude_auto: bool = False,
                        scenario_id: Optional[str] = None,
                        conclusion_type: Optional[str] = None) -> list:
        """Labels of ONE epoch inside one window, oldest first.

        `epoch_id` is required and there is no cross-epoch reader. The
        window is closed at both ends and keyed on `observed_at` — the
        LABELLED conclusion's instant, not the moment the analyst typed —
        because S1-CALIB-026 measures a period of the tool's behaviour, and
        keying on the typing instant would move a label between windows
        whenever somebody caught up on a backlog.
        """
        if not isinstance(epoch_id, str) or not epoch_id.strip():
            raise DomainError(
                "labels_in_epoch needs an epoch_id: a read that spans "
                "epochs is a read that pools two label populations, which "
                "is F-16 at the storage layer")
        if until < since:
            raise DomainError(
                f"label window is inverted: since={since} until={until}")
        query = ["SELECT * FROM calibration_label WHERE epoch_id = ? "
                 "AND observed_at >= ? AND observed_at <= ?"]
        params: list = [epoch_id.strip(), float(since), float(until)]
        if exclude_auto:
            query.append(" AND is_automated = 0")
        for column, value in (("scenario_id", scenario_id),
                              ("conclusion_type", conclusion_type)):
            if value is not None:
                query.append(f" AND {column} = ?")
                params.append(value)
        query.append(" ORDER BY observed_at ASC, labelled_at ASC, id ASC")
        rows = self._read_connection().execute("".join(query),
                                               params).fetchall()
        return [_label_row(row) for row in rows]

    # ── FN drafts + the S9 run record (WP-0.4 v2 / ADR-V3-012) ──────────
    def append_fn_draft(self, draft, *, now: Optional[float] = None,
                        connection=None) -> bool:
        """Record one FN draft. True if stored, False if already present.

        Same idempotence shape as `append_label`: the S9 cycle re-scans a
        sliding window daily, and a re-run must converge on the same
        draft rather than doubling the pending count that widens the
        published recall interval.
        """
        stamped = time.time() if now is None else float(now)
        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO calibration_fn_draft "
                "(draft_id, created_at, scenario_id, conclusion_type, "
                " conclusion_id, label, reason, proposed_analyst_id, "
                " generator_id, generator_version, rule_id, epoch_id, "
                " observed_at, labelled_at, sources_json, evidence_url) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (draft.draft_id, stamped, draft.scenario_id,
                 draft.conclusion_type, draft.conclusion_id, draft.label,
                 draft.reason, draft.proposed_analyst_id,
                 draft.generator_id, draft.generator_version,
                 draft.rule_id, draft.epoch_id, draft.observed_at,
                 draft.labelled_at,
                 json.dumps(list(draft.sources)), draft.evidence_url))
            return cursor.rowcount > 0

    def fn_drafts(self, *, epoch_id: str,
                  scenario_id: Optional[str] = None) -> list:
        """Every stored FN draft of one epoch, oldest first."""
        if not isinstance(epoch_id, str) or not epoch_id.strip():
            raise DomainError("fn_drafts needs an epoch_id")
        query = ["SELECT * FROM calibration_fn_draft WHERE epoch_id = ?"]
        params: list = [epoch_id.strip()]
        if scenario_id is not None:
            query.append(" AND scenario_id = ?")
            params.append(scenario_id)
        query.append(" ORDER BY observed_at ASC, id ASC")
        rows = self._read_connection().execute("".join(query),
                                               params).fetchall()
        found = []
        for row in rows:
            record = dict(row)
            record["sources"] = json.loads(record.pop("sources_json") or "[]")
            found.append(record)
        return found

    def unlabelled_fn_drafts(self, *, epoch_id: str) -> list:
        """Drafts with no FALSE_NEGATIVE label on their conclusion yet.

        HALF of "pending": the other half is the adjudication fold (a
        REJECTED draft leaves no label but is nonetheless answered), and
        that lives in `v3/calibration/human.py::pending_draft_counts`,
        which is the ONE definition of pending. This method deliberately
        returns rows rather than counts so that the definition upstream
        can subtract per draft instead of guessing at aggregates.
        """
        if not isinstance(epoch_id, str) or not epoch_id.strip():
            raise DomainError("unlabelled_fn_drafts needs an epoch_id")
        rows = self._read_connection().execute(
            "SELECT d.* FROM calibration_fn_draft d WHERE d.epoch_id = ? "
            "AND NOT EXISTS (SELECT 1 FROM calibration_label l "
            "  WHERE l.conclusion_id = d.conclusion_id "
            "  AND l.label = 'FALSE_NEGATIVE' AND l.epoch_id = d.epoch_id) "
            "ORDER BY d.observed_at ASC, d.id ASC",
            (epoch_id.strip(),)).fetchall()
        found = []
        for row in rows:
            record = dict(row)
            record["sources"] = json.loads(record.pop("sources_json") or "[]")
            found.append(record)
        return found

    def append_s9_run(self, *, ran_at: float, window_start: float,
                      window_end: float, outcome: str, report: dict,
                      connection=None) -> None:
        """One S9 cycle's record — the persisted heartbeat (F-01) and the
        AP4 answer to 'what did the calibrator actually do that day'."""
        with self._maybe_transaction(connection) as conn:
            conn.execute(
                "INSERT INTO calibration_run "
                "(ran_at, window_start, window_end, outcome, report_json) "
                "VALUES (?,?,?,?,?)",
                (float(ran_at), float(window_start), float(window_end),
                 outcome, json.dumps(report, ensure_ascii=False)))

    def latest_s9_run_at(self) -> Optional[float]:
        row = self._read_connection().execute(
            "SELECT MAX(ran_at) AS newest FROM calibration_run").fetchone()
        value = row["newest"] if row else None
        return None if value is None else float(value)

    def labels_for_conclusion(self, conclusion_id: str) -> list:
        """Every label ever written on one conclusion, oldest first.

        Every one, including the superseded — the forensic half. All three
        calibration disasters were found by asking what a label used to
        say, which is a question production's UPDATE-in-place
        `analyst_feedback` cannot answer.
        """
        rows = self._read_connection().execute(
            "SELECT * FROM calibration_label WHERE conclusion_id = ? "
            "ORDER BY labelled_at ASC, id ASC", (conclusion_id,)).fetchall()
        return [_label_row(row) for row in rows]

    def count_labels(self, *, epoch_id: Optional[str] = None) -> int:
        if epoch_id is None:
            return int(self._read_connection().execute(
                "SELECT COUNT(*) FROM calibration_label").fetchone()[0])
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM calibration_label WHERE epoch_id = ?",
            (epoch_id,)).fetchone()[0])

    # ── proposals ───────────────────────────────────────────────────────
    def append_proposal(self, record: ProposalRecord, *,
                        now: Optional[float] = None, connection=None) -> bool:
        """Emit one proposal. True if stored, False if the id already exists.

        Re-emitting an identical proposal is a no-op rather than a second
        queue entry: `proposal_id` is derived from what the proposal IS
        (`v3.calibration.lifecycle.proposal_id_for`), so two runs of the
        same calibration pass over the same evidence converge instead of
        stacking. That is S1-CALIB-040's dedup exit, made structural — and
        it fails CLOSED, unlike production's, whose dedup query treats a
        database error as "no duplicate" (ACCIDENTAL A6, ADR-V3-006).
        """
        if not isinstance(record, ProposalRecord):
            raise TypeError(
                f"append_proposal expects a ProposalRecord, got "
                f"{type(record).__name__}")
        stamped = time.time() if now is None else float(now)
        with self._maybe_transaction(connection) as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO calibration_proposal "
                "(proposal_id, proposal_type, scenario_id, target_country, "
                " proposal_key, prior_value, proposed_value, direction, "
                " impact, sample_n, emitted_at, recorded_at, epoch_id, "
                " formula_ref, evidence_json, payload_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.proposal_id, record.proposal_type, record.scenario_id,
                 record.target_country, record.proposal_key,
                 record.prior_value, record.proposed_value, record.direction,
                 record.impact, record.sample_n, record.emitted_at, stamped,
                 record.epoch_id, record.formula_ref, record.evidence_json(),
                 record.payload_json()))
            if cursor.rowcount > 0:
                return True
            stored = conn.execute(
                "SELECT proposed_value, epoch_id FROM calibration_proposal "
                "WHERE proposal_id = ?", (record.proposal_id,)).fetchone()
            existing = dict(stored) if stored else {}
            expected = {"proposed_value": record.proposed_value,
                        "epoch_id": record.epoch_id}
            if existing != expected:
                raise DomainError(
                    f"proposal {record.proposal_id!r} already exists holding "
                    f"{existing}, and this emission carries {expected}. One "
                    f"identity cannot stand for two different changes: the "
                    f"adjudication commands point at the id, so the analyst "
                    f"would be approving whichever row was read last.")
        return False

    def proposal_by_id(self, proposal_id: str) -> Optional[dict]:
        row = self._read_connection().execute(
            "SELECT * FROM calibration_proposal WHERE proposal_id = ?",
            (proposal_id,)).fetchone()
        return _proposal_row(row) if row else None

    def proposals_between(self, start: float, end: float, *,
                          scenario_id: Optional[str] = None,
                          proposal_type: Optional[str] = None,
                          epoch_id: Optional[str] = None,
                          limit: Optional[int] = None) -> list:
        """Emitted proposals in a window, NEWEST first — the queue's order.

        Newest first because this is a work queue an analyst reads, not a
        fold: the folds in `v3/commands/state.py` need oldest-first and say
        so. Two orders in one codebase is a real hazard, so the two callers
        are named here rather than left to be inferred.
        """
        if end < start:
            raise DomainError(
                f"proposal window is inverted: start={start} end={end}")
        query = ["SELECT * FROM calibration_proposal "
                 "WHERE emitted_at >= ? AND emitted_at <= ?"]
        params: list = [float(start), float(end)]
        for column, value in (("scenario_id", scenario_id),
                              ("proposal_type", proposal_type),
                              ("epoch_id", epoch_id)):
            if value is not None:
                query.append(f" AND {column} = ?")
                params.append(value)
        query.append(" ORDER BY emitted_at DESC, id DESC")
        if limit is not None:
            query.append(" LIMIT ?")
            params.append(int(limit))
        rows = self._read_connection().execute("".join(query),
                                               params).fetchall()
        return [_proposal_row(row) for row in rows]

    def count_proposals(self) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) FROM calibration_proposal").fetchone()[0])


__all__ = ["CalibrationLedgerMixin"]
