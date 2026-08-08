"""The S8 attention ledger — `LedgerStore`'s AP1 half (WP-4.1f).

A fourth module on the store's base chain, for the 800-line house limit
and under the same rule the others follow: `v3/api/store_source.py`
resolves `LedgerStore`'s bases from the source, so the methods here are
audited by `readonly.py` and `writeonly.py` exactly as if they had stayed
in `store.py`.

One table, and the reason it exists is a defect:

    attention_rank   the order the tool put its own findings in, and the
                     three factors that produced that order.

G-03's finding was that `attention_score` lived ONLY in `triage_score.js`.
The rank an analyst acted on was computed in a browser, from a
`localStorage` timestamp no server could see, and vanished on the next
poll — so AP4 could replay every automated judgement except the one that
decided what the analyst looked at FIRST. P5 O-8 ruled the ranking into
the backend and required it to land in a ledger; this is that ledger.

**A snapshot is written whole or not at all.** `append_snapshot` takes the
ordered rows and writes them in one transaction, because a half-written
snapshot is a ranking with holes in it, and a ranking with holes is worse
than none: the missing row is indistinguishable from a row that scored
below the floor.
"""
from __future__ import annotations

import json
import time
from typing import Optional, Sequence

from v3.kernel.errors import DomainError
from v3.ledger.records import AttentionRankRecord


def _rank_row(row) -> dict:
    record = dict(row)
    record["components"] = json.loads(record.pop("components_json") or "{}")
    return record


class AttentionLedgerMixin:
    """`LedgerStore`'s attention half (WP-4.1f)."""

    def append_attention_snapshot(self, records: Sequence[AttentionRankRecord],
                                  *, now: Optional[float] = None,
                                  connection=None) -> int:
        """Write one whole snapshot. Returns the number of rows stored.

        Refuses a batch that is not one snapshot, and refuses one whose
        ranks are not 1..n without gaps or repeats. Both refusals are about
        the same property: the stored rank is what the analyst was shown,
        and a snapshot whose ranks skip 3 cannot be told apart from one
        where row 3 failed to write.

        Idempotent per `(snapshot_id, item_kind, item_id)` like every other
        append here, so re-running a tick is a no-op rather than a second
        snapshot under the same id.
        """
        rows = tuple(records)
        if not rows:
            raise DomainError(
                "append_attention_snapshot needs at least one row: an empty "
                "snapshot and no snapshot are different facts, and writing "
                "the first as the second is how 'nothing needed attention' "
                "comes to look like 'the ranker never ran'")
        for record in rows:
            if not isinstance(record, AttentionRankRecord):
                raise DomainError(
                    f"append_attention_snapshot takes AttentionRankRecords, "
                    f"got {type(record).__name__}")
        snapshot_ids = {record.snapshot_id for record in rows}
        if len(snapshot_ids) != 1:
            raise DomainError(
                f"one call writes one snapshot, got {sorted(snapshot_ids)}: "
                f"two snapshots in one transaction share a commit, so a "
                f"reader bounding at an instant would see half of each")
        instants = {record.computed_at for record in rows}
        if len(instants) != 1:
            raise DomainError(
                f"a snapshot is computed at ONE instant, got "
                f"{sorted(instants)}: `?at=` bounds on this column, and rows "
                f"of one ranking that answer different bounds are not one "
                f"ranking")
        positions = sorted(record.rank_position for record in rows)
        if positions != list(range(1, len(rows) + 1)):
            raise DomainError(
                f"a snapshot's ranks must be 1..{len(rows)} exactly, got "
                f"{positions}: a gap is indistinguishable from a row that "
                f"failed to write, and a repeat makes 'rank 2' ambiguous")
        stamped = time.time() if now is None else float(now)
        stored = 0
        with self._maybe_transaction(connection) as conn:
            for record in rows:
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO attention_rank "
                    "(snapshot_id, computed_at, recorded_at, scenario_id, "
                    " item_kind, item_id, rank_position, score, novelty, "
                    " confidence_delta, analyst_blindness, formula_ref, "
                    " narrative_template_ref, narrative, components_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (record.snapshot_id, record.computed_at, stamped,
                     record.scenario_id, record.item_kind, record.item_id,
                     record.rank_position, record.score, record.novelty,
                     record.confidence_delta, record.analyst_blindness,
                     record.formula_ref, record.narrative_template_ref,
                     record.narrative, record.components_json()))
                stored += 1 if cursor.rowcount > 0 else 0
        return stored

    def latest_attention_snapshot_id(self, at_ts: float) -> Optional[str]:
        """The id of the newest snapshot computed at or before `at_ts`.

        Separate from reading the rows so that "which snapshot answers this
        instant" is one decision made once. Live and `?at=` differ only in
        what is passed here (P7 derivation principle 4).
        """
        row = self._read_connection().execute(
            "SELECT snapshot_id FROM attention_rank "
            "WHERE computed_at <= ? ORDER BY computed_at DESC, id DESC "
            "LIMIT 1", (float(at_ts),)).fetchone()
        return None if row is None else str(row["snapshot_id"])

    def attention_snapshot(self, snapshot_id: str) -> list:
        """One snapshot's rows, in rank order."""
        rows = self._read_connection().execute(
            "SELECT * FROM attention_rank WHERE snapshot_id = ? "
            "ORDER BY rank_position ASC", (str(snapshot_id),)).fetchall()
        return [_rank_row(row) for row in rows]

    def attention_ranks_for_item(self, *, item_kind: str, item_id: str,
                                 until: Optional[float] = None,
                                 limit: Optional[int] = None) -> list:
        """One item's rank history, newest first (R9's `?type=attention`).

        The question this answers is "how long has the tool been asking me
        to look at this, and at what rank" — which is the question an
        analyst asks after an incident, and the one production could not
        answer at all because the rank was never stored.
        """
        query = ["SELECT * FROM attention_rank "
                 "WHERE item_kind = ? AND item_id = ?"]
        params: list = [str(item_kind), str(item_id)]
        if until is not None:
            query.append(" AND computed_at <= ?")
            params.append(float(until))
        query.append(" ORDER BY computed_at DESC, id DESC")
        if limit is not None:
            query.append(" LIMIT ?")
            params.append(int(limit))
        rows = self._read_connection().execute("".join(query),
                                               params).fetchall()
        return [_rank_row(row) for row in rows]

    def count_attention_ranks(self) -> int:
        return int(self._read_connection().execute(
            "SELECT COUNT(*) AS n FROM attention_rank").fetchone()["n"])


__all__ = ["AttentionLedgerMixin"]
