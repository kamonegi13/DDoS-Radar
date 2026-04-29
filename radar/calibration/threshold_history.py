"""Append-only ledger of every threshold value that has ever been in force.

Phase A foundation. Every auto-tune writes a new row; conclusions look up
the value that was active at their `observed_at` time, not the current
live one. This makes auto-tuning NP6-compliant: drill-down on any
conclusion always shows the threshold that produced it.

Schema (radar/database.py migration v28):

    threshold_history (
        id, emitted_at, key, value (str-encoded JSON),
        scope_scenario_id, effective_from, effective_to,
        derived_from, applied_by, revertible_to_id, sample_n,
        formula_ref, evidence_json, magnitude_pct,
        state ('active'|'reverted'|'superseded')
    )

Read path: `value_at(key, scope_scenario_id, ts)` returns the row whose
`[effective_from, effective_to)` window contains `ts`. If no row
matches (key has never been auto-tuned), returns None — caller falls
back to the env-default.

Write path: `record_change(...)` is the only entry point. It is called
exclusively by the governor (auto_tune_governor.py) so that
bounded-magnitude / cooldown rules cannot be bypassed by a misbehaving
calibrator.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from radar.database import db

log = logging.getLogger("radar.calibration.threshold_history")


@dataclass(frozen=True)
class ThresholdRecord:
    """In-memory representation of a row from `threshold_history`."""
    id: int
    emitted_at: float
    key: str
    value: Any  # decoded JSON (could be float, dict, list)
    scope_scenario_id: Optional[str]
    effective_from: float
    effective_to: Optional[float]
    derived_from: str
    applied_by: str
    revertible_to_id: Optional[int]
    sample_n: int
    formula_ref: str
    evidence: dict
    magnitude_pct: float
    state: str


def _row_to_record(row) -> ThresholdRecord:
    return ThresholdRecord(
        id=row[0],
        emitted_at=row[1],
        key=row[2],
        value=json.loads(row[3]),
        scope_scenario_id=row[4],
        effective_from=row[5],
        effective_to=row[6],
        derived_from=row[7],
        applied_by=row[8],
        revertible_to_id=row[9],
        sample_n=row[10],
        formula_ref=row[11],
        evidence=json.loads(row[12] or "{}"),
        magnitude_pct=row[13],
        state=row[14],
    )


_COLS = (
    "id, emitted_at, key, value, scope_scenario_id, effective_from, "
    "effective_to, derived_from, applied_by, revertible_to_id, sample_n, "
    "formula_ref, evidence_json, magnitude_pct, state"
)


def value_at(
    key: str,
    *,
    scope_scenario_id: Optional[str] = None,
    ts: Optional[float] = None,
) -> Optional[ThresholdRecord]:
    """Return the threshold row in force for ``key`` at ``ts``.

    Resolution order:
      1. scope_scenario_id-specific row whose [effective_from, effective_to)
         brackets ts (state='active')
      2. global (scope_scenario_id IS NULL) row, same window
      3. None — caller should fall back to env-default

    ``ts`` defaults to "now". This is critical: a conclusion built for
    observed_at=T1 must pass ts=T1, not now, so the dereferencer returns
    the threshold that was in force when the conclusion fired.
    """
    if ts is None:
        ts = time.time()
    conn = db._get_conn()  # noqa: SLF001
    # Try scenario-scoped first.
    # Note: state filter intentionally omitted — `value_at` answers
    # "what was in force at ts", which can be a row that's now
    # superseded. Reverted rows are also a legitimate historical
    # answer for their effective window. The state filter belongs in
    # `latest()` (which asks "what is in force now").
    if scope_scenario_id:
        row = conn.execute(
            f"SELECT {_COLS} FROM threshold_history "
            "WHERE key=? AND scope_scenario_id=? "
            "AND effective_from <= ? "
            "AND (effective_to IS NULL OR effective_to > ?) "
            "ORDER BY effective_from DESC LIMIT 1",
            (key, scope_scenario_id, ts, ts),
        ).fetchone()
        if row:
            return _row_to_record(row)
    row = conn.execute(
        f"SELECT {_COLS} FROM threshold_history "
        "WHERE key=? AND scope_scenario_id IS NULL "
        "AND effective_from <= ? "
        "AND (effective_to IS NULL OR effective_to > ?) "
        "ORDER BY effective_from DESC LIMIT 1",
        (key, ts, ts),
    ).fetchone()
    if row:
        return _row_to_record(row)
    return None


def latest(
    key: str,
    *,
    scope_scenario_id: Optional[str] = None,
) -> Optional[ThresholdRecord]:
    """Latest active row for (key, scope) regardless of effective_from
    relationship to now. Used by the governor to compute next-step
    delta and check cooldowns.
    """
    conn = db._get_conn()  # noqa: SLF001
    if scope_scenario_id:
        row = conn.execute(
            f"SELECT {_COLS} FROM threshold_history "
            "WHERE key=? AND scope_scenario_id=? AND state='active' "
            "ORDER BY effective_from DESC LIMIT 1",
            (key, scope_scenario_id),
        ).fetchone()
        if row:
            return _row_to_record(row)
    row = conn.execute(
        f"SELECT {_COLS} FROM threshold_history "
        "WHERE key=? AND scope_scenario_id IS NULL AND state='active' "
        "ORDER BY effective_from DESC LIMIT 1",
        (key, ),
    ).fetchone()
    return _row_to_record(row) if row else None


def record_change(
    *,
    key: str,
    value: Any,
    scope_scenario_id: Optional[str],
    derived_from: str,
    applied_by: str,
    sample_n: int,
    formula_ref: str,
    evidence: Optional[dict] = None,
    magnitude_pct: float = 0.0,
    revertible_to_id: Optional[int] = None,
    effective_from: Optional[float] = None,
) -> int:
    """Append a new threshold change to the ledger.

    INTERNAL: only auto_tune_governor.commit() should call this. Direct
    callers bypass bounded-magnitude / cooldown rules.

    Side effect: any prior 'active' row for the same (key, scope_scenario_id)
    has its effective_to set to this row's effective_from and its state
    flipped to 'superseded'. A reverted row keeps state='reverted'.

    Returns the new row's id.
    """
    if effective_from is None:
        effective_from = time.time()
    value_str = json.dumps(value, sort_keys=True)
    evidence_str = json.dumps(evidence or {}, sort_keys=True)
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        # Close prior active row.
        if scope_scenario_id is None:
            conn.execute(
                "UPDATE threshold_history SET effective_to=?, state='superseded' "
                "WHERE key=? AND scope_scenario_id IS NULL AND state='active'",
                (effective_from, key),
            )
        else:
            conn.execute(
                "UPDATE threshold_history SET effective_to=?, state='superseded' "
                "WHERE key=? AND scope_scenario_id=? AND state='active'",
                (effective_from, key, scope_scenario_id),
            )
        cur = conn.execute(
            "INSERT INTO threshold_history "
            "(emitted_at, key, value, scope_scenario_id, effective_from, "
            " effective_to, derived_from, applied_by, revertible_to_id, "
            " sample_n, formula_ref, evidence_json, magnitude_pct, state) "
            "VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, 'active')",
            (time.time(), key, value_str, scope_scenario_id, effective_from,
             derived_from, applied_by, revertible_to_id, int(sample_n),
             formula_ref, evidence_str, float(magnitude_pct)),
        )
        new_id = cur.lastrowid
    log.info(
        "[threshold_history] %s scope=%s applied_by=%s formula=%s "
        "magnitude=%.2f%% sample_n=%d row_id=%d",
        key, scope_scenario_id or "GLOBAL", applied_by, formula_ref,
        magnitude_pct, sample_n, new_id,
    )
    return new_id


def revert(row_id: int, *, reverted_by: str) -> Optional[int]:
    """Mark a row as reverted and create a new 'active' row carrying the
    pre-change value (read from row.revertible_to_id). Returns the new row id.

    Returns None if the row cannot be reverted (no revertible_to_id, or
    already non-active).
    """
    conn = db._get_conn()  # noqa: SLF001
    row = conn.execute(
        f"SELECT {_COLS} FROM threshold_history WHERE id=?", (row_id,),
    ).fetchone()
    if not row:
        log.warning("revert: row id=%d not found", row_id)
        return None
    rec = _row_to_record(row)
    if rec.state != "active":
        log.warning("revert: row id=%d state=%s, not revertible", row_id, rec.state)
        return None
    if rec.revertible_to_id is None:
        log.warning("revert: row id=%d has no revertible_to_id", row_id)
        return None
    prior = conn.execute(
        f"SELECT {_COLS} FROM threshold_history WHERE id=?",
        (rec.revertible_to_id,),
    ).fetchone()
    if not prior:
        log.warning("revert: prior row id=%d not found", rec.revertible_to_id)
        return None
    prior_rec = _row_to_record(prior)
    with conn.writing():
        conn.execute(
            "UPDATE threshold_history SET state='reverted' WHERE id=?",
            (row_id,),
        )
    return record_change(
        key=rec.key,
        value=prior_rec.value,
        scope_scenario_id=rec.scope_scenario_id,
        derived_from=f"revert_of:{row_id}",
        applied_by=reverted_by,
        sample_n=0,
        formula_ref="threshold_history#revert",
        evidence={"reverted_row_id": row_id, "restored_from_row_id": rec.revertible_to_id},
        magnitude_pct=0.0,
        revertible_to_id=row_id,
    )


def get_by_id(row_id: int) -> Optional[ThresholdRecord]:
    """Fetch a single row by primary key. Returns None if not found.

    Used by the calibration_v2 API to serve `/threshold_history/<id>`.
    Read-only; no NP6 implications.
    """
    try:
        conn = db._get_conn()  # noqa: SLF001
        row = conn.execute(
            f"SELECT {_COLS} FROM threshold_history WHERE id=?", (row_id,),
        ).fetchone()
    except Exception as exc:
        log.debug("get_by_id %d failed: %s", row_id, exc)
        return None
    return _row_to_record(row) if row else None


def list_recent(
    *,
    hours: int = 168,
    scope_scenario_id: Optional[str] = None,
) -> list[ThresholdRecord]:
    """Return rows emitted in the last `hours`. Used by the AP3 reliability
    scoreboard and for proposal-fatigue dedup checks."""
    conn = db._get_conn()  # noqa: SLF001
    cutoff = time.time() - hours * 3600
    if scope_scenario_id:
        rows = conn.execute(
            f"SELECT {_COLS} FROM threshold_history "
            "WHERE emitted_at >= ? AND scope_scenario_id=? "
            "ORDER BY emitted_at DESC",
            (cutoff, scope_scenario_id),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT {_COLS} FROM threshold_history "
            "WHERE emitted_at >= ? ORDER BY emitted_at DESC",
            (cutoff,),
        ).fetchall()
    return [_row_to_record(r) for r in rows]


__all__ = [
    "ThresholdRecord",
    "value_at",
    "latest",
    "record_change",
    "revert",
    "list_recent",
    "get_by_id",
]
