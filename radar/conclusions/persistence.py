"""Conclusion persistence — append-only write/read to the v19 ledger.

ADR-V2-008: conclusions table is append-only. Updates happen by inserting a
new row with a fresh id; the latest row per (scenario_id, conclusion_type)
wins. We never UPDATE or DELETE rows here.

The module is deliberately a free-function shim rather than a method on
RadarDB to keep radar/database.py from continuing to grow. It uses the same
_get_conn / writing() pattern as every other persistence helper in the
project.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Optional

from radar import config
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
)

if TYPE_CHECKING:
    from radar.database import RadarDB


_INSERT_SQL = """
INSERT INTO conclusions (
    id, scenario_id, conclusion_type, state, confidence, observed_at,
    formula_ref, threshold_ref, source_urls, llm_prompt_sha256,
    calibration_status, conclusion_unavailable_reason, metadata
) VALUES (
    :id, :scenario_id, :conclusion_type, :state, :confidence, :observed_at,
    :formula_ref, :threshold_ref, :source_urls, :llm_prompt_sha256,
    :calibration_status, :conclusion_unavailable_reason, :metadata
)
"""


def save_conclusion(db: "RadarDB", c: Conclusion) -> None:
    """Append a Conclusion row to the ledger. No-op for invalid input is
    impossible — Conclusion's __post_init__ already enforced invariants.

    Side effect 2026-04-29 (ADR-V2-010 wiring): every save also feeds the
    inconclusive_continuity_log so we can detect chronic 'cannot conclude'
    runs > 7 days (which CLAUDE.md flags as a design failure). Failures
    are swallowed via the helper itself — observability must never break
    the ledger write (NP3).
    """
    conn = db._get_conn()  # noqa: SLF001 — established internal pattern
    with conn.writing():
        conn.execute(_INSERT_SQL, c.to_db_row())
    _record_continuity(db, c)


# ── change-gated writes (2026-07-04) ────────────────────────────────────────
#
# Production audit 2026-07-03: the per-tick append pattern wrote the SAME
# conclusion every ~2 minutes (one week of anomalies: 89,884 rows, 12
# distinct states), making the ledger a scoring-tick log rather than a
# conclusions ledger — 83% of a 1.7GB DB, and it forced a 90d retention
# that conflicts with AP4 replay depth. The gate writes only on state
# change, plus a heartbeat row per V2_CONCLUSION_HEARTBEAT_SEC (bounds
# replay staleness AND proves the pipeline was alive; a silent scoring
# outage is distinguishable from a long unchanged state).
#
# Two shapes:
#   * save_conclusion_gated       — SINGLE-VALUED types (threat_level,
#     trend, per_domain, attack_mode): compare against the latest row of
#     (scenario, type) — comparing per-state would break flap sequences
#     (A→B→A must write three rows or replay reads B forever).
#   * save_conclusions_batch_gated — MULTI-ROW set types (anomaly): the
#     tick's full state-set signature vs the previous batch; any set
#     change re-writes the whole batch so replay sees the complete active
#     set at one timestamp.
#
# Continuity tracking (_record_continuity) runs on EVERY tick regardless
# of gating — chronic-inconclusive detection needs the per-tick
# observation stream, not the deduplicated ledger.


def _write_on_change_enabled() -> bool:
    return bool(getattr(config, "V2_CONCLUSION_WRITE_ON_CHANGE", True))


def _heartbeat_sec() -> float:
    return float(getattr(config, "V2_CONCLUSION_HEARTBEAT_SEC", 3600))


def save_conclusion_gated(db: "RadarDB", c: Conclusion) -> bool:
    """Change-gated append for single-valued conclusion types. Returns
    True when a row was written, False when the write was deduplicated."""
    if not _write_on_change_enabled():
        save_conclusion(db, c)
        return True
    latest = latest_conclusion(db, c.scenario_id, c.conclusion_type)
    unchanged = (
        latest is not None
        and latest.state == c.state
        and latest.conclusion_unavailable_reason
            == c.conclusion_unavailable_reason
        and (c.observed_at - latest.observed_at) < _heartbeat_sec()
    )
    if unchanged:
        _record_continuity(db, c)
        return False
    save_conclusion(db, c)
    return True


def _batch_signature(rows) -> list[tuple[str, str]]:
    return sorted(rows)


def save_conclusions_batch_gated(
    db: "RadarDB", conclusions: list[Conclusion],
) -> int:
    """Set-signature-gated append for multi-row types (anomaly). All
    conclusions must share (scenario_id, conclusion_type, observed_at).
    Returns the number of rows written (0 when deduplicated)."""
    cs = list(conclusions)
    if not cs:
        return 0
    if not _write_on_change_enabled():
        for c in cs:
            save_conclusion(db, c)
        return len(cs)

    scenario_id = cs[0].scenario_id
    ctype = cs[0].conclusion_type
    sig = _batch_signature([
        (
            c.state or "",
            c.conclusion_unavailable_reason.value
            if c.conclusion_unavailable_reason is not None else "",
        )
        for c in cs
    ])
    rows = db._get_conn().execute(  # noqa: SLF001
        "SELECT state, conclusion_unavailable_reason, observed_at "
        "FROM conclusions "
        "WHERE scenario_id = ? AND conclusion_type = ? "
        "AND observed_at = ("
        "    SELECT MAX(observed_at) FROM conclusions "
        "    WHERE scenario_id = ? AND conclusion_type = ?"
        ")",
        (scenario_id, ctype.value, scenario_id, ctype.value),
    ).fetchall()
    prev_sig = _batch_signature([
        (str(r["state"] or ""), str(r["conclusion_unavailable_reason"] or ""))
        for r in rows
    ])
    unchanged = (
        bool(rows)
        and prev_sig == sig
        and (cs[0].observed_at - float(rows[0]["observed_at"]))
            < _heartbeat_sec()
    )
    if unchanged:
        for c in cs:
            _record_continuity(db, c)
        return 0
    for c in cs:
        save_conclusion(db, c)
    return len(cs)


def _record_continuity(db: "RadarDB", c: Conclusion) -> None:
    """Maintain inconclusive_continuity_log per (scenario_id, conclusion_type).

    Two events:
      * The conclusion is unavailable (state=='INSUFFICIENT_DATA' or has a
        conclusion_unavailable_reason set): if no open run exists, open one;
        if an open run exists, extend its run_length_sec.
      * The conclusion IS available: if an open run exists, close it
        (set is_available=1, finalize run_length_sec).

    The 7-day chronic-failure detection (per CLAUDE.md) is a downstream
    query against this table — this function only records the data.
    """
    try:
        is_unavailable = (
            c.state == "INSUFFICIENT_DATA"
            or c.conclusion_unavailable_reason is not None
        )
        conn = db._get_conn()  # noqa: SLF001
        # Find the most recent OPEN row for this (scenario, type).
        row = conn.execute(
            "SELECT id, observed_at, first_seen_at, is_available "
            "FROM inconclusive_continuity_log "
            "WHERE scenario_id=? AND conclusion_type=? "
            "ORDER BY observed_at DESC LIMIT 1",
            (c.scenario_id, c.conclusion_type.value),
        ).fetchone()

        with conn.writing():
            if is_unavailable:
                reason = (
                    c.conclusion_unavailable_reason.value
                    if c.conclusion_unavailable_reason is not None
                    else "INSUFFICIENT_DATA"
                )
                if row is None or row["is_available"] == 1:
                    # Open a new run — either nothing exists yet, or the
                    # last entry was 'available' and this is a new failure.
                    conn.execute(
                        "INSERT INTO inconclusive_continuity_log "
                        "(observed_at, scenario_id, conclusion_type, "
                        " is_available, reason, run_length_sec, "
                        " first_seen_at, metadata) "
                        "VALUES (?, ?, ?, 0, ?, 0, ?, ?)",
                        (c.observed_at, c.scenario_id,
                         c.conclusion_type.value, reason,
                         c.observed_at, "{}"),
                    )
                else:
                    # Extend the existing open run.
                    first_seen = row["first_seen_at"]
                    run_length = max(0.0, c.observed_at - first_seen)
                    conn.execute(
                        "INSERT INTO inconclusive_continuity_log "
                        "(observed_at, scenario_id, conclusion_type, "
                        " is_available, reason, run_length_sec, "
                        " first_seen_at, metadata) "
                        "VALUES (?, ?, ?, 0, ?, ?, ?, ?)",
                        (c.observed_at, c.scenario_id,
                         c.conclusion_type.value, reason, run_length,
                         first_seen, "{}"),
                    )
            else:
                # Conclusion IS available. Only record a closing row if an
                # open run is currently active (i.e. the previous state was
                # unavailable).
                if row is not None and row["is_available"] == 0:
                    first_seen = row["first_seen_at"]
                    run_length = max(0.0, c.observed_at - first_seen)
                    conn.execute(
                        "INSERT INTO inconclusive_continuity_log "
                        "(observed_at, scenario_id, conclusion_type, "
                        " is_available, reason, run_length_sec, "
                        " first_seen_at, metadata) "
                        "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                        (c.observed_at, c.scenario_id,
                         c.conclusion_type.value, "resolved", run_length,
                         first_seen, "{}"),
                    )
                # If row is None or already available, no record needed —
                # the table tracks transitions, not steady-states.
    except Exception as exc:
        # Observability must never break the main flow.
        import logging
        logging.getLogger("radar.continuity").debug(
            "continuity log write failed: %s", exc
        )


_SELECT_COLS = (
    "id, scenario_id, conclusion_type, state, confidence, "
    "observed_at, formula_ref, threshold_ref, source_urls, "
    "llm_prompt_sha256, calibration_status, "
    "conclusion_unavailable_reason, metadata"
)


def latest_conclusion(
    db: "RadarDB",
    scenario_id: str,
    conclusion_type: ConclusionType,
) -> Optional[Conclusion]:
    """Most recent conclusion for (scenario, type), or None if the ledger
    has no row yet. Used by API readers and round-trip tests.
    """
    row = db._get_conn().execute(  # noqa: SLF001
        f"SELECT {_SELECT_COLS} FROM conclusions "
        "WHERE scenario_id = ? AND conclusion_type = ? "
        "ORDER BY observed_at DESC LIMIT 1",
        (scenario_id, conclusion_type.value),
    ).fetchone()
    if row is None:
        return None
    return _row_to_conclusion(row)


def get_conclusion_by_id(db: "RadarDB", conclusion_id: str) -> Optional[Conclusion]:
    """Fetch a single conclusion row by primary key. Returns None if absent.
    Used by `/api/v2/conclusions/<id>` and the audit-trace endpoint.
    """
    row = db._get_conn().execute(  # noqa: SLF001
        f"SELECT {_SELECT_COLS} FROM conclusions WHERE id = ?",
        (conclusion_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_conclusion(row)


def _row_to_conclusion(row) -> Conclusion:
    """Reconstruct a Conclusion from a sqlite3.Row, reversing to_db_row().

    final_judgment_disclaimer is a tool-level constant (NP7) injected from
    config rather than stored per-row, so historical rows always reflect
    the currently configured wording.
    """
    unavailable = row["conclusion_unavailable_reason"]
    return Conclusion(
        id=row["id"],
        scenario_id=row["scenario_id"],
        conclusion_type=ConclusionType(row["conclusion_type"]),
        state=row["state"],
        confidence=row["confidence"],
        observed_at=row["observed_at"],
        formula_ref=row["formula_ref"],
        threshold_ref=json.loads(row["threshold_ref"]),
        source_urls=tuple(json.loads(row["source_urls"])),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        llm_prompt_sha256=row["llm_prompt_sha256"],
        calibration_status=json.loads(row["calibration_status"]),
        conclusion_unavailable_reason=(
            ConclusionUnavailableReason(unavailable) if unavailable else None
        ),
        metadata=json.loads(row["metadata"]),
    )
