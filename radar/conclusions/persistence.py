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
    """
    conn = db._get_conn()  # noqa: SLF001 — established internal pattern
    with conn.writing():
        conn.execute(_INSERT_SQL, c.to_db_row())


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
