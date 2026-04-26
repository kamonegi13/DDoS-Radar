"""Analyst feedback ledger — ADR-V2-011.

Persists ground-truth labels (TRUE_POSITIVE / FALSE_POSITIVE / TRUE_NEGATIVE
/ FALSE_NEGATIVE) submitted by analysts against specific conclusion rows.
Aggregation happens on read so the raw ledger remains the single source of
truth — an analyst can revise a label by inserting a newer row without
losing history.

Schema lives in DB migration v26 (radar/database.py).

NP4/NP5+8 link: per ADR-V2-011 these labels feed Design W (ADR-026)
recall calibration and attack-mode estimator validation. v2-migration.md
§11 anti-bias note ("複数アナリスト集計" を表示) is enforced on the read
path: `summarize_feedback()` returns counts, not a single verdict.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from radar.database import RadarDB


class FeedbackLabel(str, Enum):
    """Four-way confusion-matrix labels per ADR-V2-011."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    TRUE_NEGATIVE = "TRUE_NEGATIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"


@dataclass(frozen=True)
class AnalystFeedback:
    """One analyst label against one conclusion. Frozen — revisions go in
    as a new row, not a mutation of an existing row.
    """

    conclusion_id: str
    label: FeedbackLabel
    analyst_id: str
    observed_at: float
    observed_outcome_url: Optional[str] = None
    notes: Optional[str] = None
    id: Optional[int] = None  # Set after INSERT; None on construction.


_INSERT_SQL = """
INSERT INTO analyst_feedback (
    conclusion_id, label, observed_outcome_url,
    analyst_id, observed_at, notes
) VALUES (?, ?, ?, ?, ?, ?)
"""


def save_feedback(db: "RadarDB", fb: AnalystFeedback) -> int:
    """Append a feedback row. Returns the new rowid for callers that need
    to confirm-and-fetch. Caller is responsible for verifying that
    `fb.conclusion_id` exists — the FK does it at write time.
    """
    conn = db._get_conn()  # noqa: SLF001 — established internal pattern
    with conn.writing():
        cur = conn.execute(_INSERT_SQL, (
            fb.conclusion_id,
            fb.label.value,
            fb.observed_outcome_url,
            fb.analyst_id,
            fb.observed_at,
            fb.notes,
        ))
        return int(cur.lastrowid)


_SELECT_COLS = (
    "id, conclusion_id, label, observed_outcome_url, "
    "analyst_id, observed_at, notes"
)


def list_feedback(
    db: "RadarDB", conclusion_id: str, *, limit: int = 100,
) -> list[AnalystFeedback]:
    """Return all feedback rows for a conclusion, newest first.

    Capped at `limit` so a runaway labeling spree on one row can't blow
    up the response. The drill-down UI shows at most ~10; 100 is generous.
    """
    rows = db._get_conn().execute(  # noqa: SLF001
        f"SELECT {_SELECT_COLS} FROM analyst_feedback "
        "WHERE conclusion_id = ? ORDER BY observed_at DESC LIMIT ?",
        (conclusion_id, max(1, min(limit, 1000))),
    ).fetchall()
    return [_row_to_feedback(r) for r in rows]


def summarize_feedback(db: "RadarDB", conclusion_id: str) -> dict:
    """Aggregate counts per label + distinct-analyst count.

    Surfaces "how many analysts agree on what" instead of a single verdict
    so the UI can render the multi-analyst view called for in v2-migration
    §11 (analyst feedback bias mitigation). Returns zero-counts for all
    four labels even when the table is empty so the consumer never has to
    guard for missing keys.
    """
    rows = db._get_conn().execute(  # noqa: SLF001
        "SELECT label, COUNT(*) AS n, COUNT(DISTINCT analyst_id) AS distinct_analysts "
        "FROM analyst_feedback WHERE conclusion_id = ? GROUP BY label",
        (conclusion_id,),
    ).fetchall()
    counts = {label.value: 0 for label in FeedbackLabel}
    distinct_total = set()
    for r in rows:
        counts[r["label"]] = int(r["n"])
    distinct_row = db._get_conn().execute(  # noqa: SLF001
        "SELECT COUNT(DISTINCT analyst_id) AS n FROM analyst_feedback "
        "WHERE conclusion_id = ?",
        (conclusion_id,),
    ).fetchone()
    distinct = int(distinct_row["n"]) if distinct_row else 0
    total = sum(counts.values())
    return {
        "conclusion_id": conclusion_id,
        "total": total,
        "distinct_analysts": distinct,
        "label_counts": counts,
    }


def _row_to_feedback(row) -> AnalystFeedback:
    return AnalystFeedback(
        id=row["id"],
        conclusion_id=row["conclusion_id"],
        label=FeedbackLabel(row["label"]),
        observed_outcome_url=row["observed_outcome_url"],
        analyst_id=row["analyst_id"],
        observed_at=row["observed_at"],
        notes=row["notes"],
    )


def coerce_label(raw: str) -> Optional[FeedbackLabel]:
    """Parse a string into FeedbackLabel; return None on miss. Used at
    the API boundary so endpoints can return a structured 400."""
    if not isinstance(raw, str):
        return None
    try:
        return FeedbackLabel(raw.strip())
    except ValueError:
        return None


def now_seconds() -> float:
    """Indirection for tests to monkeypatch time without touching `time.time`
    at the global level (other modules also patch it)."""
    return time.time()
