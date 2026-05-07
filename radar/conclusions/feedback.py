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


# ── B1: cross-conclusion read surfaces ───────────────────────────────────────
#
# The original B1 audit (2026-05-05) flagged that analyst_feedback
# accumulates via the existing POST endpoint, but no UI exposes it
# globally — only per-conclusion drill-down via `list_feedback`.
# These helpers serve the SETTINGS audit.feedback page (read-only)
# and any other cross-conclusion consumer that wants the rolled-up
# confusion matrix or recent-activity view.

def list_recent_feedback(
    db: "RadarDB",
    *,
    hours: float = 720.0,
    analyst_kind: Optional[str] = None,
    label: Optional[FeedbackLabel] = None,
    limit: int = 200,
) -> list[dict]:
    """Return recent analyst_feedback rows joined with the parent
    conclusion's `conclusion_type` and `scenario_id` so the SETTINGS
    table can show provenance without N+1 lookups.

    Args:
      hours: lookback window. Default 30 days; max 1 year.
      analyst_kind: ``"human"`` filters to analyst_id NOT LIKE 'auto:%';
                    ``"auto"`` filters to analyst_id LIKE 'auto:%';
                    None returns both.
      label: optional FeedbackLabel filter (TP/FP/TN/FN).
      limit: row cap, clamped to [1, 2000].
    """
    import time as _time
    cutoff = _time.time() - max(0.0, float(hours)) * 3600.0
    where = ["af.observed_at >= ?"]
    params: list = [cutoff]
    if analyst_kind == "human":
        where.append("af.analyst_id NOT LIKE 'auto:%'")
    elif analyst_kind == "auto":
        where.append("af.analyst_id LIKE 'auto:%'")
    if label is not None:
        where.append("af.label = ?")
        params.append(label.value)
    params.append(max(1, min(int(limit), 2000)))
    sql = (
        "SELECT af.id, af.conclusion_id, af.label, af.analyst_id, "
        "       af.observed_at, af.notes, af.observed_outcome_url, "
        "       c.conclusion_type, c.scenario_id "
        "FROM analyst_feedback af "
        "LEFT JOIN conclusions c ON c.id = af.conclusion_id "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY af.observed_at DESC LIMIT ?"
    )
    rows = db._get_conn().execute(sql, tuple(params)).fetchall()  # noqa: SLF001
    return [
        {
            "id": r["id"],
            "conclusion_id": r["conclusion_id"],
            "label": r["label"],
            "analyst_id": r["analyst_id"],
            "observed_at": r["observed_at"],
            "notes": r["notes"],
            "observed_outcome_url": r["observed_outcome_url"],
            "conclusion_type": r["conclusion_type"],
            "scenario_id": r["scenario_id"],
        }
        for r in rows
    ]


def aggregate_feedback_matrix(
    db: "RadarDB",
    *,
    hours: float = 720.0,
    analyst_kind: Optional[str] = None,
) -> dict:
    """Cross-conclusion confusion-matrix rollup. Used by the SETTINGS
    audit.feedback page header so an analyst can see "how am I /
    is the system labelling" at a glance.

    Returns:
      {
        "window_hours":         float,
        "total":                int,
        "human_total":          int,
        "auto_total":           int,
        "distinct_analysts":    int,
        "by_label":             {TP/FP/TN/FN: int},
        "by_conclusion_type":   {ct: {label: count, ...}, ...},
        "recall":               float | None,
        "precision":            float | None,
      }

    recall = TP / (TP + FN); precision = TP / (TP + FP). Both return
    None when the denominator is 0 (no signal).
    """
    import time as _time
    cutoff = _time.time() - max(0.0, float(hours)) * 3600.0
    extra = ""
    params: list = [cutoff]
    if analyst_kind == "human":
        extra = " AND af.analyst_id NOT LIKE 'auto:%'"
    elif analyst_kind == "auto":
        extra = " AND af.analyst_id LIKE 'auto:%'"
    by_label = {label.value: 0 for label in FeedbackLabel}
    human_total = 0
    auto_total = 0
    by_ct: dict[str, dict[str, int]] = {}
    rows = db._get_conn().execute(  # noqa: SLF001
        "SELECT af.label, af.analyst_id, c.conclusion_type "
        "FROM analyst_feedback af "
        "LEFT JOIN conclusions c ON c.id = af.conclusion_id "
        f"WHERE af.observed_at >= ?{extra}",
        tuple(params),
    ).fetchall()
    for r in rows:
        lab = r["label"]
        by_label[lab] = by_label.get(lab, 0) + 1
        aid = r["analyst_id"] or ""
        if aid.startswith("auto:"):
            auto_total += 1
        else:
            human_total += 1
        ct = r["conclusion_type"] or "_unknown"
        by_ct.setdefault(ct, {l.value: 0 for l in FeedbackLabel})
        by_ct[ct][lab] = by_ct[ct].get(lab, 0) + 1
    distinct_row = db._get_conn().execute(  # noqa: SLF001
        "SELECT COUNT(DISTINCT analyst_id) AS n FROM analyst_feedback "
        f"WHERE observed_at >= ?",
        (cutoff,),
    ).fetchone()
    distinct = int(distinct_row["n"]) if distinct_row else 0
    tp = by_label.get(FeedbackLabel.TRUE_POSITIVE.value, 0)
    fp = by_label.get(FeedbackLabel.FALSE_POSITIVE.value, 0)
    fn = by_label.get(FeedbackLabel.FALSE_NEGATIVE.value, 0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    return {
        "window_hours":       float(hours),
        "total":              sum(by_label.values()),
        "human_total":        human_total,
        "auto_total":         auto_total,
        "distinct_analysts":  distinct,
        "by_label":           by_label,
        "by_conclusion_type": by_ct,
        "recall":             round(recall, 4) if recall is not None else None,
        "precision":          round(precision, 4) if precision is not None else None,
    }


def now_seconds() -> float:
    """Indirection for tests to monkeypatch time without touching `time.time`
    at the global level (other modules also patch it)."""
    return time.time()
