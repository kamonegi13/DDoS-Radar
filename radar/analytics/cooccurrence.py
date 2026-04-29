"""Country co-occurrence matrix (G.2).

For each pair (countryA, countryB), counts the number of time buckets
in the lookback window where both countries had at least one llm_intel
event. The matrix powers DBSCAN clustering in commit 9 — countries
that frequently co-occur cluster together, suggesting candidate
scenarios.

Algorithm:
  1. Bucket llm_intel.ts into N-hour bins (default 24h).
  2. For each bucket, collect the set of countries with ≥1 event.
  3. For every (A, B) pair within a bucket, increment pair count.
  4. Compute share = count / total_buckets so the pair value is
     normalized across windows of different durations.

Output is persisted as one row in cooccurrence_matrix_snapshot:
  - matrix_json: {countries: [...], pairs: [{a, b, count, share}]}
  - cell_count: len(pairs) — capped at MAX_CELLS to prevent bloat.

NP3: empty llm_intel → snapshot stores an empty matrix (cell_count=0)
     rather than failing. cell_count > MAX_CELLS → snapshot is refused
     (returns None) and the run is logged.
NP6: every snapshot has formula_ref + evidence_json (sources, total
     events, total buckets) so the matrix is reproducible.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from radar.database import db

log = logging.getLogger("radar.analytics.cooccurrence")


FORMULA_REF = "cooccurrence/v1#etl"


def _max_cells() -> int:
    """Hard cap on matrix size — refuses snapshots with more cells than
    this. Default 5000 keeps each snapshot under ~250KB JSON."""
    return int(os.getenv("COOCCURRENCE_MAX_CELLS", "5000"))


def _bucket_hours_default() -> int:
    return int(os.getenv("COOCCURRENCE_BUCKET_HOURS", "24"))


def _window_days_default() -> int:
    return int(os.getenv("COOCCURRENCE_WINDOW_DAYS", "30"))


@dataclass(frozen=True)
class PairCount:
    a: str
    b: str
    count: int
    share: float


@dataclass(frozen=True)
class CooccurrenceMatrix:
    countries: tuple[str, ...]
    pairs: tuple[PairCount, ...]
    window_days: int
    bucket_hours: int
    total_buckets: int
    total_events: int

    @property
    def cell_count(self) -> int:
        return len(self.pairs)

    def to_dict(self) -> dict:
        return {
            "countries": list(self.countries),
            "pairs": [
                {"a": p.a, "b": p.b, "count": p.count, "share": p.share}
                for p in self.pairs
            ],
            "window_days": self.window_days,
            "bucket_hours": self.bucket_hours,
            "total_buckets": self.total_buckets,
            "total_events": self.total_events,
        }


# ── Computation ──────────────────────────────────────────────────────────────


def compute_matrix(
    *, window_days: Optional[int] = None,
    bucket_hours: Optional[int] = None,
) -> CooccurrenceMatrix:
    """Build a CooccurrenceMatrix over the last `window_days` of llm_intel
    activity. Returns an empty matrix when no rows are present (NP3)."""
    wd = int(window_days) if window_days is not None else _window_days_default()
    bh = int(bucket_hours) if bucket_hours is not None else _bucket_hours_default()
    cutoff = time.time() - wd * 86400
    bucket_size = max(1, bh) * 3600

    try:
        conn = db._get_conn()  # noqa: SLF001
        rows = conn.execute(
            "SELECT theater, ts FROM llm_intel "
            "WHERE ts > ? AND theater IS NOT NULL AND theater != ''",
            (cutoff,),
        ).fetchall()
    except Exception as exc:
        log.warning("compute_matrix: query failed: %s", exc)
        rows = []

    # Bucket → set of countries.
    buckets: dict[int, set[str]] = {}
    countries: set[str] = set()
    n_events = 0
    for country, ts in rows:
        if not country:
            continue
        bucket_idx = int(ts // bucket_size)
        buckets.setdefault(bucket_idx, set()).add(country)
        countries.add(country)
        n_events += 1

    # Pair counts.
    pair_counts: dict[tuple[str, str], int] = {}
    for bucket_countries in buckets.values():
        cs = sorted(bucket_countries)
        for i in range(len(cs)):
            for j in range(i + 1, len(cs)):
                key = (cs[i], cs[j])
                pair_counts[key] = pair_counts.get(key, 0) + 1

    total_buckets = len(buckets)
    pairs = []
    for (a, b), n in sorted(pair_counts.items(), key=lambda kv: -kv[1]):
        share = (n / total_buckets) if total_buckets > 0 else 0.0
        pairs.append(PairCount(a=a, b=b, count=n, share=round(share, 4)))

    return CooccurrenceMatrix(
        countries=tuple(sorted(countries)),
        pairs=tuple(pairs),
        window_days=wd,
        bucket_hours=bh,
        total_buckets=total_buckets,
        total_events=n_events,
    )


# ── Persistence ──────────────────────────────────────────────────────────────


def snapshot(matrix: CooccurrenceMatrix) -> Optional[int]:
    """Persist a matrix to cooccurrence_matrix_snapshot.

    Returns the new row id, or None if the matrix exceeds MAX_CELLS.
    Empty matrices are persisted (cell_count=0) so the AP3 scoreboard
    can show "ETL ran but produced nothing" vs "ETL never ran".
    """
    if matrix.cell_count > _max_cells():
        log.warning(
            "cooccurrence snapshot refused: cell_count=%d > MAX_CELLS=%d",
            matrix.cell_count, _max_cells(),
        )
        return None
    matrix_json = json.dumps(matrix.to_dict(), sort_keys=True)
    evidence = {
        "total_events": matrix.total_events,
        "total_buckets": matrix.total_buckets,
        "country_count": len(matrix.countries),
    }
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO cooccurrence_matrix_snapshot "
                "(emitted_at, window_days, bucket_hours, cell_count, "
                " matrix_json, formula_ref, evidence_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), matrix.window_days, matrix.bucket_hours,
                 matrix.cell_count, matrix_json, FORMULA_REF,
                 json.dumps(evidence, sort_keys=True)),
            )
            return cur.lastrowid
    except Exception as exc:
        log.warning("snapshot failed: %s", exc)
        return None


def get_latest_snapshot() -> Optional[dict]:
    """Return the most recent snapshot row as a dict, or None."""
    try:
        conn = db._get_conn()  # noqa: SLF001
        row = conn.execute(
            "SELECT id, emitted_at, window_days, bucket_hours, cell_count, "
            "matrix_json, formula_ref, evidence_json "
            "FROM cooccurrence_matrix_snapshot "
            "ORDER BY emitted_at DESC LIMIT 1"
        ).fetchone()
    except Exception as exc:
        log.debug("get_latest_snapshot failed: %s", exc)
        return None
    if not row:
        return None
    try:
        matrix = json.loads(row[5] or "{}")
        evidence = json.loads(row[7] or "{}")
    except Exception:
        matrix, evidence = {}, {}
    return {
        "id": row[0],
        "emitted_at": row[1],
        "window_days": row[2],
        "bucket_hours": row[3],
        "cell_count": row[4],
        "matrix": matrix,
        "formula_ref": row[6],
        "evidence": evidence,
    }


# ── Driver ───────────────────────────────────────────────────────────────────


def run_once() -> dict:
    """Compute + persist one matrix snapshot. Returns a summary dict."""
    matrix = compute_matrix()
    snapshot_id = snapshot(matrix)
    return {
        "snapshot_id": snapshot_id,
        "cell_count": matrix.cell_count,
        "country_count": len(matrix.countries),
        "total_events": matrix.total_events,
        "total_buckets": matrix.total_buckets,
        "window_days": matrix.window_days,
        "bucket_hours": matrix.bucket_hours,
    }


__all__ = [
    "PairCount",
    "CooccurrenceMatrix",
    "compute_matrix",
    "snapshot",
    "get_latest_snapshot",
    "run_once",
]
