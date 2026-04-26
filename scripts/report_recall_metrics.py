"""Report recall / precision baseline from analyst_feedback ledger.

Phase 2 完了条件 "recall metrics ベースライン記録" の集計ツール (ADR-V2-005,
ADR-V2-011, §9.3 Design W との連動)。read-only。

Computes per-scenario × per-conclusion-type confusion matrix from the
``analyst_feedback`` ledger and emits:

  - TP / FP / TN / FN counts
  - recall    = TP / (TP + FN)   — NP1 critical (sensitivity)
  - precision = TP / (TP + FP)   — false-alarm rate
  - distinct_analysts (auto-source rows are treated per source by
    convention `auto:acled` / `auto:gdelt` / `auto:both`)

The "latest label per (analyst, conclusion)" rule is applied so an analyst
who revises a label doesn't double-count. Auto-feedback rows count as one
voter per source.

Output formats:
  - text (default): human-readable table
  - json: machine-readable for CI baseline tracking

Usage:
    python scripts/report_recall_metrics.py [--db PATH]
                                             [--scenario SCENARIO_ID]
                                             [--type THREAT_LEVEL|ATTACK_MODE|...]
                                             [--since EPOCH]
                                             [--json]
                                             [--exclude-auto]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault(
    "V2_NP7_DISCLAIMER",
    "This output is one node in your intelligence process.",
)

from radar.database import RadarDB  # noqa: E402

log = logging.getLogger("recall_metrics")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


@dataclass
class ConfusionCell:
    """Per-(scenario, conclusion_type) confusion matrix."""

    scenario_id: str
    conclusion_type: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    distinct_analysts: set = field(default_factory=set)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def recall(self) -> Optional[float]:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "conclusion_type": self.conclusion_type,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "total": self.total,
            "recall": self.recall,
            "precision": self.precision,
            "distinct_analysts": len(self.distinct_analysts),
        }


def collect_metrics(
    db: RadarDB,
    *,
    scenario_filter: Optional[str] = None,
    type_filter: Optional[str] = None,
    since: Optional[float] = None,
    exclude_auto: bool = False,
) -> list[ConfusionCell]:
    """Walk analyst_feedback joined to conclusions and bucket per cell.

    De-dup rule: keep the *latest* row per (conclusion_id, analyst_id).
    An analyst who flipped TRUE_POSITIVE → FALSE_POSITIVE on a row should
    have only the new label counted, not both.
    """
    sql = (
        "SELECT f.conclusion_id, f.label, f.analyst_id, f.observed_at, "
        "       c.scenario_id, c.conclusion_type "
        "FROM analyst_feedback f "
        "JOIN conclusions c ON c.id = f.conclusion_id "
        "WHERE 1=1"
    )
    params: list = []
    if scenario_filter:
        sql += " AND c.scenario_id = ?"
        params.append(scenario_filter)
    if type_filter:
        sql += " AND c.conclusion_type = ?"
        params.append(type_filter)
    if since is not None:
        sql += " AND f.observed_at >= ?"
        params.append(since)
    if exclude_auto:
        sql += " AND f.analyst_id NOT LIKE 'auto:%'"

    sql += " ORDER BY f.observed_at DESC"

    rows = db._get_conn().execute(sql, params).fetchall()  # noqa: SLF001

    # latest-per-(conclusion, analyst) — first row wins (DESC ordering).
    seen: set[tuple[str, str]] = set()
    cells: dict[tuple[str, str], ConfusionCell] = {}
    for r in rows:
        pair = (r["conclusion_id"], r["analyst_id"])
        if pair in seen:
            continue
        seen.add(pair)
        key = (r["scenario_id"], r["conclusion_type"])
        cell = cells.setdefault(
            key, ConfusionCell(scenario_id=key[0], conclusion_type=key[1]),
        )
        label = r["label"]
        if label == "TRUE_POSITIVE":
            cell.tp += 1
        elif label == "FALSE_POSITIVE":
            cell.fp += 1
        elif label == "TRUE_NEGATIVE":
            cell.tn += 1
        elif label == "FALSE_NEGATIVE":
            cell.fn += 1
        cell.distinct_analysts.add(r["analyst_id"])

    return sorted(
        cells.values(),
        key=lambda c: (c.scenario_id, c.conclusion_type),
    )


def render_text(cells: list[ConfusionCell]) -> str:
    """Compact aligned table for stdout / log capture."""
    if not cells:
        return "no analyst_feedback rows in scope"
    lines = [
        f"{'scenario_id':28s} {'type':14s} "
        f"{'TP':>4s} {'FP':>4s} {'TN':>4s} {'FN':>4s} "
        f"{'recall':>8s} {'prec':>8s} {'distA':>6s}"
    ]
    lines.append("-" * len(lines[0]))
    totals = ConfusionCell(scenario_id="<all>", conclusion_type="<all>")
    for c in cells:
        recall_s = f"{c.recall:.3f}" if c.recall is not None else "  -  "
        prec_s = f"{c.precision:.3f}" if c.precision is not None else "  -  "
        lines.append(
            f"{c.scenario_id:28s} {c.conclusion_type:14s} "
            f"{c.tp:4d} {c.fp:4d} {c.tn:4d} {c.fn:4d} "
            f"{recall_s:>8s} {prec_s:>8s} {len(c.distinct_analysts):6d}"
        )
        totals.tp += c.tp
        totals.fp += c.fp
        totals.tn += c.tn
        totals.fn += c.fn
        totals.distinct_analysts |= c.distinct_analysts
    lines.append("-" * len(lines[0]))
    recall_s = f"{totals.recall:.3f}" if totals.recall is not None else "  -  "
    prec_s = f"{totals.precision:.3f}" if totals.precision is not None else "  -  "
    lines.append(
        f"{'TOTAL':28s} {'':14s} "
        f"{totals.tp:4d} {totals.fp:4d} {totals.tn:4d} {totals.fn:4d} "
        f"{recall_s:>8s} {prec_s:>8s} {len(totals.distinct_analysts):6d}"
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default=None)
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--type", dest="type_filter", default=None)
    parser.add_argument(
        "--since", type=float, default=None,
        help="Only count feedback rows with observed_at >= EPOCH",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--exclude-auto", action="store_true",
        help="Drop analyst_id starting with 'auto:' (human-only baseline)",
    )
    args = parser.parse_args()

    if args.db:
        os.environ["RADAR_DB_PATH"] = args.db
    db = RadarDB(os.environ.get("RADAR_DB_PATH", "radar/persistence/radar.db"))

    cells = collect_metrics(
        db,
        scenario_filter=args.scenario,
        type_filter=args.type_filter,
        since=args.since,
        exclude_auto=args.exclude_auto,
    )

    if args.json:
        payload = {
            "generated_at": time.time(),
            "filters": {
                "scenario": args.scenario,
                "type": args.type_filter,
                "since": args.since,
                "exclude_auto": args.exclude_auto,
            },
            "cells": [c.to_dict() for c in cells],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(cells))

    return 0


if __name__ == "__main__":
    sys.exit(main())
