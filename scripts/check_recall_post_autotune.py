#!/usr/bin/env python3
"""Post-autotune recall gate (warn-only by default).

Tracks short-term recall changes around recent auto-tunes. After Phase A-F1
calibrators write to threshold_history, this script compares recall in the
N-hour window *after* each row's `effective_from` against the same window
*before* it. Alerts on per-cell recall drops larger than `--max-drop`.

Companion to scripts/check_recall_baseline.py:
  - check_recall_baseline.py — long-term, point-in-time snapshot
  - check_recall_post_autotune.py — short-term, per-autotune impact

Two-tier check:
  1. Global trend — recall over [now - 2*hours, now - hours] vs
     [now - hours, now]. Catches drift even when no single autotune
     can be blamed.
  2. Per-autotune attribution — for each threshold_history row,
     before/after recall comparison. Skipped if either window has
     fewer than `min_samples` feedback rows (default 10).

Default mode is warn-only: exit 0 even when regressions are detected,
so the gate can ship into CI before we have enough post-autotune data
to draw firm conclusions. Pass `--strict` to fail on regression.

NP1 (sensitivity > precision): both global and per-cell checks compare
recall directly. Precision drops are informational; recall drops fail.

NP6: every regression message includes the threshold_history row id so
analysts can trace the specific autotune.

Usage:
  python scripts/check_recall_post_autotune.py
  python scripts/check_recall_post_autotune.py --strict
  python scripts/check_recall_post_autotune.py --hours 168 --max-drop 0.10
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

os.environ.setdefault(
    "V2_NP7_DISCLAIMER",
    "This output is one node in your intelligence process.",
)

log = logging.getLogger("recall_post_autotune")
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
)


# ── data helpers ─────────────────────────────────────────────────────────────


def _global_recall(db, *, since: float, until: float) -> Optional[float]:
    """Aggregate recall (TP / (TP + FN)) over an observed_at window.

    Returns None when the window has zero TP+FN rows.
    """
    rows = db._get_conn().execute(
        "SELECT label, COUNT(*) FROM analyst_feedback "
        "WHERE observed_at >= ? AND observed_at < ? "
        "GROUP BY label",
        (since, until),
    ).fetchall()
    counts = {r[0]: r[1] for r in rows}
    tp = counts.get("TRUE_POSITIVE", 0)
    fn = counts.get("FALSE_NEGATIVE", 0)
    denom = tp + fn
    return (tp / denom) if denom > 0 else None


def _recall_for_cell(
    db, scenario_id: Optional[str], *, since: float, until: float,
    min_samples: int,
) -> Optional[float]:
    """Per-scenario recall over an observed_at window. Returns None when
    samples are insufficient."""
    if scenario_id:
        sql = (
            "SELECT f.label, COUNT(*) FROM analyst_feedback f "
            "JOIN conclusions c ON c.id = f.conclusion_id "
            "WHERE c.scenario_id=? AND f.observed_at >= ? AND f.observed_at < ? "
            "GROUP BY f.label"
        )
        params = (scenario_id, since, until)
    else:
        sql = (
            "SELECT label, COUNT(*) FROM analyst_feedback "
            "WHERE observed_at >= ? AND observed_at < ? "
            "GROUP BY label"
        )
        params = (since, until)
    try:
        rows = db._get_conn().execute(sql, params).fetchall()
    except Exception:
        return None
    counts = {r[0]: r[1] for r in rows}
    tp = counts.get("TRUE_POSITIVE", 0)
    fn = counts.get("FALSE_NEGATIVE", 0)
    fp = counts.get("FALSE_POSITIVE", 0)
    if (tp + fn + fp) < min_samples:
        return None
    denom = tp + fn
    return (tp / denom) if denom > 0 else None


# ── core logic ───────────────────────────────────────────────────────────────


def check_global_trend(
    db, *, hours: float, max_drop: float,
) -> tuple[bool, list[str]]:
    """Compare recall in [now - 2*hours, now - hours] vs [now - hours, now]."""
    now = time.time()
    pre_recall = _global_recall(
        db, since=now - 2 * hours * 3600, until=now - hours * 3600,
    )
    post_recall = _global_recall(
        db, since=now - hours * 3600, until=now,
    )
    messages: list[str] = []
    if pre_recall is None or post_recall is None:
        messages.append(
            f"info: global trend skipped — pre={pre_recall} post={post_recall}"
            f" (need feedback in both windows)"
        )
        return True, messages
    drop = pre_recall - post_recall
    if drop > max_drop:
        messages.append(
            f"WARN: global recall dropped {pre_recall:.3f} → {post_recall:.3f} "
            f"(Δ{drop:+.3f}, threshold {max_drop:+.3f}) "
            f"over the last {hours:.0f}h vs the prior {hours:.0f}h"
        )
        return False, messages
    messages.append(
        f"OK: global recall {pre_recall:.3f} → {post_recall:.3f} "
        f"(Δ{drop:+.3f}, within {max_drop:+.3f})"
    )
    return True, messages


def check_per_autotune(
    db, *, hours: float, max_drop: float, min_samples: int,
) -> tuple[bool, list[str]]:
    """For every threshold_history row whose effective_from is older than
    `hours` ago, compare per-scope recall in the windows on either side."""
    now = time.time()
    # Lookback must be wider than the comparison window so an autotune row
    # has both a pre-window (before effective_from) and a post-window
    # (after) that completes before `now`. 14d default, expanded if hours
    # is set larger.
    earliest = now - max(14 * 86400, 2 * hours * 3600)
    try:
        rows = db._get_conn().execute(
            "SELECT id, key, scope_scenario_id, effective_from "
            "FROM threshold_history "
            "WHERE state='active' AND effective_from >= ? "
            "AND effective_from <= ? "
            "ORDER BY effective_from DESC LIMIT 100",
            (earliest, now - hours * 3600),
        ).fetchall()
    except Exception as exc:
        return True, [f"info: threshold_history query failed: {exc}"]

    messages: list[str] = []
    failed = False
    if not rows:
        messages.append(
            f"info: no threshold_history rows older than {hours:.0f}h "
            f"in the last 7d — skipping per-autotune check"
        )
        return True, messages

    for row_id, key, scope, eff_from in rows:
        pre = _recall_for_cell(
            db, scope,
            since=eff_from - hours * 3600,
            until=eff_from,
            min_samples=min_samples,
        )
        post = _recall_for_cell(
            db, scope,
            since=eff_from,
            until=eff_from + hours * 3600,
            min_samples=min_samples,
        )
        if pre is None or post is None:
            messages.append(
                f"info: row id={row_id} {key} scope={scope or 'global'} skipped"
                f" (insufficient samples — pre={pre}, post={post})"
            )
            continue
        drop = pre - post
        if drop > max_drop:
            failed = True
            messages.append(
                f"WARN: row id={row_id} {key} scope={scope or 'global'} "
                f"recall {pre:.3f} → {post:.3f} (Δ{drop:+.3f})"
            )
        elif drop > 0:
            messages.append(
                f"info: row id={row_id} {key} scope={scope or 'global'} "
                f"recall slipped {pre:.3f} → {post:.3f} (Δ{drop:+.3f}, "
                f"within tolerance)"
            )
    return (not failed), messages


# ── CLI ──────────────────────────────────────────────────────────────────────


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Post-autotune recall gate (warn-only by default).",
    )
    parser.add_argument(
        "--hours", type=float, default=168.0,
        help="Window size in hours for before/after comparison (default 168=7d)",
    )
    parser.add_argument(
        "--max-drop", type=float, default=0.10,
        help="Per-cell recall drop tolerance (default 0.10)",
    )
    parser.add_argument(
        "--min-samples", type=int, default=10,
        help="Minimum (TP+FN+FP) feedback rows in each window (default 10)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 1 on regression (default: warn-only, exit 0)",
    )
    parser.add_argument(
        "--db", default=None,
        help="DB path (default: $RADAR_DB_PATH or radar/persistence/radar.db)",
    )
    args = parser.parse_args(argv)

    from radar.database import RadarDB  # noqa: E402  (late import)
    if args.db:
        os.environ["RADAR_DB_PATH"] = args.db
    db = RadarDB(os.environ.get("RADAR_DB_PATH",
                                "radar/persistence/radar.db"))

    print("Post-autotune recall gate")
    print("=" * 50)
    global_ok, global_msgs = check_global_trend(
        db, hours=args.hours, max_drop=args.max_drop,
    )
    print()
    print("[ Global trend ]")
    for m in global_msgs:
        print(f"  {m}")
    autotune_ok, autotune_msgs = check_per_autotune(
        db, hours=args.hours, max_drop=args.max_drop,
        min_samples=args.min_samples,
    )
    print()
    print("[ Per-autotune attribution ]")
    for m in autotune_msgs:
        print(f"  {m}")

    print()
    overall_ok = global_ok and autotune_ok
    if overall_ok:
        print("OK: no recall regression detected.")
    else:
        print("WARN: recall regression detected. See messages above.")
        if args.strict:
            print("Exiting 1 (--strict mode).", file=sys.stderr)
            return 1
        print("Warn-only mode (default) — exiting 0. "
              "Run with --strict to fail CI on regression.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
