#!/usr/bin/env python3
"""Recall metrics baseline tracker (Phase 2 完了条件 §9.3 Design W gate).

Snapshots the per-(scenario, conclusion_type) confusion matrix from the
live DB into a checked-in baseline file, and on subsequent runs verifies
that recall has not silently regressed. Pairs with
``scripts/report_recall_metrics.py`` (which renders the matrix) — this
script gives the human-readable report a CI hook so a regression in the
classifier or sensors trips the gate before it ships.

Two modes:

  --update       — snapshot the current matrix into
                   ``docs/baselines/recall_metrics.json`` (commit the
                   updated file). Use after a deliberate retune.
  default check  — load that baseline and compare against the live matrix.
                   Fails (exit 1) if any per-cell recall drops by more than
                   ``--max-drop`` (default 0.05) versus baseline.
  --window-days  — restrict the matrix to feedback rows observed within the
                   last N days. The window is recorded in the snapshot and
                   the check uses the baseline's window unless overridden.

Bootstrap mode:
  When the baseline file does not yet exist, the check exits 0 with a
  warning so the gate can be wired into CI before there is enough
  ``analyst_feedback`` data to call a regression. This mirrors how
  ``check_rename_coverage.py`` was rolled in as a soft gate first.

Coexistence with passive observation:
  Phase 2 完了条件 says Design W opt-in waits for analyst_feedback
  accumulation. While that observation period is in progress the gate is
  intentionally lenient (compare-only, no opt-in promotion). Once the
  ``opt_in`` flag in the baseline file flips to true a stricter gate can
  layer on top without changing the script's interface.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

os.environ.setdefault(
    "V2_NP7_DISCLAIMER",
    "This output is one node in your intelligence process.",
)

_BASELINE_PATH = _REPO_ROOT / "docs" / "baselines" / "recall_metrics.json"

log = logging.getLogger("recall_baseline")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


def _display_path(p: Path) -> str:
    """Render ``p`` relative to the repo when possible, else as-is.

    ``Path.relative_to`` raises when the target lives outside the repo
    (e.g. tmp dirs in tests, or a user-supplied ``--baseline`` outside the
    tree). The display is purely cosmetic, so swallow that and fall back.
    """
    try:
        return str(p.relative_to(_REPO_ROOT))
    except ValueError:
        return str(p)


# ── snapshot ──────────────────────────────────────────────────────────────


def _collect_snapshot(
    *,
    db_path: Optional[str] = None,
    exclude_auto: bool = False,
    since: Optional[float] = None,
) -> dict[str, Any]:
    """Build a baseline dict from the live DB. Pure data — no rendering.

    Calls into ``scripts/report_recall_metrics.collect_metrics`` so the SQL
    and de-dup rules stay shared with the on-demand reporter.

    ``since`` is an absolute unix timestamp; only feedback rows with
    ``observed_at >= since`` participate in the matrix. Lets the gate
    catch seasonal drift without re-baselining the full history.
    """
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    from radar.database import RadarDB  # noqa: E402  (late import after sys.path)
    from report_recall_metrics import collect_metrics  # noqa: E402

    if db_path:
        os.environ["RADAR_DB_PATH"] = db_path
    db = RadarDB(os.environ.get("RADAR_DB_PATH", "radar/persistence/radar.db"))

    cells = collect_metrics(db, exclude_auto=exclude_auto, since=since)
    return {
        "schema_version": 1,
        "generated_at": time.time(),
        "exclude_auto": exclude_auto,
        "since": since,
        "opt_in": False,  # flips to true once Design W opt-in fires
        "cells": [c.to_dict() for c in cells],
    }


def _load_baseline(path: Path) -> Optional[dict[str, Any]]:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _index_cells(snapshot: dict[str, Any]) -> dict[tuple[str, str], dict]:
    """Build {(scenario_id, conclusion_type) -> cell-dict} for diffing."""
    return {
        (c["scenario_id"], c["conclusion_type"]): c
        for c in snapshot.get("cells", [])
    }


# ── compare ───────────────────────────────────────────────────────────────


def compare(
    baseline: dict[str, Any],
    current: dict[str, Any],
    *,
    max_drop: float = 0.05,
) -> tuple[bool, list[str]]:
    """Return (ok, messages). ``ok`` is True iff no per-cell recall regression
    exceeds ``max_drop``. Messages are user-facing one-liners.

    Cells present in baseline but absent in current are reported as warnings
    (loss of coverage, not necessarily a recall regression). Cells new in
    current are noted but never fail the gate.
    """
    base_idx = _index_cells(baseline)
    cur_idx = _index_cells(current)

    messages: list[str] = []
    failed = False

    for key, base_cell in base_idx.items():
        base_recall = base_cell.get("recall")
        cur_cell = cur_idx.get(key)
        if cur_cell is None:
            messages.append(
                f"warn: cell {key[0]}/{key[1]} present in baseline but absent now"
            )
            continue
        cur_recall = cur_cell.get("recall")
        # Both None → no data on either side, fine.
        # Baseline None → bootstrap: nothing to compare.
        if base_recall is None:
            continue
        # Current None when baseline had a number → coverage loss, hard fail.
        if cur_recall is None:
            failed = True
            messages.append(
                f"FAIL: {key[0]}/{key[1]} recall went from "
                f"{base_recall:.3f} to None (coverage loss)"
            )
            continue
        drop = base_recall - cur_recall
        if drop > max_drop:
            failed = True
            messages.append(
                f"FAIL: {key[0]}/{key[1]} recall dropped "
                f"{base_recall:.3f} → {cur_recall:.3f} (Δ{drop:+.3f}, "
                f"threshold {max_drop:+.3f})"
            )
        elif drop > 0:
            messages.append(
                f"info: {key[0]}/{key[1]} recall slipped "
                f"{base_recall:.3f} → {cur_recall:.3f} (Δ{drop:+.3f})"
            )

    new_keys = set(cur_idx) - set(base_idx)
    for key in sorted(new_keys):
        messages.append(f"info: new cell {key[0]}/{key[1]} (not in baseline)")

    return (not failed), messages


# ── CLI ───────────────────────────────────────────────────────────────────


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--update", action="store_true",
        help="Snapshot current matrix into the baseline file (overwrites)",
    )
    parser.add_argument(
        "--db", default=None,
        help="DB path (default: $RADAR_DB_PATH or radar/persistence/radar.db)",
    )
    parser.add_argument(
        "--exclude-auto", action="store_true",
        help="Build the baseline from human-only feedback (drops auto:* rows)",
    )
    parser.add_argument(
        "--max-drop", type=float, default=0.05,
        help="Per-cell recall drop tolerance for the gate (default 0.05)",
    )
    parser.add_argument(
        "--baseline", default=str(_BASELINE_PATH),
        help="Baseline file path (default: docs/baselines/recall_metrics.json)",
    )
    parser.add_argument(
        "--window-days", type=float, default=None,
        help="Restrict the matrix to feedback rows from the last N days "
             "(absolute timestamp = now - N*86400). Catches seasonal drift "
             "without re-baselining full history.",
    )
    args = parser.parse_args(argv)

    baseline_path = Path(args.baseline)
    since: Optional[float] = (
        time.time() - args.window_days * 86400.0
        if args.window_days is not None
        else None
    )

    if args.update:
        snapshot = _collect_snapshot(
            db_path=args.db, exclude_auto=args.exclude_auto, since=since,
        )
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(snapshot, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        n = len(snapshot["cells"])
        print(f"wrote {_display_path(baseline_path)} ({n} cells)")
        return 0

    baseline = _load_baseline(baseline_path)
    if baseline is None:
        print(
            f"bootstrap: no baseline at {_display_path(baseline_path)} — "
            "run with --update once analyst_feedback has accumulated.",
        )
        return 0

    # Prefer the CLI-provided window over the baseline's frozen value;
    # falls back to baseline's snapshot window so the comparison is apples-to-apples.
    effective_since = since if since is not None else baseline.get("since")
    current = _collect_snapshot(
        db_path=args.db,
        exclude_auto=baseline.get("exclude_auto", False),
        since=effective_since,
    )
    ok, messages = compare(baseline, current, max_drop=args.max_drop)
    for m in messages:
        print(m)
    if not ok:
        print(
            "\nrecall baseline regression. If this is intentional "
            "(retune / new ground-truth source), update with:\n"
            "  python scripts/check_recall_baseline.py --update",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {len(current['cells'])} cells within "
        f"recall tolerance Δ≤{args.max_drop:+.3f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
