#!/usr/bin/env python3
"""Backtest Layer 1 (cross-evidence required) of intel_auto_judge.

Read-only analysis over `llm_intel` to quantify whether Layer 1 — the
proposed safety rule that "LLM second-pass auto-flip is blocked unless
an independent cross-evidence signal exists in the same theater within
a configurable window" — would help, hurt, or no-op given the actual
data the production radar has accumulated.

This script is deliberately observational: it does not write to the DB
and does not invoke the LLM. It simulates the Layer 1 gate against the
historical population so we can decide, with numbers, whether to ship
Layer 1 (and at what threshold).

Why we bother: implementing a safety layer whose effect we can't measure
is exactly the kind of complexity NP6 (transparency) tells us to avoid.
The output below either justifies Layer 1 with concrete counts, or tells
us the data is too sparse to justify it yet — both are valid outcomes.

Usage:
    docker exec ddos-radar python scripts/backtest_auto_judge_layer1.py
    # local (read-only is safe even with the container running, but
    # the canonical path goes through the container per CLAUDE.md):
    python scripts/backtest_auto_judge_layer1.py --db radar/persistence/radar.db
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    id: str
    source_type: str
    source_id: str
    theater: str
    confidence: float
    status: str
    created_at: float
    confirmed_at: float | None
    confirmed_by: str | None
    headline: str


def load_items(db_path: str) -> list[Item]:
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id, source_type, source_id, theater, confidence, status, "
        "created_at, confirmed_at, confirmed_by, headline "
        "FROM llm_intel ORDER BY created_at ASC"
    ).fetchall()
    conn.close()
    return [
        Item(
            id=r[0], source_type=r[1] or "", source_id=r[2] or "",
            theater=r[3] or "", confidence=float(r[4] or 0.0),
            status=r[5] or "", created_at=float(r[6] or 0.0),
            confirmed_at=(float(r[7]) if r[7] is not None else None),
            confirmed_by=r[8], headline=r[9] or "",
        )
        for r in rows
    ]


def _cross_evidence_at(target: Item, all_items: list[Item], *,
                        window_h: float, min_corrob: int,
                        require_diff_source_type: bool) -> tuple[bool, list[str]]:
    """Decide whether `target` had cross-evidence at its resolution time.

    For not-yet-resolved items (pending) the resolution time is taken as
    "now"; the cross-evidence judgment is therefore about whether a
    Layer 1 gate would, at this moment, allow an auto-flip.
    """
    eval_time = target.confirmed_at or time.time()
    earliest = eval_time - window_h * 3600.0
    seen_types: set[str] = set()
    matched_ids: list[str] = []
    for peer in all_items:
        if peer.id == target.id:
            continue
        if peer.theater != target.theater:
            continue
        # Peer must have existed AND been non-rejected at evaluation time.
        if peer.created_at < earliest or peer.created_at > eval_time:
            continue
        if peer.status == "rejected" and peer.confirmed_at and peer.confirmed_at <= eval_time:
            continue  # peer was already known-bad by eval time
        if require_diff_source_type:
            if peer.source_type == target.source_type:
                continue
        seen_types.add(peer.source_type or "<none>")
        matched_ids.append(peer.id)
        if len(seen_types) >= min_corrob:
            return True, matched_ids
    return False, matched_ids


def population_breakdown(items: list[Item]) -> dict:
    out: dict = {
        "total": len(items),
        "by_status": Counter(i.status for i in items),
        "by_source_type": Counter(i.source_type for i in items),
        "by_theater": Counter(i.theater for i in items),
        "by_confirmer": Counter(i.confirmed_by for i in items if i.confirmed_by),
    }
    if items:
        out["window_oldest_iso"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.gmtime(min(i.created_at for i in items)))
        out["window_newest_iso"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.gmtime(max(i.created_at for i in items)))
    return out


def evaluate_layer1(items: list[Item], *, window_h: float,
                    min_corrob: int, require_diff_source_type: bool) -> dict:
    """For each resolved item, ask: did it have cross-evidence available
    at the time it was resolved?

    Splits results by status path so we can see asymmetric impacts:
      - confirmed (analyst):  Layer 1 would block any LLM auto-confirm
                              that contradicted analyst intent IF analyst
                              relied on cross-evidence.
      - rejected (analyst):   Layer 1 would block any LLM auto-reject
                              of items the analyst examined.
      - pending (current):    Layer 1's footprint on next sweep.
    """
    grouped: dict[str, list[Item]] = defaultdict(list)
    for it in items:
        grouped[it.status].append(it)

    out: dict = {"params": {
        "window_h": window_h, "min_corrob": min_corrob,
        "require_diff_source_type": require_diff_source_type,
    }, "by_status": {}}

    for status, bucket in grouped.items():
        with_ev = without_ev = 0
        for it in bucket:
            has, _ = _cross_evidence_at(
                it, items, window_h=window_h, min_corrob=min_corrob,
                require_diff_source_type=require_diff_source_type,
            )
            if has:
                with_ev += 1
            else:
                without_ev += 1
        out["by_status"][status] = {
            "n": len(bucket),
            "with_cross_evidence": with_ev,
            "without_cross_evidence": without_ev,
            "pct_blocked_by_layer1": (
                round(100.0 * without_ev / max(1, len(bucket)), 1)
            ),
        }
    return out


def parameter_sweep(items: list[Item]) -> list[dict]:
    grid = []
    for window_h in (48, 72, 168):
        for min_corrob in (1, 2):
            for require_diff in (True, False):
                grid.append(evaluate_layer1(
                    items, window_h=window_h, min_corrob=min_corrob,
                    require_diff_source_type=require_diff,
                ))
    return grid


def diversity_summary(items: list[Item]) -> dict:
    """Cross-source diversity: how many distinct source_types per
    theater within a 72h rolling window. If diversity is near zero,
    Layer 1 is structurally non-functional (cannot find independent
    corroborators)."""
    by_theater: dict[str, set[str]] = defaultdict(set)
    for it in items:
        by_theater[it.theater].add(it.source_type)
    return {
        "theaters": len(by_theater),
        "avg_distinct_source_types_per_theater": (
            round(sum(len(s) for s in by_theater.values())
                  / max(1, len(by_theater)), 2)
        ),
        "max_distinct_source_types_per_theater": (
            max((len(s) for s in by_theater.values()), default=0)
        ),
        "theaters_with_only_one_source_type": sum(
            1 for s in by_theater.values() if len(s) == 1
        ),
    }


def render_text(pop: dict, sweep: list[dict], divers: dict, dbpath: str) -> str:
    out = []
    out.append("=" * 72)
    out.append(f" Layer 1 backtest — db: {dbpath}")
    out.append("=" * 72)
    out.append("")
    out.append("[Population]")
    out.append(f"  total items:           {pop['total']}")
    if pop["total"] == 0:
        out.append("  (DB has no llm_intel rows — backtest cannot proceed.)")
        return "\n".join(out)
    out.append(f"  window oldest:         {pop.get('window_oldest_iso', '?')} UTC")
    out.append(f"  window newest:         {pop.get('window_newest_iso', '?')} UTC")
    out.append("  by status:")
    for k, v in pop["by_status"].most_common():
        out.append(f"    {k:18s} {v}")
    out.append("  top source_types:")
    for k, v in pop["by_source_type"].most_common(8):
        out.append(f"    {k:18s} {v}")
    out.append("  top theaters:")
    for k, v in pop["by_theater"].most_common(8):
        out.append(f"    {k:18s} {v}")
    out.append("  confirmer markers:")
    for k, v in pop["by_confirmer"].most_common():
        out.append(f"    {k:18s} {v}")
    out.append("")
    out.append("[Source diversity — Layer 1 prerequisite]")
    out.append(f"  theaters seen:                              {divers['theaters']}")
    out.append(f"  avg distinct source_types per theater:      {divers['avg_distinct_source_types_per_theater']}")
    out.append(f"  max distinct source_types per theater:      {divers['max_distinct_source_types_per_theater']}")
    out.append(f"  theaters with only one source_type:         {divers['theaters_with_only_one_source_type']}")
    if divers["max_distinct_source_types_per_theater"] < 2:
        out.append("  ⚠️  No theater has ≥2 distinct source_types in the retention "
                   "window. Layer 1 with require_diff_source_type=True would "
                   "block 100% of LLM auto-flips because cross-evidence cannot "
                   "be sourced. Either widen retention, accept require_diff=False, "
                   "or defer Layer 1 until cross-source coverage exists.")
    out.append("")
    out.append("[Parameter sweep — % of items Layer 1 would block (no cross-evidence)]")
    out.append("  window_h | min_corr | diff_src | confirmed | rejected | pending")
    out.append("  ---------|----------|----------|-----------|----------|---------")
    for s in sweep:
        p = s["params"]
        c = s["by_status"].get("confirmed", {}).get("pct_blocked_by_layer1", 0.0)
        r = s["by_status"].get("rejected", {}).get("pct_blocked_by_layer1", 0.0)
        pn = s["by_status"].get("pending", {}).get("pct_blocked_by_layer1", 0.0)
        ac = s["by_status"].get("auto_confirmed", {}).get("pct_blocked_by_layer1", 0.0)
        out.append(
            f"  {p['window_h']:>8d} | {p['min_corrob']:>8d} | "
            f"{('yes' if p['require_diff_source_type'] else 'no'):>8s} | "
            f"{c:>8.1f}% | {r:>7.1f}% | {pn:>6.1f}%"
            + (f"   (auto_confirmed: {ac:.1f}%)" if ac else "")
        )
    out.append("")
    # Pick a "recommended preset" from the grid for easy decision making.
    recommended = next(
        (s for s in sweep if s["params"] == {
            "window_h": 72, "min_corrob": 1, "require_diff_source_type": True,
        }), None,
    )
    if recommended:
        rec = recommended["by_status"]
        out.append("[Decision summary @ recommended preset (72h / N=1 / diff_src=yes)]")
        for status in ("confirmed", "rejected", "pending", "auto_confirmed"):
            stat = rec.get(status)
            if not stat or stat["n"] == 0:
                continue
            out.append(
                f"  {status:14s} n={stat['n']:>3d}  "
                f"with_evidence={stat['with_cross_evidence']:>3d}  "
                f"without={stat['without_cross_evidence']:>3d}  "
                f"layer1_block_rate={stat['pct_blocked_by_layer1']:.1f}%"
            )
        out.append("")
        out.append("  Interpretation guide:")
        out.append("    confirmed.layer1_block_rate     — fraction of analyst-confirmed items")
        out.append("                                       that Layer 1 would have blocked an")
        out.append("                                       LLM auto-confirm on (recall risk)")
        out.append("    rejected.layer1_block_rate      — fraction of rejects with no support;")
        out.append("                                       Layer 1 would block LLM auto-reject")
        out.append("                                       there too (precision-of-rejection cost)")
        out.append("    pending.layer1_block_rate       — share of next-sweep candidates Layer 1")
        out.append("                                       would silently leave pending")
    out.append("")
    out.append("[Recommendation]")
    if pop["by_status"].get("confirmed", 0) < 5:
        out.append("  ⚠️  Confirmed-item count < 5 — too few labels to draw a")
        out.append("     statistical conclusion about Layer 1 recall impact.")
        out.append("     Recommendation: defer Layer 1 implementation until")
        out.append("     ≥30 confirmed items have accrued. Run this script again")
        out.append("     after that bar is met.")
    if divers["max_distinct_source_types_per_theater"] < 2:
        out.append("  ⚠️  Cross-source diversity = 0 in current retention window.")
        out.append("     Layer 1 cannot work as designed with the present data;")
        out.append("     either (i) widen INTEL_RETENTION_DAYS, (ii) enable more")
        out.append("     non-military sensors (apt_intel, narrative, hacktivist,")
        out.append("     diplomatic), or (iii) relax require_diff_source_type=False")
        out.append("     so headline diversity within the same source_type counts.")
    return "\n".join(out)


def analyze(db_path: str = "radar/persistence/radar.db") -> dict:
    """Run the backtest and return a structured result dict.

    Programmatic entry point — read-only, no LLM calls. Raises
    sqlite3.OperationalError if the DB cannot be opened.
    """
    items = load_items(db_path)
    return {
        "population": population_breakdown(items),
        "diversity": diversity_summary(items),
        "parameter_sweep": parameter_sweep(items),
        "db_path": db_path,
    }


def format_text(result: dict) -> str:
    """Render an analyze() result as the human-readable text report."""
    return render_text(
        result["population"], result["parameter_sweep"], result["diversity"],
        result.get("db_path", "<unknown>"),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="radar/persistence/radar.db",
                    help="path to radar SQLite DB")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON instead of text")
    args = ap.parse_args()

    try:
        result = analyze(args.db)
    except sqlite3.OperationalError as exc:
        print(f"could not open db {args.db!r}: {exc}", file=sys.stderr)
        return 2

    pop = result["population"]
    divers = result["diversity"]
    sweep = result["parameter_sweep"]

    if args.json:
        print(json.dumps({
            "population": {**pop,
                "by_status": dict(pop["by_status"]),
                "by_source_type": dict(pop["by_source_type"]),
                "by_theater": dict(pop["by_theater"]),
                "by_confirmer": dict(pop["by_confirmer"]),
            },
            "diversity": divers,
            "parameter_sweep": sweep,
        }, indent=2))
    else:
        print(render_text(pop, sweep, divers, args.db))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
