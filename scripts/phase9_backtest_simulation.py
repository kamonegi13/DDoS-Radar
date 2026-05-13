#!/usr/bin/env python3
"""Phase 9 backtest + retroactive simulation.

Two questions this answers from existing `scenario_tl_observation` rows:

  1. **Phase B candidates** — how often did past TL=2 / TL=1 firings come
     from the "single participant × 3 domains" pattern that Phase B is
     designed to downgrade? Few candidates ⇒ Phase B is safe to re-enable.
     Many candidates ⇒ a backtest classifier (or manual review) is needed
     before turning B on, because we'd be downgrading real TL=2 cases.

  2. **Phase C threshold proposal** — what would the TL distribution look
     like under A+B retroactively applied? Phase A's effect is approximated
     as `new_score = max(0, score - min(cyber, GLOBAL_CYBER_FLOOR))` since
     before Phase A every scenario inherited up to ~1.5 cyber from global
     signals. Phase B's effect is +1.0 / -1.0 on convergence depending on
     active domain & participant count. Phase E cannot be retroactively
     simulated without per-contribution history.

Read-only — never writes. Safe to run against a live container DB:

    docker exec ddos-radar python scripts/phase9_backtest_simulation.py
    docker exec ddos-radar python scripts/phase9_backtest_simulation.py --days 30
    docker exec ddos-radar python scripts/phase9_backtest_simulation.py --scenario taiwan_contingency
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path


# Phase A retroactive: subtract the observed global cyber floor (cf_botnet
# max 1.0 + threatfox max 0.5 = 1.5). Used as an upper-bound estimate;
# real per-tick global contribution may have been lower.
GLOBAL_CYBER_FLOOR = 1.5

# TL ladder (must mirror radar/scoring.py:derive_tl).
def derive_tl(total_score: float, active_domains: list[str],
              physical: float) -> int:
    if total_score >= 9 and physical >= 3.0:
        return 1
    if total_score >= 6 and len(active_domains) >= 2:
        return 2
    if total_score >= 4:
        return 3
    if total_score >= 2:
        return 4
    return 5


def parse_active_countries(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return v if isinstance(v, list) else []
    except (ValueError, TypeError):
        return []


def simulate_row(r: dict, apply_b: bool) -> dict:
    """Apply A (and optionally B) retroactively to one observation."""
    cyber_orig = float(r.get("cyber") or 0)
    physical = float(r.get("physical") or 0)
    info = float(r.get("info") or 0)
    conv = float(r.get("convergence_bonus") or 0)
    score = float(r.get("score") or 0)
    countries = parse_active_countries(r.get("active_countries"))

    # Phase A retroactive: subtract the observed global cyber floor from
    # the cyber domain. Real global contribution was ≤1.5; treat 1.5 as
    # the upper bound (the worst case where both globals fired at max).
    cyber_after_a = max(0.0, cyber_orig - GLOBAL_CYBER_FLOOR)
    # If cyber was already ≤1.5, Phase A wipes the cyber domain entirely,
    # which means it may also drop out of active_domains and reduce the
    # convergence bonus.
    domains_after = []
    if cyber_after_a > 0:
        domains_after.append("cyber")
    if physical > 0:
        domains_after.append("physical")
    if info > 0:
        domains_after.append("info")

    # Recompute convergence under Phase A's narrower active-domain set.
    # Always-on convergence rule (B off): +2.0 if ≥3, +1.0 if ==2, else 0.
    n_doms = len(domains_after)
    conv_after_a = 2.0 if n_doms >= 3 else (1.0 if n_doms == 2 else 0.0)

    # Phase B retroactive: with single participant lighting up 3 domains,
    # downgrade +2.0 → +1.0.
    conv_after_ab = conv_after_a
    b_triggered = False
    if apply_b and n_doms >= 3 and len(countries) < 2:
        conv_after_ab = 1.0
        b_triggered = True

    score_after_a = cyber_after_a + physical + info + conv_after_a
    score_after_ab = cyber_after_a + physical + info + conv_after_ab
    tl_after_a = derive_tl(score_after_a, domains_after, physical)
    tl_after_ab = derive_tl(score_after_ab, domains_after, physical)

    return {
        "scenario_id":  r["scenario_id"],
        "observed_at":  r["observed_at"],
        "tl_orig":      int(r["tl"]),
        "score_orig":   round(score, 2),
        "cyber_orig":   round(cyber_orig, 2),
        "n_countries":  len(countries),
        "n_doms_orig":  sum(
            1 for v in (cyber_orig, physical, info) if v > 0
        ),
        "score_a":      round(score_after_a, 2),
        "tl_a":         tl_after_a,
        "score_ab":     round(score_after_ab, 2),
        "tl_ab":        tl_after_ab,
        "b_triggered":  b_triggered,
        "n_doms_after_a": n_doms,
    }


def distribution(rows: list[dict], field: str) -> dict:
    c = Counter(int(r[field]) for r in rows)
    total = sum(c.values()) or 1
    return {
        f"TL{tl}": {
            "count": c.get(tl, 0),
            "pct":   round(c.get(tl, 0) / total * 100, 1),
        }
        for tl in (5, 4, 3, 2, 1)
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="radar/persistence/radar.db")
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--scenario", default=None,
                    help="restrict to a single scenario_id")
    ap.add_argument("--apply-b", action="store_true",
                    help="also simulate Phase B retroactively")
    args = ap.parse_args()

    if not Path(args.db).exists():
        print(f"ERROR: db not found: {args.db}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    cutoff = time.time() - args.days * 86400
    sql = (
        "SELECT scenario_id, observed_at, score, tl, cyber, physical, info, "
        "convergence_bonus, scoring_mode, active_countries "
        "FROM scenario_tl_observation "
        "WHERE observed_at > ? AND tl IS NOT NULL"
    )
    params: list = [cutoff]
    if args.scenario:
        sql += " AND scenario_id = ?"
        params.append(args.scenario)
    sql += " ORDER BY observed_at"
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    if not rows:
        print("no observations in window")
        return 0

    simulated = [simulate_row(r, apply_b=True) for r in rows]
    # For "A only" we recompute without B trigger.
    sim_a_only = [simulate_row(r, apply_b=False) for r in rows]

    print(f"\n=== Phase 9 backtest — last {args.days}d, "
          f"scenario={args.scenario or 'ALL'}, n={len(rows)} ===\n")

    # Distribution comparison (original / A only / A+B).
    print("TL distribution:")
    print(f"  {'':12s}  TL5     TL4     TL3     TL2     TL1")
    for label, src, field in (
        ("original",   rows,       "tl"),
        ("after A",    sim_a_only, "tl_a"),
        ("after A+B",  simulated,  "tl_ab"),
    ):
        dist = distribution(src, field)
        cells = "  ".join(
            f"{dist[f'TL{tl}']['pct']:5.1f}%"
            for tl in (5, 4, 3, 2, 1)
        )
        print(f"  {label:12s}  {cells}")

    # Per-scenario TL2/TL1 rate.
    print("\nPer-scenario TL2 / TL1 firing rate:")
    print(f"  {'scenario':24s}  {'original':>22s}  {'after A':>22s}  {'after A+B':>22s}")
    by_sc_orig: dict = {}
    by_sc_a: dict = {}
    by_sc_ab: dict = {}
    for orig, a_only, ab in zip(rows, sim_a_only, simulated):
        sid = orig["scenario_id"]
        for d, key, tl_val in (
            (by_sc_orig, "tl",    int(orig["tl"])),
            (by_sc_a,    "tl_a",  a_only["tl_a"]),
            (by_sc_ab,   "tl_ab", ab["tl_ab"]),
        ):
            d.setdefault(sid, Counter())[tl_val] += 1
    all_sids = sorted({r["scenario_id"] for r in rows})
    for sid in all_sids:
        def fmt(d):
            c = d.get(sid, Counter())
            t = sum(c.values()) or 1
            tl1, tl2 = c.get(1, 0), c.get(2, 0)
            return f"TL1={tl1:>3d}({tl1/t*100:4.1f}%) TL2={tl2:>3d}({tl2/t*100:4.1f}%)"
        print(f"  {sid:24s}  {fmt(by_sc_orig):>22s}  {fmt(by_sc_a):>22s}  {fmt(by_sc_ab):>22s}")

    # Phase B candidates: rows where B's downgrade actually triggered.
    b_candidates = [s for s in simulated if s["b_triggered"]]
    print(f"\nPhase B candidates (single participant × ≥3 domains "
          f"under A's narrower domain set): {len(b_candidates)} rows")
    n_b_was_tl2_orig = sum(1 for s in b_candidates if s["tl_orig"] == 2)
    n_b_was_tl1_orig = sum(1 for s in b_candidates if s["tl_orig"] == 1)
    n_b_dropped = sum(
        1 for s in b_candidates if s["tl_a"] != s["tl_ab"]
    )
    print(f"  ... of those, originally TL=2: {n_b_was_tl2_orig}")
    print(f"  ... of those, originally TL=1: {n_b_was_tl1_orig}")
    print(f"  ... TL band changed by B vs A-only: {n_b_dropped}")
    if b_candidates:
        print("\n  Sample (first 5 candidates):")
        for s in b_candidates[:5]:
            print(f"    {s['scenario_id']:22s} "
                  f"orig TL{s['tl_orig']} score={s['score_orig']} "
                  f"→ A TL{s['tl_a']} ({s['score_a']}) "
                  f"→ A+B TL{s['tl_ab']} ({s['score_ab']}) "
                  f"n_countries={s['n_countries']}")

    # Phase C empirical threshold proposal.
    # Targets from /api/analytics/tl_recalibration_advisory:
    #   tl2_target_per_week_max = 0.5
    #   tl1_target_per_week_max = ~0.077
    # Compute observed firings/week under A and propose adjusted floors
    # that would meet the target (if the current ladder doesn't).
    print("\nPhase C threshold check (advisory targets: TL2≤0.5/week, TL1≤~0.08/week):")
    period_weeks = args.days / 7.0 or 1
    for sid in all_sids:
        per_a = by_sc_a.get(sid, Counter())
        per_ab = by_sc_ab.get(sid, Counter())
        tl2_a_week = per_a.get(2, 0) / period_weeks
        tl1_a_week = per_a.get(1, 0) / period_weeks
        tl2_ab_week = per_ab.get(2, 0) / period_weeks
        tl1_ab_week = per_ab.get(1, 0) / period_weeks
        status_a = "OK" if (tl2_a_week <= 0.5 and tl1_a_week <= 0.08) else "OVER"
        status_ab = "OK" if (tl2_ab_week <= 0.5 and tl1_ab_week <= 0.08) else "OVER"
        print(f"  {sid:24s}  "
              f"A: TL1={tl1_a_week:6.2f}/wk TL2={tl2_a_week:6.2f}/wk [{status_a}]  "
              f"A+B: TL1={tl1_ab_week:6.2f}/wk TL2={tl2_ab_week:6.2f}/wk [{status_ab}]")

    print("\n(Phase E cannot be retroactively simulated — per-contribution "
          "history is not stored per TL observation.)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
