"""Threshold calibration analysis — Phase 1.3 Priority 5.

Reads the replay-tagged backfill rows in `conclusions` (from
backfill_v2_ledger/v1) and the underlying `scenario_tl_observation` rows
to compute empirical distributions for the trend (delta_sev) and
per_domain (cyber/physical/info scores, prior→current drops) thresholds.

The current thresholds (in trend.py / per_domain.py) were chosen
conservatively before any historical data was available:

  TREND
    RISING_DELTA   = 0.50  (severity points)
    ESCALATE_DELTA = 1.50
    MIN_SAMPLES    = 3
  PER_DOMAIN
    ACTIVE_FLOOR   = 3.0   (raw domain score)
    ELEVATED_FLOOR = 1.5
    DEGRADE_DELTA  = 1.5   (absolute drop from prior 24h baseline)

Output: percentile + state-share tables so a human can decide whether
the current thresholds match the realized distribution. The script is
read-only — it does not write to the DB or to any source files.

Usage:
    python scripts/calibrate_thresholds.py [--db PATH] [--top N]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from collections import Counter
from typing import Iterable

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import sqlite3  # noqa: E402

REPLAY_TAG = "backfill_v2_ledger/v1"


def _open(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _percentiles(vals: list[float], qs: Iterable[float]) -> dict[float, float]:
    if not vals:
        return {q: float("nan") for q in qs}
    s = sorted(vals)
    n = len(s)
    out: dict[float, float] = {}
    for q in qs:
        i = max(0, min(n - 1, int(round(q * (n - 1)))))
        out[q] = s[i]
    return out


def _fmt_pct(v: float) -> str:
    return "  nan" if v != v else f"{v:6.3f}"


def analyze_per_domain(conn: sqlite3.Connection) -> None:
    print("=" * 70)
    print("PER_DOMAIN — empirical distribution from replay-tagged rows")
    print("=" * 70)

    rows = conn.execute(
        "SELECT scenario_id, observed_at, state, metadata "
        "FROM conclusions "
        "WHERE conclusion_type = 'per_domain' "
        "  AND json_extract(metadata, '$.replay_tag') = ? "
        "ORDER BY scenario_id, observed_at",
        (REPLAY_TAG,),
    ).fetchall()
    print(f"\nrows: {len(rows)}")

    cyber, physical, info = [], [], []
    state_counter: Counter = Counter()
    drops_per_domain: dict[str, list[float]] = {"cyber": [], "physical": [], "info": []}
    prev_scores_per_scenario: dict[str, dict[str, float]] = {}

    for r in rows:
        try:
            md = json.loads(r["metadata"]) if r["metadata"] else {}
        except (TypeError, ValueError):
            md = {}
        scores = md.get("domain_scores", {}) or {}
        if "cyber" in scores:
            cyber.append(float(scores["cyber"]))
        if "physical" in scores:
            physical.append(float(scores["physical"]))
        if "info" in scores:
            info.append(float(scores["info"]))
        if r["state"]:
            state_counter[r["state"]] += 1

        prev = prev_scores_per_scenario.get(r["scenario_id"], {})
        for d in ("cyber", "physical", "info"):
            cur = float(scores.get(d, 0.0))
            old = prev.get(d)
            if old is not None and old > 0.0 and cur < old:
                drops_per_domain[d].append(old - cur)
        prev_scores_per_scenario[r["scenario_id"]] = {
            d: float(scores.get(d, 0.0)) for d in ("cyber", "physical", "info")
        }

    qs = (0.50, 0.75, 0.90, 0.95, 0.99)
    print("\nDomain score distribution (only positive values shown in pos_*):")
    print(f"{'domain':10s} {'n':>6s} {'pos_n':>6s} {'mean':>7s} {'p50':>7s} "
          f"{'p75':>7s} {'p90':>7s} {'p95':>7s} {'p99':>7s} {'max':>7s}")
    for label, vals in (("cyber", cyber), ("physical", physical), ("info", info)):
        pos = [v for v in vals if v > 0.0]
        n = len(vals)
        pn = len(pos)
        mean = statistics.mean(pos) if pos else float("nan")
        ps = _percentiles(pos, qs)
        mx = max(pos) if pos else float("nan")
        print(f"{label:10s} {n:6d} {pn:6d} {_fmt_pct(mean)} "
              f"{_fmt_pct(ps[0.50])} {_fmt_pct(ps[0.75])} {_fmt_pct(ps[0.90])} "
              f"{_fmt_pct(ps[0.95])} {_fmt_pct(ps[0.99])} {_fmt_pct(mx)}")

    print("\nDomain prior→current DROP distribution (only drops > 0):")
    print(f"{'domain':10s} {'drops_n':>8s} {'p50':>7s} {'p75':>7s} {'p90':>7s} "
          f"{'p95':>7s} {'p99':>7s} {'max':>7s}")
    for d in ("cyber", "physical", "info"):
        ds = drops_per_domain[d]
        ps = _percentiles(ds, qs)
        mx = max(ds) if ds else float("nan")
        print(f"{d:10s} {len(ds):8d} "
              f"{_fmt_pct(ps[0.50])} {_fmt_pct(ps[0.75])} {_fmt_pct(ps[0.90])} "
              f"{_fmt_pct(ps[0.95])} {_fmt_pct(ps[0.99])} {_fmt_pct(mx)}")

    print("\nState-string distribution (top 12):")
    for s, n in state_counter.most_common(12):
        sn = s if len(s) <= 70 else s[:67] + "..."
        share = 100.0 * n / max(1, sum(state_counter.values()))
        print(f"  {sn:<70s} {n:5d} ({share:5.1f}%)")

    print("\nThresholds in code today:")
    print("  ACTIVE_FLOOR   = 3.0")
    print("  ELEVATED_FLOOR = 1.5")
    print("  DEGRADE_DELTA  = 1.5  (absolute drop)")


def analyze_trend(conn: sqlite3.Connection) -> None:
    print()
    print("=" * 70)
    print("TREND — empirical delta_sev distribution (24h vs prior 24h)")
    print("=" * 70)

    # Reconstruct delta_sev from THREAT_LEVEL ledger windows. We sweep
    # the replay-tagged TL rows in chronological order and compute the
    # 24h-vs-prior-24h delta at each tick — the exact same calc that
    # _eval_window does internally, but done over the full backfill.
    tl_rows = conn.execute(
        "SELECT scenario_id, observed_at, state "
        "FROM conclusions "
        "WHERE conclusion_type = 'threat_level' "
        "  AND state IS NOT NULL "
        "  AND json_extract(metadata, '$.replay_tag') = ? "
        "ORDER BY scenario_id, observed_at",
        (REPLAY_TAG,),
    ).fetchall()
    print(f"\nTL rows backing trend calc: {len(tl_rows)}")

    # severity = 5 - tl  (tl 1..5 → sev 4..0)
    by_sc: dict[str, list[tuple[float, float]]] = {}
    for r in tl_rows:
        try:
            sev = 5 - int(r["state"])
        except (TypeError, ValueError):
            continue
        if sev < 0 or sev > 4:
            continue
        by_sc.setdefault(r["scenario_id"], []).append(
            (float(r["observed_at"]), float(sev)))

    span_hours = (
        ("short_term_24h", 24 * 3600),
        ("medium_term_7d", 7 * 24 * 3600),
        ("long_term_30d", 30 * 24 * 3600),
    )
    qs = (0.05, 0.25, 0.50, 0.75, 0.90, 0.95, 0.99)

    for label, span in span_hours:
        deltas: list[float] = []
        for sc, ticks in by_sc.items():
            for i, (t_now, _) in enumerate(ticks):
                cur = [s for tt, s in ticks
                       if tt < t_now and tt >= t_now - span]
                prev = [s for tt, s in ticks
                        if tt < t_now - span and tt >= t_now - 2 * span]
                if len(cur) < 3 or len(prev) < 3:
                    continue
                deltas.append((sum(cur) / len(cur)) - (sum(prev) / len(prev)))
        ps = _percentiles(deltas, qs)
        print(f"\n{label} (span={span}s)  delta_sev distribution "
              f"(n={len(deltas)}):")
        print(f"  p05={_fmt_pct(ps[0.05])}  p25={_fmt_pct(ps[0.25])}  "
              f"p50={_fmt_pct(ps[0.50])}  p75={_fmt_pct(ps[0.75])}  "
              f"p90={_fmt_pct(ps[0.90])}  p95={_fmt_pct(ps[0.95])}  "
              f"p99={_fmt_pct(ps[0.99])}")
        if deltas:
            abs_deltas = [abs(d) for d in deltas]
            ps2 = _percentiles(abs_deltas, qs)
            print(f"  |delta|: p50={_fmt_pct(ps2[0.50])}  "
                  f"p75={_fmt_pct(ps2[0.75])}  p90={_fmt_pct(ps2[0.90])}  "
                  f"p95={_fmt_pct(ps2[0.95])}  p99={_fmt_pct(ps2[0.99])}")
            # State share at current thresholds vs alternatives
            print(f"  State share at current thresholds "
                  f"(RISING=0.50, ESCALATE=1.50):")
            _print_state_share(deltas, 0.50, 1.50)
            for r_alt, e_alt in ((0.30, 1.00), (0.40, 1.20), (0.25, 0.80)):
                print(f"  State share at alt RISING={r_alt}, "
                      f"ESCALATE={e_alt}:")
                _print_state_share(deltas, r_alt, e_alt)

    # Trend state distribution from the actual rows that landed
    print()
    print("Realized trend state distribution (from backfilled rows):")
    rows = conn.execute(
        "SELECT state, COUNT(*) FROM conclusions "
        "WHERE conclusion_type = 'trend' "
        "  AND json_extract(metadata, '$.replay_tag') = ? "
        "GROUP BY state ORDER BY 2 DESC",
        (REPLAY_TAG,),
    ).fetchall()
    total = sum(r[1] for r in rows)
    for s, n in rows[:12]:
        sn = s if s else "<unavailable>"
        sn = sn if len(sn) <= 70 else sn[:67] + "..."
        share = 100.0 * n / max(1, total)
        print(f"  {sn:<70s} {n:5d} ({share:5.1f}%)")


def _print_state_share(deltas: list[float], rising: float,
                        escalate: float) -> None:
    states: Counter = Counter()
    for d in deltas:
        if d >= escalate:
            states["ESCALATING"] += 1
        elif d >= rising:
            states["RISING"] += 1
        elif d <= -escalate:
            states["DEEPER_DECAY"] += 1
        elif d <= -rising:
            states["COOLING"] += 1
        else:
            states["STABLE"] += 1
    n = sum(states.values())
    parts = [f"{s}={states[s]}({100.0*states[s]/n:.1f}%)"
             for s in ("ESCALATING", "RISING", "STABLE", "COOLING", "DEEPER_DECAY")
             if states[s]]
    print(f"    {'  '.join(parts)}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--db",
        default=os.path.join(_REPO_ROOT, "radar", "persistence", "radar.db"),
    )
    args = p.parse_args()
    if not os.path.exists(args.db):
        print(f"ERROR: DB not found: {args.db}", file=sys.stderr)
        return 2
    conn = _open(args.db)
    analyze_per_domain(conn)
    analyze_trend(conn)
    return 0


if __name__ == "__main__":
    sys.exit(main())
