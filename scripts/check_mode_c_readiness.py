"""Mode C readiness check — single-shot judgment for v2 default-on flip.

Per v2-migration.md observation log, Mode C (V2_API_ENABLED default-on +
v1 sunset countdown start) requires:

  C1. diff_log 14d match_rate >= 0.99 AND divergence < 50
  C2. shadow_write produced live rows for all 5 conclusion_types in
      last 1h (proxy for "all 5 hooks healthy")
  C3. live (non-replay) ledger exists for all 5 types
  C4. live TREND short_term has produced at least one real state
      (not just INSUFFICIENT_DATA) — confirms NP5+8 transient-vs-chronic
  C5. operator manually confirms no critical complaints (--ack flag)

Run inside the container:

    docker exec ddos-radar python scripts/check_mode_c_readiness.py
    docker exec ddos-radar python scripts/check_mode_c_readiness.py --ack

Exit 0 = ready, exit 1 = not ready (per-condition reason printed).
"""

from __future__ import annotations

import argparse
import sys
import time

from radar.database import db


CONCLUSION_TYPES = ("threat_level", "trend", "per_domain", "anomaly", "attack_mode")

DIFF_MATCH_RATE_FLOOR = 0.99
DIFF_DIVERGENCE_CEILING = 50
DIFF_WINDOW_SEC = 14 * 24 * 3600
LIVE_TICK_WINDOW_SEC = 3600


def check_diff_log_health() -> tuple[bool, str]:
    conn = db._get_conn()
    since = time.time() - DIFF_WINDOW_SEC
    rows = conn.execute(
        "SELECT diff_kind, COUNT(*) AS n FROM conclusion_diff_log "
        "WHERE sampled_at >= ? GROUP BY diff_kind",
        (since,),
    ).fetchall()
    counts = {r["diff_kind"]: r["n"] for r in rows}
    total = sum(counts.values())
    if total == 0:
        return False, "no diff_log rows in 14d window"
    match_rate = counts.get("match", 0) / total
    divergence = counts.get("divergence", 0)
    ok = match_rate >= DIFF_MATCH_RATE_FLOOR and divergence < DIFF_DIVERGENCE_CEILING
    return ok, (
        f"14d total={total} match_rate={match_rate:.4f} "
        f"(floor {DIFF_MATCH_RATE_FLOOR}) divergence={divergence} "
        f"(ceiling {DIFF_DIVERGENCE_CEILING})"
    )


def check_recent_tick_coverage() -> tuple[bool, str]:
    conn = db._get_conn()
    since = time.time() - LIVE_TICK_WINDOW_SEC
    rows = conn.execute(
        "SELECT conclusion_type, COUNT(*) AS n FROM conclusions "
        "WHERE observed_at >= ? GROUP BY conclusion_type",
        (since,),
    ).fetchall()
    by_type = {r["conclusion_type"]: r["n"] for r in rows}
    missing = [t for t in CONCLUSION_TYPES if by_type.get(t, 0) == 0]
    ok = len(missing) == 0
    return ok, f"last_1h counts={by_type} missing={missing}"


def check_live_ledger_per_type() -> tuple[bool, str]:
    conn = db._get_conn()
    rows = conn.execute(
        "SELECT conclusion_type, COUNT(*) AS n FROM conclusions "
        "WHERE json_extract(metadata,'$.replay_tag') IS NULL "
        "GROUP BY conclusion_type"
    ).fetchall()
    by_type = {r["conclusion_type"]: r["n"] for r in rows}
    missing = [t for t in CONCLUSION_TYPES if by_type.get(t, 0) == 0]
    ok = len(missing) == 0
    return ok, f"live (non-replay) counts={by_type} missing={missing}"


def check_live_trend_state() -> tuple[bool, str]:
    conn = db._get_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM conclusions "
        "WHERE conclusion_type='trend' "
        "  AND state IS NOT NULL "
        "  AND state LIKE 'short_term=%' "
        "  AND state NOT LIKE 'short_term=INSUFFICIENT_DATA%' "
        "  AND json_extract(metadata,'$.replay_tag') IS NULL"
    ).fetchone()
    n = row["n"]
    ok = n > 0
    return ok, (
        f"live TREND rows with real short_term state: {n} "
        "(0 = chronic INSUFFICIENT_DATA, NP5+8 violation risk)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ack",
        action="store_true",
        help="Operator acknowledges no critical complaints (C5).",
    )
    args = parser.parse_args()

    checks = [
        ("C1 diff_log_health", check_diff_log_health),
        ("C2 recent_tick_coverage", check_recent_tick_coverage),
        ("C3 live_ledger_per_type", check_live_ledger_per_type),
        ("C4 live_trend_state", check_live_trend_state),
    ]

    print("=" * 72)
    print(f"Mode C readiness check — {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print("=" * 72)

    all_ok = True
    for name, fn in checks:
        ok, detail = fn()
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {name}")
        print(f"         {detail}")
        all_ok = all_ok and ok

    if args.ack:
        print("  [PASS] C5 operator_complaint_ack")
        print("         operator confirmed no critical complaints (--ack)")
    else:
        print("  [SKIP] C5 operator_complaint_ack")
        print("         pass --ack to assert; required for final go-decision")
        all_ok = False

    print("=" * 72)
    if all_ok:
        print("READY — flip V2_API_ENABLED default to true and start v1 sunset T+90d countdown")
        return 0
    print("NOT READY — address failing conditions before Mode C flip")
    return 1


if __name__ == "__main__":
    sys.exit(main())
