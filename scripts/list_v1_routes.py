#!/usr/bin/env python3
"""List v1 routes and their residual access — staleness gate for Phase 4.

Used by the 2026-07-26 sunset routine (`v2-phase4-v1-sunset-removal`,
trig_018tXredTvRXKT58oEVE4PUk) to verify v1 traffic has actually decayed
before the routine opens the removal PR. Without this script the routine
would have to grep raw telemetry tables, which is fragile.

Reads ``SUNSETTED_V1_ROUTES`` from ``radar.conclusions.v1_sunset`` (single
source of truth) and joins with the legacy_telemetry observation table
(populated by Phase 1.4 SR4 since 2026-04-26).

Outputs:
    default            human-readable table
    --json             machine-readable JSON for the routine to parse
    --check-stale      exit 1 if any route saw access in the last 7 days
                       (run on 2026-07-26 morning to abort removal if a
                       caller is still hitting the v1 surface)

Usage examples:
    python scripts/list_v1_routes.py
    python scripts/list_v1_routes.py --json
    python scripts/list_v1_routes.py --check-stale --max-7d-hits 5
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Required by some module imports under radar.* — set before import.
os.environ.setdefault(
    "V2_NP7_DISCLAIMER",
    "This output is one node in your intelligence process.",
)


def _list_routes(*, db_path: Optional[str], now: float) -> list[dict[str, Any]]:
    """Return one record per declared v1 sunset route.

    Each record carries: pattern (regex source), successor_template,
    telemetry_key, sunset_date (ISO), days_remaining, count, last_seen,
    age_hours_since_last_seen.
    """
    from radar.conclusions.v1_sunset import (
        SUNSETTED_V1_ROUTES,
        SUNSET_DATE_EPOCH,
        SUNSET_DATE_HEADER,
    )
    from radar import legacy_telemetry as lt

    # Hydrate from the live DB so the in-memory snapshot reflects persisted
    # observation rows. Best-effort: skip silently if the DB isn't available
    # (e.g. running on a fresh checkout without radar.db).
    try:
        from radar.database import RadarDB
        if db_path:
            os.environ["RADAR_DB_PATH"] = db_path
        db = RadarDB(os.environ.get("RADAR_DB_PATH", "radar/persistence/radar.db"))
        lt.hydrate_from_db(db)
    except Exception as e:  # noqa: BLE001
        print(f"warn: could not hydrate from DB ({e}) — counts will be in-memory only",
              file=sys.stderr)

    snap = lt.snapshot()
    out: list[dict[str, Any]] = []
    for pattern, successor, telemetry_key in SUNSETTED_V1_ROUTES:
        stat = snap.get(telemetry_key)
        count = stat.count if stat else 0
        last_seen = stat.last_seen if stat else 0.0
        age_hours = (now - last_seen) / 3600.0 if last_seen > 0 else None
        out.append({
            "pattern": pattern.pattern,
            "successor_template": successor,
            "telemetry_key": telemetry_key,
            "sunset_date": SUNSET_DATE_HEADER,
            "sunset_epoch": SUNSET_DATE_EPOCH,
            "days_remaining": round((SUNSET_DATE_EPOCH - now) / 86400.0, 2),
            "count": count,
            "last_seen": last_seen,
            "age_hours_since_last_seen": (
                round(age_hours, 2) if age_hours is not None else None
            ),
        })
    return out


def _hits_in_window(records: list[dict[str, Any]], *, window_days: float) -> int:
    """Total hits whose last_seen falls within `window_days` from now."""
    cutoff = time.time() - window_days * 86400.0
    return sum(r["count"] for r in records if r["last_seen"] >= cutoff)


def _render_table(records: list[dict[str, Any]]) -> str:
    if not records:
        return "(no v1 sunset routes declared)"
    lines: list[str] = []
    lines.append(
        f"{'pattern':<48} {'count':>6} {'last_seen_age_h':>16} {'days_left':>10}"
    )
    lines.append("-" * 84)
    for r in records:
        age = (
            f"{r['age_hours_since_last_seen']:.1f}"
            if r["age_hours_since_last_seen"] is not None
            else "—"
        )
        lines.append(
            f"{r['pattern']:<48} "
            f"{r['count']:>6} "
            f"{age:>16} "
            f"{r['days_remaining']:>10.1f}"
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--db", default=None,
        help="DB path (default: $RADAR_DB_PATH or radar/persistence/radar.db)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON to stdout",
    )
    parser.add_argument(
        "--check-stale", action="store_true",
        help="Exit 1 if v1 routes saw access in the last 7 days "
             "(use on sunset day to abort removal when a caller is still hitting v1)",
    )
    parser.add_argument(
        "--max-7d-hits", type=int, default=5,
        help="--check-stale tolerance: total hits across all v1 routes in "
             "the trailing 7 days must be ≤ this value (default 5)",
    )
    args = parser.parse_args(argv)

    now = time.time()
    records = _list_routes(db_path=args.db, now=now)

    if args.json:
        print(json.dumps({
            "generated_at": now,
            "records": records,
            "hits_last_7d": _hits_in_window(records, window_days=7.0),
            "hits_last_24h": _hits_in_window(records, window_days=1.0),
        }, indent=2, sort_keys=True))
    else:
        print(_render_table(records))
        print()
        print(f"hits in last 24h: {_hits_in_window(records, window_days=1.0)}")
        print(f"hits in last 7d:  {_hits_in_window(records, window_days=7.0)}")

    if args.check_stale:
        recent = _hits_in_window(records, window_days=7.0)
        if recent > args.max_7d_hits:
            print(
                f"\nFAIL: v1 routes saw {recent} hits in the last 7 days "
                f"(tolerance: {args.max_7d_hits}). Removal PR should NOT proceed.",
                file=sys.stderr,
            )
            return 1
        print(
            f"\nOK: v1 routes saw {recent} hits in the last 7 days "
            f"(within tolerance {args.max_7d_hits}). Safe to remove."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
