#!/usr/bin/env python3
"""One-shot remediation for the 2026-08-02 cross-scenario attribution incident.

Run INSIDE the noroshi container AFTER deploying the fixed image:

    docker exec noroshi python3 scripts/remediate_cross_scenario_labels.py          # dry run
    docker exec noroshi python3 scripts/remediate_cross_scenario_labels.py --apply

Background: RSS ground-truth episodes were attributed to every scenario in
which the article's country was ANY participant. Supporting-role members
(US / CN / JP primary_ally, forward_base, strategic_observer …) pulled
articles about OTHER conflicts into a scenario's ground truth — 12/15
korean_peninsula FALSE_NEGATIVEs in the 30-day window were Iran / Ukraine /
China-strategic articles, and that frozen FN set drove four consecutive
-5% auto:tl_calibrator loosening proposals (07-21/24/27/30).

What it does (idempotent; safe to re-run):

  1. Selects every ``auto:rss`` row of ``analyst_feedback`` whose episode
     tag (``episode=<scenario>/<CC>/<day>``) anchors on a country that is
     NOT a conflict party of that scenario (roles outside
     adversary / primary_target / principal_belligerent / proxy_front),
     exports them to a gzipped JSON side-file in the persistence volume,
     then deletes them. Correctly-attributed rows are untouched.
     auto:gdelt / auto:acled / auto:horizon rows carry no per-row country
     tag and are left in place (few rows; the deployed code gate stops
     new contamination from those sources).
  2. Resets every ACTIVE ``auto:tl_calibrator`` threshold override to the
     ``derive_tl()`` defaults via a new auditable threshold_history row
     (old row → 'superseded', new row → 'active', ``revertible_to_id``
     points back). Note these overrides were never consumed by live
     scoring (application is gated on a future flag) — this is ledger
     hygiene, not a behavior change.

Attribution sets are read from the DB ``scenario_participants`` table
(live admin config) with geo_data.json presets as fallback per scenario.
Uses raw sqlite3 on purpose — importing the radar package would boot the
app stack.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import time
from collections import Counter

DB_PATH = os.environ.get("RADAR_DB_PATH", "/app/radar/persistence/radar.db")
GEO_PATH = os.environ.get("RADAR_GEO_PATH", "/app/geo_data.json")
EXPORT_DIR = os.path.dirname(DB_PATH)

# Mirror of radar.scenarios.CONFLICT_PARTY_ROLES (raw-sqlite script, no import).
CONFLICT_PARTY_ROLES = frozenset({
    "adversary", "primary_target", "principal_belligerent", "proxy_front",
})

# Mirror of radar.scoring.derive_tl() defaults.
DEFAULT_TL_THRESHOLDS = {
    "tl1_total": 9.0,
    "tl1_physical": 3.0,
    "tl2_total": 6.0,
    "tl3_total": 4.0,
    "tl4_total": 2.0,
}

INCIDENT_REF = "incident_reset:2026-08-02_cross_scenario_attribution"
RESET_APPLIED_BY = "analyst:remediation_2026-08-02"

_EPISODE_RE = re.compile(r"^episode=([a-z0-9_]+)/([A-Z]{2})/(\d{4}-\d{2}-\d{2})")


def load_attribution_sets(conn) -> dict[str, frozenset[str]]:
    """scenario_id → conflict-party countries. DB rows (live admin config)
    take precedence per scenario; geo_data.json presets fill the rest."""
    sets: dict[str, set[str]] = {}
    try:
        with open(GEO_PATH, encoding="utf-8") as f:
            geo = json.load(f)
        for sid, sc in (geo.get("SCENARIOS") or {}).items():
            sets[sid] = {
                cc for cc, p in (sc.get("participants") or {}).items()
                if p.get("role") in CONFLICT_PARTY_ROLES
            }
    except (OSError, ValueError) as exc:
        print(f"warning: cannot read presets from {GEO_PATH}: {exc}",
              file=sys.stderr)

    try:
        rows = conn.execute(
            "SELECT scenario_id, country, role FROM scenario_participants"
        ).fetchall()
    except Exception as exc:  # noqa: BLE001 — table may not exist
        print(f"warning: scenario_participants unavailable: {exc}",
              file=sys.stderr)
        rows = []
    db_side: dict[str, set[str]] = {}
    for sid, cc, role in rows:
        db_side.setdefault(sid, set())
        if role in CONFLICT_PARTY_ROLES:
            db_side[sid].add(cc)
    sets.update(db_side)  # DB config wins where present
    return {sid: frozenset(v) for sid, v in sets.items()}


def find_contaminated(conn, attribution: dict[str, frozenset[str]]):
    """Return (contaminated_rows, stats). A row is contaminated when its
    episode anchor country is not a conflict party of its scenario."""
    rows = conn.execute(
        "SELECT id, conclusion_id, label, analyst_id, observed_at, "
        "observed_outcome_url, notes FROM analyst_feedback "
        "WHERE analyst_id = 'auto:rss' AND notes LIKE 'episode=%'"
    ).fetchall()
    contaminated = []
    stats: Counter[str] = Counter()
    for r in rows:
        m = _EPISODE_RE.match(r[6] or "")
        if not m:
            stats["unparseable_note"] += 1
            continue
        scenario_id, country = m.group(1), m.group(2)
        allowed = attribution.get(scenario_id)
        if allowed is None:
            stats["unknown_scenario_kept"] += 1
            continue
        if country in allowed:
            stats["kept"] += 1
            continue
        contaminated.append(r)
        stats[f"purge:{scenario_id}/{r[2]}"] += 1
    return contaminated, stats


def purge_rows(conn, rows, *, apply: bool) -> dict:
    if not rows:
        return {"purged": 0, "export": None}
    if not apply:
        return {"purged": len(rows), "export": "(dry run — no export written)"}

    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    export_path = os.path.join(
        EXPORT_DIR, f"cross_scenario_labels_purged-{stamp}.json.gz"
    )
    payload = [
        {
            "id": r[0], "conclusion_id": r[1], "label": r[2],
            "analyst_id": r[3], "observed_at": r[4],
            "observed_outcome_url": r[5], "notes": r[6],
        }
        for r in rows
    ]
    with gzip.open(export_path, "wt", encoding="utf-8") as f:
        json.dump({
            "incident": INCIDENT_REF,
            "exported_at": time.time(),
            "reason": (
                "episode anchored on a supporting-role participant — the "
                "article describes another conflict; see "
                "docs/design/v2-migration.md §0.0"
            ),
            "rows": payload,
        }, f)

    conn.execute("BEGIN IMMEDIATE")
    conn.executemany(
        "DELETE FROM analyst_feedback WHERE id = ?",
        [(r[0],) for r in rows],
    )
    conn.commit()
    return {"purged": len(rows), "export": export_path}


def reset_calibrator_thresholds(conn, *, apply: bool) -> list[dict]:
    active = conn.execute(
        "SELECT id, key, value, scope_scenario_id FROM threshold_history "
        "WHERE state = 'active' AND applied_by = 'auto:tl_calibrator'"
    ).fetchall()
    results: list[dict] = []
    now = time.time()
    if apply:
        conn.execute("BEGIN IMMEDIATE")
    for row_id, key, value, scenario_id in active:
        band = key.rsplit(".", 1)[-1]
        default = DEFAULT_TL_THRESHOLDS.get(band)
        if default is None:
            results.append({"key": key, "skipped": "unknown band"})
            continue
        prior = float(value)
        results.append({"key": key, "prior": prior, "reset_to": default})
        if not apply:
            continue
        magnitude_pct = abs(default - prior) / prior * 100.0 if prior else 0.0
        conn.execute(
            "UPDATE threshold_history SET state='superseded', effective_to=? "
            "WHERE id=?",
            (now, row_id),
        )
        conn.execute(
            "INSERT INTO threshold_history "
            "(emitted_at, key, value, scope_scenario_id, effective_from, "
            " effective_to, derived_from, applied_by, revertible_to_id, "
            " sample_n, formula_ref, evidence_json, magnitude_pct, state) "
            "VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, 0, ?, ?, ?, 'active')",
            (
                now, key, str(default), scenario_id, now,
                INCIDENT_REF, RESET_APPLIED_BY, row_id,
                "manual_reset#derive_tl_defaults",
                json.dumps({
                    "reason": (
                        "loosening chain was motivated by cross-scenario "
                        "attributed FALSE_NEGATIVEs (articles about other "
                        "conflicts); resetting to derive_tl defaults until "
                        "clean evidence accumulates"
                    ),
                    "prior_value": prior,
                    "default_value": default,
                }),
                magnitude_pct,
            ),
        )
    if apply:
        conn.commit()
    return results


def main() -> int:
    import sqlite3
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true",
                        help="Write changes (default: dry run, report only)")
    args = parser.parse_args()

    if not os.path.exists(DB_PATH):
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(DB_PATH, timeout=60)
    mode = "APPLY" if args.apply else "DRY RUN"
    try:
        attribution = load_attribution_sets(conn)
        print(f"[{mode}] attribution sets:")
        for sid, cs in sorted(attribution.items()):
            print(f"    {sid}: {sorted(cs)}")

        contaminated, stats = find_contaminated(conn, attribution)
        print(f"[{mode}] label audit:")
        for k, v in sorted(stats.items()):
            print(f"    {k}: {v}")
        purge = purge_rows(conn, contaminated, apply=args.apply)
        print(f"[1/2] contaminated auto:rss labels: {purge['purged']} "
              f"(export: {purge['export']})")

        resets = reset_calibrator_thresholds(conn, apply=args.apply)
        for r in resets:
            print(f"[2/2] {r}")
        if not resets:
            print("[2/2] no active auto:tl_calibrator overrides — "
                  "nothing to reset")
    finally:
        conn.close()
    print(f"remediation {'complete' if args.apply else 'dry run only'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
