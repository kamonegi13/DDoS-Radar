#!/usr/bin/env python3
"""One-shot remediation for the 2026-07-03 TL-scale-inversion incident.

Run INSIDE the noroshi container AFTER deploying the fixed image:

    docker exec noroshi python3 scripts/remediate_inverted_calibration.py

What it does (idempotent; safe to re-run):

  1. Exports every auto:* row of ``analyst_feedback`` to a gzipped JSON
     side-file in the persistence volume, then deletes them. All ~30k
     rows were produced by the inverted ground-truth classifier
     (rewarding calm calls, punishing alerts) and/or per-tick
     pseudo-replication — they are unusable as calibration evidence.
  2. Resets every ACTIVE ``auto:tl_calibrator`` threshold override to the
     ``derive_tl()`` defaults via a new auditable threshold_history row
     (state machine preserved: old row → 'superseded', new row → 'active',
     ``revertible_to_id`` points back). The calibrator had re-applied a
     -5% loosening 12 times on middle_east from the same frozen inverted
     evidence, nearly halving its thresholds.

Uses raw sqlite3 on purpose — importing the radar package would boot the
app stack. Runs a single IMMEDIATE transaction per step.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
import time

DB_PATH = os.environ.get("RADAR_DB_PATH", "/app/radar/persistence/radar.db")
EXPORT_DIR = os.path.dirname(DB_PATH)

# Mirror of radar.scoring.derive_tl() defaults (THRESHOLD_REF in
# radar/conclusions/threat_level.py).
DEFAULT_TL_THRESHOLDS = {
    "tl1_total": 9.0,
    "tl1_physical": 3.0,
    "tl2_total": 6.0,
    "tl3_total": 4.0,
    "tl4_total": 2.0,
}

INCIDENT_REF = "incident_reset:2026-07-03_tl_scale_inversion"
RESET_APPLIED_BY = "analyst:remediation_2026-07-04"


def purge_auto_labels(conn) -> dict:
    rows = conn.execute(
        "SELECT id, conclusion_id, label, analyst_id, observed_at, "
        "observed_outcome_url, notes FROM analyst_feedback "
        "WHERE analyst_id LIKE 'auto:%'"
    ).fetchall()
    if not rows:
        return {"purged": 0, "export": None}

    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    export_path = os.path.join(
        EXPORT_DIR, f"auto_labels_purged-{stamp}.json.gz"
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
                "auto labels produced by TL-scale-inverted classifier "
                "and per-tick pseudo-replication; see "
                "docs/design/v2-migration.md"
            ),
            "rows": payload,
        }, f)

    conn.execute("BEGIN IMMEDIATE")
    conn.execute("DELETE FROM analyst_feedback WHERE analyst_id LIKE 'auto:%'")
    conn.commit()
    return {"purged": len(rows), "export": export_path}


def reset_calibrator_thresholds(conn) -> list[dict]:
    active = conn.execute(
        "SELECT id, key, value, scope_scenario_id FROM threshold_history "
        "WHERE state = 'active' AND applied_by = 'auto:tl_calibrator'"
    ).fetchall()
    results: list[dict] = []
    now = time.time()
    conn.execute("BEGIN IMMEDIATE")
    for row_id, key, value, scenario_id in active:
        band = key.rsplit(".", 1)[-1]
        default = DEFAULT_TL_THRESHOLDS.get(band)
        if default is None:
            results.append({"key": key, "skipped": "unknown band"})
            continue
        prior = float(value)
        magnitude_pct = abs(default - prior) / prior * 100.0 if prior else 0.0
        conn.execute(
            "UPDATE threshold_history SET state='superseded', effective_to=? "
            "WHERE id=?",
            (now, row_id),
        )
        cur = conn.execute(
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
                        "override chain was driven by inverted ground-truth "
                        "labels (fn counted alerts as misses); resetting to "
                        "derive_tl defaults until clean evidence accumulates"
                    ),
                    "prior_value": prior,
                    "default_value": default,
                }),
                magnitude_pct,
            ),
        )
        results.append({
            "key": key, "prior": prior, "reset_to": default,
            "new_row_id": cur.lastrowid,
        })
    conn.commit()
    return results


def main() -> int:
    import sqlite3
    if not os.path.exists(DB_PATH):
        print(f"DB not found: {DB_PATH}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(DB_PATH, timeout=60)
    try:
        purge = purge_auto_labels(conn)
        print(f"[1/2] auto labels purged: {purge['purged']} "
              f"(export: {purge['export']})")
        resets = reset_calibrator_thresholds(conn)
        for r in resets:
            print(f"[2/2] {r}")
        if not resets:
            print("[2/2] no active auto:tl_calibrator overrides — "
                  "nothing to reset")
    finally:
        conn.close()
    print("remediation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
