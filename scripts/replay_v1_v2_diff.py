"""Offline v1/v2 conclusion-diff replay.

Phase 1.3 acceleration: instead of waiting 14 days for live shadow-write to
accumulate (v1 TL, v2 TL) pairs via the diff sampler, this script replays
historical `scenario_tl_observation` rows through the v2 derive_threat_level
builder and records the resulting diff in `conclusion_diff_log`.

Why this is sound:
- `scenario_tl_observation` row records the v1-side state at the time:
  scenario_id, observed_at, score, tl (post-hysteresis), cyber/physical/info,
  scoring_mode, active_countries.
- v2's `derive_threat_level()` is a pure function of (state.tl, state.score,
  domains, contributions). Given the recorded fields we can reconstruct a
  ScenarioState faithful enough to drive the builder.
- The v1 TL written into the row is post-hysteresis; we additionally compute
  the raw `derive_tl(score, [domains>0], physical)` and tag the diff metadata
  when the two disagree so analysts can filter hysteresis-only divergences
  out of the safety review.

Limitations (documented in Phase 1.3 §6):
- contributions are NOT recorded in scenario_tl_observation, so source_urls
  on the replayed Conclusion will be empty. Acceptable: source_urls do not
  affect TL state derivation, only audit_trace coverage.
- ATTACK_MODE / ANOMALY require contributions, so they are out of scope here.
- TREND requires the v2 ledger of THREAT_LEVEL; we replay TL only and let
  trend backfill happen organically once 24h of replayed TL rows exist.
- LLM prompt sha256 cannot be reconstructed (the prompt body wasn't logged
  pre-Mode B). Replayed rows have llm_prompt_sha256=None.

Usage:
    python scripts/replay_v1_v2_diff.py [--limit N] [--scenario ID]
                                        [--since EPOCH] [--dry-run]
                                        [--db PATH]

Default DB: radar/persistence/radar.db. The script is read-only against
scenario_tl_observation and append-only against conclusion_diff_log.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from typing import Iterable, Optional

# Allow `python scripts/replay_v1_v2_diff.py` from repo root.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# IMPORTANT: enable v2 flags BEFORE importing radar.* so module-level
# config snapshots see them. The replay must run regardless of what
# config.env has — we don't want to depend on the operator having
# Mode B already enabled to run the replay.
os.environ.setdefault("V2_CONCLUSION_LEDGER_ENABLED", "true")
os.environ.setdefault("V2_CONCLUSION_DIFF_SAMPLER_ENABLED", "true")

from radar.conclusions.base import ConclusionType  # noqa: E402
from radar.conclusions.threat_level import derive_threat_level  # noqa: E402
from radar.database import RadarDB  # noqa: E402
from radar.scoring import ScenarioState, derive_tl  # noqa: E402

log = logging.getLogger("replay_v1_v2_diff")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


REPLAY_TAG = "replay_v1_v2_diff/v1"

_INSERT_SQL = """
INSERT INTO conclusion_diff_log (
    sampled_at, scenario_id, conclusion_type,
    v1_state, v2_state, v2_conclusion_id,
    is_match, diff_kind, metadata
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--db",
        default=os.path.join(_REPO_ROOT, "radar", "persistence", "radar.db"),
        help="Path to radar.db",
    )
    p.add_argument("--scenario", help="Restrict replay to one scenario_id")
    p.add_argument(
        "--since",
        type=float,
        help="Only replay observations with observed_at >= this epoch",
    )
    p.add_argument(
        "--limit",
        type=int,
        help="Cap rows replayed (debug). Default: replay all in window.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute diffs but skip the conclusion_diff_log INSERT.",
    )
    p.add_argument(
        "--skip-already-replayed",
        action="store_true",
        default=True,
        help="Skip (scenario, sampled_at) pairs already present from a prior "
             "replay run with the same REPLAY_TAG. Default: on.",
    )
    return p.parse_args()


def _load_observations(
    db: RadarDB,
    *,
    scenario_id: Optional[str],
    since: Optional[float],
    limit: Optional[int],
) -> list[dict]:
    sql = (
        "SELECT scenario_id, observed_at, score, tl, "
        "       cyber, physical, info, convergence_bonus, "
        "       scoring_mode, active_countries "
        "FROM scenario_tl_observation "
        "WHERE 1=1"
    )
    params: list = []
    if scenario_id is not None:
        sql += " AND scenario_id = ?"
        params.append(scenario_id)
    if since is not None:
        sql += " AND observed_at >= ?"
        params.append(since)
    sql += " ORDER BY observed_at ASC"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)

    conn = db._get_conn()  # noqa: SLF001 — same internal helper used elsewhere
    cur = conn.execute(sql, params)
    rows = []
    for r in cur.fetchall():
        try:
            ac = json.loads(r["active_countries"]) if r["active_countries"] else []
        except (TypeError, ValueError):
            ac = []
        rows.append({
            "scenario_id": r["scenario_id"],
            "observed_at": float(r["observed_at"]),
            "score": float(r["score"]),
            "tl": int(r["tl"]) if r["tl"] is not None else None,
            "cyber": float(r["cyber"]),
            "physical": float(r["physical"]),
            "info": float(r["info"]),
            "convergence_bonus": float(r["convergence_bonus"]),
            "scoring_mode": r["scoring_mode"] or "full",
            "active_countries": ac if isinstance(ac, list) else [],
        })
    return rows


def _build_state(row: dict) -> ScenarioState:
    """Reconstitute ScenarioState from a stored observation row.

    contributions is empty (not persisted); domains carries the scalars.
    is_focused=True so the builder treats this as a scoring target.
    """
    return ScenarioState(
        scenario_id=row["scenario_id"],
        is_focused=True,
        scoring_mode=row["scoring_mode"],
        score=row["score"],
        domains={
            "cyber": row["cyber"],
            "physical": row["physical"],
            "info": row["info"],
        },
        active_countries=list(row["active_countries"]),
        convergence_bonus=row["convergence_bonus"],
        tl=row["tl"],
        contributions=[],
    )


def _classify(v1: Optional[str], v2: Optional[str]) -> str:
    if v1 is None and v2 is None:
        return "match"  # both insufficient — counted as agreement
    if v1 is None:
        return "v1_missing"
    if v2 is None:
        return "divergence"  # v2 should always emit something for a recorded v1
    return "match" if v1 == v2 else "divergence"


def _existing_replay_keys(db: RadarDB) -> set[tuple[str, float]]:
    """Return (scenario_id, sampled_at) pairs already replayed."""
    conn = db._get_conn()  # noqa: SLF001
    rows = conn.execute(
        "SELECT scenario_id, sampled_at, metadata "
        "FROM conclusion_diff_log "
        "WHERE conclusion_type = ?",
        (ConclusionType.THREAT_LEVEL.value,),
    ).fetchall()
    out = set()
    for r in rows:
        try:
            md = json.loads(r["metadata"])
        except (TypeError, ValueError):
            continue
        if md.get("replay_tag") == REPLAY_TAG:
            out.add((r["scenario_id"], float(r["sampled_at"])))
    return out


def _replay_one(
    db: RadarDB,
    row: dict,
    *,
    dry_run: bool,
) -> dict:
    state = _build_state(row)
    v1_post_hysteresis = state.tl  # what was actually emitted to UI/storage

    # Re-derive raw TL so we can flag hysteresis-only differences.
    active_domains = [d for d, v in state.domains.items() if v > 0]
    v1_raw_tl = derive_tl(state.score, active_domains, state.domains["physical"])

    v2_conclusion = derive_threat_level(db, state, now=row["observed_at"])
    v2_state = v2_conclusion.state  # str | None
    v1_state = str(v1_post_hysteresis) if v1_post_hysteresis is not None else None

    diff_kind = _classify(v1_state, v2_state)
    is_match = 1 if diff_kind == "match" else 0
    hysteresis_diff = (v1_raw_tl != v1_post_hysteresis) if v1_post_hysteresis is not None else False

    metadata = {
        "replay_tag": REPLAY_TAG,
        "score": round(state.score, 3),
        "scoring_mode": state.scoring_mode,
        "v1_raw_tl": v1_raw_tl,
        "v1_post_hysteresis_tl": v1_post_hysteresis,
        "hysteresis_applied": hysteresis_diff,
        "active_domain_count": len(active_domains),
        "physical": round(state.domains["physical"], 3),
        "v2_confidence": v2_conclusion.confidence,
    }

    if not dry_run:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                _INSERT_SQL,
                (
                    row["observed_at"], state.scenario_id,
                    ConclusionType.THREAT_LEVEL.value,
                    v1_state, v2_state, None,
                    is_match, diff_kind,
                    json.dumps(metadata, sort_keys=True),
                ),
            )

    return {
        "scenario_id": state.scenario_id,
        "observed_at": row["observed_at"],
        "v1_state": v1_state,
        "v2_state": v2_state,
        "diff_kind": diff_kind,
        "hysteresis_applied": hysteresis_diff,
    }


def main() -> int:
    args = _parse_args()
    if not os.path.exists(args.db):
        log.error("DB not found: %s", args.db)
        return 2

    db = RadarDB(args.db)
    rows = _load_observations(
        db,
        scenario_id=args.scenario,
        since=args.since,
        limit=args.limit,
    )
    log.info("loaded %d observation rows", len(rows))

    skip_keys: set[tuple[str, float]] = set()
    if args.skip_already_replayed and not args.dry_run:
        skip_keys = _existing_replay_keys(db)
        if skip_keys:
            log.info("skipping %d rows already replayed in a prior run",
                     len(skip_keys))

    counters: Counter = Counter()
    per_scenario: dict[str, Counter] = {}
    hysteresis_excluded_divergences = 0
    skipped = 0

    for row in rows:
        key = (row["scenario_id"], row["observed_at"])
        if key in skip_keys:
            skipped += 1
            continue
        try:
            r = _replay_one(db, row, dry_run=args.dry_run)
        except Exception:
            log.exception("replay failed for %s @ %s",
                          row["scenario_id"], row["observed_at"])
            counters["error"] += 1
            continue
        counters[r["diff_kind"]] += 1
        per_scenario.setdefault(row["scenario_id"], Counter())[r["diff_kind"]] += 1
        if r["diff_kind"] == "divergence" and r["hysteresis_applied"]:
            hysteresis_excluded_divergences += 1

    total = sum(counters.values()) or 1

    print()
    print("=" * 70)
    print(f"Replay summary  (dry_run={args.dry_run}, skipped={skipped})")
    print("=" * 70)
    print(f"Total replayed: {total}")
    for k in ("match", "divergence", "v1_missing", "error"):
        n = counters.get(k, 0)
        pct = (n / total) * 100
        print(f"  {k:14s} {n:6d}  ({pct:5.2f}%)")
    if hysteresis_excluded_divergences:
        adj_div = counters.get("divergence", 0) - hysteresis_excluded_divergences
        adj_match = counters.get("match", 0) + hysteresis_excluded_divergences
        adj_match_pct = (adj_match / total) * 100
        print(f"  hysteresis-excluded:")
        print(f"    adjusted match     {adj_match:6d}  ({adj_match_pct:5.2f}%)")
        print(f"    adjusted divergence{adj_div:6d}")
    print()
    print("Per-scenario breakdown:")
    for sid, c in sorted(per_scenario.items()):
        sub_total = sum(c.values()) or 1
        match_pct = (c.get("match", 0) / sub_total) * 100
        div = c.get("divergence", 0)
        print(f"  {sid:24s} match={c.get('match', 0):4d} "
              f"div={div:3d} v1_missing={c.get('v1_missing', 0):3d}  "
              f"({match_pct:5.2f}% match)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
