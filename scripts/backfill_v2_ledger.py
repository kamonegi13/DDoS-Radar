"""Offline v2 ledger backfill — Phase 1.3 deep observation acceleration.

`replay_v1_v2_diff.py` validates THREAT_LEVEL equivalence (v1 == v2) over
historical scenario_tl_observation rows. This script goes further: it
backfills the `conclusions` ledger with PER_DOMAIN, ATTACK_MODE, TREND, and
THREAT_LEVEL rows derived from those same observations, so:

  1. Builder code paths get exercised against 4400+ real states. Any
     exception, schema violation, or invariant break surfaces in seconds
     rather than waiting for live traffic to hit the same edge case.

  2. The ledger gets a chronologically faithful history, which immediately
     unblocks TREND derivation (24h/7d/30d windows previously had ≤3 rows
     from Mode B start). After backfill, 24h has hundreds.

  3. PER_DOMAIN's DEGRADING detection (which compares to the prior ledger
     row) becomes accurate from the first live tick after backfill.

  4. Cross-builder distribution stats (which ATTACK_MODE rules fire, what
     PER_DOMAIN states are common) become available for calibration before
     opt-in flip — without waiting 14 days.

What this script CANNOT cover:
  - ANOMALY: requires per-signal `state.contributions`, which were never
    persisted in scenario_tl_observation. ANOMALY backfill remains an
    organic Mode B accumulation.
  - LLM augmentation: prompt sha256 history wasn't logged pre-Mode B.

Idempotency:
  Each backfilled row carries `metadata.replay_tag = "backfill_v2_ledger/v1"`.
  Re-running this script with the same DB will skip rows already replayed
  (matched on (scenario_id, observed_at, conclusion_type, replay_tag)).
  Use `--rollback` to delete every row carrying the tag and re-run cleanly.

Usage:
    python scripts/backfill_v2_ledger.py [--db PATH]
                                          [--scenario ID]
                                          [--since EPOCH]
                                          [--limit N]
                                          [--builders tl,per_domain,attack_mode,trend]
                                          [--rollback]
                                          [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import traceback
from collections import Counter, defaultdict
from typing import Optional

# Allow `python scripts/backfill_v2_ledger.py` from repo root.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

# Ledger writes are gated on V2_CONCLUSION_LEDGER_ENABLED, but only for the
# in-process hook (_maybe_persist_*). save_conclusion() itself doesn't read
# the flag, so we don't need to set it. Set the disclaimer source though.
os.environ.setdefault("V2_NP7_DISCLAIMER",
                      "This output is one node in your intelligence process.")

from radar.conclusions.attack_mode import derive_attack_mode  # noqa: E402
from radar.conclusions.base import ConclusionType  # noqa: E402
from radar.conclusions.per_domain import derive_per_domain  # noqa: E402
from radar.conclusions.persistence import save_conclusion  # noqa: E402
from radar.conclusions.threat_level import derive_threat_level  # noqa: E402
from radar.conclusions.trend import derive_trend  # noqa: E402
from radar.database import RadarDB  # noqa: E402
from radar.scoring import ScenarioState  # noqa: E402

log = logging.getLogger("backfill_v2_ledger")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


REPLAY_TAG = "backfill_v2_ledger/v1"
ALL_BUILDERS = ("tl", "per_domain", "attack_mode", "trend")
ERROR_LOG_PATH = "/tmp/backfill_v2_ledger_errors.log"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--db",
        default=os.path.join(_REPO_ROOT, "radar", "persistence", "radar.db"),
    )
    p.add_argument("--scenario", help="Restrict to one scenario_id")
    p.add_argument("--since", type=float, help="observed_at >= this epoch")
    p.add_argument("--limit", type=int, help="Cap rows replayed (debug).")
    p.add_argument(
        "--builders",
        default=",".join(ALL_BUILDERS),
        help=(
            "Comma list of builders to replay. Order matters: tl must run "
            "before trend (trend reads tl rows from the ledger). Default: "
            "all four."
        ),
    )
    p.add_argument(
        "--rollback",
        action="store_true",
        help="Delete every row carrying replay_tag and exit (no replay).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute conclusions but skip ledger inserts.",
    )
    return p.parse_args()


def _load_observations(db, *, scenario_id, since, limit) -> list[dict]:
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
    sql += " ORDER BY observed_at ASC"  # chronological — DEGRADING/TREND need this
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)

    conn = db._get_conn()  # noqa: SLF001
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


def _existing_replay_keys(db) -> set[tuple[str, float, str]]:
    """Return (scenario_id, observed_at, conclusion_type) tuples already
    backfilled in a prior run, identified by metadata.replay_tag.

    SQLite json_extract is fine here — the ledger metadata column is JSON.
    """
    conn = db._get_conn()  # noqa: SLF001
    rows = conn.execute(
        "SELECT scenario_id, observed_at, conclusion_type "
        "FROM conclusions "
        "WHERE json_extract(metadata, '$.replay_tag') = ?",
        (REPLAY_TAG,),
    ).fetchall()
    return {(r["scenario_id"], float(r["observed_at"]), r["conclusion_type"])
            for r in rows}


def _rollback(db) -> int:
    """Delete every row carrying our REPLAY_TAG. Returns rows deleted."""
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        cur = conn.execute(
            "DELETE FROM conclusions "
            "WHERE json_extract(metadata, '$.replay_tag') = ?",
            (REPLAY_TAG,),
        )
        return cur.rowcount


_ERROR_FILE_OPENED = False
_ERROR_SAMPLE_LIMIT = 5
_error_samples_emitted: dict[str, int] = {}


def _record_error(builder: str, row: dict, exc: BaseException) -> None:
    """Record a per-row exception to the side log and emit a terse warning.

    Goal: keep stdout/context budget bounded even if every row of every
    builder fails. The first _ERROR_SAMPLE_LIMIT failures per builder still
    emit a one-line WARN to stdout so silent breakage is impossible; after
    that they only land in the side log.
    """
    global _ERROR_FILE_OPENED
    mode = "a" if _ERROR_FILE_OPENED else "w"
    with open(ERROR_LOG_PATH, mode, encoding="utf-8") as fh:
        if not _ERROR_FILE_OPENED:
            fh.write(
                f"# backfill_v2_ledger error log "
                f"(per-row tracebacks)\n"
            )
            _ERROR_FILE_OPENED = True
        fh.write(
            f"\n--- builder={builder} scenario={row['scenario_id']} "
            f"observed_at={row['observed_at']}\n"
        )
        fh.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    n = _error_samples_emitted.get(builder, 0)
    if n < _ERROR_SAMPLE_LIMIT:
        log.warning(
            "builder=%s exception (%s): %s @ %s — %s: %s "
            "(traceback in %s)",
            builder, n + 1, row["scenario_id"], row["observed_at"],
            type(exc).__name__, str(exc)[:120], ERROR_LOG_PATH,
        )
        _error_samples_emitted[builder] = n + 1
    elif n == _ERROR_SAMPLE_LIMIT:
        log.warning(
            "builder=%s further exceptions suppressed; see %s",
            builder, ERROR_LOG_PATH,
        )
        _error_samples_emitted[builder] = n + 1


def _stamp_replay_tag(c) -> None:
    """Inject replay_tag into the conclusion's metadata in-place.

    Conclusion is a frozen dataclass, so we must mutate the metadata dict
    before the row is written. This is safe because metadata is the only
    field we touch and Conclusion validates structure at __post_init__.
    """
    md = dict(c.metadata) if c.metadata else {}
    md["replay_tag"] = REPLAY_TAG
    object.__setattr__(c, "metadata", md)


def main() -> int:
    args = _parse_args()
    if not os.path.exists(args.db):
        log.error("DB not found: %s", args.db)
        return 2

    db = RadarDB(args.db)

    if args.rollback:
        n = _rollback(db)
        log.info("Rolled back %d replay-tagged rows. Exiting.", n)
        return 0

    builders = [b.strip() for b in args.builders.split(",") if b.strip()]
    unknown = set(builders) - set(ALL_BUILDERS)
    if unknown:
        log.error("Unknown builders: %s. Valid: %s", unknown, ALL_BUILDERS)
        return 2

    rows = _load_observations(
        db,
        scenario_id=args.scenario,
        since=args.since,
        limit=args.limit,
    )
    log.info("Loaded %d observation rows; builders=%s", len(rows), builders)

    skip_keys = set() if args.dry_run else _existing_replay_keys(db)
    if skip_keys:
        log.info("%d (scenario, observed_at, type) tuples already backfilled "
                 "— will skip", len(skip_keys))

    counts_by_builder: Counter = Counter()
    errors_by_builder: Counter = Counter()
    states_by_builder: defaultdict[str, Counter] = defaultdict(Counter)
    insufficient_by_builder: Counter = Counter()
    skipped_by_builder: Counter = Counter()

    # Per-scenario chronological replay so DEGRADING/TREND see prior rows
    # in the right order. We sort globally (already done in _load_observations)
    # then dispatch each (scenario, observed_at) tick once.
    for row in rows:
        state = _build_state(row)

        for builder in builders:
            key = (row["scenario_id"], row["observed_at"], _ct(builder).value)
            if key in skip_keys:
                skipped_by_builder[builder] += 1
                continue
            try:
                conclusion = _dispatch(builder, db, state, row["observed_at"])
            except Exception as exc:
                # Avoid flooding stdout/context: write per-row tracebacks to a
                # side log, surface a one-line warning here, and only show the
                # first few lines at INFO level. Summary at end will quote the
                # error log path so operators know where to look.
                _record_error(builder, row, exc)
                errors_by_builder[builder] += 1
                continue

            if conclusion is None:
                # trend may legitimately produce nothing during cold-start; treat
                # as INSUFFICIENT but still count.
                insufficient_by_builder[builder] += 1
                continue

            counts_by_builder[builder] += 1
            states_by_builder[builder][conclusion.state or "<unavailable>"] += 1
            if conclusion.state is None:
                insufficient_by_builder[builder] += 1

            if not args.dry_run:
                _stamp_replay_tag(conclusion)
                save_conclusion(db, conclusion)

    print()
    print("=" * 70)
    print(f"Backfill summary  (dry_run={args.dry_run})")
    print("=" * 70)
    total_errors = 0
    for builder in builders:
        n = counts_by_builder[builder]
        e = errors_by_builder[builder]
        ins = insufficient_by_builder[builder]
        skip = skipped_by_builder[builder]
        total_errors += e
        print(f"\nbuilder = {builder}")
        print(f"  written     {n:6d}   errors {e:3d}   insufficient {ins:5d}   "
              f"skipped(prior) {skip:5d}")
        print(f"  state distribution (top 10):")
        for s, k in states_by_builder[builder].most_common(10):
            sn = s if len(s) <= 60 else s[:57] + "..."
            print(f"    {sn:<60s}  {k:5d}")
    if total_errors:
        print()
        print(f"WARNING: {total_errors} per-row exceptions occurred. "
              f"Full tracebacks in: {ERROR_LOG_PATH}")
    return 0 if total_errors == 0 else 1


def _ct(builder: str) -> ConclusionType:
    return {
        "tl": ConclusionType.THREAT_LEVEL,
        "per_domain": ConclusionType.PER_DOMAIN,
        "attack_mode": ConclusionType.ATTACK_MODE,
        "trend": ConclusionType.TREND,
    }[builder]


def _dispatch(builder: str, db, state: ScenarioState, now: float):
    if builder == "tl":
        return derive_threat_level(db, state, now=now)
    if builder == "per_domain":
        return derive_per_domain(db, state, now=now)
    if builder == "attack_mode":
        return derive_attack_mode(state, now=now)
    if builder == "trend":
        return derive_trend(db, state.scenario_id, now=now)
    raise ValueError(f"unknown builder: {builder}")


if __name__ == "__main__":
    sys.exit(main())
