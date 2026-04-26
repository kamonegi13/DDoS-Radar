"""Auto-correlate v2 conclusions with ACLED + GDELT — ADR-V2-005.

Iterates the ``conclusions`` ledger over a configurable window, pulls
ACLED political-violence events for each scenario's participant countries,
mixes in GDELT tone spikes already cached in ``gdelt_dow``, and writes
auto-labeled rows into ``analyst_feedback`` (analyst_id ``auto:acled`` /
``auto:gdelt`` / ``auto:both``).

Idempotent: a (conclusion_id, analyst_id) pair already present in
``analyst_feedback`` is skipped, so this script can run on a cron without
double-labeling.

Gated on ``V2_GROUND_TRUTH_ETL_ENABLED=true`` (NP3: opt-in). When the flag
is off, the script exits with status 0 and a warning so cron drops it
without alerting on success.

Usage:
    python scripts/run_ground_truth_etl.py [--db PATH]
                                            [--since EPOCH]
                                            [--until EPOCH]
                                            [--scenario SCENARIO_ID]
                                            [--limit N]
                                            [--dry-run]
                                            [--no-gdelt]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections import Counter, defaultdict
from typing import Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault(
    "V2_NP7_DISCLAIMER",
    "This output is one node in your intelligence process.",
)

from radar import config  # noqa: E402
from radar.conclusions.feedback import save_feedback  # noqa: E402
from radar.conclusions.ground_truth_etl import (  # noqa: E402
    AutoFeedback,
    EvidenceSource,
    ExternalEvent,
    classify_conclusion,
    has_existing_auto_feedback,
    list_conclusions_in_window,
)
from radar.database import RadarDB  # noqa: E402
from radar.scenarios import scenario_store  # noqa: E402
from radar.sensors.acled import fetch_events as fetch_acled_events  # noqa: E402

log = logging.getLogger("ground_truth_etl")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# GDELT tone spike conversion: a same-weekday Z-score below -2.0 is the
# threshold the live sensor uses for ALERT (radar/sensors/gdelt.py:73).
# We mirror that threshold here so auto-correlation aligns with what the
# tool was already calling sentiment escalation. severity is ordinal:
# 1 = single-day negative spike, 2 = sustained 3+ days.
_GDELT_SPIKE_Z_THRESHOLD = -2.0
_GDELT_SUSTAINED_DAYS = 3


def _gdelt_evidence_for_scenario(
    db: RadarDB,
    countries: list[str],
    since: float,
    until: float,
) -> list[ExternalEvent]:
    """Read recent GDELT same-weekday tones from ``gdelt_dow`` and emit one
    ``ExternalEvent`` per day-bucket whose Z-score crosses the spike
    threshold. Skips countries with too little baseline (the live sensor
    falls back to a static threshold below 7 samples; we are stricter here
    because false positives in the auto-feedback ledger waste analyst
    review time)."""
    out: list[ExternalEvent] = []
    for cc in countries:
        rows = db._get_conn().execute(  # noqa: SLF001
            "SELECT day_bucket, weekday, tone FROM gdelt_dow "
            "WHERE theater = ? AND day_bucket >= ? AND day_bucket <= ? "
            "ORDER BY day_bucket ASC",
            (cc, int(since - 86400 * 28), int(until)),
        ).fetchall()
        if not rows:
            continue
        # Rebuild per-weekday baselines from the same table.
        by_weekday: dict[int, list[float]] = defaultdict(list)
        for r in rows:
            by_weekday[int(r["weekday"])].append(float(r["tone"]))

        consecutive_spikes = 0
        for r in rows:
            db_bucket = int(r["day_bucket"])
            if db_bucket < since or db_bucket > until:
                continue
            wd = int(r["weekday"])
            samples = [t for t in by_weekday[wd] if t != float(r["tone"])]
            if len(samples) < 5:
                continue
            mean = sum(samples) / len(samples)
            std = max(
                (sum((x - mean) ** 2 for x in samples) / len(samples)) ** 0.5,
                0.5,
            )
            z = (float(r["tone"]) - mean) / std
            if z >= _GDELT_SPIKE_Z_THRESHOLD:
                consecutive_spikes = 0
                continue
            consecutive_spikes += 1
            severity = 2 if consecutive_spikes >= _GDELT_SUSTAINED_DAYS else 1
            out.append(ExternalEvent(
                source=EvidenceSource.GDELT,
                country=cc,
                event_at=float(db_bucket),
                severity=severity,
                url="https://api.gdeltproject.org/api/v2/doc/doc",
                summary=(
                    f"gdelt dow_z={z:.2f} tone={float(r['tone']):.2f} "
                    f"streak={consecutive_spikes}"
                ),
            ))
    return out


def _acled_evidence_for_scenario(
    countries: list[str],
    since: float,
    until: float,
) -> list[ExternalEvent]:
    """Wrap :func:`fetch_acled_events` with severity assignment.

    Severity = max(1, fatalities). Caps at fatality count itself so the
    FALSE_NEGATIVE rule (``severity >= GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES``)
    composes naturally without a separate threshold.
    """
    raw = fetch_acled_events(
        countries, since_epoch=since, until_epoch=until,
    )
    out: list[ExternalEvent] = []
    for ev in raw:
        out.append(ExternalEvent(
            source=EvidenceSource.ACLED,
            country=ev.country,
            event_at=ev.event_at,
            severity=max(1, ev.fatalities),
            url=ev.source_url,
            summary=(
                f"acled {ev.event_type}/{ev.sub_event_type} "
                f"fatalities={ev.fatalities} loc={ev.location}"
            ),
        ))
    return out


def _participants_for(scenario_id: str) -> list[str]:
    """Look up the scenario's participant ISO-2 codes. Returns ``[]`` if
    the scenario is unknown (deleted, renamed) — the conclusion still gets
    skipped, not crashed."""
    sc = scenario_store.get(scenario_id)
    if sc is None:
        return []
    return sorted(sc.participants.keys())


def run_etl(
    db: RadarDB,
    *,
    since: float,
    until: float,
    scenario_filter: Optional[str] = None,
    limit: int = 1000,
    dry_run: bool = False,
    enable_gdelt: bool = True,
) -> dict:
    """Drive one ETL pass. Returns a counter dict for the caller to log."""
    conclusions = list_conclusions_in_window(
        db, since=since, until=until, limit=limit,
    )
    if scenario_filter:
        conclusions = [c for c in conclusions if c.scenario_id == scenario_filter]

    by_scenario: dict[str, list] = defaultdict(list)
    for c in conclusions:
        by_scenario[c.scenario_id].append(c)

    counts: Counter[str] = Counter()
    counts["scanned"] = len(conclusions)

    for scenario_id, items in by_scenario.items():
        countries = _participants_for(scenario_id)
        if not countries:
            counts["skipped_no_participants"] += len(items)
            continue
        # Pull evidence once per scenario across the full window the
        # conclusions span; the classifier will narrow per-conclusion.
        ev_since = min(c.observed_at for c in items)
        ev_until = max(c.observed_at for c in items) + (
            config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS * 86400
        )
        acled = _acled_evidence_for_scenario(countries, ev_since, ev_until)
        gdelt = (
            _gdelt_evidence_for_scenario(db, countries, ev_since, ev_until)
            if enable_gdelt else []
        )
        evidence = acled + gdelt
        log.info(
            "scenario=%s conclusions=%d acled_events=%d gdelt_events=%d",
            scenario_id, len(items), len(acled), len(gdelt),
        )

        for c in items:
            verdict: Optional[AutoFeedback] = classify_conclusion(
                c, evidence, participant_countries=countries,
            )
            if verdict is None:
                counts["no_verdict"] += 1
                continue
            if has_existing_auto_feedback(db, c.id, verdict.analyst_id):
                counts["already_persisted"] += 1
                continue
            counts[f"label_{verdict.label.value}"] += 1
            if dry_run:
                counts["dry_run_skipped_write"] += 1
                continue
            save_feedback(db, verdict.to_analyst_feedback())
            counts["persisted"] += 1

    return dict(counts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default=None, help="DB path (default: config)")
    parser.add_argument(
        "--since", type=float, default=None,
        help="Earliest observed_at to scan (default: 14d ago)",
    )
    parser.add_argument(
        "--until", type=float, default=None,
        help="Latest observed_at to scan (default: now)",
    )
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-gdelt", action="store_true")
    parser.add_argument(
        "--force", action="store_true",
        help="Run even if V2_GROUND_TRUTH_ETL_ENABLED=false",
    )
    args = parser.parse_args()

    if not config.V2_GROUND_TRUTH_ETL_ENABLED and not args.force:
        log.warning(
            "V2_GROUND_TRUTH_ETL_ENABLED is false; exiting (use --force to override)"
        )
        return 0

    now = time.time()
    since = args.since if args.since is not None else now - 14 * 86400
    until = args.until if args.until is not None else now

    if args.db:
        os.environ["RADAR_DB_PATH"] = args.db
    db = RadarDB(os.environ.get("RADAR_DB_PATH", "radar/persistence/radar.db"))

    # ScenarioStore needs to be loaded so participant lookups work.
    if not scenario_store.loaded:
        from radar.config import _raw_geo
        scenario_store.load(_raw_geo)

    summary = run_etl(
        db,
        since=since, until=until,
        scenario_filter=args.scenario,
        limit=args.limit,
        dry_run=args.dry_run,
        enable_gdelt=not args.no_gdelt,
    )
    log.info("ETL summary: %s", summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
