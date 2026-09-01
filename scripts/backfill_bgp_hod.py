#!/usr/bin/env python3
"""Backfill `bgp_hod` from RIPE Stat's real history — D2 H-05's repair.

**PRECONDITION — deploy the repaired sensor and RESTART it FIRST.** This
script is step (2) of a three-step order: (1) ship the `bgp_routing.py`
key fix to production and RESTART the process running it, (2) run this
backfill, (3) (S3) migrate. Skipping the restart before step (2) leaves
the OLD sensor process — still holding the broken key read — writing a
fresh `0.0` into the CURRENT hour's `bgp_hod` bucket every poll cycle,
which re-contaminates the history this script just repaired. This
script's own `_assert_no_live_sensor_writes()` refuses to run when it
sees a bucket that looks like the old sensor is still doing that (see its
docstring for the exact discriminator), but that check is a safety net,
not a substitute for getting the order right — it compares database
state, not process state, and a live sensor that has not written since
before the restart will not trip it.

H-05: `radar/sensors/bgp_routing.py` read `announced_prefixes` and
`seen_ases`, two keys `country-routing-stats` has never returned, so every
one of the 5,398 rows in the live `bgp_hod` table was exactly 0.0. Fixing
the key alone leaves a repaired reading pointed at a baseline of
fabricated zeros — a series discontinuity of F-16's shape — so the key fix
and this backfill are ONE change.

**RIPE serves the history the sensor only ever sampled one point of.**
`country-routing-stats` accepts `starttime` / `endtime` and picks a
resolution from the span. Measured once, 2026-08-09: windows up to and
including 28 days answered `resolution: 1h`; 29 days was the first
window to drop to `1d`. That is upstream's downsampling policy as
observed on that date, not a documented guarantee — it can move without
notice, which is why `collect_country()` halves and retries a window
RIPE answers below hourly (`ResolutionTooCoarse`) rather than trusting
the boundary to hold. The series is RUN-LENGTH ENCODED — one `stats`
entry per distinct value, with `timeline` listing EVERY interval over
which that value held — so a reader that takes one point per entry gets
~50 irregular samples from a 4-day window and assigns each to the hour
its FIRST interval started. That is the wrong hour for every later
interval, and an hour-of-day baseline filled that way measures something
other than the hour it is filed under. Expanding the timeline instead
yields one value per hour, gapless: 336 hours from a 14-day window,
verified against the span with zero gaps and zero duplicates for every
country sampled.

**The quantity is the live path's quantity, mechanically.** The samples
are computed by `v3.adapters.cyber.ripe_bgp.prefix_count`, and
`_assert_quantity_agrees` refuses to run unless the field names declared
in `radar/sensors/bgp_routing.py` are the same two. A baseline measuring
one thing and a reading compared against another is H-05's own family.

**The epoch.** Rows whose `prefix_count` is 0.0 are the dead epoch and are
deleted for every country this run touches. They hold no information —
0.0 there was the absence of a key, not a measurement — and merging them
with real values would drag the mean far below every real reading, which
suppresses the Z branch permanently rather than firing it. Rows with real
values are never deleted; buckets this run recomputes are overwritten with
the same value from the same source, so re-running is idempotent.

**An all-zero series is refused, not written.** `resource=ZZ` — any code
RIPE does not recognise — answers HTTP 200, `status: ok`,
`resolution: 1h`, with zero prefixes for every hour. One typo in
`--countries` would otherwise install 672 fabricated zeros: the exact
state this script exists to remove, and indistinguishable from a calm
world once it is in the ledger. See `AllZeroSeries`.

Idempotent, re-runnable, and safe to interrupt: each country commits on
its own, and a country that fails leaves the previous state untouched.

    python3 scripts/backfill_bgp_hod.py --db radar/persistence/radar.db
    python3 scripts/backfill_bgp_hod.py --db copy.db --dry-run
    python3 scripts/backfill_bgp_hod.py --db copy.db --report-only

Per-country tracebacks are side-written to `--errors-log`; stdout carries
the first few plus a summary (repo convention for long-running scripts).
"""
from __future__ import annotations

import argparse
import ast
import collections
import datetime
import json
import pathlib
import sqlite3
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

# v3's adapter is a pure module — importing it starts nothing. `radar.*` is
# deliberately NOT imported: `radar/__init__.py` builds the Flask app and
# launches background workers at import time, which a backfill must not do.
from v3.adapters.cyber.ripe_bgp import (  # noqa: E402
    RIS_ASN_KEY, RIS_PREFIX_KEYS, prefix_count)

RIPE_URL = "https://stat.ripe.net/data/country-routing-stats/data.json"
SOURCEAPP = "osint-radar"

HOUR_SEC = 3600
#: `radar/config.py` — `HOD_BASELINE_DAYS (28) * 24`, the per-country cap
#: `hod_record` enforces. The backfill enforces the same one.
HOD_MAX_ENTRIES = 672
#: `HOD_MIN_SAME_HOUR` — the predicate that decides whether a bucket is
#: warm. Reported, never worked around.
HOD_MIN_SAME_HOUR = 7

DEFAULT_DAYS = 28
#: Comfortably inside the measured `1h` band (4/8/16/20/24 days all
#: answered `1h`), not at its edge. A response that comes back coarser is
#: split and retried rather than trusted.
DEFAULT_WINDOW_DAYS = 14
MIN_WINDOW_DAYS = 2
DEFAULT_SLEEP_SEC = 3.0
DEFAULT_TIMEOUT_SEC = 45
DEFAULT_ERRORS_LOG = "/tmp/backfill_bgp_hod_errors.log"
EXPECTED_RESOLUTION = "1h"
#: How many per-country failures to print in full before deferring the
#: rest to the side log.
STDOUT_ERROR_LIMIT = 5


class BackfillError(RuntimeError):
    """Anything that makes one country's window unusable."""


class ResolutionTooCoarse(BackfillError):
    """RIPE downsampled below hourly for the span we asked for."""


class AllZeroSeries(BackfillError):
    """Every sample in the window is 0.0 — refused, not written.

    Measured: `resource=ZZ` (an unknown code) comes back HTTP 200,
    `status: ok`, `resolution: 1h`, with `v4_prefixes_ris: 0` and
    `v6_prefixes_ris: 0` for every hour. K02's shape — a query the
    upstream did not honour, answering 200 with content that reads as
    "measured, nothing there" — and it is H-05's shape exactly: a series
    of zeros that a baseline cannot tell from a calm world. A typo in
    `--countries` would otherwise install 672 fabricated zeros and leave
    that country's detector dead in the way this script exists to repair.

    A country that genuinely announced nothing for 28 days is the largest
    routing anomaly there is, and it wants an analyst, not a baseline.
    """


class LiveSensorGuardTripped(BackfillError):
    """A monitored country's newest `bgp_hod` bucket is a RECENT zero.

    That is the signature of the OLD (unrepaired) sensor still running —
    see `_assert_no_live_sensor_writes()`. Refuses rather than proceeds
    because this run would delete the dead epoch only for the still-live
    old sensor to refill it on its next poll.
    """


# ── the quantity contract ───────────────────────────────────────────────

def _production_constants() -> dict:
    """`RIS_PREFIX_KEYS` / `RIS_ASN_KEY` read out of production's sensor.

    Parsed rather than imported: importing `radar.sensors.bgp_routing`
    imports `radar`, which builds a Flask app and starts worker threads.
    """
    source = (REPO / "radar" / "sensors" / "bgp_routing.py").read_text()
    found: dict = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Assign):
            continue
        target = node.targets[0]
        if isinstance(target, ast.Name) and target.id in (
                "RIS_PREFIX_KEYS", "RIS_ASN_KEY"):
            found[target.id] = ast.literal_eval(node.value)
    return found


def _assert_quantity_agrees() -> None:
    """Refuse to write a baseline the live path will not read.

    Requirement 1 of the repair, enforced at run time rather than only in
    a test: if production and v3 ever name different fields, this script
    would fill `bgp_hod` with a series the sensor never compares against.
    """
    production = _production_constants()
    ours = {"RIS_PREFIX_KEYS": tuple(RIS_PREFIX_KEYS),
            "RIS_ASN_KEY": RIS_ASN_KEY}
    mismatches = [(name, production.get(name), value)
                  for name, value in sorted(ours.items())
                  if production.get(name) != value]
    if mismatches:
        raise BackfillError(
            "the quantity this backfill writes is not the quantity "
            "production reads — refusing (D2 H-05): " + "; ".join(
                f"{name}: production={was!r} backfill={ours!r}"
                for name, was, ours in mismatches))


# ── the live-sensor guard ───────────────────────────────────────────────
#
# `_assert_quantity_agrees()` above can only compare the two source files
# ON DISK — it cannot see whether the RUNNING sensor process has been
# restarted onto them. An operator who updates the checkout but does not
# restart the container leaves the OLD sensor writing a fresh 0.0 into
# the current hour's `bgp_hod` bucket every poll cycle. This section is
# that second check, enforced at run time because the ordering rule
# (`docs/design/v3/S3-data-migration.md`) lives in a document an operator
# can skip past — this codebase's own G-07 / F-06 shape.

def _sensor_poll_interval_sec() -> int:
    """`BgpRoutingSensor`'s own poll interval, read out of its source.

    Parsed rather than imported, for the same reason as
    `_production_constants()`: importing `radar.sensors.bgp_routing`
    imports `radar`, which builds a Flask app and starts worker threads.
    `BaseSensor.__init__(self, name, domain, poll_interval)` is the
    signature `BgpRoutingSensor.__init__` calls via `super().__init__(...)`;
    the third positional argument is the cadence in seconds. Read here
    rather than hardcoded so a change to the sensor's cadence moves this
    guard's threshold automatically instead of silently going stale.
    """
    source = (REPO / "radar" / "sensors" / "bgp_routing.py").read_text()
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "__init__"
                and isinstance(node.func.value, ast.Call)
                and isinstance(node.func.value.func, ast.Name)
                and node.func.value.func.id == "super"):
            continue
        if len(node.args) >= 3:
            return int(ast.literal_eval(node.args[2]))
    raise BackfillError(
        "could not read BgpRoutingSensor's poll interval out of "
        "radar/sensors/bgp_routing.py (super().__init__(name, domain, "
        "poll_interval) not found as expected) — the live-sensor guard "
        "has nothing to compare a bucket's age against, refusing to run "
        "blind rather than skipping the check silently")


#: A live sensor writes at most one `bgp_hod` bucket per HOUR — on the
#: first poll after the hour rolls over (`_bgp_hour_bucket` in
#: `BgpRoutingSensor.fetch`) — so a zero written by a sensor that only
#: just started can land anywhere within that hour depending on when in
#: its poll cycle the rollover happened. Twice the sensor's own poll
#: interval is "roughly one sensor cycle" with margin for that alignment
#: lag, not a second hardcoded number: it is derived from
#: `_sensor_poll_interval_sec()` at run time.
GUARD_ZERO_WINDOW_CYCLES = 2


def _assert_no_live_sensor_writes(connection: sqlite3.Connection,
                                  countries: list, *, now: float,
                                  override: bool) -> None:
    """Refuse if the OLD (unrepaired) sensor looks like it is still live.

    Requirement 2 of the repair. The discriminator: historical zeros are
    exactly what this run is about to delete and must NOT trip this
    guard — every row in the dead epoch is 0.0 by construction. Only a
    zero in a country's NEWEST bucket, younger than
    `GUARD_ZERO_WINDOW_CYCLES` sensor cycles, is evidence a writer is
    still live today. Two absences must not be misread as that evidence
    either: a `bgp_hod` table that does not exist yet (a fresh database)
    and a monitored country with no row at all (never backfilled, never
    written) both mean "nothing is known," not "the old sensor is
    running" — the guard passes both through.
    """
    if override:
        return
    table_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'bgp_hod'").fetchone()
    if not table_exists:
        return
    window = _sensor_poll_interval_sec() * GUARD_ZERO_WINDOW_CYCLES
    offenders = []
    for country in countries:
        row = connection.execute(
            "SELECT hour_bucket, prefix_count FROM bgp_hod "
            "WHERE theater = ? ORDER BY hour_bucket DESC LIMIT 1",
            (country,)).fetchone()
        if row is None:
            continue
        hour_bucket, prefix_count = row
        age = now - hour_bucket
        if prefix_count == 0.0 and age < window:
            offenders.append((country, age))
    if not offenders:
        return
    detail = ", ".join(f"{country} ({age:.0f}s old)"
                       for country, age in sorted(offenders))
    raise LiveSensorGuardTripped(
        f"refusing to run: {len(offenders)} monitored "
        f"{'country is' if len(offenders) == 1 else 'countries are'} "
        f"still getting a FRESH 0.0 bgp_hod bucket younger than "
        f"{window:.0f}s — {detail}. That is what the OLD, unrepaired "
        f"ripe_bgp sensor looks like: it writes a 0.0 into the current "
        f"hour's bucket every poll cycle. If the container running this "
        f"sensor has not been DEPLOYED with the key fix AND RESTARTED "
        f"yet (D2 H-05, radar/sensors/bgp_routing.py), stop and do that "
        f"first — running this backfill now would delete the dead epoch "
        f"only for the still-live old sensor to refill it on its next "
        f"cycle. If the sensor IS already restarted onto the repaired "
        f"code and this is a genuine reading, re-run with "
        f"--override-live-sensor-guard.")


# ── RIPE ────────────────────────────────────────────────────────────────

def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(
        ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ripe_time(text: str) -> float:
    """RIPE's naive ISO timestamps are UTC."""
    return datetime.datetime.fromisoformat(
        str(text).replace("Z", "")).replace(
            tzinfo=datetime.timezone.utc).timestamp()


def fetch_window(country: str, since: float, until: float, *,
                 timeout: int) -> dict:
    """One `country-routing-stats` response, or a raised BackfillError."""
    query = urllib.parse.urlencode({
        "resource": country, "starttime": _iso(since), "endtime": _iso(until),
        "sourceapp": SOURCEAPP})
    request = urllib.request.Request(
        f"{RIPE_URL}?{query}", headers={"User-Agent": "noroshi-backfill/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            document = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, OSError) as error:
        raise BackfillError(f"{country} {_iso(since)}..{_iso(until)}: "
                            f"{error}") from error
    data = document.get("data") or {}
    resolution = str(data.get("resolution") or "")
    if resolution != EXPECTED_RESOLUTION:
        raise ResolutionTooCoarse(
            f"{country} {_iso(since)}..{_iso(until)}: RIPE answered "
            f"resolution={resolution!r}, not {EXPECTED_RESOLUTION!r}")
    return data


def expand_timeline(data: dict) -> dict:
    """`{hour_bucket: prefix_count}` from a run-length encoded response.

    Each `stats` entry holds ONE value and a `timeline` of every interval
    it held over, endpoints inclusive (measured: an entry spanning
    06:00-07:00 is followed by a different entry at 08:00). Entries whose
    RIS view is absent are skipped, never stored as 0 — that translation
    is H-05 itself.
    """
    samples: dict = {}
    for entry in data.get("stats") or ():
        value = prefix_count(entry)
        if value is None:
            continue
        for interval in entry.get("timeline") or ():
            start = interval.get("starttime")
            if not start:
                continue
            first = _parse_ripe_time(start)
            last = _parse_ripe_time(interval.get("endtime") or start)
            if last < first:
                continue
            bucket = int(first // HOUR_SEC) * HOUR_SEC
            stop = int(last // HOUR_SEC) * HOUR_SEC
            while bucket <= stop:
                samples[bucket] = float(value)
                bucket += HOUR_SEC
    return samples


def collect_country(country: str, *, since: float, until: float,
                    window_days: int, sleep_sec: float, timeout: int,
                    on_request) -> dict:
    """Chained windows covering `since`..`until`. `{hour_bucket: value}`.

    A window RIPE answers below hourly is halved and retried, down to
    `MIN_WINDOW_DAYS`; the boundary between `1h` and `1d` was measured
    once and is not trusted to stay where it was.
    """
    samples: dict = {}
    cursor = since
    while cursor < until:
        span = min(window_days * 86400.0, until - cursor)
        samples.update(_collect_span(country, cursor, cursor + span,
                                     sleep_sec=sleep_sec, timeout=timeout,
                                     on_request=on_request))
        cursor += span
    return samples


def _collect_span(country: str, since: float, until: float, *,
                  sleep_sec: float, timeout: int, on_request) -> dict:
    on_request()
    time.sleep(sleep_sec)
    try:
        return expand_timeline(fetch_window(country, since, until,
                                            timeout=timeout))
    except ResolutionTooCoarse:
        if (until - since) <= MIN_WINDOW_DAYS * 86400.0:
            raise
        middle = since + (until - since) / 2.0
        merged = _collect_span(country, since, middle, sleep_sec=sleep_sec,
                               timeout=timeout, on_request=on_request)
        merged.update(_collect_span(country, middle, until,
                                    sleep_sec=sleep_sec, timeout=timeout,
                                    on_request=on_request))
        return merged


# ── the ledger ──────────────────────────────────────────────────────────

def monitored_countries(connection: sqlite3.Connection) -> list:
    """Every participant of every enabled scenario, sorted.

    `geo_data.json` holds the presets and the `scenarios` table holds the
    enable overrides, which is the same two-layer resolution
    `radar/scenarios.py` performs — done here directly because importing
    that module boots the application.

    A preset that omits `enabled` is ENABLED, matching production's Layer
    1 default (`_parse_scenario_json`, `radar/scenarios.py:302`:
    `bool(raw.get("enabled", True))`). Every preset in the live
    `geo_data.json` sets the key explicitly today, so this has no current
    effect — but treating an omitted key as disabled, as an earlier
    version of this function did, would silently drop a future preset's
    participants from the backfill scope while production keeps scoring
    them.
    """
    presets = json.loads((REPO / "geo_data.json").read_text()).get(
        "SCENARIOS") or {}
    overrides: dict = {}
    try:
        overrides = {str(row[0]): bool(row[1]) for row in connection.execute(
            "SELECT id, enabled FROM scenarios")}
    except sqlite3.Error:
        pass
    countries = set()
    for scenario_id, preset in presets.items():
        enabled = overrides.get(
            scenario_id, bool(preset.get("enabled", True)))
        if not enabled:
            continue
        countries.update(str(code).upper()
                         for code in (preset.get("participants") or {}))
    return sorted(countries)


def dead_epoch_rows(connection: sqlite3.Connection, country: str) -> int:
    return int(connection.execute(
        "SELECT COUNT(*) FROM bgp_hod WHERE theater = ? AND prefix_count = 0.0",
        (country,)).fetchone()[0])


def write_country(connection: sqlite3.Connection, country: str,
                  samples: dict) -> dict:
    """Delete the dead epoch, upsert the real series, trim to the window.

    The trim is `hod_record`'s own (`radar/database.py:3173-3191`): keep
    the newest `HOD_MAX_ENTRIES` buckets per country, a count of buckets
    rather than a span of days.
    """
    removed = dead_epoch_rows(connection, country)
    with connection:
        connection.execute(
            "DELETE FROM bgp_hod WHERE theater = ? AND prefix_count = 0.0",
            (country,))
        connection.executemany(
            "INSERT INTO bgp_hod (theater, hour_bucket, prefix_count) "
            "VALUES (?, ?, ?) ON CONFLICT (theater, hour_bucket) "
            "DO UPDATE SET prefix_count = excluded.prefix_count",
            [(country, bucket, value) for bucket, value in
             sorted(samples.items())])
        connection.execute(
            "DELETE FROM bgp_hod WHERE theater = ? AND hour_bucket NOT IN ("
            "  SELECT hour_bucket FROM bgp_hod WHERE theater = ? "
            "  ORDER BY hour_bucket DESC LIMIT ?)",
            (country, country, HOD_MAX_ENTRIES))
    return {"zero_rows_deleted": removed, "rows_written": len(samples)}


def bucket_distribution(connection: sqlite3.Connection, country: str) -> dict:
    """Per hour-of-day sample counts, as `hod_same_hour` would see them."""
    counts = collections.Counter()
    for (bucket,) in connection.execute(
            "SELECT hour_bucket FROM bgp_hod WHERE theater = ?", (country,)):
        counts[(int(bucket) // HOUR_SEC) % 24] += 1
    per_hour = {hour: counts.get(hour, 0) for hour in range(24)}
    warm = [hour for hour, n in per_hour.items() if n >= HOD_MIN_SAME_HOUR]
    return {"per_hour": per_hour, "warm_buckets": len(warm),
            "cold_buckets": 24 - len(warm),
            "min_samples": min(per_hour.values()),
            "max_samples": max(per_hour.values()),
            "total_rows": sum(per_hour.values())}


# ── driver ──────────────────────────────────────────────────────────────

def _log_failure(path: pathlib.Path, country: str, error: BaseException,
                 shown: int) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(f"\n=== {country} @ {_iso(time.time())} ===\n")
        handle.write("".join(traceback.format_exception(
            type(error), error, error.__traceback__)))
    if shown < STDOUT_ERROR_LIMIT:
        print(f"  ! {country}: {error}")
    elif shown == STDOUT_ERROR_LIMIT:
        print(f"  ! (further failures in {path} only)")


#: Shown in `--help` (epilog) and in the module docstring above — the same
#: precondition stated twice on purpose. A rule that lives only in a
#: design doc gets skipped (this codebase's own G-07 / F-06 pattern); a
#: rule that also lives in `--help` is in front of the operator at the
#: moment they are about to run this.
PRECONDITION_HELP = (
    "PRECONDITION: deploy the repaired ripe_bgp sensor and RESTART the "
    "process running it BEFORE running this backfill. If the old, "
    "unrepaired sensor is still running when this backfill runs, it keeps "
    "writing a fresh 0.0 into the CURRENT hour's bgp_hod bucket every "
    "poll cycle, re-contaminating the history this backfill just wrote. "
    "Order: (1) deploy + restart the sensor, (2) run this script, "
    "(3) migrate (S3). This script also checks the database for the "
    "signature of a still-live old sensor at run time (see "
    "--override-live-sensor-guard) as a safety net, not a substitute for "
    "the restart.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0], epilog=PRECONDITION_HELP)
    parser.add_argument("--db", required=True,
                        help="SQLite path. NEVER the live database while "
                             "the container is running (WAL visibility).")
    parser.add_argument("--countries", default="",
                        help="Comma-separated ISO2 codes. Default: every "
                             "participant of every enabled scenario.")
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--window-days", type=int,
                        default=DEFAULT_WINDOW_DAYS)
    parser.add_argument("--sleep", type=float, default=DEFAULT_SLEEP_SEC,
                        help="Seconds between requests. Paced, not bursted.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--errors-log", default=DEFAULT_ERRORS_LOG)
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and report; write nothing.")
    parser.add_argument("--report-only", action="store_true",
                        help="Report the ledger as it stands; fetch nothing.")
    parser.add_argument("--now", type=float, default=None,
                        help="Override the clock (tests, replay).")
    parser.add_argument("--override-live-sensor-guard", action="store_true",
                        help="Skip the check for a RECENTLY written 0.0 "
                             "bgp_hod bucket (the signature of the old, "
                             "unrepaired sensor still running). Use only "
                             "after confirming the sensor container has "
                             "actually been restarted onto the repaired "
                             "code, or that a fresh 0.0 is a genuine "
                             "reading.")
    args = parser.parse_args(argv)

    if args.window_days < MIN_WINDOW_DAYS:
        print(f"--window-days must be at least {MIN_WINDOW_DAYS}")
        return 2

    connection = sqlite3.connect(args.db)
    try:
        return _run(connection, args)
    finally:
        connection.close()


def _run(connection: sqlite3.Connection, args) -> int:
    countries = ([code.strip().upper()
                  for code in args.countries.split(",") if code.strip()]
                 or monitored_countries(connection))
    now = time.time() if args.now is None else args.now
    # The CURRENT hour is left to the live sensor: production records a
    # bucket once, on its first reading of that hour, and reads strictly
    # before it.
    until = int(now // HOUR_SEC) * HOUR_SEC
    since = until - args.days * 86400

    if args.report_only:
        _report(connection, countries)
        return 0

    _assert_quantity_agrees()
    _assert_no_live_sensor_writes(
        connection, countries, now=now,
        override=args.override_live_sensor_guard)
    errors_log = pathlib.Path(args.errors_log)
    print(f"[backfill_bgp_hod] {len(countries)} countries, "
          f"{args.days}d window ({_iso(since)}..{_iso(until)}), "
          f"{args.window_days}d chunks, {args.sleep}s spacing"
          + (" — DRY RUN" if args.dry_run else ""))

    requests_made = 0

    def _count_request():
        nonlocal requests_made
        requests_made += 1

    started = time.time()
    written: dict = {}
    failures = 0
    for country in countries:
        try:
            samples = collect_country(
                country, since=since, until=until,
                window_days=args.window_days, sleep_sec=args.sleep,
                timeout=args.timeout, on_request=_count_request)
            samples = {bucket: value for bucket, value in samples.items()
                       if since <= bucket < until}
            if not samples:
                raise BackfillError(f"{country}: RIPE returned no usable "
                                    f"sample in the window")
            if not any(samples.values()):
                raise AllZeroSeries(
                    f"{country}: every one of {len(samples)} samples is 0.0 "
                    f"— refusing to write. RIPE answers this way for a code "
                    f"it does not recognise (check the country), and an "
                    f"all-zero baseline is the defect this script repairs")
            newest = sorted(samples)[-HOD_MAX_ENTRIES:]
            samples = {bucket: samples[bucket] for bucket in newest}
            if args.dry_run:
                written[country] = {
                    "zero_rows_deleted": dead_epoch_rows(connection, country),
                    "rows_written": len(samples)}
            else:
                written[country] = write_country(connection, country, samples)
        except Exception as error:                      # noqa: BLE001
            failures += 1
            _log_failure(errors_log, country, error, failures - 1)

    elapsed = time.time() - started
    print(f"[backfill_bgp_hod] {len(written)}/{len(countries)} countries, "
          f"{requests_made} requests, {elapsed:.0f}s"
          + (f", {failures} failed (see {errors_log})" if failures else ""))
    print(f"[backfill_bgp_hod] rows written: "
          f"{sum(row['rows_written'] for row in written.values())}, "
          f"dead-epoch rows removed: "
          f"{sum(row['zero_rows_deleted'] for row in written.values())}")
    if not args.dry_run:
        _report(connection, sorted(written))
    return 1 if failures else 0


def _report(connection: sqlite3.Connection, countries) -> None:
    """Per-country, per-bucket truth. Short buckets are named, not hidden."""
    print(f"\n{'country':<8}{'rows':>6}{'warm':>6}{'cold':>6}"
          f"{'min/bucket':>12}{'max/bucket':>12}   short buckets")
    short_total = 0
    for country in countries:
        stats = bucket_distribution(connection, country)
        short = [f"{hour:02d}h={n}" for hour, n in stats["per_hour"].items()
                 if n < HOD_MIN_SAME_HOUR]
        short_total += len(short)
        print(f"{country:<8}{stats['total_rows']:>6}{stats['warm_buckets']:>6}"
              f"{stats['cold_buckets']:>6}{stats['min_samples']:>12}"
              f"{stats['max_samples']:>12}   "
              + (", ".join(short[:6]) + (" …" if len(short) > 6 else "")
                 if short else "—"))
    print(f"\nHOD_MIN_SAME_HOUR = {HOD_MIN_SAME_HOUR}; "
          f"{short_total} bucket(s) below it across {len(countries)} "
          f"countries will keep withholding until the live sensor fills "
          f"them.")


if __name__ == "__main__":
    raise SystemExit(main())
