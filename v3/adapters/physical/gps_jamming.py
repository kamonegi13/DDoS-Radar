"""`gps_jamming` — S1-SENS-027, D1 §4 K12. The unit defect, in the type.

DP7 is the reason this adapter is written the way it is. The compared
quantity is `bad / (good + bad)`, a fraction in [0,1]; the shipped
thresholds were 3.0 and 7.0, percentages by intent. Nothing objected,
because comparing a fraction with 3.0 is legal arithmetic — it is simply
always False. The sensor could not fire, its health stayed green, and
nobody noticed until the spec was written.

So the thresholds here are `Ratio`, the kernel type that refuses a value
outside [0,1] at construction. The wrong number is no longer a comparison
that quietly fails; it is a build that does not start. (Production was
repaired on 2026-08-07 with the ratio-scale defaults 0.03/0.07, so the
design sheet §7-2's registered difference #1 closes as soon as the parity
window is taken from repaired data.)

K12: gpsjam publishes a manifest and the newest available day is found
there — today's tiles do not exist yet, so a client that asks for today
gets nothing and calls it calm.

**NO_DATA vs NORMAL, the way round production has it.** The legacy sensor
sets `country_status[code] = "NO_DATA"` in exactly one place: when
`COUNTRY_COORDS.get(code)` is empty, i.e. the tile grid could not be
searched for that country at all (`radar/sensors/gps_jamming.py:152-156`).
A country that HAS coordinates and finds zero tiles nearby falls through
the ordinary arithmetic — `total_aircraft == 0`, `jam_ratio == 0.0`,
`is_jammed False` — and is labelled `"NORMAL"` (`:170-224`). The port had
these two swapped: "no tiles in range" reported NO_DATA, and a country
with no coordinates produced no observation at all. The second half is the
dangerous direction — a country the sensor is structurally blind to
vanished from the output entirely, so nothing downstream could see the
blind spot, and L5's silence detector has nothing to count.
"""
from __future__ import annotations

import csv
import io

from v3.adapters.common import iso2, within_box
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_NO_DATA, STATUS_OK)
from v3.kernel import Ratio, Window

GPS_JAMMING = AdapterId("gps_jamming")

_MANIFEST_URL = "https://gpsjam.org/data/manifest.csv"
_TILES_URL = "https://gpsjam.org/data/{date}-h3_4.csv"

#: F-08's repair, in the unit of the value being compared. `Ratio` refuses
#: 3.0 outright, which is the whole point.
JAM_THRESHOLD = Ratio(0.03)
JAM_CRITICAL_THRESHOLD = Ratio(0.07)
#: Three tiles over threshold is a region, not an aircraft.
JAMMED_TILE_COUNT = 3
SEARCH_RADIUS_DEG = 3.0
H3_RESOLUTION = 4

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
#: gpsjam is a daily product with a publication lag; a day-old reading is
#: the freshest one that exists.
_FRESHNESS_HORIZON_SEC = 36 * 3600.0


def latest_manifest_date(text: str) -> str:
    """The newest day gpsjam has published (K12).

    The last line's first field. An empty manifest yields "", and the
    caller then has no date — which is a missing fetch, not a quiet day.
    """
    lines = [line for line in str(text or "").strip().splitlines()
             if line.strip()]
    if not lines:
        return ""
    return lines[-1].split(",")[0].strip()


def _tile_rows(payload) -> list[dict]:
    """CSV -> tile dicts, dropping the rows production drops.

    `radar/sensors/gps_jamming.py:97-105` wraps the whole row in
    `try: ... except (KeyError, ValueError): continue` — a count that is
    not an integer DISCARDS the tile. Coercing it to 0 instead (the port's
    first form) keeps a tile with `bad=0`, which dilutes `jam_ratio` and
    lowers the reading. `TypeError` is caught here as well: production
    leaves it uncaught, where it escapes `_fetch_tile_data` into `fetch`'s
    outer handler and blanks EVERY country to NO_DATA for that cycle
    (§7-2 registration).
    """
    text = payload.body.decode("utf-8", "replace")
    rows: list[dict] = []
    for row in csv.DictReader(io.StringIO(text)):
        cell = row.get("hex")
        if not cell:
            continue
        try:
            good = int(row.get("count_good_aircraft", 0))
            bad = int(row.get("count_bad_aircraft", 0))
        except (KeyError, ValueError, TypeError):
            continue
        rows.append({"hex": cell, "good": good, "bad": bad})
    return rows


def tile_ratio(good: int, bad: int) -> float:
    total = good + bad
    return (bad / total) if total > 0 else 0.0


def tiles_date(url: str) -> str:
    """`.../2026-08-06-h3_4.csv` -> `"2026-08-06"`.

    The legacy entry carries `"date": date_str` (`radar/sensors/
    gps_jamming.py:216`) — which day of the daily product this reading is
    from. `normalize` has no manifest and no clock, but the day is in the
    URL that was actually fetched, so it is recovered rather than dropped.
    """
    tail = str(url or "").rsplit("/", 1)[-1]
    suffix = f"-h3_{H3_RESOLUTION}.csv"
    return tail[:-len(suffix)] if tail.endswith(suffix) else ""


def _flags(*, total_tiles: int, jammed_tiles: int, total_aircraft: int,
           bad_aircraft: int, max_level: float, avg_level: float,
           is_jammed: bool, is_critical: bool, status_label: str,
           date: str) -> dict:
    """The legacy entry's keys (`radar/sensors/gps_jamming.py:205-217`).

    `prev_avg` and `surge` are absent by design: both are computed from
    `self._prev_levels`, the previous cycle's ratio held in process memory
    (DP3), which §3-2 rules to L1. The withheld verdict is NAMED in a
    sibling key rather than written into `surge` as a string.

    That is not a style choice. `radar/verification/flag_catalog.py:125`
    registers `gps_jamming.surge` as a BOOL flag whose non-firing values
    are `(False, None)` (`:84`), with a 14-day silence budget. The port
    wrote `"pending_l1_prev_ratio"` into it — a value in neither set, so
    the flag counted as FIRING on every single tick and L5 could never
    record a quiet day for this sensor. `False` would be wrong in the
    other direction: it asserts "no surge", a verdict reached from a
    baseline this layer does not hold. Absent means "not stated".
    """
    return {"total_tiles": total_tiles, "jammed_tiles": jammed_tiles,
            "total_aircraft": total_aircraft, "bad_aircraft": bad_aircraft,
            "max_level": max_level, "avg_level": avg_level,
            "is_jammed": is_jammed, "is_critical": is_critical,
            "status": status_label, "date": date,
            "surge_verdict": "pending_l1_prev_ratio"}


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """Global tile CSV -> one observation per country in scope.

    The manifest payload carries no tiles, so it produces no observations;
    its job is to tell the kernel which day to ask for.

    Tile centres arrive as `hex_lat` / `hex_lon` columns when the H3 cell
    has already been resolved. A tile whose centre is unknown is skipped
    rather than counted at (0,0) — the Gulf of Guinea is not a proxy for
    everywhere.

    Zero nearby tiles is NORMAL, not NO_DATA: production reaches that case
    through the ordinary arithmetic and labels it `"NORMAL"`. NO_DATA is
    reserved for the case production reserves it for — no coordinates for
    the country, so the tile grid could not be searched at all.
    """
    if payload.label == "manifest":
        return ()
    rows = _tile_rows(payload)
    if not rows:
        return ()
    date = tiles_date(payload.url)

    drafts: list[ObservationDraft] = []
    for country, point in _countries_in_scope(context):
        if point is None:
            # `COUNTRY_COORDS.get(code)` empty -> `_default_entry()` and
            # `country_status[code] = "NO_DATA"` (`:152-156`). Production
            # still records the row; so does this, because a country that
            # silently disappears cannot be counted as a blind spot.
            drafts.append(ObservationDraft(
                signal_source="gps_jamming", domain=PHYSICAL,
                country=country, status=STATUS_NO_DATA, raw_score=0.0,
                value="max=0.0 avg=0.0 [NO_DATA]",
                flags=_flags(total_tiles=0, jammed_tiles=0,
                             total_aircraft=0, bad_aircraft=0,
                             max_level=0.0, avg_level=0.0, is_jammed=False,
                             is_critical=False, status_label="NO_DATA",
                             date=date),
                evidence_url=payload.url))
            continue
        centre_lat, centre_lon = point
        tiles = [row for row in rows
                 if _tile_in_box(row, centre_lat, centre_lon)]
        total_good = sum(tile["good"] for tile in tiles)
        total_bad = sum(tile["bad"] for tile in tiles)
        total_aircraft = total_good + total_bad
        # Every measured quantity becomes a `Ratio` at the point it is
        # computed, so the comparisons below are Ratio-to-Ratio. Reaching
        # for `.value` here would strip exactly the unit F-08 lost.
        jam_ratio = Ratio((total_bad / total_aircraft)
                          if total_aircraft else 0.0)
        ratios = [Ratio(tile_ratio(tile["good"], tile["bad"]))
                  for tile in tiles if tile["good"] + tile["bad"] > 0]
        max_ratio = max(ratios) if ratios else Ratio(0.0)
        jammed_tiles = sum(1 for ratio in ratios if ratio >= JAM_THRESHOLD)

        is_critical = max_ratio >= JAM_CRITICAL_THRESHOLD
        is_jammed = (jammed_tiles >= JAMMED_TILE_COUNT or is_critical
                     or jam_ratio >= JAM_THRESHOLD)
        status_label = ("CRITICAL_JAMMING" if is_critical
                        else "JAMMING_DETECTED" if is_jammed else "NORMAL")
        drafts.append(ObservationDraft(
            signal_source="gps_jamming", domain=PHYSICAL, country=country,
            status=STATUS_FIRED if is_jammed else STATUS_OK,
            raw_score=2.0 if is_critical else (1.0 if is_jammed else 0.0),
            value=(f"max={max_ratio.value:.1f} avg={jam_ratio.value:.1f} "
                   f"[{status_label}]"),
            # `core.py:1812-1814`, verbatim apart from the label default —
            # production's reason falls back to "DETECTED" where its value
            # string falls back to "NO_DATA"; a computed country always has
            # a label, so the fallback is unreachable here.
            reason=(f"GPS jamming: {status_label} "
                    f"(max={max_ratio.value:.1f}, "
                    f"avg={jam_ratio.value:.1f})" if is_jammed else ""),
            flags=_flags(total_tiles=len(tiles), jammed_tiles=jammed_tiles,
                         total_aircraft=total_aircraft,
                         bad_aircraft=total_bad,
                         max_level=round(max_ratio.value, 4),
                         avg_level=round(jam_ratio.value, 4),
                         is_jammed=is_jammed, is_critical=is_critical,
                         status_label=status_label, date=date),
            evidence_url=payload.url))
    return tuple(drafts)


def tile_centre(cell: str):
    """H3 cell -> `(lat, lon)`, or None if the cell is unreadable.

    `h3` is a pure computation library, not an egress: it resolves an
    index that is already in the payload. A cell that will not resolve is
    skipped rather than defaulted, because (0, 0) is in the Gulf of Guinea
    and would attribute jamming to whichever country is nearest it.
    """
    try:
        import h3
        latitude, longitude = h3.cell_to_latlng(cell)
    except Exception:
        return None
    return (latitude, longitude)


def _tile_in_box(row, centre_lat, centre_lon) -> bool:
    point = tile_centre(row.get("hex", ""))
    if point is None:
        return False
    return within_box(point[0], point[1], centre_lat, centre_lon,
                      SEARCH_RADIUS_DEG)


def _countries_in_scope(context):
    """`(country, (lat, lon) | None)` pairs the context supplies.

    Coordinates travel with the context because the geographic ledger is
    configuration and nothing under `v3/` reads configuration directly.

    A country with no coordinates yields `None` rather than being skipped:
    production emits a NO_DATA entry for it (`radar/sensors/gps_jamming.py
    :152-156`), and dropping it instead would delete the evidence that the
    sensor is blind there.
    """
    coordinates = getattr(context, "country_coordinates", None) or {}
    for country in context.countries:
        code = iso2(country) or str(country or "").strip().upper()
        if not code:
            continue
        point = coordinates.get(code)
        yield code, ((point[0], point[1]) if point else None)


GPS_JAMMING_ADAPTER = SourceAdapter(
    adapter_id=GPS_JAMMING, category=PHYSICAL,
    requests=(RequestSpec(url=_MANIFEST_URL, expect_content="csv",
                          headers={"Accept-Encoding": "gzip, deflate"},
                          label="manifest"),
              RequestSpec(url=_TILES_URL, expect_content="csv",
                          headers={"Accept-Encoding": "gzip, deflate"},
                          label="tiles")),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="gpsjam", knowledge_refs=("K12",),
    baseline_refs=("gps_prev_ratio",))

__all__ = ["GPS_JAMMING", "GPS_JAMMING_ADAPTER", "normalize",
           "latest_manifest_date", "tile_ratio", "tiles_date",
           "JAM_THRESHOLD", "JAM_CRITICAL_THRESHOLD", "JAMMED_TILE_COUNT",
           "SEARCH_RADIUS_DEG", "H3_RESOLUTION"]
