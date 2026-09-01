"""`nasa_eonet` — S1-SENS-029. Renamed, because the old name was a lie.

The sensor was called `nasa_firms` and fetched NASA **EONET** (FIRMS was
unreachable, EONET was, and the switch was never renamed). DP6/C-07: the
identifier an analyst follows to verify a conclusion pointed at a source
that produced none of it, which is NP6's failure mode exactly. Design
sheet §7-2 registers the rename as expected difference #5.

`signal_source` is the v3 adapter id `nasa_eonet` (RULING R1). Legacy's
effective source is `rat.signal_source or rat.sensor`
(`radar/scoring.py:81`) and `core.py:1185` passes no explicit kwarg, so
the legacy value is the sensor name `nasa_firms`; the id carries the
registered rename with it. The invented `thermal_anomaly` matched neither
and would have broken both the ledger dedup identity
(`UNIQUE (tick_id, sensor, signal_source, country)`) and WP-2.8's parity
join key.

`LEGACY_ADAPTER_ID` is the old identifier, declared once. Its only
consumer today is `catalog.DESIGN_SHEET_RENAMES`, which reconciles the
built registry against the design-sheet row. **Ledger-side alias
resolution — reading migrated `nasa_firms` history under the new id — is
NOT implemented and is reserved for WP-4.1**, the composition root
(`v3/runtime/`, §1-2), which is what joins live adapters to migrated
history. Until then, history under the old id is reachable by the old id
only, and this constant is where that fact is written down.

The thermal-anomaly signal scores 3 (core.py:1185) — a fire inside a
watched country is treated as a kinetic-strike precursor. `confidence` is
the string "HIGH" in the legacy payload for every event regardless of the
event; it is preserved as a flag, not promoted to the observation's
confidence, because it was never a measurement of confidence.
"""
from __future__ import annotations

from v3.adapters.common import (as_float, iso2, list_or_empty, load_json,
                                mapping_or_empty, within_box)
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_OK)
from v3.kernel import Window

NASA_EONET = AdapterId("nasa_eonet")
#: The identifier this adapter used to ship under (§7-2 #5). Consumed by
#: `catalog.DESIGN_SHEET_RENAMES`; ledger-side alias resolution is WP-4.1's
#: (see the module docstring — it is reserved, not done).
LEGACY_ADAPTER_ID = "nasa_firms"

_EONET_URL = "https://eonet.gsfc.nasa.gov/api/v3/events"

#: Search radius in degrees, per country. Small countries get a tighter
#: box: a 3° box around Taipei reaches the Chinese mainland, and a fire
#: there is not a Taiwanese thermal anomaly.
RADIUS_DEG_DEFAULT = 3.0
#:
#: Order is the legacy table's, element for element
#: (`radar/sensors/nasa_firms.py:20-24`). Lookup does not depend on it —
#: the pin test compares the sequence because a ledger that is reordered
#: silently is a ledger whose next edit lands in the wrong place.
RADIUS_DEG_BY_COUNTRY: dict = {
    "TW": 2.0, "IL": 2.0, "KR": 2.0, "KW": 2.0, "LB": 2.0,
    "JP": 3.0, "UA": 3.0, "PH": 3.0, "GE": 2.0, "EE": 2.0,
    "LV": 2.0, "LT": 2.0,
}

_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)
_FRESHNESS_HORIZON_SEC = 6 * 3600.0

#: The sentence `core.py:1185` passes as `fired_reason` — unconditionally,
#: on the OK call as well as the FIRED one, because `add_rat` stores it
#: either way (`core.py:973-975`).
FIRED_REASON = "Kinetic Strike Precursor"
#: How many country codes the "global only" value names before it stops
#: (`core.py:1189`, `_firms_global_codes[:4]`). This one IS legacy's, and
#: it applies to a display string; the `[:10]` the port put on the anomaly
#: list itself had no counterpart anywhere in production.
GLOBAL_CODES_SHOWN = 4


def _matches(events, code: str, point, radius: float) -> list[dict]:
    """Every event inside one country's box, at most once per event."""
    matched: list[dict] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        for geometry in list_or_empty(event.get("geometry")):
            coordinates = list_or_empty(
                mapping_or_empty(geometry).get("coordinates"))
            if len(coordinates) < 2:
                continue
            longitude = as_float(coordinates[0], None)
            latitude = as_float(coordinates[1], None)
            if longitude is None or latitude is None:
                continue
            if within_box(latitude, longitude, point[0], point[1], radius):
                matched.append({
                    "lat": latitude, "lng": longitude, "code": code,
                    "confidence": "HIGH",
                    "title": event.get("title", "Wildfire")})
                break                   # one event, one registration
    return matched


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One global fetch -> one observation per country in scope.

    EONET coordinates are `[lon, lat]`. Reading them the other way puts
    every event in the wrong hemisphere, which is why the order is stated
    here and pinned by a test rather than left to the reader.

    An event matching a country through several geometries registers
    once: the same fire seen twice is one fire, and counting it twice
    would inflate the corroboration NP2 relies on.

    The matching runs to completion for EVERY country before any draft is
    built, because the value of a country with no fire depends on whether
    ANOTHER country had one (`core.py:1183-1191`). "No Anomalies" and
    "Global only [AU,US]" are different statements about the same local
    zero: the second says the feed was alive and looking elsewhere, which
    is what tells an analyst that a quiet reading is a reading.
    """
    document = load_json(payload)
    events = list_or_empty(mapping_or_empty(document).get("events"))

    scanned: list[tuple[str, float, list]] = []
    for country in context.countries:
        code = iso2(country)
        point = context.country_coordinates.get(code)
        if not code or not point:
            continue
        radius = RADIUS_DEG_BY_COUNTRY.get(code, RADIUS_DEG_DEFAULT)
        scanned.append((code, radius, _matches(events, code, point, radius)))

    #: `sorted({f["code"] for f in nasa_firms_data})`, core.py:1183 — the
    #: set is taken over the whole cycle's anomalies, not one country's.
    global_codes = sorted({code for code, _, matched in scanned if matched})

    drafts: list[ObservationDraft] = []
    for code, radius, matched in scanned:
        fired = bool(matched)
        if fired:
            value = f"Thermal Anomaly [{code}]"
        elif global_codes:
            value = (f"Global only "
                     f"[{','.join(global_codes[:GLOBAL_CODES_SHOWN])}]")
        else:
            value = "No Anomalies"
        drafts.append(ObservationDraft(
            signal_source="nasa_eonet", domain=PHYSICAL, country=code,
            status=STATUS_FIRED if fired else STATUS_OK,
            raw_score=3.0 if fired else 0.0,
            value=value, reason=FIRED_REASON,
            # Uncapped: `nasa_firms.py:85` appends without a limit and
            # `core.py:1183` reads the full list. A `[:10]` here would
            # have silently truncated detections.
            flags={"anomalies": matched, "count": len(matched),
                   "radius_deg": radius,
                   "global_codes": global_codes},
            evidence_url=payload.url))
    return tuple(drafts)


NASA_EONET_ADAPTER = SourceAdapter(
    adapter_id=NASA_EONET, category=PHYSICAL,
    requests=(RequestSpec(url=_EONET_URL, expect_content="json",
                          params=(("category", "wildfires"), ("status", "open"),
                                  ("days", "1")),
                          label="events"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="eonet")

__all__ = ["NASA_EONET", "NASA_EONET_ADAPTER", "normalize",
           "LEGACY_ADAPTER_ID", "RADIUS_DEG_DEFAULT",
           "RADIUS_DEG_BY_COUNTRY", "FIRED_REASON", "GLOBAL_CODES_SHOWN"]
