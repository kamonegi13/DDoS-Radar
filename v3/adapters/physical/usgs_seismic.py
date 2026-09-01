"""`usgs_seismic` — S1-SENS-031/032, D1 §4 K16. Detection and suppression.

Two rules share one feed, and their priority is the interesting part.

K16, the detection: magnitude >= 4.0, shallower than 10 km, inside an
adversary's territory. That is a CTBTO-shaped test for an underground
test, and it scores 3.

The suppression: an earthquake near a submarine cable explains a
connectivity drop, so the physical domain should not read that drop as
hostile action.

**Detection wins.** If a nuclear candidate exists, cable proximity does
not suppress (core.py:1743-1752) — an explanation must never hide the
event it might be explaining away. A14 asks whether these two belong in
one sensor; the design sheet keeps them together at L0 and moves the
suppression's APPLICATION to L2 gating, so this adapter states the
suppression rather than performing it.
"""
from __future__ import annotations

from v3.adapters.common import (as_float, haversine_km, iso2, list_or_empty,
                                load_json, mapping_or_empty)
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_OK, STATUS_SUPPRESSED)
from v3.kernel import Window

USGS_SEISMIC = AdapterId("usgs_seismic")

_USGS_URL = "https://earthquake.usgs.gov/fdsnws/event/1/query"

MIN_MAGNITUDE = 4.0
#: K16: a test is shallow and man-made; tectonic events at this magnitude
#: are usually deeper.
NUCLEAR_MAX_DEPTH_KM = 10.0
NUCLEAR_MIN_MAGNITUDE = 4.0
#: A deliberately coarse territory test — a 5° box around the country
#: centroid. Coarse in the sensitive direction (NP1).
TERRITORY_HALF_DEG = 5.0
CABLE_RADIUS_KM = 200.0
FETCH_LIMIT = 100
#: `usgs_seismic.py:146` stores `earthquakes[:20]`; the near-cable list is
#: capped at 10 on the next line and the nuclear candidates are not capped
#: at all. Three different caps, all legacy's.
EVENT_LIST_CAP = 20
NEAR_CABLE_LIST_CAP = 10

_CADENCE = Window.from_days(1.0, cadence_sec=900.0)
_FRESHNESS_HORIZON_SEC = 3 * 3600.0


def _earthquakes(payload) -> list[dict]:
    """GeoJSON features -> flat records. Coordinates are `[lon, lat, depth]`.

    Key set and key ORDER are `usgs_seismic.py:101-110`'s. `type` and
    `tsunami` are read from the properties and were dropped by the port;
    `type` is the field that separates an `explosion` or a
    `nuclear explosion` from an `earthquake`, which is the distinction
    this sensor exists to make (K16).
    """
    document = load_json(payload)
    features = list_or_empty(mapping_or_empty(document).get("features"))
    records: list[dict] = []
    for feature in features:
        if not isinstance(feature, dict):
            continue
        properties = mapping_or_empty(feature.get("properties"))
        coordinates = list_or_empty(
            mapping_or_empty(feature.get("geometry")).get("coordinates"))
        if len(coordinates) < 2:
            continue
        records.append({
            "mag": as_float(properties.get("mag"), 0.0) or 0.0,
            "place": properties.get("place", ""),
            "time": properties.get("time", 0),
            "lat": as_float(coordinates[1], 0.0) or 0.0,
            "lon": as_float(coordinates[0], 0.0) or 0.0,
            "depth_km": (as_float(coordinates[2], 0.0) or 0.0
                         if len(coordinates) > 2 else 0.0),
            "type": properties.get("type", "earthquake"),
            "tsunami": properties.get("tsunami", 0)})
    return records


def _in_adversary_territory(record, context) -> str:
    for adversary in context.adversaries:
        point = context.country_coordinates.get(iso2(adversary))
        if not point:
            continue
        if (abs(record["lat"] - point[0]) < TERRITORY_HALF_DEG
                and abs(record["lon"] - point[1]) < TERRITORY_HALF_DEG):
            return iso2(adversary)
    return ""


def _near_cable_record(record, context):
    """Legacy's near-cable entry, or None. `usgs_seismic.py:117-122`.

    The record is NESTED — the quake sits under `earthquake` rather than
    being spread across the entry — and it carries `distance_km`, rounded
    to one decimal. The port flattened it and dropped the distance, which
    is the only field that says HOW near "near a cable" was.
    """
    for entry in context.chokepoints:
        if len(entry) < 3:
            continue
        name, latitude, longitude = entry[0], entry[1], entry[2]
        distance = haversine_km(record["lat"], record["lon"],
                                latitude, longitude)
        if distance <= CABLE_RADIUS_KM:
            return {"earthquake": record, "chokepoint": str(name),
                    "distance_km": round(distance, 1)}
    return None                          # one chokepoint match is enough


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One global observation, as the legacy consumer emits it.

    Seismicity is not per-country: the feed is worldwide and the two
    verdicts are worldwide. The candidate countries travel in the flags so
    the analyst can see WHERE without the observation claiming to be a
    per-country measurement it is not.
    """
    records = _earthquakes(payload)
    near_cable: list[dict] = []
    candidates: list[dict] = []
    for record in records:
        entry = _near_cable_record(record, context)
        if entry is not None:
            near_cable.append(entry)
        territory = _in_adversary_territory(record, context)
        if (record["mag"] >= NUCLEAR_MIN_MAGNITUDE
                and record["depth_km"] < NUCLEAR_MAX_DEPTH_KM and territory):
            candidates.append({**record, "country": territory})

    has_cable_threat = bool(near_cable)
    has_nuclear = bool(candidates)
    suppressed = has_cable_threat and not has_nuclear
    value = f"events={len(records)} near_cable={len(near_cable)}"
    if has_nuclear:
        value += f" NUCLEAR_CANDIDATE={len(candidates)}"

    return (ObservationDraft(
        signal_source="usgs_seismic", domain=PHYSICAL, country="",
        status=(STATUS_FIRED if has_nuclear
                else STATUS_SUPPRESSED if suppressed else STATUS_OK),
        raw_score=3.0 if has_nuclear else 0.0,
        suppressed=suppressed,
        suppress_reason=(
            f"Seismic event near submarine cable "
            f"({near_cable[0]['chokepoint']})" if suppressed else None),
        value=value,
        # core.py:1738-1740. The candidate COUNT is the finding, and the
        # port emitted the verdict with no sentence attached to it.
        reason=(f"USGS: Possible underground nuclear test signature "
                f"({len(candidates)} candidates)" if has_nuclear else ""),
        flags={"earthquakes": records[:EVENT_LIST_CAP],
               "near_cable": near_cable[:NEAR_CABLE_LIST_CAP],
               "nuclear_candidates": candidates,
               "total_events": len(records),
               "candidate_countries": sorted(
                   {entry["country"] for entry in candidates}),
               "has_cable_threat": has_cable_threat,
               "has_nuclear_candidate": has_nuclear,
               # Stated for L2 gating, which APPLIES the suppression
               # (S1-PIPE-009's caller-side flag). The adapter does not.
               "suppress_physical": suppressed},
        evidence_url=payload.url),)


USGS_SEISMIC_ADAPTER = SourceAdapter(
    adapter_id=USGS_SEISMIC, category=PHYSICAL,
    requests=(RequestSpec(url=_USGS_URL, expect_content="json",
                          params=(("format", "geojson"),
                                  ("starttime", "{since_iso}"),
                                  ("minmagnitude", str(MIN_MAGNITUDE)),
                                  ("orderby", "time"),
                                  ("limit", str(FETCH_LIMIT))),
                          label="quakes"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="usgs", knowledge_refs=("K16",))

__all__ = ["USGS_SEISMIC", "USGS_SEISMIC_ADAPTER", "normalize",
           "MIN_MAGNITUDE", "NUCLEAR_MAX_DEPTH_KM", "NUCLEAR_MIN_MAGNITUDE",
           "TERRITORY_HALF_DEG", "CABLE_RADIUS_KM", "FETCH_LIMIT",
           "EVENT_LIST_CAP", "NEAR_CABLE_LIST_CAP"]
