"""`ais_maritime` — S1-SENS-026, D1 §4 K02. Chokepoint vessel anomalies.

K02 is the fact worth keeping: **AISHub answers a rate limit with HTTP 200
and an empty body**, not an error code. A client that trusts the status
line records "success, no vessels" for as long as the throttle lasts, and
"no vessels near the chokepoint" is exactly what a blockade looks like.
The kernel classifies an empty body as its own outcome, and `normalize`
returns nothing rather than an all-clear.

Two anomalies are specified, and only one of them can be computed here.
Stationary anomalies need a single reading. Dark gaps need the vessel's
previous report — history the legacy sensor kept in process memory, so a
restart erased its dark-gap detection entirely (DP3/A-03). §3-2 rules
that history to L1 as a MUST; the wiring is not WP-2.6's, so the
dependency is declared and the gap is stated rather than approximated.
"""
from __future__ import annotations

from v3.adapters.common import as_float, haversine_km, iso2, load_json
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_NO_DATA, STATUS_OK)
from v3.kernel import Window

AIS_MARITIME = AdapterId("ais_maritime")

_AISHUB_URL = "http://data.aishub.net/ws.php"
#: `AIS_DARK_GAP_THRESHOLD` / `AIS_ANCHOR_RADIUS_KM` (config.py:367-368).
DARK_GAP_THRESHOLD_SEC = 3600.0
ANCHOR_RADIUS_KM = 50.0
STATIONARY_SPEED_KT = 0.5
#: AIS ship-type codes: 35-37 military, 60-89 commercial. "Suspicious"
#: means military OR anything outside the commercial band — a warship and
#: an unclassified hull are both interesting; a container ship is not.
MILITARY_SHIP_TYPES: frozenset = frozenset({35, 36, 37})
COMMERCIAL_SHIP_TYPES: frozenset = frozenset(range(60, 90))
#: Two seconds between chokepoints. Declared, not slept.
AIS_MIN_INTERVAL_SEC = 2.0

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 3600.0


def _vessels(document) -> list:
    """AISHub's envelope: `[header, ...]`, and everything after the header.

    The legacy slice is `vessels_raw[1:]` (`radar/sensors/ais_maritime.py
    :90`) and the loop then skips non-dicts (`:96-98`). Against AISHub's
    documented shape — a header object followed by ONE array of vessels —
    that yields a single list element, which is not a dict, so no vessel
    is ever examined.

    This is preserved deliberately (an unregistered change of sensitivity
    aborts cutover, P2 §5-C), and it is the same shape of defect as DP7: a
    sensor that cannot fire and whose silence reads as calm.

    **Design sheet §3-5 H-2 carries the ruling request, and it is open.**
    Fixing this makes `ais_maritime` capable of firing for the first time
    — a sensitive difference that §7-2 would have to register, and one
    that (following DP7's precedent) should be fixed in the LIVE system
    first, so the parity window is not polluted by a sensor only v3 can
    fire. Until the owner rules, the defect stays and the tests pin it.
    """
    if not isinstance(document, list) or len(document) < 2:
        return []
    return document[1:]


def _is_stationary_anomaly(ship_type, speed, distance_km) -> bool:
    suspicious = (ship_type in MILITARY_SHIP_TYPES
                  or ship_type not in COMMERCIAL_SHIP_TYPES)
    return bool(suspicious and speed < STATIONARY_SPEED_KT
                and distance_km < ANCHOR_RADIUS_KM)


def vessel_fields(vessel, now: float):
    """The legacy coercion block, INCLUDING its skip. None = discard.

    `radar/sensors/ais_maritime.py:100-107` wraps all five conversions in
    one `try ... except (ValueError, TypeError): continue`, so a record
    with any unreadable field is DISCARDED. Coercing with defaults instead
    (the port's first form) turns a broken row into ship type 0 — outside
    the commercial band, therefore "suspicious" — at speed 0.0, therefore
    "stationary": a malformed record becomes a warship at anchor beside a
    chokepoint, and the score it produces is indistinguishable from a real
    one. Fabricating an alarm out of a parse failure is the worst failure
    direction this adapter has.

    `last_ts` is read here because it is the only input to dark-gap
    detection (`:105`, `:113-116`); without it in the output, the L1
    vessel history has nothing to store and dark gaps stay uncomputable
    even after that wiring lands.
    """
    try:
        ship_type = int(vessel.get("SHIPTYPE", 0) or 0)
        speed = float(vessel.get("SOG", 0) or 0)
        latitude = float(vessel.get("LATITUDE", 0) or 0)
        longitude = float(vessel.get("LONGITUDE", 0) or 0)
        last_ts = float(vessel.get("TIME", now) or now)
    except (ValueError, TypeError):
        return None
    return ship_type, speed, latitude, longitude, last_ts


def _chokepoint_row(name: str, context: NormalizeContext):
    """`(name, lat, lon, country)` for a chokepoint, or None.

    `NormalizeContext.chokepoints` is the geographic ledger's
    `CHOKEPOINTS` rows, passed in. The country belongs to the CHOKEPOINT
    (`geo_data.json` gives every entry a `country`, and `core.py
    :1250-1253` joins a dark gap to a country through `cp["name"]`), not
    to whatever happens to be in scope this tick.
    """
    wanted = str(name or "").strip()
    if not wanted:
        return None
    for row in getattr(context, "chokepoints", ()) or ():
        if len(row) >= 4 and str(row[0]).strip() == wanted:
            return row
    return None


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One observation per chokepoint request. Score 1 on anomaly.

    core.py:1254-1258 scores any anomaly 1. The chokepoint's country and
    coordinates come from the chokepoint itself — the request label names
    it, and `context.chokepoints` carries the row the composition root
    read from the geographic ledger.
    """
    document = load_json(payload)
    vessels = _vessels(document)
    chokepoint = _label_part(payload.label, "cp")
    row = _chokepoint_row(chokepoint, context)
    # The country is the chokepoint's, never the scope's. Falling back to
    # `context.countries[0]` — as the port did — is right for exactly one
    # watched country and wrong the moment there are two, at which point
    # every chokepoint observation in the run lands on GLOBAL.
    country = iso2(row[3]) if row else ""
    centre_lat = as_float(_label_part(payload.label, "lat"), None)
    centre_lon = as_float(_label_part(payload.label, "lon"), None)
    if centre_lat is None and row:
        centre_lat = as_float(row[1], None)
    if centre_lon is None and row:
        centre_lon = as_float(row[2], None)

    if centre_lat is None or centre_lon is None:
        # Production cannot reach this: `cp["lat"] / cp["lng"]` are read
        # straight off the CHOKEPOINTS row (`:50`). The port substituted
        # `distance_km = 0.0`, and 0.0 < ANCHOR_RADIUS_KM is true for every
        # vessel — "unknown" was spelled as "directly on top of the
        # chokepoint", so every hull in the box became an anomaly at the
        # chokepoint. Unmeasurable is NO_DATA; it is never a score.
        return (ObservationDraft(
            signal_source="ais_maritime", domain=PHYSICAL, country=country,
            status=STATUS_NO_DATA, raw_score=0.0,
            value="chokepoint centre unknown",
            flags={"chokepoint": chokepoint, "stationary_anomalies": [],
                   "vessels_examined": 0, "vessel_reports": [],
                   "dark_gap_detection": "pending_l1_vessel_history"},
            evidence_url=payload.url),)

    stationary: list[dict] = []
    reports: list[dict] = []
    seen = 0
    for vessel in vessels:
        if not isinstance(vessel, dict):
            continue                       # the DP shape above
        fields = vessel_fields(vessel, context.now)
        if fields is None:
            continue                       # malformed record — discarded
        seen += 1
        ship_type, speed, latitude, longitude, last_ts = fields
        distance_km = haversine_km(centre_lat, centre_lon,
                                   latitude, longitude)
        # `self._vessel_history[mmsi] = {"last_ts", "lat", "lng"}` (`:141`),
        # written for every vessel examined regardless of distance, because
        # a hull outside the radius now may be inside it next cycle.
        reports.append({"mmsi": str(vessel.get("MMSI", "")),
                        "last_ts": last_ts,
                        "lat": latitude, "lng": longitude})
        if _is_stationary_anomaly(ship_type, speed, distance_km):
            stationary.append({
                "mmsi": str(vessel.get("MMSI", "")),
                "name": vessel.get("NAME", "UNKNOWN"),
                "ship_type": ship_type,
                "chokepoint": chokepoint,
                "lat": latitude, "lng": longitude,
                "dist_km": round(distance_km, 1)})

    fired = bool(stationary)
    return (ObservationDraft(
        signal_source="ais_maritime", domain=PHYSICAL, country=country,
        status=STATUS_FIRED if fired else STATUS_OK,
        raw_score=1.0 if fired else 0.0,
        value=f"dark_gaps=0 stationary={len(stationary)}",
        reason=("AIS Dark Gap / Stationary Anomaly at chokepoint"
                if fired else ""),
        flags={"chokepoint": chokepoint,
               "stationary_anomalies": stationary[:10],
               "vessels_examined": seen,
               "vessel_reports": reports,
               # Stated, not silently zero: dark-gap detection needs the
               # vessel history L1 will hold (DP3).
               "dark_gap_detection": "pending_l1_vessel_history"},
        evidence_url=payload.url),)


#: AISHub's public guest account. `radar/sensors/ais_maritime.py:57` sends
#: the literal `"guest"` with the comment "AISHub guest access" — there is
#: no credential here to name, which is why this adapter declares no
#: `AuthRequirement`. The port previously wrote `"{aishub_username}"`, a
#: placeholder with no expander and no counterpart in the legacy sensor;
#: K02 records that AISHub answers a rejected request with HTTP 200 and an
#: empty body, so an unexpanded placeholder would have read as "no vessels
#: at the chokepoint" rather than as a failure.
AISHUB_USERNAME = "guest"

#: Half-width of the box queried around each chokepoint, in degrees.
#: `radar/sensors/ais_maritime.py:59-62` builds `cp_lat ± 0.5` /
#: `cp_lng ± 0.5`. It is the search aperture, so it is declared rather
#: than left for the composition root to re-derive.
CHOKEPOINT_BOX_HALF_DEG = 0.5


def _label_part(label: str, key: str) -> str:
    """`"cp=Bashi;lat=21.9;lon=121.0"` -> one field."""
    for part in str(label or "").split(";"):
        name, _, value = part.partition("=")
        if name.strip() == key:
            return value.strip()
    return ""


AIS_MARITIME_ADAPTER = SourceAdapter(
    adapter_id=AIS_MARITIME, category=PHYSICAL,
    requests=(RequestSpec(
        url=_AISHUB_URL, expect_content="json",
        params=(("username", AISHUB_USERNAME), ("format", "1"),
                ("latmin", "{latmin}"), ("latmax", "{latmax}"),
                ("lonmin", "{lonmin}"), ("lonmax", "{lonmax}")),
        headers={"User-Agent": "OSINT-Radar/8.0"},
        label="cp={chokepoint};lat={lat};lon={lon}"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="aishub", min_interval_sec=AIS_MIN_INTERVAL_SEC,
    knowledge_refs=("K02",), baseline_refs=("ais_vessel_history",))

__all__ = ["AIS_MARITIME", "AIS_MARITIME_ADAPTER", "normalize",
           "vessel_fields", "DARK_GAP_THRESHOLD_SEC", "ANCHOR_RADIUS_KM",
           "STATIONARY_SPEED_KT", "MILITARY_SHIP_TYPES",
           "COMMERCIAL_SHIP_TYPES", "AISHUB_USERNAME",
           "CHOKEPOINT_BOX_HALF_DEG"]
