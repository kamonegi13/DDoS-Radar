"""The three OpenSky adapters. S1-SENS-022 / -023 / -024 / -025, D1 §4 K01.

They are one module because they are one quota. K01: `opensky`,
`isr_hotspot` and `mil_support_air` all draw on a single anonymous
allowance (400 requests/day), and the legacy system kept them honest with
a module-level lock and a shared `_opensky_last_req_time`. Here the same
fact is a declaration — all three name the rate-limit group `opensky` —
and the runner refuses to plan two of them into the same instant.

The state-vector array is positional, and the positions are the whole
contract: index 7 is barometric altitude, 8 is on-ground, 9 is velocity,
14 is the transponder squawk. `_STATE_*` names them once so a shifted
index fails in one place instead of silently reclassifying aircraft.

**Hand-off, design sheet §3-5 H-1 — one box per country is not enough.**
`ISR_HOTSPOTS` holds 30 named zones over 21 countries, seven of which are
multi-zone (CN×3, RU×3, AU×2, IN×2, JP×2, KP×2, TW×2; the other fourteen
hold one each — counted from `geo_data.json` at WP-2.6 remediation time).
That is exactly the maritime chokepoint ledger's shape, and legacy sweeps
all of a country's zones, sums the counts per theater, and only then asks
whether the total reached the surge threshold
(`radar/sensors/isr_hotspot.py:29, 85-94, 106-107`).
`NormalizeContext` grew a dedicated `chokepoints` field for
`ais_maritime`'s version of this problem; there is no equivalent for ISR
hotspots, and `_box_request` templates ONE box per country. Nothing is
broken yet — the composition root that expands `{country}` does not exist
— but the current `RequestSpec` / `NormalizeContext` shape cannot
reproduce legacy coverage, and under-covering is a missed detection, not
a smaller sample. **WP-4.1 (`v3/runtime/`) must resolve it**, preserving
the order: expand to N zones, sum, then compare against the threshold.
`NormalizeContext` is deliberately not redesigned here — the shape of the
fix is the expander's to determine, and it has no consumer yet.
"""
from __future__ import annotations

from typing import Optional

from v3.adapters.common import (COUNTRY_PLACEHOLDER, as_float, country_of,
                                iso2, list_or_empty, load_json)
from v3.adapters.types import (AdapterId, AuthRequirement, AUTH_OAUTH2,
                               NormalizeContext, ObservationDraft, PHYSICAL,
                               RequestSpec, SourceAdapter, STATUS_FIRED,
                               STATUS_NO_DATA, STATUS_OBSERVED, STATUS_OK)
from v3.kernel import Window

OPENSKY = AdapterId("opensky")
ISR_HOTSPOT = AdapterId("isr_hotspot")
MIL_SUPPORT_AIR = AdapterId("mil_support_air")

#: K01 — one group, one quota, three adapters.
OPENSKY_GROUP = "opensky"
#: `OPENSKY_MIN_INTERVAL`, config.py:493. Declared, not slept.
OPENSKY_MIN_INTERVAL_SEC = 10.0
_STATES_URL = "https://opensky-network.org/api/states/all"

# ── state-vector positions (OpenSky's documented array order) ───────────
_STATE_ICAO24 = 0
_STATE_CALLSIGN = 1
_STATE_LON = 5
_STATE_LAT = 6
_STATE_BARO_ALT = 7
_STATE_ON_GROUND = 8
_STATE_VELOCITY = 9
_STATE_TRUE_TRACK = 10
_STATE_SQUAWK = 14
_STATE_MIN_LEN = 10

#: Legacy's sentinel for "the fetch or the parse failed", written into the
#: aircraft count itself (`radar/sensors/opensky.py:31,35`). It is not
#: decoration: `_compute_airspace_status` tests `count < 0` FIRST, sets
#: status ERROR and `continue`s before the hour-of-day baseline is touched
#: (`radar/routes/core.py:317-319`), so the scoring block at `core.py:1113`
#: sees neither CLOSURE nor ANOMALY and scores 0.
#:
#: S1-SENS-023 is a MUST on this because of what the alternative does.
#: `len([])` on an unparseable body reports ZERO aircraft over the
#: principal airport — and zero against any established baseline is a
#: 100% drop, which is CLOSURE, which is score 3, the highest this
#: adapter's family can emit. A 502 HTML error page would have
#: manufactured a maximum-severity airspace-closure alarm. The count must
#: therefore be able to say "not measured", and -1 is the spelling legacy
#: already uses everywhere downstream.
UNMEASURED_AIRCRAFT_COUNT = -1

# ── S1-SENS-024: what makes a track ISR ─────────────────────────────────
ISR_MIN_ALTITUDE_M = 9000.0
ISR_MAX_VELOCITY_MS = 160.0
ISR_SQUAWK = "7777"
#: Provenance unknown — S1 §9-4 records that the callsign ledger carries no
#: source URL, and A12 records that generic words (NAF, RAF, SAM, CARGO)
#: sit in these lists. Both are ported unchanged: the design sheet rules
#: A12 ACCIDENTAL/preserve, and inventing a cleaner list would be an
#: unregistered sensitivity change.
ISR_CALLSIGN_PREFIXES: tuple[str, ...] = (
    "FORTE", "JAKE", "MYSTIC", "RICO", "TROLL",
    "DRAGON", "COBRA", "HAWK", "REAPER", "GLOBAL",
    "RFAF", "RFF", "RSD",
    "CCA", "CHN",
    "BAF",
)
#: `ISR_SURGE_THRESHOLD`, env-read on every legacy fetch. Nothing under
#: `v3/` reads the environment, so the value is pinned here and becomes a
#: runtime-tunable key when O-18's registry lands.
ISR_SURGE_THRESHOLD = 3

# ── S1-SENS-025: support-aircraft classification, first match wins ──────
TANKER_PREFIXES: tuple[str, ...] = (
    "TEXAC", "SHELL", "PETRO", "NKCTK", "ASTRA", "VOVAG", "MRTT",
    "NAF", "RAF", "GAF", "RFF78", "RFAF78",
)
TRANSPORT_PREFIXES: tuple[str, ...] = (
    "REACH", "RCH", "CARGO", "MOOSE", "ANVIL", "STEEL", "SAM", "EXEC",
    "RFF76", "RFAF76", "VDA", "CCA20", "CHN20",
)
AWACS_PREFIXES: tuple[str, ...] = (
    "SENTRY", "DARKSTAR", "MAGIC", "WEDGE", "RFF50", "RFAF50",
    "CCA50", "CHN50",
)
TANKER_SURGE = 2
TRANSPORT_SURGE = 3
AWACS_ACTIVE = 1

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 3600.0


def _states(payload) -> Optional[list]:
    """The state vectors, or None when the body could not be read.

    None and `[]` are different facts and legacy keeps them apart. A JSON
    object whose `states` is absent or null is a real measurement of zero
    aircraft (`res.json().get("states") or []`, `opensky.py:26`); a body
    that is not a JSON object at all makes that expression raise, and the
    handler records `count: -1` (`opensky.py:35`). Collapsing the two into
    `[]` is what turns a broken response into an airspace closure.
    """
    document = load_json(payload)
    if not isinstance(document, dict):
        return None
    return list_or_empty(document.get("states"))


def _airborne(state) -> bool:
    """Ground traffic is excluded before anything else is asked of it."""
    if not isinstance(state, list) or len(state) < _STATE_MIN_LEN:
        return False
    on_ground = state[_STATE_ON_GROUND]
    return not (True if on_ground is None else bool(on_ground))


def _callsign(state) -> str:
    raw = state[_STATE_CALLSIGN] if len(state) > _STATE_CALLSIGN else ""
    return str(raw or "").strip().upper()


def _squawk(state) -> str:
    if len(state) <= _STATE_SQUAWK:
        return ""
    return str(state[_STATE_SQUAWK] or "")


def _label_part(label: str, key: str) -> str:
    """`"isr;zone=Miyako;lat=25.4;lng=125.0;cc=JP"` -> one field."""
    for part in str(label or "").split(";"):
        name, _, value = part.partition("=")
        if name.strip() == key:
            return value.strip()
    return ""


def _zone(payload) -> dict:
    """The zone this payload covers, from the request label.

    Legacy's per-zone record, `isr_hotspot.py:87-93` and
    `mil_support_air.py:136-140`: `name` first (it is the join key at
    `core.py:2931`), then the coordinates.
    """
    return {"name": _label_part(payload.label, "zone"),
            "lat": as_float(_label_part(payload.label, "lat"), None),
            "lng": as_float(_label_part(payload.label, "lng"), None)}


def _zone_country(payload, context: NormalizeContext) -> str:
    """The country, from the label's `cc` field or the usual chain.

    The zone label is `key=value` pairs rather than
    `country_from_label`'s `prefix:CC`, so the country is read from its
    own named field. `country_of` still runs behind it, which keeps the
    single-country context fallback and lets an older recorded fixture
    normalize unchanged.
    """
    return iso2(_label_part(payload.label, "cc")) or country_of(payload,
                                                                context)


def _isr_track(state, zone) -> dict:
    """`radar/sensors/isr_hotspot.py:75-84`, key for key and in order.

    `alt_m` / `vel_ms` / `heading` / `squawk` are the four the port
    dropped. They are not decoration: they are the whole reason an analyst
    can tell an ISR orbit from an airliner in the per-aircraft readout the
    map overlay draws from `hotspots[].tracks` (`core.py:2929-2933`).

    A state vector with no position falls back to the ZONE CENTRE, as
    legacy does (`isr_hotspot.py:78-79`) — the aircraft is somewhere in
    the box that was queried, so the box centre is the honest estimate.
    The port defaulted to 0.0, which places an unlocated aircraft in the
    Gulf of Guinea.
    """
    velocity = state[_STATE_VELOCITY]
    return {"icao24": state[_STATE_ICAO24],
            "callsign": _callsign(state),
            "lat": as_float(state[_STATE_LAT], zone["lat"]),
            "lon": as_float(state[_STATE_LON], zone["lng"]),
            "alt_m": as_float(state[_STATE_BARO_ALT], 0.0),
            "vel_ms": 999.0 if velocity is None else as_float(velocity, 999.0),
            "heading": (as_float(state[_STATE_TRUE_TRACK], 0.0)
                        if len(state) > _STATE_TRUE_TRACK else 0.0),
            "squawk": _squawk(state)}


def _mil_track(state, category: str, zone) -> dict:
    """`radar/sensors/mil_support_air.py:118-126`, key for key and in order.

    Legacy's own defaults, and they differ from the ISR sensor's on
    purpose: a missing velocity reads 0 here (`mil_support_air.py:105`)
    and 999 there (`isr_hotspot.py:53`), because only the ISR rule asks
    whether an aircraft is SLOW.
    """
    return {"icao24": state[_STATE_ICAO24],
            "callsign": _callsign(state),
            "category": category,
            "lat": as_float(state[_STATE_LAT], zone["lat"]),
            "lon": as_float(state[_STATE_LON], zone["lng"]),
            "alt_m": as_float(state[_STATE_BARO_ALT], 0.0),
            "vel_ms": as_float(state[_STATE_VELOCITY], 0.0)}


# ── 1. `opensky` — aircraft over the principal airport ──────────────────

def normalize_opensky(payload, context: NormalizeContext
                      ) -> tuple[ObservationDraft, ...]:
    """Aircraft count near one country's principal airport.

    S1-SENS-023: the sensor carries no status flag — CLOSURE / ANOMALY is
    decided against an hour-of-day airspace baseline in the scoring layer
    (core.py:340-372). That baseline is L1's in v3 (DP4), so this reports
    the count as OBSERVED and declares the dependency rather than
    inventing a verdict. Reporting OK instead would say "measured,
    nothing wrong", which is the difference between a gap and a silence.

    A body that could not be read is NO_DATA carrying
    `UNMEASURED_AIRCRAFT_COUNT`, never OBSERVED carrying zero. See that
    constant for why the distinction is a MUST and not a nicety.
    """
    country = country_of(payload, context)
    if not country:
        return ()
    states = _states(payload)
    if states is None:
        return (ObservationDraft(
            signal_source="opensky", domain=PHYSICAL, country=country,
            status=STATUS_NO_DATA, raw_score=0.0,
            value=f"{UNMEASURED_AIRCRAFT_COUNT} ac",
            flags={"aircraft_count": UNMEASURED_AIRCRAFT_COUNT},
            evidence_url=payload.url),)
    count = len(states)
    return (ObservationDraft(
        signal_source="opensky", domain=PHYSICAL, country=country,
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"{count} ac",
        # The marker every other OBSERVED adapter carries (`ripe_bgp`'s
        # `hod_verdict`, `check_host`'s `asphyxiation_verdict`). It names
        # the baseline the verdict is waiting on — the same one
        # `baseline_refs` declares — so the withheld score is visible in
        # the row rather than only in the status.
        flags={"aircraft_count": count,
               "airspace_verdict": "pending_l1_airspace_hod"},
        evidence_url=payload.url),)


# ── 2. `isr_hotspot` — surveillance aircraft loitering high and slow ────

def _is_isr(state) -> bool:
    altitude = as_float(state[_STATE_BARO_ALT], 0.0) or 0.0
    velocity = state[_STATE_VELOCITY]
    velocity = 999.0 if velocity is None else (as_float(velocity, 999.0))
    squawk = _squawk(state)
    callsign = _callsign(state)
    return bool(
        (altitude > ISR_MIN_ALTITUDE_M and velocity < ISR_MAX_VELOCITY_MS)
        or squawk == ISR_SQUAWK
        or any(callsign.startswith(prefix)
               for prefix in ISR_CALLSIGN_PREFIXES))


def normalize_isr_hotspot(payload, context: NormalizeContext
                          ) -> tuple[ObservationDraft, ...]:
    """S1-SENS-024. Score 2 on surge, matching core.py:1223-1228.

    Defaults for missing fields are the legacy ones and they are not
    symmetric: a missing altitude reads 0 and a missing velocity reads
    999, so an aircraft reporting neither cannot satisfy the high-and-slow
    test. That asymmetry is deliberate — it fails towards not claiming an
    ISR track from an absence of data.
    """
    country = _zone_country(payload, context)
    if not country:
        return ()
    states = _states(payload)
    if states is None:
        return (_unmeasured_isr(country, payload),)
    zone = _zone(payload)
    tracks = [_isr_track(state, zone) for state in states
              if _airborne(state) and _is_isr(state)]
    count = len(tracks)
    is_surge = count >= ISR_SURGE_THRESHOLD
    return (ObservationDraft(
        signal_source="isr_hotspot", domain=PHYSICAL, country=country,
        status=STATUS_FIRED if is_surge else STATUS_OK,
        raw_score=2.0 if is_surge else 0.0,
        value=f"{count} ISR ac in hotspot",
        # core.py:1226. Legacy passes the reason positionally on every
        # call and `add_rat` stores it whether or not the entry FIRED.
        reason=f"ISR surge: {count} aircraft" if is_surge else "",
        # `hotspots` holds ONE record because `normalize` sees one zone's
        # payload; legacy's is the same list with the country's other
        # zones appended (`isr_hotspot.py:87-93`), which is WP-4.1's join
        # to make. It travels as an array so that concatenation is the
        # whole of that step, and so `core.py:1231`'s ISR_SURGE payload
        # and `core.py:2931`'s overlay join keep the shape they read.
        flags={"count": count, "is_surge": is_surge, "tracks": tracks[:5],
               "hotspots": [{**zone, "isr_count": count,
                             "tracks": tracks[:5]}]},
        evidence_url=payload.url),)


def _unmeasured_isr(country: str, payload) -> ObservationDraft:
    """A zone whose payload could not be read reports nothing measured.

    Legacy's equivalent is structural rather than written down: a failed
    box simply never reaches `results[theater]`
    (`isr_hotspot.py:96-100`), so the theater keeps whatever the previous
    cycle cached. `normalize` has no cache to keep, and OK/0 here would
    assert "no ISR aircraft over this zone" on the strength of a body
    nobody could parse — a defeated detector, which NP1 ranks worse than
    a false positive.
    """
    return ObservationDraft(
        signal_source="isr_hotspot", domain=PHYSICAL, country=country,
        status=STATUS_NO_DATA, raw_score=0.0, value="unmeasured",
        # No zone record: legacy never appends a failed box to
        # `hotspots` (`isr_hotspot.py:96-100`), and an entry claiming
        # `isr_count: 0` would sum into the country total as a real zero.
        flags={"count": UNMEASURED_AIRCRAFT_COUNT, "is_surge": False,
               "tracks": [], "hotspots": []},
        evidence_url=payload.url)


# ── 3. `mil_support_air` — the aircraft that precede an operation ───────

def classify_support(callsign: str) -> str:
    """TANKER -> TRANSPORT -> AWACS, first match wins (S1-SENS-025).

    The order is the contract, not an implementation detail: `RFF78` is a
    tanker and `RFF76` a transport, and several prefixes are shared, so
    reordering the checks reclassifies real aircraft.
    """
    name = (callsign or "").strip().upper()
    for prefixes, label in ((TANKER_PREFIXES, "TANKER"),
                            (TRANSPORT_PREFIXES, "TRANSPORT"),
                            (AWACS_PREFIXES, "AWACS")):
        if any(name.startswith(prefix) for prefix in prefixes):
            return label
    return ""


def normalize_mil_support_air(payload, context: NormalizeContext
                              ) -> tuple[ObservationDraft, ...]:
    """S1-SENS-025. Score 2 only when AWACS and a tanker surge coincide.

    core.py:1762-1765 — tankers alone or transports alone score 1. Two
    together mean refuelling plus airborne early warning, which is the
    shape of a sortie rather than of a training day.
    """
    country = _zone_country(payload, context)
    if not country:
        return ()
    states = _states(payload)
    if states is None:
        return (_unmeasured_mil(country, payload),)
    zone = _zone(payload)
    counts = {"TANKER": 0, "TRANSPORT": 0, "AWACS": 0}
    tracks: list[dict] = []
    for state in states:
        if not _airborne(state):
            continue
        category = classify_support(_callsign(state))
        if not category:
            continue
        counts[category] += 1
        tracks.append(_mil_track(state, category, zone))

    tanker, transport, awacs = (counts["TANKER"], counts["TRANSPORT"],
                                counts["AWACS"])
    is_tanker_surge = tanker >= TANKER_SURGE
    is_transport_surge = transport >= TRANSPORT_SURGE
    is_awacs_active = awacs >= AWACS_ACTIVE
    is_surge = is_tanker_surge or is_transport_surge or is_awacs_active
    score = 2.0 if (is_awacs_active and is_tanker_surge) else (
        1.0 if is_surge else 0.0)
    return (ObservationDraft(
        signal_source="mil_support_air", domain=PHYSICAL, country=country,
        status=STATUS_FIRED if is_surge else STATUS_OK, raw_score=score,
        value=f"T={tanker} C={transport} A={awacs}",
        reason=support_reason(tanker, transport, awacs, is_tanker_surge,
                              is_transport_surge, is_awacs_active),
        flags={"tanker": tanker, "transport": transport, "awacs": awacs,
               "total": tanker + transport + awacs,
               "is_tanker_surge": is_tanker_surge,
               "is_transport_surge": is_transport_surge,
               "is_awacs_active": is_awacs_active, "is_surge": is_surge,
               "tracks": tracks[:5],
               # `mil_support_air.py:136-140`. The per-category counts,
               # not `isr_count` — the two sensors' zone records differ.
               "hotspots": [{**zone, "tanker": tanker,
                             "transport": transport, "awacs": awacs,
                             "tracks": tracks[:5]}]},
        evidence_url=payload.url),)


def support_reason(tanker: int, transport: int, awacs: int,
                   is_tanker_surge: bool, is_transport_surge: bool,
                   is_awacs_active: bool) -> str:
    """core.py:1768-1776, clause for clause and in that order.

    Which clauses appear IS the finding: "tanker surge (2), AWACS active
    (1)" is the sortie shape that scores 2, and the sentence is what an
    analyst reads next to the number. The port emitted no reason at all,
    so the verdict arrived with its own explanation missing.
    """
    parts: list[str] = []
    if is_tanker_surge:
        parts.append(f"tanker surge ({tanker})")
    if is_transport_surge:
        parts.append(f"transport surge ({transport})")
    if is_awacs_active:
        parts.append(f"AWACS active ({awacs})")
    if not parts:
        return ""
    return f"Military support aircraft: {', '.join(parts)}"


def _unmeasured_mil(country: str, payload) -> ObservationDraft:
    """As `_unmeasured_isr`: an unreadable body measures nothing."""
    return ObservationDraft(
        signal_source="mil_support_air", domain=PHYSICAL, country=country,
        status=STATUS_NO_DATA, raw_score=0.0, value="unmeasured",
        flags={"tanker": UNMEASURED_AIRCRAFT_COUNT,
               "transport": UNMEASURED_AIRCRAFT_COUNT,
               "awacs": UNMEASURED_AIRCRAFT_COUNT,
               "total": UNMEASURED_AIRCRAFT_COUNT,
               "is_tanker_surge": False, "is_transport_surge": False,
               "is_awacs_active": False, "is_surge": False, "tracks": [],
               "hotspots": []},
        evidence_url=payload.url)


# ── declarations ────────────────────────────────────────────────────────
# The bounding box is per-country and computed from geography the
# composition root holds, so it is declared as placeholders. `label`
# carries the country because the box parameters do not — which is how
# `normalize` knows what it is looking at.
def _box_request(label: str) -> RequestSpec:
    return RequestSpec(
        url=_STATES_URL, expect_content="json",
        params=(("lamin", "{lamin}"), ("lomin", "{lomin}"),
                ("lamax", "{lamax}"), ("lomax", "{lomax}")),
        label=f"{label}:{COUNTRY_PLACEHOLDER}")


def _zone_request(label: str) -> RequestSpec:
    """A box request whose label also names the ISR ZONE it covers.

    `ais_maritime`'s convention (`label="cp={chokepoint};lat={lat};
    lon={lon}"`), and for the same reason: the identity of the place is
    not recoverable from the box. Four bounding-box numbers do not say
    "Miyako Strait Patrol Corridor", `FetchedPayload.url` is the base URL
    with no query string (`v3/fetch/client.py:332`), and
    `NormalizeContext` has a `chokepoints` field for the maritime version
    of this problem but no ISR equivalent.

    Without the zone name the per-zone record cannot carry one, and
    `core.py:2931` joins the map overlay's per-aircraft `tracks` on
    exactly `h["name"] == hs["name"]` — an absent or empty name matches no
    zone, so every ISR and military-air overlay renders with no aircraft
    and nothing reports an error. `lat`/`lng` travel with it because the
    record legacy appends carries them (`isr_hotspot.py:87-93`).
    """
    return RequestSpec(
        url=_STATES_URL, expect_content="json",
        params=(("lamin", "{lamin}"), ("lomin", "{lomin}"),
                ("lamax", "{lamax}"), ("lomax", "{lomax}")),
        label=(f"{label};zone={{zone}};lat={{lat}};lng={{lng}}"
               f";cc={COUNTRY_PLACEHOLDER}"))


#: Search apertures, in degrees of half-width. These are inputs to the box
#: the expander is GIVEN, not parameters OpenSky reads: the WP-2.6 port
#: carried `_half_degrees` inside `params`, where it would have gone on the
#: wire as a query parameter the API does not know. `ais_maritime` already
#: declares its aperture this way (`CHOKEPOINT_BOX_HALF_DEG`).
AIRPORT_BOX_HALF_DEG = 0.5
ISR_BOX_HALF_DEG = 1.8

#: OAuth2 client-credentials; the token is fetched and refreshed by the
#: composition root, 300s before expiry (K01). The adapter names the secret.
#:
#: OPTIONAL, and that is production's shape rather than a concession:
#: `config.env.example:90-91` ships `OPENSKY_CLIENT_ID` empty and
#: `radar/sensors/opensky_auth.py:17` logs "running in anonymous mode (400
#: req/day limit)", after which `_get_opensky_bearer` returns "" and no
#: header is sent. Declared mandatory, all THREE OpenSky adapters aborted
#: with AUTH_MISSING before the socket opened — three physical sensors dark
#: for every default deployment, reported as no data.
_OPENSKY_AUTH = AuthRequirement(
    kind=AUTH_OAUTH2, key_id="OPENSKY_CLIENT_CREDENTIALS",
    name="Authorization", value_template="Bearer {secret}", optional=True,
    note="anonymous access still works at 400 requests/day (K01)")
OPENSKY_AUTH = _OPENSKY_AUTH

OPENSKY_ADAPTER = SourceAdapter(
    adapter_id=OPENSKY, category=PHYSICAL,
    requests=(_box_request("airports"),),
    cadence=_CADENCE, normalize=normalize_opensky,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC, auth=_OPENSKY_AUTH,
    rate_limit_group=OPENSKY_GROUP,
    min_interval_sec=OPENSKY_MIN_INTERVAL_SEC,
    knowledge_refs=("K01",), baseline_refs=("airspace_hod",))

ISR_HOTSPOT_ADAPTER = SourceAdapter(
    adapter_id=ISR_HOTSPOT, category=PHYSICAL,
    requests=(_zone_request("isr"),),
    cadence=_CADENCE, normalize=normalize_isr_hotspot,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC, auth=_OPENSKY_AUTH,
    rate_limit_group=OPENSKY_GROUP,
    min_interval_sec=OPENSKY_MIN_INTERVAL_SEC,
    knowledge_refs=("K01",))

MIL_SUPPORT_AIR_ADAPTER = SourceAdapter(
    adapter_id=MIL_SUPPORT_AIR, category=PHYSICAL,
    requests=(_zone_request("mil_air"),),
    cadence=_CADENCE, normalize=normalize_mil_support_air,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC, auth=_OPENSKY_AUTH,
    rate_limit_group=OPENSKY_GROUP,
    min_interval_sec=OPENSKY_MIN_INTERVAL_SEC,
    knowledge_refs=("K01",))

__all__ = ["OPENSKY", "ISR_HOTSPOT", "MIL_SUPPORT_AIR", "OPENSKY_ADAPTER",
           "ISR_HOTSPOT_ADAPTER", "MIL_SUPPORT_AIR_ADAPTER",
           "normalize_opensky", "normalize_isr_hotspot",
           "normalize_mil_support_air", "classify_support", "support_reason",
           "OPENSKY_GROUP", "OPENSKY_MIN_INTERVAL_SEC",
           "ISR_CALLSIGN_PREFIXES", "TANKER_PREFIXES", "TRANSPORT_PREFIXES",
           "AWACS_PREFIXES", "ISR_SURGE_THRESHOLD",
           "UNMEASURED_AIRCRAFT_COUNT",
           "OPENSKY_AUTH", "AIRPORT_BOX_HALF_DEG", "ISR_BOX_HALF_DEG"]
