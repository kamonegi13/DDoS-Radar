"""`openweather` — S1-SENS-030. A suppressor: it never adds, only explains.

The observation always scores 0 and its status is always OK
(core.py:1122-1125). What it carries is a reason: severe weather over a
watched country explains an airspace drop that would otherwise read as a
closure. The legacy call passes `suppress_reason` WITHOUT
`is_suppressed`, so the entry is not itself suppressed — it annotates.
That asymmetry is preserved deliberately; "suppressed" and "carries a
suppression reason" are different facts and the scoring layer reads them
differently.

The emitted `signal_source` is `openweather`, not the port's invented
`weather`: production's effective value is `rat.signal_source or
rat.sensor` (`radar/scoring.py:81`) and `core.py:1125` passes no explicit
kwarg, so the ledger key is the sensor name. A "semantic" rename breaks
both the L1 uniqueness key and WP-2.8's parity join.
"""
from __future__ import annotations

from v3.adapters.common import (as_float, as_int, country_of, list_or_empty,
                                load_json, mapping_or_empty)
from v3.adapters.types import (AdapterId, AUTH_API_KEY, AUTH_IN_QUERY,
                               AuthRequirement, NormalizeContext,
                               ObservationDraft, PHYSICAL, RequestSpec,
                               SourceAdapter, STATUS_OK)
from v3.kernel import Window

OPENWEATHER = AdapterId("openweather")

_WEATHER_URL = "https://api.openweathermap.org/data/2.5/weather"

SEVERE_WIND_MS = 25.0
MODERATE_WIND_MS = 15.0
DEFAULT_WEATHER_ID = 800          # "clear sky", when the field is missing
#: OpenWeather condition codes counted as severe (config.py:340-343):
#: thunderstorms, heavy rain, snow bands, dust/ash, squalls, tornado.
SEVERE_WEATHER_IDS: frozenset = frozenset(
    set(range(200, 233)) | {500, 502, 503, 504} | {521, 522, 531}
    | {600, 602, 621, 622} | {711, 762} | {771, 781} | {900, 902})

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 3 * 3600.0


def is_severe_weather(weather_id: int, wind_speed: float) -> bool:
    """`radar/sensors/openweather.py:36`."""
    return weather_id in SEVERE_WEATHER_IDS or wind_speed > SEVERE_WIND_MS


def is_moderate_weather(weather_id: int, wind_speed: float) -> bool:
    """`radar/sensors/openweather.py:37` — computed INDEPENDENTLY of severe.

    The two predicates overlap on purpose: 502 is in `SEVERE_WEATHER_IDS`
    and also inside the 5xx rain band, so production records
    `is_severe=True` AND `is_moderate=True` for it. The port derived
    `is_moderate` from the ladder (`severity == "MODERATE"`), which makes
    it False for every severe reading — a flag that means "at least
    moderate" quietly turned into "exactly moderate".
    """
    return ((500 <= weather_id < 600) or (300 <= weather_id < 400)
            or wind_speed > MODERATE_WIND_MS)


def severity_of(weather_id: int, wind_speed: float) -> str:
    """SEVERE / MODERATE / NORMAL, in the legacy order (`:38`)."""
    if is_severe_weather(weather_id, wind_speed):
        return "SEVERE"
    if is_moderate_weather(weather_id, wind_speed):
        return "MODERATE"
    return "NORMAL"


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    document = load_json(payload)
    if not isinstance(document, dict):
        return ()
    # Production keys `conditions` by the code it ASKED about — the
    # `strategic_theaters` entry whose `COUNTRY_COORDS` row built the query
    # (`radar/sensors/openweather.py:21-38`). It never reads `sys.country`.
    # The port preferred the body's `sys.country`, which on a coastal or
    # border coordinate answers with the neighbour and files the reading
    # under a country that was never queried. The label carries the code
    # that was asked for, so that is what decides.
    country = country_of(payload, context)
    if not country:
        return ()
    conditions = list_or_empty(document.get("weather"))
    first = mapping_or_empty(conditions[0]) if conditions else {}
    weather_id = as_int(first.get("id"), DEFAULT_WEATHER_ID) or \
        DEFAULT_WEATHER_ID
    wind_speed = as_float(
        mapping_or_empty(document.get("wind")).get("speed"), 0.0) or 0.0
    severity = severity_of(weather_id, wind_speed)
    is_severe = severity == "SEVERE"
    latitude, longitude = _queried_point(document, context, country)

    return (ObservationDraft(
        signal_source="openweather", domain=PHYSICAL, country=country,
        status=STATUS_OK, raw_score=0.0,
        # Not `suppressed`: the legacy call supplies a reason without the
        # flag, so this entry explains other signals without hiding itself.
        suppressed=False,
        suppress_reason="Active noise filter" if is_severe else None,
        value=f"{country}: {severity}",
        flags={"weather_id": weather_id,
               "condition": first.get("main", "Clear"),
               "description": first.get("description", ""),
               "wind_speed": round(wind_speed, 1),
               "temp_c": as_float(
                   mapping_or_empty(document.get("main")).get("temp"), None),
               "is_severe": is_severe,
               "is_moderate": is_moderate_weather(weather_id, wind_speed),
               "severity": severity,
               # `radar/sensors/openweather.py:38` carries the queried
               # point in the entry. The map overlay reads it; without it
               # the weather layer renders empty and the analyst sees an
               # airspace drop with no visible explanation next to it.
               "lat": latitude, "lng": longitude},
        evidence_url=payload.url),)


def _queried_point(document, context, country: str):
    """`(lat, lng)` for the reading — the point production stored.

    Production writes `coord["lat"] / coord["lng"]` straight from
    `COUNTRY_COORDS` (`radar/sensors/openweather.py:38`), i.e. the point it
    ASKED about, which is what the overlay pins the marker to. The context
    carries the same table; the body's own `coord` is the fallback for a
    country the context has no row for.
    """
    point = (getattr(context, "country_coordinates", None) or {}).get(country)
    if point:
        return (as_float(point[0], None), as_float(point[1], None))
    coord = mapping_or_empty(document.get("coord"))
    return (as_float(coord.get("lat"), None), as_float(coord.get("lon"), None))


OPENWEATHER_ADAPTER = SourceAdapter(
    adapter_id=OPENWEATHER, category=PHYSICAL,
    requests=(RequestSpec(url=_WEATHER_URL, expect_content="json",
                          params=(("lat", "{lat}"), ("lon", "{lon}"),
                                  ("units", "metric")),
                          label="weather:{country}"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    # `radar/sensors/openweather.py:25` — the key is the QUERY parameter
    # `appid`. OpenWeather reads no auth header at all, so the WP-2.6
    # kernel's `Auth-Key` header made every call unauthenticated (HTTP 401),
    # and this sensor's job is to EXPLAIN airspace drops: losing it turns a
    # weather-caused drop back into an apparent closure.
    auth=AuthRequirement(kind=AUTH_API_KEY, key_id="OWM_API_KEY",
                         placement=AUTH_IN_QUERY, name="appid",
                         value_template="{secret}",
                         note="quota is per-key; only focused countries are "
                              "polled (S1-SENS-030)"),
    rate_limit_group="openweather")

__all__ = ["OPENWEATHER", "OPENWEATHER_ADAPTER", "normalize", "severity_of",
           "is_severe_weather", "is_moderate_weather", "SEVERE_WEATHER_IDS",
           "SEVERE_WIND_MS", "MODERATE_WIND_MS"]
