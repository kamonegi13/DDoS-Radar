"""Helpers every `normalize` may use. Pure functions, no I/O, no clock.

Two things live here rather than in each adapter.

**Country resolution.** A `RequestSpec` is a declaration, so a per-country
source declares ONE templated request (`{country}`) instead of N concrete
ones; the concrete country therefore has to be recovered when the payload
comes back. Most upstreams echo it in the body (RIPE Stat's `resource`,
OONI's `probe_cc`); the rest carry it in the query string of the URL that
was actually fetched. `country_of` tries the body first and the URL
second, which is also what makes a recorded fixture self-describing: the
fixture's URL says which country it was recorded for.

**Arithmetic that was duplicated in the legacy sensors.** Haversine
appears in `ais_maritime` and `usgs_seismic` with the same constant;
bounding boxes appear in five sensors with the same folding rule. A-02
measured what happens when the same computation is written more than
once — the copies drift, and then the same input produces two answers
depending on which sensor saw it.

What is deliberately NOT here: hour-of-day Z-scores and least-squares
trends. DP4 records those as triplicated across `ripe_bgp`, `check_host`
and the scoring layer, and the design sheet §3-2 rules that they collapse
into the L1 baseline store plus L2's `trend.py`. Re-implementing them at
L0 would recreate the duplication the ruling removes.
"""
from __future__ import annotations

import json
import math
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import parse_qs, urlparse

#: The placeholder a per-country `RequestSpec` writes where the country
#: goes. Expansion belongs to the fetch kernel (the composition root knows
#: which countries are in scope); an adapter only declares the shape.
COUNTRY_PLACEHOLDER = "{country}"

#: Query parameter names upstreams use for "which country". Ordered: the
#: first match wins, and every entry is a real parameter of one of the 22
#: sources rather than a guess.
COUNTRY_PARAMS: tuple[str, ...] = (
    "resource",         # RIPE Stat
    "country_code",     # RIPE Atlas probes
    "probe_cc",         # RIPE Atlas measurement results
    "country",          # PeeringDB, IODA
    "cc",               # OONI aggregation
)

#: Earth radius the legacy Haversine implementations use (km). Both
#: `ais_maritime` and `usgs_seismic` hard-code 6371.
EARTH_RADIUS_KM = 6371.0


def load_json(payload) -> Any:
    """Decode a payload body, returning None rather than raising.

    One upstream serving nonsense must not abort the cycle for the other
    33 adapters; the fetch is already recorded in `fetch_log`, so the
    event stays visible without being fatal.
    """
    try:
        return json.loads(payload.body.decode("utf-8", "replace"))
    except (json.JSONDecodeError, AttributeError, UnicodeDecodeError):
        return None


def iso2(value: Any) -> str:
    """Normalize a country code to upper-case ISO2, or "" if it is not one."""
    text = str(value or "").strip().upper()
    return text if len(text) == 2 and text.isalpha() else ""


def country_from_url(url: str,
                     params: Sequence[str] = COUNTRY_PARAMS) -> str:
    """Recover the country from the URL that was actually fetched."""
    try:
        query = parse_qs(urlparse(url).query)
    except ValueError:
        return ""
    for name in params:
        for raw in query.get(name, ()):
            code = iso2(raw)
            if code:
                return code
    return ""


def country_from_label(label: str) -> str:
    """`"airports:TW"` -> `"TW"`.

    Sources whose per-country parameter is a bounding box rather than a
    country code (OpenSky) carry the country in the request label, which
    the payload preserves.
    """
    text = str(label or "")
    return iso2(text.rsplit(":", 1)[-1]) if ":" in text else ""


def country_of(payload, context, *, body_value: Any = None,
               params: Sequence[str] = COUNTRY_PARAMS) -> str:
    """Which country this payload is about: body, URL, label, then context.

    The context fallback applies only when exactly one country is in
    scope. Picking the first of several would attribute an observation to
    a country that was never queried — and a wrong country is worse than
    no country, because it reaches the convergence count as corroboration.
    """
    code = iso2(body_value)
    if code:
        return code
    code = country_from_url(getattr(payload, "url", "") or "", params)
    if code:
        return code
    code = country_from_label(getattr(payload, "label", "") or "")
    if code:
        return code
    countries = getattr(context, "countries", ()) or ()
    return iso2(countries[0]) if len(countries) == 1 else ""


def as_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    """Coerce to float, or `default`. Refuses bool (True would become 1.0)."""
    if isinstance(value, bool) or value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return default if math.isnan(number) or math.isinf(number) else number


def as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    number = as_float(value, None)
    return default if number is None else int(number)


def mapping_or_empty(value: Any) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def list_or_empty(value: Any) -> list:
    return value if isinstance(value, list) else []


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km, R=6371 — the legacy constant.

    `atan2` form, matching `usgs_seismic`: the `asin` form loses precision
    at short distances, and a chokepoint proximity test is a short
    distance.
    """
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (math.sin(d_phi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2)
    return EARTH_RADIUS_KM * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def within_box(lat: float, lon: float, center_lat: float, center_lon: float,
               half_degrees: float) -> bool:
    """A degree box around a centre, folding longitude at the meridian.

    The fold is not decorative: without it a box around a point near
    +180 excludes everything just across the line, which is where two of
    the watched chokepoints are.
    """
    if abs(lat - center_lat) > half_degrees:
        return False
    delta = abs(lon - center_lon)
    if delta > 180.0:
        delta = 360.0 - delta
    return delta <= half_degrees


def bounding_box(center_lat: float, center_lon: float,
                 half_degrees: float) -> tuple[float, float, float, float]:
    """`(lamin, lomin, lamax, lomax)` — the order OpenSky's API expects."""
    return (center_lat - half_degrees, center_lon - half_degrees,
            center_lat + half_degrees, center_lon + half_degrees)


def population_stddev(samples: Sequence[float]) -> float:
    if not samples:
        return 0.0
    mean = sum(samples) / len(samples)
    return (sum((x - mean) ** 2 for x in samples) / len(samples)) ** 0.5


__all__ = ["COUNTRY_PLACEHOLDER", "COUNTRY_PARAMS", "EARTH_RADIUS_KM",
           "load_json", "iso2", "country_from_url", "country_of", "as_float",
           "as_int", "mapping_or_empty", "list_or_empty", "haversine_km",
           "country_from_label",
           "within_box", "bounding_box", "population_stddev"]
