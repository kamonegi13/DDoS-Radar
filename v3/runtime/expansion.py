"""Scenario + geography -> the concrete requests one cycle will make.

`run_due` takes `expansions: {adapter_name: ExpansionInput}` and refuses,
loudly and per-adapter, to send a request whose placeholder it was not
given (`UNRESOLVED` — K02 records AISHub answering HTTP 200 with an empty
body to a query it rejected, which this layer would otherwise read as
"measured, nothing there"). Supplying those values is this module's whole
job.

**H-1(a)'s supply side.** `ExpansionInput.scopes` can already fan one
declaration out to N requests; what did not exist was anything to fan it
out WITH. `ISR_HOTSPOTS` holds 30 named zones over 21 countries — CN×3,
RU×3, TW×2, JP×2, KP×2, AU×2, IN×2 — and the first hand-written census in
the design sheet omitted JP's two and IN's two. JP is a forward base in
the focused scenario and its two corridors overlap Taiwan's, so those four
zones are not a rounding error in coverage; they are the middle of the
watched area. The census here is DERIVED (`Geography.zone_census`), never
transcribed, for exactly that reason.

Every scope carries a `scope_key` so the plan is readable before it is
sent, and the zone name reaches `label` so `normalize` can put it in the
`hotspots[]` record the reduction concatenates and the map overlay joins
on.
"""
from __future__ import annotations

import datetime
from typing import Iterable, Mapping, Optional, Sequence

from v3.adapters.cyber.ooni_censorship import LOOKBACK_DAYS as \
    OONI_LOOKBACK_DAYS
from v3.adapters.cyber.ripe_bgp import LOOKBACK_SEC as RIPE_BGP_LOOKBACK_SEC
from v3.adapters.info.gdelt import query_for as gdelt_query_for
from v3.adapters.physical.ais_maritime import CHOKEPOINT_BOX_HALF_DEG
from v3.adapters.physical.check_host import MAX_URLS_PER_COUNTRY
from v3.adapters.physical.ihr_health import LOOKBACK_SEC as IHR_LOOKBACK_SEC
from v3.adapters.physical.ioda_bgp import LOOKBACK_SEC as IODA_LOOKBACK_SEC
from v3.adapters.physical.opensky import (AIRPORT_BOX_HALF_DEG,
                                          ISR_BOX_HALF_DEG)
from v3.adapters.types import NormalizeContext
from v3.fetch.expand import ExpansionInput, ExpansionScope
from v3.kernel.errors import DomainError
from v3.runtime.geo import Geography, Zone

#: Adapters whose one declaration becomes one request per participant.
#: `cloudflare_radar` is here for its FOUR origin requests only — its
#: other four declarations carry no placeholder, and `expand_requests`
#: recognises a spec whose text does not vary across the scopes as a
#: single global request, so the BGP and target-ranking calls stay one
#: each rather than becoming N identical rate-limited queries.
COUNTRY_SCOPED: frozenset = frozenset({
    "cloudflare_radar", "gdelt", "greynoise", "ooni_censorship", "opensky",
    "openweather", "peeringdb_ixp", "ripe_atlas", "ripe_bgp", "tor_metrics",
})
#: Adapters whose one declaration becomes one request per ISR ZONE.
#: Separated from the above because the count differs — 30 requests, not
#: 21 — and because conflating them is how H-1 started.
ZONE_SCOPED: frozenset = frozenset({"isr_hotspot", "mil_support_air"})
#: One request per watched maritime/cable chokepoint.
CHOKEPOINT_SCOPED: frozenset = frozenset({"ais_maritime"})

#: `radar/sensors/usgs_seismic.py:65` — `starttime=_hours_ago(24)`.
USGS_LOOKBACK_SEC = 24 * 3600.0
#: `radar/config.py:328` — `GDELT_HISTORY_WINDOW` defaults to 28 days.
#: Named here because the value reaches the wire as a `{history_window}`
#: substitution and a silently different window is a silently different
#: baseline.
GDELT_HISTORY_WINDOW_DAYS = 28


def _iso(ts: float) -> str:
    """UTC, second precision — the form every one of these APIs wants."""
    return datetime.datetime.fromtimestamp(
        ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date(ts: float) -> str:
    return datetime.datetime.fromtimestamp(
        ts, datetime.timezone.utc).strftime("%Y-%m-%d")


def _time_windows(now: float) -> dict:
    """Per-adapter time substitutions, each from the adapter's own constant.

    The lookbacks are NOT invented here. `ihr_health` and `ioda_bgp`
    declare `LOOKBACK_SEC`, `ooni_censorship` declares `LOOKBACK_DAYS`;
    those are imported. The two that declare nothing (`usgs_seismic`,
    `gdelt`) are pinned against production above, with the line cited,
    because a window this layer chose freely would be a threshold this
    layer invented.
    """
    return {
        "ihr_health": {"since_iso": _iso(now - IHR_LOOKBACK_SEC),
                       "until_iso": _iso(now)},
        "ioda_bgp": {"since_epoch": f"{int(now - IODA_LOOKBACK_SEC)}",
                     "until_epoch": f"{int(now)}"},
        "ooni_censorship": {
            "since_date": _date(now - OONI_LOOKBACK_DAYS * 86400.0),
            "until_date": _date(now)},
        "usgs_seismic": {"since_iso": _iso(now - USGS_LOOKBACK_SEC)},
        "gdelt": {"history_window": f"{GDELT_HISTORY_WINDOW_DAYS}"},
        # D2 H-05 / §7-2 #136. Not a lookback for its own sake: without a
        # `starttime` RIPE answers `resolution: 1w` and the newest entry is
        # a weekly figure up to six days stale, which an HOURLY bgp_hod
        # bucket cannot hold without turning a weekly step into a
        # hundred-sigma Z. The constant is the adapter's, imported.
        "ripe_bgp": {"since_iso": _iso(now - RIPE_BGP_LOOKBACK_SEC)},
    }


def _box(lat: float, lng: float, half: float) -> dict:
    """A bounding box as the four values OpenSky's query wants.

    Formatted to one decimal because that is what the fixture-pinned
    requests carry; a float repr difference here is a different URL, and a
    different URL is a different `url_sha256` in `fetch_log`.
    """
    return {"lamin": f"{lat - half:.1f}", "lamax": f"{lat + half:.1f}",
            "lomin": f"{lng - half:.1f}", "lomax": f"{lng + half:.1f}"}


def _zone_scope(zone: Zone) -> ExpansionScope:
    values = {"country": zone.country, "zone": zone.name,
              "lat": f"{zone.lat}", "lng": f"{zone.lng}",
              **_box(zone.lat, zone.lng, ISR_BOX_HALF_DEG)}
    return ExpansionScope(scope_key=zone.scope_key, values=values)


def _country_scope(country: str, geography: Geography) -> ExpansionScope:
    values = {"country": country, "country_lower": country.lower()}
    point = geography.country_coordinates.get(country)
    if point:
        lat, lng = float(point[0]), float(point[1])
        values.update({"lat": f"{lat}", "lng": f"{lng}", "lon": f"{lng}",
                       **_box(lat, lng, AIRPORT_BOX_HALF_DEG)})
    name = geography.country_names.get(country)
    if name:
        values["country_name"] = name
    return ExpansionScope(scope_key=country, values=values)


def _chokepoint_scope(row: Sequence) -> ExpansionScope:
    name, lat, lng, country = row[0], float(row[1]), float(row[2]), row[3]
    box = _box(lat, lng, CHOKEPOINT_BOX_HALF_DEG)
    return ExpansionScope(
        scope_key=f"{country}/{name}",
        values={"country": str(country), "chokepoint": str(name),
                "lat": f"{lat}", "lon": f"{lng}",
                "latmin": box["lamin"], "latmax": box["lamax"],
                "lonmin": box["lomin"], "lonmax": box["lomax"]})


def for_cycle(geography: Geography, countries: Sequence[str], *,
              now: float, common: Optional[Mapping[str, str]] = None,
              carried: Optional[Mapping[str, Mapping[str, str]]] = None
              ) -> dict:
    """`{adapter_name: ExpansionInput}` for one cycle over these countries.

    Adapters absent from the result get `ExpansionInput()`, which resolves
    only what `common` supplies — correct for the ones that declare no
    per-country placeholder at all, and a visible `UNRESOLVED` skip for
    any that declares one this module does not know about. The skip is the
    design: a silently-unexpanded `{country}` on the wire is a request the
    upstream answers with something, and that something is read as data.
    """
    if now <= 0:
        raise DomainError(f"now must be a positive timestamp, got {now}")
    scope = tuple(dict.fromkeys(str(c).upper() for c in countries))
    if not scope:
        raise DomainError(
            "a cycle with no countries in scope would expand nothing and "
            "fetch nothing while reporting a completed sweep")
    shared = dict(common or {})

    country_scopes = tuple(_country_scope(c, geography) for c in scope)
    zone_scopes = tuple(_zone_scope(z) for z in geography.zones_for(scope))
    chokepoint_scopes = tuple(_chokepoint_scope(cp)
                              for cp in geography.chokepoints_for(scope))

    windows = _time_windows(now)
    expansions: dict = {}
    for name in COUNTRY_SCOPED:
        expansions[name] = ExpansionInput(
            scopes=country_scopes, common={**shared, **windows.get(name, {})})
    for name in ZONE_SCOPED:
        # A country with no declared zone is simply not swept by these two
        # — production's loop is over the zone ledger, not over the
        # participants, so a participant without a hotspot has never been
        # in this sensor's coverage.
        expansions[name] = ExpansionInput(scopes=zone_scopes, common=shared)
    for name in CHOKEPOINT_SCOPED:
        expansions[name] = ExpansionInput(scopes=chokepoint_scopes,
                                          common=shared)

    # ── entity-scoped: N per country, from the deployment ledger ────────
    # The design sheet's ruling on `check_host` (§7-2 #11's note) is the
    # ordering constraint here: wiring one country to N URLs BEFORE a
    # reduction exists starts a silent loss the same instant, because the
    # rows collide on `signal_source`. `v3/runtime/reduce.py` folds them,
    # so this is safe now and would not have been before.
    expansions["check_host"] = ExpansionInput(
        scopes=tuple(
            ExpansionScope(scope_key=f"{country}/{url}",
                           values={"country": country, "target_url": url})
            for country in scope
            for url in geography.infrastructure_urls.get(
                country, ())[:MAX_URLS_PER_COUNTRY]),
        common=shared)
    expansions["ct_log"] = ExpansionInput(
        scopes=tuple(
            ExpansionScope(scope_key=f"{country}/{domain}",
                           values={"country": country, "domain": domain})
            for country in scope
            for domain in geography.watched_domains.get(country, ())),
        common=shared)
    # Channels are keyed by BLOC, not by participant: `noname05716` is a
    # Russian-bloc channel, and `XX` marks the ones with no bloc at all.
    # Neither is a scenario participant, so filtering channels by the
    # participant list watches ZERO channels for the Taiwan scenario —
    # measured, not assumed. Hacktivist channels announce targets across
    # theatres, so the sweep is over every declared channel and the
    # attribution is `normalize`'s, from the post's own text.
    expansions["telegram_mirror"] = ExpansionInput(
        scopes=tuple(
            ExpansionScope(scope_key=f"{meta.get('bloc', 'XX')}/{channel}",
                           values={"channel": channel,
                                   "bloc": str(meta.get("bloc", ""))})
            for channel, meta in geography.telegram_channels.items()),
        common=shared)
    expansions["gdelt"] = ExpansionInput(
        scopes=tuple(
            ExpansionScope(scope_key=country, values={
                "country": country,
                "gdelt_query": gdelt_query_for(country,
                                               geography.country_names)})
            for country in scope),
        common={**shared, **windows["gdelt"]})

    # Adapters whose ONLY placeholders are time bounds get them without a
    # per-country fan-out: `ioda_bgp` asks about the whole internet and
    # `usgs_seismic` about the whole planet, and expanding either per
    # participant would send the same request eight times.
    for name, values in windows.items():
        if name not in expansions:
            expansions[name] = ExpansionInput(common={**shared, **values})

    # `gps_jamming` is the one declaration the composition root cannot
    # satisfy from static data: `{date}` is the newest date in the site's
    # own manifest, which is the FIRST of its two requests. Two plain
    # specs cannot express "B(A)" — `RequestContinuation` can, and this
    # adapter does not use it — so the value comes from the last cycle
    # that read a manifest, supplied by the caller. Absent, the adapter is
    # skipped as UNRESOLVED and counts against InputHealth, which is the
    # visible failure; sending the literal `{date}` would be the silent
    # one.
    for name, values in dict(carried or {}).items():
        existing = expansions.get(name)
        expansions[name] = ExpansionInput(
            scopes=getattr(existing, "scopes", ()),
            common={**(dict(existing.common) if existing else shared),
                    **dict(values)})
    return expansions


def context_for(adapter, geography: Geography, countries: Sequence[str], *,
                now: float, adversaries: Sequence[str]) -> NormalizeContext:
    """The pure-function context `normalize` is called with.

    Everything is supplied rather than read, which is what keeps
    `normalize` replayable from a recorded payload: the same bytes and the
    same context give the same drafts a year later.

    `adversaries` has NO default, and that is the fix rather than an
    inconvenience. It was hard-coded to `()` here, which read as "this
    deployment has no adversaries" to every adapter that asks — and
    `usgs_seismic` asks in order to decide whether a shallow quake sits in
    adversary territory. With an empty set its nuclear-test candidate list
    is unconditionally empty, so `has_nuclear` is permanently False: the
    adapter could not reach STATUS_FIRED or its 3.0, and worse, its
    `suppressed = has_cable_threat and not has_nuclear` had no reachable
    un-suppressing branch, so every quake near a cable was suppressed
    forever. A silence that reads as calm, which is this programme's
    signature defect. A parameter with a default can be forgotten a second
    time; a required one cannot.

    Production supplies the SENSOR-side set as the union across focused
    scenarios (`radar/scheduler.py:56-68`), which is a different set from
    the scoring-side one that `core.py:590` reads from the single focused
    scenario. v3 matches the sensor side here and registers the scoring
    side separately (§7-2 #119).
    """
    scope = tuple(dict.fromkeys(str(c).upper() for c in countries))
    return NormalizeContext(
        adapter_id=adapter.adapter_id, now=now, countries=scope,
        country_coordinates=geography.country_coordinates,
        country_names=geography.country_names,
        chokepoints=geography.chokepoints_for(scope),
        adversaries=tuple(dict.fromkeys(
            str(code).upper() for code in adversaries)),
        tactical_keywords=geography.tactical_keywords,
        geo_terms=geography.geo_terms)


def coverage_report(geography: Geography, countries: Sequence[str]) -> dict:
    """What this cycle will actually sweep, per scope kind.

    Published because "21 countries" and "30 zones" are different numbers
    and the difference IS H-1: a report that only counted countries would
    have shown full coverage while four zones went unwatched.
    """
    scope = tuple(dict.fromkeys(str(c).upper() for c in countries))
    zones = geography.zones_for(scope)
    census = geography.zone_census()
    return {
        "countries": list(scope),
        "country_requests": len(scope),
        "zones": [z.scope_key for z in zones],
        "zone_requests": len(zones),
        "zones_per_country": {c: census.get(c, 0) for c in scope},
        "countries_without_a_zone": [c for c in scope if not census.get(c)],
        "chokepoint_requests": len(geography.chokepoints_for(scope)),
    }


__all__ = ["for_cycle", "context_for", "coverage_report", "COUNTRY_SCOPED",
           "ZONE_SCOPED", "CHOKEPOINT_SCOPED"]
