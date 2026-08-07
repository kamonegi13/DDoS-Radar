"""`ihr_health` — S1-SENS-036, D1 §4 K06. Ported disabled, on purpose.

Two independent reasons, both recorded so the seat is not mistaken for an
oversight (A13 asks exactly that question):

1. All three endpoints have returned HTTP 400 since 2026-Q1 — the
   upstream changed its query contract and the client never followed.
2. The disco signal is redundant. IHR, IODA and `ripe_bgp` all publish
   `signal_source="bgp"`, and S1-SCORE-008 dedups by MAX within a source,
   so a third BGP voice adds no convergence and no score.

Reason 2 covers the DISCO half only. `ihr_delay` (`core.py:1518`) passes
no explicit `signal_source`, so its effective source is its own sensor
name — nothing dedups it, and it is a signal the roster has nowhere else.
That is why the disposition here is "disabled because the upstream is
broken", not "disabled because it is a duplicate".

K06 is why the declaration is kept rather than deleted: the canonical
host is `www.ihr.live`. `ihr.iijlab.net` 301-redirects there, and behind
a proxy that redirect is a second hop that times out. That fact costs a
day to rediscover and nothing to keep.

`enabled=False` means the kernel never plans a fetch (`run_due` skips it
with reason DISABLED) and, unlike the legacy scheduler, no thread sits in
a 60-second loop waiting for it to come back.

**Three endpoints, three rungs.** `radar/sensors/ihr.py:163-177` resolves
the country's status as `disco -> hegemony -> delay`, first match wins.
`normalize` sees ONE payload at a time, so it reports the rung THIS
endpoint supports and carries `ladder_rank` (1/2/3) so the WP-4.1
reduction picks the winner from data rather than re-deriving the
precedence a second time.
"""
from __future__ import annotations

from v3.adapters.common import iso2, list_or_empty, load_json, mapping_or_empty
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_OK)
from v3.kernel import Window

IHR_HEALTH = AdapterId("ihr_health")

#: K06 — the canonical host. Not `ihr.iijlab.net`.
IHR_API_BASE = "https://www.ihr.live/ihr/api"

#: Disco events with an average level above this scored 2 rather than 1
#: (`radar/routes/core.py:1504`).
DISCO_HIGH_LEVEL = 5.0
#: `radar/sensors/ihr.py:135` — the query window is the last two hours.
LOOKBACK_SEC = 7200.0

#: The country-status ladder, `radar/sensors/ihr.py:167-177`, with the
#: precedence it is resolved by. `NORMAL` is rank 4: no endpoint emits it,
#: it is what remains when none of the three matched.
DISCO_EVENT = "DISCO_EVENT"
HEGEMONY_ALARM = "HEGEMONY_ALARM"
DELAY_ANOMALY = "DELAY_ANOMALY"
NORMAL = "NORMAL"
LADDER_RANK: dict = {DISCO_EVENT: 1, HEGEMONY_ALARM: 2, DELAY_ANOMALY: 3,
                     NORMAL: 4}

#: `payload.label` -> the rung that endpoint can raise.
LABEL_STATUS: dict = {"disco": DISCO_EVENT, "hegemony": HEGEMONY_ALARM,
                      "network_delay": DELAY_ANOMALY}

#: `payload.label` -> the effective `signal_source` of its `add_rat` call.
#: `radar/scoring.py:81` makes that `rat.signal_source or rat.sensor`:
#: `ihr_disco` passes `signal_source="bgp"` explicitly (`core.py:1515`)
#: and `ihr_delay` passes nothing, so its source is its sensor name
#: (`core.py:1518`). Hegemony has NO `add_rat` call at all — the name
#: below is the one production gives that cache slice (`core.py:490`),
#: chosen because the three must not collide: the ledger key is
#: `UNIQUE (tick_id, sensor, signal_source, country)` and a same-key row
#: with matching content is dropped SILENTLY (`v3/ledger/store.py:290`).
LABEL_SIGNAL_SOURCE: dict = {"disco": "bgp", "hegemony": "ihr_hegemony",
                             "network_delay": "ihr_delay"}

_CADENCE = Window.from_days(1.0, cadence_sec=300.0)
_FRESHNESS_HORIZON_SEC = 1800.0

DISABLED_REASON = (
    "chronic HTTP 400 since 2026-Q1 (upstream query contract changed), and "
    "the disco signal duplicates ioda_bgp + ripe_bgp on signal_source='bgp', "
    "which S1-SCORE-008 dedups by MAX (S1-SENS-036)")


def _results(document):
    if isinstance(document, dict):
        return list_or_empty(document.get("results", document))
    return list_or_empty(document)


def _disco_country(record) -> str:
    """`radar/sensors/ihr.py:56` — the stream name IS the country code."""
    return iso2(record.get("streamname"))


def _hegemony_country(record) -> str:
    """`radar/sensors/ihr.py:84-85` — entity code, else a flat `country`."""
    return iso2(mapping_or_empty(record.get("entity")).get("code")
                or record.get("country"))


def _delay_country(record) -> str:
    """`radar/sensors/ihr.py:112-113` — the first two letters of the endpoint.

    Network-delay alarms are about a LINK, so the country is recovered
    from the human-readable endpoint name rather than from a code field.
    Taking `[:2]` of the whole string is the legacy rule verbatim; it is
    also why a name that does not start with a country code resolves to
    nothing rather than to a neighbour.
    """
    text = str(record.get("startpoint_name", "")
               or record.get("endpoint_name", "") or "").upper()
    return iso2(text[:2])


def _disco_entry(record) -> dict:
    # Key names are the legacy STORED ones (`radar/sensors/ihr.py:58-64`),
    # not the upstream field names: the source field is `starttime` and
    # the stored key is `ts`. `level` and `avglevel` are a pair and both
    # travel to the frontend; carrying one and dropping the other is the
    # `authority` defect.
    return {"ts": record.get("starttime", ""),
            "endtime": record.get("endtime", ""),
            "level": record.get("level", 0),
            "avglevel": record.get("avglevel", 0),
            "nbprobes": record.get("nbprobes", 0)}


def _hegemony_entry(record) -> dict:
    """`radar/sensors/ihr.py:87-91`. `originasn` is the fallback spelling."""
    return {"asn": record.get("asn") or record.get("originasn"),
            "deviation": record.get("deviation", 0),
            "ts": record.get("timebin", "")}


def _delay_entry(record) -> dict:
    """`radar/sensors/ihr.py:115-119`."""
    return {"link": record.get("link", ""),
            "deviation": record.get("deviation", 0),
            "ts": record.get("timebin", "")}


_ENDPOINT_PARSERS: dict = {
    "disco": (_disco_country, _disco_entry),
    "hegemony": (_hegemony_country, _hegemony_entry),
    "network_delay": (_delay_country, _delay_entry),
}


def _disco_score(events) -> float:
    """2 when any event's average level clears 5, else 1 (core.py:1504)."""
    return 2.0 if any((entry.get("avglevel") or 0) > DISCO_HIGH_LEVEL
                      for entry in events) else 1.0


def _disco_reason(country: str, events) -> str:
    """`radar/routes/core.py:1506-1509`, including the `'?'` fallback."""
    probes = events[0].get("nbprobes", "?") if events else 0
    return (f"IHR: Disconnection event in {country} "
            f"({len(events)} events, probes={probes})")


def _draft(label: str, country: str, found, url) -> ObservationDraft:
    """One country's reading from one endpoint, shaped as its `add_rat`.

    `hegemony` has no `add_rat` counterpart, so it is emitted OK / 0.0
    whatever it found: production reads it only into `country_status` and
    `deep_analysis.ihr.core_hegemony` (`core.py:2783-2784`), and giving it
    a score here would be a sensitivity change with no production basis.
    """
    fired = bool(found) and label != "hegemony"
    status_rung = LABEL_STATUS[label] if found else NORMAL
    if label == "disco":
        score = _disco_score(found) if fired else 0.0
        value = f"{len(found)} events" if fired else "—"
        reason = _disco_reason(country, found) if fired else ""
        flags = {"events": list(found)}
    elif label == "network_delay":
        score = 1.0 if fired else 0.0
        value = f"{len(found)} alarms" if fired else "—"
        reason = (f"IHR: Network delay anomaly ({len(found)} alarms)"
                  if fired else "")
        flags = {"alarms": list(found)}
    else:
        score, reason = 0.0, ""
        value = f"{len(found)} alarms" if found else "—"
        flags = {"alarms": list(found)}
    return ObservationDraft(
        signal_source=LABEL_SIGNAL_SOURCE[label], domain=PHYSICAL,
        country=country, status=STATUS_FIRED if fired else STATUS_OK,
        raw_score=score, value=value, reason=reason,
        # Uncapped: `radar/sensors/ihr.py:58` appends without a limit and
        # `core.py:2781` ships the whole list.
        flags={**flags, "status": status_rung,
               "ladder_rank": LADDER_RANK[status_rung]},
        evidence_url=url)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One endpoint's alarms -> one observation per country in scope.

    Implemented although the adapter is disabled: the payload shape is
    the knowledge asset, and a normalize function with a fixture behind it
    is the only form of that knowledge which fails when it stops being
    true.

    Countries in scope that this endpoint found nothing for get an
    explicit OK / `"—"` reading, which is what `add_rat` records for them
    (`core.py:1511`, `:1520`). Emitting nothing instead would make "the
    endpoint answered and saw nothing" indistinguishable from "the
    endpoint was never asked".
    """
    parser = _ENDPOINT_PARSERS.get(payload.label)
    if parser is None:
        return ()
    country_of_record, entry_of_record = parser

    found: dict[str, list] = {}
    for event in _results(load_json(payload)):
        record = mapping_or_empty(event)
        country = country_of_record(record)
        if not country:
            continue
        found.setdefault(country, []).append(entry_of_record(record))

    silent = {country for country in context.countries if country not in found}
    return tuple(
        _draft(payload.label, country, found.get(country, ()), payload.url)
        for country in sorted(set(found) | silent))


#: Extra query parameters that are NOT uniform across the three endpoints.
#: `radar/sensors/ihr.py:46` sends `streamtype=country` on disco alone;
#: hegemony (:74) and network_delay (:101) send three parameters. The
#: asymmetry is load-bearing: `normalize` reads `streamname` through
#: `iso2()`, and without the constraint IHR also returns ASN and IXP
#: streams whose `streamname` is numeric — every event would be dropped
#: and the adapter would normalize a live payload to nothing.
_ENDPOINT_EXTRA_PARAMS: dict = {
    "disco/events": (("streamtype", "country"),),
}


def _endpoint(name: str) -> RequestSpec:
    params = tuple(_ENDPOINT_EXTRA_PARAMS.get(name, ())) + (
        ("starttime", "{since_iso}"), ("endtime", "{until_iso}"),
        ("format", "json"))
    return RequestSpec(url=f"{IHR_API_BASE}/{name}/", expect_content="json",
                       params=params, label=name.split("/")[0])


IHR_HEALTH_ADAPTER = SourceAdapter(
    adapter_id=IHR_HEALTH, category=PHYSICAL,
    requests=(_endpoint("disco/events"), _endpoint("hegemony/alarms"),
              _endpoint("network_delay/alarms")),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="ihr", knowledge_refs=("K06",),
    enabled=False, disabled_reason=DISABLED_REASON)

__all__ = ["IHR_HEALTH", "IHR_HEALTH_ADAPTER", "normalize", "IHR_API_BASE",
           "DISABLED_REASON", "DISCO_HIGH_LEVEL", "LOOKBACK_SEC",
           "DISCO_EVENT", "HEGEMONY_ALARM", "DELAY_ANOMALY", "NORMAL",
           "LADDER_RANK", "LABEL_STATUS", "LABEL_SIGNAL_SOURCE"]
