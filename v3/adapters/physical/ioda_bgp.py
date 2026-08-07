"""`ioda_bgp` — S1-SENS-037, D1 §4 K19. Two sources, and recovery that shows.

K19: IODA and Cloudflare Radar are a deliberate pair. When IODA is
unreachable the fetch falls back to Radar's traffic anomalies, which is a
coarser but independent view of the same question.

The subtle rule is the one that makes recovery work: keep **only the
newest alert per (country, datasource)**. IODA publishes `level="normal"`
when an outage ends, so a client that keeps every alert it has seen keeps
the old `critical` forever and reports an outage that finished hours ago.
GAP-S7 records that nothing tests this; the test is here.

A17 (this adapter is `physical` while `ripe_bgp`, sharing
`signal_source="bgp"`, is `cyber`) is preserved as-is — the design sheet
defers that ruling to after cutover because domain membership feeds the
convergence count.
"""
from __future__ import annotations

from v3.adapters.common import (as_float, iso2, list_or_empty, load_json,
                                mapping_or_empty)
from v3.adapters.cyber.cloudflare_radar import CF_AUTH
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestChain, RequestSpec,
                               SourceAdapter, STATUS_FIRED, STATUS_OK)
from v3.kernel import Window

IODA_BGP = AdapterId("ioda_bgp")

_IODA_URL = "https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts"
_CF_ANOMALIES_URL = ("https://api.cloudflare.com/client/v4/radar/"
                     "traffic_anomalies")

#: Levels that count as an outage. `normal` is a recovery notice.
ALERT_LEVELS: frozenset = frozenset({"warning", "critical"})
LEVEL_RANK: dict = {"normal": 0, "warning": 1, "critical": 2}
LOOKBACK_SEC = 7200
ALERT_LIMIT = 200

_CADENCE = Window.from_days(1.0, cadence_sec=300.0)
_FRESHNESS_HORIZON_SEC = 1800.0


def latest_by_datasource(alerts) -> dict:
    """`{country: {datasource: alert}}`, newest per pair.

    `>=` on the timestamp, matching the legacy comparison: two alerts
    sharing an instant resolve to the later-listed one, and IODA lists
    the recovery after the outage it ends.
    """
    newest: dict[str, dict] = {}
    for alert in alerts:
        record = mapping_or_empty(alert)
        country = iso2(mapping_or_empty(record.get("entity")).get("code"))
        # An alert with NO `datasource` is kept, under the empty key —
        # `radar/sensors/ioda.py:96` reads `alert.get("datasource", "")` and
        # indexes `alert_sources[""]` with it, so such an alert still sets
        # the country's `max_level`. The port skipped it, which discards a
        # `critical` and reports the country as calm: the insensitive
        # direction, and the one NP1 exists to forbid.
        datasource = str(record.get("datasource") or "")
        if not country:
            continue
        moment = as_float(record.get("time"), 0.0) or 0.0
        current = newest.setdefault(country, {}).get(datasource)
        if current is None or moment >= (current.get("time") or 0.0):
            newest[country][datasource] = {
                "level": str(record.get("level") or "normal").lower(),
                "value": record.get("value"),
                "history_value": record.get("historyValue"),
                "time": moment}
    return newest


def _max_level(sources) -> str:
    return max((entry.get("level", "normal") for entry in sources.values()),
               key=lambda level: LEVEL_RANK.get(level, 0), default="normal")


#: `radar/routes/core.py:1097`. The bare sentence, and the corroborated one.
FIRED_REASON = "BGP anomaly confirmed"


def _fired_reason(degraded: bool, sources) -> str:
    """The sentence an analyst reads beside the verdict (core.py:1097-1102).

    Two independent IODA datasources agreeing is the difference between
    "something moved" and "three observation methods saw the same thing",
    and the legacy text names the datasources so the reader can check.
    The port emitted no reason at all, which loses the corroboration
    count from the only place it is ever shown.
    """
    if not degraded:
        return ""
    if len(sources) < 2:
        return FIRED_REASON
    return (f"{FIRED_REASON} by {len(sources)} independent IODA datasources "
            f"({', '.join(sources.keys())})")


def _from_ioda(payload) -> tuple[ObservationDraft, ...]:
    document = load_json(payload)
    alerts = document if isinstance(document, list) else list_or_empty(
        mapping_or_empty(document).get("data")
        or mapping_or_empty(document).get("alerts"))
    drafts: list[ObservationDraft] = []
    for country, sources in sorted(latest_by_datasource(alerts).items()):
        level = _max_level(sources)
        degraded = level in ALERT_LEVELS
        value = f"bgp={'OUTAGE' if degraded else 'NORMAL'}"
        # The ` ioda=…` segment is CONDITIONAL in production. `core.py:1088`
        # guards it with `if _ioda_src_count > 0`, and `_ioda_src_count`
        # reads `ioda_details[country]`, which `radar/sensors/ioda.py:130-137`
        # populates ONLY for countries whose `max_level` is warning or
        # critical. So a calm country's text is exactly
        # `bgp=NORMAL [ioda_proper]`; the port appended `ioda=normal(1src)`
        # to every row, which no production string ever contains.
        if degraded:
            value += f" ioda={level}({len(sources)}src)"
        value += " [ioda_proper]"
        drafts.append(ObservationDraft(
            signal_source="bgp", domain=PHYSICAL, country=country,
            status=STATUS_FIRED if degraded else STATUS_OK,
            raw_score=1.0 if degraded else 0.0, value=value,
            reason=_fired_reason(degraded, sources),
            flags={"level": level, "sources": sources,
                   "source_count": len(sources), "source": "ioda_proper"},
            evidence_url=payload.url))
    return tuple(drafts)


def _from_cloudflare(payload) -> tuple[ObservationDraft, ...]:
    document = load_json(payload)
    anomalies = list_or_empty(
        mapping_or_empty(mapping_or_empty(document).get("result")
                         ).get("trafficAnomalies"))
    affected = sorted({iso2(mapping_or_empty(entry).get("locationAlpha2"))
                       for entry in anomalies} - {""})
    return tuple(
        ObservationDraft(
            signal_source="bgp", domain=PHYSICAL, country=country,
            status=STATUS_FIRED, raw_score=1.0,
            value="bgp=OUTAGE [cf_fallback]",
            # The bare sentence: on the fallback path `ioda_details` does
            # not exist (`radar/sensors/ioda.py:185` returns statuses and
            # source only), so `_ioda_src_count` is 0 and core.py:1098's
            # corroborated variant cannot be reached.
            reason=FIRED_REASON,
            # No `sources` / `source_count`: the fallback shape genuinely
            # lacks them, and inventing an empty dict would let a consumer
            # read "0 corroborating datasources" as a measurement.
            flags={"source": "cf_fallback"},
            evidence_url=payload.url)
        for country in affected)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    if payload.label == "cf_fallback":
        return _from_cloudflare(payload)
    return _from_ioda(payload)


IODA_BGP_ADAPTER = SourceAdapter(
    adapter_id=IODA_BGP, category=PHYSICAL,
    requests=(RequestChain(
        alternatives=(
            RequestSpec(url=_IODA_URL, expect_content="json",
                        params=(("from", "{since_epoch}"),
                                ("until", "{until_epoch}"),
                                ("entityType", "country"),
                                ("limit", str(ALERT_LIMIT))),
                        label="ioda"),
            RequestSpec(url=_CF_ANOMALIES_URL, expect_content="json",
                        params=(("dateRange", "1d"), ("format", "json")),
                        # The fallback is a Cloudflare endpoint and needs
                        # Cloudflare's bearer token, while the primary needs
                        # nothing: production passes `context["cf_headers"]`
                        # into `_fetch_cf_fallback` only
                        # (`radar/sensors/ioda.py:157`). The credential
                        # therefore belongs to the request, not the source.
                        auth=CF_AUTH,
                        label="cf_fallback")),
        reason="K19 / radar/sensors/ioda.py:49-55 — `_fetch_cf_fallback` "
               "runs ONLY when `_fetch_ioda_proper` returns None. Fetching "
               "both unconditionally let a Cloudflare traffic anomaly "
               "FIRED-override IODA's OK, which is a difference in the "
               "sensitive direction produced by the kernel, not by data.",
        label="bgp_outage"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="ioda", knowledge_refs=("K19",))

__all__ = ["IODA_BGP", "IODA_BGP_ADAPTER", "normalize",
           "latest_by_datasource", "ALERT_LEVELS", "LEVEL_RANK",
           "LOOKBACK_SEC", "ALERT_LIMIT"]
