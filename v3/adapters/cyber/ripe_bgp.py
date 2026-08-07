"""`ripe_bgp` — S1-SENS-004..007, D1 §4 K15. Routing, measured not judged.

Everything this sensor concludes, it concludes from its own history:

  * the anomaly verdict is an hour-of-day Z-score over `announced_
    prefixes` (below -2.0, decreases only — a country does not get into
    trouble by announcing MORE routes)
  * the degraded path, used until seven same-hour samples exist, compares
    against a drop baseline that lived in process memory and was
    refreshed hourly — so the first cycle after any restart reported a
    drop ratio of exactly 0 (DP3/A-03)
  * the trend label is a least-squares slope over the returned series,
    one of the THREE copies of that computation DP4 records

§3-2 rules all of it into one place: L1 holds the baselines, L2's
`trend.py` holds the slope. So this adapter reports what RIPE Stat said —
prefixes, ASes, the series — as OBSERVED, and declares `bgp_hod`. That is
the honest state: the measurement is real, the verdict is not this
layer's to make, and OK would claim a verdict.

`signal_source` is `"bgp"`, shared with `ioda_bgp` and `ihr_health`, so
S1-SCORE-008 dedups the three by MAX rather than counting one event three
times.
"""
from __future__ import annotations

from v3.adapters.common import (as_float, as_int, country_of, list_or_empty,
                                load_json, mapping_or_empty)
from v3.adapters.types import (AdapterId, CYBER, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.kernel import Window

RIPE_BGP = AdapterId("ripe_bgp")

_ROUTING_STATS_URL = "https://stat.ripe.net/data/country-routing-stats/data.json"

#: K15: 0.3s between countries. Declared, not slept.
RIPE_MIN_INTERVAL_SEC = 0.3
#: S1-SENS-005/006/007 — kept as constants so the L1 baseline job and this
#: adapter cannot drift into two different rules.
HOD_MIN_SAME_HOUR = 7
HOD_MAX_ENTRIES = 672               # HOD_BASELINE_DAYS (28) x 24
HOD_ANOMALY_Z = -2.0
HOD_STDDEV_FLOOR = 1.0
DROP_THRESHOLD = 0.15
MIN_TREND_ENTRIES = 3
TREND_LABEL_PCT = 0.5

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 3 * 3600.0


def _series(document) -> list[dict]:
    data = mapping_or_empty(mapping_or_empty(document).get("data"))
    return [mapping_or_empty(entry) for entry in list_or_empty(data.get("stats"))]


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One country's routing statistics.

    An empty series is NO_DATA rather than zero prefixes: a country that
    announced nothing and a country RIPE has nothing for are different
    facts, and only one of them is an outage.
    """
    document = load_json(payload)
    data = mapping_or_empty(mapping_or_empty(document).get("data"))
    country = country_of(payload, context, body_value=data.get("resource"))
    if not country:
        return ()
    series = _series(document)
    if not series:
        return (ObservationDraft(
            signal_source="bgp", domain=CYBER, country=country,
            status=STATUS_NO_DATA, raw_score=0.0, value="NO_DATA",
            evidence_url=payload.url),)

    latest = series[-1]
    prefixes = as_int(latest.get("announced_prefixes"), 0) or 0
    ases = as_int(latest.get("seen_ases"), 0) or 0
    return (ObservationDraft(
        signal_source="bgp", domain=CYBER, country=country,
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"prefixes={prefixes} ases={ases}",
        flags={"announced_prefixes": prefixes, "seen_ases": ases,
               "entries": len(series),
               # The series travels with the observation so the trend is
               # computed once, by L2, from the same numbers — which means
               # the WHOLE series. `_compute_trend` regresses over every
               # element of `stats` (`radar/sensors/bgp_routing.py:81,119`)
               # and reports `trend_entries = len(stats)` (:140); a
               # least-squares slope is window-dependent, so a truncation
               # here silently gives L2 a different WITHDRAWING/STABLE/
               # GROWING label at the ±0.5% boundary than production's.
               "prefix_series": [as_int(entry.get("announced_prefixes"), 0)
                                 for entry in series],
               "ases_series": [as_int(entry.get("seen_ases"), 0)
                               for entry in series],
               "hod_verdict": "pending_l1_bgp_hod"},
        evidence_url=payload.url),)


RIPE_BGP_ADAPTER = SourceAdapter(
    adapter_id=RIPE_BGP, category=CYBER,
    requests=(RequestSpec(url=_ROUTING_STATS_URL, expect_content="json",
                          params=(("resource", "{country}"),
                                  ("sourceapp", "osint-radar")),
                          label="routing_stats"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="ripe", min_interval_sec=RIPE_MIN_INTERVAL_SEC,
    knowledge_refs=("K15",), baseline_refs=("bgp_hod",))

__all__ = ["RIPE_BGP", "RIPE_BGP_ADAPTER", "normalize",
           "RIPE_MIN_INTERVAL_SEC", "HOD_MIN_SAME_HOUR", "HOD_MAX_ENTRIES",
           "HOD_ANOMALY_Z", "HOD_STDDEV_FLOOR", "DROP_THRESHOLD",
           "MIN_TREND_ENTRIES", "TREND_LABEL_PCT"]
