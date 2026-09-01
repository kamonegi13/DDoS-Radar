"""`ripe_bgp` — S1-SENS-004..007, D1 §4 K15. Routing, measured not judged.

Everything this sensor concludes, it concludes from its own history:

  * the anomaly verdict is an hour-of-day Z-score over the announced
    prefix count (below -2.0, decreases only — a country does not get
    into trouble by announcing MORE routes)
  * the degraded path, used until seven same-hour samples exist, compares
    against a drop baseline that lived in process memory and was
    refreshed hourly — so the first cycle after any restart reported a
    drop ratio of exactly 0 (DP3/A-03). v3 does not transcribe it: L2
    reaches a verdict there by pooling the ledger's own `bgp_hod` buckets
    across hours, a REGISTERED difference (§7-2 #135), not a port
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

**D2 H-05 — the quantity, repaired on both sides at once (§7-2 #136).**
`announced_prefixes` is not a key RIPE returns and never was.
`country-routing-stats` answers with `v4_prefixes_ris` / `v6_prefixes_ris`
/ `asns_ris` (the RIS view) alongside `v4_prefixes_stats` /
`v6_prefixes_stats` / `asns_stats` (the registry view), so production's
`latest.get("announced_prefixes", 0)` read 0 on every cycle for the whole
life of the baseline — all 5,398 rows of the live `bgp_hod` table were
0.0 — and v3 transcribed that read faithfully. Because the quantity never
resolved there is no production behaviour to be faithful TO, so the
quantity is CHOSEN here and registered rather than inherited:

  * `v4_prefixes_ris + v6_prefixes_ris`, not the `_stats` variants, which
    carry **-1 as a sentinel** for an unavailable registry view (measured
    on every entry of every country sampled). Reading a sentinel as a
    number is H-05 one level up.
  * both families, not v4 alone: a v6-only withdrawal is a real outage
    and NP1 does not accept a detector that cannot see one.
  * a missing field yields NO_DATA, never 0. "The field is absent" and
    "this country announces no routes" are different facts and only one
    of them is an outage — collapsing them is what made H-05 silent.

Production and v3 hold one copy each of this rule because neither system
may import the other; `tests/test_bgp_prefix_quantity.py` sweeps the two
against each other so a drift fails a build instead of becoming a second
H-05.

**`{since_iso}` is part of the repair, not a tuning knob.** Asked without
a `starttime`, RIPE answers with everything since 2004 downsampled to
`resolution: 1w`, so the newest entry is a weekly figure up to six days
stale; stored into an hourly `bgp_hod` bucket that is the same number for
~168 buckets (standard deviation 0, floored to 1.0) followed by a step
the Z reads as a hundred-sigma event. A four-day window answers `1h`,
which is the clock `bgp_hod` is bucketed on.

The returned series is RUN-LENGTH ENCODED — one entry per distinct value,
`timeline` listing every interval it held over — which is why `entries`
is not an hour count and why `scripts/backfill_bgp_hod.py` expands the
timeline rather than reading one point per entry.
"""
from __future__ import annotations

from typing import Optional

from v3.adapters.common import (as_float, country_of, list_or_empty,
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

#: The two silences this adapter can be in, told apart (G-17).
PENDING_HOD = "pending_l1_bgp_hod"
#: RIPE answered, and answered at a resolution this series is not keyed
#: on. The reading is disclosed; the sample is withheld so it cannot be
#: recorded into `bgp_hod`, and the verdict with it.
PENDING_RESOLUTION = "withheld_resolution_not_hourly"

#: The RIS view's field names. `radar/sensors/bgp_routing.py`'s
#: `RIS_PREFIX_KEYS` / `RIS_ASN_KEY` are the same two declarations on the
#: production side; the sweep pins them equal.
RIS_PREFIX_KEYS = ("v4_prefixes_ris", "v6_prefixes_ris")
RIS_ASN_KEY = "asns_ris"

#: `radar/sensors/bgp_routing.py::STATS_WINDOW_DAYS` — the window that
#: keeps RIPE's answer at `1h`. Reaches the wire as `{since_iso}`, which
#: `v3/runtime/expansion.py` fills from THIS constant.
STATS_WINDOW_DAYS = 4
LOOKBACK_SEC = STATS_WINDOW_DAYS * 86400.0
#: What `data.resolution` must say for the newest entry to be an hourly
#: reading. Carried on the row, not enforced here: a downsample is a fact
#: about the payload and L2 is where facts become verdicts.
EXPECTED_RESOLUTION = "1h"

_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 3 * 3600.0


def _series(document) -> list[dict]:
    data = mapping_or_empty(mapping_or_empty(document).get("data"))
    return [mapping_or_empty(entry) for entry in list_or_empty(data.get("stats"))]


def _ris_value(entry, key: str) -> Optional[float]:
    """One RIS field as a number, or None when RIPE did not answer it.

    Negative counts as absent: no view of the routing table holds a
    negative number of prefixes, so a negative can only be a sentinel.
    """
    value = mapping_or_empty(entry).get(key)
    if isinstance(value, bool):
        return None
    number = as_float(value, None)
    return None if number is None or number < 0 else number


def prefix_count(entry) -> Optional[float]:
    """`v4_prefixes_ris + v6_prefixes_ris`, or None if neither is present.

    Fractional by design — RIPE reports 9599.5 for an hour in which the
    count changed — so this is a float and the ledger column is REAL.
    Rounding here would quantise the very movement the Z-score reads.
    """
    parts = [_ris_value(entry, key) for key in RIS_PREFIX_KEYS]
    present = [value for value in parts if value is not None]
    return sum(present) if present else None


def as_count(entry) -> Optional[float]:
    """`asns_ris`, or None when absent."""
    return _ris_value(entry, RIS_ASN_KEY)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One country's routing statistics.

    An empty series is NO_DATA rather than zero prefixes: a country that
    announced nothing and a country RIPE has nothing for are different
    facts, and only one of them is an outage. A series whose newest entry
    carries no RIS view is the same fact and gets the same answer.
    """
    document = load_json(payload)
    data = mapping_or_empty(mapping_or_empty(document).get("data"))
    country = country_of(payload, context, body_value=data.get("resource"))
    if not country:
        return ()
    series = _series(document)
    prefixes = prefix_count(series[-1]) if series else None
    if prefixes is None:
        return (ObservationDraft(
            signal_source="bgp", domain=CYBER, country=country,
            status=STATUS_NO_DATA, raw_score=0.0, value="NO_DATA",
            evidence_url=payload.url),)

    latest = series[-1]
    ases = as_count(latest)
    resolution = str(data.get("resolution") or "")
    # A reading RIPE downsampled is real but is not an HOURLY reading, so
    # it can neither be recorded into `bgp_hod` nor compared against it —
    # a weekly figure against an hour-of-day baseline is a Z about the
    # calendar. Withholding the SAMPLE is how that is enforced: L2's fold
    # and `record_phase_samples` both key on `announced_prefixes`, so its
    # absence stops the write and the verdict together, with no new
    # machinery and no branch either of them has to remember.
    # `radar/sensors/bgp_routing.py` reaches the same place by returning
    # STALE_RESOLUTION before its own record-and-score block.
    hourly = resolution == EXPECTED_RESOLUTION
    sample = {"announced_prefixes": prefixes} if hourly else {}
    return (ObservationDraft(
        signal_source="bgp", domain=CYBER, country=country,
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"prefixes={prefixes:g} ases={'?' if ases is None else f'{ases:g}'}",
        flags={**sample, "seen_ases": ases,
               "entries": len(series),
               # NP6: the two components the count is the sum of, and the
               # resolution RIPE chose. A silent downsample to `1d`/`1w`
               # changes what a "reading" means, so it travels with it.
               "v4_prefixes": _ris_value(latest, "v4_prefixes_ris"),
               "v6_prefixes": _ris_value(latest, "v6_prefixes_ris"),
               "resolution": resolution,
               "prefixes_measured": prefixes,
               # The series travels with the observation so the trend is
               # computed once, by L2, from the same numbers — which means
               # the WHOLE series. `_compute_trend` regresses over every
               # element of `stats` (`radar/sensors/bgp_routing.py`) and
               # reports `trend_entries`; a least-squares slope is
               # window-dependent, so a truncation here silently gives L2 a
               # different WITHDRAWING/STABLE/GROWING label at the ±0.5%
               # boundary than production's. Entries with no RIS view are
               # dropped rather than zeroed, on both sides, because one
               # fabricated zero drags a slope to WITHDRAWING.
               "prefix_series": [value for value in
                                 (prefix_count(entry) for entry in series)
                                 if value is not None],
               "ases_series": [value for value in
                               (as_count(entry) for entry in series)
                               if value is not None],
               "hod_verdict": PENDING_HOD if hourly else PENDING_RESOLUTION},
        evidence_url=payload.url),)


RIPE_BGP_ADAPTER = SourceAdapter(
    adapter_id=RIPE_BGP, category=CYBER,
    requests=(RequestSpec(url=_ROUTING_STATS_URL, expect_content="json",
                          params=(("resource", "{country}"),
                                  ("starttime", "{since_iso}"),
                                  ("sourceapp", "osint-radar")),
                          label="routing_stats"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="ripe", min_interval_sec=RIPE_MIN_INTERVAL_SEC,
    knowledge_refs=("K15",), baseline_refs=("bgp_hod",))

__all__ = ["RIPE_BGP", "RIPE_BGP_ADAPTER", "normalize", "prefix_count",
           "as_count", "RIS_PREFIX_KEYS", "RIS_ASN_KEY",
           "RIPE_MIN_INTERVAL_SEC", "HOD_MIN_SAME_HOUR", "HOD_MAX_ENTRIES",
           "HOD_ANOMALY_Z", "HOD_STDDEV_FLOOR", "DROP_THRESHOLD",
           "MIN_TREND_ENTRIES", "TREND_LABEL_PCT", "STATS_WINDOW_DAYS",
           "LOOKBACK_SEC", "EXPECTED_RESOLUTION", "PENDING_HOD",
           "PENDING_RESOLUTION"]
