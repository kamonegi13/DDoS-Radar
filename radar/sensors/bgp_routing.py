"""radar.sensors.bgp_routing -- BgpRoutingSensor.

Uses the stats time series from RIPE Stat's `country-routing-stats` to
compute the prefix trend (slope over the returned series) and ASN
volatility in addition to the drop_ratio and HOD Z-score anomaly
detection.

**D2 H-05 — what this sensor measured, and for how long it measured
nothing.** Until 2026-08-09 this module read `announced_prefixes` and
`seen_ases` off each stats entry. `country-routing-stats` returns
NEITHER key, and has not for the whole life of this baseline: it answers
with `v4_prefixes_ris` / `v6_prefixes_ris` / `asns_ris` (the RIS view),
`v4_prefixes_stats` / `v6_prefixes_stats` / `asns_stats` (the registry
view) and `stats_date` / `timeline`. `latest.get("announced_prefixes", 0)`
therefore read 0 on every cycle, which is why every one of the 5,398 rows
in the live `bgp_hod` table was exactly 0.0 (19 countries; 8 of them
holding a full 672-bucket window). The Z was `(0-0)/max(0,1.0)` = 0.0,
the drop ratio was 0.0, the trend slope was 0.0 and the label was
permanently STABLE — every branch of the detector unreachable.

There is therefore NO production behaviour to be faithful to here. The
quantity had to be CHOSEN, and the choice is registered (§7-2 #136):

  prefixes  `v4_prefixes_ris + v6_prefixes_ris`. Not the `_stats`
            variants: those carry **-1 as a sentinel** for "the registry
            view is unavailable" (measured: `v4_prefixes_stats: -1` on
            every entry of every country sampled), and reading a sentinel
            as a number is H-05's own trap one level up. Not v4 alone
            either — a v6-only withdrawal is a real outage and NP1 does
            not accept a detector that cannot see one.
  ASes      `asns_ris`, from the same view as the prefixes so the two
            numbers on a row describe one measurement.
  absence   `None`, never 0. Translating "the field is missing" into
            "this country announces no routes" is precisely what made
            H-05 silent, and the second-worst thing about it was that the
            fabricated 0 agreed with a baseline of fabricated 0s.

**The request carries a `starttime`, and that is part of the repair.**
Without one RIPE answers with the whole series since 2004 downsampled to
`resolution: 1w`, so `stats[-1]` is a WEEKLY figure up to six days stale.
Writing that into an hourly `bgp_hod` bucket stores the same number for
~168 consecutive buckets — standard deviation 0, floored to 1.0 — and
then steps by whatever the week moved, which the Z reads as a hundred-
sigma event. A four-day window comes back at `resolution: 1h` (measured),
which is the resolution the hour-of-day baseline is keyed at.

The series RIPE returns is RUN-LENGTH ENCODED: one stats entry per
distinct value, with `timeline` listing every interval over which that
value held. `scripts/backfill_bgp_hod.py` expands it; this module does
not need to, because it reads the newest entry and regresses over the
entries in order.
"""
from __future__ import annotations
import datetime
import math
import time
from typing import Optional

import requests

from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY, HOD_MIN_SAME_HOUR, HOD_MAX_ENTRIES,
)
from radar.sensors.base import BaseSensor
from radar.scenarios import SensorTier
from radar.database import db as _db

# Minimum stats entries required for trend computation
MIN_TREND_ENTRIES = 3

#: The RIS view's field names. The `_stats` siblings are deliberately not
#: here — see the module docstring's sentinel note.
RIS_PREFIX_KEYS = ("v4_prefixes_ris", "v6_prefixes_ris")
RIS_ASN_KEY = "asns_ris"

#: How far back to ask. Chosen as the largest window that is comfortably
#: inside RIPE's `1h` resolution band while keeping the trend regression
#: over recent routing rather than over decades of history. The band's
#: edge was measured once (2026-08-09): 4d/8d/16d/24d/28d all answered
#: `1h`, and 29d was the first window to drop to `1d`. That is upstream's
#: downsampling policy as observed on that date, not a documented
#: guarantee — it can move without notice. `fetch()` does not trust it
#: blindly either: every response's `resolution` is checked and a
#: non-`1h` answer is disclosed as `STALE_RESOLUTION` rather than scored
#: (see below); the backfill script goes further and retries with a
#: halved window (`ResolutionTooCoarse`).
STATS_WINDOW_DAYS = 4
STATS_WINDOW_SEC = STATS_WINDOW_DAYS * 86400

#: What RIPE's `resolution` must say for the newest entry to be an hourly
#: reading. Recorded on the result so a silent downsample is visible.
EXPECTED_RESOLUTION = "1h"


def _ris_value(entry: dict, key: str) -> Optional[float]:
    """One RIS field as a number, or None when RIPE did not answer it.

    Negative is treated as absent as well: no view of the routing table
    contains a negative number of prefixes, so a negative can only be a
    sentinel, and a sentinel read as a measurement is H-05.

    The coercion is deliberately the same one v3's `as_float` performs
    (`v3/adapters/common.py`) — bool refused, NaN and infinity refused, a
    numeric string accepted — because the two systems must read the same
    number out of the same bytes and only a sweep can keep two
    transcriptions of one rule from becoming two rules.
    """
    value = (entry or {}).get(key)
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return None if number < 0 else number


def prefix_count(entry: dict) -> Optional[float]:
    """`v4_prefixes_ris + v6_prefixes_ris`, or None if neither is present.

    A present-and-missing mix sums what is present rather than refusing:
    RIPE has answered v4 and omitted v6 for countries with no v6
    deployment at all, and refusing there would blind the sensor to the
    v4 series it does have.
    """
    parts = [_ris_value(entry, key) for key in RIS_PREFIX_KEYS]
    present = [value for value in parts if value is not None]
    return sum(present) if present else None


def as_count(entry: dict) -> Optional[float]:
    """`asns_ris`, or None when absent."""
    return _ris_value(entry, RIS_ASN_KEY)


def window_start_iso(now: float) -> str:
    """The `starttime` this sensor asks for, UTC, second precision."""
    return datetime.datetime.fromtimestamp(
        now - STATS_WINDOW_SEC, datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


class BgpRoutingSensor(BaseSensor):
    BGP_DROP_THRESHOLD = 0.15
    BGP_HOD_MIN        = HOD_MIN_SAME_HOUR
    BGP_HOD_MAX        = HOD_MAX_ENTRIES
    tier = SensorTier.FOCUSED_ONLY
    def __init__(self):
        super().__init__("ripe_bgp", "cyber", 1800); self._baseline: dict = {}
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", []); results: dict = {}
        t0 = time.time(); total_prefixes = 0; any_success = False; last_status = 0; last_error = ""
        _now = time.time()
        _bgp_hour_bucket = int(_now // 3600) * 3600
        _bgp_cur_hod     = (_bgp_hour_bucket // 3600) % 24
        _starttime = window_start_iso(_now)
        for idx, code in enumerate(theaters):
            if idx > 0:
                time.sleep(0.3)  # Courtesy interval for RIPE Stat API (free tier)
            try:
                res = requests.get("https://stat.ripe.net/data/country-routing-stats/data.json", params={"resource": code, "starttime": _starttime, "sourceapp": "osint-radar"}, timeout=12, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                last_status = res.status_code
                if res.status_code == 429:
                    # Don't break — continue processing remaining theaters
                    prev = (self.get_cache() or {}).get("routing_stats", {}).get(code)
                    if prev:
                        results[code] = prev
                    else:
                        results[code] = {"status": "RATE_LIMITED", "is_anomaly": False}
                    continue
                elif res.status_code == 200:
                    _payload = res.json().get("data", {})
                    stats = _payload.get("stats", [])
                    _resolution = str(_payload.get("resolution") or "")
                    if stats:
                        latest = stats[-1]
                        pfx_now = prefix_count(latest); ases_now = as_count(latest)
                        if pfx_now is None:
                            # The RIS view answered nothing. NOT zero
                            # prefixes: that claim is H-05 (D2), and it is
                            # the claim that made this sensor silent for
                            # the whole life of its baseline.
                            results[code] = {"status": "NO_DATA", "is_anomaly": False,
                                             "resolution": _resolution}
                            any_success = True
                            continue
                        if _resolution != EXPECTED_RESOLUTION:
                            # RIPE downsampled. The reading is real but it
                            # is not an HOURLY reading, so it can neither
                            # be written to an hourly series nor compared
                            # against one — a weekly figure against an
                            # hour-of-day baseline is a Z about the
                            # calendar, not about the network. Disclose
                            # the measurement, withhold the verdict.
                            #
                            # Not hypothetical: this is what the endpoint
                            # answers when the `starttime` above is lost,
                            # which is a change to OUR code, not RIPE's.
                            results[code] = {
                                "status": "STALE_RESOLUTION", "is_anomaly": False,
                                "announced_prefixes": pfx_now, "seen_ases": ases_now,
                                "v4_prefixes": _ris_value(latest, "v4_prefixes_ris"),
                                "v6_prefixes": _ris_value(latest, "v6_prefixes_ris"),
                                "resolution": _resolution,
                                "hod_z": None, "hod_n": 0}
                            total_prefixes += int(pfx_now); any_success = True
                            continue
                        bl = self._baseline.get(code, {})
                        if not bl: self._baseline[code] = {"prefixes": pfx_now, "ases": ases_now, "ts": _now}; bl = self._baseline[code]
                        # Refresh baseline BEFORE computing drop_ratio so the first reading
                        # after an hourly reset uses the new baseline, not the stale one.
                        if _now - bl.get("ts", 0) > 3600:
                            self._baseline[code] = {"prefixes": pfx_now, "ases": ases_now, "ts": _now}; bl = self._baseline[code]
                        pfx_base = bl.get("prefixes", pfx_now) or pfx_now
                        drop_ratio = max(0.0, (pfx_base - pfx_now) / pfx_base) if pfx_base else 0.0
                        total_prefixes += int(pfx_now); any_success = True

                        # HOD Z-score: record one entry per UTC hour bucket.
                        # Non-hourly answers returned above, so everything
                        # written here was measured on this series' clock.
                        _last_bucket = _db.hod_last_bucket("bgp_hod", code)
                        if _last_bucket != _bgp_hour_bucket:
                            _db.hod_record("bgp_hod", code, _bgp_hour_bucket,
                                           pfx_now, max_entries=self.BGP_HOD_MAX)
                        _bgp_same_hour = _db.hod_same_hour("bgp_hod", code,
                                                           _bgp_cur_hod, _bgp_hour_bucket)
                        _n_bgp_hod = len(_bgp_same_hour)
                        if _n_bgp_hod >= self.BGP_HOD_MIN:
                            _bm = sum(_bgp_same_hour) / _n_bgp_hod
                            _bs = max((sum((x - _bm)**2 for x in _bgp_same_hour) / _n_bgp_hod) ** 0.5, 1.0)
                            _bz = (pfx_now - _bm) / _bs
                            is_anomaly = _bz < -2.0
                            hod_info   = {"hod_z": round(_bz, 2), "hod_n": _n_bgp_hod}
                        else:
                            is_anomaly = drop_ratio > self.BGP_DROP_THRESHOLD
                            hod_info   = {"hod_z": None, "hod_n": _n_bgp_hod}

                        # Trend analysis: use full stats array
                        trend_info = self._compute_trend(stats)

                        results[code] = {
                            "announced_prefixes": pfx_now, "baseline_prefixes": pfx_base,
                            "seen_ases": ases_now, "drop_pct": round(drop_ratio * 100, 1),
                            "is_anomaly": is_anomaly,
                            "status": "ANOMALY" if is_anomaly else "NORMAL",
                            # NP6: the two RIS components the prefix count
                            # is the sum of, and the resolution RIPE chose,
                            # so a reader can re-derive the number and see
                            # a silent downsample.
                            "v4_prefixes": _ris_value(latest, "v4_prefixes_ris"),
                            "v6_prefixes": _ris_value(latest, "v6_prefixes_ris"),
                            "resolution": _resolution,
                            **hod_info,
                            **trend_info,
                        }
                    else:
                        results[code] = {"status": "NO_DATA", "is_anomaly": False}
                        any_success = True
                else:
                    results[code] = {"status": "ERROR", "is_anomaly": False, "error": f"HTTP {res.status_code}"}
            except Exception as e:
                results[code] = {"status": "ERROR", "is_anomaly": False, "error": str(e)}
                last_error = str(e)
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_prefixes, last_error)
        result = {"routing_stats": results}; self.set_cache(result)
        return result

    @staticmethod
    def _compute_trend(stats: list) -> dict:
        """Compute prefix trend and ASN volatility from the RIPE stats array.

        Returns dict with:
          - prefix_trend: slope of the prefix count (per entry, negative = withdrawing)
          - prefix_trend_pct: slope as % of mean (normalized for cross-country comparison)
          - ases_trend: slope of the AS count
          - trend_entries: number of stats entries used
          - trend_label: WITHDRAWING / STABLE / GROWING

        Entries whose RIS view is absent are DROPPED, not read as 0: one
        fabricated zero in a regression drags the slope to WITHDRAWING and
        reports an outage nobody observed.
        """
        entries = list(stats or ())
        pfx_values = [value for value in (prefix_count(s) for s in entries)
                      if value is not None]
        ases_values = [value for value in (as_count(s) for s in entries)
                       if value is not None]

        if len(pfx_values) < MIN_TREND_ENTRIES:
            return {"prefix_trend": 0.0, "prefix_trend_pct": 0.0,
                    "ases_trend": 0.0, "trend_entries": len(pfx_values),
                    "trend_label": "INSUFFICIENT_DATA"}

        pfx_slope = _linear_slope(pfx_values)
        ases_slope = _linear_slope(ases_values)

        pfx_mean = sum(pfx_values) / len(pfx_values) if pfx_values else 1.0
        pfx_trend_pct = round((pfx_slope / max(pfx_mean, 1.0)) * 100, 4)

        # Label based on normalized trend
        if pfx_trend_pct < -0.5:
            label = "WITHDRAWING"
        elif pfx_trend_pct > 0.5:
            label = "GROWING"
        else:
            label = "STABLE"

        return {
            "prefix_trend": round(pfx_slope, 2),
            "prefix_trend_pct": pfx_trend_pct,
            "ases_trend": round(ases_slope, 2),
            "trend_entries": len(pfx_values),
            "trend_label": label,
        }


def _linear_slope(values: list) -> float:
    """Simple linear regression slope over sequential indices."""
    n = len(values)
    if n < 2:
        return 0.0
    xs = list(range(n))
    sx = sum(xs)
    sy = sum(values)
    sxy = sum(x * y for x, y in zip(xs, values))
    sxx = sum(x * x for x in xs)
    denom = n * sxx - sx * sx
    if denom == 0:
        return 0.0
    return (n * sxy - sx * sy) / denom
