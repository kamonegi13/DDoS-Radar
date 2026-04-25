"""radar.sensors.bgp_routing -- BgpRoutingSensor.

Now uses the full stats time series from RIPE to compute prefix trend
(slope of announced_prefixes over time) and ASN volatility in addition
to the existing drop_ratio and HOD Z-score anomaly detection.
"""
from __future__ import annotations
import requests
import time
from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY, HOD_MIN_SAME_HOUR, HOD_MAX_ENTRIES,
)
from radar.sensors.base import BaseSensor
from radar.scenarios import SensorTier
from radar.database import db as _db

# Minimum stats entries required for trend computation
MIN_TREND_ENTRIES = 3


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
        for idx, code in enumerate(theaters):
            if idx > 0:
                time.sleep(0.3)  # Courtesy interval for RIPE Stat API (free tier)
            try:
                res = requests.get("https://stat.ripe.net/data/country-routing-stats/data.json", params={"resource": code, "sourceapp": "osint-radar"}, timeout=12, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
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
                    stats = res.json().get("data", {}).get("stats", [])
                    if stats:
                        latest = stats[-1]; pfx_now = latest.get("announced_prefixes", 0); ases_now = latest.get("seen_ases", 0)
                        bl = self._baseline.get(code, {})
                        if not bl: self._baseline[code] = {"prefixes": pfx_now, "ases": ases_now, "ts": _now}; bl = self._baseline[code]
                        # Refresh baseline BEFORE computing drop_ratio so the first reading
                        # after an hourly reset uses the new baseline, not the stale one.
                        if _now - bl.get("ts", 0) > 3600:
                            self._baseline[code] = {"prefixes": pfx_now, "ases": ases_now, "ts": _now}; bl = self._baseline[code]
                        pfx_base = bl.get("prefixes", pfx_now) or pfx_now
                        drop_ratio = max(0.0, (pfx_base - pfx_now) / pfx_base) if pfx_base else 0.0
                        total_prefixes += pfx_now; any_success = True

                        # HOD Z-score: record one entry per UTC hour bucket
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
        """Compute prefix trend and ASN volatility from full RIPE stats array.

        Returns dict with:
          - prefix_trend: slope of announced_prefixes (prefixes/entry, negative = withdrawing)
          - prefix_trend_pct: slope as % of mean (normalized for cross-country comparison)
          - ases_trend: slope of seen_ases
          - trend_entries: number of stats entries used
          - trend_label: WITHDRAWING / STABLE / GROWING
        """
        if len(stats) < MIN_TREND_ENTRIES:
            return {"prefix_trend": 0.0, "prefix_trend_pct": 0.0,
                    "ases_trend": 0.0, "trend_entries": len(stats),
                    "trend_label": "INSUFFICIENT_DATA"}

        pfx_values = [s.get("announced_prefixes", 0) for s in stats]
        ases_values = [s.get("seen_ases", 0) for s in stats]

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
            "trend_entries": len(stats),
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
