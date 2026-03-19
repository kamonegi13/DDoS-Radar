"""radar.sensors.bgp_routing -- BgpRoutingSensor."""
from __future__ import annotations
import requests
import time
from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY, HOD_MIN_SAME_HOUR, HOD_MAX_ENTRIES,
)
from radar.sensors.base import BaseSensor

class BgpRoutingSensor(BaseSensor):
    BGP_DROP_THRESHOLD = 0.15
    BGP_HOD_MIN        = HOD_MIN_SAME_HOUR
    BGP_HOD_MAX        = HOD_MAX_ENTRIES
    def __init__(self):
        super().__init__("ripe_bgp", "cyber", 1800); self._baseline: dict = {}
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", []); results: dict = {}
        t0 = time.time(); total_prefixes = 0; any_success = False; last_status = 0; last_error = ""
        _now = time.time()
        _bgp_hour_bucket = int(_now // 3600) * 3600
        _bgp_cur_hod     = (_bgp_hour_bucket // 3600) % 24
        for code in theaters:
            try:
                res = requests.get("https://stat.ripe.net/data/country-routing-stats/data.json", params={"resource": code, "sourceapp": "osint-radar"}, timeout=12, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                last_status = res.status_code
                if res.status_code == 200:
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
                        _bgp_entries = bgp_hod_db.setdefault(code, [])
                        if not _bgp_entries or _bgp_entries[-1][0] != _bgp_hour_bucket:
                            _bgp_entries.append((_bgp_hour_bucket, pfx_now))
                            bgp_hod_db[code] = _bgp_entries[-self.BGP_HOD_MAX:]
                        _bgp_same_hour = [p for (ts, p) in bgp_hod_db[code]
                                          if (ts // 3600) % 24 == _bgp_cur_hod and ts < _bgp_hour_bucket]
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

                        results[code] = {
                            "announced_prefixes": pfx_now, "baseline_prefixes": pfx_base,
                            "seen_ases": ases_now, "drop_pct": round(drop_ratio * 100, 1),
                            "is_anomaly": is_anomaly,
                            "status": "ANOMALY" if is_anomaly else "NORMAL",
                            **hod_info,
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
