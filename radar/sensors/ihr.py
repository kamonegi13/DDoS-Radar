"""radar.sensors.ihr -- Internet Health Report (IHR) sensor.

Queries IIJ/RIPE Internet Health Report for three independent signals:
  - Disconnection events (country-level connectivity outages)
  - Hegemony alarms (routing dependency anomalies)
  - Network delay alarms (latency spikes)

All endpoints are free, require no authentication, and return JSON
with native country-level granularity.

API base: https://ihr.iijlab.net/ihr/api/
Note: ihr.iijlab.net 301-redirects to www.ihr.live.
We hit www.ihr.live directly and disable redirect-following
to avoid double-hop latency through corporate proxies.
"""
from __future__ import annotations
import requests
import time
import logging
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from radar.config import COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY
from radar.sensors.base import BaseSensor

log = logging.getLogger("radar")

# Canonical hostname (ihr.iijlab.net redirects here via 301)
IHR_API_BASE = "https://www.ihr.live/ihr/api"


class IhrSensor(BaseSensor):
    """IHR sensor: disconnection events, hegemony alarms, network delay."""

    def __init__(self):
        super().__init__("ihr_health", "physical", 300)

    def _fetch_disco(self, since: str, until: str) -> tuple[dict, int, str]:
        """Fetch disconnection events. Returns (data_dict, http_status, error)."""
        url = f"{IHR_API_BASE}/disco/events/"
        params = {"streamtype": "country", "starttime": since, "endtime": until, "format": "json"}
        try:
            res = requests.get(url, params=params, timeout=30,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 200:
                data = res.json()
                results = data.get("results", data) if isinstance(data, dict) else data
                out: dict[str, list] = {}
                if isinstance(results, list):
                    for e in results:
                        code = (e.get("streamname", "") or "").upper()
                        if code and code in COUNTRY_COORDS:
                            out.setdefault(code, []).append({
                                "ts": e.get("starttime", ""),
                                "endtime": e.get("endtime", ""),
                                "level": e.get("level", 0),
                                "avglevel": e.get("avglevel", 0),
                                "nbprobes": e.get("nbprobes", 0),
                            })
                return out, res.status_code, ""
            return {}, res.status_code, f"HTTP {res.status_code}"
        except Exception as e:
            log.warning(f"[IHR] Disco events error: {e}")
            return {}, 0, f"disco: {e}"

    def _fetch_hegemony(self, since: str, until: str) -> tuple[dict, int, str]:
        """Fetch hegemony alarms. Returns (data_dict, http_status, error)."""
        url = f"{IHR_API_BASE}/hegemony/alarms/"
        params = {"starttime": since, "endtime": until, "format": "json"}
        try:
            res = requests.get(url, params=params, timeout=30,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 200:
                data = res.json()
                results = data.get("results", data) if isinstance(data, dict) else data
                out: dict[str, list] = {}
                if isinstance(results, list):
                    for alarm in results:
                        code = (alarm.get("entity", {}).get("code", "")
                                or alarm.get("country", "")).upper()
                        if code and code in COUNTRY_COORDS:
                            out.setdefault(code, []).append({
                                "asn": alarm.get("asn") or alarm.get("originasn"),
                                "deviation": alarm.get("deviation", 0),
                                "ts": alarm.get("timebin", ""),
                            })
                return out, res.status_code, ""
            return {}, res.status_code, f"HTTP {res.status_code}"
        except Exception as e:
            log.warning(f"[IHR] Hegemony alarms error: {e}")
            return {}, 0, f"hegemony: {e}"

    def _fetch_delay(self, since: str, until: str) -> tuple[dict, int, str]:
        """Fetch network delay alarms. Returns (data_dict, http_status, error)."""
        url = f"{IHR_API_BASE}/network_delay/alarms/"
        params = {"starttime": since, "endtime": until, "format": "json"}
        try:
            res = requests.get(url, params=params, timeout=30,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 200:
                data = res.json()
                results = data.get("results", data) if isinstance(data, dict) else data
                out: dict[str, list] = {}
                if isinstance(results, list):
                    for alarm in results:
                        link = alarm.get("link", "")
                        cc = (alarm.get("startpoint_name", "")
                              or alarm.get("endpoint_name", "")).upper()[:2]
                        if cc and cc in COUNTRY_COORDS:
                            out.setdefault(cc, []).append({
                                "link": link,
                                "deviation": alarm.get("deviation", 0),
                                "ts": alarm.get("timebin", ""),
                            })
                return out, res.status_code, ""
            return {}, res.status_code, f"HTTP {res.status_code}"
        except Exception as e:
            log.warning(f"[IHR] Delay alarms error: {e}")
            return {}, 0, f"delay: {e}"

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        all_codes = list(COUNTRY_COORDS.keys())
        country_status: dict[str, str] = {}
        any_success = False
        last_status = 0
        last_error = ""

        now = datetime.datetime.now(datetime.timezone.utc)
        since = (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")
        until = now.strftime("%Y-%m-%dT%H:%M")

        # Fire all 3 IHR endpoints concurrently — reduces worst-case latency
        # from 3×30s=90s to ~30s (max of parallel calls).
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_disco = ex.submit(self._fetch_disco, since, until)
            f_heg   = ex.submit(self._fetch_hegemony, since, until)
            f_delay = ex.submit(self._fetch_delay, since, until)
            disco_data,      status_d, err_d = f_disco.result()
            hegemony_alarms, status_h, err_h = f_heg.result()
            delay_alarms,    status_l, err_l = f_delay.result()

        errors = [e for e in (err_d, err_h, err_l) if e]
        last_error = "; ".join(errors) if errors else ""
        # Consider any successful endpoint a partial success
        if not err_d or disco_data:
            any_success = True
            last_status = status_d
        if not err_h or hegemony_alarms:
            any_success = True
            last_status = last_status or status_h
        if not err_l or delay_alarms:
            any_success = True
            last_status = last_status or status_l

        # Compute per-country status
        total_events = 0
        for code in all_codes:
            discos = disco_data.get(code, [])
            heg = hegemony_alarms.get(code, [])
            delays = delay_alarms.get(code, [])
            if discos:
                country_status[code] = "DISCO_EVENT"
                total_events += len(discos)
            elif heg:
                country_status[code] = "HEGEMONY_ALARM"
                total_events += len(heg)
            elif delays:
                country_status[code] = "DELAY_ANOMALY"
                total_events += len(delays)
            else:
                country_status[code] = "NORMAL"

        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, last_status, total_events, last_error)

        result = {
            "disconnections": disco_data,
            "hegemony_alarms": hegemony_alarms,
            "delay_alarms": delay_alarms,
            "country_status": country_status,
        }
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "disconnections": {}, "hegemony_alarms": {},
            "delay_alarms": {}, "country_status": {c: "NORMAL" for c in all_codes},
        }
