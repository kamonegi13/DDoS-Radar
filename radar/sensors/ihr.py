"""radar.sensors.ihr -- Internet Health Report (IHR) sensor.

Queries IIJ/RIPE Internet Health Report for three independent signals:
  - Disconnection events (country-level connectivity outages)
  - Hegemony alarms (routing dependency anomalies)
  - Network delay alarms (latency spikes)

All endpoints are free, require no authentication, and return JSON
with native country-level granularity.

API base: https://ihr.iijlab.net/ihr/api/
"""
from __future__ import annotations
import requests
import time
import logging
import datetime
from radar.config import COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY
from radar.sensors.base import BaseSensor

log = logging.getLogger("radar")

IHR_API_BASE = "https://ihr.iijlab.net/ihr/api"


class IhrSensor(BaseSensor):
    """IHR sensor: disconnection events, hegemony alarms, network delay."""

    def __init__(self):
        super().__init__("ihr_health", "physical", 300)

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        all_codes = list(COUNTRY_COORDS.keys())
        disco_data: dict[str, list] = {}
        hegemony_alarms: dict[str, list] = {}
        delay_alarms: dict[str, list] = {}
        country_status: dict[str, str] = {}
        any_success = False
        last_status = 0
        last_error = ""

        now = datetime.datetime.now(datetime.timezone.utc)
        since = (now - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M")
        until = now.strftime("%Y-%m-%dT%H:%M")

        # 1. Disconnection events (per-country)
        try:
            for code in all_codes:
                url = f"{IHR_API_BASE}/disco/events/"
                params = {
                    "streamtype": "country",
                    "streamname": code,
                    "starttime": since,
                    "endtime": until,
                    "format": "json",
                }
                res = requests.get(url, params=params, timeout=15,
                                   proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                last_status = res.status_code
                if res.status_code == 200:
                    data = res.json()
                    results = data.get("results", data) if isinstance(data, dict) else data
                    if isinstance(results, list) and results:
                        disco_data[code] = [
                            {
                                "ts": e.get("starttime", ""),
                                "endtime": e.get("endtime", ""),
                                "level": e.get("level", 0),
                                "avglevel": e.get("avglevel", 0),
                                "nbprobes": e.get("nbprobes", 0),
                            }
                            for e in results
                        ]
                    any_success = True
                # Rate limit courtesy: small delay between per-country queries
                time.sleep(0.3)
        except Exception as e:
            last_error = f"disco: {e}"
            log.warning(f"[IHR] Disco events error: {e}")

        # 2. Hegemony alarms (global, then filter by country)
        try:
            url = f"{IHR_API_BASE}/hegemony/alarms/"
            params = {"starttime": since, "endtime": until, "format": "json"}
            res = requests.get(url, params=params, timeout=20,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 200:
                data = res.json()
                results = data.get("results", data) if isinstance(data, dict) else data
                if isinstance(results, list):
                    for alarm in results:
                        code = (alarm.get("entity", {}).get("code", "")
                                or alarm.get("country", "")).upper()
                        if code and code in COUNTRY_COORDS:
                            hegemony_alarms.setdefault(code, []).append({
                                "asn": alarm.get("asn") or alarm.get("originasn"),
                                "deviation": alarm.get("deviation", 0),
                                "ts": alarm.get("timebin", ""),
                            })
                any_success = True
        except Exception as e:
            last_error = f"hegemony: {e}"
            log.warning(f"[IHR] Hegemony alarms error: {e}")

        # 3. Network delay alarms (global, then filter by country)
        try:
            url = f"{IHR_API_BASE}/network_delay/alarms/"
            params = {"starttime": since, "endtime": until, "format": "json"}
            res = requests.get(url, params=params, timeout=20,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 200:
                data = res.json()
                results = data.get("results", data) if isinstance(data, dict) else data
                if isinstance(results, list):
                    for alarm in results:
                        # Extract country from startpoint or endpoint
                        link = alarm.get("link", "")
                        cc = (alarm.get("startpoint_name", "")
                              or alarm.get("endpoint_name", "")).upper()[:2]
                        if cc and cc in COUNTRY_COORDS:
                            delay_alarms.setdefault(cc, []).append({
                                "link": link,
                                "deviation": alarm.get("deviation", 0),
                                "ts": alarm.get("timebin", ""),
                            })
                any_success = True
        except Exception as e:
            last_error = f"delay: {e}"
            log.warning(f"[IHR] Delay alarms error: {e}")

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
