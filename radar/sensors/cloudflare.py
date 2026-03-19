"""radar.sensors.cloudflare -- CloudflareSensor."""
from __future__ import annotations
import requests
import time
from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY, CF_HEADERS, CURRENT_DATE_RANGE,
)
from radar.sensors.base import BaseSensor
from radar.state import _cf_scoring_cache

class CloudflareSensor(BaseSensor):
    def __init__(self): super().__init__("cloudflare_radar", "cyber", 900)
    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        params = {"dateRange": CURRENT_DATE_RANGE, "format": "json"}
        l3_url = "https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target"
        l7_url = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target"
        try:
            r3 = requests.get(l3_url, headers=CF_HEADERS, params=params, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            duration = round((time.time() - t0) * 1000)
            if r3.status_code == 200:
                l3_data = r3.json().get("result", {}).get("top_0", [])
                r7 = requests.get(l7_url, headers=CF_HEADERS, params=params, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                l7_data = r7.json().get("result", {}).get("top_0", []) if r7.status_code == 200 else []
                records = len(l3_data) + len(l7_data)
                duration = round((time.time() - t0) * 1000)  # Remeasure after both L3+L7 requests complete
                now = time.time()
                _cf_scoring_cache[(l3_url, frozenset(params.items()))] = {"time": now, "data": l3_data}
                _cf_scoring_cache[(l7_url, frozenset(params.items()))] = {"time": now, "data": l7_data}
                result = {"active": True, "date_range": CURRENT_DATE_RANGE, "l3_targets": l3_data, "l7_targets": l7_data}
                self.log_fetch(True, duration, r3.status_code, records)
            else:
                result = {"active": True, "date_range": CURRENT_DATE_RANGE}
                self.log_fetch(False, duration, r3.status_code, 0)
        except Exception as e:
            duration = round((time.time() - t0) * 1000)
            result = {"active": True, "date_range": CURRENT_DATE_RANGE}
            self.log_fetch(False, duration, 0, 0, str(e))
        self.set_cache(result)
        return result
