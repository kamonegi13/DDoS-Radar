"""radar.sensors.ioda -- IodaSensor."""
from __future__ import annotations
import requests
import time
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
)
from radar.sensors.base import BaseSensor

class IodaSensor(BaseSensor):
    def __init__(self): super().__init__("ioda_bgp", "physical", 300)
    def fetch(self, context: dict) -> dict:
        headers = context.get("cf_headers", {})
        results = {}
        t0 = time.time(); total_anomalies = 0; any_success = False; last_status = 0; last_error = ""
        # Fetch the entire world in one request and map against all countries in COUNTRY_COORDS
        url = "https://api.cloudflare.com/client/v4/radar/traffic_anomalies"
        params = {"dateRange": "1d", "format": "json"}
        all_codes = list(COUNTRY_COORDS.keys())
        try:
            res = requests.get(url, headers=headers, params=params, timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            last_status = res.status_code
            if res.status_code == 200:
                anomalies = res.json().get("result", {}).get("trafficAnomalies", [])
                affected = {a.get("locationAlpha2", "").upper() for a in anomalies if a.get("locationAlpha2")}
                for code in all_codes:
                    results[code] = "BGP_OUTAGE" if code in affected else "NORMAL"
                total_anomalies = len(anomalies); any_success = True
            else:
                last_error = f"HTTP {last_status}"
        except Exception as e:
            last_error = str(e)
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_anomalies, last_error)
        if any_success:
            result = {"statuses": results}
            self.set_cache(result)
            return result
        # On error: preserve previous cache so existing BGP_OUTAGE detections are not wiped
        return self.get_cache() or {"statuses": {code: "NORMAL" for code in all_codes}}
