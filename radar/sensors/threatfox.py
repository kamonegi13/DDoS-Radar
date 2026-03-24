"""radar.sensors.threatfox -- ThreatFoxSensor."""
from __future__ import annotations
import logging
import os
import requests
import time
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY, HTTP_PROXY,
)
from radar.sensors.base import BaseSensor
log = logging.getLogger("radar")

class ThreatFoxSensor(BaseSensor):
    def __init__(self): super().__init__("threatfox", "cyber", 3600)
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        hits = {}

        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "get_iocs", "days": 1}

        # abuse.ch now requires Auth-Key for get_iocs as well (since 2024)
        tf_api_key = os.getenv("THREATFOX_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        if tf_api_key:
            headers["Auth-Key"] = tf_api_key

        if HTTP_PROXY:
            headers["Connection"] = "Keep-Alive"

        # Skip request when API key is not set (prevents ERROR state from 401 response)
        if not tf_api_key:
            self.log_fetch(True, 0, 0, 0, "")
            result = {"hits": hits}; self.set_cache(result)
            return result

        t0 = time.time()
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            duration = round((time.time() - t0) * 1000)

            if res.status_code == 429:
                self.handle_rate_limit(res, duration)
                return self.get_cache() or {"hits": hits}
            elif res.status_code == 200:
                data = res.json()
                if data.get("query_status") in ["ok", "no_result"]:
                    iocs = data.get("data", [])
                    for code in theaters:
                        country_name = COUNTRY_COORDS.get(code, {}).get("name", "Unknown").lower()
                        # Count IoCs related to APT tags or target country name
                        count = sum(1 for ioc in iocs if (ioc.get("tags") and any("apt" in str(tag).lower() or country_name in str(tag).lower() for tag in ioc["tags"])))
                        if count > 0: hits[code] = {"count": count, "description": f"{count} APT/State-linked IoCs detected"}
                    self.log_fetch(True, duration, res.status_code, len(iocs))
                else:
                    err_msg = data.get("query_status", "Unknown error")
                    self.log_fetch(False, duration, res.status_code, 0, f"API Error: {err_msg}")
                    self.set_error(f"API Error: {err_msg}")
            elif res.status_code == 401:
                # API key auth failure: preserve existing cache to avoid wiping valid data
                log.warning(f"[ThreatFox] HTTP 401 — Auth-Key is invalid or expired. Check THREATFOX_API_KEY.")
                self.log_fetch(False, duration, res.status_code, 0, "HTTP 401 Unauthorized")
                return self.get_cache() or {"hits": {}}
            else:
                self.log_fetch(False, duration, res.status_code, 0, f"HTTP {res.status_code}")
                self.set_error(f"HTTP {res.status_code}")
        except requests.exceptions.Timeout:
            self.log_fetch(False, round((time.time() - t0) * 1000), 0, 0, "Read timed out")
            self.set_error("Timeout connecting to ThreatFox")
        except Exception as e:
            self.log_fetch(False, round((time.time() - t0) * 1000), 0, 0, str(e))
            self.set_error(str(e))

        result = {"hits": hits}; self.set_cache(result)
        return result

# ── Additional Sensors ────────────────────────────────────────────────────────
