"""radar.sensors.ioda -- IodaSensor using Georgia Tech IODA proper API.

IODA (Internet Outage Detection and Analysis) provides three independent
observation methods:
  - bgp: BGP route monitoring (~5 min freshness)
  - merit-nt: Merit Network Telescope backscatter (~5 min)
  - ping-slash24: Active probing of 4.2M /24 blocks (~10 min)

The sensor queries the IODA alerts API for country-level anomalies and
falls back to CF Radar traffic_anomalies when the IODA API is unreachable.
"""
from __future__ import annotations
import requests
import time
import logging
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
)
from radar.sensors.base import BaseSensor

log = logging.getLogger("radar")

# IODA alert levels: "normal", "warning", "critical"
IODA_ALERT_LEVELS = {"warning", "critical"}

# Datasources we care about (ordered by reliability for DDoS detection)
IODA_DATASOURCES = ("bgp", "merit-nt", "ping-slash24")


class IodaSensor(BaseSensor):
    """IODA sensor: queries Georgia Tech IODA API for internet outage alerts.

    Returns per-country status (NORMAL / BGP_OUTAGE) plus detailed
    per-datasource alert info when available.
    """

    IODA_API_BASE = "https://api.ioda.inetintel.cc.gatech.edu/v2"

    def __init__(self):
        super().__init__("ioda_bgp", "physical", 300)

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        all_codes = list(COUNTRY_COORDS.keys())

        # Try IODA proper API first
        result = self._fetch_ioda_proper(all_codes, t0)
        if result is not None:
            return result

        # Fallback: CF Radar traffic_anomalies (legacy behavior)
        log.info("[IODA] IODA API unreachable, falling back to CF Radar traffic_anomalies")
        return self._fetch_cf_fallback(context, all_codes, t0)

    def _fetch_ioda_proper(self, all_codes: list, t0: float) -> dict | None:
        """Fetch alerts from the real IODA API. Returns None on failure."""
        # Query alerts for the last 2 hours (IODA uses Unix timestamps)
        now = int(time.time())
        since = now - 7200  # 2 hours lookback
        url = f"{self.IODA_API_BASE}/outages/alerts"
        params = {
            "from": since,
            "until": now,
            "entityType": "country",
            "limit": 200,
        }
        try:
            res = requests.get(url, params=params, timeout=20,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 429:
                self.handle_rate_limit(res, round((time.time() - t0) * 1000))
                cached = self.get_cache()
                return cached if cached else None
            if res.status_code != 200:
                log.warning(f"[IODA] IODA API returned HTTP {res.status_code}")
                return None

            data = res.json()
            alerts = data if isinstance(data, list) else data.get("data", data.get("alerts", []))
            if not isinstance(alerts, list):
                log.warning(f"[IODA] Unexpected response format: {type(alerts)}")
                return None

            # Parse alerts: build per-country detail
            # Keep only the most recent alert per (country, datasource) pair
            # to correctly handle recovery (level=normal) after an outage.
            country_alerts: dict[str, dict] = {}
            for alert in alerts:
                entity = alert.get("entity", {})
                code = (entity.get("code") or "").upper()
                if not code or code not in COUNTRY_COORDS:
                    continue

                datasource = alert.get("datasource", "")
                level = alert.get("level", "normal")
                alert_time = alert.get("time", 0)

                if code not in country_alerts:
                    country_alerts[code] = {"alert_sources": {}}
                ca = country_alerts[code]

                # Keep only the latest alert per datasource
                existing = ca["alert_sources"].get(datasource)
                if existing is None or alert_time >= existing.get("time", 0):
                    ca["alert_sources"][datasource] = {
                        "level": level,
                        "value": alert.get("value"),
                        "history_value": alert.get("historyValue"),
                        "time": alert_time,
                    }

            # Compute max_level from the latest alerts per datasource
            for ca in country_alerts.values():
                levels = [s["level"] for s in ca["alert_sources"].values()]
                if "critical" in levels:
                    ca["max_level"] = "critical"
                elif "warning" in levels:
                    ca["max_level"] = "warning"
                else:
                    ca["max_level"] = "normal"

            # Build statuses and details
            statuses = {}
            details = {}
            total_anomalies = 0
            for code in all_codes:
                ca = country_alerts.get(code)
                if ca and ca["max_level"] in IODA_ALERT_LEVELS:
                    statuses[code] = "BGP_OUTAGE"
                    total_anomalies += 1
                    details[code] = {
                        "level": ca["max_level"],
                        "sources": ca["alert_sources"],
                        "source_count": len(ca["alert_sources"]),
                    }
                else:
                    statuses[code] = "NORMAL"

            duration = round((time.time() - t0) * 1000)
            self.log_fetch(True, duration, 200, total_anomalies)
            result = {
                "statuses": statuses,
                "ioda_details": details,
                "source": "ioda_proper",
            }
            self.set_cache(result)
            return result

        except Exception as e:
            log.warning(f"[IODA] IODA API error: {e}")
            return None

    def _fetch_cf_fallback(self, context: dict, all_codes: list, t0: float) -> dict:
        """Fallback: query CF Radar traffic_anomalies (legacy behavior)."""
        headers = context.get("cf_headers", {})
        results = {}
        total_anomalies = 0
        any_success = False
        last_status = 0
        last_error = ""
        url = "https://api.cloudflare.com/client/v4/radar/traffic_anomalies"
        params = {"dateRange": "1d", "format": "json"}
        try:
            res = requests.get(url, headers=headers, params=params, timeout=15,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            last_status = res.status_code
            if res.status_code == 200:
                anomalies = res.json().get("result", {}).get("trafficAnomalies", [])
                affected = {a.get("locationAlpha2", "").upper()
                            for a in anomalies if a.get("locationAlpha2")}
                for code in all_codes:
                    results[code] = "BGP_OUTAGE" if code in affected else "NORMAL"
                total_anomalies = len(anomalies)
                any_success = True
            else:
                last_error = f"HTTP {last_status}"
        except Exception as e:
            last_error = str(e)

        self.log_fetch(any_success, round((time.time() - t0) * 1000),
                       last_status, total_anomalies, last_error)
        if any_success:
            result = {"statuses": results, "source": "cf_fallback"}
            self.set_cache(result)
            return result
        return self.get_cache() or {"statuses": {code: "NORMAL" for code in all_codes},
                                    "source": "cache_or_default"}
