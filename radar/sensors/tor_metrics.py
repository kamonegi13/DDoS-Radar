"""radar.sensors.tor_metrics -- Tor network metrics sensor (Onionoo).

Queries the Tor Project Onionoo API for censorship/disruption indicators:
  - Running relay counts per country (drop = blocking/disruption)
  - Bridge user estimates per country (surge = circumvention activity)
  - Combined: relay drop + user surge = censorship indicator

All endpoints are free, require no authentication.
Data updates roughly hourly with Tor consensus.

API base: https://onionoo.torproject.org/
"""
from __future__ import annotations
import requests
import time
import logging
from radar.config import COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY
from radar.sensors.base import BaseSensor

log = logging.getLogger("radar")

ONIONOO_BASE = "https://onionoo.torproject.org"

# Thresholds for anomaly detection (used before adaptive z-score warms up)
RELAY_DROP_FALLBACK_PCT = 0.40    # 40% relay count drop
USER_SURGE_FALLBACK_PCT = 1.00    # 100% user count increase


class TorMetricsSensor(BaseSensor):
    """Tor Metrics sensor: relay counts and bridge user estimates per country."""

    def __init__(self):
        super().__init__("tor_metrics", "info", 1800)
        self._prev_relay_counts: dict[str, int] = {}
        self._prev_user_counts: dict[str, int] = {}

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_theaters", [])
        if not theaters:
            theaters = list(COUNTRY_COORDS.keys())[:20]

        relay_counts: dict[str, dict] = {}
        client_estimates: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        last_status = 0
        last_error = ""

        # 1. Relay summary per country
        for code in theaters:
            try:
                url = f"{ONIONOO_BASE}/summary"
                params = {"country": code.lower()}
                res = requests.get(url, params=params, timeout=15,
                                   proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                                   headers={"Accept": "application/json"})
                last_status = res.status_code
                if res.status_code == 429:
                    self.handle_rate_limit(res, round((time.time() - t0) * 1000))
                    break
                elif res.status_code == 200:
                    data = res.json()
                    relays = data.get("relays", [])
                    bridges = data.get("bridges", [])
                    running_relays = sum(1 for r in relays if r.get("r", False))
                    running_bridges = sum(1 for b in bridges if b.get("r", False))
                    total_bw = sum(r.get("bw", 0) for r in relays if r.get("r"))

                    prev = self._prev_relay_counts.get(code, running_relays)
                    drop_pct = (prev - running_relays) / max(prev, 1) if prev > 0 else 0

                    relay_counts[code] = {
                        "running": running_relays,
                        "bridges": running_bridges,
                        "bandwidth_kbps": total_bw,
                        "prev": prev,
                        "drop_pct": round(drop_pct, 3),
                    }
                    any_success = True
                time.sleep(0.5)
            except Exception as e:
                last_error = f"relays({code}): {e}"

        # 2. Bridge client estimates per country
        for code in theaters:
            try:
                url = f"{ONIONOO_BASE}/clients"
                params = {"country": code.lower()}
                res = requests.get(url, params=params, timeout=15,
                                   proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                                   headers={"Accept": "application/json"})
                if res.status_code == 200:
                    data = res.json()
                    bridges = data.get("bridges", [])
                    # Get the latest client count from the most recent bridge
                    total_users = 0
                    for bridge in bridges:
                        avg_clients = bridge.get("average_clients", {})
                        cc_lower = code.lower()
                        if cc_lower in avg_clients:
                            total_users += avg_clients[cc_lower]

                    prev_users = self._prev_user_counts.get(code, total_users)
                    surge_pct = ((total_users - prev_users) / max(prev_users, 1)
                                 if prev_users > 0 else 0)
                    trend = ("SURGE" if surge_pct > USER_SURGE_FALLBACK_PCT
                             else "DROP" if surge_pct < -0.3
                             else "NORMAL")

                    client_estimates[code] = {
                        "bridge_users": total_users,
                        "prev_users": prev_users,
                        "surge_pct": round(surge_pct, 3),
                        "trend": trend,
                    }
                    any_success = True
                time.sleep(0.5)
            except Exception as e:
                last_error = f"clients({code}): {e}"

        # Determine country status
        for code in theaters:
            rc = relay_counts.get(code, {})
            ce = client_estimates.get(code, {})
            relay_drop = rc.get("drop_pct", 0) >= RELAY_DROP_FALLBACK_PCT
            user_surge = ce.get("trend") == "SURGE"

            if relay_drop and user_surge:
                country_status[code] = "CENSORSHIP_INDICATOR"
            elif relay_drop:
                country_status[code] = "RELAY_DROP"
            elif user_surge:
                country_status[code] = "USER_SURGE"
            else:
                country_status[code] = "NORMAL"

        # Update previous counts for next cycle
        for code, rc in relay_counts.items():
            if rc.get("running", 0) > 0:
                self._prev_relay_counts[code] = rc["running"]
        for code, ce in client_estimates.items():
            if ce.get("bridge_users", 0) > 0:
                self._prev_user_counts[code] = ce["bridge_users"]

        duration = round((time.time() - t0) * 1000)
        total_records = len(relay_counts) + len(client_estimates)
        self.log_fetch(any_success, duration, last_status, total_records, last_error)

        result = {
            "relay_counts": relay_counts,
            "client_estimates": client_estimates,
            "country_status": country_status,
        }
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "relay_counts": {}, "client_estimates": {},
            "country_status": {c: "NORMAL" for c in theaters},
        }
