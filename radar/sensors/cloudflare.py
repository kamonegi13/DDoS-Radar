"""radar.sensors.cloudflare -- CloudflareSensor.

Fetches CF Radar attack data (L3/L7 targets) and BGP hijack/leak events.
BGP hijack/leak detection uses the existing CF API token and provides
state-level BGP manipulation signals with confidence scoring.
"""
from __future__ import annotations
import requests
import time
import logging
from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY, CF_HEADERS, CURRENT_DATE_RANGE,
)
from radar.sensors.base import BaseSensor
from radar.state import _cf_scoring_cache, _cf_cache_lock

log = logging.getLogger("radar")

# Minimum confidence for BGP hijack/leak events to be included
BGP_EVENT_MIN_CONFIDENCE = 50


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
            if self.handle_rate_limit(r3, duration):
                return self.get_cache() or {"active": True, "date_range": CURRENT_DATE_RANGE}
            elif r3.status_code == 200:
                l3_data = r3.json().get("result", {}).get("top_0", [])
                r7 = requests.get(l7_url, headers=CF_HEADERS, params=params, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                l7_data = r7.json().get("result", {}).get("top_0", []) if r7.status_code == 200 else []
                records = len(l3_data) + len(l7_data)
                duration = round((time.time() - t0) * 1000)
                now = time.time()
                with _cf_cache_lock:
                    _cf_scoring_cache[(l3_url, frozenset(params.items()))] = {"time": now, "data": l3_data}
                    _cf_scoring_cache[(l7_url, frozenset(params.items()))] = {"time": now, "data": l7_data}
                result = {"active": True, "date_range": CURRENT_DATE_RANGE, "l3_targets": l3_data, "l7_targets": l7_data}

                # Fetch BGP hijack and leak events (non-critical; failure does not block main data)
                bgp_hijacks, bgp_leaks = self._fetch_bgp_events()
                result["bgp_hijacks"] = bgp_hijacks
                result["bgp_leaks"] = bgp_leaks
                records += len(bgp_hijacks) + len(bgp_leaks)

                self.log_fetch(True, round((time.time() - t0) * 1000), r3.status_code, records)
            else:
                result = {"active": True, "date_range": CURRENT_DATE_RANGE}
                self.log_fetch(False, duration, r3.status_code, 0)
        except Exception as e:
            duration = round((time.time() - t0) * 1000)
            result = {"active": True, "date_range": CURRENT_DATE_RANGE}
            self.log_fetch(False, duration, 0, 0, str(e))
        self.set_cache(result)
        return result

    @staticmethod
    def _fetch_bgp_events() -> tuple[list, list]:
        """Fetch BGP hijack and leak events from CF Radar.

        Returns (hijacks, leaks) as lists of parsed event dicts.
        Non-critical: returns empty lists on any failure.
        """
        hijacks = []
        leaks = []
        try:
            # BGP Hijacks
            r = requests.get(
                "https://api.cloudflare.com/client/v4/radar/bgp/hijacks/events",
                headers=CF_HEADERS,
                params={"dateRange": "1d", "format": "json"},
                timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
            )
            if r.status_code == 200:
                events = r.json().get("result", {}).get("asn_hijacks", [])
                for ev in events:
                    confidence = ev.get("confidence", 0)
                    if confidence < BGP_EVENT_MIN_CONFIDENCE:
                        continue
                    hijacks.append({
                        "type": "hijack",
                        "confidence": confidence,
                        "prefix": ev.get("prefix", ""),
                        "victim_asn": ev.get("victim_asn"),
                        "hijacker_asn": ev.get("hijacker_asn"),
                        "victim_country": (ev.get("victim_country") or "").upper(),
                        "hijacker_country": (ev.get("hijacker_country") or "").upper(),
                        "is_ongoing": ev.get("is_ongoing", False),
                        "duration": ev.get("duration"),
                    })
        except Exception as e:
            log.debug(f"[CF] BGP hijack fetch error: {e}")

        try:
            # BGP Leaks
            r = requests.get(
                "https://api.cloudflare.com/client/v4/radar/bgp/leaks/events",
                headers=CF_HEADERS,
                params={"dateRange": "1d", "format": "json"},
                timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
            )
            if r.status_code == 200:
                events = r.json().get("result", {}).get("asn_leaks", [])
                for ev in events:
                    leaks.append({
                        "type": "leak",
                        "leak_asn": ev.get("leak_asn"),
                        "leak_country": (ev.get("leak_country") or "").upper(),
                        "leaked_prefix_count": ev.get("leaked_prefix_count", 0),
                        "origin_asn": ev.get("origin_asn"),
                        "peer_count": ev.get("peer_count", 0),
                    })
        except Exception as e:
            log.debug(f"[CF] BGP leak fetch error: {e}")

        return hijacks, leaks
