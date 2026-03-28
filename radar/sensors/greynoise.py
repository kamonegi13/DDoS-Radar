"""radar.sensors.greynoise -- GreyNoiseSensor."""
from __future__ import annotations
import datetime
import logging
import re
import requests
import threading
import time
import os
from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY,
)
from radar.sensors.base import BaseSensor

GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
log = logging.getLogger("radar")

class GreyNoiseSensor(BaseSensor):
    """
    Cyber Domain sensor: uses GreyNoise API to distinguish whether traffic is
    "indiscriminate internet noise (scanners etc.)" or "intentional attacks".
    Returns a suppression flag to attenuate threat confidence when noise ratio is high.

    - Community API (free): per-IP checks (used with ThreatFox IoCs)
    - Enterprise GNQL (paid): per-country/tag noise statistics
    Operates passively (always NORMAL) when no API key is configured.
    """
    GNQL_STATS_URL  = "https://api.greynoise.io/v2/experimental/gnql/stats"
    COMMUNITY_URL   = "https://api.greynoise.io/v3/community/{ip}"
    RIOT_URL        = "https://api.greynoise.io/v2/riot/{ip}"

    # Community API: daily request limit (free tier)
    COMMUNITY_DAILY_LIMIT = 50
    # IP lookup cache TTL (seconds): GreyNoise updates data daily
    IP_CACHE_TTL = 86400

    def __init__(self):
        super().__init__("greynoise", "cyber", 1800)
        self._gnql_unavailable: bool = False  # Set to True once Community key is confirmed (no further retries)
        # For on-demand IP lookups: cache + daily rate limit
        self._ip_cache: dict[str, dict] = {}          # ip → {result, fetched_at}
        self._daily_count: int   = 0                   # Lookup count for today
        self._daily_date:  str   = ""                  # Date string for counter reset (YYYY-MM-DD)
        self._ip_lock = threading.Lock()

    def _get_headers(self) -> dict:
        h = {"Accept": "application/json", "User-Agent": "OSINT-Radar/9.0"}
        if GREYNOISE_API_KEY:
            h["key"] = GREYNOISE_API_KEY
        return h

    def lookup_community_ip(self, ip: str) -> dict:
        """Look up noise/classification info for a single IP via Community API.
        - Cache hit (within 24h): return without API call
        - Daily limit (50 req/day) reached: return error
        - No API key: return error
        Returns: {"ip", "noise", "riot", "classification", "name", "last_seen",
                 "message", "cached", "fetched_at", "daily_remaining", "error"}
        """
        import re
        # Basic IPv4 validation
        if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
            return {"ip": ip, "error": "Invalid IPv4 address", "cached": False}

        if not GREYNOISE_API_KEY:
            return {"ip": ip, "error": "GREYNOISE_API_KEY is not configured", "cached": False}

        now = time.time()
        today = datetime.date.today().isoformat()

        with self._ip_lock:
            # Reset counter if the date has changed
            if self._daily_date != today:
                self._daily_count = 0
                self._daily_date  = today

            # Cache check
            cached = self._ip_cache.get(ip)
            if cached and (now - cached["fetched_at"]) < self.IP_CACHE_TTL:
                result = dict(cached["result"])
                result["cached"]          = True
                result["daily_remaining"] = max(0, self.COMMUNITY_DAILY_LIMIT - self._daily_count)
                return result

            # Rate limit check
            if self._daily_count >= self.COMMUNITY_DAILY_LIMIT:
                return {
                    "ip": ip, "cached": False,
                    "daily_remaining": 0,
                    "error": f"Daily limit ({self.COMMUNITY_DAILY_LIMIT} req/day) reached. Resets at UTC 0:00 tomorrow."
                }

            # API call
            self._daily_count += 1
            remaining = self.COMMUNITY_DAILY_LIMIT - self._daily_count

        # HTTP call outside the lock
        try:
            url = self.COMMUNITY_URL.format(ip=ip)
            res = requests.get(url, headers=self._get_headers(),
                               timeout=8, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 404:
                # IP not observed by GreyNoise
                result = {
                    "ip": ip, "noise": False, "riot": False,
                    "classification": "unknown", "name": None,
                    "last_seen": None, "message": "This IP has not been observed by GreyNoise.",
                    "cached": False, "fetched_at": now, "daily_remaining": remaining, "error": None
                }
            elif res.status_code == 429:
                with self._ip_lock:
                    self._daily_count = max(0, self._daily_count - 1)
                    actual_remaining = max(0, self.COMMUNITY_DAILY_LIMIT - self._daily_count)
                return {"ip": ip, "cached": False, "daily_remaining": actual_remaining,
                        "error": "rate_limited(429)"}
            elif res.status_code != 200:
                with self._ip_lock:
                    self._daily_count = max(0, self._daily_count - 1)  # Roll back count on failure
                    actual_remaining = max(0, self.COMMUNITY_DAILY_LIMIT - self._daily_count)
                return {"ip": ip, "cached": False, "daily_remaining": actual_remaining,
                        "error": f"HTTP {res.status_code}"}
            else:
                d = res.json()
                result = {
                    "ip":             d.get("ip", ip),
                    "noise":          d.get("noise", False),
                    "riot":           d.get("riot", False),
                    "classification": d.get("classification", "unknown"),
                    "name":           d.get("name"),
                    "last_seen":      d.get("last_seen"),
                    "message":        d.get("message"),
                    "cached":         False,
                    "fetched_at":     now,
                    "daily_remaining": remaining,
                    "error":          None
                }

            # Save to cache (with TTL eviction to prevent unbounded growth)
            with self._ip_lock:
                self._ip_cache[ip] = {"result": result, "fetched_at": now}
                # Evict expired entries (older than IP_CACHE_TTL)
                if len(self._ip_cache) > 200:
                    stale = [k for k, v in self._ip_cache.items()
                             if now - v["fetched_at"] > self.IP_CACHE_TTL]
                    for k in stale:
                        del self._ip_cache[k]
            return result

        except Exception as e:
            with self._ip_lock:
                self._daily_count = max(0, self._daily_count - 1)
                actual_remaining = max(0, self.COMMUNITY_DAILY_LIMIT - self._daily_count)
            return {"ip": ip, "cached": False, "daily_remaining": actual_remaining, "error": str(e)}

    def _query_gnql_stats(self, country_code: str) -> dict:
        """Fetch noise ratio for traffic targeting the specified country via GNQL stats.
        Requires an Enterprise API key."""
        if not GREYNOISE_API_KEY:
            return {}
        try:
            # Filtering by classification:malicious excludes benign classifications,
            # causing noise_ratio to always be 0 — fetch all traffic without filter
            query = f"metadata.destination_country:{country_code}"
            res = requests.get(
                self.GNQL_STATS_URL,
                params={"query": query, "count": 500},
                headers=self._get_headers(),
                timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if res.status_code == 401:
                # Community API key cannot access GNQL Stats (Enterprise only)
                # Warn once, then skip (do not repeat every poll)
                if not self._gnql_unavailable:
                    log.warning(f"[GreyNoise] HTTP 401 — GNQL Stats requires an Enterprise API key. "
                          f"Operating as UNKNOWN (no suppression) with Community key. (Suppressing further messages)")
                    self._gnql_unavailable = True
                return {"gnql_unavailable": True}
            if res.status_code != 200:
                return {}
            data = res.json()
            # Retrieve classification distribution
            classifications = data.get("stats", {}).get("classifications", [])
            total  = sum(c.get("count", 0) for c in classifications)
            noise  = sum(c.get("count", 0) for c in classifications
                         if c.get("classification") == "benign")
            malicious = total - noise
            noise_ratio = round(noise / total, 3) if total > 0 else 0.0
            return {
                "total_ips":    total,
                "noise_ips":    noise,
                "malicious_ips": malicious,
                "noise_ratio":  noise_ratio,
            }
        except Exception:
            return {}

    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        results: dict = {}
        t0 = time.time()
        any_success = False

        gnql_unavailable = self._gnql_unavailable  # Permanently True after first 401

        for idx, theater in enumerate(theaters):
            if idx > 0 and GREYNOISE_API_KEY and not gnql_unavailable:
                time.sleep(0.5)  # Courtesy interval for GreyNoise API (Enterprise)
            if GREYNOISE_API_KEY and not gnql_unavailable:
                # Fetch per-country noise statistics via Enterprise GNQL
                stats = self._query_gnql_stats(theater)
                if stats.get("gnql_unavailable"):
                    gnql_unavailable = True
                    self._gnql_unavailable = True
                    stats = {}
            else:
                # No API key or Community key (GNQL unavailable): treat as UNKNOWN
                stats = {}

            noise_ratio = stats.get("noise_ratio", None)

            if noise_ratio is not None:
                any_success = True
                # Noise ratio > 70% → "NOISE_DOMINANT" → attenuate threat confidence
                noise_class = ("NOISE_DOMINANT"  if noise_ratio > 0.70 else
                               "MIXED"           if noise_ratio > 0.40 else
                               "TARGETED")
                suppress_confidence = (noise_class == "NOISE_DOMINANT")
            else:
                noise_class = "UNKNOWN"
                suppress_confidence = False

            results[theater] = {
                "noise_ratio":          noise_ratio,
                "noise_class":          noise_class,
                "suppress_confidence":  suppress_confidence,
                "total_ips":            stats.get("total_ips"),
                "malicious_ips":        stats.get("malicious_ips"),
                "api_key_configured":   bool(GREYNOISE_API_KEY),
                "gnql_tier":            "community_limited" if gnql_unavailable else ("enterprise" if GREYNOISE_API_KEY else "none"),
                "status":               noise_class,
            }

        # GNQL unsupported (Community key) or no API key → UNKNOWN is normal operation, success=True
        # Return False only when all theaters are empty due to network errors
        log_success = any_success or gnql_unavailable or not GREYNOISE_API_KEY or not theaters
        self.log_fetch(log_success, round((time.time() - t0) * 1000), 200, len(results))
        result = {"greynoise": results}
        self.set_cache(result)
        return result

