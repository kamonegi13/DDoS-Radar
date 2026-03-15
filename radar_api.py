# radar_api.py — MDO C4ISR Dashboard — Predictive Deep Pattern Analysis
from __future__ import annotations
from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import datetime
import time
import threading
import hashlib
import os
import json
import math
import xml.etree.ElementTree as ET
import urllib3
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────────────────────────────────────
# External Config & Geo Data Loader
# ─────────────────────────────────────────────────────────────────────────────
def _load_env(path: str = "config.env") -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv(path)
        print(f"[Config] Loaded via python-dotenv: {path}")
        return
    except ImportError:
        pass
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
        print(f"[Config] Loaded manually: {path}")
    except FileNotFoundError:
        print(f"[Config] {path} not found — using defaults")

_load_env()

COUNTRY_COORDS, STATE_ASNS, AIRPORT_BOXES, CHOKEPOINTS = {}, {}, {}, []

# Country → Region mapping for UI grouping
COUNTRY_REGIONS: dict[str, str] = {
    # East Asia
    "CN": "East Asia", "JP": "East Asia", "KR": "East Asia", "TW": "East Asia",
    "KP": "East Asia", "MN": "East Asia", "HK": "East Asia", "MO": "East Asia",
    # SE Asia
    "PH": "SE Asia", "VN": "SE Asia", "TH": "SE Asia", "ID": "SE Asia",
    "MY": "SE Asia", "SG": "SE Asia", "MM": "SE Asia", "KH": "SE Asia",
    "LA": "SE Asia", "TL": "SE Asia", "BN": "SE Asia",
    # South Asia
    "IN": "S. Asia", "PK": "S. Asia", "BD": "S. Asia", "LK": "S. Asia",
    "NP": "S. Asia", "MV": "S. Asia", "AF": "S. Asia", "BT": "S. Asia",
    # Central Asia
    "KZ": "C. Asia", "UZ": "C. Asia", "KG": "C. Asia", "TJ": "C. Asia",
    "TM": "C. Asia", "AZ": "C. Asia", "AM": "C. Asia", "GE": "C. Asia",
    # Middle East
    "IR": "Middle East", "IQ": "Middle East", "SA": "Middle East", "AE": "Middle East",
    "IL": "Middle East", "YE": "Middle East", "SY": "Middle East", "LB": "Middle East",
    "JO": "Middle East", "KW": "Middle East", "QA": "Middle East", "OM": "Middle East",
    "BH": "Middle East", "TR": "Middle East",
    # North Africa
    "EG": "N. Africa", "LY": "N. Africa", "TN": "N. Africa", "DZ": "N. Africa",
    "MA": "N. Africa", "SD": "N. Africa",
    # Sub-Saharan Africa
    "NG": "Africa", "GH": "Africa", "SN": "Africa", "ET": "Africa",
    "KE": "Africa", "TZ": "Africa", "ZA": "Africa", "RW": "Africa",
    "UG": "Africa", "ZM": "Africa", "ZW": "Africa", "AO": "Africa",
    "CD": "Africa", "CM": "Africa", "CI": "Africa", "MG": "Africa",
    "MZ": "Africa", "ML": "Africa", "NE": "Africa",
    # Western Europe
    "GB": "W. Europe", "FR": "W. Europe", "DE": "W. Europe", "IT": "W. Europe",
    "ES": "W. Europe", "NL": "W. Europe", "BE": "W. Europe", "PT": "W. Europe",
    "CH": "W. Europe", "AT": "W. Europe", "IE": "W. Europe", "GR": "W. Europe",
    "LU": "W. Europe", "MT": "W. Europe", "CY": "W. Europe", "IS": "W. Europe",
    "AD": "W. Europe",
    # Northern Europe
    "SE": "N. Europe", "NO": "N. Europe", "DK": "N. Europe", "FI": "N. Europe",
    "EE": "N. Europe", "LV": "N. Europe", "LT": "N. Europe",
    # Eastern Europe
    "UA": "E. Europe", "PL": "E. Europe", "CZ": "E. Europe", "SK": "E. Europe",
    "HU": "E. Europe", "RO": "E. Europe", "BG": "E. Europe", "BY": "E. Europe",
    "MD": "E. Europe", "RS": "E. Europe", "HR": "E. Europe", "BA": "E. Europe",
    "AL": "E. Europe", "MK": "E. Europe", "ME": "E. Europe", "SI": "E. Europe",
    "XK": "E. Europe",
    # Russia
    "RU": "Russia",
    # North America
    "US": "N. America", "CA": "N. America", "MX": "N. America", "PR": "N. America",
    # Latin America
    "BR": "L. America", "AR": "L. America", "CO": "L. America", "CL": "L. America",
    "PE": "L. America", "VE": "L. America", "EC": "L. America", "BO": "L. America",
    "UY": "L. America", "PY": "L. America", "GY": "L. America", "SR": "L. America",
    # Caribbean / C. America
    "CU": "Caribbean", "DO": "Caribbean", "JM": "Caribbean",
    "GT": "Caribbean", "HN": "Caribbean", "SV": "Caribbean",
    "CR": "Caribbean", "PA": "Caribbean", "NI": "Caribbean",
    # Oceania
    "AU": "Oceania", "NZ": "Oceania", "MU": "Oceania", "FJ": "Oceania",
    "PG": "Oceania",
}
ISR_HOTSPOTS: list = []
NARRATIVE_SOURCES: dict = {}
TACTICAL_KEYWORDS: dict = {}
HISTORICAL_EVENTS: list = []
CABLE_ROUTES: list = []
THREAT_ACTOR_MAPPING: dict = {}
INFRASTRUCTURE_URLS:  dict = {}
try:
    with open("geo_data.json", "r", encoding="utf-8") as f:
        geo_data = json.load(f)
        COUNTRY_COORDS      = geo_data.get("COUNTRY_COORDS", {})
        STATE_ASNS          = geo_data.get("STATE_ASNS", {})
        AIRPORT_BOXES       = geo_data.get("AIRPORT_BOXES", {})
        CHOKEPOINTS         = geo_data.get("CHOKEPOINTS", [])
        ISR_HOTSPOTS        = geo_data.get("ISR_HOTSPOTS", [])
        NARRATIVE_SOURCES   = geo_data.get("NARRATIVE_SOURCES", {})
        TACTICAL_KEYWORDS   = geo_data.get("TACTICAL_KEYWORDS", {})
        HISTORICAL_EVENTS   = geo_data.get("HISTORICAL_EVENTS", [])
        CABLE_ROUTES        = geo_data.get("CABLE_ROUTES", [])
        THREAT_ACTOR_MAPPING = geo_data.get("THREAT_ACTOR_MAPPING", {})
        INFRASTRUCTURE_URLS  = geo_data.get("INFRASTRUCTURE_URLS", {})
        print("[Config] Loaded static data from geo_data.json")
except Exception as e:
    print(f"[Warning] Failed to load geo_data.json: {e}")

# ── Proxy & SSL Configuration ──
HTTP_PROXY  = os.getenv("HTTP_PROXY", "")
HTTPS_PROXY = os.getenv("HTTPS_PROXY", "")
GLOBAL_PROXIES = {}
if HTTP_PROXY:  GLOBAL_PROXIES["http"]  = HTTP_PROXY
if HTTPS_PROXY: GLOBAL_PROXIES["https"] = HTTPS_PROXY

SSL_VERIFY_ENV = os.getenv("SSL_VERIFY", "true").lower()
SSL_VERIFY = False if SSL_VERIFY_ENV in ("false", "0", "no") else True

if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("[Warning] SSL Verification is DISABLED via config.env")

CF_API_TOKEN               = os.getenv("CF_API_TOKEN", "")
OWM_API_KEY                = os.getenv("OWM_API_KEY", "")
CURRENT_DATE_RANGE         = os.getenv("CURRENT_DATE_RANGE",  "1d")
BASELINE_DATE_RANGE        = os.getenv("BASELINE_DATE_RANGE", "7d")
CACHE_EXPIRY               = int(os.getenv("CACHE_EXPIRY", "900"))
SCORE_REFRESH_SEC          = int(os.getenv("SCORE_REFRESH_SEC", "60"))   # Minimum scoring recalculation interval (seconds)

DEFAULT_CORE        = os.getenv("DEFAULT_CORE", "TW")
DEFAULT_CORRELATES  = [x.strip() for x in os.getenv("DEFAULT_CORRELATES", "JP,US").split(",") if x.strip()]
DEFAULT_ADVERSARIES = [x.strip() for x in os.getenv("DEFAULT_ADVERSARIES", "CN,RU,KP").split(",") if x.strip()]
DEFAULT_PINS        = [x.strip() for x in os.getenv("DEFAULT_PINS", "TW,JP,US").split(",") if x.strip()]

CF_HEADERS = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}

AIRSPACE_WINDOW             = int(os.getenv("AIRSPACE_WINDOW", "20"))
AIRSPACE_ANOMALY_THRESHOLD  = float(os.getenv("AIRSPACE_ANOMALY_THRESHOLD", "0.40"))
AIRSPACE_CLOSURE_THRESHOLD  = float(os.getenv("AIRSPACE_CLOSURE_THRESHOLD", "0.05"))
GDELT_TONE_ALERT_THRESHOLD  = float(os.getenv("GDELT_TONE_ALERT_THRESHOLD", "-15.0"))
GDELT_HISTORY_WINDOW        = int(os.getenv("GDELT_HISTORY_WINDOW", "28"))
CONVERGENCE_DUAL_BONUS      = int(os.getenv("CONVERGENCE_DUAL_BONUS", "1"))
CONVERGENCE_FULL_BONUS      = int(os.getenv("CONVERGENCE_FULL_BONUS", "2"))
THREAT_LEVEL_HYSTERESIS_CYCLES = int(os.getenv("THREAT_LEVEL_HYSTERESIS_CYCLES", "1"))

SEVERE_WEATHER_IDS = (
    set(range(200, 233)) | {500, 502, 503, 504} | {521, 522, 531} |
    {600, 602, 621, 622} | {711, 762} | {771, 781} | {900, 902}
)

# ── Deep Pattern Analysis Config ───────────────────────────────────────────────
# A. DDoS Acceleration Engine
AMBUSH_ZSCORE_THRESHOLD = float(os.getenv("AMBUSH_ZSCORE_THRESHOLD", "2.0"))
DERIVATIVE_WINDOW       = int(os.getenv("DERIVATIVE_WINDOW", "5"))
SYNC_DELTA_MS           = float(os.getenv("SYNC_DELTA_MS", "500"))
SYNC_C2_THRESHOLD       = float(os.getenv("SYNC_C2_THRESHOLD", "0.70"))
# B. Narrative Burst Detector
NARRATIVE_ZSCORE_ALERT    = float(os.getenv("NARRATIVE_ZSCORE_ALERT", "2.0"))
NARRATIVE_ZSCORE_CRITICAL = float(os.getenv("NARRATIVE_ZSCORE_CRITICAL", "3.0"))
NARRATIVE_BASELINE_DAYS   = int(os.getenv("NARRATIVE_BASELINE_DAYS", "30"))
NARRATIVE_POLL_INTERVAL   = int(os.getenv("NARRATIVE_POLL_INTERVAL", "1800"))
# C. Sequence Scorer
SEQUENCE_WINDOW          = int(os.getenv("SEQUENCE_WINDOW", "86400"))
SEQUENCE_FULL_BONUS      = int(os.getenv("SEQUENCE_FULL_BONUS", "3"))
SEQUENCE_PARTIAL_BONUS   = int(os.getenv("SEQUENCE_PARTIAL_BONUS", "1"))
# D. Maritime / ISR
AIS_DARK_GAP_THRESHOLD   = int(os.getenv("AIS_DARK_GAP_THRESHOLD", "3600"))
AIS_ANCHOR_RADIUS_KM     = float(os.getenv("AIS_ANCHOR_RADIUS_KM", "50"))
ISR_ICAO_TYPES           = [t.strip().upper() for t in os.getenv(
    "ISR_ICAO_TYPES", "RC135,RC-135,E3,E-3,RQ4,RQ-4,P8,P-8,EP3,EP-3,U2,TR1,E8,E-8"
).split(",") if t.strip()]
ISR_SURGE_THRESHOLD      = int(os.getenv("ISR_SURGE_THRESHOLD", "3"))

# OpenSky Network authentication
# Basic auth deprecated after 2026-03-18 → migrated to OAuth2 Bearer token
# Set OPENSKY_CLIENT_ID / OPENSKY_CLIENT_SECRET in config.env
# Authenticated: 4000 req/day (anonymous: 400 req/day)
OPENSKY_CLIENT_ID     = os.getenv("OPENSKY_CLIENT_ID", "")
OPENSKY_CLIENT_SECRET = os.getenv("OPENSKY_CLIENT_SECRET", "")
OPENSKY_TOKEN_URL     = "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token"

# ─────────────────────────────────────────────────────────────────────────────
# OpenSky OAuth2 token cache
# ─────────────────────────────────────────────────────────────────────────────
_opensky_oauth_token: dict = {"access_token": "", "expires_at": 0.0}
_opensky_oauth_lock         = threading.Lock()
if not OPENSKY_CLIENT_ID:
    print("[OpenSky] WARNING: OPENSKY_CLIENT_ID not set — running in anonymous mode (400 req/day limit)")

def _get_opensky_bearer() -> str:
    """Fetch and cache Bearer token via OAuth2 Client Credentials flow.
    Auto-refreshes 5 minutes before expiry. Returns empty string if credentials not set (anonymous access)."""
    global _opensky_oauth_token
    if not OPENSKY_CLIENT_ID:
        return ""
    with _opensky_oauth_lock:
        if time.time() < _opensky_oauth_token["expires_at"] - 300:
            return _opensky_oauth_token["access_token"]
        try:
            res = requests.post(
                OPENSKY_TOKEN_URL,
                data={"grant_type": "client_credentials",
                      "client_id": OPENSKY_CLIENT_ID,
                      "client_secret": OPENSKY_CLIENT_SECRET},
                timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if res.status_code == 200:
                td = res.json()
                _opensky_oauth_token["access_token"] = td.get("access_token", "")
                _opensky_oauth_token["expires_at"]   = time.time() + td.get("expires_in", 1800)
                print(f"[OpenSky OAuth2] Token acquired, expires_in={td.get('expires_in')}s")
                return _opensky_oauth_token["access_token"]
            print(f"[OpenSky OAuth2] Token fetch failed: HTTP {res.status_code} — {res.text[:200]}")
        except Exception as e:
            print(f"[OpenSky OAuth2] Token fetch error: {e}")
        return ""

# ─────────────────────────────────────────────────────────────────────────────
# Shared OpenSky API rate limiter
# Module-level sharing since OpenSkySensor and IsrHotspotSensor both hit the same API.
# ─────────────────────────────────────────────────────────────────────────────
_opensky_lock          = threading.Lock()
_opensky_last_req_time = 0.0
OPENSKY_MIN_INTERVAL   = int(os.getenv("OPENSKY_MIN_INTERVAL", "10"))  # seconds per request

def _opensky_get(params: dict, timeout: int = 12) -> requests.Response:
    """Shared OpenSky API request function for both sensors (rate limiter + OAuth2 built-in).
    On 429, respects Retry-After header and retries once."""
    global _opensky_last_req_time

    def _do_request() -> requests.Response:
        headers = {}
        token = _get_opensky_bearer()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return requests.get(
            "https://opensky-network.org/api/states/all",
            params=params, timeout=timeout,
            headers=headers, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
        )

    with _opensky_lock:
        elapsed = time.time() - _opensky_last_req_time
        if elapsed < OPENSKY_MIN_INTERVAL:
            time.sleep(OPENSKY_MIN_INTERVAL - elapsed)
        _opensky_last_req_time = time.time()
        res = _do_request()

    # Handle 429 outside the lock to avoid holding it during long sleeps
    if res.status_code == 429:
        retry_after = int(res.headers.get("X-Rate-Limit-Retry-After-Seconds", 60))
        auth_status = 'yes' if _opensky_oauth_token.get('access_token') else 'no'
        print(f"[OpenSky] 429 rate-limited, Retry-After={retry_after}s (auth={auth_status})")
        if retry_after <= 120:
            # Only retry short waits. Return 429 as-is for long waits (anonymous quota exceeded)
            time.sleep(retry_after)
            with _opensky_lock:
                _opensky_last_req_time = time.time()
                res = _do_request()

    return res

# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RationaleEntry:
    sensor: str
    domain: str
    status: str
    value: str
    score: int
    fired_reason: Optional[str] = None
    suppressed: bool = False
    suppress_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "sensor": self.sensor, "domain": self.domain, "status": self.status,
            "value": self.value, "score": self.score, "fired_reason": self.fired_reason,
            "suppressed": self.suppressed, "suppress_reason": self.suppress_reason,
        }

# ─────────────────────────────────────────────────────────────────────────────
# Sensors Base
# ─────────────────────────────────────────────────────────────────────────────
class BaseSensor(ABC):
    def __init__(self, name: str, domain: str, poll_interval: int):
        self.name = name; self.domain = domain; self.poll_interval = poll_interval; self.enabled = True
        self._cache: dict = {}; self._cache_time: float = 0.0; self._last_error: str = ""
        self._lock = threading.Lock(); self._fetch_log: list = []
    @abstractmethod
    def fetch(self, context: dict) -> dict: pass
    def get_cache(self) -> dict:
        with self._lock: return dict(self._cache)
    def set_cache(self, data: dict):
        with self._lock:
            self._cache = data; self._cache_time = time.time(); self._last_error = ""
            last = self._fetch_log[-1] if self._fetch_log else {}
            if not last.get("_from_log_fetch"):
                rec_count = sum(len(v) for v in data.values() if isinstance(v, (list, dict)))
                self._fetch_log.append({"ts": datetime.datetime.now().isoformat(), "success": True, "duration_ms": None, "http_status": None, "records": rec_count, "error": ""})
                self._fetch_log = self._fetch_log[-10:]
    def set_error(self, error: str):
        with self._lock:
            self._last_error = error
            last = self._fetch_log[-1] if self._fetch_log else {}
            if not last.get("_from_log_fetch"):
                self._fetch_log.append({"ts": datetime.datetime.now().isoformat(), "success": False, "duration_ms": None, "http_status": None, "records": 0, "error": error[:300]})
                self._fetch_log = self._fetch_log[-10:]
    def log_fetch(self, success: bool, duration_ms: int = 0, http_status: int = 0, records: int = 0, error: str = ""):
        with self._lock:
            self._fetch_log.append({"ts": datetime.datetime.now().isoformat(), "success": success, "duration_ms": duration_ms, "http_status": http_status, "records": records, "error": error[:300] if error else "", "_from_log_fetch": True})
            self._fetch_log = self._fetch_log[-10:]
    def get_fetch_log(self) -> list:
        with self._lock: return [{k: v for k, v in e.items() if k != "_from_log_fetch"} for e in self._fetch_log]
    @property
    def health(self) -> str:
        if not self.enabled: return "DISABLED"
        if self._last_error: return "ERROR"
        elapsed = time.time() - self._cache_time
        if elapsed > self.poll_interval * 3: return "STALE" if self._cache else "INITIALIZING"
        return "OK"
    def to_config_dict(self) -> dict:
        return {"name": self.name, "domain": self.domain, "enabled": self.enabled, "health": self.health, "poll_interval_sec": self.poll_interval, "last_error": self._last_error, "cache_age_sec": round(time.time() - self._cache_time) if self._cache_time else None}

# ─────────────────────────────────────────────────────────────────────────────
# Sensor Implementations
# ─────────────────────────────────────────────────────────────────────────────
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
                for code in all_codes:
                    results[code] = "NORMAL"
        except Exception as e:
            for code in all_codes:
                results[code] = "NORMAL"
            last_error = str(e)
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_anomalies, last_error)
        result = {"statuses": results}; self.set_cache(result)
        return result

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

class OpenSkySensor(BaseSensor):
    def __init__(self): super().__init__("opensky", "physical", 1800)
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", []); results: dict = {}; delta = 0.5
        t0 = time.time(); total_states = 0; any_success = False; last_status = 0; last_error = ""
        for code in theaters:
            box = AIRPORT_BOXES.get(code)
            if not box: continue
            lat, lng = box["lat"], box["lng"]
            params = {"lamin": lat - delta, "lamax": lat + delta, "lomin": lng - delta, "lomax": lng + delta}
            try:
                res = _opensky_get(params)
                last_status = res.status_code
                if res.status_code == 200:
                    count = len(res.json().get("states") or [])
                    results[code] = {"airport": box["airport"], "count": count, "lat": lat, "lng": lng, "error": None}
                    total_states += count; any_success = True
                else:
                    results[code] = {"airport": box["airport"], "count": -1, "lat": lat, "lng": lng, "error": f"http_{res.status_code}"}
                    last_error = f"HTTP {res.status_code}"
            except Exception as e:
                results[code] = {"airport": box.get("airport", code), "count": -1, "lat": lat, "lng": lng, "error": str(e)}
                last_error = str(e)
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_states, last_error)
        result = {"airports": results}; self.set_cache(result)
        return result

class OpenWeatherSensor(BaseSensor):
    def __init__(self): super().__init__("openweather", "physical", 1800)
    def fetch(self, context: dict) -> dict:
        # Weather noise check for strategic_theaters only (all_targets is too large, risks API quota exhaustion)
        targets = context.get("strategic_theaters", []); api_key = context.get("owm_api_key", "")
        if not api_key:
            self.set_error("OWM_API_KEY not configured"); return {"conditions": {}}
        conditions: dict = {}
        t0 = time.time(); total_records = 0; any_success = False; last_status = 0; last_error = ""
        for code in targets:
            coord = COUNTRY_COORDS.get(code)
            if not coord: continue
            try:
                res = requests.get("https://api.openweathermap.org/data/2.5/weather", params={"lat": coord["lat"], "lon": coord["lng"], "appid": api_key, "units": "metric"}, timeout=5, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                last_status = res.status_code
                if res.status_code == 200:
                    d = res.json(); w = (d.get("weather") or [{}])[0]; wind = d.get("wind", {}).get("speed", 0)
                    wid = w.get("id", 800)
                    is_severe = wid in SEVERE_WEATHER_IDS or wind > 25
                    is_moderate = (500 <= wid < 600) or (300 <= wid < 400) or wind > 15
                    conditions[code] = {"weather_id": wid, "condition": w.get("main", "Clear"), "description": w.get("description", ""), "wind_speed": round(wind, 1), "temp_c": d.get("main", {}).get("temp"), "is_severe": is_severe, "is_moderate": is_moderate, "severity": "SEVERE" if is_severe else "MODERATE" if is_moderate else "NORMAL", "lat": coord["lat"], "lng": coord["lng"]}
                    total_records += 1; any_success = True
            except Exception as e:
                last_error = str(e)
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_records, last_error)
        result = {"conditions": conditions}; self.set_cache(result)
        return result

class PeeringDbSensor(BaseSensor):
    def __init__(self): super().__init__("peeringdb_ixp", "physical", 14400)
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", []); ixp_data: dict = {}
        t0 = time.time(); total_ixps = 0; any_success = False; last_status = 0; last_error = ""
        def _fetch_peeringdb(code: str):
            return requests.get(
                "https://www.peeringdb.com/api/ix",
                params={"country": code},
                headers={"Accept": "application/json"},
                timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )

        rate_limited = 0
        for idx, code in enumerate(theaters):
            if idx > 0:
                time.sleep(10)  # PeeringDB rate limit mitigation (10s/request)
            try:
                res = _fetch_peeringdb(code)
                last_status = res.status_code
                if res.status_code == 429:
                    # 429 → wait 60s and retry once
                    time.sleep(60)
                    try:
                        res = _fetch_peeringdb(code)
                        last_status = res.status_code
                    except Exception:
                        pass
                if res.status_code == 200:
                    items = res.json().get("data", []); coord = COUNTRY_COORDS.get(code, {})
                    ixps = [{"id": ix.get("id"), "name": ix.get("name", ""), "city": ix.get("city", ""), "country": code, "lat": coord.get("lat", 0), "lng": coord.get("lng", 0), "status": ix.get("status", "ok"), "aka": ix.get("name_long", "")} for ix in items]
                    ixp_data[code] = {"ixps": ixps, "count": len(ixps)}
                    total_ixps += len(items); any_success = True
                elif res.status_code == 429:
                    ixp_data[code] = {"ixps": [], "count": 0, "error": "rate_limited"}
                    rate_limited += 1
                else:
                    ixp_data[code] = {"ixps": [], "count": 0, "error": f"HTTP {res.status_code}"}
                    last_error = f"HTTP {res.status_code}"
            except Exception as e:
                ixp_data[code] = {"ixps": [], "count": 0, "error": str(e)}
                last_error = str(e)
        if rate_limited and not last_error:
            last_error = f"rate_limited ({rate_limited} countries)"
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_ixps, last_error if not any_success else "")
        result = {"ixp_data": ixp_data}; self.set_cache(result)
        return result

class BgpRoutingSensor(BaseSensor):
    BGP_DROP_THRESHOLD = 0.15
    def __init__(self):
        super().__init__("ripe_bgp", "cyber", 1800); self._baseline: dict = {}
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", []); results: dict = {}
        t0 = time.time(); total_prefixes = 0; any_success = False; last_status = 0; last_error = ""
        for code in theaters:
            try:
                res = requests.get("https://stat.ripe.net/data/country-routing-stats/data.json", params={"resource": code, "sourceapp": "osint-radar"}, timeout=12, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                last_status = res.status_code
                if res.status_code == 200:
                    stats = res.json().get("data", {}).get("stats", [])
                    if stats:
                        latest = stats[-1]; pfx_now = latest.get("announced_prefixes", 0); ases_now = latest.get("seen_ases", 0)
                        bl = self._baseline.get(code, {})
                        if not bl: self._baseline[code] = {"prefixes": pfx_now, "ases": ases_now, "ts": time.time()}; bl = self._baseline[code]
                        pfx_base = bl.get("prefixes", pfx_now) or pfx_now
                        drop_ratio = max(0.0, (pfx_base - pfx_now) / pfx_base) if pfx_base else 0.0
                        is_anomaly = drop_ratio > self.BGP_DROP_THRESHOLD
                        results[code] = {"announced_prefixes": pfx_now, "baseline_prefixes": pfx_base, "seen_ases": ases_now, "drop_pct": round(drop_ratio * 100, 1), "is_anomaly": is_anomaly, "status": "ANOMALY" if is_anomaly else "NORMAL"}
                        if time.time() - bl.get("ts", 0) > 3600: self._baseline[code] = {"prefixes": pfx_now, "ases": ases_now, "ts": time.time()}
                        total_prefixes += pfx_now; any_success = True
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

class GDELTSensor(BaseSensor):
    QUERY_TEMPLATES = {
        "TW": '"Taiwan" (military OR invasion OR strait OR conflict)', "PH": '"Philippines" (military OR "South China Sea" OR conflict)',
        "JP": '"Japan" (military OR defense OR strait OR China)', "KR": '"Korea" (military OR nuclear OR "North Korea")',
        "UA": '"Ukraine" (war OR military OR Russia OR offensive)', "IL": '"Israel" (military OR attack OR Gaza OR Iran)',
        "US": '"United States" (military OR China OR Taiwan OR Russia)', "AU": '"Australia" (military OR China OR defense OR Pacific)'
    }
    def __init__(self): super().__init__("gdelt", "info", 1800)
    def _fetch_tone(self, query: str, timespan: str) -> Optional[float]:
        try:
            res = requests.get("https://api.gdeltproject.org/api/v2/doc/doc", params={"query": query, "mode": "TimelineTone", "timespan": timespan, "format": "json"}, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code != 200: return None
            timeline = res.json().get("timeline") or []
            if not timeline: return None
            values = [pt["value"] for pt in timeline[0].get("data", []) if "value" in pt]
            return round(sum(values) / len(values), 3) if values else None
        except Exception: return None
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", []); weather_conds = context.get("weather_conditions", {})
        alert_threshold = context.get("gdelt_tone_threshold", GDELT_TONE_ALERT_THRESHOLD); history_window = context.get("gdelt_history_window", GDELT_HISTORY_WINDOW)
        tones: dict = {}
        t0 = time.time()
        for code in theaters:
            query = self.QUERY_TEMPLATES.get(code)
            if not query:
                country_name = COUNTRY_COORDS.get(code, {}).get("name", code)
                query = f'"{country_name}" (military OR conflict OR attack OR defense OR war)'
            tone_current = self._fetch_tone(query, "1d"); tone_baseline = self._fetch_tone(query, f"{history_window}d")
            if tone_current is None:
                tones[code] = {"status": "NO_DATA"}
                continue
            delta = (tone_current - tone_baseline) if tone_baseline is not None else None
            is_severe_wx = weather_conds.get(code, {}).get("is_severe", False)
            is_alert = (not is_severe_wx and tone_current < alert_threshold)
            tones[code] = {"tone_current": tone_current, "tone_baseline": tone_baseline, "delta": round(delta, 3) if delta is not None else None, "is_alert": is_alert, "weather_suppressed": is_severe_wx, "status": ("WEATHER_NOISE" if is_severe_wx and tone_current < alert_threshold else "ALERT" if is_alert else "NORMAL")}
        self.log_fetch(True, round((time.time() - t0) * 1000), 200, len(tones))
        result = {"gdelt_tones": tones}; self.set_cache(result)
        return result

# ── Sensors (Production Implementation) ──
class NasaFirmsSensor(BaseSensor):
    """Switched from NASA FIRMS to NASA EONET Wildfires API (FIRMS server unreachable).
    No API key required. eonet.gsfc.nasa.gov verified reachable in corporate proxy environments.
    """
    EONET_URL = "https://eonet.gsfc.nasa.gov/api/v3/events"
    # Tolerance in degrees to determine if an event is near the target theater
    GEO_RADIUS_DEG = 10.0

    def __init__(self): super().__init__("nasa_firms", "physical", 3600)

    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        anomalies = []

        t0 = time.time()
        try:
            res = requests.get(
                self.EONET_URL,
                params={"category": "wildfires", "status": "open", "days": 1},
                timeout=15,
                proxies=GLOBAL_PROXIES,
                verify=SSL_VERIFY
            )
            duration = round((time.time() - t0) * 1000)

            if res.status_code == 200:
                events = res.json().get("events", [])
                record_count = len(events)
                self.log_fetch(True, duration, res.status_code, record_count)

                # Extract nearby events by comparing distance to each theater's coordinates
                for code in theaters:
                    coord = COUNTRY_COORDS.get(code)
                    if not coord: continue
                    tlat, tlng = coord["lat"], coord["lng"]

                    for ev in events:
                        for geo in (ev.get("geometry") or []):
                            coords = geo.get("coordinates")
                            if not coords or len(coords) < 2: continue
                            # EONET coordinates are in [lng, lat] order
                            elng, elat = coords[0], coords[1]
                            if (abs(elat - tlat) <= self.GEO_RADIUS_DEG and
                                    abs(elng - tlng) <= self.GEO_RADIUS_DEG):
                                anomalies.append({
                                    "lat": elat, "lng": elng,
                                    "code": code, "confidence": "HIGH",
                                    "title": ev.get("title", "Wildfire")
                                })
                                break  # Avoid registering the same event to the same theater twice
            else:
                self.log_fetch(False, duration, res.status_code, 0, f"HTTP {res.status_code}")
                self.set_error(f"HTTP {res.status_code}")

        except requests.exceptions.Timeout:
            self.log_fetch(False, round((time.time() - t0) * 1000), 0, 0, "Timeout (EONET)")
            self.set_error("Timeout connecting to NASA EONET")
        except Exception as e:
            self.log_fetch(False, round((time.time() - t0) * 1000), 0, 0, str(e))
            self.set_error(str(e))

        result = {"anomalies": anomalies}; self.set_cache(result)
        return result

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

            if res.status_code == 200:
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
                # API key auth failure: prompt to configure key but do not treat as ERROR
                print(f"[ThreatFox] HTTP 401 — Auth-Key is invalid or expired. Check THREATFOX_API_KEY.")
                self.log_fetch(False, duration, res.status_code, 0, "HTTP 401 Unauthorized")
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

class RssNarrativeSensor(BaseSensor):
    """
    Fetches RSS feeds from TASS / Xinhua / Mehr News etc., analyzes keyword
    frequency with Z-Score to detect "narrative bursts".
    Compares against 30-day baseline (daily normalized frequency) to filter
    routine propaganda and alert only statistically significant spikes.
    """
    def __init__(self):
        super().__init__("rss_narrative", "info", 1800)
        self._baseline: dict = {}   # {theater: {"daily_counts": [float,...], "last_updated": float}}
        self._lock = threading.Lock()

    @staticmethod
    def _fetch_rss_text(url: str) -> str:
        """Fetch RSS feed and return text. Returns empty string on failure."""
        try:
            res = requests.get(url, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                               headers={"User-Agent": "Mozilla/5.0 (OSINT-Radar/8.0)"})
            if res.status_code == 200:
                return res.text
        except Exception:
            pass
        return ""

    @staticmethod
    def _count_keywords_in_rss(xml_text: str, keywords: list) -> tuple:
        """
        Parse RSS XML and return keyword hit count and article count.
        Duplicate articles are excluded using difflib.
        Returns: (keyword_hits: int, article_count: int)
        """
        if not xml_text:
            return 0, 0
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return 0, 0

        # Dedup: normalized hash of first 60 chars of title in a set (O(N) vs O(N²))
        titles_seen: set = set()
        keyword_hits, article_count = 0, 0
        keywords_lower = [k.lower() for k in keywords]

        for item in root.iter("item"):
            title_el = item.find("title")
            desc_el  = item.find("description")
            title = (title_el.text or "").strip() if title_el is not None else ""
            desc  = (desc_el.text  or "").strip() if desc_el  is not None else ""
            text  = (title + " " + desc).lower()

            # Detect duplicates via normalized 60-char key (eliminates SequenceMatcher O(N²))
            title_key = "".join(c for c in title.lower()[:60] if c.isalnum())
            if title_key and title_key in titles_seen:
                continue
            if title_key:
                titles_seen.add(title_key)

            article_count += 1
            if any(kw in text for kw in keywords_lower):
                keyword_hits += 1

        return keyword_hits, article_count

    def _compute_zscore(self, theater: str, today_normalized: float) -> tuple:
        """
        Compute Z-Score against 30-day baseline.
        Returns: (z_score: float, mean: float, std: float)
        """
        with self._lock:
            bl = self._baseline.get(theater, {})
            daily = bl.get("daily_counts", [])

        if len(daily) < 7:
            return 0.0, 0.0, 0.0
        n = len(daily)
        mean = sum(daily) / n
        variance = sum((x - mean) ** 2 for x in daily) / n
        std = math.sqrt(variance) if variance > 0 else 0.0
        z = (today_normalized - mean) / std if std > 0 else 0.0
        return round(z, 3), round(mean, 4), round(std, 4)

    def _update_baseline(self, theater: str, today_normalized: float):
        """Update daily baseline list (retains up to NARRATIVE_BASELINE_DAYS days)."""
        with self._lock:
            if theater not in self._baseline:
                self._baseline[theater] = {"daily_counts": [], "last_updated": 0.0}
            bl = self._baseline[theater]
            bl["daily_counts"].append(today_normalized)
            bl["daily_counts"] = bl["daily_counts"][-NARRATIVE_BASELINE_DAYS:]
            bl["last_updated"] = time.time()

    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        results: dict = {}
        t0 = time.time()
        total_hits = 0

        for theater in theaters:
            keywords = TACTICAL_KEYWORDS.get(theater, TACTICAL_KEYWORDS.get("DEFAULT", []))
            if not keywords:
                continue

            combined_hits, combined_articles = 0, 0
            for source_name, rss_url in NARRATIVE_SOURCES.items():
                xml_text = self._fetch_rss_text(rss_url)
                hits, articles = self._count_keywords_in_rss(xml_text, keywords)
                combined_hits    += hits
                combined_articles += articles

            # Normalize by total article count (prevent division by zero)
            normalized = combined_hits / max(combined_articles, 1)

            z_score, mean_val, std_val = self._compute_zscore(theater, normalized)
            self._update_baseline(theater, normalized)

            status = "NORMAL"
            if z_score >= NARRATIVE_ZSCORE_CRITICAL:
                status = "CRITICAL_BURST"
            elif z_score >= NARRATIVE_ZSCORE_ALERT:
                status = "BURST"

            results[theater] = {
                "z_score":            z_score,
                "normalized_freq":    round(normalized, 4),
                "baseline_mean":      mean_val,
                "baseline_std":       std_val,
                "keyword_hits":       combined_hits,
                "article_count":      combined_articles,
                "status":             status,
                "is_burst":           status in ("BURST", "CRITICAL_BURST"),
                "keywords_monitored": keywords[:5],
            }
            total_hits += combined_hits

        self.log_fetch(True, round((time.time() - t0) * 1000), 200, total_hits)
        result = {"narratives": results}
        self.set_cache(result)
        return result


class IsrHotspotSensor(BaseSensor):
    """
    Uses OpenSky Network states/all API to measure military/reconnaissance aircraft density
    within 200km of ISR_HOTSPOTS. Operates independently from OpenSkySensor (civilian airport monitoring).
    Identifies ISR pattern as high-altitude (>9000m) and low-speed (<160 m/s) aircraft.
    """
    # 200km ≈ 1.8° (latitude)
    RADIUS_DEG = 1.8

    def __init__(self):
        super().__init__("isr_hotspot", "physical", 1800)

    def fetch(self, context: dict) -> dict:
        theaters = set(context.get("strategic_theaters", []))
        results: dict = {}
        t0 = time.time()
        any_success = False; last_status = 0; last_error = ""

        for hotspot in ISR_HOTSPOTS:
            theater = hotspot.get("theater", "")
            if theater not in theaters:
                continue
            lat, lng = hotspot["lat"], hotspot["lng"]
            name = hotspot["name"]
            r = self.RADIUS_DEG
            params = {
                "lamin": lat - r, "lamax": lat + r,
                "lomin": lng - r, "lomax": lng + r,
            }
            try:
                res = _opensky_get(params)
                if res.status_code == 200:
                    states = res.json().get("states") or []
                    # ISR characteristics filter: high altitude (>9000m) + low speed (<160 m/s)
                    # or squawk=7777 (government/military code)
                    isr_count = 0
                    isr_tracks = []
                    for s in states:
                        # states fields: [icao24, callsign, origin, time_pos, last, lon, lat, baro_alt, on_ground, vel, track, vrate, ...]
                        if len(s) < 10: continue
                        baro_alt  = s[7]  if s[7]  is not None else 0
                        on_ground = s[8]  if s[8]  is not None else True
                        velocity  = s[9]  if s[9]  is not None else 999
                        squawk    = s[14] if len(s) > 14 and s[14] is not None else ""
                        callsign  = (s[1] or "").strip().upper()
                        if on_ground:
                            continue
                        is_high_slow  = (baro_alt > 9000 and velocity < 160)
                        is_mil_squawk = (squawk == "7777")
                        is_isr_call   = any(
                            callsign.startswith(pfx)
                            for pfx in ("FORTE", "JAKE", "MYSTIC", "RICO", "TROLL",
                                        "DRAGON", "COBRA", "HAWK", "REAPER", "GLOBAL")
                        )
                        if is_high_slow or is_mil_squawk or is_isr_call:
                            isr_count += 1
                            isr_tracks.append({
                                "icao24":   s[0],
                                "callsign": callsign,
                                "alt_m":    baro_alt,
                                "vel_ms":   velocity,
                                "squawk":   squawk,
                            })
                    existing = results.get(theater, {"count": 0, "hotspots": []})
                    existing["count"] += isr_count
                    existing["hotspots"].append({
                        "name":      name,
                        "lat":       lat,
                        "lng":       lng,
                        "isr_count": isr_count,
                        "tracks":    isr_tracks[:5],  # Metadata for up to 5 aircraft
                    })
                    results[theater] = existing
                    any_success = True; last_status = res.status_code
                else:
                    last_status = res.status_code
                    last_error = f"HTTP {res.status_code}"
            except Exception as e:
                last_error = str(e)

        total_isr = sum(d["count"] for d in results.values())
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_isr, last_error if not any_success else "")

        # ISR surge detection
        for theater, data in results.items():
            data["is_surge"] = data["count"] >= ISR_SURGE_THRESHOLD

        result = {"isr_data": results}
        self.set_cache(result)
        return result


class AisMaritimeSensor(BaseSensor):
    """
    Detects maritime anomalies near CHOKEPOINTS using public AIS data.
    - AIS Dark Gap: vessel with AIS transmission interrupted for a threshold period (possible EMCON)
    - Stationary Anomaly: non-cargo/non-fishing vessel anchored near chokepoint for extended time

    Primary API: AISHub public stream (data.aishub.net)
    No-auth endpoint / rate-limited (60s/request)
    Fallback: MarineTraffic public data (when available)
    """
    AISHUB_URL = "http://data.aishub.net/ws.php"
    # Non-commercial / non-fishing vessel types (AIS Ship Type codes)
    # 30-35: Fishing, 60-69: Passenger, 70-79: Cargo, 80-89: Tanker
    # 35,36,37: Military, Naval, law enforcement
    MILITARY_SHIP_TYPES = {35, 36, 37}
    COMMERCIAL_TYPES    = set(range(60, 90))

    def __init__(self):
        super().__init__("ais_maritime", "physical", 1800)
        self._vessel_history: dict = {}  # {mmsi: {"last_ts": float, "lat": float, "lng": float}}

    @staticmethod
    def _haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
        """Compute distance (km) between two points using the Haversine formula."""
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlng = math.radians(lng2 - lng1)
        a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlng/2)**2
        return R * 2 * math.asin(math.sqrt(a))

    def fetch(self, context: dict) -> dict:
        now = time.time()
        dark_gaps, stationary_anomalies, chokepoint_alerts = [], [], []
        t0 = time.time()
        cp_success = 0; cp_errors = 0; last_error = ""

        for cp in CHOKEPOINTS:
            cp_lat, cp_lng = cp["lat"], cp["lng"]
            cp_name = cp["name"]
            # Fetch vessels near this chokepoint from AISHub
            # Guest API is rate-limited on consecutive requests — insert delay between requests
            if cp_success + cp_errors > 0:
                time.sleep(2)   # AISHub guest API rate limit mitigation (2s/request)
            params = {
                "username":  "guest",  # AISHub guest access
                "format":    "1",      # JSON format
                "latmin":    cp_lat - 0.5,
                "latmax":    cp_lat + 0.5,
                "lonmin":    cp_lng - 0.5,
                "lonmax":    cp_lng + 0.5,
            }
            try:
                res = requests.get(
                    self.AISHUB_URL, params=params,
                    timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                    headers={"User-Agent": "OSINT-Radar/8.0"}
                )
                if res.status_code != 200:
                    cp_errors += 1; last_error = f"HTTP {res.status_code}"
                    continue
                raw_text = res.text.strip()
                if not raw_text:
                    # AISHub guest API: returns HTTP 200 + empty body when rate-limited
                    # Treat as "no data", not an error — proceed to next chokepoint
                    continue
                try:
                    vessels_raw = res.json()
                except ValueError:
                    # Non-empty but non-JSON (HTML error page etc.) → skip
                    continue
                # AISHub response format: [[header], [vessel,...], ...]
                if not isinstance(vessels_raw, list) or len(vessels_raw) < 2:
                    continue  # No vessels in vicinity (normal)
                header  = vessels_raw[0]
                vessels = vessels_raw[1:]
                cp_success += 1
            except Exception as e:
                cp_errors += 1; last_error = str(e)
                continue

            for vessel in vessels:
                if not isinstance(vessel, dict):
                    continue
                mmsi      = str(vessel.get("MMSI", ""))
                try:
                    ship_type = int(vessel.get("SHIPTYPE", 0) or 0)
                    speed     = float(vessel.get("SOG", 0) or 0)    # Speed Over Ground (knots)
                    lat       = float(vessel.get("LATITUDE", 0) or 0)
                    lng       = float(vessel.get("LONGITUDE", 0) or 0)
                    last_ts   = float(vessel.get("TIME", now) or now)
                except (ValueError, TypeError):
                    continue  # Malformed vessel record — skip
                name      = vessel.get("NAME", "UNKNOWN")

                dist_km = self._haversine_km(cp_lat, cp_lng, lat, lng)

                # AIS Dark Gap: AIS transmission silent for >= AIS_DARK_GAP_THRESHOLD seconds since last record
                prev = self._vessel_history.get(mmsi)
                if prev:
                    gap_sec = now - prev["last_ts"]
                    if gap_sec > AIS_DARK_GAP_THRESHOLD and dist_km < AIS_ANCHOR_RADIUS_KM:
                        dark_gaps.append({
                            "mmsi":      mmsi,
                            "name":      name,
                            "chokepoint": cp_name,
                            "gap_hours": round(gap_sec / 3600, 1),
                            "lat":       lat,
                            "lng":       lng,
                            "dist_km":   round(dist_km, 1),
                        })

                # Stationary anomaly: non-commercial, speed <0.5kt, within 50km of chokepoint
                is_suspicious_type = ship_type in self.MILITARY_SHIP_TYPES or ship_type not in self.COMMERCIAL_TYPES
                if is_suspicious_type and speed < 0.5 and dist_km < AIS_ANCHOR_RADIUS_KM:
                    stationary_anomalies.append({
                        "mmsi":       mmsi,
                        "name":       name,
                        "ship_type":  ship_type,
                        "chokepoint": cp_name,
                        "lat":        lat,
                        "lng":        lng,
                        "dist_km":    round(dist_km, 1),
                    })

                # Update vessel history
                self._vessel_history[mmsi] = {"last_ts": last_ts, "lat": lat, "lng": lng}

        # Remove vessel history older than 24 hours (memory leak prevention)
        cutoff_ts = now - 86400
        stale_mmsi = [m for m, v in self._vessel_history.items() if v["last_ts"] < cutoff_ts]
        for m in stale_mmsi:
            del self._vessel_history[m]
        # Evict oldest entries when limit exceeded (max 5000 vessels)
        if len(self._vessel_history) > 5000:
            sorted_mmsi = sorted(self._vessel_history, key=lambda m: self._vessel_history[m]["last_ts"])
            for m in sorted_mmsi[:len(self._vessel_history) - 5000]:
                del self._vessel_history[m]

        total_anomalies = len(dark_gaps) + len(stationary_anomalies)
        # cp_errors=0 and cp_success=0 means all skipped due to rate limiting → treat as OK, not ERROR
        fetch_ok = (cp_success > 0) or (cp_errors == 0)
        err_note = f"{cp_errors} CP errors: {last_error}" if cp_errors and not cp_success else ""
        self.log_fetch(fetch_ok, round((time.time() - t0) * 1000), 200 if cp_success else 0, total_anomalies, err_note)
        result = {
            "dark_gaps":            dark_gaps,
            "stationary_anomalies": stationary_anomalies,
            "has_anomaly":          total_anomalies > 0,
        }
        self.set_cache(result)
        return result

# ─────────────────────────────────────────────────────────────────────────────
# v9 New Sensors: TelegramMirrorSensor / CheckHostSensor / GreyNoiseSensor
# ─────────────────────────────────────────────────────────────────────────────

# ── Config loading (placed before sensor definitions) ─────────────────────────
GREYNOISE_API_KEY        = os.getenv("GREYNOISE_API_KEY", "")
CHECKHOST_NODES_STR      = os.getenv("CHECKHOST_NODES",
    "jp1.node.check-host.net,us1.node.check-host.net,"
    "de1.node.check-host.net,nl1.node.check-host.net,fr1.node.check-host.net")
CHECKHOST_NODES          = [n.strip() for n in CHECKHOST_NODES_STR.split(",") if n.strip()]
CHECKHOST_POLL_INTERVAL  = int(os.getenv("CHECKHOST_POLL_INTERVAL", "600"))
CHECKHOST_TIMEOUT_MS     = int(os.getenv("CHECKHOST_TIMEOUT_MS", "3000"))
TELEGRAM_MIRROR_POLL     = int(os.getenv("TELEGRAM_MIRROR_POLL_INTERVAL", "900"))
TELEGRAM_ATTACK_KW_RAW   = os.getenv(
    "TELEGRAM_ATTACK_KEYWORDS",
    "target,attack,ddos,http flood,under attack,down,offline,op,#target"
)
TELEGRAM_ATTACK_KEYWORDS = [k.strip().lower() for k in TELEGRAM_ATTACK_KW_RAW.split(",") if k.strip()]

# Scraper User-Agent pool — rotated per request to reduce fingerprinting
_SCRAPER_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

class TelegramMirrorSensor(BaseSensor):
    """
    Info Domain sensor: scrapes public mirror pages on tgstat.com / telemetr.io
    and monitors channel posts based on THREAT_ACTOR_MAPPING.
    No phone number or login required. Parses "target URLs" and "attack declarations"
    from posts and auto-registers them via register_sequence_event.
    """
    TGSTAT_URL   = "https://tgstat.com/channel/@{channel}/stat"
    TELEMETR_URL = "https://telemetr.io/@{channel}"
    # URL extraction pattern (https?://example.com format)
    _URL_RE = __import__("re").compile(
        r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s<"\']*)?'
    )
    _intercept_log: list = []   # class-level ring buffer (shared across instances)
    _MAX_LOG        = 50
    _last_poll_ts: str  = ""
    _last_poll_ok: bool = False

    def __init__(self):
        super().__init__("telegram_mirror", "info", TELEGRAM_MIRROR_POLL)

    def _scrape_channel(self, channel: str) -> str:
        """Fetch public channel page from tgstat.com and return text.
        Falls back to telemetr.io on failure.
        Applies UA rotation and exponential backoff on 403/429."""
        import random as _rnd
        for url_tpl in (self.TGSTAT_URL, self.TELEMETR_URL):
            url = url_tpl.format(channel=channel)
            delay = 2.0  # initial backoff base (seconds)
            for attempt in range(3):
                try:
                    ua = _rnd.choice(_SCRAPER_UA_POOL)
                    res = requests.get(
                        url, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                        headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"}
                    )
                    if res.status_code == 200 and len(res.text) > 200:
                        return res.text
                    if res.status_code in (403, 429):
                        # Exponential backoff: 2s → 4s → 8s with ±20% jitter
                        sleep_time = delay * (2 ** attempt) * _rnd.uniform(0.8, 1.2)
                        time.sleep(min(sleep_time, 30.0))
                        continue
                    break  # non-retryable error (404, 5xx) — try next source
                except Exception:
                    break
        return ""

    @staticmethod
    def _extract_text(html: str) -> str:
        """Strip scripts and styles from HTML and return plain text (no BeautifulSoup required)."""
        import re
        text = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>',  ' ', text,  flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'&[a-zA-Z0-9#]+;', ' ', text)
        return text.lower()

    def _parse_posts(self, text: str, keywords: list) -> tuple:
        """Extract target URLs and attack declarations from text.
        Returns: (targets: list[str], has_attack_intent: bool, matched_keywords: list[str])
        Word-boundary matching: use \\b so "target" does not match "targeting".
        Keywords with len<=2 (e.g. "op") are skipped to avoid false positives.
        Phrases (with spaces) and #hashtags are specific enough for substring match.
        """
        import re as _re
        targets = self._URL_RE.findall(text)
        gov_targets = [u for u in targets if any(
            pat in u for pat in (".gov", ".mil", ".parliament", ".bundestag",
                                  ".elysee", ".president", "bank", "energy", "telecom")
        )]
        matched_kws = []
        for kw in keywords:
            if len(kw) <= 2:                          # "op" etc. — too short, causes noise; skip
                continue
            if ' ' in kw or kw.startswith('#'):       # phrase / hashtag — substring match is specific enough
                if kw in text:
                    matched_kws.append(kw)
            else:                                     # single word — word boundary prevents "targeting" matching "target"
                if _re.search(r'\b' + _re.escape(kw) + r'\b', text):
                    matched_kws.append(kw)
        has_intent = len(matched_kws) > 0
        return gov_targets[:10], has_intent, matched_kws

    def _extract_snippet(self, text: str, keywords: list, context: int = 100) -> str:
        """Extract up to 200 chars of context around the keyword as a snippet.
        Uses the same word-boundary logic as _parse_posts to prevent false-positive snippets.
        """
        import re as _re
        for kw in keywords:
            if len(kw) <= 2:
                continue
            if ' ' in kw or kw.startswith('#'):
                m = _re.search(_re.escape(kw), text)
            else:
                m = _re.search(r'\b' + _re.escape(kw) + r'\b', text)
            if m:
                idx   = m.start()
                start = max(0, idx - 60)
                end   = min(len(text), idx + len(kw) + context)
                raw   = text[start:end].strip()
                raw   = _re.sub(r'\s+', ' ', raw)
                return f"...{raw}..."
        return ""

    @classmethod
    def _log_detection(cls, theater: str, channel: str, channel_url: str,
                       status: str, keywords: list, targets: list, snippet: str) -> None:
        """Append an entry to the intercept log (CLEAR status is not recorded)."""
        entry = {
            "ts":              time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "theater":         theater,
            "channel":         channel,
            "channel_url":     channel_url,
            "status":          status,
            "keywords_matched": keywords,
            "target_urls":     targets[:5],
            "snippet":         snippet,
        }
        cls._intercept_log.insert(0, entry)
        if len(cls._intercept_log) > cls._MAX_LOG:
            cls._intercept_log.pop()

    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        results: dict = {}
        t0 = time.time()
        total_hits = 0
        any_success = False

        for theater in theaters:
            channels = THREAT_ACTOR_MAPPING.get(theater, [])
            if not channels:
                continue

            theater_targets: list = []
            theater_intent   = False
            active_channels: list = []

            import random as _rnd_jitter
            for i, channel in enumerate(channels):
                if i > 0:
                    # Inter-channel jitter: 1.5–4.0 s to reduce rate-limit fingerprinting
                    time.sleep(_rnd_jitter.uniform(1.5, 4.0))
                html = self._scrape_channel(channel)
                if not html:
                    continue
                any_success = True
                text = self._extract_text(html)
                targets, has_intent, matched_kws = self._parse_posts(text, TELEGRAM_ATTACK_KEYWORDS)
                if has_intent or targets:
                    theater_targets.extend(targets)
                    if has_intent:
                        theater_intent = True
                    active_channels.append(channel)
                    total_hits += 1
                    snippet    = self._extract_snippet(text, matched_kws or TELEGRAM_ATTACK_KEYWORDS)
                    ch_url     = self.TGSTAT_URL.format(channel=channel)
                    det_status = "INTENT_DETECTED" if has_intent else "TARGETS_FOUND"
                    self._log_detection(theater, channel, ch_url, det_status, matched_kws, targets, snippet)

            results[theater] = {
                "channels_monitored": channels,
                "active_channels":    active_channels,
                "target_urls":        list(set(theater_targets)),
                "has_attack_intent":  theater_intent,
                "status":             "INTENT_DETECTED" if theater_intent else
                                      "TARGETS_FOUND" if theater_targets else "CLEAR",
            }

            # Register sequence event
            if theater_intent:
                register_sequence_event(theater, "NARRATIVE_BURST", {
                    "source": "telegram_mirror",
                    "channels": active_channels,
                    "targets": list(set(theater_targets))[:5],
                })

        TelegramMirrorSensor._last_poll_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        TelegramMirrorSensor._last_poll_ok = any_success or len(theaters) == 0
        self.log_fetch(any_success or len(theaters) == 0,
                       round((time.time() - t0) * 1000), 200, total_hits)
        result = {"telegram": results}
        self.set_cache(result)
        return result


class CheckHostSensor(BaseSensor):
    """
    Infra Domain sensor: uses check-host.net API to run reachability checks
    against INFRASTRUCTURE_URLS from multiple global nodes and compute Success Rate.
    Also invoked on DDoS acceleration spike detection (from WeightedConvergenceEngine).
    """
    CHECK_HOST_API = "https://check-host.net/check-http"
    RESULT_API     = "https://check-host.net/check-result/{request_id}"
    # Per-URL cooldown: only re-check a URL if ≥ 5 min has elapsed since last poll
    _URL_COOLDOWN_SEC = 300
    _url_last_poll: dict = {}   # url → unix timestamp of last successful check
    # Rolling latency history: last 12 readings per URL (≈1 h at 5-min poll interval)
    _url_latency_history: dict = {}  # url → deque of latency_ms floats

    def __init__(self):
        super().__init__("check_host", "physical", CHECKHOST_POLL_INTERVAL)

    def check_url(self, url: str, nodes: list) -> dict:
        """Check a single URL from multiple nodes and return {success_rate, node_ok, results}.
        Detects CDN-masked asphyxiation: success_rate==1.0 but latency > 3× 1-hour rolling avg."""
        try:
            # Pass list of tuples to requests to allow repeated same key
            params = [("host", url), ("max_nodes", min(len(nodes), 5))]
            params += [("node[]", n) for n in nodes[:5]]
            res = requests.get(
                self.CHECK_HOST_API,
                params=params,
                headers={"Accept": "application/json",
                         "User-Agent": "OSINT-Radar/9.0"},
                timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if res.status_code != 200:
                return {"success_rate": None, "error": f"HTTP {res.status_code}"}

            data = res.json()
            request_id = data.get("request_id", "")
            if not request_id:
                return {"success_rate": None, "error": "no request_id"}

            # Wait up to 10 seconds for results
            time.sleep(5)
            r2 = requests.get(
                self.RESULT_API.format(request_id=request_id),
                headers={"Accept": "application/json",
                         "User-Agent": "OSINT-Radar/9.0"},
                timeout=12, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if r2.status_code != 200:
                return {"success_rate": None, "error": f"result HTTP {r2.status_code}"}

            node_results = r2.json()
            ok_count  = 0
            all_count = 0
            latencies: list = []
            # Per-node result map: short label (e.g. "JP", "US") → "OK"/"FAIL"/"TIMEOUT"
            node_ok: dict = {}
            for node_id, checks in node_results.items():
                # Derive short display label from hostname prefix (e.g. "jp1" → "JP1")
                node_label = node_id.split(".")[0][:3].upper()
                if not isinstance(checks, list):
                    # Node returned null: still pending (5s wait insufficient) or unreachable.
                    # Do NOT count in all_count — pending nodes must not dilute success_rate.
                    node_ok[node_label] = "PENDING"
                    continue
                for chk in checks:
                    # check-host.net HTTP result format:
                    # [ok_flag, time_seconds, status_msg, http_code_str, ip]
                    # ok_flag: 1=success, 0=failure
                    # e.g. [1, 0.634, "Found", "302", "1.2.3.4"]
                    # error:  [0, 0.0, "Connection refused", "", ""]
                    # individual null entry: single check still pending
                    if chk is None:
                        # Individual check still pending — do NOT count in all_count.
                        # Treating as failure would dilute success_rate identically to
                        # the top-level null case fixed above.
                        node_ok[node_label] = "PENDING"
                        continue
                    if not isinstance(chk, list) or len(chk) < 2:
                        continue
                    all_count += 1
                    ok_flag  = chk[0]                                 # int: 1 or 0
                    time_s   = chk[1] if isinstance(chk[1], (int, float)) else None
                    http_str = chk[3] if len(chk) > 3 else None      # e.g. "200", "302"
                    # Determine success: ok_flag==1 AND HTTP code < 400 (if available)
                    try:
                        http_int = int(http_str) if http_str else None
                    except (ValueError, TypeError):
                        http_int = None
                    is_ok = (ok_flag == 1) and (http_int is None or http_int < 400)
                    if is_ok:
                        ok_count += 1
                    if time_s is not None and time_s > 0:
                        lat_ms = time_s * 1000  # seconds → ms
                        latencies.append(lat_ms)
                        if lat_ms > CHECKHOST_TIMEOUT_MS:
                            node_ok[node_label] = "TIMEOUT"
                        else:
                            node_ok[node_label] = "OK" if is_ok else "FAIL"
                    else:
                        node_ok[node_label] = "OK" if is_ok else "FAIL"

            success_rate = round(ok_count / all_count, 3) if all_count > 0 else None
            avg_latency  = round(sum(latencies) / len(latencies)) if latencies else None

            # NOTE: Latency-based success_rate penalty removed.
            # Cross-continental checks (e.g. EU nodes → TW/UA gov sites) legitimately
            # exceed 3000ms without indicating failure. HTTP ok_flag already captures
            # true failures. High latency is surfaced via node_ok TIMEOUT labels and
            # the asphyxiation detector below — it must not corrupt success_rate.

            # ── Asphyxiation detection (CDN masking) ─────────────────────────────
            # Compute rolling baseline BEFORE appending current sample so the spike
            # does not contaminate the baseline it is being compared against.
            if url not in CheckHostSensor._url_latency_history:
                CheckHostSensor._url_latency_history[url] = deque(maxlen=12)
            lat_history = list(CheckHostSensor._url_latency_history[url])
            rolling_avg = sum(lat_history) / len(lat_history) if len(lat_history) >= 3 else None
            # Asphyxiation: success looks 100% but latency has tripled vs rolling baseline
            asphyxiation = (
                success_rate is not None and success_rate >= 0.99
                and avg_latency is not None and rolling_avg is not None
                and avg_latency > rolling_avg * 3.0
            )
            # Append current sample after comparison (update history for next cycle)
            if avg_latency is not None:
                CheckHostSensor._url_latency_history[url].append(avg_latency)

            return {
                "success_rate":   success_rate,
                "ok_nodes":       ok_count,
                "total_nodes":    all_count,
                "avg_latency_ms": avg_latency,
                "node_ok":        node_ok,
                "asphyxiation":   asphyxiation,
                "rolling_avg_latency_ms": round(rolling_avg) if rolling_avg else None,
                "status": ("OK"      if success_rate and success_rate >= 0.8 else
                           "PARTIAL" if success_rate and success_rate >= 0.3 else
                           "BLACKOUT"),
            }
        except Exception as e:
            return {"success_rate": None, "error": str(e)}

    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        results: dict = {}
        t0 = time.time()
        total_checked = 0
        any_success   = False
        now = time.time()

        for theater in theaters:
            urls = INFRASTRUCTURE_URLS.get(theater, [])
            if not urls:
                continue

            url_results: dict = {}
            ok_count   = 0
            asphyx_any = False
            url_count  = 0

            for url in urls[:3]:  # Rate limit mitigation: max 3 URLs per theater
                # Per-URL cooldown: skip if polled within the last 5 minutes
                last_poll = CheckHostSensor._url_last_poll.get(url, 0)
                if now - last_poll < CheckHostSensor._URL_COOLDOWN_SEC:
                    # Reuse cached result from previous fetch if available
                    cached_ch = self.get_cache().get("check_host", {})
                    prev = cached_ch.get(theater, {}).get("urls", {}).get(url)
                    if prev:
                        url_results[url] = prev
                        url_count += 1
                        if prev.get("success_rate", 0) >= 0.8:
                            ok_count += 1
                        if prev.get("asphyxiation"):
                            asphyx_any = True
                    continue

                chk = self.check_url(url, CHECKHOST_NODES)
                url_results[url] = chk
                url_count += 1
                if chk.get("success_rate") is not None:
                    any_success = True
                    total_checked += 1
                    CheckHostSensor._url_last_poll[url] = now
                    if chk["success_rate"] >= 0.8:
                        ok_count += 1
                if chk.get("asphyxiation"):
                    asphyx_any = True

            # Overall success rate for the theater
            theater_success_rate = ok_count / url_count if url_count else None
            overall_status = ("OK"      if theater_success_rate and theater_success_rate >= 0.8 else
                              "PARTIAL" if theater_success_rate and theater_success_rate >= 0.3 else
                              "BLACKOUT")

            results[theater] = {
                "urls":                 url_results,
                "theater_success_rate": theater_success_rate,
                "status":               overall_status,
                "asphyxiation":         asphyx_any,
            }

        self.log_fetch(any_success, round((time.time() - t0) * 1000), 200, total_checked)
        result = {"check_host": results}
        self.set_cache(result)
        return result


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

            # Save to cache
            with self._ip_lock:
                self._ip_cache[ip] = {"result": result, "fetched_at": now}
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
                    print(f"[GreyNoise] HTTP 401 — GNQL Stats requires an Enterprise API key. "
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

        for theater in theaters:
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



# ─────────────────────────────────────────────────────────────────────────────
# SensorRegistry & Engine
# ─────────────────────────────────────────────────────────────────────────────
class SensorRegistry:
    def __init__(self): self._sensors: dict[str, BaseSensor] = {}; self._lock = threading.Lock()
    def register(self, sensor: BaseSensor):
        with self._lock: self._sensors[sensor.name] = sensor
    def get(self, name: str) -> Optional[BaseSensor]: return self._sensors.get(name)
    def set_enabled(self, name: str, enabled: bool):
        with self._lock:
            if name in self._sensors: self._sensors[name].enabled = enabled
    def health_report(self) -> dict: return {name: s.health for name, s in self._sensors.items()}
    def config_list(self) -> list: return [s.to_config_dict() for s in self._sensors.values()]

class WeightedConvergenceEngine:
    DOMAIN_WEIGHTS = {"cyber": 0.50, "physical": 0.30, "info": 0.20}
    def compute_domain_scores(self, rationale: list) -> dict:
        scores = {"cyber": 0, "physical": 0, "info": 0}
        for entry in rationale:
            if isinstance(entry, RationaleEntry) and not entry.suppressed and entry.status == "FIRED":
                if entry.domain in scores: scores[entry.domain] += entry.score
        return scores
    def compute_convergence_score(self, domain_scores: dict) -> float:
        return sum(min(domain_scores.get(d, 0), 10) * w for d, w in self.DOMAIN_WEIGHTS.items())
    def compute_convergence_level(self, domain_scores: dict) -> str:
        active = sum(1 for s in domain_scores.values() if s > 0)
        return "FULL_CONVERGENCE" if active >= 3 else "DUAL_DOMAIN" if active == 2 else "SINGLE_DOMAIN" if active == 1 else "NONE"
    def apply_convergence_bonus(self, score: int, domain_scores: dict) -> tuple:
        level = self.compute_convergence_level(domain_scores)
        bonus = CONVERGENCE_FULL_BONUS if level == "FULL_CONVERGENCE" else CONVERGENCE_DUAL_BONUS if level == "DUAL_DOMAIN" else 0
        return score + bonus, bonus, level
    def compute_threat_level(self, score: int, tl1_hard: bool) -> int:
        if score >= 9 and tl1_hard: return 1
        if score >= 6: return 2
        if score >= 4: return 3
        if score >= 2: return 4
        return 5
    def apply_hysteresis(self, new_tl: int, history: list) -> tuple:
        if not history: return new_tl, False
        last_tl = history[-1][1]
        if new_tl > last_tl:
            held = min(new_tl, last_tl + 1)
            return held, (held != new_tl)
        return new_tl, False
    def build_system_note(self, threat_level: int, domain_scores: dict, convergence_level: str, rationale: list, noise_filters: list, tl_held: bool = False) -> str:
        fired = [e for e in rationale if isinstance(e, RationaleEntry) and e.status == "FIRED"]
        suppressed = [e for e in rationale if isinstance(e, RationaleEntry) and e.suppressed]
        held_note = " [HYSTERESIS HOLD]" if tl_held else ""
        parts = [f"Assessed THREAT LEVEL {threat_level}{held_note}."]
        conv_label = {"FULL_CONVERGENCE": f"⚡ FULL CONVERGENCE (+{CONVERGENCE_FULL_BONUS}pt bonus)", "DUAL_DOMAIN": f"⚠ DUAL DOMAIN (+{CONVERGENCE_DUAL_BONUS}pt bonus)", "SINGLE_DOMAIN": "Single Domain Activity", "NONE": ""}.get(convergence_level, "")
        if conv_label: parts.append(conv_label + ".")
        active_domains = [f"{d.upper()}({domain_scores[d]}pt)" for d in ("cyber", "physical", "info") if domain_scores.get(d, 0) > 0]
        if active_domains: parts.append(f"Active Domains: {', '.join(active_domains)}.")
        if fired: parts.append(f"Triggered Sensors: {', '.join(e.sensor for e in fired)}.")
        if suppressed: parts.append(f"Suppressed (Noise): {', '.join(e.sensor for e in suppressed)}.")
        if noise_filters: parts.append(f"Active Suppressors: {'; '.join(noise_filters)}.")
        return " ".join(parts)

    # ── Derivative & Synchronicity Methods ────────────────────────────────────
    @staticmethod
    def _linear_regression_slope(xs: list, ys: list) -> float:
        """Return the slope from least-squares linear regression."""
        n = len(xs)
        if n < 2: return 0.0
        sx, sy, sxy, sxx = sum(xs), sum(ys), sum(x*y for x,y in zip(xs,ys)), sum(x*x for x in xs)
        denom = n * sxx - sx * sx
        return (n * sxy - sx * sy) / denom if denom != 0 else 0.0

    def compute_velocity(self, ts_series: list) -> float:
        """First derivative: threat score change velocity (pt/s). Smoothed via linear regression slope over DERIVATIVE_WINDOW points."""
        pts = ts_series[-DERIVATIVE_WINDOW:] if len(ts_series) >= 2 else []
        if len(pts) < 2: return 0.0
        t0 = pts[0][0]
        xs = [p[0] - t0 for p in pts]
        ys = [p[1] for p in pts]
        return round(self._linear_regression_slope(xs, ys), 6)

    def compute_acceleration(self, ts_series: list) -> float:
        """Second derivative: rate of velocity change (pt/s²). Computed from a linear regression slope over consecutive velocity points."""
        if len(ts_series) < 4: return 0.0
        # Generate velocity series
        velocities = []
        for i in range(1, len(ts_series)):
            dt = ts_series[i][0] - ts_series[i-1][0]
            if dt > 0:
                velocities.append((ts_series[i][0], (ts_series[i][1] - ts_series[i-1][1]) / dt))
        if len(velocities) < 2: return 0.0
        t0 = velocities[0][0]
        xs = [v[0] - t0 for v in velocities]
        ys = [v[1] for v in velocities]
        return round(self._linear_regression_slope(xs, ys), 8)

    def detect_ambush_pattern(self, ts_series: list) -> tuple:
        """
        Flags an Ambush Pattern (sudden rapid escalation) when the acceleration Z-Score
        exceeds AMBUSH_ZSCORE_THRESHOLD and acceleration is positive.
        Returns: (is_ambush: bool, z_score: float, velocity: float, acceleration: float)
        """
        if len(ts_series) < 5:
            return False, 0.0, 0.0, 0.0
        velocity = self.compute_velocity(ts_series)
        # Generate acceleration time series by shifting windows rather than computing from all points
        acc_series = []
        window = min(DERIVATIVE_WINDOW, len(ts_series) // 2)
        for i in range(window, len(ts_series)):
            sub = ts_series[i-window:i+1]
            acc_series.append(self.compute_acceleration(sub))
        if len(acc_series) < 3:
            return False, 0.0, velocity, 0.0
        current_acc = acc_series[-1]
        mean_acc = sum(acc_series[:-1]) / len(acc_series[:-1])
        variance = sum((a - mean_acc) ** 2 for a in acc_series[:-1]) / len(acc_series[:-1])
        std_acc = math.sqrt(variance) if variance > 0 else 0.0
        z_score = (current_acc - mean_acc) / std_acc if std_acc > 0 else 0.0
        is_ambush = (z_score > AMBUSH_ZSCORE_THRESHOLD) and (current_acc > 0) and (velocity > 0)
        return is_ambush, round(z_score, 3), round(velocity, 6), round(current_acc, 8)

    @staticmethod
    def compute_sync_score(origin_timestamps: dict) -> float:
        """
        Compute synchrony score from attack-start timestamps across multiple GEO sources.
        origin_timestamps: {country_code: timestamp_ms}
        Returns: sync_score (0.0–1.0). Exceeding SYNC_C2_THRESHOLD indicates suspected state-level C2.
        """
        codes = list(origin_timestamps.keys())
        n = len(codes)
        if n < 2: return 0.0
        pair_count = n * (n - 1) // 2
        sync_pairs = 0
        for i in range(n):
            for j in range(i + 1, n):
                dt = abs(origin_timestamps[codes[i]] - origin_timestamps[codes[j]])
                if dt <= SYNC_DELTA_MS:
                    sync_pairs += 1
        return round(sync_pairs / pair_count, 3) if pair_count > 0 else 0.0

    # ── v9: Temporal Coherence / Maskirovka / Blockade Index ─────────────────

    @staticmethod
    def compute_temporal_coherence(sequence_events: dict, theaters: list,
                                   window_sec: float = 60.0) -> tuple:
        """
        Verify that attack-start timing across multiple theaters converges within window_sec seconds.
        High synchrony (within 1 minute) is treated as evidence of state-level integrated C2.

        sequence_events: {theater: [{"ts": float, "type": str, ...}, ...]}
        theaters: list of theaters to evaluate
        Returns: (is_synchronized: bool, coherence_score: float, bonus: int, detail: str)
        """
        # Collect timestamps of the first SYNC_DDOS or NARRATIVE_BURST event per theater
        first_events: dict = {}
        for theater in theaters:
            events = sequence_events.get(theater, [])
            trigger_events = [
                e["ts"] for e in events
                if e.get("type") in ("SYNC_DDOS", "NARRATIVE_BURST")
            ]
            if trigger_events:
                first_events[theater] = min(trigger_events)

        if len(first_events) < 2:
            return False, 0.0, 0, "insufficient_events"

        ts_list = list(first_events.values())
        spread_sec = max(ts_list) - min(ts_list)

        if spread_sec <= window_sec:
            # Sync within 1 minute → state C2 bonus +2
            coherence_score = round(1.0 - spread_sec / window_sec, 3)
            detail = f"C2_SYNC_CONFIRMED: {len(first_events)} theaters within {spread_sec:.1f}s"
            return True, coherence_score, 2, detail
        elif spread_sec <= window_sec * 5:
            # Loose sync within 5 minutes → partial bonus +1
            coherence_score = round(max(0.0, 1.0 - spread_sec / (window_sec * 5)), 3)
            detail = f"C2_SYNC_PARTIAL: {len(first_events)} theaters within {spread_sec:.1f}s"
            return False, coherence_score, 1, detail

        return False, 0.0, 0, f"no_sync: spread={spread_sec:.1f}s"

    @staticmethod
    def detect_maskirovka(core_degraded: bool, narrative_burst: bool,
                          check_host_status: Optional[str],
                          telegram_intent: bool,
                          other_sensors_alive: bool = True) -> tuple:
        """
        Maskirovka (deception operation) detection:
        Flags when physical disruption (Check-Host/IODA at BLACKOUT/PARTIAL) is present
        but the narrative (Telegram mirror / RSS) is silent.

        other_sensors_alive: True when ≥1 adjacent theater's sensors are responding normally.
            Distinguishes deliberate regional suppression from a global API outage.
            When True, confidence is upgraded MEDIUM → HIGH (+1 score bonus via rationale).

        Returns: (is_maskirovka: bool, confidence: str, reason: str)
        """
        has_physical_outage   = core_degraded or check_host_status in ("BLACKOUT", "PARTIAL")
        has_narrative_silence = not narrative_burst and not telegram_intent

        if has_physical_outage and has_narrative_silence:
            if other_sensors_alive:
                return True, "HIGH", (
                    "Physical outage confirmed, all narrative channels silent, "
                    "and adjacent theater sensors are live — "
                    "deliberate regional suppression confirmed (Maskirovka HIGH)"
                )
            return True, "MEDIUM", (
                "Physical outage confirmed but all narrative channels silent — "
                "possible deception operation (Maskirovka); "
                "cross-theater sensor liveness unconfirmed"
            )
        return False, "NONE", ""

    @staticmethod
    def _agg_node_status(statuses: list) -> str:
        """Worst-case node status aggregation across multiple URL checks.
        Priority: FAIL > TIMEOUT > OK > PENDING (unknown last)."""
        if "FAIL"    in statuses: return "FAIL"
        if "TIMEOUT" in statuses: return "TIMEOUT"
        if "OK"      in statuses: return "OK"
        return "PENDING"

    @staticmethod
    def compute_blockade_index(ddos_intensity: float, ripe_drop_pct: float,
                               checkhost_success_rate: Optional[float],
                               asphyxiation: bool = False) -> float:
        """
        Effective Blockade Index: (DDoS intensity × RIPE delay) / Check-Host success rate
        Scores the effectiveness of "communications blackout" from 0 to 10.

        ddos_intensity:         CF spike factor (average spike multiplier)
        ripe_drop_pct:          RIPE BGP prefix drop rate (0–100)
        checkhost_success_rate: Check-Host success rate (0.0–1.0, None = not measured)
        asphyxiation:           CDN-masking detected — success_rate==100% but latency ≥ 3× baseline.
                                Apply 1.5× weight penalty: the CDN is absorbing the attack but
                                infrastructure is being choked (latency stress, not packet drop).
        """
        # Normalize RIPE delay to 0–1 (drop_pct 100% = 1.0)
        ripe_factor = min(ripe_drop_pct / 100.0, 1.0)
        # Cap DDoS intensity at 10
        intensity = min(ddos_intensity, 10.0)
        numerator = intensity * (1.0 + ripe_factor)   # RIPE 0% = intensity only, 100% = 2×
        # When Check-Host has not yet polled, use IODA fallback degraded flag
        denominator = max(checkhost_success_rate if checkhost_success_rate is not None else 1.0, 0.05)
        raw = numerator / denominator
        # Asphyxiation multiplier: CDN masks packet loss but latency tripling reveals infrastructure strain
        if asphyxiation:
            raw *= 1.5
        return round(min(raw, 10.0), 2)

# ─────────────────────────────────────────────────────────────────────────────
# Global instances
# ─────────────────────────────────────────────────────────────────────────────
registry = SensorRegistry()
for s in [
    CloudflareSensor(), IodaSensor(), OpenSkySensor(), OpenWeatherSensor(),
    GDELTSensor(), PeeringDbSensor(), BgpRoutingSensor(), NasaFirmsSensor(), ThreatFoxSensor(),
    # Additional sensors (v8)
    RssNarrativeSensor(), IsrHotspotSensor(), AisMaritimeSensor(),
    # Additional sensors (v9)
    TelegramMirrorSensor(), CheckHostSensor(), GreyNoiseSensor(),
]:
    registry.register(s)
engine = WeightedConvergenceEngine()

def _build_default_context() -> dict:
    """Build sensor context based on default config. Used by the background scheduler."""
    return {
        "all_targets":         sorted(set([DEFAULT_CORE] + DEFAULT_CORRELATES + DEFAULT_PINS)),
        "strategic_theaters":  sorted(set([DEFAULT_CORE] + DEFAULT_CORRELATES)),
        "cf_headers":          CF_HEADERS,
        "owm_api_key":         OWM_API_KEY,
        "weather_conditions":  {},
        "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD,
        "gdelt_history_window": GDELT_HISTORY_WINDOW,
    }

def _sensor_scheduler_worker(sensor: BaseSensor):
    """Dedicated background fetch thread for a sensor.
    - Normal: periodic fetch every poll_interval
    - On failure: retry up to 3 times at shorter intervals [5min, 10min, 30min]
    """
    # Use only retry intervals shorter than poll_interval
    # (Short-cycle sensors like IODA=5min need no retry → results in empty list)
    _RETRY_DELAYS = [d for d in [300, 600, 1800] if d < sensor.poll_interval]

    def _do_fetch() -> bool:
        ctx = _build_default_context()
        if sensor.name == "gdelt":
            owm = registry.get("openweather")
            if owm: ctx["weather_conditions"] = owm.get_cache().get("conditions", {})
        sensor.fetch(ctx)
        log = sensor.get_fetch_log()
        return bool(log and log[-1].get("success"))

    # Fetch immediately at startup
    try:
        success = _do_fetch()
    except Exception as e:
        print(f"[Sensor/{sensor.name}] Initial fetch error: {e}")
        success = False

    while True:
        if not success and _RETRY_DELAYS:
            # On failure: retry at shorter intervals
            for delay in _RETRY_DELAYS:
                time.sleep(delay)
                try:
                    success = _do_fetch()
                    if success:
                        print(f"[Sensor/{sensor.name}] Retry succeeded after {delay}s")
                        break
                except Exception as e:
                    print(f"[Sensor/{sensor.name}] Retry error (delay={delay}s): {e}")
            # After retries complete, resume normal poll_interval wait
        else:
            time.sleep(sensor.poll_interval)

        try:
            success = _do_fetch()
        except Exception as e:
            print(f"[Sensor/{sensor.name}] Scheduled fetch error: {e}")
            success = False

# Start background sensor schedulers
for _s in registry._sensors.values():
    threading.Thread(target=_sensor_scheduler_worker, args=(_s,),
                     daemon=True, name=f"sensor-{_s.name}").start()

global_cache      = {"time": 0, "data": {}, "strategic": {}}
_global_cache_lock = threading.Lock()   # Thread safety for full global_cache replacement
baseline_cache:    dict = {}
time_series_db:    dict = {}   # {theater: [float,...]}  ← backward compat: values only
time_series_ts_db: dict = {}   # {theater: [(ts, val),...]} ← with timestamps
time_series_l3_db: dict = {}
time_series_l7_db: dict = {}
airspace_baseline: dict = {}
threat_history:    deque = deque(maxlen=20)
alert_timeline:    deque = deque(maxlen=288)
ALERT_TIMELINE_MAX = 288  # Must match deque maxlen

# Event log for sequence scorer
# {theater: [{"ts": float, "type": str, "meta": dict}, ...]}
sequence_event_log: dict = {}
SEQUENCE_EVENT_TYPES = ["NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY", "AIS_DARK_GAP",
                        "TELEGRAM_INTENT", "MASKIROVKA", "C2_SYNC", "INFRA_BLACKOUT"]  # v9

# CF scoring-loop result cache (short-term cache for scoring, independent of sensor fetch)
# Key: (url, frozenset(params.items())) → {"time": float, "data": list}
_cf_scoring_cache: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────
# ── Sequence Scorer ───────────────────────────────────────────────────────────
def register_sequence_event(theater: str, event_type: str, meta: dict = None):
    """Register an event in the escalation chain log."""
    global sequence_event_log
    if theater not in sequence_event_log:
        sequence_event_log[theater] = []
    sequence_event_log[theater].append({
        "ts":   time.time(),
        "type": event_type,
        "meta": meta or {},
    })
    # Remove entries older than 24h to conserve memory
    cutoff = time.time() - SEQUENCE_WINDOW
    sequence_event_log[theater] = [
        e for e in sequence_event_log[theater] if e["ts"] >= cutoff
    ]

def compute_sequence_bonus(theater: str) -> tuple:
    """
    Validate the escalation chain within a 24h window and return bonus score and status string.
    Chain order (loose co-existence mode): all event types must exist within SEQUENCE_WINDOW.
    Strict ordering is not required, but temporal direction is verified (first event precedes last).
    Returns: (bonus: int, chain_status: str, events_found: list)
    """
    now = time.time()
    cutoff = now - SEQUENCE_WINDOW
    events = [e for e in sequence_event_log.get(theater, []) if e["ts"] >= cutoff]
    if not events:
        return 0, "NO_EVENTS", []

    # Chain definition order (loose co-existence: existence check only)
    chain_def = ["NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY"]
    found_types = {e["type"] for e in events}
    found_in_chain = [t for t in chain_def if t in found_types]
    found_count = len(found_in_chain)

    # Temporal direction check: first event must precede last (sanity check)
    if len(events) >= 2:
        earliest = min(e["ts"] for e in events)
        latest_ts = max(e["ts"] for e in events)
        timespan_h = round((latest_ts - earliest) / 3600, 1)
    else:
        timespan_h = 0.0

    if found_count == 4:
        return SEQUENCE_FULL_BONUS, f"FULL_CHAIN_CONFIRMED [{timespan_h}h span]", found_in_chain
    elif found_count >= 3:
        return SEQUENCE_PARTIAL_BONUS, f"PARTIAL_CHAIN ({found_count}/4): {found_in_chain}", found_in_chain
    else:
        return 0, f"INSUFFICIENT_CHAIN ({found_count}/4)", found_in_chain

def get_fallback_coord(code: str) -> dict:
    h = int(hashlib.md5((code or "Unknown").encode()).hexdigest(), 16)
    return {"lat": (h % 100) - 50, "lng": ((h // 100) % 360) - 180, "name": f"Origin: {code}"}

def fetch_cf_data(url: str, params: dict) -> list:
    try:
        res = requests.get(url, headers=CF_HEADERS, params=params, timeout=5, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
        if res.status_code == 200: return res.json().get("result", {}).get("top_0", [])
    except Exception: pass
    return []

def fetch_cf_data_cached(url: str, params: dict, ttl: float = None) -> list:
    """Cache CF API calls within the scoring loop.
    Uses CACHE_EXPIRY when TTL is omitted. Prevents repeated fetches on reload.
    Cleans up expired entries on each call to prevent memory leaks."""
    global _cf_scoring_cache
    if ttl is None:
        ttl = CACHE_EXPIRY
    now = time.time()
    # Remove expired entries (memory leak prevention)
    expired = [k for k, v in _cf_scoring_cache.items() if now - v["time"] > ttl * 2]
    for k in expired:
        del _cf_scoring_cache[k]
    cache_key = (url, frozenset(params.items()))
    entry = _cf_scoring_cache.get(cache_key)
    if entry and (now - entry["time"]) < ttl:
        return entry["data"]
    data = fetch_cf_data(url, params)
    _cf_scoring_cache[cache_key] = {"time": now, "data": data}
    return data

def parse_origins(origins_list: list) -> dict:
    parsed = {}
    for o in origins_list:
        code = o.get("origin1") or o.get("location") or o.get("clientCountryAlpha2")
        if not code:
            for k, v in o.items():
                if isinstance(v, str) and len(v) == 2 and v.isupper(): code = v; break
        weight = float(o.get("value") or o.get("count") or 1.0)
        if code: parsed[code] = weight
    return parsed

def calculate_overlap(dist1: dict, dist2: dict) -> float:
    if not dist1 or not dist2: return 0.0
    return round(sum(min(dist1.get(k, 0.0), dist2.get(k, 0.0)) for k in set(dist1) | set(dist2)), 2)

_asn_cache: dict = {}  # {target_code: {"time": float, "data": dict}}

def fetch_asn_origins(target_code: str) -> dict:
    global _asn_cache
    now = time.time()
    # Remove expired entries (memory leak prevention)
    expired = [k for k, v in _asn_cache.items() if now - v["time"] > CACHE_EXPIRY * 2]
    for k in expired:
        del _asn_cache[k]
    entry = _asn_cache.get(target_code)
    if entry and (now - entry["time"]) < CACHE_EXPIRY:
        return entry["data"]
    try:
        res = requests.get("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/ases/origin", headers=CF_HEADERS, params={"location": target_code, "dateRange": CURRENT_DATE_RANGE, "format": "json"}, timeout=5, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
        if res.status_code == 200:
            data = {f"AS{item.get('originAsn') or item.get('clientASN') or item.get('originAsnId')}": float(item.get("value", 0)) for item in res.json().get("result", {}).get("top_0", []) if item.get("originAsn") or item.get("clientASN") or item.get("originAsnId")}
            _asn_cache[target_code] = {"time": now, "data": data}
            return data
    except Exception: pass
    return {}

def compute_confidence(spike_factor: float, code: str, is_new_actor: bool, is_state_asn: bool) -> str:
    if is_state_asn and spike_factor > 2.0: return "HIGH"
    if is_new_actor: return "LOW"
    if spike_factor > 3.0: return "MEDIUM"
    if spike_factor > 2.0: return "MEDIUM"
    return "LOW"

# ─────────────────────────────────────────────────────────────────────────────
# Main API Route
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/app_config", methods=["GET"])
def app_config():
    return jsonify({
        "default_core": DEFAULT_CORE,
        "default_correlates": DEFAULT_CORRELATES,
        "default_adversaries": DEFAULT_ADVERSARIES,
        "default_pins": DEFAULT_PINS,
        "available_countries": [
            {"code": code, "name": info["name"], "region": COUNTRY_REGIONS.get(code, "Other"),
             "lat": info["lat"], "lng": info["lng"]}
            for code, info in sorted(COUNTRY_COORDS.items(), key=lambda x: x[1]["name"])
        ],
    })

@app.route("/api/threat_data", methods=["GET"])
def get_threat_data():
    global global_cache, baseline_cache, time_series_db, time_series_l3_db, time_series_l7_db

    current_time = time.time()
    targets_param  = request.args.get("targets", ",".join(DEFAULT_PINS)); requested_targets = [t.strip().upper() for t in targets_param.split(",") if t.strip()]
    correlates_param = request.args.get("correlates", ",".join(DEFAULT_CORRELATES)); correlate_targets = [t.strip().upper() for t in correlates_param.split(",") if t.strip()]
    adv_param = request.args.get("adversaries", ",".join(DEFAULT_ADVERSARIES)); adversary_states = [a.strip().upper() for a in adv_param.split(",") if a.strip()]
    core_theater = request.args.get("core", DEFAULT_CORE).strip().upper()
    force_sync   = request.args.get("force", "false").lower() == "true"
    
    # HITL Analyst MUTE parameters
    muted_sensors = [s.strip() for s in request.args.get("muted", "").split(",") if s.strip()]

    required_keys = set(requested_targets + correlate_targets)
    if core_theater: required_keys.add(core_theater)

    strategic_theaters_set = set([core_theater] + correlate_targets)
    
    sensor_context = {
        "all_targets": list(required_keys), 
        "strategic_theaters": list(strategic_theaters_set),
        "cf_headers": CF_HEADERS, "owm_api_key": OWM_API_KEY, 
        "weather_conditions": {}, "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD, 
        "gdelt_history_window": GDELT_HISTORY_WINDOW
    }

    # Sensors are individually scheduled in the background.
    # Immediate fetch only on force_sync (SYNC button). Do not wait on missing_data.
    # (At startup, background threads are fetching in parallel; waiting for sync would
    #  block for minutes on slow sensors like PeeringDB/AIS).
    if force_sync:
        executor = ThreadPoolExecutor(max_workers=10)
        futures = [executor.submit(sensor.fetch, sensor_context)
                   for sensor in registry._sensors.values() if sensor.enabled]
        try:
            for future in as_completed(futures, timeout=60):
                try:
                    future.result()
                except Exception:
                    pass
        except TimeoutError:
            # Use cached data for timed-out sensors.
            # Let them complete in the background and update the cache.
            pass
        finally:
            executor.shutdown(wait=False, cancel_futures=False)

    if (current_time - global_cache.get("time", 0) > SCORE_REFRESH_SEC) or force_sync:
        # Extract required states from caches
        cf_sensor = registry.get("cloudflare_radar")
        ioda_sensor = registry.get("ioda_bgp")
        ioda_data = ioda_sensor.get_cache().get("statuses", {}) if ioda_sensor else {}
        owm_sensor = registry.get("openweather")
        weather_conditions = owm_sensor.get_cache().get("conditions", {}) if owm_sensor else {}
        opensky_sensor = registry.get("opensky")
        airspace_data = opensky_sensor.get_cache().get("airports", {}) if opensky_sensor else {}
        gdelt_sensor = registry.get("gdelt")
        gdelt_tones = gdelt_sensor.get_cache().get("gdelt_tones", {}) if gdelt_sensor else {}
        peeringdb_sensor = registry.get("peeringdb_ixp")
        ixp_data = peeringdb_sensor.get_cache().get("ixp_data", {}) if peeringdb_sensor else {}
        bgp_routing_sensor = registry.get("ripe_bgp")
        bgp_routing_data = bgp_routing_sensor.get_cache().get("routing_stats", {}) if bgp_routing_sensor else {}
        nasa_firms_sensor = registry.get("nasa_firms")
        nasa_firms_data = nasa_firms_sensor.get_cache().get("anomalies", []) if nasa_firms_sensor else []
        threatfox_sensor = registry.get("threatfox")
        threatfox_data = threatfox_sensor.get_cache().get("hits", {}) if threatfox_sensor else {}
        # Fetch additional sensor data (v8)
        rss_narrative_sensor = registry.get("rss_narrative")
        narrative_data = rss_narrative_sensor.get_cache().get("narratives", {}) if rss_narrative_sensor else {}
        isr_hotspot_sensor = registry.get("isr_hotspot")
        isr_data = isr_hotspot_sensor.get_cache().get("isr_data", {}) if isr_hotspot_sensor else {}
        ais_maritime_sensor = registry.get("ais_maritime")
        ais_dark_gaps        = ais_maritime_sensor.get_cache().get("dark_gaps", []) if ais_maritime_sensor else []
        ais_stationary       = ais_maritime_sensor.get_cache().get("stationary_anomalies", []) if ais_maritime_sensor else []
        ais_has_anomaly      = ais_maritime_sensor.get_cache().get("has_anomaly", False) if ais_maritime_sensor else False
        # Fetch additional sensor data (v9)
        telegram_mirror_sensor = registry.get("telegram_mirror")
        telegram_data          = telegram_mirror_sensor.get_cache().get("telegram", {}) if telegram_mirror_sensor else {}
        check_host_sensor      = registry.get("check_host")
        checkhost_data         = check_host_sensor.get_cache().get("check_host", {}) if check_host_sensor else {}
        greynoise_sensor       = registry.get("greynoise")
        greynoise_data         = greynoise_sensor.get_cache().get("greynoise", {}) if greynoise_sensor else {}

        airspace_anomalies, noise_filters_applied = [], []
        for code, ainfo in airspace_data.items():
            count = ainfo.get("count", -1)
            if count < 0: ainfo["status"] = "ERROR"; continue
            if code not in airspace_baseline: airspace_baseline[code] = {"readings": [], "avg": 0.0}
            bl = airspace_baseline[code]
            bl["readings"].append(count); bl["readings"] = bl["readings"][-AIRSPACE_WINDOW:]
            n = len(bl["readings"])
            bl["avg"] = sum(bl["readings"]) / n if n > 0 else 0.0
            ainfo["baseline_avg"] = round(bl["avg"], 1); ainfo["baseline_n"] = n

            if n < 3 or bl["avg"] < 1:
                ainfo["status"] = "BASELINE_BUILDING"; ainfo["drop_pct"] = 0.0; continue

            drop_ratio = max(0.0, (bl["avg"] - count) / bl["avg"]); ainfo["drop_pct"] = round(drop_ratio * 100, 1)
            weather_suppressed = weather_conditions.get(code, {}).get("is_severe", False)

            severity = "CLOSURE" if drop_ratio >= (1.0 - AIRSPACE_CLOSURE_THRESHOLD) else "ANOMALY" if drop_ratio >= (1.0 - AIRSPACE_ANOMALY_THRESHOLD) else "NORMAL"
            if severity in ("CLOSURE", "ANOMALY"):
                if weather_suppressed:
                    ainfo["status"] = "WEATHER_NOISE"; noise_filters_applied.append(f"weather_noise@{code}: airspace {severity.lower()} suppressed")
                else:
                    ainfo["status"] = severity
                    airspace_anomalies.append({"code": code, "airport": ainfo.get("airport", code), "count": count, "baseline": ainfo["baseline_avg"], "drop_pct": ainfo["drop_pct"], "severity": severity, "lat": ainfo.get("lat"), "lng": ainfo.get("lng")})
            else: ainfo["status"] = "NORMAL"

        degraded_targets_raw, degraded_targets_effective = [], []
        g_l3 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/target", {"dateRange": CURRENT_DATE_RANGE, "format": "json"}))
        g_l7 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/target", {"dateRange": CURRENT_DATE_RANGE, "format": "json"}))

        target_details, origin_distributions, origin_distributions_l3, origin_distributions_l7 = {}, {}, {}, {}
        adversary_strikes, vector_shifts = [], []

        for t in list(required_keys):
            if ioda_data.get(t, "NORMAL") == "BGP_OUTAGE":
                degraded_targets_raw.append(t)
                if weather_conditions.get(t, {}).get("is_severe", False): noise_filters_applied.append(f"weather_noise@{t}: BGP outage suppressed")
                else: degraded_targets_effective.append(t)

        for t in required_keys:
            if t not in time_series_db: time_series_db[t] = []
            if t not in time_series_l3_db: time_series_l3_db[t] = []
            if t not in time_series_l7_db: time_series_l7_db[t] = []

            if t not in baseline_cache or (current_time - baseline_cache[t]["time"] > 86400):
                b_l3 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin", {"location": t, "dateRange": BASELINE_DATE_RANGE, "format": "json"}, ttl=86400))
                b_l7 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin", {"location": t, "dateRange": BASELINE_DATE_RANGE, "format": "json"}, ttl=86400))
                baseline_cache[t] = {"time": current_time, "l3": b_l3, "l7": b_l7}

            b_data = baseline_cache[t]
            g_l3_share_display, g_l7_share_display = g_l3.get(t, 0.0), g_l7.get(t, 0.0)
            g_l3_share, g_l7_share = max(g_l3_share_display, 0.1), max(g_l7_share_display, 0.1)
            global_target_share = (g_l3_share_display + g_l7_share_display) / 2.0

            o_l3 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer3/top/locations/origin", {"location": t, "dateRange": CURRENT_DATE_RANGE, "format": "json"}))
            o_l7 = parse_origins(fetch_cf_data_cached("https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin", {"location": t, "dateRange": CURRENT_DATE_RANGE, "format": "json"}))

            state_asn_hits = {}
            if t in strategic_theaters_set:
                for asn_key in fetch_asn_origins(t):
                    if asn_key in STATE_ASNS: state_asn_hits.setdefault(STATE_ASNS[asn_key], []).append(asn_key)

            combined_sources, normalized_dist, normalized_dist_l3, normalized_dist_l7 = {}, {}, {}, {}
            target_weighted_spike, total_local_pct, target_l3_spike_sum, target_l7_spike_sum = 0.0, 0.0, 0.0, 0.0
            all_origin_codes = set(o_l3) | set(o_l7)

            # ── Spike anti-inflation guard ──
            # Skip spike computation when baseline data is empty (at startup or CF API error).
            # Computing with an empty baseline sets all origins to the 0.5% minimum, causing 90×+ false positives.
            has_baseline = bool(b_data.get("l3") or b_data.get("l7"))

            for code in all_origin_codes:
                local_l3_pct, local_l7_pct = o_l3.get(code, 0.0), o_l7.get(code, 0.0)
                current_local_pct = max(local_l3_pct, local_l7_pct)

                is_new_actor = (code not in b_data["l3"]) and (code not in b_data["l7"])
                # Adversary states (CN/RU/KP etc.) use a lower baseline floor to detect even small attacks.
                # Non-adversary states use a higher floor (3%) to suppress noise.
                # Example: KP at baseline 0.1% → current 2% correctly detected as a 4× spike.
                is_adversary_origin = code in adversary_states
                _floor_new   = 0.5 if is_adversary_origin else 3.0  # new actor (not in baseline)
                _floor_exist = 0.5 if is_adversary_origin else 2.0  # existing actor
                base_l3 = max(b_data["l3"].get(code, _floor_new), _floor_new if code not in b_data["l3"] else _floor_exist)
                base_l7 = max(b_data["l7"].get(code, _floor_new), _floor_new if code not in b_data["l7"] else _floor_exist)
                l3_spike = (local_l3_pct / base_l3) if local_l3_pct > 0 else 0.0
                l7_spike = (local_l7_pct / base_l7) if local_l7_pct > 0 else 0.0
                # Cap spike multiplier at 25× (prevent extreme amplification from statistical noise)
                spike_factor = min(max(l3_spike, l7_spike), 25.0)

                normalized_dist_l3[code], normalized_dist_l7[code], normalized_dist[code] = local_l3_pct, local_l7_pct, current_local_pct

                # Include in spike aggregation only when baseline exists and absolute value is significant (≥1%)
                if has_baseline and current_local_pct >= 1.0:
                    target_weighted_spike += spike_factor * current_local_pct
                    target_l3_spike_sum += l3_spike * current_local_pct
                    target_l7_spike_sum += l7_spike * current_local_pct
                    total_local_pct += current_local_pct

                global_l3_weight = g_l3_share * (local_l3_pct / 100.0); global_l7_weight = g_l7_share * (local_l7_pct / 100.0)
                total_global_weight = global_l3_weight + global_l7_weight

                is_direct_strike = False
                if code in adversary_states and t in strategic_theaters_set and spike_factor >= 4.0 and current_local_pct > 3.0:
                    adversary_strikes.append({"actor": code, "target": t, "spike": round(spike_factor, 1), "pct": round(current_local_pct, 1)})
                    is_direct_strike = True

                per_origin_l7_shift = (l7_spike >= 2.5 and l7_spike > l3_spike * 1.5 and local_l7_pct > 1.5)
                is_state_asn = code in state_asn_hits
                confidence = compute_confidence(spike_factor, code, is_new_actor, is_state_asn)

                if total_global_weight > 0.01 or is_direct_strike:
                    coord = COUNTRY_COORDS.get(code) or get_fallback_coord(code)
                    combined_sources[code] = {"lat": coord["lat"], "lng": coord["lng"], "name": coord["name"], "code": code, "weight": total_global_weight, "l3_weight": global_l3_weight, "l7_weight": global_l7_weight, "spike_factor": round(spike_factor, 2), "l3_spike": round(l3_spike, 2), "l7_spike": round(l7_spike, 2), "is_l7_shift": per_origin_l7_shift, "is_new_actor": is_new_actor, "is_state_asn": is_state_asn, "state_asns": state_asn_hits.get(code, []), "confidence": confidence}

            origin_distributions[t], origin_distributions_l3[t], origin_distributions_l7[t] = normalized_dist, normalized_dist_l3, normalized_dist_l7
            # Floor normalization denominator at 5% (prevents avg_spike overestimation at low traffic)
            avg_l3_spike = target_l3_spike_sum / max(total_local_pct, 5.0); avg_l7_spike = target_l7_spike_sum / max(total_local_pct, 5.0)
            shift_actors = [s["code"] for s in combined_sources.values() if s.get("is_l7_shift")]
            is_vector_shift = ((avg_l7_spike >= 2.5 and avg_l7_spike > avg_l3_spike * 1.5) or len(shift_actors) > 0)
            if is_vector_shift and t in strategic_theaters_set: vector_shifts.append(t)

            avg_spike_record = round(target_weighted_spike / max(total_local_pct, 5.0), 2)
            time_series_db[t].append(avg_spike_record); time_series_db[t] = time_series_db[t][-15:]
            time_series_l3_db[t].append(round(avg_l3_spike, 2)); time_series_l3_db[t] = time_series_l3_db[t][-15:]
            time_series_l7_db[t].append(round(avg_l7_spike, 2)); time_series_l7_db[t] = time_series_l7_db[t][-15:]
            # Update timestamped time series (for derivative computation)
            if t not in time_series_ts_db: time_series_ts_db[t] = []
            time_series_ts_db[t].append((current_time, avg_spike_record))
            time_series_ts_db[t] = time_series_ts_db[t][-30:]  # Retain more points for derivative computation

            target_details[t] = {"global_share": global_target_share, "global_share_l3": g_l3_share_display, "global_share_l7": g_l7_share_display, "avg_spike": avg_spike_record, "is_vector_shift": is_vector_shift, "shift_actors": shift_actors, "sources": list(combined_sources.values())}

        correlations, correlations_l3, correlations_l7 = {}, {}, {}
        if core_theater in origin_distributions:
            for t in correlate_targets:
                if t != core_theater and t in origin_distributions:
                    key = f"{core_theater}-{t}"
                    correlations[key]    = calculate_overlap(origin_distributions[core_theater], origin_distributions[t])
                    correlations_l3[key] = calculate_overlap(origin_distributions_l3.get(core_theater, {}), origin_distributions_l3.get(t, {}))
                    correlations_l7[key] = calculate_overlap(origin_distributions_l7.get(core_theater, {}), origin_distributions_l7.get(t, {}))

        elevated_theaters = [t for t in strategic_theaters_set if target_details.get(t, {}).get("avg_spike", 0) > 3.0]
        is_coordinated = len(elevated_theaters) >= 2

        core_spike     = target_details.get(core_theater, {}).get("avg_spike", 0)
        core_degraded  = core_theater in degraded_targets_effective
        core_shifted   = core_theater in vector_shifts
        # State-directed coordinated ops typically show 20–35% overlap. 45%+ indicates large civilian botnet.
        high_correlation = any(v > 30.0 for v in correlations.values())
        major_adversary  = len(adversary_strikes) > 0
        tl1_hard = core_spike > 5.0 and core_degraded

        rationale: list[RationaleEntry] = []

        def add_rat(sensor, domain, status, value, score, fired_reason, is_suppressed=False, suppress_reason=None):
            _is_muted = (sensor in muted_sensors) or is_suppressed
            _s_reason = "Analyst Muted (HITL)" if (sensor in muted_sensors) else suppress_reason
            rationale.append(RationaleEntry(sensor=sensor, domain=domain, status=status, value=value, score=score, fired_reason=fired_reason, suppressed=_is_muted, suppress_reason=_s_reason))

        if not (cf_sensor and cf_sensor.enabled):
            add_rat("cloudflare_radar", "cyber", "DISABLED", "sensor off", 0, None)
        else:
            spike_score = (1 if core_spike > 2.0 else 0) + (1 if core_spike > 4.0 else 0) + (1 if core_spike > 6.0 else 0)
            add_rat("cf_spike_core", "cyber", "FIRED" if core_spike > 2.0 else "OK", f"{core_spike:.2f}x", spike_score, f"Core theater spike exceeds 2x baseline" if spike_score else None)
            max_overlap = max(correlations.values(), default=0.0)
            add_rat("cf_botnet_overlap", "cyber", "FIRED" if high_correlation else "OK", f"{max_overlap:.1f}% overlap", 1 if high_correlation else 0, "Shared botnet >30%" if high_correlation else None)
            add_rat("cf_vector_shift", "cyber", "FIRED" if core_shifted else "OK", f"theaters={vector_shifts}", 1 if core_shifted else 0, "L7 application-layer escalation detected" if core_shifted else None)
            add_rat("cf_adversary_strike", "cyber", "FIRED" if major_adversary else "OK", f"{len(adversary_strikes)} strike(s)", 2 if major_adversary else 0, f"Adversary state direct strike" if major_adversary else None)
            add_rat("cf_coordinated", "cyber", "FIRED" if is_coordinated else "OK", f"theaters={elevated_theaters}", 1 if is_coordinated else 0, f"Simultaneous surge" if is_coordinated else None)

        if not (ioda_sensor and ioda_sensor.enabled):
            add_rat("ioda_bgp", "physical", "DISABLED", "sensor off", 0, None)
        else:
            weather_suppressed_bgp = [t for t in degraded_targets_raw if t not in degraded_targets_effective]
            bgp_value = f"bgp={'OUTAGE' if core_degraded else 'NORMAL'}"
            if weather_suppressed_bgp: bgp_value += f" weather_muted={weather_suppressed_bgp}"
            _wx_suppressed = (core_theater in weather_suppressed_bgp)
            add_rat("ioda_bgp", "physical", "FIRED" if core_degraded else "OK", bgp_value, 1 if core_degraded else 0, f"BGP anomaly confirmed" if core_degraded else None, is_suppressed=_wx_suppressed, suppress_reason=f"Weather-muted: {weather_suppressed_bgp}" if weather_suppressed_bgp else None)

        if not (opensky_sensor and opensky_sensor.enabled):
            add_rat("opensky", "physical", "DISABLED", "sensor off", 0, None)
        else:
            core_airspace = airspace_data.get(core_theater, {})
            airspace_status = core_airspace.get("status", "NO_DATA")
            airspace_score, airspace_fired, airspace_reason = 0, False, None
            if airspace_status == "CLOSURE": airspace_score, airspace_fired, airspace_reason = 3, True, f"Airport near-total closure"
            elif airspace_status == "ANOMALY": airspace_score, airspace_fired, airspace_reason = 2, True, f"Airspace anomaly"
            airspace_value = f"{core_airspace.get('airport','N/A')}: {core_airspace.get('count','?')} ac" if core_airspace else "No airport data"
            add_rat("opensky", "physical", "FIRED" if airspace_fired else ("SUPPRESSED" if airspace_status == "WEATHER_NOISE" else "OK"), airspace_value, airspace_score, airspace_reason, is_suppressed=(airspace_status == "WEATHER_NOISE"), suppress_reason="Severe weather detected" if airspace_status == "WEATHER_NOISE" else None)

        if not (owm_sensor and owm_sensor.enabled):
            add_rat("openweather", "physical", "DISABLED", "sensor off", 0, None)
        else:
            core_weather = weather_conditions.get(core_theater, {})
            add_rat("openweather", "physical", "OK", f"{core_theater}: {core_weather.get('severity', 'NORMAL')}", 0, None, suppress_reason=f"Active noise filter" if core_weather.get("is_severe") else None)

        if not (gdelt_sensor and gdelt_sensor.enabled):
            add_rat("gdelt", "info", "DISABLED", "sensor off", 0, None)
        else:
            core_tone = gdelt_tones.get(core_theater, {})
            tone_status, gdelt_alert = core_tone.get("status", "NO_DATA"), core_tone.get("status") == "ALERT"
            add_rat("gdelt", "info", "SUPPRESSED" if tone_status == "WEATHER_NOISE" else "FIRED" if gdelt_alert else "OK", tone_status, 1 if gdelt_alert else 0, "Media tone collapse" if gdelt_alert else None, is_suppressed=(tone_status == "WEATHER_NOISE"), suppress_reason="Severe weather detected" if tone_status == "WEATHER_NOISE" else None)

        if not (bgp_routing_sensor and bgp_routing_sensor.enabled):
            add_rat("ripe_bgp", "cyber", "DISABLED", "sensor off", 0, None)
        else:
            core_bgp, bgp_anomaly = bgp_routing_data.get(core_theater, {}), bgp_routing_data.get(core_theater, {}).get("is_anomaly", False)
            add_rat("ripe_bgp", "cyber", "FIRED" if bgp_anomaly else "OK", "ANOMALY" if bgp_anomaly else "NORMAL", 1 if bgp_anomaly else 0, "BGP prefix withdrawal" if bgp_anomaly else None)

        # NASA FIRMS (Physical)
        if nasa_firms_sensor and nasa_firms_sensor.enabled:
            has_firms = any(f["code"] == core_theater for f in nasa_firms_data)
            add_rat("nasa_firms", "physical", "FIRED" if has_firms else "OK", f"Thermal Anomalies", 3 if has_firms else 0, "Kinetic Strike Precursor")

        # ThreatFox (Cyber)
        if threatfox_sensor and threatfox_sensor.enabled:
            has_tf = core_theater in threatfox_data
            add_rat("threatfox", "cyber", "FIRED" if has_tf else "OK", "APT C2 Hit", 1 if has_tf else 0, "Known APT infra matched")

        if peeringdb_sensor and peeringdb_sensor.enabled:
            add_rat("peeringdb_ixp", "physical", "OK", f"IXP(s) registered", 0, None)

        # ── Additional sensor rationale + Sequence Event registration ──────────────────────

        # RSS narrative burst
        core_narrative = narrative_data.get(core_theater, {})
        narrative_burst = core_narrative.get("is_burst", False)
        narrative_z     = core_narrative.get("z_score", 0.0)
        narrative_status = core_narrative.get("status", "NORMAL")
        if rss_narrative_sensor and rss_narrative_sensor.enabled:
            n_score = 2 if narrative_status == "CRITICAL_BURST" else 1 if narrative_burst else 0
            add_rat("rss_narrative", "info",
                    "FIRED" if narrative_burst else "OK",
                    f"Z={narrative_z:.2f} [{narrative_status}]",
                    n_score,
                    f"Narrative Burst Z={narrative_z:.2f}" if narrative_burst else None)
            if narrative_burst:
                register_sequence_event(core_theater, "NARRATIVE_BURST",
                                        {"z_score": narrative_z, "status": narrative_status})

        # ISR hotspot surge
        core_isr = isr_data.get(core_theater, {})
        isr_surge = core_isr.get("is_surge", False)
        isr_count = core_isr.get("count", 0)
        if isr_hotspot_sensor and isr_hotspot_sensor.enabled:
            add_rat("isr_hotspot", "physical",
                    "FIRED" if isr_surge else "OK",
                    f"{isr_count} ISR ac in hotspot",
                    2 if isr_surge else 0,
                    f"ISR surge: {isr_count} aircraft" if isr_surge else None)
            if isr_surge:
                register_sequence_event(core_theater, "ISR_SURGE",
                                        {"count": isr_count, "hotspots": core_isr.get("hotspots", [])})

        # AIS maritime anomaly
        if ais_maritime_sensor and ais_maritime_sensor.enabled:
            core_gaps = [g for g in ais_dark_gaps if any(
                cp["country"] == core_theater for cp in CHOKEPOINTS if cp["name"] == g.get("chokepoint")
            )]
            ais_fired = ais_has_anomaly or len(core_gaps) > 0
            add_rat("ais_maritime", "physical",
                    "FIRED" if ais_fired else "OK",
                    f"dark_gaps={len(ais_dark_gaps)} stationary={len(ais_stationary)}",
                    1 if ais_fired else 0,
                    "AIS Dark Gap / Stationary Anomaly at chokepoint" if ais_fired else None)
            if ais_fired:
                register_sequence_event(core_theater, "AIS_DARK_GAP",
                                        {"dark_gaps": len(ais_dark_gaps), "stationary": len(ais_stationary)})

        # FIRMS → register Sequence Event (reuse existing sensor result)
        has_firms_core = any(f.get("code") == core_theater for f in nasa_firms_data)
        if has_firms_core:
            register_sequence_event(core_theater, "FIRMS_ANOMALY",
                                    {"hotspots": [f for f in nasa_firms_data if f.get("code") == core_theater]})

        # Sync DDoS detection → register Sequence Event (only at high sync + high score)
        if is_coordinated and high_correlation:
            register_sequence_event(core_theater, "SYNC_DDOS",
                                    {"coordinated_theaters": elevated_theaters,
                                     "max_overlap": max(correlations.values(), default=0.0)})

        # ── v9 sensor rationale ────────────────────────────────────────────────

        # Telegram Mirror (Info Domain)
        core_telegram       = telegram_data.get(core_theater, {})
        telegram_intent     = core_telegram.get("has_attack_intent", False)
        telegram_status     = core_telegram.get("status", "CLEAR")
        telegram_active_ch  = core_telegram.get("active_channels", [])
        if telegram_mirror_sensor and telegram_mirror_sensor.enabled:
            tg_score = 2 if telegram_intent else (1 if telegram_status == "TARGETS_FOUND" else 0)
            add_rat("telegram_mirror", "info",
                    "FIRED" if (telegram_intent or telegram_status == "TARGETS_FOUND") else "OK",
                    f"{telegram_status} ch={telegram_active_ch[:3]}",
                    tg_score,
                    f"Attack intent intercepted on Telegram: {telegram_active_ch}" if telegram_intent else
                    "Target URLs found in Telegram channels" if telegram_status == "TARGETS_FOUND" else None)
            if telegram_intent:
                register_sequence_event(core_theater, "NARRATIVE_BURST", {
                    "source": "telegram_mirror", "channels": telegram_active_ch,
                    "targets": core_telegram.get("target_urls", [])[:5],
                })

        # Check-Host (Physical Domain)
        core_checkhost   = checkhost_data.get(core_theater, {})
        ch_status        = core_checkhost.get("status", "UNKNOWN")
        ch_success_rate  = core_checkhost.get("theater_success_rate")
        if check_host_sensor and check_host_sensor.enabled:
            ch_score = (3 if ch_status == "BLACKOUT" else 2 if ch_status == "PARTIAL" else 0)
            ch_fired = ch_status in ("BLACKOUT", "PARTIAL")
            add_rat("check_host", "physical",
                    "FIRED" if ch_fired else ("OK" if ch_status == "OK" else "NO_DATA"),
                    f"{ch_status} success={ch_success_rate:.0%}" if ch_success_rate is not None else ch_status,
                    ch_score,
                    f"Infrastructure availability: {ch_status} (success_rate={ch_success_rate:.0%})" if ch_fired and ch_success_rate is not None else None)

        # GreyNoise (Cyber Domain — noise suppressor)
        core_greynoise     = greynoise_data.get(core_theater, {})
        gn_noise_class     = core_greynoise.get("noise_class", "UNKNOWN")
        gn_suppress        = core_greynoise.get("suppress_confidence", False)
        gn_noise_ratio     = core_greynoise.get("noise_ratio")
        if greynoise_sensor and greynoise_sensor.enabled:
            add_rat("greynoise", "cyber",
                    "SUPPRESSED" if gn_suppress else "OK",
                    f"{gn_noise_class} noise={gn_noise_ratio:.0%}" if gn_noise_ratio is not None else gn_noise_class,
                    0,   # GreyNoise provides suppression only, not a bonus
                    None,
                    is_suppressed=gn_suppress,
                    suppress_reason=f"GreyNoise: {gn_noise_class} — traffic classified as internet background noise" if gn_suppress else None)

        # ── v9 Temporal Coherence analysis ─────────────────────────────────────
        is_c2_sync, coherence_score, temporal_bonus, temporal_detail = \
            engine.compute_temporal_coherence(sequence_event_log, list(strategic_theaters_set))

        # ── Asphyxiation flag from Check-Host (CDN masking detection) ───────────
        ch_asphyxiation = core_checkhost.get("asphyxiation", False)

        # ── Cross-theater sensor liveness for Maskirovka confidence upgrade ─────
        # Other sensors are considered "alive" if ≥1 non-core theater's Check-Host
        # or IODA sensor returned a valid (non-error) result recently.
        other_theater_live = False
        for _t in strategic_theaters_set:
            if _t == core_theater:
                continue
            _other_ch = checkhost_data.get(_t, {})
            if _other_ch.get("theater_success_rate") is not None:
                other_theater_live = True
                break
            if ioda_data.get(_t) in ("NORMAL", "BGP_OUTAGE"):
                other_theater_live = True
                break

        # ── v9 Maskirovka detection ─────────────────────────────────────────────
        is_maskirovka, maskirovka_conf, maskirovka_reason = engine.detect_maskirovka(
            core_degraded=core_degraded,
            narrative_burst=narrative_burst or telegram_intent,
            check_host_status=ch_status,
            telegram_intent=telegram_intent,
            other_sensors_alive=other_theater_live,
        )
        if is_maskirovka:
            # HIGH confidence = +2 score (cross-theater confirmed suppression),
            # MEDIUM confidence = +1 score (no corroborating cross-theater data)
            msk_score = 2 if maskirovka_conf == "HIGH" else 1
            add_rat("maskirovka_flag", "info",
                    "FIRED", f"conf={maskirovka_conf}",
                    msk_score, maskirovka_reason)

        # ── Derivative computation (Velocity / Acceleration / Ambush) ───────────────
        ts_series_core = time_series_ts_db.get(core_theater, [])
        is_ambush, ambush_z, velocity_val, acceleration_val = engine.detect_ambush_pattern(ts_series_core)
        if is_ambush:
            add_rat("ddos_acceleration", "cyber",
                    "FIRED", f"Ambush Z={ambush_z:.2f} v={velocity_val:.4f}",
                    2, f"Exponential escalation detected (2nd derivative Z={ambush_z:.2f})")

        # ── Sequence Bonus computation ──────────────────────────────────────────
        seq_bonus, seq_status, seq_chain = compute_sequence_bonus(core_theater)

        domain_scores = engine.compute_domain_scores(rationale)
        total_score = sum(e.score for e in rationale if e.status == "FIRED" and not e.suppressed)
        convergence_score = engine.compute_convergence_score(domain_scores)
        score_with_bonus, conv_bonus, convergence_level = engine.apply_convergence_bonus(total_score, domain_scores)
        # Add Sequence Bonus and Temporal Coherence Bonus to final score
        score_with_bonus += seq_bonus + temporal_bonus
        tl_raw = engine.compute_threat_level(score_with_bonus, tl1_hard)
        threat_level, tl_held = engine.apply_hysteresis(tl_raw, threat_history)
        threat_history.append((current_time, threat_level))
        # deque(maxlen=20) automatically evicts old entries

        system_note = engine.build_system_note(threat_level, domain_scores, convergence_level, rationale, noise_filters_applied, tl_held)

        # Deep analysis result summary
        deep_analytics = {
            "velocity":        round(velocity_val, 6),
            "acceleration":    round(acceleration_val, 8),
            "is_ambush":       is_ambush,
            "ambush_z_score":  ambush_z,
            "sequence_bonus":  seq_bonus,
            "sequence_status": seq_status,
            "sequence_chain":  seq_chain,
            "narrative": {
                "z_score": narrative_z,
                "status":  narrative_status,
                "is_burst": narrative_burst,
            },
            "isr": {
                "count":    isr_count,
                "is_surge": isr_surge,
            },
            "ais": {
                "dark_gaps":   len(ais_dark_gaps),
                "stationary":  len(ais_stationary),
                "has_anomaly": ais_has_anomaly,
            },
            # Blockade Index v9: (DDoS intensity × RIPE delay) / Check-Host success rate
            # asphyxiation=True applies 1.5× weight when CDN masks packet loss but latency triples
            "blockade_index": engine.compute_blockade_index(
                ddos_intensity=core_spike,
                ripe_drop_pct=bgp_routing_data.get(core_theater, {}).get("drop_pct", 0.0),
                checkhost_success_rate=ch_success_rate,
                asphyxiation=ch_asphyxiation,
            ),
            # Temporal Coherence (v9 C2 synchrony analysis)
            "temporal_coherence": {
                "is_c2_sync":     is_c2_sync,
                "coherence_score": coherence_score,
                "bonus":          temporal_bonus,
                "detail":         temporal_detail,
            },
            # Maskirovka deception detection (v9)
            "maskirovka": {
                "detected":    is_maskirovka,
                "confidence":  maskirovka_conf,
                "reason":      maskirovka_reason,
            },
            # Check-Host Survival (v9) — includes detailed data + asphyxiation flag
            "check_host": {
                "theater_success_rate": ch_success_rate,
                "status":              ch_status,
                "url_results":         core_checkhost.get("urls", {}),
                "nodes":               CHECKHOST_NODES,
                "asphyxiation":        ch_asphyxiation,
                # Aggregate per-node OK/FAIL across all checked URLs
                # Aggregate per-node status across all checked URLs.
                # Uses worst-case: FAIL > TIMEOUT > OK > PENDING
                # (preserves TIMEOUT/PENDING so the frontend renders correct dot colors)
                "node_ok": {
                    node: WeightedConvergenceEngine._agg_node_status([
                        url_r["node_ok"][node]
                        for url_r in core_checkhost.get("urls", {}).values()
                        if isinstance(url_r, dict) and node in url_r.get("node_ok", {})
                    ])
                    for node in set(
                        n
                        for url_r in core_checkhost.get("urls", {}).values()
                        if isinstance(url_r, dict)
                        for n in url_r.get("node_ok", {}).keys()
                    )
                },
            },
            # Telegram Mirror (v9) — includes channel/URL details
            "telegram_mirror": {
                "has_intent":          telegram_intent,
                "status":              telegram_status,
                "active_channels":     telegram_active_ch,
                "channels_monitored":  core_telegram.get("channels_monitored", []),
                "target_urls":         core_telegram.get("target_urls", []),
                "theater_breakdown":   telegram_data,
                "recent_hits":         TelegramMirrorSensor._intercept_log[:10],
                "last_poll_ts":        TelegramMirrorSensor._last_poll_ts,
                "last_poll_ok":        TelegramMirrorSensor._last_poll_ok,
            },
            # GreyNoise (v9) — includes tier info
            "greynoise": {
                "noise_class":   gn_noise_class,
                "noise_ratio":   gn_noise_ratio,
                "suppressing":   gn_suppress,
                "gnql_tier":     core_greynoise.get("gnql_tier", "none"),
                "theater_data":  {t: greynoise_data.get(t, {}) for t in (strategic_theaters_set or set())},
            },
        }

        score_breakdown = {
            "core_spike_val": round(core_spike, 2), "core_spike_2x": core_spike > 2.0, "core_spike_4x": core_spike > 4.0, "core_spike_6x": core_spike > 6.0,
            "high_correlation": high_correlation, "core_shifted": core_shifted, "major_adversary": major_adversary, "core_degraded": core_degraded,
            "is_coordinated": is_coordinated, "tl1_hard": tl1_hard, "total_score": total_score,
            "convergence_bonus": conv_bonus, "sequence_bonus": seq_bonus, "temporal_bonus": temporal_bonus,
            "score_with_bonus": score_with_bonus, "threat_raw": tl_raw, "threat_held": tl_held,
            "is_c2_sync": is_c2_sync, "is_maskirovka": is_maskirovka,
        }

        # ioda_overlays: extract BGP_OUTAGE countries from full IODA cache (global display)
        ioda_overlays = [
            {"code": code, "lat": COUNTRY_COORDS[code]["lat"], "lng": COUNTRY_COORDS[code]["lng"],
             "name": COUNTRY_COORDS[code]["name"], "status": "BGP_OUTAGE"}
            for code, status in ioda_data.items()
            if status == "BGP_OUTAGE" and code in COUNTRY_COORDS
        ]

        _new_cache = {
            "time": current_time,
            "data": target_details,
            "strategic": {
                "core_theater": core_theater, "threat_level": threat_level, "threat_score": total_score, "threat_breakdown": score_breakdown,
                "correlations": correlations, "correlations_l3": correlations_l3, "correlations_l7": correlations_l7,
                "adversary_strikes": adversary_strikes, "vector_shifts": vector_shifts,
                "degraded_theaters": [t for t in degraded_targets_effective if t in strategic_theaters_set],
                "degraded_theaters_raw": [t for t in degraded_targets_raw if t in strategic_theaters_set],
                "coordinated_theaters": elevated_theaters if is_coordinated else [],
                "domains": {
                    d: {"score": domain_scores.get(d, 0), "weight": engine.DOMAIN_WEIGHTS.get(d, 0), "weighted": round(min(domain_scores.get(d, 0), 10) * engine.DOMAIN_WEIGHTS.get(d, 0), 2), "status": "CRITICAL" if domain_scores.get(d, 0) >= 6 else "ELEVATED" if domain_scores.get(d, 0) >= 3 else "WATCH" if domain_scores.get(d, 0) >= 1 else "NORMAL"} for d in ("cyber", "physical", "info")
                },
                "convergence_score": round(convergence_score, 2), "convergence_level": convergence_level,
                "rationale_matrix": [e.to_dict() for e in rationale], "noise_filters_applied": noise_filters_applied, "system_note": system_note,
                "country_intel": {
                    code: {
                        "weather": weather_conditions.get(code), "airspace": airspace_data.get(code), "gdelt": gdelt_tones.get(code),
                        "bgp_routing": bgp_routing_data.get(code), "ixp_count": ixp_data.get(code, {}).get("count", 0),
                        "ixp_names": [ix["name"] for ix in ixp_data.get(code, {}).get("ixps", [])], "ioda_status": ioda_data.get(code, "NORMAL"),
                        "is_bgp_degraded": code in degraded_targets_effective,
                    } for code in strategic_theaters_set if code in COUNTRY_COORDS
                },
                "map_overlays": {
                    "ioda_outages": ioda_overlays, "airspace_anomaly": airspace_anomalies,
                    "weather_events": [{"code": c, "lat": info.get("lat"), "lng": info.get("lng"), "condition": info.get("condition", ""), "description": info.get("description", ""), "severity": info.get("severity", "NORMAL"), "wind_speed": info.get("wind_speed", 0), "is_severe": info.get("is_severe", False)} for c, info in weather_conditions.items() if info.get("severity") in ("SEVERE", "MODERATE")],
                    "gdelt_events": [{"code": c, "lat": COUNTRY_COORDS[c]["lat"], "lng": COUNTRY_COORDS[c]["lng"], "name": COUNTRY_COORDS[c]["name"], "tone_current": info.get("tone_current"), "tone_baseline": info.get("tone_baseline"), "delta": info.get("delta"), "status": info.get("status", "NORMAL"), "is_alert": info.get("is_alert", False)} for c, info in gdelt_tones.items() if c in COUNTRY_COORDS and info.get("status") in ("ALERT", "WEATHER_NOISE")],
                    "critical_nodes": [{"type": "IXP", "id": ix["id"], "name": ix["name"], "aka": ix.get("aka", ""), "city": ix["city"], "country": c, "lat": ix["lat"], "lng": ix["lng"], "status": ix.get("status", "ok")} for c, cdata in ixp_data.items() for ix in cdata.get("ixps", []) if ix.get("lat") and ix.get("lng")],
                    "firms_anomalies": nasa_firms_data,
                    "chokepoints": (lambda dg_names={g["chokepoint"] for g in ais_dark_gaps}, st_names={s["chokepoint"] for s in ais_stationary}: [
                        {
                            "name":    c["name"],
                            "lat":     c["lat"],
                            "lng":     c["lng"],
                            "country": c["country"],
                            "type":    c.get("type", "cable_landing"),
                            "cables":  c.get("cables", []),
                            "status":  ("dark_gap"   if c["name"] in dg_names else
                                        "stationary" if c["name"] in st_names else
                                        "normal"),
                        }
                        for c in CHOKEPOINTS  # Display all chokepoints (no country filter)
                    ])(),
                    "cable_routes": CABLE_ROUTES,
                    # Additional overlays
                    "isr_hotspots": [
                        {"name": hs["name"], "lat": hs["lat"], "lng": hs["lng"],
                         "theater": hs["theater"],
                         "isr_count": isr_data.get(hs["theater"], {}).get("count", 0),
                         "is_surge": isr_data.get(hs["theater"], {}).get("is_surge", False)}
                        for hs in ISR_HOTSPOTS if hs["theater"] in strategic_theaters_set
                    ],
                    "ais_dark_gaps":  ais_dark_gaps[:10],
                    "ais_stationary": ais_stationary[:10],
                },
                # Deep analysis block
                "analytics": deep_analytics,
            },
        }
        with _global_cache_lock:
            global_cache = _new_cache

        alert_timeline.append({
            "ts": current_time, "threat_level": threat_level, "threat_raw": tl_raw, "threat_held": tl_held, "score": total_score, "score_with_bonus": score_with_bonus,
            "convergence_level": convergence_level, "convergence_bonus": conv_bonus,
            "sequence_bonus": seq_bonus, "sequence_status": seq_status,
            "domain_cyber": round(domain_scores.get("cyber", 0), 2), "domain_physical": round(domain_scores.get("physical", 0), 2), "domain_info": round(domain_scores.get("info", 0), 2),
            "core_theater": core_theater, "degraded_theaters": [t for t in degraded_targets_effective if t in strategic_theaters_set],
            "is_coordinated": is_coordinated, "system_note": system_note,
            "velocity": round(velocity_val, 5), "is_ambush": is_ambush,
            "blockade_index": deep_analytics["blockade_index"],
        })
        # deque(maxlen=ALERT_TIMELINE_MAX) automatically evicts old entries

    results = []
    for t in requested_targets:
        t_info = COUNTRY_COORDS.get(t, {"lat": 0, "lng": 0, "name": t})
        data = global_cache["data"].get(t, {"global_share": 0, "global_share_l3": 0, "global_share_l7": 0, "is_vector_shift": False, "shift_actors": [], "sources": []})
        
        degraded_raw = global_cache["strategic"].get("degraded_theaters_raw", [])
        degraded_eff = global_cache["strategic"].get("degraded_theaters", [])
        
        # Compute velocity and acceleration per target
        ts_series_t = time_series_ts_db.get(t, [])
        t_vel = engine.compute_velocity(ts_series_t)
        t_ambush, t_ambush_z, _, _ = engine.detect_ambush_pattern(ts_series_t)
        results.append({
            "lat": t_info["lat"], "lng": t_info["lng"], "info": t_info["name"], "code": t,
            "global_share": data.get("global_share", 0.0), "global_share_l3": data.get("global_share_l3", 0.0), "global_share_l7": data.get("global_share_l7", 0.0),
            "is_bgp_outage": t in degraded_raw,
            "is_bgp_effective": t in degraded_eff,
            "is_vector_shift": data.get("is_vector_shift", False), "shift_actors": data.get("shift_actors", []),
            "trend_history": time_series_db.get(t, []), "trend_history_l3": time_series_l3_db.get(t, []), "trend_history_l7": time_series_l7_db.get(t, []),
            "sources": data.get("sources", []),
            "velocity": round(t_vel, 5),
            "is_ambush": t_ambush,
            "ambush_z":  t_ambush_z,
        })

    return jsonify({
        "timestamp":       datetime.datetime.now().isoformat(),
        "sensor_health":   registry.health_report(),
        "strategic_alert": global_cache["strategic"],
        "targets":         results,
        "threat_history":  list(threat_history),
    })

@app.route("/api/sensor_config", methods=["GET", "POST"])
def sensor_config():
    if request.method == "GET": return jsonify({"sensors": registry.config_list(), "domain_weights": engine.DOMAIN_WEIGHTS})
    body = request.get_json(silent=True) or {}
    name, enabled = body.get("name", ""), body.get("enabled")
    if not name or enabled is None: return jsonify({"error": "name and enabled are required"}), 400
    if registry.get(name) is None: return jsonify({"error": f"Unknown sensor: {name}"}), 404
    registry.set_enabled(name, bool(enabled))
    return jsonify({"ok": True, "sensor": name, "enabled": registry.get(name).enabled})

@app.route("/api/data_status", methods=["GET"])
def data_status():
    now = time.time(); sensors_status = []
    for s in registry._sensors.values():
        log = s.get_fetch_log()
        sensors_status.append({
            "sensor": s.name, "domain": s.domain, "enabled": s.enabled, "health": s.health,
            "poll_interval_sec": s.poll_interval, "cache_age_sec": round(now - s._cache_time) if s._cache_time else None,
            "cache_size_chars": len(str(s._cache)), "last_error": s._last_error, "last_fetch": log[-1] if log else None, "fetch_log": log,
        })
    return jsonify({"ts": datetime.datetime.now().isoformat(), "sensors": sensors_status})

@app.route("/api/alert_timeline", methods=["GET"])
def api_alert_timeline():
    limit = min(int(request.args.get("limit", 288)), 288)
    return jsonify({"ts": datetime.datetime.now().isoformat(), "count": len(alert_timeline), "timeline": list(alert_timeline)[-limit:]})

@app.route("/api/telegram_log/clear", methods=["POST"])
def api_telegram_log_clear():
    """Clear the Telegram SIGINT intercept log."""
    TelegramMirrorSensor._intercept_log.clear()
    return jsonify({"ok": True, "ts": datetime.datetime.now(datetime.timezone.utc).isoformat()})

@app.route("/api/sitrep", methods=["GET"])
def api_sitrep():
    now_ts = datetime.datetime.now(datetime.timezone.utc)
    if not alert_timeline: 
        return jsonify({"ts": now_ts.isoformat(), "text": "No data available yet.", "summary": {}})
    
    _tl = list(alert_timeline)
    recent, latest, oldest = _tl[-12:], _tl[-1], _tl[0]
    span_min = round((latest["ts"] - oldest["ts"]) / 60) if len(alert_timeline) > 1 else 0
    levels = [e["threat_level"] for e in recent]
    min_d, max_d, avg_d = min(levels), max(levels), round(sum(levels) / len(levels), 1)
    
    conv_counts = {}
    for e in recent:
        lv = e.get("convergence_level", "NONE")
        conv_counts[lv] = conv_counts.get(lv, 0) + 1
    dominant_conv = max(conv_counts, key=lambda k: conv_counts[k])
    
    active_domains = []
    if latest.get("domain_cyber", 0) > 0: active_domains.append("CYBER")
    if latest.get("domain_physical", 0) > 0: active_domains.append("PHYSICAL")
    if latest.get("domain_info", 0) > 0: active_domains.append("INFO")
    
    trend = "INSUFFICIENT DATA"
    if len(levels) >= 3:
        trend_val = latest["threat_level"] - levels[0]
        trend = "ESCALATING" if trend_val < 0 else "DE-ESCALATING" if trend_val > 0 else "STABLE"

    core = latest.get("core_theater") or "UNKNOWN"
    note = latest.get("system_note", "")
    
    text_lines = [
        "UNCLASSIFIED // FOR OFFICIAL USE ONLY",
        "TACTICAL SITUATION REPORT (SITREP)",
        f"DTG: {now_ts.strftime('%d%H%MZ %b %Y').upper()}",
        "--------------------------------------------------",
        "1. OVERALL ASSESSMENT",
        f"   CURRENT THREAT LEVEL : LEVEL {latest['threat_level']} [{trend}]",
        f"   PRIMARY THEATER      : {core}",
        f"   CONVERGENCE STATE    : {dominant_conv.replace('_', ' ')}",
        f"   OBSERVATION WINDOW   : {span_min} MIN / {len(alert_timeline)} CYCLES",
        "",
        "2. DOMAIN ACTIVITY (LAST 1H)",
        f"   THREAT RANGE         : LV {min_d} - LV {max_d} (AVG: {avg_d})",
        f"   ACTIVE DOMAINS       : {', '.join(active_domains) if active_domains else 'NONE'}",
    ]
    
    degraded = latest.get("degraded_theaters", [])
    if degraded: 
        text_lines += [f"   CRITICAL OUTAGES     : {', '.join(degraded)}"]
    
    if latest.get("is_coordinated"): 
        text_lines += ["   WARNING              : COORDINATED MULTI-FRONT ACTIVITY DETECTED"]

    text_lines += [
        "",
        "3. SYSTEM RATIONALE & ANALYST NOTE",
        f"   {note}" if note else "   NO ADDITIONAL RATIONALE PROVIDED.",
        "",
        "4. RECOMMENDATION",
        "   System assessment is probabilistic. Human-in-the-loop (HITL) verification required.",
        "--------------------------------------------------"
    ]

    return jsonify({
        "ts": now_ts.isoformat(), 
        "text": "\n".join(text_lines),
        "summary": {
            "threat_current": latest["threat_level"],
            "threat_trend": trend, 
            "threat_min_1h": min_d,
            "threat_max_1h": max_d,
            "threat_avg_1h": avg_d, 
            "convergence": dominant_conv, 
            "active_domains": active_domains, 
            "core_theater": core, 
            "span_minutes": span_min, 
            "cycle_count": len(alert_timeline)
        },
    })

# ─────────────────────────────────────────────────────────────────────────────
# ── Advanced Analytics Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/sequence_chain", methods=["GET"])
def api_sequence_chain():
    """
    Return escalation chain status for all theaters.
    Query parameter: ?theater=TW (omit for all theaters)
    """
    theater_param = request.args.get("theater", "").upper()
    now = time.time()
    result = {}
    theaters = [theater_param] if theater_param else list(sequence_event_log.keys())
    for th in theaters:
        bonus, status, chain = compute_sequence_bonus(th)
        cutoff = now - SEQUENCE_WINDOW
        events = [e for e in sequence_event_log.get(th, []) if e["ts"] >= cutoff]
        result[th] = {
            "sequence_bonus":  bonus,
            "chain_status":    status,
            "chain_found":     chain,
            "events":          [
                {"ts": e["ts"], "dt": datetime.datetime.fromtimestamp(e["ts"]).isoformat(),
                 "type": e["type"], "meta": e["meta"]}
                for e in sorted(events, key=lambda x: x["ts"])
            ],
            "window_hours": SEQUENCE_WINDOW // 3600,
        }
    return jsonify({"ts": datetime.datetime.now().isoformat(), "chains": result})


@app.route("/api/deep_analytics", methods=["GET"])
def api_deep_analytics():
    """
    Detailed endpoint for deep analysis results.
    Returns velocity/acceleration/ambush/narrative/ISR/AIS/blockade_index.
    """
    theater_param = request.args.get("theater", DEFAULT_CORE).upper()
    ts_series = time_series_ts_db.get(theater_param, [])
    velocity   = engine.compute_velocity(ts_series)
    acc        = engine.compute_acceleration(ts_series)
    is_ambush, ambush_z, _, _ = engine.detect_ambush_pattern(ts_series)
    seq_bonus, seq_status, seq_chain = compute_sequence_bonus(theater_param)

    narrative_sensor = registry.get("rss_narrative")
    narrative_info   = narrative_sensor.get_cache().get("narratives", {}).get(theater_param, {}) if narrative_sensor else {}
    isr_sensor       = registry.get("isr_hotspot")
    isr_info         = isr_sensor.get_cache().get("isr_data", {}).get(theater_param, {}) if isr_sensor else {}
    ais_sensor       = registry.get("ais_maritime")
    ais_gaps         = ais_sensor.get_cache().get("dark_gaps", []) if ais_sensor else []
    ais_stat         = ais_sensor.get_cache().get("stationary_anomalies", []) if ais_sensor else []

    # Blockade Index v9: (DDoS intensity × RIPE delay) / Check-Host success rate
    strategic    = global_cache.get("strategic", {})
    analytics_v9 = strategic.get("analytics", {})
    core_spike_v = strategic.get("threat_breakdown", {}).get("core_spike_val", 0.0)
    is_degraded  = theater_param in strategic.get("degraded_theaters", [])
    # Use v9 blockade_index from cache if available, otherwise recompute with compute_blockade_index
    if "blockade_index" in analytics_v9:
        blockade_idx = analytics_v9["blockade_index"]
    else:
        bgp_s   = registry.get("ripe_bgp")
        ch_s    = registry.get("check_host")
        ripe_drop = bgp_s.get_cache().get("routing_stats", {}).get(theater_param, {}).get("drop_pct", 0.0) if bgp_s else 0.0
        ch_rate   = ch_s.get_cache().get("check_host", {}).get(theater_param, {}).get("theater_success_rate") if ch_s else None
        blockade_idx = engine.compute_blockade_index(core_spike_v, ripe_drop, ch_rate)

    # Velocity trend (format time series for response)
    velocity_series = []
    for i in range(1, len(ts_series)):
        dt = ts_series[i][0] - ts_series[i-1][0]
        if dt > 0:
            v = (ts_series[i][1] - ts_series[i-1][1]) / dt
            velocity_series.append({
                "ts": ts_series[i][0],
                "dt": datetime.datetime.fromtimestamp(ts_series[i][0]).isoformat(),
                "velocity": round(v, 6),
                "spike_val": ts_series[i][1],
            })

    return jsonify({
        "ts": datetime.datetime.now().isoformat(),
        "theater": theater_param,
        "acceleration_engine": {
            "velocity":      round(velocity, 6),
            "acceleration":  round(acc, 8),
            "is_ambush":     is_ambush,
            "ambush_z_score": ambush_z,
            "velocity_series": velocity_series[-20:],
        },
        "sequence_scorer": {
            "bonus":  seq_bonus,
            "status": seq_status,
            "chain":  seq_chain,
            "events": [
                {"ts": e["ts"], "dt": datetime.datetime.fromtimestamp(e["ts"]).isoformat(),
                 "type": e["type"]}
                for e in sorted(sequence_event_log.get(theater_param, []), key=lambda x: x["ts"])
            ],
        },
        "narrative_burst": {
            "z_score":         narrative_info.get("z_score", 0.0),
            "status":          narrative_info.get("status", "NO_DATA"),
            "is_burst":        narrative_info.get("is_burst", False),
            "normalized_freq": narrative_info.get("normalized_freq", 0.0),
            "baseline_mean":   narrative_info.get("baseline_mean", 0.0),
            "baseline_std":    narrative_info.get("baseline_std", 0.0),
            "keyword_hits":    narrative_info.get("keyword_hits", 0),
            "article_count":   narrative_info.get("article_count", 0),
        },
        "isr_hotspot": {
            "count":    isr_info.get("count", 0),
            "is_surge": isr_info.get("is_surge", False),
            "hotspots": isr_info.get("hotspots", []),
        },
        "ais_maritime": {
            "dark_gaps":   ais_gaps[:5],
            "stationary":  ais_stat[:5],
            "has_anomaly": bool(ais_gaps or ais_stat),
        },
        "blockade_index": {
            "value":       blockade_idx,
            "ddos_spike":  core_spike_v,
            "is_degraded": is_degraded,
            "interpretation": (
                "INFRASTRUCTURE_NEUTRALIZATION" if blockade_idx >= 7.0 else
                "SEVERE_DISRUPTION"             if blockade_idx >= 4.0 else
                "POLITICAL_NOISE"               if blockade_idx >= 1.5 else
                "NORMAL"
            ),
        },
    })


@app.route("/api/salute_report", methods=["GET"])
def api_salute_report():
    """
    Generate the current threat situation as a SALUTE format (Size/Activity/Location/Unit/Time/Equipment)
    contact report. Activates the analyst's trained cognitive mode.
    """
    strat = global_cache.get("strategic", {})
    p8    = strat.get("analytics", {})
    now_ts = datetime.datetime.now(datetime.timezone.utc)
    dtg = now_ts.strftime("%d%H%MZ %b %Y").upper()
    threat_level = strat.get("threat_level", 5)
    core   = strat.get("core_theater", "UNKNOWN")
    bd     = strat.get("threat_breakdown", {})
    adv_raw = strat.get("adversary_strikes", [])
    adv     = list(dict.fromkeys(a.get("actor", str(a)) if isinstance(a, dict) else str(a) for a in adv_raw))
    corr   = strat.get("correlations", {})
    isr    = p8.get("isr", {})
    ais    = p8.get("ais", {})
    narr   = p8.get("narrative", {})
    bi     = p8.get("blockade_index", 0.0)
    seq    = p8.get("sequence_status", "NO_EVENTS")

    # SIZE: actors and scale involved
    size_parts = []
    if adv:          size_parts.append(f"ADVERSARY STATES: {', '.join(adv)}")
    if corr:         size_parts.append(f"CORRELATED THEATERS: {len(corr)}")
    if isr.get("count", 0): size_parts.append(f"ISR AIRCRAFT: {isr['count']}")
    size = "; ".join(size_parts) if size_parts else "UNKNOWN — ASSESSMENT IN PROGRESS"

    # ACTIVITY: observed activity
    acts = []
    if bd.get("core_spike_val", 0) > 2:
        layer = "L7 APPLICATION" if bd.get("core_shifted") else "L3 VOLUMETRIC"
        acts.append(f"DDoS {bd['core_spike_val']:.1f}x SPIKE ({layer})")
    if bd.get("is_coordinated"):  acts.append("COORDINATED MULTI-FRONT ACTIVITY")
    if isr.get("is_surge"):       acts.append("ISR SURGE CONFIRMED")
    if ais.get("dark_gaps", 0):   acts.append(f"AIS DARK GAP x{ais['dark_gaps']} AT CHOKEPOINTS")
    if narr.get("is_burst"):      acts.append(f"NARRATIVE BURST Z={narr.get('z_score',0):.1f}")
    if p8.get("is_ambush"):       acts.append(f"AMBUSH PATTERN (Z={p8.get('ambush_z_score',0):.1f})")
    activity = "; ".join(acts) if acts else "ROUTINE — NO SIGNIFICANT ACTIVITY"

    # LOCATION: primary threat location
    degraded = strat.get("degraded_theaters", [])
    loc_parts = [f"PRIMARY: {core}"]
    if degraded: loc_parts.append(f"DEGRADED: {', '.join(degraded)}")
    location = " / ".join(loc_parts)

    # UNIT: attribution assessment
    if adv and bd.get("major_adversary"):
        unit = f"STATE-ATTRIBUTED — {', '.join(adv)} STATE ASN CONFIRMED"
    elif bd.get("is_coordinated"):
        unit = "COORDINATED — PROBABLE STATE C2 (UNKNOWN ATTRIBUTION)"
    else:
        unit = "UNKNOWN — ATTRIBUTION ASSESSMENT PENDING"

    # EQUIPMENT: attack vectors and tools used
    equip_parts = []
    if bd.get("core_shifted"):     equip_parts.append("L7 HTTP FLOOD (DECISION-PARALYSIS TYPE)")
    elif bd.get("core_spike_val", 0) > 2: equip_parts.append("L3 BANDWIDTH EXHAUSTION (BLINDING TYPE)")
    if bd.get("tl1_hard"):         equip_parts.append("INFRASTRUCTURE NEUTRALIZATION CAPABILITY")
    if isr.get("is_surge"):        equip_parts.append("ISR PLATFORM DEPLOYMENT")
    if ais.get("dark_gaps", 0):    equip_parts.append("COVERT MARITIME ELEMENT")
    equip = "; ".join(equip_parts) if equip_parts else "STANDARD CYBER TOOLS"

    # ASSESSMENT
    sig_map = {1: "CRITICAL", 2: "HIGH", 3: "SIGNIFICANT", 4: "MODERATE", 5: "ROUTINE"}
    significance = sig_map.get(threat_level, "UNKNOWN")

    bi_interp = (
        "INFRASTRUCTURE_NEUTRALIZATION" if bi >= 7.0 else
        "SEVERE_DISRUPTION"             if bi >= 4.0 else
        "POLITICAL_NOISE"               if bi >= 1.5 else "NORMAL"
    )

    report = {
        "dtg":          dtg,
        "size":         size,
        "activity":     activity,
        "location":     location,
        "unit":         unit,
        "time":         dtg,
        "equipment":    equip,
        "assessment":   significance,
        "threat_level": threat_level,
        "blockade_interpretation": bi_interp,
        "blockade_index": bi,
        "sequence_status": seq,
        "cross_ref": (
            f"SEQ CHAIN: {seq}" if seq not in ("NO_EVENTS", "INSUFFICIENT_CHAIN (0/4)") else "NO ACTIVE SEQUENCE CHAIN"
        ),
    }
    return jsonify({"ts": now_ts.isoformat(), "report": report})


@app.route("/api/weather_brief", methods=["GET"])
def api_weather_brief():
    """
    Convert current sensor data to an "Operational Weather Brief" format and return it.
    Uses meteorological terminology to intuitively represent the threat environment.
    """
    strat = global_cache.get("strategic", {})
    p8    = strat.get("analytics", {})
    bd    = strat.get("threat_breakdown", {})
    isr   = p8.get("isr", {})
    ais   = p8.get("ais", {})
    narr  = p8.get("narrative", {})
    bi    = p8.get("blockade_index", 0.0)
    vel   = p8.get("velocity", 0.0)
    is_ambush = p8.get("is_ambush", False)

    # CYBER ATMOSPHERE
    spike = bd.get("core_spike_val", 0.0)
    if is_ambush:
        cyber_state = "RAPID INTENSIFICATION"
        cyber_desc  = f"Exponential escalation detected. Eye-wall forming. Barometric pressure dropping at {vel*900:.2f}pt/cycle."
    elif spike > 6:
        cyber_state = "MAJOR STORM"
        cyber_desc  = f"Category {min(int(spike/2),5)} cyber storm. {spike:.1f}x baseline. L{'7' if bd.get('core_shifted') else '3'} dominant vector."
    elif spike > 3:
        cyber_state = "ACTIVE STORM FRONT"
        cyber_desc  = f"Significant disturbance. {spike:.1f}x baseline. Deepening conditions expected."
    elif spike > 1:
        cyber_state = "ELEVATED SWELL"
        cyber_desc  = f"Choppy seas. {spike:.1f}x baseline. Monitor for front development."
    else:
        cyber_state = "CLEAR"
        cyber_desc  = "Calm conditions. Background noise only. Visibility good."

    # MARITIME ENVIRONMENT (AIS)
    if ais.get("dark_gaps", 0) > 2:
        mar_state = "ZERO VISIBILITY — DENSE FOG"
        mar_desc  = f"{ais['dark_gaps']} vessels gone dark near critical chokepoints. Radio silence indicates covert posture."
    elif ais.get("dark_gaps", 0) > 0:
        mar_state = "REDUCED VISIBILITY — PATCHY FOG"
        mar_desc  = f"{ais['dark_gaps']} AIS Dark Gap(s) detected. Recommend continuous monitoring."
    elif ais.get("stationary", 0) > 0:
        mar_state = "RESTRICTED WATERS — OBSTACLE"
        mar_desc  = f"{ais['stationary']} non-commercial vessel(s) anchored near chokepoint. Anomalous."
    else:
        mar_state = "CLEAR PASSAGE"
        mar_desc  = "Normal maritime traffic. No AIS anomalies detected."

    # INFORMATION ENVIRONMENT (Narrative)
    nz = narr.get("z_score", 0.0)
    ns = narr.get("status", "NORMAL")
    if ns == "CRITICAL_BURST":
        info_state = "INFORMATION STORM — HURRICANE FORCE"
        info_desc  = f"Z={nz:.1f}. Tactical keyword saturation. Propaganda machine in overdrive. Pre-operation information preparation detected."
    elif ns == "BURST":
        info_state = "ELEVATED PRESSURE — BUILDING STORM"
        info_desc  = f"Z={nz:.1f}. Unusual keyword spike in state media. Storm front approaching."
    else:
        info_state = "STEADY STATE"
        info_desc  = f"Z={nz:.1f}. Background propaganda within normal parameters. No significant front detected."

    # AIR PICTURE (ISR)
    if isr.get("is_surge"):
        air_state = "ACTIVE — FULL ISR DEPLOYMENT"
        air_desc  = f"{isr.get('count',0)} ISR aircraft confirmed at strategic hotspot(s). Pre-strike reconnaissance posture."
    elif isr.get("count", 0) > 0:
        air_state = "OBSERVED — ROUTINE ISR PATTERN"
        air_desc  = f"{isr.get('count',0)} ISR aircraft observed. Normal patrol frequency."
    else:
        air_state = "CLEAR SKIES"
        air_desc  = "No ISR concentration detected at monitored hotspots."

    # BLOCKADE (Infrastructure pressure)
    if bi >= 7:
        infra_state = "CATASTROPHIC — INFRASTRUCTURE COLLAPSE"
        infra_desc  = f"Index {bi:.1f}. Combined DDoS and BGP withdrawal. Blackout conditions. Invasion precursor signature."
    elif bi >= 4:
        infra_state = "SEVERE — SUSTAINED PRESSURE"
        infra_desc  = f"Index {bi:.1f}. Significant infrastructure degradation concurrent with cyber activity."
    elif bi >= 1.5:
        infra_state = "ELEVATED — POLITICAL NOISE LEVEL"
        infra_desc  = f"Index {bi:.1f}. Cyber activity without confirmed infrastructure impact. Signaling operation likely."
    else:
        infra_state = "NOMINAL"
        infra_desc  = f"Index {bi:.1f}. Infrastructure stable. No disruption confirmed."

    return jsonify({
        "ts": datetime.datetime.now().isoformat(),
        "brief": {
            "cyber":    {"state": cyber_state,  "detail": cyber_desc},
            "maritime": {"state": mar_state,    "detail": mar_desc},
            "info":     {"state": info_state,   "detail": info_desc},
            "air":      {"state": air_state,    "detail": air_desc},
            "infra":    {"state": infra_state,  "detail": infra_desc},
        }
    })


@app.route("/api/historical_events", methods=["GET"])
def api_historical_events():
    """Return the HISTORICAL_EVENTS pattern library."""
    return jsonify({"events": HISTORICAL_EVENTS})


@app.route("/api/ip_check", methods=["GET"])
def api_ip_check():
    """Look up IP address noise/classification info via GreyNoise Community API.

    Query params:
        ip (str, required): IPv4 address to investigate

    Response:
        {
          "ip":             "1.2.3.4",
          "noise":          false,         // true = internet background noise (mass scanners etc.)
          "riot":           false,         // true = legitimate infrastructure (Google, Cloudflare etc.)
          "classification": "malicious",   // malicious / benign / unknown
          "name":           "Mirai Botnet",
          "last_seen":      "2026-03-13",
          "message":        "...",
          "cached":         false,         // true = cache hit (no API quota consumed)
          "fetched_at":     1234567890.0,
          "daily_remaining": 47,           // remaining requests today
          "error":          null
        }

    Note:
        Community API: 50 req/day. Same IP cached for 24h without consuming quota.
        Uses Community endpoint even with Enterprise key (separate from GNQL Stats).
    """
    ip = request.args.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip parameter required. Example: /api/ip_check?ip=1.2.3.4"}), 400

    gn_sensor = registry.get("greynoise")
    if not gn_sensor:
        return jsonify({"error": "GreyNoiseSensor is not initialized"}), 503

    result = gn_sensor.lookup_community_ip(ip)

    if result.get("error") and "limit" not in result["error"] and "Invalid" not in result["error"]:
        return jsonify(result), 502
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
# Background cleanup thread
# Removes old entries from global caches every hour to prevent memory leaks in long-running processes.
# ─────────────────────────────────────────────────────────────────────────────
def _cache_cleanup_worker():
    """Daemon thread: removes expired cache entries from all caches every hour."""
    CLEANUP_INTERVAL = 3600  # 1 hour
    BASELINE_MAX_AGE = 86400 * 7   # baseline expires after 7 days
    SEQ_LOG_WINDOW   = SEQUENCE_WINDOW  # 24h
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            now = time.time()
            # baseline_cache: remove theaters not updated for 7+ days
            stale = [k for k, v in list(baseline_cache.items()) if now - v.get("time", 0) > BASELINE_MAX_AGE]
            for k in stale:
                baseline_cache.pop(k, None)

            # sequence_event_log: re-trim entries older than 24h per theater and remove empty theaters
            cutoff = now - SEQ_LOG_WINDOW
            for th in list(sequence_event_log.keys()):
                sequence_event_log[th] = [e for e in sequence_event_log[th] if e["ts"] >= cutoff]
                if not sequence_event_log[th]:
                    del sequence_event_log[th]

            # _cf_scoring_cache / _asn_cache: sweep all expired entries as a precaution
            for k in [k for k, v in list(_cf_scoring_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _cf_scoring_cache.pop(k, None)
            for k in [k for k, v in list(_asn_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _asn_cache.pop(k, None)

            # greynoise _ip_cache: remove entries older than 24h
            gn = registry.get("greynoise")
            if gn:
                with gn._ip_lock:
                    stale_ips = [k for k, v in list(gn._ip_cache.items())
                                 if now - v["fetched_at"] > gn.IP_CACHE_TTL]
                    for k in stale_ips:
                        gn._ip_cache.pop(k, None)

            print(f"[Cleanup] baseline_cache={len(baseline_cache)} seqlog={len(sequence_event_log)} "
                  f"cf_cache={len(_cf_scoring_cache)} asn_cache={len(_asn_cache)}")
        except Exception as e:
            print(f"[Cleanup] Error: {e}")

_cleanup_thread = threading.Thread(target=_cache_cleanup_worker, daemon=True, name="cache-cleanup")
_cleanup_thread.start()

if __name__ == "__main__":
    # use_reloader=False: Flask's stat reloader spawns two processes (file watcher + actual worker),
    # causing module-level initialization code (sensor thread startup, OAuth2 token fetch etc.)
    # to run twice.
    # use_reloader=False forces single-process mode and prevents duplicate logs.
    # Debug features (detailed error display, code reload) remain active.
    app.run(host="127.0.0.1", port=8000, debug=True, use_reloader=False)