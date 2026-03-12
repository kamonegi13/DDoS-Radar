# radar_api.py — MDO C4ISR Dashboard — Predictive Deep Pattern Analysis
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
ISR_HOTSPOTS: list = []
NARRATIVE_SOURCES: dict = {}
TACTICAL_KEYWORDS: dict = {}
HISTORICAL_EVENTS: list = []
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
SCORE_REFRESH_SEC          = int(os.getenv("SCORE_REFRESH_SEC", "60"))   # スコアリング計算の最短間隔 (秒)

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
        targets = context.get("all_targets", []); headers = context.get("cf_headers", {})
        results = {}
        t0 = time.time(); total_anomalies = 0; any_success = False; last_status = 0; last_error = ""
        # 1回のリクエストで全国を取得 (location 指定なし → グローバル結果から国別にフィルタ)
        url = "https://api.cloudflare.com/client/v4/radar/traffic_anomalies"
        params = {"dateRange": "1d", "format": "json"}
        try:
            res = requests.get(url, headers=headers, params=params, timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            last_status = res.status_code
            if res.status_code == 200:
                anomalies = res.json().get("result", {}).get("trafficAnomalies", [])
                # 国別に仕分け
                affected = {a.get("locationAlpha2", "").upper() for a in anomalies if a.get("locationAlpha2")}
                for code in targets:
                    results[code] = "BGP_OUTAGE" if code in affected else "NORMAL"
                total_anomalies = len(anomalies); any_success = True
            else:
                for code in targets:
                    results[code] = "NORMAL"
        except Exception as e:
            for code in targets:
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
                duration = round((time.time() - t0) * 1000)  # L3+L7 両リクエスト完了後に再計測
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
    def __init__(self): super().__init__("opensky", "physical", 600)
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", []); results: dict = {}; delta = 0.5
        t0 = time.time(); total_states = 0; any_success = False; last_status = 0; last_error = ""
        for code in theaters:
            box = AIRPORT_BOXES.get(code)
            if not box: continue
            lat, lng = box["lat"], box["lng"]
            params = {"lamin": lat - delta, "lamax": lat + delta, "lomin": lng - delta, "lomax": lng + delta}
            try:
                res = requests.get("https://opensky-network.org/api/states/all", params=params, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
                last_status = res.status_code
                if res.status_code == 200:
                    count = len(res.json().get("states") or [])
                    results[code] = {"airport": box["airport"], "count": count, "lat": lat, "lng": lng, "error": None}
                    total_states += count; any_success = True
                else:
                    results[code] = {"airport": box["airport"], "count": -1, "lat": lat, "lng": lng, "error": f"http_{res.status_code}"}
            except Exception as e:
                results[code] = {"airport": box.get("airport", code), "count": -1, "lat": lat, "lng": lng, "error": str(e)}
                last_error = str(e)
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_states, last_error)
        result = {"airports": results}; self.set_cache(result)
        return result

class OpenWeatherSensor(BaseSensor):
    def __init__(self): super().__init__("openweather", "physical", 1800)
    def fetch(self, context: dict) -> dict:
        targets = context.get("all_targets", []); api_key = context.get("owm_api_key", "")
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
                time.sleep(10)  # PeeringDB レート制限対策 (10s/request)
            try:
                res = _fetch_peeringdb(code)
                last_status = res.status_code
                if res.status_code == 429:
                    # 429 → 60秒待機して1回リトライ
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
            if not query: continue
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
    """NASA FIRMS → NASA EONET Wildfires API に切替（FIRMSサーバー到達不可のため）
    APIキー不要。eonet.gsfc.nasa.gov は企業プロキシ環境でも疎通確認済み。
    """
    EONET_URL = "https://eonet.gsfc.nasa.gov/api/v3/events"
    # 対象シアターに近いイベントか判定する許容距離（度）
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

                # 各シアターの座標と距離比較して近傍イベントを抽出
                for code in theaters:
                    coord = COUNTRY_COORDS.get(code)
                    if not coord: continue
                    tlat, tlng = coord["lat"], coord["lng"]

                    for ev in events:
                        for geo in (ev.get("geometry") or []):
                            coords = geo.get("coordinates")
                            if not coords: continue
                            # EONET座標は [lng, lat] 形式
                            elng, elat = coords[0], coords[1]
                            if (abs(elat - tlat) <= self.GEO_RADIUS_DEG and
                                    abs(elng - tlng) <= self.GEO_RADIUS_DEG):
                                anomalies.append({
                                    "lat": elat, "lng": elng,
                                    "code": code, "confidence": "HIGH",
                                    "title": ev.get("title", "Wildfire")
                                })
                                break  # 同イベントを同シアターに重複登録しない
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

        # abuse.ch は get_iocs にも Auth-Key を要求するようになった（2024年以降）
        tf_api_key = os.getenv("THREATFOX_API_KEY", "")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        if tf_api_key:
            headers["Auth-Key"] = tf_api_key

        if HTTP_PROXY:
            headers["Connection"] = "Keep-Alive"

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
                        # APTタグ、または対象国名に関連するIoCをカウント
                        count = sum(1 for ioc in iocs if (ioc.get("tags") and any("apt" in str(tag).lower() or country_name in str(tag).lower() for tag in ioc["tags"])))
                        if count > 0: hits[code] = {"count": count, "description": f"{count} APT/State-linked IoCs detected"}
                    self.log_fetch(True, duration, res.status_code, len(iocs))
                else:
                    err_msg = data.get("query_status", "Unknown error")
                    self.log_fetch(False, duration, res.status_code, 0, f"API Error: {err_msg}")
                    self.set_error(f"API Error: {err_msg}")
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
    TASS / Xinhua / Mehr News 等の RSS フィードを取得し、戦術キーワードの
    出現頻度を Z-Score 分析して「ナラティブバースト」を検出する。
    30日間のベースライン（日次正規化頻度）との比較で日常プロパガンダを排除し、
    統計的に有意なスパイクのみをアラートする。
    """
    def __init__(self):
        super().__init__("rss_narrative", "info", 1800)
        self._baseline: dict = {}   # {theater: {"daily_counts": [float,...], "last_updated": float}}
        self._lock = threading.Lock()

    @staticmethod
    def _fetch_rss_text(url: str) -> str:
        """RSS フィードを取得してテキストを返す。失敗時は空文字列。"""
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
        RSS XML を解析して対象キーワードの出現数と記事数を返す。
        重複記事は difflib で除外する。
        Returns: (keyword_hits: int, article_count: int)
        """
        if not xml_text:
            return 0, 0
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return 0, 0

        # 重複判定: タイトル先頭60文字の正規化ハッシュを set で管理 (O(N) vs O(N²))
        titles_seen: set = set()
        keyword_hits, article_count = 0, 0
        keywords_lower = [k.lower() for k in keywords]

        for item in root.iter("item"):
            title_el = item.find("title")
            desc_el  = item.find("description")
            title = (title_el.text or "").strip() if title_el is not None else ""
            desc  = (desc_el.text  or "").strip() if desc_el  is not None else ""
            text  = (title + " " + desc).lower()

            # 先頭60文字の正規化キーで重複を検出（SequenceMatcherのO(N²)を排除）
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
        30日間のベースラインに対する Z-Score を計算する。
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
        """ベースライン日次リストを更新する（最大 NARRATIVE_BASELINE_DAYS 日分保持）。"""
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

            # 記事総数で正規化（0除算防止）
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
    OpenSky Network の states/all API を使用して ISR_HOTSPOTS 周辺 200km 圏内の
    軍用・偵察機の密度を計測する。既存 OpenSkySensor（民間空港監視）とは独立して動作。
    高高度（>9000m）かつ低速（<160 m/s）の航空機を ISR パターンとして識別する。
    """
    # 200km ≈ 1.8° (緯度方向)
    RADIUS_DEG = 1.8

    def __init__(self):
        super().__init__("isr_hotspot", "physical", 600)

    def fetch(self, context: dict) -> dict:
        theaters = set(context.get("strategic_theaters", []))
        results: dict = {}
        t0 = time.time()

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
                res = requests.get(
                    "https://opensky-network.org/api/states/all",
                    params=params, timeout=10,
                    proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
                )
                duration = round((time.time() - t0) * 1000)
                if res.status_code == 200:
                    states = res.json().get("states") or []
                    # ISR 特性フィルター: 高高度 (>9000m) + 低速 (<160 m/s)
                    # または squawk=7777 (政府/軍用コード)
                    isr_count = 0
                    isr_tracks = []
                    for s in states:
                        # states フィールド: [icao24, callsign, origin, time_pos, last, lon, lat, baro_alt, on_ground, vel, track, vrate, ...]
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
                        "tracks":    isr_tracks[:5],  # 最大5機分のメタデータ
                    })
                    results[theater] = existing
                    self.log_fetch(True, duration, res.status_code, isr_count)
                else:
                    self.log_fetch(False, duration, res.status_code, 0, f"HTTP {res.status_code}")
            except Exception as e:
                self.log_fetch(False, round((time.time() - t0) * 1000), 0, 0, str(e))

        # ISR サージ判定
        for theater, data in results.items():
            data["is_surge"] = data["count"] >= ISR_SURGE_THRESHOLD

        result = {"isr_data": results}
        self.set_cache(result)
        return result


class AisMaritimeSensor(BaseSensor):
    """
    公開 AIS データを使用して CHOKEPOINTS 付近の海上異常を検出する。
    - AIS Dark Gap: 一定時間以上 AIS 送信が途絶えた艦船（電波封止の可能性）
    - Stationary Anomaly: 非貨物・非漁業艦船がチョークポイント付近に長時間停泊

    主要 API: AISHub の公開ストリーム (data.aishub.net)
    認証不要エンドポイント / レート制限あり (60秒/リクエスト)
    フォールバック: MarineTraffic 公開データ（利用可能な場合）
    """
    AISHUB_URL = "http://data.aishub.net/ws.php"
    # 非商業・非漁業の艦船タイプ (AIS Ship Type codes)
    # 30-35: Fishing, 60-69: Passenger, 70-79: Cargo, 80-89: Tanker
    # 35,36,37: Military, Naval, law enforcement
    MILITARY_SHIP_TYPES = {35, 36, 37}
    COMMERCIAL_TYPES    = set(range(60, 90))

    def __init__(self):
        super().__init__("ais_maritime", "physical", 1800)
        self._vessel_history: dict = {}  # {mmsi: {"last_ts": float, "lat": float, "lng": float}}

    @staticmethod
    def _haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
        """2点間の距離（km）をハーバーサイン公式で計算する。"""
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
            # AISHub から当該チョークポイント周辺の艦船を取得
            # ゲストAPIは連続リクエストにレート制限があるため、リクエスト間に待機を挿入
            if cp_success + cp_errors > 0:
                time.sleep(2)   # AISHub ゲスト API レート制限への配慮 (2s/request)
            params = {
                "username":  "guest",  # AISHub ゲストアクセス
                "format":    "1",      # JSON 形式
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
                    # AISHub ゲストAPI: レート制限時は HTTP 200 + 空ボディを返す
                    # エラーではなく「データなし」として扱い次のCPへ
                    continue
                try:
                    vessels_raw = res.json()
                except ValueError:
                    # 空でないが JSON でない場合 (HTML エラーページ等) → スキップ
                    continue
                # AISHub レスポンス: [[header], [vessel,...], ...]
                if not isinstance(vessels_raw, list) or len(vessels_raw) < 2:
                    continue  # 周辺に艦船なし (正常)
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
                ship_type = int(vessel.get("SHIPTYPE", 0) or 0)
                speed     = float(vessel.get("SOG", 0) or 0)    # Speed Over Ground (knots)
                lat       = float(vessel.get("LATITUDE", 0) or 0)
                lng       = float(vessel.get("LONGITUDE", 0) or 0)
                last_ts   = float(vessel.get("TIME", now) or now)
                name      = vessel.get("NAME", "UNKNOWN")

                dist_km = self._haversine_km(cp_lat, cp_lng, lat, lng)

                # AIS Dark Gap 検出: 前回記録から AIS_DARK_GAP_THRESHOLD 秒以上途絶
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

                # 停泊異常: 非商業・速度<0.5ノット・チョークポイント50km圏内
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

                # 艦船履歴を更新
                self._vessel_history[mmsi] = {"last_ts": last_ts, "lat": lat, "lng": lng}

        # 24時間以上前の艦船履歴を削除（メモリリーク対策）
        cutoff_ts = now - 86400
        stale_mmsi = [m for m, v in self._vessel_history.items() if v["last_ts"] < cutoff_ts]
        for m in stale_mmsi:
            del self._vessel_history[m]
        # 上限超過時は最古エントリから削除（最大5000隻）
        if len(self._vessel_history) > 5000:
            sorted_mmsi = sorted(self._vessel_history, key=lambda m: self._vessel_history[m]["last_ts"])
            for m in sorted_mmsi[:len(self._vessel_history) - 5000]:
                del self._vessel_history[m]

        total_anomalies = len(dark_gaps) + len(stationary_anomalies)
        err_note = f"{cp_errors} CP errors: {last_error}" if cp_errors and not cp_success else ""
        self.log_fetch(cp_success > 0, round((time.time() - t0) * 1000), 200 if cp_success else 0, total_anomalies, err_note)
        result = {
            "dark_gaps":            dark_gaps,
            "stationary_anomalies": stationary_anomalies,
            "has_anomaly":          total_anomalies > 0,
        }
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
        """最小二乗法による線形回帰の傾きを返す。"""
        n = len(xs)
        if n < 2: return 0.0
        sx, sy, sxy, sxx = sum(xs), sum(ys), sum(x*y for x,y in zip(xs,ys)), sum(x*x for x in xs)
        denom = n * sxx - sx * sx
        return (n * sxy - sx * sy) / denom if denom != 0 else 0.0

    def compute_velocity(self, ts_series: list) -> float:
        """1階微分: 脅威スコア変化速度（pt/秒）。DERIVATIVE_WINDOW点の線形回帰傾きで平滑化。"""
        pts = ts_series[-DERIVATIVE_WINDOW:] if len(ts_series) >= 2 else []
        if len(pts) < 2: return 0.0
        t0 = pts[0][0]
        xs = [p[0] - t0 for p in pts]
        ys = [p[1] for p in pts]
        return round(self._linear_regression_slope(xs, ys), 6)

    def compute_acceleration(self, ts_series: list) -> float:
        """2階微分: 速度の変化率（pt/秒²）。連続する速度点列から線形回帰傾きで計算。"""
        if len(ts_series) < 4: return 0.0
        # 速度列を生成
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
        加速度のZ-Score が AMBUSH_ZSCORE_THRESHOLD を超え、かつ正の加速度を示す場合に
        Ambush Pattern (待伏せ型急速エスカレーション) と判定する。
        Returns: (is_ambush: bool, z_score: float, velocity: float, acceleration: float)
        """
        if len(ts_series) < 5:
            return False, 0.0, 0.0, 0.0
        velocity = self.compute_velocity(ts_series)
        # 加速度を全点から計算するのではなく、ウィンドウをシフトして加速度時系列を生成
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
        複数GEO発信源の攻撃開始タイムスタンプから同期性スコアを計算する。
        origin_timestamps: {country_code: timestamp_ms}
        Returns: sync_score (0.0〜1.0)。SYNC_C2_THRESHOLD を超えると国家C2の疑い。
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

# ─────────────────────────────────────────────────────────────────────────────
# Global instances
# ─────────────────────────────────────────────────────────────────────────────
registry = SensorRegistry()
for s in [
    CloudflareSensor(), IodaSensor(), OpenSkySensor(), OpenWeatherSensor(),
    GDELTSensor(), PeeringDbSensor(), BgpRoutingSensor(), NasaFirmsSensor(), ThreatFoxSensor(),
    # 追加センサー
    RssNarrativeSensor(), IsrHotspotSensor(), AisMaritimeSensor(),
]:
    registry.register(s)
engine = WeightedConvergenceEngine()

def _build_default_context() -> dict:
    """デフォルト設定ベースのセンサーコンテキストを構築する。バックグラウンドスケジューラが使用。"""
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
    """センサー専用のバックグラウンドフェッチスレッド。poll_interval ごとに定期フェッチする。"""
    # 起動時は即時フェッチ
    try:
        ctx = _build_default_context()
        if sensor.name == "gdelt":
            owm = registry.get("openweather")
            if owm: ctx["weather_conditions"] = owm.get_cache().get("conditions", {})
        sensor.fetch(ctx)
    except Exception as e:
        print(f"[Sensor/{sensor.name}] Initial fetch error: {e}")
    while True:
        time.sleep(sensor.poll_interval)
        try:
            ctx = _build_default_context()
            if sensor.name == "gdelt":
                owm = registry.get("openweather")
                if owm: ctx["weather_conditions"] = owm.get_cache().get("conditions", {})
            sensor.fetch(ctx)
        except Exception as e:
            print(f"[Sensor/{sensor.name}] Scheduled fetch error: {e}")

# バックグラウンドセンサースケジューラを起動
for _s in registry._sensors.values():
    threading.Thread(target=_sensor_scheduler_worker, args=(_s,),
                     daemon=True, name=f"sensor-{_s.name}").start()

global_cache      = {"time": 0, "data": {}, "strategic": {}}
_global_cache_lock = threading.Lock()   # global_cache 全体置き換え時のスレッド安全
baseline_cache:    dict = {}
time_series_db:    dict = {}   # {theater: [float,...]}  ← 後方互換: 値のみ
time_series_ts_db: dict = {}   # {theater: [(ts, val),...]} ← タイムスタンプ付き
time_series_l3_db: dict = {}
time_series_l7_db: dict = {}
airspace_baseline: dict = {}
threat_history:    deque = deque(maxlen=20)
alert_timeline:    deque = deque(maxlen=288)
ALERT_TIMELINE_MAX = 288  # deque の maxlen と一致させること

# シーケンス・スコアラー用イベントログ
# {theater: [{"ts": float, "type": str, "meta": dict}, ...]}
sequence_event_log: dict = {}
SEQUENCE_EVENT_TYPES = ["NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY", "AIS_DARK_GAP"]

# CF scoring-loop result cache（センサーfetchとは独立したスコアリング用短期キャッシュ）
# キー: (url, frozenset(params.items())) → {"time": float, "data": list}
_cf_scoring_cache: dict = {}

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────
# ── Sequence Scorer ───────────────────────────────────────────────────────────
def register_sequence_event(theater: str, event_type: str, meta: dict = None):
    """エスカレーション連鎖ログにイベントを登録する。"""
    global sequence_event_log
    if theater not in sequence_event_log:
        sequence_event_log[theater] = []
    sequence_event_log[theater].append({
        "ts":   time.time(),
        "type": event_type,
        "meta": meta or {},
    })
    # 24h 超過エントリを削除してメモリを節約
    cutoff = time.time() - SEQUENCE_WINDOW
    sequence_event_log[theater] = [
        e for e in sequence_event_log[theater] if e["ts"] >= cutoff
    ]

def compute_sequence_bonus(theater: str) -> tuple:
    """
    24h ウィンドウ内のエスカレーション連鎖を検証し、ボーナス点数と状態文字列を返す。
    連鎖順序 (緩やかな共存モード): 全イベントタイプが SEQUENCE_WINDOW 内に存在すれば OK。
    厳格順序は求めないが、時系列の方向は検証する（最初のイベントが最後より前であること）。
    Returns: (bonus: int, chain_status: str, events_found: list)
    """
    now = time.time()
    cutoff = now - SEQUENCE_WINDOW
    events = [e for e in sequence_event_log.get(theater, []) if e["ts"] >= cutoff]
    if not events:
        return 0, "NO_EVENTS", []

    # 連鎖定義順序（緩やかな共存: 存在チェックのみ）
    chain_def = ["NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY"]
    found_types = {e["type"] for e in events}
    found_in_chain = [t for t in chain_def if t in found_types]
    found_count = len(found_in_chain)

    # 時系列の方向検証: 最初のイベントが最後のイベントより前（当然だが念のため確認）
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
    """スコアリングループ内のCF API呼び出しをキャッシュする。
    TTL省略時はCACHE_EXPIRYを使用。リロード時の毎回フェッチを防ぐ。
    呼び出しごとに期限切れエントリを削除してメモリリークを防ぐ。"""
    global _cf_scoring_cache
    if ttl is None:
        ttl = CACHE_EXPIRY
    now = time.time()
    # 期限切れエントリを削除（メモリリーク対策）
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
    # 期限切れエントリを削除（メモリリーク対策）
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

    # センサーはバックグラウンドで個別スケジューリング済み。
    # force_sync (SYNCボタン) 時のみ即時フェッチ。missing_data では待機しない
    # (起動直後はバックグラウンドスレッドが並行フェッチ中のため、同期待ちすると
    #  PeeringDB/AIS 等の低速センサーで数分ブロックされる)。
    if force_sync:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(sensor.fetch, sensor_context) for sensor in registry._sensors.values() if sensor.enabled]
            for future in as_completed(futures, timeout=60):
                pass

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
        # 追加センサーデータ取得
        rss_narrative_sensor = registry.get("rss_narrative")
        narrative_data = rss_narrative_sensor.get_cache().get("narratives", {}) if rss_narrative_sensor else {}
        isr_hotspot_sensor = registry.get("isr_hotspot")
        isr_data = isr_hotspot_sensor.get_cache().get("isr_data", {}) if isr_hotspot_sensor else {}
        ais_maritime_sensor = registry.get("ais_maritime")
        ais_dark_gaps        = ais_maritime_sensor.get_cache().get("dark_gaps", []) if ais_maritime_sensor else []
        ais_stationary       = ais_maritime_sensor.get_cache().get("stationary_anomalies", []) if ais_maritime_sensor else []
        ais_has_anomaly      = ais_maritime_sensor.get_cache().get("has_anomaly", False) if ais_maritime_sensor else False

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
            # ベースラインデータが空の場合（起動直後・CF APIエラー時）はスパイク計算をスキップ。
            # 空ベースラインで計算すると全発信元が最小値(0.5%)基準となり90倍超のフォールスポジティブが発生する。
            has_baseline = bool(b_data.get("l3") or b_data.get("l7"))

            for code in all_origin_codes:
                local_l3_pct, local_l7_pct = o_l3.get(code, 0.0), o_l7.get(code, 0.0)
                current_local_pct = max(local_l3_pct, local_l7_pct)

                is_new_actor = (code not in b_data["l3"]) and (code not in b_data["l7"])
                # 敵対国（CN/RU/KP等）は低いベースラインフロアを維持して小量攻撃も検知する。
                # 非敵対国は高いフロア（3%）でノイズを抑制。
                # 例: KP がベースライン0.1% → 現在2% のケースで4倍スパイクとして正しく検出できる。
                is_adversary_origin = code in adversary_states
                _floor_new   = 0.5 if is_adversary_origin else 3.0  # 新規actor（ベースラインにない）
                _floor_exist = 0.5 if is_adversary_origin else 2.0  # 既存actor
                base_l3 = max(b_data["l3"].get(code, _floor_new), _floor_exist if code not in b_data["l3"] else _floor_new)
                base_l7 = max(b_data["l7"].get(code, _floor_new), _floor_exist if code not in b_data["l7"] else _floor_new)
                l3_spike = (local_l3_pct / base_l3) if local_l3_pct > 0 else 0.0
                l7_spike = (local_l7_pct / base_l7) if local_l7_pct > 0 else 0.0
                # スパイク倍率を25倍でキャップ（統計ノイズによる極端な増幅を防ぐ）
                spike_factor = min(max(l3_spike, l7_spike), 25.0)

                normalized_dist_l3[code], normalized_dist_l7[code], normalized_dist[code] = local_l3_pct, local_l7_pct, current_local_pct

                # ベースラインあり かつ 絶対値が有意（≥1%）の場合のみスパイク集計に算入
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
            # 正規化分母を最低5%に引き上げ（少量トラフィック時のavg_spike過大評価を防ぐ）
            avg_l3_spike = target_l3_spike_sum / max(total_local_pct, 5.0); avg_l7_spike = target_l7_spike_sum / max(total_local_pct, 5.0)
            shift_actors = [s["code"] for s in combined_sources.values() if s.get("is_l7_shift")]
            is_vector_shift = ((avg_l7_spike >= 2.5 and avg_l7_spike > avg_l3_spike * 1.5) or len(shift_actors) > 0)
            if is_vector_shift and t in strategic_theaters_set: vector_shifts.append(t)

            avg_spike_record = round(target_weighted_spike / max(total_local_pct, 5.0), 2)
            time_series_db[t].append(avg_spike_record); time_series_db[t] = time_series_db[t][-15:]
            time_series_l3_db[t].append(round(avg_l3_spike, 2)); time_series_l3_db[t] = time_series_l3_db[t][-15:]
            time_series_l7_db[t].append(round(avg_l7_spike, 2)); time_series_l7_db[t] = time_series_l7_db[t][-15:]
            # タイムスタンプ付き時系列を更新（微分計算用）
            if t not in time_series_ts_db: time_series_ts_db[t] = []
            time_series_ts_db[t].append((current_time, avg_spike_record))
            time_series_ts_db[t] = time_series_ts_db[t][-30:]  # 微分には多めに保持

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
        # 国家主導の協調作戦は20〜35%重複が典型。45%は民間大型ボットネット水準で高すぎる。
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

        # ── 追加センサー rationale + Sequence Event 登録 ──────────────────────────

        # RSS ナラティブバースト
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

        # ISR ホットスポットサージ
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

        # AIS 海上異常
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

        # FIRMS → Sequence Event 登録（既存センサーの結果を流用）
        has_firms_core = any(f.get("code") == core_theater for f in nasa_firms_data)
        if has_firms_core:
            register_sequence_event(core_theater, "FIRMS_ANOMALY",
                                    {"hotspots": [f for f in nasa_firms_data if f.get("code") == core_theater]})

        # Sync DDoS 検出 → Sequence Event 登録（高同期性かつ高スコアの場合）
        if is_coordinated and high_correlation:
            register_sequence_event(core_theater, "SYNC_DDOS",
                                    {"coordinated_theaters": elevated_theaters,
                                     "max_overlap": max(correlations.values(), default=0.0)})

        # ── 微分計算 (Velocity / Acceleration / Ambush) ───────────────────────────
        ts_series_core = time_series_ts_db.get(core_theater, [])
        is_ambush, ambush_z, velocity_val, acceleration_val = engine.detect_ambush_pattern(ts_series_core)
        if is_ambush:
            add_rat("ddos_acceleration", "cyber",
                    "FIRED", f"Ambush Z={ambush_z:.2f} v={velocity_val:.4f}",
                    2, f"Exponential escalation detected (2nd derivative Z={ambush_z:.2f})")

        # ── Sequence Bonus 計算 ───────────────────────────────────────────────────
        seq_bonus, seq_status, seq_chain = compute_sequence_bonus(core_theater)

        domain_scores = engine.compute_domain_scores(rationale)
        total_score = sum(e.score for e in rationale if e.status == "FIRED" and not e.suppressed)
        convergence_score = engine.compute_convergence_score(domain_scores)
        score_with_bonus, conv_bonus, convergence_level = engine.apply_convergence_bonus(total_score, domain_scores)
        # Sequence Bonus を最終スコアに加算
        score_with_bonus += seq_bonus
        tl_raw = engine.compute_threat_level(score_with_bonus, tl1_hard)
        threat_level, tl_held = engine.apply_hysteresis(tl_raw, threat_history)
        threat_history.append((current_time, threat_level))
        # deque(maxlen=20) により自動的に古いエントリが削除される

        system_note = engine.build_system_note(threat_level, domain_scores, convergence_level, rationale, noise_filters_applied, tl_held)

        # 深層解析結果まとめ
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
            # Blockade Index: DDoS強度 / ネットワーク到達可能性 (0〜10)
            # IODA BGP 正常 = 1.0, OUTAGE = 0.1（到達不可）
            "blockade_index": round(
                min(core_spike, 10.0) / max(0.1 if core_degraded else 1.0, 0.1), 2
            ),
        }

        score_breakdown = {
            "core_spike_val": round(core_spike, 2), "core_spike_2x": core_spike > 2.0, "core_spike_4x": core_spike > 4.0, "core_spike_6x": core_spike > 6.0,
            "high_correlation": high_correlation, "core_shifted": core_shifted, "major_adversary": major_adversary, "core_degraded": core_degraded,
            "is_coordinated": is_coordinated, "tl1_hard": tl1_hard, "total_score": total_score,
            "convergence_bonus": conv_bonus, "sequence_bonus": seq_bonus, "score_with_bonus": score_with_bonus, "threat_raw": tl_raw, "threat_held": tl_held,
        }

        ioda_overlays = [{"code": t, "lat": COUNTRY_COORDS[t]["lat"], "lng": COUNTRY_COORDS[t]["lng"], "name": COUNTRY_COORDS[t]["name"], "status": "BGP_OUTAGE"} for t in degraded_targets_raw if t in COUNTRY_COORDS]

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
                    "chokepoints": [{"name": c["name"], "lat": c["lat"], "lng": c["lng"], "country": c["country"]} for c in CHOKEPOINTS if c["country"] in requested_targets],
                    # 追加オーバーレイ
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
                # 深層解析ブロック
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
        # deque(maxlen=ALERT_TIMELINE_MAX) により自動的に古いエントリが削除される

    results = []
    for t in requested_targets:
        t_info = COUNTRY_COORDS.get(t, {"lat": 0, "lng": 0, "name": t})
        data = global_cache["data"].get(t, {"global_share": 0, "global_share_l3": 0, "global_share_l7": 0, "is_vector_shift": False, "shift_actors": [], "sources": []})
        
        degraded_raw = global_cache["strategic"].get("degraded_theaters_raw", [])
        degraded_eff = global_cache["strategic"].get("degraded_theaters", [])
        
        # 各ターゲットの速度・加速度計算
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
            "threat_min_1h": max_d, 
            "threat_max_1h": min_d, 
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
    全シアターのエスカレーション連鎖状態を返す。
    クエリパラメータ: ?theater=TW (省略時は全シアター)
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
    深層解析結果の詳細エンドポイント。
    velocity/acceleration/ambush/narrative/ISR/AIS/blockade_index を返す。
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

    # Blockade Index: core DDoS spike / IODA degradation factor
    strategic = global_cache.get("strategic", {})
    core_spike_v = strategic.get("threat_breakdown", {}).get("core_spike_val", 0.0)
    is_degraded  = theater_param in strategic.get("degraded_theaters", [])
    blockade_idx = round(min(core_spike_v, 10.0) / max(0.1 if is_degraded else 1.0, 0.1), 2)

    # 速度トレンド（時系列を整形して返す）
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
    現在の脅威状況を SALUTE フォーマット (Size/Activity/Location/Unit/Time/Equipment)
    の接触報告として生成して返す。アナリストの訓練された認知モードを起動する。
    """
    strat = global_cache.get("strategic", {})
    p8    = strat.get("analytics", {})
    now_ts = datetime.datetime.now(datetime.timezone.utc)
    dtg = now_ts.strftime("%d%H%MZ %b %Y").upper()
    threat_level = strat.get("threat_level", 5)
    core   = strat.get("core_theater", "UNKNOWN")
    bd     = strat.get("threat_breakdown", {})
    adv_raw = strat.get("adversary_strikes", [])
    adv     = [a["actor"] if isinstance(a, dict) else str(a) for a in adv_raw]
    corr   = strat.get("correlations", {})
    isr    = p8.get("isr", {})
    ais    = p8.get("ais", {})
    narr   = p8.get("narrative", {})
    bi     = p8.get("blockade_index", 0.0)
    seq    = p8.get("sequence_status", "NO_EVENTS")

    # SIZE: 関与勢力・規模
    size_parts = []
    if adv:          size_parts.append(f"ADVERSARY STATES: {', '.join(adv)}")
    if corr:         size_parts.append(f"CORRELATED THEATERS: {len(corr)}")
    if isr.get("count", 0): size_parts.append(f"ISR AIRCRAFT: {isr['count']}")
    size = "; ".join(size_parts) if size_parts else "UNKNOWN — ASSESSMENT IN PROGRESS"

    # ACTIVITY: 観測された活動
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

    # LOCATION: 主要脅威地点
    degraded = strat.get("degraded_theaters", [])
    loc_parts = [f"PRIMARY: {core}"]
    if degraded: loc_parts.append(f"DEGRADED: {', '.join(degraded)}")
    location = " / ".join(loc_parts)

    # UNIT: 帰属判断
    if adv and bd.get("major_adversary"):
        unit = f"STATE-ATTRIBUTED — {', '.join(adv)} STATE ASN CONFIRMED"
    elif bd.get("is_coordinated"):
        unit = "COORDINATED — PROBABLE STATE C2 (UNKNOWN ATTRIBUTION)"
    else:
        unit = "UNKNOWN — ATTRIBUTION ASSESSMENT PENDING"

    # EQUIPMENT: 使用手段・攻撃ベクター
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
    現在のセンサーデータを「作戦気象ブリーフ」フォーマットに変換して返す。
    気象用語を使って脅威環境を直感的に表現する。
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
    """HISTORICAL_EVENTS パターンライブラリを返す。"""
    return jsonify({"events": HISTORICAL_EVENTS})


# ─────────────────────────────────────────────────────────────────────────────
# バックグラウンドクリーンアップスレッド
# 1時間ごとに各グローバルキャッシュの古いエントリを削除し、長期稼働時のメモリリークを防ぐ。
# ─────────────────────────────────────────────────────────────────────────────
def _cache_cleanup_worker():
    """デーモンスレッド: 1時間ごとに各種キャッシュの期限切れエントリを削除する。"""
    CLEANUP_INTERVAL = 3600  # 1時間
    BASELINE_MAX_AGE = 86400 * 7   # baselineは7日で失効
    SEQ_LOG_WINDOW   = SEQUENCE_WINDOW  # 24h
    while True:
        time.sleep(CLEANUP_INTERVAL)
        try:
            now = time.time()
            # baseline_cache: 7日以上更新されていないシアターを削除
            stale = [k for k, v in list(baseline_cache.items()) if now - v.get("time", 0) > BASELINE_MAX_AGE]
            for k in stale:
                baseline_cache.pop(k, None)

            # sequence_event_log: 各シアターの24h超エントリを再トリムし、空シアターを削除
            cutoff = now - SEQ_LOG_WINDOW
            for th in list(sequence_event_log.keys()):
                sequence_event_log[th] = [e for e in sequence_event_log[th] if e["ts"] >= cutoff]
                if not sequence_event_log[th]:
                    del sequence_event_log[th]

            # _cf_scoring_cache / _asn_cache: 念のため全失効エントリを掃除
            for k in [k for k, v in list(_cf_scoring_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _cf_scoring_cache.pop(k, None)
            for k in [k for k, v in list(_asn_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _asn_cache.pop(k, None)

            print(f"[Cleanup] baseline_cache={len(baseline_cache)} seqlog={len(sequence_event_log)} "
                  f"cf_cache={len(_cf_scoring_cache)} asn_cache={len(_asn_cache)}")
        except Exception as e:
            print(f"[Cleanup] Error: {e}")

_cleanup_thread = threading.Thread(target=_cache_cleanup_worker, daemon=True, name="cache-cleanup")
_cleanup_thread.start()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)