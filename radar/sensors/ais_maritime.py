"""radar.sensors.ais_maritime -- AisMaritimeSensor."""
from __future__ import annotations
import math
import os
import requests
import time
from radar.config import (
    CHOKEPOINTS, GLOBAL_PROXIES, SSL_VERIFY, AIS_DARK_GAP_THRESHOLD, AIS_ANCHOR_RADIUS_KM,
)
from radar.sensors.base import BaseSensor

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
TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD = float(os.getenv("TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD", "0.5"))

# Scraper User-Agent pool — rotated per request to reduce fingerprinting
_SCRAPER_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
