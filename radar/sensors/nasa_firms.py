"""radar.sensors.nasa_firms -- NasaFirmsSensor."""
from __future__ import annotations
import requests
import time
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
)
from radar.sensors.base import BaseSensor

class NasaFirmsSensor(BaseSensor):
    """Switched from NASA FIRMS to NASA EONET Wildfires API (FIRMS server unreachable).
    No API key required. eonet.gsfc.nasa.gov verified reachable in corporate proxy environments.
    """
    EONET_URL = "https://eonet.gsfc.nasa.gov/api/v3/events"
    # Adaptive radius per theater size. Small countries (TW, IL) use tight
    # radius to avoid overwhelming false positives from neighboring countries'
    # natural fires. Large countries default to 3.0° (≈330km).
    _THEATER_RADIUS: dict[str, float] = {
        "TW": 2.0, "IL": 2.0, "KR": 2.0, "KW": 2.0, "LB": 2.0,
        "JP": 3.0, "UA": 3.0, "PH": 3.0, "GE": 2.0, "EE": 2.0,
        "LV": 2.0, "LT": 2.0,
    }
    GEO_RADIUS_DEG_DEFAULT = 3.0

    def __init__(self):
        super().__init__("nasa_firms", "physical", 3600)
        self._last_event_sig: str = ""  # Skip reprocessing when wildfire set unchanged

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

            if res.status_code == 429:
                self.handle_rate_limit(res, round((time.time() - t0) * 1000))
                return self.get_cache() or {"anomalies": []}
            elif res.status_code == 200:
                events = res.json().get("events", [])
                record_count = len(events)
                self.log_fetch(True, duration, res.status_code, record_count)

                # Skip spatial scan when wildfire set is unchanged
                import hashlib as _hl
                sig = _hl.md5(
                    (f"{record_count}|" + "|".join(e.get("id", "") for e in events[:10])).encode()
                ).hexdigest()
                if sig == self._last_event_sig:
                    cached = self.get_cache()
                    if cached:
                        import logging as _log
                        _log.getLogger("radar").debug("[NASA_FIRMS] Wildfire set unchanged — returning cache")
                        return cached
                self._last_event_sig = sig

                # Extract nearby events by comparing distance to each theater's coordinates
                for code in theaters:
                    coord = COUNTRY_COORDS.get(code)
                    if not coord: continue
                    tlat, tlng = coord["lat"], coord["lng"]
                    radius = self._THEATER_RADIUS.get(code, self.GEO_RADIUS_DEG_DEFAULT)

                    for ev in events:
                        for geo in (ev.get("geometry") or []):
                            coords = geo.get("coordinates")
                            if not coords or len(coords) < 2: continue
                            # EONET coordinates are in [lng, lat] order
                            elng, elat = coords[0], coords[1]
                            if (abs(elat - tlat) <= radius and
                                    abs(elng - tlng) <= radius):
                                anomalies.append({
                                    "lat": elat, "lng": elng,
                                    "code": code, "confidence": "HIGH",
                                    "title": ev.get("title", "Wildfire")
                                })
                                break  # Avoid registering the same event to the same theater twice
            else:
                self.log_fetch(False, duration, res.status_code, 0, f"HTTP {res.status_code}")
                self.set_error(f"HTTP {res.status_code}")
                return self.get_cache() or {"anomalies": []}

        except requests.exceptions.Timeout:
            self.log_fetch(False, round((time.time() - t0) * 1000), 0, 0, "Timeout (EONET)")
            self.set_error("Timeout connecting to NASA EONET")
            return self.get_cache() or {"anomalies": []}
        except Exception as e:
            self.log_fetch(False, round((time.time() - t0) * 1000), 0, 0, str(e))
            self.set_error(str(e))
            return self.get_cache() or {"anomalies": []}

        result = {"anomalies": anomalies}
        if anomalies or res.status_code == 200:
            # Only update cache on successful fetch (preserve previous fire events on error)
            self.set_cache(result)
        return result
