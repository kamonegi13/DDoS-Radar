"""radar.sensors.usgs_seismic -- USGS Earthquake/Seismic sensor.

Monitors USGS Earthquake Hazards API for seismic events that may
affect submarine cable infrastructure and contribute to physical-
domain disruption (e.g., earthquakes near cable landing stations
or chokepoints).

This is primarily a noise-suppressor: major seismic events near
undersea cables explain physical-layer disruptions without adversary
intent. Also detects potential nuclear test signatures (>4.0 magnitude
events in adversary territory with shallow depth).

API: https://earthquake.usgs.gov/fdsnws/event/1/
No API key required (public USGS service).
"""
from __future__ import annotations
import hashlib
import logging
import time
import math
import requests
from radar.sensors.base import BaseSensor
import os as _os
from radar.config import (
    COUNTRY_COORDS, CHOKEPOINTS, GLOBAL_PROXIES, SSL_VERIFY,
    USGS_CABLE_RADIUS_KM,
)

log = logging.getLogger("radar")

_USGS_URL = "https://earthquake.usgs.gov/fdsnws/event/1/query"


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute great-circle distance in km between two lat/lon points."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class UsgsSeismicSensor(BaseSensor):
    """USGS Earthquake sensor (physical domain noise suppressor / nuclear test detector)."""

    def __init__(self):
        super().__init__("usgs_seismic", "physical", 900)
        self._last_event_sig: str = ""  # MD5 of recent event IDs; skip processing when unchanged

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        adversaries = set(context.get("adversary_states", []))
        any_success = False
        last_error = ""

        earthquakes = []
        near_cable = []
        nuclear_candidates = []

        try:
            params = {
                "format": "geojson",
                "starttime": _hours_ago(24),
                "minmagnitude": float(_os.getenv("USGS_MIN_MAGNITUDE", "4.0")),
                "orderby": "time",
                "limit": 100,
            }
            res = requests.get(
                _USGS_URL, params=params, timeout=20,
                proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
            )
            if res.status_code == 429:
                self.handle_rate_limit(res, round((time.time() - t0) * 1000))
                return self.get_cache() or {"quakes": {}, "country_status": {}}
            elif res.status_code == 200:
                data = res.json()
                features = data.get("features", [])
                any_success = True

                # Skip expensive proximity scan when event set is unchanged
                sig = hashlib.md5(
                    "|".join(f.get("id", "") for f in features[:20]).encode()
                ).hexdigest()
                if sig == self._last_event_sig:
                    cached = self.get_cache()
                    if cached:
                        log.debug("[USGS] Event set unchanged — returning cache")
                        duration = round((time.time() - t0) * 1000)
                        self.log_fetch(True, duration, res.status_code, len(features))
                        return cached
                self._last_event_sig = sig

                for feat in features:
                    props = feat.get("properties", {})
                    geom = feat.get("geometry", {})
                    coords = geom.get("coordinates", [0, 0, 0])
                    lon, lat, depth_km = coords[0], coords[1], coords[2] if len(coords) > 2 else 0

                    eq = {
                        "mag": props.get("mag", 0),
                        "place": props.get("place", ""),
                        "time": props.get("time", 0),
                        "lat": lat,
                        "lon": lon,
                        "depth_km": depth_km,
                        "type": props.get("type", "earthquake"),
                        "tsunami": props.get("tsunami", 0),
                    }
                    earthquakes.append(eq)

                    # Check proximity to submarine cable landing stations / chokepoints
                    for cp in CHOKEPOINTS:
                        dist = _haversine_km(lat, lon, cp["lat"], cp["lng"])
                        if dist <= USGS_CABLE_RADIUS_KM:
                            near_cable.append({
                                "earthquake": eq,
                                "chokepoint": cp["name"],
                                "distance_km": round(dist, 1),
                            })
                            break  # One chokepoint match is enough

                    # Nuclear test candidate: shallow (<10km), in adversary territory,
                    # magnitude 4.0+ (CTBTO-like detection criteria)
                    if (eq["mag"] >= 4.0 and depth_km < 10 and
                            _in_adversary_territory(lat, lon, adversaries)):
                        nuclear_candidates.append(eq)

        except Exception as e:
            last_error = str(e)
            log.warning(f"[USGS] Fetch error: {e}")

        # Determine overall status
        has_cable_threat = len(near_cable) > 0
        has_nuclear_candidate = len(nuclear_candidates) > 0
        suppress_physical = has_cable_threat and not has_nuclear_candidate
        # Major seismic near cables = noise suppression explanation
        # But nuclear candidates = actually alarming

        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, 0, len(earthquakes), last_error)

        result = {
            "seismic": {
                "earthquakes": earthquakes[:20],
                "near_cable": near_cable[:10],
                "nuclear_candidates": nuclear_candidates,
                "total_events": len(earthquakes),
                "has_cable_threat": has_cable_threat,
                "has_nuclear_candidate": has_nuclear_candidate,
                "suppress_physical": suppress_physical,
            }
        }
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {"seismic": {
            "earthquakes": [], "near_cable": [], "nuclear_candidates": [],
            "total_events": 0, "has_cable_threat": False,
            "has_nuclear_candidate": False, "suppress_physical": False,
        }}


def _hours_ago(n: int) -> str:
    """Return ISO-format timestamp N hours ago."""
    import datetime
    dt = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=n)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _in_adversary_territory(lat: float, lon: float, adversaries: set) -> bool:
    """Check if coordinates fall within rough bounding box of adversary states."""
    for code in adversaries:
        info = COUNTRY_COORDS.get(code)
        if not info:
            continue
        # Simple 5-degree bounding box (rough check)
        clat, clon = info["lat"], info["lng"]
        if abs(lat - clat) < 5.0 and abs(lon - clon) < 5.0:
            return True
    return False
