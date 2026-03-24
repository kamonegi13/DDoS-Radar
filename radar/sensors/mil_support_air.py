"""radar.sensors.mil_support_air -- Military Support Aircraft sensor.

Extends the ISR hotspot concept by tracking non-ISR military support
aircraft: tankers (KC-135, KC-10, A330 MRTT), transports (C-17, C-5,
C-130, AN-124), and AWACS (E-3, E-7). These indicate force projection
logistics or major exercise/deployment activity.

Tanker surge near a theater = extended combat air patrol capability.
Transport surge = force deployment / evacuation preparation.

Uses OpenSky Network API (same as ISR Hotspot sensor).
"""
from __future__ import annotations
import logging
import time
from radar.config import ISR_HOTSPOTS, GLOBAL_PROXIES, SSL_VERIFY
from radar.sensors.base import BaseSensor
from radar.sensors.opensky_auth import _opensky_get

log = logging.getLogger("radar")

# Military support aircraft callsign prefixes (NATO/Western + major adversary)
_TANKER_PREFIXES = (
    "TEXAC", "SHELL", "PETRO",    # USAF tanker callsigns (KC-135, KC-46)
    "NKCTK", "ASTRA",              # KC-10 / KC-46
    "VOVAG", "MRTT",               # Airbus MRTT
    "NAF", "RAF", "GAF",           # National Air Force prefixes (US/UK/German)
)
_TRANSPORT_PREFIXES = (
    "REACH", "RCH",                # USAF C-17 / C-5 (Air Mobility Command)
    "CARGO", "MOOSE",              # C-130 / C-5 callsigns
    "ANVIL", "STEEL",              # MAC heavy lift
    "SAM", "EXEC",                 # VIP / executive transport
)
_AWACS_PREFIXES = (
    "SENTRY", "DARKSTAR", "MAGIC", # E-3 AWACS
    "WEDGE",                        # E-7 Wedgetail
)

# Combined set for quick lookup
_ALL_MIL_PREFIXES = _TANKER_PREFIXES + _TRANSPORT_PREFIXES + _AWACS_PREFIXES


class MilSupportAirSensor(BaseSensor):
    """Military support aircraft sensor (physical domain)."""

    # 200km radius like ISR sensor
    RADIUS_DEG = 1.8

    def __init__(self):
        super().__init__("mil_support_air", "physical", 1800)

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = set(context.get("strategic_theaters", []))
        results: dict[str, dict] = {}
        any_success = False
        last_status = 0
        last_error = ""

        for hotspot in ISR_HOTSPOTS:
            theater = hotspot.get("theater", "")
            if theater not in theaters:
                continue
            lat, lng = hotspot["lat"], hotspot["lng"]
            name = hotspot["name"]
            r = self.RADIUS_DEG

            try:
                res = _opensky_get({
                    "lamin": lat - r, "lamax": lat + r,
                    "lomin": lng - r, "lomax": lng + r,
                })
                if res.status_code == 200:
                    states = res.json().get("states") or []
                    tanker_count = 0
                    transport_count = 0
                    awacs_count = 0
                    tracks = []

                    for s in states:
                        if len(s) < 10:
                            continue
                        callsign = (s[1] or "").strip().upper()
                        on_ground = s[8] if s[8] is not None else True
                        if on_ground:
                            continue

                        baro_alt = s[7] if s[7] is not None else 0
                        velocity = s[9] if s[9] is not None else 0

                        category = _classify_mil(callsign)
                        if not category:
                            continue

                        if category == "TANKER":
                            tanker_count += 1
                        elif category == "TRANSPORT":
                            transport_count += 1
                        elif category == "AWACS":
                            awacs_count += 1

                        tracks.append({
                            "icao24": s[0],
                            "callsign": callsign,
                            "category": category,
                            "lat": s[6] if s[6] is not None else lat,
                            "lon": s[5] if s[5] is not None else lng,
                            "alt_m": baro_alt,
                            "vel_ms": velocity,
                        })

                    existing = results.get(theater, {
                        "tanker": 0, "transport": 0, "awacs": 0,
                        "total": 0, "hotspots": [],
                    })
                    existing["tanker"] += tanker_count
                    existing["transport"] += transport_count
                    existing["awacs"] += awacs_count
                    existing["total"] += tanker_count + transport_count + awacs_count
                    existing["hotspots"].append({
                        "name": name, "lat": lat, "lng": lng,
                        "tanker": tanker_count, "transport": transport_count,
                        "awacs": awacs_count, "tracks": tracks[:5],
                    })
                    results[theater] = existing
                    any_success = True
                    last_status = res.status_code
                else:
                    last_status = res.status_code
                    last_error = f"HTTP {res.status_code}"

            except Exception as e:
                last_error = str(e)

        # Determine status per theater
        for theater, data in results.items():
            data["is_tanker_surge"] = data["tanker"] >= 2
            data["is_transport_surge"] = data["transport"] >= 3
            data["is_awacs_active"] = data["awacs"] >= 1
            data["is_surge"] = (data["is_tanker_surge"] or
                                data["is_transport_surge"] or
                                data["is_awacs_active"])

        total_ac = sum(d["total"] for d in results.values())
        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, last_status, total_ac, last_error)

        result = {"mil_air_data": results}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or result


def _classify_mil(callsign: str) -> str:
    """Classify a callsign into military support category."""
    for pfx in _TANKER_PREFIXES:
        if callsign.startswith(pfx):
            return "TANKER"
    for pfx in _TRANSPORT_PREFIXES:
        if callsign.startswith(pfx):
            return "TRANSPORT"
    for pfx in _AWACS_PREFIXES:
        if callsign.startswith(pfx):
            return "AWACS"
    return ""
