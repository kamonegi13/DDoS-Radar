"""radar.sensors.isr_hotspot -- IsrHotspotSensor."""
from __future__ import annotations
import os
import time
from radar.config import ISR_HOTSPOTS
from radar.sensors.base import BaseSensor
from radar.sensors.opensky_auth import _opensky_get
from radar.scenarios import SensorTier

class IsrHotspotSensor(BaseSensor):
    """
    Uses OpenSky Network states/all API to measure military/reconnaissance aircraft density
    within 200km of ISR_HOTSPOTS. Operates independently from OpenSkySensor (civilian airport monitoring).
    Identifies ISR pattern as high-altitude (>9000m) and low-speed (<160 m/s) aircraft.
    """
    tier = SensorTier.FOCUSED_ONLY
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
                            for pfx in (
                                # NATO/Western ISR callsigns
                                "FORTE", "JAKE", "MYSTIC", "RICO", "TROLL",
                                "DRAGON", "COBRA", "HAWK", "REAPER", "GLOBAL",
                                # Russian Air Force ISR/patrol (ADS-B when active)
                                "RFAF", "RFF", "RSD",  # Russian AF prefixes
                                # Chinese PLAAF ISR/patrol
                                "CCA", "CHN",           # Chinese military prefixes
                                "BAF",                   # Belarusian AF
                            )
                        )
                        if is_high_slow or is_mil_squawk or is_isr_call:
                            isr_count += 1
                            isr_tracks.append({
                                "icao24":   s[0],
                                "callsign": callsign,
                                "lat":      s[6] if s[6] is not None else lat,
                                "lon":      s[5] if s[5] is not None else lng,
                                "alt_m":    baro_alt,
                                "vel_ms":   velocity,
                                "heading":  s[10] if len(s) > 10 and s[10] is not None else 0,
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
            data["is_surge"] = data["count"] >= int(os.getenv("ISR_SURGE_THRESHOLD", "3"))

        result = {"isr_data": results}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or result

