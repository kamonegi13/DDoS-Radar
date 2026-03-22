"""radar.sensors.gps_jamming -- GPS Interference Detection sensor.

Monitors GPS jamming/spoofing activity near strategic theaters via
the GPSJam project data (crowdsourced ADS-B-derived GPS interference).
Also checks EUROCONTROL / FAA GPS interference reports.

GPS jamming is a strong indicator of electronic warfare activity
and is frequently observed in pre-conflict scenarios (e.g., Baltic
states, Eastern Mediterranean, Taiwan Strait).

Data source: gpsjam.org (public, no API key)
"""
from __future__ import annotations
import logging
import time
import requests
from radar.sensors.base import BaseSensor
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
    GPS_JAM_THRESHOLD, GPS_JAM_CRITICAL_THRESHOLD,
)

log = logging.getLogger("radar")

# GPSJam data endpoint (aggregated hex tiles with interference levels)
_GPSJAM_URL = "https://gpsjam.org/api"
# Fallback: EUROCONTROL GPS NOTAM feed
_EUROCONTROL_GPS_URL = "https://www.eurocontrol.int/gps-navaids-loss"


class GpsJammingSensor(BaseSensor):
    """GPS interference detection sensor (physical domain)."""

    def __init__(self):
        super().__init__("gps_jamming", "physical", 1800)
        self._prev_levels: dict[str, float] = {}

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_theaters", [])
        adversaries = context.get("adversary_states", [])
        all_targets = list(set(theaters + adversaries))
        if not all_targets:
            all_targets = list(COUNTRY_COORDS.keys())[:10]

        jamming_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        last_error = ""

        for code in all_targets:
            coord = COUNTRY_COORDS.get(code)
            if not coord:
                continue

            try:
                # Query GPSJam API for interference around country center
                lat, lon = coord["lat"], coord["lng"]
                res = requests.get(
                    f"{_GPSJAM_URL}/interference",
                    params={
                        "lat": lat, "lon": lon,
                        "radius": 300,  # km
                        "hours": 24,
                    },
                    timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                    headers={"Accept": "application/json"},
                )

                if res.status_code == 200:
                    data = res.json()
                    any_success = True

                    # Parse interference data
                    tiles = data if isinstance(data, list) else data.get("tiles", [])
                    total_tiles = len(tiles)
                    jammed_tiles = sum(1 for t in tiles
                                       if isinstance(t, dict) and
                                       t.get("level", 0) >= GPS_JAM_THRESHOLD)
                    max_level = max(
                        (t.get("level", 0) for t in tiles if isinstance(t, dict)),
                        default=0)
                    avg_level = (sum(t.get("level", 0) for t in tiles if isinstance(t, dict))
                                 / max(total_tiles, 1)) if total_tiles > 0 else 0

                    prev = self._prev_levels.get(code, avg_level)
                    surge = avg_level > prev * 1.5 if prev > 0 else False

                    is_jammed = (jammed_tiles >= 3 or
                                 max_level >= GPS_JAM_CRITICAL_THRESHOLD or
                                 avg_level >= GPS_JAM_THRESHOLD)

                    jamming_data[code] = {
                        "total_tiles": total_tiles,
                        "jammed_tiles": jammed_tiles,
                        "max_level": round(max_level, 2),
                        "avg_level": round(avg_level, 2),
                        "prev_avg": round(prev, 2),
                        "surge": surge,
                        "is_jammed": is_jammed,
                        "is_critical": max_level >= GPS_JAM_CRITICAL_THRESHOLD,
                    }

                    if max_level >= GPS_JAM_CRITICAL_THRESHOLD:
                        country_status[code] = "CRITICAL_JAMMING"
                    elif is_jammed:
                        country_status[code] = "JAMMING_DETECTED"
                    else:
                        country_status[code] = "NORMAL"

                    if avg_level > 0:
                        self._prev_levels[code] = avg_level

                elif res.status_code == 404:
                    # GPSJam API may not cover all regions
                    jamming_data[code] = _default_entry()
                    country_status[code] = "NO_DATA"

                time.sleep(0.5)

            except Exception as e:
                last_error = f"gps({code}): {e}"
                log.warning(f"[GPSJam] Error for {code}: {e}")
                jamming_data[code] = _default_entry()
                country_status[code] = "NO_DATA"

        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, 0,
                       sum(d.get("total_tiles", 0) for d in jamming_data.values()),
                       last_error)

        result = {"jamming_data": jamming_data, "country_status": country_status}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "jamming_data": {},
            "country_status": {c: "NO_DATA" for c in all_targets},
        }


def _default_entry() -> dict:
    return {
        "total_tiles": 0, "jammed_tiles": 0,
        "max_level": 0, "avg_level": 0,
        "prev_avg": 0, "surge": False,
        "is_jammed": False, "is_critical": False,
    }
