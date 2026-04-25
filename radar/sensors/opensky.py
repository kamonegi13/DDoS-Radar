"""radar.sensors.opensky -- OpenSkySensor."""
from __future__ import annotations
import time
from radar.config import (
    AIRPORT_BOXES,
)
from radar.sensors.base import BaseSensor
from radar.sensors.opensky_auth import _opensky_get
from radar.scenarios import SensorTier

class OpenSkySensor(BaseSensor):
    tier = SensorTier.FOCUSED_ONLY
    def __init__(self): super().__init__("opensky", "physical", 1800)
    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_countries", []); results: dict = {}; delta = 0.5
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
                    states = res.json().get("states") or []
                    count = len(states)
                    results[code] = {"airport": box["airport"], "count": count, "lat": lat, "lng": lng, "error": None}
                    total_states += count; any_success = True
                else:
                    results[code] = {"airport": box["airport"], "count": -1, "lat": lat, "lng": lng,
                                     "error": f"http_{res.status_code}"}
                    last_error = f"HTTP {res.status_code}"
            except Exception as e:
                results[code] = {"airport": box.get("airport", code), "count": -1, "lat": lat, "lng": lng, "error": str(e)}
                last_error = str(e)
        self.log_fetch(any_success, round((time.time() - t0) * 1000), last_status, total_states, last_error)
        result = {"airports": results}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or result
