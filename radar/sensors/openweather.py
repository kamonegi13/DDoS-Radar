"""radar.sensors.openweather -- OpenWeatherSensor."""
from __future__ import annotations
import requests
import time
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY, SEVERE_WEATHER_IDS,
)
from radar.sensors.base import BaseSensor

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
