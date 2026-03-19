"""radar.sensors.gdelt -- GDELTSensor."""
from __future__ import annotations
import datetime
import requests
import time
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY, GDELT_TONE_ALERT_THRESHOLD, GDELT_HISTORY_WINDOW,
)
from radar.sensors.base import BaseSensor
from radar.database import db as _db

class GDELTSensor(BaseSensor):
    QUERY_TEMPLATES = {
        "TW": '"Taiwan" (military OR invasion OR strait OR conflict)', "PH": '"Philippines" (military OR "South China Sea" OR conflict)',
        "JP": '"Japan" (military OR defense OR strait OR China)', "KR": '"Korea" (military OR nuclear OR "North Korea")',
        "UA": '"Ukraine" (war OR military OR Russia OR offensive)', "IL": '"Israel" (military OR attack OR Gaza OR Iran)',
        "US": '"United States" (military OR China OR Taiwan OR Russia)', "AU": '"Australia" (military OR China OR defense OR Pacific)'
    }
    DOW_MIN_SAMPLES = 3    # Minimum same-weekday samples before DoW Z-score is valid
    DOW_MAX_PER_DAY = 20   # Max stored tones per weekday (≈20 weeks)
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
        _now_ts = time.time()
        _cur_weekday = datetime.datetime.fromtimestamp(_now_ts, tz=datetime.timezone.utc).weekday()  # 0=Mon … 6=Sun
        _cur_day_bucket = int(_now_ts // 86400) * 86400  # UTC day bucket
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

            # DoW normalization: store today's tone in SQLite and compute Z-score
            _last_dow_bucket = _db.gdelt_dow_last_bucket(code)
            if _last_dow_bucket != _cur_day_bucket:
                _db.gdelt_dow_record(code, _cur_day_bucket, _cur_weekday,
                                     tone_current, max_entries=self.DOW_MAX_PER_DAY * 7)
            # Collect same-weekday tones from previous days (exclude today)
            _same_dow = _db.gdelt_dow_same_weekday(code, _cur_weekday, _cur_day_bucket)
            _n_dow = len(_same_dow)
            if _n_dow >= self.DOW_MIN_SAMPLES:
                _dow_mean = sum(_same_dow) / _n_dow
                _dow_std  = max((sum((x - _dow_mean)**2 for x in _same_dow) / _n_dow) ** 0.5, 0.5)
                _dow_z    = (tone_current - _dow_mean) / _dow_std
                # Negative tone = more hostile sentiment; large negative Z = anomalous hostility
                is_alert  = (not is_severe_wx) and (_dow_z < -2.0 or tone_current < alert_threshold)
                dow_info  = {"dow_z": round(_dow_z, 2), "dow_n": _n_dow, "dow_mean": round(_dow_mean, 3)}
            else:
                is_alert = (not is_severe_wx and tone_current < alert_threshold)
                dow_info = {"dow_z": None, "dow_n": _n_dow, "dow_mean": None}

            tones[code] = {
                "tone_current": tone_current, "tone_baseline": tone_baseline,
                "delta": round(delta, 3) if delta is not None else None,
                "is_alert": is_alert, "weather_suppressed": is_severe_wx,
                "status": ("WEATHER_NOISE" if is_severe_wx and tone_current < alert_threshold
                           else "ALERT" if is_alert else "NORMAL"),
                **dow_info,
            }
        self.log_fetch(True, round((time.time() - t0) * 1000), 200, len(tones))
        result = {"gdelt_tones": tones}; self.set_cache(result)
        return result

# ── Sensors (Production Implementation) ──
