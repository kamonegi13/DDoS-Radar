"""radar.sensors.notam -- FAA NOTAM anomaly sensor.

Fetches NOTAMs (Notices to Air Missions) via the FAA NOTAM API to detect
airspace restriction surges that may indicate military activity or conflict
preparation. A sudden spike in TFRs (Temporary Flight Restrictions) or
military NOTAMs near strategic theaters is a strong physical-domain signal.

FAA NOTAM API: https://notams.aim.faa.gov/notamSearch/
Also uses ICAO API as fallback for non-US theaters.

No API key required for FAA endpoint (public).
"""
from __future__ import annotations
import logging
import time
import requests
from radar.sensors.base import BaseSensor
from radar.config import (
    COUNTRY_COORDS, AIRPORT_BOXES, GLOBAL_PROXIES, SSL_VERIFY,
    NOTAM_SURGE_THRESHOLD, NOTAM_MILITARY_KEYWORDS,
)

log = logging.getLogger("radar")

# FAA NOTAM search API (public, no auth)
_FAA_NOTAM_URL = "https://notams.aim.faa.gov/notamSearch/search"

# ICAO NOTAM API (public)
_ICAO_NOTAM_URL = "https://applications.icao.int/dataservices/api/notams-realtime-list"


def _decimal_to_dms(deg: float) -> tuple[int, int, int]:
    """Convert decimal degrees to (degrees, minutes, seconds)."""
    d = abs(deg)
    degrees = int(d)
    minutes = int((d - degrees) * 60)
    seconds = int(((d - degrees) * 60 - minutes) * 60)
    return (degrees, minutes, seconds)


class NotamSensor(BaseSensor):
    """FAA/ICAO NOTAM anomaly sensor (physical domain)."""

    def __init__(self):
        super().__init__("notam", "physical", 1800)
        # DISABLED: No free international NOTAM API available.
        # FAA covers US only; ICAO API has 100-call free limit.
        # Physical domain signals covered by GPS Jamming, ISR Hotspot, Mil Support Air.
        # Re-enable when FAA NMS or ICAO offers viable free tier.
        self.enabled = False
        self._prev_counts: dict[str, int] = {}

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = context.get("strategic_theaters", [])
        if not theaters:
            theaters = list(COUNTRY_COORDS.keys())[:10]

        notam_data: dict[str, dict] = {}
        country_status: dict[str, str] = {}
        any_success = False
        last_status = 0
        last_error = ""

        for code in theaters:
            try:
                # Use airport box from config for bounding-box search
                box = AIRPORT_BOXES.get(code, {})
                if not box:
                    coord = COUNTRY_COORDS.get(code)
                    if coord:
                        # Fallback: 3-degree bounding box around country center
                        box = {
                            "lamin": coord["lat"] - 3.0,
                            "lamax": coord["lat"] + 3.0,
                            "lomin": coord["lng"] - 3.0,
                            "lomax": coord["lng"] + 3.0,
                        }
                    else:
                        continue

                # Try FAA NOTAM search (JSON endpoint)
                # Compute center of bounding box in DMS format
                center_lat = box.get("lamin", 0) + (box.get("lamax", 0) - box.get("lamin", 0)) / 2
                center_lon = box.get("lomin", 0) + (box.get("lomax", 0) - box.get("lomin", 0)) / 2
                lat_dms = _decimal_to_dms(center_lat)
                lon_dms = _decimal_to_dms(center_lon)

                payload = {
                    "searchType": 0,
                    "designatorsForLocation": "",
                    "latMinutes": lat_dms[1],
                    "latSeconds": lat_dms[2],
                    "longMinutes": lon_dms[1],
                    "longSeconds": lon_dms[2],
                    "radius": 100,
                    "radiusSearchLatDirection": "N" if center_lat >= 0 else "S",
                    "radiusSearchLongDirection": "E" if center_lon >= 0 else "W",
                    "radiusSearchLatDeg": lat_dms[0],
                    "radiusSearchLongDeg": lon_dms[0],
                    "fcmSequenceNumber": 0,
                    "notamType": "N",
                    "offset": 0,
                    "pageSize": 50,
                    "sortColumn": "notamNumber",
                    "sortDirection": "DESC",
                }
                res = requests.post(
                    _FAA_NOTAM_URL, json=payload,
                    timeout=(10, 45), proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                )
                last_status = res.status_code

                notams = []
                total_count = 0
                mil_count = 0
                tfr_count = 0

                if res.status_code == 200:
                    data = res.json()
                    items = data if isinstance(data, list) else data.get("notamList", [])
                    total_count = len(items)
                    for item in items:
                        text = ""
                        if isinstance(item, dict):
                            text = (item.get("icaoMessage", "") or
                                    item.get("traditionalMessage", "") or
                                    str(item))
                        else:
                            text = str(item)
                        text_upper = text.upper()

                        is_mil = any(kw in text_upper for kw in NOTAM_MILITARY_KEYWORDS)
                        is_tfr = "TFR" in text_upper or "FLIGHT RESTRICTION" in text_upper
                        if is_mil:
                            mil_count += 1
                        if is_tfr:
                            tfr_count += 1
                        notams.append({
                            "text": text[:200],
                            "is_military": is_mil,
                            "is_tfr": is_tfr,
                        })
                    any_success = True

                prev = self._prev_counts.get(code, total_count)
                surge_pct = ((total_count - prev) / max(prev, 1)
                             if prev > 0 else 0)

                is_surge = (total_count >= NOTAM_SURGE_THRESHOLD or
                            mil_count >= 3 or
                            (surge_pct > 0.5 and total_count > 5))

                notam_data[code] = {
                    "total": total_count,
                    "military": mil_count,
                    "tfr": tfr_count,
                    "prev": prev,
                    "surge_pct": round(surge_pct, 3),
                    "is_surge": is_surge,
                    "recent": notams[:5],
                }

                if is_surge:
                    country_status[code] = "NOTAM_SURGE"
                elif mil_count > 0 or tfr_count > 0:
                    country_status[code] = "ELEVATED"
                else:
                    country_status[code] = "NORMAL"

                # Update prev counts
                if total_count > 0:
                    self._prev_counts[code] = total_count

                time.sleep(1.0)  # Rate limit

            except Exception as e:
                last_error = f"notam({code}): {e}"
                log.warning(f"[NOTAM] Error for {code}: {e}")

        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, last_status,
                       sum(d["total"] for d in notam_data.values()), last_error)

        result = {"notam_data": notam_data, "country_status": country_status}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "notam_data": {},
            "country_status": {c: "NORMAL" for c in theaters},
        }
