"""radar.sensors.space_weather -- NOAA SWPC space weather sensor.

Fetches solar/geomagnetic data from NOAA Space Weather Prediction Center.
Used as a noise suppressor: when Kp index or X-ray flux exceeds thresholds,
physical domain sensors (IODA BGP, OpenSky, Check-Host) are flagged for
suppression to prevent false positives from geomagnetic storms.

No API key required (NOAA SWPC is free/public).
"""
from __future__ import annotations
import logging
import time
import requests
from radar.sensors.base import BaseSensor
from radar.config import (
    GLOBAL_PROXIES, SSL_VERIFY,
    SPACE_WEATHER_KP_SUPPRESS_THRESHOLD,
    SPACE_WEATHER_XRAY_SUPPRESS_CLASS,
)

log = logging.getLogger("radar")

# X-ray flare class severity ordering
_XRAY_CLASS_ORDER = {"A": 0, "B": 1, "C": 2, "M": 3, "X": 4}

_KP_URL = "https://services.swpc.noaa.gov/products/noaa-planetary-k-index-forecast.json"
_XRAY_URL = "https://services.swpc.noaa.gov/json/goes/primary/xrays-6-hour.json"


def _classify_storm(kp: float) -> str:
    """Map Kp index to NOAA storm level label."""
    if kp >= 9:
        return "EXTREME"
    if kp >= 8:
        return "SEVERE"
    if kp >= 7:
        return "STRONG"
    if kp >= 6:
        return "MODERATE"
    if kp >= 5:
        return "MINOR"
    return "NONE"


def _parse_xray_class(flux: float) -> str:
    """Classify X-ray flux (W/m²) into standard flare class."""
    if flux >= 1e-4:
        return "X"
    if flux >= 1e-5:
        return "M"
    if flux >= 1e-6:
        return "C"
    if flux >= 1e-7:
        return "B"
    return "A"


class SpaceWeatherSensor(BaseSensor):
    """NOAA SWPC space weather sensor (physical domain noise suppressor)."""

    def __init__(self):
        # Poll every 30 minutes (space weather changes slowly)
        super().__init__("space_weather", "physical", 1800)

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        kp_index = 0.0
        kp_forecast_24h = 0.0
        xray_flux = 0.0
        xray_class = "A"

        # Fetch Kp index forecast
        try:
            res = requests.get(_KP_URL, timeout=15,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 429:
                log.warning("[SpaceWeather] Kp API rate limited (429)")
            elif res.status_code == 200:
                rows = res.json()
                # Format: [[time_tag, Kp, observed/estimated/predicted], ...]
                # First row is header. Find most recent observed value.
                observed = [r for r in rows[1:] if len(r) >= 3 and r[2] == "observed"]
                if observed:
                    kp_index = float(observed[-1][1])
                # Max Kp in next 24h (any status)
                all_kp = [float(r[1]) for r in rows[1:] if len(r) >= 2]
                if all_kp:
                    kp_forecast_24h = max(all_kp)
        except Exception as e:
            log.warning(f"[SpaceWeather] Kp fetch error: {e}")

        # Fetch X-ray flux
        try:
            res = requests.get(_XRAY_URL, timeout=15,
                               proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
            if res.status_code == 429:
                log.warning("[SpaceWeather] X-ray API rate limited (429)")
            elif res.status_code == 200:
                data = res.json()
                if data:
                    # Use most recent entry; flux is in W/m²
                    latest = data[-1]
                    xray_flux = float(latest.get("flux", 0))
                    xray_class = _parse_xray_class(xray_flux)
        except Exception as e:
            log.warning(f"[SpaceWeather] X-ray fetch error: {e}")

        storm_level = _classify_storm(max(kp_index, kp_forecast_24h))

        # Determine suppression
        suppress_threshold = _XRAY_CLASS_ORDER.get(
            SPACE_WEATHER_XRAY_SUPPRESS_CLASS, 3)
        kp_triggers = kp_index >= SPACE_WEATHER_KP_SUPPRESS_THRESHOLD
        xray_triggers = _XRAY_CLASS_ORDER.get(xray_class, 0) >= suppress_threshold
        suppress_physical = kp_triggers or xray_triggers

        suppress_reason = ""
        if suppress_physical:
            parts = []
            if kp_triggers:
                parts.append(f"Kp={kp_index:.1f} (≥{SPACE_WEATHER_KP_SUPPRESS_THRESHOLD})")
            if xray_triggers:
                parts.append(f"X-ray {xray_class}-class (≥{SPACE_WEATHER_XRAY_SUPPRESS_CLASS})")
            suppress_reason = f"Geomagnetic storm: {', '.join(parts)} — " \
                              f"physical sensor noise expected"

        cache = {
            "space_weather": {
                "kp_index": kp_index,
                "kp_forecast_24h": kp_forecast_24h,
                "xray_class": xray_class,
                "xray_flux": xray_flux,
                "storm_level": storm_level,
                "suppress_physical": suppress_physical,
                "suppress_reason": suppress_reason,
            }
        }

        duration_ms = int((time.time() - t0) * 1000)
        self.set_cache(cache)
        self.log_fetch(True, duration_ms=duration_ms, records=1)
        log.info(f"[SpaceWeather] Kp={kp_index:.1f} forecast={kp_forecast_24h:.1f} "
                 f"xray={xray_class} storm={storm_level} suppress={suppress_physical}")
        return cache
