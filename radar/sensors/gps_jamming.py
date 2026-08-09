"""radar.sensors.gps_jamming -- GPS Interference Detection sensor.

Monitors GPS jamming/spoofing activity near strategic theaters via
the GPSJam project data (crowdsourced ADS-B-derived GPS interference).

GPS jamming is a strong indicator of electronic warfare activity
and is frequently observed in pre-conflict scenarios (e.g., Baltic
states, Eastern Mediterranean, Taiwan Strait).

Data source: gpsjam.org daily H3 hex tile CSV files (public, no API key).
Each tile reports count_good_aircraft / count_bad_aircraft where "bad"
means degraded GPS navigation accuracy (NACp/NIC drop detected via ADS-B).
"""
from __future__ import annotations
import csv
import datetime
import io
import logging
import time
import requests
import h3
from radar.sensors.base import BaseSensor
import os as _os
from radar.config import (
    COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY,
)

log = logging.getLogger("radar")

# GPSJam publishes daily H3 resolution-4 tile CSV files
_GPSJAM_DATA_URL = "https://gpsjam.org/data"
_GPSJAM_MANIFEST_URL = f"{_GPSJAM_DATA_URL}/manifest.csv"
_H3_RESOLUTION = 4

# H3 resolution 4 hex has ~1,770 km² area; edge length ~22 km.
# At this resolution, 1° latitude ≈ 2 hexes.
# We search within ~3° (~330 km) of the country center.
_SEARCH_RADIUS_DEG = 3.0


def _h3_to_lat_lon(h3_hex: str) -> tuple[float, float] | None:
    """Get H3 hex center coordinates using the h3 library."""
    try:
        lat, lon = h3.cell_to_latlng(h3_hex)
        return (lat, lon)
    except Exception:
        return None


class GpsJammingSensor(BaseSensor):
    """GPS interference detection sensor (physical domain)."""

    def __init__(self):
        super().__init__("gps_jamming", "physical", 1800)
        self._prev_levels: dict[str, float] = {}
        self._latest_date: str = ""
        self._last_processed_date: str = ""  # Date for which tile data was last fully downloaded

    def _get_latest_date(self) -> str:
        """Fetch manifest.csv to find the most recent available date."""
        try:
            res = requests.get(
                _GPSJAM_MANIFEST_URL, timeout=15,
                proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                headers={"Accept-Encoding": "gzip, deflate"},
            )
            if res.status_code == 429:
                log.warning("[GPSJam] Manifest rate-limited (429)")
                return self._latest_date or ""
            if res.status_code != 200:
                return self._latest_date or ""
            lines = res.text.strip().split("\n")
            if len(lines) < 2:
                return ""
            last_line = lines[-1]
            date_str = last_line.split(",")[0]
            self._latest_date = date_str
            return date_str
        except Exception as e:
            log.warning(f"[GPSJam] Manifest fetch error: {e}")
            return self._latest_date or ""

    def _fetch_tile_data(self, date_str: str) -> list[dict]:
        """Fetch H3 tile CSV for a given date."""
        url = f"{_GPSJAM_DATA_URL}/{date_str}-h3_{_H3_RESOLUTION}.csv"
        res = requests.get(
            url, timeout=30,
            proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
            headers={"Accept-Encoding": "gzip, deflate"},
        )
        if res.status_code == 429:
            raise ValueError(f"Rate limited (429) for {url}")
        if res.status_code != 200:
            raise ValueError(f"HTTP {res.status_code} for {url}")
        reader = csv.DictReader(io.StringIO(res.text))
        tiles = []
        for row in reader:
            try:
                tiles.append({
                    "hex": row["hex"],
                    "good": int(row.get("count_good_aircraft", 0)),
                    "bad": int(row.get("count_bad_aircraft", 0)),
                })
            except (KeyError, ValueError):
                continue
        return tiles

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
        date_str = ""

        try:
            # Get latest available date from manifest
            date_str = self._get_latest_date()
            if not date_str:
                raise ValueError("No date available from manifest")

            # Skip expensive tile download if this date was already processed
            if date_str == self._last_processed_date:
                cached = self.get_cache()
                if cached:
                    log.debug(f"[GPSJam] Date {date_str} unchanged — returning cache")
                    duration = round((time.time() - t0) * 1000)
                    self.log_fetch(True, duration, 0,
                                   sum(d.get("total_tiles", 0) for d in cached.get("jamming_data", {}).values()))
                    return cached

            # Fetch global tile data (single request for all countries)
            all_tiles = self._fetch_tile_data(date_str)
            any_success = True
            log.info(f"[GPSJam] Fetched {len(all_tiles)} tiles for {date_str}")

            # Pre-compute lat/lon for all tiles once (h3 library gives exact centers)
            tile_coords = []
            for tile in all_tiles:
                center = _h3_to_lat_lon(tile["hex"])
                if center is not None:
                    tile_coords.append((tile, center[0], center[1]))
            log.info(f"[GPSJam] Resolved coordinates for {len(tile_coords)}/{len(all_tiles)} tiles")

            for code in all_targets:
                coord = COUNTRY_COORDS.get(code)
                if not coord:
                    jamming_data[code] = _default_entry()
                    country_status[code] = "NO_DATA"
                    continue

                lat, lon = coord["lat"], coord["lng"]

                # Filter tiles within search radius using pre-computed coords
                nearby_tiles = []
                for tile, tlat, tlon in tile_coords:
                    dlat = abs(tlat - lat)
                    dlon = abs(tlon - lon)
                    if dlon > 180:
                        dlon = 360 - dlon
                    if dlat <= _SEARCH_RADIUS_DEG and dlon <= _SEARCH_RADIUS_DEG:
                        nearby_tiles.append(tile)

                total_tiles = len(nearby_tiles)
                log.debug(f"[GPSJam] {code}: {total_tiles} nearby tiles (radius={_SEARCH_RADIUS_DEG}°)")
                total_good = sum(t["good"] for t in nearby_tiles)
                total_bad = sum(t["bad"] for t in nearby_tiles)
                total_aircraft = total_good + total_bad

                # Compute jamming ratio (bad / total aircraft)
                if total_aircraft > 0:
                    jam_ratio = total_bad / total_aircraft
                else:
                    jam_ratio = 0.0

                # Fix 2026-08-07 (F-08): the compared values are fractions
                # in [0, 1] (bad / total aircraft), but these thresholds
                # shipped percent-scaled at 3.0 / 7.0 — outside the domain,
                # so is_jammed and is_critical were mathematically
                # unreachable while fetch health stayed green. Defaults are
                # now the same numbers on the ratio scale.
                _jam_thr  = float(_os.getenv("GPS_JAM_THRESHOLD",          "0.03"))
                _crit_thr = float(_os.getenv("GPS_JAM_CRITICAL_THRESHOLD", "0.07"))
                jammed_tiles = sum(1 for t in nearby_tiles
                                   if (t["good"] + t["bad"]) > 0 and
                                   t["bad"] / (t["good"] + t["bad"]) >= _jam_thr)
                max_ratio = max(
                    (t["bad"] / (t["good"] + t["bad"])
                     for t in nearby_tiles if (t["good"] + t["bad"]) > 0),
                    default=0.0)

                prev = self._prev_levels.get(code, jam_ratio)
                surge = jam_ratio > prev * 1.5 if prev > 0 else False

                is_jammed = (jammed_tiles >= 3 or
                             max_ratio >= _crit_thr or
                             jam_ratio >= _jam_thr)

                jamming_data[code] = {
                    "total_tiles": total_tiles,
                    "jammed_tiles": jammed_tiles,
                    "total_aircraft": total_aircraft,
                    "bad_aircraft": total_bad,
                    "max_level": round(max_ratio, 4),
                    "avg_level": round(jam_ratio, 4),
                    "prev_avg": round(prev, 4),
                    "surge": surge,
                    "is_jammed": is_jammed,
                    "is_critical": max_ratio >= _crit_thr,
                    "date": date_str,
                }

                if max_ratio >= _crit_thr:
                    country_status[code] = "CRITICAL_JAMMING"
                elif is_jammed:
                    country_status[code] = "JAMMING_DETECTED"
                else:
                    country_status[code] = "NORMAL"

                if jam_ratio > 0:
                    self._prev_levels[code] = jam_ratio

        except Exception as e:
            last_error = f"gpsjam: {e}"
            log.warning(f"[GPSJam] Fetch error: {e}")
            for code in all_targets:
                if code not in jamming_data:
                    jamming_data[code] = _default_entry()
                    country_status[code] = "NO_DATA"

        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, 0,
                       sum(d.get("total_tiles", 0) for d in jamming_data.values()),
                       last_error)

        result = {"jamming_data": jamming_data, "country_status": country_status}
        if any_success:
            self._last_processed_date = date_str
            self.set_cache(result)
            return result
        return self.get_cache() or {
            "jamming_data": {},
            "country_status": {c: "NO_DATA" for c in all_targets},
        }


def _default_entry() -> dict:
    return {
        "total_tiles": 0, "jammed_tiles": 0,
        "total_aircraft": 0, "bad_aircraft": 0,
        "max_level": 0, "avg_level": 0,
        "prev_avg": 0, "surge": False,
        "is_jammed": False, "is_critical": False,
    }
