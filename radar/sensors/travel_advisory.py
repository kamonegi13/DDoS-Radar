"""radar.sensors.travel_advisory -- Travel Advisory sensor.

Monitors US State Department travel advisory level changes via the
public Travel Advisories API. An upgrade in advisory level for a
strategic theater (e.g., Level 3 "Reconsider Travel" or Level 4
"Do Not Travel") is a strong info-domain indicator.

API: https://travel.state.gov/_res/rss/TAsTWs.xml (RSS)
Also uses data.gov JSON endpoint as primary source.

No API key required.
"""
from __future__ import annotations
import logging
import time
import requests
from radar.sensors.base import BaseSensor
from radar.config import COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY

log = logging.getLogger("radar")

# State Department Travel Advisory API (JSON)
_TRAVEL_ADV_URL = "https://travel.state.gov/_res/rss/TAsTWs.xml"
_TRAVEL_ADV_JSON = "https://cadatalog.state.gov/catalog/api/action/datastore_search"

# Country code mapping: ISO3166 alpha-2 used by our system; State Dept uses alpha-2 as well.
# Advisory levels: 1=Exercise Normal Precautions, 2=Exercise Increased Caution,
# 3=Reconsider Travel, 4=Do Not Travel


class TravelAdvisorySensor(BaseSensor):
    """US State Department Travel Advisory monitor (info domain)."""

    def __init__(self):
        super().__init__("travel_advisory", "info", 3600)
        self._prev_levels: dict[str, int] = {}

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = set(context.get("strategic_theaters", []))
        adversaries = set(context.get("adversary_states", []))
        all_targets = theaters | adversaries
        if not all_targets:
            all_targets = set(list(COUNTRY_COORDS.keys())[:20])

        advisory_data: dict[str, dict] = {}
        any_success = False
        last_error = ""

        try:
            # Primary: fetch all advisories via RSS/XML
            res = requests.get(
                _TRAVEL_ADV_URL, timeout=20,
                proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                headers={"Accept": "application/xml, text/xml, */*"},
            )
            if res.status_code == 429:
                self.handle_rate_limit(res, round((time.time() - t0) * 1000))
                return self.get_cache() or {"advisories": {}, "country_status": {}}
            elif res.status_code == 200:
                # Parse simple XML (no external XML lib required)
                text = res.text
                any_success = True

                # Extract items from RSS
                items = text.split("<item>")[1:] if "<item>" in text else []
                for item_xml in items:
                    title = _extract_tag(item_xml, "title")
                    desc = _extract_tag(item_xml, "description")
                    pub_date = _extract_tag(item_xml, "pubDate")

                    # Parse advisory level from title
                    # Format: "Country Name - Travel Advisory" or contains "Level X"
                    level = _parse_level(title + " " + desc)
                    country_code = _match_country_code(title, all_targets)

                    if country_code and level > 0:
                        prev = self._prev_levels.get(country_code, level)
                        upgraded = level > prev
                        advisory_data[country_code] = {
                            "level": level,
                            "prev_level": prev,
                            "upgraded": upgraded,
                            "title": title[:200],
                            "pub_date": pub_date,
                            "level_label": _level_label(level),
                        }
                        self._prev_levels[country_code] = level

        except Exception as e:
            last_error = str(e)
            log.warning(f"[TravelAdvisory] Fetch error: {e}")

        # Fill in missing countries with defaults
        for code in all_targets:
            if code not in advisory_data:
                prev = self._prev_levels.get(code, 0)
                advisory_data[code] = {
                    "level": prev if prev > 0 else 0,
                    "prev_level": prev,
                    "upgraded": False,
                    "title": "",
                    "pub_date": "",
                    "level_label": _level_label(prev) if prev > 0 else "UNKNOWN",
                }

        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, 0, len(advisory_data), last_error)

        result = {"advisories": advisory_data}
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {"advisories": {}}


def _extract_tag(xml: str, tag: str) -> str:
    """Extract text content from a simple XML tag."""
    start = xml.find(f"<{tag}>")
    end = xml.find(f"</{tag}>")
    if start >= 0 and end > start:
        content = xml[start + len(tag) + 2:end]
        # Strip CDATA wrapper if present
        if content.startswith("<![CDATA["):
            content = content[9:]
            if content.endswith("]]>"):
                content = content[:-3]
        return content.strip()
    return ""


def _parse_level(text: str) -> int:
    """Extract advisory level (1-4) from text."""
    text_upper = text.upper()
    if "LEVEL 4" in text_upper or "DO NOT TRAVEL" in text_upper:
        return 4
    if "LEVEL 3" in text_upper or "RECONSIDER TRAVEL" in text_upper:
        return 3
    if "LEVEL 2" in text_upper or "INCREASED CAUTION" in text_upper:
        return 2
    if "LEVEL 1" in text_upper or "NORMAL PRECAUTIONS" in text_upper:
        return 1
    return 0


def _level_label(level: int) -> str:
    """Return human-readable label for advisory level."""
    return {
        1: "NORMAL_PRECAUTIONS",
        2: "INCREASED_CAUTION",
        3: "RECONSIDER_TRAVEL",
        4: "DO_NOT_TRAVEL",
    }.get(level, "UNKNOWN")


def _match_country_code(title: str, targets: set) -> str:
    """Match a country name in the title to a known country code."""
    from radar.config import COUNTRY_COORDS
    title_upper = title.upper()
    for code in targets:
        info = COUNTRY_COORDS.get(code)
        if info and info.get("name", "").upper() in title_upper:
            return code
    # Fallback: check all countries
    for code, info in COUNTRY_COORDS.items():
        if info.get("name", "").upper() in title_upper:
            return code
    return ""
