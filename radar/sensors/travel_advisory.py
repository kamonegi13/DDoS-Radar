"""radar.sensors.travel_advisory -- Travel Advisory sensor.

Monitors travel advisory level changes from multiple independent
government sources:
  - US State Department (travel.state.gov RSS)
  - UK FCDO (Foreign, Commonwealth & Development Office) (gov.uk Atom)
  - Canada GAC (Global Affairs Canada) (travel.gc.ca HTML scrape)

Multi-source convergence: when multiple independent governments
simultaneously upgrade advisories for the same country, the signal
confidence increases (independent confirmation reduces single-source
political bias). Single-source upgrades are noted as potentially
politically motivated.

US/UK use public RSS/Atom feeds. Canada GAC discontinued RSS;
advisories are scraped from the HTML table at travel.gc.ca/travelling/advisories.
No API keys required.
"""
from __future__ import annotations
import logging
import re
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from radar.sensors.base import BaseSensor
from radar.config import COUNTRY_COORDS, GLOBAL_PROXIES, SSL_VERIFY

log = logging.getLogger("radar")

# --- Advisory source definitions ---
_SOURCES = {
    "US": {
        "name": "US State Department",
        "url": "https://travel.state.gov/_res/rss/TAsTWs.xml",
        "accept": "application/xml, text/xml, */*",
    },
    "UK": {
        "name": "UK FCDO",
        "url": "https://www.gov.uk/foreign-travel-advice.atom",
        "accept": "application/atom+xml, application/xml, */*",
    },
    "CA": {
        "name": "Canada GAC",
        "url": "https://travel.gc.ca/travelling/advisories",
        "accept": "text/html, */*",
        "html_scrape": True,
    },
}

# UK FCDO level keywords (mapped to 1-4 scale)
_FCDO_LEVEL_MAP = {
    "advise against all travel": 4,
    "advise against all but essential travel": 3,
    "advises against all travel": 4,
    "advises against all but essential travel": 3,
}

# Canada GAC risk levels
_GAC_LEVEL_MAP = {
    "avoid all travel": 4,
    "avoid non-essential travel": 3,
    "exercise a high degree of caution": 2,
    "take normal security precautions": 1,
}


class TravelAdvisorySensor(BaseSensor):
    """Multi-source Travel Advisory monitor (info domain).

    Fetches advisories from US, UK, and Canada independently, then
    computes convergence: multiple governments upgrading the same
    country simultaneously = higher confidence signal.
    """

    def __init__(self):
        super().__init__("travel_advisory", "info", 3600)
        # Per-source previous levels: {source: {country_code: level}}
        self._prev_levels: dict[str, dict[str, int]] = {
            src: {} for src in _SOURCES
        }

    def _fetch_source(self, source_key: str, all_targets: set) -> tuple[dict, bool]:
        """Fetch and parse a single advisory source.
        Returns: (country_data: dict, success: bool)
        """
        src = _SOURCES[source_key]
        prev = self._prev_levels[source_key]
        data: dict[str, dict] = {}

        try:
            res = requests.get(
                src["url"], timeout=20,
                proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                headers={"Accept": src["accept"]},
            )
            if res.status_code == 429:
                log.warning(f"[TravelAdvisory] Rate limited by {src['name']}")
                return data, False
            if res.status_code != 200:
                log.warning(f"[TravelAdvisory] {src['name']} returned {res.status_code}")
                return data, False

            text = res.text

            # Canada GAC: HTML table scraping (RSS discontinued)
            if src.get("html_scrape"):
                data = _parse_gac_html(text, all_targets, prev)
                return data, True

            # Parse RSS <item> or Atom <entry> blocks
            if "<entry>" in text:
                items = text.split("<entry>")[1:]
                tag_title, tag_desc, tag_date = "title", "summary", "updated"
            else:
                items = text.split("<item>")[1:] if "<item>" in text else []
                tag_title, tag_desc, tag_date = "title", "description", "pubDate"

            for item_xml in items:
                title = _extract_tag(item_xml, tag_title)
                desc = _extract_tag(item_xml, tag_desc)
                pub_date = _extract_tag(item_xml, tag_date)

                combined = title + " " + desc
                if source_key == "UK":
                    level = _parse_level_fcdo(combined)
                else:
                    level = _parse_level(combined)

                country_code = _match_country_code(title, all_targets)

                if country_code and level > 0:
                    prev_lv = prev.get(country_code, level)
                    upgraded = level > prev_lv
                    data[country_code] = {
                        "level": level,
                        "prev_level": prev_lv,
                        "upgraded": upgraded,
                        "title": title[:200],
                        "pub_date": pub_date,
                        "level_label": _level_label(level),
                    }
                    prev[country_code] = level

            return data, True

        except Exception as e:
            log.warning(f"[TravelAdvisory] {src['name']} error: {e}")
            return data, False

    def fetch(self, context: dict) -> dict:
        t0 = time.time()
        theaters = set(context.get("strategic_theaters", []))
        adversaries = set(context.get("adversary_states", []))
        all_targets = theaters | adversaries
        if not all_targets:
            all_targets = set(list(COUNTRY_COORDS.keys())[:20])

        # Fetch all sources in parallel (US/UK/Canada are independent)
        source_results: dict[str, dict] = {}
        any_success = False
        sources_ok: list[str] = []

        with ThreadPoolExecutor(max_workers=len(_SOURCES)) as ex:
            futures = {ex.submit(self._fetch_source, src_key, all_targets): src_key
                       for src_key in _SOURCES}
            for fut in as_completed(futures):
                src_key = futures[fut]
                data, ok = fut.result()
                source_results[src_key] = data
                if ok:
                    any_success = True
                    sources_ok.append(src_key)

        # Merge: compute per-country consensus from all sources
        advisory_data: dict[str, dict] = {}

        for code in all_targets:
            source_levels: dict[str, int] = {}
            best_entry: dict = {}
            best_level = 0

            for src_key in _SOURCES:
                entry = source_results[src_key].get(code)
                if entry and entry["level"] > 0:
                    source_levels[src_key] = entry["level"]
                    if entry["level"] > best_level:
                        best_level = entry["level"]
                        best_entry = entry

            if best_entry:
                # Convergence: count how many sources report level >= 3
                upgrading_sources = [
                    s for s, lv in source_levels.items()
                    if lv >= 3
                ]
                upgraded_sources = [
                    s for s in _SOURCES
                    if source_results[s].get(code, {}).get("upgraded", False)
                ]
                convergence_count = len(upgrading_sources)
                advisory_data[code] = {
                    **best_entry,
                    "source_levels": source_levels,
                    "convergence_count": convergence_count,
                    "converged": convergence_count >= 2,
                    "upgraded_sources": upgraded_sources,
                    "single_source_warning": (
                        len(source_levels) == 1 and best_level >= 3
                    ),
                }
            else:
                # No data from any source
                fallback_lv = max(
                    (self._prev_levels[s].get(code, 0) for s in _SOURCES),
                    default=0,
                )
                advisory_data[code] = {
                    "level": fallback_lv,
                    "prev_level": fallback_lv,
                    "upgraded": False,
                    "title": "",
                    "pub_date": "",
                    "level_label": _level_label(fallback_lv) if fallback_lv > 0 else "UNKNOWN",
                    "source_levels": {},
                    "convergence_count": 0,
                    "converged": False,
                    "upgraded_sources": [],
                    "single_source_warning": False,
                }

        duration = round((time.time() - t0) * 1000)
        self.log_fetch(any_success, duration, 0, len(advisory_data),
                       "" if any_success else "all sources failed")

        result = {
            "advisories": advisory_data,
            "sources_ok": sources_ok,
        }
        if any_success:
            self.set_cache(result)
            return result
        return self.get_cache() or {"advisories": {}}


def _parse_gac_html(html: str, all_targets: set, prev: dict) -> dict:
    """Parse Canada GAC travel advisory HTML table.
    Table rows contain: country name, risk level text, last-updated date.
    Risk level is also encoded in the SVG icon filename.
    """
    data: dict[str, dict] = {}
    # Match table rows: each <tr> contains country link + risk level text + date
    # Pattern: <a href="/destinations/...">Country Name</a> ... risk level text ... date
    row_re = re.compile(
        r'<tr[^>]*>.*?'
        r'<a\s+href="/destinations/[^"]*">([^<]+)</a>'  # country name
        r'.*?</td>\s*<td[^>]*>([^<]+)</td>'              # risk level text
        r'\s*<td[^>]*>([^<]*)</td>'                       # date
        r'.*?</tr>',
        re.DOTALL | re.IGNORECASE,
    )
    # Also try icon-based detection as fallback
    icon_level_map = {
        "do-not-travel": 4,
        "reconsider-travel": 3,
        "increased-caution": 2,
        "normal-precautions": 1,
    }
    for m in row_re.finditer(html):
        country_name = m.group(1).strip()
        risk_text = m.group(2).strip()
        pub_date = m.group(3).strip()

        # Match country code
        country_code = _match_country_code(country_name, all_targets)
        if not country_code:
            continue

        # Parse level from risk text
        level = _parse_level_gac(risk_text)

        # Fallback: check for icon filename in the row
        if level == 0:
            row_text = m.group(0)
            for icon_name, icon_lv in icon_level_map.items():
                if icon_name in row_text:
                    level = icon_lv
                    break

        if level > 0:
            prev_lv = prev.get(country_code, level)
            upgraded = level > prev_lv
            data[country_code] = {
                "level": level,
                "prev_level": prev_lv,
                "upgraded": upgraded,
                "title": f"{country_name} - {risk_text}"[:200],
                "pub_date": pub_date,
                "level_label": _level_label(level),
            }
            prev[country_code] = level

    return data


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
    """Extract US State Dept advisory level (1-4) from text."""
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


def _parse_level_fcdo(text: str) -> int:
    """Extract UK FCDO advisory level (mapped to 1-4 scale)."""
    text_lower = text.lower()
    for phrase, level in _FCDO_LEVEL_MAP.items():
        if phrase in text_lower:
            return level
    # FCDO doesn't always use standard phrases; check for severity hints
    if any(w in text_lower for w in ("extreme risk", "war zone", "armed conflict")):
        return 4
    if any(w in text_lower for w in ("high risk", "significant risk")):
        return 3
    # If we found a FCDO entry but can't parse level, assume baseline caution
    if "travel" in text_lower:
        return 2
    return 0


def _parse_level_gac(text: str) -> int:
    """Extract Canada GAC advisory level (mapped to 1-4 scale)."""
    text_lower = text.lower()
    for phrase, level in _GAC_LEVEL_MAP.items():
        if phrase in text_lower:
            return level
    # GAC numeric risk levels
    if "risk level 4" in text_lower:
        return 4
    if "risk level 3" in text_lower:
        return 3
    if "risk level 2" in text_lower:
        return 2
    if "risk level 1" in text_lower:
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
