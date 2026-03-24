"""radar.sensors.rss_narrative -- RssNarrativeSensor."""
from __future__ import annotations
import math
import requests
import threading
import time
import xml.etree.ElementTree as ET
from radar.config import (
    ADVERSARY_NARRATIVE_SOURCES, TACTICAL_KEYWORDS, GLOBAL_PROXIES, SSL_VERIFY, NARRATIVE_ZSCORE_ALERT, NARRATIVE_ZSCORE_CRITICAL, NARRATIVE_BASELINE_DAYS,
)
from radar.sensors.base import BaseSensor

class RssNarrativeSensor(BaseSensor):
    """
    Fetches RSS feeds from TASS / Xinhua / Mehr News etc., analyzes keyword
    frequency with Z-Score to detect "narrative bursts".
    Compares against 30-day baseline (daily normalized frequency) to filter
    routine propaganda and alert only statistically significant spikes.
    """
    def __init__(self):
        super().__init__("rss_narrative", "info", 1800)
        self._baseline: dict = {}   # {theater: {"daily_counts": [float,...], "last_updated": float}}
        self._lock = threading.Lock()

    @staticmethod
    def _fetch_rss_text(url: str) -> str:
        """Fetch RSS feed and return text. Returns empty string on failure."""
        try:
            res = requests.get(url, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                               headers={"User-Agent": "Mozilla/5.0 (OSINT-Radar/8.0)"})
            if res.status_code == 429:
                return ""  # rate-limited, skip this feed
            if res.status_code == 200:
                return res.text
        except Exception:
            pass
        return ""

    @staticmethod
    def _count_keywords_in_rss(xml_text: str, keywords: list) -> tuple:
        """
        Parse RSS XML and return keyword hit count and article count.
        Duplicate articles are excluded using difflib.
        Returns: (keyword_hits: int, article_count: int)
        """
        if not xml_text:
            return 0, 0
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return 0, 0

        # Dedup: normalized hash of first 60 chars of title in a set (O(N) vs O(N²))
        titles_seen: set = set()
        keyword_hits, article_count = 0, 0
        keywords_lower = [k.lower() for k in keywords]

        for item in root.iter("item"):
            title_el = item.find("title")
            desc_el  = item.find("description")
            title = (title_el.text or "").strip() if title_el is not None else ""
            desc  = (desc_el.text  or "").strip() if desc_el  is not None else ""
            text  = (title + " " + desc).lower()

            # Detect duplicates via normalized 60-char key (eliminates SequenceMatcher O(N²))
            title_key = "".join(c for c in title.lower()[:60] if c.isalnum())
            if title_key and title_key in titles_seen:
                continue
            if title_key:
                titles_seen.add(title_key)

            article_count += 1
            if any(kw in text for kw in keywords_lower):
                keyword_hits += 1

        return keyword_hits, article_count

    def _compute_zscore(self, theater: str, today_normalized: float) -> tuple:
        """
        Compute Z-Score against 30-day baseline.
        Returns: (z_score: float, mean: float, std: float)
        """
        with self._lock:
            bl = self._baseline.get(theater, {})
            daily = bl.get("daily_counts", [])

        if len(daily) < 7:
            return 0.0, 0.0, 0.0
        n = len(daily)
        mean = sum(daily) / n
        variance = sum((x - mean) ** 2 for x in daily) / n
        std = math.sqrt(variance) if variance > 0 else 0.0
        z = (today_normalized - mean) / std if std > 0 else 0.0
        return round(z, 3), round(mean, 4), round(std, 4)

    def _update_baseline(self, theater: str, today_normalized: float):
        """Update daily baseline list (retains up to NARRATIVE_BASELINE_DAYS days)."""
        with self._lock:
            if theater not in self._baseline:
                self._baseline[theater] = {"daily_counts": [], "last_updated": 0.0}
            bl = self._baseline[theater]
            bl["daily_counts"].append(today_normalized)
            bl["daily_counts"] = bl["daily_counts"][-NARRATIVE_BASELINE_DAYS:]
            bl["last_updated"] = time.time()

    def fetch(self, context: dict) -> dict:
        theaters        = context.get("strategic_theaters", [])
        adversary_states = context.get("adversary_states", [])
        results: dict = {}
        t0 = time.time()
        total_hits = 0

        # Select sources from configured adversary blocs.
        # Merging by dict-key deduplicates overlapping sources (e.g. BY reuses TASS).
        sources: dict = {}
        for actor in adversary_states:
            sources.update(ADVERSARY_NARRATIVE_SOURCES.get(actor, {}))
        # Fallback: if no adversary configured, use all known sources
        if not sources:
            for bloc_sources in ADVERSARY_NARRATIVE_SOURCES.values():
                sources.update(bloc_sources)

        for theater in theaters:
            keywords = TACTICAL_KEYWORDS.get(theater, TACTICAL_KEYWORDS.get("DEFAULT", []))
            if not keywords:
                continue

            combined_hits, combined_articles = 0, 0
            for source_name, rss_url in sources.items():
                xml_text = self._fetch_rss_text(rss_url)
                hits, articles = self._count_keywords_in_rss(xml_text, keywords)
                combined_hits    += hits
                combined_articles += articles

            # Normalize by total article count (prevent division by zero)
            normalized = combined_hits / max(combined_articles, 1)

            z_score, mean_val, std_val = self._compute_zscore(theater, normalized)
            self._update_baseline(theater, normalized)

            status = "NORMAL"
            if z_score >= NARRATIVE_ZSCORE_CRITICAL:
                status = "CRITICAL_BURST"
            elif z_score >= NARRATIVE_ZSCORE_ALERT:
                status = "BURST"

            results[theater] = {
                "z_score":            z_score,
                "normalized_freq":    round(normalized, 4),
                "baseline_mean":      mean_val,
                "baseline_std":       std_val,
                "keyword_hits":       combined_hits,
                "article_count":      combined_articles,
                "status":             status,
                "is_burst":           status in ("BURST", "CRITICAL_BURST"),
                "keywords_monitored": keywords[:5],
            }
            total_hits += combined_hits

        self.log_fetch(True, round((time.time() - t0) * 1000), 200, total_hits)
        result = {"narratives": results}
        self.set_cache(result)
        return result

