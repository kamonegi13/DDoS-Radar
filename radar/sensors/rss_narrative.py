"""radar.sensors.rss_narrative -- RssNarrativeSensor."""
from __future__ import annotations
import hashlib
import math
import requests
import threading
import time
import xml.etree.ElementTree as ET
import os as _os
from radar.config import (
    ADVERSARY_NARRATIVE_SOURCES, TACTICAL_KEYWORDS, GLOBAL_PROXIES, SSL_VERIFY, LLM_ENABLED,
)
from radar.sensors.base import BaseSensor

# Track narrative burst items already submitted to intel_queue (dedup across cycles)
_burst_submitted: set[str] = set()
_MAX_BURST_SUBMITTED = 500

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

    @staticmethod
    def _get_burst_articles(xml_text: str, keywords: list, max_articles: int = 4) -> list[dict]:
        """Extract matched articles from RSS XML for LLM burst analysis.
        Called only when Z-score burst is detected — does not duplicate the
        counting logic, just collects article text for semantic analysis.
        """
        if not xml_text:
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []

        keywords_lower = [k.lower() for k in keywords]
        titles_seen: set = set()
        articles = []

        for item in root.iter("item"):
            title_el = item.find("title")
            desc_el  = item.find("description")
            link_el  = item.find("link")
            title = (title_el.text or "").strip() if title_el is not None else ""
            desc  = (desc_el.text  or "").strip() if desc_el  is not None else ""
            link  = (link_el.text  or "").strip() if link_el  is not None else ""

            title_key = "".join(c for c in title.lower()[:60] if c.isalnum())
            if title_key and title_key in titles_seen:
                continue
            if title_key:
                titles_seen.add(title_key)

            text_lower = (title + " " + desc).lower()
            if any(kw in text_lower for kw in keywords_lower):
                articles.append({
                    "title":   title,
                    "summary": desc[:300],
                    "link":    link,
                })
            if len(articles) >= max_articles:
                break

        return articles

    def _submit_narrative_burst_to_llm(
        self,
        theater: str,
        burst_articles: list[dict],
        z_score: float,
        sources_used: list[str],
        status: str,
    ) -> int:
        """Analyze narrative burst articles with LLM and submit to intel_queue.
        Returns number of items submitted (0 or 1).
        """
        if not burst_articles or not LLM_ENABLED:
            return 0

        try:
            from radar.intel_queue import intel_queue
            from radar.llm_client import llm_analyze_json, llm_available
        except Exception:
            return 0

        if not llm_available():
            return 0

        # Dedup key: theater + day bucket (one intel item per theater per day per burst level)
        day_bucket = int(time.time() // 86400)
        dedup_key = hashlib.md5(f"narrative-{theater}-{status}-{day_bucket}".encode()).hexdigest()
        if dedup_key in _burst_submitted:
            return 0

        from radar.llm_client import sanitize_llm_input, today_str
        articles_text = "\n\n".join(
            f"[{i+1}] {sanitize_llm_input(a['title'], 120)}\n{sanitize_llm_input(a['summary'], 200)}"
            for i, a in enumerate(burst_articles[:4])
        )
        total_matched = len(burst_articles)
        sources_str = ", ".join(sources_used)

        system_prompt = (
            "You are a strategic intelligence analyst specializing in information warfare "
            "and pre-conflict narrative patterns. "
            "Analyze these adversary media articles that triggered a statistical keyword burst "
            "and classify the narrative type. "
            "Respond ONLY with a JSON object, no explanation."
        )
        user_prompt = (
            f"Today's date: {today_str()}\n"
            f"Theater: {theater}\n"
            f"Z-score: {z_score:.2f} (statistical keyword burst; {total_matched} articles matched)\n"
            f"Sources: {sources_str}\n"
            f"Sample articles (showing {min(4, total_matched)} of {total_matched}):\n\n"
            f"{articles_text}\n\n"
            "Return a JSON object:\n"
            "{\n"
            '  "headline": "One-sentence summary of the narrative shift (max 100 chars)",\n'
            '  "narrative_type": "pre-operation_conditioning|threat_escalation|response_to_incident|propaganda_routine|unknown",\n'
            '  "dominant_theme": "Key theme across articles (e.g. sovereignty, military threat, sanctions)",\n'
            '  "escalation_signal": true or false,\n'
            '  "urgency": "critical|high|medium|low",\n'
            '  "confidence": 0.0\n'
            "}\n"
            "narrative_type guide:\n"
            "- pre-operation_conditioning: Preparing audience for imminent military action (new, escalating tone)\n"
            "- threat_escalation: Adversary responding to or amplifying a genuine, current escalation\n"
            "- response_to_incident: Reactive coverage of an already-occurred incident\n"
            "- propaganda_routine: Content matching the source's normal publishing frequency and framing\n"
            "  with no new trigger, specific threat, or escalation language beyond the baseline pattern.\n"
            "  Classify based on whether the content departs from baseline patterns, not based on origin country.\n"
            "Confidence guide:\n"
            "- 0.75+: Strong pre-operation conditioning language with a specific, new triggering event\n"
            "- 0.60-0.74: Elevated narrative with clear new escalatory framing\n"
            "- <0.55: Routine burst with no new specific trigger — set escalation_signal=false"
        )

        result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=256)
        if not result["ok"]:
            return 0

        from radar.llm_client import safe_float, safe_enum
        data = result["data"]
        confidence = safe_float(data.get("confidence"), default=0.0)

        _NARRATIVE_TYPES = {
            "pre-operation_conditioning", "threat_escalation",
            "response_to_incident", "propaganda_routine", "unknown",
        }
        narrative_type = safe_enum(data.get("narrative_type"), _NARRATIVE_TYPES, "unknown")

        if not data.get("escalation_signal", False) or confidence < 0.40:
            # Mark dedup even for non-escalation bursts to avoid spamming LLM every cycle
            _burst_submitted.add(dedup_key)
            if len(_burst_submitted) > _MAX_BURST_SUBMITTED:
                to_remove = list(_burst_submitted)[:_MAX_BURST_SUBMITTED // 2]
                for k in to_remove:
                    _burst_submitted.discard(k)
            return 0

        # Additive scoring: type_base + urgency_bonus (max = 3.0, no multiplicative inflation)
        urgency = safe_enum(
            data.get("urgency"), {"critical", "high", "medium", "low"}, "medium"
        )
        type_base = {
            "pre-operation_conditioning": 2.5,
            "threat_escalation":          2.0,
            "response_to_incident":       1.5,
            "propaganda_routine":         0.5,
            "unknown":                    1.0,
        }.get(narrative_type, 1.0)
        urgency_bonus = {"critical": 0.5, "high": 0.2, "medium": 0.0, "low": 0.0}.get(urgency, 0.0)
        score_delta = round(type_base + urgency_bonus, 1)

        item = {
            "source_type":  "narrative",
            "source_id":    f"narrative_{theater.lower()}",
            "theater":      theater,
            "ts":           time.time(),
            "confidence":   round(confidence, 3),
            "raw_text":     articles_text[:1000],
            "raw_url":      burst_articles[0].get("link", "") if burst_articles else "",
            "headline":     data.get("headline", f"Narrative burst: {theater} z={z_score:.1f}")[:100],
            "llm_fields": {
                "narrative_type":  narrative_type,
                "dominant_theme":  data.get("dominant_theme", ""),
                "z_score":         round(z_score, 2),
                "burst_status":    status,
                "sources":         sources_str,
                "escalation_signal": True,
            },
            "score_delta":  score_delta,
            "domain":       "info",
        }

        item_id = intel_queue.submit(item)
        if item_id:
            _burst_submitted.add(dedup_key)
            if len(_burst_submitted) > _MAX_BURST_SUBMITTED:
                to_remove = list(_burst_submitted)[:_MAX_BURST_SUBMITTED // 2]
                for k in to_remove:
                    _burst_submitted.discard(k)
            log.info(
                f"[RssNarrative] LLM burst submitted: {item['headline'][:60]} "
                f"(theater={theater}, type={narrative_type}, z={z_score:.2f}, conf={confidence:.2f})"
            )
            return 1
        return 0

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
            bl["daily_counts"] = bl["daily_counts"][-int(_os.getenv("NARRATIVE_BASELINE_DAYS", "30")):]
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
            # Accumulate burst articles per source (used for LLM analysis if burst detected)
            burst_article_pool: list[dict] = []
            fetched_sources: list[str] = []
            xml_texts: dict[str, str] = {}

            for source_name, rss_url in sources.items():
                xml_text = self._fetch_rss_text(rss_url)
                xml_texts[source_name] = xml_text
                hits, articles = self._count_keywords_in_rss(xml_text, keywords)
                combined_hits    += hits
                combined_articles += articles
                if xml_text:
                    fetched_sources.append(source_name)

            # Normalize by total article count (prevent division by zero)
            normalized = combined_hits / max(combined_articles, 1)

            z_score, mean_val, std_val = self._compute_zscore(theater, normalized)
            self._update_baseline(theater, normalized)

            status = "NORMAL"
            if z_score >= float(_os.getenv("NARRATIVE_ZSCORE_CRITICAL", "3.0")):
                status = "CRITICAL_BURST"
            elif z_score >= float(_os.getenv("NARRATIVE_ZSCORE_ALERT", "2.0")):
                status = "BURST"

            # On burst: collect matched articles and submit to LLM intel pipeline
            if status in ("BURST", "CRITICAL_BURST"):
                for source_name, xml_text in xml_texts.items():
                    burst_article_pool.extend(
                        self._get_burst_articles(xml_text, keywords, max_articles=2)
                    )
                if burst_article_pool:
                    self._submit_narrative_burst_to_llm(
                        theater, burst_article_pool, z_score, fetched_sources, status
                    )

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

