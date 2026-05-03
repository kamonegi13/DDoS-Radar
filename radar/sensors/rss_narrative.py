"""radar.sensors.rss_narrative -- RssNarrativeSensor."""
from __future__ import annotations
import hashlib
import logging
import math
import re
import requests
import threading
import time
import defusedxml.ElementTree as ET
import os as _os

# Stop-words to drop when extracting atomic terms from multi-word phrases.
# These appear in too many news articles to be useful as standalone signals.
_TERM_STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for",
    "of", "is", "are", "was", "were", "be", "by", "with", "from",
    "this", "that", "as", "it", "its", "has", "have", "had",
    "near", "over", "after", "before", "during", "amid",
    "new", "old", "all", "any", "no", "not", "but",
    # Generic words that appear in too many news contexts to be discriminating
    "policy", "relations", "tensions", "crisis", "operations",
})


def _expand_keywords(keywords: list) -> tuple[list[str], list[str]]:
    """Split TACTICAL_KEYWORDS into (phrases, atomic_terms).

    phrases: original multi-word entries — kept for high-precision substring match.
    atomic_terms: significant single words extracted from each phrase, deduped.
                  These provide recall when news articles paraphrase official wording.

    Example:
        ["combat readiness", "encirclement"] →
            phrases    = ["combat readiness", "encirclement"]
            atomic     = ["combat", "readiness", "encirclement"]
    """
    phrases: list[str] = []
    atomic: set[str] = set()
    for kw in keywords:
        kw_lower = kw.lower().strip()
        if not kw_lower:
            continue
        if " " in kw_lower or "-" in kw_lower:
            phrases.append(kw_lower)
        # Extract significant words from each entry
        for tok in re.findall(r"[a-z]+", kw_lower):
            if len(tok) >= 4 and tok not in _TERM_STOPWORDS:
                atomic.add(tok)
    return phrases, sorted(atomic)
from radar.config import (
    ADVERSARY_NARRATIVE_SOURCES, TACTICAL_KEYWORDS, GLOBAL_PROXIES, SSL_VERIFY, LLM_ENABLED,
    NARRATIVE_GEO_TERMS,
)
from radar.sensors.base import BaseSensor

log = logging.getLogger("radar")

# Track narrative burst items already submitted to intel_queue (dedup across cycles)
_burst_submitted: dict[str, None] = {}
_burst_submitted_lock = threading.Lock()

# ── Geographic relevance filter ─────────────────────────────────────────────
# Pre-compiled regex cache for NARRATIVE_GEO_TERMS per theater.
_geo_regex_cache: dict[str, re.Pattern] = {}
_geo_regex_lock = threading.Lock()


def _get_geo_regex(theater: str, terms: list[str]) -> re.Pattern | None:
    """Get or compile a regex matching any geo term for a theater."""
    if not terms:
        return None
    with _geo_regex_lock:
        if theater not in _geo_regex_cache:
            parts = []
            for t in terms:
                t_lower = t.lower().strip()
                if not t_lower:
                    continue
                # Multi-word or long terms: substring match (low false-positive risk)
                # Short single words: word-boundary to prevent partial matches
                if " " in t_lower or len(t_lower) >= 6:
                    parts.append(re.escape(t_lower))
                else:
                    parts.append(r"\b" + re.escape(t_lower) + r"\b")
            if not parts:
                return None
            _geo_regex_cache[theater] = re.compile("|".join(parts))
        return _geo_regex_cache.get(theater)


def _classify_article_geo(
    text_lower: str,
    current_theater: str,
    all_geo_terms: dict[str, list[str]],
) -> str:
    """Classify an article's geographic relevance to a theater.

    Returns:
        "match"   — article mentions this theater's geography
        "other"   — article mentions another monitored theater but NOT this one
        "generic" — no monitored theater geography detected (global/ambiguous)
    """
    # Check current theater first
    current_terms = all_geo_terms.get(current_theater, [])
    current_re = _get_geo_regex(current_theater, current_terms)
    if current_re and current_re.search(text_lower):
        return "match"

    # Check all other theaters
    for code, terms in all_geo_terms.items():
        if code == current_theater:
            continue
        other_re = _get_geo_regex(code, terms)
        if other_re and other_re.search(text_lower):
            return "other"

    return "generic"
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
    def _count_keywords_in_rss(
        xml_text: str,
        keywords: list,
        current_theater: str = "",
        all_geo_terms: dict[str, list[str]] | None = None,
    ) -> tuple:
        """
        Parse RSS XML and return keyword hit count and article count.
        Two-tier matching: phrase substring (high precision) + atomic word boundary (high recall).
        An article counts as a hit if it matches at least one phrase or two atomic terms,
        preventing single-word matches from inflating the baseline.

        Geographic filter (when all_geo_terms is provided):
        - Articles about another monitored theater are excluded from keyword_hits
        - article_count is NEVER filtered (denominator stays total for Z-score stability)

        Returns: (keyword_hits: int, article_count: int)
        """
        if not xml_text:
            return 0, 0
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            log.debug("[RssNarrative] RSS XML parse error")
            return 0, 0

        phrases, atomic = _expand_keywords(keywords)
        # Compile word-boundary regex for atomic terms (single pass per article)
        atomic_re = re.compile(
            r"\b(?:" + "|".join(re.escape(t) for t in atomic) + r")\b"
        ) if atomic else None

        use_geo = bool(all_geo_terms and current_theater)
        titles_seen: set = set()
        keyword_hits, article_count = 0, 0

        for item in root.iter("item"):
            title_el = item.find("title")
            desc_el  = item.find("description")
            title = (title_el.text or "").strip() if title_el is not None else ""
            desc  = (desc_el.text  or "").strip() if desc_el  is not None else ""
            text  = (title + " " + desc).lower()

            title_key = "".join(c for c in title.lower()[:60] if c.isalnum())
            if title_key and title_key in titles_seen:
                continue
            if title_key:
                titles_seen.add(title_key)

            # article_count always increments (unfiltered denominator)
            article_count += 1

            # Geographic relevance: skip keyword counting for other-theater articles
            if use_geo:
                geo = _classify_article_geo(text, current_theater, all_geo_terms)
                if geo == "other":
                    continue

            # Tier 1: phrase match (high precision)
            if any(p in text for p in phrases):
                keyword_hits += 1
                continue
            # Tier 2: atomic term match (require ≥2 distinct terms to count as hit)
            if atomic_re:
                matches = set(atomic_re.findall(text))
                if len(matches) >= 2:
                    keyword_hits += 1

        return keyword_hits, article_count

    @staticmethod
    def _get_burst_articles(
        xml_text: str,
        keywords: list,
        max_articles: int = 4,
        current_theater: str = "",
        all_geo_terms: dict[str, list[str]] | None = None,
    ) -> list[dict]:
        """Extract matched articles from RSS XML for LLM burst analysis.
        Uses the same two-tier matching as _count_keywords_in_rss to stay
        consistent with hit counts (otherwise burst-detected articles could
        appear empty when only atomic terms matched).
        Geographic filter: excludes articles about other monitored theaters.
        """
        if not xml_text:
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            log.debug("[RssNarrative] RSS XML parse error (burst)")
            return []

        phrases, atomic = _expand_keywords(keywords)
        atomic_re = re.compile(
            r"\b(?:" + "|".join(re.escape(t) for t in atomic) + r")\b"
        ) if atomic else None

        use_geo = bool(all_geo_terms and current_theater)
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

            # Geographic filter: skip articles about other monitored theaters
            if use_geo:
                geo = _classify_article_geo(text_lower, current_theater, all_geo_terms)
                if geo == "other":
                    continue

            phrase_hit = any(p in text_lower for p in phrases)
            atomic_hits = len(set(atomic_re.findall(text_lower))) if atomic_re else 0
            if phrase_hit or atomic_hits >= 2:
                articles.append({
                    "title":   title,
                    "summary": desc[:300],
                    "link":    link,
                })
            if len(articles) >= max_articles:
                break

        return articles

    # Narrative type enum — shared between parse & scoring
    _NARRATIVE_TYPES: frozenset = frozenset({
        "pre-operation_conditioning", "threat_escalation",
        "response_to_incident", "propaganda_routine", "unknown",
    })
    _URGENCY_TYPES: frozenset = frozenset({"critical", "high", "medium", "low"})

    # Max articles fed to LLM per burst. 6 gives clustering headroom without
    # exploding token cost. With 2 articles/source cap, this lets up to 3
    # distinct sources contribute to a cluster decision.
    _LLM_POOL_CAP: int = 6

    def _submit_narrative_burst_to_llm(
        self,
        theater: str,
        burst_articles: list[dict],
        z_score: float,
        sources_used: list[str],
        status: str,
    ) -> int:
        """Analyze narrative burst articles with LLM, split into thematically
        coherent clusters, and submit each coherent cluster as a separate intel
        item. Returns total number of clusters submitted to intel_queue.

        Clustering addresses the failure mode where a single burst pools
        articles across sources that match tactical keywords but cover
        unrelated topics (e.g. naval port call + AI scholar + destroyer drill).
        The legacy single-synthesis flow was forced to fabricate a common
        narrative; the cluster flow separates them so each intel item is
        thematically coherent and the analyst can accept/reject per-theme.
        """
        if not burst_articles or not LLM_ENABLED:
            return 0

        try:
            from radar.intel_queue import intel_queue
            from radar.llm_client import llm_analyze_json, llm_available, record_sensor_skip
        except Exception:
            return 0

        if not llm_available():
            record_sensor_skip("llm_unavailable", caller="rss_narrative")
            return 0

        # Burst-level dedup: prevent re-calling LLM on same burst within a day.
        # Per-cluster dedup is handled downstream by intel_queue's Jaccard check.
        day_bucket = int(time.time() // 86400)
        burst_dedup = hashlib.md5(
            f"narrative-burst-{theater}-{status}-{day_bucket}".encode(),
            usedforsecurity=False,
        ).hexdigest()
        with _burst_submitted_lock:
            if burst_dedup in _burst_submitted:
                record_sensor_skip(f"burst_dedup_24h:{theater}", caller="rss_narrative")
                return 0
            _burst_submitted[burst_dedup] = None
            if len(_burst_submitted) > _MAX_BURST_SUBMITTED:
                for k in list(_burst_submitted)[:_MAX_BURST_SUBMITTED // 2]:
                    _burst_submitted.pop(k, None)

        from radar.llm_client import sanitize_llm_input, today_str
        pool = burst_articles[:self._LLM_POOL_CAP]
        articles_text = "\n\n".join(
            f"[{i+1}] {sanitize_llm_input(a['title'], 120)}\n{sanitize_llm_input(a['summary'], 200)}"
            for i, a in enumerate(pool)
        )
        sources_str = ", ".join(sources_used)

        system_prompt = (
            "You are a strategic intelligence analyst specializing in "
            "information warfare and pre-conflict narrative patterns. "
            "Analyze adversary media articles that triggered a statistical "
            "keyword burst. Group the articles by thematic coherence: "
            "articles on unrelated topics MUST go in separate clusters. "
            "NEVER fabricate a common narrative across unrelated articles. "
            "Respond ONLY with a JSON object, no explanation."
        )
        user_prompt = (
            f"Today's date: {today_str()}\n"
            f"Theater: {theater}\n"
            f"Z-score: {z_score:.2f} (statistical keyword burst; {len(pool)} articles)\n"
            f"Sources: {sources_str}\n\n"
            f"Articles:\n\n{articles_text}\n\n"
            "Return a JSON object:\n"
            "{\n"
            '  "clusters": [\n'
            "    {\n"
            '      "article_indices": [1, 3],\n'
            '      "headline": "One-sentence summary of THIS cluster\'s narrative (max 100 chars)",\n'
            '      "narrative_type": "pre-operation_conditioning|threat_escalation|response_to_incident|propaganda_routine|unknown",\n'
            '      "dominant_theme": "Key theme of THIS cluster only",\n'
            '      "escalation_signal": true or false,\n'
            '      "countries": ["ISO codes addressed in this cluster"],\n'
            '      "country_weights": {"ISO": 0.0-1.0},\n'
            '      "urgency": "critical|high|medium|low",\n'
            '      "confidence": 0.0-1.0\n'
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Clustering rules:\n"
            "- ONE cluster if all articles share a coherent theme.\n"
            "- MULTIPLE clusters when articles cover distinctly different topics\n"
            "  (e.g. some about naval activity, others about diplomatic pressure).\n"
            "- article_indices are 1-based and must reference articles listed above.\n"
            "- An article may belong to multiple clusters only when it genuinely\n"
            "  bridges themes; otherwise assign to exactly one cluster.\n"
            "- Off-topic articles that do NOT support any narrative theme should\n"
            "  be omitted from all clusters rather than forced into one.\n\n"
            "narrative_type guide:\n"
            "- pre-operation_conditioning: Preparing audience for imminent military action\n"
            "- threat_escalation: Adversary amplifying a genuine current escalation\n"
            "- response_to_incident: Reactive coverage of an already-occurred incident\n"
            "- propaganda_routine: Matches source's baseline framing with no new trigger.\n"
            "  Classify by departure from baseline patterns, not origin country.\n\n"
            "IMPORTANT: The 'Theater' label above is for CONTEXT only. "
            "Assign 'countries' based on the article content, NOT the Theater label. "
            "If articles discuss a DIFFERENT region than the labeled Theater, "
            "set countries to that region's ISO codes.\n\n"
            "Confidence (per cluster):\n"
            "- 0.75+: Strong pre-operation conditioning with specific new trigger\n"
            "- 0.60-0.74: Elevated narrative with clear new escalatory framing\n"
            "- <0.55: Routine burst, no new trigger — set escalation_signal=false"
        )

        from radar.llm_routing import UseCase
        result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=512,
                                  use_case=UseCase.SENSOR_EXTRACT)

        if not result["ok"]:
            return 0

        clusters = self._parse_narrative_clusters(result["data"], pool, theater)
        if not clusters:
            from radar.llm_client import record_sensor_drop
            record_sensor_drop("no_valid_clusters")
            return 0

        submitted = 0
        for cluster in clusters:
            if self._submit_narrative_cluster(
                cluster, pool, theater, z_score, sources_str, status, intel_queue
            ):
                submitted += 1
        return submitted

    @classmethod
    def _parse_narrative_clusters(
        cls, data: dict, pool: list[dict], theater: str
    ) -> list[dict]:
        """Normalize LLM output into a list of validated cluster dicts.

        Accepts both:
          - New format: {"clusters": [{article_indices, headline, ...}, ...]}
          - Legacy format: flat {headline, narrative_type, ...} — treated as
            one cluster covering all pool articles (backward compat path so a
            model that ignores the new schema still produces usable output).
        """
        from radar.llm_client import safe_float, safe_enum

        raw_clusters = data.get("clusters")
        legacy_fallback = False
        if not isinstance(raw_clusters, list) or not raw_clusters:
            raw_clusters = [data]
            legacy_fallback = True
            log.debug("[RssNarrative] LLM returned no clusters; using legacy single-synthesis fallback")

        out: list[dict] = []
        for rc in raw_clusters:
            if not isinstance(rc, dict):
                continue

            raw_idx = rc.get("article_indices") or []
            idx_set: set[int] = set()
            for v in raw_idx:
                try:
                    i = int(v) - 1
                    if 0 <= i < len(pool):
                        idx_set.add(i)
                except (TypeError, ValueError):
                    continue
            if not idx_set:
                if legacy_fallback:
                    idx_set = set(range(min(len(pool), 4)))
                else:
                    continue  # cluster with no valid indices — discard

            narrative_type = safe_enum(rc.get("narrative_type"),
                                       cls._NARRATIVE_TYPES, "unknown")
            confidence = safe_float(rc.get("confidence"), default=0.0)
            escalation_signal = bool(rc.get("escalation_signal", False))
            urgency = safe_enum(rc.get("urgency"), cls._URGENCY_TYPES, "medium")
            dominant_theme = str(rc.get("dominant_theme") or "")[:100]
            headline = str(rc.get("headline") or "")[:100]
            if not headline:
                headline = f"Narrative burst: {theater} — {dominant_theme[:60]}"

            raw_countries = rc.get("countries") or []
            raw_weights = rc.get("country_weights") or {}
            countries = [c.strip().upper() for c in raw_countries
                         if isinstance(c, str) and len(c.strip()) == 2]
            country_weights: dict[str, float] = {}
            for c in countries:
                w = raw_weights.get(c, raw_weights.get(c.lower(), 1.0))
                country_weights[c] = max(0.0, min(1.0, safe_float(w, default=1.0)))
            if theater not in countries:
                countries = [theater] + countries
                country_weights.setdefault(theater, 1.0)

            out.append({
                "indices":           sorted(idx_set),
                "narrative_type":    narrative_type,
                "confidence":        confidence,
                "escalation_signal": escalation_signal,
                "urgency":           urgency,
                "dominant_theme":    dominant_theme,
                "headline":          headline,
                "countries":         countries,
                "country_weights":   country_weights,
            })
        return out

    @staticmethod
    def _submit_narrative_cluster(
        cluster: dict,
        pool: list[dict],
        theater: str,
        z_score: float,
        sources_str: str,
        status: str,
        intel_queue,
    ) -> bool:
        """Submit one validated cluster to intel_queue. Returns True if accepted."""
        from radar.llm_client import sanitize_llm_input, record_sensor_drop

        confidence = cluster["confidence"]
        narrative_type = cluster["narrative_type"]

        # Drop non-escalatory or below-floor clusters (spam prevention).
        # intel_queue also re-checks confidence floor; we pre-filter here to
        # avoid the sensor_drop metric double-counting.
        if not cluster["escalation_signal"]:
            record_sensor_drop("no_escalation_signal")
            return False
        if confidence < 0.35:
            record_sensor_drop("below_floor")
            return False

        # Build raw_text from this cluster's supporting articles ONLY.
        # Numbered [1..N] within the cluster so the analyst sees just the
        # articles that support this headline.
        supporting = [pool[i] for i in cluster["indices"]]
        if not supporting:
            return False
        articles_text = "\n\n".join(
            f"[{j+1}] {sanitize_llm_input(a['title'], 120)}\n{sanitize_llm_input(a['summary'], 200)}"
            for j, a in enumerate(supporting)
        )
        raw_url = supporting[0].get("link", "")

        type_base = {
            "pre-operation_conditioning": 2.5,
            "threat_escalation":          2.0,
            "response_to_incident":       1.5,
            "propaganda_routine":         0.5,
            "unknown":                    1.0,
        }.get(narrative_type, 1.0)
        urgency_bonus = {"critical": 0.5, "high": 0.2,
                         "medium": 0.0, "low": 0.0}.get(cluster["urgency"], 0.0)
        score_delta = round(type_base + urgency_bonus, 1)

        item = {
            "source_type":     "narrative",
            "source_id":       f"narrative_{theater.lower()}",
            "theater":         theater,
            "countries":       cluster["countries"],
            "country_weights": cluster["country_weights"],
            "ts":              time.time(),
            "confidence":      round(confidence, 3),
            "raw_text":        articles_text[:1000],
            "raw_url":         raw_url,
            "headline":        cluster["headline"],
            "llm_fields": {
                "narrative_type":    narrative_type,
                "dominant_theme":    cluster["dominant_theme"],
                "z_score":           round(z_score, 2),
                "burst_status":      status,
                "sources":           sources_str,
                "escalation_signal": True,
                "article_count":     len(supporting),
            },
            "score_delta":     score_delta,
            "domain":          "info",
        }

        item_id = intel_queue.submit(item)
        if item_id:
            log.info(
                f"[RssNarrative] LLM cluster submitted: {cluster['headline'][:60]} "
                f"(theater={theater}, type={narrative_type}, n={len(supporting)}, "
                f"z={z_score:.2f}, conf={confidence:.2f})"
            )
            return True
        return False

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
        if std > 0:
            z = (today_normalized - mean) / std
        elif today_normalized > 0 and mean == 0:
            # Baseline is a flat stream of zeros — first non-zero activity is
            # itself a burst signal. Without this branch, the first signal
            # against a silent baseline is silently reported as z=0
            # (sensitivity/recall is prioritized over precision per design).
            z = float(_os.getenv("NARRATIVE_ZSCORE_FIRST_SIGNAL", "3.0"))
        else:
            z = 0.0
        return round(z, 3), round(mean, 4), round(std, 4)

    def _update_baseline(self, theater: str, today_normalized: float):
        """Update rolling baseline (NARRATIVE_BASELINE_DAYS days of cycles).

        Bug fix 2026-04-29: prior code capped the list at NARRATIVE_BASELINE_DAYS
        entries, but the sensor fetches every 1800 s (48 cycles/day). The cap
        therefore truncated the rolling window to ~15 hours instead of 30 days,
        and the z-score normalized against itself — observed effect was 100%
        `no_burst_this_cycle` pre_filter rejection in production. Cap is now
        `NARRATIVE_BASELINE_DAYS × cycles_per_day`, derived from the sensor's
        own fetch_interval so it auto-adjusts if cadence ever changes.
        """
        cycles_per_day = max(1, int(86400 / max(1, self.poll_interval)))
        cap = int(_os.getenv("NARRATIVE_BASELINE_DAYS", "30")) * cycles_per_day
        with self._lock:
            if theater not in self._baseline:
                self._baseline[theater] = {"daily_counts": [], "last_updated": 0.0}
            bl = self._baseline[theater]
            bl["daily_counts"].append(today_normalized)
            bl["daily_counts"] = bl["daily_counts"][-cap:]
            bl["last_updated"] = time.time()

    def fetch(self, context: dict) -> dict:
        # Narrative baseline is per-country. We cover every participant country
        # across all scorable scenarios so background scenarios receive intel
        # signal too (ADR-004).
        theaters        = (context.get("all_participant_countries")
                           or context.get("strategic_theaters", []))
        adversary_states = context.get("adversary_states", [])
        results: dict = {}
        t0 = time.time()
        total_hits = 0
        bursts_this_cycle = 0
        feeds_dead_this_cycle = 0
        from radar.llm_client import record_sensor_skip

        # Warn once for theaters that have TACTICAL_KEYWORDS but no GEO_TERMS
        if not hasattr(self, "_geo_warned"):
            self._geo_warned: set = set()
        for theater in theaters:
            if (theater not in NARRATIVE_GEO_TERMS
                    and theater in TACTICAL_KEYWORDS
                    and theater not in self._geo_warned):
                log.warning(
                    f"[RssNarrative] Theater {theater} has TACTICAL_KEYWORDS "
                    f"but no NARRATIVE_GEO_TERMS — geo filter will pass "
                    f"generic articles only"
                )
                self._geo_warned.add(theater)

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
                hits, articles = self._count_keywords_in_rss(
                    xml_text, keywords,
                    current_theater=theater,
                    all_geo_terms=NARRATIVE_GEO_TERMS,
                )
                combined_hits    += hits
                combined_articles += articles
                if xml_text:
                    fetched_sources.append(source_name)
                else:
                    feeds_dead_this_cycle += 1

            # Normalize by total article count (prevent division by zero)
            normalized = combined_hits / max(combined_articles, 1)

            z_score, mean_val, std_val = self._compute_zscore(theater, normalized)
            self._update_baseline(theater, normalized)

            status = "NORMAL"
            if z_score >= float(_os.getenv("NARRATIVE_ZSCORE_CRITICAL", "3.0")):
                status = "CRITICAL_BURST"
            elif z_score >= float(_os.getenv("NARRATIVE_ZSCORE_ALERT", "2.0")):
                status = "BURST"

            # On burst: collect matched articles and submit to LLM intel pipeline.
            # NOTE: This LLM submission stays in the sensor layer because it must
            # run at sensor fetch frequency (30min), not at API poll frequency (15s).
            # The intel_queue has its own dedup/confidence/auto_confirm pipeline.
            # Sequence event registration is handled by the scoring layer (core.py).
            if status in ("BURST", "CRITICAL_BURST"):
                bursts_this_cycle += 1
                for source_name, xml_text in xml_texts.items():
                    burst_article_pool.extend(
                        self._get_burst_articles(
                            xml_text, keywords, max_articles=2,
                            current_theater=theater,
                            all_geo_terms=NARRATIVE_GEO_TERMS,
                        )
                    )
                if burst_article_pool:
                    self._submit_narrative_burst_to_llm(
                        theater, burst_article_pool, z_score, fetched_sources, status
                    )
                else:
                    record_sensor_skip(f"burst_no_pool_articles:{theater}", caller="rss_narrative")

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

        # Cycle-level diagnostics: distinguish 'all theaters normal' (expected
        # silence) from 'all feeds dead' (broken pipeline).
        if theaters and bursts_this_cycle == 0:
            if feeds_dead_this_cycle and not any(
                results[t].get("article_count", 0) > 0 for t in results
            ):
                record_sensor_skip("all_feeds_dead", caller="rss_narrative")
            else:
                record_sensor_skip("no_burst_this_cycle", caller="rss_narrative")

        self.log_fetch(True, round((time.time() - t0) * 1000), 200, total_hits)
        result = {"narratives": results}
        self.set_cache(result)
        return result

