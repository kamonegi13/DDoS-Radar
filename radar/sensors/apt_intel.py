"""radar.sensors.apt_intel -- AptIntelSensor.

Monitors public security vendor blogs (RSS) for APT attribution reports and
submits LLM-analyzed items to the intel_queue.

Processing flow:
  RSS feeds (Google TAG / Microsoft Security / Palo Alto Unit42 / etc.)
  → parse recent articles (72h)
  → pre-filter by APT/threat-actor keywords
  → dedup by article-hash
  → LLM analysis: extract attributed_actor, actor_nexus, targeted_sector,
    ttp_category, theater, escalation_signal
  → intel_queue.submit() with source_type="apt_intel"

Distinct from DiplomaticSensor and MilitaryExerciseSensor:
  - Focuses on STATE-SPONSORED cyber actors (APT groups), not diplomacy or exercises
  - Bridges the gap for theaters (TW/KP) where direct military signaling is covert
  - Pre-positioning and espionage campaigns are leading indicators of kinetic action
  - Multiple vendors reporting the same actor simultaneously = activity surge signal
"""
from __future__ import annotations
import hashlib
import logging
import os
import time
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

import requests

from radar.sensors.base import BaseSensor
from radar.config import LLM_ENABLED, GLOBAL_PROXIES, SSL_VERIFY

log = logging.getLogger("radar")

_POLL_INTERVAL = int(os.getenv("APT_INTEL_POLL_INTERVAL", "3600"))  # 1 hour

# Public security vendor blog RSS sources.
# These publish APT attribution reports, threat actor profiles, and campaign analyses.
_APT_SOURCES = {
    "GOOGLE_TAG": {
        "url": "https://blog.google/threat-analysis-group/rss/",
        "vendor": "Google TAG",
        "nexus_focus": ["CN", "RU", "KP", "IR"],
    },
    "MICROSOFT_SECURITY": {
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "vendor": "Microsoft MSTIC",
        "nexus_focus": ["CN", "RU", "KP", "IR"],
    },
    "UNIT42": {
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "vendor": "Palo Alto Unit42",
        "nexus_focus": ["CN", "RU", "KP", "IR"],
    },
    "SENTINELONE": {
        "url": "https://www.sentinelone.com/blog/feed/",
        "vendor": "SentinelOne",
        "nexus_focus": ["CN", "RU", "KP"],
    },
    "RECORDEDFUTURE": {
        "url": "https://www.recordedfuture.com/feed",
        "vendor": "Recorded Future",
        "nexus_focus": ["CN", "RU", "KP", "IR"],
    },
    "CROWDSTRIKE": {
        "url": "https://www.crowdstrike.com/blog/feed/",
        "vendor": "CrowdStrike",
        "nexus_focus": ["CN", "RU", "KP", "IR"],
    },
    "MANDIANT": {
        "url": "https://www.mandiant.com/resources/blog/rss.xml",
        "vendor": "Mandiant",
        "nexus_focus": ["CN", "RU", "KP", "IR"],
    },
}

# Nexus (adversary state) to candidate theaters mapping.
# Used to provide LLM with candidate theaters when article doesn't specify.
_NEXUS_TO_THEATERS = {
    "CN": ["TW", "JP", "PH", "IN", "US", "AU"],
    "RU": ["UA", "PL", "LT", "LV", "EE", "FI", "DE", "US"],
    "KP": ["KR", "JP", "US"],
    "IR": ["IL", "SA", "AE", "US"],
}

# Keywords to pre-filter articles as APT/threat-actor relevant before LLM call.
_APT_KEYWORDS = [
    # Actor names / aliases
    "apt", "volt typhoon", "salt typhoon", "hafnium", "fancy bear", "cozy bear",
    "lazarus", "kimsuky", "apt41", "apt28", "apt29", "sandworm", "turla",
    "charming kitten", "muddy water", "dragonbridge", "gothic panda",
    "threat actor", "threat group", "state-sponsored", "nation-state",
    # TTP categories relevant to pre-conflict
    "pre-positioning", "living off the land", "critical infrastructure",
    "supply chain", "zero-day", "backdoor", "espionage", "cyber espionage",
    "attribution", "campaign", "intrusion",
    # Geographic focus
    "taiwan", "semiconductor", "south china sea", "korean peninsula",
    "ukraine", "nato", "middle east",
]

# Processed article hashes to avoid reprocessing
_processed: set[str] = set()
_MAX_PROCESSED = 1000


def _article_hash(source_name: str, title: str) -> str:
    raw = f"apt-{source_name}-{title[:60]}"
    return hashlib.md5(raw.encode()).hexdigest()


def _fetch_rss(url: str) -> str:
    try:
        resp = requests.get(
            url, timeout=15,
            proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
            headers={"User-Agent": "Mozilla/5.0 (OSINT-Radar/8.0)"},
        )
        if resp.status_code == 200:
            return resp.text
        if resp.status_code == 429:
            log.debug(f"[AptIntel] 429 rate-limited: {url}")
    except Exception as e:
        log.debug(f"[AptIntel] Fetch failed {url}: {e}")
    return ""


def _parse_articles(xml_text: str, max_age_h: int = 72) -> list[dict]:
    """Parse RSS XML and return recent APT-relevant articles."""
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    cutoff = time.time() - max_age_h * 3600
    articles = []
    seen_titles: set[str] = set()
    kw_lower = [k.lower() for k in _APT_KEYWORDS]

    for item in root.iter("item"):
        title_el   = item.find("title")
        desc_el    = item.find("description")
        pubdate_el = item.find("pubDate")
        link_el    = item.find("link")

        title   = (title_el.text   or "").strip() if title_el   is not None else ""
        summary = (desc_el.text    or "").strip() if desc_el    is not None else ""
        pubdate = (pubdate_el.text or "").strip() if pubdate_el is not None else ""
        link    = (link_el.text    or "").strip() if link_el    is not None else ""

        title_key = "".join(c for c in title.lower()[:60] if c.isalnum())
        if title_key and title_key in seen_titles:
            continue
        if title_key:
            seen_titles.add(title_key)

        pub_ts = 0.0
        if pubdate:
            try:
                pub_ts = parsedate_to_datetime(pubdate).timestamp()
            except Exception:
                pass

        if pub_ts > 0 and pub_ts < cutoff:
            continue

        text_lower = (title + " " + summary).lower()
        if not any(kw in text_lower for kw in kw_lower):
            continue

        articles.append({
            "title":   title,
            "summary": summary[:500],
            "pub_ts":  pub_ts,
            "link":    link,
        })

        if len(articles) >= 5:
            break

    return articles


class AptIntelSensor(BaseSensor):
    """Monitors security vendor blogs for APT attribution reports as pre-conflict indicators."""

    def __init__(self):
        super().__init__("apt_intel", "cyber", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"apt_intel": {"llm_disabled": True}}

        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available

        if not llm_available():
            log.debug("[AptIntel] LLM not available — skipping")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"apt_intel": {"llm_offline": True}}

        strategic_theaters = set(context.get("strategic_theaters", []))
        t0 = time.time()
        submitted = 0

        for source_name, meta in _APT_SOURCES.items():
            # Determine candidate theaters: intersection of nexus-mapped theaters
            # and currently active strategic theaters
            candidate_theaters: list[str] = []
            for nexus in meta["nexus_focus"]:
                for t in _NEXUS_TO_THEATERS.get(nexus, []):
                    if t not in candidate_theaters:
                        if not strategic_theaters or t in strategic_theaters:
                            candidate_theaters.append(t)

            if not candidate_theaters:
                continue

            xml_text = _fetch_rss(meta["url"])
            articles = _parse_articles(xml_text)
            if not articles:
                continue

            vendor = meta["vendor"]
            theaters_str = ", ".join(candidate_theaters)

            for art in articles:
                key = _article_hash(source_name, art["title"])
                if key in _processed:
                    continue
                _processed.add(key)

                if len(_processed) > _MAX_PROCESSED:
                    to_remove = list(_processed)[:_MAX_PROCESSED // 2]
                    for k in to_remove:
                        _processed.discard(k)

                article_text = f"{art['title']}\n{art['summary'][:500]}"

                system_prompt = (
                    "You are a cyber threat intelligence analyst specializing in "
                    "state-sponsored APT groups and their geopolitical implications. "
                    "Analyze this security vendor report for escalation signals relevant "
                    f"to any of these theaters: {theaters_str}. "
                    "Respond ONLY with a JSON object, no explanation."
                )
                user_prompt = (
                    f"Source: {vendor} threat intelligence blog\n"
                    f"Candidate theaters: {theaters_str}\n\n"
                    f"Article:\n{article_text}\n\n"
                    "Return a JSON object:\n"
                    "{\n"
                    '  "headline": "One-sentence escalation summary (max 100 chars)",\n'
                    '  "escalation_signal": true or false,\n'
                    '  "theater": "Single most relevant theater code from candidate list",\n'
                    '  "attributed_actor": "APT group name or alias (e.g. Volt Typhoon)",\n'
                    '  "actor_nexus": "State sponsor ISO code (CN/RU/KP/IR/XX)",\n'
                    '  "targeted_sector": "critical_infrastructure|government|military|financial|telecom|defense_industrial|academic|unknown",\n'
                    '  "ttp_category": "pre-positioning|active-exploitation|espionage|sabotage|financial|disruption|unknown",\n'
                    '  "urgency": "critical|high|medium|low",\n'
                    '  "confidence": 0.0\n'
                    "}\n"
                    "Confidence guide:\n"
                    "- 0.80-0.95: Confirmed attribution to state nexus + active campaign against theater\n"
                    "- 0.65-0.79: Strong indicators of state-nexus actor targeting theater infrastructure\n"
                    "- 0.55-0.64: Possible state-nexus activity with theater relevance\n"
                    "- <0.55: Generic threat intel, no specific theater relevance (escalation_signal=false)\n"
                    "pre-positioning and sabotage TTPs against critical infrastructure: always escalation_signal=true.\n"
                    "If article discusses only historical activity or has no theater relevance: confidence<0.40."
                )

                result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=300)

                if not result["ok"]:
                    log.debug(f"[AptIntel] LLM parse failed {source_name}: {result.get('error')}")
                    continue

                data = result["data"]
                confidence = float(data.get("confidence", 0.0))

                if not data.get("escalation_signal", False) or confidence < 0.55:
                    log.debug(f"[AptIntel] No signal {source_name} conf={confidence:.2f}")
                    continue

                llm_theater = data.get("theater", "").strip().upper()
                theater = llm_theater if llm_theater in candidate_theaters else (candidate_theaters[0] if candidate_theaters else "")
                if not theater:
                    continue

                ttp = data.get("ttp_category", "unknown")
                urgency = data.get("urgency", "medium")
                # Score reflects severity: sabotage/pre-positioning are leading indicators
                ttp_score = {
                    "sabotage":            3.5,
                    "active-exploitation": 3.0,
                    "pre-positioning":     2.5,
                    "disruption":          2.5,
                    "espionage":           1.5,
                    "financial":           1.0,
                    "unknown":             1.0,
                }.get(ttp, 1.0)
                urgency_mult = {"critical": 1.3, "high": 1.1, "medium": 1.0, "low": 0.8}.get(urgency, 1.0)
                score_delta = round(ttp_score * urgency_mult, 1)

                item = {
                    "source_type":  "apt_intel",
                    "source_id":    f"apt_{source_name.lower()}",
                    "theater":      theater,
                    "ts":           time.time(),
                    "confidence":   round(confidence, 3),
                    "raw_text":     article_text[:1000],
                    "raw_url":      art.get("link", ""),
                    "headline":     data.get("headline", f"APT activity: {data.get('attributed_actor','unknown')} / {theater}")[:100],
                    "llm_fields": {
                        "attributed_actor": data.get("attributed_actor", "unknown"),
                        "actor_nexus":      data.get("actor_nexus", "XX"),
                        "targeted_sector":  data.get("targeted_sector", "unknown"),
                        "ttp_category":     ttp,
                        "urgency":          urgency,
                        "vendor":           vendor,
                        "escalation_signal": True,
                    },
                    "score_delta":  score_delta,
                    "domain":       "cyber",
                }

                item_id = intel_queue.submit(item)
                if item_id:
                    submitted += 1
                    log.info(
                        f"[AptIntel] Submitted: {item['headline'][:60]} "
                        f"(src={source_name}, theater={theater}, actor={data.get('attributed_actor','?')}, "
                        f"ttp={ttp}, conf={confidence:.2f})"
                    )

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(True, duration_ms, 0, submitted)
        result_data = {"apt_intel": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
