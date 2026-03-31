"""radar.sensors.diplomatic -- DiplomaticSensor.

Monitors official government/diplomatic RSS feeds for escalation signals and
submits LLM-analyzed items to the intel_queue.

Processing flow:
  RSS feeds (MOFA / State Dept / MFA) → parse recent articles (24h)
  → dedup by article-hash → LLM escalation analysis (per source-theater pair)
  → intel_queue.submit() with source_type="diplomatic"

Compared to RssNarrativeSensor (which measures keyword frequency Z-scores),
DiplomaticSensor focuses on:
  - Official government statements, not adversary media
  - Individual article-level LLM analysis (not statistical baseline comparison)
  - Structured extraction: diplomatic_action, target_country, urgency, escalation_signal
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

_POLL_INTERVAL = int(os.getenv("DIPLOMATIC_POLL_INTERVAL", "3600"))  # 1 hour

# Official diplomatic RSS sources, each mapped to relevant theaters.
# Sources that report on multiple theaters are listed with all relevant ones.
_DIPLOMATIC_SOURCES = {
    "US_STATE": {
        "url": "https://www.state.gov/press-releases/feed/",
        "country": "US",
        "theaters": ["TW", "UA", "KP", "IR", "IL", "JP", "PH"],
    },
    "JP_MOFA": {
        "url": "https://www.mofa.go.jp/rss/rss.xml",
        "country": "JP",
        "theaters": ["TW", "JP", "KP", "CN"],
    },
    "CN_MFA": {
        "url": "https://www.fmprc.gov.cn/mfa_eng/rss.xml",
        "country": "CN",
        "theaters": ["TW", "JP", "PH", "IN"],
    },
    "TW_MOFA": {
        "url": "https://en.mofa.gov.tw/rss.aspx",
        "country": "TW",
        "theaters": ["TW"],
    },
    "RU_MFA": {
        "url": "https://mid.ru/en/rss.xml",
        "country": "RU",
        "theaters": ["UA"],
    },
    "KCNA_WATCH": {
        "url": "https://kcnawatch.org/feed/",
        "country": "KP",
        "theaters": ["KP", "JP"],
    },
    "NATO": {
        "url": "https://www.nato.int/cps/en/natolive/news.htm?rss=y",
        "country": "NATO",
        "theaters": ["UA"],
    },
}

# Escalation-relevant keywords to pre-filter articles before sending to LLM
_ESC_KEYWORDS = [
    "military", "warning", "condemn", "sanction", "expel", "recall",
    "sovereignty", "incursion", "invasion", "threat", "provocation",
    "mobilize", "deploy", "exercise", "posture", "ultimatum", "ceasefire",
    "missile", "nuclear", "blockade", "strait", "escalat", "conflict",
    "aggression", "violation", "retaliat",
    # Japanese/Chinese transliterations in English text
    "taiwan strait", "south china sea", "senkaku", "diaoyu",
    "korean peninsula", "indo-pacific",
]

# Processed article hashes to avoid reprocessing
_processed: set[str] = set()
_MAX_PROCESSED = 1000


def _article_hash(source_name: str, title: str) -> str:
    """Hash keyed on article identity only (not theater) to prevent duplicate submissions."""
    raw = f"dipl-{source_name}-{title[:60]}"
    return hashlib.md5(raw.encode()).hexdigest()


def _fetch_rss(url: str) -> str:
    """Fetch RSS feed text. Returns empty string on failure."""
    try:
        resp = requests.get(
            url, timeout=15,
            proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
            headers={"User-Agent": "Mozilla/5.0 (OSINT-Radar/8.0)"},
        )
        if resp.status_code == 200:
            return resp.text
        if resp.status_code == 429:
            log.debug(f"[Diplomatic] 429 rate-limited: {url}")
    except Exception as e:
        log.debug(f"[Diplomatic] Fetch failed {url}: {e}")
    return ""


def _parse_articles(xml_text: str, max_age_h: int = 48) -> list[dict]:
    """Parse RSS XML and return recent articles as dicts with title, summary, pub_ts."""
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    cutoff = time.time() - max_age_h * 3600
    articles = []
    seen_titles: set[str] = set()

    for item in root.iter("item"):
        title_el   = item.find("title")
        desc_el    = item.find("description")
        pubdate_el = item.find("pubDate")
        link_el    = item.find("link")

        title   = (title_el.text   or "").strip() if title_el   is not None else ""
        summary = (desc_el.text    or "").strip() if desc_el    is not None else ""
        pubdate = (pubdate_el.text or "").strip() if pubdate_el is not None else ""
        link    = (link_el.text    or "").strip() if link_el    is not None else ""

        # Dedup by title
        title_key = "".join(c for c in title.lower()[:60] if c.isalnum())
        if title_key and title_key in seen_titles:
            continue
        if title_key:
            seen_titles.add(title_key)

        # Parse pub date
        pub_ts = 0.0
        if pubdate:
            try:
                pub_ts = parsedate_to_datetime(pubdate).timestamp()
            except Exception:
                pass

        # Skip articles older than cutoff (if date available)
        if pub_ts > 0 and pub_ts < cutoff:
            continue

        # Pre-filter: only articles with escalation-relevant keywords
        text_lower = (title + " " + summary).lower()
        if not any(kw in text_lower for kw in _ESC_KEYWORDS):
            continue

        articles.append({
            "title":   title,
            "summary": summary[:400],
            "pub_ts":  pub_ts,
            "link":    link,
        })

        if len(articles) >= 5:  # Cap at 5 per source
            break

    return articles


class DiplomaticSensor(BaseSensor):
    """Monitors official diplomatic RSS feeds for escalation signals."""

    def __init__(self):
        super().__init__("diplomatic", "info", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"diplomatic": {"llm_disabled": True}}

        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available

        if not llm_available():
            log.debug("[Diplomatic] LLM not available — skipping")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"diplomatic": {"llm_offline": True}}

        strategic_theaters = set(context.get("strategic_theaters", []))
        t0 = time.time()
        submitted = 0

        for source_name, meta in _DIPLOMATIC_SOURCES.items():
            theaters = [t for t in meta["theaters"] if t in strategic_theaters or not strategic_theaters]
            if not theaters:
                continue

            xml_text = _fetch_rss(meta["url"])
            articles = _parse_articles(xml_text)
            if not articles:
                continue

            # Dedup at article level (not theater level) to prevent same article
            # being submitted once per theater.
            new_articles = []
            for art in articles:
                key = _article_hash(source_name, art["title"])
                if key not in _processed:
                    new_articles.append((key, art))
                    _processed.add(key)
            if not new_articles:
                continue

            if len(_processed) > _MAX_PROCESSED:
                to_remove = list(_processed)[:_MAX_PROCESSED // 2]
                for k in to_remove:
                    _processed.discard(k)

            country = meta["country"]
            articles_text = "\n".join(
                f"[{i+1}] {a['title']}\n  {a['summary'][:200]}"
                for i, (_, a) in enumerate(new_articles[:3])
            )
            theaters_str = ", ".join(theaters)

            # Single LLM call per source: ask LLM to identify the most relevant theater
            system_prompt = (
                "You are a diplomatic intelligence analyst. "
                "Analyze these official government statements for escalation signals "
                f"relevant to any of these theaters: {theaters_str}. "
                "Respond ONLY with a JSON object, no explanation."
            )
            user_prompt = (
                f"Source: {country} official diplomatic statements\n"
                f"Relevant theaters: {theaters_str}\n\n"
                f"Recent statements:\n{articles_text}\n\n"
                "Return a JSON object:\n"
                "{\n"
                '  "headline": "One-sentence escalation summary (max 100 chars)",\n'
                '  "escalation_signal": true or false,\n'
                '  "theater": "The single most relevant theater code from the list above",\n'
                '  "diplomatic_action": "warning|condemnation|sanction|expulsion|military_posture|ceasefire|statement|none",\n'
                '  "target_country": "Country being addressed or criticized",\n'
                '  "urgency": "critical|high|medium|low",\n'
                '  "confidence": 0.0\n'
                "}\n"
                "Confidence guide:\n"
                "- 0.80-0.95: Explicit military warning or sanction announcement\n"
                "- 0.65-0.79: Strong condemnation or posturing language\n"
                "- 0.55-0.64: Relevant but ambiguous diplomatic language\n"
                "- <0.55: Routine statement, no escalation signal (set escalation_signal=false)\n"
                "If statements have no relevance to any theater, return confidence<0.40."
            )

            result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=256)

            if not result["ok"]:
                log.debug(f"[Diplomatic] LLM parse failed {source_name}: {result.get('error')}")
                continue

            data = result["data"]
            confidence = float(data.get("confidence", 0.0))

            if not data.get("escalation_signal", False) or confidence < 0.55:
                log.debug(f"[Diplomatic] No signal {source_name} conf={confidence:.2f}")
                continue

            # Use theater from LLM response if valid, otherwise first in list
            llm_theater = data.get("theater", "").strip().upper()
            theater = llm_theater if llm_theater in theaters else theaters[0]

            urgency = data.get("urgency", "low")
            score_delta = {"critical": 3.0, "high": 2.0, "medium": 1.5, "low": 1.0}.get(urgency, 1.0)

            raw_url = new_articles[0][1].get("link", "")

            item = {
                "source_type":  "diplomatic",
                "source_id":    f"diplomatic_{source_name.lower()}",
                "theater":      theater,
                "ts":           time.time(),
                "confidence":   round(confidence, 3),
                "raw_text":     articles_text[:1000],
                "raw_url":      raw_url,
                "headline":     data.get("headline", f"Diplomatic escalation signal: {source_name} / {theater}")[:100],
                "llm_fields": {
                    "diplomatic_action": data.get("diplomatic_action", "statement"),
                    "target_country":    data.get("target_country", ""),
                    "urgency":           urgency,
                    "source_country":    country,
                    "escalation_signal": True,
                },
                "score_delta":  score_delta,
                "domain":       "info",
            }

            item_id = intel_queue.submit(item)
            if item_id:
                submitted += 1
                log.info(
                    f"[Diplomatic] Submitted: {item['headline'][:60]} "
                    f"(src={source_name}, theater={theater}, conf={confidence:.2f}, urgency={urgency})"
                )

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(True, duration_ms, 0, submitted)
        result_data = {"diplomatic": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
