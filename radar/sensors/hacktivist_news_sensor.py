"""radar.sensors.hacktivist_news_sensor -- HacktivistNewsSensor.

Monitors security news RSS feeds for hacktivist campaign reporting and DDoS
attack coverage.  Supplements the Telegram mirror sensor by providing an
"observation of observers" layer — security journalists and researchers who
monitor private Telegram channels publish their findings on public news sites.

Processing flow:
  Security news RSS feeds (BleepingComputer, TheRecord, CyberScoop, etc.)
  → parse recent articles (48h)
  → pre-filter by hacktivist/DDoS keywords
  → dedup by article hash
  → LLM analysis: extract group, theater, attack_type, urgency
  → intel_queue.submit() with source_type="hacktivist"

Data source properties:
  - Free, open, no authentication required
  - OPSEC-safe (anonymous HTTP, indistinguishable from normal RSS readers)
  - Latency: hours behind Telegram (acceptable for strategic warning)
  - High signal quality: journalist-verified, lower false positive rate
"""
from __future__ import annotations
import hashlib
import logging
import os
import threading
import time
import defusedxml.ElementTree as ET
from email.utils import parsedate_to_datetime

import requests

from radar.sensors.base import BaseSensor
from radar.config import LLM_ENABLED, GLOBAL_PROXIES, SSL_VERIFY, COUNTRY_COORDS

log = logging.getLogger("radar")

_POLL_INTERVAL = int(os.getenv("HACKTIVIST_NEWS_POLL_INTERVAL", "1800"))  # 30 min

# Security news RSS sources that regularly cover hacktivist campaigns.
# All are free, public, and require no API key.
_NEWS_SOURCES = {
    "BLEEPING_COMPUTER": {
        "url": "https://www.bleepingcomputer.com/feed/",
        "org": "BleepingComputer",
    },
    "THE_RECORD": {
        "url": "https://therecord.media/feed",
        "org": "TheRecord",
    },
    "THE_HACKER_NEWS": {
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "org": "TheHackerNews",
    },
    "CYBERSCOOP": {
        "url": "https://cyberscoop.com/feed/",
        "org": "CyberScoop",
    },
    "DARK_READING": {
        "url": "https://www.darkreading.com/rss.xml",
        "org": "DarkReading",
    },
}

# Pre-filter keywords: hacktivist campaign language.
# These focus on ACTIVE CAMPAIGN reporting, not generic security news.
_HACKTIVIST_KEYWORDS = [
    # Group names (most prolific current groups)
    "noname057", "killnet", "cyber army of russia", "anonymous sudan",
    "dragonforce", "mysterious team", "it army of ukraine",
    "darkstorm", "siegedsec", "indian cyber force", "ghostclan",
    "people's cyber army", "xaknet", "sylhet gang",
    # Attack type language
    "ddos attack", "ddos campaign", "distributed denial",
    "hacktivist", "hacktivism", "hacktivist group",
    "defacement", "data leak", "hack-and-leak",
    # Campaign/targeting language
    "claimed responsibility", "attack claimed", "targeted by",
    "cyberattack on", "cyber attack on", "took down", "knocked offline",
    "government websites", "government sites",
    "critical infrastructure attack",
    # DDoS-specific tools/techniques
    "ddosia", "botnet attack", "http flood", "layer 7",
]

# Keywords indicating resolved/historical/marketing content — discard
_DISCARD_KEYWORDS = [
    "how to protect", "best practices", "product review",
    "webinar", "ebook", "whitepaper", "sponsored",
]

_processed: dict[str, None] = {}
_processed_lock = threading.Lock()
_MAX_PROCESSED = 500


def _article_hash(source_name: str, title: str) -> str:
    raw = f"hacknews-{source_name}-{title[:60]}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


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
            log.debug(f"[HackNews] 429 rate-limited: {url}")
    except Exception as e:
        log.debug(f"[HackNews] Fetch failed {url}: {e}")
    return ""


def _parse_articles(xml_text: str, max_age_h: int = 48) -> list[dict]:
    """Parse RSS XML and return recent hacktivist-relevant articles.
    Supports both RSS 2.0 (<item>) and Atom (<entry>) formats.
    """
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        log.debug("[HackNews] RSS XML parse error")
        return []

    cutoff = time.time() - max_age_h * 3600
    articles = []
    seen: set[str] = set()
    kw_lower = [k.lower() for k in _HACKTIVIST_KEYWORDS]
    dis_kw = [k.lower() for k in _DISCARD_KEYWORDS]

    # Handle both RSS 2.0 and Atom namespaces
    ns = {"atom": "http://www.w3.org/2005/Atom"}

    for item in list(root.iter("item")) + list(root.iter("{http://www.w3.org/2005/Atom}entry")):
        # RSS 2.0 fields
        title_el = item.find("title") or item.find("atom:title", ns)
        desc_el = (item.find("description") or item.find("atom:summary", ns)
                   or item.find("atom:content", ns))
        pubdate_el = (item.find("pubDate") or item.find("atom:published", ns)
                      or item.find("atom:updated", ns))
        link_el = item.find("link") or item.find("atom:link", ns)

        title = (title_el.text or "").strip() if title_el is not None else ""
        summary = (desc_el.text or "").strip() if desc_el is not None else ""
        pubdate = (pubdate_el.text or "").strip() if pubdate_el is not None else ""

        # Handle Atom link (may be in href attribute)
        if link_el is not None:
            link = link_el.get("href", "") or (link_el.text or "").strip()
        else:
            link = ""

        # Dedup by normalized title
        title_key = "".join(c for c in title.lower()[:60] if c.isalnum())
        if title_key and title_key in seen:
            continue
        if title_key:
            seen.add(title_key)

        # Parse publication date
        pub_ts = 0.0
        if pubdate:
            try:
                pub_ts = parsedate_to_datetime(pubdate).timestamp()
            except Exception:
                # Try ISO 8601 format (common in Atom feeds)
                try:
                    from datetime import datetime, timezone
                    pub_ts = datetime.fromisoformat(
                        pubdate.replace("Z", "+00:00")
                    ).timestamp()
                except Exception:
                    pass

        if pub_ts > 0 and pub_ts < cutoff:
            continue

        # Strip HTML tags from summary
        import re
        summary_clean = re.sub(r'<[^>]+>', ' ', summary)
        summary_clean = re.sub(r'\s+', ' ', summary_clean).strip()

        text_lower = (title + " " + summary_clean).lower()

        # Hard discard: marketing/generic language
        if any(kw in text_lower for kw in dis_kw):
            continue

        # Require hacktivist keyword match
        if not any(kw in text_lower for kw in kw_lower):
            continue

        articles.append({
            "title": title,
            "summary": summary_clean[:500],
            "pub_ts": pub_ts,
            "link": link,
        })

        if len(articles) >= 5:
            break

    return articles


class HacktivistNewsSensor(BaseSensor):
    """Monitors security news RSS feeds for hacktivist campaign reporting."""

    def __init__(self):
        super().__init__("hacktivist_news", "info", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"hacktivist_news": {"llm_disabled": True}}

        from radar.intel_queue import intel_queue
        from radar.llm_client import (
            llm_analyze_json, llm_available, record_sensor_drop, record_sensor_skip,
            safe_float, safe_enum, sanitize_llm_input, today_str,
        )

        if not llm_available():
            log.debug("[HackNews] LLM not available — skipping")
            record_sensor_skip("llm_unavailable", caller="hacktivist_news")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"hacktivist_news": {"llm_offline": True}}

        # LLM sensor covers every participant country across all scorable
        # scenarios (ADR-004).
        strategic_theaters = set(context.get("all_participant_countries")
                                  or context.get("strategic_theaters", []))
        t0 = time.time()
        submitted = 0
        any_feed_ok = False
        feeds_dead = 0
        feeds_no_articles = 0

        for source_name, meta in _NEWS_SOURCES.items():
            xml_text = _fetch_rss(meta["url"])
            if xml_text:
                any_feed_ok = True
            else:
                feeds_dead += 1
                record_sensor_skip(f"feed_fetch_failed:{source_name}", caller="hacktivist_news")
            articles = _parse_articles(xml_text)
            if not articles:
                if xml_text:
                    feeds_no_articles += 1
                    # 2026-04-29: classify the failure mode like diplomatic
                    # so audits separate "URL stale" from "filter strict
                    # against a healthy feed". Live audit showed all 5
                    # cyber-news feeds are healthy (rss_with_items) but
                    # hacktivist_keyword match rate is genuinely ~2% —
                    # this is base-rate β, not implementation α. Tagging
                    # accordingly so the next audit reports it correctly.
                    try:
                        from radar.sensors.diplomatic import _classify_feed
                        feed_class = _classify_feed(xml_text)
                    except Exception:
                        feed_class = "unknown"
                    if feed_class == "returns_html":
                        record_sensor_skip(f"feed_url_stale_html:{source_name}", caller="hacktivist_news")
                    elif feed_class == "rss_empty":
                        record_sensor_skip(f"feed_empty:{source_name}", caller="hacktivist_news")
                    elif feed_class == "unparseable":
                        record_sensor_skip(f"feed_unparseable:{source_name}", caller="hacktivist_news")
                    else:
                        # Healthy feed, filter rejected all articles — likely
                        # genuine base rate (hacktivist coverage in mainstream
                        # cyber news is sparse). Distinct from a stale URL.
                        record_sensor_skip(
                            f"no_kw_match_healthy_feed:{source_name}",
                            caller="hacktivist_news",
                        )
                continue

            org = meta["org"]
            new_articles_this_feed = 0

            for art in articles:
                key = _article_hash(source_name, art["title"])
                with _processed_lock:
                    if key in _processed:
                        continue
                    _processed[key] = None
                    if len(_processed) > _MAX_PROCESSED:
                        for k in list(_processed)[:_MAX_PROCESSED // 2]:
                            _processed.pop(k, None)
                new_articles_this_feed += 1

                safe_title = sanitize_llm_input(art["title"], 120)
                safe_summary = sanitize_llm_input(art["summary"], 500)
                article_text = f"{art['title']}\n{art['summary'][:500]}"

                theaters_str = ", ".join(sorted(strategic_theaters)) if strategic_theaters else "any"

                system_prompt = (
                    "You are a cyber threat intelligence analyst specializing in "
                    "hacktivist groups and DDoS campaigns. Analyze this security "
                    "news article for active hacktivist threat intelligence. "
                    "Respond ONLY with a JSON object, no explanation."
                )
                user_prompt = (
                    f"Today's date: {today_str()}\n"
                    f"Source: {org} security news\n"
                    f"Active strategic theaters: {theaters_str}\n\n"
                    f"Article:\n{safe_title}\n{safe_summary}\n\n"
                    "Return a JSON object:\n"
                    "{\n"
                    '  "headline": "One-sentence threat summary (max 100 chars)",\n'
                    '  "is_active_campaign": true or false,\n'
                    '  "group_name": "Hacktivist group name or unknown",\n'
                    '  "theater": "ISO country code of PRIMARY target, or null",\n'
                    '  "countries": ["ISO codes of ALL targeted countries"],\n'
                    '  "country_weights": {"ISO": 0.0-1.0 relevance weight per country},\n'
                    '  "attack_type": "DDoS|defacement|data_leak|combined|none",\n'
                    '  "target_sector": "government|military|financial|telecom|'
                    'energy|media|transport|healthcare|unknown",\n'
                    '  "urgency": "critical|high|medium|low",\n'
                    '  "confidence": 0.0\n'
                    "}\n"
                    "is_active_campaign = true ONLY if the article describes an "
                    "ONGOING or RECENT (within 48h) hacktivist campaign — not a "
                    "historical retrospective or generic trend piece.\n"
                    "theater must be null if no specific target country is named.\n"
                    "IMPORTANT: The 'active strategic theaters' list is for CONTEXT only. "
                    "Do NOT force-assign a theater from that list. Assign theater based "
                    "solely on the country ACTUALLY targeted in the article. If the "
                    "targeted country is not in the list, still return its ISO code — "
                    "the system will handle filtering.\n"
                    "Confidence guide:\n"
                    "- 0.80-0.95: Named group + named target + confirmed ongoing attack\n"
                    "- 0.65-0.79: Named group + target country, attack reported\n"
                    "- 0.40-0.64: Campaign mentioned but details vague\n"
                    "- <0.40: No actionable intelligence"
                )

                from radar.llm_routing import UseCase
                result = llm_analyze_json(
                    user_prompt, system=system_prompt, max_tokens=250,
                    use_case=UseCase.SENSOR_EXTRACT,
                )

                if not result["ok"]:
                    log.debug(
                        f"[HackNews] LLM parse failed {source_name}: "
                        f"{result.get('error')}"
                    )
                    continue

                data = result["data"]
                confidence = safe_float(data.get("confidence"), default=0.0)

                if not data.get("is_active_campaign", False):
                    log.debug(
                        f"[HackNews] Not active campaign: "
                        f"{art['title'][:60]}"
                    )
                    record_sensor_drop("not_active_campaign")
                    continue

                if confidence < 0.35:
                    log.debug(
                        f"[HackNews] Low confidence {confidence:.2f}: "
                        f"{art['title'][:60]}"
                    )
                    record_sensor_drop("below_floor")
                    continue

                # Parse multi-country output (Phase 3)
                raw_countries = data.get("countries") or []
                raw_weights = data.get("country_weights") or {}
                countries = [c.strip().upper() for c in raw_countries
                             if isinstance(c, str) and len(c.strip()) == 2]
                country_weights = {}
                for c in countries:
                    w = raw_weights.get(c, raw_weights.get(c.lower(), 1.0))
                    country_weights[c] = max(0.0, min(1.0, safe_float(w, default=1.0)))

                # Theater validation
                theater = (data.get("theater") or "").strip().upper() or None
                if not theater or theater in ("NULL", "NONE"):
                    log.debug(
                        f"[HackNews] No theater: {art['title'][:60]}"
                    )
                    record_sensor_drop("no_theater")
                    continue

                if strategic_theaters and theater not in strategic_theaters:
                    log.debug(
                        f"[HackNews] Theater {theater} not strategic: "
                        f"{art['title'][:60]}"
                    )
                    record_sensor_drop("theater_not_strategic")
                    continue

                if theater not in countries:
                    countries = [theater] + countries
                    country_weights.setdefault(theater, 1.0)

                urgency = safe_enum(
                    data.get("urgency"),
                    {"critical", "high", "medium", "low"}, "medium",
                )
                attack_type = safe_enum(
                    data.get("attack_type"),
                    {"DDoS", "defacement", "data_leak", "combined", "none"},
                    "DDoS",
                )

                # Scoring: base by urgency, type bonus
                base = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}
                type_bonus = {"DDoS": 0.5, "combined": 0.5, "defacement": 0.3,
                              "data_leak": 0.2, "none": 0.0}
                score_delta = round(
                    base.get(urgency, 1.0) + type_bonus.get(attack_type, 0.0),
                    1,
                )

                item = {
                    "source_type": "hacktivist",
                    "source_id": f"hacknews_{source_name.lower()}",
                    "theater": theater,
                    "countries": countries,
                    "country_weights": country_weights,
                    "ts": time.time(),
                    "confidence": round(confidence, 3),
                    "raw_text": article_text[:1000],
                    "raw_url": art.get("link", ""),
                    "headline": data.get(
                        "headline",
                        f"Hacktivist campaign: {data.get('group_name', '?')} / {theater}",
                    )[:100],
                    "llm_fields": {
                        "group_name": data.get("group_name", "unknown"),
                        "attack_type": attack_type,
                        "target_sector": data.get("target_sector", "unknown"),
                        "urgency": urgency,
                        "source_org": org,
                        "news_source": True,
                    },
                    "score_delta": score_delta,
                    "domain": "info",
                }

                item_id = intel_queue.submit(item)
                if item_id:
                    submitted += 1
                    log.info(
                        f"[HackNews] Submitted: {item['headline'][:60]} "
                        f"(src={source_name}, theater={theater}, "
                        f"group={data.get('group_name', '?')}, "
                        f"conf={confidence:.2f})"
                    )

            if articles and new_articles_this_feed == 0:
                record_sensor_skip(f"all_dedup:{source_name}", caller="hacktivist_news")

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(any_feed_ok, duration_ms, 0, submitted)
        result_data = {"hacktivist_news": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
