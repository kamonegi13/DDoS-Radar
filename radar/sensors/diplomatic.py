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
import threading
import time
import defusedxml.ElementTree as ET
from email.utils import parsedate_to_datetime

import requests

from radar.sensors.base import BaseSensor
from radar.config import LLM_ENABLED, GLOBAL_PROXIES, SSL_VERIFY, COUNTRY_COORDS

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

# Processed article hashes to avoid reprocessing (dict preserves insertion order for LRU)
_processed: dict[str, None] = {}
_processed_lock = threading.Lock()
_MAX_PROCESSED = 1000


def _article_hash(source_name: str, title: str) -> str:
    """Hash keyed on article identity only (not theater) to prevent duplicate submissions."""
    raw = f"dipl-{source_name}-{title[:60]}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


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


def _theater_names(theaters: list[str]) -> list[str]:
    """Resolve theater codes to lowercase country/region names for text matching."""
    names = []
    for code in theaters:
        entry = COUNTRY_COORDS.get(code, {})
        name = entry.get("name", "")
        if name:
            names.append(name.lower())
    return names


def _parse_articles(xml_text: str, max_age_h: int = 48,
                    theater_names: list[str] | None = None) -> list[dict]:
    """Parse RSS XML and return recent articles as dicts with title, summary, pub_ts.
    Two-slot system:
      Slot 1: up to 5 articles matching escalation keywords
      Slot 2: up to 2 articles matching only theater names (no keyword match)
    """
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        log.debug("[Diplomatic] RSS XML parse error")
        return []

    cutoff = time.time() - max_age_h * 3600
    keyword_articles = []
    theater_only_articles = []
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

        art = {"title": title, "summary": summary[:400], "pub_ts": pub_ts, "link": link}
        text_lower = (title + " " + summary).lower()

        # Slot 1: escalation keyword match (up to 5)
        if any(kw in text_lower for kw in _ESC_KEYWORDS):
            if len(keyword_articles) < 5:
                keyword_articles.append(art)
            continue

        # Slot 2: theater-name-only match (up to 2) — no keyword hit
        if theater_names and any(tn in text_lower for tn in theater_names):
            if len(theater_only_articles) < 2:
                theater_only_articles.append(art)

        if len(keyword_articles) >= 5 and len(theater_only_articles) >= 2:
            break

    return keyword_articles + theater_only_articles


class DiplomaticSensor(BaseSensor):
    """Monitors official diplomatic RSS feeds for escalation signals."""

    def __init__(self):
        super().__init__("diplomatic", "info", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"diplomatic": {"llm_disabled": True}}

        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available, record_sensor_drop, safe_float, safe_enum, sanitize_llm_input, today_str

        if not llm_available():
            log.debug("[Diplomatic] LLM not available — skipping")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"diplomatic": {"llm_offline": True}}

        # LLM sensor covers every participant country across all scorable
        # scenarios (ADR-004).
        strategic_theaters = set(context.get("all_participant_countries")
                                  or context.get("strategic_theaters", []))
        t0 = time.time()
        submitted = 0
        any_feed_ok = False

        for source_name, meta in _DIPLOMATIC_SOURCES.items():
            theaters = [t for t in meta["theaters"] if t in strategic_theaters or not strategic_theaters]
            if not theaters:
                continue

            xml_text = _fetch_rss(meta["url"])
            if xml_text:
                any_feed_ok = True
            t_names = _theater_names(theaters)
            articles = _parse_articles(xml_text, theater_names=t_names)
            if not articles:
                continue

            country = meta["country"]
            theaters_str = ", ".join(theaters)

            # Process each article independently for precise per-article theater assignment
            for art in articles:
                key = _article_hash(source_name, art["title"])
                with _processed_lock:
                    if key in _processed:
                        continue
                    _processed[key] = None
                    if len(_processed) > _MAX_PROCESSED:
                        for k in list(_processed)[:_MAX_PROCESSED // 2]:
                            _processed.pop(k, None)

                safe_title   = sanitize_llm_input(art["title"], 120)
                safe_summary = sanitize_llm_input(art["summary"], 400)
                article_text = f"{art['title']}\n{art['summary'][:400]}"

                system_prompt = (
                    "You are a diplomatic intelligence analyst. "
                    "Analyze this official government statement for escalation signals "
                    f"relevant to any of these theaters: {theaters_str}. "
                    "Respond ONLY with a JSON object, no explanation."
                )
                user_prompt = (
                    f"Today's date: {today_str()}\n"
                    f"Source: {country} official diplomatic statements\n"
                    f"Relevant theaters: {theaters_str}\n\n"
                    f"Statement:\n{safe_title}\n{safe_summary}\n\n"
                    "Return a JSON object:\n"
                    "{\n"
                    '  "headline": "One-sentence escalation summary (max 100 chars)",\n'
                    '  "escalation_signal": true or false,\n'
                    '  "geographic_focus": "What country or region does this statement specifically address?",\n'
                    '  "theater": "Theater code from the list above, or null",\n'
                    '  "countries": ["ISO codes of ALL countries explicitly addressed"],\n'
                    '  "country_weights": {"ISO": 0.0-1.0 relevance weight per country},\n'
                    '  "theater_link": "direct|indirect|none — does the statement specifically address this theater?",\n'
                    '  "diplomatic_action": "warning|condemnation|sanction|expulsion|military_posture|ceasefire|statement|none",\n'
                    '  "target_country": "Country being addressed or criticized",\n'
                    '  "urgency": "critical|high|medium|low",\n'
                    '  "confidence": 0.0\n'
                    "}\n"
                    "BIAS CHECK — before assigning theater, ask yourself:\n"
                    "- Does the statement EXPLICITLY name or address the theater country/region?\n"
                    "- Or am I inferring a connection because the issuing country is an adversary?\n"
                    "- A statement about EU sanctions on Russia is 'direct' for UA, but 'none' for TW.\n"
                    "Set theater_link='direct' ONLY when the statement explicitly addresses the theater.\n"
                    "Set theater_link='indirect' for strategic inference only — confidence will be reduced.\n"
                    "Set theater=null and theater_link='none' if no specific theater is addressed.\n\n"
                    "Confidence guide:\n"
                    "- 0.80-0.95: Explicit military warning, sanction announcement, or expulsion\n"
                    "- 0.65-0.79: Strong condemnation or direct posturing language\n"
                    "- 0.40-0.64: Relevant but ambiguous diplomatic language\n"
                    "- <0.40: Routine statement, no escalation signal — set escalation_signal=false, theater=null"
                )

                result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=256)

                if not result["ok"]:
                    log.debug(f"[Diplomatic] LLM parse failed {source_name}: {result.get('error')}")
                    continue

                data = result["data"]
                confidence = safe_float(data.get("confidence"), default=0.0)

                if not data.get("escalation_signal", False) or confidence < 0.35:
                    log.debug(f"[Diplomatic] No signal {source_name} conf={confidence:.2f}")
                    record_sensor_drop("no_escalation_signal" if not data.get("escalation_signal") else "below_floor")
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

                # Discard if LLM could not assign a specific theater — no forced fallback
                llm_theater = (data.get("theater") or "").strip().upper()
                if not llm_theater or llm_theater not in theaters:
                    log.debug(f"[Diplomatic] No specific theater match for {source_name} (llm={llm_theater!r})")
                    record_sensor_drop("theater_mismatch")
                    continue
                theater = llm_theater

                if theater not in countries:
                    countries = [theater] + countries
                    country_weights.setdefault(theater, 1.0)

                # Theater link validation: indirect/none links indicate LLM over-association
                theater_link = safe_enum(
                    data.get("theater_link"), {"direct", "indirect", "none"}, "none"
                )
                if theater_link == "none":
                    log.debug(
                        f"[Diplomatic] Discarding theater_link=none: {source_name} "
                        f"geo={data.get('geographic_focus', '?')!r} → {theater}"
                    )
                    record_sensor_drop("theater_link_none")
                    continue
                if theater_link == "indirect":
                    confidence = min(confidence, 0.45)
                    log.debug(
                        f"[Diplomatic] Indirect theater link: {source_name} "
                        f"geo={data.get('geographic_focus', '?')!r} → {theater} "
                        f"(conf capped to {confidence:.2f})"
                    )

                urgency = safe_enum(data.get("urgency"), {"critical", "high", "medium", "low"}, "low")
                score_delta = {"critical": 3.0, "high": 2.0, "medium": 1.5, "low": 1.0}.get(urgency, 1.0)

                item = {
                    "source_type":  "diplomatic",
                    "source_id":    f"diplomatic_{source_name.lower()}",
                    "theater":      theater,
                    "countries":    countries,
                    "country_weights": country_weights,
                    "ts":           time.time(),
                    "confidence":   round(confidence, 3),
                    "raw_text":     article_text[:1000],
                    "raw_url":      art.get("link", ""),
                    "headline":     data.get("headline", f"Diplomatic escalation signal: {source_name} / {theater}")[:100],
                    "llm_fields": {
                        "diplomatic_action": data.get("diplomatic_action", "statement"),
                        "target_country":    data.get("target_country", ""),
                        "urgency":           urgency,
                        "source_country":    country,
                        "geographic_focus":  data.get("geographic_focus", ""),
                        "theater_link":      theater_link,
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
        self.log_fetch(any_feed_ok, duration_ms, 0, submitted)
        result_data = {"diplomatic": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
