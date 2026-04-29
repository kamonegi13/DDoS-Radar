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
#
# Feed audit 2026-04-18:
#   Working: US_STATE, TW_MOFA, KCNA_WATCH
#   Dead:   JP_MOFA (WAF 403), CN_MFA (RSS discontinued, domain→mfa.gov.cn),
#           RU_MFA (404), NATO (RSS discontinued, 301→HTML)
#   Dead feeds are kept for retry from different network environments.
# 2026-04-29 (R1 — Operational Observability): the seven primary MFA / NATO
# RSS endpoints have all been retired or moved to non-RSS press-release
# pages (see scripts/audit_intel_sensors.py + diplomatic._classify_feed
# probing on 2026-04-29):
#   US_STATE  state.gov/press-releases/feed/    → returns_html (URL stale)
#   JP_MOFA   mofa.go.jp/rss/rss.xml             → 404 / WAF (DC-IP from container)
#   CN_MFA    fmprc.gov.cn/mfa_eng/rss.xml       → returns_html (RSS discontinued)
#   TW_MOFA   en.mofa.gov.tw/rss.aspx            → returns_html (SPA migration)
#   RU_MFA    mid.ru/en/rss.xml                  → returns_html (broken / geo-blocked)
#   KCNA_WATCH kcnawatch.org/feed/               → rss_empty (intermittent)
#   NATO      nato.int/cps/en/natolive/news_rss  → 404 (RSS discontinued)
#
# Replacement strategy: Google News RSS with a targeted boolean query per
# country. This is durable across MFA website redesigns, returns 30-100
# items per query at any given time, and surfaces coverage from major news
# wires (Reuters, AP, AFP) reporting on each ministry — exactly the
# escalation-relevant signal the LLM downstream is looking for. Two primary
# feeds also survived (TASS for Russian state media, NK News for DPRK
# coverage) and are added as supplementary sources where they complement
# the Google News query.
#
# All endpoints below were verified on 2026-04-29 to return rss_with_items
# with a non-trivial item count.
_GNEWS_BASE = "https://news.google.com/rss/search?q={q}&hl=en&gl=US&ceid=US:en"

_DIPLOMATIC_SOURCES = {
    "US_STATE": {
        "url": _GNEWS_BASE.format(
            q='site:state.gov+OR+%22State+Department%22+press'),
        "country": "US",
        "theaters": ["TW", "UA", "KP", "IR", "IL", "JP", "PH"],
    },
    "JP_MOFA": {
        "url": _GNEWS_BASE.format(q='Japan+foreign+minister'),
        "country": "JP",
        "theaters": ["TW", "JP", "KP", "CN"],
    },
    "CN_MFA": {
        "url": _GNEWS_BASE.format(q='China+foreign+ministry+spokesperson'),
        "country": "CN",
        "theaters": ["TW", "JP", "PH", "IN"],
    },
    "TW_MOFA": {
        "url": _GNEWS_BASE.format(q='Taiwan+MOFA+statement'),
        "country": "TW",
        "theaters": ["TW"],
    },
    "RU_MFA_TASS": {
        # TASS is Russian state media with healthy primary RSS — preferred
        # over Google News for Russian-government-perspective coverage.
        "url": "https://tass.com/rss/v2.xml",
        "country": "RU",
        "theaters": ["UA", "IR", "IL", "SY", "KP"],
    },
    "RU_MFA_GNEWS": {
        # Cross-source coverage of Russian foreign-ministry activity —
        # complements TASS (which is sometimes self-censored on Ukraine).
        "url": _GNEWS_BASE.format(q='Russia+MFA+Lavrov+foreign+ministry'),
        "country": "RU",
        "theaters": ["UA", "IR", "IL", "SY", "KP"],
    },
    "KCNA_WATCH": {
        # Currently rss_empty in production but keeps the feed monitored
        # in case it repopulates. NK_NEWS below covers the gap.
        "url": "https://kcnawatch.org/feed/",
        "country": "KP",
        "theaters": ["KP", "JP"],
    },
    "NK_NEWS": {
        # Independent DPRK-watching outlet, 300 items in current feed.
        "url": "https://www.nknews.org/feed/",
        "country": "KP",
        "theaters": ["KP", "JP", "KR"],
    },
    "NATO": {
        "url": _GNEWS_BASE.format(q='NATO+Secretary+General+statement'),
        "country": "NATO",
        "theaters": ["UA"],
    },
    "IL_MFA": {
        # New 2026-04-29: previously absent. Israel MFA primary feed is dead;
        # using Google News query for foreign-ministry coverage.
        "url": _GNEWS_BASE.format(q='Israel+foreign+ministry+statement'),
        "country": "IL",
        "theaters": ["IL", "IR", "LB", "SY"],
    },
    "IR_MFA": {
        # New 2026-04-29: previously absent. Iran MFA primary feed is dead.
        "url": _GNEWS_BASE.format(q='Iran+foreign+ministry'),
        "country": "IR",
        "theaters": ["IR", "IL", "SY", "LB"],
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


_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "application/rss+xml, application/xml, text/xml, */*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ja;q=0.8",
}


def _fetch_rss(url: str) -> str:
    """Fetch RSS feed text. Returns empty string on failure."""
    try:
        resp = requests.get(
            url, timeout=15,
            proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
            headers=_BROWSER_HEADERS,
        )
        if resp.status_code == 200:
            return resp.text
        log.info(f"[Diplomatic] HTTP {resp.status_code} from {url}")
    except Exception as e:
        log.info(f"[Diplomatic] Fetch failed {url}: {e}")
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


def _parse_xml_tolerant(xml_text: str):
    """Parse XML with the strict defusedxml parser first, then fall back to
    lxml with recover=True for the malformed RSS that several diplomatic
    feeds emit (RU MID encoding garbage, TW MOFA unescaped &, US STATE
    HTML wrapping the feed). Returns an ElementTree root or None.

    Live audit on 2026-04-29 showed every diplomatic feed except KCNA_WATCH
    failing the strict parser; the previous code silently returned [] on
    ParseError, which surfaced in llm_call_log as 'no_articles_post_filter'
    even though the feed itself was the cause.
    """
    if not xml_text:
        return None
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        pass
    try:
        from lxml import etree as _lxml_et
        parser = _lxml_et.XMLParser(recover=True, encoding=None)
        root = _lxml_et.fromstring(xml_text.encode("utf-8", errors="replace"), parser)
        return root if root is not None else None
    except Exception:
        return None


def _classify_feed(xml_text: str) -> str:
    """Distinguish feed failure modes for the audit log:
      - 'rss_with_items' (healthy)
      - 'rss_empty'      (valid RSS, but <channel> has 0 <item>)
      - 'returns_html'   (server returned a web page, URL is stale)
      - 'unparseable'    (XML so malformed that even lxml recovery fails)
      - 'unknown'        (anything else)

    Used by the sensor to record_sensor_skip a more useful reason than
    the previous catch-all 'no_articles_post_filter'.
    """
    if not xml_text:
        return "unknown"
    head = xml_text.lstrip()[:200].lower()
    if head.startswith("<!doctype html") or head.startswith("<html"):
        return "returns_html"
    root = _parse_xml_tolerant(xml_text)
    if root is None:
        return "unparseable"
    # lxml may report .tag as a string or a function depending on element
    # type; check using a getter that tolerates both.
    def _has_item(node) -> bool:
        for child in node.iter():
            tag = getattr(child, "tag", None)
            if isinstance(tag, str) and (tag == "item" or tag.endswith("}item")):
                return True
            if isinstance(tag, str) and (tag == "entry" or tag.endswith("}entry")):
                return True  # Atom-format feeds
        return False
    root_tag = getattr(root, "tag", "")
    if isinstance(root_tag, str) and ("rss" in root_tag.lower() or "feed" in root_tag.lower() or root_tag.endswith("}rss")):
        return "rss_with_items" if _has_item(root) else "rss_empty"
    if isinstance(root_tag, str) and ("html" in root_tag.lower()):
        return "returns_html"
    return "unknown"


def _parse_articles(xml_text: str, max_age_h: int = 48,
                    theater_names: list[str] | None = None) -> list[dict]:
    """Parse RSS XML and return recent articles as dicts with title, summary, pub_ts.
    Three-slot system:
      Slot 1: up to 5 articles matching escalation keywords
      Slot 2: up to 2 articles matching only theater names (no keyword match)
      Slot 3: 1 most-recent article as fallback when slots 1+2 are both empty
              (ensures LLM sees something even when keyword/theater filters miss)
    """
    root = _parse_xml_tolerant(xml_text)
    if root is None:
        if xml_text:
            log.debug("[Diplomatic] RSS XML unparseable even with recovery (len=%d)",
                      len(xml_text))
        return []

    cutoff = time.time() - max_age_h * 3600
    keyword_articles = []
    theater_only_articles = []
    fallback_article = None  # most-recent article for slot 3
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

        # Track most-recent article for slot 3 fallback
        if fallback_article is None or pub_ts > fallback_article.get("pub_ts", 0):
            fallback_article = art

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

    result = keyword_articles + theater_only_articles
    # Slot 3: if both primary slots are empty, send the most-recent article
    # as a fallback so the LLM can assess it. This prevents total blindness
    # when keyword/theater name filters miss non-English diplomatic statements.
    if not result and fallback_article and fallback_article.get("title"):
        result = [fallback_article]
    return result


class DiplomaticSensor(BaseSensor):
    """Monitors official diplomatic RSS feeds for escalation signals."""

    def __init__(self):
        super().__init__("diplomatic", "info", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"diplomatic": {"llm_disabled": True}}

        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available, record_sensor_drop, record_sensor_skip, safe_float, safe_enum, sanitize_llm_input, today_str

        if not llm_available():
            log.debug("[Diplomatic] LLM not available — skipping")
            record_sensor_skip("llm_unavailable", caller="diplomatic")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"diplomatic": {"llm_offline": True}}

        # LLM sensor covers every participant country across all scorable
        # scenarios (ADR-004).
        strategic_theaters = set(context.get("all_participant_countries")
                                  or context.get("strategic_theaters", []))
        t0 = time.time()
        submitted = 0
        any_feed_ok = False

        feeds_tried = 0
        feeds_ok = 0
        total_articles = 0

        for source_name, meta in _DIPLOMATIC_SOURCES.items():
            theaters = [t for t in meta["theaters"] if t in strategic_theaters or not strategic_theaters]
            if not theaters:
                continue

            feeds_tried += 1
            xml_text = _fetch_rss(meta["url"])
            if xml_text:
                any_feed_ok = True
                feeds_ok += 1
            else:
                record_sensor_skip(f"feed_fetch_failed:{source_name}", caller="diplomatic")
            t_names = _theater_names(theaters)
            articles = _parse_articles(xml_text, theater_names=t_names)
            total_articles += len(articles)
            if not articles:
                if xml_text:
                    # 2026-04-29: classify the failure mode so future audits
                    # can tell whether the URL is stale (returns_html / rss_empty)
                    # vs the filter being too strict (no_articles_post_filter
                    # against a healthy rss_with_items feed).
                    feed_class = _classify_feed(xml_text)
                    log.info(f"[Diplomatic] {source_name}: feed_class={feed_class} 0 articles")
                    if feed_class == "returns_html":
                        record_sensor_skip(f"feed_url_stale_html:{source_name}", caller="diplomatic")
                    elif feed_class == "rss_empty":
                        record_sensor_skip(f"feed_empty:{source_name}", caller="diplomatic")
                    elif feed_class == "unparseable":
                        record_sensor_skip(f"feed_unparseable:{source_name}", caller="diplomatic")
                    else:
                        record_sensor_skip(f"no_articles_post_filter:{source_name}", caller="diplomatic")
                continue

            country = meta["country"]
            theaters_str = ", ".join(theaters)

            # Process each article independently for precise per-article theater assignment
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

            if articles and new_articles_this_feed == 0:
                record_sensor_skip(f"all_dedup:{source_name}", caller="diplomatic")

        duration_ms = round((time.time() - t0) * 1000)
        log.info(
            f"[Diplomatic] Cycle done: feeds={feeds_ok}/{feeds_tried} "
            f"articles={total_articles} submitted={submitted} ({duration_ms}ms)"
        )
        self.log_fetch(any_feed_ok, duration_ms, 0, submitted)
        result_data = {"diplomatic": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
