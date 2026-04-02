"""radar.sensors.apt_intel -- AptIntelSensor.

Monitors GOVERNMENT CERT/advisory RSS feeds for state-sponsored cyber threat
warnings and submits LLM-analyzed items to the intel_queue.

Design rationale (v2 — complete rewrite):

  Previous design used security VENDOR blogs (SentinelOne, CrowdStrike, etc.).
  This caused fundamental problems:
    1. Vendor blogs are marketing content — "we blocked X" posts represent
       RESOLVED threats, not pre-conflict leading indicators.
    2. No geographic specificity requirement — global supply chain attacks
       were incorrectly mapped to geopolitical theaters.
    3. Forced theater assignment — code always picked a theater even when
       the LLM found no geographic relevance, causing misclassification.

  This version uses GOVERNMENT CERT/advisory sources ONLY:
    - Governments issue advisories only for ACTIVE, ONGOING threats
    - No marketing incentive → no inflation of severity
    - Advisories are specific (named actors, named target sectors/countries)
    - Five Eyes joint advisories represent consensus intelligence

Processing flow:
  Government CERT RSS feeds (CISA / JPCERT / NCSC-UK / ENISA / BSI)
  → parse recent articles (72h)
  → pre-filter: advisory/alert language + geographic/sector specificity
  → dedup by article-hash
  → Stage 1 LLM gate: "Is this an active threat with explicit geographic target?"
      → NO (global/generic/resolved) → discard, no further processing
  → Stage 2 LLM analysis: extract actor, theater, TTP, urgency
  → intel_queue.submit() only if confirmed geographic relevance

Key architectural change:
  theater is NEVER force-assigned. If the advisory does not name a specific
  country/region as a target, the item is discarded at Stage 1.
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
from radar.config import LLM_ENABLED, GLOBAL_PROXIES, SSL_VERIFY, COUNTRY_COORDS

log = logging.getLogger("radar")

_POLL_INTERVAL = int(os.getenv("APT_INTEL_POLL_INTERVAL", "3600"))  # 1 hour

# Government CERT and national cyber authority RSS feeds.
# These publish advisories only for ACTIVE, CONFIRMED threats.
# No vendor blog entries — only government-sourced intelligence.
_CERT_SOURCES = {
    "CISA_ALERTS": {
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "authority": "CISA (US)",
        "region": "US",
        "theater_hints": ["US", "UA", "TW", "JP", "KR", "AU"],
    },
    "CISA_ACTIVITY": {
        "url": "https://www.cisa.gov/uscert/ncas/current-activity.xml",
        "authority": "CISA (US)",
        "region": "US",
        "theater_hints": ["US", "UA", "TW", "JP", "KR", "AU"],
    },
    "JPCERT": {
        "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rss",
        "authority": "JPCERT/CC (JP)",
        "region": "JP",
        "theater_hints": ["JP", "TW", "KR", "KP"],
    },
    "NCSC_UK": {
        "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        "authority": "NCSC (UK)",
        "region": "GB",
        "theater_hints": ["GB", "UA", "IL", "IR"],
    },
    "ENISA": {
        "url": "https://www.enisa.europa.eu/news/enisa-news/RSS?section=All",
        "authority": "ENISA (EU)",
        "region": "EU",
        "theater_hints": ["UA", "DE", "FR", "PL", "LT", "LV", "EE"],
    },
    "BSI_GERMANY": {
        "url": "https://www.bsi.bund.de/SiteGlobals/Functions/RSSFeed/RSSNewsfeed/RSSNewsfeed_Meldungen.xml",
        "authority": "BSI (DE)",
        "region": "DE",
        "theater_hints": ["DE", "UA", "PL"],
    },
    "ACSC_AUSTRALIA": {
        "url": "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/rss",
        "authority": "ACSC (AU)",
        "region": "AU",
        "theater_hints": ["AU", "TW", "JP", "PH"],
    },
}

# Pre-filter keywords: advisory language + state-actor indicators.
# These focus on ACTIVE THREAT language, not retrospective/marketing language.
# Keywords intentionally exclude "blocked", "prevented", "stopped" — those
# indicate resolved incidents, not active threats.
_ADVISORY_KEYWORDS = [
    # Advisory/warning language (government-style)
    "advisory", "alert", "warning", "actively exploiting", "active exploitation",
    "under active attack", "observed in the wild", "in the wild",
    "immediate action", "patch immediately", "emergency directive",
    # State-actor indicators (specific, named)
    "volt typhoon", "salt typhoon", "hafnium", "flax typhoon",
    "fancy bear", "cozy bear", "apt28", "apt29", "sandworm", "turla",
    "lazarus", "kimsuky", "andariel", "bluenoroff",
    "charming kitten", "muddy water", "apt35", "apt34",
    "apt41", "gothic panda", "bronze silhouette",
    "state-sponsored", "nation-state", "state actor",
    # Sector targeting (critical infrastructure)
    "critical infrastructure", "industrial control", "scada", "ics",
    "water treatment", "power grid", "energy sector", "defense contractor",
    "telecommunications", "financial sector",
    # Pre-conflict TTP language
    "pre-positioning", "living off the land", "lotl",
    "persistence", "lateral movement", "command and control",
]

# Keywords that indicate a RESOLVED or MARKETING incident — discard these
# at the pre-filter stage before any LLM call.
_DISCARD_KEYWORDS = [
    "we blocked", "we prevented", "we stopped", "our platform detected",
    "our product", "how we", "case study", "product update", "webinar",
    "whitepaper", "ebook", "download", "register now", "join us",
]

# Processed article hashes to avoid reprocessing
_processed: set[str] = set()
_MAX_PROCESSED = 1000


def _theater_names(theaters: list[str]) -> list[str]:
    """Resolve theater codes to lowercase country/region names for text matching."""
    names = []
    for code in theaters:
        entry = COUNTRY_COORDS.get(code, {})
        name = entry.get("name", "")
        if name:
            names.append(name.lower())
    return names


def _article_hash(source_name: str, title: str) -> str:
    raw = f"cert-{source_name}-{title[:60]}"
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


def _parse_articles(xml_text: str, max_age_h: int = 72,
                    theater_names: list[str] | None = None) -> list[dict]:
    """Parse RSS XML and return recent advisory-relevant articles.
    Pre-filter: require advisory language AND exclude marketing/resolved content.
    Two-slot system:
      Slot 1: up to 5 articles matching advisory keywords
      Slot 2: up to 2 articles matching only theater names (no keyword match)
    """
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    cutoff = time.time() - max_age_h * 3600
    keyword_articles = []
    theater_only_articles = []
    seen_titles: set[str] = set()
    adv_kw = [k.lower() for k in _ADVISORY_KEYWORDS]
    dis_kw = [k.lower() for k in _DISCARD_KEYWORDS]

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

        # Hard discard: marketing/resolved language → skip before LLM
        if any(kw in text_lower for kw in dis_kw):
            continue

        art = {"title": title, "summary": summary[:500], "pub_ts": pub_ts, "link": link}

        # Slot 1: advisory keyword match (up to 5)
        if any(kw in text_lower for kw in adv_kw):
            if len(keyword_articles) < 5:
                keyword_articles.append(art)
            continue

        # Slot 2: theater-name-only match (up to 2)
        if theater_names and any(tn in text_lower for tn in theater_names):
            if len(theater_only_articles) < 2:
                theater_only_articles.append(art)

        if len(keyword_articles) >= 5 and len(theater_only_articles) >= 2:
            break

    return keyword_articles + theater_only_articles


class AptIntelSensor(BaseSensor):
    """Monitors government CERT advisories for active state-sponsored cyber threats."""

    def __init__(self):
        super().__init__("apt_intel", "cyber", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"apt_intel": {"llm_disabled": True}}

        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available, safe_float, safe_enum, sanitize_llm_input, today_str

        if not llm_available():
            log.debug("[AptIntel] LLM not available — skipping")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"apt_intel": {"llm_offline": True}}

        strategic_theaters = set(context.get("strategic_theaters", []))
        t0 = time.time()
        submitted = 0

        for source_name, meta in _CERT_SOURCES.items():
            # Theater hints: used only to inform LLM context, NOT for forced assignment
            theater_hints = [t for t in meta["theater_hints"]
                             if not strategic_theaters or t in strategic_theaters]

            xml_text = _fetch_rss(meta["url"])
            t_names = _theater_names(theater_hints)
            articles = _parse_articles(xml_text, theater_names=t_names)
            if not articles:
                continue

            authority = meta["authority"]

            for art in articles:
                key = _article_hash(source_name, art["title"])
                if key in _processed:
                    continue
                _processed.add(key)

                if len(_processed) > _MAX_PROCESSED:
                    to_remove = list(_processed)[:_MAX_PROCESSED // 2]
                    for k in to_remove:
                        _processed.discard(k)

                safe_title   = sanitize_llm_input(art["title"], 120)
                safe_summary = sanitize_llm_input(art["summary"], 500)
                article_text = f"{art['title']}\n{art['summary'][:500]}"
                llm_article  = f"{safe_title}\n{safe_summary}"
                hints_str = ", ".join(theater_hints) if theater_hints else "any"

                # ── Stage 1: Gate check ───────────────────────────────────────
                gate_system = (
                    "You are a cyber threat intelligence triage analyst. "
                    "Evaluate whether a government advisory describes an ACTIVE, ONGOING "
                    "state-sponsored threat with EXPLICIT targeting of a specific country, "
                    "region, or critical sector. "
                    "Respond ONLY with a JSON object."
                )
                gate_prompt = (
                    f"Today's date: {today_str()}\n"
                    f"Advisory source: {authority}\n"
                    f"Advisory text:\n{llm_article}\n\n"
                    "Answer these two questions with a JSON object:\n"
                    "{\n"
                    '  "is_active_threat": true or false,\n'
                    '  "has_geographic_target": true or false,\n'
                    '  "reason": "one sentence"\n'
                    "}\n"
                    "is_active_threat = true ONLY if the advisory describes a CURRENTLY ACTIVE or ONGOING "
                    "threat (not a resolved/patched/historical incident).\n"
                    "has_geographic_target = true ONLY if the advisory EXPLICITLY names a specific country, "
                    "region, sector, or infrastructure type as the target (not just the issuing country).\n"
                    "If the advisory is generic (e.g. 'patch this CVE', global supply chain, "
                    "no named victim country): has_geographic_target = false."
                )

                gate_result = llm_analyze_json(gate_prompt, system=gate_system, max_tokens=120)
                if not gate_result["ok"]:
                    log.debug(f"[AptIntel] Stage1 parse failed {source_name}: {gate_result.get('error')}")
                    continue

                gate_data = gate_result["data"]
                if not gate_data.get("is_active_threat", False):
                    log.debug(f"[AptIntel] Stage1 DISCARD (not active): {art['title'][:60]}")
                    continue
                if not gate_data.get("has_geographic_target", False):
                    log.debug(f"[AptIntel] Stage1 DISCARD (no geo target): {art['title'][:60]}")
                    continue

                # ── Stage 2: Full analysis ────────────────────────────────────
                # Only reached if Stage 1 confirmed: active + geographically targeted.
                # Theater assignment is based SOLELY on what the advisory names —
                # no fallback to hints list if LLM finds no match.
                analysis_system = (
                    "You are a strategic cyber threat intelligence analyst. "
                    "Analyze this government CERT advisory — it has already been confirmed "
                    "as an active threat with explicit geographic targeting. "
                    "Extract structured intelligence. "
                    "Respond ONLY with a JSON object, no explanation."
                )
                analysis_prompt = (
                    f"Today's date: {today_str()}\n"
                    f"Advisory source: {authority}\n"
                    f"Active strategic theaters for context: {hints_str}\n\n"
                    f"Advisory:\n{llm_article}\n\n"
                    "Return a JSON object:\n"
                    "{\n"
                    '  "headline": "One-sentence threat summary (max 100 chars)",\n'
                    '  "theater": "ISO country code of the PRIMARY targeted country/region, '
                    'OR null if not in the active theaters list above",\n'
                    '  "attributed_actor": "APT group or state actor name, or unknown",\n'
                    '  "actor_nexus": "Sponsoring state ISO code (CN/RU/KP/IR/XX)",\n'
                    '  "targeted_sector": "critical_infrastructure|government|military|financial|'
                    'telecom|defense_industrial|academic|unknown",\n'
                    '  "ttp_category": "pre-positioning|active-exploitation|espionage|sabotage|'
                    'financial|disruption|unknown",\n'
                    '  "urgency": "critical|high|medium|low",\n'
                    '  "confidence": 0.0\n'
                    "}\n"
                    "CRITICAL: theater must be null if the advisory does not explicitly name "
                    "a country that matches the active theaters list. Do NOT infer or guess.\n"
                    "Confidence guide:\n"
                    "- 0.80-0.95: Named state actor + named target country in active theater\n"
                    "- 0.65-0.79: Likely state actor + sector in theater explicitly named\n"
                    "- 0.55-0.64: Possible state actor, theater inferred from sector/region\n"
                    "- <0.55: Insufficient specificity even after Stage 1 (set theater=null)"
                )

                result = llm_analyze_json(analysis_prompt, system=analysis_system, max_tokens=280)
                if not result["ok"]:
                    log.debug(f"[AptIntel] Stage2 parse failed {source_name}: {result.get('error')}")
                    continue

                data = result["data"]
                confidence = safe_float(data.get("confidence"), default=0.0)

                # Hard gate: no theater → discard (no forced assignment)
                theater = (data.get("theater") or "").strip().upper() or None
                if not theater or theater in ("NULL", "NONE"):
                    log.debug(f"[AptIntel] Stage2 DISCARD (no theater): {art['title'][:60]}")
                    continue

                # Verify theater is in active strategic theaters (or no filter set)
                if strategic_theaters and theater not in strategic_theaters:
                    log.debug(f"[AptIntel] Stage2 DISCARD (theater {theater} not strategic): {art['title'][:60]}")
                    continue

                if confidence < 0.40:
                    log.debug(f"[AptIntel] Stage2 low confidence {confidence:.2f}: {art['title'][:60]}")
                    continue

                _TTP_CATEGORIES = {
                    "pre-positioning", "active-exploitation", "espionage", "sabotage",
                    "financial", "disruption", "unknown",
                }
                ttp = safe_enum(data.get("ttp_category"), _TTP_CATEGORIES, "unknown")
                urgency = safe_enum(data.get("urgency"), {"critical", "high", "medium", "low"}, "medium")

                # Additive scoring: ttp_base + urgency_bonus (max = 3.0, no multiplicative inflation)
                ttp_base = {
                    "sabotage":            2.5,
                    "active-exploitation": 2.0,
                    "pre-positioning":     2.0,
                    "disruption":          1.5,
                    "espionage":           1.5,
                    "financial":           1.0,
                    "unknown":             1.0,
                }.get(ttp, 1.0)
                urgency_bonus = {"critical": 0.5, "high": 0.2, "medium": 0.0, "low": 0.0}.get(urgency, 0.0)
                score_delta = round(ttp_base + urgency_bonus, 1)

                item = {
                    "source_type":  "apt_intel",
                    "source_id":    f"cert_{source_name.lower()}",
                    "theater":      theater,
                    "ts":           time.time(),
                    "confidence":   round(confidence, 3),
                    "raw_text":     article_text[:1000],
                    "raw_url":      art.get("link", ""),
                    "headline":     data.get("headline",
                                            f"CERT advisory: {data.get('attributed_actor','unknown')} / {theater}")[:100],
                    "llm_fields": {
                        "attributed_actor": data.get("attributed_actor", "unknown"),
                        "actor_nexus":      data.get("actor_nexus", "XX"),
                        "targeted_sector":  data.get("targeted_sector", "unknown"),
                        "ttp_category":     ttp,
                        "urgency":          urgency,
                        "authority":        authority,
                        "gate_reason":      gate_data.get("reason", ""),
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
                        f"(src={source_name}, theater={theater}, "
                        f"actor={data.get('attributed_actor','?')}, ttp={ttp}, conf={confidence:.2f})"
                    )

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(True, duration_ms, 0, submitted)
        result_data = {"apt_intel": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
