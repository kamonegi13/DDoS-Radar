"""radar.sensors.military_exercise -- MilitaryExerciseSensor.

Monitors RSS feeds from military/defense news sources for exercise and
deployment announcements that indicate escalatory posturing.

Processing flow:
  RSS feeds (PLA Daily, Indo-PACOM, USNI, DefenseNews, etc.)
  → parse recent articles (48h)
  → pre-filter by military-exercise keywords
  → dedup by article hash
  → LLM analysis: extract exercise_name, force_type, scale, theater, escalation
  → intel_queue.submit() with source_type="military"

Distinct from DiplomaticSensor (which monitors statements),
MilitaryExerciseSensor focuses on:
  - Force posturing and deployment announcements
  - Exercise start/end notifications
  - Troop/asset movement near contested theaters
  - Readiness elevation notices
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

_POLL_INTERVAL = int(os.getenv("MILITARY_EXERCISE_POLL_INTERVAL", "3600"))  # 1 hour

# Military/defense RSS sources mapped to relevant theaters
_MILITARY_SOURCES = {
    "PACOM_NEWS": {
        "url": "https://www.pacom.mil/Media/News/rss/",
        "org": "USINDOPACOM",
        "theaters": ["TW", "JP", "KP", "PH"],
    },
    "USNI_NEWS": {
        "url": "https://news.usni.org/feed",
        "org": "USNI",
        "theaters": ["TW", "JP", "KP", "UA", "IR", "IL"],
    },
    "DEFENSE_NEWS": {
        "url": "https://www.defensenews.com/arc/outboundfeeds/rss/",
        "org": "DefenseNews",
        "theaters": ["TW", "UA", "KP", "JP", "IL", "IR"],
    },
    "PLA_DAILY": {
        "url": "http://eng.chinamil.com.cn/rss/rss.xml",
        "org": "PLA",
        "theaters": ["TW", "JP", "PH", "IN"],
    },
    "TASS_MILITARY": {
        "url": "https://tass.com/rss/v2.xml",
        "org": "TASS",
        "theaters": ["UA"],
    },
    "JANES": {
        "url": "https://www.janes.com/feeds/news",
        "org": "Janes",
        "theaters": ["TW", "UA", "KP", "JP", "IR"],
    },
    "STARS_STRIPES": {
        "url": "https://www.stripes.com/arcio/rss/",
        "org": "Stars&Stripes",
        "theaters": ["JP", "KP", "TW", "UA"],
    },
}

# Keywords indicating military exercise or deployment activity
_EXERCISE_KEYWORDS = [
    "exercise", "drill", "maneuver", "deployment", "troops", "warship",
    "carrier strike", "amphibious", "live fire", "combat readiness",
    "mobilization", "military operation", "force posture", "air defense",
    "naval blockade", "submarine", "ballistic missile", "hypersonic",
    "military exercise", "joint exercise", "combined exercise",
    "PLA exercise", "PLAAF", "PLAN", "PLARF",
    "encirclement", "combat patrol", "warplane", "fighter jet",
    "destroyer", "frigate", "aircraft carrier",
    "forward deploy", "preposition", "staging area",
]

_processed: set[str] = set()
_MAX_PROCESSED = 1000


def _article_hash(source_name: str, title: str) -> str:
    """Hash keyed on article identity only (not theater) to prevent duplicate submissions."""
    raw = f"mil-{source_name}-{title[:60]}"
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
            log.debug(f"[MilExercise] 429 rate-limited: {url}")
    except Exception as e:
        log.debug(f"[MilExercise] Fetch failed {url}: {e}")
    return ""


def _parse_articles(xml_text: str, max_age_h: int = 48) -> list[dict]:
    """Parse RSS, filter by age and exercise keywords, return up to 5 articles."""
    if not xml_text:
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    cutoff = time.time() - max_age_h * 3600
    articles = []
    seen: set[str] = set()
    kw_lower = [k.lower() for k in _EXERCISE_KEYWORDS]

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
        if title_key and title_key in seen:
            continue
        if title_key:
            seen.add(title_key)

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
            "summary": summary[:400],
            "pub_ts":  pub_ts,
            "link":    link,
        })
        if len(articles) >= 5:
            break

    return articles


class MilitaryExerciseSensor(BaseSensor):
    """Monitors defense RSS feeds for military exercise and deployment escalation signals."""

    def __init__(self):
        super().__init__("military_exercise", "info", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"military_exercise": {"llm_disabled": True}}

        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available

        if not llm_available():
            log.debug("[MilExercise] LLM not available — skipping")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"military_exercise": {"llm_offline": True}}

        strategic_theaters = set(context.get("strategic_theaters", []))
        t0 = time.time()
        submitted = 0

        for source_name, meta in _MILITARY_SOURCES.items():
            theaters = [t for t in meta["theaters"] if t in strategic_theaters or not strategic_theaters]
            if not theaters:
                continue

            xml_text = _fetch_rss(meta["url"])
            articles = _parse_articles(xml_text)
            if not articles:
                continue

            org = meta["org"]
            theaters_str = ", ".join(theaters)

            # Process each article independently for precise per-article theater assignment
            for art in articles:
                key = _article_hash(source_name, art["title"])
                if key in _processed:
                    continue
                _processed.add(key)

                if len(_processed) > _MAX_PROCESSED:
                    to_remove = list(_processed)[:_MAX_PROCESSED // 2]
                    for k in to_remove:
                        _processed.discard(k)

                article_text = f"{art['title']}\n{art['summary'][:400]}"

                system_prompt = (
                    "You are a military intelligence analyst. "
                    "Analyze this defense/military news item for exercise and deployment "
                    f"escalation signals relevant to any of these theaters: {theaters_str}. "
                    "Respond ONLY with a JSON object, no explanation."
                )
                user_prompt = (
                    f"Source: {org} defense news\n"
                    f"Relevant theaters: {theaters_str}\n\n"
                    f"Article:\n{article_text}\n\n"
                    "Return a JSON object:\n"
                    "{\n"
                    '  "headline": "One-sentence escalation summary (max 100 chars)",\n'
                    '  "escalation_signal": true or false,\n'
                    '  "theater": "The single most relevant theater code from the list above",\n'
                    '  "exercise_type": "live_fire|amphibious|naval|air|cyber|combined|deployment|none",\n'
                    '  "force_type": "naval|air|ground|rocket|cyber|combined",\n'
                    '  "scale": "strategic|operational|tactical",\n'
                    '  "urgency": "critical|high|medium|low",\n'
                    '  "confidence": 0.0\n'
                    "}\n"
                    "Confidence guide:\n"
                    "- 0.80-0.95: Active live-fire exercise near theater OR forward deployment\n"
                    "- 0.65-0.79: Large-scale exercise announcement with clear theater relevance\n"
                    "- 0.55-0.64: Routine exercise with some escalatory indicators\n"
                    "- <0.55: Routine training, no escalation relevance (set escalation_signal=false)\n"
                    "PLA exercises near Taiwan Strait or South China Sea: always escalation_signal=true.\n"
                    "If article has no relevance to any theater, return confidence<0.40."
                )

                result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=256)

                if not result["ok"]:
                    log.debug(f"[MilExercise] LLM parse failed {source_name}: {result.get('error')}")
                    continue

                data = result["data"]
                confidence = float(data.get("confidence", 0.0))

                if not data.get("escalation_signal", False) or confidence < 0.55:
                    log.debug(f"[MilExercise] No signal {source_name} conf={confidence:.2f}")
                    continue

                llm_theater = data.get("theater", "").strip().upper()
                theater = llm_theater if llm_theater in theaters else theaters[0]

                urgency = data.get("urgency", "low")
                scale   = data.get("scale", "tactical")
                scale_mult = {"strategic": 1.5, "operational": 1.2, "tactical": 1.0}.get(scale, 1.0)
                base_score = {"critical": 3.0, "high": 2.5, "medium": 2.0, "low": 1.5}.get(urgency, 1.5)
                score_delta = round(base_score * scale_mult, 1)

                item = {
                    "source_type":  "military",
                    "source_id":    f"military_{source_name.lower()}",
                    "theater":      theater,
                    "ts":           time.time(),
                    "confidence":   round(confidence, 3),
                    "raw_text":     article_text[:1000],
                    "raw_url":      art.get("link", ""),
                    "headline":     data.get("headline", f"Military exercise signal: {org} / {theater}")[:100],
                    "llm_fields": {
                        "exercise_type": data.get("exercise_type", "none"),
                        "force_type":    data.get("force_type", "combined"),
                        "scale":         scale,
                        "urgency":       urgency,
                        "source_org":    org,
                        "escalation_signal": True,
                    },
                    "score_delta":  score_delta,
                    "domain":       "physical",
                }

                item_id = intel_queue.submit(item)
                if item_id:
                    submitted += 1
                    log.info(
                        f"[MilExercise] Submitted: {item['headline'][:60]} "
                        f"(src={source_name}, theater={theater}, conf={confidence:.2f}, scale={scale})"
                    )

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(True, duration_ms, 0, submitted)
        result_data = {"military_exercise": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
