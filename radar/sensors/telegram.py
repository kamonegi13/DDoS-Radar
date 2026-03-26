"""radar.sensors.telegram -- TelegramMirrorSensor."""
from __future__ import annotations
import logging
import math
import re
import requests
import time
from radar.config import (
    THREAT_ACTOR_MAPPING, TELEGRAM_CHANNEL_META, GLOBAL_PROXIES, SSL_VERIFY, NARRATIVE_ZSCORE_ALERT, NARRATIVE_ZSCORE_CRITICAL, NARRATIVE_BASELINE_DAYS,
)
from radar.sensors.base import BaseSensor
from radar.scoring import register_sequence_event
import os
import threading
log = logging.getLogger("radar")

TELEGRAM_MIRROR_POLL = int(os.getenv("TELEGRAM_MIRROR_POLL_INTERVAL", "900"))
TELEGRAM_ATTACK_KW_RAW = os.getenv(
    "TELEGRAM_ATTACK_KEYWORDS",
    "target,attack,ddos,http flood,under attack,down,offline,op,#target"
)
TELEGRAM_ATTACK_KEYWORDS = [k.strip().lower() for k in TELEGRAM_ATTACK_KW_RAW.split(",") if k.strip()]
TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD = float(os.getenv("TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD", "0.5"))

# Multi-stage confidence scoring for attack claims.
# Stage 1: Declaration only (keywords matched) → base confidence 0.2
# Stage 2: Declaration + government target URLs found → 0.4
# Stage 3: Declaration + Z-score burst (corroborated by frequency) → 0.6
# Cross-validation with other sensors (CheckHost/IODA) happens in scoring engine.
_CONF_DECLARATION_ONLY = 0.2
_CONF_WITH_GOV_TARGETS = 0.4
_CONF_WITH_ZSCORE_BURST = 0.6

_SCRAPER_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

class TelegramMirrorSensor(BaseSensor):
    """
    Info Domain sensor: scrapes public mirror pages on tgstat.com / telemetr.io
    and monitors channel posts based on THREAT_ACTOR_MAPPING.
    No phone number or login required. Parses "target URLs" and "attack declarations"
    from posts and auto-registers them via register_sequence_event.
    """
    TGSTAT_URL   = "https://tgstat.com/channel/@{channel}/stat"
    TELEMETR_URL = "https://telemetr.io/@{channel}"
    # URL extraction pattern (https?://example.com format)
    _URL_RE = re.compile(
        r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s<"\']*)?'
    )
    _intercept_log: list = []   # class-level ring buffer (shared across instances)
    _intercept_lock = threading.Lock()  # Protects _intercept_log and _baseline_tg
    _MAX_LOG        = 50
    _last_poll_ts: str  = ""
    _last_poll_ok: bool = False
    _baseline_tg: dict  = {}    # theater → {"daily_counts": [], "last_updated": 0.0}

    def __init__(self):
        super().__init__("telegram_mirror", "info", TELEGRAM_MIRROR_POLL)

    def _scrape_channel(self, channel: str) -> str:
        """Fetch public channel page from tgstat.com and return text.
        Falls back to telemetr.io on failure.
        Applies UA rotation and exponential backoff on 403/429."""
        import random as _rnd
        for url_tpl in (self.TGSTAT_URL, self.TELEMETR_URL):
            url = url_tpl.format(channel=channel)
            delay = 2.0  # initial backoff base (seconds)
            for attempt in range(3):
                try:
                    ua = _rnd.choice(_SCRAPER_UA_POOL)
                    res = requests.get(
                        url, timeout=10, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
                        headers={"User-Agent": ua, "Accept-Language": "en-US,en;q=0.9"}
                    )
                    if res.status_code == 200 and len(res.text) > 200:
                        return res.text
                    if res.status_code in (403, 429):
                        # Exponential backoff: 2s → 4s → 8s with ±20% jitter
                        sleep_time = delay * (2 ** attempt) * _rnd.uniform(0.8, 1.2)
                        time.sleep(min(sleep_time, 30.0))
                        continue
                    break  # non-retryable error (404, 5xx) — try next source
                except Exception:
                    break
        return ""

    @staticmethod
    def _extract_text(html: str) -> str:
        """Strip scripts and styles from HTML and return plain text (no BeautifulSoup required)."""
        import re
        text = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>',  ' ', text,  flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<[^>]+>', ' ', text)
        text = re.sub(r'&[a-zA-Z0-9#]+;', ' ', text)
        return text.lower()

    def _parse_posts(self, text: str, keywords: list) -> tuple:
        """Extract target URLs and attack declarations from text.
        Returns: (targets: list[str], has_attack_intent: bool, matched_keywords: list[str])
        Word-boundary matching: use \\b so "target" does not match "targeting".
        Keywords with len<=2 (e.g. "op") are skipped to avoid false positives.
        Phrases (with spaces) and #hashtags are specific enough for substring match.
        """
        import re as _re
        targets = self._URL_RE.findall(text)
        gov_targets = [u for u in targets if any(
            pat in u for pat in (".gov", ".mil", ".parliament", ".bundestag",
                                  ".elysee", ".president", "bank", "energy", "telecom")
        )]
        matched_kws = []
        for kw in keywords:
            if len(kw) <= 2:                          # "op" etc. — too short, causes noise; skip
                continue
            if ' ' in kw or kw.startswith('#'):       # phrase / hashtag — substring match is specific enough
                if kw in text:
                    matched_kws.append(kw)
            else:                                     # single word — word boundary prevents "targeting" matching "target"
                if _re.search(r'\b' + _re.escape(kw) + r'\b', text):
                    matched_kws.append(kw)
        has_intent = len(matched_kws) > 0
        return gov_targets[:10], has_intent, matched_kws

    def _extract_snippet(self, text: str, keywords: list, context: int = 100) -> str:
        """Extract up to 200 chars of context around the keyword as a snippet.
        Uses the same word-boundary logic as _parse_posts to prevent false-positive snippets.
        """
        import re as _re
        for kw in keywords:
            if len(kw) <= 2:
                continue
            if ' ' in kw or kw.startswith('#'):
                m = _re.search(_re.escape(kw), text)
            else:
                m = _re.search(r'\b' + _re.escape(kw) + r'\b', text)
            if m:
                idx   = m.start()
                start = max(0, idx - 60)
                end   = min(len(text), idx + len(kw) + context)
                raw   = text[start:end].strip()
                raw   = _re.sub(r'\s+', ' ', raw)
                return f"...{raw}..."
        return ""

    @classmethod
    def _log_detection(cls, theater: str, channel: str, channel_url: str,
                       status: str, keywords: list, targets: list, snippet: str) -> None:
        """Append an entry to the intercept log (CLEAR status is not recorded)."""
        entry = {
            "ts":              time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "theater":         theater,
            "channel":         channel,
            "channel_url":     channel_url,
            "status":          status,
            "keywords_matched": keywords,
            "target_urls":     targets[:5],
            "snippet":         snippet,
        }
        with cls._intercept_lock:
            cls._intercept_log.insert(0, entry)
            if len(cls._intercept_log) > cls._MAX_LOG:
                cls._intercept_log.pop()

    @classmethod
    def _compute_zscore_tg(cls, theater: str, today_normalized: float) -> tuple:
        """Compute Z-score against rolling baseline (same logic as RssNarrativeSensor).
        Returns: (z_score, mean, std). Returns (0,0,0) until ≥7 days of data."""
        with cls._intercept_lock:
            bl    = cls._baseline_tg.get(theater, {})
            daily = list(bl.get("daily_counts", []))  # snapshot under lock
        if len(daily) < 7:
            return 0.0, 0.0, 0.0
        n        = len(daily)
        mean     = sum(daily) / n
        variance = sum((x - mean) ** 2 for x in daily) / n
        std      = math.sqrt(variance) if variance > 0 else 0.0
        z        = (today_normalized - mean) / std if std > 0 else 0.0
        return round(z, 3), round(mean, 4), round(std, 4)

    @classmethod
    def _update_baseline_tg(cls, theater: str, today_normalized: float):
        """Append today's normalized frequency to rolling baseline (capped at NARRATIVE_BASELINE_DAYS)."""
        with cls._intercept_lock:
            if theater not in cls._baseline_tg:
                cls._baseline_tg[theater] = {"daily_counts": [], "last_updated": 0.0}
            bl = cls._baseline_tg[theater]
            bl["daily_counts"].append(today_normalized)
            bl["daily_counts"] = bl["daily_counts"][-NARRATIVE_BASELINE_DAYS:]
            bl["last_updated"] = time.time()

    @staticmethod
    def _count_keyword_hits(text: str, keywords: list) -> int:
        """Count total keyword occurrences in text using the same matching rules as _parse_posts."""
        import re as _re
        total = 0
        for kw in keywords:
            if len(kw) <= 2:
                continue
            if ' ' in kw or kw.startswith('#'):
                total += text.count(kw)
            else:
                total += len(_re.findall(r'\b' + _re.escape(kw) + r'\b', text))
        return total

    def fetch(self, context: dict) -> dict:
        theaters = context.get("strategic_theaters", [])
        results: dict = {}
        t0 = time.time()
        total_hits = 0
        any_success = False

        for theater in theaters:
            channels = THREAT_ACTOR_MAPPING.get(theater, [])
            if not channels:
                continue

            theater_targets: list = []
            theater_intent   = False
            active_channels: list = []
            total_kw_hits    = 0
            channels_scraped = 0

            # Compute mean confidence_weight for this theater's channel set
            ch_confidences = [
                TELEGRAM_CHANNEL_META.get(ch, {}).get("confidence_weight", 0.5)
                for ch in channels
            ]
            mean_confidence = sum(ch_confidences) / len(ch_confidences) if ch_confidences else 0.5

            import random as _rnd_jitter
            for i, channel in enumerate(channels):
                if i > 0:
                    # Inter-channel jitter: 1.5–4.0 s to reduce rate-limit fingerprinting
                    time.sleep(_rnd_jitter.uniform(1.5, 4.0))
                html = self._scrape_channel(channel)
                if not html:
                    continue
                any_success = True
                channels_scraped += 1
                text = self._extract_text(html)
                targets, has_intent, matched_kws = self._parse_posts(text, TELEGRAM_ATTACK_KEYWORDS)
                kw_hits = self._count_keyword_hits(text, TELEGRAM_ATTACK_KEYWORDS)
                total_kw_hits += kw_hits
                if has_intent or targets:
                    theater_targets.extend(targets)
                    if has_intent:
                        theater_intent = True
                    active_channels.append(channel)
                    total_hits += 1
                    snippet    = self._extract_snippet(text, matched_kws or TELEGRAM_ATTACK_KEYWORDS)
                    ch_url     = self.TGSTAT_URL.format(channel=channel)
                    det_status = "INTENT_DETECTED" if has_intent else "TARGETS_FOUND"
                    self._log_detection(theater, channel, ch_url, det_status, matched_kws, targets, snippet)

            # Z-score analysis: normalize hits per channel scraped
            normalized = total_kw_hits / max(channels_scraped, 1)
            z_score = self._compute_zscore_tg(theater, normalized)[0]
            self._update_baseline_tg(theater, normalized)

            is_burst = False
            if z_score >= NARRATIVE_ZSCORE_CRITICAL:
                tg_status = "CRITICAL_BURST"
                is_burst  = True
            elif z_score >= NARRATIVE_ZSCORE_ALERT:
                tg_status = "BURST"
                is_burst  = True
            elif theater_intent:
                tg_status = "INTENT_DETECTED"
            elif theater_targets:
                tg_status = "TARGETS_FOUND"
            else:
                tg_status = "CLEAR"

            # Multi-stage confidence: escalates with corroborating evidence
            gov_target_found = any(
                any(pat in u for pat in (".gov", ".mil", ".parliament"))
                for u in theater_targets
            )
            if is_burst:
                claim_conf = _CONF_WITH_ZSCORE_BURST
            elif theater_intent and gov_target_found:
                claim_conf = _CONF_WITH_GOV_TARGETS
            elif theater_intent:
                claim_conf = _CONF_DECLARATION_ONLY
            else:
                claim_conf = 0.0  # No claim detected

            results[theater] = {
                "channels_monitored": channels,
                "active_channels":    active_channels,
                "target_urls":        list(set(theater_targets)),
                "has_attack_intent":  theater_intent,
                "status":             tg_status,
                "z_score":            z_score,
                "is_burst":           is_burst,
                "claim_confidence":   round(claim_conf, 3),
                "confidence_stage":   ("burst" if is_burst else
                                       "gov_target" if gov_target_found and theater_intent else
                                       "declaration" if theater_intent else "none"),
                "normalized_freq":    round(normalized, 5),
            }

            # Register sequence event on intent or Z-score burst
            if theater_intent or is_burst:
                register_sequence_event(theater, "NARRATIVE_BURST", {
                    "source":   "telegram_mirror",
                    "channels": active_channels,
                    "targets":  list(set(theater_targets))[:5],
                    "z_score":  z_score,
                })

        TelegramMirrorSensor._last_poll_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        TelegramMirrorSensor._last_poll_ok = any_success or len(theaters) == 0
        self.log_fetch(any_success or len(theaters) == 0,
                       round((time.time() - t0) * 1000), 200, total_hits)
        result = {"telegram": results}
        self.set_cache(result)
        return result

