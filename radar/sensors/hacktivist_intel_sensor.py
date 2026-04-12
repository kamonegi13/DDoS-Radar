"""radar.sensors.hacktivist_intel_sensor -- HacktiivistIntelSensor.

Reads TelegramMirrorSensor's intercept log (already scraped, no new HTTP requests)
and submits detected attack declarations to the LLM Intel queue for analysis.

Processing flow:
  TelegramMirrorSensor._intercept_log (in-memory)
      ↓ all entries (CLEAR included — full-text LLM scan, no keyword pre-filter)
      ↓ dedup: skip already-processed entries (track by ts+channel)
      ↓ LLM analysis: extract target_sector, attack_type, timeline, confidence
      ↓ intel_queue.submit() → AUTO-CONFIRMED (≥0.80) or PENDING (<0.80)

This sensor runs on a longer interval (every 30 min by default) and is a
pure post-processor — it does NOT contribute its own rationale entry to the
scoring engine directly. Score contribution happens via intel_queue.
"""
from __future__ import annotations
import hashlib
import logging
import os
import time

from radar.sensors.base import BaseSensor
from radar.config import LLM_ENABLED, TELEGRAM_CHANNEL_META

log = logging.getLogger("radar")

_POLL_INTERVAL = int(os.getenv("HACKTIVIST_INTEL_POLL_INTERVAL", "1800"))  # 30 min

# Track processed entries: set of (ts_str, channel) tuples to avoid re-processing
_processed: dict[str, None] = {}
_MAX_PROCESSED = 1000  # prevent unbounded growth


def _entry_key(entry: dict) -> str:
    """Stable dedup key for an intercept log entry."""
    raw = f"{entry.get('ts','')}-{entry.get('channel','')}-{entry.get('theater','')}"
    return hashlib.md5(raw.encode()).hexdigest()


class HacktiivistIntelSensor(BaseSensor):
    """Post-processor: converts TelegramMirrorSensor detections into LLM intel items."""

    def __init__(self):
        super().__init__("hacktivist_intel", "info", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"hacktivist_intel": {"llm_disabled": True}}

        from radar.sensors.telegram import TelegramMirrorSensor
        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available, record_sensor_drop

        if not llm_available():
            log.debug("[HacktiivistIntel] LLM not available — skipping")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"hacktivist_intel": {"llm_offline": True}}

        t0 = time.time()
        submitted = 0

        with TelegramMirrorSensor._intercept_lock:
            entries = list(TelegramMirrorSensor._intercept_log)

        for entry in entries:
            key = _entry_key(entry)
            if key in _processed:
                continue

            theater      = entry.get("theater", "")
            channel      = entry.get("channel", "")
            snippet      = entry.get("snippet", "")
            text_excerpt = entry.get("text_excerpt", "")
            targets      = entry.get("target_urls", [])
            keywords     = entry.get("keywords_matched", [])
            ch_url       = entry.get("channel_url", "")

            # Use snippet if available (keyword-matched context), fall back to full excerpt
            text_content = snippet or text_excerpt
            if not text_content:
                _processed[key] = None
                continue

            # Build LLM prompt
            ch_meta = TELEGRAM_CHANNEL_META.get(channel, {})
            group_hint = ch_meta.get("group_name", channel)
            raw_text = (
                f"[Telegram channel: {channel} ({group_hint})]\n"
                f"Theater: {theater}\n"
                f"Status: {entry.get('status')}\n"
                f"Keywords matched: {', '.join(keywords) if keywords else 'none'}\n"
                f"Target URLs found: {', '.join(targets[:5]) if targets else 'none'}\n"
                f"Channel content:\n{text_content[:1000]}"
            )

            system_prompt = (
                "You are a cyber threat intelligence analyst. "
                "Analyze the following Telegram channel content from a known hacktivist community "
                "and extract structured threat intelligence. "
                "Content may include full channel page text — focus on threat-relevant signals. "
                "Respond ONLY with a JSON object, no explanation."
            )
            user_prompt = (
                f"{raw_text}\n\n"
                "Return a JSON object with these exact fields:\n"
                "{\n"
                '  "headline": "One-sentence summary of the threat (max 100 chars)",\n'
                '  "target_sector": "Primary target sector (e.g. financial, government, telecom, energy, media)",\n'
                '  "attack_type": "Type of attack (e.g. DDoS, defacement, data leak, phishing)",\n'
                '  "timeline": "Imminent (within hours), Soon (within 24h), Planned (days), Unknown",\n'
                '  "group_name": "Hacktivist group name if identifiable, else Unknown",\n'
                f' "theater": "The most relevant theater code from this list: {theater} — or null if the content targets a completely different region",\n'
                '  "countries": ["ISO codes of ALL targeted countries"],\n'
                '  "country_weights": {"ISO": 0.0-1.0 relevance weight per country},\n'
                '  "confidence": 0.0,\n'
                '  "is_credible_threat": true or false\n'
                "}\n"
                "Confidence scoring:\n"
                "- 0.80-0.95: Explicit target URLs, named attack type, imminent/active operation\n"
                "- 0.65-0.79: Named sector/country target with attack declaration\n"
                "- 0.40-0.54: Generic threat language, no specific target confirmed\n"
                "- <0.40: Noise, spam, unrelated content — set is_credible_threat=false\n"
                "If the content contains no threat signals or is clearly noise/spam, set confidence below 0.40 "
                "and is_credible_threat to false.\n"
                f"The channel is associated with theater {theater!r}. "
                "If the content clearly targets a different region, set theater=null."
            )

            result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=256)
            _processed[key] = None

            # Prune processed dict if too large (evict oldest entries)
            if len(_processed) > _MAX_PROCESSED:
                for k in list(_processed)[:_MAX_PROCESSED // 2]:
                    _processed.pop(k, None)

            if not result["ok"]:
                log.debug(f"[HacktiivistIntel] LLM parse failed for {channel}: {result.get('error')}")
                continue

            from radar.llm_client import safe_float, safe_enum
            data = result["data"]
            confidence = safe_float(data.get("confidence"), default=0.0)

            # Both conditions must be true to proceed — credible AND sufficient confidence
            if not data.get("is_credible_threat", False) or confidence < 0.35:
                log.debug(f"[HacktiivistIntel] Low credibility for {channel} conf={confidence:.2f} — skipped")
                record_sensor_drop("not_credible" if not data.get("is_credible_threat") else "below_floor")
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

            # Verify theater: use LLM-assigned theater if it disagrees with channel metadata,
            # but only if the LLM returned a non-null value (LLM can detect off-topic posts)
            llm_theater_raw = data.get("theater")
            if llm_theater_raw is None or str(llm_theater_raw).strip().upper() in ("NULL", "NONE", ""):
                log.debug(f"[HacktiivistIntel] LLM flagged theater mismatch for {channel} — skipped")
                record_sensor_drop("theater_null")
                continue
            resolved_theater = str(llm_theater_raw).strip().upper()
            # Accept LLM theater override if it's a plausible 2-letter code; otherwise keep original
            if len(resolved_theater) == 2 and resolved_theater.isalpha():
                theater = resolved_theater

            if theater not in countries:
                countries = [theater] + countries
                country_weights.setdefault(theater, 1.0)

            # Map domain: DDoS → cyber, defacement → cyber, data leak → info
            attack_type = safe_enum(
                (data.get("attack_type") or "").lower(),
                {"ddos", "defacement", "flood", "disruption", "data_leak", "phishing", "ransomware", "unknown"},
                "unknown"
            )
            domain = "cyber" if any(t in attack_type for t in ("ddos", "defacement", "flood", "disruption")) else "info"

            # Additive score: sector_base + timeline_bonus (max 3.0)
            sector = (data.get("target_sector") or "").lower()
            sector_base = 2.0 if any(s in sector for s in ("government", "financial", "energy", "telecom", "military")) else 1.0
            timeline = (data.get("timeline") or "").lower()
            timeline_bonus = {"imminent": 1.0, "soon": 0.5, "planned": 0.2}.get(timeline, 0.0)
            score_delta = min(round(sector_base + timeline_bonus, 1), 3.0)

            item = {
                "source_type":  "hacktivist",
                "source_id":    f"hacktivist_{channel}",
                "theater":      theater,
                "countries":    countries,
                "country_weights": country_weights,
                "ts":           time.time(),
                "confidence":   confidence,
                "raw_text":     raw_text[:1000],
                "raw_url":      ch_url,
                "headline":     data.get("headline", f"Hacktivist activity detected: {channel}")[:100],
                "llm_fields": {
                    "target_sector": data.get("target_sector", ""),
                    "attack_type":   data.get("attack_type", ""),
                    "timeline":      data.get("timeline", "Unknown"),
                    "group_name":    data.get("group_name", group_hint),
                    "channel_id":    channel,
                },
                "score_delta":  score_delta,
                "domain":       domain,
            }

            item_id = intel_queue.submit(item)
            if item_id:
                submitted += 1
                log.info(f"[HacktiivistIntel] Submitted: {item['headline'][:60]} "
                         f"(conf={confidence:.2f}, theater={theater})")

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(True, duration_ms, 0, submitted)
        result_data = {"hacktivist_intel": {"submitted": submitted, "processed_total": len(_processed)}}
        self.set_cache(result_data)
        return result_data
