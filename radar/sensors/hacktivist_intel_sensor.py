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
_processed: set[str] = set()
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
        from radar.llm_client import llm_analyze_json, llm_available

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
                _processed.add(key)
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
                '  "confidence": 0.0,\n'
                '  "is_credible_threat": true or false\n'
                "}\n"
                "Set confidence between 0.55 and 0.95 based on:\n"
                "- Specificity of targets (URLs, sector, country)\n"
                "- Presence of attack keywords or declarations\n"
                "- Channel credibility\n"
                "- Coherence of the threat claim\n"
                "If the content contains no threat signals or is clearly noise/spam, set confidence below 0.40 "
                "and is_credible_threat to false."
            )

            result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=256)
            _processed.add(key)

            # Prune processed set if too large
            if len(_processed) > _MAX_PROCESSED:
                # Remove oldest half (sets are unordered; just clear a chunk)
                to_remove = list(_processed)[:_MAX_PROCESSED // 2]
                for k in to_remove:
                    _processed.discard(k)

            if not result["ok"]:
                log.debug(f"[HacktiivistIntel] LLM parse failed for {channel}: {result.get('error')}")
                continue

            data = result["data"]
            confidence = float(data.get("confidence", 0.0))

            if not data.get("is_credible_threat", False) and confidence < 0.55:
                log.debug(f"[HacktiivistIntel] Low credibility for {channel} — skipped")
                continue

            # Map domain: DDoS → cyber, defacement → cyber, data leak → info
            attack_type = (data.get("attack_type") or "").lower()
            domain = "cyber" if any(t in attack_type for t in ("ddos", "defacement", "flood", "disruption")) else "info"

            # score_delta: 1 for basic declaration, 2 for specific gov/financial targets
            sector = (data.get("target_sector") or "").lower()
            score_delta = 2.0 if any(s in sector for s in ("government", "financial", "energy", "telecom", "military")) else 1.0

            item = {
                "source_type":  "hacktivist",
                "source_id":    f"telegram_{channel}",
                "theater":      theater,
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
