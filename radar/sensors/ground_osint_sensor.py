"""radar.sensors.ground_osint_sensor -- GroundOsintSensor.

Supplements existing DDoS sensors by detecting pre-attack and in-progress
attack declarations from Telegram channels, then correlating with live
sensor data to provide:
  1. Pre-attack warning: declaration before Cloudflare/CheckHost detect impact
  2. Attribution: links observed DDoS traffic to declared actor/group
  3. Coverage gap: catches attacks on targets outside the focused scenario

Compared to HacktiivistIntelSensor (which does general intent analysis),
GroundOsintSensor focuses specifically on:
  - "Attack is starting NOW / underway" signals
  - Direct correlation with live CloudFlare and CheckHost sensor data
  - Estimating whether the LLM-detected claim is backed by real traffic

LLM fields extracted:
  ddos_target      : target domain/IP/sector mentioned
  attack_vector    : http_flood | l3_volumetric | tcp_syn | application | mixed
  is_ongoing       : true if attack described as currently in progress
  corroborates_cf  : LLM's assessment of whether CF data would show this
  source_platform  : telegram | forum | paste | twitter
"""
from __future__ import annotations
import logging
import os
import time

from radar.sensors.base import BaseSensor
from radar.config import LLM_ENABLED, TELEGRAM_CHANNEL_META

log = logging.getLogger("radar")

_POLL_INTERVAL = int(os.getenv("GROUND_OSINT_POLL_INTERVAL", "1800"))  # 30 min

# Keywords indicating an ongoing or imminent attack (stronger signal than HacktiivistIntel)
_ONGOING_KEYWORDS = {
    "under attack", "being attacked", "going down", "site down", "offline now",
    "attack started", "attack launched", "flood started", "hitting now",
    "攻撃中", "攻撃開始", "ダウン", "落ちた",
}

# Processed entry keys (same dedup logic as HacktiivistIntelSensor)
_processed: dict[str, None] = {}
_MAX_PROCESSED = 500


def _entry_key(entry: dict) -> str:
    import hashlib
    raw = f"gnd-{entry.get('ts','')}-{entry.get('channel','')}-{entry.get('theater','')}"
    return hashlib.md5(raw.encode()).hexdigest()


def _has_ongoing_signal(snippet: str, targets: list) -> bool:
    """Check if snippet contains ongoing-attack language."""
    lower = snippet.lower()
    return any(kw in lower for kw in _ONGOING_KEYWORDS) or len(targets) >= 2


class GroundOsintSensor(BaseSensor):
    """Correlates Telegram DDoS declarations with live CF/CheckHost sensor data."""

    def __init__(self):
        super().__init__("ground_osint", "info", _POLL_INTERVAL)

    def _get_live_sensor_snapshot(self, registry) -> dict:
        """Pull current cache from Cloudflare and CheckHost sensors for correlation."""
        snapshot = {}
        try:
            cf = registry.get("cloudflare_radar")
            if cf:
                snapshot["cf"] = cf.get_cache()
        except Exception:
            pass
        try:
            ch = registry.get("check_host")
            if ch:
                snapshot["checkhost"] = ch.get_cache()
        except Exception:
            pass
        return snapshot

    def _cf_has_active_attack(self, cf_cache: dict, theater: str) -> bool:
        """Check if Cloudflare cache shows active attack traffic for the theater."""
        try:
            attacks = cf_cache.get("attacks", {})
            # CF cache structure: attacks[theater] = {l3: [...], l7: [...]}
            theater_data = attacks.get(theater, {})
            l3 = theater_data.get("l3", [])
            l7 = theater_data.get("l7", [])
            return bool(l3 or l7)
        except Exception:
            return False

    def _checkhost_degraded(self, ch_cache: dict, theater: str) -> bool:
        """Check if CheckHost shows degraded reachability for the theater."""
        try:
            results = ch_cache.get("results", {})
            theater_data = results.get(theater, {})
            success_rate = theater_data.get("success_rate", 1.0)
            return success_rate < 0.7
        except Exception:
            return False

    def fetch(self, context: dict) -> dict:
        if not LLM_ENABLED:
            self.log_fetch(True, 0, 0, 0, "")
            return {"ground_osint": {"llm_disabled": True}}

        from radar.sensors.telegram import TelegramMirrorSensor
        from radar.intel_queue import intel_queue
        from radar.llm_client import llm_analyze_json, llm_available, record_sensor_drop, safe_float, safe_enum, sanitize_llm_input, today_str

        if not llm_available():
            log.debug("[GroundOsint] LLM not available — skipping")
            self.log_fetch(True, 0, 0, 0, "llm_unavailable")
            return {"ground_osint": {"llm_offline": True}}

        t0 = time.time()
        submitted = 0

        # Get live sensor snapshot for correlation
        registry = context.get("_registry")
        live = self._get_live_sensor_snapshot(registry) if registry else {}
        cf_cache = live.get("cf", {})
        ch_cache = live.get("checkhost", {})

        with TelegramMirrorSensor._intercept_lock:
            entries = list(TelegramMirrorSensor._intercept_log)

        for entry in entries:
            # Ground OSINT focuses on entries with actual target URLs (more concrete)
            targets = entry.get("target_urls", [])
            snippet = entry.get("snippet", "")
            status  = entry.get("status", "")

            if status not in {"INTENT_DETECTED", "TARGETS_FOUND", "BURST", "CRITICAL_BURST"}:
                continue
            if not targets and not _has_ongoing_signal(snippet, targets):
                continue

            key = _entry_key(entry)
            if key in _processed:
                continue

            theater = entry.get("theater", "")
            channel = entry.get("channel", "")
            ch_url  = entry.get("channel_url", "")
            ch_meta = TELEGRAM_CHANNEL_META.get(channel, {})
            group_hint = ch_meta.get("group_name", channel)

            # Check live correlation
            cf_active  = self._cf_has_active_attack(cf_cache, theater)
            ch_degraded = self._checkhost_degraded(ch_cache, theater)
            corroborates = cf_active or ch_degraded

            safe_snippet = sanitize_llm_input(snippet, 400)
            raw_text = (
                f"[Ground OSINT — Telegram: {channel} ({group_hint})]\n"
                f"Theater: {theater}\n"
                f"Status: {status}\n"
                f"Target URLs: {', '.join(targets[:5])}\n"
                f"Snippet: {snippet}\n"
                f"CF active attack detected: {cf_active}\n"
                f"CheckHost degraded: {ch_degraded}"
            )
            llm_raw = (
                f"[Ground OSINT — Telegram: {channel} ({group_hint})]\n"
                f"Theater: {theater}\n"
                f"Status: {status}\n"
                f"Target URLs: {', '.join(targets[:5])}\n"
                f"Snippet: {safe_snippet}\n"
                f"CF active attack detected: {cf_active}\n"
                f"CheckHost degraded: {ch_degraded}"
            )

            system_prompt = (
                "You are a DDoS threat intelligence analyst. "
                "Analyze this ground-level OSINT report from a Telegram channel "
                "and assess whether it represents an active or imminent DDoS attack. "
                "Respond ONLY with a JSON object."
            )
            user_prompt = (
                f"{llm_raw}\n\n"
                "Return a JSON object with these exact fields:\n"
                "{\n"
                '  "headline": "One-sentence attack summary (max 100 chars)",\n'
                '  "ddos_target": "Primary target domain, IP, or sector",\n'
                '  "attack_vector": "http_flood | l3_volumetric | tcp_syn | application | mixed | unknown",\n'
                '  "is_ongoing": true or false,\n'
                '  "corroborates_sensor": true or false,\n'
                '  "source_platform": "telegram",\n'
                '  "confidence": 0.0\n'
                "}\n"
                "confidence scoring guide:\n"
                "- 0.85-0.95: Specific target URLs + ongoing language\n"
                "- 0.70-0.84: Specific targets named, intent clear\n"
                "- 0.55-0.69: Generic intent, no specific targets\n"
                "- <0.55: Noise or unverifiable claim — set is_ongoing=false\n"
                "Set corroborates_sensor=true only if the content explicitly describes "
                "an ongoing or just-launched attack. Do not factor in sensor data from the context header."
            )

            result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=256)
            _processed[key] = None

            if len(_processed) > _MAX_PROCESSED:
                for k in list(_processed)[:_MAX_PROCESSED // 2]:
                    _processed.pop(k, None)

            if not result["ok"]:
                log.debug(f"[GroundOsint] LLM parse failed for {channel}: {result.get('error')}")
                continue

            data = result["data"]
            confidence = safe_float(data.get("confidence"), default=0.0)

            # Boost confidence if live sensors already show attack (single boost, Python-only)
            python_boost = 0.0
            if corroborates and confidence >= 0.35:
                python_boost = 0.10
                confidence = min(confidence + python_boost, 0.95)

            if confidence < 0.35:
                log.debug(f"[GroundOsint] Low confidence {confidence:.2f} for {channel} — skipped")
                record_sensor_drop("below_floor")
                continue

            # score_delta: higher for ongoing attacks corroborated by sensors
            is_ongoing   = data.get("is_ongoing", False)
            corr_sensor  = data.get("corroborates_sensor", False) or corroborates
            if is_ongoing and corr_sensor:
                score_delta = 3.0   # Active + corroborated: strongest signal
            elif is_ongoing or corr_sensor:
                score_delta = 2.0   # One condition met
            else:
                score_delta = 1.0   # Declaration only

            countries = [theater] if theater else []
            country_weights = {theater: 1.0} if theater else {}

            item = {
                "source_type":  "ground_osint",
                "source_id":    f"ground_osint_{channel}",
                "theater":      theater,
                "countries":    countries,
                "country_weights": country_weights,
                "ts":           time.time(),
                "confidence":   round(confidence, 3),
                "raw_text":     raw_text[:1000],
                "raw_url":      ch_url,
                "headline":     data.get("headline", f"Ground OSINT: DDoS activity {theater}")[:100],
                "llm_fields": {
                    "ddos_target":        data.get("ddos_target", ""),
                    "attack_vector":      data.get("attack_vector", "unknown"),
                    "is_ongoing":         is_ongoing,
                    "corroborates_sensor": corr_sensor,
                    "source_platform":    "telegram",
                    "channel_id":         channel,
                    "python_confidence_boost": python_boost,
                },
                "score_delta":  score_delta,
                "domain":       "cyber",
            }

            item_id = intel_queue.submit(item)
            if item_id:
                submitted += 1
                log.info(
                    f"[GroundOsint] Submitted: {item['headline'][:60]} "
                    f"(conf={confidence:.2f}, ongoing={is_ongoing}, corr={corr_sensor})"
                )

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(True, duration_ms, 0, submitted)
        result_data = {"ground_osint": {"submitted": submitted}}
        self.set_cache(result_data)
        return result_data
