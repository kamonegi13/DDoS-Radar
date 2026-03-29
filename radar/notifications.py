"""radar.notifications -- External alert notification system.

Sends alerts to Slack, Microsoft Teams, and generic Webhooks
when threat level changes, ambush patterns are detected, or
sequence chains complete.

Configuration via environment variables:
  NOTIFY_SLACK_WEBHOOK    — Slack Incoming Webhook URL
  NOTIFY_TEAMS_WEBHOOK    — Microsoft Teams Incoming Webhook URL
  NOTIFY_WEBHOOK_URL      — Generic HTTP POST webhook URL
  NOTIFY_DEBOUNCE_SEC     — Minimum seconds between same-type alerts (default: 300)
  NOTIFY_ENABLED          — Set to "false" to disable all notifications
"""
from __future__ import annotations
import json
import logging
import os
import threading
import time
from typing import Optional
import requests

log = logging.getLogger("radar")

# ── Config helpers (read dynamically so changes to config.env take effect without restart) ──
def _slack_webhook()   -> str:  return os.getenv("NOTIFY_SLACK_WEBHOOK", "")
def _teams_webhook()   -> str:  return os.getenv("NOTIFY_TEAMS_WEBHOOK", "")
def _generic_webhook() -> str:  return os.getenv("NOTIFY_WEBHOOK_URL", "")
def _debounce_sec()    -> int:  return int(os.getenv("NOTIFY_DEBOUNCE_SEC", "300"))
def _enabled()         -> bool: return os.getenv("NOTIFY_ENABLED", "true").lower() != "false"

# Debounce tracker: {alert_key: last_sent_timestamp}
_last_sent: dict[str, float] = {}
_lock = threading.Lock()


def _should_send(alert_key: str) -> bool:
    """Check debounce — return True if this alert type hasn't been sent recently."""
    with _lock:
        now = time.time()
        last = _last_sent.get(alert_key, 0)
        if now - last < _debounce_sec():
            return False
        _last_sent[alert_key] = now
        return True


def _send_slack(text: str, color: str = "#ff0000"):
    """Send alert to Slack via Incoming Webhook. Raises on failure."""
    url = _slack_webhook()
    if not url:
        return
    payload = {
        "attachments": [{
            "color": color,
            "text": text,
            "ts": int(time.time()),
        }]
    }
    resp = requests.post(url, json=payload, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:100]}")


def _send_teams(title: str, text: str, color: str = "FF0000"):
    """Send alert to Microsoft Teams via Incoming Webhook. Raises on failure."""
    url = _teams_webhook()
    if not url:
        return
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": color,
        "summary": title,
        "sections": [{
            "activityTitle": title,
            "text": text,
            "markdown": True,
        }]
    }
    resp = requests.post(url, json=payload, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:100]}")


def _send_generic(event_type: str, data: dict):
    """Send alert to generic webhook as JSON POST. Raises on failure."""
    url = _generic_webhook()
    if not url:
        return
    payload = {
        "event": event_type,
        "timestamp": time.time(),
        "data": data,
    }
    resp = requests.post(url, json=payload, timeout=10)
    if resp.status_code not in (200, 201, 202, 204):
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:100]}")


# ── Notification log (ring buffer for UI feedback) ───────────────────────────
_notification_log: list[dict] = []
_NOTIFY_LOG_MAX = 50

def get_notification_log() -> list[dict]:
    """Return recent notification delivery log for UI display."""
    with _lock:
        return list(_notification_log)

def _log_delivery(channel: str, event_type: str, title: str, success: bool, detail: str = ""):
    """Record a notification delivery attempt."""
    entry = {
        "ts": time.time(), "channel": channel, "event": event_type,
        "title": title, "success": success, "detail": detail,
    }
    with _lock:
        _notification_log.append(entry)
        if len(_notification_log) > _NOTIFY_LOG_MAX:
            _notification_log.pop(0)
    # Emit to connected clients via WS
    try:
        from radar.ws import emit_notification_result
        emit_notification_result(entry)
    except Exception:
        pass


def _dispatch(event_type: str, title: str, text: str, data: dict,
              color_slack: str = "#ff0000", color_teams: str = "FF0000"):
    """Dispatch to all configured channels in background threads."""
    if not _enabled():
        return

    def _slack_with_log():
        try:
            _send_slack(f"*{title}*\n{text}", color_slack)
            _log_delivery("slack", event_type, title, True)
        except Exception as e:
            _log_delivery("slack", event_type, title, False, str(e))

    def _teams_with_log():
        try:
            _send_teams(title, text, color_teams)
            _log_delivery("teams", event_type, title, True)
        except Exception as e:
            _log_delivery("teams", event_type, title, False, str(e))

    def _generic_with_log():
        try:
            _send_generic(event_type, data)
            _log_delivery("webhook", event_type, title, True)
        except Exception as e:
            _log_delivery("webhook", event_type, title, False, str(e))

    if _slack_webhook():
        threading.Thread(target=_slack_with_log, daemon=True).start()
    if _teams_webhook():
        threading.Thread(target=_teams_with_log, daemon=True).start()
    if _generic_webhook():
        threading.Thread(target=_generic_with_log, daemon=True).start()


# ── Public API ────────────────────────────────────────────────────────────────

def notify_threat_level_change(theater: str, old_level: int, new_level: int,
                                score: float):
    """Notify when threat level changes."""
    alert_key = f"tl_change:{theater}"
    if not _should_send(alert_key):
        return

    direction = "ESCALATED" if new_level < old_level else "DE-ESCALATED"
    color = "#ff0000" if new_level <= 2 else "#ff9900" if new_level <= 3 else "#36a64f"
    title = f"Threat Level {direction}: {theater}"
    text = (f"Theater **{theater}**: TL{old_level} → TL{new_level} "
            f"(score: {score:.1f})")
    data = {"theater": theater, "old_level": old_level, "new_level": new_level,
            "score": score, "direction": direction}

    log.info(f"[Notify] {title} — {text}")
    _dispatch("threat_level_change", title, text, data,
              color_slack=color, color_teams=color.replace("#", ""))


def notify_ambush_alert(theater: str, alert_data: dict):
    """Notify on ambush pattern detection."""
    alert_key = f"ambush:{theater}"
    if not _should_send(alert_key):
        return

    title = f"AMBUSH PATTERN DETECTED: {theater}"
    z_score = alert_data.get("z_score", 0)
    accel = alert_data.get("acceleration", 0)
    text = (f"Theater **{theater}**: 2nd-derivative Z-score={z_score:.2f}, "
            f"acceleration={accel:.2f}")
    data = {"theater": theater, **alert_data}

    log.info(f"[Notify] {title}")
    _dispatch("ambush_alert", title, text, data)


def notify_sequence_complete(theater: str, chain_status: str, events: list):
    """Notify when sequence chain completes or reaches partial threshold."""
    if chain_status not in ("FULL_CHAIN", "PARTIAL"):
        return

    alert_key = f"sequence:{theater}:{chain_status}"
    if not _should_send(alert_key):
        return

    title = f"Sequence Chain {chain_status}: {theater}"
    event_types = [e.get("type", "?") for e in events]
    text = f"Theater **{theater}**: {' → '.join(event_types)}"
    data = {"theater": theater, "status": chain_status, "events": events}

    color = "#ff0000" if chain_status == "FULL_CHAIN" else "#ff9900"
    log.info(f"[Notify] {title}")
    _dispatch("sequence_chain", title, text, data,
              color_slack=color, color_teams=color.replace("#", ""))


def notify_sensor_failure(sensor_name: str, error: str):
    """Notify on persistent sensor failure (after retries exhausted)."""
    alert_key = f"sensor_fail:{sensor_name}"
    if not _should_send(alert_key):
        return

    title = f"Sensor Failure: {sensor_name}"
    text = f"Sensor **{sensor_name}** has failed after retries: {error[:200]}"
    data = {"sensor": sensor_name, "error": error}

    log.warning(f"[Notify] {title}")
    _dispatch("sensor_failure", title, text, data,
              color_slack="#ff9900", color_teams="FF9900")
