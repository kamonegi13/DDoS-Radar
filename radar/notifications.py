"""radar.notifications — external alert dispatch.

Sends alerts to Slack-compat webhooks (including Discord's `/slack`
endpoint), Microsoft Teams, native Discord webhooks, and generic HTTP
webhooks when threat level changes, ambush patterns are detected,
sequence chains complete, or drift events accumulate.

Configuration via environment variables:
  NOTIFY_SLACK_WEBHOOK    — Slack Incoming Webhook URL. Discord's
                            ``/slack`` compatibility endpoint also
                            accepts this format.
  NOTIFY_DISCORD_WEBHOOK  — Native Discord webhook URL. When set,
                            sends rich embeds with native colors,
                            fields, and the NP7 disclaimer footer.
  NOTIFY_TEAMS_WEBHOOK    — Microsoft Teams Incoming Webhook URL.
  NOTIFY_WEBHOOK_URL      — Generic HTTP POST webhook (raw JSON).
  NOTIFY_DEBOUNCE_SEC     — Minimum seconds between same-type alerts
                            (default: 300).
  NOTIFY_ENABLED          — "false" disables all notifications.
  RADAR_PUBLIC_URL        — Base URL the analyst uses to reach the
                            Noroshi UI. When set, notifications
                            embed a deep link to the affected scenario.
                            Example: http://192.168.107.1:8000

Severity tiers (D1-B, 2026-05-12):
  critical — TL1/TL2, ambush, full sequence chains, red drift.
             Color: red. Adds a prominent CRITICAL header.
  warn     — TL3, partial sequence chains, sensor failure.
             Color: orange.
  info     — TL4/TL5, de-escalations, auto-acks. Color: green.

NP7 (organizational node): every dispatched message carries the
``Final judgment by analyst organization`` footer so a recipient
cannot mistake the alert for an authoritative conclusion.
"""
from __future__ import annotations
import collections
import datetime as _dt
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger("radar")


# ── Config helpers (read dynamically so config.env changes apply live) ─────
def _slack_webhook()    -> str: return os.getenv("NOTIFY_SLACK_WEBHOOK", "")
def _discord_webhook()  -> str: return os.getenv("NOTIFY_DISCORD_WEBHOOK", "")
def _teams_webhook()    -> str: return os.getenv("NOTIFY_TEAMS_WEBHOOK", "")
def _generic_webhook()  -> str: return os.getenv("NOTIFY_WEBHOOK_URL", "")
def _debounce_sec()     -> int: return int(os.getenv("NOTIFY_DEBOUNCE_SEC", "300"))
def _enabled()          -> bool: return os.getenv("NOTIFY_ENABLED", "true").lower() != "false"
def _public_url()       -> str: return os.getenv("RADAR_PUBLIC_URL", "").rstrip("/")


# NP7 footer text. Kept short so it fits in every channel's footer field.
NP7_FOOTER = (
    "Final judgment by analyst organization. "
    "One signal node, not a complete assessment."
)


# ── Severity tier (D1-B) ──────────────────────────────────────────────────


@dataclass(frozen=True)
class _SeverityStyle:
    label: str            # "critical" / "warn" / "info"
    emoji: str            # 🔴 / 🟠 / 🟢
    discord_color: int    # 0xRRGGBB
    slack_color: str      # "#rrggbb"
    teams_color: str      # "RRGGBB"


_SEVERITY: dict[str, _SeverityStyle] = {
    "critical": _SeverityStyle("critical", "🔴", 0xE74C3C, "#e74c3c", "E74C3C"),
    "warn":     _SeverityStyle("warn",     "🟠", 0xF39C12, "#f39c12", "F39C12"),
    "info":     _SeverityStyle("info",     "🟢", 0x2ECC71, "#2ecc71", "2ECC71"),
}


def _severity(name: str) -> _SeverityStyle:
    return _SEVERITY.get(name, _SEVERITY["warn"])


def _severity_for_tl(new_level: int, old_level: int) -> str:
    """Map (old, new) threat level pair → severity tier.

    Escalations to TL1/TL2 are critical, escalations to TL3 are warn,
    everything else (TL4/TL5 or de-escalations) is info.
    """
    if new_level < old_level:  # escalation (lower number = higher threat)
        if new_level <= 2:
            return "critical"
        if new_level == 3:
            return "warn"
        return "info"
    # de-escalation or no change
    return "info"


# ── Debounce tracker ──────────────────────────────────────────────────────

_last_sent: dict[str, float] = {}
_lock = threading.Lock()


def _should_send(alert_key: str) -> bool:
    """Return True if this alert type hasn't been sent within debounce window."""
    with _lock:
        now = time.time()
        last = _last_sent.get(alert_key, 0)
        if now - last < _debounce_sec():
            return False
        _last_sent[alert_key] = now
        return True


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


# ── Channel-specific senders ──────────────────────────────────────────────


def _send_slack(title: str, text: str, severity: str,
                fields: list[dict] | None = None,
                url: str = "") -> None:
    """Send to a Slack-compat webhook. Discord's `/slack` endpoint
    also accepts this format and renders attachments as embeds.

    Slack attachments support a `fields` list, `title`, `title_link`,
    `text`, `color`, and `ts` — Discord maps each to the embed
    equivalent so this single payload renders richly on both platforms.
    """
    target = _slack_webhook()
    if not target:
        return
    style = _severity(severity)
    attachment: dict = {
        "color": style.slack_color,
        "title": title,
        "text": text,
        "ts": int(time.time()),
        "footer": NP7_FOOTER,
        "mrkdwn_in": ["text", "fields"],
    }
    if url:
        attachment["title_link"] = url
    if fields:
        attachment["fields"] = [
            {"title": f["name"], "value": str(f["value"])[:512],
             "short": bool(f.get("inline", True))}
            for f in fields
        ]
    payload = {"attachments": [attachment]}
    resp = requests.post(target, json=payload, timeout=10)
    if resp.status_code not in (200, 204):
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:120]}")


def _send_discord(title: str, text: str, severity: str,
                  fields: list[dict] | None = None,
                  url: str = "") -> None:
    """Send to a native Discord webhook with a rich embed.

    Unlike the Slack-compat path, this uses Discord's first-class embed
    schema directly — better field rendering, native color, footer text,
    and ISO timestamp. Configure NOTIFY_DISCORD_WEBHOOK to enable.
    """
    target = _discord_webhook()
    if not target:
        return
    style = _severity(severity)
    embed: dict = {
        "title": f"{style.emoji} {title}",
        "description": text,
        "color": style.discord_color,
        "footer": {"text": NP7_FOOTER},
        "timestamp": _iso_now(),
    }
    if url:
        embed["url"] = url
    if fields:
        embed["fields"] = [
            {"name": str(f["name"])[:256],
             "value": str(f["value"])[:1024],
             "inline": bool(f.get("inline", True))}
            for f in fields[:25]  # Discord embed field cap
        ]
    payload = {
        "username": "Noroshi",
        "embeds": [embed],
    }
    resp = requests.post(target, json=payload, timeout=10)
    if resp.status_code not in (200, 204):
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:120]}")


def _send_teams(title: str, text: str, severity: str,
                fields: list[dict] | None = None,
                url: str = "") -> None:
    """Send to a Microsoft Teams webhook via the MessageCard schema."""
    target = _teams_webhook()
    if not target:
        return
    style = _severity(severity)
    section: dict = {
        "activityTitle": f"{style.emoji} {title}",
        "text": text,
        "markdown": True,
    }
    if fields:
        section["facts"] = [
            {"name": str(f["name"])[:256],
             "value": str(f["value"])[:512]}
            for f in fields
        ]
    card: dict = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": style.teams_color,
        "summary": title,
        "sections": [section, {"text": f"_{NP7_FOOTER}_"}],
    }
    if url:
        card["potentialAction"] = [{
            "@type": "OpenUri",
            "name": "Open in Noroshi",
            "targets": [{"os": "default", "uri": url}],
        }]
    resp = requests.post(target, json=card, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:120]}")


def _send_generic(event_type: str, data: dict) -> None:
    """Send a structured JSON envelope to the generic HTTP webhook."""
    target = _generic_webhook()
    if not target:
        return
    payload = {
        "event": event_type,
        "timestamp": time.time(),
        "data": data,
        "disclaimer": NP7_FOOTER,
    }
    resp = requests.post(target, json=payload, timeout=10)
    if resp.status_code not in (200, 201, 202, 204):
        raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:120]}")


# ── In-memory notification log (UI ring buffer) ───────────────────────────

_notification_log: collections.deque[dict] = collections.deque(maxlen=50)


def get_notification_log() -> list[dict]:
    """Return recent notification delivery log for UI display."""
    with _lock:
        return list(_notification_log)


def _log_delivery(channel: str, event_type: str, title: str,
                  success: bool, detail: str = "") -> None:
    entry = {
        "ts": time.time(), "channel": channel, "event": event_type,
        "title": title, "success": success, "detail": detail,
    }
    with _lock:
        _notification_log.append(entry)
    try:
        from radar.ws import emit_notification_result
        emit_notification_result(entry)
    except Exception:
        pass


# ── Dispatch (D1-B/C: severity + Discord-native + slack-compat) ───────────


def _dispatch(event_type: str, title: str, text: str, *,
              severity: str = "warn",
              fields: list[dict] | None = None,
              url: str = "",
              data: dict | None = None) -> None:
    """Fan out one notification to every configured channel.

    ``severity`` drives color, emoji, and (in future) digest routing.
    ``fields`` is a list of ``{name, value, inline?}`` dicts that each
    channel renders into its native field equivalent.
    ``url`` is the deep link back into the Noroshi UI (when
    ``RADAR_PUBLIC_URL`` is configured by the caller).
    ``data`` is the raw event payload forwarded to the generic webhook.
    """
    if not _enabled():
        return
    data = data or {}

    def _wrap(name: str, fn) -> None:
        try:
            fn()
            _log_delivery(name, event_type, title, True)
        except Exception as e:
            _log_delivery(name, event_type, title, False, str(e))

    # Channels fire in parallel daemon threads so a slow webhook never
    # blocks the scoring tick. NP3 — every error is captured per channel.
    if _slack_webhook():
        threading.Thread(
            target=_wrap, daemon=True,
            args=("slack", lambda: _send_slack(
                title, text, severity, fields=fields, url=url)),
        ).start()
    if _discord_webhook():
        threading.Thread(
            target=_wrap, daemon=True,
            args=("discord", lambda: _send_discord(
                title, text, severity, fields=fields, url=url)),
        ).start()
    if _teams_webhook():
        threading.Thread(
            target=_wrap, daemon=True,
            args=("teams", lambda: _send_teams(
                title, text, severity, fields=fields, url=url)),
        ).start()
    if _generic_webhook():
        threading.Thread(
            target=_wrap, daemon=True,
            args=("webhook", lambda: _send_generic(event_type, data)),
        ).start()


def _scenario_url(scenario_id: str) -> str:
    """Build a deep link to a scenario's UI page, or "" if no public URL."""
    base = _public_url()
    if not base or not scenario_id:
        return ""
    return f"{base}/?focus={scenario_id}"


# ── Public API ────────────────────────────────────────────────────────────


def notify_scenario_tl_change(scenario_id: str, scenario_name: str,
                              old_level: int, new_level: int,
                              score: float,
                              what_changed: dict | None = None) -> None:
    """Notify when a scenario's threat level changes.

    Phase C migrated this away from the legacy theater-based notifier
    (``notify_threat_level_change``) which was removed 2026-05-12 after
    Discord users reported a duplicate-notification pattern: both fired
    on every TL transition.

    severity is derived from the new_level (TL1/TL2 = critical, TL3 =
    warn, TL4+ or de-escalation = info). The notification includes the
    domain delta, gained/lost signal list, and a deep link back into
    the scenario page when RADAR_PUBLIC_URL is configured.
    """
    alert_key = f"sc_tl_change:{scenario_id}"
    if not _should_send(alert_key):
        return

    severity = _severity_for_tl(new_level, old_level)
    direction = "ESCALATED" if new_level < old_level else "DE-ESCALATED"
    # Headline carries direction + TL transition + scenario name in one
    # scannable line; description carries the absolute score and the
    # scenario_id (kept as code for click/grep ergonomics).
    title = f"{direction} · TL{old_level} → TL{new_level} — {scenario_name}"
    text = f"Score **{score:.2f}** · `{scenario_id}`"

    # Fields carry only the diagnostic delta — the *why* this TL changed.
    # The previous tabular restatement of scenario/previous/current/score
    # was pure repetition of the title and description.
    fields: list[dict] = []
    if what_changed:
        deltas = what_changed.get("domain_deltas") or {}
        if deltas:
            parts = [f"{d.upper()} {v:+.1f}" for d, v in deltas.items()]
            fields.append({
                "name": "Domains",
                "value": " · ".join(parts), "inline": False,
            })
        new_sigs = what_changed.get("new_signals") or []
        if new_sigs:
            fields.append({
                "name": "Signals added",
                "value": ", ".join(new_sigs)[:512], "inline": False,
            })
        lost_sigs = what_changed.get("removed_signals") or []
        if lost_sigs:
            fields.append({
                "name": "Signals removed",
                "value": ", ".join(lost_sigs)[:512], "inline": False,
            })

    data = {
        "scenario_id": scenario_id, "scenario_name": scenario_name,
        "old_level": old_level, "new_level": new_level,
        "score": score, "direction": direction,
        "severity": severity,
        "what_changed": what_changed,
    }
    log.info(f"[Notify] {title} — {scenario_id} TL{old_level}->TL{new_level}")
    _dispatch("scenario_tl_change", title, text,
              severity=severity, fields=fields,
              url=_scenario_url(scenario_id), data=data)


def notify_ambush_alert(theater: str, alert_data: dict) -> None:
    """Notify on ambush pattern detection. Always treated as critical."""
    alert_key = f"ambush:{theater}"
    if not _should_send(alert_key):
        return

    title = f"AMBUSH PATTERN — {theater}"
    z_score = alert_data.get("z_score", 0)
    accel = alert_data.get("acceleration", 0)
    velocity = alert_data.get("velocity", 0)
    # Description retains the historical-context sentence (genuine analytic
    # value) and the scenario id as code for click/grep. The previous
    # standalone Theater field duplicated the title.
    text = (
        f"`{theater}` — sudden coordinated acceleration. "
        f"This pattern historically precedes large-scale offensive activity."
    )
    fields = [
        {"name": "Z-score",  "value": f"{z_score:.2f}", "inline": True},
        {"name": "Accel.",   "value": f"{accel:.2f}", "inline": True},
        {"name": "Velocity", "value": f"{velocity:.2f}", "inline": True},
    ]
    data = {"theater": theater, **alert_data}
    log.warning(f"[Notify] {title}")
    _dispatch("ambush_alert", title, text,
              severity="critical", fields=fields,
              url=_scenario_url(theater), data=data)


def notify_sequence_complete(theater: str, chain_status: str,
                             events: list) -> None:
    """Notify when a sequence chain reaches FULL_CHAIN or PARTIAL."""
    if chain_status not in ("FULL_CHAIN", "PARTIAL"):
        return
    alert_key = f"sequence:{theater}:{chain_status}"
    if not _should_send(alert_key):
        return

    severity = "critical" if chain_status == "FULL_CHAIN" else "warn"
    title = f"Sequence Chain {chain_status} — {theater}"
    event_types = [e.get("type", "?") for e in events]
    # Description carries the chain itself — that *is* the headline content.
    # Previous Theater/Status/Length inline fields all restated title or
    # description, so they're dropped.
    text = (
        f"`{theater}` · {len(events)} events · "
        f"{' → '.join(event_types)[:1024]}"
    )
    fields: list[dict] = []
    data = {"theater": theater, "status": chain_status, "events": events}
    log.warning(f"[Notify] {title}")
    _dispatch("sequence_chain", title, text,
              severity=severity, fields=fields,
              url=_scenario_url(theater), data=data)


def notify_drift_unack(events: list[dict]) -> None:
    """Notify when red-severity drift events have stayed unack.

    Called by the daily scheduler hook when amber events have been
    auto-ack'd but red ones remain.
    """
    if not events:
        return
    earliest = min(int(e.get("id") or 0) for e in events)
    alert_key = f"drift_unack:{len(events)}:{earliest}"
    if not _should_send(alert_key):
        return

    title = f"Calibration drift unacknowledged ({len(events)} red)"
    text = (
        f"{len(events)} red-severity calibration drift event(s) have been "
        f"unacknowledged longer than the notify threshold. Review on the "
        f"AUTO-TUNE dashboard."
    )
    sample_lines = []
    for e in events[:5]:
        sc = e.get("scenario_id") or "?"
        sig = e.get("drift_signal") or "?"
        d = e.get("days_unack", 0)
        cc = e.get("target_country") or ""
        suffix = f" [{cc}]" if cc else ""
        sample_lines.append(f"• `{sc}` / {sig}{suffix} ({d:.1f}d unack)")
    if len(events) > 5:
        sample_lines.append(f"… and {len(events) - 5} more")
    fields = [
        {"name": "Total red events", "value": str(len(events)), "inline": True},
        {"name": "Oldest event ID", "value": str(earliest), "inline": True},
        {"name": "Sample", "value": "\n".join(sample_lines)[:1024],
         "inline": False},
    ]
    data = {"count": len(events), "earliest_id": earliest,
            "events": events[:10]}
    log.warning(f"[Notify] {title}")
    _dispatch("drift_unack", title, text,
              severity="critical", fields=fields, data=data)


def notify_sensor_failure(sensor_name: str, error: str) -> None:
    """Notify on persistent sensor failure (after retries exhausted)."""
    alert_key = f"sensor_fail:{sensor_name}"
    if not _should_send(alert_key):
        return

    title = f"Sensor failure — {sensor_name}"
    text = (
        f"Sensor `{sensor_name}` has failed after all retry attempts. "
        f"Investigate before signal coverage degrades further."
    )
    fields = [
        {"name": "Sensor", "value": f"`{sensor_name}`", "inline": True},
        {"name": "Error",  "value": error[:512] if error else "(no detail)",
         "inline": False},
    ]
    data = {"sensor": sensor_name, "error": error}
    log.warning(f"[Notify] {title}")
    _dispatch("sensor_failure", title, text,
              severity="warn", fields=fields, data=data)
