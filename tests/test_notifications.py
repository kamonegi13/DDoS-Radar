"""Tests for radar.notifications — Discord-native + severity-tiered dispatch.

Covers the 2026-05-12 rewrite:
- D0: notify_threat_level_change removed (only notify_scenario_tl_change remains)
- D1-A: NP7 footer present on every payload
- D1-B: severity tier (critical/warn/info) drives color and emoji
- D1-C: native Discord embed path (NOTIFY_DISCORD_WEBHOOK)
- D1-D: RADAR_PUBLIC_URL produces a deep-link `url` field
- D1-E: scenario_id appears once (as a labelled field), not duplicated in title
"""
from __future__ import annotations

import os
from typing import Any
from unittest.mock import patch

import pytest

# Avoid app-import side effects (this module doesn't depend on the Flask app).
os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

from radar import notifications  # noqa: E402


# ── helpers ───────────────────────────────────────────────────────────────


class _FakeResp:
    def __init__(self, status_code: int = 200, text: str = "ok") -> None:
        self.status_code = status_code
        self.text = text


@pytest.fixture(autouse=True)
def _reset_debounce():
    """Clear the debounce dict between tests so back-to-back calls send."""
    notifications._last_sent.clear()
    yield
    notifications._last_sent.clear()


@pytest.fixture
def captured(monkeypatch):
    """Capture every (target_kind, url, payload) sent during a test."""
    seen: list[dict] = []

    def _fake_post(url, json=None, timeout=None, **kw):
        # Determine which channel based on the configured webhook URL.
        kind = None
        for k, env in (
            ("slack",   "NOTIFY_SLACK_WEBHOOK"),
            ("discord", "NOTIFY_DISCORD_WEBHOOK"),
            ("teams",   "NOTIFY_TEAMS_WEBHOOK"),
            ("webhook", "NOTIFY_WEBHOOK_URL"),
        ):
            if url == os.getenv(env, ""):
                kind = k
                break
        seen.append({"kind": kind or "unknown", "url": url, "payload": json})
        return _FakeResp(200)

    monkeypatch.setattr(notifications.requests, "post", _fake_post)
    return seen


def _wait_for_dispatch():
    """notifications._dispatch fires per-channel daemon threads. We can't
    join all daemons (the radar process has many unrelated long-lived
    workers); instead we poll the captured-call list until it stops
    growing for a short stable window. With the mocked requests.post
    each thread completes in <1ms so this returns near-instantly.
    """
    import time as _t
    # Allow scheduler / radar workers (unrelated to this test) to keep
    # running by giving notifications a short head start, then a settle
    # window. Total upper bound: ~0.5s per dispatch call.
    _t.sleep(0.15)


# ── D0: legacy function removed ───────────────────────────────────────────


def test_legacy_theater_notifier_is_gone() -> None:
    assert not hasattr(notifications, "notify_threat_level_change"), (
        "notify_threat_level_change must be removed — it caused duplicate "
        "TL change notifications alongside notify_scenario_tl_change."
    )


# ── D1-B: severity mapping ────────────────────────────────────────────────


@pytest.mark.parametrize("old,new,expected", [
    (4, 2, "critical"),  # escalate into critical band
    (4, 1, "critical"),
    (4, 3, "warn"),      # escalate into warn band
    (5, 4, "info"),      # escalate but still low
    (2, 4, "info"),      # de-escalation always info
])
def test_severity_for_tl(old: int, new: int, expected: str) -> None:
    assert notifications._severity_for_tl(new, old) == expected


# ── D1-C/D/E: Discord-native embed contents ───────────────────────────────


def test_scenario_tl_change_sends_discord_embed_with_np7_and_deep_link(
    monkeypatch, captured,
):
    monkeypatch.setenv("NOTIFY_DISCORD_WEBHOOK", "https://discord.test/hook")
    monkeypatch.setenv("RADAR_PUBLIC_URL", "https://radar.example.com")
    monkeypatch.delenv("NOTIFY_SLACK_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_TEAMS_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)

    notifications.notify_scenario_tl_change(
        "taiwan_contingency", "Taiwan Contingency",
        old_level=4, new_level=2, score=8.1,
        what_changed={
            "domain_deltas": {"info": 0.5, "cyber": 0.3},
            "new_signals": ["bg_observer_rss"],
        },
    )
    _wait_for_dispatch()

    discord_calls = [c for c in captured if c["kind"] == "discord"]
    assert len(discord_calls) == 1, (
        f"expected one discord call, got {len(discord_calls)}: {captured}"
    )
    embed = discord_calls[0]["payload"]["embeds"][0]
    # D1-B: severity → red color + 🔴 emoji
    assert embed["color"] == notifications._SEVERITY["critical"].discord_color
    assert embed["title"].startswith("🔴 ")
    # D1-E: scenario_id appears once (in the description as code), not
    # duplicated in the title or restated as a labelled field.
    assert "taiwan_contingency" not in embed["title"]
    assert "`taiwan_contingency`" in embed["description"]
    field_names = {f["name"] for f in embed["fields"]}
    assert "Scenario" not in field_names, (
        "redundant Scenario field must be dropped — scenario_id lives in "
        "the description now (one mention, not two)"
    )
    # Fields carry only the diagnostic delta (the *why*).
    assert "Domains" in field_names
    assert "Signals added" in field_names
    # D1-D: deep link constructed from RADAR_PUBLIC_URL
    assert embed["url"] == (
        "https://radar.example.com/?focus=taiwan_contingency"
    )
    # D1-A: NP7 disclaimer in footer
    assert "Final judgment by analyst organization" in embed["footer"]["text"]


def test_scenario_tl_change_omits_url_when_public_url_unset(
    monkeypatch, captured,
):
    monkeypatch.setenv("NOTIFY_DISCORD_WEBHOOK", "https://discord.test/hook")
    monkeypatch.delenv("RADAR_PUBLIC_URL", raising=False)
    monkeypatch.delenv("NOTIFY_SLACK_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_TEAMS_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)

    notifications.notify_scenario_tl_change(
        "korean_peninsula", "Korean Peninsula",
        old_level=4, new_level=3, score=5.0,
    )
    _wait_for_dispatch()

    discord_calls = [c for c in captured if c["kind"] == "discord"]
    assert discord_calls, "expected at least one discord call"
    embed = discord_calls[0]["payload"]["embeds"][0]
    assert "url" not in embed, (
        "embed must omit url when RADAR_PUBLIC_URL is unset (NP3 graceful)"
    )


# ── Slack-compat (Discord /slack endpoint) renders with title_link too ────


def test_slack_compat_path_includes_title_link_and_footer(
    monkeypatch, captured,
):
    monkeypatch.setenv("NOTIFY_SLACK_WEBHOOK", "https://discord.test/slack")
    monkeypatch.setenv("RADAR_PUBLIC_URL", "https://radar.example.com")
    monkeypatch.delenv("NOTIFY_DISCORD_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_TEAMS_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)

    notifications.notify_scenario_tl_change(
        "middle_east", "Middle East",
        old_level=4, new_level=2, score=7.5,
    )
    _wait_for_dispatch()

    slack_calls = [c for c in captured if c["kind"] == "slack"]
    assert slack_calls, "expected slack-compat dispatch"
    attachment = slack_calls[0]["payload"]["attachments"][0]
    assert attachment["title_link"] == (
        "https://radar.example.com/?focus=middle_east"
    )
    assert "Final judgment by analyst organization" in attachment["footer"]
    # severity drives color
    assert attachment["color"] == (
        notifications._SEVERITY["critical"].slack_color
    )


# ── Debounce still active ─────────────────────────────────────────────────


def test_debounce_blocks_second_call_within_window(monkeypatch, captured):
    monkeypatch.setenv("NOTIFY_DISCORD_WEBHOOK", "https://discord.test/hook")
    monkeypatch.delenv("NOTIFY_SLACK_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_TEAMS_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)

    notifications.notify_scenario_tl_change(
        "eastern_europe", "Eastern Europe",
        old_level=4, new_level=2, score=8.0,
    )
    notifications.notify_scenario_tl_change(
        "eastern_europe", "Eastern Europe",
        old_level=2, new_level=1, score=9.5,
    )
    _wait_for_dispatch()

    discord_calls = [c for c in captured if c["kind"] == "discord"]
    assert len(discord_calls) == 1, (
        "debounce window should suppress the second call for the same "
        f"scenario; got {len(discord_calls)} calls"
    )


# ── Generic webhook payload carries the disclaimer ────────────────────────


def test_generic_webhook_includes_disclaimer(monkeypatch, captured):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://generic.test/hook")
    monkeypatch.delenv("NOTIFY_SLACK_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_DISCORD_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_TEAMS_WEBHOOK", raising=False)

    notifications.notify_sensor_failure("opensky", "timeout")
    _wait_for_dispatch()

    web_calls = [c for c in captured if c["kind"] == "webhook"]
    assert web_calls
    payload = web_calls[0]["payload"]
    assert "Final judgment by analyst organization" in payload["disclaimer"]
    assert payload["event"] == "sensor_failure"


# ── notify_drift_unack still produces critical severity ───────────────────


def test_drift_unack_uses_critical_severity(monkeypatch, captured):
    monkeypatch.setenv("NOTIFY_DISCORD_WEBHOOK", "https://discord.test/hook")
    monkeypatch.delenv("NOTIFY_SLACK_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_TEAMS_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)

    notifications.notify_drift_unack([
        {"id": 7, "scenario_id": "taiwan_contingency",
         "drift_signal": "participant_silent", "days_unack": 2.4,
         "target_country": "TW"},
    ])
    _wait_for_dispatch()

    discord_calls = [c for c in captured if c["kind"] == "discord"]
    assert discord_calls
    embed = discord_calls[0]["payload"]["embeds"][0]
    assert embed["color"] == notifications._SEVERITY["critical"].discord_color


# ── NP3: a failing channel must not affect other channels ─────────────────


def test_channel_failure_does_not_block_others(monkeypatch):
    """If Slack returns 500, Discord must still receive the embed.
    Per-channel exceptions are logged but never propagate."""
    monkeypatch.setenv("NOTIFY_SLACK_WEBHOOK", "https://broken.test/hook")
    monkeypatch.setenv("NOTIFY_DISCORD_WEBHOOK", "https://discord.test/hook")
    monkeypatch.delenv("NOTIFY_TEAMS_WEBHOOK", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)

    seen: list[str] = []

    def _fake_post(url, json=None, timeout=None, **kw):
        seen.append(url)
        if "broken" in url:
            return _FakeResp(500, "boom")
        return _FakeResp(200)

    monkeypatch.setattr(notifications.requests, "post", _fake_post)
    notifications.notify_sensor_failure("apt_intel", "downstream timeout")
    _wait_for_dispatch()

    assert any("discord.test" in u for u in seen), (
        "Discord embed must still send even when Slack channel raises"
    )
