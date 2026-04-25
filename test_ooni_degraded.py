"""Tests for OoniSensor self-healing degraded mode (added 2026-04-22)."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import requests

from radar.sensors.ooni import OoniSensor


def _ctx(targets):
    return {"strategic_countries": targets, "adversary_states": []}


def _mock_500():
    res = MagicMock()
    res.status_code = 500
    return res


def _mock_200(rows=None):
    res = MagicMock()
    res.status_code = 200
    res.json.return_value = {"result": rows or []}
    return res


# ── Failure-mode tracking ────────────────────────────────────────────────

def test_500_increments_http_5xx_counter():
    sensor = OoniSensor()
    with patch("radar.sensors.ooni.requests.get", return_value=_mock_500()):
        sensor.fetch(_ctx(["TW"]))
    assert sensor._failure_modes["http_5xx"] == 1
    assert sensor._failure_modes["timeout"] == 0


def test_timeout_increments_timeout_counter():
    sensor = OoniSensor()
    with patch("radar.sensors.ooni.requests.get",
               side_effect=requests.exceptions.Timeout()):
        sensor.fetch(_ctx(["TW"]))
    assert sensor._failure_modes["timeout"] == 1
    assert sensor._failure_modes["http_5xx"] == 0


def test_conn_error_increments_conn_error_counter():
    sensor = OoniSensor()
    with patch("radar.sensors.ooni.requests.get",
               side_effect=requests.exceptions.ConnectionError("boom")):
        sensor.fetch(_ctx(["TW"]))
    assert sensor._failure_modes["conn_error"] == 1


# ── Self-healing transitions ─────────────────────────────────────────────

def test_enters_degraded_after_three_consecutive_empty_cycles():
    sensor = OoniSensor()
    assert sensor._upstream_status == "unknown"
    assert sensor.poll_interval == OoniSensor._NORMAL_INTERVAL
    with patch("radar.sensors.ooni.requests.get", return_value=_mock_500()):
        for _ in range(3):
            sensor.fetch(_ctx(["TW"]))
    assert sensor._upstream_status == "degraded"
    assert sensor.poll_interval == OoniSensor._DEGRADED_INTERVAL
    assert sensor._consecutive_failures == 3


def test_does_not_enter_degraded_before_threshold():
    sensor = OoniSensor()
    with patch("radar.sensors.ooni.requests.get", return_value=_mock_500()):
        for _ in range(2):
            sensor.fetch(_ctx(["TW"]))
    assert sensor._upstream_status != "degraded"
    assert sensor.poll_interval == OoniSensor._NORMAL_INTERVAL


def test_degraded_mode_probes_one_country_only():
    """Once degraded, probe_targets shrinks to one to avoid hammering.

    We can't trust mock.call_count because radar.sensors.* share the same
    requests module object, so background scheduler threads spuriously
    increment any patched mock. Instead, count failures the OONI sensor
    itself attributes to api.ooni.io via _failure_modes.
    """
    sensor = OoniSensor()

    def ooni_only_500(url, **kwargs):
        if "api.ooni.io" in url:
            return _mock_500()
        # Anything else: fail loudly so we notice if a non-OONI call
        # somehow reaches this side_effect.
        raise AssertionError(f"unexpected non-OONI URL: {url}")

    with patch("radar.sensors.ooni.requests.get", side_effect=ooni_only_500):
        for _ in range(3):
            sensor.fetch(_ctx(["TW", "US", "JP", "KR"]))
        assert sensor._upstream_status == "degraded"
        before = sensor._failure_modes["http_5xx"]
        sensor.fetch(_ctx(["TW", "US", "JP", "KR"]))
        delta = sensor._failure_modes["http_5xx"] - before
        # In degraded mode, exactly one theater should be probed → one 500.
        assert delta == 1, f"expected 1 OONI request in degraded mode, got {delta}"


def test_recovery_snaps_back_to_normal_cadence():
    sensor = OoniSensor()
    # Drive into degraded
    with patch("radar.sensors.ooni.requests.get", return_value=_mock_500()):
        for _ in range(3):
            sensor.fetch(_ctx(["TW"]))
    assert sensor._upstream_status == "degraded"
    # Single 200 response should restore normal cadence
    with patch("radar.sensors.ooni.requests.get", return_value=_mock_200()):
        sensor.fetch(_ctx(["TW"]))
    assert sensor._upstream_status == "healthy"
    assert sensor._consecutive_failures == 0
    assert sensor.poll_interval == OoniSensor._NORMAL_INTERVAL


# ── Diagnostics surface ──────────────────────────────────────────────────

def test_upstream_health_exposes_status_and_failure_modes():
    sensor = OoniSensor()
    health = sensor.upstream_health()
    assert "status" in health
    assert "consecutive_failures" in health
    assert "current_interval_sec" in health
    assert "failure_modes" in health
    for key in ("timeout", "conn_error", "http_5xx", "http_4xx", "json_error"):
        assert key in health["failure_modes"]
