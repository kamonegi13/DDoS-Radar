"""GreyNoise GNQL-unavailable handling.

GreyNoise deprecated the v2 GNQL stats endpoint in 2026 (HTTP 410). The
sensor previously special-cased only 401, so any other non-200 status was
swallowed into an empty stats dict, leaving the sensor permanently
success=False on the health dashboard (a false DEGRADED). GNQL being
unavailable is *normal operation* for non-Enterprise keys / a dead endpoint:
the sensor degrades to UNKNOWN (no confidence suppression) and must report
success=True.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")

import radar.sensors.greynoise as g


@pytest.fixture
def keyed(monkeypatch):
    """Simulate a configured API key so the GNQL path is exercised."""
    monkeypatch.setattr(g, "GREYNOISE_API_KEY", "x" * 64)


def _fetch_with_status(status: int) -> tuple:
    s = g.GreyNoiseSensor()
    resp = MagicMock()
    resp.status_code = status
    resp.text = "stub"
    with patch.object(g.requests, "get", return_value=resp):
        out = s.fetch({"strategic_theaters": ["TW", "JP"]})
    return s, out


@pytest.mark.parametrize("status", [410, 401, 403, 429])
def test_non_200_gnql_degrades_to_unknown_success_true(keyed, status):
    s, out = _fetch_with_status(status)
    log = s.get_fetch_log()[-1]
    assert log["success"] is True, f"status {status} must not mark a fetch failure"
    assert s._gnql_unavailable is True
    assert out["greynoise"]["TW"]["noise_class"] == "UNKNOWN"
    assert out["greynoise"]["TW"]["suppress_confidence"] is False


def test_gnql_unavailable_warned_once(keyed):
    s, _ = _fetch_with_status(410)
    # Second poll must not re-flip or crash; flag stays set.
    resp = MagicMock(); resp.status_code = 410; resp.text = "stub"
    with patch.object(g.requests, "get", return_value=resp):
        s.fetch({"strategic_theaters": ["TW"]})
    assert s._gnql_unavailable is True
    assert s.get_fetch_log()[-1]["success"] is True


def test_no_key_is_success_unknown(monkeypatch):
    """No API key at all → UNKNOWN, success=True (normal OPSEC-friendly mode)."""
    monkeypatch.setattr(g, "GREYNOISE_API_KEY", "")
    s = g.GreyNoiseSensor()
    out = s.fetch({"strategic_theaters": ["TW"]})
    assert s.get_fetch_log()[-1]["success"] is True
    assert out["greynoise"]["TW"]["noise_class"] == "UNKNOWN"
