"""Tests for CertspotterSource (Phase 2A primary CT source).

The tests are HTTP-mocked — no real certspotter calls — so they run
deterministically in CI and don't burn the upstream's free-tier 30 req/hr
budget. The certspotter response shape mirrored here was validated
empirically against the live API during Phase 2 design (see commit
context: mofa.gov.tw, mod.gov.tw etc. all returned the exact dict shape
we parse below).

Coverage:
  * Response parsing: dns_names + issuer.name → CertObservation tuple
  * Skip-on-malformed: missing issuer → observation dropped (issuer_norm
    == "unknown" can't be deduped)
  * Wildcard SAN preservation: `*.gov.tw` survives into
    subject_alt_names so the orchestrator's wildcard-TLD detector still
    sees it
  * Failure-mode counters: timeout / 5xx / 4xx / 403 / 429 each land in
    their own bucket so the operator panel can distinguish "broken" from
    "blocked"
  * Token-bucket rate limiter: enforces sliding window, doesn't burst
    across boundaries
  * Auth header injection: when CERTSPOTTER_API_TOKEN is set the local
    bucket widens AND the Authorization header rides on every request
  * Health dict shape: matches the contract defined in base.py so the
    sensor_health endpoint can render every source uniformly
"""
from __future__ import annotations

import time
from unittest.mock import patch, MagicMock

import pytest
import requests

from radar.sensors.ct_log_sources.certspotter import (
    CertspotterSource,
    _TokenBucket,
)
from radar.sensors.ct_log_sources.base import CertObservation


# ── Response parsing ─────────────────────────────────────────────────────

def _make_response(status: int, body=None, headers=None):
    """Build a requests.Response-shaped MagicMock."""
    res = MagicMock(spec=requests.Response)
    res.status_code = status
    res.json = MagicMock(return_value=body if body is not None else [])
    res.text = ""
    res.headers = headers or {}
    return res


_SAMPLE_CERT = {
    "id": "10356725417",
    "tbs_sha256": "abc",
    "cert_sha256": "def",
    "dns_names": ["no06.mofa.gov.tw", "*.mofa.gov.tw"],
    "pubkey_sha256": "ghi",
    "issuer": {"name": "C=TW, O=\"Chunghwa Telecom Co., Ltd.\", CN=HiPKI OV TLS CA - G1"},
    "not_before": "2025-05-09T00:05:10Z",
    "not_after": "2026-05-09T00:05:10Z",
    "revoked": False,
}


def test_parse_response_yields_cert_observation():
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(200, [_SAMPLE_CERT])):
        out = src.fetch_domain("mofa.gov.tw")
    assert out is not None
    assert len(out) == 1
    obs = out[0]
    assert isinstance(obs, CertObservation)
    assert obs.domain == "mofa.gov.tw"
    # parse_issuer splits on `,` without honoring quoted commas in DN
    # values — the documented trade-off. The trailing `, Ltd.` piece is
    # dropped, but the remaining key is stable across sources (crt.sh
    # gets the same truncation), which is what the dedup needs.
    assert obs.issuer_norm == "chunghwa telecom co."
    assert "Chunghwa Telecom" in obs.issuer_raw
    assert obs.common_name == "no06.mofa.gov.tw"
    # Wildcard SAN must survive — the orchestrator's wildcard-TLD detector
    # depends on seeing it.
    assert "*.mofa.gov.tw" in obs.subject_alt_names
    assert obs.serial == "10356725417"
    assert obs.source_name == "certspotter"


def test_parse_response_skips_malformed_issuer():
    """An issuance with no parseable issuer DN can't be deduped — drop it
    rather than fabricate an `unknown` key."""
    bad_cert = dict(_SAMPLE_CERT)
    bad_cert["issuer"] = None
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(200, [bad_cert])):
        out = src.fetch_domain("mofa.gov.tw")
    assert out == []


def test_parse_response_handles_string_issuer():
    """Some certspotter responses send issuer as a flat string rather than
    a {"name": ...} object. Treat both as equivalent inputs."""
    cert = dict(_SAMPLE_CERT)
    cert["issuer"] = "C=US, O=Let's Encrypt, CN=R3"
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(200, [cert])):
        out = src.fetch_domain("mofa.gov.tw")
    assert len(out) == 1
    assert out[0].issuer_norm == "let's encrypt"


def test_parse_response_picks_non_wildcard_for_common_name():
    """When dns_names contains both `*.foo` and `bar.foo`, prefer the
    non-wildcard form for common_name. The wildcard still rides in SANs."""
    cert = dict(_SAMPLE_CERT)
    cert["dns_names"] = ["*.gov.tw", "president.gov.tw", "*.president.gov.tw"]
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(200, [cert])):
        out = src.fetch_domain("gov.tw")
    assert out[0].common_name == "president.gov.tw"
    assert "*.gov.tw" in out[0].subject_alt_names


def test_empty_response_returns_empty_list_not_none():
    """200 + [] is meaningful — upstream confirms 'no recent certs'. The
    orchestrator uses this to advance the warm-up marker."""
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(200, [])):
        out = src.fetch_domain("mofa.gov.tw")
    assert out == []
    assert src._failure_modes["empty_result"] == 1


# ── Failure modes ────────────────────────────────────────────────────────

def test_timeout_increments_timeout_counter_and_returns_none():
    src = CertspotterSource()
    with patch(
        "radar.sensors.ct_log_sources.certspotter.requests.get",
        side_effect=requests.exceptions.Timeout("read timeout"),
    ):
        out = src.fetch_domain("mofa.gov.tw")
    assert out is None
    assert src._failure_modes["timeout"] == 1
    assert src._consecutive_failures == 1


def test_connection_error_increments_conn_error_counter():
    src = CertspotterSource()
    with patch(
        "radar.sensors.ct_log_sources.certspotter.requests.get",
        side_effect=requests.exceptions.ConnectionError("DNS fail"),
    ):
        out = src.fetch_domain("mofa.gov.tw")
    assert out is None
    assert src._failure_modes["conn_error"] == 1


def test_403_lands_in_dedicated_bucket():
    """403 from certspotter on ccTLD gov domains (e.g. gov.ua) is a
    region/policy block — must be distinguishable from generic 4xx so the
    operator can decide whether to remove the domain from the watched
    set or wait for upstream policy change."""
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(403)):
        out = src.fetch_domain("president.gov.ua")
    assert out is None
    assert src._failure_modes["http_403"] == 1
    assert src._failure_modes["http_4xx"] == 0


def test_429_arms_rate_limit_window_and_uses_retry_after():
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(429, headers={"Retry-After": "120"})):
        out = src.fetch_domain("mofa.gov.tw")
    assert out is None
    assert src._failure_modes["http_4xx"] == 1
    assert src._last_retry_after_sec == 120
    assert src._rate_limited_until_ts > time.time()
    # While the upstream rate-limit is armed, subsequent calls short-circuit
    # without touching the network.
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get") as gm:
        out2 = src.fetch_domain("president.gov.tw")
    assert out2 is None
    assert gm.call_count == 0


def test_500_increments_5xx_counter():
    src = CertspotterSource()
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(503)):
        out = src.fetch_domain("mofa.gov.tw")
    assert out is None
    assert src._failure_modes["http_5xx"] == 1


def test_invalid_json_increments_json_error_counter():
    src = CertspotterSource()
    bad = _make_response(200)
    bad.json.side_effect = ValueError("not json")
    bad.text = "<html>oops</html>"
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=bad):
        out = src.fetch_domain("mofa.gov.tw")
    assert out is None
    assert src._failure_modes["json_error"] == 1


def test_success_resets_consecutive_failures():
    src = CertspotterSource()
    src._consecutive_failures = 4
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               return_value=_make_response(200, [])):
        src.fetch_domain("mofa.gov.tw")
    assert src._consecutive_failures == 0
    assert src._status == "healthy"
    assert src._last_success_ts > 0


# ── Token-bucket rate limiter ────────────────────────────────────────────

def test_bucket_allows_up_to_max_then_blocks():
    b = _TokenBucket(max_calls=3, window_sec=3600)
    assert b.try_acquire()
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()
    assert b.remaining() == 0


def test_bucket_releases_after_window():
    b = _TokenBucket(max_calls=2, window_sec=60)
    # Backdate two calls outside the window.
    b._calls = [time.time() - 120, time.time() - 90]
    assert b.try_acquire()
    assert b.remaining() == 1


def test_bucket_next_slot_in_sec_is_zero_when_room():
    b = _TokenBucket(max_calls=2, window_sec=3600)
    b.try_acquire()
    assert b.next_slot_in_sec() == 0.0


def test_bucket_next_slot_in_sec_is_positive_when_full():
    b = _TokenBucket(max_calls=1, window_sec=3600)
    b.try_acquire()
    assert b.next_slot_in_sec() > 3500


def test_local_rate_limit_blocks_fetch_without_network_call():
    """When the local bucket is exhausted the fetch path must short-circuit
    before hitting requests.get — that's the entire point of the bucket."""
    src = CertspotterSource(rate_limit_calls=1, rate_limit_window_sec=3600)
    src._bucket._calls = [time.time()]  # exhaust the bucket
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get") as gm:
        out = src.fetch_domain("mofa.gov.tw")
    assert out is None
    assert gm.call_count == 0
    assert src._failure_modes["rate_limited_local"] == 1


# ── Auth header / token handling ─────────────────────────────────────────

def test_api_token_widens_local_bucket_and_injects_auth_header():
    src = CertspotterSource(api_token="secret-token-123",
                            rate_limit_calls=10)
    # Authenticated callers should not be capped at the free-tier 25.
    assert src._rate_limit_calls >= 250

    captured = {}

    def fake_get(url, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return _make_response(200, [])

    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               side_effect=fake_get):
        src.fetch_domain("mofa.gov.tw")

    assert captured["headers"].get("Authorization") == "Bearer secret-token-123"


def test_no_api_token_omits_auth_header():
    captured = {}

    def fake_get(url, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return _make_response(200, [])

    src = CertspotterSource()  # no token
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get",
               side_effect=fake_get):
        src.fetch_domain("mofa.gov.tw")

    assert "Authorization" not in captured["headers"]


# ── CB / mark_dead ───────────────────────────────────────────────────────

def test_mark_dead_opens_cb_and_blocks_subsequent_fetches():
    src = CertspotterSource()
    src.mark_dead(cooldown_sec=300)
    assert src._status == "dead"
    with patch("radar.sensors.ct_log_sources.certspotter.requests.get") as gm:
        out = src.fetch_domain("mofa.gov.tw")
    assert out is None
    assert gm.call_count == 0


def test_health_dict_matches_uniform_shape():
    """The operator panel renders every source through the same template;
    the shape here is the contract the panel expects."""
    src = CertspotterSource(api_token="t")
    h = src.health()
    assert set(["status", "last_success_ts", "consecutive_failures",
                "mode_counters", "source_specific"]).issubset(h.keys())
    ss = h["source_specific"]
    assert "rate_limit_calls" in ss
    assert "local_bucket_remaining" in ss
    assert ss["authenticated"] is True
