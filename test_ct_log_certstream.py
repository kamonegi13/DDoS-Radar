"""Tests for CertstreamSource (Phase 2B push CT source).

The ws transport is NOT exercised here — `process_message` is a pure
function-of-state wrapper that takes a JSON string and writes to the
shared buffer, which lets us test the filter pipeline (coarse pre-filter
→ exact watched-apex check → observation construction) without standing
up a real WebSocketApp loop. The transport is covered by the live spike
script (_spike_certstream.py) which is run manually.

Coverage:
  * _build_suffix_set: derives SLD endings (gov.tw, go.jp) from apexes
  * _match_watched: apex hit, subdomain hit, wildcard hit, the
    `notkantei.go.jp` near-miss trap rejected, empty-string safe
  * process_message: coarse pre-filter rejects unrelated certs cheaply
  * process_message: records exactly one observation per matched apex
  * process_message: a cert spanning N watched apexes records N times
  * process_message: heartbeat counted, no observation
  * process_message: malformed JSON / non-dict counted, no observation
  * health(): status precedence — unknown → healthy → degraded → dead
  * update_watched(): hot-reload swaps the suffix set atomically
"""
from __future__ import annotations

import json
import time

import pytest

from radar.sensors.ct_log_sources.buffer import ObservationBuffer
from radar.sensors.ct_log_sources.certstream import (
    CertstreamSource,
    _build_suffix_set,
    _match_watched,
)


# ── Pure-function helpers ────────────────────────────────────────────────

def test_build_suffix_set_extracts_slds():
    """Last-2-labels of each apex feeds the coarse-filter set. So
    `cisa.gov` (already 2 labels) goes in as-is, while `mofa.gov.tw`
    contributes `gov.tw`.
    """
    s = _build_suffix_set(["mofa.gov.tw", "kantei.go.jp", "cisa.gov"])
    assert "gov.tw" in s
    assert "go.jp" in s
    assert "cisa.gov" in s


def test_build_suffix_set_handles_dirty_input():
    s = _build_suffix_set(["", None, "  GOV.TW  ", ".kantei.go.jp"])
    assert "gov.tw" in s
    assert "go.jp" in s
    # empty / None / single-label-after-strip should not crash
    assert "" not in s


def test_match_watched_apex_hit():
    watched = {"mofa.gov.tw"}
    assert _match_watched("mofa.gov.tw", watched) == "mofa.gov.tw"


def test_match_watched_subdomain_hit():
    watched = {"kantei.go.jp"}
    assert _match_watched("attacker.kantei.go.jp", watched) == "kantei.go.jp"


def test_match_watched_wildcard_strips_prefix():
    watched = {"kantei.go.jp"}
    assert _match_watched("*.kantei.go.jp", watched) == "kantei.go.jp"


def test_match_watched_rejects_lookalike_prefix():
    """`notkantei.go.jp` must not match watched `kantei.go.jp` — this is
    the suffix-vs-substring trap that motivated using `endswith("." + w)`
    instead of `endswith(w)`.
    """
    watched = {"kantei.go.jp"}
    assert _match_watched("notkantei.go.jp", watched) is None


def test_match_watched_empty_string_safe():
    assert _match_watched("", {"x.com"}) is None
    assert _match_watched(None, {"x.com"}) is None  # type: ignore[arg-type]


def test_match_watched_case_insensitive():
    watched = {"mofa.gov.tw"}
    assert _match_watched("ATTACKER.MOFA.GOV.TW", watched) == "mofa.gov.tw"


# ── process_message: filter & record ─────────────────────────────────────

def _make_source(watched=("mofa.gov.tw", "kantei.go.jp")) -> CertstreamSource:
    buf = ObservationBuffer(max_obs=1000, window_hours=24)
    return CertstreamSource(
        buffer=buf,
        watched_domains=list(watched),
        ws_url="wss://example/test",
    )


def _calidog_msg(*, sans, issuer="C=US, O=Let's Encrypt, CN=R3", cn=None,
                 not_before=None, message_type="certificate_update"):
    if not_before is None:
        not_before = time.time() - 3600  # 1h ago — inside the 24h window
    if cn is None:
        cn = sans[0] if sans else ""
    return json.dumps({
        "message_type": message_type,
        "data": {
            "leaf_cert": {
                "all_domains": sans,
                "subject": {"CN": cn},
                "issuer": {"C": "US", "O": "Let's Encrypt", "CN": "R3"} if "Let" in issuer else {"raw": issuer},
                "not_before": not_before,
                "serial_number": "abc123",
            },
        },
    })


def test_process_message_coarse_filter_rejects_unrelated():
    """A cert for example.com with watched={mofa.gov.tw} must be rejected
    at the coarse-suffix step — no per-watched-domain comparison cost.
    """
    src = _make_source(watched=("mofa.gov.tw",))
    raw = _calidog_msg(sans=["example.com", "www.example.com"])
    recorded = src.process_message(raw)
    assert recorded == 0
    assert src._messages_total == 1
    assert src._matches_total == 0


def test_process_message_records_apex_match():
    src = _make_source(watched=("mofa.gov.tw",))
    raw = _calidog_msg(sans=["mofa.gov.tw"])
    recorded = src.process_message(raw)
    assert recorded == 1
    assert src._matches_total == 1
    drained = src._buffer.drain_for_scoring()
    assert "mofa.gov.tw" in drained
    assert len(drained["mofa.gov.tw"]) == 1


def test_process_message_records_subdomain_match():
    src = _make_source(watched=("kantei.go.jp",))
    raw = _calidog_msg(sans=["attacker.kantei.go.jp"])
    recorded = src.process_message(raw)
    assert recorded == 1
    drained = src._buffer.drain_for_scoring()
    assert "kantei.go.jp" in drained


def test_process_message_records_wildcard_subject():
    src = _make_source(watched=("kantei.go.jp",))
    raw = _calidog_msg(sans=["*.kantei.go.jp"])
    recorded = src.process_message(raw)
    assert recorded == 1
    obs = src._buffer.drain_for_scoring()["kantei.go.jp"][0]
    # SAN list must preserve the wildcard so the orchestrator's wildcard-TLD
    # detector can still fire on it.
    assert "*.kantei.go.jp" in obs.subject_alt_names


def test_process_message_records_each_matched_apex_once():
    """One cert spanning two watched apexes → two observations."""
    src = _make_source(watched=("mofa.gov.tw", "kantei.go.jp"))
    raw = _calidog_msg(sans=["mofa.gov.tw", "kantei.go.jp", "unrelated.example.com"])
    recorded = src.process_message(raw)
    assert recorded == 2
    drained = src._buffer.drain_for_scoring()
    assert set(drained.keys()) == {"mofa.gov.tw", "kantei.go.jp"}


def test_process_message_handles_heartbeat():
    src = _make_source()
    raw = json.dumps({"message_type": "heartbeat", "data": {}})
    recorded = src.process_message(raw)
    assert recorded == 0
    assert src._failure_modes["heartbeat_only"] == 1
    assert src._matches_total == 0


def test_process_message_malformed_json_counted():
    src = _make_source()
    recorded = src.process_message("{not json")
    assert recorded == 0
    assert src._failure_modes["parse_error"] == 1


def test_process_message_non_dict_counted():
    src = _make_source()
    recorded = src.process_message(json.dumps([1, 2, 3]))
    assert recorded == 0
    assert src._failure_modes["non_dict_message"] == 1


def test_process_message_drops_obs_with_unparseable_issuer():
    """Issuer that resolves to "unknown" via parse_issuer must be dropped
    before reaching the buffer — without a normalized issuer the dedup key
    breaks down.
    """
    src = _make_source(watched=("mofa.gov.tw",))
    msg = {
        "message_type": "certificate_update",
        "data": {
            "leaf_cert": {
                "all_domains": ["mofa.gov.tw"],
                "subject": {"CN": "mofa.gov.tw"},
                "issuer": {},  # empty → DN string ""
                "not_before": time.time() - 3600,
                "serial_number": "x",
            },
        },
    }
    recorded = src.process_message(json.dumps(msg))
    assert recorded == 0


def test_process_message_drops_obs_with_unparseable_not_before():
    """make_observation returns None when not_before can't be parsed."""
    src = _make_source(watched=("mofa.gov.tw",))
    raw = _calidog_msg(sans=["mofa.gov.tw"], not_before="garbage")
    recorded = src.process_message(raw)
    assert recorded == 0
    assert src._failure_modes["make_obs_failed"] == 1


# ── health() status precedence ───────────────────────────────────────────

def test_health_unknown_before_first_message():
    src = _make_source()
    h = src.health()
    assert h["status"] == "unknown"
    assert h["source_specific"]["messages_total"] == 0


def test_health_healthy_after_recent_message():
    src = _make_source(watched=("mofa.gov.tw",))
    src.process_message(_calidog_msg(sans=["mofa.gov.tw"]))
    h = src.health()
    assert h["status"] == "healthy"
    assert h["source_specific"]["matches_total"] == 1


def test_health_degraded_when_failures_present():
    src = _make_source()
    src._consecutive_failures = 1
    src._last_message_ts = time.time()  # otherwise stays "unknown"
    h = src.health()
    assert h["status"] == "degraded"


def test_health_degraded_when_liveness_breached():
    src = _make_source()
    # Pretend last message arrived a long time ago
    src._last_message_ts = time.time() - (src._liveness_sec + 60)
    h = src.health()
    assert h["status"] == "degraded"
    assert h["source_specific"]["liveness_breached"] is True


def test_health_dead_after_many_consecutive_failures():
    src = _make_source()
    src._consecutive_failures = 6
    h = src.health()
    assert h["status"] == "dead"


# ── update_watched(): hot-reload ─────────────────────────────────────────

def test_update_watched_swaps_suffix_set():
    src = _make_source(watched=("mofa.gov.tw",))
    # Initially gov.tw matches
    raw = _calidog_msg(sans=["new.kantei.go.jp"])
    assert src.process_message(raw) == 0  # not in watched yet
    src.update_watched(["kantei.go.jp"])
    raw2 = _calidog_msg(sans=["new.kantei.go.jp"])
    assert src.process_message(raw2) == 1  # now matches


def test_update_watched_drops_stale_apex():
    src = _make_source(watched=("mofa.gov.tw", "kantei.go.jp"))
    src.update_watched(["mofa.gov.tw"])  # drop kantei
    raw = _calidog_msg(sans=["foo.kantei.go.jp"])
    assert src.process_message(raw) == 0
