"""Tests for the multi-source CtLogSensor orchestrator (Phase 1).

The orchestrator is the seam introduced when the legacy single-file
implementation was split into transport-owning sources + a shared
ObservationBuffer + scoring orchestrator. The trust-class evaluation
itself (test_ct_log_redesign.py) is unchanged; what these tests cover is
the new wiring:

  * Backfill flow: orchestrator drives each pull source per selected
    domain, the source's CertObservation list is recorded into the buffer,
    and drain returns observations grouped by domain for scoring.
  * Source semantics:
      - source returns None (transport failure) → no buffer write
      - source returns []   (200 OK, no certs)  → no write, warm-up armed
      - source returns [obs] (data)             → recorded, drain returns
  * Multi-source idempotency: when the buffer keys collapse a duplicate
    observation across sources, scoring fires exactly once.
  * Self-healing degraded mode: 3 consecutive None-only cycles flip the
    sensor into degraded mode; one alive cycle recovers it.
  * Parity: feeding a recorded crt.sh fixture through the orchestrator
    produces the same scoring outcome the pre-refactor implementation
    would have produced for the same fixture.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.database import RadarDB
from radar.sensors.ct_log import CtLogSensor, CT_LOG_DEGRADED_INTERVAL_SEC
from radar.sensors.ct_log_sources.base import (
    BaseCtLogPullSource,
    CertObservation,
)
from radar.sensors.ct_log_sources.crtsh import _parse_issuer
from radar.config import (
    CT_LOG_WARMUP_DAYS,
    CT_LOG_OBSERVATION_WINDOW_HOURS,
)
from radar import database as _db_mod


# ── Fakes ─────────────────────────────────────────────────────────────────

class FakePullSource(BaseCtLogPullSource):
    """Programmable pull source for orchestrator tests.

    Two response modes:
      - per_domain={d: [r1, r2, ...]}: per-domain queue. Useful when the
        test wants to assert that obs come back for one specific watched
        domain. For domains not in the map: falls through to default.
      - default=[r1, r2, ...]: response queue applied to *any* domain when
        per_domain has no entry. Lets self-healing tests reason about
        cycles instead of round-robin domain selection.

    Each item is one of:
        None              → transport failure
        []                → 200 OK with no certs
        [CertObservation] → data response
    Once a queue is exhausted the last item is returned forever so
    steady-state tests don't have to enumerate every cycle.
    """

    name = "fake"

    def __init__(
        self,
        per_domain: dict[str, list] | None = None,
        default: list | None = None,
    ):
        self._per_domain = {d: list(rs) for d, rs in (per_domain or {}).items()}
        self._default = list(default) if default is not None else None
        self._calls: list[str] = []

    @staticmethod
    def _pop_or_last(rs: list):
        if not rs:
            return None
        if len(rs) > 1:
            return rs.pop(0)
        return rs[0]

    def fetch_domain(self, domain):
        self._calls.append(domain)
        if domain in self._per_domain:
            return self._pop_or_last(self._per_domain[domain])
        if self._default is not None:
            return self._pop_or_last(self._default)
        return None

    def health(self) -> dict:
        return {
            "status": "fake",
            "last_success_ts": 0.0,
            "consecutive_failures": 0,
            "mode_counters": {},
            "source_specific": {"calls": list(self._calls)},
        }


def _obs(
    domain: str,
    issuer: str = "C=US, O=Let's Encrypt, CN=R3",
    not_before_offset_sec: float = 0.0,
    serial: str = "",
    source: str = "fake",
) -> CertObservation:
    norm, raw = _parse_issuer(issuer)
    return CertObservation(
        domain=domain.lower(),
        issuer_norm=norm,
        issuer_raw=raw,
        common_name=domain,
        subject_alt_names=(),
        not_before_ts=time.time() + not_before_offset_sec,
        serial=serial,
        source_name=source,
        observed_at_ts=time.time(),
    )


@pytest.fixture
def testdb(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test_orch.db")
    db = RadarDB(db_path)
    # Sensor reaches into the global db module — point it at the test DB.
    monkeypatch.setattr(_db_mod, "db", db)
    yield db
    db.close()


@pytest.fixture
def warm_taiwan_ctx(testdb):
    """Theater context with a single-domain TW watched set, plus a TW
    domain that is fully warmed-up so anomaly fires are not suppressed."""
    from radar.config import CT_LOG_WATCHED_DOMAINS
    domain = CT_LOG_WATCHED_DOMAINS["TW"][0]
    testdb.ct_log_set_first_observed(
        domain, time.time() - (CT_LOG_WARMUP_DAYS + 5) * 86400
    )
    return {"strategic_countries": ["TW"], "adversary_states": []}, domain


# ── Backfill flow ─────────────────────────────────────────────────────────

def test_orchestrator_records_observations_into_buffer(warm_taiwan_ctx, testdb):
    """fetch_domain returning [obs] should land that obs in the buffer
    and the drain should hand it back to the scoring stage."""
    ctx, domain = warm_taiwan_ctx
    sensor = CtLogSensor()
    # Default response: every polled domain gets the same single-obs reply.
    sensor._pull_sources = [FakePullSource(default=[[_obs(domain)]])]

    result = sensor.fetch(ctx)
    assert "TW" in result["ct_data"]
    # The orchestrator polls multiple TW domains per cycle (round-robin
    # budget). Each call returns one obs whose obs.domain is the warmed
    # `domain` — so they collapse in the buffer to a single record and
    # only that warmed domain has scoring observations.
    assert result["ct_data"]["TW"]["total_recent"] == 1
    assert result["country_status"]["TW"] == "NORMAL"


def test_source_failure_does_not_trip_score(warm_taiwan_ctx, testdb):
    """Source returning None for every poll = total transport failure;
    the orchestrator should fall back to cached/empty rather than score
    a phantom NORMAL on no data."""
    ctx, _domain = warm_taiwan_ctx
    sensor = CtLogSensor()
    sensor._pull_sources = [FakePullSource(default=[None])]

    result = sensor.fetch(ctx)
    # No prior cache → empty data + NORMAL placeholder per existing
    # backward-compat shape.
    assert result["ct_data"] == {}
    # Failure was counted toward self-healing.
    assert sensor._consecutive_failures == 1


def test_empty_response_arms_warmup_marker(testdb, monkeypatch):
    """200 OK with empty cert list on an unseen domain should set the
    first_observed marker without recording any buffer entry."""
    from radar.config import CT_LOG_WATCHED_DOMAINS
    # Confirm at least one TW domain has no marker yet.
    fresh_domains = [d for d in CT_LOG_WATCHED_DOMAINS["TW"]
                     if testdb.ct_log_first_observed(d) is None]
    assert fresh_domains, "fixture invariant"

    sensor = CtLogSensor()
    sensor._pull_sources = [FakePullSource(default=[[]])]

    sensor.fetch({"strategic_countries": ["TW"], "adversary_states": []})

    # Markers armed for every polled domain (round-robin slice).
    after = [d for d in fresh_domains if testdb.ct_log_first_observed(d) is not None]
    assert after, "at least one polled domain should now have a marker"
    # Buffer has no observations.
    assert sensor._buffer.stats()["observations_in_buffer"] == 0


def test_alive_response_with_only_out_of_window_certs_arms_marker(testdb, monkeypatch):
    """Phase 2B regression: certspotter's first call to a domain returns
    at most one historical issuance. When that issuance is older than the
    24h observation window, the orchestrator's drain filters it out — but
    we still know upstream sees the domain, so the warm-up marker MUST be
    armed. Prior behavior gated marker arming on `not got_data`, leaving
    those domains stuck in 'never observed' forever and never converging
    onto a known-CA baseline."""
    from radar.config import CT_LOG_WATCHED_DOMAINS, CT_LOG_OBSERVATION_WINDOW_HOURS
    fresh_domains = [d for d in CT_LOG_WATCHED_DOMAINS["TW"]
                     if testdb.ct_log_first_observed(d) is None]
    assert fresh_domains, "fixture invariant"

    # Inject one observation per polled domain that is older than the
    # observation window — drain will filter it out at scoring time.
    out_of_window_offset = -((CT_LOG_OBSERVATION_WINDOW_HOURS + 1) * 3600)
    sensor = CtLogSensor()
    sensor._pull_sources = [FakePullSource(default=[
        [_obs("placeholder.example", not_before_offset_sec=out_of_window_offset)]
    ])]
    # Patch the obs construction so domain matches whatever the orchestrator
    # asked about — easier than threading per-domain queues for this test.
    real_fetch = sensor._pull_sources[0].fetch_domain

    def fetch_with_matching_domain(domain):
        rs = real_fetch(domain)
        if isinstance(rs, list) and rs:
            patched = [_obs(domain, not_before_offset_sec=out_of_window_offset)]
            return patched
        return rs

    sensor._pull_sources[0].fetch_domain = fetch_with_matching_domain

    sensor.fetch({"strategic_countries": ["TW"], "adversary_states": []})

    after = [d for d in fresh_domains if testdb.ct_log_first_observed(d) is not None]
    assert after, ("first_observed must arm even when the response carried "
                   "only out-of-window certs — alive=True is the signal")


# ── Multi-source idempotency ─────────────────────────────────────────────

def test_duplicate_observation_across_sources_fires_once(warm_taiwan_ctx, testdb):
    """When two sources deliver the same logical cert (same domain, same
    serial, same issuer, same day), the buffer dedup should collapse them
    and scoring should fire exactly one anomaly."""
    ctx, domain = warm_taiwan_ctx
    untrusted = "C=RU, O=Russian Trusted Certificate Authority, CN=Sub CA"
    obs_a = _obs(domain, issuer=untrusted, serial="ABCD1234", source="src_a")
    obs_b = _obs(domain, issuer=untrusted, serial="ABCD1234", source="src_b")

    sensor = CtLogSensor()
    sensor._pull_sources = [
        FakePullSource(default=[[obs_a]]),
        FakePullSource(default=[[obs_b]]),
    ]

    result = sensor.fetch(ctx)
    events = result["ct_data"]["TW"]["untrusted_ca_events"]
    assert len(events) == 1, "Buffer dedup must collapse cross-source duplicates"


# ── Self-healing degraded mode ───────────────────────────────────────────

def test_three_failed_cycles_trigger_degraded_mode(warm_taiwan_ctx, testdb):
    ctx, _domain = warm_taiwan_ctx
    sensor = CtLogSensor()
    sensor._pull_sources = [FakePullSource(default=[None])]

    for cycle in range(1, 4):
        sensor.fetch(ctx)
        if cycle < 3:
            assert sensor._upstream_status != "degraded"
    assert sensor._upstream_status == "degraded"
    assert sensor.poll_interval == CT_LOG_DEGRADED_INTERVAL_SEC


def test_one_alive_cycle_recovers_from_degraded(warm_taiwan_ctx, testdb):
    ctx, domain = warm_taiwan_ctx
    sensor = CtLogSensor()
    # First 3 cycles: every poll returns None (transport down).
    # Cycle 4: every poll returns [obs] for the warmed domain.
    # Default-mode queue advances per call; the test crosses 3 fail cycles
    # then injects data for the 4th.
    fake = FakePullSource(default=[None])
    sensor._pull_sources = [fake]

    for _ in range(3):
        sensor.fetch(ctx)
    assert sensor._upstream_status == "degraded"

    # Re-program the fake to return obs on the next call.
    fake._default = [[_obs(domain)]]
    sensor.fetch(ctx)
    assert sensor._upstream_status == "healthy"
    assert sensor._consecutive_failures == 0
    assert sensor.poll_interval == sensor._NORMAL_INTERVAL


def test_no_pull_attempt_does_not_increment_failures():
    """If no targets have watched-domains in this cycle, the orchestrator
    short-circuits before any pull source is consulted; counts must stay
    untouched (otherwise we'd flap into degraded just because the active
    theaters happened to lack curated domains)."""
    sensor = CtLogSensor()
    sensor._pull_sources = [FakePullSource()]  # nothing matches anyway

    # Use an unknown country to guarantee the early-return path.
    ctx = {"strategic_countries": ["ZZ"], "adversary_states": []}
    sensor.fetch(ctx)
    assert sensor._consecutive_failures == 0


# ── upstream_health structure ────────────────────────────────────────────

def test_upstream_health_aggregates_per_source():
    """Each registered source should appear in the `sources` map; the
    operator panel relies on this for the diagnostics rendering."""
    sensor = CtLogSensor()
    sensor._pull_sources = [
        FakePullSource(),
    ]
    health = sensor.upstream_health()
    assert "sources" in health
    assert "fake" in health["sources"]
    assert health["sources"]["fake"]["status"] == "fake"
    # Buffer stats are exposed unconditionally so the panel can render
    # capacity_used_pct without conditional UI.
    assert "buffer" in health
    assert "observations_in_buffer" in health["buffer"]


# ── sensor_fetch_log.error source-degradation summary ───────────────────

class _DegradedFakeSource(BaseCtLogPullSource):
    """Pull source whose health() reports specific degradation flags.

    Used to assert the orchestrator's _summarize_source_state composes the
    sensor_fetch_log.error tag correctly. fetch_domain returns None so the
    orchestrator treats the source as transport-failing this cycle.
    """

    def __init__(self, name: str, health_payload: dict):
        self.name = name
        self._health = health_payload

    def fetch_domain(self, domain):
        return None

    def health(self) -> dict:
        return self._health


def test_summarize_source_state_silent_when_all_healthy():
    sensor = CtLogSensor()
    sensor._pull_sources = [_DegradedFakeSource("foo", {
        "status": "healthy",
        "consecutive_failures": 0,
        "mode_counters": {"timeout": 0},
        "source_specific": {"cb_open": False, "rate_limited": False},
    })]
    assert sensor._summarize_source_state() == ""


def test_summarize_source_state_flags_cb_open_and_rate_limited():
    sensor = CtLogSensor()
    sensor._pull_sources = [
        _DegradedFakeSource("certspotter", {
            "status": "healthy",
            "consecutive_failures": 0,
            "mode_counters": {},
            "source_specific": {
                "cb_open": False,
                "rate_limited": True,
                "rate_limited_remaining_sec": 71,
            },
        }),
        _DegradedFakeSource("crtsh", {
            "status": "healthy",
            "consecutive_failures": 0,
            "mode_counters": {},
            "source_specific": {
                "cb_open": True,
                "cb_open_remaining_sec": 300,
                "rate_limited": False,
            },
        }),
    ]
    summary = sensor._summarize_source_state()
    assert "certspotter=rate_limited(71s)" in summary
    assert "crtsh=cb_open(300s)" in summary


def test_summarize_source_state_includes_dead_with_top_modes():
    sensor = CtLogSensor()
    sensor._pull_sources = [_DegradedFakeSource("crtsh", {
        "status": "dead",
        "consecutive_failures": 8,
        "mode_counters": {"timeout": 5, "http_5xx": 3, "conn_error": 1},
        "source_specific": {"cb_open": False, "rate_limited": False},
    })]
    summary = sensor._summarize_source_state()
    assert "crtsh=dead:cf=8" in summary
    # Top-2 most frequent failure modes.
    assert "timeout=5" in summary
    assert "http_5xx=3" in summary
    # Lower-frequency mode is not promoted.
    assert "conn_error" not in summary


def test_summarize_source_state_handles_health_exception():
    class _BrokenHealth(BaseCtLogPullSource):
        name = "broken"

        def fetch_domain(self, d):
            return None

        def health(self):
            raise RuntimeError("boom")

    sensor = CtLogSensor()
    sensor._pull_sources = [_BrokenHealth()]
    assert sensor._summarize_source_state() == "broken=health_err:RuntimeError"


def test_fetch_log_error_combines_country_and_source_degradation(
    warm_taiwan_ctx, testdb, monkeypatch
):
    """End-to-end: when a source reports degradation AND a per-country
    scoring branch raises, the sensor_fetch_log error field should carry
    both signals so an operator reading /api/admin/sensor_fetch_log sees
    the full picture without cross-checking /api/admin/sensor_health."""
    ctx, domain = warm_taiwan_ctx

    # Active fake delivers a normal cert so drain has an entry → the per-
    # country branch enters _inspect_domain and the patched exception
    # surfaces from the per-country try/except, not the outer drain.
    active_fake = FakePullSource(default=[[_obs(domain)]])
    # Degraded fake reports rate_limit; orchestrator skips it because
    # the active fake's response stops the fallback chain. Its health()
    # is what the summary helper picks up.
    degraded = _DegradedFakeSource("certspotter", {
        "status": "healthy",
        "consecutive_failures": 0,
        "mode_counters": {},
        "source_specific": {
            "cb_open": False,
            "rate_limited": True,
            "rate_limited_remaining_sec": 120,
        },
    })

    sensor = CtLogSensor()
    sensor._pull_sources = [active_fake, degraded]

    def _boom(*args, **kwargs):
        raise RuntimeError("inspect failure")

    monkeypatch.setattr(sensor, "_inspect_domain", _boom)

    captured: dict = {}

    def _capture_log(success, duration_ms, items_found, items_fresh, error):
        captured["error"] = error

    monkeypatch.setattr(sensor, "log_fetch", _capture_log)
    sensor.fetch(ctx)

    err = captured.get("error", "")
    assert "errors(TW)" in err
    assert "src(" in err
    assert "certspotter=rate_limited(120s)" in err


# ── Parity: legacy single-cycle flow vs orchestrator drain ───────────────

def test_orchestrator_parity_with_legacy_inspect_for_single_cycle(
    warm_taiwan_ctx, testdb
):
    """The orchestrator-driven scoring of one cycle of crt.sh fixture data
    must match what _inspect_domain would produce when called directly on
    the same observations. This pins down the contract that Phase 1 was
    *only* a refactor — no scoring drift."""
    ctx, domain = warm_taiwan_ctx
    untrusted = "C=RU, O=Russian Trusted Certificate Authority, CN=Sub CA"
    fixture = [
        _obs(domain, issuer=untrusted, serial="A1"),
        _obs(domain, issuer=untrusted, serial="A2", not_before_offset_sec=-60),
        _obs(domain, issuer="C=US, O=Let's Encrypt, CN=R3", serial="A3",
             not_before_offset_sec=-120),
    ]

    # Direct: legacy contract — score the fixture in isolation.
    direct_sensor = CtLogSensor()
    direct_summary = direct_sensor._inspect_domain(
        domain, "TW", fixture, time.time(), testdb,
    )

    # Reset DB state for the orchestrator pass (the direct call mutated
    # known_cas; Phase 1 parity asserts the trust-decision *output*, not
    # cumulative DB state).
    testdb._get_conn().execute(
        "DELETE FROM ct_log_known_ca_per_domain WHERE domain=?", (domain,)
    )
    testdb._get_conn().commit()

    orch_sensor = CtLogSensor()
    orch_sensor._pull_sources = [FakePullSource(default=[list(fixture)])]
    orch_result = orch_sensor.fetch(ctx)

    assert orch_result["country_status"]["TW"] == "UNTRUSTED_CA_DETECTED"
    orch_events = orch_result["ct_data"]["TW"]["untrusted_ca_events"]
    # Same anomaly count as the direct call (one untrusted CA → one event;
    # the second cert from the same CA in-window must dedup).
    assert len(orch_events) == len(direct_summary["untrusted_events"]) == 1
    # Same total_recent (both code paths see the same window-eligible obs).
    assert (
        orch_result["ct_data"]["TW"]["total_recent"]
        == direct_summary["total_recent"]
    )


# ── Window filter (defence-in-depth) ─────────────────────────────────────

def test_observations_outside_window_are_dropped_at_drain(warm_taiwan_ctx, testdb):
    """The buffer's window filter and _inspect_domain's redundant window
    check should jointly ensure stale observations don't contribute."""
    ctx, domain = warm_taiwan_ctx
    # not_before older than the observation window
    stale_offset = -(CT_LOG_OBSERVATION_WINDOW_HOURS * 3600 + 7200)
    fresh = _obs(domain, issuer="C=US, O=Let's Encrypt, CN=R3", serial="X1")
    stale = _obs(
        domain, issuer="C=US, O=Let's Encrypt, CN=R3",
        serial="X2", not_before_offset_sec=stale_offset,
    )

    sensor = CtLogSensor()
    sensor._pull_sources = [FakePullSource(default=[[fresh, stale]])]
    result = sensor.fetch(ctx)
    assert result["ct_data"]["TW"]["total_recent"] == 1
