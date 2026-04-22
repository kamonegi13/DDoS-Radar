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
    return {"strategic_theaters": ["TW"], "adversary_states": []}, domain


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

    sensor.fetch({"strategic_theaters": ["TW"], "adversary_states": []})

    # Markers armed for every polled domain (round-robin slice).
    after = [d for d in fresh_domains if testdb.ct_log_first_observed(d) is not None]
    assert after, "at least one polled domain should now have a marker"
    # Buffer has no observations.
    assert sensor._buffer.stats()["observations_in_buffer"] == 0


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
    ctx = {"strategic_theaters": ["ZZ"], "adversary_states": []}
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
