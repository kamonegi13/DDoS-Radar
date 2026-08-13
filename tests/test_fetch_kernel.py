"""WP-2.5 — the shared fetch kernel's pure core and its I/O edge.

Design sheet §6-3. Nothing here touches the network: the client is
exercised through an injected fake session, which is the same seam the
34 adapters will use in WP-2.6/2.7.
"""
import ast
import inspect
import json

import pytest

from v3.adapters.types import (AUTH_API_KEY, AUTH_IN_QUERY, AUTH_OAUTH2,
                               AdapterId, AuthRequirement, RequestSpec,
                               SourceAdapter)
from v3.fetch import breaker, client, limiter, parse, policy, schedule
from v3.fetch.breaker import BreakerState
from v3.fetch.limiter import LimiterState
from v3.fetch.registry import AdapterRegistry
from v3.kernel import Window
from v3.kernel.errors import DomainError

T0 = 1_700_000_000.0


def _adapter(name, *, group="", interval=0.0, cadence_sec=3600.0,
             enabled=True, reason="", auth=None):
    return SourceAdapter(
        adapter_id=AdapterId(name), category="cyber",
        requests=(RequestSpec(url=f"https://example.test/{name}"),)
        if enabled else (),
        cadence=Window.from_days(1.0, cadence_sec=cadence_sec),
        normalize=lambda payload, context: (),
        freshness_horizon_sec=3600.0, rate_limit_group=group,
        min_interval_sec=interval, enabled=enabled, disabled_reason=reason,
        auth=auth or AuthRequirement())


# ── circuit breaker (S1-SCORE-038 / S4-NF-003) ──────────────────────────

class TestBreaker:
    def test_a_fresh_breaker_is_closed(self):
        assert BreakerState().state == breaker.CLOSED
        assert breaker.should_skip(BreakerState()) is False

    def test_failures_below_the_threshold_keep_it_closed(self):
        state = BreakerState()
        for _ in range(policy.CB_FAILURE_THRESHOLD - 1):
            state = breaker.step(state, breaker.FAILURE, T0)
        assert state.state == breaker.CLOSED
        assert state.fail_count == policy.CB_FAILURE_THRESHOLD - 1

    def test_the_threshold_failure_opens_it(self):
        state = BreakerState()
        for _ in range(policy.CB_FAILURE_THRESHOLD):
            state = breaker.step(state, breaker.FAILURE, T0)
        assert state.state == breaker.OPEN
        assert state.opened_at == T0
        assert breaker.should_skip(state) is True

    def test_an_open_breaker_stays_shut_before_its_delay(self):
        state = BreakerState(state=breaker.OPEN, fail_count=5, opened_at=T0,
                             recovery_delay_sec=300.0)
        effective = breaker.effective_state(state, T0 + 299)
        assert effective.state == breaker.OPEN
        assert breaker.should_skip(effective) is True

    def test_it_becomes_half_open_once_the_delay_elapses(self):
        state = BreakerState(state=breaker.OPEN, fail_count=5, opened_at=T0,
                             recovery_delay_sec=300.0)
        effective = breaker.effective_state(state, T0 + 300)
        assert effective.state == breaker.HALF_OPEN
        assert breaker.should_skip(effective) is False

    def test_a_successful_probe_closes_and_resets_the_ladder(self):
        half_open = BreakerState(state=breaker.HALF_OPEN, fail_count=7,
                                 opened_at=T0, recovery_delay_sec=1200.0)
        closed = breaker.step(half_open, breaker.SUCCESS, T0 + 400)
        assert closed.state == breaker.CLOSED
        assert closed.fail_count == 0
        assert closed.recovery_delay_sec == policy.CB_INITIAL_DELAY_SEC

    def test_a_failed_probe_reopens_and_doubles_the_delay(self):
        half_open = BreakerState(state=breaker.HALF_OPEN, fail_count=5,
                                 opened_at=T0, recovery_delay_sec=300.0)
        reopened = breaker.step(half_open, breaker.FAILURE, T0 + 400)
        assert reopened.state == breaker.OPEN
        assert reopened.recovery_delay_sec == 600.0
        assert reopened.opened_at == T0 + 400

    def test_the_doubled_delay_is_capped(self):
        state = BreakerState(state=breaker.HALF_OPEN, fail_count=9,
                             opened_at=T0,
                             recovery_delay_sec=policy.CB_MAX_DELAY_SEC)
        assert breaker.step(state, breaker.FAILURE, T0).recovery_delay_sec \
            == policy.CB_MAX_DELAY_SEC

    def test_a_success_in_closed_clears_accumulated_failures(self):
        """A flapping upstream must not accumulate its way to OPEN."""
        state = breaker.step(BreakerState(), breaker.FAILURE, T0)
        state = breaker.step(state, breaker.SUCCESS, T0 + 1)
        assert state.fail_count == 0

    def test_asking_whether_to_skip_consumes_no_probe(self):
        """S4-NF-003: the judgement is `effective_state`, called once.

        `should_skip` must be time-independent, or calling it twice would
        promote OPEN to HALF_OPEN twice and hand out two probe slots.
        """
        state = BreakerState(state=breaker.OPEN, fail_count=5, opened_at=T0,
                             recovery_delay_sec=300.0)
        assert breaker.should_skip(state) is breaker.should_skip(state)
        effective = breaker.effective_state(state, T0 + 300)
        assert breaker.effective_state(effective, T0 + 9999) is effective

    def test_an_open_breaker_without_an_opened_at_is_refused(self):
        with pytest.raises(DomainError, match="when it opened"):
            BreakerState(state=breaker.OPEN, opened_at=None)

    def test_an_unknown_state_is_refused(self):
        with pytest.raises(DomainError):
            BreakerState(state="MAYBE")

    def test_an_unknown_outcome_is_refused(self):
        with pytest.raises(DomainError):
            breaker.step(BreakerState(), "probably", T0)


# ── rate limiter (shared groups, D1 §4 K01/K15) ─────────────────────────

class TestLimiter:
    def test_an_unthrottled_group_is_always_allowed(self):
        assert limiter.is_allowed(LimiterState(), "g", 0.0, T0) is True

    def test_a_group_is_blocked_inside_its_interval(self):
        state = LimiterState().record("peeringdb", T0)
        assert limiter.is_allowed(state, "peeringdb", 10.0, T0 + 5) is False
        assert limiter.is_allowed(state, "peeringdb", 10.0, T0 + 10) is True

    def test_wait_seconds_reports_the_remainder(self):
        state = LimiterState().record("peeringdb", T0)
        assert limiter.wait_seconds(state, "peeringdb", 10.0, T0 + 4) == \
            pytest.approx(6.0)
        assert limiter.wait_seconds(state, "peeringdb", 10.0, T0 + 99) == 0.0

    def test_three_adapters_share_one_group(self):
        """K01: OpenSky's quota is consumed by three sensors, one account."""
        state = LimiterState().record("opensky", T0)
        for adapter_group in ("opensky", "opensky", "opensky"):
            assert limiter.is_allowed(state, adapter_group, 30.0,
                                      T0 + 5) is False

    def test_separate_groups_do_not_interfere(self):
        state = LimiterState().record("opensky", T0)
        assert limiter.is_allowed(state, "peeringdb", 10.0, T0 + 1) is True

    def test_recording_returns_a_new_state(self):
        first = LimiterState()
        second = first.record("g", T0)
        assert first.as_dict() == {} and second.as_dict() == {"g": T0}

    def test_a_non_positive_timestamp_is_refused(self):
        with pytest.raises(DomainError):
            LimiterState(last_request_at={"g": 0.0})


# ── schedule (F-01) ─────────────────────────────────────────────────────

class TestSchedule:
    CADENCE = Window.from_days(1.0, cadence_sec=3600.0)

    def test_an_adapter_that_never_ran_is_due(self):
        assert schedule.is_due(T0, None, self.CADENCE) is True

    def test_it_is_not_due_inside_the_cadence(self):
        assert schedule.is_due(T0 + 3599, T0, self.CADENCE) is False

    def test_it_is_due_on_the_cadence_boundary(self):
        assert schedule.is_due(T0 + 3600, T0, self.CADENCE) is True

    def test_a_restart_does_not_shift_the_phase(self):
        """F-01 regression, stated as the defect stated itself.

        The legacy scheduler assigned daily jobs by `_cycle % 24 == N` off
        a process counter that reset to 0 on restart, so offsets above the
        uptime never ran — measured 2026-08-04 at uptime 9h with offsets
        10-12 unexecuted. Here due-ness reads a PERSISTED last_run_at, so
        restarting mid-cadence changes nothing at all.
        """
        last_run = T0
        for restart_at in (T0 + 100, T0 + 1800, T0 + 3400):
            assert schedule.is_due(restart_at, last_run, self.CADENCE) is False
        assert schedule.is_due(T0 + 3600, last_run, self.CADENCE) is True

    def test_a_long_cadence_job_still_runs_after_many_restarts(self):
        """The specific shape F-01 broke: a 24h job under hourly restarts."""
        daily = Window.from_days(1.0, cadence_sec=86400.0)
        last_run = T0
        for hour in range(1, 24):
            assert schedule.is_due(T0 + hour * 3600, last_run, daily) is False
        assert schedule.is_due(T0 + 86400, last_run, daily) is True

    def test_next_run_at_is_the_boundary(self):
        assert schedule.next_run_at(T0 + 10, T0, self.CADENCE) == T0 + 3600

    def test_next_run_at_for_a_new_adapter_is_now(self):
        assert schedule.next_run_at(T0, None, self.CADENCE) == T0

    def test_overdue_is_measured(self):
        assert schedule.overdue_by(T0 + 5000, T0, self.CADENCE) == \
            pytest.approx(1400.0)
        assert schedule.overdue_by(T0 + 100, T0, self.CADENCE) == 0.0

    def test_a_future_last_run_is_not_due_rather_than_an_error(self):
        """Clock skew must not stop the other adapters in the cycle."""
        assert schedule.is_due(T0, T0 + 5000, self.CADENCE) is False

    def test_a_bare_number_of_seconds_is_refused(self):
        with pytest.raises(DomainError, match="Window"):
            schedule.is_due(T0, None, 3600.0)


# ── tolerant parser and feed death causes (§1-7) ────────────────────────

GOOD_RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Alpha</title><link>https://a.test/1</link>
<description>first</description><guid>g1</guid></item>
<item><title>Beta</title><link>https://a.test/2</link></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Gamma</title><link href="https://a.test/3"/><id>g3</id>
<summary>third</summary></entry></feed>"""

BROKEN_BUT_RECOVERABLE = b"""<?xml version="1.0"?><rss><channel>
<item><title>Delta</title><link>https://a.test/4</link></item>
<item><title>Unclosed</channel></rss>"""


class TestParse:
    def test_a_well_formed_feed_parses_strictly(self):
        result = parse.parse_feed(GOOD_RSS)
        assert result.outcome == parse.OK
        assert result.stage == parse.STAGE_STRICT
        assert [item.title for item in result.items] == ["Alpha", "Beta"]
        assert result.items[0].link == "https://a.test/1"

    def test_atom_entries_are_read_too(self):
        result = parse.parse_feed(ATOM)
        assert result.outcome == parse.OK
        assert result.items[0].title == "Gamma"
        assert result.items[0].link == "https://a.test/3"

    def test_a_broken_feed_is_recovered_in_stage_two(self):
        """A-02: only `diplomatic` had this, so the same feed parsed or
        did not depending on which sensor fetched it."""
        result = parse.parse_feed(BROKEN_BUT_RECOVERABLE)
        assert result.outcome == parse.OK
        assert result.stage == parse.STAGE_RECOVER
        assert any(item.title == "Delta" for item in result.items)

    def test_html_instead_of_a_feed_is_classified(self):
        """CN_MFA retired its RSS and serves the site (K07)."""
        result = parse.parse_feed(b"<!DOCTYPE html><html><body>hi</body></html>")
        assert result.outcome == parse.RETURNS_HTML

    def test_an_html_content_type_is_enough(self):
        result = parse.parse_feed(b"<rss></rss>", content_type="text/html")
        assert result.outcome == parse.RETURNS_HTML

    def test_an_empty_body_is_rss_empty(self):
        assert parse.parse_feed(b"   ").outcome == parse.RSS_EMPTY

    def test_a_feed_with_no_items_is_rss_empty(self):
        """KCNA goes intermittently empty (K07); that is a liveness fact."""
        result = parse.parse_feed(
            b'<?xml version="1.0"?><rss><channel></channel></rss>')
        assert result.outcome == parse.RSS_EMPTY

    def test_an_http_error_is_classified_before_the_body(self):
        """JP_MOFA answers 404/WAF (K07)."""
        result = parse.parse_feed(GOOD_RSS, http_status=404)
        assert result.outcome == parse.HTTP_ERROR

    def test_a_451_is_a_geo_block(self):
        assert parse.parse_feed(b"", http_status=451).outcome == parse.GEO_BLOCK

    def test_a_403_with_a_region_marker_is_a_geo_block(self):
        """RU_MFA geo-blocks (K07)."""
        result = parse.parse_feed(
            b"This service is not available in your country.",
            http_status=403)
        assert result.outcome == parse.GEO_BLOCK

    def test_a_plain_403_is_an_http_error(self):
        assert parse.parse_feed(b"denied", http_status=403).outcome == \
            parse.HTTP_ERROR

    def test_unparseable_rubbish_is_classified_not_raised(self):
        result = parse.parse_feed(b"\x00\x01\x02 not xml at all")
        assert result.outcome in (parse.UNPARSEABLE, parse.RSS_EMPTY)
        assert result.detail

    def test_every_death_cause_is_reachable(self):
        """The five §1-7 names are not decoration."""
        bomb = (b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY a "a">'
                b'<!ENTITY b "&a;&a;">]><rss><channel><item><title>&b;'
                b'</title></item></channel></rss>')
        reached = {
            parse.parse_feed(b"<!DOCTYPE html>").outcome,
            parse.parse_feed(b"").outcome,
            parse.parse_feed(b"\x00\x01", http_status=200).outcome,
            parse.parse_feed(b"x", http_status=500).outcome,
            parse.parse_feed(b"", http_status=451).outcome,
            parse.parse_feed(bomb).outcome,
        }
        assert parse.DEATH_CAUSES <= reached | {parse.RSS_EMPTY}

    def test_a_dead_feed_reports_itself_as_dead(self):
        assert parse.parse_feed(b"<!DOCTYPE html>").is_dead is True
        assert parse.parse_feed(GOOD_RSS).is_alive is True

    def test_an_empty_fetch_counts_as_dead_not_as_success(self):
        """The legacy habit of counting 'fetched, zero items' as a plain
        success is how a feed looked healthy while producing nothing."""
        assert parse.parse_feed(b"   ").is_dead is True


# ── policy ──────────────────────────────────────────────────────────────

class TestPolicy:
    def test_the_breaker_constants_match_s1_score_038(self):
        assert policy.CB_FAILURE_THRESHOLD == 5
        assert policy.CB_INITIAL_DELAY_SEC == 300.0
        assert policy.CB_MAX_DELAY_SEC == 3600.0

    def test_every_constant_discloses_its_source(self):
        for name in policy.pinned_names():
            threshold = policy.pinned(name)
            assert not threshold.is_registry_backed, name
            assert len(threshold.provenance_ref) > 20, name

    def test_the_retry_after_ceiling_is_the_k01_value(self):
        assert policy.RETRY_AFTER_MAX_SEC == 120.0

    def test_backoff_doubles(self):
        assert policy.backoff_delay(1) == 1.0
        assert policy.backoff_delay(2) == 2.0
        assert policy.backoff_delay(3) == 4.0

    def test_a_zero_attempt_is_refused(self):
        with pytest.raises(ValueError):
            policy.backoff_delay(0)


# ── registry (F-02) ─────────────────────────────────────────────────────

class TestRegistry:
    def _registry(self):
        return AdapterRegistry([
            _adapter("cloudflare_radar"), _adapter("ioda_bgp"),
            _adapter("opensky", group="opensky", interval=30.0),
            _adapter("isr_hotspot", group="opensky", interval=30.0),
            _adapter("mil_support_air", group="opensky", interval=30.0),
            _adapter("notam", enabled=False,
                     reason="no free international NOTAM API exists (K14)"),
        ])

    def test_a_known_name_resolves(self):
        assert self._registry().resolve("ioda_bgp").value == "ioda_bgp"

    def test_the_exact_f02_typos_are_refused(self):
        """`cf` and `ioda` are what the legacy allow-list actually held."""
        registry = self._registry()
        for typo in ("cf", "ioda"):
            with pytest.raises(DomainError, match="F-02"):
                registry.resolve(typo)

    def test_the_refusal_suggests_the_real_name(self):
        with pytest.raises(DomainError, match="ioda_bgp"):
            self._registry().resolve("ioda")

    def test_get_refuses_a_bare_string(self):
        registry = self._registry()
        with pytest.raises(DomainError, match="AdapterId"):
            registry.get("ioda_bgp")

    def test_duplicate_ids_are_refused(self):
        with pytest.raises(DomainError, match="duplicate"):
            AdapterRegistry([_adapter("dup"), _adapter("dup")])

    def test_shared_quotas_are_visible(self):
        groups = self._registry().rate_limit_groups()
        assert groups["opensky"] == ("isr_hotspot", "mil_support_air",
                                     "opensky")

    def test_disabled_adapters_are_listed_not_hidden(self):
        registry = self._registry()
        assert [a.name for a in registry.disabled()] == ["notam"]
        assert "notam" not in [a.name for a in registry.enabled()]

    def test_required_secrets_are_enumerable(self):
        registry = AdapterRegistry([
            _adapter("threatfox", auth=AuthRequirement(
                kind=AUTH_API_KEY, key_id="THREATFOX_AUTH_KEY",
                name="Auth-Key", value_template="{secret}")),
            _adapter("open_one")])
        assert registry.required_key_ids() == ("THREATFOX_AUTH_KEY",)


# ── the shared client, through an injected session ──────────────────────

class _Response:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status_code = status
        self.content = body
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, chunk_size=65536):
        for start in range(0, len(self.content), chunk_size):
            yield self.content[start:start + chunk_size]

    def close(self):
        self.closed = True


class _Session:
    """Records calls; returns queued responses. Never touches a socket."""

    def __init__(self, *responses):
        self._queue = list(responses)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self._queue:
            return _Response()
        item = self._queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class TestClient:
    def _client(self, *responses, **kwargs):
        return client.HttpClient(session=_Session(*responses),
                                 sleeper=lambda _s: None, **kwargs)

    def test_a_successful_fetch_returns_a_payload(self):
        http = self._client(_Response(200, b'{"data": []}',
                                      {"Content-Type": "application/json"}))
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.succeeded
        assert outcome.payload.body == b'{"data": []}'
        assert outcome.payload.content_type == "application/json"
        assert outcome.body_sha256

    def test_the_timeout_is_always_passed(self):
        """S4-NF-002: a fetch without a timeout blocks the event loop."""
        session = _Session(_Response())
        http = client.HttpClient(session=session, sleeper=lambda _s: None)
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert session.calls[0]["timeout"] == (policy.HTTP_CONNECT_TIMEOUT_SEC,
                                               policy.HTTP_TIMEOUT_SEC)

    def test_a_non_positive_timeout_is_refused_at_construction(self):
        with pytest.raises(DomainError, match="timeout"):
            client.HttpClient(session=_Session(), timeout_sec=0)

    def test_a_body_that_dies_mid_read_is_an_outcome_not_an_exception(self):
        """Shadow, 2026-08-13, first tick after the redeploy: one upstream
        closed its chunked body early and the whole tick died with an
        unhandled ChunkedEncodingError — the try around the fetch covered
        `session.request` and left `_read_capped` outside it. The same
        family as every other one-bad-source-takes-the-cycle defect."""
        import requests as _requests

        class _DyingBody(_Response):
            def iter_content(self, chunk_size=65536):
                yield b'{"da'
                raise _requests.exceptions.ChunkedEncodingError(
                    "Response ended prematurely")

        http = self._client(_DyingBody(), _DyingBody(), _DyingBody())
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.outcome == client.CONNECTION_ERROR
        assert outcome.succeeded is False
        assert "ChunkedEncodingError" in outcome.detail

    def test_a_mid_read_death_retries_before_giving_up(self):
        import requests as _requests

        class _DyingBody(_Response):
            def iter_content(self, chunk_size=65536):
                raise _requests.exceptions.ChunkedEncodingError("early end")

        good = _Response(200, b'{"data": []}')
        http = self._client(_DyingBody(), good)
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.succeeded is True
        assert outcome.attempts == 2

    def test_an_http_error_is_reported_not_raised(self):
        http = self._client(_Response(404, b"nope"))
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.outcome == client.HTTP_ERROR and outcome.status == 404

    def test_a_retryable_status_is_retried(self):
        http = self._client(_Response(503), _Response(200, b"ok"))
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.succeeded and outcome.attempts == 2

    def test_a_short_retry_after_is_honoured(self):
        http = self._client(_Response(429, b"", {"Retry-After": "5"}),
                            _Response(200, b"ok"))
        assert http.fetch(RequestSpec(url="https://x.test/a"),
                          now=T0).succeeded

    def test_a_long_retry_after_gives_up_immediately(self):
        """K01: above 120s the quota is gone, not merely throttled.

        Waiting cannot recover a daily quota, so the legacy client stops
        rather than sleeping through it — and so does this one.
        """
        session = _Session(
            _Response(429, b"", {"X-Rate-Limit-Retry-After-Seconds": "3600"}),
            _Response(200, b"ok"))
        http = client.HttpClient(session=session, sleeper=lambda _s: None)
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.outcome == client.RATE_LIMITED
        assert len(session.calls) == 1
        assert "quota is exhausted" in outcome.detail

    def test_an_oversized_body_is_refused(self):
        http = self._client(_Response(200, b"x" * 100))
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                             max_body_bytes=10)
        assert outcome.outcome == client.TOO_LARGE

    def test_a_timeout_exhausts_the_ladder_then_reports(self):
        import requests as requests_lib
        http = self._client(requests_lib.Timeout("slow"),
                            requests_lib.Timeout("slow"),
                            requests_lib.Timeout("slow"))
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.outcome == client.TIMEOUT
        assert outcome.attempts == policy.HTTP_MAX_ATTEMPTS

    def test_an_injected_api_key_reaches_the_header(self):
        session = _Session(_Response())
        http = client.HttpClient(session=session, sleeper=lambda _s: None,
                                 credentials={"THREATFOX_AUTH_KEY": "secret"})
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                   auth=AuthRequirement(kind=AUTH_API_KEY,
                                        key_id="THREATFOX_AUTH_KEY",
                                        name="Auth-Key",
                                        value_template="{secret}"))
        assert session.calls[0]["headers"]["Auth-Key"] == "secret"

    def test_a_missing_credential_fails_without_a_request(self):
        """Nothing under v3/ reads the environment to fill a gap."""
        session = _Session(_Response())
        http = client.HttpClient(session=session, sleeper=lambda _s: None)
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                             auth=AuthRequirement(kind=AUTH_API_KEY,
                                                  key_id="MISSING",
                                                  name="Auth-Key",
                                                  value_template="{secret}"))
        assert outcome.outcome == client.AUTH_MISSING
        assert session.calls == []
        assert "composition root" in outcome.detail

    def test_the_url_hash_is_stable(self):
        http = self._client(_Response())
        first = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        second = http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert first.url_sha256 == second.url_sha256

    def test_fetch_refuses_anything_but_a_request_spec(self):
        with pytest.raises(DomainError):
            self._client().fetch("https://x.test/a", now=T0)


# ── review fixes: the parser's hard cases ───────────────────────────────

FEEDS = __import__("pathlib").Path(__file__).resolve().parent / "fixtures" / "feeds"


class TestRealFeedDeathShapes:
    """D1 §4 K07's four recorded shapes, as fixtures rather than comments.

    "The knowledge exists only in comments and branches" is D1's own
    assessment of this material. A comment does not fail when the
    behaviour changes; these do.
    """

    def test_jp_mofa_answers_404_behind_a_waf(self):
        result = parse.parse_feed(
            (FEEDS / "jp_mofa_404_waf.html").read_bytes(), http_status=404)
        assert result.outcome == parse.HTTP_ERROR

    def test_cn_mfa_retired_its_rss_and_serves_the_website(self):
        result = parse.parse_feed(
            (FEEDS / "cn_mfa_returns_html.html").read_bytes())
        assert result.outcome == parse.RETURNS_HTML

    def test_ru_mfa_geo_blocks(self):
        result = parse.parse_feed(
            (FEEDS / "ru_mfa_geo_block.txt").read_bytes(), http_status=403)
        assert result.outcome == parse.GEO_BLOCK

    def test_kcna_goes_intermittently_empty(self):
        """A well-formed feed with no items is a liveness fact, not a
        success — the legacy habit of counting it as one is how a source
        looked healthy while producing nothing."""
        result = parse.parse_feed((FEEDS / "kcna_rss_empty.xml").read_bytes())
        assert result.outcome == parse.RSS_EMPTY
        assert result.is_dead is True

    def test_all_four_shapes_are_distinguishable(self):
        outcomes = {
            parse.parse_feed((FEEDS / "jp_mofa_404_waf.html").read_bytes(),
                             http_status=404).outcome,
            parse.parse_feed(
                (FEEDS / "cn_mfa_returns_html.html").read_bytes()).outcome,
            parse.parse_feed((FEEDS / "ru_mfa_geo_block.txt").read_bytes(),
                             http_status=403).outcome,
            parse.parse_feed(
                (FEEDS / "kcna_rss_empty.xml").read_bytes()).outcome,
        }
        assert len(outcomes) == 4


class TestEntityAttackNeverReachesRecovery:
    """A hostile payload is not a broken feed.

    defusedxml refuses it, but the blanket handler used to fall through to
    lxml with `recover=True` — which returns a tree, so the result was
    reported OK and the only interesting fact (an upstream sent a bomb)
    survived as free text nobody reads.
    """

    def test_a_billion_laughs_payload_is_classified_as_an_attack(self):
        result = parse.parse_feed((FEEDS / "billion_laughs.xml").read_bytes())
        assert result.outcome == parse.ENTITY_ATTACK

    def test_it_never_reaches_stage_two(self):
        result = parse.parse_feed((FEEDS / "billion_laughs.xml").read_bytes())
        assert result.stage == parse.STAGE_STRICT
        assert result.outcome != parse.OK

    def test_the_attack_is_a_death_cause_of_its_own(self):
        assert parse.ENTITY_ATTACK in parse.DEATH_CAUSES
        assert parse.ENTITY_ATTACK != parse.UNPARSEABLE

    def test_an_external_entity_reference_is_also_refused(self):
        payload = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                   b'"file:///etc/passwd">]><rss><channel><item>'
                   b'<title>&x;</title></item></channel></rss>')
        assert parse.parse_feed(payload).outcome == parse.ENTITY_ATTACK

    def test_a_merely_broken_feed_still_recovers(self):
        """The short-circuit must not disable ordinary recovery."""
        assert parse.parse_feed(BROKEN_BUT_RECOVERABLE).outcome == parse.OK


class TestParserDependenciesAreDeclared:
    """The CRITICAL: lxml was undeclared and imported inside a try/except.

    A production image without it lost ALL stage-2 recovery, reporting
    every recoverable feed as UNPARSEABLE — a silent recall loss.
    """

    def test_lxml_is_imported_at_module_scope(self):
        import ast
        from pathlib import Path
        source = (Path(parse.__file__)).read_text(encoding="utf-8")
        tree = ast.parse(source)
        top_level = {
            (node.module or "")
            for node in tree.body if isinstance(node, ast.ImportFrom)}
        assert "lxml" in top_level
        assert "defusedxml" in top_level

    def test_no_parser_import_hides_inside_a_function(self):
        import ast
        from pathlib import Path
        tree = ast.parse(Path(parse.__file__).read_text(encoding="utf-8"))
        buried = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if isinstance(inner, ast.ImportFrom) and (
                        inner.module or "").split(".")[0] in ("lxml",
                                                              "defusedxml"):
                    buried.append(f"{node.name}:{inner.lineno}")
        assert buried == []

    def test_both_parsers_are_declared_dependencies(self):
        from pathlib import Path
        requirements = (Path(parse.__file__).resolve().parent.parent.parent
                        / "requirements.txt").read_text(encoding="utf-8")
        assert "lxml" in requirements
        assert "defusedxml" in requirements


class TestBodyCapStopsTheRead:
    """The guard has to stop the read, not measure it afterwards."""

    class _Chunked:
        def __init__(self, chunks, status=200):
            self.status_code = status
            self.headers = {}
            self._chunks = chunks
            self.closed = False
            self.delivered = 0

        def iter_content(self, chunk_size=65536):
            for chunk in self._chunks:
                self.delivered += len(chunk)
                yield chunk

        def close(self):
            self.closed = True

    def _client_for(self, response):
        class _S:
            def request(_self, *a, **k):
                return response
        return client.HttpClient(session=_S(), sleeper=lambda _s: None)

    def test_an_oversized_stream_is_refused(self):
        response = self._Chunked([b"x" * 1000] * 20)
        outcome = self._client_for(response).fetch(
            RequestSpec(url="https://x.test/big"), now=T0,
            max_body_bytes=5000)
        assert outcome.outcome == client.TOO_LARGE

    def test_the_read_is_abandoned_rather_than_completed(self):
        response = self._Chunked([b"x" * 1000] * 20)
        self._client_for(response).fetch(
            RequestSpec(url="https://x.test/big"), now=T0,
            max_body_bytes=5000)
        assert response.delivered < 20_000

    def test_the_response_is_closed(self):
        response = self._Chunked([b"x" * 1000] * 20)
        self._client_for(response).fetch(
            RequestSpec(url="https://x.test/big"), now=T0,
            max_body_bytes=5000)
        assert response.closed is True

    def test_a_body_inside_the_cap_is_assembled_whole(self):
        response = self._Chunked([b"abc", b"def", b"ghi"])
        outcome = self._client_for(response).fetch(
            RequestSpec(url="https://x.test/ok"), now=T0, max_body_bytes=100)
        assert outcome.succeeded and outcome.payload.body == b"abcdefghi"

    def test_streaming_is_requested(self):
        calls = []

        class _S:
            def request(_self, *a, **k):
                calls.append(k)
                return TestBodyCapStopsTheRead._Chunked([b"ok"])
        client.HttpClient(session=_S(), sleeper=lambda _s: None).fetch(
            RequestSpec(url="https://x.test/a"), now=T0)
        assert calls[0]["stream"] is True


class TestClientErgonomics:
    def test_the_timeout_is_a_connect_read_pair(self):
        calls = []

        class _S:
            def request(_self, *a, **k):
                calls.append(k)
                return TestBodyCapStopsTheRead._Chunked([b"{}"])
        http = client.HttpClient(session=_S(), sleeper=lambda _s: None)
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert calls[0]["timeout"] == (policy.HTTP_CONNECT_TIMEOUT_SEC,
                                       policy.HTTP_TIMEOUT_SEC)

    def test_a_non_positive_connect_timeout_is_refused(self):
        with pytest.raises(DomainError, match="timeouts must be positive"):
            client.HttpClient(session=object(), connect_timeout_sec=0)

    def test_it_closes_itself_as_a_context_manager(self):
        class _S:
            closed = False

            def close(_self):
                _S.closed = True
        with client.HttpClient(session=_S(), sleeper=lambda _s: None):
            pass
        assert _S.closed is True

    def test_retry_after_is_read_case_insensitively(self):
        """The live CaseInsensitiveDict is used, not a dict() copy."""
        import requests as requests_lib

        class _S:
            def __init__(_self):
                _self.calls = 0

            def request(_self, *a, **k):
                _self.calls += 1
                response = TestBodyCapStopsTheRead._Chunked([b""], status=429)
                response.headers = requests_lib.structures.CaseInsensitiveDict(
                    {"retry-after": "3600"})
                return response
        session = _S()
        outcome = client.HttpClient(session=session,
                                    sleeper=lambda _s: None).fetch(
            RequestSpec(url="https://x.test/a"), now=T0)
        assert outcome.outcome == client.RATE_LIMITED
        assert session.calls == 1


class TestHashabilityRuling:
    """frozen=True advertises hashability; these hold mappings.

    The ruling is: value-equal, deliberately unhashable, and the failure
    is immediate and legible rather than a TypeError from inside a
    generated __hash__.
    """

    @pytest.mark.parametrize("value", [
        RequestSpec(url="https://x.test"),
        __import__("v3.adapters.types", fromlist=["ObservationDraft"]
                   ).ObservationDraft(signal_source="s", domain="cyber",
                                      country="TW", status="FIRED"),
        LimiterState(),
    ])
    def test_it_is_unhashable_and_says_so(self, value):
        with pytest.raises(TypeError, match="unhashable"):
            hash(value)

    def test_value_equality_still_works(self):
        assert RequestSpec(url="https://x.test") == \
            RequestSpec(url="https://x.test")
        assert LimiterState().record("g", T0) == LimiterState().record("g", T0)


# ── the client applies the DECLARATION, and nothing else ────────────────
#
# WP-2.6 fidelity sweep. `_auth_headers` used to decide the header name
# itself — `Auth-Key` for every api_key adapter — which is correct for
# abuse.ch and wrong for Cloudflare, GreyNoise and OpenWeather. Three
# sources were presenting a credential no server would read.

class TestAuthIsAppliedAsDeclared:
    def _client(self, credentials=None, response=None):
        session = _Session(response or _Response())
        return client.HttpClient(session=session, sleeper=lambda _s: None,
                                 credentials=credentials or {}), session

    def test_a_declared_header_name_is_the_one_sent(self):
        http, session = self._client({"GREYNOISE_API_KEY": "gn"})
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                   auth=AuthRequirement(kind=AUTH_API_KEY,
                                        key_id="GREYNOISE_API_KEY",
                                        name="key",
                                        value_template="{secret}"))
        assert session.calls[0]["headers"]["key"] == "gn"
        assert "Auth-Key" not in session.calls[0]["headers"]

    def test_a_bearer_template_is_rendered(self):
        http, session = self._client({"CF_API_TOKEN": "tok"})
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                   auth=AuthRequirement(kind=AUTH_API_KEY,
                                        key_id="CF_API_TOKEN",
                                        name="Authorization",
                                        value_template="Bearer {secret}"))
        assert session.calls[0]["headers"]["Authorization"] == "Bearer tok"

    def test_a_query_placed_credential_never_becomes_a_header(self):
        """OpenWeather reads no auth header. `appid` is a query parameter."""
        http, session = self._client({"OWM_API_KEY": "owm"})
        http.fetch(RequestSpec(url="https://x.test/a",
                               params=(("lat", "25.0"),)), now=T0,
                   auth=AuthRequirement(kind=AUTH_API_KEY,
                                        key_id="OWM_API_KEY",
                                        placement=AUTH_IN_QUERY,
                                        name="appid",
                                        value_template="{secret}"))
        call = session.calls[0]
        assert ("appid", "owm") in list(call["params"])
        assert all("owm" not in str(v) for v in call["headers"].values())

    def test_the_declared_parameters_keep_their_place_ahead_of_the_key(self):
        http, session = self._client({"OWM_API_KEY": "owm"})
        http.fetch(RequestSpec(url="https://x.test/a",
                               params=(("lat", "25"), ("lon", "121"))), now=T0,
                   auth=AuthRequirement(kind=AUTH_API_KEY,
                                        key_id="OWM_API_KEY",
                                        placement=AUTH_IN_QUERY,
                                        name="appid",
                                        value_template="{secret}"))
        assert list(session.calls[0]["params"]) == [
            ("lat", "25"), ("lon", "121"), ("appid", "owm")]

    def test_an_absent_optional_credential_fetches_anonymously(self):
        """OpenSky's production default. Refusing here took three physical
        sensors dark for every deployment running the shipped example."""
        http, session = self._client({})
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                             auth=AuthRequirement(
                                 kind=AUTH_OAUTH2,
                                 key_id="OPENSKY_CLIENT_CREDENTIALS",
                                 name="Authorization",
                                 value_template="Bearer {secret}",
                                 optional=True))
        assert outcome.outcome == client.OK
        assert len(session.calls) == 1
        assert "Authorization" not in session.calls[0]["headers"]

    def test_a_supplied_optional_credential_is_still_used(self):
        http, session = self._client({"OPENSKY_CLIENT_CREDENTIALS": "tok"})
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                   auth=AuthRequirement(kind=AUTH_OAUTH2,
                                        key_id="OPENSKY_CLIENT_CREDENTIALS",
                                        name="Authorization",
                                        value_template="Bearer {secret}",
                                        optional=True))
        assert session.calls[0]["headers"]["Authorization"] == "Bearer tok"

    def test_an_absent_mandatory_credential_still_refuses(self):
        http, session = self._client({})
        outcome = http.fetch(RequestSpec(url="https://x.test/a"), now=T0,
                             auth=AuthRequirement(kind=AUTH_API_KEY,
                                                  key_id="CF_API_TOKEN",
                                                  name="Authorization",
                                                  value_template="Bearer {secret}"))
        assert outcome.outcome == client.AUTH_MISSING
        assert session.calls == []

    def test_a_per_request_credential_beats_the_adapter_one(self):
        """ioda_bgp: the primary needs nothing, the fallback needs
        Cloudflare's token."""
        http, session = self._client({"CF_API_TOKEN": "tok"})
        spec = RequestSpec(url="https://cf.test/a",
                           auth=AuthRequirement(kind=AUTH_API_KEY,
                                                key_id="CF_API_TOKEN",
                                                name="Authorization",
                                                value_template="Bearer {secret}"))
        http.fetch(spec, now=T0, auth=AuthRequirement())
        assert session.calls[0]["headers"]["Authorization"] == "Bearer tok"

    def test_no_declared_credential_means_no_auth_of_any_kind(self):
        http, session = self._client({"CF_API_TOKEN": "tok"})
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        headers = session.calls[0]["headers"]
        assert "Authorization" not in headers and "Auth-Key" not in headers

    def test_the_client_knows_no_source_names(self):
        """The repaired defect was a header name written into the kernel.

        Read as CODE, not as text: the comment explaining the repair
        naturally names `Auth-Key`, and a check that could not tell the
        two apart would push the explanation out of the file that needs
        it most.
        """
        tree = ast.parse(inspect.getsource(client))
        literals = {node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Constant)
                    and isinstance(node.value, str)}
        # Docstrings are prose, not wire values.
        code_literals = literals - set(ast.get_docstring(tree) or "")
        for name in ("Auth-Key", "appid", "Bearer {secret}"):
            offenders = [text for text in code_literals
                         if name in text and "\n" not in text]
            assert not offenders, (
                f"{name!r} is back in client.py as a value ({offenders}); "
                f"the header is the adapter's declaration, not the "
                f"kernel's assumption")


class TestBodiesAndRepeatedParameters:
    def _client(self, response=None):
        session = _Session(response or _Response())
        return client.HttpClient(session=session,
                                 sleeper=lambda _s: None), session

    def test_a_json_body_is_sent_as_bytes_with_its_content_type(self):
        http, session = self._client()
        http.fetch(RequestSpec(url="https://tf.test/", method="POST",
                               body={"query": "get_iocs", "days": 1},
                               body_content_type="application/json"), now=T0)
        call = session.calls[0]
        assert call["method"] == "POST"
        assert json.loads(call["data"].decode()) == {"query": "get_iocs",
                                                     "days": 1}
        assert call["headers"]["Content-Type"] == "application/json"

    def test_a_bodyless_request_sends_no_body(self):
        http, session = self._client()
        http.fetch(RequestSpec(url="https://x.test/a"), now=T0)
        assert session.calls[0]["data"] is None

    def test_repeated_parameters_reach_the_session_intact(self):
        http, session = self._client()
        http.fetch(RequestSpec(
            url="https://ch.test/", params=(("host", "https://gov.tw"),
                                            ("max_nodes", "5"),
                                            ("node[]", "jp1"),
                                            ("node[]", "us1"))), now=T0)
        assert list(session.calls[0]["params"]) == [
            ("host", "https://gov.tw"), ("max_nodes", "5"),
            ("node[]", "jp1"), ("node[]", "us1")]

    def test_the_session_receives_a_sequence_not_a_mapping(self):
        """A mapping at the boundary would collapse the repeats we just
        went to the trouble of declaring."""
        http, session = self._client()
        http.fetch(RequestSpec(url="https://x.test",
                               params=(("a", "1"), ("a", "2"))), now=T0)
        params = session.calls[0]["params"]
        assert not isinstance(params, dict)
        assert len(list(params)) == 2
