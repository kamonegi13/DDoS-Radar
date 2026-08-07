"""Can each adapter issue ITS PRODUCTION REQUEST? One test per source.

The WP-2.6 fidelity sweep found eight adapters that could not — not
because their normalization was wrong, but because the WP-2.5 declaration
model could not express the request. Each would have failed **silently in
the direction that reads as calm**: a 401 or a 403 or a query about
nothing, recorded as "measured, no data", which is how a blind spot
becomes a quiet day.

Every test here drives the SHIPPED declaration through the SHIPPED
expander and the SHIPPED client against an injected session, and asserts
the bytes that reach the wire. Nothing is asserted about the declaration
in the abstract; the question is what a real cycle would send.

Where the production shape can be read out of `radar/sensors/` without
importing it (importing boots the Flask app and ~40 threads), it is read
rather than transcribed — a transcription is a copy that rots, and this
suite exists because copies rotted.
"""
import ast
import json
from pathlib import Path

import pytest

from v3.adapters.catalog import build_registry
from v3.adapters.types import AUTH_IN_QUERY, RequestChain
from v3.fetch import client, recorder
from v3.fetch.expand import (ExpansionInput, ExpansionScope, carried_values,
                             continue_with, expand_requests)

REPO_ROOT = Path(__file__).resolve().parent.parent
T0 = 1_700_000_000.0

#: Material the composition root would inject. Names only — the values are
#: obviously fake, and no adapter ever sees either.
CREDENTIALS = {
    "CF_API_TOKEN": "cf-token",
    "GREYNOISE_API_KEY": "gn-key",
    "OWM_API_KEY": "owm-key",
    "THREATFOX_API_KEY": "tf-key",
    "CERTSPOTTER_API_TOKEN": "cs-token",
    "OPENSKY_CLIENT_CREDENTIALS": "os-token",
}


def legacy_source(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


class _Response:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status_code = status
        self.content = body
        self.headers = headers or {}

    def iter_content(self, chunk_size=65536):
        yield self.content

    def close(self):
        pass


class _Session:
    """Records exactly what would go on the wire. Opens no socket."""

    def __init__(self, *responses):
        self._queue = list(responses) or [_Response()]
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self._queue.pop(0) if len(self._queue) > 1 else self._queue[0]


def wire(adapter_name, scope_values=None, *, responses=(), credentials=None,
         common=None, sleeps=None):
    """Every request the shipped pipeline would actually send.

    Declaration -> expander -> client -> session. If any of the four
    cannot carry the shape, this is where it shows.

    Continuations are followed the same way the runner follows them, and
    through the same two functions (`carried_values` / `continue_with`),
    so a second request whose address comes out of the first response is
    exercised here rather than assumed. `sleeps`, when given a list,
    collects the declared inter-request delays the client was asked for.
    """
    adapter = build_registry().get(build_registry().resolve(adapter_name))
    expansion = ExpansionInput(
        scopes=(ExpansionScope(values=dict(scope_values or {}),
                               scope_key="fixture"),),
        common=dict(common or {}))
    steps = expand_requests(adapter.requests, expansion)
    session = _Session(*responses)
    waited = sleeps if sleeps is not None else []
    http = client.HttpClient(
        session=session, sleeper=waited.append,
        credentials=CREDENTIALS if credentials is None else credentials)
    outcomes = []
    for step in steps:
        for spec in step.alternatives:
            outcome = http.fetch(spec, now=T0, auth=adapter.auth)
            outcomes.append(outcome)
            if not outcome.succeeded:
                continue
            if step.continuation is not None:
                document = (outcome.payload.json() if outcome.payload
                            else None)
                values, missing = carried_values(step.continuation, document)
                if not missing:
                    http.pause(step.continuation.delay_sec)
                    outcomes.append(http.fetch(
                        continue_with(step.continuation, values),
                        now=T0, auth=adapter.auth))
            break
    return session.calls, outcomes


# ── 1. cloudflare_radar — Authorization: Bearer, not Auth-Key ──────────

class TestCloudflareRadarCanFetch:
    """`radar/config.py:322` — `{"Authorization": f"Bearer {CF_API_TOKEN}"}`.

    The kernel sent `Auth-Key`. Cloudflare answers an unrecognised
    credential with 403, and this adapter carries the L3/L7 attack share
    that half the cyber domain's convergence rests on.
    """

    def test_production_sends_a_bearer_authorization_header(self):
        source = legacy_source("radar/config.py")
        assert 'CF_HEADERS = {"Authorization": f"Bearer {CF_API_TOKEN}"' in \
            source

    def test_the_shipped_request_carries_that_header(self):
        calls, outcomes = wire("cloudflare_radar")
        assert len(calls) == 4          # l3, l7, hijacks, leaks
        for call in calls:
            assert call["headers"]["Authorization"] == "Bearer cf-token"
            assert "Auth-Key" not in call["headers"]
        assert all(outcome.succeeded for outcome in outcomes)

    def test_without_the_token_it_refuses_rather_than_asking_anonymously(
            self):
        calls, outcomes = wire("cloudflare_radar", credentials={})
        assert calls == []
        assert {o.outcome for o in outcomes} == {client.AUTH_MISSING}


# ── 2. greynoise — the header is literally `key` ───────────────────────

class TestGreynoiseCanFetch:
    def test_production_uses_a_header_named_key(self):
        source = legacy_source("radar/sensors/greynoise.py")
        assert 'h["key"] = GREYNOISE_API_KEY' in source

    def test_the_shipped_request_carries_that_header(self):
        calls, _ = wire("greynoise", {"country": "TW"})
        assert calls[0]["headers"]["key"] == "gn-key"
        assert "Auth-Key" not in calls[0]["headers"]

    def test_the_country_reaches_the_query_rather_than_a_brace(self):
        calls, _ = wire("greynoise", {"country": "TW"})
        assert ("query", "metadata.destination_country:TW") in list(
            calls[0]["params"])


# ── 3. openweather — the key is a QUERY PARAMETER ──────────────────────

class TestOpenweatherCanFetch:
    """`radar/sensors/openweather.py:25` — `params={..., "appid": api_key}`.

    OpenWeather reads no auth header at all. This sensor's whole job is to
    EXPLAIN an airspace drop as weather; losing it turns a storm back into
    an apparent closure, which is a false positive in the opposite
    direction from the usual worry — and equally a loss of meaning.
    """

    def test_production_passes_the_key_as_appid(self):
        source = legacy_source("radar/sensors/openweather.py")
        assert '"appid": api_key' in source

    def test_the_shipped_request_puts_it_in_the_query_string(self):
        calls, _ = wire("openweather", {"country": "TW", "lat": "25.03",
                                        "lon": "121.56"})
        params = list(calls[0]["params"])
        assert params == [("lat", "25.03"), ("lon", "121.56"),
                          ("units", "metric"), ("appid", "owm-key")]

    def test_no_credential_appears_in_any_header(self):
        calls, _ = wire("openweather", {"country": "TW", "lat": "25.03",
                                        "lon": "121.56"})
        assert all("owm-key" not in str(value)
                   for value in calls[0]["headers"].values())

    def test_the_declaration_says_query_not_header(self):
        registry = build_registry()
        auth = registry.get(registry.resolve("openweather")).auth
        assert auth.placement == AUTH_IN_QUERY and auth.name == "appid"


# ── 4. opensky (x3) — anonymous is the production default ──────────────

class TestOpenskyCanFetchAnonymously:
    """`config.env.example:90-91` ships the client id EMPTY, and
    `opensky_auth.py:17` logs "running in anonymous mode (400 req/day
    limit)". Declared mandatory, all three OpenSky adapters aborted with
    AUTH_MISSING before the socket opened — airspace, ISR and military
    support air, dark, reported as no data.
    """

    # `zone` / `lat` / `lng` travel in the LABEL, `ais_maritime`'s
    # convention: the zone's name and centre are not recoverable from the
    # payload (`FetchedPayload.url` is the base URL) and there is no ISR
    # field on `NormalizeContext`. Without them the per-zone `hotspots[]`
    # record cannot name itself, and `core.py:2929-2931` joins that record
    # to the ledger on `name`.
    ZONE = {"country": "TW", "lamin": "23.0", "lomin": "119.0",
            "lamax": "26.6", "lomax": "122.6",
            "zone": "Taiwan Strait Median Line", "lat": "24.5",
            "lng": "119.5"}

    def test_production_ships_the_credential_empty(self):
        example = legacy_source("config.env.example")
        assert "OPENSKY_CLIENT_ID=\n" in example

    def test_production_sends_no_header_when_the_token_is_absent(self):
        source = legacy_source("radar/sensors/opensky_auth.py")
        assert "if token:" in source and 'headers["Authorization"]' in source

    @pytest.mark.parametrize("name", ["opensky", "isr_hotspot",
                                      "mil_support_air"])
    def test_each_of_the_three_fetches_without_a_credential(self, name):
        calls, outcomes = wire(name, self.ZONE, credentials={})
        assert len(calls) == 1
        assert outcomes[0].succeeded
        assert "Authorization" not in calls[0]["headers"]

    @pytest.mark.parametrize("name", ["opensky", "isr_hotspot",
                                      "mil_support_air"])
    def test_a_supplied_token_is_still_used(self, name):
        calls, _ = wire(name, self.ZONE)
        assert calls[0]["headers"]["Authorization"] == "Bearer os-token"

    def test_the_box_reaches_the_wire_as_numbers(self):
        calls, _ = wire("opensky", self.ZONE)
        assert list(calls[0]["params"]) == [
            ("lamin", "23.0"), ("lomin", "119.0"),
            ("lamax", "26.6"), ("lomax", "122.6")]

    def test_the_search_aperture_is_not_sent_to_opensky(self):
        """The port carried `_half_degrees` inside `params`, where it would
        have gone on the wire as a parameter the API does not know. It is
        an input to the BOX, so it is a declared constant like
        `ais_maritime`'s."""
        from v3.adapters.physical import opensky
        calls, _ = wire("opensky", self.ZONE)
        assert all(not name.startswith("_") for name, _ in calls[0]["params"])
        assert opensky.AIRPORT_BOX_HALF_DEG == 0.5
        assert opensky.ISR_BOX_HALF_DEG == 1.8


# ── 5. threatfox — a JSON body, and a key that is genuinely required ───

class TestThreatfoxCanFetch:
    def test_production_posts_a_json_body(self):
        source = legacy_source("radar/sensors/threatfox.py")
        assert 'payload = {"query": "get_iocs", "days": 1}' in source
        assert "requests.post(url, json=payload" in source

    def test_the_shipped_request_posts_that_exact_body(self):
        calls, _ = wire("threatfox")
        call = calls[0]
        assert call["method"] == "POST"
        assert json.loads(call["data"].decode()) == {"query": "get_iocs",
                                                     "days": 1}
        assert call["headers"]["Content-Type"] == "application/json"
        assert list(call["params"]) == []

    def test_the_auth_key_header_is_the_one_abuse_ch_wants(self):
        calls, _ = wire("threatfox")
        assert calls[0]["headers"]["Auth-Key"] == "tf-key"

    def test_the_browser_user_agent_survives(self):
        calls, _ = wire("threatfox")
        assert calls[0]["headers"]["User-Agent"].startswith("Mozilla/")

    def test_a_missing_key_records_auth_missing_rather_than_a_quiet_zero(
            self):
        """Production's keyless path calls `log_fetch(True, ...)` with zero
        hits — a SUCCESS that found nothing. K10 says a keyless get_iocs is
        a 401, so there is no anonymous mode to fall back to. This is the
        one credential the sweep listed as optional that is deliberately
        NOT: reproducing the skip would reproduce the silence."""
        source = legacy_source("radar/sensors/threatfox.py")
        assert "if not tf_api_key:" in source
        assert "self.log_fetch(True, 0, 0, 0, \"\")" in source
        calls, outcomes = wire("threatfox", credentials={})
        assert calls == []
        assert outcomes[0].outcome == client.AUTH_MISSING


# ── 6. ct_log — expand TWICE, an optional token, and a real fallback ───

class TestCtLogCanFetch:
    """Three separate impossibilities in one adapter."""

    def test_production_expands_both_dns_names_and_issuer(self):
        source = legacy_source("radar/sensors/ct_log_sources/certspotter.py")
        assert '"expand": ["dns_names", "issuer"],' in source

    def test_the_shipped_request_sends_expand_twice(self):
        calls, _ = wire("ct_log", {"domain": "gov.tw"})
        params = list(calls[0]["params"])
        assert [value for name, value in params if name == "expand"] == [
            "dns_names", "issuer"]

    def test_without_issuer_every_certificate_would_parse_to_unknown(self):
        """Why the second value is not cosmetic: `parse_issuer` reads the
        issuer field, and a certificate whose issuer is unknown is dropped
        before any rule sees it."""
        from v3.adapters.cyber import ct_log
        assert ct_log.parse_issuer("") == ("unknown", "unknown")
        assert ct_log.parse_issuer("C=US, O=Let's Encrypt")[1] != "unknown"

    def test_the_full_certspotter_query_is_production_order(self):
        calls, _ = wire("ct_log", {"domain": "gov.tw"})
        assert list(calls[0]["params"]) == [
            ("domain", "gov.tw"), ("include_subdomains", "true"),
            ("match_wildcards", "true"), ("expand", "dns_names"),
            ("expand", "issuer")]

    def test_production_makes_the_token_optional(self):
        source = legacy_source("radar/sensors/ct_log_sources/certspotter.py")
        assert "if self._api_token:" in source

    def test_the_free_tier_is_reachable_without_a_token(self):
        calls, outcomes = wire("ct_log", {"domain": "gov.tw"},
                               credentials={})
        assert len(calls) == 1 and outcomes[0].succeeded
        assert "Authorization" not in calls[0]["headers"]

    def test_a_token_becomes_a_bearer_header(self):
        calls, _ = wire("ct_log", {"domain": "gov.tw"})
        assert calls[0]["headers"]["Authorization"] == "Bearer cs-token"

    def test_crtsh_is_a_fallback_not_a_second_query(self):
        calls, _ = wire("ct_log", {"domain": "gov.tw"})
        assert len(calls) == 1
        assert "certspotter" in calls[0]["url"]

    def test_crtsh_is_reached_when_certspotter_rejects(self):
        calls, _ = wire("ct_log", {"domain": "gov.tw"},
                        responses=(_Response(403, b""), _Response(200)))
        assert [call["url"] for call in calls] == [
            "https://api.certspotter.com/v1/issuances", "https://crt.sh/"]

    def test_the_chain_states_why_it_exists(self):
        registry = build_registry()
        chain = registry.get(registry.resolve("ct_log")).requests[0]
        assert isinstance(chain, RequestChain)
        assert "K05" in chain.reason


# ── 7. check_host — five named vantage points, and a CONTINUATION ──────

#: Stage one's reply carries a handle and no measurement; stage two's
#: carries the measurement. `radar/sensors/checkhost.py:60-76`.
_HANDSHAKE = (_Response(body=b'{"request_id": "abc123", "ok": 1}'),
              _Response(body=b'{"jp1.node.check-host.net": '
                             b'[[1, 0.21, "Found", "200", "1.2.3.4"]]}'))


class TestCheckHostCanFetch:
    """`radar/sensors/checkhost.py:46-47` builds a LIST of tuples, and its
    own comment says why: "Pass list of tuples to requests to allow
    repeated same key". The port could express none of the five, so
    check-host.net chose its own nodes and the JP/US/DE/NL/FR verdict had
    nothing behind it.
    """

    def test_production_sends_node_once_per_node(self):
        source = legacy_source("radar/sensors/checkhost.py")
        assert 'params += [("node[]", n) for n in nodes[:5]]' in source

    def test_the_five_nodes_are_the_production_five_in_order(self):
        source = legacy_source("radar/sensors/checkhost.py")
        default = next(
            ast.literal_eval(node.args[1])
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.Call)
            and getattr(node.func, "attr", "") == "getenv"
            and node.args and getattr(node.args[0], "value", "")
            == "CHECKHOST_NODES")
        from v3.adapters.physical import check_host
        assert list(check_host.NODES) == [n.strip()
                                          for n in default.split(",")]

    def test_the_shipped_request_sends_all_five(self):
        calls, _ = wire("check_host", {"target_url": "https://www.gov.tw"},
                        responses=_HANDSHAKE)
        params = list(calls[0]["params"])
        assert params == [
            ("host", "https://www.gov.tw"), ("max_nodes", "5"),
            ("node[]", "jp1.node.check-host.net"),
            ("node[]", "us1.node.check-host.net"),
            ("node[]", "de1.node.check-host.net"),
            ("node[]", "nl1.node.check-host.net"),
            ("node[]", "fr1.node.check-host.net")]

    def test_both_stages_send_the_production_headers(self):
        """`checkhost.py:51-52` and `:69-70` — the same pair, twice.

        Without `Accept`, check-host.net answers HTML, and HTML that
        parses to no nodes is indistinguishable here from a country whose
        nodes all answered.
        """
        calls, _ = wire("check_host", {"target_url": "https://www.gov.tw"},
                        responses=_HANDSHAKE)
        for call in calls:
            assert call["headers"]["Accept"] == "application/json"
            assert call["headers"]["User-Agent"] == "OSINT-Radar/9.0"

    def test_the_reason_is_a_field_rather_than_an_improvised_flag(self):
        """Ruling 5. It used to live in `flags["reason"]`, invented by this
        adapter alone."""
        import inspect

        from v3.adapters.physical import check_host
        source = inspect.getsource(check_host)
        assert '"reason":' not in source
        assert 'reason="fewer than two responding checks"' in source


class TestCheckHostContinuation:
    """"A **then** B(A)" — the ninth shape the model could not carry.

    `RequestChain` says "A **or** B": the second alternative runs when the
    first FAILS. check-host.net is the opposite — the second request runs
    because the first SUCCEEDED, is addressed by a value out of that
    success, and must wait five seconds before it exists
    (`radar/sensors/checkhost.py:60-72`). Declared as two independent
    requests, `{request_id}` had no value at plan time, so `run_due`
    skipped the whole adapter as `unresolved_placeholder` — the most
    direct infrastructure-reachability sensor in the roster, silent every
    cycle, with a recorded reason nobody was reading.
    """

    def test_production_takes_the_handle_from_the_first_response(self):
        source = legacy_source("radar/sensors/checkhost.py")
        assert 'request_id = data.get("request_id", "")' in source
        assert "self.RESULT_API.format(request_id=request_id)" in source

    def test_production_waits_five_seconds_between_the_two(self):
        source = legacy_source("radar/sensors/checkhost.py")
        slept = [node.args[0].value
                 for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call)
                 and getattr(node.func, "attr", "") == "sleep"]
        assert slept == [5]
        from v3.adapters.physical import check_host
        assert check_host.RESULT_DELAY_SEC == float(slept[0])

    def test_the_declaration_is_a_continuation_not_a_chain(self):
        from v3.adapters.types import RequestChain, RequestContinuation
        adapter = build_registry().get(build_registry().resolve("check_host"))
        declared, = adapter.requests
        assert isinstance(declared, RequestContinuation)
        assert not isinstance(declared, RequestChain)
        assert [value.placeholder for value in declared.carries] \
            == ["request_id"]
        assert declared.carries[0].path == ("request_id",)

    def test_the_plan_leaves_the_carried_slot_unresolved(self):
        """It is not the caller's to supply, so it is not an error."""
        adapter = build_registry().get(build_registry().resolve("check_host"))
        step, = expand_requests(adapter.requests, ExpansionInput(
            scopes=(ExpansionScope(values={"target_url": "https://x.tw"}),)))
        assert step.continuation is not None
        assert "{request_id}" in step.continuation.spec.url
        assert step.continuation.carried_slots == frozenset({"request_id"})

    def test_the_second_request_is_addressed_by_the_first_response(self):
        sleeps = []
        calls, outcomes = wire("check_host",
                               {"target_url": "https://www.gov.tw"},
                               responses=_HANDSHAKE, sleeps=sleeps)
        assert len(calls) == 2
        assert calls[1]["url"] == "https://check-host.net/check-result/abc123"
        assert all(outcome.succeeded for outcome in outcomes)
        assert sleeps == [5.0]

    def test_a_reply_without_a_handle_is_recorded_not_swallowed(self, store):
        """`checkhost.py:62-63` — `if not request_id: ... "no request_id"`.

        The fetch SUCCEEDED and the measurement does not exist. Recording
        that as an ordinary HTTP failure would send the breaker after the
        wrong thing; recording nothing at all would leave the country
        looking measured.
        """
        from v3.adapters.catalog import build_registry as registry
        from v3.fetch import runner
        from v3.fetch.state import AdapterState

        adapter = registry().get(registry().resolve("check_host"))
        session = _Session(_Response(body=b'{"error": "limit_exceeded"}'))
        http = client.HttpClient(session=session, sleeper=lambda _s: None,
                                 credentials={})
        plan = runner.run_due(
            T0, [adapter], {"check_host": AdapterState(adapter_id="check_host")},
            expansions={"check_host": ExpansionInput(scopes=(
                ExpansionScope(values={"target_url": "https://x.tw"}),))})
        assert plan.planned_ids == ("check_host",)
        result = runner.execute_plan(plan, registry(), client=http,
                                     store=store, tick_id="t1",
                                     countries=("TW",))
        assert result.results[0].outcome == client.CONTINUATION_UNRESOLVED
        outcomes = [row["outcome"] for row
                    in recorder.fetch_log_for(store, "check_host")]
        assert client.CONTINUATION_UNRESOLVED in outcomes
        assert len(session.calls) == 1     # the second was never addressable

    def test_the_measurement_reaches_the_ledger(self, store):
        """Declaration -> expander -> client -> recorder, end to end."""
        from v3.adapters.catalog import build_registry as registry
        from v3.fetch import runner
        from v3.fetch.state import AdapterState

        adapter = registry().get(registry().resolve("check_host"))
        session = _Session(*_HANDSHAKE)
        http = client.HttpClient(session=session, sleeper=lambda _s: None,
                                 credentials={})
        plan = runner.run_due(
            T0, [adapter], {"check_host": AdapterState(adapter_id="check_host")},
            expansions={"check_host": ExpansionInput(scopes=(
                ExpansionScope(values={"target_url": "https://x.tw"}),))})
        result = runner.execute_plan(plan, registry(), client=http,
                                     store=store, tick_id="t1",
                                     countries=("TW",))
        assert result.results[0].outcome == client.OK
        # Stage one carries no measurement, so exactly one observation.
        assert result.observations_written == 1
        assert len(session.calls) == 2
        assert len(recorder.fetch_log_for(store, "check_host")) == 2


@pytest.fixture()
def store(tmp_path):
    from v3.ledger import LedgerStore
    instance = LedgerStore(str(tmp_path / "v3.db"))
    try:
        yield instance
    finally:
        instance.close()


# ── 8. ioda_bgp — a conditional fallback with its OWN credential ───────

class TestIodaBgpCanFetch:
    SCOPE = {"since_epoch": "1699992800", "until_epoch": "1700000000"}

    def test_production_calls_cloudflare_only_when_ioda_returns_none(self):
        source = legacy_source("radar/sensors/ioda.py")
        assert "result = self._fetch_ioda_proper(all_codes, t0)" in source
        assert "if result is not None:\n            return result" in source

    def test_a_healthy_ioda_never_touches_cloudflare(self):
        calls, _ = wire("ioda_bgp", self.SCOPE)
        assert len(calls) == 1
        assert "ioda.inetintel" in calls[0]["url"]

    def test_a_failing_ioda_falls_through_to_cloudflare(self):
        calls, _ = wire("ioda_bgp", self.SCOPE,
                        responses=(_Response(404, b""), _Response(200)))
        assert len(calls) == 2
        assert "cloudflare" in calls[1]["url"]

    def test_the_fallback_carries_cloudflares_bearer_token(self):
        """The primary needs no credential; the fallback needs Cloudflare's.
        Production passes `context["cf_headers"]` into `_fetch_cf_fallback`
        alone (`radar/sensors/ioda.py:157`), so the credential belongs to
        the REQUEST rather than to the source."""
        calls, _ = wire("ioda_bgp", self.SCOPE,
                        responses=(_Response(404, b""), _Response(200)))
        assert "Authorization" not in calls[0]["headers"]
        assert calls[1]["headers"]["Authorization"] == "Bearer cf-token"

    def test_the_timestamps_reach_the_wire_as_numbers(self):
        calls, _ = wire("ioda_bgp", self.SCOPE)
        assert list(calls[0]["params"]) == [
            ("from", "1699992800"), ("until", "1700000000"),
            ("entityType", "country"), ("limit", "200")]


# ── the property that made all eight invisible ─────────────────────────

class TestNoPlaceholderCanReachTheWire:
    """Every one of these failures was silent, and they were silent for the
    same reason: a request that is malformed in a way the server tolerates
    comes back 200-with-nothing, or 401, and this layer reads either as
    "measured, no data".
    """

    def test_no_shipped_declaration_leaves_a_brace_unaccounted_for(self):
        """Each placeholder an adapter declares must be expandable — the
        suite above supplies values for all of them. This test is the
        inventory that keeps a NEW placeholder from being added with no
        caller and no test."""
        from v3.fetch.expand import placeholders_in
        registry = build_registry()
        declared = {
            adapter.name: sorted(
                {name for spec in adapter.declared_specs
                 for name in placeholders_in(spec)})
            for adapter in registry.all()}
        assert {name: value for name, value in declared.items() if value} == {
            "ais_maritime": ["chokepoint", "lat", "latmax", "latmin", "lon",
                             "lonmax", "lonmin"],
            "check_host": ["request_id", "target_url"],
            "ct_log": ["domain"],
            "gps_jamming": ["date"],
            "greynoise": ["country"],
            "ihr_health": ["since_iso", "until_iso"],
            "ioda_bgp": ["since_epoch", "until_epoch"],
            "isr_hotspot": ["country", "lamax", "lamin", "lat", "lng",
                            "lomax", "lomin", "zone"],
            "mil_support_air": ["country", "lamax", "lamin", "lat", "lng",
                                "lomax", "lomin", "zone"],
            "ooni_censorship": ["country", "since_date", "until_date"],
            "opensky": ["country", "lamax", "lamin", "lomax", "lomin"],
            "openweather": ["country", "lat", "lon"],
            "peeringdb_ixp": ["country"],
            # `{measurement_id}` is gone: the three ids in
            # `DEFAULT_MEASUREMENT_IDS` are now three concrete addresses,
            # so no caller can forget to supply them.
            "ripe_atlas": ["country"],
            "ripe_bgp": ["country"],
            "usgs_seismic": ["since_iso"],
        }

    @pytest.mark.parametrize("name,values", [
        ("ripe_bgp", {"country": "TW"}),
        ("ooni_censorship", {"country": "TW", "since_date": "2026-08-01",
                             "until_date": "2026-08-07"}),
        ("peeringdb_ixp", {"country": "TW"}),
        ("ripe_atlas", {"country": "TW", "measurement_id": "1001"}),
        ("usgs_seismic", {"since_iso": "2026-08-06T00:00:00"}),
        ("nasa_eonet", {}),
        ("space_weather", {}),
        ("gps_jamming", {"date": "2026-08-06"}),
        ("apt_intel", {}),
    ])
    def test_the_rest_of_the_roster_also_reaches_the_wire_resolved(
            self, name, values):
        calls, outcomes = wire(name, values)
        assert calls, f"{name} issued no request"
        for call in calls:
            assert "{" not in call["url"]
            for key, value in call["params"]:
                assert "{" not in str(value), (name, key, value)
        assert all(outcome.succeeded for outcome in outcomes)
