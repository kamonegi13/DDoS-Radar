"""WP-2.6 — the roster, the knowledge ledger, and the I/O barriers.

Three accounting jobs live here, and each one fails on drift rather than
on someone noticing:

1. **Totality.** The design sheet §3-2 table is parsed from the document
   itself and compared with what this package exports. An adapter that
   goes missing, an identifier that drifts, or a row added to the sheet
   without a port all fail. Same shape as the ETL's `S3_MIGRATE_35` check
   and L2's clause registry — `scenarios` went missing from the migration
   plan precisely because nothing compared the plan with the spec.

2. **D1 §4's twenty facts.** One fact, one test, with the fact in the
   test's name (§6-2). The meta-test below checks the mapping in both
   directions: a fact claimed by an adapter with no test fails, and a
   test naming a fact no adapter claims fails.

3. **The four I/O barriers**, run against every adapter rather than
   against the exemplar alone — including the closure-smuggling shape
   that WP-2.5 proved barriers 2 and 3 cannot see.
"""
import ast
import re
import socket
import threading
from pathlib import Path

import pytest

from v3.adapters import catalog, knowledge
from v3.adapters.catalog import (DESIGN_SHEET_RENAMES, WP26_ADAPTERS,
                                 WP26_DESIGN_SHEET_ROWS, build_registry,
                                 expected_adapter_ids)
from v3.adapters.knowledge import (KNOWLEDGE, KNOWLEDGE_TESTS, WP26_KNOWLEDGE,
                                   unknown_refs)
from v3.adapters.types import (ADAPTER_STATUSES, AdapterId, FetchedPayload,
                               NormalizeContext, ObservationDraft,
                               RequestChain)

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "docs" / "design" / "v3" / "wp25-l0-adapter-design.md"
ADAPTERS_DIR = REPO_ROOT / "v3" / "adapters"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "adapters"
T0 = 1_700_000_000.0


# ── 1. totality against the design sheet ────────────────────────────────

def _design_sheet_rows() -> list[tuple[int, str]]:
    """Parse §3-2's table out of the document, not out of a copy of it."""
    text = SPEC.read_text(encoding="utf-8")
    section = text.split("### 3-2.")[1].split("### 3-3.")[0]
    rows = re.findall(r"^\|\s*(\d+)\s*\|\s*`([a-z0-9_]+)`\s*\|",
                      section, flags=re.MULTILINE)
    return [(int(number), name) for number, name in rows]


class TestTheRosterMatchesTheDesignSheet:
    def test_the_transcription_matches_the_document(self):
        assert _design_sheet_rows() == list(WP26_DESIGN_SHEET_ROWS)

    def test_the_sheet_lists_twenty_two_adapters(self):
        assert len(WP26_DESIGN_SHEET_ROWS) == 22

    def test_every_declared_adapter_is_built(self):
        assert tuple(adapter.name for adapter in WP26_ADAPTERS) == \
            expected_adapter_ids()

    def test_no_adapter_is_built_that_the_sheet_does_not_list(self):
        assert set(adapter.name for adapter in WP26_ADAPTERS) == \
            set(expected_adapter_ids())

    def test_the_only_rename_is_the_one_the_sheet_mandates(self):
        """DP6/§7-2 #5: the sensor called itself FIRMS and fetched EONET."""
        assert DESIGN_SHEET_RENAMES == {"nasa_firms": "nasa_eonet"}


class TestTheExpectedDifferenceRegister:
    """§7-2 read from the document. P2 §5-C makes an unregistered
    difference a cutover abort, so the register is a contract, not a note:
    a WP-2.6 adapter that behaves differently from live v2 must appear
    here or must be changed back.
    """

    @staticmethod
    def _registered() -> list[str]:
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 7-2.")[1].split("\n## ")[0]
        return re.findall(r"^\|\s*\d+\s*\|\s*`([a-z0-9_]+)`", section,
                          flags=re.MULTILINE)

    def test_threatfox_zero_hit_observations_are_registered(self):
        """S1-SENS-014 says a country with no hits MUST NOT appear; the
        port emits an OK observation for it anyway, so that "nothing seen"
        and "not looked at" stop being the same absence (NP1). Sound, and
        still a processing difference — so it is registered rather than
        left for the parity harness to discover."""
        assert "threatfox" in self._registered()

    def test_the_ct_log_score_three_ceiling_is_registered(self):
        """RULING #4. While the untrusted-CA verdict stays OBSERVED-
        pending, a payload legacy scores 3 scores at most 2 here. That is
        the *insensitive* direction — the one class that aborts cutover
        under C-02/C-03 — so it is registered now rather than after
        someone sees whether the L1 wiring lands first. Registering
        something that later becomes moot costs nothing; the reverse
        costs the cutover."""
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 7-2.")[1].split("\n## ")[0]
        row = [line for line in section.splitlines()
               if line.startswith("| 8 ") and "`ct_log`" in line]
        assert len(row) == 1, "§7-2 #8 (ct_log score-3 ceiling) is missing"
        assert "insensitive" in row[0]

    def test_every_registered_name_is_a_real_adapter_or_a_known_rename(self):
        known = set(expected_adapter_ids()) | set(DESIGN_SHEET_RENAMES)
        wp27 = {"hacktivist_news", "travel_advisory"}   # §3-3, not this WP
        assert set(self._registered()) - known - wp27 == set()

    def test_the_open_hand_offs_are_written_down_where_the_code_points(self):
        """Two adapter docstrings cite §3-5 — the ISR multi-zone gap and
        the AISHub envelope ruling request. A citation to a section that
        does not exist is how "raised for a ruling" became a claim nobody
        could check."""
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 3-5.")[1].split("\n## ")[0]
        assert "H-1" in section and "H-2" in section
        assert "ISR_HOTSPOTS" in section and "AISHub" in section
        assert "WP-4.1" in section          # H-1 names its landing WP
        assert "裁定待ち" in section          # H-2 says the ruling is open

    def test_the_split_is_seven_cyber_and_fifteen_physical(self):
        registry = build_registry()
        assert len(registry.by_category("cyber")) == 7
        assert len(registry.by_category("physical")) == 15

    def test_exactly_two_adapters_are_disabled_and_both_say_why(self):
        disabled = build_registry().disabled()
        assert [adapter.name for adapter in disabled] == \
            ["ihr_health", "notam"]
        assert all(adapter.disabled_reason for adapter in disabled)

    def test_every_identifier_resolves_through_the_registry(self):
        """F-02: a name that resolves nowhere used to be indistinguishable
        from one naming a disabled adapter."""
        registry = build_registry()
        for name in expected_adapter_ids():
            assert registry.get(registry.resolve(name)).name == name
        with pytest.raises(Exception):
            registry.resolve("cf")      # the F-02 string itself


class TestTheDeclarationsAreWellFormed:
    @pytest.mark.parametrize("adapter", WP26_ADAPTERS,
                             ids=lambda a: a.name)
    def test_each_adapter_declares_a_finite_freshness_horizon(self, adapter):
        assert adapter.freshness_horizon_sec > 0

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS,
                             ids=lambda a: a.name)
    def test_each_adapter_names_only_known_knowledge_items(self, adapter):
        assert unknown_refs(adapter.knowledge_refs) == frozenset()

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS,
                             ids=lambda a: a.name)
    def test_no_adapter_carries_a_credential_value(self, adapter):
        """Auth is a NAME for a secret; the composition root supplies the
        value. Nothing under `v3/` reads the environment."""
        if adapter.auth.is_required:
            assert adapter.auth.key_id and adapter.auth.key_id.isupper()

    def test_the_opensky_family_shares_one_rate_limit_group(self):
        groups = build_registry().rate_limit_groups()
        assert groups["opensky"] == ("isr_hotspot", "mil_support_air",
                                     "opensky")

    def test_the_required_secrets_are_the_expected_six(self):
        # THREE of the six moved to `optional_key_ids` — not because the
        # sources stopped wanting them, but because production runs without
        # them: OpenSky ships anonymous (config.env.example:90-91),
        # CertSpotter's free tier is tokenless. Declaring those mandatory
        # aborted the fetch with AUTH_MISSING before the socket opened.
        assert build_registry().required_key_ids() == (
            "CF_API_TOKEN", "GREYNOISE_API_KEY", "OWM_API_KEY",
            "THREATFOX_API_KEY")
        assert build_registry().optional_key_ids() == (
            "CERTSPOTTER_API_TOKEN", "OPENSKY_CLIENT_CREDENTIALS")

    def test_baseline_dependencies_are_declared_where_they_exist(self):
        """DP3: nine sensors kept detection state in process memory, so a
        restart cost detection capability silently. A declared dependency
        is visible in the registry; an instance dictionary is visible to
        nobody."""
        declared = {adapter.name: adapter.baseline_refs
                    for adapter in WP26_ADAPTERS if adapter.baseline_refs}
        assert set(declared) == {
            "opensky", "ais_maritime", "gps_jamming", "check_host",
            "ripe_atlas", "ripe_bgp", "ooni_censorship", "ct_log",
            "apt_intel", "cloudflare_radar"}


# ── 2. D1 §4's twenty facts, one test each ──────────────────────────────

class TestKnowledgeLedger:
    def test_the_twenty_items_are_all_transcribed(self):
        assert len(KNOWLEDGE) == 20
        assert sorted(KNOWLEDGE) == [f"K{n:02d}" for n in range(1, 21)]

    def test_the_design_sheet_declares_the_same_twenty(self):
        text = SPEC.read_text(encoding="utf-8")
        section = text.split("### 3-1.")[1].split("### 3-2.")[0]
        assert set(re.findall(r"\bK(\d{2})\b", section)) == \
            {f"{n:02d}" for n in range(1, 21)}

    def test_every_fact_this_batch_owns_has_a_test(self):
        assert set(KNOWLEDGE_TESTS) == WP26_KNOWLEDGE

    def test_every_named_test_exists_in_this_module(self):
        """A mapping entry whose test was renamed away stops being a claim
        and starts being a lie."""
        module = globals()
        for key, name in sorted(KNOWLEDGE_TESTS.items()):
            found = any(name in dir(value) for value in module.values()
                        if isinstance(value, type)) or name in module
            assert found, f"{key} names a missing test: {name}"

    def test_every_fact_this_batch_owns_is_claimed_by_an_adapter(self):
        claimed = {ref for adapter in WP26_ADAPTERS
                   for ref in adapter.knowledge_refs}
        assert claimed == WP26_KNOWLEDGE

    def test_the_other_five_facts_belong_to_the_next_batch(self):
        assert knowledge.WP27_KNOWLEDGE == frozenset(
            {"K07", "K08", "K13", "K18", "K20"})


class TestKnowledgeItems:
    """One item, one test, the fact written into the name (§6-2)."""

    def test_k01_opensky_three_adapters_share_one_rate_limit_group(self):
        from v3.adapters.physical import opensky
        for adapter in (opensky.OPENSKY_ADAPTER, opensky.ISR_HOTSPOT_ADAPTER,
                        opensky.MIL_SUPPORT_AIR_ADAPTER):
            assert adapter.rate_limit_group == "opensky"
            assert adapter.min_interval_sec == 10.0
        # A per-adapter limiter would let three adapters that each respect
        # the quota collectively exceed it.
        assert build_registry().rate_limit_groups()["opensky"] == (
            "isr_hotspot", "mil_support_air", "opensky")

    def test_k02_aishub_rate_limit_is_http_200_with_empty_body(self):
        """An empty body on a 200 is a throttle, not "no vessels". The
        kernel classifies it, and `normalize` returns nothing rather than
        an all-clear — because "no vessels near the chokepoint" is what a
        blockade looks like."""
        from v3.adapters.physical import ais_maritime
        empty = FetchedPayload(url="http://data.aishub.net/ws.php", status=200,
                               body=b"", fetched_at=T0, label="cp=X;lat=0;lon=0")
        drafts = ais_maritime.normalize(
            empty, NormalizeContext(adapter_id=AdapterId("ais_maritime"),
                                    now=T0, countries=("TW",)))
        assert drafts[0].flags["vessels_examined"] == 0
        assert drafts[0].status != "FIRED"

    def test_k03_checkhost_two_stage_request_id_flow_and_no_latency_penalty(
            self):
        from v3.adapters.physical import check_host
        from v3.adapters.types import RequestContinuation
        # K03's first fact is a CONTINUATION, not two independent requests:
        # the second one's address is inside the first one's answer. As two
        # requests, `{request_id}` was unresolvable at plan time and the
        # adapter was skipped every cycle (design sheet §2-4 row 8).
        declared, = check_host.CHECK_HOST_ADAPTER.requests
        assert isinstance(declared, RequestContinuation)
        labels = [spec.label for spec in declared.alternatives]
        assert labels == ["request", "result"]
        assert "{request_id}" in declared.then.url
        assert [value.placeholder for value in declared.carries] \
            == ["request_id"]
        assert declared.delay_sec == check_host.RESULT_DELAY_SEC
        assert check_host.RESULT_DELAY_SEC == 5.0
        # Latency never lowers the rate: a 9-second intercontinental check
        # that succeeded is a success.
        assert check_host.summarise_nodes(
            {"a.node": [[1, 9.0, "Found", "302", ""]],
             "b.node": [[1, 8.5, "Found", "302", ""]]})["success_rate"] == 1.0

    def test_k04_ooni_degrades_after_three_empty_cycles(self):
        from v3.adapters.cyber import ooni_censorship
        assert ooni_censorship.DEGRADED_AFTER_FAILURES == 3
        assert ooni_censorship.DEGRADED_CADENCE_SEC == 7200.0
        assert ooni_censorship.NORMAL_CADENCE_SEC == 1800.0

    def test_k05_ct_log_empty_200_is_authoritative_success(self):
        """Falling through to the next source after a 200-empty discards
        an answer and lets a slower source's staleness overwrite it."""
        from v3.adapters.cyber import ct_log
        empty = FetchedPayload(url="https://api.certspotter.com/v1/issuances",
                               status=200, body=b"[]", fetched_at=T0,
                               label="certspotter")
        drafts = ct_log.normalize(
            empty, NormalizeContext(adapter_id=AdapterId("ct_log"), now=T0,
                                    countries=("TW",)))
        assert len(drafts) == 1 and drafts[0].flags["total_recent"] == 0

    def test_k06_ihr_is_reached_at_the_www_ihr_live_mirror(self):
        """`ihr.iijlab.net` 301s here; behind a proxy that hop times out."""
        from v3.adapters.physical import ihr_health
        assert ihr_health.IHR_API_BASE == "https://www.ihr.live/ihr/api"
        assert all(spec.url.startswith("https://www.ihr.live")
                   for spec in ihr_health.IHR_HEALTH_ADAPTER.requests)

    def test_k09_cisa_advisory_feed_url_is_the_moved_one(self):
        """The URL is asserted against the LIVE sensor rather than a
        literal. This test previously held a literal the port had
        invented, so it certified the drift it existed to catch —
        `tests/test_adapters_cyber.py::TestAptIntel` parses
        `_CERT_SOURCES` and pins all five."""
        from v3.adapters.cyber import apt_intel
        assert "/cybersecurity-advisories/" in apt_intel.CISA_ADVISORIES_URL
        assert apt_intel.CISA_ADVISORIES_URL == \
            dict(apt_intel.FEEDS)["cisa_advisories"]
        # Akamai answers 403 to script user-agents.
        assert apt_intel.APT_INTEL_ADAPTER.requests[0].headers[
            "User-Agent"].startswith("Mozilla/")

    def test_k10_threatfox_sends_auth_key_on_get_iocs(self):
        """It did not always need one; today a keyless call is a 401, and
        a 401 that keeps the old cache looks like a quiet day."""
        from v3.adapters.cyber import threatfox
        auth = threatfox.THREATFOX_ADAPTER.auth
        assert auth.is_required and auth.key_id == "THREATFOX_API_KEY"
        assert auth.name == "Auth-Key" and auth.value_template == "{secret}"
        # A JSON BODY, as production sends it (`threatfox.py:20,42`) — the
        # first port made it a query string, which abuse.ch does not read.
        spec = threatfox.THREATFOX_ADAPTER.requests[0]
        assert spec.method == "POST" and spec.params == ()
        assert spec.body["query"] == "get_iocs"

    def test_k11_greynoise_gnql_failure_is_permanent_and_still_a_success(self):
        """410 (v2 retired), 401 (community key), 403/429 (tier, rate) are
        structural unavailability. Treating them as failures manufactures
        a permanently DEGRADED sensor nobody reads any more."""
        from v3.adapters.cyber import greynoise
        # A body that does not parse into the shape production reads
        # (`greynoise.py:192-197`). `b"{}"` is NOT that: production's two
        # chained `.get(..., default)` calls make an empty object a
        # MEASURED zero (TARGETED, ratio 0%), not an unobtainable one.
        empty = FetchedPayload(url="https://api.greynoise.io/x", status=200,
                               body=b"not json", fetched_at=T0,
                               label="gnql:TW")
        draft = greynoise.normalize(
            empty, NormalizeContext(adapter_id=AdapterId("greynoise"),
                                    now=T0, countries=("TW",)))[0]
        assert draft.flags["noise_class"] == "UNKNOWN"
        assert draft.flags["suppress_confidence"] is False

    def test_k12_gpsjam_discovers_the_newest_day_from_the_manifest(self):
        """Today's tiles do not exist; asking for them returns nothing,
        which reads as calm."""
        from v3.adapters.physical import gps_jamming
        manifest = (FIXTURES / "gps_jamming" / "manifest.csv").read_text()
        assert gps_jamming.latest_manifest_date(manifest) == "2026-08-06"
        assert gps_jamming.latest_manifest_date("") == ""
        assert gps_jamming.GPS_JAMMING_ADAPTER.requests[0].label == "manifest"

    def test_k14_notam_is_disabled_because_no_free_api_exists(self):
        from v3.adapters.physical import notam
        assert notam.NOTAM_ADAPTER.enabled is False
        assert "no free international NOTAM API" in \
            notam.NOTAM_ADAPTER.disabled_reason

    def test_k15_courtesy_delays_are_declared_not_slept(self):
        """RIPE 0.3s, GreyNoise 0.5s, PeeringDB 10s, OONI 0.5s — one
        mechanism, not four sleeps inside four fetch functions."""
        registry = build_registry()
        expected = {"ripe_bgp": 0.3, "greynoise": 0.5, "peeringdb_ixp": 10.0,
                    "ooni_censorship": 0.5, "ripe_atlas": 0.3}
        for name, interval in expected.items():
            adapter = registry.get(registry.resolve(name))
            assert adapter.min_interval_sec == interval, name

    def test_k16_usgs_nuclear_candidate_needs_magnitude_depth_and_territory(
            self):
        from v3.adapters.physical import usgs_seismic
        assert usgs_seismic.NUCLEAR_MIN_MAGNITUDE == 4.0
        assert usgs_seismic.NUCLEAR_MAX_DEPTH_KM == 10.0
        assert usgs_seismic.TERRITORY_HALF_DEG == 5.0

    def test_k17_space_weather_suppresses_at_kp_six_or_xray_class_m(self):
        from v3.adapters.physical import space_weather
        assert space_weather.KP_SUPPRESS_THRESHOLD == 6.0
        assert space_weather.XRAY_SUPPRESS_CLASS == "M"
        assert space_weather.XRAY_CLASS_ORDER["M"] == 3

    def test_k19_ioda_falls_back_to_cloudflare_radar(self):
        from v3.adapters.physical import ioda_bgp
        # A CHAIN, not two unconditional requests: production reaches
        # Cloudflare only when `_fetch_ioda_proper` returns None
        # (`radar/sensors/ioda.py:49-55`). Fetching both let a Cloudflare
        # anomaly FIRED-override IODA's OK.
        chain = ioda_bgp.IODA_BGP_ADAPTER.requests[0]
        assert isinstance(chain, RequestChain)
        assert [spec.label for spec in chain.alternatives] == [
            "ioda", "cf_fallback"]
        assert "ioda.inetintel" in chain.alternatives[0].url
        assert "cloudflare" in chain.alternatives[1].url
        # ...and the fallback carries Cloudflare's own credential, because
        # the primary needs none.
        assert chain.alternatives[0].auth is None
        assert chain.alternatives[1].auth.key_id == "CF_API_TOKEN"


# ── 3. the four I/O barriers, across all 22 ─────────────────────────────

class _NoNetwork:
    """RECORDS connect attempts as well as refusing them (WP-2.5).

    The first version of this guard only raised, which a smuggled
    `HttpClient` defeats: the client catches `requests.RequestException`
    by design and returns a CONNECTION_ERROR outcome, so `normalize`
    returns normally and an exception-expecting barrier sees a clean run.
    Counting attempts detects the call regardless of who swallows it.

    `connect` is patched rather than the socket class, because replacing
    the class breaks import machinery and makes the test pass for the
    wrong reason.
    """

    def __init__(self):
        self.attempts = []

    def __enter__(self):
        guard = self
        self._connect = socket.socket.connect
        self._getaddrinfo = socket.getaddrinfo

        def refuse_connect(_self, address, *args, **kwargs):
            guard.attempts.append(("connect", address))
            raise AssertionError(f"normalize reached the network ({address})")

        def refuse_lookup(host, *args, **kwargs):
            # Resolution happens FIRST and fails before connect() is
            # called, so instrumenting connect alone missed the attempt.
            guard.attempts.append(("resolve", host))
            raise AssertionError(
                f"normalize reached the network (resolving {host})")

        socket.socket.connect = refuse_connect
        socket.getaddrinfo = refuse_lookup
        return self

    def __exit__(self, *exc):
        socket.socket.connect = self._connect
        socket.getaddrinfo = self._getaddrinfo

    @property
    def reached_the_network(self) -> bool:
        return bool(self.attempts)


def _fixture_payloads(adapter_name: str):
    directory = FIXTURES / adapter_name
    if not directory.is_dir():
        return []
    return [FetchedPayload(url=f"https://recorded.test/{path.name}",
                           status=200, body=path.read_bytes(), fetched_at=T0,
                           label=path.stem)
            for path in sorted(directory.iterdir()) if path.is_file()]


class TestBarrierFourAcrossEveryAdapter:
    """Executing every `normalize` with the network instrumented.

    Barriers 1-3 read signatures, imports and import-time effects; a
    `normalize` that CAPTURED a client at declaration time imports nothing
    when called and starts nothing when imported, so only this one sees
    it. WP-2.5 proved that on the exemplar; here it runs against all 22.
    """

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS, ids=lambda a: a.name)
    def test_normalize_never_reaches_the_network(self, adapter):
        context = NormalizeContext(
            adapter_id=adapter.adapter_id, now=T0, countries=("TW", "JP"),
            country_coordinates={"TW": (25.03, 121.5), "JP": (35.68, 139.7)},
            country_names={"TW": "Taiwan", "JP": "Japan"},
            chokepoints=(("Bashi Channel", 21.9, 121.0, "TW"),),
            adversaries=("CN",))
        payloads = _fixture_payloads(adapter.name) or [
            FetchedPayload(url="https://recorded.test/empty", status=200,
                           body=b"{}", fetched_at=T0)]
        with _NoNetwork() as guard:
            for payload in payloads:
                drafts = adapter.normalize(payload, context)
                assert isinstance(drafts, tuple)
                for draft in drafts:
                    assert isinstance(draft, ObservationDraft)
        assert guard.reached_the_network is False

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS, ids=lambda a: a.name)
    def test_normalize_emits_only_known_statuses(self, adapter):
        """A status outside the vocabulary reaches the scoring kernel as a
        string nothing admits — silently scoring zero."""
        context = NormalizeContext(
            adapter_id=adapter.adapter_id, now=T0, countries=("TW",),
            country_coordinates={"TW": (25.03, 121.5)},
            country_names={"TW": "Taiwan"},
            chokepoints=(("Bashi Channel", 21.9, 121.0, "TW"),),
            adversaries=("CN",))
        for payload in _fixture_payloads(adapter.name):
            for draft in adapter.normalize(payload, context):
                assert draft.status in ADAPTER_STATUSES, draft.status

    @pytest.mark.parametrize("adapter", WP26_ADAPTERS, ids=lambda a: a.name)
    def test_normalization_is_deterministic(self, adapter):
        """Same bytes, same instant, same values — what makes a recorded
        fixture meaningful and a parity replay possible."""
        context = NormalizeContext(
            adapter_id=adapter.adapter_id, now=T0, countries=("TW",),
            country_coordinates={"TW": (25.03, 121.5)},
            country_names={"TW": "Taiwan"},
            chokepoints=(("Bashi Channel", 21.9, 121.0, "TW"),),
            adversaries=("CN",))
        for payload in _fixture_payloads(adapter.name):
            assert adapter.normalize(payload, context) == \
                adapter.normalize(payload, context)

    def test_malformed_bytes_never_raise(self):
        """One upstream serving nonsense must not abort the cycle for the
        other 21 adapters."""
        context = NormalizeContext(adapter_id=AdapterId("probe"), now=T0,
                                   countries=("TW",),
                                   country_coordinates={"TW": (25.0, 121.5)})
        for adapter in WP26_ADAPTERS:
            for body in (b"", b"\x00\x01not json", b"<html>nope</html>",
                         b"[]", b"{}", b"null"):
                payload = FetchedPayload(url="https://recorded.test/x",
                                         status=200, body=body,
                                         fetched_at=T0, label="result")
                assert isinstance(adapter.normalize(payload, context), tuple)


class TestBarriersTwoAndThree:
    def test_no_adapter_module_imports_an_http_or_socket_library(
            self, discipline_gate):
        forbidden = discipline_gate._HTTP_MODULES
        offenders = []
        for path in sorted(ADAPTERS_DIR.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                else:
                    continue
                for module in modules:
                    if any(module == entry or module.startswith(entry + ".")
                           or entry.startswith(module + ".")
                           for entry in forbidden):
                        offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []

    def test_the_gate_passes_over_the_whole_package(self, discipline_gate):
        assert discipline_gate.main(["v3/adapters"]) == 0

    def test_importing_every_adapter_starts_no_thread(self):
        """§1-2: import is inert. ~40 threads at import is what pointed the
        legacy suite at the production database."""
        before = threading.active_count()
        import importlib
        for module in ("v3.adapters.catalog", "v3.adapters.cyber.ct_log",
                       "v3.adapters.physical.opensky"):
            importlib.import_module(module)
        assert threading.active_count() == before

    def test_no_adapter_module_imports_the_legacy_package(self):
        for path in sorted(ADAPTERS_DIR.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            assert "import radar" not in source, path.name
            assert "from radar" not in source, path.name
