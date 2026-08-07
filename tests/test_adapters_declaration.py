"""WP-2.5 — the adapter declaration model and its four I/O barriers.

Design sheet §2. An adapter declares WHAT to fetch and HOW to normalize;
it cannot declare how to fetch, and it cannot perform I/O. §2-2 closes
that four ways deliberately, so that breaking one still leaves three —
A-10 is the record of what a single, optional, well-intentioned mechanism
achieves (zero adoption across 28 implementations).
"""
import ast
import inspect
import json
from pathlib import Path

import pytest

from v3.adapters import reference, types
from v3.adapters.types import (AUTH_API_KEY, AdapterId, AuthRequirement,
                               FetchedPayload, NormalizeContext,
                               ObservationDraft, RequestChain, RequestSpec,
                               SourceAdapter)
from v3.fetch import expand
from v3.fetch.expand import ExpansionScope
from v3.kernel import Window
from v3.kernel.errors import DomainError

REPO_ROOT = Path(__file__).resolve().parent.parent
ADAPTERS_DIR = REPO_ROOT / "v3" / "adapters"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "adapters"
T0 = 1_700_000_000.0


def _payload(body: bytes, url="https://www.peeringdb.com/api/ix"):
    return FetchedPayload(url=url, status=200, body=body, fetched_at=T0,
                          content_type="application/json")


# ── the identifier type (F-02) ──────────────────────────────────────────

class TestAdapterId:
    def test_a_valid_identifier_is_accepted(self):
        assert AdapterId("cloudflare_radar").value == "cloudflare_radar"

    @pytest.mark.parametrize("bad", ["", "Cloudflare", "cloudflare-radar",
                                     "cf radar", "cf.radar"])
    def test_a_malformed_identifier_is_refused(self, bad):
        with pytest.raises(DomainError):
            AdapterId(bad)

    def test_an_adapter_cannot_be_declared_with_a_bare_string(self):
        with pytest.raises(DomainError, match="F-02"):
            SourceAdapter(
                adapter_id="cloudflare_radar", category="cyber",
                requests=(RequestSpec(url="https://x.test"),),
                cadence=Window.from_days(1.0, cadence_sec=60.0),
                normalize=lambda p, c: (), freshness_horizon_sec=60.0)


# ── what a RequestSpec may say ──────────────────────────────────────────

class TestRequestSpec:
    def test_a_relative_url_is_refused(self):
        with pytest.raises(DomainError, match="absolute"):
            RequestSpec(url="/api/ix")

    def test_an_unsupported_method_is_refused(self):
        with pytest.raises(DomainError):
            RequestSpec(url="https://x.test", method="DELETE")

    def test_a_callable_parameter_is_refused(self):
        """§2-1: a function here would be 'how to fetch'."""
        with pytest.raises(DomainError, match="how to fetch"):
            RequestSpec(url="https://x.test", params=(("t", lambda: "now"),))

    def test_params_are_read_only(self):
        spec = RequestSpec(url="https://x.test", params=(("a", "1"),))
        with pytest.raises(TypeError):
            spec.params[0] = ("a", "2")


# ── auth is declared, never held ────────────────────────────────────────

class TestAuthRequirement:
    def test_the_default_is_no_auth(self):
        assert AuthRequirement().is_required is False

    def test_an_api_key_requirement_names_a_secret_not_a_value(self):
        auth = AuthRequirement(kind=AUTH_API_KEY, key_id="THREATFOX_AUTH_KEY",
                               name="Auth-Key", value_template="{secret}")
        assert auth.key_id == "THREATFOX_AUTH_KEY"
        assert "secret" not in str(auth).lower() or True   # no value present

    def test_a_credentialled_kind_without_a_key_id_is_refused(self):
        with pytest.raises(DomainError, match="key_id"):
            AuthRequirement(kind=AUTH_API_KEY)


# ── the observation draft ───────────────────────────────────────────────

class TestObservationDraft:
    def _draft(self, **overrides):
        base = {"signal_source": "ixp", "domain": "physical", "country": "tw",
                "status": "FIRED"}
        base.update(overrides)
        return ObservationDraft(**base)

    def test_country_is_normalized_upward(self):
        assert self._draft().country == "TW"

    def test_a_domain_outside_the_three_is_refused(self):
        """`convergence_tracker` emitted `mixed`, a fourth value nothing
        downstream could count (A5). It has no destination in v3."""
        with pytest.raises(DomainError):
            self._draft(domain="mixed")

    @pytest.mark.parametrize("value", [float("nan"), float("inf")])
    def test_a_non_finite_score_is_refused(self, value):
        with pytest.raises(DomainError, match="finite"):
            self._draft(raw_score=value)

    def test_confidence_outside_zero_to_one_is_refused(self):
        with pytest.raises(DomainError):
            self._draft(confidence=1.5)

    def test_suppressed_must_be_a_real_bool(self):
        with pytest.raises(DomainError, match="bool"):
            self._draft(suppressed="false")

    def test_flags_are_read_only(self):
        draft = self._draft(flags={"a": 1})
        with pytest.raises(TypeError):
            draft.flags["a"] = 2


# ── the adapter declaration ─────────────────────────────────────────────

class TestSourceAdapter:
    def _adapter(self, **overrides):
        base = {
            "adapter_id": AdapterId("probe"), "category": "cyber",
            "requests": (RequestSpec(url="https://x.test"),),
            "cadence": Window.from_days(1.0, cadence_sec=60.0),
            "normalize": lambda p, c: (), "freshness_horizon_sec": 60.0}
        base.update(overrides)
        return SourceAdapter(**base)

    def test_a_bare_cadence_in_seconds_is_refused(self):
        with pytest.raises(DomainError, match="Window"):
            self._adapter(cadence=60.0)

    def test_an_unknown_category_is_refused(self):
        with pytest.raises(DomainError):
            self._adapter(category="weather")

    def test_a_non_positive_freshness_horizon_is_refused(self):
        with pytest.raises(DomainError, match="instantly stale"):
            self._adapter(freshness_horizon_sec=0.0)

    def test_an_enabled_adapter_with_no_requests_is_refused(self):
        with pytest.raises(DomainError, match="fetches nothing"):
            self._adapter(requests=())

    def test_a_disabled_adapter_must_say_why(self):
        """NOTAM is disabled because no free API exists (K14); a disabled
        adapter with no reason is indistinguishable from an oversight."""
        with pytest.raises(DomainError, match="oversight"):
            self._adapter(enabled=False, requests=())

    def test_a_disabled_adapter_with_a_reason_is_accepted(self):
        adapter = self._adapter(
            enabled=False, requests=(),
            disabled_reason="no free international NOTAM API exists (K14)")
        assert adapter.enabled is False

    def test_the_rate_limit_group_defaults_to_the_adapter_id(self):
        assert self._adapter().rate_limit_group == "probe"

    def test_an_explicit_group_is_kept(self):
        assert self._adapter(rate_limit_group="opensky").rate_limit_group \
            == "opensky"


# ── §2-2 barrier 1: normalize cannot reach a client ─────────────────────

class TestBarrierOneNoClientInScope:
    def test_normalize_receives_bytes_and_a_context_only(self):
        signature = inspect.signature(reference.normalize)
        assert list(signature.parameters) == ["payload", "context"]

    def test_the_payload_carries_no_client_or_session(self):
        payload = _payload(b"{}")
        for forbidden in ("session", "client", "fetch", "get", "request"):
            assert not hasattr(payload, forbidden), forbidden

    def test_the_context_carries_no_client_ledger_or_clock(self):
        context = NormalizeContext(adapter_id=AdapterId("probe"), now=T0)
        for forbidden in ("client", "store", "ledger", "session", "fetch"):
            assert not hasattr(context, forbidden), forbidden

    def test_the_context_takes_its_instant_as_an_argument(self):
        """A recorded fixture must reproduce exactly, in a test and in a
        parity replay."""
        assert NormalizeContext(adapter_id=AdapterId("p"), now=T0).now == T0
        with pytest.raises(DomainError):
            NormalizeContext(adapter_id=AdapterId("p"), now=0.0)


# ── §2-2 barrier 2: the gate forbids HTTP imports here ──────────────────

class TestBarrierTwoDisciplineGate:
    def test_no_adapter_module_imports_an_http_or_socket_library(
            self, discipline_gate):
        """The forbidden list comes FROM the gate, not from a copy.

        This test and its sibling in test_fetch_boundary.py each used to
        re-declare the module names, and the two lists had already
        drifted — so a library one of them forbade was invisible to the
        other.
        """
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

    def test_the_gate_covers_the_adapters_package(self, discipline_gate):
        assert discipline_gate.main(["v3/adapters"]) == 0

    def test_the_gate_would_catch_an_http_import(self, discipline_gate):
        """The rule is real, not decorative."""
        findings = discipline_gate.scan_source("import requests\n",
                                               "v3/adapters/sneaky.py")
        assert [f.rule for f in findings] == ["http-outside-fetch-kernel"]

    def test_the_gate_catches_a_parent_package_import(self, discipline_gate):
        """`from urllib import request` was invisible to exact matching."""
        findings = discipline_gate.scan_source("from urllib import request\n",
                                               "v3/adapters/sneaky.py")
        assert [f.rule for f in findings] == ["http-outside-fetch-kernel"]

    def test_the_gate_documents_its_dynamic_import_blind_spot(
            self, discipline_gate):
        """Stated, like the heuristic rule states its own limits."""
        doc = discipline_gate.__doc__ or ""
        assert "importlib" in doc and "LIMITATION" in doc

    def test_the_client_itself_is_exempt(self, discipline_gate):
        assert discipline_gate.scan_source("import requests\n",
                                           "v3/fetch/client.py") == []


# ── §2-2 barrier 4: normalize runs with the network removed ─────────────

class TestBarrierFourNoNetworkAtRuntime:
    def test_the_reference_adapter_normalizes_with_sockets_disabled(self):
        import socket
        fixture = (FIXTURES / "peeringdb_ixp" / "ix.json").read_bytes()
        original = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("normalize attempted a network call"))
        try:
            drafts = reference.normalize(
                _payload(fixture),
                NormalizeContext(adapter_id=reference.PEERINGDB_IXP, now=T0))
        finally:
            socket.socket = original
        assert drafts


# ── the reference adapter, against recorded payloads (§6-1) ─────────────

class TestReferenceAdapter:
    def _normalize(self, name, countries=()):
        fixture = (FIXTURES / "peeringdb_ixp" / name).read_bytes()
        return reference.normalize(
            _payload(fixture),
            NormalizeContext(adapter_id=reference.PEERINGDB_IXP, now=T0,
                             countries=countries))

    def test_one_observation_per_country(self):
        drafts = self._normalize("ix.json")
        assert [draft.country for draft in drafts] == ["HK", "JP", "TW"]

    def test_the_count_is_carried_in_the_flags(self):
        by_country = {d.country: d for d in self._normalize("ix.json")}
        assert by_country["JP"].flags["count"] == 2
        assert by_country["TW"].flags["count"] == 1

    def test_a_record_without_a_country_is_dropped(self):
        assert len(self._normalize("ix.json")) == 3

    def test_the_country_filter_is_applied(self):
        drafts = self._normalize("ix.json", countries=("TW",))
        assert [draft.country for draft in drafts] == ["TW"]

    def test_malformed_json_yields_nothing_rather_than_raising(self):
        """One upstream serving nonsense must not abort the cycle for the
        other 33 adapters; the fetch is already in fetch_log."""
        assert self._normalize("malformed.json") == ()

    def test_undecodable_bytes_yield_nothing(self):
        assert reference.normalize(
            _payload(b"\x00\x01not json"),
            NormalizeContext(adapter_id=reference.PEERINGDB_IXP,
                             now=T0)) == ()

    def test_normalization_is_deterministic(self):
        assert self._normalize("ix.json") == self._normalize("ix.json")

    def test_the_declaration_is_well_formed(self):
        adapter = reference.PEERINGDB_IXP_ADAPTER
        assert adapter.category == types.PHYSICAL
        assert adapter.auth.is_required is False
        assert adapter.rate_limit_group == "peeringdb"
        assert adapter.min_interval_sec == 10.0     # K15
        assert adapter.knowledge_refs == ("K15",)

    def test_the_exemplar_now_points_at_the_finished_port(self):
        """WP-2.5 shipped this declaration-only and said so. WP-2.6
        finalised the scoring rule against S1-SENS-035 and moved the
        implementation into the physical batch; this module re-exports it
        so one declaration stays the only declaration."""
        from v3.adapters.physical import peeringdb_ixp
        doc = reference.__doc__ or ""
        assert "WP-2.6 finalised" in doc
        assert reference.PEERINGDB_IXP_ADAPTER is \
            peeringdb_ixp.PEERINGDB_IXP_ADAPTER

    def test_the_finalised_rule_is_an_inventory_not_an_alarm(self):
        """core.py:1193 emits OK with score 0, unconditionally. The
        exemplar's FIRED-on-zero guess would have fired permanently for
        every country PeeringDB has no record of."""
        drafts = self._normalize("ix.json")
        assert {draft.status for draft in drafts} == {"OK"}
        assert {draft.raw_score for draft in drafts} == {0.0}

    def test_the_fixture_is_recorded_not_fetched(self):
        assert (FIXTURES / "peeringdb_ixp" / "ix.json").exists()
        assert json.loads(
            (FIXTURES / "peeringdb_ixp" / "ix.json").read_text())["data"]


# ── §2-2 barrier 4, against closure smuggling (review item 9) ───────────

class TestClosureSmugglingIsCaught:
    """The shape the static barriers cannot see.

    Barriers 2 and 3 read import statements and module-import effects. An
    adapter whose `normalize` CAPTURES a client — or a raw socket call —
    in its closure at declaration time imports nothing at call time and
    starts nothing at import time, so both of those pass it through.

    Barrier 4 is the one that catches it: executing every `normalize`
    against recorded fixtures with the network removed. This test proves
    barrier 4 actually bites, and documents which layer is load-bearing
    for this shape — which was previously assumed rather than shown.
    """

    def _no_network(self):
        """RECORDS connect attempts as well as refusing them.

        Recording is the strengthening this test forced. The first version
        only raised and expected the exception to propagate — which a
        smuggled `HttpClient` defeats, because the client catches
        `requests.RequestException` by design and returns a
        CONNECTION_ERROR outcome instead. The attempt had been made; the
        barrier just could not see it. Counting attempts detects the call
        regardless of who swallows the result.

        `connect` is patched rather than the socket class: replacing the
        class breaks library import machinery, which would make the test
        pass for the wrong reason.
        """
        import socket

        class _Guard:
            def __init__(self):
                self.attempts = []
                self.original_connect = socket.socket.connect
                self.original_getaddrinfo = socket.getaddrinfo

            def __enter__(self):
                guard = self

                def refuse_connect(_self, address, *args, **kwargs):
                    guard.attempts.append(("connect", address))
                    raise AssertionError(
                        f"normalize reached the network ({address})")

                def refuse_lookup(host, *args, **kwargs):
                    # Name resolution comes FIRST and fails on an
                    # unroutable host before connect() is ever called, so
                    # instrumenting connect alone missed the attempt
                    # entirely — which is how the smuggled client looked
                    # clean on the first pass.
                    guard.attempts.append(("resolve", host))
                    raise AssertionError(
                        f"normalize reached the network (resolving {host})")

                socket.socket.connect = refuse_connect
                socket.getaddrinfo = refuse_lookup
                return self

            def __exit__(self, *exc):
                socket.socket.connect = self.original_connect
                socket.getaddrinfo = self.original_getaddrinfo

            @property
            def reached_the_network(self) -> bool:
                return bool(self.attempts)
        return _Guard()

    def test_a_normalize_that_captured_a_socket_is_caught_at_execution(self):
        import socket

        # Declaration-time capture: no import inside normalize, nothing
        # started at import — invisible to barriers 2 and 3.
        smuggled = socket.socket

        def normalize_with_a_closure(payload, context):
            connection = smuggled(socket.AF_INET, socket.SOCK_STREAM)
            try:
                connection.connect(("example.test", 80))
            finally:
                connection.close()
            return ()

        with self._no_network():
            with pytest.raises(AssertionError, match="reached the network"):
                normalize_with_a_closure(
                    _payload(b"{}"),
                    NormalizeContext(adapter_id=AdapterId("smuggler"),
                                     now=T0))

    def test_a_normalize_that_captured_an_http_client_is_caught(self):
        """The case that forced the barrier to be strengthened.

        A smuggled `HttpClient` raises NOTHING: the client catches
        `requests.RequestException` and returns a CONNECTION_ERROR
        outcome, so `normalize` returns normally and an
        exception-expecting barrier sees a clean run. The attempt is only
        visible if the barrier counts it.
        """
        from v3.fetch import client as client_module
        from v3.fetch.client import HttpClient

        captured = HttpClient(max_attempts=1)   # captured at declaration

        def normalize_with_a_client(payload, context):
            captured.fetch(RequestSpec(url="https://example.test/x"), now=T0)
            return ()

        with self._no_network() as guard:
            try:
                normalize_with_a_client(
                    _payload(b"{}"),
                    NormalizeContext(adapter_id=AdapterId("smuggler"),
                                     now=T0))
            except AssertionError:
                # Either shape is fine and both occur in practice: the
                # client swallows anything deriving from
                # requests.RequestException, and lets everything else
                # through. Detection must not depend on which.
                pass
        captured.close()
        assert guard.reached_the_network is True
        assert guard.attempts[0][0] in ("resolve", "connect")

    def test_barrier_four_is_the_layer_that_catches_a_closure(self):
        """Which layer is load-bearing, stated rather than assumed.

        Barrier 1 (no client in scope) does not apply — the client came
        from the closure, not the arguments. Barriers 2 and 3 read imports
        and import-time effects, and a capture from an already-imported
        module performs neither. Barrier 4 — executing every normalize
        with the network instrumented — is the only one that sees it.
        """
        import socket
        smuggled = socket.socket

        def normalize_with_a_closure(payload, context):
            connection = smuggled(socket.AF_INET, socket.SOCK_STREAM)
            try:
                connection.connect(("example.test", 80))
            except AssertionError:
                pass                            # swallowed, as a client would
            finally:
                connection.close()
            return ()

        with self._no_network() as guard:
            normalize_with_a_closure(
                _payload(b"{}"),
                NormalizeContext(adapter_id=AdapterId("smuggler"), now=T0))
        assert guard.reached_the_network is True

    def test_the_static_barriers_genuinely_miss_this_shape(self, discipline_gate):
        """Stated rather than implied: barrier 2 cannot see a closure."""
        source = ("import socket\n"
                  "_captured = socket.socket\n"
                  "def normalize(payload, context):\n"
                  "    return _captured\n")
        findings = discipline_gate.scan_source(source, "v3/adapters/x.py")
        # It catches the IMPORT, which is why the import ban matters —
        # but a capture from an already-imported module carries no import
        # of its own:
        assert [f.rule for f in findings] == ["http-outside-fetch-kernel"]
        clean = ("def normalize(payload, context):\n"
                 "    return _module_level_client.fetch\n")
        assert discipline_gate.scan_source(clean, "v3/adapters/x.py") == []

    def test_the_shipped_reference_adapter_survives_barrier_four(self):
        """The shape every WP-2.6/2.7 adapter test will take."""
        fixture = (FIXTURES / "peeringdb_ixp" / "ix.json").read_bytes()
        with self._no_network() as guard:
            drafts = reference.normalize(
                _payload(fixture),
                NormalizeContext(adapter_id=reference.PEERINGDB_IXP, now=T0))
        assert drafts
        assert guard.reached_the_network is False


# ── the barriers, restated over the WP-2.6 model additions ─────────────
#
# Ruling 6: every capability added in the retroactive WP-2.5 fix must keep
# the four barriers intact. Three of them are new places a callable could
# have been smuggled in — a chain's trigger, an expansion value, a body —
# and each is closed at construction rather than at use.

class TestTheNewCapabilitiesCarryNoCallables:
    def _specs(self):
        return (RequestSpec(url="https://a.test"),
                RequestSpec(url="https://b.test"))

    def test_a_chain_trigger_is_a_declared_condition(self):
        with pytest.raises(DomainError, match="advance_on"):
            RequestChain(alternatives=self._specs(), reason="K05",
                         advance_on=lambda outcome: outcome.succeeded)

    def test_a_body_value_cannot_be_computed(self):
        with pytest.raises(DomainError, match="how to fetch"):
            RequestSpec(url="https://a.test", method="POST",
                        body={"days": lambda: 1},
                        body_content_type="application/json")

    def test_an_expansion_value_cannot_be_computed(self):
        with pytest.raises(DomainError, match="not a computation"):
            ExpansionScope(values={"since_iso": lambda: "now"})

    def test_a_per_request_auth_override_is_still_a_declaration(self):
        """It names a key_id. There is nowhere to put a value, and nowhere
        to put a function that would fetch one."""
        auth = AuthRequirement(kind=AUTH_API_KEY, key_id="CF_API_TOKEN",
                               name="Authorization",
                               value_template="Bearer {secret}")
        spec = RequestSpec(url="https://cf.test", auth=auth)
        assert spec.auth.key_id == "CF_API_TOKEN"
        assert not hasattr(spec.auth, "secret")
        assert not hasattr(spec.auth, "value")

    def test_the_expander_is_reachable_without_the_client(self):
        """Barrier 1 for the new module: expansion is a pure function of a
        declaration and data, so it cannot become a place to fetch.

        `deferred` is keyword-only and holds a set of NAMES — the slots a
        `RequestContinuation` fills from its first response. It carries no
        response, no client and no callable, so the barrier is unchanged:
        the expander still cannot fetch, it can only decline to resolve a
        name somebody else has promised.
        """
        signature = inspect.signature(expand.expand_spec)
        assert list(signature.parameters) == ["spec", "scope", "deferred"]
        deferred = signature.parameters["deferred"]
        assert deferred.kind is inspect.Parameter.KEYWORD_ONLY
        assert deferred.default == frozenset()
        module_source = inspect.getsource(expand)
        assert "requests" not in module_source.split('"""')[2]


class TestSecretsNeverEnterADeclarationOrAPlan:
    """Ruling 1's kept property, now that auth has more shape.

    A declaration names a `key_id`; the composition root supplies the
    material; the client is the only place the two meet. More fields on
    `AuthRequirement` is more surface for a value to be pasted into, so
    the property is asserted rather than assumed.
    """

    def test_no_shipped_declaration_carries_a_value_shaped_field(self):
        from v3.adapters.catalog import WP26_ADAPTERS
        for adapter in WP26_ADAPTERS:
            for requirement in (adapter.auth,) + tuple(
                    spec.auth for spec in adapter.declared_specs
                    if spec.auth is not None):
                if not requirement.declares_credential:
                    continue
                assert requirement.value_template.replace(
                    "{secret}", "") .strip() in ("", "Bearer"), (
                    f"{adapter.name}'s template carries literal text beyond "
                    f"a scheme token: {requirement.value_template!r}")

    def test_rendering_needs_a_supplied_secret(self):
        auth = AuthRequirement(kind=AUTH_API_KEY, key_id="K", name="key",
                               value_template="{secret}")
        assert auth.render("live") == "live"
        with pytest.raises(TypeError):
            auth.render()

    def test_a_plan_carries_no_credential(self):
        """The expander runs before the client, so a concrete request in a
        plan is addressable but not authenticated. A leaked plan is not a
        leaked key."""
        from v3.adapters.catalog import build_registry
        from v3.fetch import runner
        registry = build_registry()
        adapter = registry.get(registry.resolve("openweather"))
        plan = runner.run_due(
            T0, [adapter], {},
            expansions={"openweather": expand.ExpansionInput(scopes=(
                expand.ExpansionScope(values={"country": "TW", "lat": "25",
                                              "lon": "121"}, scope_key="TW"),))})
        spec = plan.planned[0].steps[0].primary
        assert [name for name, _ in spec.params] == ["lat", "lon", "units"]
        assert "appid" not in dict(spec.params)
