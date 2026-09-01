"""WP-2.5 (retroactive) — what the declaration model must be able to SAY.

The WP-2.6 fidelity sweep found 97 infidelities across the 22 ported
adapters and traced a large share of them not to the adapters but to
**this model**: eight adapters could not issue their production request at
all, and would have failed silently in the direction that reads as calm.

Each class below pins one of those gaps shut. The tests are written
against the model rather than against an adapter on purpose — an adapter
can be fixed one at a time, but a model that cannot express a shape makes
every adapter that needs it wrong at once, which is how one defect became
eight.
"""
import json

import pytest

from v3.adapters.types import (AUTH_API_KEY, AUTH_IN_HEADER, AUTH_IN_QUERY,
                               AUTH_NONE, AUTH_OAUTH2,
                               FALLBACK_ON_FAILURE,
                               FALLBACK_ON_FAILURE_OR_EMPTY, AdapterId,
                               AuthRequirement, RequestChain,
                               RequestContinuation, RequestSpec,
                               ResponseValue, SourceAdapter, ObservationDraft)
from v3.kernel import Window
from v3.kernel.errors import DomainError

T0 = 1_700_000_000.0


def _adapter(**overrides):
    base = {
        "adapter_id": AdapterId("reference"), "category": "cyber",
        "requests": (RequestSpec(url="https://x.test"),),
        "cadence": Window.from_days(1.0, cadence_sec=60.0),
        "normalize": lambda payload, context: (),
        "freshness_horizon_sec": 60.0}
    base.update(overrides)
    return SourceAdapter(**base)


# ── ruling 1: auth has a placement, a name, and may be optional ─────────

class TestAuthPlacementIsDeclaredNotAssumed:
    """`client.py` hard-coded `{"Auth-Key": secret}` for every adapter.

    That header is correct for exactly one source (abuse.ch). Cloudflare
    needs `Authorization: Bearer`, GreyNoise's header is literally `key`,
    and OpenWeather does not take a header at all — the key is the query
    parameter `appid`. Three sources were therefore sending a credential
    no server would read, which returns 401/403, which the adapter reads
    as "no data", which reads as a quiet day.
    """

    def test_a_credential_must_name_the_header_it_travels_in(self):
        with pytest.raises(DomainError, match="name"):
            AuthRequirement(kind=AUTH_API_KEY, key_id="K",
                            value_template="{secret}")

    def test_a_credential_must_declare_how_its_value_is_written(self):
        with pytest.raises(DomainError, match="value_template"):
            AuthRequirement(kind=AUTH_API_KEY, key_id="K", name="Auth-Key")

    def test_a_value_template_without_the_secret_slot_is_refused(self):
        with pytest.raises(DomainError, match=r"\{secret\}"):
            AuthRequirement(kind=AUTH_API_KEY, key_id="K", name="Auth-Key",
                            value_template="Bearer abc")

    def test_a_value_template_with_two_secret_slots_is_refused(self):
        with pytest.raises(DomainError, match="once"):
            AuthRequirement(kind=AUTH_API_KEY, key_id="K", name="X",
                            value_template="{secret}{secret}")

    def test_a_header_placement_is_expressible(self):
        auth = AuthRequirement(kind=AUTH_API_KEY, key_id="K", name="key",
                               value_template="{secret}")
        assert auth.placement == AUTH_IN_HEADER
        assert auth.in_header is True and auth.in_query is False

    def test_a_bearer_template_is_expressible(self):
        auth = AuthRequirement(kind=AUTH_OAUTH2, key_id="K",
                               name="Authorization",
                               value_template="Bearer {secret}")
        assert auth.render("tok") == "Bearer tok"

    def test_a_query_parameter_placement_is_expressible(self):
        auth = AuthRequirement(kind=AUTH_API_KEY, key_id="K",
                               placement=AUTH_IN_QUERY, name="appid",
                               value_template="{secret}")
        assert auth.in_query is True and auth.in_header is False

    def test_an_unknown_placement_is_refused(self):
        with pytest.raises(DomainError, match="placement"):
            AuthRequirement(kind=AUTH_API_KEY, key_id="K", name="x",
                            value_template="{secret}", placement="cookie")

    def test_the_declaration_still_never_holds_the_value(self):
        auth = AuthRequirement(kind=AUTH_API_KEY, key_id="OWM_API_KEY",
                               placement=AUTH_IN_QUERY, name="appid",
                               value_template="{secret}")
        assert "OWM_API_KEY" in repr(auth)
        assert auth.key_id == "OWM_API_KEY"
        # The only way to obtain a value is to be handed one.
        assert auth.render("live-key") == "live-key"


class TestOptionalCredentials:
    """Three physical sensors went dark because the model could not say
    "optional".

    `opensky` runs ANONYMOUS in production — `config.env.example` ships
    `OPENSKY_CLIENT_ID=` empty and `opensky_auth.py` logs "running in
    anonymous mode (400 req/day limit)" and sends no header. `ct_log`'s
    CertSpotter token and `threatfox`'s Auth-Key are likewise `if key:`
    guards. Declared mandatory, all three abort with AUTH_MISSING before
    the socket opens.
    """

    def test_a_credential_can_be_declared_optional(self):
        auth = AuthRequirement(kind=AUTH_OAUTH2, key_id="K",
                               name="Authorization",
                               value_template="Bearer {secret}",
                               optional=True)
        assert auth.declares_credential is True
        assert auth.is_required is False

    def test_a_mandatory_credential_is_still_required(self):
        auth = AuthRequirement(kind=AUTH_API_KEY, key_id="K", name="Auth-Key",
                               value_template="{secret}")
        assert auth.declares_credential is True
        assert auth.is_required is True

    def test_optionality_without_a_credential_is_refused(self):
        """"An absent credential is fine" is a lie where none is declared."""
        with pytest.raises(DomainError, match="optional"):
            AuthRequirement(kind=AUTH_NONE, optional=True)

    def test_the_default_is_still_no_auth(self):
        assert AuthRequirement().declares_credential is False
        assert AuthRequirement().is_required is False


# ── ruling 2: bodies and repeated parameters ────────────────────────────

class TestRepeatedParameters:
    """`node[]` five times, `expand` twice. A mapping can hold neither.

    `check_host` sends `node[]` once per node (JP/US/DE/NL/FR);
    `ct_log`'s CertSpotter call sends `expand=dns_names` AND
    `expand=issuer`. Without `issuer` every certificate parses to
    `unknown` and is dropped, so the adapter is permanently silent — the
    exact shape of failure NP1 exists to forbid.
    """

    def test_the_same_name_may_appear_more_than_once(self):
        spec = RequestSpec(url="https://x.test",
                           params=(("expand", "dns_names"),
                                   ("expand", "issuer")))
        assert spec.param_values("expand") == ("dns_names", "issuer")

    def test_five_repeats_survive(self):
        nodes = ("jp1", "us1", "de1", "nl1", "fr1")
        spec = RequestSpec(url="https://x.test",
                           params=tuple(("node[]", n) for n in nodes))
        assert spec.param_values("node[]") == nodes

    def test_order_is_preserved_exactly_as_declared(self):
        spec = RequestSpec(url="https://x.test",
                           params=(("b", "2"), ("a", "1"), ("b", "3")))
        assert spec.params == (("b", "2"), ("a", "1"), ("b", "3"))

    def test_a_mapping_is_refused_and_says_why(self):
        """A mapping silently keeps one value per name. Say so at the line
        where it is written, not at the socket where it is invisible."""
        with pytest.raises(DomainError, match="pairs"):
            RequestSpec(url="https://x.test", params={"expand": "dns_names"})

    def test_params_are_immutable(self):
        spec = RequestSpec(url="https://x.test", params=(("a", "1"),))
        assert isinstance(spec.params, tuple)
        with pytest.raises(TypeError):
            spec.params[0] = ("a", "2")

    def test_a_callable_value_is_still_refused(self):
        with pytest.raises(DomainError, match="how to fetch"):
            RequestSpec(url="https://x.test", params=(("t", lambda: "now"),))

    def test_a_malformed_pair_is_refused(self):
        with pytest.raises(DomainError, match="pair"):
            RequestSpec(url="https://x.test", params=(("a", "1", "2"),))


class TestJsonBody:
    """ThreatFox posts a JSON body in production; the port sent a query
    string.

    `radar/sensors/threatfox.py:42` is `requests.post(url, json=payload)`
    with `{"query": "get_iocs", "days": 1}`. abuse.ch answers a query
    string with an error, and an error that keeps the previous cache
    looks exactly like a quiet day (K10).
    """

    def test_a_json_body_is_expressible(self):
        spec = RequestSpec(url="https://x.test", method="POST",
                           body={"query": "get_iocs", "days": 1},
                           body_content_type="application/json")
        assert spec.body["query"] == "get_iocs"
        assert json.loads(spec.body_bytes().decode()) == {
            "query": "get_iocs", "days": 1}

    def test_a_body_on_a_get_is_refused(self):
        with pytest.raises(DomainError, match="POST"):
            RequestSpec(url="https://x.test",
                        body={"a": 1}, body_content_type="application/json")

    def test_a_body_must_declare_its_content_type(self):
        with pytest.raises(DomainError, match="body_content_type"):
            RequestSpec(url="https://x.test", method="POST", body={"a": 1})

    def test_a_content_type_without_a_body_is_refused(self):
        with pytest.raises(DomainError, match="no body"):
            RequestSpec(url="https://x.test", method="POST",
                        body_content_type="application/json")

    def test_a_non_json_body_content_type_is_refused(self):
        with pytest.raises(DomainError, match="json"):
            RequestSpec(url="https://x.test", method="POST", body={"a": 1},
                        body_content_type="application/x-www-form-urlencoded")

    def test_a_content_type_header_beside_a_body_is_refused(self):
        """One declaration of the wire's content type, not two that drift."""
        with pytest.raises(DomainError, match="Content-Type"):
            RequestSpec(url="https://x.test", method="POST", body={"a": 1},
                        body_content_type="application/json",
                        headers={"Content-Type": "application/json"})

    def test_a_callable_inside_the_body_is_refused(self):
        with pytest.raises(DomainError, match="how to fetch"):
            RequestSpec(url="https://x.test", method="POST",
                        body={"t": lambda: 1},
                        body_content_type="application/json")

    def test_a_body_is_immutable(self):
        spec = RequestSpec(url="https://x.test", method="POST",
                           body={"a": 1}, body_content_type="application/json")
        with pytest.raises(TypeError):
            spec.body["a"] = 2

    def test_no_body_means_no_bytes(self):
        assert RequestSpec(url="https://x.test").body_bytes() is None


# ── ruling 3: declarative fallback chains ───────────────────────────────

class TestRequestChain:
    """K05 and ioda_bgp fetch a SECOND source only when the first fails.

    v3's runner fetched every declared spec unconditionally, which for
    `ioda_bgp` let a Cloudflare traffic anomaly FIRED-override IODA's OK.
    That is a structural difference in the sensitive direction, produced
    by the model's inability to say "only if".
    """

    def _spec(self, name):
        return RequestSpec(url=f"https://{name}.test", label=name)

    def _chain(self, **overrides):
        base = {"alternatives": (self._spec("a"), self._spec("b")),
                "reason": "K19: IODA first, Cloudflare only on failure"}
        base.update(overrides)
        return RequestChain(**base)

    def test_a_chain_declares_alternatives_in_order(self):
        assert [s.label for s in self._chain().alternatives] == ["a", "b"]

    def test_the_default_trigger_is_failure(self):
        assert self._chain().advance_on == FALLBACK_ON_FAILURE

    def test_an_empty_body_trigger_is_expressible(self):
        chain = self._chain(advance_on=FALLBACK_ON_FAILURE_OR_EMPTY)
        assert chain.advance_on == FALLBACK_ON_FAILURE_OR_EMPTY

    def test_an_unknown_trigger_is_refused(self):
        with pytest.raises(DomainError, match="advance_on"):
            self._chain(advance_on="whenever")

    def test_a_chain_of_one_is_refused(self):
        """A single-alternative chain is a plain spec wearing a costume."""
        with pytest.raises(DomainError, match="two"):
            self._chain(alternatives=(self._spec("a"),))

    def test_a_chain_must_hold_request_specs(self):
        with pytest.raises(DomainError, match="RequestSpec"):
            self._chain(alternatives=(self._spec("a"), "https://b.test"))

    def test_an_adapter_may_declare_a_chain_beside_a_plain_spec(self):
        adapter = _adapter(requests=(self._spec("always"), self._chain()))
        assert len(adapter.requests) == 2

    def test_a_chain_must_say_why_a_fallback_exists(self):
        """A fallback with no stated cause is indistinguishable from a
        second source someone forgot to delete."""
        with pytest.raises(DomainError, match="reason"):
            self._chain(reason="")

    def test_declared_specs_are_still_reachable_flat(self):
        adapter = _adapter(requests=(self._spec("always"), self._chain()))
        assert [s.label for s in adapter.declared_specs] == [
            "always", "a", "b"]


# ── ruling 6 (WP-2.6 remediation): "A then B(A)" ────────────────────────

class TestRequestContinuation:
    """A chain says "A **or** B". `check_host` needs "A **then** B(A)".

    `radar/sensors/checkhost.py:60-72`: the first request answers with a
    `request_id`, the sensor sleeps five seconds, and the measurement is
    read from `check-result/{request_id}`. Expressed as two independent
    requests, the second had no address at plan time, so `run_due` skipped
    the whole adapter as `unresolved_placeholder` — every cycle, with a
    recorded reason nobody read. The gap was structural, not clerical: no
    arrangement of `RequestSpec` and `RequestChain` can say it.
    """

    def _first(self):
        return RequestSpec(url="https://check-host.test/check-http",
                           label="request")

    def _then(self):
        return RequestSpec(url="https://check-host.test/result/{request_id}",
                           label="result")

    def _continuation(self, **overrides):
        base = {"first": self._first(), "then": self._then(),
                "carries": (ResponseValue(placeholder="request_id",
                                          path=("request_id",)),),
                "delay_sec": 5.0,
                "reason": "K03: the measurement exists only behind the "
                          "handle the first call returns"}
        base.update(overrides)
        return RequestContinuation(**base)

    def test_it_declares_which_field_carries_the_handle(self):
        carried, = self._continuation().carries
        assert carried.placeholder == "request_id"
        assert carried.path == ("request_id",)
        assert carried.slot == "{request_id}"

    def test_it_declares_how_long_rather_than_sleeping(self):
        """The adapter says HOW LONG; `HttpClient.pause` decides HOW."""
        assert self._continuation().delay_sec == 5.0

    def test_a_negative_delay_is_refused(self):
        with pytest.raises(DomainError, match="delay_sec"):
            self._continuation(delay_sec=-1.0)

    def test_it_is_not_a_chain(self):
        """The difference is whether the second request runs on SUCCESS or
        on FAILURE, and conflating them inverts it."""
        assert not isinstance(self._continuation(), RequestChain)

    def test_carrying_nothing_is_refused(self):
        with pytest.raises(DomainError, match="at least one"):
            self._continuation(carries=())

    def test_carrying_a_value_the_second_request_never_uses_is_refused(self):
        """An extraction nobody consumes reads as a working handshake."""
        with pytest.raises(DomainError, match="never writes"):
            self._continuation(carries=(ResponseValue(placeholder="token",
                                                      path=("token",)),))

    def test_the_same_slot_twice_is_refused(self):
        value = ResponseValue(placeholder="request_id", path=("request_id",))
        other = ResponseValue(placeholder="request_id", path=("id",))
        with pytest.raises(DomainError, match="twice"):
            self._continuation(carries=(value, other))

    def test_it_must_say_why_a_second_request_exists(self):
        with pytest.raises(DomainError, match="why the second request"):
            self._continuation(reason="")

    def test_an_extraction_path_is_data_not_a_lookup_function(self):
        """A callable here is `normalize`'s job smuggled into the
        declaration, and with it a second way to reach the network."""
        with pytest.raises(DomainError, match="callable"):
            ResponseValue(placeholder="request_id",
                          path=(lambda document: document["request_id"],))

    def test_an_extraction_with_no_path_is_refused(self):
        with pytest.raises(DomainError, match="no path"):
            ResponseValue(placeholder="request_id", path=())

    def test_an_adapter_may_declare_one(self):
        adapter = _adapter(requests=(self._continuation(),))
        assert [s.label for s in adapter.declared_specs] == \
            ["request", "result"]


# ── ruling 5: a draft carries its reason ────────────────────────────────

class TestObservationDraftReason:
    """`fired_reason` had nowhere to go, so `check_host` improvised into
    `flags`."""

    def _draft(self, **overrides):
        base = {"signal_source": "ixp", "domain": "physical", "country": "tw",
                "status": "FIRED"}
        base.update(overrides)
        return ObservationDraft(**base)

    def test_a_draft_carries_its_reason(self):
        draft = self._draft(reason="BGP anomaly confirmed")
        assert draft.reason == "BGP anomaly confirmed"

    def test_the_default_is_empty_not_none(self):
        assert self._draft().reason == ""

    def test_a_non_string_reason_is_refused(self):
        with pytest.raises(DomainError, match="reason"):
            self._draft(reason=42)

    def test_whitespace_is_stripped(self):
        assert self._draft(reason="  why  ").reason == "why"


# ── the model still refuses "how to fetch" ──────────────────────────────

class TestTheModelStillCannotExpressHowToFetch:
    """Everything above adds WHAT. None of it adds HOW."""

    @pytest.mark.parametrize("field_name", [
        "timeout", "timeout_sec", "retries", "max_attempts", "parser",
        "circuit_breaker", "session", "client", "on_error", "sink"])
    def test_no_new_field_names_a_fetch_mechanism(self, field_name):
        assert field_name not in RequestSpec.__dataclass_fields__
        assert field_name not in RequestChain.__dataclass_fields__
        assert field_name not in SourceAdapter.__dataclass_fields__

    def test_a_chain_cannot_carry_a_callable_decision(self):
        """"Try B when f(outcome)" would be a fetch policy in an adapter."""
        with pytest.raises(DomainError, match="advance_on"):
            RequestChain(alternatives=(RequestSpec(url="https://a.test"),
                                       RequestSpec(url="https://b.test")),
                         reason="K05", advance_on=lambda outcome: True)
