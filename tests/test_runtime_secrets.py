"""WP-4.1 — credential injection, and the visibility of anonymous running.

Two properties, both of which production got wrong at some point:

  * an adapter never sees a secret. It declares `key_id` / `placement` /
    `name` / `value_template`; the composition root supplies material and
    `HttpClient` renders it. The registry is the source of truth for WHICH
    keys exist, so a hardcoded inventory cannot drift out of step.
  * absence of an OPTIONAL credential is not failure — production ships
    OpenSky anonymous at 400 req/day and CertSpotter tokenless, and
    declaring those mandatory took three physical sensors dark — but it is
    also not silence. A source running at a reduced quota fails by
    returning LESS, which under NP1 is the worst failure mode there is, so
    the material cannot be obtained without the account of what it misses.
"""
import pytest

from v3.adapters.catalog import build_registry
from v3.adapters.types import (AUTH_API_KEY, AdapterId, AuthRequirement,
                               RequestSpec, SourceAdapter)
from v3.kernel.errors import DomainError
from v3.kernel.window import Window
from v3.runtime import secrets


def _adapter(name: str, auth: AuthRequirement) -> SourceAdapter:
    return SourceAdapter(
        adapter_id=AdapterId(name), category="cyber",
        cadence=Window.from_days(1.0, cadence_sec=300.0),
        requests=(RequestSpec(url="https://example.test/x"),),
        normalize=lambda payload, context: (),
        auth=auth, freshness_horizon_sec=3600.0)


REQUIRED = AuthRequirement(kind=AUTH_API_KEY, key_id="NEEDED_KEY",
                           name="Auth-Key", value_template="{secret}")
OPTIONAL = AuthRequirement(kind=AUTH_API_KEY, key_id="NICE_KEY",
                           name="Auth-Key", value_template="{secret}",
                           optional=True, note="free tier works tokenless")


class TestTheKeyInventoryIsDerived:
    def test_it_comes_from_the_adapters_not_from_a_list(self):
        registry = build_registry()
        derived = secrets.required_key_ids(registry.all())
        assert set(derived) == set(registry.required_key_ids()) | set(
            registry.optional_key_ids())

    def test_the_real_registry_declares_the_five_known_keys(self):
        # GREYNOISE_API_KEY left the inventory with its adapter
        # (2026-08-13): GNQL v2 is 410 Gone, so no key of any tier can
        # reach it, and inventorying it told the operator a key was
        # wanted that no request could ever spend.
        registry = build_registry()
        assert secrets.required_key_ids(registry.all()) == (
            "CERTSPOTTER_API_TOKEN", "CF_API_TOKEN",
            "OPENSKY_CLIENT_CREDENTIALS", "OWM_API_KEY", "THREATFOX_API_KEY")


class TestResolutionSaysWhatWillHappen:
    def test_supplied_material_is_authenticated(self):
        plan = secrets.resolve([_adapter("a", REQUIRED)],
                               {"NEEDED_KEY": "value"})
        assert plan.mode_for("a") == secrets.AUTHENTICATED
        assert plan.material["NEEDED_KEY"] == "value"
        assert plan.is_fully_credentialled

    def test_a_missing_optional_credential_means_anonymous_not_failure(self):
        plan = secrets.resolve([_adapter("b", OPTIONAL)], {})
        assert plan.mode_for("b") == secrets.ANONYMOUS
        assert [p.adapter_id for p in plan.anonymous] == ["b"]
        assert plan.unsatisfied == ()

    def test_a_missing_required_credential_is_named_before_the_cycle(self):
        """Known up front, not reconstructed from fetch_log afterwards."""
        plan = secrets.resolve([_adapter("c", REQUIRED)], {})
        assert plan.mode_for("c") == secrets.UNSATISFIED
        assert [p.adapter_id for p in plan.unsatisfied] == ["c"]

    def test_an_adapter_declaring_nothing_is_not_reported_as_degraded(self):
        plan = secrets.resolve([_adapter("d", AuthRequirement())], {})
        assert plan.postures == ()
        assert plan.is_fully_credentialled
        assert plan.mode_for("d") == secrets.AUTHENTICATED

    def test_an_empty_string_counts_as_absent(self):
        """A key set to '' is what a half-finished deploy leaves behind;
        rendering `Auth-Key: ` is a request the source answers with
        nothing, which this layer would read as 'no data'."""
        plan = secrets.resolve([_adapter("e", OPTIONAL)],
                               {"NICE_KEY": "   "})
        assert plan.mode_for("e") == secrets.ANONYMOUS
        assert "NICE_KEY" not in plan.material

    def test_a_per_request_credential_is_seen_too(self):
        """`ioda_bgp`'s fallback needs Cloudflare's token while its
        primary needs none — a posture built from `adapter.auth` alone
        would report that adapter as needing nothing."""
        adapter = SourceAdapter(
            adapter_id=AdapterId("ioda_like"), category="cyber",
            cadence=Window.from_days(1.0, cadence_sec=300.0),
            requests=(RequestSpec(url="https://a.test/x"),
                      RequestSpec(url="https://b.test/x", auth=REQUIRED)),
            normalize=lambda payload, context: (),
            freshness_horizon_sec=3600.0)
        plan = secrets.resolve([adapter], {})
        assert plan.mode_for("ioda_like") == secrets.UNSATISFIED


class TestTheDisclosureNeverCarriesASecret:
    def test_as_dict_names_keys_never_values(self):
        plan = secrets.resolve([_adapter("a", REQUIRED)],
                               {"NEEDED_KEY": "s3cret"})
        rendered = repr(plan.as_dict())
        assert "NEEDED_KEY" in rendered and "s3cret" not in rendered

    def test_the_announcement_says_what_anonymity_costs(self):
        plan = secrets.resolve([_adapter("b", OPTIONAL)], {})
        assert plan.announcement() == (
            "b: running ANONYMOUSLY — no NICE_KEY supplied. "
            "free tier works tokenless",)

    def test_the_announcement_says_a_required_key_stops_the_fetch(self):
        plan = secrets.resolve([_adapter("c", REQUIRED)], {})
        assert plan.announcement() == (
            "c: NO FETCH — required credential NEEDED_KEY was not "
            "supplied; every request will return auth_missing before the "
            "socket opens.",)

    def test_a_fully_credentialled_run_announces_nothing(self):
        plan = secrets.resolve([_adapter("a", REQUIRED)],
                               {"NEEDED_KEY": "value"})
        assert plan.announcement() == ()

    def test_material_and_postures_travel_together(self):
        """Structural, not a convention: there is no way to obtain the
        keys without also obtaining the list of sources they do not
        cover."""
        import dataclasses
        fields = {f.name for f in dataclasses.fields(secrets.CredentialPlan)}
        assert fields == {"material", "postures"}


class TestTheEnvironmentReadIsNarrow:
    def test_it_reads_only_the_keys_the_adapters_declare(self, monkeypatch):
        monkeypatch.setenv("NEEDED_KEY", "value")
        monkeypatch.setenv("UNRELATED_SECRET", "should-not-be-read")
        found = secrets.from_environment(["NEEDED_KEY"])
        assert dict(found) == {"NEEDED_KEY": "value"}

    def test_a_bare_string_is_refused(self):
        with pytest.raises(DomainError, match="sequence of key ids"):
            secrets.from_environment("NEEDED_KEY")

    def test_whitespace_only_values_are_absent(self, monkeypatch):
        monkeypatch.setenv("NEEDED_KEY", "  ")
        assert dict(secrets.from_environment(["NEEDED_KEY"])) == {}

    def test_resolve_with_no_source_reads_the_environment(self, monkeypatch):
        monkeypatch.setenv("NEEDED_KEY", "from-env")
        plan = secrets.resolve([_adapter("a", REQUIRED)])
        assert plan.material["NEEDED_KEY"] == "from-env"


class TestPostureValidation:
    def test_an_unknown_mode_is_refused(self):
        with pytest.raises(DomainError, match="unknown credential mode"):
            secrets.CredentialPosture(adapter_id="a", key_id="K",
                                      mode="probably_fine")

    @pytest.mark.parametrize("field", ["adapter_id", "key_id"])
    def test_empty_identity_is_refused(self, field):
        kwargs = {"adapter_id": "a", "key_id": "K",
                  "mode": secrets.AUTHENTICATED, field: "  "}
        with pytest.raises(DomainError, match="must be non-empty"):
            secrets.CredentialPosture(**kwargs)
