"""WP-2.5 (retroactive) — the placeholder expander (ruling 4).

Before this module existed, `{country}`, `{lat}` and `{since_iso}` went on
the wire **literally**. Six adapters declared such templates and nothing
under `v3/fetch` ever substituted them: `ripe_bgp` would have asked RIPE
about the resource named `{country}`, `usgs_seismic` would have asked for
quakes since the string `{since_iso}`. K02 records that AISHub answers a
rejected request with HTTP 200 and an empty body — so the failure would
have been recorded as a successful fetch that found nothing.

The expander lives in the fetch kernel, not the composition root, for the
same reason the client does: a substitution performed by each caller is a
substitution each caller can get wrong, and getting it wrong is silent.

§3-5 H-1 — ISR hotspots are N named zones per country — is the shape this
must carry: ONE declared spec expanding to N concrete requests.
"""
import pytest

from v3.adapters.types import RequestChain, RequestSpec
from v3.fetch import expand
from v3.fetch.expand import ExpansionInput, ExpansionScope
from v3.kernel.errors import DomainError


def _scope(key, **values):
    return ExpansionScope(scope_key=key, values=values)


# ── what a template says ────────────────────────────────────────────────

class TestPlaceholderDiscovery:
    def test_placeholders_are_found_in_the_url(self):
        spec = RequestSpec(url="https://x.test/check-result/{request_id}")
        assert expand.placeholders_in(spec) == frozenset({"request_id"})

    def test_placeholders_are_found_in_parameter_values(self):
        spec = RequestSpec(url="https://x.test",
                           params=(("resource", "{country}"),))
        assert expand.placeholders_in(spec) == frozenset({"country"})

    def test_placeholders_are_found_in_headers_and_labels(self):
        spec = RequestSpec(url="https://x.test", label="weather:{country}",
                           headers={"X-Zone": "{zone}"})
        assert expand.placeholders_in(spec) == frozenset({"country", "zone"})

    def test_placeholders_are_found_inside_a_json_body(self):
        spec = RequestSpec(url="https://x.test", method="POST",
                           body={"query": "get_iocs", "cc": "{country}"},
                           body_content_type="application/json")
        assert expand.placeholders_in(spec) == frozenset({"country"})

    def test_a_spec_with_no_template_reports_none(self):
        assert expand.placeholders_in(
            RequestSpec(url="https://x.test")) == frozenset()

    def test_an_escaped_brace_is_not_a_placeholder(self):
        spec = RequestSpec(url="https://x.test", params=(("q", "{{literal}}"),))
        assert expand.placeholders_in(spec) == frozenset()


# ── substitution ────────────────────────────────────────────────────────

class TestExpandSpec:
    def test_a_url_placeholder_is_substituted(self):
        spec = RequestSpec(url="https://x.test/{country}/routing")
        out = expand.expand_spec(spec, _scope("TW", country="TW"))
        assert out.url == "https://x.test/TW/routing"

    def test_parameter_values_are_substituted_in_order(self):
        spec = RequestSpec(url="https://x.test",
                           params=(("lat", "{lat}"), ("lon", "{lon}"),
                                   ("units", "metric")))
        out = expand.expand_spec(spec, _scope("TW", lat="25.0", lon="121.5"))
        assert out.params == (("lat", "25.0"), ("lon", "121.5"),
                              ("units", "metric"))

    def test_repeated_parameters_survive_expansion(self):
        spec = RequestSpec(url="https://x.test",
                           params=(("expand", "dns_names"),
                                   ("expand", "issuer"),
                                   ("domain", "{domain}")))
        out = expand.expand_spec(spec, _scope("gov.tw", domain="gov.tw"))
        assert out.params == (("expand", "dns_names"), ("expand", "issuer"),
                              ("domain", "gov.tw"))

    def test_a_body_is_substituted(self):
        spec = RequestSpec(url="https://x.test", method="POST",
                           body={"query": "get_iocs", "cc": "{country}"},
                           body_content_type="application/json")
        out = expand.expand_spec(spec, _scope("TW", country="TW"))
        assert out.body["cc"] == "TW"

    def test_the_label_is_substituted_so_normalize_can_read_it(self):
        spec = RequestSpec(url="https://x.test", label="isr:{country}:{zone}")
        out = expand.expand_spec(spec, _scope("z", country="TW",
                                              zone="strait_midline"))
        assert out.label == "isr:TW:strait_midline"

    def test_an_escaped_brace_becomes_a_literal_brace(self):
        spec = RequestSpec(url="https://x.test", params=(("q", "{{a}}"),))
        out = expand.expand_spec(spec, _scope("x"))
        assert out.params == (("q", "{a}"),)

    def test_an_unresolved_placeholder_is_refused_loudly(self):
        """This is the whole point: `{country}` must never reach the wire."""
        spec = RequestSpec(url="https://x.test",
                           params=(("resource", "{country}"),), label="stats")
        with pytest.raises(DomainError) as caught:
            expand.expand_spec(spec, _scope("empty"))
        assert "country" in str(caught.value)
        assert "stats" in str(caught.value)

    def test_the_refusal_names_what_the_scope_did_offer(self):
        spec = RequestSpec(url="https://x.test/{lat}")
        with pytest.raises(DomainError, match="latitude"):
            expand.expand_spec(spec, _scope("x", latitude="25.0"))

    def test_a_non_string_value_is_refused(self):
        spec = RequestSpec(url="https://x.test/{lat}")
        with pytest.raises(DomainError, match="string"):
            expand.expand_spec(spec, ExpansionScope(values={"lat": 25.0}))

    def test_expansion_does_not_mutate_the_declaration(self):
        spec = RequestSpec(url="https://x.test/{country}")
        expand.expand_spec(spec, _scope("TW", country="TW"))
        assert spec.url == "https://x.test/{country}"


# ── fan-out: one declared spec, N concrete requests (H-1) ───────────────

class TestFanOut:
    def test_one_scope_yields_one_request(self):
        spec = RequestSpec(url="https://x.test/{country}")
        steps = expand.expand_requests((spec,),
                              ExpansionInput(scopes=(_scope("TW",
                                                            country="TW"),)))
        assert len(steps) == 1
        assert steps[0].alternatives[0].url == "https://x.test/TW"

    def test_the_isr_multi_zone_case_expands_to_one_request_per_zone(self):
        """§3-5 H-1. TW has two ISR zones; both must be asked about.

        The legacy sensor loops `for hotspot in ISR_HOTSPOTS` and sums per
        country. One declared box template must therefore become N boxes,
        or v3 sees the Taiwan Strait midline and not the East China Sea
        ADIZ overlap — a coverage reduction, which under NP1 is a missed
        detection rather than a smaller sample.
        """
        box = RequestSpec(
            url="https://opensky.test/states/all",
            params=(("lamin", "{lamin}"), ("lomin", "{lomin}"),
                    ("lamax", "{lamax}"), ("lomax", "{lomax}")),
            label="isr:{country}:{zone}")
        zones = (
            _scope("TW/strait_midline", country="TW", zone="strait_midline",
                   lamin="23.0", lomin="119.0", lamax="26.6", lomax="122.6"),
            _scope("TW/adiz_overlap", country="TW", zone="adiz_overlap",
                   lamin="24.2", lomin="121.2", lamax="27.8", lomax="124.8"))
        steps = expand.expand_requests((box,), ExpansionInput(scopes=zones))

        assert len(steps) == 2
        assert [s.scope_key for s in steps] == ["TW/strait_midline",
                                                "TW/adiz_overlap"]
        assert [s.alternatives[0].label for s in steps] == [
            "isr:TW:strait_midline", "isr:TW:adiz_overlap"]
        # each zone its own box
        assert steps[0].alternatives[0].param_values("lamin") == ("23.0",)
        assert steps[1].alternatives[0].param_values("lamin") == ("24.2",)

    def test_a_scope_independent_spec_is_fetched_once_not_n_times(self):
        """`usgs_seismic` asks the world one question. Five countries in
        scope must not become five identical requests."""
        spec = RequestSpec(url="https://usgs.test/query",
                           params=(("starttime", "{since_iso}"),),
                           label="quakes")
        steps = expand.expand_requests(
            (spec,),
            ExpansionInput(scopes=tuple(_scope(c, country=c)
                                        for c in ("TW", "JP", "US")),
                           common={"since_iso": "2026-08-06T00:00:00"}))
        assert len(steps) == 1
        assert steps[0].alternatives[0].param_values("starttime") == (
            "2026-08-06T00:00:00",)
        assert steps[0].scope_key == ""

    def test_a_spec_with_no_placeholders_is_fetched_once(self):
        spec = RequestSpec(url="https://noaa.test/kp.json", label="kp")
        steps = expand.expand_requests((spec,), ExpansionInput(
            scopes=tuple(_scope(c, country=c) for c in ("TW", "JP"))))
        assert len(steps) == 1

    def test_no_scopes_at_all_still_expands_run_wide_values(self):
        spec = RequestSpec(url="https://usgs.test/{since_iso}")
        steps = expand.expand_requests((spec,), ExpansionInput(
            common={"since_iso": "2026-08-06"}))
        assert steps[0].alternatives[0].url == "https://usgs.test/2026-08-06"

    def test_a_scope_value_beats_a_common_value(self):
        spec = RequestSpec(url="https://x.test/{country}")
        steps = expand.expand_requests((spec,), ExpansionInput(
            scopes=(_scope("TW", country="TW"),), common={"country": "GLOBAL"}))
        assert steps[0].alternatives[0].url == "https://x.test/TW"

    def test_declaration_order_is_preserved_across_specs(self):
        first = RequestSpec(url="https://x.test/a", label="a")
        second = RequestSpec(url="https://x.test/b", label="b")
        steps = expand.expand_requests((first, second), ExpansionInput())
        assert [s.alternatives[0].label for s in steps] == ["a", "b"]


# ── chains survive expansion as chains ──────────────────────────────────

class TestChainExpansion:
    def test_a_chain_expands_into_one_step_with_both_alternatives(self):
        chain = RequestChain(
            alternatives=(RequestSpec(url="https://ioda.test/{country}",
                                      label="ioda"),
                          RequestSpec(url="https://cf.test/{country}",
                                      label="cf_fallback")),
            reason="K19")
        steps = expand.expand_requests((chain,), ExpansionInput(
            scopes=(_scope("TW", country="TW"),)))
        assert len(steps) == 1
        assert [s.label for s in steps[0].alternatives] == ["ioda",
                                                            "cf_fallback"]
        assert steps[0].alternatives[0].url == "https://ioda.test/TW"
        assert steps[0].alternatives[1].url == "https://cf.test/TW"

    def test_the_trigger_travels_with_the_step(self):
        chain = RequestChain(
            alternatives=(RequestSpec(url="https://a.test"),
                          RequestSpec(url="https://b.test")),
            reason="K05")
        steps = expand.expand_requests((chain,), ExpansionInput())
        assert steps[0].advance_on == chain.advance_on
        assert steps[0].reason == "K05"

    def test_a_chain_fans_out_per_scope_too(self):
        chain = RequestChain(
            alternatives=(RequestSpec(url="https://a.test/{country}"),
                          RequestSpec(url="https://b.test/{country}")),
            reason="K05")
        steps = expand.expand_requests((chain,), ExpansionInput(scopes=(
            _scope("TW", country="TW"), _scope("JP", country="JP"))))
        assert len(steps) == 2
        assert steps[1].alternatives[1].url == "https://b.test/JP"

    def test_a_plain_spec_becomes_a_step_of_one_alternative(self):
        steps = expand.expand_requests((RequestSpec(url="https://a.test"),),
                              ExpansionInput())
        assert len(steps[0].alternatives) == 1


# ── the expander holds no secrets and performs no I/O ───────────────────

class TestExpanderDiscipline:
    def test_the_scope_is_plain_strings(self):
        scope = ExpansionScope(values={"country": "TW"}, scope_key="TW")
        with pytest.raises(TypeError):
            scope.values["country"] = "JP"

    def test_a_callable_value_is_refused(self):
        with pytest.raises(DomainError):
            ExpansionScope(values={"country": lambda: "TW"})

    def test_the_expander_imports_no_http_library(self):
        import inspect
        source = inspect.getsource(expand)
        for library in ("requests", "httpx", "socket", "urllib"):
            assert f"import {library}" not in source


# ── H-1: what the expander closed, and what it did not ─────────────────

class TestH1IsHalfClosed:
    """§3-5 H-1 was handed to WP-4.1 on the assumption the model could
    carry it. Half of that assumption was wrong and is now fixed; the
    other half is real, and this class states precisely which.

    H-1 has two parts:
      (a) one declared box must become N boxes, one per named ISR zone;
      (b) the surge threshold must be applied to the SUM over zones, not
          to each zone (`radar/sensors/isr_hotspot.py:85-94, 106-107`
          accumulates `results[theater]["count"] += isr_count` and only
          then asks `count >= 3`).

    (a) is closed here. (b) is NOT, and it cannot be closed inside L0:
    `normalize` is called once per fetched payload and sees one zone, so
    nothing in this layer is in a position to add two zones together.
    """

    ZONES = (
        ExpansionScope(scope_key="TW/strait_midline", values={
            "country": "TW", "zone": "Taiwan Strait Median Line",
            "lat": "24.5", "lng": "120.5", "lamin": "23.0",
            "lomin": "119.0", "lamax": "26.6", "lomax": "122.6"}),
        ExpansionScope(scope_key="TW/adiz_overlap", values={
            "country": "TW", "zone": "Senkaku / East China Sea ADIZ Overlap",
            "lat": "26.0", "lng": "123.0", "lamin": "24.2",
            "lomin": "121.2", "lamax": "27.8", "lomax": "124.8"}))

    def test_part_a_the_zones_each_get_their_own_request(self):
        from v3.adapters.catalog import build_registry
        registry = build_registry()
        adapter = registry.get(registry.resolve("isr_hotspot"))
        steps = expand.expand_requests(
            adapter.requests, ExpansionInput(scopes=self.ZONES))
        assert len(steps) == 2
        boxes = [dict(step.alternatives[0].params) for step in steps]
        assert boxes[0]["lamin"] == "23.0" and boxes[1]["lamin"] == "24.2"

    def test_part_a_each_request_says_which_zone_it_is(self):
        """`normalize` reads `payload.label`, which is the only channel it
        has — so the zone has to survive into it."""
        from v3.adapters.catalog import build_registry
        registry = build_registry()
        adapter = registry.get(registry.resolve("isr_hotspot"))
        steps = expand.expand_requests(
            adapter.requests, ExpansionInput(scopes=self.ZONES))
        # The label now carries the zone's NAME and centre, not just the
        # country. `radar/routes/core.py:2929-2931` joins the observed
        # zone record to the `ISR_HOTSPOTS` ledger on `h["name"]`, and
        # `core.py:1231` puts the whole zone array in the `ISR_SURGE`
        # payload — so something DOES group by zone, which is the
        # question this test's earlier note left open (§3-5 H-1(c)).
        assert [step.alternatives[0].label for step in steps] == [
            "isr;zone=Taiwan Strait Median Line;lat=24.5;lng=120.5;cc=TW",
            "isr;zone=Senkaku / East China Sea ADIZ Overlap;"
            "lat=26.0;lng=123.0;cc=TW"]
        assert [step.scope_key for step in steps] == ["TW/strait_midline",
                                                      "TW/adiz_overlap"]

    def test_part_b_is_still_open_and_L1_makes_it_loud(self):
        """Two zone-level drafts for one country cannot both be stored.

        `signal_observation` is UNIQUE on
        `(tick_id, sensor, signal_source, country)`, and a re-record with
        different content raises rather than being dropped (S5-VERIF-019).
        So the missing reduction is a hard error, not a silent halving —
        which is the right failure, but it is still a gap, and it belongs
        to WP-4.1's composition root: sum the zones, THEN threshold.
        """
        from v3.ledger.schema import SCHEMA_SQL
        assert ("UNIQUE (tick_id, sensor, signal_source, country)"
                in SCHEMA_SQL)
