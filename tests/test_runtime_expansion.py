"""WP-4.1 — geography, expansion supply, and the baseline account.

§3-5 H-1(a)'s supply side. `ExpansionInput.scopes` could already carry one
declaration to N requests; nothing existed to carry it WITH. The zone
census is the reason this is tested against the real `geo_data.json` and
not only against a fixture: the design sheet's hand-written census omitted
JP×2 and IN×2, and JP is a forward base in the focused scenario whose two
corridors overlap Taiwan's. A census that is derived cannot be wrong in
that way; a census that is transcribed already was.
"""
import pytest

from v3.adapters.catalog import build_registry
from v3.fetch.runner import UNRESOLVED, run_due
from v3.kernel.errors import DomainError
from v3.runtime import baselines, expansion, geo

NOW = 1_800_000_000.0


@pytest.fixture(scope="module")
def real_geography():
    return geo.load()


class TestTheCensusIsDerivedNotTranscribed:
    def test_the_ledger_holds_thirty_zones_over_twenty_one_countries(
            self, real_geography):
        assert len(real_geography.zones) == 30
        assert len(real_geography.zone_census()) == 21

    def test_the_seven_multi_zone_countries_are_what_the_addendum_says(
            self, real_geography):
        census = real_geography.zone_census()
        multi = {c: n for c, n in census.items() if n > 1}
        assert multi == {"CN": 3, "RU": 3, "TW": 2, "JP": 2, "KP": 2,
                         "AU": 2, "IN": 2}

    def test_japans_two_corridors_are_present(self, real_geography):
        """The pair the first census dropped. JP is a forward base in the
        focused scenario and these overlap Taiwan's own two zones."""
        names = [z.name for z in real_geography.zones if z.country == "JP"]
        assert len(names) == 2

    def test_the_stale_field_name_is_read_not_rewritten(self):
        """`geo_data.json` still tags zones `theater`. Translating on read
        is not the same as migrating the file."""
        built = geo.from_document({"ISR_HOTSPOTS": [
            {"name": "z", "lat": 1.0, "lng": 2.0, "theater": "tw"}]})
        assert built.zones[0].country == "TW"

    def test_a_zone_without_a_name_is_refused(self):
        with pytest.raises(DomainError, match="no usable country/name"):
            geo.from_document({"ISR_HOTSPOTS": [
                {"name": "", "lat": 1.0, "lng": 2.0, "theater": "TW"}]})

    def test_a_missing_file_raises_rather_than_degrading(self, tmp_path):
        with pytest.raises(DomainError, match="narrowed sweep"):
            geo.load(tmp_path / "absent.json")

    def test_the_comment_key_is_not_treated_as_a_country(self,
                                                         real_geography):
        assert "_COMMENT" not in real_geography.watched_domains
        assert all(len(code) == 2 for code in real_geography.watched_domains)


class TestParticipantsComeFromTheScenario:
    def test_they_are_ordered_by_coupling_weight(self, real_geography):
        ordered = geo.participants_of(real_geography, "taiwan_contingency")
        assert ordered[0] == "TW"

    def test_an_unknown_scenario_is_refused_by_name(self, real_geography):
        with pytest.raises(DomainError, match="unknown scenario"):
            geo.participants_of(real_geography, "atlantis")

    def test_the_adversary_role_is_read_from_the_ledger(self,
                                                        real_geography):
        assert geo.adversaries_of(real_geography,
                                  "taiwan_contingency") == ("CN",)


class TestOneDeclarationBecomesNRequests:
    def test_taiwans_two_zones_each_get_a_request(self, real_geography):
        supplied = expansion.for_cycle(real_geography, ["TW"], now=NOW)
        assert len(supplied["isr_hotspot"].scopes) == 2

    def test_the_zone_name_reaches_the_request(self, real_geography):
        supplied = expansion.for_cycle(real_geography, ["TW"], now=NOW)
        registry = build_registry()
        adapter = registry.get(registry.resolve("isr_hotspot"))
        from v3.fetch.expand import expand_requests
        steps = expand_requests(adapter.requests, supplied["isr_hotspot"])
        labels = [step.alternatives[0].label for step in steps]
        assert all("zone=" in label and "cc=TW" in label for label in labels)
        assert len({label for label in labels}) == 2

    def test_each_zone_gets_its_own_box(self, real_geography):
        supplied = expansion.for_cycle(real_geography, ["TW"], now=NOW)
        boxes = [scope.values["lamin"]
                 for scope in supplied["isr_hotspot"].scopes]
        assert len(set(boxes)) == 2

    def test_a_country_with_no_zone_is_simply_not_swept_by_it(
            self, real_geography):
        """Production loops over the ZONE ledger, not the participants, so
        a participant with no hotspot has never been in this sensor's
        coverage — reported, not silently equated with a swept country."""
        report = expansion.coverage_report(real_geography, ["US"])
        assert report["zone_requests"] == 0
        assert report["countries_without_a_zone"] == ["US"]

    def test_the_coverage_report_counts_zones_and_countries_separately(
            self, real_geography):
        report = expansion.coverage_report(real_geography, ["TW", "CN"])
        assert report["country_requests"] == 2
        assert report["zone_requests"] == 5

    def test_an_empty_scope_is_refused(self, real_geography):
        with pytest.raises(DomainError, match="fetch nothing"):
            expansion.for_cycle(real_geography, [], now=NOW)


class TestEveryEnabledAdapterResolves:
    """The completion condition for the supply: nothing goes UNRESOLVED
    for a reason the composition root could have fixed."""

    def test_no_adapter_is_skipped_for_a_missing_placeholder(
            self, real_geography):
        participants = geo.participants_of(real_geography,
                                           "taiwan_contingency")
        supplied = expansion.for_cycle(
            real_geography, participants, now=NOW,
            carried={"gps_jamming": {"date": "2026-08-07"}})
        registry = build_registry()
        plan = run_due(NOW, registry.enabled(), {}, None, supplied)
        assert [s.adapter_id.value for s in plan.skipped_for(UNRESOLVED)] == []

    def test_gps_jamming_is_the_one_that_needs_a_carried_value(
            self, real_geography):
        """Its `{date}` is the newest date in its OWN first response, and
        it declares two flat specs where the model has a type for exactly
        this. Without the carry it is skipped — visibly — rather than
        sending the literal placeholder."""
        participants = geo.participants_of(real_geography,
                                           "taiwan_contingency")
        supplied = expansion.for_cycle(real_geography, participants, now=NOW)
        registry = build_registry()
        plan = run_due(NOW, registry.enabled(), {}, None, supplied)
        assert [s.adapter_id.value
                for s in plan.skipped_for(UNRESOLVED)] == ["gps_jamming"]

    def test_check_host_asks_about_at_most_three_urls_per_country(
            self, real_geography):
        from v3.adapters.physical.check_host import MAX_URLS_PER_COUNTRY
        supplied = expansion.for_cycle(real_geography, ["UA"], now=NOW)
        assert len(supplied["check_host"].scopes) <= MAX_URLS_PER_COUNTRY

    def test_telegram_sweeps_every_channel_not_only_participants(
            self, real_geography):
        """Measured: the channel ledger's blocs are RU/UA/IR/… and none of
        them is a Taiwan participant, so filtering by participant watches
        zero channels."""
        supplied = expansion.for_cycle(real_geography, ["TW"], now=NOW)
        assert len(supplied["telegram_mirror"].scopes) == len(
            real_geography.telegram_channels)


class TestTheNormalizeContextIsSupplied:
    def test_it_carries_the_countries_and_the_geography(self,
                                                        real_geography):
        registry = build_registry()
        adapter = registry.get(registry.resolve("ais_maritime"))
        context = expansion.context_for(adapter, real_geography, ["TW"],
                                        now=NOW, adversaries=["CN"])
        assert context.countries == ("TW",)
        assert context.chokepoints
        assert all(row[3] == "TW" for row in context.chokepoints)

    def test_the_adversaries_arrive_rather_than_being_empty(self,
                                                            real_geography):
        """The regression. `adversaries` was hard-coded to `()` here, and
        the adapters that read it silently watched nobody."""
        registry = build_registry()
        adapter = registry.get(registry.resolve("usgs_seismic"))
        context = expansion.context_for(adapter, real_geography, ["TW"],
                                        now=NOW, adversaries=["cn", "CN"])
        assert context.adversaries == ("CN",)

    def test_omitting_the_adversaries_is_not_expressible(self,
                                                         real_geography):
        """No default, so the omission that caused the defect cannot be
        written a second time."""
        import inspect
        parameter = inspect.signature(
            expansion.context_for).parameters["adversaries"]
        assert parameter.default is inspect.Parameter.empty
        assert parameter.kind is inspect.Parameter.KEYWORD_ONLY

    def test_it_reaches_no_client_or_store(self, real_geography):
        import dataclasses
        from v3.adapters.types import NormalizeContext
        fields = {f.name for f in dataclasses.fields(NormalizeContext)}
        assert not (fields & {"client", "session", "store", "ledger"})


class TestTheBaselineAccountIsHonest:
    def test_the_answerable_baselines_are_named(self):
        assert set(baselines.PREVIOUS_CYCLE_SCALARS) >= {
            "atlas_prev_probe_count", "tor_prev_relay_count",
            "tor_prev_user_count"}

    def test_every_declared_baseline_is_either_answered_or_explained(self):
        registry = build_registry()
        report = baselines.coverage(registry.all())
        assert report["unanswered"]
        for name in report["unanswered"]:
            assert report["reasons"][name] != "no supply wired", name

    def test_the_register_entry_cannot_be_retired_yet(self):
        """§7-2 #9 says a partially-wired family must NOT be retired. The
        test states the condition rather than the intention."""
        registry = build_registry()
        report = baselines.coverage(registry.all())
        assert report["unanswered"], (
            "every declared baseline is answered — §7-2 #9 and #40 are now "
            "retirable and this test should be replaced by the retirement")

    def test_the_previous_cycle_read_returns_the_prior_rows_flags(
            self, tmp_path):
        from v3.kernel import Evidence
        from v3.ledger.records import SignalObservation
        from v3.ledger.store import LedgerStore
        store = LedgerStore(str(tmp_path / "b.db"))
        try:
            store.append_signal(SignalObservation(
                tick_id="t0", sensor="ripe_atlas", signal_source="ripe_atlas",
                domain="physical", country="TW",
                evidence=Evidence.observe({"active": 100},
                                          observed_at=NOW - 100,
                                          freshness_horizon_sec=86400.0,
                                          source="ripe_atlas"),
                status="OBSERVED", raw_score=0.0,
                flags={"active": 100}), now=NOW - 100)
            resolved = baselines.previous_cycle(store, now=NOW,
                                                countries=["TW"])
            assert resolved["atlas_prev_probe_count"]["TW"] == 100.0
        finally:
            store.close()

    def test_an_empty_ledger_yields_no_baselines_rather_than_zeros(
            self, tmp_path):
        """A zero previous count makes every drop calculation report 0%
        and every censorship event look like a quiet day."""
        from v3.ledger.store import LedgerStore
        store = LedgerStore(str(tmp_path / "empty.db"))
        try:
            assert baselines.previous_cycle(store, now=NOW,
                                            countries=["TW"]) == {}
        finally:
            store.close()
