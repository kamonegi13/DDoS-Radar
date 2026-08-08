"""WP-4.1 conditions 2, 3 and 5, plus P7 §1 coverage accounting.

Condition 2 — the ten v1/v2 duplicate pairs are one contract.
Condition 3 — the vocabulary is country/scenario; `theater` is gone.
Condition 5 (from WP-3.1) — ONE envelope, NP7 required by the type.

The coverage block is the honest half: it computes what P7's surface
asks for against what is served, so "implemented" is a number rather
than a memory. A P7 entry that is neither served nor deferred fails the
suite — which is the same partition discipline `v3.conclusions.registry`
uses for clauses, for the same reason.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from v3.api import registry as REG
from v3.api import routes as R
from v3.api.envelope import ApiResponse, tool_response
from v3.api.vocabulary import FORBIDDEN_RESPONSE_KEYS, TOOL_SCOPE
from v3.conclusions import ConclusionEnvelope, NP7_DISCLAIMER
from v3.kernel.errors import DomainError

REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = REPO_ROOT / "v3" / "api"


def _api_sources():
    return sorted(API_DIR.rglob("*.py"))


class TestConditionTwoTheDuplicatePairsCollapsed:
    def test_all_ten_pairs_are_accounted_for(self):
        assert len(REG.DUPLICATE_PAIRS) == 10
        proposals = [pair.proposal for pair in REG.DUPLICATE_PAIRS]
        assert proposals == sorted(set(proposals))

    def test_each_pair_names_exactly_one_destination(self):
        for pair in REG.DUPLICATE_PAIRS:
            assert pair.disposition.strip(), pair.proposal
            # None is a destination too: P7 dropped both members. What is
            # forbidden is a pair with two live shapes.
            assert pair.v3_route is None or isinstance(pair.v3_route, str)

    def test_every_named_destination_is_a_real_p7_entry(self):
        known = set(REG.P7_SURFACE) | {route.route_id for route in R.ROUTES}
        for pair in REG.DUPLICATE_PAIRS:
            if pair.v3_route is None:
                continue
            assert pair.v3_route in known, (pair.proposal, pair.v3_route)

    def test_no_two_pairs_land_on_conflicting_shapes(self):
        """PROP-005 and PROP-006 both land on R7; that is unification."""
        landed = [pair.v3_route for pair in REG.DUPLICATE_PAIRS
                  if pair.v3_route is not None]
        assert len(landed) >= 8
        # Every landing site must be one of the served or deferred ids —
        # never a new endpoint invented for one pair.
        for site in landed:
            assert site in REG.served_ids() | REG.deferred_ids() \
                or R.by_id(site) is not None, site


class TestConditionThreeTheVocabulary:
    def test_no_response_may_carry_retired_vocabulary(self):
        with pytest.raises(DomainError) as excinfo:
            tool_response(observed_at=1.0, theater="TW")
        assert "theater" in str(excinfo.value)

    def test_the_check_reaches_nested_structures(self):
        with pytest.raises(DomainError):
            tool_response(observed_at=1.0,
                          block={"rows": [{"theater": "TW"}]})

    def test_the_word_appears_nowhere_in_the_package_as_a_key(self):
        offences = []
        for path in _api_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and \
                        isinstance(node.value, str) and \
                        node.value in FORBIDDEN_RESPONSE_KEYS:
                    # vocabulary.py declares the forbidden set itself.
                    if path.name == "vocabulary.py":
                        continue
                    offences.append(f"{path.name}:{node.lineno}")
        assert offences == [], offences

    def test_every_route_path_uses_scenario_or_country_vocabulary(self):
        for route in R.ROUTES:
            lowered = route.path.lower()
            for word in FORBIDDEN_RESPONSE_KEYS:
                assert word not in lowered, route.route_id


class TestConditionFiveOneEnvelope:
    def test_there_is_no_second_envelope_class_under_the_package(self):
        offenders = []
        for path in _api_sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                fields = {item.target.id
                          for item in node.body
                          if isinstance(item, ast.AnnAssign)
                          and isinstance(item.target, ast.Name)}
                if {"disclaimer"} & fields:
                    offenders.append(f"{path.name}:{node.name}")
        assert offenders == [], (
            f"a second envelope shape is defect G-13, which is how the NP7 "
            f"sentence went missing once already: {offenders}")

    def test_the_response_type_carries_the_conclusion_envelope(self):
        response = tool_response(observed_at=10.0)
        assert isinstance(response, ApiResponse)
        assert isinstance(response.envelope, ConclusionEnvelope)

    def test_a_response_cannot_be_built_from_a_dict(self):
        with pytest.raises(DomainError):
            ApiResponse(status=200, envelope={"api_version": "3.0"})

    def test_the_tool_scope_projection_still_carries_the_disclaimer(self):
        payload = tool_response(observed_at=10.0).as_dict()
        assert payload["final_judgment_disclaimer"] == NP7_DISCLAIMER
        assert payload["scenario_id"] == TOOL_SCOPE


class TestTheSurfaceAccounting:
    def test_every_p7_entry_is_served_or_deferred(self):
        assert REG.unaccounted() == frozenset(), sorted(REG.unaccounted())

    def test_nothing_is_both(self):
        assert REG.double_counted() == frozenset()

    def test_every_served_entry_names_routes_that_exist(self):
        for item in REG.SERVED:
            assert item.route_ids, item.p7_id
            for route_id in item.route_ids:
                assert R.by_id(route_id) is not None, route_id

    def test_every_route_belongs_to_a_served_entry(self):
        claimed = {route_id for item in REG.SERVED
                   for route_id in item.route_ids}
        declared = {route.route_id for route in R.ROUTES}
        assert declared == claimed, (
            f"a route with no P7 entry is an endpoint P7 does not have; "
            f"P7 §1.4 says 'no endpoint exists without a mapping'. "
            f"unclaimed={sorted(declared - claimed)}")

    def test_every_deferred_entry_names_an_owner_and_a_reason(self):
        for item in REG.DEFERRED:
            assert item.owner.strip() and item.reason.strip(), item.p7_id

    def test_the_coverage_numbers_are_computed_not_asserted(self):
        report = REG.coverage()
        assert report["p7_total"] == 28
        assert report["served"] + report["deferred"] == report["p7_total"]
        assert report["routes"] == len(R.ROUTES)

    def test_the_surface_grew_rather_than_the_accounting_loosening(self):
        """WP-4.1f: 13 served -> 21. Pinned so a future change that shrinks
        coverage has to say so out loud rather than pass quietly."""
        report = REG.coverage()
        assert report["served"] >= 21, report
        assert report["deferred"] <= 7, report


class TestEveryRouteIsAProjection:
    """Condition 1 restated over the table, in both directions.

    Until WP-4.1c the table held only reads, so "no route has a side
    effect" was the whole rule. With commands on it the rule splits, and
    the second half is the new one: a command that FAILS to declare its
    effect is as wrong as a read that declares one. An undeclared effect
    would be handed a read context by the dispatcher and would then have
    nothing to write through — a POST that silently did nothing.
    """

    def test_no_safe_method_route_has_a_side_effect(self):
        from v3.api.vocabulary import SAFE_METHODS
        for route in R.ROUTES:
            if route.method in SAFE_METHODS:
                assert route.side_effect is False, route.route_id

    def test_every_unsafe_method_route_declares_its_side_effect(self):
        """...unless it is a DECLARED dry run, which C6 is.

        Narrowed by WP-4.1f rather than dropped. The rule's purpose is that
        an author cannot forget to declare an effect — a POST handed a read
        context would answer 200 having done nothing. A counterfactual is
        genuinely a POST with no effect, so the exemption is a named set
        with a stated reason per member, and the NEXT test proves the claim
        instead of trusting it.
        """
        from v3.api.vocabulary import SAFE_METHODS
        unsafe = [route for route in R.ROUTES
                  if route.method not in SAFE_METHODS]
        assert unsafe, "the command surface is empty"
        for route in unsafe:
            if route.route_id in R.DRY_RUN_ROUTES:
                assert route.side_effect is False, route.route_id
                assert R.DRY_RUN_ROUTES[route.route_id].strip(), route.route_id
                continue
            assert route.side_effect is True, route.route_id

    def test_a_dry_run_route_cannot_be_declared_without_being_listed(self):
        with pytest.raises(DomainError) as excinfo:
            R._dry_run("CX", "/api/v3/x", lambda ctx: None, ("I-2",))
        assert "DRY_RUN_ROUTES" in str(excinfo.value)

    def test_every_dry_run_entry_names_a_route_that_exists(self):
        for route_id in R.DRY_RUN_ROUTES:
            route = R.by_id(route_id)
            assert route is not None and route.side_effect is False, route_id

    def test_a_get_declaring_a_side_effect_is_refused(self):
        from v3.api.authorization import Access
        from v3.api.vocabulary import ROLE_VIEWER
        with pytest.raises(DomainError) as excinfo:
            R.Route(route_id="RX", method="GET", path="/api/v3/x",
                    access=Access.at_least(ROLE_VIEWER, reason="r"),
                    handler=lambda ctx: None, serves=("O-1",),
                    side_effect=True)
        assert "A-01" in str(excinfo.value)

    def test_every_route_declares_what_output_it_serves(self):
        for route in R.ROUTES:
            assert route.serves, route.route_id


class TestConditionThreeTheWebsocketVocabulary:
    """`theater` events are gone — asserted on the names, not on prose."""

    def test_the_channel_has_exactly_the_four_declared_events(self):
        from v3.api import ws
        assert ws.EVENTS == REG.WS_EVENTS
        assert len(ws.EVENTS) == 4

    def test_every_retired_event_names_what_it_became(self):
        from v3.api import ws
        for retired, replacement in ws.RETIRED_EVENTS.items():
            assert replacement, retired
            assert retired not in ws.EVENTS

    def test_the_theater_subscription_verbs_are_retired(self):
        from v3.api import ws
        assert ws.RETIRED_EVENTS["subscribe_theater"] == "subscribe_scenario"
        assert ws.SUBSCRIBE == "subscribe_scenario"

    def test_the_room_is_the_scenario(self):
        from v3.api import ws
        assert ws.room_for("taiwan_contingency") == \
            "scenario:taiwan_contingency"
        assert ws.scenario_of("scenario:taiwan_contingency") == \
            "taiwan_contingency"

    def test_a_room_cannot_be_keyed_by_the_retired_word(self):
        from v3.api import ws
        with pytest.raises(DomainError):
            ws.room_for("theater_tw")

    def test_the_three_anomaly_channels_collapsed_into_one(self):
        from v3.api import ws
        collapsed = {ws.RETIRED_EVENTS[name]
                     for name in ("ambush_alert", "sequence_event",
                                  "threat_update")}
        assert collapsed == {ws.CONCLUSION_UPDATE}
