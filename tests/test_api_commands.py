"""P7 C1 / C2 / C9 end to end — through `handle()`, without a server.

The read suite proves a GET cannot write. This one proves the harder
half: that a POST writes, that the write is READ by something, and that
neither fact rests on a handler remembering anything.

`TestG01IsStructurallyDead` is the centrepiece. G-01 was
`POST /api/v2/conclusions/<id>/feedback` in four variants, three of which
called `_require_analyst()`. The endpoint fed the calibration chain whose
three disasters were all label contamination. Here the gate is a field of
the route table, so the tests below are about the table's effect, not
about a call the handler makes.
"""
from __future__ import annotations

import json

import pytest

from tests.conclusions_fixtures import NOW, healthy, provenance
from v3.api import (ANONYMOUS, ApiRequest, Principal, ReadContext,
                    ReadOnlyLedger, ScenarioRef, handle)
from v3.api import routes as R
from v3.api.vocabulary import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from v3.api.write import CommandJournal, WriteContext
from v3.api.writeonly import CommandLedger
from v3.commands import state as S
from v3.conclusions import Conclusion, NP7_DISCLAIMER, THREAT_LEVEL, to_record
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore

SCENARIO = "taiwan_contingency"
OTHER = "korea_peninsula"
VIEWER = Principal(user_id="v-1", role=ROLE_VIEWER)
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)
ADMIN = Principal(user_id="ad-1", role=ROLE_ADMIN)
CONCLUSION_ID = "concl-1"


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "commands.db"))
    handle_.append_conclusion(to_record(Conclusion(
        scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL, observed_at=NOW,
        confidence=0.8, provenance=provenance("tl@S1-CONC-001"),
        input_health=healthy(), state="TL4",
        threshold_ref={"tl_critical": 3.0}, source_urls=("https://x/1",),
        calibration_status={"status": "measured"},
        metadata={"id": CONCLUSION_ID})))
    yield handle_
    handle_.close()


def _read_context(store, *, now=NOW):
    return ReadContext(
        ledger=ReadOnlyLedger(store), now=now,
        scenarios=(ScenarioRef(scenario_id=SCENARIO, focused=True),
                   ScenarioRef(scenario_id=OTHER)))


def _write_context(store, principal=ANALYST, *, now=NOW):
    return WriteContext(read=_read_context(store, now=now),
                        ledger=CommandLedger(store), principal=principal)


def _stored_conclusion_id(store) -> str:
    row = store.latest_conclusion_at(NOW, scenario_id=SCENARIO,
                                     conclusion_type=THREAT_LEVEL)
    return row["id"]


def _post(store, path, body=None, principal=ANALYST, *, context=None,
          now=NOW):
    ctx = context if context is not None else _write_context(store, principal,
                                                             now=now)
    request = ApiRequest(method="POST", path=path, body=body or {},
                         principal=principal)
    return handle(request, ctx)


def _get(store, path, params=None, principal=VIEWER, *, now=NOW):
    request = ApiRequest(method="GET", path=path, params=params or {},
                         principal=principal)
    return handle(request, _read_context(store, now=now))


class TestG01IsStructurallyDead:
    """The gate is the route's field. These test the table's effect."""

    def test_an_anonymous_caller_is_told_401_not_404(self, store):
        response = _post(store, "/api/v3/conclusions/nope/feedback",
                         principal=ANONYMOUS,
                         context=_read_context(store))
        assert response.status == 401

    def test_a_viewer_is_refused_before_the_body_runs(self, store):
        response = _post(store, "/api/v3/conclusions/nope/feedback",
                         principal=VIEWER, context=_read_context(store))
        assert response.status == 403
        # 403 rather than 404: a caller who may not act must not learn
        # whether the conclusion exists.

    def test_an_analyst_may_label(self, store):
        cid = _stored_conclusion_id(store)
        response = _post(store, f"/api/v3/conclusions/{cid}/feedback",
                         {"label": "TRUE_POSITIVE", "reason": "現地報道と一致"})
        assert response.status == 200

    def test_every_command_route_states_analyst_or_higher(self):
        for route in R.ROUTES:
            if not route.side_effect:
                continue
            assert route.access.public is False, route.route_id
            assert route.access.minimum_role in (ROLE_ANALYST, ROLE_ADMIN)

    def test_the_label_is_read_back_by_a_projection(self, store):
        cid = _stored_conclusion_id(store)
        _post(store, f"/api/v3/conclusions/{cid}/feedback",
              {"label": "FALSE_POSITIVE", "reason": "誤検知と判断"})
        body = _get(store, f"/api/v3/conclusions/{cid}").as_dict()
        labels = body["analyst_labels"]
        assert labels["a-1"]["label"] == "FALSE_POSITIVE"
        assert labels["a-1"]["reason"] == "誤検知と判断"

    def test_the_outcome_url_survives_into_the_projection(self, store):
        """`conclusions_v2.py:344-347` promotes a human label to ground
        truth only when it carries an outcome URL. A projection that
        dropped the field would demote every analyst label out of the
        calibration chain without saying so — insensitive (C-02/C-03)."""
        cid = _stored_conclusion_id(store)
        _post(store, f"/api/v3/conclusions/{cid}/feedback",
              {"label": "FALSE_NEGATIVE", "reason": "見逃し",
               "observed_outcome_url": "https://news/1"})
        body = _get(store, f"/api/v3/conclusions/{cid}").as_dict()
        assert body["analyst_labels"]["a-1"]["observed_outcome_url"] \
            == "https://news/1"

    def test_a_label_without_a_reason_is_refused(self, store):
        cid = _stored_conclusion_id(store)
        response = _post(store, f"/api/v3/conclusions/{cid}/feedback",
                         {"label": "TRUE_POSITIVE"})
        assert response.status == 400
        assert store.count_commands() == 0

    def test_a_missing_conclusion_is_404_for_someone_permitted(self, store):
        response = _post(store, "/api/v3/conclusions/ghost/feedback",
                         {"label": "TRUE_POSITIVE", "reason": "r"})
        assert response.status == 404


class TestFocusIsACommandAndItsEffectIsReal:
    def test_focus_cannot_be_set_through_a_get(self, store):
        response = _get(store, "/api/v3/focus")
        assert response.status in (400, 404)
        assert store.count_commands() == 0

    def test_a_post_moves_the_projection(self, store):
        before = _get(store, "/api/v3/scenarios").as_dict()
        assert before["focused_scenario"] is None
        assert before["focus_source"] == "deployment_default"
        response = _post(store, "/api/v3/focus", {"scenario_id": OTHER})
        assert response.status == 200
        after = _get(store, "/api/v3/scenarios").as_dict()
        assert after["focused_scenario"] == OTHER
        assert after["focus_source"] == "command_log"
        rows = {row["scenario_id"]: row["focused"] for row in
                after["scenarios"]}
        assert rows == {SCENARIO: False, OTHER: True}

    def test_the_response_states_the_read_back_value(self, store):
        body = _post(store, "/api/v3/focus",
                     {"scenario_id": OTHER}).as_dict()
        assert body["effect"] == {"focused_scenario": OTHER}
        assert body["command"]["before"] is None
        assert body["command"]["after"] == OTHER
        assert body["changed"] is True

    def test_an_unknown_scenario_is_refused_and_records_nothing(self, store):
        response = _post(store, "/api/v3/focus", {"scenario_id": "atlantis"})
        assert response.status == 404
        assert store.count_commands() == 0

    def test_the_record_names_who_moved_the_tools_attention(self, store):
        _post(store, "/api/v3/focus", {"scenario_id": OTHER},
              principal=ADMIN)
        row = store.command_records(action=S.FOCUS_SET)[-1]
        assert row["actor_id"] == "ad-1"
        assert row["actor_role"] == ROLE_ADMIN


class TestGroundTruthHasBothHalves:
    def test_an_assertion_appears_in_the_read_projection(self, store):
        _post(store, f"/api/v3/scenarios/{SCENARIO}/ground_truth",
              {"observed_at": NOW - 3600, "source_url": "https://n/1",
               "description": "港湾封鎖", "reason": "2 系統で確認"})
        body = _get(store, "/api/v3/ground_truth").as_dict()
        entries = body["ground_truth"][SCENARIO]
        assert len(entries) == 1
        assert entries[0]["description"] == "港湾封鎖"
        assert entries[0]["asserted_by"] == "a-1"

    def test_an_entry_without_a_source_is_refused(self, store):
        response = _post(store, f"/api/v3/scenarios/{SCENARIO}/ground_truth",
                         {"observed_at": NOW - 10, "description": "d",
                          "reason": "r"})
        assert response.status == 400
        assert store.count_commands() == 0

    def test_an_entry_without_a_reason_is_refused(self, store):
        response = _post(store, f"/api/v3/scenarios/{SCENARIO}/ground_truth",
                         {"observed_at": NOW - 10, "source_url": "https://n",
                          "description": "d"})
        assert response.status == 400

    def test_reasserting_the_same_event_is_visibly_not_a_change(self, store):
        payload = {"observed_at": NOW - 3600, "source_url": "https://n/1",
                   "description": "港湾封鎖", "reason": "r"}
        _post(store, f"/api/v3/scenarios/{SCENARIO}/ground_truth", payload)
        second = _post(store, f"/api/v3/scenarios/{SCENARIO}/ground_truth",
                       payload, now=NOW + 5).as_dict()
        assert second["changed"] is False
        assert len(second["effect"]["ground_truth"]) == 1
        # Still two rows: the second assertion is a fact about the analyst
        # even though it moved nothing. AP4 wants both.
        assert store.count_commands() == 2

    def test_the_scope_filter_refuses_an_unknown_scenario(self, store):
        response = _get(store, "/api/v3/ground_truth",
                        {"scenario_id": "atlantis"})
        assert response.status == 404


class TestTheDispatcherEnforcesTheDiscipline:
    def test_a_command_on_a_read_only_deployment_is_503(self, store):
        response = _post(store, "/api/v3/focus", {"scenario_id": OTHER},
                         context=_read_context(store))
        assert response.status == 503
        assert response.as_dict()["error"] == "api.unavailable"

    def test_a_read_route_never_receives_the_write_context(self, store):
        seen = {}

        def spy(context, **kwargs):
            seen["type"] = type(context).__name__
            return original(context, **kwargs)

        route = R.by_id("R1")
        original = route.handler
        object.__setattr__(route, "handler", spy)
        try:
            request = ApiRequest(method="GET", path="/api/v3/scenarios",
                                 principal=ANALYST)
            handle(request, _write_context(store))
        finally:
            object.__setattr__(route, "handler", original)
        assert seen["type"] == "ReadContext"

    def test_a_command_that_records_nothing_is_a_failure(self, store):
        route = R.by_id("C1")
        original = route.handler

        def silent(context, **kwargs):
            from v3.api.envelope import tool_response
            return tool_response(observed_at=context.now)

        object.__setattr__(route, "handler", silent)
        try:
            with pytest.raises(DomainError) as excinfo:
                _post(store, "/api/v3/focus", {"scenario_id": OTHER})
        finally:
            object.__setattr__(route, "handler", original)
        assert "S2-PROP-019" in str(excinfo.value)

    def test_a_command_that_records_twice_is_a_failure(self, store):
        route = R.by_id("C1")
        original = route.handler

        def twice(context, **kwargs):
            first = original(context, **kwargs)
            original(context, **kwargs)
            return first

        object.__setattr__(route, "handler", twice)
        try:
            with pytest.raises(DomainError):
                _post(store, "/api/v3/focus", {"scenario_id": OTHER})
        finally:
            object.__setattr__(route, "handler", original)

    def test_a_wrong_verb_on_a_command_path_is_not_a_404(self, store):
        request = ApiRequest(method="DELETE", path="/api/v3/focus",
                             principal=ANALYST)
        response = handle(request, _write_context(store))
        assert response.status == 400
        assert response.as_dict()["error"] == "api.method_not_allowed"


class TestCommandsUseTheOneEnvelope:
    def test_a_command_answer_carries_the_np7_sentence(self, store):
        body = _post(store, "/api/v3/focus",
                     {"scenario_id": OTHER}).as_dict()
        assert body["final_judgment_disclaimer"] == NP7_DISCLAIMER

    def test_a_command_answer_is_stamped_with_freshness_once(self, store):
        body = _post(store, "/api/v3/focus",
                     {"scenario_id": OTHER}).as_dict()
        assert "data_freshness_sec" in body
        assert "served_at" in body

    def test_a_command_answer_is_json(self, store):
        body = _post(store, "/api/v3/focus",
                     {"scenario_id": OTHER}).as_dict()
        assert json.loads(json.dumps(body))

    def test_a_command_answer_cannot_restate_the_effect(self, store):
        from v3.api.envelope import command_response

        class Fake:
            def as_dict(self):
                return {"command": {}, "sequence": 1, "changed": True,
                        "effect": {}}

        with pytest.raises(DomainError):
            command_response(SCENARIO, Fake(), observed_at=NOW,
                             effect={"focused_scenario": "x"})


class TestTheSurfaceAccountsForWhatLanded:
    def test_three_command_families_are_served(self):
        from v3.api import registry as REG
        assert {"C1", "C2", "C9"} <= REG.served_ids()

    def test_every_remaining_command_names_a_blocker_not_a_category(self):
        from v3.api import registry as REG
        for item in REG.DEFERRED:
            if not item.p7_id.startswith("C"):
                continue
            assert item.reason.strip() != "書込面", item.p7_id
            assert len(item.reason) > 20, item.p7_id

    def test_the_websocket_transport_is_registered_not_merely_absent(self):
        from v3.api import registry as REG
        assert REG.WS_TRANSPORT.owner.strip()
        assert len(REG.WS_TRANSPORT.reason) > 40
        # It is NOT counted against P7's 28 — the surface accounting is
        # REST; the channel is registered beside it so the decision to
        # decline it is reviewable rather than invisible.
        assert REG.WS_TRANSPORT.p7_id not in REG.P7_SURFACE
        assert REG.coverage()["served"] + REG.coverage()["deferred"] == 28
