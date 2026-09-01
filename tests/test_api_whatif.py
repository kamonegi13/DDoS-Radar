"""P7 C6 — one counterfactual, on the server's kernel, writing nothing.

Three production systems collapse here (`whatif/simulate`,
`whatif_weights`, the `X-Scenario-Overlay` header). G-09 is the reason it
matters: the frontend reimplemented the scoring arithmetic, so the "what
if" answer and the real answer came from two formulas and only one of them
was the tool's.

The two claims a test can actually make:

* **it writes nothing** — every table counted before and after, and the
  handler is handed a `ReadContext`, which holds no writer at all;
* **it is the same kernel** — a counterfactual with an EMPTY overlay must
  reproduce the baseline exactly, because if the two ran different code
  they would not agree on a no-op.
"""
from __future__ import annotations

import pytest

from tests.conclusions_fixtures import NOW
from v3.api import (ANONYMOUS, ApiRequest, Principal, ReadContext,
                    ReadOnlyLedger, ScenarioRef, handle)
from v3.api import routes as R
from v3.api.vocabulary import ROLE_ANALYST, ROLE_VIEWER
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.config.resolution import ConfigResolver
from v3.kernel import Evidence
from v3.ledger import LedgerStore, SignalObservation

SCENARIO = "taiwan_contingency"
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)
VIEWER = Principal(user_id="v-1", role=ROLE_VIEWER)

_TABLES = ("signal_observation", "tl_observation", "conclusion",
           "command_record", "calibration_label", "calibration_proposal",
           "attention_rank", "baseline_stat", "entity_observation",
           "fetch_log", "llm_call")


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "whatif.db"))
    for index, (country, score) in enumerate((("TW", 3.0), ("US", 1.5))):
        handle_.append_signal(SignalObservation(
            tick_id="t1", sensor="ripe_bgp", signal_source=f"bgp{index}",
            domain="cyber", country=country,
            evidence=Evidence.observe({}, source="ripe",
                                      observed_at=NOW - 300,
                                      freshness_horizon_sec=3600.0),
            status="FIRED", raw_score=score, confidence=0.9), NOW)
    yield handle_
    handle_.close()


def _counts(store) -> dict:
    conn = store._read_connection()
    return {name: conn.execute(f"SELECT COUNT(*) AS n FROM {name}"  # noqa: S608
                               ).fetchone()["n"] for name in _TABLES}


def _resolver():
    return ConfigResolver(environment={})


def _read_context(store, *, now=NOW, principal=ANALYST, config=True,
                  scenarios=None):
    return ReadContext(
        ledger=ReadOnlyLedger(store), now=now, principal=principal,
        config=_resolver() if config else None,
        scenarios=scenarios if scenarios is not None else (
            ScenarioRef(scenario_id=SCENARIO,
                        participants={"TW": 1.0, "US": 0.6},
                        roles={"TW": "primary_target", "US": "primary_ally"},
                        adversaries=("CN",), focused=True,
                        chain_country="TW"),))


def _post(store, body=None, *, principal=ANALYST, context=None, now=NOW):
    ctx = context if context is not None else _read_context(
        store, now=now, principal=principal)
    return handle(ApiRequest(method="POST", path="/api/v3/whatif",
                             body=body or {}, principal=principal), ctx)


class TestItWritesNothing:
    def test_the_route_declares_no_side_effect_and_says_why(self):
        route = R.by_id("C6")
        assert route.method == "POST" and route.side_effect is False
        assert R.DRY_RUN_ROUTES["C6"].strip()

    def test_every_table_is_unchanged(self, store):
        before = _counts(store)
        assert _post(store, {"settings": {"domain_cap": 4.0}}).status == 200
        assert _counts(store) == before

    def test_the_handler_is_handed_a_read_context_even_from_a_writer(self,
                                                                     store):
        """The structural claim behind `side_effect=False`.

        A write context reaches the dispatcher; the route's declaration
        makes the handler receive `context.read`, which holds no
        `CommandLedger` at all. So "it cannot write" is the type it was
        given, not a property of what the body happens to do.
        """
        write_context = WriteContext(read=_read_context(store),
                                     ledger=CommandLedger(store),
                                     principal=ANALYST)
        before = _counts(store)
        response = _post(store, {}, context=write_context)
        assert response.status == 200
        assert _counts(store) == before

    def test_the_handler_module_never_names_a_writer(self):
        import ast
        from pathlib import Path
        source = (Path(__file__).resolve().parent.parent / "v3" / "api" /
                  "handlers" / "whatif.py").read_text(encoding="utf-8")
        names = {node.attr for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Attribute)}
        assert "commit" not in names
        assert not [name for name in names if name.startswith("append_")]


class TestItIsTheSameKernel:
    def test_an_empty_overlay_reproduces_the_baseline_exactly(self, store):
        body = _post(store, {}).as_dict()
        assert body["baseline"] == body["counterfactual"], (
            "a no-op counterfactual that differs from the baseline means "
            "the two ran different code — which is G-09")

    def test_a_settings_overlay_changes_the_counterfactual_only(self, store):
        body = _post(store, {"settings": {"global_signal_weight": 0.1}}
                     ).as_dict()
        assert body["counterfactual"]["settings"]["global_signal_weight"] \
            == 0.1
        assert body["baseline"]["settings"]["global_signal_weight"] != 0.1

    def test_a_weight_overlay_changes_the_score(self, store):
        body = _post(store, {"weights": {SCENARIO: {"US": 0.0}}}).as_dict()
        baseline = body["baseline"]["scenarios"][SCENARIO]
        varied = body["counterfactual"]["scenarios"][SCENARIO]
        assert baseline != varied, (
            "dropping a participant's coupling weight to zero must change "
            "what the kernel computes")

    def test_both_runs_are_reported_with_their_settings(self, store):
        body = _post(store, {}).as_dict()
        for side in ("baseline", "counterfactual"):
            assert set(body[side]) == {"settings", "scenarios"}
            assert body[side]["settings"]["domain_cap"] is not None

    def test_the_overlay_is_echoed_so_the_answer_names_its_question(self,
                                                                    store):
        body = _post(store, {"weights": {SCENARIO: {"US": 0.2}},
                             "focus": SCENARIO}).as_dict()
        assert body["overlay"]["weights"] == {SCENARIO: {"US": 0.2}}
        assert body["overlay"]["focus"] == SCENARIO


class TestTheVocabularyIsClosed:
    def test_an_unknown_top_level_key_is_refused(self, store):
        response = _post(store, {"overlay": {}})
        assert response.status == 400
        assert response.as_dict()["error_detail"]["detail"]["unknown"] == \
            ["overlay"]

    def test_an_unknown_settings_key_is_refused(self, store):
        response = _post(store, {"settings": {"tl_critical": 3.0}})
        assert response.status == 400
        assert "tl_critical" in \
            response.as_dict()["error_detail"]["detail"]["unknown"]

    def test_an_out_of_range_setting_is_refused_not_clamped(self, store):
        assert _post(store, {"settings": {"global_signal_weight": 5.0}}
                     ).status == 400

    def test_adding_a_participant_is_not_a_counterfactual(self, store):
        response = _post(store, {"weights": {SCENARIO: {"JP": 0.5}}})
        assert response.status == 400
        assert "JP" in response.as_dict()["error_detail"]["detail"]["unknown"]

    def test_an_unknown_scenario_is_404(self, store):
        assert _post(store, {"weights": {"nope": {"TW": 0.5}}}).status == 404

    def test_a_deployment_with_no_chain_answers_503(self, store):
        response = _post(store, {}, context=_read_context(store,
                                                          config=False))
        assert response.status == 503


class TestAccess:
    def test_an_anonymous_caller_gets_401(self, store):
        assert _post(store, {}, principal=ANONYMOUS).status == 401

    def test_a_viewer_may_not_run_a_counterfactual(self, store):
        assert _post(store, {}, principal=VIEWER).status == 403
