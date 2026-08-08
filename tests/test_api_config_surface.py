"""WP-4.1d — P7 R14 and C7, on a real ledger, through the real dispatcher.

WP-4.1c deferred both with one blocker, stated as a prohibition rather
than a delay: v3's resolution terminated in the legacy registry, so an
override written here would be read by nothing and `commit()`'s effect
verification would refuse every command. **Shipping C7 in that state would
have BEEN G-15**, not risked it.

That is why the mutation test in this file is the centre of it. It makes
the chain blind to the row that was just written — exactly the condition
WP-4.1c described — and requires the command to fail. If that test ever
passes with a green commit, the endpoint has become the defect again.
"""
from __future__ import annotations

import pytest

from v3.api import errors as E
from v3.api.dispatch import handle
from v3.api.readonly import ReadOnlyLedger
from v3.api.request import ApiRequest, Principal, ReadContext, ScenarioRef
from v3.api.vocabulary import API_PREFIX, DELETE, GET, POST
from v3.api.write import Change, WriteContext
from v3.api.writeonly import CommandLedger
from v3.commands import spec as SPEC
from v3.commands import state as S
from v3.config import registry as R
from v3.config.resolution import (ConfigResolver, SOURCE_DEFAULT, SOURCE_ENV,
                                  SOURCE_OVERRIDE)
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.scoring.settings import resolve_settings

NOW = 1_760_000_000.0
SCENARIO = "taiwan_contingency"
KEY = "DOMAIN_CAP"


@pytest.fixture()
def store(tmp_path):
    handle = LedgerStore(str(tmp_path / "config.db"))
    yield handle
    handle.close()


def read_context(store, *, now=NOW, chain=None, environment=None):
    return ReadContext(
        ledger=ReadOnlyLedger(store), now=now,
        scenarios=(ScenarioRef(scenario_id=SCENARIO),),
        config=chain if chain is not None
        else ConfigResolver(environment or {}))


def write_context(store, *, now=NOW, body=None, role="analyst",
                  chain=None, environment=None):
    return WriteContext(
        read=read_context(store, now=now, chain=chain,
                          environment=environment),
        ledger=CommandLedger(store),
        principal=Principal(user_id="u-1", role=role), body=dict(body or {}))


def post_override(store, *, key=KEY, value=9.0, reason="演習期間中の暫定",
                  now=NOW, environment=None):
    context = write_context(store, now=now,
                            body={"value": value, "reason": reason},
                            environment=environment)
    return handle(ApiRequest(method=POST, path=f"{API_PREFIX}/config/{key}",
                             body=context.body,
                             principal=context.principal), context)


class TestR14ServesTheLayerNotJustTheNumber:
    def test_it_lists_every_variable_key(self, store):
        response = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/config",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store))
        assert response.status == 200
        body = response.as_dict()
        assert [row["key"] for row in body["config"]] == \
            list(R.variable_keys())
        assert body["variable_keys"] == list(R.variable_keys())
        assert body["layers"] == ["override", "env", "default"]

    def test_each_row_states_its_source_default_reason_and_reader(self, store):
        body = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/config",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store)).as_dict()
        row = next(r for r in body["config"] if r["key"] == KEY)
        assert row["source"] == SOURCE_DEFAULT
        assert row["value"] == R.default_of(KEY)
        assert row["default"] == R.default_of(KEY)
        assert row["consumer"] == R.SCORING_CONSUMER
        assert row["why"]
        assert row["override"] is None

    def test_the_environment_layer_is_visible_even_when_it_does_not_win(
            self, store):
        post_override(store, environment={KEY: "7.0"})
        body = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/config",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store, environment={KEY: "7.0"})).as_dict()
        row = next(r for r in body["config"] if r["key"] == KEY)
        assert row["source"] == SOURCE_OVERRIDE
        assert row["env_present"] is True
        assert body["environment_layer_keys"] == [KEY]

    def test_a_deployment_with_no_chain_says_so_rather_than_guessing(self,
                                                                     store):
        context = ReadContext(ledger=ReadOnlyLedger(store), now=NOW)
        response = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/config",
                       principal=Principal(user_id="u", role="viewer")),
            context)
        assert response.status == 503
        assert response.envelope.error == E.UNAVAILABLE

    def test_a_viewer_may_read_it(self, store):
        response = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/config",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store))
        assert response.status == 200


class TestC7WritesThroughTheCommandSurface:
    def test_an_override_is_a_command_row_with_an_actor_and_a_reason(self,
                                                                     store):
        response = post_override(store)
        assert response.status == 200
        rows = store.command_records(action=S.CONFIG_OVERRIDE)
        assert len(rows) == 1
        assert rows[0]["actor_id"] == "u-1"
        assert rows[0]["reason"] == "演習期間中の暫定"
        assert rows[0]["target_kind"] == S.TARGET_CONFIG
        assert rows[0]["target_id"] == KEY

    def test_the_response_reports_the_value_read_back_not_the_one_sent(
            self, store):
        body = post_override(store, value=9.0).as_dict()
        effect = body["effect"]["config"]
        assert effect["value"] == 9.0
        assert effect["source"] == SOURCE_OVERRIDE
        assert effect["override"]["actor_id"] == "u-1"

    def test_the_override_is_visible_to_r14_afterwards(self, store):
        post_override(store, value=9.0)
        body = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/config",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store)).as_dict()
        row = next(r for r in body["config"] if r["key"] == KEY)
        assert (row["source"], row["value"]) == (SOURCE_OVERRIDE, 9.0)

    def test_delete_returns_the_key_to_the_layer_below(self, store):
        post_override(store, value=9.0, environment={KEY: "7.0"})
        context = write_context(store, now=NOW + 1, body={"reason": "演習終了"},
                                environment={KEY: "7.0"})
        response = handle(
            ApiRequest(method=DELETE, path=f"{API_PREFIX}/config/{KEY}",
                       body=context.body, principal=context.principal),
            context)
        assert response.status == 200
        effect = response.as_dict()["effect"]["config"]
        assert (effect["source"], effect["value"]) == (SOURCE_ENV, 7.0)
        assert effect["override"] is None

    def test_the_clear_is_an_append_not_a_delete(self, store):
        post_override(store, value=9.0)
        context = write_context(store, now=NOW + 1, body={"reason": "戻す"})
        handle(ApiRequest(method=DELETE, path=f"{API_PREFIX}/config/{KEY}",
                          body=context.body, principal=context.principal),
               context)
        assert store.count_commands() == 2, \
            "the decision trail must hold the removal as an event (AP4)"

    def test_a_reason_is_required_on_both_verbs(self, store):
        for method, body in ((POST, {"value": 9.0}), (DELETE, {})):
            context = write_context(store, body=body)
            response = handle(
                ApiRequest(method=method,
                           path=f"{API_PREFIX}/config/{KEY}", body=body,
                           principal=context.principal), context)
            assert response.status == 400, method
        assert store.count_commands() == 0

    def test_a_missing_value_is_a_refusal_not_a_clear(self, store):
        context = write_context(store, body={"reason": "r"})
        response = handle(
            ApiRequest(method=POST, path=f"{API_PREFIX}/config/{KEY}",
                       body=context.body, principal=context.principal),
            context)
        assert response.status == 400
        assert store.count_commands() == 0

    def test_a_pinned_key_is_refused_with_its_provenance(self, store):
        response = post_override(store, key="TL1_SCORE_FLOOR", value=8.0)
        assert response.status == 400
        detail = response.as_dict()["error_detail"]["detail"]
        assert detail["key"] == "TL1_SCORE_FLOOR"
        assert "S1-SCORE-004" in \
            response.as_dict()["error_detail"]["message"]
        assert store.count_commands() == 0, \
            "a refused override must leave no row: an audit row for a " \
            "change that did not happen is G-15 with better paperwork"

    def test_an_unknown_key_is_refused(self, store):
        response = post_override(store, key="NO_SUCH_KEY", value=1.0)
        assert response.status == 400
        assert store.count_commands() == 0

    def test_a_value_the_unit_does_not_admit_is_refused(self, store):
        response = post_override(store, key="LLM_INTEL_PRIMARY_THRESHOLD",
                                 value=3.0)
        assert response.status == 400
        assert store.count_commands() == 0

    def test_a_bool_key_refuses_an_integer(self, store):
        response = post_override(store, key="GLOBAL_SIGNALS_DECOUPLED",
                                 value=0)
        assert response.status == 400

    def test_a_viewer_cannot_write(self, store):
        context = write_context(store, role="viewer",
                                body={"value": 9.0, "reason": "r"})
        response = handle(
            ApiRequest(method=POST, path=f"{API_PREFIX}/config/{KEY}",
                       body=context.body, principal=context.principal),
            context)
        assert response.status == 403
        assert store.count_commands() == 0

    def test_a_read_only_deployment_answers_503(self, store):
        response = handle(
            ApiRequest(method=POST, path=f"{API_PREFIX}/config/{KEY}",
                       body={"value": 9.0, "reason": "r"},
                       principal=Principal(user_id="u", role="analyst")),
            read_context(store))
        assert response.status == 503

    def test_replay_bounds_the_override_at_an_instant(self, store):
        post_override(store, value=9.0, now=NOW)
        chain = ConfigResolver()
        ledger = ReadOnlyLedger(store)
        assert chain.resolve(KEY, ledger=ledger, at=NOW - 1).source == \
            SOURCE_DEFAULT
        assert chain.resolve(KEY, ledger=ledger, at=NOW).source == \
            SOURCE_OVERRIDE


class TestTheEffectVerificationIsTheWholePoint:
    """WP-4.1c's prohibition, kept as a live test rather than a memory."""

    def test_a_chain_blind_to_the_new_row_refuses_the_command(self, store,
                                                              monkeypatch):
        """THE mutation. This is the exact condition WP-4.1c measured: an
        override row is written and the resolution path does not read it.
        Before the v3 chain existed, every C7 call looked like this."""
        calls = {"n": 0}
        truth = S.config_override

        def blind(ledger, key, *, until=None):
            calls["n"] += 1
            # The first call computes `before`; going blind afterwards is
            # what makes the read-back disagree with the claim.
            return truth(ledger, key, until=until) if calls["n"] == 1 else None

        monkeypatch.setattr(S, "config_override", blind)
        context = write_context(store, body={"value": 9.0, "reason": "r"})
        with pytest.raises(DomainError) as excinfo:
            context.commit(Change(
                action=S.CONFIG_OVERRIDE,
                target=SPEC.Target(kind=S.TARGET_CONFIG, id=KEY),
                payload={"value": 9.0}, reason="r"))
        assert "G-15" in str(excinfo.value)

    def test_the_command_cannot_be_committed_without_a_chain(self, store):
        context = WriteContext(
            read=ReadContext(ledger=ReadOnlyLedger(store), now=NOW),
            ledger=CommandLedger(store),
            principal=Principal(user_id="u-1", role="analyst"))
        with pytest.raises(DomainError) as excinfo:
            context.commit(Change(
                action=S.CONFIG_OVERRIDE,
                target=SPEC.Target(kind=S.TARGET_CONFIG, id=KEY),
                payload={"value": 9.0}, reason="r"))
        assert "G-15" in str(excinfo.value)

    def test_the_fold_equals_a_replay_of_every_row(self, store):
        post_override(store, value=9.0, now=NOW)
        post_override(store, value=8.0, now=NOW + 1)
        rows = store.command_records(target_kind=S.TARGET_CONFIG,
                                     target_id=KEY)
        assert [row["after"]["value"] for row in rows] == [9.0, 8.0]
        assert S.config_state(ReadOnlyLedger(store), KEY) == rows[-1]["after"]


class TestTheOverrideReachesTheScoringPath:
    """R14 showing the new value is necessary and not sufficient.

    G-15's UI showed the new value too. What matters is that the function
    which turns keys into the numbers the tool computes with — the
    registered consumer — produces the overridden value.
    """

    def test_resolve_settings_sees_the_override(self, store):
        baseline = resolve_settings(
            ConfigResolver().settings_resolver(
                ledger=ReadOnlyLedger(store))).domain_cap
        assert baseline == R.default_of(KEY)

        post_override(store, value=9.0)
        chain = ConfigResolver()
        after = resolve_settings(
            chain.settings_resolver(ledger=ReadOnlyLedger(store),
                                    at=NOW)).domain_cap
        assert after == 9.0

    def test_clearing_it_takes_the_scoring_path_back(self, store):
        post_override(store, value=9.0, now=NOW)
        context = write_context(store, now=NOW + 1, body={"reason": "戻す"})
        handle(ApiRequest(method=DELETE, path=f"{API_PREFIX}/config/{KEY}",
                          body=context.body, principal=context.principal),
               context)
        settings = resolve_settings(
            ConfigResolver().settings_resolver(ledger=ReadOnlyLedger(store),
                                               at=NOW + 1))
        assert settings.domain_cap == R.default_of(KEY)

    def test_the_environment_layer_reaches_it_too(self, store):
        settings = resolve_settings(
            ConfigResolver({KEY: "7.5"}).settings_resolver(
                ledger=ReadOnlyLedger(store)))
        assert settings.domain_cap == 7.5


class TestR10DisclosesBothHalvesOfO18:
    """P7 R10 asks for both forms. Before WP-4.1d it served only pinned
    constants, so the group-(a) set existed in code and in no document."""

    def test_it_serves_the_variable_declarations_and_the_constants(self,
                                                                   store):
        body = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/thresholds",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store)).as_dict()
        thresholds = body["thresholds"]
        assert {row["key"] for row in thresholds["variable"]} == \
            set(R.variable_keys())
        assert "TL1_SCORE_FLOOR" in thresholds["scoring_pinned"]
        assert set(thresholds["variable"][0]) >= {
            "key", "unit", "default", "why", "consumer", "catalogue"}

    def test_the_two_halves_do_not_overlap(self, store):
        body = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/thresholds",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store)).as_dict()
        thresholds = body["thresholds"]
        variable = {row["key"] for row in thresholds["variable"]}
        assert variable & set(thresholds["scoring_pinned"]) == set()

    def test_the_disclosure_survives_json(self, store):
        import json
        body = handle(
            ApiRequest(method=GET, path=f"{API_PREFIX}/thresholds",
                       principal=Principal(user_id="u", role="viewer")),
            read_context(store)).as_dict()
        assert json.loads(json.dumps(body, ensure_ascii=False)) == body


class TestTheAuditRowAndTheProjectedOverrideAgree:
    def test_the_reason_is_normalised_identically_in_both(self, store):
        post_override(store, reason="   演習期間中の暫定   ")
        row = store.command_records(action=S.CONFIG_OVERRIDE)[0]
        assert row["reason"] == "演習期間中の暫定"
        assert row["after"]["override"]["reason"] == row["reason"]

    def test_the_actor_on_the_row_is_the_actor_in_the_state(self, store):
        post_override(store)
        row = store.command_records(action=S.CONFIG_OVERRIDE)[0]
        assert row["after"]["override"]["actor_id"] == row["actor_id"]
        assert row["after"]["override"]["at"] == row["issued_at"]
