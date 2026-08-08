"""WP-4.1c — the write seam, property by property.

Each class below corresponds to one of the four properties the seam
claims, and every test is written so that it fails if the property became
conventional rather than structural. Where a claim is about the shape of
the code (what a method writes, what a dataclass carries), the test reads
the source by AST rather than trusting a docstring — the same discipline
WP-2.6 adopted after finding 97 transcription infidelities in constants
that looked correctly copied.

The defects being answered, in one line each:

    G-01  one endpoint of four forgot the authorization call
    E-17  a guard suppressed a conclusion and left no trace
    G-15  a change was recorded, displayed, and read by nothing
"""
from __future__ import annotations

import ast
import json
import sqlite3
from dataclasses import fields
from pathlib import Path

import pytest

from v3.api import errors as E
from v3.api.readonly import READ_METHODS, ReadOnlyLedger, WRITE_METHODS
from v3.api.request import ANONYMOUS, Principal, ReadContext, ScenarioRef
from v3.api.write import Change, CommandJournal, WriteContext
from v3.api.writeonly import (COMMAND_METHODS, COMMAND_TABLE, CommandLedger,
                              audit_command_writes)
from v3.commands import spec as SPEC
from v3.commands import state as S
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.ledger.records import CommandRecord

REPO_ROOT = Path(__file__).resolve().parent.parent
NOW = 1_760_000_000.0
SCENARIO = "taiwan_contingency"


@pytest.fixture()
def store(tmp_path):
    handle = LedgerStore(str(tmp_path / "seam.db"))
    yield handle
    handle.close()


def build_context(store, *, now: float = NOW,
                  role: str = "analyst", user: str = "u-1",
                  body: dict | None = None) -> WriteContext:
    read = ReadContext(ledger=ReadOnlyLedger(store), now=now,
                       scenarios=(ScenarioRef(scenario_id=SCENARIO),))
    return WriteContext(read=read, ledger=CommandLedger(store),
                        principal=Principal(user_id=user, role=role),
                        body=dict(body or {}))


class TestTheDoorIsOne:
    """Property 2, first half: there is one writer and it is audited."""

    def test_the_command_ledger_forwards_exactly_one_method(self):
        assert COMMAND_METHODS == frozenset({"append_command"})

    def test_every_other_store_method_is_unreachable(self, store):
        seam = CommandLedger(store)
        for name in sorted(WRITE_METHODS | READ_METHODS):
            if name in COMMAND_METHODS:
                assert callable(getattr(seam, name))
                continue
            with pytest.raises(AttributeError) as excinfo:
                getattr(seam, name)
            assert "G-15" in str(excinfo.value)

    def test_the_seam_cannot_be_given_a_second_writer(self, store):
        seam = CommandLedger(store)
        with pytest.raises(DomainError):
            seam.append_conclusion = store.append_conclusion

    def test_ast_proves_the_forwarded_method_writes_only_that_table(self):
        report = audit_command_writes()
        assert report["extra_tables"] == [], (
            "append_command gained a second table; the one audited door "
            "now leads to a room nothing folds")

    def test_ast_proves_nothing_else_writes_the_command_table(self):
        report = audit_command_writes()
        assert report["writers"] == sorted(COMMAND_METHODS), (
            f"{COMMAND_TABLE} is written by {report['writers']}; a decision "
            f"trail with a second author cannot be trusted to be complete")

    def test_the_two_ledger_faces_stay_disjoint(self):
        assert "append_command" in WRITE_METHODS
        assert "append_command" not in READ_METHODS
        assert "command_records" in READ_METHODS


class TestTheHandlerCannotForgeAnActor:
    """Property 1: the principal arrives resolved and is not restatable."""

    def test_a_change_carries_no_actor_field(self):
        names = {item.name for item in fields(Change)}
        assert names == {"action", "target", "payload", "reason"}, (
            "a handler must have nothing to record an actor WITH; that is "
            "what makes forging one impossible rather than forbidden")

    def test_the_stored_actor_is_the_contexts_principal(self, store):
        context = build_context(store, user="analyst-7")
        committed = context.commit(Change(
            action=S.FOCUS_SET,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        assert committed.record.actor_id == "analyst-7"
        assert committed.record.actor_role == "analyst"

    def test_a_payload_cannot_supply_the_actor(self, store):
        """The submitted document is recorded verbatim — and ignored when
        the row's actor is written. Anything else would let the client
        choose whose label entered the calibration chain."""
        context = build_context(store, user="real-1")
        committed = context.commit(Change(
            action=S.GROUND_TRUTH_ASSERT,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO),
            payload={"actor": "someone-else", "actor_id": "someone-else",
                     "observed_at": NOW - 5, "source_url": "https://x/9",
                     "description": "d"},
            reason="r"))
        assert committed.record.actor_id == "real-1"
        row = store.command_records(action=S.GROUND_TRUTH_ASSERT)[-1]
        assert row["actor_id"] == "real-1"
        assert row["after"][0]["asserted_by"] == "real-1"
        # The claim IS kept, in the payload, where it is evidence about
        # the request rather than an identity the tool acted on.
        assert row["payload"]["actor"] == "someone-else"

    def test_an_anonymous_caller_cannot_hold_a_write_context(self, store):
        read = ReadContext(ledger=ReadOnlyLedger(store), now=NOW)
        with pytest.raises(DomainError) as excinfo:
            WriteContext(read=read, ledger=CommandLedger(store),
                         principal=ANONYMOUS)
        assert "AP4" in str(excinfo.value)

    def test_no_command_handler_names_the_actor_resolution(self):
        # The sibling of tests/test_api_authorization.py's scan, aimed at
        # the write path: a command handler that reached for the principal
        # could start deciding with it.
        source = (REPO_ROOT / "v3" / "api" / "handlers"
                  / "commands.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr != "principal", node.lineno


class TestTheAuditRowIsTheChange:
    """Property 2, second half, and E-17's answer."""

    def test_the_row_records_actor_action_before_after_and_reason(self,
                                                                  store):
        context = build_context(store)
        committed = context.commit(Change(
            action=S.GROUND_TRUTH_ASSERT,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO),
            payload={"observed_at": NOW - 100, "source_url": "https://x/1",
                     "description": "港湾封鎖"},
            reason="現地報道 2 系統で確認"))
        row = committed.record.as_dict()
        for key in ("actor_id", "actor_role", "action", "target_kind",
                    "target_id", "issued_at", "before", "after", "reason"):
            assert key in row, key
        assert row["before"] == []
        assert row["after"][0]["description"] == "港湾封鎖"
        assert row["reason"] == "現地報道 2 系統で確認"

    def test_a_reason_is_required_where_the_action_requires_one(self, store):
        context = build_context(store)
        with pytest.raises(E.ApiFailure) as excinfo:
            context.commit(Change(
                action=S.CONCLUSION_LABEL,
                target=SPEC.Target(kind=S.TARGET_CONCLUSION, id="c-1"),
                payload={"label": "TRUE_POSITIVE"}))
        assert excinfo.value.status == 400

    def test_a_blank_reason_is_not_a_reason(self, store):
        context = build_context(store)
        with pytest.raises(E.ApiFailure):
            context.commit(Change(
                action=S.CONCLUSION_LABEL,
                target=SPEC.Target(kind=S.TARGET_CONCLUSION, id="c-1"),
                payload={"label": "TRUE_POSITIVE"}, reason="   "))

    def test_the_row_cannot_be_edited_afterwards(self, store):
        build_context(store).commit(Change(
            action=S.FOCUS_SET,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        with pytest.raises(sqlite3.DatabaseError) as excinfo:
            with store.transaction() as conn:
                conn.execute("UPDATE command_record SET actor_id = 'x'")
        assert "append-only" in str(excinfo.value)

    def test_the_row_cannot_be_deleted_even_by_the_prune_gate(self, store):
        build_context(store).commit(Change(
            action=S.FOCUS_SET,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        with pytest.raises(sqlite3.DatabaseError):
            with store.transaction() as conn:
                store._set_prune_flag(conn, True)
                conn.execute("DELETE FROM command_record")
        assert store.count_commands() == 1

    def test_retention_never_expires_a_decision(self, store):
        build_context(store).commit(Change(
            action=S.FOCUS_SET,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        store.prune_expired(now=NOW + 86400.0 * 4000)
        assert store.count_commands() == 1


class TestOneProjectionOnly:
    """Property 3: a command cannot write against a state it invented."""

    def test_the_commands_reads_go_through_the_read_seam(self, store):
        context = build_context(store)
        assert isinstance(context.read.ledger, ReadOnlyLedger)
        with pytest.raises(AttributeError):
            context.read.ledger.append_conclusion

    def test_a_write_context_refuses_a_raw_store_for_reading(self, store):
        with pytest.raises(DomainError):
            WriteContext(read=store, ledger=CommandLedger(store),
                         principal=Principal(user_id="u", role="analyst"))

    def test_a_write_context_refuses_a_raw_store_for_writing(self, store):
        read = ReadContext(ledger=ReadOnlyLedger(store), now=NOW)
        with pytest.raises(DomainError) as excinfo:
            WriteContext(read=read, ledger=store,
                         principal=Principal(user_id="u", role="analyst"))
        assert "G-15" in str(excinfo.value)

    def test_the_resolver_used_by_the_command_is_the_one_the_api_serves(self):
        # Not "they agree" — the same function object. Two functions that
        # agree today are the shape G-15 took: a registry and a reader
        # that agreed until one of them was edited.
        assert SPEC.spec_for(S.FOCUS_SET).resolve is S.resolve_focus
        assert SPEC.spec_for(S.CONCLUSION_LABEL).resolve is S.resolve_labels
        from v3.api.handlers import conclusions as H_conclusions
        from v3.api.handlers import scenarios as H_scenarios
        assert H_scenarios.focus_state is S.focus_state
        assert H_conclusions.labels_for is S.labels_for

    def test_the_fold_equals_a_replay_of_every_row(self, store):
        """The state is the last row's `after` — and that is only true if
        every row came through `commit()`. Replaying each row through its
        own `apply` and comparing is how a row written any other way would
        be caught."""
        context = build_context(store)
        for index, label in enumerate(("TRUE_POSITIVE", "FALSE_POSITIVE")):
            build_context(store, now=NOW + index, user=f"u-{index}").commit(
                Change(action=S.CONCLUSION_LABEL,
                       target=SPEC.Target(kind=S.TARGET_CONCLUSION,
                                          id="c-42"),
                       payload={"label": label}, reason="確認済"))
        rows = store.command_records(action=S.CONCLUSION_LABEL,
                                     target_id="c-42")
        replayed: dict = {}
        for row in rows:
            replayed = S.apply_label(replayed, target_id="c-42",
                                     payload=row["payload"],
                                     actor_id=row["actor_id"],
                                     at=row["issued_at"])
        assert replayed == S.labels_for(context.read.ledger, "c-42")


class TestTheClaimedEffectIsVerified:
    """Property 4 — G-15's answer, and the mutation test that proves it."""

    def test_the_response_states_the_read_back_value(self, store):
        context = build_context(store)
        committed = context.commit(Change(
            action=S.FOCUS_SET,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        assert committed.effective == SCENARIO
        assert committed.effective == S.focus_state(context.read.ledger)

    def test_a_write_the_read_path_does_not_show_is_refused(self, store,
                                                            monkeypatch):
        """The mutation: make the resolver blind to what was just written,
        exactly as G-15's resolution chain was blind to its override rows.
        The command must fail rather than report success."""
        context = build_context(store)
        truth = S.focus_state
        calls = {"n": 0}

        def blind(ledger, *, until=None):
            calls["n"] += 1
            # First call (computing `before`) tells the truth; the
            # read-back call returns the pre-change value, which is what a
            # resolution chain that ignores its own override rows does.
            return None if calls["n"] > 1 else truth(ledger, until=until)

        monkeypatch.setattr(S, "focus_state", blind)
        with pytest.raises(DomainError) as excinfo:
            context.commit(Change(
                action=S.FOCUS_SET,
                target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        assert "G-15" in str(excinfo.value)

    def test_the_effect_is_named_by_the_spec_not_by_the_handler(self):
        for spec in SPEC.SPECS:
            assert spec.effect_key.strip(), spec.action

    def test_ast_proves_the_reported_effect_is_read_back_after_the_append(
            self):
        """A behavioural test cannot separate "read back" from "echoed",
        because the seam refuses the only case where the two differ. So
        the ORDER is asserted on the source: resolve, append, resolve
        again, and report the second resolve. An edit that reported
        `after` instead would still pass every behavioural test and would
        have reintroduced exactly the thing G-15 was."""
        source = (REPO_ROOT / "v3" / "api" / "write.py").read_text(
            encoding="utf-8")
        tree = ast.parse(source)
        commit = next(node for node in ast.walk(tree)
                      if isinstance(node, ast.FunctionDef)
                      and node.name == "commit")
        appended_at = None
        resolved_after_append = None
        reported = None
        for node in ast.walk(commit):
            if isinstance(node, ast.Call) and isinstance(node.func,
                                                         ast.Attribute):
                if node.func.attr == "append_command":
                    appended_at = node.lineno
            if isinstance(node, ast.Assign) and node.targets:
                target = node.targets[0]
                if getattr(target, "id", None) == "effective":
                    resolved_after_append = node.lineno
                    assert isinstance(node.value, ast.Call)
                    assert node.value.func.attr == "_resolve"
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id == "Committed":
                for keyword in node.keywords:
                    if keyword.arg == "effective":
                        reported = getattr(keyword.value, "id", None)
        assert appended_at is not None, "commit no longer appends"
        assert resolved_after_append is not None
        assert resolved_after_append > appended_at, (
            "the effect is resolved BEFORE the append, so it cannot be "
            "evidence that the append took effect")
        assert reported == "effective", (
            f"the response reports {reported!r}; it must report the value "
            f"read back through the projection, never the computed one")


class TestTheClosedVocabulary:
    """A verb the registry does not declare is not a command."""

    def test_an_unregistered_action_is_refused(self, store):
        context = build_context(store)
        with pytest.raises(DomainError) as excinfo:
            context.commit(Change(
                action="focus.clear_everything",
                target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        assert "unknown command action" in str(excinfo.value)

    def test_an_action_cannot_act_on_the_wrong_target_kind(self, store):
        context = build_context(store)
        with pytest.raises(DomainError):
            context.commit(Change(
                action=S.FOCUS_SET,
                target=SPEC.Target(kind=S.TARGET_CONCLUSION, id="c-1")))

    def test_the_label_vocabulary_is_the_calibration_one(self):
        from v3.calibration.ground_truth import RULE_ORDER
        assert S.ANALYST_LABELS == frozenset(RULE_ORDER)

    def test_a_label_outside_the_vocabulary_is_refused(self, store):
        context = build_context(store)
        with pytest.raises(E.ApiFailure) as excinfo:
            context.commit(Change(
                action=S.CONCLUSION_LABEL,
                target=SPEC.Target(kind=S.TARGET_CONCLUSION, id="c-1"),
                payload={"label": "PROBABLY"}, reason="なんとなく"))
        assert excinfo.value.status == 400


class TestTheRecordIsStorable:
    """A record that cannot round-trip is a state that stops comparing."""

    def test_a_non_json_value_is_refused_at_construction(self):
        with pytest.raises(DomainError) as excinfo:
            CommandRecord(command_id="c", action="a", target_kind="scenario",
                          target_id="s", actor_id="u", actor_role="analyst",
                          issued_at=NOW, before=object(), after=None)
        assert "repeatable" in str(excinfo.value)

    def test_the_stored_row_round_trips(self, store):
        context = build_context(store)
        committed = context.commit(Change(
            action=S.GROUND_TRUTH_ASSERT,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO),
            payload={"observed_at": NOW - 10, "source_url": "https://x/2",
                     "description": "d"},
            reason="r"))
        row = store.command_records(action=S.GROUND_TRUTH_ASSERT)[-1]
        assert row["after"] == committed.record.after
        assert json.dumps(row, sort_keys=True)

    def test_replay_bounds_the_state_at_an_instant(self, store):
        build_context(store, now=NOW).commit(Change(
            action=S.FOCUS_SET,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        ledger = ReadOnlyLedger(store)
        assert S.focus_state(ledger, until=NOW - 1) is None
        assert S.focus_state(ledger, until=NOW) == SCENARIO


class TestTheJournalIsTheDispatchersNotTheHandlers:
    def test_a_fresh_journal_counts_nothing(self):
        assert len(CommandJournal()) == 0

    def test_each_commit_lands_in_the_journal(self, store):
        context = build_context(store)
        context.commit(Change(
            action=S.FOCUS_SET,
            target=SPEC.Target(kind=S.TARGET_SCENARIO, id=SCENARIO)))
        assert len(context.journal) == 1
