"""P7 R9 — one decision trail, five production surfaces absorbed.

Production answers "what changed on the 12th" from five endpoints with
five row shapes (`decisions/history`, `auto_judge/decisions`,
`config_audit`, `llm_routing/audit`, `llm_features/audit`), so the answers
cannot be merged. R9 is one projection over `command_record` plus the S8
rank snapshot — the automated judgement AP4 most needed and production
never stored at all (G-03).

The pinned properties: one shape for every row, `automated` as a FIELD
(production infers it from a marker string inside a text column —
ACCIDENTAL A9), a misspelt filter refused rather than answered with an
empty list, and no second table.
"""
from __future__ import annotations

import pytest

from tests.conclusions_fixtures import NOW, healthy, provenance
from v3.api import (ApiRequest, Principal, ReadContext, ReadOnlyLedger,
                    ScenarioRef, handle)
from v3.api.handlers import decisions as H
from v3.api.vocabulary import ROLE_ANALYST
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
from v3.ledger import LedgerStore
from v3.runtime import attention as RUNTIME

SCENARIO = "taiwan_contingency"
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)
OTHER_ANALYST = Principal(user_id="a-2", role=ROLE_ANALYST)
HOUR = 3600.0

_ROW_KEYS = {"decision_type", "id", "action", "target_id", "actor_id",
             "actor_role", "decided_at", "reason", "before", "after",
             "automated"}


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "decisions.db"))
    handle_.append_conclusion(to_record(Conclusion(
        scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
        observed_at=NOW - HOUR, confidence=0.7,
        provenance=provenance("tl@S1-CONC-001"), input_health=healthy(),
        state="TL3", threshold_ref={}, source_urls=(),
        calibration_status={})))
    RUNTIME.rank_cycle(now=NOW - 60, store=handle_,
                       scenario_ids=[SCENARIO])
    yield handle_
    handle_.close()


def _read_context(store, *, now=NOW, principal=ANALYST):
    return ReadContext(ledger=ReadOnlyLedger(store), now=now,
                       principal=principal,
                       scenarios=(ScenarioRef(scenario_id=SCENARIO),))


def _write_context(store, principal=ANALYST, *, now=NOW):
    return WriteContext(read=_read_context(store, now=now,
                                           principal=principal),
                        ledger=CommandLedger(store), principal=principal)


def _get(store, path, params=None, *, principal=ANALYST, now=NOW):
    return handle(ApiRequest(method="GET", path=path, params=params or {},
                             principal=principal),
                  _read_context(store, now=now, principal=principal))


def _post(store, path, body=None, *, principal=ANALYST, now=NOW):
    return handle(ApiRequest(method="POST", path=path, body=body or {},
                             principal=principal),
                  _write_context(store, principal, now=now))


@pytest.fixture()
def acted(store):
    _post(store, "/api/v3/focus", {"scenario_id": SCENARIO,
                                   "reason": "演習開始"})
    return store


class TestOneShapeForEveryDecision:
    def test_every_row_has_the_same_keys(self, acted):
        rows = _get(acted, "/api/v3/decisions").as_dict()["decisions"]
        assert rows, "the fixture produced no decisions"
        for row in rows:
            assert _ROW_KEYS <= set(row), sorted(_ROW_KEYS - set(row))

    def test_a_command_and_a_rank_snapshot_appear_in_one_list(self, acted):
        rows = _get(acted, "/api/v3/decisions").as_dict()["decisions"]
        kinds = {row["decision_type"] for row in rows}
        assert "scenario" in kinds
        assert H.TYPE_ATTENTION_RANK in kinds

    def test_automated_is_a_field_not_a_marker_string(self, acted):
        rows = _get(acted, "/api/v3/decisions").as_dict()["decisions"]
        by_kind = {row["decision_type"]: row for row in rows}
        assert by_kind["scenario"]["automated"] is False
        assert by_kind[H.TYPE_ATTENTION_RANK]["automated"] is True
        assert by_kind[H.TYPE_ATTENTION_RANK]["actor_id"] is None

    def test_newest_first(self, acted):
        rows = _get(acted, "/api/v3/decisions").as_dict()["decisions"]
        stamps = [row["decided_at"] for row in rows]
        assert stamps == sorted(stamps, reverse=True)

    def test_the_rank_row_carries_its_components_and_its_narrative(self,
                                                                   acted):
        row = [r for r in _get(acted, "/api/v3/decisions").as_dict()[
            "decisions"] if r["decision_type"] == H.TYPE_ATTENTION_RANK][0]
        assert row["components"]["novelty"] is not None
        assert row["formula_ref"] and row["narrative_template_ref"]
        assert row["reason"], "the narrative is the row's plain-language why"


class TestFiltering:
    def test_a_type_filter_narrows(self, acted):
        rows = _get(acted, "/api/v3/decisions",
                    {"type": "scenario"}).as_dict()["decisions"]
        assert rows and {r["decision_type"] for r in rows} == {"scenario"}

    def test_an_unknown_type_is_refused_rather_than_answered_empty(self,
                                                                   acted):
        response = _get(acted, "/api/v3/decisions", {"type": "llm_routing"})
        assert response.status == 400
        detail = response.as_dict()["error_detail"]["detail"]
        assert "llm_routing" not in detail["decision_types"]

    def test_an_actor_filter_excludes_the_automated_face(self, acted):
        rows = _get(acted, "/api/v3/decisions",
                    {"actor_id": ANALYST.user_id}).as_dict()["decisions"]
        assert rows
        assert all(row["automated"] is False for row in rows), (
            "asking what an analyst decided must not answer with what the "
            "tool decided")

    def test_an_actor_filter_can_come_back_empty_for_another_analyst(self,
                                                                     acted):
        rows = _get(acted, "/api/v3/decisions",
                    {"actor_id": OTHER_ANALYST.user_id}
                    ).as_dict()["decisions"]
        assert rows == []

    def test_the_limit_is_bounded(self, acted):
        assert _get(acted, "/api/v3/decisions",
                    {"limit": "99999"}).status == 400
        assert _get(acted, "/api/v3/decisions", {"limit": "0"}).status == 400
        assert _get(acted, "/api/v3/decisions", {"limit": "1"}
                    ).as_dict()["returned"] == 1

    def test_at_bounds_the_trail(self, acted):
        past = _get(acted, "/api/v3/decisions",
                    {"at": str(NOW - 3600)}).as_dict()["decisions"]
        assert all(row["decided_at"] <= NOW - 3600 for row in past)


class TestByIdAndTotality:
    def test_a_command_is_addressable_by_its_id(self, acted):
        rows = _get(acted, "/api/v3/decisions",
                    {"type": "scenario"}).as_dict()["decisions"]
        command_id = rows[0]["id"]
        body = _get(acted, f"/api/v3/decisions/{command_id}").as_dict()
        assert body["decision"]["command_id"] == command_id

    def test_an_unknown_id_is_404(self, acted):
        assert _get(acted, "/api/v3/decisions/nope").status == 404

    def test_the_declared_types_cover_every_command_target_kind(self):
        from v3.commands import spec as SPEC
        assert set(SPEC.TARGET_KINDS) <= set(H.DECISION_TYPES)

    def test_there_is_no_second_decision_table(self):
        """The registry's ruling: `command_record` already IS the ledger."""
        from v3.ledger.schema import PERSISTED_TABLES
        assert "decision" not in PERSISTED_TABLES
        assert "decisions" not in PERSISTED_TABLES

    def test_a_read_writes_nothing(self, acted):
        before = (acted.count_commands(), acted.count_attention_ranks())
        _get(acted, "/api/v3/decisions")
        assert (acted.count_commands(),
                acted.count_attention_ranks()) == before
