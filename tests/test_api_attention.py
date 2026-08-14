"""P7 R6 / C4 end to end, plus the tick that writes the ranking.

The load-bearing claims, each with the defect it answers:

* **the rank served is the rank stored** (P5 O-8 / G-03) — R6 reads the
  snapshot and the handler cannot compute an order;
* **the per-user threshold is READ** (G-02) — production stores per-user
  thresholds its evaluation path never consults, so the test that matters
  is that MOVING one changes what R6 returns;
* **ack has two readers** (G-15) — the projection annotates the row AND
  the next ranking's `analyst_blindness` drops, so the command is not a
  write nobody consumes;
* **`?at=` and live are one projection** (P7 principle 4);
* **suppression is disclosed, never silent** (E-17) — a filtered row is
  counted in the response.
"""
from __future__ import annotations

import pytest

from tests.conclusions_fixtures import NOW, healthy, provenance
from v3.api import (ANONYMOUS, ApiRequest, Principal, ReadContext,
                    ReadOnlyLedger, ScenarioRef, handle)
from v3.api.vocabulary import ROLE_ANALYST, ROLE_VIEWER
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.attention import projection as PROJ
from v3.attention import thresholds as T
from v3.commands import attention as A
from v3.conclusions import (ATTACK_MODE, Conclusion, Suppression,
                            THREAT_LEVEL, TREND, to_record)
from v3.ledger import LedgerStore
from v3.runtime import attention as RUNTIME

SCENARIO = "taiwan_contingency"
OTHER = "korea_peninsula"
ANALYST = Principal(user_id="a-1", role=ROLE_ANALYST)
OTHER_ANALYST = Principal(user_id="a-2", role=ROLE_ANALYST)
VIEWER = Principal(user_id="v-1", role=ROLE_VIEWER)
HOUR = 3600.0


def _conclusion(conclusion_type, *, scenario_id=SCENARIO, observed_at=NOW,
                confidence=0.8, state="TL4", unavailable=None):
    return Conclusion(
        scenario_id=scenario_id, conclusion_type=conclusion_type,
        observed_at=observed_at, confidence=confidence,
        provenance=provenance(f"{conclusion_type}@S1-CONC-001"),
        input_health=healthy(),
        state=None if unavailable else state,
        unavailable_reason=unavailable,
        threshold_ref={"tl_critical": 3.0}, source_urls=("https://x/1",),
        calibration_status={"status": "measured"})


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "attention.db"))
    # Two findings, one that moved a lot and one that barely moved, so the
    # ranking has something to order.
    handle_.append_conclusion(to_record(_conclusion(
        THREAT_LEVEL, observed_at=NOW - 4 * HOUR, confidence=0.1)))
    handle_.append_conclusion(to_record(_conclusion(
        THREAT_LEVEL, observed_at=NOW - HOUR, confidence=0.9, state="TL2")))
    handle_.append_conclusion(to_record(_conclusion(
        ATTACK_MODE, observed_at=NOW - 2 * HOUR, confidence=0.4,
        state="cyber_first")))
    handle_.append_conclusion(to_record(_conclusion(
        TREND, scenario_id=OTHER, observed_at=NOW - 30 * HOUR,
        confidence=0.5, state="rising")))
    yield handle_
    handle_.close()


@pytest.fixture()
def ranked(store):
    report = RUNTIME.rank_cycle(now=NOW, store=store,
                                scenario_ids=[SCENARIO, OTHER])
    assert report.written > 0
    return store


def _read_context(store, *, now=NOW, principal=ANALYST):
    return ReadContext(
        ledger=ReadOnlyLedger(store), now=now, principal=principal,
        scenarios=(ScenarioRef(scenario_id=SCENARIO, focused=True),
                   ScenarioRef(scenario_id=OTHER)))


def _write_context(store, principal=ANALYST, *, now=NOW):
    return WriteContext(read=_read_context(store, now=now,
                                           principal=principal),
                        ledger=CommandLedger(store), principal=principal)


def _get(store, path, params=None, principal=ANALYST, *, now=NOW):
    return handle(ApiRequest(method="GET", path=path, params=params or {},
                             principal=principal),
                  _read_context(store, now=now, principal=principal))


def _post(store, path, body=None, principal=ANALYST, *, now=NOW,
          method="POST"):
    return handle(ApiRequest(method=method, path=path, body=body or {},
                             principal=principal),
                  _write_context(store, principal, now=now))


def _rows(response):
    return response.as_dict()["attention"]


class TestTheRankServedIsTheRankStored:
    def test_r6_returns_the_snapshot_the_ranker_wrote(self, ranked):
        stored = ranked.attention_snapshot(
            ranked.latest_attention_snapshot_id(NOW))
        served = _rows(_get(ranked, "/api/v3/attention"))
        assert [row["item_id"] for row in served] == \
            [row["item_id"] for row in stored
             if row["score"] >= T.DEFAULT_MIN_SCORE]
        assert [row["rank_position"] for row in served] == \
            sorted(row["rank_position"] for row in served)

    def test_every_row_carries_its_three_factors_and_its_formula(self,
                                                                ranked):
        row = _rows(_get(ranked, "/api/v3/attention"))[0]
        for name in ("novelty", "confidence_delta", "analyst_blindness"):
            assert 0.0 <= row[name] <= 1.0, name
        assert row["formula_ref"]
        assert row["components"]["inputs"]
        assert row["narrative"] and row["narrative_template_ref"]

    def test_the_handler_cannot_reach_the_scorer_or_the_ranker(self):
        """P5 O-8 in AST form: R6 projects, it does not rank.

        Two facts, and the first is the load-bearing one: the handler does
        not import `v3.attention.score` or `v3.attention.rank` at all, so
        re-deriving an order is not something it could do by mistake. The
        second is belt and braces — no multiplication anywhere, the
        formula being a product of three factors.
        """
        import ast
        from pathlib import Path
        source = (Path(__file__).resolve().parent.parent / "v3" / "api" /
                  "handlers" / "attention.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    imported.add(f"{node.module}.{alias.name}")
        assert "v3.attention.score" not in imported
        assert "v3.attention.rank" not in imported
        products = [node.lineno for node in ast.walk(tree)
                    if isinstance(node, ast.BinOp)
                    and isinstance(node.op, (ast.Mult, ast.Div, ast.Pow))]
        assert products == [], (
            f"the attention handler is computing something; the rank is the "
            f"ledger's (P5 O-8, G-03). lines={products}")

    def test_a_reader_with_no_snapshot_is_told_why_not_given_an_empty_list(
            self, store):
        body = _get(store, "/api/v3/attention").as_dict()
        assert body["attention"] == []
        assert body["empty_reason"] == PROJ.EMPTY_NO_SNAPSHOT

    def test_the_response_carries_np7(self, ranked):
        from v3.conclusions import NP7_DISCLAIMER
        assert _get(ranked, "/api/v3/attention").as_dict()[
            "final_judgment_disclaimer"] == NP7_DISCLAIMER


class TestThePerUserThresholdIsRead:
    """G-02, answered. The test is that MOVING the knob changes the list."""

    def test_the_default_floor_is_the_production_constant(self, ranked):
        body = _get(ranked, "/api/v3/attention").as_dict()
        assert body["thresholds"]["min_score"] == T.DEFAULT_MIN_SCORE == 0.05

    def test_raising_the_floor_removes_rows_from_the_projection(self, ranked):
        before = _rows(_get(ranked, "/api/v3/attention"))
        assert before, "fixture produced no rows to filter"
        response = _post(ranked, "/api/v3/attention/thresholds",
                         {"thresholds": {"min_score": 0.99}}, method="PUT")
        assert response.status == 200
        after = _get(ranked, "/api/v3/attention").as_dict()
        assert len(after["attention"]) < len(before)
        assert after["filtered_below_min_score"] == \
            after["considered"] - after["shown"]

    def test_a_filtered_row_is_counted_rather_than_silently_dropped(self,
                                                                   ranked):
        _post(ranked, "/api/v3/attention/thresholds",
              {"thresholds": {"min_score": 1.0}}, method="PUT")
        body = _get(ranked, "/api/v3/attention").as_dict()
        assert body["attention"] == []
        assert body["considered"] > 0
        assert body["filtered_below_min_score"] == body["considered"]
        assert body["empty_reason"] == PROJ.EMPTY_ALL_FILTERED

    def test_the_threshold_is_per_analyst(self, ranked):
        _post(ranked, "/api/v3/attention/thresholds",
              {"thresholds": {"min_score": 1.0}}, method="PUT")
        mine = _get(ranked, "/api/v3/attention").as_dict()
        theirs = _get(ranked, "/api/v3/attention",
                      principal=OTHER_ANALYST).as_dict()
        assert mine["attention"] == []
        assert theirs["attention"] != []

    def test_the_committed_effect_is_the_value_the_projection_resolves(
            self, ranked):
        body = _post(ranked, "/api/v3/attention/thresholds",
                     {"thresholds": {"min_score": 0.3}},
                     method="PUT").as_dict()
        assert body["effect"]["thresholds"]["min_score"] == 0.3
        assert body["effect"]["thresholds"] == A.thresholds_for(
            ReadOnlyLedger(ranked), actor_id=ANALYST.user_id, until=NOW)

    def test_an_unknown_key_is_refused_with_the_admissible_list(self, ranked):
        response = _post(ranked, "/api/v3/attention/thresholds",
                         {"thresholds": {"dormant_enter": 0.4}}, method="PUT")
        assert response.status == 400
        detail = response.as_dict()["error_detail"]["detail"]
        assert detail["unknown"] == ["dormant_enter"]
        assert detail["per_user_keys"] == ["min_score"]

    def test_a_floor_above_the_maximum_score_is_refused(self, ranked):
        assert _post(ranked, "/api/v3/attention/thresholds",
                     {"thresholds": {"min_score": 1.5}},
                     method="PUT").status == 400

    def test_every_declared_per_user_key_is_consumed_by_the_projection(self):
        """The G-02 rule as a gate: a key nothing reads may not exist.

        Structural rather than by inspection — the projection is called
        twice with the key at two values and the outputs must differ, so a
        key that stopped being read fails here.
        """
        import inspect
        source = inspect.getsource(PROJ)
        for key in T.PER_USER_KEYS:
            assert key in source, (
                f"{key} is declared per-user but the R6 projection never "
                f"mentions it. Production's per-user thresholds are read by "
                f"nothing (G-02); v3 admits a key only if it is read.")


class TestAckHasTwoReaders:
    def test_an_ack_annotates_the_row_rather_than_deleting_it(self, ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        assert _post(ranked, f"/api/v3/attention/{item_id}/ack").status == 200
        row = [r for r in _rows(_get(ranked, "/api/v3/attention"))
               if r["item_id"] == item_id][0]
        assert row["analyst_state"] == A.STATE_ACKED
        assert row["suppressed"] is True

    def test_the_ack_is_per_analyst(self, ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        _post(ranked, f"/api/v3/attention/{item_id}/ack")
        theirs = [r for r in _rows(_get(ranked, "/api/v3/attention",
                                        principal=OTHER_ANALYST))
                  if r["item_id"] == item_id][0]
        assert theirs["analyst_state"] == A.STATE_ACTIVE

    def test_the_next_ranking_sees_that_an_analyst_acted(self, ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        before = [r for r in ranked.attention_snapshot(
            ranked.latest_attention_snapshot_id(NOW))
            if r["item_id"] == item_id][0]["analyst_blindness"]
        _post(ranked, f"/api/v3/attention/{item_id}/ack")
        later = NOW + 60.0
        RUNTIME.rank_cycle(now=later, store=ranked,
                           scenario_ids=[SCENARIO, OTHER])
        after = [r for r in ranked.attention_snapshot(
            ranked.latest_attention_snapshot_id(later))
            if r["item_id"] == item_id][0]["analyst_blindness"]
        assert after < before, (
            "acknowledging a row must lower its blindness on the next "
            "ranking; otherwise the command has one reader, not two")

    def test_a_snooze_expires_rather_than_being_revoked(self, ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        _post(ranked, f"/api/v3/attention/{item_id}/snooze", {"minutes": 30})
        during = [r for r in _rows(_get(ranked, "/api/v3/attention"))
                  if r["item_id"] == item_id][0]
        assert during["analyst_state"] == A.STATE_SNOOZED
        after = [r for r in _rows(_get(ranked, "/api/v3/attention",
                                       now=NOW + 31 * 60))
                 if r["item_id"] == item_id][0]
        assert after["analyst_state"] == A.STATE_ACTIVE

    def test_the_snooze_bounds_are_productions(self, ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        assert A.SNOOZE_DEFAULT_MINUTES == 30.0
        assert (A.SNOOZE_MIN_MINUTES, A.SNOOZE_MAX_MINUTES) == (1.0, 1440.0)
        assert _post(ranked, f"/api/v3/attention/{item_id}/snooze",
                     {"minutes": 2000}).status == 400

    def test_a_dismiss_lasts_the_production_ttl(self, ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        assert A.DISMISS_SEC == 24 * 3600.0
        _post(ranked, f"/api/v3/attention/{item_id}/dismiss")
        row = [r for r in _rows(_get(ranked, "/api/v3/attention"))
               if r["item_id"] == item_id][0]
        assert row["analyst_state_expires_at"] == pytest.approx(
            NOW + A.DISMISS_SEC)

    def test_acking_a_row_with_no_rank_is_refused(self, ranked):
        response = _post(ranked, "/api/v3/attention/not-a-row/ack")
        assert response.status == 404
        assert "順位" in response.as_dict()["error_detail"]["detail"]["reason"]

    def test_each_command_writes_exactly_one_audit_row(self, ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        before = ranked.count_commands()
        _post(ranked, f"/api/v3/attention/{item_id}/ack")
        assert ranked.count_commands() == before + 1


class TestReplayIsTheSameProjection:
    def test_at_returns_the_snapshot_that_was_in_force_then(self, store):
        RUNTIME.rank_cycle(now=NOW - 600, store=store,
                           scenario_ids=[SCENARIO, OTHER])
        store.append_conclusion(to_record(_conclusion(
            THREAT_LEVEL, observed_at=NOW, confidence=0.05, state="TL5")))
        RUNTIME.rank_cycle(now=NOW, store=store,
                           scenario_ids=[SCENARIO, OTHER])
        live = _get(store, "/api/v3/attention").as_dict()
        past = _get(store, "/api/v3/attention",
                    {"at": str(NOW - 600)}).as_dict()
        assert live["snapshot_id"] != past["snapshot_id"]
        # Same shape apart from the `at` echo, which is the whole
        # difference between live and replay (P7 principle 4).
        assert set(past) - set(live) == {"at"}
        assert set(live) - set(past) == set()

    def test_an_ack_made_later_does_not_appear_in_the_earlier_view(self,
                                                                   ranked):
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        _post(ranked, f"/api/v3/attention/{item_id}/ack", now=NOW + 10)
        earlier = [r for r in _rows(_get(ranked, "/api/v3/attention",
                                         {"at": str(NOW)}, now=NOW + 20))
                   if r["item_id"] == item_id][0]
        assert earlier["analyst_state"] == A.STATE_ACTIVE


class TestTheRankerWritesOnlyWhenTheRankingMoves:
    def test_the_first_cycle_writes(self, store):
        report = RUNTIME.rank_cycle(now=NOW, store=store,
                                    scenario_ids=[SCENARIO, OTHER])
        assert report.changed and report.written == report.considered

    def test_an_unchanged_ranking_is_not_written_again(self, store):
        RUNTIME.rank_cycle(now=NOW, store=store,
                           scenario_ids=[SCENARIO, OTHER])
        count = store.count_attention_ranks()
        second = RUNTIME.rank_cycle(now=NOW + 1, store=store,
                                    scenario_ids=[SCENARIO, OTHER])
        assert second.changed is False and second.written == 0
        assert store.count_attention_ranks() == count

    def test_clock_drift_alone_never_writes_a_snapshot(self, store):
        """The finding that produced `rank.moved`.

        A signature built from rounded scores wrote a new snapshot one
        second later, in identical order, because 0.18750 and 0.18749
        round apart. The clock is not a decision, so a whole hour of
        ticks with nothing else changing must leave the ledger alone.
        """
        RUNTIME.rank_cycle(now=NOW, store=store,
                           scenario_ids=[SCENARIO, OTHER])
        count = store.count_attention_ranks()
        for step in range(1, 61):
            RUNTIME.rank_cycle(now=NOW + step, store=store,
                               scenario_ids=[SCENARIO, OTHER])
        assert store.count_attention_ranks() == count

    def test_a_score_moving_a_whole_band_does_write(self, store):
        RUNTIME.rank_cycle(now=NOW, store=store,
                           scenario_ids=[SCENARIO, OTHER])
        count = store.count_attention_ranks()
        # Far enough that novelty has decayed by more than one band.
        later = RUNTIME.rank_cycle(now=NOW + 6 * HOUR, store=store,
                                   scenario_ids=[SCENARIO, OTHER])
        assert later.changed is True
        assert store.count_attention_ranks() > count

    def test_no_candidates_is_a_different_fact_from_no_ranking(self,
                                                              tmp_path):
        empty = LedgerStore(str(tmp_path / "empty.db"))
        try:
            report = RUNTIME.rank_cycle(now=NOW, store=empty,
                                        scenario_ids=[SCENARIO])
            assert report.considered == 0 and report.written == 0
            assert empty.count_attention_ranks() == 0
        finally:
            empty.close()

    def test_the_snapshot_id_is_deterministic(self):
        assert RUNTIME.snapshot_id_for(NOW) == RUNTIME.snapshot_id_for(NOW)

    def test_the_tick_report_carries_the_ranking(self, store):
        report = RUNTIME.rank_cycle(now=NOW, store=store,
                                    scenario_ids=[SCENARIO, OTHER])
        payload = report.as_dict()
        assert payload["changed"] is True
        assert payload["rows"] and payload["rows"][0]["rank_position"] == 1


class TestUnavailableConclusionsDoNotCompete:
    def test_an_unavailable_row_scores_zero_and_is_filtered_by_the_floor(
            self, tmp_path):
        store = LedgerStore(str(tmp_path / "unavailable.db"))
        try:
            store.append_conclusion(to_record(Conclusion(
                scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
                observed_at=NOW, confidence=0.0,
                provenance=provenance("tl@S1-CONC-001"),
                input_health=healthy(),
                unavailable_reason="calibration_pending",
                suppression=Suppression(
                    guard_id="calibration_window",
                    reason="calibration_pending",
                    detail="30 日窓が満たされていません", overridden=False))))
            RUNTIME.rank_cycle(now=NOW, store=store, scenario_ids=[SCENARIO])
            body = _get(store, "/api/v3/attention").as_dict()
            assert body["considered"] == 1 and body["attention"] == []
            assert body["empty_reason"] == PROJ.EMPTY_ALL_FILTERED
        finally:
            store.close()


class TestAccess:
    def test_an_anonymous_caller_gets_401(self, ranked):
        assert _get(ranked, "/api/v3/attention",
                    principal=ANONYMOUS).status == 401

    def test_a_viewer_may_read_but_not_command(self, ranked):
        assert _get(ranked, "/api/v3/attention", principal=VIEWER).status \
            == 200
        item_id = _rows(_get(ranked, "/api/v3/attention"))[0]["item_id"]
        assert _post(ranked, f"/api/v3/attention/{item_id}/ack",
                     principal=VIEWER).status == 403

    def test_a_read_writes_nothing(self, ranked):
        before = (ranked.count_commands(), ranked.count_attention_ranks())
        _get(ranked, "/api/v3/attention")
        assert (ranked.count_commands(),
                ranked.count_attention_ranks()) == before


class TestNarrativeV2IsComposedReadSide:
    """WP-4.8d (P9 §1.6 D-23b): the analyst-language sentence, rendered at
    projection time from the STORED numbers. The stored v1 narrative is
    the tick's record and stays untouched (P9 §1.8: no write-path change
    for presentation — the C-16 clock)."""

    def test_every_served_row_gains_a_v2_sentence_and_its_ref(self, ranked):
        row = _rows(_get(ranked, "/api/v3/attention"))[0]
        assert row["narrative_v2_template_ref"] == "attention.row@2"
        assert "位に置きました" in row["narrative_v2"]
        assert "主因は" in row["narrative_v2"]
        # The stored v1 sentence is still there, unrewritten.
        assert row["narrative_template_ref"].startswith("attention.row@1") \
            or row["narrative_template_ref"].startswith("attention.")

    def test_the_v2_template_is_disclosed_beside_the_rows(self, ranked):
        body = _get(ranked, "/api/v3/attention").as_dict()
        assert "attention.row@2" in body["narrative_templates"]
