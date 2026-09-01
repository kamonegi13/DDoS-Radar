"""WP-4.1f — the S8 attention ledger: the score, the rank, the row.

G-03's finding was that `attention_score` existed ONLY in
`triage_score.js`: computed in a browser, from a `localStorage`
timestamp, discarded on the next poll. So AP4 could replay every automated
judgement except the one that decided what the analyst looked at first,
and P5 O-8 ruled the ranking into the backend with a ledger behind it.

What this file pins:

* the formula against the browser module, input by input — a SWEEP over
  the three factors' domains, because every time this programme ported
  production semantics by reading, the reading was wrong somewhere;
* that the components are stored, so a score is re-derivable from the row
  rather than only from a tool that is still running;
* that the ranking has a TOTAL order (production's tie-break was the
  order a browser happened to build an array in);
* that the snapshot is written when the ranking moves and not otherwise.
"""
from __future__ import annotations

import json
import math

import pytest

from v3.attention import narrative as N
from v3.attention import rank as RANK
from v3.attention import score as S
from v3.attention import supply as SUPPLY
from v3.attention import thresholds as T
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.ledger.records import ATTENTION_FACTORS, AttentionRankRecord

NOW = 1_760_000_000.0
HOUR = 3600.0


def _inputs(**kwargs) -> S.Inputs:
    base = {"item_kind": S.ITEM_CONCLUSION, "item_id": "c1",
            "scenario_id": "taiwan_contingency", "confidence": 0.8}
    base.update(kwargs)
    return S.Inputs(**base)


# ── the browser module, transcribed and swept ───────────────────────────
def _js_novelty(last_fire_ts, now):
    if last_fire_ts is None:
        return 1.0
    age = max(0.0, now - last_fire_ts)
    return max(0.0, min(1.0, 1.0 - age / (48 * 3600)))


def _js_conf_delta(conf, prev):
    clamped = max(0.0, min(1.0, conf))
    if prev is None:
        return clamped
    return max(0.0, min(1.0, abs(clamped - max(0.0, min(1.0, prev)))))


def _js_blindness(last_view_ts, now):
    if last_view_ts is None:
        return 1.0
    since = max(0.0, now - last_view_ts)
    return max(0.0, min(1.0, since / (6 * 3600)))


class TestTheFormulaMatchesTheBrowserModule:
    """`triage_score.js`, swept rather than spot-checked.

    WP-2.6's sweep of 34 adapters found 97 transcription infidelities in
    constants that looked correctly copied, so a formula ported by reading
    is a formula not yet verified. 3 x 11 x 13 x 13 = 5,577 points.
    """

    def test_the_horizons_are_the_module_constants(self):
        assert T.NOVELTY_HORIZON_SEC == 48 * 3600
        assert T.BLINDNESS_HORIZON_SEC == 6 * 3600
        assert T.MAX_SCORE == 1.0
        assert T.DEFAULT_MIN_SCORE == 0.05

    def test_the_three_factors_agree_across_their_domains(self):
        mismatches = []
        ages = [None] + [h * HOUR for h in
                         (0, 1, 6, 12, 24, 47, 48, 49, 96, 10_000)]
        confidences = [0.0, 0.05, 0.2, 0.5, 0.8, 1.0]
        previous = [None, 0.0, 0.1, 0.5, 0.8, 1.0, 0.95]
        idles = [None] + [h * HOUR for h in (0, 1, 3, 5.9, 6, 6.1, 24)]
        for age in ages:
            last_changed = None if age is None else NOW - age
            for confidence in confidences:
                for prev in previous:
                    for idle in idles:
                        last_action = None if idle is None else NOW - idle
                        got = S.score_for(_inputs(
                            last_changed_at=last_changed,
                            confidence=confidence,
                            previous_confidence=prev,
                            last_analyst_action_at=last_action), now=NOW)
                        want = (_js_novelty(last_changed, NOW)
                                * _js_conf_delta(confidence, prev)
                                * _js_blindness(last_action, NOW))
                        want = min(1.0, max(0.0, want))
                        if not math.isclose(got.score, want, abs_tol=1e-12):
                            mismatches.append(
                                (age, confidence, prev, idle, got.score, want))
        assert mismatches == [], mismatches[:5]

    def test_an_unavailable_conclusion_scores_zero_with_its_reason(self):
        provenance = S.score_for(
            _inputs(last_changed_at=NOW, confidence=1.0,
                    unavailable_reason="calibration_pending"), now=NOW)
        assert provenance.score == 0.0
        assert provenance.zero_reasons == (S.REASON_UNAVAILABLE,)

    def test_clamp_treats_a_non_number_as_zero_like_the_module_does(self):
        assert S.clamp01("0.5") == 0.0
        assert S.clamp01(float("nan")) == 0.0
        assert S.clamp01(float("inf")) == 0.0
        assert S.clamp01(True) == 0.0
        assert S.clamp01(-3) == 0.0
        assert S.clamp01(7) == 1.0

    def test_the_delta_is_absolute_so_a_collapse_also_asks_for_attention(self):
        rising = S.score_for(_inputs(confidence=0.9, previous_confidence=0.2,
                                     last_changed_at=NOW), now=NOW)
        falling = S.score_for(_inputs(confidence=0.2, previous_confidence=0.9,
                                      last_changed_at=NOW), now=NOW)
        assert rising.confidence_delta == falling.confidence_delta


class TestTheComponentsAreThePersistedRationale:
    def test_the_provenance_carries_the_inputs_not_only_the_factors(self):
        provenance = S.score_for(
            _inputs(last_changed_at=NOW - HOUR, previous_confidence=0.3,
                    last_analyst_action_at=NOW - 2 * HOUR), now=NOW)
        stated = provenance.inputs
        for key in ("last_changed_at", "confidence", "previous_confidence",
                    "last_analyst_action_at", "now"):
            assert key in stated, key
        assert set(provenance.horizons) == {
            "novelty_horizon_sec", "blindness_horizon_sec", "max_score"}

    def test_the_score_is_re_derivable_from_the_stored_row_alone(self):
        provenance = S.score_for(
            _inputs(last_changed_at=NOW - 5 * HOUR, confidence=0.7,
                    previous_confidence=0.2,
                    last_analyst_action_at=NOW - 3 * HOUR), now=NOW)
        stored = json.loads(json.dumps(provenance.as_dict()))
        replayed = S.score_for(_inputs(
            last_changed_at=stored["inputs"]["last_changed_at"],
            confidence=stored["inputs"]["confidence"],
            previous_confidence=stored["inputs"]["previous_confidence"],
            last_analyst_action_at=stored["inputs"][
                "last_analyst_action_at"]), now=stored["inputs"]["now"])
        assert replayed.as_dict() == stored

    def test_the_record_refuses_a_factor_outside_the_unit_interval(self):
        with pytest.raises(DomainError):
            AttentionRankRecord(
                snapshot_id="s1", computed_at=NOW, scenario_id="tw",
                item_kind="conclusion", item_id="c1", rank_position=1,
                score=0.5, novelty=1.4, confidence_delta=0.5,
                analyst_blindness=0.5, formula_ref="f",
                narrative_template_ref="t@1", narrative="n")

    def test_the_record_refuses_a_zero_rank(self):
        with pytest.raises(DomainError):
            AttentionRankRecord(
                snapshot_id="s1", computed_at=NOW, scenario_id="tw",
                item_kind="conclusion", item_id="c1", rank_position=0,
                score=0.5, novelty=0.5, confidence_delta=0.5,
                analyst_blindness=0.5, formula_ref="f",
                narrative_template_ref="t@1", narrative="n")

    def test_the_three_factor_names_are_spelled_once(self):
        assert ATTENTION_FACTORS == ("novelty", "confidence_delta",
                                     "analyst_blindness")
        for name in ATTENTION_FACTORS:
            assert hasattr(S.Provenance, "__slots__")
            assert name in S.Provenance.__slots__


class TestTheOrderIsTotalAndDeclared:
    def test_ranks_are_one_based_and_contiguous(self):
        ranked = RANK.rank(
            [_inputs(item_id=f"c{i}", confidence=0.1 * i,
                     last_changed_at=NOW) for i in range(1, 6)], now=NOW)
        assert [position for _, _, position in ranked] == [1, 2, 3, 4, 5]

    def test_higher_score_ranks_first(self):
        ranked = RANK.rank([
            _inputs(item_id="low", confidence=0.1, last_changed_at=NOW),
            _inputs(item_id="high", confidence=0.9, last_changed_at=NOW)],
            now=NOW)
        assert [inputs.item_id for inputs, _, _ in ranked] == ["high", "low"]

    def test_a_tie_is_broken_by_the_declared_hint_then_ids(self):
        """Production's tie-break was array insertion order, which a stored
        row cannot reproduce. Here it is data on the row."""
        ranked = RANK.rank([
            _inputs(item_id="b", confidence=0.5, last_changed_at=NOW,
                    context={RANK.ORDER_HINT: 2}),
            _inputs(item_id="a", confidence=0.5, last_changed_at=NOW,
                    context={RANK.ORDER_HINT: 1})], now=NOW)
        assert [inputs.item_id for inputs, _, _ in ranked] == ["a", "b"]

    def test_the_order_does_not_depend_on_input_order(self):
        items = [_inputs(item_id=name, confidence=conf, last_changed_at=NOW)
                 for name, conf in (("a", 0.4), ("b", 0.4), ("c", 0.9))]
        forward = [i.item_id for i, _, _ in RANK.rank(items, now=NOW)]
        backward = [i.item_id
                    for i, _, _ in RANK.rank(list(reversed(items)), now=NOW)]
        assert forward == backward

    def test_a_non_numeric_order_hint_is_refused(self):
        with pytest.raises(DomainError):
            RANK.rank([_inputs(context={RANK.ORDER_HINT: "first"})], now=NOW)


class TestTheNarrativeIsATemplate:
    def test_the_same_row_always_produces_the_same_sentence(self):
        inputs = _inputs(last_changed_at=NOW - HOUR, previous_confidence=0.2,
                         last_analyst_action_at=NOW - 4 * HOUR,
                         context={"conclusion_type": "threat_level"})
        provenance = S.score_for(inputs, now=NOW)
        first = N.render_row(inputs=inputs, provenance=provenance, rank=1)
        second = N.render_row(inputs=inputs, provenance=provenance, rank=1)
        assert first == second
        assert first[1] == "attention.row@1"

    def test_the_sentence_names_the_three_factors_and_the_score(self):
        inputs = _inputs(last_changed_at=NOW - HOUR, previous_confidence=0.2,
                         last_analyst_action_at=NOW - 4 * HOUR)
        text, _ = N.render_row(inputs=inputs,
                               provenance=S.score_for(inputs, now=NOW), rank=3)
        for token in ("novelty", "confidence_delta", "analyst_blindness",
                      "3 位"):
            assert token in text, token

    def test_a_zero_row_gets_the_reason_not_the_arithmetic(self):
        inputs = _inputs(unavailable_reason="calibration_pending")
        text, ref = N.render_row(inputs=inputs,
                                 provenance=S.score_for(inputs, now=NOW),
                                 rank=9)
        assert ref == "attention.silent@1"
        assert "結論不可" in text

    def test_a_template_with_no_slots_is_refused(self):
        with pytest.raises(DomainError):
            N.Template(template_id="x", version="1", text="固定文")

    def test_an_unfilled_slot_is_an_error_not_an_empty_string(self):
        template = N.Template(template_id="x", version="1", text="{a}{b}")
        with pytest.raises(DomainError):
            template.render({"a": 1})

    # ── WP-4.13a (P9 §1.13 D-28): the v4 sentence speaks a REASON ──────
    def _components(self, **extra_inputs):
        inputs = {"last_changed_at": NOW - 2 * HOUR, "confidence": 0.8,
                  "previous_confidence": 0.2,
                  "last_analyst_action_at": NOW - 3 * HOUR, "now": NOW}
        inputs.update(extra_inputs)
        return {"inputs": inputs,
                "horizons": {"blindness_horizon_sec": 6 * HOUR}}

    def test_v4_speaks_the_change_instant_when_the_basis_is_real(self):
        text, ref = N.render_row_v4(
            components=self._components(
                novelty_basis=N.NOVELTY_BASIS_STATE_CHANGE),
            scenario_label="台湾正面", subject="anomaly", rank=1,
            substance="検知源 check_host（US）")
        assert ref == "attention.row_changed@1"
        assert "理由:" in text
        assert "2.0 時間前に状態が変化し" in text
        assert "確度が 0.200 → 0.800 と動き" in text
        assert "3.0 時間続いているため" in text

    def test_v4_without_the_marker_does_not_claim_a_change(self):
        # A row scored before WP-4.11 carries a WRITE instant in
        # `last_changed_at`; calling it a state change would be a false
        # sentence, so the reason speaks only the two real factors.
        text, ref = N.render_row_v4(
            components=self._components(),
            scenario_label="台湾正面", subject="anomaly", rank=2,
            substance="検知源 check_host（US）")
        assert ref == "attention.row@4"
        assert "理由:" in text
        assert "状態が変化" not in text
        assert "確度が 0.200 → 0.800 と動き" in text

    def test_v4_with_the_marker_but_no_instant_falls_back(self):
        text, ref = N.render_row_v4(
            components=self._components(
                novelty_basis=N.NOVELTY_BASIS_STATE_CHANGE,
                last_changed_at=None),
            scenario_label="台湾正面", subject="anomaly", rank=1,
            substance="検知源 check_host（US）")
        assert ref == "attention.row@4"
        assert "状態が変化" not in text

    def test_the_v4_templates_are_disclosed(self):
        disclosed = N.disclosure()
        assert "attention.row@4" in disclosed
        assert "attention.row_changed@1" in disclosed
        # The superseded refs stay: a replay of an old row must still
        # find the words that were shown (AP4).
        assert "attention.row@3" in disclosed
        assert "attention.row@1" in disclosed


# ── the ledger ──────────────────────────────────────────────────────────
@pytest.fixture()
def store(tmp_path):
    handle = LedgerStore(str(tmp_path / "v3.db"))
    yield handle
    handle.close()


def _records(store, *, snapshot_id="attn-1", computed_at=NOW, count=3):
    items = [_inputs(item_id=f"c{i}", confidence=0.9 - 0.1 * i,
                     last_changed_at=computed_at)
             for i in range(count)]
    ranked = RANK.rank(items, now=computed_at)
    return RANK.records_for(ranked, snapshot_id=snapshot_id,
                            computed_at=computed_at)


class TestTheSnapshotIsWrittenWholeOrNotAtAll:
    def test_the_schema_version_carries_the_table(self, store):
        # v7 brought attention_rank; the exact-version pin follows the
        # schema forward (v8 = WP-0.4 v2's calibration_fn_draft +
        # calibration_run) so this test keeps failing loudly whenever a
        # migration lands without its version bump.
        from v3.ledger.schema import SCHEMA_VERSION
        assert store.schema_version() == SCHEMA_VERSION >= 7
        assert store.count_attention_ranks() == 0

    def test_a_snapshot_round_trips_with_its_components(self, store):
        records = _records(store)
        assert store.append_attention_snapshot(records, now=NOW) == 3
        rows = store.attention_snapshot("attn-1")
        assert [row["rank_position"] for row in rows] == [1, 2, 3]
        assert rows[0]["components"]["formula_ref"] == S.FORMULA_REF
        assert set(rows[0]["components"]) >= {"novelty", "confidence_delta",
                                              "analyst_blindness", "inputs"}

    def test_an_empty_snapshot_is_refused(self, store):
        with pytest.raises(DomainError):
            store.append_attention_snapshot([], now=NOW)

    def test_two_snapshots_in_one_call_are_refused(self, store):
        first = _records(store, snapshot_id="a", count=1)
        second = _records(store, snapshot_id="b", count=1)
        with pytest.raises(DomainError):
            store.append_attention_snapshot(first + second, now=NOW)

    def test_a_gap_in_the_ranks_is_refused(self, store):
        records = _records(store, count=3)
        with pytest.raises(DomainError):
            store.append_attention_snapshot(records[:1] + records[2:],
                                            now=NOW)

    def test_the_table_is_append_only(self, store):
        store.append_attention_snapshot(_records(store), now=NOW)
        with store.transaction() as conn:
            with pytest.raises(Exception):
                conn.execute("UPDATE attention_rank SET score = 0.0")
        with store.transaction() as conn:
            with pytest.raises(Exception):
                conn.execute("DELETE FROM attention_rank")

    def test_re_writing_the_same_snapshot_is_a_no_op(self, store):
        records = _records(store)
        store.append_attention_snapshot(records, now=NOW)
        assert store.append_attention_snapshot(records, now=NOW) == 0
        assert store.count_attention_ranks() == 3

    def test_the_snapshot_for_an_instant_is_the_newest_at_or_before_it(
            self, store):
        store.append_attention_snapshot(
            _records(store, snapshot_id="old", computed_at=NOW - 600),
            now=NOW)
        store.append_attention_snapshot(
            _records(store, snapshot_id="new", computed_at=NOW), now=NOW)
        assert store.latest_attention_snapshot_id(NOW) == "new"
        assert store.latest_attention_snapshot_id(NOW - 1) == "old"
        assert store.latest_attention_snapshot_id(NOW - 10_000) is None

    def test_one_item_s_rank_history_is_readable(self, store):
        store.append_attention_snapshot(
            _records(store, snapshot_id="old", computed_at=NOW - 600),
            now=NOW)
        store.append_attention_snapshot(
            _records(store, snapshot_id="new", computed_at=NOW), now=NOW)
        history = store.attention_ranks_for_item(item_kind="conclusion",
                                                 item_id="c0")
        assert len(history) == 2
        assert history[0]["computed_at"] > history[1]["computed_at"]


class TestTheSeamsSeeTheNewMethods:
    def test_the_read_seam_forwards_the_readers_and_refuses_the_writer(
            self, store):
        from v3.api.readonly import ReadOnlyLedger
        ledger = ReadOnlyLedger(store)
        assert callable(ledger.attention_snapshot)
        assert callable(ledger.latest_attention_snapshot_id)
        with pytest.raises(AttributeError):
            ledger.append_attention_snapshot

    def test_the_ast_audit_still_classifies_every_method(self):
        from v3.api.readonly import audit_store_methods
        assert audit_store_methods()["misclassified"] == []

    def test_the_command_seam_still_has_exactly_one_writer(self):
        from v3.api.writeonly import audit_command_writes
        report = audit_command_writes()
        assert report["writers"] == ["append_command"]
        assert report["extra_tables"] == []


class TestSupplyReadsOneSourcePerFactor:
    """Each factor has ONE source in L1, and each edge is exercised.

    A factor that stops reading its source does not fail loudly — it
    degenerates. `confidence_delta` losing its predecessor silently
    becomes "the confidence", which is a plausible-looking number that is
    not the thing AP1 asks for; the mutation sweep found exactly that gap
    and these are the tests that close it.
    """

    def test_the_predecessor_is_the_previous_row_of_the_same_type(self,
                                                                  store):
        from tests.conclusions_fixtures import healthy, provenance
        from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
        for observed_at, confidence in ((NOW - 4 * HOUR, 0.2),
                                        (NOW - HOUR, 0.9)):
            store.append_conclusion(to_record(Conclusion(
                scenario_id="taiwan_contingency",
                conclusion_type=THREAT_LEVEL, observed_at=observed_at,
                confidence=confidence, provenance=provenance("tl"),
                input_health=healthy(),
                state=f"TL{int(confidence * 10)}", threshold_ref={},
                source_urls=(), calibration_status={})))
        latest = store.latest_conclusion_at(
            NOW, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL)
        assert SUPPLY.previous_confidence(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, latest_id=latest["id"],
            now=NOW) == pytest.approx(0.2)
        candidate = SUPPLY.candidate_for(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, now=NOW)
        assert candidate.previous_confidence == pytest.approx(0.2)
        assert candidate.confidence == pytest.approx(0.9)
        # The whole point of reading it: the delta is the MOVEMENT, not
        # the level. Without the predecessor this would be 0.9.
        assert S.score_for(candidate, now=NOW).confidence_delta == \
            pytest.approx(0.7)

    def test_a_first_ever_conclusion_has_no_predecessor(self, store):
        from tests.conclusions_fixtures import healthy, provenance
        from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
        store.append_conclusion(to_record(Conclusion(
            scenario_id="taiwan_contingency", conclusion_type=THREAT_LEVEL,
            observed_at=NOW - HOUR, confidence=0.6,
            provenance=provenance("tl"), input_health=healthy(),
            state="TL3", threshold_ref={}, source_urls=(),
            calibration_status={})))
        candidate = SUPPLY.candidate_for(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, now=NOW)
        assert candidate.previous_confidence is None
        assert S.score_for(candidate, now=NOW).confidence_delta == \
            pytest.approx(0.6)

    def test_a_predecessor_beyond_the_lookback_is_not_read(self, store):
        from tests.conclusions_fixtures import healthy, provenance
        from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
        for observed_at, confidence in (
                (NOW - SUPPLY.PREDECESSOR_LOOKBACK_SEC - HOUR, 0.2),
                (NOW - HOUR, 0.9)):
            store.append_conclusion(to_record(Conclusion(
                scenario_id="taiwan_contingency",
                conclusion_type=THREAT_LEVEL, observed_at=observed_at,
                confidence=confidence, provenance=provenance("tl"),
                input_health=healthy(), state=f"S{confidence}",
                threshold_ref={}, source_urls=(), calibration_status={})))
        candidate = SUPPLY.candidate_for(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, now=NOW)
        assert candidate.previous_confidence is None

    # ── WP-4.11 (P9 §6.9): novelty reads the STATE diff, not the write ──
    def _tl_row(self, *, observed_at, confidence, state):
        from tests.conclusions_fixtures import healthy, provenance
        from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
        return to_record(Conclusion(
            scenario_id="taiwan_contingency", conclusion_type=THREAT_LEVEL,
            observed_at=observed_at, confidence=confidence,
            provenance=provenance("tl"), input_health=healthy(),
            state=state, threshold_ref={}, source_urls=(),
            calibration_status={}))

    def test_the_change_instant_is_the_last_state_diff_not_the_last_write(
            self, store):
        from v3.conclusions import THREAT_LEVEL
        # TL4 → TL2 five hours ago, then the same TL2 re-written an hour
        # ago (confidence jitter). The OLD read answered NOW - HOUR and
        # crowned every candidate maximally novel (D-25(a)); the fact is
        # that the finding last said something different 5h ago.
        for observed_at, confidence, state in (
                (NOW - 10 * HOUR, 0.30, "TL4"),
                (NOW - 5 * HOUR, 0.80, "TL2"),
                (NOW - HOUR, 0.82, "TL2")):
            store.append_conclusion(self._tl_row(
                observed_at=observed_at, confidence=confidence,
                state=state))
        candidate = SUPPLY.candidate_for(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, now=NOW)
        assert candidate.last_changed_at == pytest.approx(NOW - 5 * HOUR)
        assert S.score_for(candidate, now=NOW).novelty == pytest.approx(
            1.0 - (5 * HOUR) / T.NOVELTY_HORIZON_SEC)

    def test_a_stable_history_is_old_not_novel(self, store):
        from v3.conclusions import THREAT_LEVEL
        # Same state across the whole window: unchanged since at least
        # the window's oldest row. Answering None here would score a
        # maximally STABLE finding as maximally NOVEL.
        for observed_at, confidence in ((NOW - 60 * HOUR, 0.50),
                                        (NOW - 30 * HOUR, 0.55),
                                        (NOW - HOUR, 0.52)):
            store.append_conclusion(self._tl_row(
                observed_at=observed_at, confidence=confidence,
                state="TL3"))
        candidate = SUPPLY.candidate_for(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, now=NOW)
        assert candidate.last_changed_at == pytest.approx(NOW - 60 * HOUR)
        assert S.score_for(candidate, now=NOW).novelty == 0.0

    def test_a_first_ever_row_dates_the_change_at_its_own_instant(
            self, store):
        from v3.conclusions import THREAT_LEVEL
        store.append_conclusion(self._tl_row(
            observed_at=NOW - HOUR, confidence=0.6, state="TL3"))
        candidate = SUPPLY.candidate_for(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, now=NOW)
        # Nothing → TL3 IS a change, dated by the row that first said it.
        assert candidate.last_changed_at == pytest.approx(NOW - HOUR)

    def test_the_novelty_basis_marker_rides_into_the_stored_inputs(
            self, store):
        from v3.conclusions import THREAT_LEVEL
        store.append_conclusion(self._tl_row(
            observed_at=NOW - HOUR, confidence=0.6, state="TL3"))
        candidate = SUPPLY.candidate_for(
            store, scenario_id="taiwan_contingency",
            conclusion_type=THREAT_LEVEL, now=NOW)
        stored = S.score_for(candidate, now=NOW).inputs
        # WP-4.13a picks its words on this marker: without it, a row's
        # `last_changed_at` is a write instant and must not be spoken
        # as a state change.
        assert stored[N.NOVELTY_BASIS_KEY] == N.NOVELTY_BASIS_STATE_CHANGE

    def test_the_order_hint_follows_the_declared_conclusion_types(self):
        from v3.conclusions.vocabulary import CONCLUSION_TYPES
        hints = [SUPPLY._order_hint(name) for name in CONCLUSION_TYPES]
        assert hints == sorted(hints)
        assert SUPPLY._order_hint("not_a_type") == float(
            len(CONCLUSION_TYPES))
