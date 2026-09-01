"""WP-0.4 v2 (0.4d) — Tier 2: the model reads, and changes nothing yet.

What must hold before this rung is ever trusted, and therefore what is
pinned here:

* the vocabulary is CLOSED and has no reject — a model that could drop
  an FN candidate would let the detection layer's own blind spots decide
  what the audit is allowed to see;
* effect is off, and a verdict says so on its own row, so "recorded" and
  "acted on" can never be confused after the fact;
* an unusable answer leaves the draft pending (silence must not read as
  agreement);
* every way of doing nothing is counted apart (G-17);
* the prompt is deterministic and versioned, because an agreement rate
  that cannot name the words it was measured under is not attributable.
"""
from __future__ import annotations

import pytest

from v3.calibration import llm_reader as LLM
from v3.calibration import runner as RUNNER
from v3.calibration import thresholds as T
from v3.fetch.llm import LlmRequest, LlmResult
from v3.kernel.errors import DomainError

DRAFT = {
    "draft_id": "fnd_1", "scenario_id": "taiwan_contingency",
    "conclusion_type": "threat_level", "conclusion_id": "c1",
    "label": "FALSE_NEGATIVE", "reason": "external evidence outranks the call",
    "proposed_analyst_id": "auto:rss", "sources": ["rss"],
    "evidence_url": "https://example.invalid/a", "observed_at": 1.0,
    "created_at": 2.0,
}
ROSTER = {"TW": "primary_target", "CN": "adversary"}


class _Egress:
    """The shape `tier2_pass` needs, with no network behind it."""

    def __init__(self, *, enabled=True, model_id="gpt-oss:20b"):
        self.enabled = enabled
        self.model_id = model_id
        self.client = object()
        self.endpoint = "http://llm.invalid"
        self.replay_only = False


class TestTheVocabularyIsClosed:
    def test_there_are_exactly_two_verdicts_and_neither_is_reject(self):
        assert set(LLM.VERDICTS) == {"agree_confirm", "route_to_human"}
        assert "reject" not in " ".join(LLM.VERDICTS)

    def test_the_schema_pins_the_enum_at_the_transport(self):
        enum = LLM.VERDICT_SCHEMA["properties"]["verdict"]["enum"]
        assert enum == list(LLM.VERDICTS)

    def test_an_unknown_verdict_is_refused(self):
        with pytest.raises(DomainError):
            LLM.parse_verdict({"verdict": "reject", "reason": "x"},
                              draft_id="d", model_id="m", response_text="{}")

    def test_a_missing_verdict_is_refused_not_defaulted(self):
        with pytest.raises(DomainError):
            LLM.parse_verdict({"reason": "x"}, draft_id="d", model_id="m",
                              response_text="{}")


class TestEffectIsEarnedNotAssumed:
    def test_effect_is_off(self):
        assert LLM.TIER2_EFFECT_ENABLED is False

    def test_a_verdict_records_whether_it_was_effective(self):
        verdict = LLM.parse_verdict(
            {"verdict": "agree_confirm", "reason": "r",
             "event_real": True, "attribution_holds": True},
            draft_id="d", model_id="m", response_text="{}")
        assert verdict.effective is False
        assert verdict.releases is False

    def test_agreement_alone_cannot_release_while_effect_is_off(self):
        verdict = LLM.Tier2Verdict(
            draft_id="d", verdict=LLM.AGREE_CONFIRM, reason="r",
            model_id="m", prompt_ref=LLM.PROMPT_REF, response_text="{}",
            effective=False)
        assert verdict.releases is False


class TestThePromptIsReproducible:
    def test_the_same_draft_produces_the_same_prompt(self):
        first = LLM.prompt_for(DRAFT, participants=ROSTER)
        assert first == LLM.prompt_for(DRAFT, participants=ROSTER)

    def test_the_roster_order_does_not_change_the_prompt(self):
        reversed_roster = dict(reversed(list(ROSTER.items())))
        assert LLM.prompt_for(DRAFT, participants=ROSTER) == \
            LLM.prompt_for(DRAFT, participants=reversed_roster)

    def test_the_prompt_carries_a_versioned_ref(self):
        assert LLM.PROMPT_REF == f"{LLM.PROMPT_ID}@{LLM.PROMPT_VERSION}"

    def test_the_system_prompt_carries_the_bench_findings(self):
        # Measured 2026-08-15 across three live readings: without these
        # the model routed candidates it should have confirmed.
        assert "あなたの仕事ではありません" in LLM.SYSTEM_PROMPT
        assert "実行主体国とは限りません" in LLM.SYSTEM_PROMPT

    def test_the_prompt_asks_only_what_it_supplies_the_material_for(self):
        # v2 asked whether `country` was consistent while sending no
        # country — a draft is scenario-level and has no country field —
        # and the reader correctly answered that it could not check.
        # The question is now scenario attribution, which the roster
        # and the per-line country codes DO answer.
        assert "指定シナリオに帰属しうるか" in LLM.SYSTEM_PROMPT
        assert "国の帰属（country）は証拠と整合" not in LLM.SYSTEM_PROMPT
        assert LLM.PROMPT_VERSION == "3"

    def test_the_request_is_deterministic_and_schema_bound(self):
        request = LLM.request_for(DRAFT, participants=ROSTER)
        assert isinstance(request, LlmRequest)
        assert request.temperature == 0.0
        assert request.response_format is LLM.VERDICT_SCHEMA
        body = request.body()
        assert body["format"]["properties"]["verdict"]["enum"] == \
            list(LLM.VERDICTS)
        assert body["think"] == T.S9_TIER2_THINK
        assert body["options"]["num_predict"] == T.S9_TIER2_MAX_TOKENS


class TestTheSecondReaderIsNotTheFirstOne:
    def test_the_tier2_model_is_pinned_apart_from_the_deployment(self):
        # A second opinion from the weights the detection stages run is
        # the first opinion again — the correlated failure this rung
        # exists to break.
        assert LLM.TIER2_MODEL_ID == "gpt-oss:20b"
        request = LLM.request_for(DRAFT, participants=ROSTER)
        assert request.model_id == LLM.TIER2_MODEL_ID

    def test_the_pass_does_not_inherit_the_egress_model(self, tmp_path,
                                                        monkeypatch):
        from v3.ledger import LedgerStore
        store = LedgerStore(str(tmp_path / "t2model.db"))
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: (DRAFT,))
        seen = {}
        import v3.fetch.llm as llm_module

        def _capture(request, **kwargs):
            seen["model_id"] = request.model_id
            return LlmResult(ok=True, response_text="{}",
                             data={"verdict": "route_to_human",
                                   "reason": "r"})

        monkeypatch.setattr(llm_module, "submit", _capture)
        RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                          egress=_Egress(model_id="gemma4:26b"))
        assert seen["model_id"] == LLM.TIER2_MODEL_ID
        assert store.llm_verdicts()[0]["model_id"] == LLM.TIER2_MODEL_ID
        store.close()


class TestTheRequestBodyKeepsProductionShape:
    def test_a_string_format_still_serialises_as_before(self):
        body = LlmRequest(prompt="p", model_id="m").body()
        assert body["format"] == "json"
        assert "think" not in body

    def test_a_non_schema_non_string_format_is_refused(self):
        with pytest.raises(DomainError):
            LlmRequest(prompt="p", model_id="m", response_format=7)


class TestTier2Pass:
    def _store(self, tmp_path, drafts):
        from v3.ledger import LedgerStore
        store = LedgerStore(str(tmp_path / "t2.db"))
        store._drafts = drafts
        return store

    def test_nothing_pending_asks_nothing(self, tmp_path, monkeypatch):
        store = self._store(tmp_path, [])
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: ())
        report = RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                                   egress=_Egress())
        assert report["asked"] == 0 and report["skipped"] == {}
        store.close()

    def test_no_egress_is_counted_not_silent(self, tmp_path, monkeypatch):
        store = self._store(tmp_path, [DRAFT])
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: (DRAFT,))
        report = RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                                   egress=None)
        assert report["skipped"] == {LLM.SKIP_NO_EGRESS: 1}
        store.close()

    def test_a_disabled_model_is_a_different_fact(self, tmp_path,
                                                  monkeypatch):
        store = self._store(tmp_path, [DRAFT])
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: (DRAFT,))
        report = RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                                   egress=_Egress(enabled=False))
        assert report["skipped"] == {LLM.SKIP_DISABLED: 1}
        store.close()

    def test_a_verdict_is_recorded_and_stays_ineffective(self, tmp_path,
                                                         monkeypatch):
        store = self._store(tmp_path, [DRAFT])
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: (DRAFT,))
        monkeypatch.setattr(
            RUNNER, "tier2_pass", RUNNER.tier2_pass)  # keep the real one
        import v3.fetch.llm as llm_module
        monkeypatch.setattr(llm_module, "submit", lambda *a, **k: LlmResult(
            ok=True, data={"verdict": "agree_confirm", "reason": "同意",
                           "event_real": True, "attribution_holds": True},
            response_text='{"verdict": "agree_confirm"}'))
        report = RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                                   egress=_Egress())
        assert report["asked"] == 1 and report["recorded"] == 1
        assert report["verdicts"] == {"agree_confirm": 1}
        rows = store.llm_verdicts()
        assert len(rows) == 1
        assert rows[0]["effective"] is False
        assert rows[0]["prompt_ref"] == LLM.PROMPT_REF
        store.close()

    def test_an_unusable_answer_leaves_the_draft_pending(self, tmp_path,
                                                        monkeypatch):
        store = self._store(tmp_path, [DRAFT])
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: (DRAFT,))
        import v3.fetch.llm as llm_module
        monkeypatch.setattr(llm_module, "submit", lambda *a, **k: LlmResult(
            ok=True, data={"verdict": "maybe"}, response_text="{}"))
        report = RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                                   egress=_Egress())
        assert report["skipped"] == {LLM.SKIP_UNPARSEABLE: 1}
        assert store.llm_verdicts() == []
        store.close()

    def test_a_failed_call_is_named_by_its_own_reason(self, tmp_path,
                                                      monkeypatch):
        store = self._store(tmp_path, [DRAFT])
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: (DRAFT,))
        import v3.fetch.llm as llm_module
        monkeypatch.setattr(llm_module, "submit", lambda *a, **k: LlmResult(
            ok=False, error="http_error"))
        report = RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                                   egress=_Egress())
        assert report["skipped"] == {"http_error": 1}
        store.close()

    def test_the_same_draft_is_not_re_asked_under_the_same_prompt(
            self, tmp_path, monkeypatch):
        store = self._store(tmp_path, [DRAFT])
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: (DRAFT,))
        import v3.fetch.llm as llm_module
        monkeypatch.setattr(llm_module, "submit", lambda *a, **k: LlmResult(
            ok=True, data={"verdict": "route_to_human", "reason": "不明"},
            response_text="{}"))
        RUNNER.tier2_pass(store, now=10.0, scenarios=(), egress=_Egress())
        second = RUNNER.tier2_pass(store, now=20.0, scenarios=(),
                                   egress=_Egress())
        assert second["asked"] == 0
        assert len(store.llm_verdicts()) == 1
        store.close()

    def test_the_cap_defers_rather_than_drops(self, tmp_path, monkeypatch):
        many = tuple(dict(DRAFT, draft_id=f"fnd_{i}") for i in range(5))
        store = self._store(tmp_path, list(many))
        monkeypatch.setattr(RUNNER.HUMAN, "pending_drafts",
                            lambda *a, **k: many)
        import v3.fetch.llm as llm_module
        monkeypatch.setattr(llm_module, "submit", lambda *a, **k: LlmResult(
            ok=True, data={"verdict": "route_to_human", "reason": "r"},
            response_text="{}"))
        report = RUNNER.tier2_pass(store, now=10.0, scenarios=(),
                                   egress=_Egress(), limit=2)
        assert report["asked"] == 2
        assert report["deferred"] == 3
        store.close()


class TestAgreementMeasurement:
    def _verdict(self, draft_id, verdict):
        return LLM.Tier2Verdict(
            draft_id=draft_id, verdict=verdict, reason="r", model_id="m",
            prompt_ref=LLM.PROMPT_REF, response_text="{}")

    def test_only_drafts_a_human_ruled_on_are_compared(self):
        report = LLM.agreement(
            [self._verdict("a", LLM.AGREE_CONFIRM),
             self._verdict("b", LLM.AGREE_CONFIRM)],
            {"a": "confirmed"})
        assert report["compared"] == 1
        assert report["agreed"] == 1
        assert report["agreement_rate"] == pytest.approx(1.0)

    def test_routing_something_a_human_rejected_counts_as_agreement(self):
        report = LLM.agreement([self._verdict("a", LLM.ROUTE_TO_HUMAN)],
                               {"a": "rejected"})
        assert report["agreed"] == 1

    def test_hedging_on_a_real_miss_is_counted_apart(self):
        report = LLM.agreement([self._verdict("a", LLM.ROUTE_TO_HUMAN)],
                               {"a": "confirmed"})
        assert report["agreed"] == 0
        assert report["hedged_on_real_miss"] == 1

    def test_no_comparisons_reports_none_not_zero(self):
        report = LLM.agreement([self._verdict("a", LLM.AGREE_CONFIRM)], {})
        assert report["compared"] == 0
        assert report["agreement_rate"] is None

    def test_the_rate_names_the_prompt_it_was_measured_under(self):
        assert LLM.agreement([], {})["prompt_ref"] == LLM.PROMPT_REF
