"""The projections themselves — behaviour, exercised without a server.

Every test here builds a ledger, wraps it in the read seam, and calls
`handle()`. There is no Flask app, no socket and no thread, which is the
property the legacy surface could not offer: reaching an endpoint there
meant importing `radar`, which booted the app and ~40 sensor threads.

The load-bearing behaviours pinned below:

* `?at=` produces the SAME projection as live (P7 principle 4). The test
  asserts byte-equality of the two bodies apart from the `at` echo.
* a read leaves the ledger unchanged — asserted by counting rows before
  and after, because A-01 was a read that appended.
* `calibration_pending` is served WITH a countdown (the 2026-08-08
  ruling), not as a bare absence.
* the NP7 sentence is on every response, including the 404s and 400s.
"""
from __future__ import annotations

import json

import pytest

from tests.conclusions_fixtures import NOW, healthy, provenance
from v3.api import (ANONYMOUS, ApiRequest, Principal, ReadContext,
                    ReadOnlyLedger, ScenarioRef, handle)
from v3.api.vocabulary import ROLE_VIEWER, TOOL_SCOPE
from v3.conclusions import (CALIBRATION_PENDING, CONCLUSION_TYPES,
                            Conclusion, InputHealth, NP7_DISCLAIMER,
                            PER_DOMAIN, Suppression, THREAT_LEVEL, TREND,
                            to_record)
from v3.conclusions import thresholds as CT
from v3.kernel import Evidence, ThreatLevel
from v3.ledger import LedgerStore, SignalObservation, TLObservation
from v3.runtime import attention as RANKER
from v3.runtime import ops_health as OPS

SCENARIO = "taiwan_contingency"
VIEWER = Principal(user_id="analyst-1", role=ROLE_VIEWER)
DAY = 86400.0


def _conclusion(conclusion_type: str, *, state="TL4", observed_at=NOW,
                unavailable_reason=None, health=None,
                suppression=None) -> Conclusion:
    return Conclusion(
        scenario_id=SCENARIO, conclusion_type=conclusion_type,
        observed_at=observed_at, confidence=0.8,
        provenance=provenance(f"{conclusion_type}@S1-CONC-001"),
        input_health=health or healthy(), state=state,
        unavailable_reason=unavailable_reason, suppression=suppression,
        threshold_ref={"tl_critical": 3.0}, source_urls=("https://x/1",),
        calibration_status={"status": "measured", "recall": 0.9},
        metadata={"note": "fixture"})


@pytest.fixture()
def store(tmp_path):
    handle_ = LedgerStore(str(tmp_path / "v3.db"))
    yield handle_
    handle_.close()


@pytest.fixture()
def seeded(store):
    for index, conclusion_type in enumerate(CONCLUSION_TYPES):
        store.append_conclusion(to_record(_conclusion(
            conclusion_type, state=f"S{index}",
            observed_at=NOW - 60 + index * 0.1)))
    for index in range(6):
        store.append_tl(TLObservation(
            tick_id=f"tick{index}", scenario_id=SCENARIO,
            observed_at=NOW - (6 - index) * 900.0,
            threat_level=ThreatLevel(4), score=2.4))
    store.append_signal(SignalObservation(
        tick_id="tick5", sensor="ripe_bgp", signal_source="bgp",
        domain="cyber", country="TW",
        evidence=Evidence.observe({}, source="ripe", observed_at=NOW - 300,
                                  freshness_horizon_sec=3600.0),
        status="FIRED", raw_score=3.0, confidence=0.9,
        evidence_url="https://ripe/1"), NOW)
    store.append_signal(SignalObservation(
        tick_id="tick5", sensor="ripe_bgp", signal_source="bgp2",
        domain="cyber", country="TW",
        evidence=Evidence.observe({}, source="ripe", observed_at=NOW - 290,
                                  freshness_horizon_sec=3600.0),
        status="FIRED", raw_score=1.0, confidence=0.5,
        suppressed=True, suppress_reason="noise_exclusion:maintenance"), NOW)
    return store


def _context(store, *, now=NOW, scenarios=None, adapters=("ripe_bgp",)):
    return ReadContext(
        ledger=ReadOnlyLedger(store), now=now,
        scenarios=scenarios if scenarios is not None else (
            ScenarioRef(scenario_id=SCENARIO,
                        participants={"TW": 1.0, "US": 0.6},
                        adversaries=("CN",), focused=True),),
        adapters=adapters, app_config={"cadence_sec": 900})


def _get(store, path, params=None, principal=VIEWER, **ctx_kwargs):
    context = _context(store, **ctx_kwargs)
    request = ApiRequest(method="GET", path=path, params=params or {},
                         principal=principal)
    return handle(request, context)


class TestEveryResponseCarriesNP7:
    def test_a_success_does(self, seeded):
        body = _get(seeded, "/api/v3/scenarios").as_dict()
        assert body["final_judgment_disclaimer"] == NP7_DISCLAIMER

    def test_a_404_does(self, seeded):
        response = _get(seeded, "/api/v3/scenarios/nope/conclusions")
        assert response.status == 404
        assert response.as_dict()["final_judgment_disclaimer"] \
            == NP7_DISCLAIMER

    def test_a_401_does(self, seeded):
        response = _get(seeded, "/api/v3/self_eval", principal=ANONYMOUS)
        assert response.status == 401
        body = response.as_dict()
        assert body["final_judgment_disclaimer"] == NP7_DISCLAIMER
        assert body["error_detail"]["code"] == "api.unauthenticated"

    def test_an_unknown_path_is_404_with_the_sentence(self, seeded):
        response = _get(seeded, "/api/v3/nothing_here")
        assert response.status == 404
        assert response.as_dict()["final_judgment_disclaimer"] \
            == NP7_DISCLAIMER

    def test_every_body_is_json_serialisable(self, seeded):
        for path in ("/api/v3/scenarios",
                     f"/api/v3/scenarios/{SCENARIO}/conclusions",
                     f"/api/v3/scenarios/{SCENARIO}/conclusions/history",
                     f"/api/v3/scenarios/{SCENARIO}/evidence",
                     f"/api/v3/scenarios/{SCENARIO}/report.md",
                     "/api/v3/self_eval", "/api/v3/sensors",
                     "/api/v3/thresholds", "/api/v3/app_config",
                     "/healthz"):
            body = _get(seeded, path).as_dict()
            json.dumps(body, allow_nan=False)


class TestReadsHaveNoSideEffects:
    """Condition 1, measured rather than asserted."""

    def test_no_projection_writes_a_row(self, seeded):
        before = (seeded.count_signals(), seeded.count_tl(),
                  seeded.count_conclusions())
        for path in ("/api/v3/scenarios",
                     f"/api/v3/scenarios/{SCENARIO}/conclusions",
                     f"/api/v3/scenarios/{SCENARIO}/conclusions/history",
                     f"/api/v3/scenarios/{SCENARIO}/evidence",
                     "/api/v3/self_eval", "/api/v3/sensors",
                     "/api/v3/thresholds", "/healthz"):
            _get(seeded, path)
        after = (seeded.count_signals(), seeded.count_tl(),
                 seeded.count_conclusions())
        assert before == after

    def test_the_same_read_twice_returns_the_same_bytes(self, seeded):
        first = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions")
        second = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions")
        assert first.as_dict() == second.as_dict()


class TestR2Conclusions:
    def test_it_serves_all_five_types(self, seeded):
        body = _get(seeded,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        types = {item["conclusion_type"] for item in body["conclusions"]}
        assert types == set(CONCLUSION_TYPES)
        assert body["projection"]["types_missing"] == []

    def test_a_missing_type_is_named_not_omitted(self, store):
        store.append_conclusion(to_record(_conclusion(THREAT_LEVEL)))
        body = _get(store,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        assert body["projection"]["types_present"] == [THREAT_LEVEL]
        assert set(body["projection"]["types_missing"]) == \
            set(CONCLUSION_TYPES) - {THREAT_LEVEL}

    def test_an_unknown_scenario_is_404(self, seeded):
        assert _get(seeded, "/api/v3/scenarios/mars/conclusions").status \
            == 404

    def test_the_derivation_fields_survive_the_round_trip(self, seeded):
        body = _get(seeded,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        row = next(item for item in body["conclusions"]
                   if item["conclusion_type"] == THREAT_LEVEL)
        assert row["threshold_ref"] == {"tl_critical": 3.0}
        assert row["source_urls"] == ["https://x/1"]
        assert row["provenance"]["formula_ref"].endswith("S1-CONC-001")
        assert row["input_health"]["sources_ok"]

    def test_an_unknown_query_parameter_is_a_400_naming_it(self, seeded):
        response = _get(seeded,
                        f"/api/v3/scenarios/{SCENARIO}/conclusions",
                        params={"focus": "1"})
        assert response.status == 400
        assert "focus" in response.as_dict()["error_detail"]["detail"][
            "unknown"]

    def test_focus_cannot_be_registered_through_a_read(self, seeded):
        """PROP-001, concretely: the GET that set focus is gone."""
        response = _get(seeded, "/api/v3/scenarios",
                        params={"focus": SCENARIO})
        assert response.status == 400


class TestReplayIsTheSameProjection:
    def test_at_now_equals_live_apart_from_the_echo(self, seeded):
        live = _get(seeded,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        replay = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions",
                      params={"at": str(NOW)}).as_dict()
        assert replay.pop("at") == NOW
        assert live == replay

    def test_an_earlier_instant_sees_the_earlier_row(self, store):
        store.append_conclusion(to_record(_conclusion(
            THREAT_LEVEL, state="TL5", observed_at=NOW - 2 * DAY)))
        store.append_conclusion(to_record(_conclusion(
            THREAT_LEVEL, state="TL2", observed_at=NOW - 60)))
        now_body = _get(store,
                        f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        then_body = _get(store, f"/api/v3/scenarios/{SCENARIO}/conclusions",
                         params={"at": str(NOW - DAY)}).as_dict()
        assert now_body["conclusions"][0]["state"] == "TL2"
        assert then_body["conclusions"][0]["state"] == "TL5"

    def test_a_future_instant_is_refused(self, seeded):
        response = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions",
                        params={"at": str(NOW + 1000)})
        assert response.status == 400

    def test_a_nonsense_instant_is_refused(self, seeded):
        response = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions",
                        params={"at": "yesterday"})
        assert response.status == 400

    def test_replay_and_live_share_one_envelope_shape(self, seeded):
        live = _get(seeded,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        replay = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions",
                      params={"at": str(NOW)}).as_dict()
        assert set(replay) - set(live) == {"at"}


class TestTheCalibrationCountdownIsVisible:
    """The 2026-08-08 ruling: not merely 'no conclusion'."""

    def _pending(self, store, observed_days: float):
        health = InputHealth(sources_ok=("a", "b"),
                             history_span_sec=observed_days * DAY)
        store.append_conclusion(to_record(_conclusion(
            THREAT_LEVEL, state=None,
            unavailable_reason=CALIBRATION_PENDING, health=health,
            suppression=Suppression(
                guard_id="history_below_calibration_window",
                reason=CALIBRATION_PENDING,
                detail="観測履歴が較正窓に達していません",
                overridden=False))))

    def test_the_response_states_the_days_remaining(self, store):
        self._pending(store, observed_days=10.0)
        body = _get(store,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        countdown = body["calibration_pending"]
        expected = CT.CALIBRATION_MIN_HISTORY_DAYS - 10.0
        assert countdown["days_remaining"] == pytest.approx(expected)
        assert countdown["days_observed"] == pytest.approx(10.0)
        assert countdown["window_days"] == CT.CALIBRATION_MIN_HISTORY_DAYS
        assert THREAT_LEVEL in countdown["types"]

    def test_the_countdown_is_absent_when_nothing_is_pending(self, seeded):
        body = _get(seeded,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        assert "calibration_pending" not in body

    def test_the_countdown_never_goes_negative(self, store):
        self._pending(store, observed_days=CT.CALIBRATION_MIN_HISTORY_DAYS
                      + 5)
        body = _get(store,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        assert body["calibration_pending"]["days_remaining"] == 0.0

    def test_the_unavailable_reason_is_still_on_the_conclusion(self, store):
        self._pending(store, observed_days=1.0)
        body = _get(store,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        row = body["conclusions"][0]
        assert row["state"] is None
        assert row["conclusion_unavailable_reason"] == CALIBRATION_PENDING
        assert row["suppression"]["guard_id"] == \
            "history_below_calibration_window"


class TestR1Scenarios:
    def test_it_lists_the_configured_scenarios_with_focus(self, seeded):
        body = _get(seeded, "/api/v3/scenarios").as_dict()
        assert body["scenario_count"] == 1
        row = body["scenarios"][0]
        assert row["scenario_id"] == SCENARIO and row["focused"] is True
        assert row["participants"] == {"TW": 1.0, "US": 0.6}
        assert row["threat_level"] == 4

    def test_a_never_observed_scenario_says_so(self, store):
        body = _get(store, "/api/v3/scenarios", scenarios=(
            ScenarioRef(scenario_id="new_one"),)).as_dict()
        row = body["scenarios"][0]
        assert row["never_observed"] is True
        assert row["threat_level"] is None

    def test_the_null_zone_is_a_state_not_a_default(self, store):
        store.append_tl(TLObservation(
            tick_id="t0", scenario_id=SCENARIO, observed_at=NOW - 100,
            threat_level=None, score=0.0))
        row = _get(store, "/api/v3/scenarios").as_dict()["scenarios"][0]
        assert row["in_null_zone"] is True
        assert row["threat_level"] is None
        assert row["never_observed"] is False

    def test_a_row_carries_the_japanese_display_name(self, seeded):
        """P9 §5 — the card's primary label. `scenario_id` is the raw key
        the tool sorts by, not the vocabulary an analyst reads."""
        body = _get(seeded, "/api/v3/scenarios", scenarios=(
            ScenarioRef(scenario_id=SCENARIO, display_name_ja="台湾正面",
                        display_name_source="display_name_ja"),)).as_dict()
        row = body["scenarios"][0]
        assert row["display_name_ja"] == "台湾正面"
        assert row["display_name_source"] == "display_name_ja"

    def test_a_missing_display_name_is_a_disclosed_fallback(self, store):
        """Falling back to the id is fine; falling back SILENTLY is not —
        the client cannot otherwise tell a declared name that happens to
        equal the id from a name nobody declared."""
        row = _get(store, "/api/v3/scenarios", scenarios=(
            ScenarioRef(scenario_id="new_one"),)).as_dict()["scenarios"][0]
        assert row["display_name_ja"] == "new_one"
        assert row["display_name_source"] == "scenario_id"


class TestR1DerivedFrom:
    """P9 §5 / R-E — every row says where its number came from.

    The second owner review (P9 §1.2 D-11) read TL 4 on a card and could
    not say which domains, how many observations, or which scoring scope
    produced it. The answer is the PER_DOMAIN conclusion the same tick
    wrote; R1 projects that row through the SAME read path R2 uses
    (`latest_conclusion_at` + `from_row`), so this is disclosure of a
    stored fact, never a second derivation (A-02).
    """

    @staticmethod
    def _per_domain(observed_at=NOW, metadata=None):
        return Conclusion(
            scenario_id=SCENARIO, conclusion_type=PER_DOMAIN,
            observed_at=observed_at, confidence=0.7,
            provenance=provenance("per_domain@S1-CONC-019"),
            input_health=healthy(),
            state="cyber=ACTIVE;physical=STABLE;info=STABLE",
            threshold_ref={"elevated_floor": 2.5},
            source_urls=("https://x/1",),
            calibration_status={"status": "measured"},
            metadata=metadata if metadata is not None else {
                "domain_scores": {"cyber": 3.1, "physical": 0.0,
                                  "info": 0.4},
                "domain_states": {"cyber": "ACTIVE", "physical": "STABLE",
                                  "info": "STABLE"},
                "domain_source_counts": {"cyber": 2, "physical": 0,
                                         "info": 1},
            })

    def test_the_row_projects_the_per_domain_conclusion(self, seeded):
        seeded.append_conclusion(to_record(self._per_domain()))
        row = _get(seeded, "/api/v3/scenarios").as_dict()["scenarios"][0]
        derived = row["derived_from"]
        assert derived["supplied"] is True
        assert derived["domains"]["cyber"] == {
            "score": 3.1, "state": "ACTIVE", "sources": 2}
        assert derived["domains"]["physical"] == {
            "score": 0.0, "state": "STABLE", "sources": 0}
        assert derived["observed_at"] == NOW
        assert derived["conclusion_id"]

    def test_no_row_at_all_is_a_state_not_zeros(self, store):
        """G-17: "no per-domain row" and "three quiet domains" are
        different facts, and a reader must be able to tell them apart."""
        row = _get(store, "/api/v3/scenarios", scenarios=(
            ScenarioRef(scenario_id="new_one"),)).as_dict()["scenarios"][0]
        assert row["derived_from"] == {"supplied": False,
                                       "reason": "no_per_domain_row"}

    def test_an_unavailable_conclusion_carries_its_reason(self, store):
        conclusion = Conclusion(
            scenario_id=SCENARIO, conclusion_type=PER_DOMAIN,
            observed_at=NOW, confidence=0.0,
            provenance=provenance("per_domain@S1-CONC-019"),
            input_health=healthy(), state=None,
            unavailable_reason="insufficient_data",
            suppression=Suppression(
                guard_id="all_domains_silent",
                reason="insufficient_data",
                detail="全ドメインが無信号のため域別の像を出せません",
                overridden=False),
            threshold_ref={}, source_urls=(),
            calibration_status={"status": "measured"},
            metadata={"domain_scores": {"cyber": 0.0, "physical": 0.0,
                                        "info": 0.0},
                      "domain_states": {}, "domain_source_counts": {}})
        store.append_conclusion(to_record(conclusion))
        row = _get(store, "/api/v3/scenarios").as_dict()["scenarios"][0]
        derived = row["derived_from"]
        assert derived["supplied"] is True
        assert derived["unavailable_reason"] == "insufficient_data"

    def test_replayed_instants_do_not_see_the_future(self, seeded):
        """The projection is `latest_conclusion_at(now)`, so a per-domain
        row written after `now` must not leak into it."""
        seeded.append_conclusion(to_record(self._per_domain(
            observed_at=NOW + 600)))
        row = _get(seeded, "/api/v3/scenarios").as_dict()["scenarios"][0]
        # The seeded fixture wrote an older PER_DOMAIN row (metadata is
        # fixture-shaped), so the projection supplies THAT row, not the
        # future one.
        assert row["derived_from"]["supplied"] is True
        assert row["derived_from"]["observed_at"] < NOW


class TestR1BoardSummary:
    """P9 §5 / R-A — R1 answers 「何か変わったか」 as a Japanese sentence.

    The sentence is composed by P7 §4's template engine, server-side. It
    is not a convenience: composing it in the page would be the frontend
    re-deriving a conclusion the backend already holds (G-09), which is
    the defect P5 O-8 removed from `triage_score.js`.
    """

    def _summary(self, store, **kwargs):
        return _get(store, "/api/v3/scenarios",
                    **kwargs).as_dict()["board_summary"]

    def test_the_envelope_carries_text_its_template_and_its_inputs(
            self, seeded):
        summary = self._summary(seeded)
        assert set(summary) == {"text", "template_ref", "inputs"}
        assert summary["template_ref"].startswith("board.summary@")
        assert summary["text"].endswith("。")

    def test_the_template_is_disclosed_beside_the_sentence(self, seeded):
        """NP6 — a sentence whose template nobody can look up is a
        sentence nobody can re-derive. Same shape as R6's
        `narrative_templates`."""
        body = _get(seeded, "/api/v3/scenarios").as_dict()
        disclosed = body["board_summary_templates"]
        ref = body["board_summary"]["template_ref"]
        assert ref in disclosed
        assert disclosed[ref]["slots"] and disclosed[ref]["text"]

    def test_it_counts_the_scenarios_that_moved_in_24h(self, store):
        for index, level in ((0, 4), (1, 4), (2, 2)):
            store.append_tl(TLObservation(
                tick_id=f"t{index}", scenario_id=SCENARIO,
                observed_at=NOW - DAY - 100 + index * 2000.0,
                threat_level=ThreatLevel(level), score=2.0))
        store.append_tl(TLObservation(
            tick_id="now", scenario_id=SCENARIO, observed_at=NOW - 10,
            threat_level=ThreatLevel(2), score=4.0))
        inputs = self._summary(store)["inputs"]
        assert inputs["scenario_count"] == 1
        assert inputs["changed_count"] == 1
        assert inputs["changed_scenario_ids"] == [SCENARIO]

    def test_an_unmoved_scenario_is_counted_as_unchanged_not_as_absent(
            self, store):
        for index, at in ((0, NOW - DAY - 100), (1, NOW - 10)):
            store.append_tl(TLObservation(
                tick_id=f"t{index}", scenario_id=SCENARIO, observed_at=at,
                threat_level=ThreatLevel(4), score=2.0))
        inputs = self._summary(store)["inputs"]
        assert inputs["changed_count"] == 0
        assert inputs["unchanged_count"] == 1
        assert inputs["undetermined_count"] == 0
        assert inputs["changed_scenario_ids"] == []

    def test_a_scenario_with_no_24h_comparison_is_undetermined(self, store):
        """`severity_delta_24h is None` is neither "changed" nor "did not
        change". Folding it into either is the fake zero this projection
        already refuses one level down."""
        store.append_tl(TLObservation(
            tick_id="t0", scenario_id=SCENARIO, observed_at=NOW - 60,
            threat_level=ThreatLevel(4), score=2.0))
        inputs = self._summary(store)["inputs"]
        assert inputs["undetermined_count"] == 1
        assert inputs["changed_count"] == 0 and inputs["unchanged_count"] == 0

    def test_a_cold_deployment_says_so_rather_than_reporting_zero_change(
            self, store):
        """The honesty rule. "0 件が変化" on a tool that has concluded
        nothing is a confident wrong answer — the exact shape of the empty
        cache that returned CLEAR."""
        summary = self._summary(store, scenarios=(
            ScenarioRef(scenario_id="new_one"),))
        assert summary["template_ref"].startswith("board.summary.cold@")
        assert "結論可能なシナリオがまだありません" in summary["text"]
        assert summary["inputs"]["concluded_count"] == 0
        assert summary["inputs"]["never_observed_count"] == 1

    def test_a_component_it_cannot_supply_is_named_never_dropped(self, store):
        """G-17. The attention fold is per-reader; an unidentified reader
        has no ranked list. The sentence must SAY that rather than read as
        "nothing needs attention"."""
        request = ApiRequest(method="GET", path="/api/v3/scenarios",
                             params={}, principal=VIEWER)
        context = _context(store)
        summary = handle(request, context).as_dict()["board_summary"]
        components = summary["inputs"]["components"]
        assert set(components) >= {"change_24h", "attention", "trust"}
        assert components["attention"]["supplied"] is False
        assert components["attention"]["reason"] == "ranker_has_not_run"
        assert "attention" in summary["inputs"]["unsupplied"]
        assert "なし" in summary["text"] or "不明" in summary["text"]

    def test_the_top_ranked_row_is_the_one_the_sentence_names(self, seeded):
        report = RANKER.rank_cycle(now=NOW, store=seeded,
                                   scenario_ids=[SCENARIO])
        assert report.written > 0
        top = seeded.attention_snapshot(
            seeded.latest_attention_snapshot_id(NOW))[0]
        summary = self._summary(seeded)
        attention = summary["inputs"]["components"]["attention"]
        assert attention["supplied"] is True
        assert attention["item_id"] == top["item_id"]
        assert attention["rank"] == 1

    def test_the_trust_band_is_the_ops_fold_and_not_a_second_reading(
            self, seeded):
        """One measurement, two surfaces. A board that folded the monitors
        itself would be free to disagree with R7 about the same
        deployment."""
        trust = self._summary(seeded)["inputs"]["components"]["trust"]
        expected = OPS.probe_absent(now=NOW)
        assert trust["band"] == expected["worst_band"] == "reserved"
        assert trust["worst_monitor"] == expected["worst_monitor"]
        assert trust["worst_verdict"] == expected["worst_verdict"]
        assert trust["reason"] == expected["worst_reason"]
        assert trust["supplied"] is True, (
            "an unprobed deployment still MEASURES reserved; a missing "
            "field would let the page read it as unknown")

    def test_the_same_ledger_produces_the_same_sentence(self, seeded):
        """AP2 — reproducible, because it is a template and not a model."""
        assert self._summary(seeded) == self._summary(seeded)

    def test_the_sentence_names_the_scenario_by_its_display_name(self,
                                                                 seeded):
        RANKER.rank_cycle(now=NOW, store=seeded, scenario_ids=[SCENARIO])
        summary = self._summary(seeded, scenarios=(
            ScenarioRef(scenario_id=SCENARIO, display_name_ja="台湾正面",
                        display_name_source="display_name_ja"),))
        assert "台湾正面" in summary["text"]
        assert SCENARIO not in summary["text"]


class TestR3History:
    def test_it_returns_the_unthinned_stream_and_its_views(self, seeded):
        body = _get(
            seeded,
            f"/api/v3/scenarios/{SCENARIO}/conclusions/history").as_dict()
        history = body["history"]
        assert history["point_count"] == 6
        assert history["chronic_null_zone"]["is_chronic"] is False
        assert [w["window_days"] for w in history["windows"]] == [1, 7]

    def test_an_oversized_window_is_refused(self, seeded):
        response = _get(
            seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions/history",
            params={"window": str(400 * DAY)})
        assert response.status == 400


class TestR5Evidence:
    def test_suppressed_rows_are_served_with_their_reason(self, seeded):
        body = _get(seeded,
                    f"/api/v3/scenarios/{SCENARIO}/evidence").as_dict()
        evidence = body["evidence"]
        assert evidence["observation_count"] == 2
        assert evidence["fired_count"] == 1
        assert evidence["suppressed_count"] == 1
        assert evidence["suppressed"][0]["suppress_reason"] == \
            "noise_exclusion:maintenance"

    def test_a_suppressed_row_is_not_counted_as_fired(self, seeded):
        evidence = _get(
            seeded,
            f"/api/v3/scenarios/{SCENARIO}/evidence").as_dict()["evidence"]
        assert all(not row["suppressed"] for row in evidence["fired"])

    def test_the_domain_filter_narrows_the_matrix(self, seeded):
        evidence = _get(
            seeded, f"/api/v3/scenarios/{SCENARIO}/evidence",
            params={"domain": "physical"}).as_dict()["evidence"]
        assert evidence["observation_count"] == 0


class TestR4Derivation:
    def _an_id(self, store):
        body = _get(store,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        return body["conclusions"][0]["id"]

    def test_a_conclusion_is_addressable_by_id(self, seeded):
        conclusion_id = self._an_id(seeded)
        body = _get(seeded, f"/api/v3/conclusions/{conclusion_id}").as_dict()
        assert body["conclusions"][0]["id"] == conclusion_id

    def test_the_derivation_surface_discloses_the_formula_and_thresholds(
            self, seeded):
        conclusion_id = self._an_id(seeded)
        body = _get(
            seeded,
            f"/api/v3/conclusions/{conclusion_id}/derivation").as_dict()
        derivation = body["derivation"]
        assert derivation["formula_ref"].endswith("S1-CONC-001")
        assert derivation["threshold_ref"] == {"tl_critical": 3.0}
        assert derivation["source_urls"] == ["https://x/1"]
        assert "input_health" in derivation

    def test_an_unknown_id_is_404(self, seeded):
        assert _get(seeded, "/api/v3/conclusions/nope").status == 404


class TestR7AndR8Reliability:
    def test_an_unmeasurable_recall_is_none_with_a_reason(self, seeded):
        block = _get(seeded, "/api/v3/self_eval").as_dict()["self_eval"]
        assert block["calibration"]["recall"] is None
        assert block["calibration"]["recall_error"]
        assert block["calibration"]["drift"] is None

    def test_it_never_reports_zero_for_unmeasurable(self, seeded):
        block = _get(seeded, "/api/v3/self_eval").as_dict()["self_eval"]
        assert block["calibration"]["recall"] != 0.0
        assert block["calibration"]["drift"] != 0.0

    def test_the_data_block_reports_real_counts(self, seeded):
        block = _get(seeded, "/api/v3/self_eval").as_dict()["self_eval"]
        assert block["data"]["signal_count"] == 2
        assert block["data"]["tl_count"] == 6
        assert block["data"]["conclusion_count"] == len(CONCLUSION_TYPES)

    def test_a_declared_but_silent_sensor_is_listed_not_omitted(self, store):
        body = _get(store, "/api/v3/sensors",
                    adapters=("ripe_bgp", "gps_jamming")).as_dict()
        silent = {row["sensor"]: row for row in body["sensors"]}
        assert set(silent) == {"ripe_bgp", "gps_jamming"}
        assert silent["gps_jamming"]["observation_count"] == 0
        assert silent["gps_jamming"]["last_observed_at"] is None

    def test_observations_for_an_unknown_sensor_are_404(self, seeded):
        assert _get(seeded,
                    "/api/v3/sensors/nope/observations").status == 404

    def test_observations_come_back_for_a_live_sensor(self, seeded):
        body = _get(seeded,
                    "/api/v3/sensors/ripe_bgp/observations").as_dict()
        assert body["observation_count"] == 2
        assert body["scenario_id"] == TOOL_SCOPE


class TestR10AndR12AndR15:
    def test_thresholds_disclose_constants_too(self, seeded):
        body = _get(seeded, "/api/v3/thresholds").as_dict()
        assert "CALIBRATION_MIN_HISTORY_DAYS" in body["thresholds"][
            "conclusions"]
        assert body["thresholds"]["calibration"]
        assert body["unavailable_reason_registry"]

    def test_the_report_carries_the_sentence_in_the_document(self, seeded):
        body = _get(seeded,
                    f"/api/v3/scenarios/{SCENARIO}/report.md").as_dict()
        markdown = body["report"]["markdown"]
        assert NP7_DISCLAIMER in markdown
        assert f"# {SCENARIO}" in markdown
        for conclusion_type in CONCLUSION_TYPES:
            assert f"## {conclusion_type}" in markdown

    def test_healthz_is_public(self, seeded):
        """Public, and honest about what it does not know.

        This context is built without an ops probe, so the loop's state is
        UNSUPPLIED and the answer is `unknown` — not `ok`. That used to be
        a literal `"ok"`, which is why the shadow container reported
        healthy over a loop that had never completed a tick.
        The contract this test guards is that the route is PUBLIC; the
        four statuses are `tests/test_v3_health_surface.py`.
        """
        response = _get(seeded, "/healthz", principal=ANONYMOUS)
        assert response.status == 200
        assert response.as_dict()["health"]["status"] == "unknown"

    def test_app_config_is_what_the_composition_root_supplied(self, seeded):
        body = _get(seeded, "/api/v3/app_config").as_dict()
        assert body["app_config"] == {"cadence_sec": 900}


class TestTheEvaluationOrder:
    def test_authentication_is_decided_before_existence(self, seeded):
        """A caller with no principal never learns the id was wrong."""
        response = _get(seeded, "/api/v3/conclusions/does-not-exist",
                        principal=ANONYMOUS)
        assert response.status == 401

    def test_a_known_path_with_the_wrong_verb_is_not_a_404(self, seeded):
        request = ApiRequest(method="POST", path="/api/v3/scenarios",
                             principal=VIEWER)
        response = handle(request, _context(seeded))
        assert response.status == 400
        assert response.as_dict()["error_detail"]["code"] == \
            "api.method_not_allowed"


class TestTrendTypeSurvivesTheRoundTrip:
    def test_a_trend_row_rebuilds_with_its_metadata(self, store):
        store.append_conclusion(to_record(_conclusion(
            TREND, state="RISING")))
        body = _get(store,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        row = next(item for item in body["conclusions"]
                   if item["conclusion_type"] == TREND)
        assert row["state"] == "RISING"
        assert row["metadata"]["note"] == "fixture"


class TestTheFreshnessStamp:
    """P7 §3 — every projection says how old what it shows is."""

    def test_every_route_stamps_it(self, seeded):
        for path in ("/api/v3/scenarios",
                     f"/api/v3/scenarios/{SCENARIO}/conclusions",
                     f"/api/v3/scenarios/{SCENARIO}/conclusions/history",
                     f"/api/v3/scenarios/{SCENARIO}/evidence",
                     f"/api/v3/scenarios/{SCENARIO}/report.md",
                     "/api/v3/self_eval", "/api/v3/sensors",
                     "/api/v3/thresholds", "/api/v3/app_config", "/healthz"):
            body = _get(seeded, path).as_dict()
            assert "data_freshness_sec" in body, path
            assert body["served_at"] == NOW, path

    def test_a_refusal_is_stamped_too(self, seeded):
        body = _get(seeded, "/api/v3/scenarios/mars/conclusions").as_dict()
        assert "data_freshness_sec" in body

    def test_it_reports_the_age_of_the_row_not_of_the_request(self, store):
        store.append_conclusion(to_record(_conclusion(
            THREAT_LEVEL, observed_at=NOW - 3600.0)))
        body = _get(store,
                    f"/api/v3/scenarios/{SCENARIO}/conclusions").as_dict()
        assert body["data_freshness_sec"] == pytest.approx(3600.0)

    def test_a_handler_cannot_stamp_it_a_second_time(self):
        from v3.api.envelope import tool_response, with_freshness
        from v3.kernel.errors import DomainError
        response = tool_response(observed_at=NOW, data_freshness_sec=0.0)
        with pytest.raises(DomainError):
            with_freshness(response, NOW)


class TestTheUnimplementedIsRefusedNotFaked:
    def test_include_narrative_is_a_400_naming_its_owner(self, seeded):
        response = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions",
                        params={"include": "narrative"})
        assert response.status == 400
        detail = response.as_dict()["error_detail"]["detail"]
        assert detail["owner"].startswith("WP-4.1")

    def test_it_is_not_answered_with_a_silently_narrative_free_body(
            self, seeded):
        response = _get(seeded, f"/api/v3/scenarios/{SCENARIO}/conclusions",
                        params={"include": "narrative"})
        assert response.as_dict()["conclusions"] == []


class TestTheSeamCannotBeGrafted:
    def test_a_read_only_ledger_refuses_assignment(self, store):
        from v3.kernel.errors import DomainError
        ledger = ReadOnlyLedger(store)
        with pytest.raises(DomainError):
            ledger._store = store

    def test_it_refuses_to_wrap_itself(self, store):
        from v3.kernel.errors import DomainError
        with pytest.raises(DomainError):
            ReadOnlyLedger(ReadOnlyLedger(store))

    def test_the_dispatcher_refuses_a_context_that_is_not_read_only(
            self, store):
        from v3.kernel.errors import DomainError
        request = ApiRequest(method="GET", path="/healthz")
        with pytest.raises(DomainError):
            handle(request, store)
