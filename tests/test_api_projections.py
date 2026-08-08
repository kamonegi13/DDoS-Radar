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
                            Suppression, THREAT_LEVEL, TREND, to_record)
from v3.conclusions import thresholds as CT
from v3.kernel import Evidence, ThreatLevel
from v3.ledger import LedgerStore, SignalObservation, TLObservation

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
        response = _get(seeded, "/healthz", principal=ANONYMOUS)
        assert response.status == 200
        assert response.as_dict()["health"]["status"] == "ok"

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
