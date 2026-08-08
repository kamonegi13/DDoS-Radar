"""WP-3.1 — the invariants a Conclusion enforces at construction.

Completion conditions 1 (Provenance required), 3 (suppression recorded),
4 (missing data is not calm) and 5 (one envelope, NP7 required) are all
properties of the type rather than of the code that happens to call it.
These tests are what stops them being downgraded to conventions.
"""
import copy
import json
import pickle

import pytest

from tests.conclusions_fixtures import NOW, healthy, provenance
from v3.conclusions import (Availability, Conclusion, ConclusionEnvelope,
                            InputHealth, Suppression, build)
from v3.conclusions import vocabulary as V
from v3.conclusions.availability import Candidate, evaluate
from v3.kernel.errors import DomainError, ProvenanceRequiredError


def _base(**overrides):
    kwargs = dict(scenario_id="taiwan_contingency",
                  conclusion_type=V.THREAT_LEVEL, observed_at=NOW,
                  confidence=0.5, provenance=provenance(),
                  input_health=healthy(), state="4")
    kwargs.update(overrides)
    return kwargs


class TestConditionOneProvenanceIsRequired:
    def test_a_conclusion_cannot_be_built_without_provenance(self):
        kwargs = _base()
        del kwargs["provenance"]
        with pytest.raises(TypeError):
            Conclusion(**kwargs)

    def test_a_none_provenance_is_refused(self):
        with pytest.raises(ProvenanceRequiredError):
            Conclusion(**_base(provenance=None))

    def test_a_dict_shaped_like_provenance_is_refused(self):
        with pytest.raises(ProvenanceRequiredError):
            Conclusion(**_base(provenance={"formula_ref": "x",
                                           "computed_at": NOW}))

    def test_the_message_says_why_disclosure_cannot_be_added_later(self):
        with pytest.raises(ProvenanceRequiredError) as excinfo:
            Conclusion(**_base(provenance=None))
        assert "NP6" in str(excinfo.value)

    def test_an_unavailable_conclusion_also_needs_provenance(self):
        suppression = Suppression(guard_id="g", reason=V.INSUFFICIENT_DATA,
                                  detail="nothing", overridden=False)
        with pytest.raises(ProvenanceRequiredError):
            Conclusion(**_base(provenance=None, state=None,
                               unavailable_reason=V.INSUFFICIENT_DATA,
                               suppression=suppression, confidence=0.0))


class TestConditionThreeSuppressionIsRecorded:
    def test_unavailable_without_a_suppression_record_is_refused(self):
        with pytest.raises(DomainError, match="E-17"):
            Conclusion(**_base(state=None,
                               unavailable_reason=V.SENSOR_DEGRADED,
                               confidence=0.0))

    def test_the_recorded_reason_must_match_the_conclusion(self):
        suppression = Suppression(guard_id="g", reason=V.UPSTREAM_FAILURE,
                                  detail="all feeds down", overridden=False)
        with pytest.raises(DomainError, match="two answers"):
            Conclusion(**_base(state=None,
                               unavailable_reason=V.SENSOR_DEGRADED,
                               suppression=suppression, confidence=0.0))

    def test_an_overridden_suppression_cannot_also_be_unavailable(self):
        suppression = Suppression(guard_id="g", reason=V.SENSOR_DEGRADED,
                                  detail="half the feeds", overridden=True)
        with pytest.raises(DomainError, match="published anyway"):
            Conclusion(**_base(state=None,
                               unavailable_reason=V.SENSOR_DEGRADED,
                               suppression=suppression, confidence=0.0))

    def test_a_live_suppression_beside_a_published_state_is_refused(self):
        suppression = Suppression(guard_id="g", reason=V.SENSOR_DEGRADED,
                                  detail="half the feeds", overridden=False)
        with pytest.raises(DomainError, match="must make the conclusion"):
            Conclusion(**_base(suppression=suppression))

    def test_a_suppression_needs_plain_text_not_only_a_code(self):
        with pytest.raises(DomainError, match="plain text"):
            Suppression(guard_id="g", reason=V.SENSOR_DEGRADED, detail="  ",
                        overridden=False)

    def test_a_suppression_carries_every_guard_that_was_evaluated(self):
        verdict = evaluate(InputHealth(sources_failed=("a", "b")),
                           Candidate(state="5", calm=True))
        assert verdict.suppression is not None
        guard_ids = {item.guard_id for item in verdict.suppression.evaluated}
        assert guard_ids == {"upstream_total_loss",
                             "sensor_coverage_degraded", "no_basis_at_all",
                             "derivation_produced_nothing",
                             "history_below_calibration_window"}

    def test_the_record_survives_into_the_ledger_metadata(self):
        verdict = evaluate(InputHealth(sources_failed=("a",)),
                           Candidate(state="5", calm=True))
        conclusion = build(
            scenario_id="s", conclusion_type=V.THREAT_LEVEL, observed_at=NOW,
            confidence=0.0, provenance=provenance(),
            input_health=InputHealth(sources_failed=("a",)),
            availability=verdict)
        payload = json.loads(conclusion.json_metadata())
        assert payload["suppression"]["guard_id"] == "upstream_total_loss"
        assert payload["suppression"]["overridden"] is False


class TestConditionFourAbsentDataIsNeverCalm:
    def test_a_state_with_no_source_consulted_is_refused(self):
        with pytest.raises(DomainError, match="G-17"):
            Conclusion(**_base(input_health=InputHealth()))

    def test_the_refusal_names_the_report_that_did_it(self):
        with pytest.raises(DomainError) as excinfo:
            Conclusion(**_base(input_health=InputHealth()))
        assert "ROUTINE" in str(excinfo.value)

    def test_an_unavailable_conclusion_with_no_basis_is_fine(self):
        health = InputHealth()
        verdict = evaluate(health, Candidate(state="5", calm=True))
        conclusion = build(scenario_id="s", conclusion_type=V.THREAT_LEVEL,
                           observed_at=NOW, confidence=0.0,
                           provenance=provenance(), input_health=health,
                           availability=verdict)
        assert conclusion.unavailable_reason == V.INSUFFICIENT_DATA

    def test_a_healthy_quiet_tick_still_produces_a_calm_verdict(self):
        # The other half of condition 4: genuine calm has to stay sayable,
        # otherwise "no data" and "quiet" collapse the other way round and
        # every tick is unavailable (NP5+8's design failure).
        conclusion = Conclusion(**_base(state="5"))
        assert conclusion.is_available and conclusion.state == "5"

    def test_input_health_travels_on_the_row(self):
        conclusion = Conclusion(**_base())
        assert conclusion.as_dict()["input_health"]["consulted"] == 4

    def test_a_source_cannot_be_both_healthy_and_failed(self):
        with pytest.raises(DomainError, match="hides an outage"):
            InputHealth(sources_ok=("a",), sources_failed=("a",))

    def test_a_bare_string_source_list_is_refused(self):
        with pytest.raises(DomainError, match="counts its characters"):
            InputHealth(sources_ok="ripe_bgp")


class TestConditionFiveOneEnvelopeWithTheDisclaimer:
    def test_the_disclaimer_is_a_required_field_of_the_conclusion(self):
        with pytest.raises(DomainError, match="NP7"):
            Conclusion(**_base(disclaimer=""))

    def test_a_none_disclaimer_is_refused(self):
        with pytest.raises(DomainError):
            Conclusion(**_base(disclaimer=None))

    def test_the_envelope_carries_the_disclaimer(self):
        envelope = ConclusionEnvelope(scenario_id="s",
                                      conclusions=(Conclusion(**_base()),))
        assert envelope.as_dict()["final_judgment_disclaimer"] == \
            V.NP7_DISCLAIMER

    def test_an_error_response_uses_the_same_envelope(self):
        envelope = ConclusionEnvelope.failure(
            scenario_id="s", error="unknown_conclusion_type", observed_at=NOW)
        payload = envelope.as_dict()
        assert payload["final_judgment_disclaimer"] == V.NP7_DISCLAIMER
        assert payload["api_version"] == "3.0"
        assert payload["error"] == "unknown_conclusion_type"

    def test_a_blank_disclaimer_on_an_error_envelope_is_refused(self):
        with pytest.raises(DomainError, match="G-13"):
            ConclusionEnvelope(scenario_id="s", disclaimer="")

    def test_every_conclusion_keeps_its_own_disclaimer_inside_the_envelope(self):
        envelope = ConclusionEnvelope(scenario_id="s",
                                      conclusions=(Conclusion(**_base()),))
        item = envelope.as_dict()["conclusions"][0]
        assert item["final_judgment_disclaimer"] == V.NP7_DISCLAIMER

    def test_extra_cannot_overwrite_a_reserved_key(self):
        # `extra` is merged last in as_dict(), so a reserved key there is
        # a path that overwrites the NP7 sentence AFTER the constructor
        # validated it — G-13 by a side door, on the error path where the
        # sentence went missing the first time.
        with pytest.raises(DomainError, match="reserved key"):
            ConclusionEnvelope.failure(
                scenario_id="s", error="boom", observed_at=NOW,
                final_judgment_disclaimer=None)

    def test_extra_cannot_replace_the_conclusions_list(self):
        with pytest.raises(DomainError, match="reserved key"):
            ConclusionEnvelope(scenario_id="s",
                               extra={"conclusions": "gone"})

    def test_extra_is_copied_not_aliased(self):
        supplied = {"note": "hello"}
        envelope = ConclusionEnvelope(scenario_id="s", extra=supplied)
        supplied["injected"] = "x"
        assert "injected" not in envelope.as_dict()

    def test_a_substitute_disclaimer_is_refused(self):
        with pytest.raises(DomainError, match="THE NP7 disclaimer"):
            ConclusionEnvelope(scenario_id="s", disclaimer="Trust me.")

    def test_the_envelope_refuses_a_hand_built_dict(self):
        # ACCIDENTAL A2: the empty-scenario response bypassed the type and
        # therefore every invariant on it.
        with pytest.raises(DomainError, match="A2"):
            ConclusionEnvelope(scenario_id="s", conclusions=({"state": "5"},))

    def test_observed_at_defaults_to_the_newest_conclusion(self):
        older = Conclusion(**_base(observed_at=NOW - 60))
        newer = Conclusion(**_base(observed_at=NOW))
        envelope = ConclusionEnvelope(scenario_id="s",
                                      conclusions=(older, newer))
        assert envelope.observed_at == NOW

    def test_replay_uses_the_same_shape_as_live(self):
        envelope = ConclusionEnvelope(scenario_id="s", at=NOW - 3600,
                                      conclusions=(Conclusion(**_base()),))
        payload = envelope.as_dict()
        assert payload["at"] == NOW - 3600
        assert set(payload) >= {"api_version", "scenario_id", "observed_at",
                                "final_judgment_disclaimer", "conclusions"}


class TestSchemaInvariants:
    def test_only_the_five_types_are_accepted(self):
        with pytest.raises(DomainError, match="five outputs"):
            Conclusion(**_base(conclusion_type="salute_report"))

    def test_ids_are_unique_per_conclusion(self):
        ids = {Conclusion(**_base()).conclusion_id for _ in range(50)}
        assert len(ids) == 50

    def test_confidence_above_one_is_refused_not_clamped(self):
        with pytest.raises(DomainError, match="refused rather than clamped"):
            Conclusion(**_base(confidence=1.4))

    def test_confidence_below_zero_is_refused(self):
        with pytest.raises(DomainError):
            Conclusion(**_base(confidence=-0.1))

    def test_state_and_reason_are_exclusive(self):
        suppression = Suppression(guard_id="g", reason=V.INSUFFICIENT_DATA,
                                  detail="d", overridden=False)
        with pytest.raises(DomainError, match="whichever one it prefers"):
            Conclusion(**_base(state="4",
                               unavailable_reason=V.INSUFFICIENT_DATA,
                               suppression=suppression))

    def test_neither_state_nor_reason_is_refused(self):
        with pytest.raises(DomainError, match="NP5"):
            Conclusion(**_base(state=None))

    def test_an_unknown_reason_is_refused(self):
        suppression_kwargs = dict(guard_id="g", reason="feeling_uncertain",
                                  detail="d", overridden=False)
        with pytest.raises(DomainError, match="F-12"):
            Suppression(**suppression_kwargs)

    def test_a_conclusion_is_frozen(self):
        conclusion = Conclusion(**_base())
        with pytest.raises(Exception):
            conclusion.state = "1"

    def test_metadata_cannot_be_edited_through_the_conclusion(self):
        conclusion = Conclusion(**_base(metadata={"score": 2.5}))
        with pytest.raises(TypeError):
            conclusion.metadata["score"] = 9.9

    def test_a_substitute_conclusion_disclaimer_is_refused(self):
        # Requiring "some non-empty text" would let the sentence be
        # replaced as easily as it was once dropped.
        with pytest.raises(DomainError, match="THE sentence"):
            Conclusion(**_base(disclaimer="Trust me bro."))

    def test_nested_metadata_cannot_be_edited_through_the_builder(self):
        # A read-only proxy over a SHALLOW copy leaves rationale_matrix,
        # ranked_modes and windows — the structures carrying the actual
        # disclosure — shared with the caller. Immutability one level deep
        # is the kind of guarantee that reads as complete and is not.
        supplied = {"rationale_matrix": [{"final_contribution": 3.2}]}
        conclusion = Conclusion(**_base(metadata=supplied))
        supplied["rationale_matrix"][0]["final_contribution"] = 999.0
        assert conclusion.metadata["rationale_matrix"][0][
            "final_contribution"] == 3.2

    def test_nested_metadata_cannot_be_edited_through_as_dict(self):
        conclusion = Conclusion(**_base(
            metadata={"rationale_matrix": [{"final_contribution": 3.2}]}))
        payload = conclusion.as_dict()
        payload["metadata"]["rationale_matrix"][0][
            "final_contribution"] = -1.0
        assert conclusion.metadata["rationale_matrix"][0][
            "final_contribution"] == 3.2

    def test_nested_threshold_ref_is_protected_the_same_way(self):
        supplied = {"ladder": {"tl1": 9.0}}
        conclusion = Conclusion(**_base(threshold_ref=supplied))
        supplied["ladder"]["tl1"] = 0.1
        assert conclusion.threshold_ref["ladder"]["tl1"] == 9.0

    def test_it_survives_a_pickle_round_trip_revalidated(self):
        conclusion = Conclusion(**_base(metadata={"score": 2.5}))
        restored = pickle.loads(pickle.dumps(conclusion))
        assert restored.as_dict() == conclusion.as_dict()

    def test_deepcopy_works_despite_the_read_only_mappings(self):
        conclusion = Conclusion(**_base(metadata={"score": 2.5}))
        assert copy.deepcopy(conclusion).as_dict() == conclusion.as_dict()

    def test_the_api_form_is_json_serialisable(self):
        conclusion = Conclusion(**_base(metadata={"score": 2.5}))
        assert json.loads(json.dumps(conclusion.as_dict()))["state"] == "4"

    def test_ledger_metadata_is_key_sorted(self):
        conclusion = Conclusion(**_base(metadata={"b": 1, "a": 2}))
        payload = conclusion.json_metadata()
        assert payload.index('"a"') < payload.index('"b"')

    def test_build_refuses_a_bare_reason_string(self):
        with pytest.raises(TypeError, match="F-12"):
            build(scenario_id="s", conclusion_type=V.THREAT_LEVEL,
                  observed_at=NOW, confidence=0.0, provenance=provenance(),
                  input_health=healthy(), availability=V.INSUFFICIENT_DATA)

    def test_an_availability_without_a_suppression_is_refused(self):
        with pytest.raises(DomainError, match="E-17"):
            Availability(available=False, reason=V.INSUFFICIENT_DATA,
                         suppression=None)

    def test_an_available_availability_cannot_carry_a_reason(self):
        with pytest.raises(DomainError):
            Availability(available=True, reason=V.INSUFFICIENT_DATA,
                         suppression=None)


class TestUnavailableAssertsNothing:
    """S1-CONC-004: an unavailable conclusion is not a finding of absence."""

    def test_the_row_says_so_explicitly(self):
        health = InputHealth(sources_ok=("a",), history_span_sec=0.0)
        verdict = evaluate(health, Candidate(state="5", calm=True))
        conclusion = build(scenario_id="s", conclusion_type=V.ATTACK_MODE,
                           observed_at=NOW, confidence=0.0,
                           provenance=provenance(), input_health=health,
                           availability=verdict)
        assert conclusion.metadata["asserts_absence"] is False
        assert conclusion.metadata["reason_detail"]

    def test_a_transient_reason_is_marked_transient(self):
        health = InputHealth(sources_ok=("a",), history_span_sec=0.0)
        verdict = evaluate(health, Candidate(state="5", calm=True))
        conclusion = build(scenario_id="s", conclusion_type=V.THREAT_LEVEL,
                           observed_at=NOW, confidence=0.0,
                           provenance=provenance(), input_health=health,
                           availability=verdict)
        assert conclusion.unavailable_reason == V.CALIBRATION_PENDING
        assert conclusion.metadata["is_transient"] is True

    def test_confidence_of_an_unavailable_conclusion_is_zero(self):
        health = InputHealth()
        verdict = evaluate(health, Candidate(state=None, calm=True,
                                             derivable=False, detail="none"))
        conclusion = build(scenario_id="s", conclusion_type=V.TREND,
                           observed_at=NOW, confidence=0.9,
                           provenance=provenance(), input_health=health,
                           availability=verdict)
        assert conclusion.confidence == 0.0
