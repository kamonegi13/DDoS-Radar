"""WP-0.4 v2 — the ETL edges: rows -> classifier inputs, verdicts -> drafts.

What this file pins, and the incident each guard answers:

* the identity ladder names the post-ACLED FN sources (`auto:rss`,
  `auto:rss_gdelt`) — without them the severity-floor rule raises on the
  very evidence the pipeline is built on;
* only FIRED, unsuppressed, graded-source rows become events — a
  suppressed row testifying in scoring's own audit is circularity with
  an extra step;
* an unavailable conclusion never becomes a position — scoring "cannot
  conclude" as a calm call is incident #1's perfect record, rebuilt out
  of absences;
* Tier 1 is a gate with exactly two answers, keyed to the pinned
  convergence floor (NP2);
* draft ids are deterministic so the daily re-scan converges.
"""
from __future__ import annotations

import json

import pytest

from v3.calibration import etl as ETL
from v3.calibration import ground_truth as GT
from v3.calibration import recall as R
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError

NOW = 1_760_000_000.0
HOUR = 3600.0


def _signal_row(**overrides) -> dict:
    base = {
        "signal_source": "bg_observer_rss", "sensor": "bg_observer_rss",
        "status": "FIRED", "suppressed": 0, "observed_at": NOW - HOUR,
        "raw_score": 5.0, "confidence": 0.6,
        "flags": json.dumps({"fatalities": 12,
                             "extractor_confidence": 0.9}),
        "evidence_url": "https://example.invalid/a",
    }
    base.update(overrides)
    return base


class TestTheLadderNamesThePostAcledSources:
    def test_rss_alone_is_one_automated_voter(self):
        assert GT.analyst_id_for(("rss",)) == "auto:rss"

    def test_rss_and_gdelt_converging_are_still_one_voter(self):
        assert GT.analyst_id_for(("rss", "gdelt")) == "auto:rss_gdelt"

    def test_the_pair_outranks_the_gdelt_single(self):
        # {"gdelt"} <= {"rss", "gdelt"} too — the pair entry must win,
        # or convergence would be recorded as a single-source identity.
        assert GT.analyst_id_for(("gdelt", "rss")) == "auto:rss_gdelt"

    def test_the_acled_entries_are_unchanged(self):
        assert GT.analyst_id_for(("acled", "gdelt")) == "auto:both"
        assert GT.analyst_id_for(("gdelt",)) == "auto:gdelt"


class TestEventFromSignal:
    def test_a_graded_rss_row_becomes_an_event(self):
        event = ETL.event_from_signal(_signal_row())
        assert event is not None
        assert event.source == "rss"
        assert event.fatalities == 12
        assert event.confidence == pytest.approx(0.9)
        assert event.url == "https://example.invalid/a"
        assert not event.is_circular

    def test_a_gdelt_row_becomes_a_zero_fatality_event(self):
        event = ETL.event_from_signal(_signal_row(
            signal_source="gdelt", sensor="gdelt", flags="{}",
            confidence=0.5))
        assert event is not None
        assert event.source == "gdelt"
        assert event.fatalities == 0
        assert event.confidence == pytest.approx(0.5)

    def test_a_non_graded_sensor_is_out_of_scope(self):
        assert ETL.event_from_signal(_signal_row(
            signal_source="ripe_bgp")) is None

    def test_a_suppressed_row_may_not_testify(self):
        assert ETL.event_from_signal(_signal_row(suppressed=1)) is None

    def test_an_observed_row_is_a_baseline_sample_not_an_event(self):
        assert ETL.event_from_signal(_signal_row(
            status="OBSERVED")) is None

    def test_mangled_flags_degrade_to_no_fatalities_not_a_crash(self):
        event = ETL.event_from_signal(_signal_row(flags="not json"))
        assert event is not None
        assert event.fatalities == 0


class TestPositionFromConclusion:
    def test_a_threat_level_row_becomes_a_position(self):
        position = ETL.position_from_conclusion(
            {"conclusion_type": "threat_level", "state": "TL2",
             "observed_at": NOW - HOUR}, now=NOW)
        assert position is not None
        assert position.tl == 2
        assert position.state == "TL2"

    def test_an_unavailable_conclusion_is_never_a_position(self):
        assert ETL.position_from_conclusion(
            {"conclusion_type": "threat_level", "state": None,
             "conclusion_unavailable_reason": "calibration_pending",
             "observed_at": NOW}, now=NOW) is None

    def test_attack_mode_is_out_of_measurement(self):
        # ADR-V3-012: its FN ground truth cannot be minted from RSS/GDELT.
        assert ETL.position_from_conclusion(
            {"conclusion_type": "attack_mode", "state": "cyber_first",
             "observed_at": NOW}, now=NOW) is None

    def test_an_unparseable_state_keeps_the_position_but_not_the_tl(self):
        position = ETL.position_from_conclusion(
            {"conclusion_type": "threat_level", "state": "weird",
             "observed_at": NOW - HOUR}, now=NOW)
        assert position is not None and position.tl is None


class TestTlOfState:
    def test_the_ladder_reads_the_defcon_style_number(self):
        assert ETL.tl_of_state("TL4") == 4
        assert ETL.tl_of_state("TL5") == 5

    def test_anything_else_is_none_never_a_guess(self):
        for value in ("", None, "4", "TLx", 4):
            assert ETL.tl_of_state(value) is None


class TestTier1IsAGate:
    def test_convergence_releases(self):
        assert ETL.tier1_decision(("gdelt", "rss")) == "auto_confirm"

    def test_a_single_source_waits(self):
        assert ETL.tier1_decision(("rss",)) == "pending"
        assert ETL.tier1_decision(()) == "pending"

    def test_the_floor_is_the_pinned_threshold(self):
        assert T.S9_TIER1_MIN_DISTINCT_SOURCES == 2


class TestDrafts:
    def _verdict(self):
        position = ETL.position_from_conclusion(
            {"conclusion_type": "threat_level", "state": "TL5",
             "observed_at": NOW - HOUR}, now=NOW)
        event = ETL.event_from_signal(_signal_row())
        verdict = GT.classify(position, (event,))
        assert verdict.label == "FALSE_NEGATIVE"
        return verdict

    def test_the_draft_id_is_deterministic(self):
        first = ETL.draft_id_for(conclusion_id="c1", rule_id="r",
                                 epoch_id="e")
        assert first == ETL.draft_id_for(conclusion_id="c1", rule_id="r",
                                         epoch_id="e")
        assert first != ETL.draft_id_for(conclusion_id="c2", rule_id="r",
                                         epoch_id="e")

    def test_a_draft_carries_the_verdict_verbatim(self):
        verdict = self._verdict()
        draft = ETL.draft_for(verdict, scenario_id="taiwan_contingency",
                              conclusion_id="c1", observed_at=NOW - HOUR,
                              labelled_at=NOW, sources=("rss",))
        assert draft.label == "FALSE_NEGATIVE"
        assert draft.rule_id == verdict.provenance.rule_id
        assert draft.proposed_analyst_id == verdict.analyst_id
        assert draft.sources == ("rss",)

    def test_only_an_fn_verdict_may_become_a_draft(self):
        position = ETL.position_from_conclusion(
            {"conclusion_type": "threat_level", "state": "TL2",
             "observed_at": NOW - HOUR}, now=NOW)
        event = ETL.event_from_signal(_signal_row())
        verdict = GT.classify(position, (event,))
        assert verdict.label == "TRUE_POSITIVE"
        with pytest.raises(DomainError):
            ETL.draft_for(verdict, scenario_id="s", conclusion_id="c",
                          observed_at=NOW, labelled_at=NOW, sources=())


class TestTheRecallInterval:
    def test_pending_widens_the_lower_bound(self):
        assert R.recall(tp=2, fn=1) == pytest.approx(2 / 3)
        assert R.recall_lower_bound(tp=2, fn=1, pending=1) == \
            pytest.approx(0.5)

    def test_an_empty_denominator_is_unmeasured_not_zero(self):
        assert R.recall_lower_bound(tp=0, fn=0, pending=0) is None

    def test_no_pending_means_the_bound_meets_the_point(self):
        assert R.recall_lower_bound(tp=3, fn=1, pending=0) == \
            R.recall(tp=3, fn=1)
