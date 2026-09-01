"""WP-2.8 — the comparison engine, clause by clause.

Every number here is hand-computed from S5-VERIF-023..029's definitions.
The engine is where a parity result is most easily flattered — by counting
a missing row as agreement, by averaging a v3 miss against a v3 extra, or
by comparing raw TL integers and getting the sign backwards — so each of
those is tested as a distinct failure it must refuse to commit.
"""
import pytest

from v3.kernel import ThreatLevel
from v3.kernel.errors import DomainError, OrderingForbiddenError
from v3.parity.compare import (ANOMALY, ATTACK_MODE, DE_ESCALATE, ESCALATE,
                               _percentile,
                               INSENSITIVE, MATCH, MISMATCH, ONE_SIDE_MISSING,
                               PARTIAL, PER_DOMAIN, SENSITIVE, SIDE_LEGACY,
                               SIDE_V3, THREAT_LEVEL, TREND, Contributor,
                               Reading, TickKey, Transition, compare_tick,
                               compare_transitions, extract_transitions)
from v3.parity.summary import summarise

T0 = 1_700_000_000.0


def key(kind=THREAT_LEVEL, at=T0, scenario="taiwan_contingency") -> TickKey:
    return TickKey(scenario, kind, at)


def tl(value):
    return Reading(threat_level=ThreatLevel(value))


class TestSeveritySpaceOnly:
    """S5-VERIF-024: raw TL comparison must not be reachable."""

    def test_a_reading_holds_a_kernel_threat_level(self):
        assert tl(2).threat_level.severity() == 4

    def test_a_raw_int_is_refused_at_construction(self):
        with pytest.raises(DomainError, match="kernel ThreatLevel"):
            Reading(threat_level=3)

    def test_the_levels_themselves_refuse_ordering(self):
        with pytest.raises(OrderingForbiddenError):
            _ = ThreatLevel(1) < ThreatLevel(5)

    def test_severity_is_six_minus_tl(self):
        for value in range(1, 6):
            assert tl(value).severity == 6 - value

    def test_the_null_zone_has_no_severity(self):
        assert Reading().severity is None


class TestTickVerdicts:
    def test_identical_levels_match(self):
        result = compare_tick(key(), tl(3), tl(3))
        assert result.verdict == MATCH and result.direction is None

    def test_two_null_zones_match(self):
        """S5-VERIF-025: INSUFFICIENT_DATA on both sides is agreement."""
        result = compare_tick(key(), Reading(), Reading())
        assert result.verdict == MATCH

    def test_a_quieter_v3_is_insensitive_and_blocking(self):
        """legacy TL2 (severity 4) vs v3 TL4 (severity 2)."""
        result = compare_tick(key(), tl(2), tl(4))
        assert result.verdict == MISMATCH
        assert result.direction == INSENSITIVE
        assert result.is_blocking is True

    def test_a_louder_v3_is_sensitive_and_not_blocking(self):
        result = compare_tick(key(), tl(4), tl(2))
        assert result.verdict == MISMATCH
        assert result.direction == SENSITIVE
        assert result.is_blocking is False

    def test_v3_alone_in_the_null_zone_is_insensitive(self):
        """Declining to conclude where legacy raised a level is seeing less."""
        result = compare_tick(key(), tl(2), Reading())
        assert result.verdict == MISMATCH
        assert result.direction == INSENSITIVE

    def test_legacy_alone_in_the_null_zone_is_sensitive(self):
        result = compare_tick(key(), Reading(), tl(2))
        assert result.direction == SENSITIVE

    def test_a_missing_legacy_row_is_neither_agreement_nor_disagreement(self):
        result = compare_tick(key(), None, tl(3))
        assert result.verdict == ONE_SIDE_MISSING
        assert result.missing_side == SIDE_LEGACY
        assert result.is_blocking is False

    def test_a_missing_v3_row_is_recorded_as_such(self):
        result = compare_tick(key(), tl(3), None)
        assert result.verdict == ONE_SIDE_MISSING
        assert result.missing_side == SIDE_V3

    def test_a_key_with_nothing_on_either_side_is_refused(self):
        with pytest.raises(DomainError):
            compare_tick(key(), None, None)

    def test_an_unknown_conclusion_type_is_refused(self):
        with pytest.raises(DomainError, match="S5-VERIF-027"):
            compare_tick(key(kind="invented"), tl(3), tl(3))


class TestUnavailableReasonIsPartOfIdentity:
    """S5-VERIF-027: a different reason is a different answer."""

    def test_same_null_zone_different_reason_is_a_mismatch(self):
        legacy = Reading(unavailable_reason="insufficient_data")
        v3 = Reading(unavailable_reason="calibration_missing")
        result = compare_tick(key(), legacy, v3)
        assert result.verdict == MISMATCH
        assert "unavailable_reason" in result.detail

    def test_same_reason_still_matches(self):
        reading = Reading(unavailable_reason="insufficient_data")
        assert compare_tick(key(), reading, reading).verdict == MATCH


class TestPerTypeRules:
    def test_per_domain_needs_every_domain_to_agree(self):
        legacy = Reading(domain_states={"cyber": "A", "physical": "B",
                                        "info": "C"})
        same = Reading(domain_states={"cyber": "A", "physical": "B",
                                      "info": "C"})
        differs = Reading(domain_states={"cyber": "A", "physical": "B",
                                         "info": "X"})
        assert compare_tick(key(PER_DOMAIN), legacy, same).verdict == MATCH
        result = compare_tick(key(PER_DOMAIN), legacy, differs)
        assert result.verdict == MISMATCH and "info" in result.detail

    def test_attack_mode_compares_the_state_string(self):
        assert compare_tick(key(ATTACK_MODE), Reading(state="X"),
                            Reading(state="X")).verdict == MATCH
        assert compare_tick(key(ATTACK_MODE), Reading(state="X"),
                            Reading(state="Y")).verdict == MISMATCH

    def test_trend_direction_only_agreement_is_partial(self):
        result = compare_tick(key(TREND), Reading(state="ESCALATING_FAST"),
                              Reading(state="ESCALATING_SLOW"))
        assert result.verdict == PARTIAL

    def test_trend_opposite_directions_is_a_full_mismatch(self):
        result = compare_tick(key(TREND), Reading(state="ESCALATING"),
                              Reading(state="STABLE"))
        assert result.verdict == MISMATCH

    def test_anomaly_compares_key_sets(self):
        legacy = Reading(anomaly_keys=frozenset({"a", "b"}))
        assert compare_tick(key(ANOMALY), legacy, legacy).verdict == MATCH

    def test_an_anomaly_missing_from_v3_is_insensitive(self):
        legacy = Reading(anomaly_keys=frozenset({"a", "b"}))
        v3 = Reading(anomaly_keys=frozenset({"a"}))
        result = compare_tick(key(ANOMALY), legacy, v3)
        assert result.verdict == MISMATCH
        assert result.direction == INSENSITIVE

    def test_an_extra_anomaly_in_v3_is_sensitive(self):
        legacy = Reading(anomaly_keys=frozenset({"a"}))
        v3 = Reading(anomaly_keys=frozenset({"a", "b"}))
        assert compare_tick(key(ANOMALY), legacy, v3).direction == SENSITIVE


class TestContributorAgreement:
    """S5-VERIF-028."""

    def _reading(self, *names):
        return Reading(threat_level=ThreatLevel(3), contributing=tuple(
            Contributor(name, "src", "TW") for name in names))

    def test_identical_sets_score_one(self):
        result = compare_tick(key(), self._reading("a", "b"),
                              self._reading("a", "b"))
        assert result.jaccard == pytest.approx(1.0)

    def test_half_overlap_scores_one_third(self):
        result = compare_tick(key(), self._reading("a", "b"),
                              self._reading("b", "c"))
        assert result.jaccard == pytest.approx(1 / 3)

    def test_two_empty_sets_agree_completely(self):
        result = compare_tick(key(), tl(3), tl(3))
        assert result.jaccard == pytest.approx(1.0)

    def test_agreeing_tls_can_still_disagree_on_evidence(self):
        """The coincidental-agreement case NP6 refuses to accept."""
        result = compare_tick(key(), self._reading("a"), self._reading("z"))
        assert result.verdict == MATCH
        assert result.jaccard == pytest.approx(0.0)


class TestTransitions:
    """S5-VERIF-026."""

    def _series(self, *pairs):
        return [(at, tl(value)) for at, value in pairs]

    def test_a_flat_series_has_no_transitions(self):
        assert extract_transitions(self._series((T0, 5), (T0 + 60, 5))) == ()

    def test_a_change_is_extracted_with_its_direction(self):
        found = extract_transitions(self._series((T0, 5), (T0 + 60, 3)))
        assert len(found) == 1
        assert found[0].direction == ESCALATE     # severity 1 -> 3
        assert found[0].to_severity == 3

    def test_relaxing_is_a_de_escalation(self):
        found = extract_transitions(self._series((T0, 2), (T0 + 60, 4)))
        assert found[0].direction == DE_ESCALATE

    def test_entering_the_null_zone_is_a_transition(self):
        series = [(T0, tl(3)), (T0 + 60, Reading())]
        found = extract_transitions(series)
        assert len(found) == 1 and found[0].direction == DE_ESCALATE

    def test_matching_transitions_pair_with_their_lag(self):
        legacy = (Transition(T0, 1, 3),)
        v3 = (Transition(T0 + 120, 1, 3),)
        timing = compare_transitions(legacy, v3)
        assert timing.deltas == (120.0,)
        assert timing.median_delta_sec == 120.0
        assert timing.unpaired_legacy == 0 and timing.unpaired_v3 == 0

    def test_a_different_destination_does_not_pair(self):
        timing = compare_transitions((Transition(T0, 1, 3),),
                                     (Transition(T0 + 5, 1, 4),))
        assert timing.unpaired_legacy == 1 and timing.unpaired_v3 == 1
        assert timing.deltas == ()

    def test_a_different_direction_does_not_pair(self):
        timing = compare_transitions((Transition(T0, 1, 3),),
                                     (Transition(T0 + 5, 5, 3),))
        assert timing.unpaired_legacy == 1 and timing.unpaired_v3 == 1

    def test_the_nearest_candidate_wins(self):
        legacy = (Transition(T0, 1, 3),)
        v3 = (Transition(T0 + 600, 1, 3), Transition(T0 + 30, 1, 3))
        timing = compare_transitions(legacy, v3)
        assert timing.deltas == (30.0,)
        assert timing.unpaired_v3 == 1

    def test_p95_is_reported(self):
        legacy = tuple(Transition(T0 + i * 1000, 1, 3) for i in range(20))
        v3 = tuple(Transition(T0 + i * 1000 + i, 1, 3) for i in range(20))
        timing = compare_transitions(legacy, v3)
        assert timing.p95_delta_sec is not None
        assert timing.p95_delta_sec >= timing.median_delta_sec


class TestPercentileIsNearestRank:
    """The p95/p05 definition, pinned.

    `round(f*n + 0.5)` inherited Python's banker's rounding and was off by
    one in both self-flattering directions: at n=20 it reported the
    maximum as p95, and it skipped the single worst value at p05. Both
    statistics exist to keep the report honest, so both are pinned here.
    """

    @pytest.mark.parametrize("n,fraction,expected", [
        (20, 0.95, 19.0),
        (20, 0.05, 1.0),      # the worst tick must be included
        (100, 0.95, 95.0),
        (100, 0.05, 5.0),
        (1, 0.95, 1.0),
        (1, 0.05, 1.0),
        (2, 0.95, 2.0),
        (2, 0.05, 1.0),
    ])
    def test_pinned_ranks(self, n, fraction, expected):
        ordered = tuple(float(i) for i in range(1, n + 1))
        assert _percentile(ordered, fraction) == expected

    def test_p95_is_never_the_maximum_for_n_of_twenty(self):
        ordered = tuple(float(i) for i in range(1, 21))
        assert _percentile(ordered, 0.95) < ordered[-1]

    def test_p05_includes_the_single_worst_value(self):
        ordered = (0.0,) + tuple(float(i) for i in range(1, 20))
        assert _percentile(ordered, 0.05) == 0.0

    def test_an_empty_sequence_is_refused(self):
        with pytest.raises(DomainError):
            _percentile((), 0.95)

    def test_the_p05_reaches_the_worst_jaccard_in_a_summary(self):
        """End to end: one bad-evidence tick among twenty must surface."""
        comparisons = [
            compare_tick(key(at=T0 + i * 60),
                         Reading(threat_level=ThreatLevel(3),
                                 contributing=(Contributor("a", "s", "TW"),)),
                         Reading(threat_level=ThreatLevel(3),
                                 contributing=(Contributor("a", "s", "TW"),)))
            for i in range(19)]
        comparisons.append(compare_tick(
            key(at=T0 + 19 * 60),
            Reading(threat_level=ThreatLevel(3),
                    contributing=(Contributor("a", "s", "TW"),)),
            Reading(threat_level=ThreatLevel(3),
                    contributing=(Contributor("z", "s", "TW"),))))
        summary = summarise(comparisons)
        assert summary.jaccard_p05 == pytest.approx(0.0)


class TestSummary:
    """S5-VERIF-025 and 029 in aggregate."""

    def _comparisons(self, matches, insensitive, sensitive, missing):
        out = []
        stamp = T0
        for _ in range(matches):
            out.append(compare_tick(key(at=stamp), tl(3), tl(3)))
            stamp += 60
        for _ in range(insensitive):
            out.append(compare_tick(key(at=stamp), tl(2), tl(4)))
            stamp += 60
        for _ in range(sensitive):
            out.append(compare_tick(key(at=stamp), tl(4), tl(2)))
            stamp += 60
        for _ in range(missing):
            out.append(compare_tick(key(at=stamp), None, tl(3)))
            stamp += 60
        return out

    def test_agreement_excludes_one_side_missing_from_the_denominator(self):
        summary = summarise(self._comparisons(8, 1, 1, 10))
        assert summary.both_present == 10
        assert summary.agreement_rate == pytest.approx(0.8)

    def test_directions_are_counted_separately_never_summed(self):
        summary = summarise(self._comparisons(5, 3, 2, 0))
        assert summary.insensitive == 3 and summary.sensitive == 2
        assert summary.has_blocking_mismatch is True

    def test_a_purely_sensitive_run_does_not_block(self):
        summary = summarise(self._comparisons(5, 0, 4, 0))
        assert summary.has_blocking_mismatch is False

    def test_too_many_gaps_voids_the_run(self):
        summary = summarise(self._comparisons(90, 0, 0, 10))
        assert summary.one_side_missing_rate == pytest.approx(0.1)
        assert summary.is_void is True

    def test_a_few_gaps_do_not_void_the_run(self):
        summary = summarise(self._comparisons(98, 0, 0, 2))
        assert summary.is_void is False

    def test_agreement_is_none_when_nothing_is_comparable(self):
        """Neither 0.0 nor 1.0 — the data supports no claim."""
        summary = summarise(self._comparisons(0, 0, 0, 5))
        assert summary.agreement_rate is None

    def test_examples_accompany_the_counts(self):
        summary = summarise(self._comparisons(0, 3, 0, 0))
        assert len(summary.insensitive_examples) == 3
        assert all(c.is_blocking for c in summary.insensitive_examples)

    def test_missing_rows_do_not_drag_the_jaccard_down(self):
        summary = summarise(self._comparisons(2, 0, 0, 8))
        assert summary.jaccard_median == pytest.approx(1.0)

    def test_the_summary_is_json_ready(self):
        import json
        json.dumps(summarise(self._comparisons(3, 1, 1, 1)).as_dict(),
                   allow_nan=False)
