"""WP-3.2 condition 4 — the twelve guards the three incidents left behind.

S1-calibration marks twelve clauses "由来: インシデント #1/#2/#3":

    001 severity space          002 conflict-party attribution
    004 FN definition           005 TP definition
    006 horizon before absence  009 kinetic tier needs a verb
    010 relevance ladder        011 episode granularity
    013 idempotency             016 direction-keyed freshness
    023 revert                  028 one recall window

They are the sediment of five weeks of rewarding calm misjudgements, of
12/15 Korean false negatives being Iran and Ukraine articles, and of one
article generating 23,000 labels. Each is pinned below by the behaviour
that would have caught its incident.
"""
from __future__ import annotations

import pytest

from v3.calibration import ground_truth as GT
from v3.calibration import epoch as E
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError
from v3.kernel.threat_level import ThreatLevel


# ── 001: severity space ─────────────────────────────────────────────────

class TestSeveritySpace:
    """Incident #2: the classifier treated 5 as worst. TL is DEFCON-style."""

    def test_severity_is_six_minus_tl(self):
        assert GT.severity_of(1) == 5
        assert GT.severity_of(5) == 1

    def test_a_tl_outside_one_to_five_raises_rather_than_scoring(self):
        for bad in (0, 6, -1):
            with pytest.raises(DomainError):
                GT.severity_of(bad)

    def test_an_unparsed_state_string_raises_rather_than_scoring_quietly(self):
        with pytest.raises(DomainError):
            GT.severity_of("ELEVATED")

    def test_the_kernel_type_has_no_ordering_operators(self):
        # The structural half: even if a call site forgot severity_of, a
        # bare `<` on the kernel type refuses.
        with pytest.raises(TypeError):
            ThreatLevel(1) < ThreatLevel(5)

    def test_tl_one_is_the_alert_end(self):
        assert GT.severity_of(1) > GT.severity_of(5)


# ── 002: attribution ────────────────────────────────────────────────────

class TestConflictPartyAttribution:
    """Incident #3: supporting-role fan-out pulled other wars in."""

    def test_the_attribution_roles_match_production(self):
        assert GT.CONFLICT_PARTY_ROLES == frozenset({
            "adversary", "primary_target", "principal_belligerent",
            "proxy_front"})

    @pytest.mark.parametrize("role", ["primary_ally", "forward_base",
                                      "strategic_observer"])
    def test_supporting_roles_may_not_be_attributed(self, role):
        assert GT.may_attribute(role) is False

    @pytest.mark.parametrize("role", sorted(GT.CONFLICT_PARTY_ROLES))
    def test_conflict_party_roles_may_be_attributed(self, role):
        assert GT.may_attribute(role) is True

    def test_sensing_keeps_the_wide_net(self):
        # NP1: the ETL gate must NOT be applied to bg_observer.
        assert GT.may_sense("strategic_observer") is True
        assert GT.may_sense("forward_base") is True

    def test_an_unknown_role_may_not_be_attributed(self):
        assert GT.may_attribute("some_new_role") is False

    def test_an_empty_attribution_skips_rather_than_raising(self):
        assert GT.attributable_countries({}) == ()

    def test_only_conflict_party_participants_survive(self):
        participants = {"TW": "primary_target", "US": "primary_ally",
                        "CN": "adversary", "JP": "forward_base"}
        assert GT.attributable_countries(participants) == ("CN", "TW")


# ── 004/005/006: the label rules and their order ────────────────────────

def _ev(**kw):
    base = dict(source="acled", severity=12, fatalities=12, confidence=0.9,
                observed_at=1000.0, url="https://example.test/a")
    base.update(kw)
    return GT.ExternalEvent(**base)


def _obs(**kw):
    base = dict(conclusion_type="threat_level", tl=5, state="5",
                observed_at=1000.0, now=1000.0 + 8 * 86400.0)
    base.update(kw)
    return GT.ToolPosition(**base)


class TestRuleOrder:
    """S1-CALIB-003: FN > TP > FP > TN, first match wins, NP1 encoded."""

    def test_the_declared_order_is_fn_tp_fp_tn(self):
        assert GT.RULE_ORDER == ("FALSE_NEGATIVE", "TRUE_POSITIVE",
                                 "FALSE_POSITIVE", "TRUE_NEGATIVE")

    def test_no_rule_matching_produces_no_label_at_all(self):
        # Not TN: "consistent with the evidence so far, but the horizon
        # that would let us claim absence has not elapsed".
        verdict = GT.classify(_obs(now=1000.0 + 3600.0), events=())
        assert verdict.label is None
        assert verdict.reason == "horizon_not_elapsed"

    def test_a_false_negative_beats_a_true_positive_on_the_same_input(self):
        # An under-rated call with a qualifying event is a miss, not a hit.
        verdict = GT.classify(_obs(tl=5), events=(_ev(),))
        assert verdict.label == "FALSE_NEGATIVE"


class TestFalseNegative:
    """S1-CALIB-004: TL=5 plus an external high-intensity event."""

    def test_tl_five_with_a_severe_acled_event_is_a_miss(self):
        assert GT.classify(_obs(tl=5), events=(_ev(),)).label \
            == "FALSE_NEGATIVE"

    def test_the_acled_tripwire_fires_at_severity_ten(self):
        # Production runs TWO false-negative paths and both are ported:
        # ground_truth_etl's ACLED tripwire (TL=5 and severity >= 10) and
        # run_rss_etl's graded under-rating. Below the tripwire the graded
        # rule still calls it a miss — which is correct, and is why the
        # tripwire alone was never sufficient.
        assert T.GT_FN_FATALITIES == 10
        low = GT.classify(_obs(tl=5), events=(_ev(source="acled",
                                                  severity=9),))
        high = GT.classify(_obs(tl=5), events=(_ev(source="acled",
                                                   severity=10),))
        assert low.label == high.label == "FALSE_NEGATIVE"
        assert high.provenance.rule_id == "false_negative_acled_tripwire"
        assert low.provenance.rule_id == "false_negative_severity_floor"

    def test_the_tripwire_is_acled_only(self):
        # A GDELT event at the same severity takes the graded path: the
        # narrow rule names ACLED specifically.
        verdict = GT.classify(_obs(tl=5), events=(_ev(source="gdelt",
                                                      severity=20),))
        assert verdict.provenance.rule_id == "false_negative_severity_floor"

    @pytest.mark.parametrize("source", ["llm_intel", "sequence_events"])
    def test_internal_sources_may_never_evidence_a_miss(self, source):
        # Incident #1's circularity: these are the same signals scoring
        # consumes, so if they fire the TL rises — they cannot reveal what
        # the tool missed.
        verdict = GT.classify(_obs(tl=5), events=(_ev(source=source),))
        assert verdict.label != "FALSE_NEGATIVE"
        assert "circular" in verdict.reason

    def test_internal_sources_may_still_corroborate_a_hit(self):
        verdict = GT.classify(_obs(tl=2), events=(_ev(source="llm_intel",
                                                      fatalities=0,
                                                      severity=3),))
        assert verdict.label == "TRUE_POSITIVE"

    def test_a_graded_under_rating_is_a_miss_even_above_tl_five(self):
        # S1-CALIB-008: a mass-casualty event demands severity >= 4, i.e.
        # TL <= 2. A TL3 call against 12 dead is a miss, not a hit.
        verdict = GT.classify(_obs(tl=3), events=(_ev(fatalities=12),))
        assert verdict.label == "FALSE_NEGATIVE"

    def test_the_severity_floor_ladder(self):
        assert GT.expected_severity_floor(fatalities=10, confidence=0.0) == 4
        assert GT.expected_severity_floor(fatalities=1, confidence=0.0) == 3
        assert GT.expected_severity_floor(fatalities=0, confidence=0.60) == 3
        assert GT.expected_severity_floor(fatalities=0, confidence=0.59) == 2

    def test_the_floor_is_computed_in_one_place(self):
        # A binary TL=5 tripwire cannot catch graded under-rating; the
        # clause requires the TL->severity conversion here and nowhere
        # else in the rule set.
        assert GT.expected_severity_floor(fatalities=0, confidence=0.0) == \
            T.SEVERITY_FLOOR_ESCALATION


class TestTruePositive:
    """S1-CALIB-005."""

    def test_an_alert_call_with_a_qualifying_event_is_a_hit(self):
        assert GT.classify(_obs(tl=2), events=(_ev(fatalities=0, severity=3),)
                           ).label == "TRUE_POSITIVE"

    def test_tl_three_is_the_alert_boundary_and_is_included(self):
        assert GT.is_alert(GT.ToolPosition(conclusion_type="threat_level",
                                           tl=3, state="3", observed_at=0.0,
                                           now=0.0)) is True
        assert GT.is_alert(GT.ToolPosition(conclusion_type="threat_level",
                                           tl=4, state="4", observed_at=0.0,
                                           now=0.0)) is False

    def test_attack_mode_with_a_real_state_is_an_alert(self):
        pos = GT.ToolPosition(conclusion_type="attack_mode", tl=None,
                              state="DDOS_PRECURSOR", observed_at=0.0,
                              now=0.0)
        assert GT.is_alert(pos) is True

    def test_attack_mode_with_insufficient_data_is_not_an_alert(self):
        pos = GT.ToolPosition(conclusion_type="attack_mode", tl=None,
                              state="INSUFFICIENT_DATA", observed_at=0.0,
                              now=0.0)
        assert GT.is_alert(pos) is False

    @pytest.mark.parametrize("ctype", ["trend", "per_domain"])
    def test_trend_and_per_domain_are_never_auto_labelled(self, ctype):
        # They are diagnostic surfaces; auto-labelling them pollutes
        # Design W's primary recall metric.
        pos = GT.ToolPosition(conclusion_type=ctype, tl=2, state="2",
                              observed_at=1000.0, now=1000.0 + 8 * 86400.0)
        verdict = GT.classify(pos, events=(_ev(),))
        assert verdict.label is None
        assert verdict.reason == "type_not_scorable"

    def test_the_forward_window_is_closed_at_both_ends(self):
        end = 1000.0 + T.GT_FORWARD_WINDOW_SEC
        assert GT.in_forward_window(observed_at=1000.0, event_at=1000.0)
        assert GT.in_forward_window(observed_at=1000.0, event_at=end)
        assert not GT.in_forward_window(observed_at=1000.0, event_at=end + 1)
        assert not GT.in_forward_window(observed_at=1000.0, event_at=999.0)

    def test_a_state_that_will_not_reduce_to_a_number_is_not_an_alert(self):
        pos = GT.ToolPosition(conclusion_type="threat_level", tl=None,
                              state="ELEVATED", observed_at=0.0, now=0.0)
        assert GT.is_alert(pos) is False


class TestHorizonAndTheAbsenceClaim:
    """S1-CALIB-006, incident #1."""

    def test_neither_fp_nor_tn_before_the_horizon_elapses(self):
        almost = 1000.0 + T.GT_FP_TN_HORIZON_SEC - 1.0
        assert GT.classify(_obs(tl=5, now=almost), events=()).label is None
        assert GT.classify(_obs(tl=2, now=almost), events=()).label is None

    def test_the_horizon_boundary_is_inclusive(self):
        exactly = 1000.0 + T.GT_FP_TN_HORIZON_SEC
        assert GT.classify(_obs(tl=5, now=exactly), events=()).label \
            == "TRUE_NEGATIVE"

    def test_a_calm_call_with_nothing_in_the_window_is_a_true_negative(self):
        assert GT.classify(_obs(tl=5), events=()).label == "TRUE_NEGATIVE"

    def test_an_alert_with_nothing_in_the_window_is_a_false_positive(self):
        assert GT.classify(_obs(tl=2), events=()).label == "FALSE_POSITIVE"

    def test_an_absence_claim_never_names_a_source(self):
        # Incident #1: `auto:acled` was claimed with ACLED unconfigured.
        for tl, label in ((5, "TRUE_NEGATIVE"), (2, "FALSE_POSITIVE")):
            verdict = GT.classify(_obs(tl=tl), events=())
            assert verdict.label == label
            assert verdict.analyst_id == "auto:horizon"

    def test_the_horizon_analyst_id_is_the_only_absence_identity(self):
        assert GT.ABSENCE_ANALYST_ID == "auto:horizon"


class TestAutomatedIdentityIsOneVote:
    """S1-CALIB-007: N agreeing automatic sources are ONE voter."""

    def test_acled_and_gdelt_together_are_one_identity(self):
        assert GT.analyst_id_for(("acled", "gdelt")) == "auto:both"

    def test_llm_and_sequence_together_are_one_identity(self):
        assert GT.analyst_id_for(("llm_intel", "sequence_events")) \
            == "auto:mixed"

    def test_a_single_source_names_itself(self):
        assert GT.analyst_id_for(("acled",)) == "auto:acled"
        assert GT.analyst_id_for(("gdelt",)) == "auto:gdelt"

    def test_acled_outranks_gdelt_when_only_one_of_the_pair_is_present(self):
        assert GT.analyst_id_for(("acled", "llm_intel")) == "auto:acled"

    def test_every_automated_identity_carries_the_auto_prefix(self):
        for sources in (("acled",), ("gdelt",), ("acled", "gdelt"),
                        ("llm_intel",), ("sequence_events",),
                        ("llm_intel", "sequence_events")):
            assert GT.analyst_id_for(sources).startswith("auto:")


# ── 009: kinetic tier ───────────────────────────────────────────────────

class TestKineticTier:
    """Incident #3: 12 of Korea's 15 false negatives were posture pieces."""

    @pytest.mark.parametrize("text", [
        "airstrike on the northern port",
        "shelling continued through the night",
        "bombardment of the border district",
        "missiles strike the airfield",
        "missiles launch toward the strait",
    ])
    def test_an_action_verb_reaches_the_kinetic_tier(self, text):
        assert GT.classify_tier(text).tier == "kinetic"

    @pytest.mark.parametrize("text", [
        "new missile unveiled at the parade",
        "rocket artillery deployed to the province",
        "artillery units to be modernised next year",
    ])
    def test_a_bare_weapon_noun_falls_back_to_posture(self, text):
        # A weapons test and a weapons strike share the noun. Only one is
        # an escalation.
        assert GT.classify_tier(text).tier == "posture"

    def test_the_posture_tier_carries_the_escalation_floor(self):
        assert GT.classify_tier("new missile unveiled").severity_floor == \
            T.SEVERITY_FLOOR_ESCALATION

    def test_fatalities_are_never_fabricated(self):
        # Production once substituted 1 for "unspecified".
        assert GT.classify_tier("shelling continued").fatalities == 0

    def test_the_confidence_ladder(self):
        assert GT.confidence_for(tier="kinetic", fatalities=3) == \
            T.CONFIDENCE_WITH_FATALITIES
        assert GT.confidence_for(tier="kinetic", fatalities=0) == \
            T.CONFIDENCE_KINETIC
        assert GT.confidence_for(tier="posture", fatalities=0) == \
            T.CONFIDENCE_POSTURE

    def test_a_fatality_count_beats_the_tier_in_the_confidence_ladder(self):
        assert GT.confidence_for(tier="posture", fatalities=4) == \
            T.CONFIDENCE_WITH_FATALITIES


# ── 010: relevance ladder ───────────────────────────────────────────────

class TestRelevanceLadder:
    """Incident #2's follow-up: a bear-spray incident and a typhoon."""

    def test_intrinsically_military_vocabulary_qualifies_alone(self):
        assert GT.is_relevant("airstrike near the strait",
                              countries=()).qualified is True

    def test_intrinsically_military_vocabulary_overrides_a_noise_veto(self):
        verdict = GT.is_relevant("typhoon delays the airstrike response",
                                 countries=())
        assert verdict.qualified is True
        assert verdict.rung == "intrinsic"

    def test_a_weak_verb_alone_does_not_qualify(self):
        assert GT.is_relevant("an attack on the shop", countries=()
                              ).qualified is False

    def test_a_weak_verb_qualifies_with_a_military_actor_noun(self):
        assert GT.is_relevant("an attack by the navy", countries=()
                              ).qualified is True

    def test_a_weak_verb_qualifies_with_two_recognised_countries(self):
        assert GT.is_relevant("an attack reported", countries=("TW", "CN")
                              ).qualified is True

    def test_one_country_is_not_enough_for_a_weak_verb(self):
        assert GT.is_relevant("an attack reported", countries=("TW",)
                              ).qualified is False

    @pytest.mark.parametrize("text", [
        "a bear attack on a hiker",
        "typhoon causes an explosion at the plant",
        "a shooting outside a nightclub",
    ])
    def test_noise_vocabulary_vetoes_a_weak_verb_match(self, text):
        assert GT.is_relevant(text, countries=("TW", "CN")).qualified is False

    def test_the_ladder_is_not_applied_to_sensing(self):
        # NP1: bg_observer keeps the wide net.
        assert GT.relevance_applies_to("etl") is True
        assert GT.relevance_applies_to("bg_observer") is False

    def test_a_country_alias_does_not_swallow_a_trailing_period(self):
        # `\b` fails on "U.S." — the alias boundary must be `(?!\w)`.
        assert GT.mentions_country("the U.S. responded", alias="U.S.") is True

    def test_an_alias_still_requires_a_word_boundary_on_the_right(self):
        assert GT.mentions_country("USSR archives", alias="US") is False


# ── 011: episode granularity ────────────────────────────────────────────

class TestEpisodeGranularity:
    """One external event is one trial. Incident #2's follow-up: a single
    article scored every conclusion in a 72h window, and 30 days produced
    about 23,000 labels."""

    def test_the_episode_key_is_scenario_country_and_utc_day(self):
        key = GT.episode_key(scenario_id="korean_peninsula", country="KP",
                             event_at=1_785_700_000.0)
        assert key == "korean_peninsula/KP/2026-08-02"

    def test_one_article_anchors_to_one_country_per_scenario(self):
        countries = GT.anchor_country(
            mentioned=("US", "CN", "TW"),
            participants={"TW": "primary_target", "CN": "adversary",
                          "US": "primary_ally"})
        assert countries == "CN"

    def test_an_article_with_no_conflict_party_anchors_nowhere(self):
        assert GT.anchor_country(
            mentioned=("US", "JP"),
            participants={"US": "primary_ally", "JP": "forward_base"}) is None

    def test_the_heaviest_floor_wins_within_one_episode(self):
        merged = GT.merge_episode_evidence((_ev(fatalities=0, severity=2),
                                            _ev(fatalities=20, severity=20)))
        assert merged.severity_floor == T.SEVERITY_FLOOR_MASS_CASUALTY

    def test_the_earliest_report_time_anchors_the_prior_window(self):
        merged = GT.merge_episode_evidence((_ev(observed_at=5000.0),
                                            _ev(observed_at=2000.0)))
        assert merged.event_at == 2000.0

    def test_an_episode_is_scored_once(self):
        assert GT.episode_scoring_passes() == 1


# ── 013: idempotency ────────────────────────────────────────────────────

class TestIdempotency:

    def test_the_three_keys_are_declared(self):
        assert GT.IDEMPOTENCY_KEYS == (
            "conclusion_id+analyst_id", "rss_episode_note_prefix",
            "day_cap_scenario_label_day")

    def test_the_episode_stamp_is_the_note_prefix(self):
        note = GT.episode_note("korean_peninsula", "KP", 1_785_700_000.0,
                               detail="acled=1")
        assert note.startswith("episode=korean_peninsula/KP/2026-08-02 ")

    def test_the_note_is_truncated_to_the_production_length(self):
        note = GT.episode_note("s", "C", 1_785_700_000.0, detail="x" * 999)
        assert len(note) == T.GT_NOTE_TRUNCATE

    def test_the_day_cap_key_collapses_a_days_worth_of_conclusions(self):
        assert GT.day_cap_key("korea", "TRUE_POSITIVE", 1_785_700_000.0) == \
            "korea/TRUE_POSITIVE/2026-08-02"

    def test_two_conclusions_the_same_day_share_one_day_cap_key(self):
        a = GT.day_cap_key("korea", "TRUE_POSITIVE", 1_785_700_000.0)
        b = GT.day_cap_key("korea", "TRUE_POSITIVE", 1_785_700_000.0 + 3600)
        assert a == b


# ── every label carries its epoch ───────────────────────────────────────

class TestLabelsCarryTheirEpoch:

    def test_a_verdict_carries_full_label_provenance(self):
        verdict = GT.classify(_obs(tl=5), events=(_ev(),))
        assert isinstance(verdict.provenance, E.LabelProvenance)
        assert verdict.provenance.epoch_id == E.CURRENT_EPOCH.epoch_id

    def test_the_rule_that_fired_is_recorded_as_the_rule_id(self):
        verdict = GT.classify(_obs(tl=3), events=(_ev(),))
        assert verdict.provenance.rule_id == "false_negative_severity_floor"

    def test_the_generator_version_belongs_to_the_current_epoch(self):
        assert E.CURRENT_EPOCH.accepts(GT.GENERATOR_ID,
                                       GT.GENERATOR_VERSION)

    def test_a_verdict_with_no_label_still_records_why(self):
        verdict = GT.classify(_obs(now=1000.0), events=())
        assert verdict.label is None and verdict.reason
