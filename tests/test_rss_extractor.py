"""Tests for radar/conclusions/rss_extractor.py — pure regex baseline + LLM hook.

Pins:
  - regex extractor is deterministic + dependency-free
  - LLM path falls back to regex on any failure (NP3, OPSEC fallback)
  - country / fatality detection corner cases
  - allowed_countries narrows the candidate set
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

from radar.conclusions.rss_extractor import (
    KineticMatch,
    extract_kinetic,
    extract_kinetic_regex,
    extract_kinetic_regex_all,
    verify_alias_coverage,
    _COUNTRY_ALIASES,
)


# ── regex baseline ─────────────────────────────────────────────────────────

def test_regex_extracts_numeric_fatalities_and_country():
    out = extract_kinetic_regex("Israeli airstrike kills 12 in southern Lebanon, officials say")
    assert isinstance(out, KineticMatch)
    assert out.country in ("IL", "LB")  # both alias-match; first-wins
    assert out.fatalities == 12
    assert out.source == "regex"
    assert out.confidence >= 0.80


def test_regex_extracts_inverted_fatality_phrasing():
    out = extract_kinetic_regex("Strike killed at least 8 civilians in Gaza, Israeli military said")
    assert out is not None
    assert out.fatalities == 8


def test_regex_extracts_word_form_fatalities():
    out = extract_kinetic_regex("Three Russian soldiers dead in Ukraine border clash")
    assert out is not None
    assert out.fatalities == 3
    assert out.country in ("RU", "UA")


def test_regex_takes_max_when_multiple_counts_present():
    out = extract_kinetic_regex(
        "North Korea missile strike: 5 killed initially, death toll rose to 30")
    assert out is not None
    assert out.fatalities == 30
    assert out.country == "KP"


def test_regex_emits_lower_confidence_for_verb_only_match():
    out = extract_kinetic_regex("Russian missile launched toward Ukraine; no immediate casualties")
    assert out is not None
    assert out.fatalities == 1  # verb-only fallback severity
    assert out.confidence < 0.80


def test_regex_returns_none_when_no_country():
    assert extract_kinetic_regex("Twelve killed in factory fire") is None


def test_regex_returns_none_when_no_kinetic_signal():
    assert extract_kinetic_regex("Japan and South Korea trade ministers meet in Seoul") is None


def test_regex_returns_none_for_empty_text():
    assert extract_kinetic_regex("") is None
    assert extract_kinetic_regex(None) is None


def test_regex_allowed_countries_narrows_candidates():
    text = "Iranian missile struck Saudi oil facility; 3 dead"
    # Without filter, IR or SA would match. Restrict to TW only → no match.
    out = extract_kinetic_regex(text, allowed_countries=["TW"])
    assert out is None


def test_regex_allowed_countries_picks_only_listed():
    text = "Iranian missile struck Saudi oil facility; 3 dead"
    out = extract_kinetic_regex(text, allowed_countries=["SA"])
    assert out is not None
    assert out.country == "SA"


def test_regex_summary_truncated_to_240_chars():
    long = "Russia attacks Ukraine — " + ("." * 500) + " killed 7"
    out = extract_kinetic_regex(long)
    assert out is not None
    assert len(out.summary) <= 240


def test_regex_is_deterministic():
    text = "PLA exercise near Taiwan: Chinese drones spotted; 2 killed in clashes"
    a = extract_kinetic_regex(text)
    b = extract_kinetic_regex(text)
    assert a == b


def test_regex_dataclass_is_frozen():
    out = extract_kinetic_regex("North Korea missile attack: 5 killed")
    assert out is not None
    with pytest.raises(Exception):
        out.fatalities = 99  # type: ignore[misc]


# ── extract_kinetic with LLM hook ──────────────────────────────────────────

def test_public_api_returns_regex_when_use_llm_false():
    out = extract_kinetic("Israeli strike kills 4 in Lebanon")
    assert out is not None
    assert out.source == "regex"


def test_public_api_returns_regex_when_llm_invoke_is_none():
    """Even with use_llm=True, if llm_invoke=None we must use regex."""
    out = extract_kinetic("Russian missile attack kills 7 in Ukraine",
                          use_llm=True, llm_invoke=None)
    assert out is not None
    assert out.source == "regex"


def test_llm_path_overrides_regex_when_output_valid():
    def fake_llm(_prompt):
        return '{"country": "TW", "fatalities": 9, "confidence": 0.92}'
    out = extract_kinetic("PLA exercise near Taiwan; reports of casualties",
                          use_llm=True, llm_invoke=fake_llm)
    assert out is not None
    assert out.source == "llm"
    assert out.country == "TW"
    assert out.fatalities == 9
    assert out.confidence == 0.92


def test_llm_path_falls_back_to_regex_on_exception():
    def boom(_prompt):
        raise RuntimeError("model offline")
    out = extract_kinetic("Israeli airstrike kills 5 in Lebanon",
                          use_llm=True, llm_invoke=boom)
    assert out is not None
    assert out.source == "regex"
    assert out.fatalities == 5


def test_llm_path_falls_back_when_json_invalid():
    def garbled(_prompt):
        return "not actually JSON"
    out = extract_kinetic("Russian artillery kills 3 in Ukraine",
                          use_llm=True, llm_invoke=garbled)
    assert out is not None
    assert out.source == "regex"


def test_llm_path_falls_back_when_country_not_recognized():
    def bad_country(_prompt):
        return '{"country": "ZZ", "fatalities": 5, "confidence": 0.8}'
    out = extract_kinetic("Strike kills 5 in Lebanon",
                          use_llm=True, llm_invoke=bad_country)
    assert out is not None
    assert out.source == "regex"


def test_llm_path_falls_back_when_fatalities_negative():
    def bad_fat(_prompt):
        return '{"country": "IL", "fatalities": -1, "confidence": 0.8}'
    out = extract_kinetic("Israeli airstrike", use_llm=True, llm_invoke=bad_fat)
    # Regex finds no fatalities + has verb + IL → verb-only fallback
    assert out is not None
    assert out.source == "regex"


def test_llm_path_falls_back_when_country_outside_allowed():
    def picks_outside(_prompt):
        return '{"country": "RU", "fatalities": 8, "confidence": 0.9}'
    out = extract_kinetic("Some Russian/Ukrainian incident; 8 dead",
                          allowed_countries=["UA"],
                          use_llm=True, llm_invoke=picks_outside)
    # LLM picked RU but allowed only UA → fall back to regex
    assert out is not None
    assert out.source == "regex"
    assert out.country == "UA"


def test_llm_confidence_clamped_to_0_95_max():
    def overconfident(_prompt):
        return '{"country": "IR", "fatalities": 2, "confidence": 1.5}'
    out = extract_kinetic("Iranian drones killed 2 in Iraq",
                          use_llm=True, llm_invoke=overconfident)
    assert out is not None
    assert out.source == "llm"
    assert out.confidence <= 0.95


def test_llm_confidence_default_when_missing():
    def no_conf(_prompt):
        return '{"country": "TW", "fatalities": 3}'
    out = extract_kinetic("Taiwan strait incident: 3 killed",
                          use_llm=True, llm_invoke=no_conf)
    assert out is not None
    assert out.source == "llm"
    assert 0.0 <= out.confidence <= 0.95


def test_llm_path_returns_none_when_regex_also_misses():
    """If neither regex nor LLM finds a country, the function returns None."""
    def empty(_prompt):
        return "{}"
    assert extract_kinetic("Markets opened mixed in early trading",
                           use_llm=True, llm_invoke=empty) is None


# ── ADR-V2-015 Phase 2: alias coverage invariant ──────────────────────────

def test_alias_coverage_against_geo_data_json():
    """Every scenario participant in geo_data.json must have an alias.
    A new participant added without an alias breaks bg_observer recall."""
    import json
    import pathlib
    geo_path = pathlib.Path(__file__).resolve().parent.parent / "geo_data.json"
    with geo_path.open() as f:
        geo = json.load(f)
    participants: set[str] = set()
    for sc in geo.get("SCENARIOS", {}).values():
        for cc in sc.get("participants", {}).keys():
            participants.add(cc)
    gap = verify_alias_coverage(participants)
    assert gap == [], (
        f"alias coverage gap — {gap} have no entry in _COUNTRY_ALIASES. "
        f"Add them to radar/conclusions/rss_extractor.py."
    )


def test_verify_alias_coverage_returns_missing_codes_sorted():
    gap = verify_alias_coverage({"US", "ZZ", "AAA"})
    assert gap == ["AAA", "ZZ"]
    assert verify_alias_coverage({"US"}) == []
    assert verify_alias_coverage(set()) == []


def test_phase2_added_aliases_present():
    """The 11 codes added in Phase 2 must all be present."""
    for cc in ("AU", "BY", "EE", "FI", "GU", "LT", "LV",
               "MD", "MY", "RO", "SK"):
        assert cc in _COUNTRY_ALIASES, f"{cc} missing from _COUNTRY_ALIASES"


def test_belarus_alias_detects_lukashenko_and_minsk():
    # Use BY-only headline (no other country mentioned) so first-wins
    # alias iteration doesn't pick PL/RU/UA.
    out = extract_kinetic_regex("Lukashenko orders Minsk mobilization of reservists")
    assert isinstance(out, KineticMatch)
    assert out.country == "BY"
    assert out.confidence == 0.40  # escalation verb only


# ── ADR-V2-015 Phase 3: multi-country broadcast extraction ────────────────

def test_extract_all_returns_multi_country_for_dual_actor_headline():
    # Phrase chosen to match _NUMERIC_FATALITIES_INVERTED: "killed 12".
    out = extract_kinetic_regex_all(
        "Russian forces attack Ukraine; killed 12"
    )
    assert isinstance(out, list)
    countries = {m.country for m in out}
    assert {"RU", "UA"}.issubset(countries)
    for m in out:
        assert m.fatalities == 12
        assert m.confidence == 0.85


def test_extract_all_returns_empty_when_no_country():
    assert extract_kinetic_regex_all("Markets closed flat") == []


def test_extract_all_returns_empty_when_no_verb_or_fatality():
    """Country alone is not enough — needs a verb or fatality."""
    assert extract_kinetic_regex_all("Trade ministers from Japan and South Korea meet") == []


def test_extract_all_respects_allowed_countries():
    out = extract_kinetic_regex_all(
        "Russian forces attack Ukraine; killed 5",
        allowed_countries=["UA"],
    )
    countries = {m.country for m in out}
    assert countries == {"UA"}


def test_extract_all_dedupes_duplicate_country_mentions():
    out = extract_kinetic_regex_all(
        "Russia attacks Russia again — Russian forces deploy"
    )
    countries = [m.country for m in out]
    assert countries.count("RU") == 1


# ── ADR-V2-015 Phase 6: escalation-verb (no-fatality) detection ───────────

def test_escalation_verb_mobilization_low_confidence():
    # BY-only mention (no PL collision) — verifies escalation-verb path.
    out = extract_kinetic_regex(
        "Belarus mobilizes additional reservists this week, Minsk announces"
    )
    assert isinstance(out, KineticMatch)
    assert out.country == "BY"
    assert out.fatalities == 0
    assert out.confidence == 0.40


def test_escalation_verb_diplomatic_break():
    out = extract_kinetic_regex(
        "China recalls its ambassador from the Philippines amid maritime row"
    )
    assert isinstance(out, KineticMatch)
    assert out.country in ("CN", "PH")
    assert out.confidence == 0.40


def test_escalation_verb_missile_test():
    # 'missile' alone is in _KINETIC_VERBS so it returns 0.60 — that
    # is the correct ladder behaviour. The escalation-verb path only
    # kicks in when no kinetic verb is present, e.g. 'troop buildup'
    # without 'missile'/'airstrike'/etc.
    out = extract_kinetic_regex(
        "Pyongyang announces troop buildup near the DMZ"
    )
    assert isinstance(out, KineticMatch)
    assert out.country == "KP"
    assert out.confidence == 0.40
    assert out.fatalities == 0


def test_kinetic_verb_outranks_escalation_verb():
    """When kinetic + escalation both present, fatalities path wins."""
    # Use numeric digits + 'killed N' so _NUMERIC_FATALITIES_INVERTED matches.
    out = extract_kinetic_regex(
        "Russian airstrike killed 3 as Ukraine mobilizes reservists"
    )
    assert isinstance(out, KineticMatch)
    # numeric fatalities path takes precedence over verb-only paths
    assert out.confidence == 0.85
    assert out.fatalities == 3


def test_pure_protest_not_treated_as_escalation():
    """'protest' is intentionally NOT in _ESCALATION_VERBS."""
    assert extract_kinetic_regex(
        "Protesters gathered outside the Russian embassy in London"
    ) is None


# ── escalation-relevance gate (ground-truth labeling only) ────────────────
#
# Added 2026-07-04 after production ground truth was found contaminated
# with domestic accidents and natural disasters in participant countries
# (e.g. a bear-spray incident and a typhoon labeled as taiwan_contingency
# escalation evidence). The gate is applied by the ETL runners only — the
# bg_observer sensing path keeps the wider net (NP1).

from radar.conclusions.rss_extractor import is_escalation_relevant  # noqa: E402


def test_strong_kinetic_is_relevant():
    assert is_escalation_relevant("Russian missile strike kills 12 in Kyiv")
    assert is_escalation_relevant("Artillery shelling reported near Kharkiv")


def test_escalation_verb_is_relevant():
    assert is_escalation_relevant("China deploys troops near Taiwan strait")
    assert is_escalation_relevant("North Korea missile test draws condemnation")


def test_disaster_with_fatalities_is_not_relevant():
    assert not is_escalation_relevant("Typhoon Lan kills 12 in Japan")
    assert not is_escalation_relevant(
        "Earthquake in Taiwan: death toll rises to 30"
    )


def test_domestic_accident_is_not_relevant():
    assert not is_escalation_relevant(
        "Bear spray goes off in Japan post office, 13 people treated"
    )
    assert not is_escalation_relevant(
        "Bus crash in South Korea leaves 8 dead"
    )


def test_military_accident_without_kinetic_context_is_not_relevant():
    # An army transport accident is not interstate escalation.
    assert not is_escalation_relevant(
        "Military plane crash kills 3 soldiers in Philippines training flight"
    )


def test_weak_kinetic_with_two_countries_is_relevant():
    assert is_escalation_relevant("China attacks Taiwan patrol vessel")
    assert is_escalation_relevant("Russia attacks Ukraine, kills 12")


def test_weak_kinetic_single_country_no_actor_is_not_relevant():
    assert not is_escalation_relevant(
        "Mass shooting at Taiwan nightclub leaves 5 dead"
    )
    assert not is_escalation_relevant("Explosion at Manila fireworks factory")


def test_weak_kinetic_with_military_actor_is_relevant():
    assert is_escalation_relevant(
        "Ambush on army patrol kills 4 troops in Philippines"
    )


def test_noise_does_not_veto_strong_kinetic():
    # A missile test reported alongside storm coverage is still relevant.
    assert is_escalation_relevant(
        "North Korea missile test proceeds amid typhoon warnings"
    )


def test_empty_text_is_not_relevant():
    assert not is_escalation_relevant("")
