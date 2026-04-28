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
