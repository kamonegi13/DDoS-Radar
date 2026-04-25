"""Tests for APT intel Stage 1 + Stage 2 prompt deduplication (T1).

Stage 2 must reuse the Stage 1 summary instead of re-sending the full
advisory body. This eliminates ~5,600 tokens/day of duplicate prompt
content across the daily APT poll cycle.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest


_DISTINCTIVE_BODY = (
    "Volt Typhoon actors have established persistent access to multiple "
    "United States critical infrastructure organizations across the energy, "
    "water, transportation, and communications sectors. CISA assesses that "
    "the actors are pre-positioning for disruptive cyber operations during "
    "a future geopolitical crisis. Specific targeting includes operational "
    "technology environments at electric utilities in DETECTABLE_BODY_MARKER."
)


def _build_rss(title: str, body: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<rss version="2.0"><channel>\n'
        f'<item><title>{title}</title>'
        f'<description>{body}</description>'
        '<link>https://example.gov/advisory/1</link>'
        '<pubDate>Fri, 24 Apr 2026 12:00:00 +0000</pubDate>'
        '</item>\n'
        '</channel></rss>'
    )


@pytest.fixture(autouse=True)
def _reset_processed_cache():
    from radar.sensors import apt_intel
    with apt_intel._processed_lock:
        apt_intel._processed.clear()
    yield
    with apt_intel._processed_lock:
        apt_intel._processed.clear()


def _capture_llm_calls(stage1_summary: str | None = "Volt Typhoon pre-positioning in US energy sector."):
    """Build a mock for llm_analyze_json that captures prompts and returns
    valid Stage 1 / Stage 2 responses.

    Returns: (mock_callable, captured_prompts list)
    """
    captured: list[dict] = []

    stage1_response = {
        "is_strategically_relevant": True,
        "has_geographic_target": True,
        "reason": "Named state actor with explicit US targeting",
    }
    if stage1_summary is not None:
        stage1_response["summary"] = stage1_summary

    stage2_response = {
        "headline": "Volt Typhoon targets US critical infrastructure",
        "theater": "US",
        "countries": ["US"],
        "country_weights": {"US": 1.0},
        "attributed_actor": "Volt Typhoon",
        "actor_nexus": "CN",
        "targeted_sector": "critical_infrastructure",
        "ttp_category": "pre-positioning",
        "urgency": "high",
        "confidence": 0.85,
    }

    responses = [
        {"ok": True, "data": stage1_response},
        {"ok": True, "data": stage2_response},
    ]
    call_idx = {"n": 0}

    def _mock(prompt, system="", temperature=0.1, max_tokens=512, caller=""):
        captured.append({
            "stage": "stage1" if call_idx["n"] == 0 else "stage2",
            "prompt": prompt,
            "system": system,
            "max_tokens": max_tokens,
        })
        i = call_idx["n"]
        call_idx["n"] += 1
        if i < len(responses):
            return responses[i]
        return {"ok": False, "error": "unexpected extra call"}

    return _mock, captured


def _run_fetch_with_mocks(mock_llm):
    """Drive AptIntelSensor.fetch with all external calls mocked.

    Returns the captured-prompts list passed in via mock_llm closure.
    """
    from radar.sensors import apt_intel

    rss_xml = _build_rss(
        title="CISA Advisory: Volt Typhoon US Infrastructure Targeting",
        body=_DISTINCTIVE_BODY,
    )

    sensor = apt_intel.AptIntelSensor()
    context = {
        "all_participant_countries": ["US", "TW", "JP", "CN"],
        "strategic_countries": ["US", "TW", "JP", "CN"],
    }

    with patch("radar.sensors.apt_intel._fetch_rss", return_value=rss_xml), \
         patch("radar.llm_client.llm_available", return_value=True), \
         patch("radar.llm_client.llm_analyze_json", side_effect=mock_llm), \
         patch("radar.intel_queue.intel_queue.submit",
               return_value={"verdict": "auto_confirmed", "id": 1}):
        sensor.fetch(context)


# ── T1.1: Stage 1 prompt must request `summary` field ────────────────────────

def test_stage1_prompt_requests_summary_field():
    """Stage 1 schema must include a `summary` field for Stage 2 reuse."""
    mock_llm, captured = _capture_llm_calls()
    _run_fetch_with_mocks(mock_llm)

    stage1_calls = [c for c in captured if c["stage"] == "stage1"]
    assert stage1_calls, "Stage 1 was not invoked"

    stage1_prompt = stage1_calls[0]["prompt"]
    assert '"summary"' in stage1_prompt, (
        "Stage 1 JSON schema must declare a `summary` field so Stage 2 "
        "can reuse it instead of re-reading the full body. "
        f"Prompt:\n{stage1_prompt}"
    )


# ── T1.2: Stage 2 prompt must NOT contain the full article body ──────────────

def test_stage2_prompt_omits_full_article_body():
    """Stage 2 must not re-send the article body — that's the whole point."""
    mock_llm, captured = _capture_llm_calls()
    _run_fetch_with_mocks(mock_llm)

    stage2_calls = [c for c in captured if c["stage"] == "stage2"]
    assert stage2_calls, "Stage 2 was not invoked"

    stage2_prompt = stage2_calls[0]["prompt"]
    assert "DETECTABLE_BODY_MARKER" not in stage2_prompt, (
        "Stage 2 prompt still contains the original article body. "
        "T1 dedup requires Stage 2 to reuse Stage 1's extracted summary "
        "instead of re-sending the full advisory text. "
        f"Prompt:\n{stage2_prompt}"
    )


# ── T1.3: Stage 2 prompt must include the Stage 1 summary ────────────────────

def test_stage2_prompt_includes_stage1_summary():
    """Stage 2 must receive the Stage 1 summary so it has enough context."""
    summary_marker = "Volt Typhoon SUMMARY_MARKER pre-positioning."
    mock_llm, captured = _capture_llm_calls(stage1_summary=summary_marker)
    _run_fetch_with_mocks(mock_llm)

    stage2_calls = [c for c in captured if c["stage"] == "stage2"]
    assert stage2_calls, "Stage 2 was not invoked"

    stage2_prompt = stage2_calls[0]["prompt"]
    assert "SUMMARY_MARKER" in stage2_prompt, (
        "Stage 2 prompt must include the Stage 1 summary to retain context. "
        f"Prompt:\n{stage2_prompt}"
    )


# ── T1.4: Backward-compat — fallback when Stage 1 omits summary ──────────────

def test_stage2_falls_back_when_stage1_omits_summary():
    """Cached Stage 1 responses won't have `summary` — fall back to title only.

    Falling back to the title (not the full body) keeps the dedup benefit
    even on legacy cached responses; the worst case is reduced Stage 2
    quality, not a crash.
    """
    mock_llm, captured = _capture_llm_calls(stage1_summary=None)
    _run_fetch_with_mocks(mock_llm)

    stage2_calls = [c for c in captured if c["stage"] == "stage2"]
    assert stage2_calls, "Stage 2 should still run on legacy Stage 1 output"

    stage2_prompt = stage2_calls[0]["prompt"]
    # Even in fallback, we must NOT regress to sending the full body
    assert "DETECTABLE_BODY_MARKER" not in stage2_prompt, (
        "Even when Stage 1 omits `summary`, Stage 2 must not re-send the "
        "full body. Fall back to title-only context instead."
    )
    # Title should still be present so Stage 2 has minimal context
    assert "Volt Typhoon" in stage2_prompt, (
        "Stage 2 fallback must still include the article title for context."
    )
