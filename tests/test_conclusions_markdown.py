"""Unit tests for radar/conclusions/markdown.py — the pure renderer.

The renderer is the data-shape contract for the `.md` export endpoint:
analysts paste these reports into wikis/tickets, so we exercise the
shape (header, sections, json blocks, audit trace, unavailable handling)
rather than golden-string equality which would churn on cosmetic edits.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")

from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    new_conclusion_id,
)
from radar.conclusions.markdown import (
    _fmt_json,
    _fmt_ts,
    render_scenario_markdown,
)


_DISCLAIMER = "Tool conclusion only — final judgment by organizational process."


def _make_tl(scenario_id: str = "test_md_scenario", **overrides) -> Conclusion:
    base = dict(
        id=new_conclusion_id(),
        scenario_id=scenario_id,
        conclusion_type=ConclusionType.THREAT_LEVEL,
        state="3",
        confidence=0.78,
        observed_at=1_700_000_000.0,
        formula_ref="radar/scoring.py#derive_tl@v2.0.1",
        threshold_ref={"total": 9.0, "physical": 3.0},
        source_urls=("https://example.test/a", "https://example.test/b"),
        final_judgment_disclaimer=_DISCLAIMER,
        calibration_status={"sampler": "OK"},
        metadata={"raw_score": 9.4},
    )
    base.update(overrides)
    return Conclusion(**base)


def _make_unavailable(scenario_id: str = "test_md_scenario") -> Conclusion:
    return Conclusion(
        id=new_conclusion_id(),
        scenario_id=scenario_id,
        conclusion_type=ConclusionType.ATTACK_MODE,
        state=None,
        confidence=0.0,
        observed_at=1_700_000_000.0,
        formula_ref="radar/attack_mode.py#derive@v0.1.0",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=_DISCLAIMER,
        conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
        metadata={"reason_detail": "no signals yet"},
    )


# ── helpers ─────────────────────────────────────────────────────────────


def test_fmt_ts_returns_iso_utc_seconds():
    s = _fmt_ts(1_700_000_000.0)
    assert s == "2023-11-14T22:13:20+00:00"


def test_fmt_ts_handles_zero_epoch():
    assert _fmt_ts(0) == "(unknown)"


def test_fmt_json_sorts_keys_for_diff_stability():
    a = _fmt_json({"b": 2, "a": 1})
    b = _fmt_json({"a": 1, "b": 2})
    assert a == b
    assert a.index('"a"') < a.index('"b"')


# ── header ──────────────────────────────────────────────────────────────


def test_renders_scenario_header_with_id_and_disclaimer():
    md = render_scenario_markdown(
        "taiwan_contingency",
        [_make_tl()],
        scenario_name="Taiwan Contingency",
        disclaimer=_DISCLAIMER,
        api_version="2.0",
        generated_at=1_700_000_000.0,
    )
    assert md.startswith("# DDoS-Radar Scenario Report — Taiwan Contingency\n")
    assert "- **Scenario ID**: `taiwan_contingency`" in md
    assert "- **Generated (UTC)**: 2023-11-14T22:13:20+00:00" in md
    assert "- **API version**: `2.0`" in md
    assert f"> {_DISCLAIMER}" in md


def test_falls_back_to_id_when_no_scenario_name():
    md = render_scenario_markdown(
        "raw_scenario_id",
        [_make_tl()],
        disclaimer=_DISCLAIMER,
    )
    assert md.startswith("# DDoS-Radar Scenario Report — raw_scenario_id\n")


def test_disclaimer_appears_only_once_per_report():
    """NP7 disclaimer is per-report, not per-section."""
    md = render_scenario_markdown(
        "sid",
        [_make_tl(), _make_tl(conclusion_type=ConclusionType.TREND, state="rising",
                              formula_ref="radar/trend.py#v1")],
        disclaimer=_DISCLAIMER,
    )
    assert md.count(f"> {_DISCLAIMER}") == 1


# ── per-conclusion sections ─────────────────────────────────────────────


def test_renders_conclusion_section_with_human_title():
    md = render_scenario_markdown("sid", [_make_tl()], disclaimer=_DISCLAIMER)
    assert "## Threat Level" in md


def test_renders_state_confidence_observed_at_id_formula():
    c = _make_tl()
    md = render_scenario_markdown("sid", [c], disclaimer=_DISCLAIMER)
    assert "- **State**: `3`" in md
    assert "- **Confidence**: 0.78" in md
    assert f"- **Conclusion ID**: `{c.id}`" in md
    assert "- **Formula**: `radar/scoring.py#derive_tl@v2.0.1`" in md


def test_renders_thresholds_as_json_fenced_block():
    md = render_scenario_markdown("sid", [_make_tl()], disclaimer=_DISCLAIMER)
    assert "### Thresholds" in md
    assert "```json" in md
    assert '"physical": 3.0' in md
    assert '"total": 9.0' in md


def test_renders_source_urls_as_bullets():
    md = render_scenario_markdown("sid", [_make_tl()], disclaimer=_DISCLAIMER)
    assert "### Sources" in md
    assert "- https://example.test/a" in md
    assert "- https://example.test/b" in md


def test_omits_sources_section_when_empty():
    c = _make_tl(source_urls=())
    md = render_scenario_markdown("sid", [c], disclaimer=_DISCLAIMER)
    assert "### Sources" not in md


def test_renders_calibration_when_present():
    md = render_scenario_markdown("sid", [_make_tl()], disclaimer=_DISCLAIMER)
    assert "### Calibration" in md
    assert '"sampler": "OK"' in md


def test_omits_calibration_when_empty():
    c = _make_tl(calibration_status={})
    md = render_scenario_markdown("sid", [c], disclaimer=_DISCLAIMER)
    assert "### Calibration" not in md


def test_renders_metadata_when_present():
    md = render_scenario_markdown("sid", [_make_tl()], disclaimer=_DISCLAIMER)
    assert "### Metadata" in md
    assert '"raw_score": 9.4' in md


# ── unavailable conclusions ─────────────────────────────────────────────


def test_renders_unavailable_state_with_reason():
    md = render_scenario_markdown(
        "sid", [_make_unavailable()], disclaimer=_DISCLAIMER,
    )
    assert "## Estimated Attack Mode" in md
    assert "_unavailable_" in md
    assert "`insufficient_data`" in md


# ── audit trace ─────────────────────────────────────────────────────────


def test_embeds_llm_prompt_details_when_audit_trace_provided():
    c = _make_tl(llm_prompt_sha256="ab" * 32)
    audit = {
        c.id: {
            "llm_prompt": {
                "sha256": "ab" * 32,
                "model": "llama3.1:8b",
                "temperature": 0.1,
                "prompt_text": "please analyze foo bar baz",
            }
        }
    }
    md = render_scenario_markdown(
        "sid", [c], disclaimer=_DISCLAIMER, audit_traces=audit,
    )
    assert "<details><summary>LLM prompt (full text)</summary>" in md
    assert f"- **sha256**: `{'ab' * 32}`" in md
    assert "- **model**: `llama3.1:8b`" in md
    assert "please analyze foo bar baz" in md
    assert "</details>" in md


def test_omits_llm_prompt_block_when_no_trace_for_conclusion():
    c = _make_tl()
    md = render_scenario_markdown(
        "sid", [c], disclaimer=_DISCLAIMER, audit_traces={},
    )
    assert "<details>" not in md


def test_omits_llm_prompt_block_when_marked_missing():
    """Purged-prompt case: trace dict is present but `missing=True` — we
    must not render an empty <details> block in that case."""
    c = _make_tl(llm_prompt_sha256="ff" * 32)
    audit = {c.id: {"llm_prompt": {"sha256": "ff" * 32, "missing": True}}}
    md = render_scenario_markdown(
        "sid", [c], disclaimer=_DISCLAIMER, audit_traces=audit,
    )
    assert "<details>" not in md


# ── empty scenario ──────────────────────────────────────────────────────


def test_renders_placeholder_when_no_conclusions():
    md = render_scenario_markdown("sid", [], disclaimer=_DISCLAIMER)
    assert "_No conclusions available for this scenario yet._" in md
    # NP7 disclaimer still required even when there's nothing to report.
    assert f"> {_DISCLAIMER}" in md


# ── output shape ────────────────────────────────────────────────────────


def test_output_ends_with_single_newline():
    """Diff-friendly: stable trailing newline regardless of section count."""
    md = render_scenario_markdown("sid", [_make_tl()], disclaimer=_DISCLAIMER)
    assert md.endswith("\n")
    assert not md.endswith("\n\n")


def test_renders_iterable_input_not_just_list():
    """Accepts any Iterable[Conclusion] — generator must work."""
    def gen():
        yield _make_tl()
    md = render_scenario_markdown("sid", gen(), disclaimer=_DISCLAIMER)
    assert "## Threat Level" in md
