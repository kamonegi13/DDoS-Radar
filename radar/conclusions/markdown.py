"""Markdown export — render a scenario's latest conclusions as a single .md.

Pure rendering layer over `Conclusion` instances. No DB access, no Flask
context: caller fetches the conclusions and passes them in. This keeps the
function trivially testable (no fixtures) and reusable from anywhere — API
endpoint, CLI replay, or a future PDF/printable view.

Output structure (per conclusion):
    ## <Title>
    - **State / Confidence / Observed at**
    - **Formula / Thresholds / Sources / Calibration**
    - Optional `<details>` audit-trace block with full LLM prompt text

The disclaimer (NP7) appears once at the top of the document, not per
section, because it applies to the whole report not individual conclusions.
"""

from __future__ import annotations

import datetime
import json
from typing import Iterable, Optional

from radar.conclusions.base import Conclusion, ConclusionType


_TYPE_TITLES = {
    ConclusionType.THREAT_LEVEL: "Threat Level",
    ConclusionType.TREND: "Trend",
    ConclusionType.PER_DOMAIN: "Per-Domain Indicators",
    ConclusionType.ANOMALY: "Anomalies",
    ConclusionType.ATTACK_MODE: "Estimated Attack Mode",
}


def _fmt_ts(epoch: float) -> str:
    """ISO 8601 UTC, second precision. Stable across runs for diffability."""
    if not epoch:
        return "(unknown)"
    return datetime.datetime.fromtimestamp(
        epoch, tz=datetime.timezone.utc
    ).isoformat(timespec="seconds")


def _fmt_json(obj: object) -> str:
    """Pretty-print a dict/list for an md fenced block. Sort keys for diff stability."""
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def _render_conclusion_section(
    c: Conclusion,
    audit_trace: Optional[dict] = None,
) -> str:
    """Render one Conclusion as a markdown section. Audit trace is optional —
    when present, embeds an expandable details block with the resolved LLM
    prompt text (if any) for full NP6 compliance.
    """
    title = _TYPE_TITLES.get(c.conclusion_type, c.conclusion_type.value)
    lines = [f"## {title}", ""]
    if c.is_available():
        lines.append(f"- **State**: `{c.state}`")
    else:
        reason = c.conclusion_unavailable_reason
        reason_value = reason.value if reason is not None else "unknown"
        lines.append(f"- **State**: _unavailable_ — `{reason_value}`")
    lines.extend([
        f"- **Confidence**: {c.confidence:.2f}",
        f"- **Observed at**: {_fmt_ts(c.observed_at)}",
        f"- **Conclusion ID**: `{c.id}`",
        f"- **Formula**: `{c.formula_ref}`",
        "",
        "### Thresholds",
        "```json",
        _fmt_json(c.threshold_ref),
        "```",
        "",
    ])
    if c.source_urls:
        lines.append("### Sources")
        for url in c.source_urls:
            lines.append(f"- {url}")
        lines.append("")
    if c.calibration_status:
        lines.extend([
            "### Calibration",
            "```json",
            _fmt_json(c.calibration_status),
            "```",
            "",
        ])
    if c.metadata:
        lines.extend([
            "### Metadata",
            "```json",
            _fmt_json(c.metadata),
            "```",
            "",
        ])
    if audit_trace and audit_trace.get("llm_prompt"):
        prompt = audit_trace["llm_prompt"]
        if not prompt.get("missing"):
            lines.extend([
                "<details><summary>LLM prompt (full text)</summary>",
                "",
                f"- **sha256**: `{prompt.get('sha256', '')}`",
                f"- **model**: `{prompt.get('model', '')}`",
                f"- **temperature**: `{prompt.get('temperature', '')}`",
                "",
                "```",
                str(prompt.get("prompt_text", "")),
                "```",
                "",
                "</details>",
                "",
            ])
    return "\n".join(lines)


def render_scenario_markdown(
    scenario_id: str,
    conclusions: Iterable[Conclusion],
    *,
    scenario_name: Optional[str] = None,
    disclaimer: str = "",
    api_version: str = "",
    generated_at: Optional[float] = None,
    audit_traces: Optional[dict] = None,
) -> str:
    """Render the full scenario report.

    audit_traces: optional `{conclusion_id: trace_dict}` map (typically the
    output of /audit_trace endpoint). Sections without a matching trace
    omit the LLM prompt block.
    """
    import time as _time

    ts = generated_at if generated_at is not None else _time.time()
    title_name = scenario_name or scenario_id
    head = [
        f"# DDoS-Radar Scenario Report — {title_name}",
        "",
        f"- **Scenario ID**: `{scenario_id}`",
        f"- **Generated (UTC)**: {_fmt_ts(ts)}",
    ]
    if api_version:
        head.append(f"- **API version**: `{api_version}`")
    head.append("")
    if disclaimer:
        head.extend(["> " + line for line in disclaimer.splitlines()])
        head.append("")

    sections = []
    conclusions_list = list(conclusions)
    if not conclusions_list:
        sections.append("_No conclusions available for this scenario yet._")
    else:
        for c in conclusions_list:
            trace = (audit_traces or {}).get(c.id)
            sections.append(_render_conclusion_section(c, audit_trace=trace))

    return "\n".join(head + sections).rstrip() + "\n"
