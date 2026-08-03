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


# Analyst-facing report headings. The export is a deliverable the analyst
# reads and circulates, so it follows the Japanese-only UI policy
# (docs/design/ja-localization.md); identifiers and JSON payloads below
# stay verbatim for NP6 traceability.
_TYPE_TITLES = {
    ConclusionType.THREAT_LEVEL: "脅威レベル",
    ConclusionType.TREND: "トレンド",
    ConclusionType.PER_DOMAIN: "ドメイン別兆候",
    ConclusionType.ANOMALY: "個別異常事象",
    ConclusionType.ATTACK_MODE: "推定攻撃モード",
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
        lines.append(f"- **状態**: `{c.state}`")
    else:
        reason = c.conclusion_unavailable_reason
        reason_value = reason.value if reason is not None else "unknown"
        lines.append(f"- **状態**: _結論不可_ — `{reason_value}`")
    lines.extend([
        f"- **確信度**: {c.confidence:.2f}",
        f"- **観測時刻**: {_fmt_ts(c.observed_at)}",
        f"- **結論 ID**: `{c.id}`",
        f"- **導出式**: `{c.formula_ref}`",
        "",
        "### 閾値",
        "```json",
        _fmt_json(c.threshold_ref),
        "```",
        "",
    ])
    if c.source_urls:
        lines.append("### 一次ソース")
        for url in c.source_urls:
            lines.append(f"- {url}")
        lines.append("")
    if c.calibration_status:
        lines.extend([
            "### Calibration",  # §2: 英語のまま
            "```json",
            _fmt_json(c.calibration_status),
            "```",
            "",
        ])
    if c.metadata:
        lines.extend([
            "### メタデータ",
            "```json",
            _fmt_json(c.metadata),
            "```",
            "",
        ])
    if audit_trace and audit_trace.get("llm_prompt"):
        prompt = audit_trace["llm_prompt"]
        if not prompt.get("missing"):
            lines.extend([
                "<details><summary>LLM プロンプト（全文）</summary>",
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
        f"# Noroshi シナリオレポート — {title_name}",
        "",
        f"- **シナリオ ID**: `{scenario_id}`",
        f"- **生成時刻 (UTC)**: {_fmt_ts(ts)}",
    ]
    if api_version:
        head.append(f"- **API バージョン**: `{api_version}`")
    head.append("")
    if disclaimer:
        head.extend(["> " + line for line in disclaimer.splitlines()])
        head.append("")

    sections = []
    conclusions_list = list(conclusions)
    if not conclusions_list:
        sections.append("_このシナリオにはまだ結論がありません。_")
    else:
        for c in conclusions_list:
            trace = (audit_traces or {}).get(c.id)
            sections.append(_render_conclusion_section(c, audit_trace=trace))

    return "\n".join(head + sections).rstrip() + "\n"
