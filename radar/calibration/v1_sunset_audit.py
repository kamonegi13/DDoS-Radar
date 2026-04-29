"""V1 sunset residue audit (Phase E).

Reports v1-related code, flags, and DB activity that remained after the
early v1 sunset (commit c4484bf, 2026-04-29). Read-only — does not mutate
code, config, or database.

NP6 — produces a structured report (findings + file/line locators) so
analysts can decide what to retire and on what cadence.

NP7 — read-only by design. Audit surfaces the state; the human decides.

Severity tiers:
  HIGH    — actively running v1/v2 comparison code or recent diff-log writes
  MEDIUM  — feature flags whose values still imply pre-sunset behavior
  LOW     — historical comments / docstrings (informational)

Usage:
  python -m radar.calibration.v1_sunset_audit            # text report
  python -m radar.calibration.v1_sunset_audit --json     # structured JSON
  python -m radar.calibration.v1_sunset_audit --strict   # exit 1 on HIGH
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("radar.calibration.v1_sunset_audit")


REPO_ROOT = Path(__file__).resolve().parents[2]
RADAR_DIR = REPO_ROOT / "radar"


@dataclass(frozen=True)
class Finding:
    severity: str       # "HIGH" | "MEDIUM" | "LOW"
    category: str       # "active_code" | "flag_default" | "db_activity" | "historical"
    title: str
    detail: str
    file_path: Optional[str] = None
    line: Optional[int] = None
    actionable: bool = True


@dataclass(frozen=True)
class AuditReport:
    generated_at: float
    findings: tuple[Finding, ...]

    @property
    def high(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "HIGH")

    @property
    def medium(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "MEDIUM")

    @property
    def low(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity == "LOW")


# ── 1. Active code paths still running v1/v2 sampling ────────────────────────


_DIFF_CALL_RE = re.compile(r"^\s*_maybe_sample_v1_v2_diff\(state\)\s*$", re.MULTILINE)


def _audit_active_code() -> list[Finding]:
    findings: list[Finding] = []
    scoring_py = RADAR_DIR / "scoring.py"
    if scoring_py.exists():
        try:
            text = scoring_py.read_text(encoding="utf-8")
        except Exception as exc:
            log.debug("read scoring.py failed: %s", exc)
            text = ""
        match = _DIFF_CALL_RE.search(text)
        if match:
            line = text[: match.start()].count("\n") + 1
            findings.append(Finding(
                severity="HIGH",
                category="active_code",
                title="v1/v2 diff sampler call site still wired in scoring loop",
                detail=("scoring.py invokes _maybe_sample_v1_v2_diff every focused cycle. "
                        "After v1 sunset (2026-04-29) this is dead code unless the diff "
                        "distribution is still being monitored. Removal is safe once "
                        "V2_CONCLUSION_DIFF_SAMPLER_ENABLED is permanently false."),
                file_path=str(scoring_py.relative_to(REPO_ROOT)),
                line=line,
            ))
    diff_sampler_py = RADAR_DIR / "conclusions" / "diff_sampler.py"
    if diff_sampler_py.exists():
        findings.append(Finding(
            severity="HIGH",
            category="active_code",
            title="diff_sampler module still present",
            detail=("radar/conclusions/diff_sampler.py implements the v1 vs v2 comparison "
                    "helper. With v1 routes removed, comparison output is no longer "
                    "actionable. Schedule removal once the diff_log table is archived."),
            file_path=str(diff_sampler_py.relative_to(REPO_ROOT)),
        ))
    return findings


# ── 2. Feature flag values vs post-sunset expectation ────────────────────────


# (flag_name, expected_post_sunset_value, why)
_FLAG_EXPECTATIONS: tuple[tuple[str, bool, str], ...] = (
    ("V2_CONCLUSION_LEDGER_ENABLED", True,
     "v1 is sunset; the ledger is the sole conclusion writer. Default should be true."),
    ("V2_CONCLUSION_DIFF_SAMPLER_ENABLED", False,
     "Sampler compares v1 against v2; with v1 removed it has no signal. Should remain false."),
    ("V2_TREND_ENABLED", True,
     "Per-conclusion-type rollback flag. Trend should default-on post-sunset."),
    ("V2_PER_DOMAIN_ENABLED", True,
     "Per-domain default-on post-sunset."),
    ("V2_ATTACK_MODE_ENABLED", True,
     "Attack mode default-on post-sunset."),
    ("V2_CONTINUITY_LOG_ENABLED", True,
     "Continuity log default-on post-sunset."),
)


def _audit_flag_defaults() -> list[Finding]:
    findings: list[Finding] = []
    try:
        from radar import config
    except Exception as exc:
        findings.append(Finding(
            severity="MEDIUM",
            category="flag_default",
            title="Could not import radar.config",
            detail=f"Audit cannot inspect feature flag values: {exc}",
            actionable=False,
        ))
        return findings

    for name, expected, why in _FLAG_EXPECTATIONS:
        actual = getattr(config, name, None)
        if actual is None:
            continue
        if bool(actual) != expected:
            findings.append(Finding(
                severity="MEDIUM",
                category="flag_default",
                title=f"Flag {name} value is {actual!r}, expected {expected!r} post-sunset",
                detail=why,
                file_path="radar/config.py",
            ))
    return findings


# ── 3. DB write activity to conclusion_diff_log ──────────────────────────────


def _audit_db_activity() -> list[Finding]:
    findings: list[Finding] = []
    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001 — established internal pattern
        row = conn.execute(
            "SELECT MAX(sampled_at), COUNT(*) FROM conclusion_diff_log"
        ).fetchone()
    except Exception as exc:
        log.debug("DB audit failed: %s", exc)
        findings.append(Finding(
            severity="LOW",
            category="db_activity",
            title="Could not query conclusion_diff_log",
            detail=f"Audit cannot determine sampler activity: {exc}",
            actionable=False,
        ))
        return findings

    latest, row_count = row if row else (None, 0)

    if latest is not None:
        age_h = (time.time() - latest) / 3600.0
        if age_h < 24:
            findings.append(Finding(
                severity="HIGH",
                category="db_activity",
                title="conclusion_diff_log received writes within last 24h",
                detail=(f"Latest write {age_h:.1f}h ago. Sampler is still active. "
                        f"Set V2_CONCLUSION_DIFF_SAMPLER_ENABLED=false to stop."),
            ))
        elif age_h < 24 * 7:
            findings.append(Finding(
                severity="MEDIUM",
                category="db_activity",
                title="conclusion_diff_log received writes within last week",
                detail=f"Latest write {age_h:.0f}h ago. Sampler may have been recently disabled.",
            ))
        else:
            findings.append(Finding(
                severity="LOW",
                category="db_activity",
                title=f"conclusion_diff_log idle for {age_h / 24:.0f} days (table can be archived)",
                detail="No writes in over a week. Safe to drop after archival.",
                actionable=False,
            ))

    if row_count and row_count > 0:
        findings.append(Finding(
            severity="LOW",
            category="db_activity",
            title=f"conclusion_diff_log holds {row_count} historical rows",
            detail="Audit-only retention. Consider archival/deletion after Mode C completion.",
            actionable=False,
        ))
    return findings


# ── 4. Historical references in live code (informational) ────────────────────


_V1_TOKEN_RE = re.compile(r"\bv1\b", re.IGNORECASE)
_SKIP_DIRS = frozenset({"__pycache__", ".venv", "node_modules", "_archive"})
_SKIP_FILES = frozenset({"v1_sunset_audit.py"})


def _audit_historical_refs() -> list[Finding]:
    """Count v1 references in live Python code. LOW severity, informational only."""
    count = 0
    for path in RADAR_DIR.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name in _SKIP_FILES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for line in text.splitlines():
            stripped = line.lower()
            if not _V1_TOKEN_RE.search(line):
                continue
            # Suppress noise: version strings, REST API path fragments
            if "version" in stripped or "/v1" in stripped or "api/1" in stripped:
                continue
            count += 1
    findings: list[Finding] = []
    if count > 0:
        findings.append(Finding(
            severity="LOW",
            category="historical",
            title=f"{count} 'v1' references remain in live Python code",
            detail=("Most are docstring pointers to docs/_archive/scenario-refactor-v1.8.1.md "
                    "or comparison comments. No action required; flagged for completeness."),
            actionable=False,
        ))
    return findings


# ── Orchestration ────────────────────────────────────────────────────────────


def run_audit() -> AuditReport:
    """Aggregate every audit category. Each helper is fault-tolerant (NP3)."""
    findings: list[Finding] = []
    for fn in (_audit_active_code, _audit_flag_defaults,
               _audit_db_activity, _audit_historical_refs):
        try:
            findings.extend(fn())
        except Exception as exc:
            log.exception("audit step %s failed", fn.__name__)
            findings.append(Finding(
                severity="LOW",
                category="historical",
                title=f"Audit step {fn.__name__} failed",
                detail=str(exc)[:200],
                actionable=False,
            ))
    return AuditReport(generated_at=time.time(), findings=tuple(findings))


def format_text(report: AuditReport) -> str:
    lines: list[str] = []
    lines.append("V1 sunset residue audit")
    lines.append("=" * 60)
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report.generated_at))}")
    lines.append("")
    for severity in ("HIGH", "MEDIUM", "LOW"):
        section = [f for f in report.findings if f.severity == severity]
        lines.append(f"{severity}: {len(section)} finding(s)")
        lines.append("-" * 60)
        if not section:
            lines.append("  (none)")
        for f in section:
            lines.append(f"  [{f.category}] {f.title}")
            if f.file_path:
                loc = f.file_path
                if f.line is not None:
                    loc += f":{f.line}"
                lines.append(f"    location: {loc}")
            lines.append(f"    {f.detail}")
            lines.append("")
        lines.append("")
    lines.append(
        f"Summary: HIGH={len(report.high)} MEDIUM={len(report.medium)} LOW={len(report.low)}"
    )
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="V1 sunset residue audit (Phase E).")
    parser.add_argument("--json", action="store_true", help="emit structured JSON instead of text")
    parser.add_argument("--strict", action="store_true", help="exit 1 if any HIGH finding present")
    args = parser.parse_args(argv)

    report = run_audit()

    if args.json:
        out = {
            "generated_at": report.generated_at,
            "findings": [asdict(f) for f in report.findings],
            "counts": {
                "high": len(report.high),
                "medium": len(report.medium),
                "low": len(report.low),
            },
        }
        print(json.dumps(out, indent=2))
    else:
        print(format_text(report))

    if args.strict and report.high:
        return 1
    return 0


__all__ = [
    "Finding",
    "AuditReport",
    "run_audit",
    "format_text",
    "main",
]


if __name__ == "__main__":
    sys.exit(main())
