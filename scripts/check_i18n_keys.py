#!/usr/bin/env python3
"""i18n key audit — Japanese-only UI (CLAUDE.md §1, docs/design/ja-localization.md).

Three independent checks fold into one CLI gate:

  1. **STRINGS key audit**
     Cross-checks the ``STRINGS`` dictionary in ``i18n.js`` against keys
     actually referenced in HTML (``data-i18n*=``) and JS (``_t('key')``).
     Reports:
       - undefined_refs: keys called from HTML/JS but missing from STRINGS
                         (would render as the key string at runtime — bug)
       - unused_keys:    keys defined in STRINGS but never referenced
                         (delete candidates)
       - opaque_calls:   ``_t(`tmpl.${var}`)`` template literals or var
                         args — flagged for manual review

  2. **Untranslated-value detection (fatal)**
     Every STRINGS value must contain Japanese, unless it is legitimately
     code — an ALL-CAPS state code, a unit, a number, pure symbols, or a
     term that ja-localization.md §2 keeps in English on purpose (recall,
     drift, BGP, NP6, sensor IDs …). Catches translation misses
     structurally instead of by eyeball.

  3. **Japanese-only shell (fatal)**
     The bilingual INTEL GUIDE was retired 2026-08-02. No
     ``.guide-lang-en`` block may survive, and ``<html>`` must declare
     ``lang="ja"`` so screen readers pick the Japanese TTS voice
     (WCAG 2.2 SC 3.1.1 / 3.1.2).

Wired into ``scripts/check_ci.sh``. Use ``--strict`` to also fail on
undefined_refs (default: warn only).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# Files to scan for key references.
_HTML_FILES = ("index.html",)
# Every JS file that calls _t(). i18n.js is excluded from the *reference*
# scan (it is the dictionary itself; its own _t() uses are the runtime
# implementation, not UI call sites).
_JS_FILES = (
    "radar.js",
    "tradecraft.js",
    "controls_panel.js",
    "autotune_wizard.js",
    "llm_features_hub.js",
    "self_explanation.js",
    "triage_display_mode.js",
    "triage_score.js",
    "map_dim.js",
    "hud_v2_overlay.js",
    "wp_alarm.js",
    "login-init.js",
)

# Match `STRINGS = {` opener in i18n.js.
_STRINGS_OPEN = re.compile(r"^\s*const\s+STRINGS\s*=\s*\{\s*$")

# Match a key definition line:  'namespace.key':  'value' or "value"
_KEY_DEF = re.compile(r"""^\s*['"]([^'"]+)['"]\s*:\s*""")
# Same, but also capturing a single-quoted value (for the translation check).
_KEY_VAL = re.compile(
    r"""^\s*'([A-Za-z0-9_.]+)'\s*:\s*'((?:[^'\\]|\\.)*)'\s*,?\s*(?://.*)?$"""
)

# data-i18n="key", data-i18n-html, data-i18n-tip, data-i18n-ph
_HTML_ATTR = re.compile(r"""data-i18n(?:-(?:html|tip|ph))?\s*=\s*(?:"([^"]+)"|'([^']+)')""")

# _t('key') or _t("key") — literal first-arg only. Template literals / vars
# are reported as opaque (cannot resolve statically).
_T_LITERAL = re.compile(r"""(?<![A-Za-z0-9_])_t\(\s*(?:'([^'\\]+)'|"([^"\\]+)")\s*[,)]""")
_T_OPAQUE = re.compile(r"""(?<![A-Za-z0-9_])_t\(\s*(?!['"])""")

# Retired bilingual-guide marker — must no longer appear anywhere.
_GUIDE_LANG_EN = re.compile(r'class\s*=\s*"[^"]*\bguide-lang-en\b[^"]*"')
# <html lang="ja"> (attribute order agnostic).
_HTML_LANG_JA = re.compile(r'<html\b[^>]*\blang\s*=\s*"ja"', re.IGNORECASE)

# ── untranslated-value detection ──────────────────────────────────────────
# Hiragana / katakana / CJK ideographs / Japanese punctuation.
_JA_CHAR = re.compile(r"[぀-ヿ一-鿿、。（）「」]")

# Terms ja-localization.md §2 deliberately keeps in English.
_KEEP_EN = (
    r"recall|precision|drift|Calibration|calibration|BGP|ASN|OSINT|HUMINT|"
    r"SIGINT|LLM|RSS|C2|ISR|AIS|NOTAM|TTP|IoC|TL|GDELT|ACLED|Ollama|"
    r"Cloudflare|OpenSky|RIPE|IODA|CRITICAL|SEVERE|HIGH|ELEVATED|NORMAL|"
    r"TP|FP|FN|TN|F1|Z-score|NP[1-8]|AP[1-4]|ADR|full|lite|auto|OK|RED|"
    r"API|UTC|JSON|CSV|PDF|Markdown|SITREP|HUD|ID|URL|IP|UI|conf|n/a|N/A"
)
# A value made up only of: whitespace, punctuation/symbols, digits,
# {placeholders}, and the keep-English terms above needs no Japanese.
_ONLY_CODE = re.compile(
    rf"^(?:\s|[^\w\s]|\{{[a-zA-Z_][a-zA-Z0-9_]*\}}|\d|{_KEEP_EN})*$"
)

# Keys whose value is a machine identifier rather than prose, and therefore
# legitimately contains no Japanese. Kept as an explicit list, not a clever
# regex: a pattern loose enough to pass `eps={eps}` also passes real English,
# which would defeat the gate. Adding a key here is a reviewable decision.
_CODE_ONLY_KEYS: frozenset[str] = frozenset({
    # ── identifiers / hyperparameters / DB columns ────────────────────
    # Must match the API verbatim so an analyst can trace a displayed
    # value back to its source row (NP6).
    "discovery.panel.eps",
    "discovery.panel.min_samples",
    "discovery.panel.run_id",
    "wizard.row.sample_n",
    "wizard.row.run_id",
    # ── time horizons and units ───────────────────────────────────────
    "cc.horizon.short", "cc.horizon.medium", "cc.horizon.long",
    "panel.llm_intel.diag_col_ms",
    # ── formulas rendered verbatim ────────────────────────────────────
    "drill_modal.calib.recall", "drill_modal.calib.precision",
    "tl_prox.near_esc", "tl_prox.near_deesc",
    "evidence.group.total", "sysconfig.llm.fetch_error",
    # ── scoring-mode / rule-state codes (mirror API values) ───────────
    "cc.scoring_mode.lite", "scenario.badge.lite",
    "watchpane.scope.focused", "watchpane.scope.global",
    "watchpane.row.suppressed", "watchpane.row.fired",
    "hud.coord.mode.all", "hud.coord.mode.strong", "hud.coord.mode.off",
    "wizard.tab.recall_positive", "wizard.tab.recall_negative",
    "modal.help.ch10",
    # ── HUD wordmarks: a dense uppercase chip row the INTEL GUIDE
    #    references by these exact names. Kept English as a coherent set
    #    (docs/design/ja-localization.md §2).
    "hud.btn.sync", "hud.btn.chain", "hud.btn.tools", "hud.btn.evidence",
    "hud.btn.salute", "hud.label.sys", "hud.label.climate",
    "hud.label.intel", "hud.label.bg_alert", "hud.label.eta",
    "hud.label.hod_z", "hud.label.context_align", "hud.label.direction",
    "climate.badge_prefix", "llm_routing.chip.title", "fleet.col.cb",
    "badge.media_alert", "badge.awacs",
    # ── vendor / protocol / tradecraft acronyms ───────────────────────
    "tools.telegram_sigint", "tools.greynoise",
    "drill_modal.llm.temperature", "drill_modal.llm.sha256",
    "gn.tier.enterprise", "gn.tier.community", "gn.tier.no_key",
    "gn.result.noise", "gn.result.targeted", "gn.result.riot",
    "panel.llm_intel.filter_apt",   # Advanced Persistent Threat
    "panel.tradecraft.tab.ach",     # Analysis of Competing Hypotheses
    "panel.usermgr.btn.pw",
})


def _needs_translation(key: str, value: str) -> bool:
    """True when a STRINGS value looks like untranslated English prose."""
    if _JA_CHAR.search(value):
        return False
    if key in _CODE_ONLY_KEYS:
        return False
    return not _ONLY_CODE.match(value)


@dataclass(frozen=True)
class Report:
    defined_keys: frozenset[str]
    referenced_keys: frozenset[str]
    opaque_calls: tuple[tuple[str, int], ...] = field(default_factory=tuple)
    untranslated: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    guide_en_count: int = 0
    html_lang_ja: bool = False

    @property
    def undefined_refs(self) -> frozenset[str]:
        return self.referenced_keys - self.defined_keys

    @property
    def unused_keys(self) -> frozenset[str]:
        return self.defined_keys - self.referenced_keys

    @property
    def ja_only_ok(self) -> bool:
        return self.guide_en_count == 0 and self.html_lang_ja

    @property
    def translation_ok(self) -> bool:
        return not self.untranslated

    def to_dict(self) -> dict:
        return {
            "defined_count": len(self.defined_keys),
            "referenced_count": len(self.referenced_keys),
            "undefined_refs": sorted(self.undefined_refs),
            "unused_keys": sorted(self.unused_keys),
            "opaque_calls": [
                {"file": f, "line": ln} for f, ln in self.opaque_calls
            ],
            "untranslated": [
                {"key": k, "value": v} for k, v in self.untranslated
            ],
            "guide_en_blocks": self.guide_en_count,
            "html_lang_ja": self.html_lang_ja,
            "ja_only_ok": self.ja_only_ok,
            "translation_ok": self.translation_ok,
        }


def parse_strings(i18n_path: Path) -> tuple[set[str], list[tuple[str, str]]]:
    """Extract keys, and the (key, value) pairs that still look English."""
    keys: set[str] = set()
    untranslated: list[tuple[str, str]] = []
    in_block = False
    depth = 0
    for line in i18n_path.read_text(encoding="utf-8").splitlines():
        if not in_block:
            if _STRINGS_OPEN.match(line):
                in_block = True
                depth = 1
            continue
        depth += line.count("{") - line.count("}")
        if depth <= 0:
            break
        m = _KEY_DEF.match(line)
        if m:
            keys.add(m.group(1))
        mv = _KEY_VAL.match(line)
        if mv and _needs_translation(mv.group(1), mv.group(2)):
            untranslated.append((mv.group(1), mv.group(2)))
    return keys, untranslated


def scan_html(path: Path) -> set[str]:
    out: set[str] = set()
    for m in _HTML_ATTR.finditer(path.read_text(encoding="utf-8")):
        key = m.group(1) or m.group(2)
        if key:
            out.add(key)
    return out


def scan_js(path: Path) -> tuple[set[str], list[tuple[str, int]]]:
    refs: set[str] = set()
    opaque: list[tuple[str, int]] = []
    text = path.read_text(encoding="utf-8")
    for m in _T_LITERAL.finditer(text):
        key = m.group(1) or m.group(2)
        if key:
            refs.add(key)
    rel = str(path.relative_to(_REPO_ROOT))
    for i, line in enumerate(text.splitlines(), start=1):
        if not _T_OPAQUE.search(line):
            continue
        if re.search(r"function\s+_t\s*\(", line):
            continue
        opaque.append((rel, i))
    return refs, opaque


def build_report() -> Report:
    defined, untranslated = parse_strings(_REPO_ROOT / "i18n.js")
    referenced: set[str] = set()
    opaque: list[tuple[str, int]] = []

    for name in _HTML_FILES:
        p = _REPO_ROOT / name
        if p.exists():
            referenced |= scan_html(p)

    for name in _JS_FILES:
        p = _REPO_ROOT / name
        if not p.exists():
            continue
        refs, op = scan_js(p)
        referenced |= refs
        opaque.extend(op)

    html_text = (_REPO_ROOT / "index.html").read_text(encoding="utf-8")

    return Report(
        defined_keys=frozenset(defined),
        referenced_keys=frozenset(referenced),
        opaque_calls=tuple(opaque),
        untranslated=tuple(untranslated),
        guide_en_count=len(_GUIDE_LANG_EN.findall(html_text)),
        html_lang_ja=bool(_HTML_LANG_JA.search(html_text)),
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 1 on undefined_refs too (default: warn-only; "
             "untranslated values and the JA-only shell are always fatal)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON to stdout",
    )
    args = parser.parse_args(argv)

    report = build_report()

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print("i18n audit (Japanese-only UI per CLAUDE.md §1):")
        print(f"  defined keys:    {len(report.defined_keys)}")
        print(f"  referenced keys: {len(report.referenced_keys)}")
        print(f"  undefined refs:  {len(report.undefined_refs)} "
              f"{'(would render as the key string at runtime)' if report.undefined_refs else ''}")
        print(f"  unused keys:     {len(report.unused_keys)} "
              f"{'(delete candidates)' if report.unused_keys else ''}")
        print(f"  opaque _t calls: {len(report.opaque_calls)} "
              f"(template literals / variables — manual review)")
        print()
        print("Japanese-only shell:")
        print(f"  untranslated values: {len(report.untranslated)} "
              f"{'OK' if report.translation_ok else 'FAIL'}")
        print(f"  guide-lang-en blocks: {report.guide_en_count} "
              f"{'OK' if report.guide_en_count == 0 else 'FAIL (bilingual guide retired)'}")
        print(f"  <html lang=\"ja\">: {'OK' if report.html_lang_ja else 'FAIL'} "
              f"(WCAG 3.1.1)")

        if report.undefined_refs:
            print("\nUndefined references (top 30):", file=sys.stderr)
            for k in sorted(report.undefined_refs)[:30]:
                print(f"  - {k}", file=sys.stderr)
            if len(report.undefined_refs) > 30:
                print(f"  ... and {len(report.undefined_refs) - 30} more",
                      file=sys.stderr)

        if report.unused_keys:
            print("\nUnused keys (top 30):")
            for k in sorted(report.unused_keys)[:30]:
                print(f"  - {k}")
            if len(report.unused_keys) > 30:
                print(f"  ... and {len(report.unused_keys) - 30} more")

    # Untranslated prose is fatal: the whole point of the Japanese-only
    # rewrite is that no English sentence reaches the analyst. If a value
    # is a legitimate code, add its term to _KEEP_EN rather than muting
    # the gate.
    if not report.translation_ok:
        print(f"\nFAIL: {len(report.untranslated)} STRINGS values contain no "
              f"Japanese and are not recognized codes:", file=sys.stderr)
        for k, v in report.untranslated[:30]:
            print(f"  - {k}: {v!r}", file=sys.stderr)
        if len(report.untranslated) > 30:
            print(f"  ... and {len(report.untranslated) - 30} more",
                  file=sys.stderr)
        return 1
    if report.guide_en_count:
        print(f"\nFAIL: {report.guide_en_count} .guide-lang-en block(s) remain. "
              f"The bilingual INTEL GUIDE was retired 2026-08-02 — the guide "
              f"is Japanese-only (docs/design/ja-localization.md §5).",
              file=sys.stderr)
        return 1
    if not report.html_lang_ja:
        print("\nFAIL: <html> must declare lang=\"ja\" so assistive tech "
              "selects the Japanese voice (WCAG 2.2 SC 3.1.1).",
              file=sys.stderr)
        return 1
    if args.strict and report.undefined_refs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
