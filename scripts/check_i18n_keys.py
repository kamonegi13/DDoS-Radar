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

**Two scopes (WP-4.2).** The v1 surface (``i18n.js`` + the twelve legacy JS
files) and the v3 surface (``v3/ui/strings.js`` + ``v3/ui/*.js`` +
``v3/ui/index.html``) are audited independently, because P8 §8 prunes the
1,556 v1 keys only once v3's screen inventory is fixed — until then the two
tables carry different debts and one gate cannot hold both to one standard.
The v3 scope is therefore **stricter**: undefined references AND unused keys
are fatal there, since a greenfield dictionary that already contains a dead
key contains a key that should never have been written.

The v3 scope also resolves keys built by concatenation (``'ui.trust.state.'
+ state``). A prefix literal marks every key beneath it as reachable; a full
literal that names no defined key is still an undefined reference. Without
that, the pure modules' ``labelKey`` discipline — which is what keeps prose
out of the logic — would read as hundreds of dead keys.
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
    r"recall|precision|drift|calibration|BGP|ASN|OSINT|HUMINT|"
    r"SIGINT|LLM|RSS|C2|ISR|AIS|NOTAM|TTP|IoC|TL|GDELT|ACLED|Ollama|"
    r"Cloudflare|OpenSky|RIPE|IODA|CRITICAL|SEVERE|HIGH|ELEVATED|NORMAL|"
    r"TP|FP|FN|TN|F1|Z-score|SHA|NP[1-8]|AP[1-4]|ADR|full|lite|auto|OK|RED|"
    r"API|UTC|JSON|CSV|PDF|Markdown|SITREP|HUD|ID|URL|IP|UI|conf|n/a"
)
# A value made up only of: whitespace, punctuation/symbols, digits,
# {placeholders}, and the keep-English terms above needs no Japanese.
# Case-insensitive so 'Recall (TP/(TP+FN))' and 'recall' both resolve
# against the same term list.
_ONLY_CODE = re.compile(
    rf"^(?:\s|[^\w\s]|\{{[a-zA-Z_][a-zA-Z0-9_]*\}}|\d|{_KEEP_EN})*$",
    re.IGNORECASE,
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
    "tl_prox.near_esc", "tl_prox.near_deesc",
    "evidence.group.total", "sysconfig.llm.fetch_error",
    # ── scoring-mode / rule-state codes (mirror API values) ───────────
    "cc.scoring_mode.lite",
    "watchpane.scope.focused", "watchpane.scope.global",
    "watchpane.row.suppressed", "watchpane.row.fired",
    "hud.coord.mode.all", "hud.coord.mode.strong", "hud.coord.mode.off",
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
    "drill_modal.llm.temperature",
    "gn.tier.enterprise", "gn.tier.community", "gn.tier.no_key",
    "gn.result.noise", "gn.result.targeted", "gn.result.riot",
    "panel.llm_intel.filter_apt",   # Advanced Persistent Threat
    "panel.tradecraft.tab.ach",     # Analysis of Competing Hypotheses
    "panel.usermgr.btn.pw",
    # ── v3 (WP-4.2): AP3 component name and a JSON example ────────────
    #   `null-zone` is the AP3 indicator's name, kept English with the
    #   rest of the reliability vocabulary (recall / precision / drift)
    #   per ja-localization.md §2. The placeholder is a literal request
    #   body an analyst types verbatim.
    "ui.trust.component.null_zone",
    "ui.whatif.placeholder",
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


# ── v3 scope (WP-4.2) ─────────────────────────────────────────────────────
_V3_DIR = _REPO_ROOT / "v3" / "ui"
_V3_DICTIONARY = _V3_DIR / "strings.js"

#: A key literal, or a prefix ending in a dot for a concatenated family.
#:
#: Three namespaces, not one. `ui.*` is the screen inventory; WP-4.3c adds
#: `term.*` (P9 §4 — the one-sentence definition of each internal term) and
#: `empty.*` (P9 §3.5 — the role / reason / fills-when triple every empty
#: surface owes its reader). Both are named by P9 itself, and a namespace the
#: scanner does not know would report every key in it as unused — which would
#: read as "delete these" rather than "the audit cannot see them".
_V3_KEY_LITERAL = re.compile(r"""['"]((?:ui|term|empty)\.[A-Za-z0-9_.]*)['"]""")


def scan_v3_references() -> set[str]:
    """Every key literal and key prefix the v3 surface mentions."""
    refs: set[str] = set()
    for path in sorted(_V3_DIR.glob("*.js")):
        if path == _V3_DICTIONARY:
            continue
        for match in _V3_KEY_LITERAL.finditer(path.read_text(encoding="utf-8")):
            refs.add(match.group(1))
    for path in sorted(_V3_DIR.glob("*.html")):
        refs |= scan_html(path)
    return refs


def build_v3_report() -> Report:
    if not _V3_DICTIONARY.exists():
        return Report(defined_keys=frozenset(), referenced_keys=frozenset(),
                      html_lang_ja=True)
    defined, untranslated = parse_strings(_V3_DICTIONARY)
    referenced = scan_v3_references()

    full_refs = {ref for ref in referenced if not ref.endswith(".")}
    prefixes = {ref for ref in referenced if ref.endswith(".")}

    # A defined key is reached either by its own literal or by a prefix that
    # some module concatenates onto.
    reached = {
        key for key in defined
        if key in full_refs or any(key.startswith(p) for p in prefixes)
    }
    # An undefined reference is a full literal naming nothing. Prefixes are
    # never undefined references: a family with no members is caught by the
    # unused-key half instead.
    undefined = full_refs - defined

    html_files = sorted(_V3_DIR.glob("*.html"))
    lang_ok = all(bool(_HTML_LANG_JA.search(p.read_text(encoding="utf-8")))
                  for p in html_files) if html_files else True
    guide_en = sum(len(_GUIDE_LANG_EN.findall(p.read_text(encoding="utf-8")))
                   for p in html_files)

    return Report(
        defined_keys=frozenset(defined),
        # Report the reached set as "referenced" so the Report's own
        # undefined/unused properties stay meaningful for the v3 scope.
        referenced_keys=frozenset(reached | undefined),
        untranslated=tuple(untranslated),
        guide_en_count=guide_en,
        html_lang_ja=lang_ok,
    )


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
    v3_report = build_v3_report()

    if args.json:
        payload = report.to_dict()
        payload["v3"] = v3_report.to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True))
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
        print()
        print("v3 scope (v3/ui/strings.js — undefined AND unused are fatal):")
        print(f"  defined keys:    {len(v3_report.defined_keys)}")
        print(f"  undefined refs:  {len(v3_report.undefined_refs)}")
        print(f"  unused keys:     {len(v3_report.unused_keys)}")
        print(f"  untranslated:    {len(v3_report.untranslated)}")

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
    # ── the v3 scope, held to the stricter standard ──────────────────────
    if v3_report.defined_keys or v3_report.referenced_keys:
        if not v3_report.translation_ok:
            print(f"\nFAIL (v3): {len(v3_report.untranslated)} STRINGS values "
                  f"contain no Japanese and are not recognized codes:",
                  file=sys.stderr)
            for k, v in v3_report.untranslated[:30]:
                print(f"  - {k}: {v!r}", file=sys.stderr)
            return 1
        if not v3_report.html_lang_ja:
            print('\nFAIL (v3): the v3 shell must declare <html lang="ja">.',
                  file=sys.stderr)
            return 1
        if v3_report.guide_en_count:
            print(f"\nFAIL (v3): {v3_report.guide_en_count} .guide-lang-en "
                  f"block(s) in the v3 shell.", file=sys.stderr)
            return 1
        if v3_report.undefined_refs:
            print(f"\nFAIL (v3): {len(v3_report.undefined_refs)} key(s) are "
                  f"referenced but not defined — they would render as the key "
                  f"string:", file=sys.stderr)
            for key in sorted(v3_report.undefined_refs)[:30]:
                print(f"  - {key}", file=sys.stderr)
            return 1
        if v3_report.unused_keys:
            print(f"\nFAIL (v3): {len(v3_report.unused_keys)} key(s) are "
                  f"defined and never used. P8 §8 ports the dictionary by "
                  f"pruning it, so an unused key in a greenfield table is a "
                  f"key that should not have been written:", file=sys.stderr)
            for key in sorted(v3_report.unused_keys)[:30]:
                print(f"  - {key}", file=sys.stderr)
            return 1

    if args.strict and report.undefined_refs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
