#!/usr/bin/env python3
"""i18n key audit — EN-only UI + INTEL GUIDE bilingual parity (CLAUDE.md §3).

Two independent checks fold into one CLI gate:

  1. **STRINGS audit (UI side, EN-only)**
     Cross-checks the ``STRINGS`` dictionary in ``i18n.js`` against keys
     actually referenced in HTML (``data-i18n*=``) and JS (``_t('key')``).
     Reports:
       - undefined_refs: keys called from HTML/JS but missing from STRINGS
                         (would render as the key string at runtime — bug)
       - unused_keys:    keys defined in STRINGS but never referenced
                         (delete candidates)
       - opaque_calls:   ``_t(`tmpl.${var}`)`` template literals or var
                         args — flagged for manual review

  2. **INTEL GUIDE parity (long-form bilingual prose)**
     The help-modal in ``index.html`` keeps a hand-curated EN/JA pair for
     analyst reading. The pair must match: every ``.guide-lang-en`` block
     needs a sibling ``.guide-lang-ja`` and vice versa. A missing-pair is
     a hard fail.

Wired into ``scripts/check_ci.sh``. Use ``--strict`` to fail on any
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
# i18n.js excluded from JS scan (it's the dictionary itself, no _t() callers).
_JS_FILES = ("radar.js", "tradecraft.js", "hud_v2_overlay.js", "wp_alarm.js")

# Match `STRINGS = {` opener in i18n.js (replaces the old LANG.en block).
_STRINGS_OPEN = re.compile(r"^\s*const\s+STRINGS\s*=\s*\{\s*$")

# Match a key definition line:  'namespace.key':  'value' or "value"
_KEY_DEF = re.compile(r"""^\s*['"]([^'"]+)['"]\s*:\s*""")

# data-i18n="key", data-i18n-html, data-i18n-tip, data-i18n-ph
_HTML_ATTR = re.compile(r"""data-i18n(?:-(?:html|tip|ph))?\s*=\s*(?:"([^"]+)"|'([^']+)')""")

# _t('key') or _t("key") — literal first-arg only. Template literals / vars
# are reported as opaque (cannot resolve statically).
_T_LITERAL = re.compile(r"""(?<![A-Za-z0-9_])_t\(\s*(?:'([^'\\]+)'|"([^"\\]+)")\s*[,)]""")
_T_OPAQUE = re.compile(r"""(?<![A-Za-z0-9_])_t\(\s*(?!['"])""")

# INTEL GUIDE bilingual class markers. Defined in i18n.js setGuideLang().
_GUIDE_LANG_EN = re.compile(r'class\s*=\s*"[^"]*\bguide-lang-en\b[^"]*"')
_GUIDE_LANG_JA = re.compile(r'class\s*=\s*"[^"]*\bguide-lang-ja\b[^"]*"')


@dataclass(frozen=True)
class Report:
    defined_keys: frozenset[str]
    referenced_keys: frozenset[str]
    opaque_calls: tuple[tuple[str, int], ...] = field(default_factory=tuple)
    guide_en_count: int = 0
    guide_ja_count: int = 0

    @property
    def undefined_refs(self) -> frozenset[str]:
        return self.referenced_keys - self.defined_keys

    @property
    def unused_keys(self) -> frozenset[str]:
        return self.defined_keys - self.referenced_keys

    @property
    def guide_parity_ok(self) -> bool:
        return self.guide_en_count == self.guide_ja_count

    def to_dict(self) -> dict:
        return {
            "defined_count": len(self.defined_keys),
            "referenced_count": len(self.referenced_keys),
            "undefined_refs": sorted(self.undefined_refs),
            "unused_keys": sorted(self.unused_keys),
            "opaque_calls": [
                {"file": f, "line": ln} for f, ln in self.opaque_calls
            ],
            "guide_en_blocks": self.guide_en_count,
            "guide_ja_blocks": self.guide_ja_count,
            "guide_parity_ok": self.guide_parity_ok,
        }


def parse_strings_keys(i18n_path: Path) -> set[str]:
    """Extract every key from the STRINGS = { ... } object in i18n.js."""
    keys: set[str] = set()
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
    return keys


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


def count_guide_blocks(html_path: Path) -> tuple[int, int]:
    """Count `.guide-lang-en` and `.guide-lang-ja` element occurrences in HTML.

    Used to enforce INTEL GUIDE bilingual parity — every EN block needs a
    JA block and vice versa.
    """
    text = html_path.read_text(encoding="utf-8")
    en = len(_GUIDE_LANG_EN.findall(text))
    ja = len(_GUIDE_LANG_JA.findall(text))
    return en, ja


def build_report() -> Report:
    defined = parse_strings_keys(_REPO_ROOT / "i18n.js")
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

    en_count, ja_count = count_guide_blocks(_REPO_ROOT / "index.html")

    return Report(
        defined_keys=frozenset(defined),
        referenced_keys=frozenset(referenced),
        opaque_calls=tuple(opaque),
        guide_en_count=en_count,
        guide_ja_count=ja_count,
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 1 if any undefined_refs OR INTEL GUIDE parity fails "
             "(default: warn-only on undefined_refs; parity always fatal)",
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
        print(f"i18n audit (EN-only UI per CLAUDE.md §3.1):")
        print(f"  defined keys:    {len(report.defined_keys)}")
        print(f"  referenced keys: {len(report.referenced_keys)}")
        print(f"  undefined refs:  {len(report.undefined_refs)} "
              f"{'(would render as the key string at runtime)' if report.undefined_refs else ''}")
        print(f"  unused keys:     {len(report.unused_keys)} "
              f"{'(delete candidates)' if report.unused_keys else ''}")
        print(f"  opaque _t calls: {len(report.opaque_calls)} "
              f"(template literals / variables — manual review)")
        print()
        print(f"INTEL GUIDE parity (.guide-lang-en vs .guide-lang-ja):")
        print(f"  EN blocks: {report.guide_en_count}")
        print(f"  JA blocks: {report.guide_ja_count}")
        print(f"  parity:    {'OK' if report.guide_parity_ok else 'FAIL'}")

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

    # GUIDE parity is always fatal — bilingual contract is the ONE place we
    # gate hard, since machine translation cannot rescue long-form prose.
    if not report.guide_parity_ok:
        print(
            f"\nFAIL: INTEL GUIDE bilingual parity broken "
            f"({report.guide_en_count} EN vs {report.guide_ja_count} JA blocks). "
            f"Every .guide-lang-en needs a sibling .guide-lang-ja and vice versa.",
            file=sys.stderr,
        )
        return 1
    if args.strict and report.undefined_refs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
