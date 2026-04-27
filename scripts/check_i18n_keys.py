#!/usr/bin/env python3
"""i18n key audit — JA-side only (per CLAUDE.md §3.1, EN frozen 2026-04-28).

Cross-checks `i18n.js` (JA block) against the keys actually referenced in:
  - HTML: `data-i18n=`, `data-i18n-html=`, `data-i18n-tip=`, `data-i18n-ph=`
  - JS:   `_t('key')` and `_t("key")` (string-literal calls only)

Reports three categories:
  - `undefined_refs`: keys referenced in code but absent from JA dictionary
                     (will fall back to the key itself at runtime — visible bug)
  - `unused_keys`:    keys defined in JA but never referenced
                     (delete candidates — safe per JA-primary policy)
  - `opaque_calls`:   `_t(...)` calls that use template literals or variables
                     (cannot resolve statically; reported for manual review)

Wired into ``scripts/check_ci.sh`` as a non-fatal warn first; flip to fatal
once the tree is clean.

Usage:
    python scripts/check_i18n_keys.py            # exit 0 + warning summary
    python scripts/check_i18n_keys.py --strict   # exit 1 if any undefined ref
    python scripts/check_i18n_keys.py --json     # machine-readable output
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
_JS_FILES = ("radar.js", "tradecraft.js", "hud_v2_overlay.js", "wp_alarm.js")  # exclude i18n.js (the dictionary itself; no _t() calls)

# Match the JA block opening / closing in i18n.js.
_JA_BLOCK_OPEN = re.compile(r"^\s*ja:\s*\{\s*$")
_JA_BLOCK_CLOSE = re.compile(r"^\s*\}\s*[,;]?\s*$")  # closing brace of ja: block

# Match a key definition line:  'namespace.key':  'value' or "value"
# Allows trailing commas and inline comments.
_KEY_DEF = re.compile(r"""^\s*['"]([^'"]+)['"]\s*:\s*""")

# data-i18n="key", data-i18n-html, data-i18n-tip, data-i18n-ph (single OR double quotes)
_HTML_ATTR = re.compile(r"""data-i18n(?:-(?:html|tip|ph))?\s*=\s*(?:"([^"]+)"|'([^']+)')""")

# _t('key') or _t("key") — string-literal first argument only.
# Any expression first arg (template literal, variable, concat) → opaque.
_T_LITERAL = re.compile(r"""(?<![A-Za-z0-9_])_t\(\s*(?:'([^'\\]+)'|"([^"\\]+)")\s*[,)]""")
# Capture _t calls that DON'T start with a quoted literal — for the opaque report.
_T_OPAQUE = re.compile(r"""(?<![A-Za-z0-9_])_t\(\s*(?!['"])""")


@dataclass(frozen=True)
class Report:
    defined_keys: frozenset[str]
    referenced_keys: frozenset[str]
    opaque_calls: tuple[tuple[str, int], ...] = field(default_factory=tuple)

    @property
    def undefined_refs(self) -> frozenset[str]:
        return self.referenced_keys - self.defined_keys

    @property
    def unused_keys(self) -> frozenset[str]:
        return self.defined_keys - self.referenced_keys

    def to_dict(self) -> dict:
        return {
            "defined_count": len(self.defined_keys),
            "referenced_count": len(self.referenced_keys),
            "undefined_refs": sorted(self.undefined_refs),
            "unused_keys": sorted(self.unused_keys),
            "opaque_calls": [
                {"file": f, "line": ln} for f, ln in self.opaque_calls
            ],
        }


def parse_ja_keys(i18n_path: Path) -> set[str]:
    """Extract every key defined in the `ja:` block of i18n.js."""
    keys: set[str] = set()
    in_ja = False
    depth = 0
    for line in i18n_path.read_text(encoding="utf-8").splitlines():
        if not in_ja:
            if _JA_BLOCK_OPEN.match(line):
                in_ja = True
                depth = 1
            continue
        # Track brace depth so we stop at the matching close.
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
    # For opaque calls, walk line-by-line so we can report line numbers.
    rel = str(path.relative_to(_REPO_ROOT))
    for i, line in enumerate(text.splitlines(), start=1):
        if not _T_OPAQUE.search(line):
            continue
        # Exclude false positives: function definitions like `function _t(`
        if re.search(r"function\s+_t\s*\(", line):
            continue
        # Some opaque calls are still string-only on a follow-up line; tolerate them.
        opaque.append((rel, i))
    return refs, opaque


def build_report() -> Report:
    defined = parse_ja_keys(_REPO_ROOT / "i18n.js")
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

    return Report(
        defined_keys=frozenset(defined),
        referenced_keys=frozenset(referenced),
        opaque_calls=tuple(opaque),
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 1 if any undefined_refs (default: warn-only, exit 0)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON to stdout instead of human report",
    )
    args = parser.parse_args(argv)

    report = build_report()

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 1 if (args.strict and report.undefined_refs) else 0

    print(f"i18n audit (JA-only per CLAUDE.md §3.1):")
    print(f"  defined keys:    {len(report.defined_keys)}")
    print(f"  referenced keys: {len(report.referenced_keys)}")
    print(f"  undefined refs:  {len(report.undefined_refs)} "
          f"{'(would render as the key string at runtime)' if report.undefined_refs else ''}")
    print(f"  unused keys:     {len(report.unused_keys)} "
          f"{'(delete candidates)' if report.unused_keys else ''}")
    print(f"  opaque _t calls: {len(report.opaque_calls)} "
          f"(template literals / variables — manual review)")

    if report.undefined_refs:
        print("\nUndefined references (top 30):", file=sys.stderr)
        for k in sorted(report.undefined_refs)[:30]:
            print(f"  - {k}", file=sys.stderr)
        if len(report.undefined_refs) > 30:
            print(f"  ... and {len(report.undefined_refs) - 30} more", file=sys.stderr)

    if report.unused_keys:
        print("\nUnused keys (top 30):")
        for k in sorted(report.unused_keys)[:30]:
            print(f"  - {k}")
        if len(report.unused_keys) > 30:
            print(f"  ... and {len(report.unused_keys) - 30} more")

    if args.strict and report.undefined_refs:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
