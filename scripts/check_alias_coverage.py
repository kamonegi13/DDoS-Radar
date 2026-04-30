#!/usr/bin/env python3
"""ADR-V2-015 Phase 2: alias coverage CI gate.

Verifies that every country appearing as a participant in geo_data.json
has a matching entry in ``radar.conclusions.rss_extractor._COUNTRY_ALIASES``.
A new scenario participant added without an alias breaks bg_observer's
ability to detect that country in RSS — silent recall loss.

Standalone (no radar package import) so it can run pre-commit / in CI
without triggering DB or sensor startup. Reads the alias map directly
by AST-parsing the source file.

Exit codes:
  0 — all participants covered
  1 — at least one participant has no alias entry (printed)
  2 — internal error (file not found, parse failure)
"""
from __future__ import annotations

import ast
import json
import pathlib
import sys


_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_GEO_PATH = _REPO_ROOT / "geo_data.json"
_EXTRACTOR_PATH = _REPO_ROOT / "radar" / "conclusions" / "rss_extractor.py"


def _load_aliases_from_source(path: pathlib.Path) -> set[str]:
    """Parse the rss_extractor source and extract the keys of
    ``_COUNTRY_ALIASES`` without importing the module (which would
    trigger the radar package init chain).
    """
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.target.id == "_COUNTRY_ALIASES":
            value = node.value
            if isinstance(value, ast.Dict):
                return {
                    k.value
                    for k in value.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "_COUNTRY_ALIASES":
                    if isinstance(node.value, ast.Dict):
                        return {
                            k.value
                            for k in node.value.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)
                        }
    raise RuntimeError("_COUNTRY_ALIASES not found in rss_extractor.py")


def _load_participants(path: pathlib.Path) -> set[str]:
    with path.open() as f:
        geo = json.load(f)
    out: set[str] = set()
    for sc in geo.get("SCENARIOS", {}).values():
        for cc in sc.get("participants", {}).keys():
            out.add(cc)
    return out


def main() -> int:
    if not _GEO_PATH.exists():
        print(f"[alias-coverage] geo_data.json not found at {_GEO_PATH}",
              file=sys.stderr)
        return 2
    if not _EXTRACTOR_PATH.exists():
        print(f"[alias-coverage] rss_extractor.py not found at {_EXTRACTOR_PATH}",
              file=sys.stderr)
        return 2
    try:
        aliases = _load_aliases_from_source(_EXTRACTOR_PATH)
        participants = _load_participants(_GEO_PATH)
    except Exception as exc:  # noqa: BLE001
        print(f"[alias-coverage] parse failure: {exc}", file=sys.stderr)
        return 2
    gap = sorted(p for p in participants if p not in aliases)
    if gap:
        print(
            f"[alias-coverage] FAIL — {len(gap)} participant(s) missing "
            f"from _COUNTRY_ALIASES: {gap}\n"
            f"  Add entries to "
            f"radar/conclusions/rss_extractor.py:_COUNTRY_ALIASES",
            file=sys.stderr,
        )
        return 1
    print(
        f"[alias-coverage] OK — {len(participants)} participants, "
        f"{len(aliases)} aliases",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
