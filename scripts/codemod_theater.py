"""theater → {country, scenario, focused_country} codemod (Phase 1 scaffolding).

Per ADR-V2-006 in docs/design/v2-migration.md, the v1 term "theater" overloaded
two distinct concepts (country tag + scenario unit). v2 splits them:

  * `theater` (column / SQL key)            → `country`
  * `core_theater` / `_default_theater`     → `focused_country`
  * `theater` in user-facing prompts/docs   → `country` or `scenario` (manual)
  * `theater` in legacy v1 API params       → KEEP (v1 adapter wraps v2)

This script DOES NOT mutate code by default. It runs in three modes:

  discover  — walk all files, classify every `theater` occurrence, emit a
              JSON manifest at scripts/_codemod_manifest.json
  diff      — read the manifest and print the proposed unified diff to stdout
  apply     — read the manifest and apply rewrites in-place (requires
              `--i-have-a-clean-git-tree` to guard against losing work)

Usage:
    python scripts/codemod_theater.py discover
    python scripts/codemod_theater.py diff       # review before applying
    python scripts/codemod_theater.py apply --i-have-a-clean-git-tree

Coverage scope (from current snapshot, 2026-04-25):
    71 files, ~1,612 occurrences. Excludes .venv, .git, node_modules.

Phase 1 plan:
    1. discover  → manual review of manifest (especially AMBIGUOUS rows)
    2. resolve ambiguities by editing manifest in place
    3. diff      → eyeball the rewrite
    4. apply     → commit on a dedicated branch
    5. run full test suite + smoke tradecraft
    6. v1 adapter for /api/* params accepting `?theater=` retained per ADR-V2-006
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "scripts" / "_codemod_manifest.json"

# Files / directories never touched by the codemod.
EXCLUDED_DIR_PARTS = frozenset({".venv", ".git", "node_modules", "__pycache__", "scripts"})
EXCLUDED_FILES = frozenset({
    "docs/design/scenario-refactor.md",  # frozen v1 design doc
    "scripts/codemod_theater.py",        # this file itself
})

# File extensions to scan.
SCAN_EXTENSIONS = (".py", ".js", ".html", ".md", ".json")

Classification = Literal[
    "rename_to_country",        # mechanical: theater → country
    "rename_to_focused_country",  # core_theater → focused_country
    "keep_v1_api_param",        # /api/... ?theater= must remain (v1 adapter)
    "user_facing_text",         # docstrings, prompt templates → review
    "ambiguous",                # cannot classify automatically — manual review
]


@dataclass(frozen=True)
class Occurrence:
    """One `theater` occurrence with its proposed classification."""

    path: str        # repo-relative path
    line: int        # 1-indexed
    col: int         # 0-indexed
    snippet: str     # ~80 chars of surrounding text
    matched: str     # the actual matched token (e.g. "core_theater", "theater")
    classification: Classification
    proposed: str    # what `matched` would be replaced with (or empty)
    note: str = ""   # human-readable rationale


# Regex for a token *containing* "theater" anywhere in the identifier.
TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*theater[A-Za-z0-9_]*", re.IGNORECASE)


def _is_excluded(path: Path) -> bool:
    rel = path.relative_to(REPO_ROOT)
    if any(part in EXCLUDED_DIR_PARTS for part in rel.parts):
        return True
    return str(rel) in EXCLUDED_FILES


def _walk_files() -> Iterable[Path]:
    for ext in SCAN_EXTENSIONS:
        for p in REPO_ROOT.rglob(f"*{ext}"):
            if not _is_excluded(p):
                yield p


def _classify(token: str, line_text: str, path: Path) -> tuple[Classification, str, str]:
    """Return (classification, proposed_replacement, note) for a single token."""
    lower = token.lower()
    line_lower = line_text.lower()

    # 1. /api/... ?theater= — keep for v1 compat
    if "request.args" in line_lower and "theater" in line_lower:
        return ("keep_v1_api_param", "", "v1 API param — adapter handles v2 mapping")
    if re.search(r"@app\.route|@bp\.route", line_lower) and "theater" in line_lower:
        return ("keep_v1_api_param", "", "route decorator — keep")

    # 2. core_theater → focused_country
    if lower in {"core_theater", "_default_theater", "default_theater"}:
        return (
            "rename_to_focused_country",
            "focused_country" if lower == "core_theater" else "default_focused_country",
            "scenario-focused country variable",
        )
    if "core_theater" in lower:
        return ("rename_to_focused_country", token.replace("core_theater", "focused_country"),
                "compound containing core_theater")

    # 3. SQL identifier or pure `theater` token → rename to country
    if lower == "theater":
        # Inside SQL CREATE / WHERE / INDEX, this is a column name.
        # In Python variables, also country-equivalent.
        return ("rename_to_country", "country", "DB column / variable rename")

    # 4. Compound identifiers (theater_baselines, _theater_names, etc.)
    if "theater" in lower and not _is_user_facing(line_text):
        return ("rename_to_country", token.replace("theater", "country").replace("Theater", "Country"),
                "compound identifier")

    # 5. User-facing text (docstrings, prompts, comments)
    if _is_user_facing(line_text):
        return ("user_facing_text", "", "review prompt/comment manually — country or scenario?")

    return ("ambiguous", "", "no rule matched; manual review")


_USER_FACING_HINTS = (
    "you are", "respond with", "json", "narrative", "##", "#", "<!--",
    "prompt", "explanation", "description", "guide",
)


def _is_user_facing(line_text: str) -> bool:
    low = line_text.lower().strip()
    if low.startswith(("#", "//", "/*", "*", '"""', "'''")):
        return True
    return any(hint in low for hint in _USER_FACING_HINTS)


def discover() -> list[Occurrence]:
    """Walk repo, return classified occurrences."""
    found: list[Occurrence] = []
    for path in _walk_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "theater" not in text.lower():
            continue
        rel = str(path.relative_to(REPO_ROOT))
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in TOKEN_RE.finditer(line):
                token = match.group(0)
                classification, proposed, note = _classify(token, line, path)
                snippet = line.strip()[:120]
                found.append(Occurrence(
                    path=rel, line=lineno, col=match.start(),
                    snippet=snippet, matched=token,
                    classification=classification, proposed=proposed, note=note,
                ))
    return found


def write_manifest(occurrences: list[Occurrence]) -> None:
    payload = {
        "generated_for": "v2-migration ADR-V2-006",
        "total": len(occurrences),
        "by_classification": _summarize(occurrences),
        "occurrences": [o.__dict__ for o in occurrences],
    }
    MANIFEST_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False))


def _summarize(occs: list[Occurrence]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for o in occs:
        counts[o.classification] = counts.get(o.classification, 0) + 1
    return counts


def load_manifest() -> list[Occurrence]:
    if not MANIFEST_PATH.exists():
        sys.exit(f"manifest not found at {MANIFEST_PATH}; run `discover` first")
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return [Occurrence(**row) for row in payload["occurrences"]]


def cmd_discover() -> None:
    occs = discover()
    write_manifest(occs)
    print(f"Discovered {len(occs)} occurrences across "
          f"{len({o.path for o in occs})} files.")
    for cls, count in sorted(_summarize(occs).items(), key=lambda kv: -kv[1]):
        print(f"  {cls:30s} {count:>5d}")
    print(f"\nManifest written to {MANIFEST_PATH.relative_to(REPO_ROOT)}")
    print("Next: review AMBIGUOUS rows in the manifest, then run `diff`.")


def cmd_diff() -> None:
    occs = load_manifest()
    rewritable = [o for o in occs if o.proposed and o.classification != "keep_v1_api_param"]
    print(f"Would rewrite {len(rewritable)} of {len(occs)} occurrences.\n")
    by_file: dict[str, list[Occurrence]] = {}
    for o in rewritable:
        by_file.setdefault(o.path, []).append(o)
    for path, file_occs in sorted(by_file.items()):
        print(f"--- {path}  ({len(file_occs)} changes)")
        for o in file_occs[:5]:
            print(f"    L{o.line}: {o.matched} → {o.proposed}    [{o.classification}]")
        if len(file_occs) > 5:
            print(f"    ... and {len(file_occs) - 5} more")


def cmd_apply(force: bool) -> None:
    if not force:
        sys.exit("apply requires --i-have-a-clean-git-tree")
    if _git_dirty():
        sys.exit("working tree is dirty; commit or stash before applying")
    occs = load_manifest()
    rewritable = [o for o in occs if o.proposed and o.classification != "keep_v1_api_param"]
    edits_by_file: dict[str, list[Occurrence]] = {}
    for o in rewritable:
        edits_by_file.setdefault(o.path, []).append(o)

    for path, file_occs in edits_by_file.items():
        full = REPO_ROOT / path
        text = full.read_text(encoding="utf-8")
        # Apply per-line, per-column to avoid token-substring collisions.
        lines = text.splitlines(keepends=True)
        # Sort descending so column offsets remain valid.
        for o in sorted(file_occs, key=lambda x: (x.line, -x.col)):
            line = lines[o.line - 1]
            before = line[:o.col]
            after = line[o.col + len(o.matched):]
            lines[o.line - 1] = before + o.proposed + after
        full.write_text("".join(lines), encoding="utf-8")
        print(f"rewrote {len(file_occs):>4d} occurrences in {path}")
    print("\nDone. Review with `git diff`, then run pytest.")


def _git_dirty() -> bool:
    out = subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO_ROOT)
    return bool(out.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("discover", help="scan repo, write classification manifest")
    sub.add_parser("diff", help="show what apply would change")
    apply_p = sub.add_parser("apply", help="rewrite files in-place")
    apply_p.add_argument("--i-have-a-clean-git-tree", action="store_true", dest="force")

    args = parser.parse_args()
    if args.cmd == "discover":
        cmd_discover()
    elif args.cmd == "diff":
        cmd_diff()
    elif args.cmd == "apply":
        cmd_apply(args.force)


if __name__ == "__main__":
    main()
