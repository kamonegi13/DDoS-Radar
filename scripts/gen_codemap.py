"""Codemap generator — extract structural index from Python source.

For each target file, produce a one-page Markdown codemap listing:
  - Module-level docstring (1 line summary)
  - Top-level constants
  - Classes (with method list + line ranges)
  - Top-level functions (with signature + line ranges)
  - 1-line docstring summaries

Goal: a future Claude session can read the codemap (~30 lines, ~600 tokens)
instead of full-reading the source file (~1000 lines, ~30K tokens). This
addresses the context-budget findings in docs/design/v2-phase1-handoff.md
§コンテキスト消費の注意.

Usage:
    python scripts/gen_codemap.py             # regenerate all codemaps
    python scripts/gen_codemap.py --check     # CI mode: fail if stale
    python scripts/gen_codemap.py path/to.py  # single file

Outputs go to docs/CODEMAPS/<dotted.module.path>.md
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
CODEMAP_DIR = REPO_ROOT / "docs" / "CODEMAPS"

# Target files. Mirrors the "do not full-Read" list in
# docs/design/v2-phase1-handoff.md L138-152, plus the new conclusions/
# subpackage that we want navigable without full reads.
DEFAULT_TARGETS: tuple[str, ...] = (
    "radar/database.py",
    "radar/scoring.py",
    "radar/intel_queue.py",
    "radar/intel_auto_judge.py",
    "radar/diagnostics.py",
    "radar/engine.py",
    "radar/scenarios.py",
    "radar/llm_client.py",
    "radar/persistence.py",
    "radar/scheduler.py",
    "radar/config.py",
    "radar/routes/core.py",
    "radar/routes/analytics.py",
    "radar/routes/admin.py",
    "radar/routes/intel.py",
    "radar/routes/conclusions_v2.py",
    "radar/conclusions/base.py",
    "radar/conclusions/api.py",
    "radar/conclusions/persistence.py",
    "radar/conclusions/diff_sampler.py",
    "radar/conclusions/calibration.py",
    "radar/conclusions/trend.py",
    "radar/conclusions/per_domain.py",
    "radar/conclusions/attack_mode.py",
    "radar/conclusions/attack_mode_extensions.py",
    "radar/conclusions/threat_level.py",
    "radar/conclusions/anomaly.py",
    "radar/conclusions/shadow_metrics.py",
    "radar/conclusions/ground_truth_etl.py",
    "radar/sensors/acled.py",
)


@dataclass(frozen=True)
class FuncInfo:
    name: str
    line_start: int
    line_end: int
    signature: str
    summary: str  # first line of docstring, "" if absent


@dataclass(frozen=True)
class ClassInfo:
    name: str
    line_start: int
    line_end: int
    summary: str
    methods: tuple[FuncInfo, ...]


@dataclass(frozen=True)
class ModuleMap:
    rel_path: str
    line_count: int
    summary: str
    constants: tuple[str, ...]
    classes: tuple[ClassInfo, ...]
    functions: tuple[FuncInfo, ...]


def _first_line(docstring: str | None) -> str:
    if not docstring:
        return ""
    for line in docstring.strip().splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = []
    a = node.args
    posonly = list(a.posonlyargs)
    regular = list(a.args)
    for arg in posonly + regular:
        ann = ast.unparse(arg.annotation) if arg.annotation else ""
        args.append(f"{arg.arg}: {ann}" if ann else arg.arg)
    if a.vararg:
        args.append(f"*{a.vararg.arg}")
    elif a.kwonlyargs:
        args.append("*")
    for arg in a.kwonlyargs:
        ann = ast.unparse(arg.annotation) if arg.annotation else ""
        args.append(f"{arg.arg}: {ann}" if ann else arg.arg)
    if a.kwarg:
        args.append(f"**{a.kwarg.arg}")
    ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{prefix} {node.name}({', '.join(args)}){ret}"


def _func_info(node: ast.FunctionDef | ast.AsyncFunctionDef) -> FuncInfo:
    return FuncInfo(
        name=node.name,
        line_start=node.lineno,
        line_end=getattr(node, "end_lineno", node.lineno),
        signature=_signature(node),
        summary=_first_line(ast.get_docstring(node)),
    )


def _class_info(node: ast.ClassDef) -> ClassInfo:
    methods: list[FuncInfo] = []
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.append(_func_info(item))
    return ClassInfo(
        name=node.name,
        line_start=node.lineno,
        line_end=getattr(node, "end_lineno", node.lineno),
        summary=_first_line(ast.get_docstring(node)),
        methods=tuple(methods),
    )


def _constants(tree: ast.Module) -> tuple[str, ...]:
    out: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id.isupper():
                    out.append(tgt.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id.isupper():
                out.append(node.target.id)
    return tuple(out)


def parse_module(rel_path: str) -> ModuleMap:
    src_path = REPO_ROOT / rel_path
    source = src_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(src_path))

    classes: list[ClassInfo] = []
    functions: list[FuncInfo] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes.append(_class_info(node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(_func_info(node))

    return ModuleMap(
        rel_path=rel_path,
        line_count=len(source.splitlines()),
        summary=_first_line(ast.get_docstring(tree)),
        constants=_constants(tree),
        classes=tuple(classes),
        functions=tuple(functions),
    )


def render_codemap(mod: ModuleMap) -> str:
    lines: list[str] = []
    lines.append(f"# Codemap: `{mod.rel_path}`")
    lines.append("")
    lines.append(f"_Generated by `scripts/gen_codemap.py`. Do not hand-edit._")
    lines.append("")
    lines.append(f"- **Lines**: {mod.line_count}")
    if mod.summary:
        lines.append(f"- **Module purpose**: {mod.summary}")
    lines.append("")

    if mod.constants:
        lines.append("## Top-level constants")
        lines.append("")
        for name in mod.constants:
            lines.append(f"- `{name}`")
        lines.append("")

    if mod.classes:
        lines.append("## Classes")
        lines.append("")
        for cls in mod.classes:
            lines.append(f"### `{cls.name}` (L{cls.line_start}–{cls.line_end})")
            if cls.summary:
                lines.append(f"_{cls.summary}_")
            lines.append("")
            if cls.methods:
                lines.append("| Method | Lines | Summary |")
                lines.append("|--------|-------|---------|")
                for m in cls.methods:
                    summary = m.summary.replace("|", "\\|") if m.summary else ""
                    lines.append(f"| `{m.name}` | L{m.line_start}–{m.line_end} | {summary} |")
                lines.append("")

    if mod.functions:
        lines.append("## Top-level functions")
        lines.append("")
        lines.append("| Function | Lines | Summary |")
        lines.append("|----------|-------|---------|")
        for f in mod.functions:
            summary = f.summary.replace("|", "\\|") if f.summary else ""
            lines.append(f"| `{f.name}` | L{f.line_start}–{f.line_end} | {summary} |")
        lines.append("")

    if mod.functions or any(c.methods for c in mod.classes):
        lines.append("## Signatures")
        lines.append("")
        lines.append("```python")
        for cls in mod.classes:
            for m in cls.methods:
                lines.append(f"# L{m.line_start}  ({cls.name})")
                lines.append(m.signature)
        for f in mod.functions:
            lines.append(f"# L{f.line_start}")
            lines.append(f.signature)
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def codemap_path(rel_path: str) -> Path:
    dotted = rel_path.replace("/", ".").removesuffix(".py")
    return CODEMAP_DIR / f"{dotted}.md"


def write_codemap(rel_path: str) -> tuple[Path, str]:
    mod = parse_module(rel_path)
    body = render_codemap(mod)
    out = codemap_path(rel_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")
    return out, body


def render_index(targets: Iterable[str]) -> str:
    lines: list[str] = []
    lines.append("# CODEMAPS Index")
    lines.append("")
    lines.append("Per-file structural maps. **Read these instead of full-loading the source file.**")
    lines.append("")
    lines.append("Generated by `scripts/gen_codemap.py`. Run `python scripts/gen_codemap.py` after")
    lines.append("structural changes to keep maps in sync.")
    lines.append("")
    lines.append("| Source file | Codemap | Lines |")
    lines.append("|-------------|---------|-------|")
    for rel in targets:
        try:
            mod = parse_module(rel)
        except FileNotFoundError:
            continue
        cm = codemap_path(rel)
        rel_link = cm.relative_to(CODEMAP_DIR)
        lines.append(f"| `{rel}` | [{rel_link}]({rel_link}) | {mod.line_count} |")
    lines.append("")
    return "\n".join(lines)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Specific files to (re)generate")
    parser.add_argument("--check", action="store_true",
                        help="Exit non-zero if any codemap is stale (CI mode)")
    args = parser.parse_args(argv)

    targets = tuple(args.paths) if args.paths else DEFAULT_TARGETS

    if args.check:
        stale: list[str] = []
        for rel in targets:
            try:
                mod = parse_module(rel)
            except FileNotFoundError:
                continue
            expected = render_codemap(mod)
            existing = codemap_path(rel)
            if not existing.exists() or _hash(existing.read_text()) != _hash(expected):
                stale.append(rel)
        if stale:
            print("Stale codemaps detected. Run `python scripts/gen_codemap.py` to refresh:",
                  file=sys.stderr)
            for s in stale:
                print(f"  - {s}", file=sys.stderr)
            return 1
        print(f"OK: {len(targets)} codemaps up to date.")
        return 0

    written = 0
    for rel in targets:
        try:
            out, _ = write_codemap(rel)
        except FileNotFoundError:
            print(f"SKIP (missing): {rel}", file=sys.stderr)
            continue
        written += 1
        print(f"wrote {out.relative_to(REPO_ROOT)}")

    index_body = render_index(targets)
    (CODEMAP_DIR / "index.md").write_text(index_body, encoding="utf-8")
    print(f"wrote {(CODEMAP_DIR / 'index.md').relative_to(REPO_ROOT)}")
    print(f"\nGenerated {written} codemaps in {CODEMAP_DIR.relative_to(REPO_ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
