#!/usr/bin/env python3
"""K-kernel discipline gate (WP-2.1).

The kernel's guarantees are enforced by the types at runtime. Two of them
are also cheap to check statically, and both are properties a reviewer
cannot reliably eyeball:

  1. **No direct environment reads anywhere under v3/.** Threshold is the
     only sanctioned path to a configured value, and `os.getenv` is
     exactly how 95 of 98 registered keys ended up unread (G-15).

  2. **No module-scope import of the legacy application.** Importing any
     `radar.*` module runs radar/__init__.py, which boots the Flask app
     and spawns ~30 sensor threads. The kernel's one permitted legacy
     dependency (config_layered, for Threshold.registry_backed) must stay
     inside a function so it is paid only on resolution.

A third rule is heuristic and reported as such: flagging `int(...)` /
`float(...)` applied to something named like a threat level, and direct
ordering comparisons between such names. ThreatLevel already raises on
all of these at runtime; the static pass only catches them earlier, and
only when the naming cooperates.

Usage:  python scripts/check_kernel_discipline.py [path ...]
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ROOTS = ("v3",)

# Canonical origins, resolved through each file's own import bindings —
# literal-name matching was bypassable by `import os as env_mod`,
# `from os import environ` and `from os import getenv as x` alike.
_CANON_GETENV = "os.getenv"
_CANON_ENVIRON = "os.environ"
# Names that suggest a threat level / a unit-bearing value. Heuristic:
# these rules depend on naming, and the runtime types enforce the same
# contracts regardless.
_TL_HINTS = ("threat_level", "_tl", "tl_", "threatlevel")
_UNIT_HINTS = ("ratio", "percent", "pct", "threshold")
# The test-only injection seam on Threshold.resolve / exceeded_by.
_SEAM_KWARG = "resolver"
_TEST_PATH_MARKERS = ("tests/", "test_")
# The module that DEFINES the seam forwards it internally
# (exceeded_by -> resolve); flagging that would be flagging the contract.
_SEAM_OWNER = "v3/kernel/threshold.py"
# The blessed comparison idioms — never flag these.
_SAFE_SUFFIXES = (".severity", ".severity_key")


class Finding:
    __slots__ = ("path", "line", "rule", "message")

    def __init__(self, path: str, line: int, rule: str, message: str):
        self.path, self.line, self.rule, self.message = path, line, rule, message

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.message}"


def _looks_like_threat_level(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _TL_HINTS)


def _looks_like_unit(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _UNIT_HINTS)


def _name_of(node: ast.AST) -> str:
    """Dotted name for a reference, base included.

    Returning only `node.attr` made every `x.value` look identical, so
    `tl_a.value > tl_b.value` — which reintroduces the inversion in full —
    was invisible to the heuristics below.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    return ""


def _import_bindings(tree: ast.Module) -> dict:
    """{local name -> dotted origin} for every import in the file."""
    bindings: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    bindings[head] = head
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                bindings[local] = (f"{module}.{alias.name}" if module
                                   else alias.name)
    return bindings


def _resolve(dotted: str, bindings: dict):
    if not dotted:
        return None
    head, _, rest = dotted.partition(".")
    base = bindings.get(head)
    if base is None:
        return None
    return f"{base}.{rest}" if rest else base


class _KernelVisitor(ast.NodeVisitor):
    """Collects violations for one module."""

    def __init__(self, rel_path: str, bindings: dict):
        self.rel_path = rel_path
        self.bindings = bindings
        self.findings: list[Finding] = []
        self._function_depth = 0
        self.is_test_path = any(marker in rel_path
                                for marker in _TEST_PATH_MARKERS)
        self.is_seam_owner = rel_path.endswith(_SEAM_OWNER)

    # ── module-scope legacy imports ────────────────────────────────────
    def visit_FunctionDef(self, node):  # noqa: N802
        self._function_depth += 1
        self.generic_visit(node)
        self._function_depth -= 1

    visit_AsyncFunctionDef = visit_FunctionDef

    def _check_legacy_import(self, module: str, node: ast.AST) -> None:
        if not module or not (module == "radar" or module.startswith("radar.")):
            return
        if self._function_depth == 0:
            self.findings.append(Finding(
                self.rel_path, node.lineno, "legacy-import-at-module-scope",
                f"module-scope import of {module!r}: importing radar.* boots "
                f"the legacy application (Flask app, migrations, ~30 sensor "
                f"threads). Move it inside the function that needs it."))

    def visit_Import(self, node):  # noqa: N802
        for alias in node.names:
            self._check_legacy_import(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):  # noqa: N802
        self._check_legacy_import(node.module or "", node)
        self.generic_visit(node)

    # ── environment reads ──────────────────────────────────────────────
    def visit_Call(self, node):  # noqa: N802
        callee = _name_of(node.func)
        resolved = _resolve(callee, self.bindings)
        if resolved in (_CANON_GETENV, f"{_CANON_ENVIRON}.get",
                        f"{_CANON_ENVIRON}.setdefault"):
            self.findings.append(Finding(
                self.rel_path, node.lineno, "direct-env-read",
                f"{callee}() resolves to {resolved} — not a configuration "
                f"path in v3: use "
                f"Threshold.registry_backed(key) for an operationally "
                f"variable value, or Threshold.pinned(value, "
                f"provenance_ref=...) for a constant (P6 O-18)."))
        if not self.is_test_path and not self.is_seam_owner and any(
                kw.arg == _SEAM_KWARG for kw in node.keywords):
            self.findings.append(Finding(
                self.rel_path, node.lineno, "test-only-seam",
                f"{_SEAM_KWARG}= is a test-only injection point on "
                f"Threshold.resolve()/exceeded_by(). In production it is a "
                f"private configuration path, which is the G-15 shape — "
                f"leave it unset so the real 3-layer chain answers."))
        if callee in ("int", "float") and node.args:
            argument = _name_of(node.args[0])
            if argument and _looks_like_threat_level(argument):
                self.findings.append(Finding(
                    self.rel_path, node.lineno, "threat-level-coercion",
                    f"{callee}({argument}) would strip a ThreatLevel down to "
                    f"a comparable number — the shape of calibration "
                    f"incident #2. Use .severity()."))
        self.generic_visit(node)

    def visit_Subscript(self, node):  # noqa: N802
        if _resolve(_name_of(node.value), self.bindings) == _CANON_ENVIRON:
            self.findings.append(Finding(
                self.rel_path, node.lineno, "direct-env-read",
                "os.environ[...] is not a configuration path in v3; use "
                "Threshold (P6 O-18)."))
        self.generic_visit(node)

    def visit_Attribute(self, node):  # noqa: N802
        if _resolve(_name_of(node), self.bindings) == _CANON_ENVIRON:
            self.findings.append(Finding(
                self.rel_path, node.lineno, "direct-env-read",
                "os.environ access is not a configuration path in v3; use "
                "Threshold (P6 O-18)."))
        self.generic_visit(node)

    # ── threat-level ordering (heuristic) ──────────────────────────────
    def visit_Compare(self, node):  # noqa: N802
        ordering = {ast.Lt, ast.LtE, ast.Gt, ast.GtE}
        if any(type(op) in ordering for op in node.ops):
            names = [_name_of(node.left)] + [_name_of(c) for c in node.comparators]
            # severity() IS the sanctioned way to order threat levels.
            if any(name.endswith(_SAFE_SUFFIXES) for name in names):
                self.generic_visit(node)
                return
            if any(name and _looks_like_threat_level(name) for name in names):
                self.findings.append(Finding(
                    self.rel_path, node.lineno, "threat-level-ordering",
                    "ordering comparison on something named like a threat "
                    "level: the scale is inverted (TL1 = CRITICAL), so this "
                    "reads backwards. Compare .severity() instead."))
            elif any(name.endswith(".value") and _looks_like_unit(name)
                     for name in names):
                self.findings.append(Finding(
                    self.rel_path, node.lineno, "unit-value-comparison",
                    "comparing .value on a unit-bearing name strips the "
                    "unit and recreates F-08 (a ratio measured against a "
                    "percentage). Compare the typed values themselves, or "
                    "use Threshold.exceeded_by()."))
        self.generic_visit(node)


def scan_source(source: str, rel_path: str) -> list[Finding]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [Finding(rel_path, exc.lineno or 0, "syntax-error", str(exc))]
    visitor = _KernelVisitor(rel_path, _import_bindings(tree))
    visitor.visit(tree)
    return visitor.findings


def scan_paths(roots) -> list[Finding]:
    findings: list[Finding] = []
    for root in roots:
        base = Path(root)
        if not base.is_absolute():
            base = _REPO_ROOT / base
        if not base.exists():
            continue
        files = [base] if base.is_file() else sorted(base.rglob("*.py"))
        for path in files:
            if "__pycache__" in path.parts:
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                findings.append(Finding(str(path), 0, "unreadable", str(exc)))
                continue
            rel = path.relative_to(_REPO_ROOT).as_posix() \
                if path.is_relative_to(_REPO_ROOT) else str(path)
            findings.extend(scan_source(source, rel))
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=None,
                        help="paths to scan (default: v3/)")
    args = parser.parse_args(argv)

    roots = args.paths or list(_DEFAULT_ROOTS)
    findings = scan_paths(roots)
    scanned = ", ".join(roots)
    if not findings:
        print(f"kernel discipline OK — {scanned} clean")
        return 0

    print(f"kernel discipline violations in {scanned}:", file=sys.stderr)
    for finding in findings:
        print(f"  - {finding}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
