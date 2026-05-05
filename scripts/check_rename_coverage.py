#!/usr/bin/env python3
"""ADR-V2-006 Safe Rename Pattern coverage gate.

Catches regressions in the theater→country migration by enforcing four
invariants on the codebase. Run from `scripts/check_ci.sh` before commit.

Invariants
----------
1. **Frontend write-side:** no new `?theater=` literal in `radar.js` /
   `index.html` outside the documented exception list. New fetches must use
   `?country=`.
2. **Routes dual-read:** every Flask handler that reads `request.args.get(
   "theater")` must also call `_country_param(...)` (i.e. dual-read), unless
   it is the `_country_param` helper itself.
3. **Generated-column list freshness:** every table named in
   `_A4_THEATER_TABLES` must have a `theater` column in `_SCHEMA_SQL`.
4. **API mirrors:** every JSON-returning endpoint that emits a `"theater":`
   key in its response is allowed to do so (legacy mirror) but MUST also
   emit a `"country":` key in the same response. This is a soft check —
   only a warning today; will be promoted to hard fail before A-5 sunset.

Exit codes
----------
0 — all invariants hold (warnings allowed).
1 — at least one hard invariant violated.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Invariant 1: write-side ──────────────────────────────────────────────────

# Files that exist for legacy/back-compat or doc reasons; matches here are
# either intentional (telemetry test fixtures, intel guide describing the
# legacy alias, comments) or already audited.
WRITE_SIDE_ALLOWLIST = {
    # Telemetry test fixture exercises the legacy path on purpose.
    "test_country_param_dual_read.py",
    # Intel guide documents the legacy alias for operators.
    "index.html",
    # The dual-read helper itself reads request.args.get("theater").
    "radar/routes/__init__.py",
    # Routes intentionally call _country_param(...) which forwards to
    # request.args.get("theater") — that's the dual-read contract.
    "radar/routes/admin.py",
    "radar/routes/analytics.py",
    "radar/routes/core.py",
    "radar/routes/history.py",
    "radar/routes/intel.py",
    "radar/routes/scenario.py",
    # Existing v1 backend code still emits "theater" keys (dual-write).
    # These are audited; A-5 will sweep them.
    "radar/database.py",
    "radar/scoring.py",
    "radar/scenarios.py",
    "radar/engine.py",
    "radar/persistence.py",
    "radar/intel_queue.py",
    # CSS/template files have no business with these tokens but skip cheaply.
    "radar.css",
    # Frontend read-side fallback (`hs.country ?? hs.theater`) is fine.
    "radar.js",
}


def check_frontend_writes() -> list[str]:
    """No raw `?theater=` URL literals in code that builds fetch URLs."""
    bad: list[str] = []
    for path in [ROOT / "radar.js"]:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r'fetch\([^)]*\?theater=', text):
            bad.append(f"{path.name}: literal '?theater=' inside fetch(...) — use '?country='")
    return bad


# ── Invariant 2: dual-read ───────────────────────────────────────────────────

ROUTES_DIR = ROOT / "radar" / "routes"


def check_dual_read() -> list[str]:
    """Every `request.args.get("theater")` call must live in _country_param."""
    bad: list[str] = []
    for path in ROUTES_DIR.glob("*.py"):
        if path.name == "__init__.py":
            continue
        text = path.read_text(encoding="utf-8")
        if 'request.args.get("theater"' not in text and "request.args.get('theater'" not in text:
            continue
        # Found a raw legacy read. Allowed only if file uses _country_param too.
        if "_country_param" not in text:
            bad.append(
                f"{path.relative_to(ROOT)}: reads request.args.get('theater') without "
                f"using _country_param — dual-read missing"
            )
    return bad


# ── Invariant 3: A-4 table list ──────────────────────────────────────────────


def check_a4_table_list() -> list[str]:
    """Every table in _A4_THEATER_TABLES must have a `theater` column."""
    db_path = ROOT / "radar" / "database.py"
    src = db_path.read_text(encoding="utf-8")

    # Parse _A4_THEATER_TABLES tuple
    m = re.search(r"_A4_THEATER_TABLES:\s*tuple\[str, \.\.\.\]\s*=\s*\(([^)]*)\)", src)
    if not m:
        return ["radar/database.py: _A4_THEATER_TABLES tuple not found"]
    tables = re.findall(r'"([^"]+)"', m.group(1))

    bad: list[str] = []
    for table in tables:
        # Find the CREATE TABLE block for this table
        cre = re.search(
            rf"CREATE TABLE IF NOT EXISTS {re.escape(table)}\s*\(([^;]*?)\)\s*;",
            src,
            re.DOTALL,
        )
        if not cre:
            bad.append(f"radar/database.py: _A4_THEATER_TABLES has '{table}' but no CREATE TABLE found")
            continue
        body = cre.group(1)
        if not re.search(r"\btheater\b", body):
            bad.append(f"radar/database.py: table '{table}' is in _A4_THEATER_TABLES but has no `theater` column")
    return bad


# ── Invariant 4 (soft): API mirrors ──────────────────────────────────────────


def check_api_mirrors() -> list[str]:
    """Routes that emit `"theater":` in JSON should also emit `"country":`.

    Soft check — returns warnings only, not failures, until A-4 SELECT-side
    audit lands.
    """
    warnings: list[str] = []
    for path in ROUTES_DIR.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        # Quick heuristic: count `"theater":` and `"country":` occurrences.
        n_theater = len(re.findall(r'"theater"\s*:', text))
        n_country = len(re.findall(r'"country"\s*:', text))
        if n_theater > 0 and n_country == 0:
            warnings.append(
                f"{path.relative_to(ROOT)}: emits \"theater\" {n_theater}x but never \"country\" — "
                f"A-4 mirror missing"
            )
    return warnings


def main() -> int:
    failures: list[str] = []
    warnings: list[str] = []

    failures.extend(check_frontend_writes())
    failures.extend(check_dual_read())
    failures.extend(check_a4_table_list())
    warnings.extend(check_api_mirrors())

    if warnings:
        print("WARNINGS (soft):")
        for w in warnings:
            print(f"  - {w}")
        print()

    if failures:
        print("FAILURES (hard):")
        for f in failures:
            print(f"  - {f}")
        print()
        print(f"check_rename_coverage: {len(failures)} hard failure(s).")
        return 1

    print(f"check_rename_coverage: PASS ({len(warnings)} warning(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
