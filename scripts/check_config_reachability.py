#!/usr/bin/env python3
"""Config reachability regression gate (WP-1.2 / S5-VERIF-013).

Runs the static half of the reachability audit
(``radar.verification.config_static_audit``) and compares the per-key
classification against a checked-in baseline. It fails only on
*regression*:

  * a newly registered key that does not resolve through ``get_config()``;
  * an existing key whose class got worse (FULL -> PARTIAL -> DEAD ->
    BYPASSED);
  * a new registry-vs-hardcoded default mismatch.

Improvements — keys routed back through the resolution chain, mismatches
removed — pass, and are printed so the baseline can be refreshed
deliberately with ``--update-baseline``.

This gate is deliberately NOT the whole check. P3:156 is explicit that a
static CI gate alone is insufficient, because the 71 import-time frozen
constants and the "registered but never read" direction only show up at
runtime; that half runs daily inside the app and surfaces through
``/api/v2/self_eval`` -> ``config_reachability``. This script exists so a
*new* bypass cannot be merged silently in the meantime.

Usage:
    python scripts/check_config_reachability.py                # check
    python scripts/check_config_reachability.py --update-baseline
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import types
from pathlib import Path
from typing import Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parent.parent

BASELINE_PATH = _REPO_ROOT / "docs" / "baselines" / "config_reachability_baseline.json"

# Higher = worse. A key may only move down this ladder deliberately.
_SEVERITY = {
    "FULL_RESOLUTION": 0,
    "PARTIAL": 1,
    "DEAD": 2,
    "BYPASSED": 3,
}


def _load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_audit_module():
    """Load the audit module WITHOUT importing the radar package.

    `import radar` executes radar/__init__.py, which migrates and writes the
    production SQLite file and starts ~30 sensor threads that reach out over
    the network. A gate that runs as a pre-commit hook must do none of that,
    so the two modules it needs — both pure at import time — are loaded from
    their files under a stub package. Inside an already-booted process
    (the test suite) the real modules are reused instead.
    """
    if "radar" in sys.modules:
        from radar.verification import config_static_audit as csa
        return csa

    stub = types.ModuleType("radar")
    stub.__path__ = [str(_REPO_ROOT / "radar")]
    sys.modules["radar"] = stub
    stub.config_layered = _load_file(
        "radar.config_layered", _REPO_ROOT / "radar" / "config_layered.py")
    verification = types.ModuleType("radar.verification")
    verification.__path__ = [str(_REPO_ROOT / "radar" / "verification")]
    sys.modules["radar.verification"] = verification
    return _load_file(
        "radar.verification.config_static_audit",
        _REPO_ROOT / "radar" / "verification" / "config_static_audit.py")


def build_snapshot() -> dict:
    """Classify the repository from source alone — no application boot."""
    csa = _load_audit_module()
    csa.clear_cache()
    result = csa.audit(keys=csa.registry_from_ast())
    return {
        "registered_total": result.registered_total,
        "counts": dict(result.counts),
        "classes": {key: cls.verdict for key, cls in sorted(result.keys.items())},
        "default_mismatches": {m.key: m.site
                               for m in result.default_mismatches},
        "unregistered_resolution_reads": sorted(
            result.unregistered_resolution_reads),
    }


def _severity(verdict: str) -> int:
    return _SEVERITY.get(verdict, max(_SEVERITY.values()))


def compare_baseline(baseline: dict, current: dict
                     ) -> tuple[list[str], list[str]]:
    """(regressions, improvements) between two snapshots. Pure."""
    base_classes = baseline.get("classes", {})
    cur_classes = current.get("classes", {})
    regressions: list[str] = []
    improvements: list[str] = []

    for key, verdict in sorted(cur_classes.items()):
        was = base_classes.get(key)
        if was is None:
            if _severity(verdict) > _SEVERITY["FULL_RESOLUTION"]:
                regressions.append(
                    f"new key {key} does not resolve through get_config "
                    f"({verdict}) — route it through the registry chain")
            continue
        if _severity(verdict) > _severity(was):
            regressions.append(f"{key}: {was} -> {verdict}")
        elif _severity(verdict) < _severity(was):
            improvements.append(f"{key}: {was} -> {verdict}")

    base_mismatch = set(baseline.get("default_mismatches", {}))
    cur_mismatch = set(current.get("default_mismatches", {}))
    for key in sorted(cur_mismatch - base_mismatch):
        regressions.append(
            f"{key}: hardcoded default now contradicts the registry "
            f"({current['default_mismatches'][key]})")
    for key in sorted(base_mismatch - cur_mismatch):
        improvements.append(f"{key}: default mismatch resolved")

    for key in sorted(set(base_classes) - set(cur_classes)):
        improvements.append(f"{key}: no longer registered")
    return (regressions, improvements)


def _write_baseline(snapshot: dict) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update-baseline", action="store_true",
                        help="snapshot the current classification and exit 0")
    args = parser.parse_args(argv)

    snapshot = build_snapshot()
    if args.update_baseline:
        _write_baseline(snapshot)
        print(f"baseline written: {BASELINE_PATH.relative_to(_REPO_ROOT)} "
              f"({snapshot['registered_total']} keys)")
        return 0

    if not BASELINE_PATH.exists():
        print("WARN: no config reachability baseline yet — run with "
              "--update-baseline. Skipping (bootstrap mode).")
        return 0

    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    regressions, improvements = compare_baseline(baseline, snapshot)

    counts = snapshot["counts"]
    print(f"config reachability: {snapshot['registered_total']} registered — "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for line in improvements:
        print(f"  improved: {line}")
    if not regressions:
        return 0
    print("\nconfig reachability REGRESSION:", file=sys.stderr)
    for line in regressions:
        print(f"  - {line}", file=sys.stderr)
    print("\nRegistered keys must be read through get_config() so a SETTINGS "
          "edit reaches the running system (S5-VERIF-013). If the change is "
          "deliberate, refresh with --update-baseline.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
