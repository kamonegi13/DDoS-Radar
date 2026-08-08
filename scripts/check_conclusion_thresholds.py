#!/usr/bin/env python3
"""Compare v3/conclusions' pinned thresholds against production, by AST.

WP-2.6's sweep found 97 transcription infidelities across 22 adapters, and
every one of them was in a value that looked correctly copied. WP-2.7's
during-the-port checks found ~30 more, four of them in code shipped
earlier in the same package. The lesson recorded there is that an S1
citation line is a LEAD, not a source: the module constant is the source,
and the only reliable way to read it is to parse it.

So this gate reads `radar/conclusions/*.py` with `ast.literal_eval` and
compares each constant against the pinned value in
`v3/conclusions/thresholds.py`. It runs in CI, which means a later edit to
either side has to explain itself.

A constant that is deliberately different is declared in `EXPECTED_DIFFS`
with its registration reference, so "we changed this on purpose" and "we
mistyped this" cannot look the same (P2 §5-C: revert or register, never
silent).

Usage:
    python scripts/check_conclusion_thresholds.py          # gate
    python scripts/check_conclusion_thresholds.py --report # show all
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PRODUCTION = REPO_ROOT / "radar" / "conclusions"

# v3 pinned name -> (production module, production constant)
MAPPING: dict[str, tuple[str, str]] = {
    "TL_CONFIDENCE_DENOM": ("threat_level", "_CONFIDENCE_DENOM"),
    "TL_LITE_CONFIDENCE_FACTOR": ("threat_level", "_LITE_CONFIDENCE_FACTOR"),
    "TREND_RISING_DELTA": ("trend", "RISING_DELTA"),
    "TREND_ESCALATE_DELTA": ("trend", "ESCALATE_DELTA"),
    "TREND_MIN_SAMPLES": ("trend", "MIN_SAMPLES"),
    "DOMAIN_ACTIVE_FLOOR": ("per_domain", "ACTIVE_FLOOR"),
    "DOMAIN_ELEVATED_FLOOR": ("per_domain", "ELEVATED_FLOOR"),
    "DOMAIN_DEGRADE_DELTA": ("per_domain", "DEGRADE_DELTA"),
    "ANOMALY_DEFAULT_LIMIT": ("anomaly", "DEFAULT_LIMIT"),
    "ANOMALY_MAX_IMPORTANCE": ("anomaly", "_MAX_IMPORTANCE"),
    "ANOMALY_RECENCY_TIME_CONSTANT_H": ("anomaly",
                                        "_RECENCY_TIME_CONSTANT_HOURS"),
    "ANOMALY_NOVELTY_WINDOW_COUNT": ("anomaly", "_NOVELTY_WINDOW"),
    "ANOMALY_NOVELTY_FLOOR": ("anomaly", "_NOVELTY_FLOOR"),
    "ATTACK_CYBER_DDOS_FLOOR": ("attack_mode", "CYBER_DDOS_FLOOR"),
    "ATTACK_INFO_NARRATIVE_FLOOR": ("attack_mode", "INFO_NARRATIVE_FLOOR"),
    "ATTACK_PHYSICAL_KINETIC_FLOOR": ("attack_mode",
                                      "PHYSICAL_KINETIC_FLOOR"),
    "ATTACK_ALL_DOMAIN_HYBRID_FLOOR": ("attack_mode",
                                       "ALL_DOMAIN_HYBRID_FLOOR"),
    "ATTACK_HYBRID_CLUSTER_MIN": ("attack_mode", "HYBRID_INTEL_CLUSTER_MIN"),
    "ATTACK_INFO_DOMINANCE_RATIO": ("attack_mode", "INFO_DOMINANCE_RATIO"),
    "ATTACK_CONFIDENCE_CEILING": ("attack_mode_extensions",
                                  "_EXT_CONFIDENCE_CEIL"),
    "ATTACK_MARGIN_BASE_CONFIDENCE": ("attack_mode_extensions",
                                      "_EXT_CONFIDENCE_FLOOR"),
}

# Values v3 deliberately does not take from production.
EXPECTED_DIFFS: dict[str, str] = {}

# Pinned names this gate CANNOT reach, each with the reason. Production
# keeps these as inline literals inside a function body rather than as a
# module constant, so `ast.literal_eval` on a module-scope assignment
# finds nothing to compare against.
#
# This list exists because a gate that reports "21 checked, 0 differences"
# and says nothing about the other 18 reads as coverage. Every name here
# was hand-verified against the cited expression; the completeness check
# below then makes it impossible to add a pinned threshold and quietly
# leave it out of both lists.
STRUCTURALLY_UNMAPPABLE: dict[str, str] = {
    "TREND_CONFIDENCE_CEILING":
        "trend.py:_confidence_from_samples — inline min(0.95, base)",
    "TREND_CONFIDENCE_PER_WINDOW_CAP":
        "trend.py:_confidence_from_samples — inline min(0.30, ...)",
    "TREND_CONFIDENCE_PER_WINDOW_BASE":
        "trend.py:_confidence_from_samples — inline 0.15 + n*0.01",
    "TREND_CONFIDENCE_PER_SAMPLE":
        "trend.py:_confidence_from_samples — inline n * 0.01",
    "TREND_PARTIAL_PENALTY":
        "trend.py:_confidence_from_samples — inline base - 0.15",
    "DOMAIN_MAGNITUDE_DENOM":
        "per_domain.py:_confidence — inline sum(...) / 12.0",
    "ANOMALY_NOVELTY_LOOKBACK_SEC":
        "anomaly.py:_NOVELTY_LOOKBACK_SEC is `24 * 3600`, a BinOp rather "
        "than a literal, so literal_eval declines it",
    "ATTACK_TENTATIVE_CONFIDENCE":
        "attack_mode.py:derive_attack_mode — inline top.confidence < 0.6",
    "ATTACK_MARGIN_SPAN":
        "attack_mode.py:_apply_rules — inline 0.55 + 0.4 * margin",
    "ATTACK_HYBRID_BASE_CONFIDENCE":
        "attack_mode.py:_apply_rules — inline 0.50 + ...",
    "ATTACK_HYBRID_PER_COUNTRY":
        "attack_mode.py:_apply_rules — inline 0.05 * active_n",
    "ATTACK_HYBRID_PER_DOMAIN_SUM":
        "attack_mode.py:_apply_rules — inline 0.02 * sum_d",
    "ATTACK_INFO_DOMINANCE_SCALE":
        "attack_mode.py:_apply_rules — inline 0.10 * (info / ...)",
    "ATTACK_INFO_DOMINANCE_EPSILON":
        "attack_mode.py:_apply_rules — inline max(other_max, 0.1)",
    "ATTACK_PURE_INFO_CONFIDENCE":
        "attack_mode.py:_apply_rules — inline _ModeMatch(..., 0.65, ...)",
    # Guard thresholds: v3 has no production counterpart by design.
    "UPSTREAM_FAILURE_RATIO":
        "no production counterpart — F-12's generation paths are new",
    "SENSOR_DEGRADED_RATIO":
        "no production counterpart — F-12's generation paths are new",
    "CALIBRATION_MIN_HISTORY_DAYS":
        "no production counterpart — F-12's generation paths are new",
}


def unaccounted_pins() -> list:
    """Pinned names in neither list. Always empty, or the gate fails."""
    from v3.conclusions.thresholds import _PINNED

    return sorted(set(_PINNED) - set(MAPPING) - set(STRUCTURALLY_UNMAPPABLE))


def _module_constants(module: str) -> dict:
    """Every module-scope literal assignment in a production module."""
    path = PRODUCTION / f"{module}.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: dict = {}
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and \
                isinstance(node.target, ast.Name) and node.value is not None:
            targets = [node.target.id]
        if not targets:
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError):
            continue
        for name in targets:
            found[name] = value
    return found


def compare() -> list[dict]:
    from v3.conclusions import thresholds as T

    cache: dict[str, dict] = {}
    findings: list[dict] = []
    for pinned_name, (module, constant) in sorted(MAPPING.items()):
        if module not in cache:
            cache[module] = _module_constants(module)
        production = cache[module].get(constant, "<missing>")
        ours = getattr(T, pinned_name, "<missing>")
        matches = (production == ours)
        findings.append({
            "v3": pinned_name, "production": f"{module}.{constant}",
            "v3_value": ours, "production_value": production,
            "matches": matches,
            "registered": EXPECTED_DIFFS.get(pinned_name),
        })
    return findings


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true",
                        help="print every comparison, not only failures")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(REPO_ROOT))
    findings = compare()
    failures = [f for f in findings
                if not f["matches"] and not f["registered"]]

    if args.report:
        for finding in findings:
            mark = "ok " if finding["matches"] else (
                "REG" if finding["registered"] else "DIFF")
            print(f"  [{mark}] {finding['v3']:<34} "
                  f"v3={finding['v3_value']!r:<10} "
                  f"prod={finding['production_value']!r} "
                  f"({finding['production']})")

    orphans = unaccounted_pins()
    if orphans:
        print(f"\n{len(orphans)} pinned threshold(s) are in neither MAPPING "
              f"nor STRUCTURALLY_UNMAPPABLE: {orphans}.\nA gate that is "
              f"silent about what it cannot see reads as coverage. Map it "
              f"to its production constant, or record WHY it cannot be "
              f"mapped.", file=sys.stderr)
        return 1

    if failures:
        print(f"\n{len(failures)} conclusion threshold(s) differ from "
              f"production with no registered reason:", file=sys.stderr)
        for finding in failures:
            print(f"  {finding['v3']}: v3={finding['v3_value']!r} "
                  f"production={finding['production_value']!r} "
                  f"({finding['production']})", file=sys.stderr)
        print("\nEither correct the value or register the difference in "
              "docs/design/v3/wp25-l0-adapter-design.md §7-2 and add it to "
              "EXPECTED_DIFFS here.", file=sys.stderr)
        return 1

    print(f"conclusion thresholds: {len(findings)} checked against "
          f"production by AST, {len(STRUCTURALLY_UNMAPPABLE)} unmappable "
          f"with a stated reason, {len(EXPECTED_DIFFS)} registered "
          f"difference(s) — 0 unaccounted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
