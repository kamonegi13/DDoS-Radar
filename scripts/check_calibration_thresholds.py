#!/usr/bin/env python3
"""Compare v3/calibration's pinned thresholds against production, by AST.

The sibling of `check_conclusion_thresholds.py`, for the layer where a
silent numeric drift does the most damage. WP-2.6's sweep found 97
transcription infidelities in values that looked correctly copied; WP-3.1
found more inside code shipped earlier in its own package. The lesson is
the same one: an S1 citation line is a LEAD, and the module is the source.

Calibration keeps most of its numbers as `os.getenv(KEY, "default")` calls
inside function bodies rather than as module constants, so this gate reads
three shapes rather than one:

    constant   a module-level literal assignment
    dictkey    a key of a module-level dict literal
    envdefault the default argument of an os.getenv call anywhere in the
               module — the shape S1-calibration §3 records for most of
               this layer

A value v3 deliberately does not take from production is declared in
EXPECTED_DIFFS with its registration reference, so "changed on purpose"
and "mistyped" cannot look the same (P2 §5-C: revert or register).

Usage:
    python scripts/check_calibration_thresholds.py            # gate
    python scripts/check_calibration_thresholds.py --report   # show all
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

CONSTANT = "constant"
DICTKEY = "dictkey"
ENVDEFAULT = "envdefault"

# v3 pinned name -> (module path, locator, kind)
MAPPING: dict = {
    # ── ground truth ────────────────────────────────────────────────────
    "GT_ALERT_SEVERITY_MIN": ("radar/conclusions/ground_truth_etl.py",
                              "_ALERT_SEVERITY_MIN", CONSTANT),
    "GT_NOTE_TRUNCATE": ("radar/conclusions/ground_truth_etl.py",
                         "_NOTE_TRUNCATE", CONSTANT),
    "SEVERITY_FLOOR_MASS_CASUALTY": (
        "radar/conclusions/ground_truth_etl.py",
        "EXPECTED_SEVERITY_MASS_CASUALTY", CONSTANT),
    "SEVERITY_FLOOR_KINETIC": ("radar/conclusions/ground_truth_etl.py",
                               "EXPECTED_SEVERITY_KINETIC", CONSTANT),
    "SEVERITY_FLOOR_ESCALATION": ("radar/conclusions/ground_truth_etl.py",
                                  "EXPECTED_SEVERITY_ESCALATION", CONSTANT),
    "GT_FORWARD_WINDOW_H": ("radar/config.py", "GROUND_TRUTH_WINDOW_HOURS",
                            ENVDEFAULT),
    "GT_FP_TN_HORIZON_D": ("radar/config.py",
                           "GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS",
                           ENVDEFAULT),
    "GT_FN_FATALITIES": ("radar/config.py",
                         "GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES",
                         ENVDEFAULT),

    # ── recall metrics / calibration status ─────────────────────────────
    "MIN_RECALL_DENOM": ("radar/conclusions/calibration.py",
                         "_MIN_RECALL_SAMPLES", CONSTANT),
    "DEGRADED_RECALL_FLOOR": ("radar/conclusions/calibration.py",
                              "_DEGRADED_RECALL_THRESHOLD", CONSTANT),
    "CALIBRATION_CACHE_TTL_SEC": ("radar/conclusions/calibration.py",
                                  "_CACHE_TTL_SEC", CONSTANT),

    # ── TL threshold calibrator ─────────────────────────────────────────
    "TL_CALIB_MIN_FEEDBACK": ("radar/calibration/tl_threshold_calibrator.py",
                              "TL_CALIB_MIN_FEEDBACK_PER_CELL", ENVDEFAULT),
    "TL_CALIB_RECALL_FLOOR": ("radar/calibration/tl_threshold_calibrator.py",
                              "TL_CALIB_RECALL_FLOOR", ENVDEFAULT),
    "TL_CALIB_PRECISION_CEILING": (
        "radar/calibration/tl_threshold_calibrator.py",
        "TL_CALIB_PRECISION_CEILING", ENVDEFAULT),
    "TL_CALIB_PRECISION_MIN_FLOOR": (
        "radar/calibration/tl_threshold_calibrator.py",
        "TL_CALIB_PRECISION_MIN_FLOOR", ENVDEFAULT),

    # ── tier governor ───────────────────────────────────────────────────
    "TIER_PROMOTE_0_TO_1_ROWS": (
        "radar/calibration/auto_apply_tier_governor.py",
        "PROMOTE_TIER0_TO_TIER1.min_auto_feedback_rows", DICTKEY),
    "TIER_PROMOTE_1_TO_2_DAYS": (
        "radar/calibration/auto_apply_tier_governor.py",
        "PROMOTE_TIER1_TO_TIER2.min_days_at_tier", DICTKEY),
    "TIER_PROMOTE_2_TO_3_DAYS": (
        "radar/calibration/auto_apply_tier_governor.py",
        "PROMOTE_TIER2_TO_TIER3.min_days_at_tier", DICTKEY),
    "TIER_PROMOTE_MAX_REVERT_RATE": (
        "radar/calibration/auto_apply_tier_governor.py",
        "PROMOTE_TIER1_TO_TIER2.max_revert_rate", DICTKEY),
    "TIER_DEMOTE_REVERT_RATE_24H": (
        "radar/calibration/auto_apply_tier_governor.py",
        "DEMOTE_TIER1_TO_TIER0.max_revert_rate_24h", DICTKEY),
    "TIER_CONSECUTIVE_FAILURE_LIMIT": (
        "radar/calibration/auto_apply_tier_governor.py",
        "CONSECUTIVE_FAILURE_LIMIT", CONSTANT),
    "HIGH_COOLDOWN_HOURS": (
        "radar/calibration/auto_apply_tier_governor.py",
        "HIGH_COOLDOWN_HOURS_DEFAULT", CONSTANT),
    "TIER_CAP": ("radar/calibration/auto_apply_tier_governor.py",
                 "TIER_FULL", CONSTANT),

    # ── proposal issue path ─────────────────────────────────────────────
    "PROPOSAL_DEDUP_WINDOW_D": ("radar/calibration/scenario_improver.py",
                                "SCENARIO_IMPROVER_DEDUP_DAYS", ENVDEFAULT),
    "PROPOSAL_MAX_PENDING": ("radar/calibration/scenario_improver.py",
                             "SCENARIO_IMPROVER_MAX_ACTIVE", ENVDEFAULT),
    "WEIGHT_STEP_IMPROVER": ("radar/calibration/scenario_improver.py",
                             "SCENARIO_IMPROVER_WEIGHT_STEP", ENVDEFAULT),
    "MISSING_PARTICIPANT_EVENT_N": (
        "radar/calibration/scenario_improver.py",
        "SCENARIO_IMPROVER_MISSING_EVENT_N", ENVDEFAULT),
    "VITALITY_SIGNAL_FLOOR": ("radar/calibration/_proposal_guards.py",
                              "PROPOSAL_GUARDS_SCENARIO_DORMANT_FLOOR",
                              ENVDEFAULT),
    "VITALITY_MIN_COVERAGE": ("radar/calibration/_proposal_guards.py",
                              "PROPOSAL_GUARDS_MIN_COVERAGE", ENVDEFAULT),

    # ── auto-tune governor ──────────────────────────────────────────────
    "AUTOTUNE_MIN_SAMPLE_N": ("radar/calibration/auto_tune_governor.py",
                              "AUTO_TUNE_MIN_SAMPLE_N", ENVDEFAULT),
    "AUTOTUNE_COOLDOWN_H": ("radar/calibration/auto_tune_governor.py",
                            "AUTO_TUNE_COOLDOWN_HOURS", ENVDEFAULT),
    "AUTOTUNE_MAX_MAGNITUDE_PCT": (
        "radar/calibration/auto_tune_governor.py",
        "AUTO_TUNE_MAX_MAGNITUDE_PCT", ENVDEFAULT),
}

# Collections compared wholesale rather than value by value.
COLLECTION_MAPPING: dict = {
    "PROTECTED_ROLES": ("radar/calibration/_proposal_guards.py",
                        "PROTECTED_ROLES", "v3.calibration.guards"),
    "DEFAULT_TL_THRESHOLDS": (
        "radar/calibration/tl_threshold_calibrator.py",
        "DEFAULT_TL_THRESHOLDS", "v3.calibration.proposals"),
}

# Values v3 deliberately does not take from production. Each names the
# registration entry that authorises the difference.
EXPECTED_DIFFS: dict = {}

# Pinned names this gate cannot reach, each with the reason it cannot.
# The completeness check below makes it impossible to add a pinned
# threshold and quietly leave it out of both lists — a gate that reports
# "26 checked, 0 differences" while saying nothing about the rest reads as
# coverage it does not have.
STRUCTURALLY_UNMAPPABLE: dict = {
    "S9_RUN_INTERVAL_H":
        "WP-0.4 v2 (ADR-V3-012) — new to v3; production has no S9 "
        "runner, so there is no v1 value to read",
    "S9_POSITION_LOOKBACK_D":
        "WP-0.4 v2 — new to v3; derived from GT_FP_TN_HORIZON_D + daily "
        "cadence + slack, not ported from production",
    "S9_TIER1_MIN_DISTINCT_SOURCES":
        "WP-0.4 v2 — new to v3; production confirmed FN labels by "
        "analyst hand, so no convergence floor exists to map",
    "S9_TIER2_MAX_TOKENS":
        "WP-0.4 v2 Tier 2 — new to v3; production has no LLM second "
        "reader for calibration labels, so there is no value to read",
    "S9_TIER2_DRAFTS_PER_CYCLE":
        "WP-0.4 v2 Tier 2 — new to v3; same reason as the token bound",
    "GT_KINETIC_CONFIDENCE_FLOOR":
        "ground_truth_etl.py — inline `confidence >= 0.60` inside "
        "_expected_severity_floor; no module constant",
    "CONFIDENCE_WITH_FATALITIES":
        "rss_extractor.py — inline literal in the extractor's return "
        "dicts (confidence=0.85)",
    "CONFIDENCE_KINETIC":
        "rss_extractor.py — inline literal (confidence=0.60)",
    "CONFIDENCE_POSTURE":
        "rss_extractor.py — inline literal (confidence=0.40)",
    "RELEVANCE_MIN_RECOGNISED_COUNTRIES":
        "rss_extractor.py:is_escalation_relevant — inline "
        "`len(_detect_all_countries(text)) >= 2`",
    "CALIBRATION_WINDOW_D":
        "radar/conclusions/calibration.py — `_WINDOW_DAYS = getattr("
        "config, 'CALIBRATION_WINDOW_DAYS', 30)`; the key is registered "
        "nowhere, so the getattr default is the value (DP4). Not an "
        "os.getenv call, so the envdefault reader does not see it",
    "DESIGN_W_MAX_DROP":
        "check_recall_baseline.py — a keyword-argument default on "
        "compare(), not a module constant",
    "TL_CALIB_DEGENERATE_PRECISION_MARGIN":
        "tl_threshold_calibrator.py:219 — the literal +0.20 inside "
        "`precision < PRECISION_MIN_FLOOR + 0.20`",
    "TL_CALIB_TIGHTEN_RECALL_FLOOR":
        "tl_threshold_calibrator.py:234 — the literal 0.99 inside the "
        "tighten branch condition",
    "TL_CALIB_LOOSER_FACTOR":
        "tl_threshold_calibrator.py — inline `round(current * 0.95, 3)`",
    "TL_CALIB_TIGHTER_FACTOR":
        "tl_threshold_calibrator.py — inline `round(current * 1.05, 3)`",
    "TL_CALIB_ROUND_DIGITS":
        "tl_threshold_calibrator.py — the 3 in `round(..., 3)`",
    "WEIGHT_STEP_STRUCTURE_PROPOSER":
        "scenario_structure_proposer.py — hardcoded 0.20 inside the "
        "dormant-participant branch (ACCIDENTAL A8: differs from the "
        "improver's 0.15 with no stated reason)",
    "WEIGHT_CEILING":
        "scenario_improver.py — inline `round(min(0.95, w + step), 2)`",
    "WEIGHT_FLOOR":
        "scenario_improver.py — inline `round(max(0.10, w - step), 2)`",
    "PROPOSAL_WINDOW_D":
        "scenario_improver.py / scenario_structure_proposer.py — the "
        "30-day window is hardcoded at several call sites",
    "GLOBAL_MIN_SIGNALS":
        "_proposal_guards.py — keyword argument only (S1-calibration §3 "
        "records this explicitly: 'キーワード引数のみ')",
    "ZERO_SOURCES_FOR_STRONG":
        "_proposal_guards.py — the ladder is `if zero_count >= 5` inline; "
        "the 5 is len(SOURCE_NAMES), checked by the collection comparison",
    "ZERO_SOURCES_FOR_MODERATE":
        "_proposal_guards.py — inline `elif zero_count >= 3`",
}


def _module_tree(rel_path: str):
    return ast.parse((REPO_ROOT / rel_path).read_text(encoding="utf-8"))


def _literal(node):
    """literal_eval, plus the `frozenset({...})` / `set({...})` wrappers.

    Production writes its role sets as `frozenset({...})`, which is a Call
    node — `ast.literal_eval` refuses it, and the first version of this
    gate reported the comparison as "unreadable". Reporting a set as
    unreadable when it is one unwrap away is the coverage-shaped hole the
    completeness check exists to prevent.
    """
    try:
        return ast.literal_eval(node)
    except Exception:
        pass
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
            and node.func.id in ("frozenset", "set") and len(node.args) == 1:
        try:
            return frozenset(ast.literal_eval(node.args[0]))
        except Exception:
            return None
    return None


def _read_constant(tree, name: str):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return _literal(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target,
                                                            ast.Name) \
                and node.target.id == name:
            return _literal(node.value)
    return None


def _read_dictkey(tree, locator: str):
    dict_name, _, key = locator.partition(".")
    container = _read_constant(tree, dict_name)
    if isinstance(container, dict):
        return container.get(key)
    return None


def _read_envdefault(tree, key: str):
    """The default argument of `os.getenv(key, default)`, anywhere."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_getenv = (isinstance(func, ast.Attribute)
                     and func.attr == "getenv") or (
            isinstance(func, ast.Name) and func.id == "getenv")
        if not is_getenv or len(node.args) < 2:
            continue
        try:
            name = ast.literal_eval(node.args[0])
            default = ast.literal_eval(node.args[1])
        except Exception:
            continue
        if name == key:
            return default
    return None


_READERS = {CONSTANT: _read_constant, DICTKEY: _read_dictkey,
            ENVDEFAULT: _read_envdefault}


def _as_number(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()

    from v3.calibration import thresholds as v3t

    pinned = v3t.disclosure()
    differences: list = []
    unreachable: list = []
    checked = 0

    trees: dict = {}
    for name, (rel_path, locator, kind) in sorted(MAPPING.items()):
        if name not in pinned:
            differences.append(
                f"{name}: mapped here but not pinned in "
                f"v3/calibration/thresholds.py")
            continue
        tree = trees.setdefault(rel_path, _module_tree(rel_path))
        raw = _READERS[kind](tree, locator)
        production = _as_number(raw)
        if production is None:
            unreachable.append(f"{name}: {rel_path}:{locator} ({kind}) "
                               f"did not yield a number (got {raw!r})")
            continue
        checked += 1
        mine = pinned[name]["value"]
        if abs(mine - production) > 1e-12:
            if name in EXPECTED_DIFFS:
                if args.report:
                    print(f"  registered diff {name}: v3={mine} "
                          f"prod={production} ({EXPECTED_DIFFS[name]})")
                continue
            differences.append(
                f"{name}: v3 pins {mine}, {rel_path}:{locator} says "
                f"{production}")
        elif args.report:
            print(f"  ok {name} = {mine} ({rel_path}:{locator})")

    # Collections.
    import importlib
    for name, (rel_path, locator, module_name) in sorted(
            COLLECTION_MAPPING.items()):
        tree = trees.setdefault(rel_path, _module_tree(rel_path))
        production = _read_constant(tree, locator)
        module = importlib.import_module(module_name)
        mine = getattr(module, name, None)
        if production is None or mine is None:
            unreachable.append(f"{name}: collection not readable")
            continue
        checked += 1
        if set(production) != set(mine) or (
                isinstance(production, dict) and dict(production) != dict(mine)):
            differences.append(
                f"{name}: v3 has {sorted(mine)}, {rel_path}:{locator} has "
                f"{sorted(production)}")
        elif args.report:
            print(f"  ok {name} (collection, {len(mine)} entries)")

    # Completeness: every pinned name is mapped, unmappable, or a diff.
    accounted = set(MAPPING) | set(STRUCTURALLY_UNMAPPABLE) | \
        set(EXPECTED_DIFFS)
    orphans = sorted(set(pinned) - accounted)
    if orphans:
        differences.append(
            f"pinned but neither mapped nor declared unmappable: {orphans}. "
            f"Add each to MAPPING or to STRUCTURALLY_UNMAPPABLE with the "
            f"reason it cannot be read.")
    stale = sorted(accounted - set(pinned))
    if stale:
        differences.append(
            f"declared here but no longer pinned: {stale}")

    if unreachable:
        print(f"\n{len(unreachable)} mapped name(s) unreadable:",
              file=sys.stderr)
        for line in unreachable:
            print(f"  {line}", file=sys.stderr)

    if differences:
        print(f"\nFAIL: {len(differences)} calibration threshold "
              f"difference(s):", file=sys.stderr)
        for line in differences:
            print(f"  {line}", file=sys.stderr)
        return 1

    print(f"calibration thresholds: {checked} compared against production "
          f"by AST, 0 unregistered differences "
          f"({len(STRUCTURALLY_UNMAPPABLE)} structurally unreachable, "
          f"each declared with a reason).")
    return 0 if not unreachable else 1


if __name__ == "__main__":
    sys.exit(main())
