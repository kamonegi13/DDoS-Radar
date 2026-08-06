#!/usr/bin/env bash
# Local CI gate — run before commit / push.
#
# Currently checks:
#   1. Codemap freshness (scripts/gen_codemap.py --check)
#   2. (future) scripts/check_rename_coverage.py for theater→country sub-phases
#
# Install as a git pre-commit hook (optional, opt-in):
#   ln -s ../../scripts/check_ci.sh .git/hooks/pre-commit
#
# Usage:
#   scripts/check_ci.sh           # run all gates
#   scripts/check_ci.sh --quick   # skip slow checks (currently same as default)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

FAIL=0

step() {
    echo
    echo "=== $1 ==="
}

step "Codemap freshness (Python)"
if ! python scripts/gen_codemap.py --check; then
    echo "FAIL: Python codemaps are stale. Run: python scripts/gen_codemap.py" >&2
    FAIL=1
fi

step "Codemap freshness (Frontend)"
if ! python scripts/gen_frontend_codemap.py --check; then
    echo "FAIL: frontend codemaps are stale. Run: python scripts/gen_frontend_codemap.py" >&2
    FAIL=1
fi

step "Rename coverage (theater→country)"
if ! python scripts/check_rename_coverage.py; then
    echo "FAIL: rename coverage gate. See output above." >&2
    FAIL=1
fi

step "Recall metrics baseline (Design W gate)"
if ! python scripts/check_recall_baseline.py; then
    echo "FAIL: recall baseline gate. See output above." >&2
    FAIL=1
fi

step "Post-autotune recall gate (warn-only)"
# Warn-only by default — short-term post-autotune recall changes are
# advisory until the post-autotune feedback set is large enough. Flip
# to --strict once observation period concludes.
if ! python scripts/check_recall_post_autotune.py; then
    echo "FAIL: post-autotune recall gate. See output above." >&2
    FAIL=1
fi

step "bg_observer alias coverage (ADR-V2-015 Phase 2)"
if ! python scripts/check_alias_coverage.py; then
    echo "FAIL: scenario participants missing from rss_extractor _COUNTRY_ALIASES." >&2
    FAIL=1
fi

step "i18n key audit + untranslated detection (Japanese-only UI, 2026-08-02)"
# GUIDE parity is fatal in the script. STRINGS undefined_refs/unused are
# warn-only here — flip to --strict once the unused-key cleanup lands.
python scripts/check_i18n_keys.py || { echo "FAIL: i18n audit reported issues. See output above." >&2; FAIL=1; }

step "Config reachability (WP-1.2 / S5-VERIF-013)"
# Static half only — fails when a NEW registered key bypasses the 3-layer
# resolution chain, or a hardcoded default starts contradicting the
# registry. The runtime half (import-time frozen constants, "registered but
# never read") runs daily in-app and surfaces at /api/v2/self_eval.
if ! python scripts/check_config_reachability.py; then
    echo "FAIL: config reachability regression. See output above." >&2
    FAIL=1
fi

step "K-kernel discipline (WP-2.1 / P6 O-18)"
# v3 code reads configuration through Threshold, never os.getenv (G-15),
# and never imports radar.* at module scope (that boots the legacy app).
if ! python scripts/check_kernel_discipline.py; then
    echo "FAIL: kernel discipline violation. See output above." >&2
    FAIL=1
fi

step "Secret scan (Phase 1 audit follow-up)"
# Pure-Python scanner; no external dependency. Conservative regexes, with
# placeholder/identifier suppression. Flips fatal so leaked credentials
# can never be re-introduced silently.
if ! python scripts/check_secrets.py; then
    echo "FAIL: potential secrets detected. See output above." >&2
    FAIL=1
fi

step "v1→v2 migration-scaffolding residue (v1_sunset_audit)"
# Surfaces migration leftovers that outlived the v1→v2 cutover (dead diff
# samplers, stale flags, residual v1 code) — the orphan class that silently
# degraded production before the 2026-05-30 teardown. Warn-only for now: the
# only standing HIGH is transient (conclusion_diff_log had pre-retirement
# writes inside the 24h window) and self-clears. Flip to `--strict` once that
# window passes so scaffolding teardown is enforced, not manual.
python -m radar.calibration.v1_sunset_audit || true

if [[ $FAIL -eq 0 ]]; then
    echo
    echo "All gates passed."
    exit 0
fi

echo
echo "One or more gates failed. See output above." >&2
exit 1
