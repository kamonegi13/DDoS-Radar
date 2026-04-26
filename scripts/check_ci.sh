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

if [[ $FAIL -eq 0 ]]; then
    echo
    echo "All gates passed."
    exit 0
fi

echo
echo "One or more gates failed. See output above." >&2
exit 1
