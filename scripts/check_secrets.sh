#!/bin/sh
# scripts/check_secrets.sh — pre-commit guard against secret leaks.
#
# Runs gitleaks against the staged changes only. Blocks the commit if any
# secret-shaped value is detected. Mirrors GitHub's Push Protection so that
# we catch secrets locally before they ever reach the remote (the 2026-05-04
# config.env mask-corruption + 2026-03-11 plaintext-key incidents both would
# have been blocked here).
#
# Wire as a git hook:
#   ln -sf ../../scripts/check_secrets.sh .git/hooks/pre-commit
#
# Bypass (use sparingly, requires explicit reason):
#   git commit --no-verify
#
# Exits 0 on clean, 1 on detected leak.

set -e

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "[check_secrets] gitleaks not installed — skipping."
    echo "[check_secrets] Install: brew install gitleaks"
    exit 0
fi

# Scan staged content (--staged) using the gitleaks built-in ruleset plus
# any project-local .gitleaks.toml. --redact suppresses the actual secret
# value in stderr so it does not echo into our terminal logs.
if ! gitleaks protect --staged --redact --no-banner 2>&1; then
    cat <<'EOF'

[check_secrets] BLOCKED — secret-shaped content detected in staged changes.

Resolve before committing:
  1. Remove the secret from the file (use config.env / env vars / vault).
  2. Re-stage and try `git commit` again.
  3. If this is a false positive, add it to .gitleaks.toml allowlist
     (do NOT use --no-verify casually; it's logged via reflog).

Reference: docs/design/secret-handling.md (if present) and
https://github.com/gitleaks/gitleaks#configuration

EOF
    exit 1
fi
