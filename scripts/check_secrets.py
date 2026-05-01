#!/usr/bin/env python3
"""Lightweight secret scanner — Phase 1 (audit follow-up).

Scans staged + working-tree files for credential-shaped strings before
they land in git history. Pure Python, no external dependencies, so it
runs in any environment without `brew install gitleaks` etc.

Coverage targets (from full-codebase-review.md Security C1):
- Cloudflare API tokens / global keys
- AWS access keys (AKIA / ASIA prefixes)
- JWT_SECRET-style hex strings >= 32 chars assigned to secret-named vars
- Generic API key / token / password assignments with non-placeholder values
- OAuth client secrets
- Private key blocks (PEM)

Usage::
    scripts/check_secrets.py                 # scan tracked files (skips ignored)
    scripts/check_secrets.py --staged        # scan only files staged for commit
    scripts/check_secrets.py path/to/file    # scan specific paths

Exit code: 0 = clean, 1 = potential secrets found.

Designed for git pre-commit + scripts/check_ci.sh integration.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# ── Patterns ────────────────────────────────────────────────────────────────
# Each pattern is (name, regex, min_length_of_secret_group). Callers should
# verify the captured group is not a placeholder via _is_placeholder() below.

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # AWS
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    # Generic 64-char hex (JWT_SECRET-style, common for `secrets.token_hex(32)`)
    # Only flag when assigned to a secret-shaped variable name.
    (
        "secret_assignment_hex",
        re.compile(
            r"(?i)\b("
            r"jwt_secret(?:_key)?|"
            r"secret_key|"
            r"api_secret|"
            r"client_secret|"
            r"password|"
            r"passwd|"
            r"access_token|"
            r"refresh_token|"
            r"auth_token"
            r")\s*[:=]\s*['\"]?([A-Fa-f0-9]{32,})['\"]?",
        ),
    ),
    # Generic API key assignment with realistic value (>= 20 chars, non-placeholder).
    # Requires QUOTES around the value — bare identifier references like
    # `api_token=MY_CONFIG_CONSTANT` are not credentials and would otherwise
    # produce constant false positives in source code.
    (
        "api_key_assignment",
        re.compile(
            r"(?i)\b("
            r"[a-z_]*api[_-]?(?:key|token)|"
            r"bearer[_-]?token|"
            r"oauth[_-]?token"
            r")\s*[:=]\s*['\"]([A-Za-z0-9_\-+/=]{20,})['\"]",
        ),
    ),
    # PEM private key blocks
    (
        "pem_private_key",
        re.compile(
            r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PRIVATE)\s+PRIVATE\s+KEY-----"
        ),
    ),
    # Slack tokens
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    # GitHub tokens (classic + fine-grained)
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
]

_PLACEHOLDER_VALUES: set[str] = {
    # Common placeholder strings — case-insensitive comparison applied below.
    "your_api_key_here",
    "your_secret_here",
    "changeme",
    "change_me",
    "replace_me",
    "xxx",
    "xxxxxxxx",
    "example",
    "placeholder",
    "todo",
    "tbd",
    "redacted",
    "deadbeef",
}


_IDENTIFIER_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")


def _is_placeholder(value: str) -> bool:
    """Cheap heuristic: ignore obviously-fake values from .env.example etc."""
    v = value.strip("'\"").lower()
    raw = value.strip("'\"")
    if v in _PLACEHOLDER_VALUES:
        return True
    # All-zero or all-x sequences
    if len(set(v)) <= 2 and len(v) >= 16:
        return True
    # Contains literal placeholder words
    if any(token in v for token in ("example", "placeholder", "your_", "<your_", "<replace")):
        return True
    # ALL_CAPS_IDENTIFIER references (Python constant names, env var names) —
    # `api_token=CERTSPOTTER_API_TOKEN` is a config constant, not a secret.
    if _IDENTIFIER_RE.match(raw):
        return True
    return False


# ── File selection ──────────────────────────────────────────────────────────

# Paths and extensions we never scan (binary / vendored / build artifacts).
_SKIP_DIRS: set[str] = {
    ".git", ".venv", "node_modules", "__pycache__",
    ".pytest_cache", ".ruff_cache", "dist", "build",
    "persistence", "radar/persistence",
    ".claude",  # local-only review artifacts; gitignored anyway
}
_SKIP_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".whl",
    ".db", ".db-shm", ".db-wal", ".sqlite", ".sqlite3",
    ".pyc", ".pyo", ".so", ".dylib", ".dll",
    ".lock",  # poetry.lock / package-lock.json already shipped via package mgrs
}
# Filenames we scan despite extension exclusions if they exist (e.g. scripted).
_FORCE_INCLUDE_NAMES: set[str] = {"config.env", ".env"}


def _should_scan(path: Path) -> bool:
    if not path.is_file():
        return False
    parts = set(path.parts)
    if parts & _SKIP_DIRS:
        return False
    if path.suffix in _SKIP_EXTENSIONS:
        return False
    # Files larger than 2 MB are almost always not source — skip to keep
    # the scanner fast and avoid scanning binaries that slipped past the
    # extension list.
    try:
        if path.stat().st_size > 2 * 1024 * 1024:
            return False
    except OSError:
        return False
    return True


def _git_tracked_files(repo_root: Path) -> list[Path]:
    """Return files tracked by git (respects .gitignore)."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_root), "ls-files"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Not a git repo; fall back to walking the tree.
        return [p for p in repo_root.rglob("*") if _should_scan(p)]
    return [repo_root / line for line in out.splitlines() if line]


def _git_staged_files(repo_root: Path) -> list[Path]:
    """Return files staged for commit (added or modified)."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(repo_root),
             "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            text=True, stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    return [repo_root / line for line in out.splitlines() if line]


# ── Scanning ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Finding:
    file: Path
    line: int
    pattern: str
    snippet: str

    def render(self, repo_root: Path) -> str:
        try:
            rel = self.file.relative_to(repo_root)
        except ValueError:
            rel = self.file
        return f"  {rel}:{self.line}  [{self.pattern}]  {self.snippet}"


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    for line_no, line in enumerate(text.splitlines(), start=1):
        # Quick skip — lines with only whitespace or comments without `=` are
        # never going to host a credential assignment.
        if "=" not in line and "BEGIN" not in line and "AKIA" not in line and "xox" not in line:
            continue
        for name, pat in _PATTERNS:
            for match in pat.finditer(line):
                # For assignment-style patterns, the secret is in group 2.
                # For shape-only patterns (AWS, PEM, Slack) the whole match
                # is the credential.
                if match.lastindex and match.lastindex >= 2:
                    captured = match.group(match.lastindex)
                else:
                    captured = match.group(0)
                if _is_placeholder(captured):
                    continue
                # Trim long captures for display.
                snippet_value = captured if len(captured) <= 24 else captured[:8] + "…" + captured[-4:]
                snippet = f"{match.group(1) if match.lastindex else name}={snippet_value}"
                findings.append(
                    Finding(file=path, line=line_no, pattern=name, snippet=snippet)
                )
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--staged", action="store_true",
        help="Scan only files staged for commit",
    )
    parser.add_argument(
        "paths", nargs="*",
        help="Specific paths to scan (relative or absolute)",
    )
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent

    if args.paths:
        targets = [Path(p).resolve() for p in args.paths]
    elif args.staged:
        targets = _git_staged_files(repo_root)
    else:
        targets = _git_tracked_files(repo_root)

    targets = [p for p in targets if _should_scan(p) or p.name in _FORCE_INCLUDE_NAMES]

    findings: list[Finding] = []
    for target in targets:
        findings.extend(scan_file(target))

    if findings:
        print(f"Secret scan FAIL — {len(findings)} potential credential(s) found:",
              file=sys.stderr)
        for f in findings:
            print(f.render(repo_root), file=sys.stderr)
        print(
            "\nIf any finding is a real secret: rotate the credential and "
            "remove the value from the file.\nIf the finding is a false "
            "positive (test fixture, sample, example), add a placeholder "
            "value or move it under .gitignore.\nThis scanner is intentionally "
            "conservative — false positives are expected and easy to fix.",
            file=sys.stderr,
        )
        return 1

    print(f"Secret scan OK — {len(targets)} file(s) clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
