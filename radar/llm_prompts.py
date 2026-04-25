"""LLM prompt persistence — sha256-deduplicated store for NP6 transparency.

ADR-V2-009: every LLM call's prompt is persisted to llm_prompts (one row
per unique sha256) and llm_call_log gains a prompt_sha256 FK so analysts
can answer "what exactly did we ask the LLM to produce this conclusion?"
without trawling logs.

Module is a thin free-function shim; the storage tables (llm_prompts +
llm_call_log.prompt_sha256) were added in DB migration v20.

Safety: prompts are stored as plain text. PII / secrets must NOT appear
in prompt templates. _redact_secrets() strips obvious env-derived tokens
before storage; tests pin this contract.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from radar.database import RadarDB

log = logging.getLogger("radar")


# Env vars whose values must never appear in stored prompts. If any of these
# substrings appears in the prompt, we abort persistence rather than risk
# leaking. The list is conservative — add to it when new secret-bearing
# env vars are introduced.
_SECRET_ENV_VARS = (
    "JWT_SECRET_KEY",
    "DEFAULT_ADMIN_PASSWORD",
    "CF_API_TOKEN",
    "OWM_API_KEY",
)


def _contains_secret(prompt: str) -> Optional[str]:
    """Return the name of the first secret env var whose value is present
    in the prompt, or None if clean. Empty env values are skipped (defaults).
    """
    for var in _SECRET_ENV_VARS:
        val = os.getenv(var, "")
        if val and len(val) >= 8 and val in prompt:
            return var
    return None


def compute_prompt_sha256(prompt: str, system: str = "") -> str:
    """Stable hash for a (system, prompt) pair. system is included so the
    same user prompt under a different system instruction dedups separately.
    """
    h = hashlib.sha256()
    h.update(system.encode("utf-8"))
    h.update(b"\x00")
    h.update(prompt.encode("utf-8"))
    return h.hexdigest()


_UPSERT_SQL = """
INSERT INTO llm_prompts (
    prompt_sha256, prompt_text, model, temperature, prompt_version,
    first_seen_at, last_seen_at, use_count
) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
ON CONFLICT(prompt_sha256) DO UPDATE SET
    last_seen_at = excluded.last_seen_at,
    use_count    = use_count + 1
"""


def save_prompt(
    db: "RadarDB",
    prompt: str,
    system: str = "",
    model: str = "",
    temperature: Optional[float] = None,
    prompt_version: str = "",
) -> Optional[str]:
    """Persist (or bump use_count for) a prompt and return its sha256.

    Returns None if persistence was skipped (secret detected or DB error).
    Caller should treat None as "do not link this call to a prompt row";
    the call still proceeds (NP3 — observability never breaks main flow).
    """
    secret = _contains_secret(prompt + "\n" + system)
    if secret is not None:
        log.warning("[llm_prompts] refusing to persist prompt — contains $%s", secret)
        return None

    sha = compute_prompt_sha256(prompt, system)
    full_text = system + "\n\x00\n" + prompt if system else prompt
    now = time.time()
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                _UPSERT_SQL,
                (sha, full_text, model[:80], temperature, prompt_version, now, now),
            )
        return sha
    except Exception:
        log.exception("[llm_prompts] save failed (non-fatal)")
        return None


def get_prompt(db: "RadarDB", sha256: str) -> Optional[dict]:
    """Read back a prompt row. Returns None if not found."""
    row = db._get_conn().execute(  # noqa: SLF001
        """
        SELECT prompt_sha256, prompt_text, model, temperature, prompt_version,
               first_seen_at, last_seen_at, use_count
        FROM llm_prompts
        WHERE prompt_sha256 = ?
        """,
        (sha256,),
    ).fetchone()
    if row is None:
        return None
    return dict(row)
