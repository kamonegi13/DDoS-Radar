"""Retention tests for the two LLM ledgers (2026-07-04 debris cleanup).

1. llm_call_log: LLM_CALL_LOG_RETENTION_DAYS (default 30) was DEAD CODE —
   a hardcoded 7-day DELETE ran first in _prune_stale_rows, so the
   documented/configurable retention never had any effect. These tests
   pin the config-driven behavior.

2. llm_prompts: the sha256-keyed prompt store had NO retention at all.
   Because prompts embed live dynamic content, distinct hashes accumulate
   forever (the only genuinely unbounded table in the 2026-07-03 audit).
   Retention keys on last_seen_at and must exceed CONCLUSIONS_RETENTION_DAYS
   (90d) so every live conclusion keeps its prompt provenance (NP6).
"""
import hashlib
import os
import time
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.database import db


@pytest.fixture
def probe_calls():
    """Insert llm_call_log rows at 10d and 40d age; cleanup by caller tag."""
    caller = f"test_{uuid.uuid4().hex[:8]}"
    now = time.time()
    conn = db._get_conn()
    with conn.writing():
        for age_days in (10, 40):
            conn.execute(
                "INSERT INTO llm_call_log "
                "(ts, caller, model, duration_ms, outcome, verdict, "
                " confidence, headline, error, prompt_sha256, "
                " use_case, shadow_model_choice, thinking_trace) "
                "VALUES (?, ?, 'test', 1, 'ok', '', 0.5, '', '', NULL, "
                " NULL, NULL, NULL)",
                (now - age_days * 86400, caller),
            )
    yield caller
    with conn.writing():
        conn.execute("DELETE FROM llm_call_log WHERE caller = ?", (caller,))


@pytest.fixture
def probe_prompts():
    """Insert llm_prompts rows last seen 10d and 200d ago."""
    tag = uuid.uuid4().hex[:8]
    now = time.time()
    hashes = {}
    conn = db._get_conn()
    with conn.writing():
        for name, age_days in (("recent", 10), ("stale", 200)):
            sha = hashlib.sha256(f"{tag}-{name}".encode()).hexdigest()
            hashes[name] = sha
            conn.execute(
                "INSERT INTO llm_prompts "
                "(prompt_sha256, prompt_text, model, temperature, "
                " prompt_version, first_seen_at, last_seen_at, use_count) "
                "VALUES (?, 'test prompt', 'test', 0.0, 'v1', ?, ?, 1)",
                (sha, now - age_days * 86400, now - age_days * 86400),
            )
    yield hashes
    with conn.writing():
        for sha in hashes.values():
            conn.execute(
                "DELETE FROM llm_prompts WHERE prompt_sha256 = ?", (sha,),
            )


def _call_count(caller: str) -> int:
    return db._get_conn().execute(
        "SELECT COUNT(*) AS c FROM llm_call_log WHERE caller = ?",
        (caller,),
    ).fetchone()["c"]


def _prompt_exists(sha: str) -> bool:
    return db._get_conn().execute(
        "SELECT 1 FROM llm_prompts WHERE prompt_sha256 = ?", (sha,),
    ).fetchone() is not None


class TestLlmCallLogRetention:
    def test_config_retention_is_honored_not_hardcoded_7d(self, probe_calls):
        """A 10-day-old row must SURVIVE the default 30d retention.
        Before the fix, a hardcoded 7d DELETE removed it regardless of
        LLM_CALL_LOG_RETENTION_DAYS."""
        db._prune_stale_rows()
        assert _call_count(probe_calls) == 1  # 40d row pruned, 10d survives

    def test_env_override_shortens_retention(self, probe_calls, monkeypatch):
        monkeypatch.setenv("LLM_CALL_LOG_RETENTION_DAYS", "5")
        db._prune_stale_rows()
        assert _call_count(probe_calls) == 0  # both 10d and 40d pruned


class TestLlmPromptsRetention:
    def test_stale_prompts_pruned_recent_survive(self, probe_prompts):
        db._prune_stale_rows()
        assert _prompt_exists(probe_prompts["recent"])
        assert not _prompt_exists(probe_prompts["stale"])

    def test_retention_never_undercuts_conclusions_window(
        self, probe_prompts, monkeypatch,
    ):
        """NP6: a live conclusion must always be able to resolve its
        llm_prompt_sha256. Even if an operator sets the prompt retention
        below CONCLUSIONS_RETENTION_DAYS, the effective floor is
        conclusions retention + margin — a 100-day-old prompt survives a
        30-day override while conclusions are kept 90 days."""
        monkeypatch.setenv("LLM_PROMPTS_RETENTION_DAYS", "30")
        now = time.time()
        conn = db._get_conn()
        sha = probe_prompts["recent"]
        with conn.writing():
            conn.execute(
                "UPDATE llm_prompts SET last_seen_at = ? "
                "WHERE prompt_sha256 = ?",
                (now - 100 * 86400, sha),
            )
        db._prune_stale_rows()
        assert _prompt_exists(sha)
