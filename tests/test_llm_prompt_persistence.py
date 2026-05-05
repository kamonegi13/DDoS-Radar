"""Tests for v2.0 LLM prompt persistence (ADR-V2-009).

Validates:
- sha256 is stable for the same (system, prompt) pair
- UPSERT semantics: same hash => use_count incremented, last_seen_at advanced
- Different system instructions dedup separately
- Secret-bearing prompts are refused (PII / token leakage guard)
- llm_call_log gets the prompt_sha256 link wired through llm_analyze_json
- Feature flag off => no rows written, no link populated
"""

from __future__ import annotations

import sqlite3
import time
from unittest.mock import patch

import pytest

from radar.database import RadarDB
from radar.llm_prompts import (
    compute_prompt_sha256,
    get_prompt,
    save_prompt,
)


@pytest.fixture
def db(tmp_path) -> RadarDB:
    return RadarDB(str(tmp_path / "llm_prompts.db"))


def test_sha256_is_stable_for_same_prompt() -> None:
    a = compute_prompt_sha256("hello", "system A")
    b = compute_prompt_sha256("hello", "system A")
    assert a == b
    assert len(a) == 64


def test_sha256_distinguishes_system_from_prompt() -> None:
    """Different system instructions must produce different hashes even if
    the user prompt is identical (NP6: traceable to exact prompt context)."""
    a = compute_prompt_sha256("hello", "system A")
    b = compute_prompt_sha256("hello", "system B")
    assert a != b


def test_save_prompt_creates_row(db: RadarDB) -> None:
    sha = save_prompt(db, prompt="analyze this", system="be terse",
                      model="llama3.1:8b", temperature=0.1)
    assert sha is not None
    row = get_prompt(db, sha)
    assert row is not None
    assert row["model"] == "llama3.1:8b"
    assert row["temperature"] == 0.1
    assert row["use_count"] == 1


def test_save_prompt_dedups_and_increments_use_count(db: RadarDB) -> None:
    sha1 = save_prompt(db, prompt="same prompt", system="", model="m")
    sha2 = save_prompt(db, prompt="same prompt", system="", model="m")
    assert sha1 == sha2
    row = get_prompt(db, sha1)
    assert row["use_count"] == 2


def test_save_prompt_advances_last_seen_on_repeat(db: RadarDB) -> None:
    sha = save_prompt(db, prompt="p", system="", model="m")
    first_seen = get_prompt(db, sha)["last_seen_at"]
    time.sleep(0.01)
    save_prompt(db, prompt="p", system="", model="m")
    second_seen = get_prompt(db, sha)["last_seen_at"]
    assert second_seen > first_seen


def test_save_prompt_distinguishes_systems(db: RadarDB) -> None:
    sha_a = save_prompt(db, prompt="p", system="A", model="m")
    sha_b = save_prompt(db, prompt="p", system="B", model="m")
    assert sha_a != sha_b
    assert get_prompt(db, sha_a)["use_count"] == 1
    assert get_prompt(db, sha_b)["use_count"] == 1


def test_save_prompt_refuses_secret_bearing_input(db: RadarDB, monkeypatch) -> None:
    """Prompt persistence is a transparency feature, not a secret store.
    If a secret leaks into a prompt template, refuse to persist."""
    monkeypatch.setenv("JWT_SECRET_KEY", "super-secret-jwt-token-1234567890")
    sha = save_prompt(db, prompt="please analyze: super-secret-jwt-token-1234567890",
                      system="", model="m")
    assert sha is None
    # And nothing was written.
    with sqlite3.connect(db._db_path) as conn:
        n = conn.execute("SELECT COUNT(*) FROM llm_prompts").fetchone()[0]
    assert n == 0


def test_save_prompt_ignores_empty_secret_env(db: RadarDB, monkeypatch) -> None:
    """If a secret env var is empty, the redactor must NOT match the empty
    string against every prompt — that would block all persistence."""
    monkeypatch.setenv("JWT_SECRET_KEY", "")
    sha = save_prompt(db, prompt="benign", system="", model="m")
    assert sha is not None


def test_get_prompt_returns_none_for_unknown_hash(db: RadarDB) -> None:
    assert get_prompt(db, "0" * 64) is None


def test_llm_call_log_link_when_flag_on(db: RadarDB, monkeypatch) -> None:
    """Integration: llm_analyze_json populates llm_call_log.prompt_sha256
    when V2_LLM_PROMPT_PERSISTENCE_ENABLED=True and the call succeeds."""
    from radar import config, llm_client

    monkeypatch.setattr(config, "V2_LLM_PROMPT_PERSISTENCE_ENABLED", True)
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)

    # Patch the db singleton used by llm_client._maybe_persist_prompt and _log_call.
    import radar.database as dbmod
    monkeypatch.setattr(dbmod, "db", db)

    fake_response = type("R", (), {
        "status_code": 200,
        "json": lambda self: {"response": '{"confidence": 0.9, "headline": "x"}'},
    })()
    with patch.object(llm_client.requests, "post", return_value=fake_response):
        result = llm_client.llm_analyze_json(
            prompt="test prompt for integration", system="be brief", caller="test_caller",
        )
    assert result["ok"] is True

    with sqlite3.connect(db._db_path) as conn:
        conn.row_factory = sqlite3.Row
        prompts = conn.execute("SELECT prompt_sha256, prompt_text FROM llm_prompts").fetchall()
        calls = conn.execute(
            "SELECT prompt_sha256 FROM llm_call_log WHERE caller='test_caller'"
        ).fetchall()
    assert len(prompts) == 1
    assert len(calls) == 1
    assert calls[0]["prompt_sha256"] == prompts[0]["prompt_sha256"]


def test_llm_call_log_no_link_when_flag_off(db: RadarDB, monkeypatch) -> None:
    """Feature flag off → prompt_sha256 column stays NULL on the call row."""
    from radar import config, llm_client

    monkeypatch.setattr(config, "V2_LLM_PROMPT_PERSISTENCE_ENABLED", False)
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)
    import radar.database as dbmod
    monkeypatch.setattr(dbmod, "db", db)

    fake_response = type("R", (), {
        "status_code": 200,
        "json": lambda self: {"response": '{"confidence": 0.5}'},
    })()
    with patch.object(llm_client.requests, "post", return_value=fake_response):
        llm_client.llm_analyze_json(prompt="x", system="", caller="off_test")

    with sqlite3.connect(db._db_path) as conn:
        n_prompts = conn.execute("SELECT COUNT(*) FROM llm_prompts").fetchone()[0]
        sha = conn.execute(
            "SELECT prompt_sha256 FROM llm_call_log WHERE caller='off_test'"
        ).fetchone()[0]
    assert n_prompts == 0
    assert sha is None


def test_persistence_failure_does_not_break_llm_call(monkeypatch) -> None:
    """If the prompt persistence layer raises, llm_analyze_json must still
    return a usable result (NP3: observability cannot break main flow)."""
    from radar import config, llm_client

    monkeypatch.setattr(config, "V2_LLM_PROMPT_PERSISTENCE_ENABLED", True)
    monkeypatch.setattr(llm_client, "LLM_ENABLED", True)

    import radar.database as dbmod

    class _BrokenDB:
        def _get_conn(self):
            raise RuntimeError("simulated outage")

        def llm_call_log_append(self, **kwargs):
            pass  # silently swallow log failure too

    monkeypatch.setattr(dbmod, "db", _BrokenDB())

    fake_response = type("R", (), {
        "status_code": 200,
        "json": lambda self: {"response": '{"confidence": 0.5}'},
    })()
    with patch.object(llm_client.requests, "post", return_value=fake_response):
        result = llm_client.llm_analyze_json(prompt="x", system="", caller="broken")

    assert result["ok"] is True
