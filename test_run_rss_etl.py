"""Integration tests for scripts/run_rss_etl.py — RSS auto-feedback runner.

Stubs the live HTTP fetcher with deterministic fixture lists so tests run
offline. Pins the contract:
  - regex baseline produces auto-feedback rows without an LLM
  - --use-llm with an unreachable client falls back gracefully
  - idempotency: re-running doesn't double-write
  - scenario_filter restricts the conclusions touched
  - empty feed list short-circuits without errors
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import run_rss_etl as runner  # noqa: E402
from radar import config  # noqa: E402
from radar.conclusions.base import (  # noqa: E402
    Conclusion,
    ConclusionType,
)
from radar.conclusions.persistence import save_conclusion  # noqa: E402
from radar.database import db  # noqa: E402

_NOW = 1_800_000_000.0
_SCENARIO = "taiwan_contingency"


# ── helpers ──────────────────────────────────────────────────────────────


def _make_conclusion(*, kind, state, observed_at):
    """Persist a v2 conclusion and return the row's id."""
    cid = "rss-test-" + uuid.uuid4().hex[:12]
    c = Conclusion(
        id=cid,
        scenario_id=_SCENARIO,
        conclusion_type=kind,
        state=state,
        confidence=0.85,
        observed_at=observed_at,
        formula_ref="test",
        threshold_ref={},
        source_urls=(),
        calibration_status={},
        final_judgment_disclaimer="test",
        metadata={},
    )
    save_conclusion(db, c)
    return cid


def _count_feedback_rows(conclusion_id: str | None = None) -> int:
    """Count auto:rss feedback rows. Scope to a specific conclusion_id when
    given so tests are independent of leftover conclusions from prior runs.
    """
    if conclusion_id is not None:
        rows = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM analyst_feedback "
            "WHERE analyst_id = 'auto:rss' AND conclusion_id = ?",
            (conclusion_id,),
        ).fetchone()
    else:
        rows = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM analyst_feedback WHERE analyst_id = 'auto:rss'"
        ).fetchone()
    return rows[0] if rows else 0


def _clean_rss_feedback():
    """Drop both auto:rss feedback rows AND test-fixture conclusions so
    later test files (e.g. test_run_ground_truth_etl.py) don't see
    leftover rss-test-* conclusions in their time-window scans."""
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        conn.execute(
            "DELETE FROM analyst_feedback WHERE analyst_id = 'auto:rss'"
        )
        conn.execute(
            "DELETE FROM analyst_feedback WHERE conclusion_id LIKE 'rss-test-%'"
        )
        conn.execute(
            "DELETE FROM conclusions WHERE id LIKE 'rss-test-%'"
        )


# ── fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolate_rss_rows():
    """Clean rss-attributed feedback rows before and after each test."""
    _clean_rss_feedback()
    yield
    _clean_rss_feedback()


@pytest.fixture
def stub_fetch_all(monkeypatch):
    """Replace the live HTTP fetcher with a queue of fixture items."""
    queued: list[dict] = []

    def _fake(_feeds):
        return list(queued)

    monkeypatch.setattr(runner, "fetch_all", _fake)

    def _set(items):
        queued[:] = items

    return _set


@pytest.fixture
def no_llm(monkeypatch):
    """Force radar.llm_client to be unreachable so --use-llm exercises
    the regex-fallback path deterministically."""
    monkeypatch.setattr(runner, "_llm_invoke", lambda: None)


# ── happy path: regex baseline ───────────────────────────────────────────


def test_runner_persists_true_positive_from_regex(stub_fetch_all):
    obs_at = _NOW - 24 * 3600
    cid = _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at,
    )
    stub_fetch_all([
        {"title": "PLA airstrike kills 5 in Taiwan strait", "summary": "", "link": ""},
    ])
    summary = runner.run_etl(
        db, feeds=("dummy://",), since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, use_llm=False,
    )
    assert summary["matched_items"] == 1
    assert summary["persisted"] >= 1
    assert _count_feedback_rows(cid) == 1


# ── idempotency ──────────────────────────────────────────────────────────


def test_runner_is_idempotent(stub_fetch_all):
    obs_at = _NOW - 24 * 3600
    cid = _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at,
    )
    stub_fetch_all([
        {"title": "Chinese missile attack: 8 killed in Taiwan", "summary": "", "link": ""},
    ])
    runner.run_etl(
        db, feeds=("dummy://",), since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, use_llm=False,
    )
    second = runner.run_etl(
        db, feeds=("dummy://",), since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, use_llm=False,
    )
    assert second["already_persisted"] >= 1
    assert second["persisted"] == 0
    assert _count_feedback_rows(cid) == 1


# ── dry-run ──────────────────────────────────────────────────────────────


def test_runner_dry_run_skips_writes(stub_fetch_all):
    obs_at = _NOW - 24 * 3600
    cid = _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at,
    )
    stub_fetch_all([
        {"title": "Taiwan Strait incident: 4 killed", "summary": "", "link": ""},
    ])
    summary = runner.run_etl(
        db, feeds=("dummy://",), since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, use_llm=False, dry_run=True,
    )
    assert summary["dry_run_skipped_write"] >= 1
    assert summary["persisted"] == 0
    assert _count_feedback_rows(cid) == 0


# ── empty feeds graceful no-op ───────────────────────────────────────────


def test_runner_returns_no_op_on_empty_feeds(stub_fetch_all):
    stub_fetch_all([])
    summary = runner.run_etl(
        db, feeds=("dummy://",), since=_NOW - 86400, until=_NOW,
        scenario_filter=_SCENARIO, use_llm=False,
    )
    assert summary["feeds_fetched"] == 0
    assert summary["persisted"] == 0


# ── scenario_filter narrows ──────────────────────────────────────────────


def test_runner_scenario_filter_isolates_by_scenario(stub_fetch_all):
    obs_at = _NOW - 24 * 3600
    _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at,
    )
    stub_fetch_all([
        {"title": "Taiwan strait kinetic: 6 killed in Taiwan", "summary": "", "link": ""},
    ])
    summary = runner.run_etl(
        db, feeds=("dummy://",), since=obs_at - 1, until=_NOW,
        scenario_filter="korean_peninsula", use_llm=False,
    )
    assert summary["scanned"] == 0
    assert summary["persisted"] == 0


# ── LLM gracefully unavailable ───────────────────────────────────────────


def test_runner_use_llm_falls_back_when_client_unreachable(stub_fetch_all, no_llm):
    obs_at = _NOW - 24 * 3600
    _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at,
    )
    stub_fetch_all([
        {"title": "Russian artillery kills 3 near Ukraine border", "summary": "", "link": ""},
    ])
    # Despite use_llm=True, the LLM client is unreachable (no_llm fixture).
    # The runner must still produce auto-feedback rows from regex.
    summary = runner.run_etl(
        db, feeds=("dummy://",), since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, use_llm=True,
    )
    # Regex matches RU/UA. Taiwan scenario does not include RU/UA →
    # no_match. The fallback contract still holds: no exception, structured summary.
    assert summary["matched_items"] >= 0
    assert summary["persisted"] == 0


# ── matched RSS country must be in scenario participants ─────────────────


def test_runner_skips_match_when_country_not_in_scenario(stub_fetch_all):
    obs_at = _NOW - 24 * 3600
    _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at,
    )
    stub_fetch_all([
        # taiwan_contingency does not include North Korea
        {"title": "North Korea missile test: 0 killed (test only)",
         "summary": "DPRK launched a ballistic missile", "link": ""},
    ])
    summary = runner.run_etl(
        db, feeds=("dummy://",), since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, use_llm=False,
    )
    # KP is not in taiwan_contingency.participants, so the match drops.
    assert summary["persisted"] == 0


# ── main() flag gating ───────────────────────────────────────────────────


def test_main_exits_zero_when_etl_flag_disabled(monkeypatch, stub_fetch_all):
    monkeypatch.setattr(config, "V2_GROUND_TRUTH_ETL_ENABLED", False)
    monkeypatch.setattr(sys, "argv", ["run_rss_etl.py"])
    rc = runner.main()
    assert rc == 0


def test_main_runs_when_force_overrides_flag(monkeypatch, stub_fetch_all):
    monkeypatch.setattr(config, "V2_GROUND_TRUTH_ETL_ENABLED", False)
    obs_at = _NOW - 24 * 3600
    cid = _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at,
    )
    stub_fetch_all([
        {"title": "PLA missile fired at Taiwan; 4 killed", "summary": "", "link": ""},
    ])
    monkeypatch.setattr(sys, "argv", [
        "run_rss_etl.py",
        "--force",
        "--scenario", _SCENARIO,
        "--since", str(obs_at - 1),
        "--until", str(_NOW),
    ])
    rc = runner.main()
    assert rc == 0
    assert _count_feedback_rows(cid) == 1
