"""Integration tests for `scripts/run_ground_truth_etl.py` (ADR-V2-005).

The classifier is unit-tested in test_ground_truth_etl.py. This file
exercises the *runner* — the orchestration layer that:

  - enumerates conclusions in [since, until] from the live DB,
  - groups them per scenario, looks up participant ISO-2 codes,
  - pulls ACLED + GDELT evidence (we stub the network calls),
  - delegates to classify_conclusion,
  - skips writes that already exist (idempotency),
  - tallies a Counter for the cron caller.

Why integration: the runner has its own failure modes (scenario lookup,
counter accounting, dry-run gating, scenario_filter slicing) that the
pure classifier tests can't surface.

Patterns mirror test_ground_truth_etl.py — same _NOW clock, same
gt_etl_test_ scenario_id prefix and cleanup fixture, same monkeypatch
style for the ACLED HTTP layer.
"""

from __future__ import annotations

import os
import sys
import time

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")

from radar import config
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    new_conclusion_id,
)
from radar.conclusions.feedback import FeedbackLabel
from radar.conclusions.persistence import save_conclusion
from radar.database import db
from radar.scenarios import Participant, Role, Scenario, scenario_store

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "scripts"))
import run_ground_truth_etl as runner  # noqa: E402


_NOW = 1_800_000_000.0
_SCENARIO = "taiwan_contingency"  # exists in geo_data.json with TW/JP/CN


def _make_conclusion(
    *, kind: ConclusionType, state: str, observed_at: float,
    scenario_id: str = _SCENARIO,
) -> Conclusion:
    c = Conclusion(
        id=f"gt_etl_runner_{new_conclusion_id()}",
        scenario_id=scenario_id,
        conclusion_type=kind,
        state=state,
        confidence=0.7,
        observed_at=observed_at,
        formula_ref="test#runner",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
    )
    save_conclusion(db, c)
    return c


def _count_feedback_rows(prefix: str = "gt_etl_runner_") -> int:
    row = db._get_conn().execute(
        "SELECT COUNT(*) AS n FROM analyst_feedback WHERE conclusion_id LIKE ?",
        (f"{prefix}%",),
    ).fetchone()
    return int(row["n"])


def _wipe_test_fixture_rows():
    """Drop both ETL-test and RSS-test fixture rows. RSS-test rows are
    cleaned here too so that even if test_run_rss_etl.py crashes mid-
    teardown the next ETL test sees a clean slate."""
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM analyst_feedback "
                "WHERE conclusion_id LIKE 'gt_etl_runner_%' "
                "   OR conclusion_id LIKE 'rss-test-%'"
            )
            conn.execute(
                "DELETE FROM conclusions "
                "WHERE id LIKE 'gt_etl_runner_%' "
                "   OR id LIKE 'rss-test-%'"
            )
    except Exception:
        pass


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    _wipe_test_fixture_rows()
    yield
    _wipe_test_fixture_rows()


@pytest.fixture(autouse=True)
def ensure_scenario_store_loaded():
    """Most tests need scenario_store to know about taiwan_contingency.

    The startup path in radar/__init__.py already loads it for normal pytest
    runs, but make it explicit so this file works in isolation."""
    if not scenario_store.loaded:
        scenario_store.load(config._raw_geo)
    yield


@pytest.fixture
def stub_acled(monkeypatch):
    """Replace the ACLED fetcher used by the runner so tests don't hit the
    network. The runner imports fetch_events at module load, so we patch
    the imported binding (`runner.fetch_acled_events`)."""
    state = {"events": []}

    def _set(events):
        state["events"] = list(events)

    def _stub(countries, *, since_epoch, until_epoch=None, **kw):
        from radar.sensors.acled import ACLEDEvent
        cc_set = {c.upper() for c in countries}
        return [
            e for e in state["events"]
            if e.country.upper() in cc_set
            and since_epoch <= e.event_at <= (until_epoch or float("inf"))
        ]

    monkeypatch.setattr(runner, "fetch_acled_events", _stub)
    return _set


@pytest.fixture
def no_gdelt(monkeypatch):
    """Force GDELT evidence to empty so tests focus on ACLED behaviour
    without depending on whatever rows happen to live in gdelt_dow."""
    monkeypatch.setattr(
        runner, "_gdelt_evidence_for_scenario",
        lambda db, countries, since, until: [],
    )


def _acled_evt(country: str, at: float, fatalities: int):
    from radar.sensors.acled import ACLEDEvent
    return ACLEDEvent(
        country=country, event_at=at,
        event_type="Battles", sub_event_type="Armed clash",
        fatalities=fatalities, location="Test Loc",
        source_url=f"https://example.test/acled/{country}/{int(at)}",
        notes="runner integration test event",
    )


# ── happy path: TP labelled and persisted ──────────────────────────────────


def test_runner_persists_true_positive(stub_acled, no_gdelt):
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    stub_acled([_acled_evt("TW", obs_at + 6 * 3600, fatalities=5)])

    summary = runner.run_etl(
        db, since=obs_at - 1, until=_NOW, scenario_filter=_SCENARIO,
    )
    assert summary["scanned"] >= 1
    assert summary.get("label_TRUE_POSITIVE", 0) == 1
    assert summary.get("persisted", 0) == 1
    assert _count_feedback_rows() == 1


# ── idempotency ────────────────────────────────────────────────────────────


def test_runner_is_idempotent(stub_acled, no_gdelt):
    """Re-running on the same window must NOT duplicate rows.

    This guards the cron use case — we want analysts to schedule the ETL
    every hour without producing N rows per conclusion."""
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    stub_acled([_acled_evt("TW", obs_at + 6 * 3600, fatalities=5)])

    first = runner.run_etl(db, since=obs_at - 1, until=_NOW, scenario_filter=_SCENARIO)
    assert first.get("persisted", 0) == 1

    second = runner.run_etl(db, since=obs_at - 1, until=_NOW, scenario_filter=_SCENARIO)
    assert second.get("already_persisted", 0) == 1
    assert second.get("persisted", 0) == 0
    assert _count_feedback_rows() == 1


# ── dry_run gates the write but still classifies ──────────────────────────


def test_runner_dry_run_classifies_without_writing(stub_acled, no_gdelt):
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    stub_acled([_acled_evt("TW", obs_at + 6 * 3600, fatalities=5)])

    summary = runner.run_etl(
        db, since=obs_at - 1, until=_NOW, scenario_filter=_SCENARIO, dry_run=True,
    )
    assert summary.get("label_TRUE_POSITIVE", 0) == 1
    assert summary.get("dry_run_skipped_write", 0) == 1
    assert summary.get("persisted", 0) == 0
    assert _count_feedback_rows() == 0


# ── scenario_filter narrows the input set ─────────────────────────────────


def test_runner_scenario_filter_skips_other_scenarios(stub_acled, no_gdelt):
    """A conclusion belonging to korean_peninsula should be skipped when the
    runner is invoked with scenario_filter=taiwan_contingency."""
    obs_at = _NOW - 24 * 3600
    _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3",
        observed_at=obs_at, scenario_id="korean_peninsula",
    )
    _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3",
        observed_at=obs_at, scenario_id=_SCENARIO,
    )
    stub_acled([_acled_evt("TW", obs_at + 6 * 3600, fatalities=5)])

    summary = runner.run_etl(
        db, since=obs_at - 1, until=_NOW, scenario_filter=_SCENARIO,
    )
    assert summary["scanned"] == 1
    assert summary.get("label_TRUE_POSITIVE", 0) == 1


# ── unknown scenario gracefully skipped ───────────────────────────────────


def test_runner_skips_conclusions_with_unknown_scenario(
    stub_acled, no_gdelt, monkeypatch,
):
    """If scenario_store has no entry for a conclusion's scenario_id, the
    runner counts it under skipped_no_participants but never crashes."""
    obs_at = _NOW - 24 * 3600
    _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3",
        observed_at=obs_at, scenario_id="ghost_scenario",
    )
    stub_acled([])

    summary = runner.run_etl(db, since=obs_at - 1, until=_NOW)
    assert summary.get("skipped_no_participants", 0) >= 1
    assert summary.get("persisted", 0) == 0


# ── no rule fires → counted under no_verdict ──────────────────────────────


def test_runner_counts_no_verdict_when_no_rule_matches(stub_acled, no_gdelt):
    """A high-TL conclusion without any corroborating event AND inside the
    horizon window yields no_verdict — neither TP, nor FP (since horizon
    hasn't elapsed), nor FN (TL is not 1)."""
    obs_at = _NOW - 1 * 3600  # too recent to mark FALSE_POSITIVE
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    stub_acled([])

    summary = runner.run_etl(
        db, since=obs_at - 1, until=_NOW, scenario_filter=_SCENARIO,
    )
    assert summary.get("no_verdict", 0) == 1
    assert summary.get("persisted", 0) == 0


# ── enable_gdelt=False isolates ACLED behaviour ───────────────────────────


def test_runner_disables_gdelt_when_flag_false(stub_acled, monkeypatch):
    """With enable_gdelt=False the GDELT helper must not be invoked at all
    — protects the runner from passing a None db or pulling stale rows
    when the operator explicitly opts out."""
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    stub_acled([_acled_evt("TW", obs_at + 6 * 3600, fatalities=5)])

    called = {"n": 0}
    def _spy(db_, countries, since, until):
        called["n"] += 1
        return []
    monkeypatch.setattr(runner, "_gdelt_evidence_for_scenario", _spy)

    summary = runner.run_etl(
        db, since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, enable_gdelt=False,
    )
    assert called["n"] == 0
    assert summary.get("label_TRUE_POSITIVE", 0) == 1


# ── feature-flag gate (main entry) ────────────────────────────────────────


def test_main_exits_zero_when_flag_disabled(monkeypatch, capsys):
    """When V2_GROUND_TRUTH_ETL_ENABLED is false and --force is not passed,
    main() must return 0 so cron treats it as a successful no-op."""
    monkeypatch.setattr(config, "V2_GROUND_TRUTH_ETL_ENABLED", False)
    monkeypatch.setattr(sys, "argv", ["run_ground_truth_etl.py"])

    rc = runner.main()
    assert rc == 0


def test_main_runs_when_force_overrides_flag(monkeypatch, stub_acled, no_gdelt):
    """--force is the operator escape hatch when the flag is off but the
    job needs to run (e.g. one-off backfill). Must execute the ETL pass.

    Note: this test exercises the ACLED-enabled path, so ACLED creds
    must be present (otherwise the new graceful-degradation logic in
    main() would auto-flip enable_acled=False and the stub fetcher
    would never run).
    """
    monkeypatch.setattr(config, "V2_GROUND_TRUTH_ETL_ENABLED", False)
    monkeypatch.setattr(config, "ACLED_API_KEY", "present")
    monkeypatch.setattr(config, "ACLED_API_EMAIL", "x@example.com")
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    stub_acled([_acled_evt("TW", obs_at + 6 * 3600, fatalities=5)])

    monkeypatch.setattr(sys, "argv", [
        "run_ground_truth_etl.py",
        "--force",
        "--scenario", _SCENARIO,
        "--since", str(obs_at - 1),
        "--until", str(_NOW),
        "--no-gdelt",
    ])
    rc = runner.main()
    assert rc == 0
    assert _count_feedback_rows() == 1


# ── empty input window: counters intact ───────────────────────────────────


def test_runner_returns_empty_summary_when_no_conclusions(stub_acled, no_gdelt):
    """Window with zero conclusions must return scanned=0 and not raise."""
    summary = runner.run_etl(
        db, since=_NOW + 86400, until=_NOW + 2 * 86400,
        scenario_filter=_SCENARIO,
    )
    assert summary.get("scanned", 0) == 0
    assert summary.get("persisted", 0) == 0


# ── ACLED-optional paths (OPSEC fallback) ────────────────────────────────


def test_runner_disables_acled_when_flag_false(stub_acled, no_gdelt, monkeypatch):
    """With enable_acled=False the ACLED fetcher must not be invoked, even
    when an ACLED stub would otherwise return events."""
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    stub_acled([_acled_evt("TW", obs_at + 6 * 3600, fatalities=5)])
    calls = []
    real_fetch = runner.fetch_acled_events

    def _spy(*a, **kw):
        calls.append((a, kw))
        return real_fetch(*a, **kw)

    monkeypatch.setattr(runner, "fetch_acled_events", _spy)

    summary = runner.run_etl(
        db, since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO, enable_acled=False, enable_gdelt=True,
    )
    assert calls == []
    # No ACLED evidence; GDELT spy returned [] in no_gdelt fixture (still set
    # by the test default), so summary['persisted'] is 0 — but the key
    # contract is that fetch_acled_events was never called.
    assert isinstance(summary, dict)


def test_runner_returns_no_op_when_both_sources_disabled(stub_acled, no_gdelt):
    """If both --no-gdelt and --no-acled are set, the runner must short-
    circuit and not waste DB scans."""
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    summary = runner.run_etl(
        db, since=obs_at - 1, until=_NOW,
        scenario_filter=_SCENARIO,
        enable_gdelt=False, enable_acled=False,
    )
    assert summary == {"scanned": 0, "skipped_both_sources_disabled": 1}


def test_main_falls_back_to_gdelt_only_when_acled_creds_missing(
    monkeypatch, stub_acled
):
    """Missing ACLED_API_KEY/EMAIL → main() must propagate enable_acled=False
    so the pipeline degrades gracefully to GDELT-only correlation."""
    monkeypatch.setattr(config, "V2_GROUND_TRUTH_ETL_ENABLED", True)
    monkeypatch.setattr(config, "ACLED_API_KEY", "")
    monkeypatch.setattr(config, "ACLED_API_EMAIL", "")
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)

    captured = {}
    real = runner.run_etl

    def _spy(db_, **kw):
        captured.update(kw)
        return real(db_, **kw)

    monkeypatch.setattr(runner, "run_etl", _spy)
    monkeypatch.setattr(sys, "argv", [
        "run_ground_truth_etl.py",
        "--scenario", _SCENARIO,
        "--since", str(obs_at - 1),
        "--until", str(_NOW),
        "--no-gdelt",
    ])
    rc = runner.main()
    assert rc == 0
    assert captured.get("enable_acled") is False


def test_main_no_acled_flag_propagates(monkeypatch, stub_acled):
    """Explicit --no-acled must propagate even when creds are present."""
    monkeypatch.setattr(config, "V2_GROUND_TRUTH_ETL_ENABLED", True)
    monkeypatch.setattr(config, "ACLED_API_KEY", "present")
    monkeypatch.setattr(config, "ACLED_API_EMAIL", "x@example.com")
    obs_at = _NOW - 24 * 3600
    _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)

    captured = {}
    real = runner.run_etl

    def _spy(db_, **kw):
        captured.update(kw)
        return real(db_, **kw)

    monkeypatch.setattr(runner, "run_etl", _spy)
    monkeypatch.setattr(sys, "argv", [
        "run_ground_truth_etl.py",
        "--scenario", _SCENARIO,
        "--since", str(obs_at - 1),
        "--until", str(_NOW),
        "--no-acled", "--no-gdelt",
    ])
    rc = runner.main()
    assert rc == 0
    assert captured.get("enable_acled") is False
    assert captured.get("enable_gdelt") is False
