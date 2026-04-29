"""Tests for radar.diagnostics — weekly observability runner.

Verifies the cadence gate, the import path, and graceful degradation
when one of the underlying script modules fails.
"""
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")


def test_run_once_returns_audit_and_backtest_keys(tmp_path, monkeypatch):
    """A clean invocation populates both sub-results and a ran_at timestamp."""
    from radar import diagnostics

    # Stub out the script modules so the test doesn't depend on a real DB.
    fake_audit = type("M", (), {
        "analyze": staticmethod(lambda db: {"diversity_7d": {"avg_distinct": 1.0, "max_distinct": 1}}),
        "format_text": staticmethod(lambda r: "AUDIT-TEXT"),
    })
    fake_backtest = type("M", (), {
        "analyze": staticmethod(lambda db: {"diversity": {"avg_distinct": 1.0, "max_distinct": 1}}),
        "format_text": staticmethod(lambda r: "BACKTEST-TEXT"),
    })
    monkeypatch.setattr(diagnostics, "_import_scripts",
                        lambda: (fake_audit, fake_backtest))

    result = diagnostics.run_once(db_path=str(tmp_path / "x.db"))
    assert "audit" in result
    assert "backtest" in result
    assert isinstance(result["ran_at"], float)
    assert result["audit"]["diversity_7d"]["max_distinct"] == 1


def test_maybe_run_respects_cadence_gate(monkeypatch):
    """First call runs; immediate second call within the interval is a
    no-op until the gate elapses."""
    from radar import diagnostics

    calls = {"n": 0}
    def fake_run_once(db_path=None):
        calls["n"] += 1
        return {"audit": {}, "backtest": {}, "ran_at": time.time()}
    monkeypatch.setattr(diagnostics, "run_once", fake_run_once)
    diagnostics._force_reset_for_tests()

    first = diagnostics.maybe_run()
    assert first is not None
    assert calls["n"] == 1

    # Second invocation immediately after — gate must block.
    second = diagnostics.maybe_run()
    assert second is None
    assert calls["n"] == 1


def test_maybe_run_runs_again_after_interval(monkeypatch):
    """Setting WEEKLY_DIAGNOSTICS_INTERVAL_HOURS to the minimum (1h)
    and rolling the in-memory timestamp back lets the gate fire again."""
    from radar import diagnostics
    monkeypatch.setenv("WEEKLY_DIAGNOSTICS_INTERVAL_HOURS", "1")

    calls = {"n": 0}
    def fake_run_once(db_path=None):
        calls["n"] += 1
        return {"audit": {}, "backtest": {}, "ran_at": time.time()}
    monkeypatch.setattr(diagnostics, "run_once", fake_run_once)
    diagnostics._force_reset_for_tests()

    diagnostics.maybe_run()
    # Roll back the timestamp by 2h to simulate a week elapsed.
    diagnostics._last_run_at = time.time() - 2 * 3600
    diagnostics.maybe_run()
    assert calls["n"] == 2


def test_run_once_survives_audit_failure(monkeypatch):
    """If the audit module raises, the backtest still runs and the
    result dict reflects the partial outcome (NP3)."""
    from radar import diagnostics

    def boom_audit(db):
        raise RuntimeError("audit blew up")
    fake_audit = type("M", (), {
        "analyze": staticmethod(boom_audit),
        "format_text": staticmethod(lambda r: ""),
    })
    fake_backtest = type("M", (), {
        "analyze": staticmethod(lambda db: {"diversity": {}}),
        "format_text": staticmethod(lambda r: "BACKTEST-OK"),
    })
    monkeypatch.setattr(diagnostics, "_import_scripts",
                        lambda: (fake_audit, fake_backtest))

    result = diagnostics.run_once()
    assert result["audit"] == {}        # audit failed → empty
    assert "diversity" in result["backtest"]  # backtest succeeded


def test_diversity_signal_classifies_correctly():
    from radar import diagnostics
    # Single-source case
    sig = diagnostics._diversity_signal(
        audit_result={"diversity_7d": {"avg_distinct": 1.0, "max_distinct": 1}},
        backtest_result={},
    )
    assert "Layer 1 still blocked" in sig

    # Emerging
    sig2 = diagnostics._diversity_signal(
        audit_result={"diversity_7d": {"avg_distinct": 1.4, "max_distinct": 2}},
        backtest_result={},
    )
    assert "emerging" in sig2

    # Layer 1 ready
    sig3 = diagnostics._diversity_signal(
        audit_result={"diversity_7d": {"avg_distinct": 2.3, "max_distinct": 4}},
        backtest_result={},
    )
    assert "Layer 1 unlock conditions met" in sig3


def test_interval_minimum_is_one_hour(monkeypatch):
    """Misconfiguration safety: typo'd very-low value gets clamped to 1h."""
    from radar import diagnostics
    monkeypatch.setenv("WEEKLY_DIAGNOSTICS_INTERVAL_HOURS", "0.001")
    assert diagnostics._interval_seconds() >= 3600.0
