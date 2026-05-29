"""Tests for radar.calibration.run_now (Tier 1, commit 2)."""
from __future__ import annotations

import json
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.calibration import run_now


# ── RunResult dataclass ──


class TestRunResult:
    def test_succeeded_is_true_when_no_error(self):
        r = run_now.RunResult(phase="tl", started_at=time.time(),
                              duration_ms=10.0, summary={"applied": 1})
        assert r.succeeded is True

    def test_succeeded_is_false_when_error_set(self):
        r = run_now.RunResult(phase="tl", started_at=time.time(),
                              duration_ms=10.0, summary={}, error="boom")
        assert r.succeeded is False

    def test_immutable(self):
        r = run_now.RunResult(phase="tl", started_at=time.time(),
                              duration_ms=10.0)
        with pytest.raises(Exception):
            r.phase = "drift"


# ── Phase function lookup ──


class TestPhaseFunc:
    @pytest.mark.parametrize("phase", ["tl", "llm_conf", "sensor_disable",
                                       "scenario", "drift"])
    def test_returns_callable(self, phase):
        fn = run_now._phase_func(phase)
        assert callable(fn)

    def test_unknown_phase_raises(self):
        with pytest.raises(ValueError):
            run_now._phase_func("nope")


# ── Single-phase dispatch ──


class TestDispatchOne:
    def test_captures_summary(self, monkeypatch):
        called = {"n": 0}

        def fake_phase():
            called["n"] += 1
            return {"applied": 5}

        monkeypatch.setattr(run_now, "_phase_func", lambda p: fake_phase)
        results = run_now.dispatch("tl")
        assert len(results) == 1
        r = results[0]
        assert r.phase == "tl"
        assert r.succeeded
        assert r.summary == {"applied": 5}
        assert r.duration_ms >= 0
        assert called["n"] == 1

    def test_phase_returning_none_yields_empty_summary(self, monkeypatch):
        monkeypatch.setattr(run_now, "_phase_func", lambda p: lambda: None)
        results = run_now.dispatch("tl")
        assert results[0].summary == {}
        assert results[0].succeeded

    def test_phase_exception_is_captured(self, monkeypatch):
        def boom():
            raise RuntimeError("kaboom")

        monkeypatch.setattr(run_now, "_phase_func", lambda p: boom)
        results = run_now.dispatch("tl")
        assert len(results) == 1
        r = results[0]
        assert r.succeeded is False
        assert r.error is not None
        assert "kaboom" in r.error
        assert r.summary == {}

    def test_import_failure_is_captured(self, monkeypatch):
        def bad_import(p):
            raise ImportError("module missing")

        monkeypatch.setattr(run_now, "_phase_func", bad_import)
        results = run_now.dispatch("drift")
        assert len(results) == 1
        assert results[0].succeeded is False
        assert "import_failed" in results[0].error


# ── 'all' dispatch ──


class TestDispatchAll:
    def test_runs_phases_in_order(self, monkeypatch):
        seen: list[str] = []

        def fake_phase_func(phase):
            def runner():
                seen.append(phase)
                return {"phase": phase}
            return runner

        monkeypatch.setattr(run_now, "_phase_func", fake_phase_func)
        results = run_now.dispatch("all")
        assert len(results) == len(run_now._PHASE_ORDER)
        assert seen == list(run_now._PHASE_ORDER)
        assert [r.phase for r in results] == list(run_now._PHASE_ORDER)
        assert all(r.succeeded for r in results)

    def test_one_phase_failure_does_not_block_others(self, monkeypatch):
        def fake_phase_func(phase):
            if phase == "sensor_disable":
                def fail():
                    raise RuntimeError("sensor failure")
                return fail
            return lambda: {"ok": True}

        monkeypatch.setattr(run_now, "_phase_func", fake_phase_func)
        results = run_now.dispatch("all")
        assert len(results) == len(run_now._PHASE_ORDER)
        n_ok = sum(1 for r in results if r.succeeded)
        n_err = sum(1 for r in results if not r.succeeded)
        assert n_err == 1
        assert n_ok == len(run_now._PHASE_ORDER) - 1
        # The failing phase is precisely sensor_disable
        failed = [r for r in results if not r.succeeded]
        assert failed[0].phase == "sensor_disable"
        assert "sensor failure" in failed[0].error


# ── Validation ──


class TestDispatchValidation:
    def test_unknown_phase_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown phase"):
            run_now.dispatch("not_a_phase")

    def test_empty_phase_raises(self):
        with pytest.raises(ValueError):
            run_now.dispatch("")


# ── Text report formatting ──


class TestFormatResults:
    def test_handles_empty(self):
        text = run_now.format_results([])
        assert "Calibration run_now report" in text
        assert "(no results)" in text

    def test_renders_ok_and_err(self):
        results = [
            run_now.RunResult(phase="tl", started_at=time.time(),
                              duration_ms=12.0, summary={"applied": 1}),
            run_now.RunResult(phase="drift", started_at=time.time(),
                              duration_ms=8.0, summary={}, error="boom"),
        ]
        text = run_now.format_results(results)
        assert "[OK ]" in text
        assert "[ERR]" in text
        assert "Summary: 1 ok, 1 err" in text
        assert "boom" in text


# ── CLI ──


class TestCLI:
    def test_text_mode_for_single_phase(self, monkeypatch, capsys):
        monkeypatch.setattr(run_now, "_phase_func", lambda p: lambda: {"ok": 1})
        rc = run_now.main(["tl"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "Calibration run_now report" in captured.out
        assert "tl" in captured.out

    def test_json_mode_emits_valid_json(self, monkeypatch, capsys):
        monkeypatch.setattr(run_now, "_phase_func", lambda p: lambda: {"ok": 1})
        rc = run_now.main(["tl", "--json"])
        captured = capsys.readouterr()
        assert rc == 0
        data = json.loads(captured.out)
        assert data["phase"] == "tl"
        assert data["n_ok"] == 1
        assert data["n_err"] == 0
        assert len(data["results"]) == 1
        assert data["results"][0]["phase"] == "tl"

    def test_returns_1_when_any_phase_fails(self, monkeypatch, capsys):
        def fake(p):
            def boom():
                raise RuntimeError("bad")
            return boom
        monkeypatch.setattr(run_now, "_phase_func", fake)
        rc = run_now.main(["tl"])
        assert rc == 1

    def test_unknown_phase_exits_2(self, capsys):
        # argparse rejects with exit code 2 for choice violations
        with pytest.raises(SystemExit) as exc_info:
            run_now.main(["nope"])
        assert exc_info.value.code == 2

    def test_all_phase_runs_each(self, monkeypatch, capsys):
        seen: list[str] = []

        def fake(p):
            def runner():
                seen.append(p)
                return {}
            return runner

        monkeypatch.setattr(run_now, "_phase_func", fake)
        rc = run_now.main(["all", "--json"])
        captured = capsys.readouterr()
        assert rc == 0
        data = json.loads(captured.out)
        assert data["phase"] == "all"
        assert len(data["results"]) == len(run_now._PHASE_ORDER)
        assert seen == list(run_now._PHASE_ORDER)
