"""Unit tests for scripts/check_recall_baseline.compare().

Covers the gate's six branches:
  - bootstrap (baseline cell recall=None) — never fails
  - no regression (deltas <= 0)
  - drop within tolerance — info, no fail
  - drop exceeding tolerance — hard fail
  - coverage loss (baseline has number, current is None) — hard fail
  - missing cell (key absent in current) — soft warn, no fail
  - new cell in current — info, no fail
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from check_recall_baseline import compare  # noqa: E402


def _snap(*cells: dict) -> dict:
    return {"schema_version": 1, "cells": list(cells)}


def _cell(scenario: str, ctype: str, recall: float | None) -> dict:
    return {
        "scenario_id": scenario,
        "conclusion_type": ctype,
        "recall": recall,
        "tp": 0, "fp": 0, "fn": 0, "tn": 0,  # placeholders
    }


def test_no_change_passes() -> None:
    base = _snap(_cell("twn", "ATTACK_MODE", 0.80))
    cur = _snap(_cell("twn", "ATTACK_MODE", 0.80))
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is True
    assert all("FAIL" not in m for m in messages)


def test_recall_improvement_passes() -> None:
    base = _snap(_cell("twn", "TREND", 0.70))
    cur = _snap(_cell("twn", "TREND", 0.85))
    ok, _ = compare(base, cur, max_drop=0.05)
    assert ok is True


def test_drop_within_tolerance_passes_with_info() -> None:
    base = _snap(_cell("twn", "TREND", 0.80))
    cur = _snap(_cell("twn", "TREND", 0.77))
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is True
    assert any("info" in m and "slipped" in m for m in messages)


def test_drop_exceeding_tolerance_fails() -> None:
    base = _snap(_cell("twn", "ATTACK_MODE", 0.80))
    cur = _snap(_cell("twn", "ATTACK_MODE", 0.60))
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is False
    assert any("FAIL" in m for m in messages)


def test_drop_just_under_threshold_passes() -> None:
    base = _snap(_cell("twn", "TREND", 0.80))
    cur = _snap(_cell("twn", "TREND", 0.76))  # drop 0.04, under 0.05
    ok, _ = compare(base, cur, max_drop=0.05)
    assert ok is True


def test_coverage_loss_fails() -> None:
    base = _snap(_cell("twn", "ANOMALY", 0.75))
    cur = _snap(_cell("twn", "ANOMALY", None))
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is False
    assert any("coverage loss" in m for m in messages)


def test_bootstrap_recall_none_in_baseline_skips() -> None:
    base = _snap(_cell("twn", "PER_DOMAIN", None))
    cur = _snap(_cell("twn", "PER_DOMAIN", 0.10))
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is True
    assert all("FAIL" not in m for m in messages)


def test_missing_cell_in_current_warns_no_fail() -> None:
    base = _snap(
        _cell("twn", "TREND", 0.80),
        _cell("twn", "ATTACK_MODE", 0.70),
    )
    cur = _snap(_cell("twn", "TREND", 0.80))
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is True
    assert any("warn" in m and "ATTACK_MODE" in m for m in messages)


def test_new_cell_in_current_is_informational() -> None:
    base = _snap(_cell("twn", "TREND", 0.80))
    cur = _snap(
        _cell("twn", "TREND", 0.80),
        _cell("kor", "TREND", 0.65),
    )
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is True
    assert any("new cell" in m and "kor" in m for m in messages)


def test_multiple_cells_one_regression_fails() -> None:
    base = _snap(
        _cell("twn", "TREND", 0.80),
        _cell("twn", "ATTACK_MODE", 0.75),
        _cell("kor", "TREND", 0.70),
    )
    cur = _snap(
        _cell("twn", "TREND", 0.79),
        _cell("twn", "ATTACK_MODE", 0.50),  # regression
        _cell("kor", "TREND", 0.71),
    )
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is False
    fail_messages = [m for m in messages if "FAIL" in m]
    assert len(fail_messages) == 1
    assert "ATTACK_MODE" in fail_messages[0]


def test_custom_max_drop_threshold_respected() -> None:
    base = _snap(_cell("twn", "TREND", 0.80))
    cur = _snap(_cell("twn", "TREND", 0.72))

    ok_strict, _ = compare(base, cur, max_drop=0.05)
    assert ok_strict is False

    ok_lenient, _ = compare(base, cur, max_drop=0.10)
    assert ok_lenient is True


def test_empty_baseline_and_current_passes() -> None:
    ok, messages = compare(_snap(), _snap(), max_drop=0.05)
    assert ok is True
    assert messages == []


def test_both_recall_none_skips() -> None:
    base = _snap(_cell("twn", "ANOMALY", None))
    cur = _snap(_cell("twn", "ANOMALY", None))
    ok, messages = compare(base, cur, max_drop=0.05)
    assert ok is True
    assert all("FAIL" not in m for m in messages)


# ── --window-days CLI plumbing ─────────────────────────────────────────────

def test_window_days_propagates_since_to_collect_metrics(monkeypatch, tmp_path) -> None:
    """--window-days N must materialize as since=now-N*86400 inside the snapshot."""
    import check_recall_baseline as crb

    captured: dict = {}

    def fake_snapshot(*, db_path=None, exclude_auto=False, since=None):
        captured["since"] = since
        captured["exclude_auto"] = exclude_auto
        return {"schema_version": 1, "exclude_auto": exclude_auto,
                "since": since, "opt_in": False, "cells": []}

    monkeypatch.setattr(crb, "_collect_snapshot", fake_snapshot)

    baseline_path = tmp_path / "baseline.json"
    rc = crb.main([
        "--update", "--window-days", "30",
        "--baseline", str(baseline_path),
    ])
    assert rc == 0
    assert captured["since"] is not None
    # 30d ago, allow 5s slack for execution time
    expected = __import__("time").time() - 30 * 86400.0
    assert abs(captured["since"] - expected) < 5.0


def test_window_days_omitted_means_full_history(monkeypatch, tmp_path) -> None:
    import check_recall_baseline as crb

    captured: dict = {}

    def fake_snapshot(*, db_path=None, exclude_auto=False, since=None):
        captured["since"] = since
        return {"schema_version": 1, "exclude_auto": False,
                "since": since, "opt_in": False, "cells": []}

    monkeypatch.setattr(crb, "_collect_snapshot", fake_snapshot)

    baseline_path = tmp_path / "baseline.json"
    rc = crb.main(["--update", "--baseline", str(baseline_path)])
    assert rc == 0
    assert captured["since"] is None


def test_check_inherits_baseline_window(monkeypatch, tmp_path) -> None:
    """When --window-days is omitted on check, current snapshot must reuse baseline.since."""
    import json as _json
    import check_recall_baseline as crb

    baseline_path = tmp_path / "baseline.json"
    baseline_payload = {
        "schema_version": 1, "exclude_auto": False,
        "since": 1_700_000_000.0, "opt_in": False,
        "cells": [_cell("twn", "TREND", 0.80)],
    }
    baseline_path.write_text(_json.dumps(baseline_payload), encoding="utf-8")

    captured: dict = {}

    def fake_snapshot(*, db_path=None, exclude_auto=False, since=None):
        captured["since"] = since
        return {"schema_version": 1, "exclude_auto": False,
                "since": since, "opt_in": False,
                "cells": [_cell("twn", "TREND", 0.80)]}

    monkeypatch.setattr(crb, "_collect_snapshot", fake_snapshot)

    rc = crb.main(["--baseline", str(baseline_path)])
    assert rc == 0
    assert captured["since"] == 1_700_000_000.0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


# ── WP-0.2 G-07: the programmatic gate API the governor calls ──────────────
class TestEvaluateAgainstBaseline:
    """`auto_tune_governor._recall_gate_is_red()` has always called this
    function; until 2026-08-07 it did not exist, so the governor's
    `except Exception -> False` fail-open fired on every invocation and the
    recall gate never blocked anything."""

    def _baseline(self, tmp_path, cells, since=None):
        import json
        path = tmp_path / "baseline.json"
        path.write_text(json.dumps({
            "schema_version": 1, "exclude_auto": False, "since": since,
            "opt_in": False, "cells": cells,
        }), encoding="utf-8")
        return path

    def _cell(self, recall, scenario="s1", ctype="threat_level"):
        return {"scenario_id": scenario, "conclusion_type": ctype,
                "tp": 10, "fp": 1, "tn": 5, "fn": 2, "total": 18,
                "recall": recall, "precision": 0.9, "distinct_analysts": 2}

    def test_the_attribute_the_governor_calls_exists(self):
        import scripts.check_recall_baseline as mod
        assert callable(getattr(mod, "evaluate_against_baseline", None))

    def test_missing_baseline_reports_no_baseline(self, tmp_path):
        from scripts.check_recall_baseline import evaluate_against_baseline
        report = evaluate_against_baseline(
            baseline_path=tmp_path / "absent.json")
        assert report["status"] == "NO_BASELINE"
        assert report["status"] != "FAIL", "absence must not read as regression"

    def test_pass_when_recall_holds(self, tmp_path, monkeypatch):
        import scripts.check_recall_baseline as mod
        path = self._baseline(tmp_path, [self._cell(0.80)])
        monkeypatch.setattr(mod, "_collect_snapshot",
                            lambda **kw: {"cells": [self._cell(0.80)]})
        report = mod.evaluate_against_baseline(baseline_path=path)
        assert report["status"] == "PASS"

    def test_fail_when_recall_drops_beyond_tolerance(self, tmp_path,
                                                    monkeypatch):
        import scripts.check_recall_baseline as mod
        path = self._baseline(tmp_path, [self._cell(0.80)])
        monkeypatch.setattr(mod, "_collect_snapshot",
                            lambda **kw: {"cells": [self._cell(0.50)]})
        report = mod.evaluate_against_baseline(baseline_path=path,
                                               tolerance=0.05)
        assert report["status"] == "FAIL"
        assert any("recall" in m for m in report["messages"])

    def test_a_drop_inside_tolerance_passes(self, tmp_path, monkeypatch):
        import scripts.check_recall_baseline as mod
        path = self._baseline(tmp_path, [self._cell(0.80)])
        monkeypatch.setattr(mod, "_collect_snapshot",
                            lambda **kw: {"cells": [self._cell(0.76)]})
        assert mod.evaluate_against_baseline(
            baseline_path=path, tolerance=0.05)["status"] == "PASS"

    def test_window_flags_are_inherited_from_the_baseline(self, tmp_path,
                                                          monkeypatch):
        # S5-VERIF-038: both sides must be measured the same way.
        import scripts.check_recall_baseline as mod
        path = self._baseline(tmp_path, [self._cell(0.80)], since=1234.0)
        seen = {}

        def _fake(**kw):
            seen.update(kw)
            return {"cells": [self._cell(0.80)]}

        monkeypatch.setattr(mod, "_collect_snapshot", _fake)
        report = mod.evaluate_against_baseline(baseline_path=path)
        assert seen["since"] == 1234.0
        assert seen["exclude_auto"] is False
        assert report["since"] == 1234.0

    def test_report_is_json_serializable(self, tmp_path, monkeypatch):
        import json

        import scripts.check_recall_baseline as mod
        path = self._baseline(tmp_path, [self._cell(0.80)])
        monkeypatch.setattr(mod, "_collect_snapshot",
                            lambda **kw: {"cells": [self._cell(0.80)]})
        json.dumps(mod.evaluate_against_baseline(baseline_path=path))


class TestDatabaseHandleReuse:
    """G-07 follow-up: once the gate actually works it runs several times a
    day from the calibrators. Constructing a second RadarDB against the
    production file each time means a full PRAGMA integrity_check over
    ~1.9 GB plus a leaked connection."""

    def test_in_app_calls_reuse_the_running_singleton(self, monkeypatch):
        import sys
        import types

        import scripts.check_recall_baseline as mod
        sentinel = object()
        fake = types.ModuleType("radar.database")
        fake.db = sentinel
        monkeypatch.setitem(sys.modules, "radar.database", fake)
        assert mod._shared_db_if_in_app() is sentinel
        assert mod._shared_db_if_in_app("radar/persistence/radar.db") is sentinel

    def test_an_explicit_other_path_is_never_hijacked(self, monkeypatch):
        import sys
        import types

        import scripts.check_recall_baseline as mod
        fake = types.ModuleType("radar.database")
        fake.db = object()
        monkeypatch.setitem(sys.modules, "radar.database", fake)
        assert mod._shared_db_if_in_app("/tmp/other.db") is None

    def test_cli_path_constructs_its_own_handle(self, monkeypatch):
        import sys

        import scripts.check_recall_baseline as mod
        monkeypatch.delitem(sys.modules, "radar.database", raising=False)
        assert mod._shared_db_if_in_app() is None

    def test_the_snapshot_uses_the_handed_over_handle(self, monkeypatch):
        import scripts.check_recall_baseline as mod
        sentinel = object()
        seen = {}
        monkeypatch.setitem(
            __import__("sys").modules, "report_recall_metrics",
            _fake_reporter(seen))
        mod._collect_snapshot(db=sentinel)
        assert seen["db"] is sentinel

    def test_the_in_app_path_does_not_touch_radar_db_path_env(self,
                                                              monkeypatch):
        import os

        import scripts.check_recall_baseline as mod
        monkeypatch.delenv("RADAR_DB_PATH", raising=False)
        monkeypatch.setitem(
            __import__("sys").modules, "report_recall_metrics",
            _fake_reporter({}))
        mod._collect_snapshot(db=object(), db_path="/tmp/should_be_ignored.db")
        assert os.environ.get("RADAR_DB_PATH") is None, \
            "handing over a live handle must not rewrite the process env"


def _fake_reporter(seen):
    """Stand-in for scripts/report_recall_metrics with no DB access."""
    import types
    module = types.ModuleType("report_recall_metrics")

    def collect_metrics(db, *, exclude_auto=False, since=None):
        seen["db"] = db
        return []

    module.collect_metrics = collect_metrics
    return module
