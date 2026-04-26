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

_REPO_ROOT = Path(__file__).resolve().parent
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


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
