"""Tests for radar.observability.followup_watch.

Pins the contract that:
  - run_once evaluates every registered watch
  - a met condition emits exactly one WARN on first observation, INFO
    on subsequent observations until the condition clears
  - a watch raising inside its check() is logged at debug and the
    other watches still run (NP3 — one bad check cannot mask the rest)
  - returned dict shape is {"fired": [...], "skipped": [...], "evaluated": N}
"""
from __future__ import annotations

import logging

import pytest

from radar.observability import followup_watch as fw


@pytest.fixture(autouse=True)
def _reset_cache():
    """Clear the module-level fire cache around every test so order
    independence holds."""
    snap = dict(fw._LAST_FIRED_AT)  # noqa: SLF001
    fw._LAST_FIRED_AT.clear()  # noqa: SLF001
    yield
    fw._LAST_FIRED_AT.clear()  # noqa: SLF001
    fw._LAST_FIRED_AT.update(snap)  # noqa: SLF001


def _patch_watches(monkeypatch, watches: tuple[fw.Watch, ...]):
    """Replace the registry with a deterministic test set."""
    monkeypatch.setattr(fw, "_WATCHES", watches)


def test_no_watches_returns_zero(monkeypatch):
    _patch_watches(monkeypatch, ())
    out = fw.run_once()
    assert out == {"fired": [], "skipped": [], "evaluated": 0}


def test_unmet_condition_does_not_fire(monkeypatch, caplog):
    _patch_watches(monkeypatch, (fw.Watch(
        name="t.unmet", description="-",
        check=lambda: (False, "no signal"),
    ),))
    with caplog.at_level(logging.WARNING):
        out = fw.run_once()
    assert out["fired"] == []
    assert "TRIGGER MET" not in caplog.text


def test_met_condition_warns_first_time(monkeypatch, caplog):
    _patch_watches(monkeypatch, (fw.Watch(
        name="t.met", description="trigger detail",
        check=lambda: (True, "metric=42"),
    ),))
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        out = fw.run_once()
    assert out["fired"] == ["t.met"]
    assert "TRIGGER MET: t.met" in caplog.text
    assert "metric=42" in caplog.text


def test_subsequent_observations_demote_to_info(monkeypatch, caplog):
    _patch_watches(monkeypatch, (fw.Watch(
        name="t.persist", description="-",
        check=lambda: (True, "metric=5"),
    ),))
    # First observation — WARN.
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    caplog.clear()
    # Second observation — must NOT WARN again.
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    assert "TRIGGER MET" not in caplog.text
    # But the INFO heartbeat must surface so silent-cron readers can see it.
    with caplog.at_level(logging.INFO,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    assert "still met: t.persist" in caplog.text


def test_clearing_condition_resets_cache_so_re_warns(monkeypatch, caplog):
    state = {"met": True}
    watch = fw.Watch(
        name="t.flip", description="-",
        check=lambda: (state["met"], "ok"),
    )
    _patch_watches(monkeypatch, (watch,))
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    # Condition clears — cache must reset so future re-trigger WARNs again.
    state["met"] = False
    fw.run_once()
    state["met"] = True
    caplog.clear()
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    assert "TRIGGER MET: t.flip" in caplog.text


def test_failing_check_does_not_block_others(monkeypatch):
    def _boom():
        raise RuntimeError("simulated")
    _patch_watches(monkeypatch, (
        fw.Watch(name="t.boom",  description="-", check=_boom),
        fw.Watch(name="t.ok",    description="-",
                 check=lambda: (True, "yes")),
    ))
    out = fw.run_once()
    assert out["evaluated"] == 2
    assert "t.boom" in out["skipped"]
    assert "t.ok" in out["fired"]


# ── Live wiring sanity (the 4 production checks must be importable
#    and each must return a (bool, str) tuple even on a clean DB) ──


@pytest.mark.parametrize("watch_name", [
    "B1.analyst_feedback_viewer",
    "B5.chronic_chip_details",
    "B7.silent_failures_buckets",
    "B9.alias_gap_editor",
])
def test_production_watch_returns_well_formed_tuple(watch_name):
    matches = [w for w in fw._WATCHES if w.name == watch_name]
    assert len(matches) == 1, f"watch {watch_name} not registered"
    result = matches[0].check()
    assert isinstance(result, tuple) and len(result) == 2
    met, detail = result
    assert isinstance(met, bool)
    assert isinstance(detail, str)
