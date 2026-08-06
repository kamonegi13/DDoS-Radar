"""WP-1.3 — window health / unit consistency check (S5-VERIF-007..011).

Two acceptance targets, both still unfixed on purpose (WP-0.2 owns the
repairs; a check written after the fix proves nothing):

  F-06  telegram_mirror caps its rolling baseline at NARRATIVE_BASELINE_DAYS
        *samples* rather than days x cycles-per-day. At a 900 s cadence the
        declared 30-day window is really 7.5 hours, so the z-score
        normalises against the last few hours of itself.
  F-08  gps_jamming compares a ratio in [0,1] against thresholds defaulting
        to 3.0 / 7.0, i.e. a percent scale. The comparison can never be
        true, and fetch health stays green forever.

The check must detect both from the *current* source, and must classify
every catalogued baseline and comparison — including the healthy ones, so
"nothing to say" and "not looked at" stay distinguishable.
"""
import json
import os
import time
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

import radar.config  # noqa: F401  — populates the config registry
from radar import registry
from radar.verification import window_catalog as wc
from radar.verification import window_unit_health as wuh

REPO_ROOT = Path(__file__).resolve().parent.parent
DAY = 86400.0


@pytest.fixture
def wuh_db(l5_tmp_db):
    return l5_tmp_db(wuh, "l5win")


@pytest.fixture
def telegram_baseline_clean():
    """Telegram's baseline is CLASS state — restore it or later tests inherit
    whatever this one appended."""
    from radar.sensors.telegram import TelegramMirrorSensor
    saved = TelegramMirrorSensor._baseline_tg
    TelegramMirrorSensor._baseline_tg = {}
    yield TelegramMirrorSensor
    TelegramMirrorSensor._baseline_tg = saved


def _by_target(results):
    return {r["target"]: r for r in results}


def _window_result(target, results=None):
    rows = results if results is not None else wuh.evaluate_windows()
    return _by_target(rows)[target]


# ── F-06 ACCEPTANCE ─────────────────────────────────────────────────────────
class TestF06Acceptance:
    def test_real_telegram_baseline_caps_at_thirty_samples(
            self, telegram_baseline_clean):
        """Drive the real classmethod — prove the cap is samples, not days."""
        sensor_cls = telegram_baseline_clean
        for _ in range(120):
            sensor_cls._update_baseline_tg("TW", 1.0)
        counts = sensor_cls._baseline_tg["TW"]["daily_counts"]
        assert len(counts) == 30, \
            "cap is NARRATIVE_BASELINE_DAYS raw samples (F-06)"

    def test_real_rss_baseline_caps_at_days_times_cycles(self):
        from radar.sensors.rss_narrative import RssNarrativeSensor
        sensor = RssNarrativeSensor()
        assert sensor.poll_interval == 1800
        for _ in range(2000):
            sensor._update_baseline("TW", 1.0)
        assert len(sensor._baseline["TW"]["daily_counts"]) == 30 * 48, \
            "the 2026-04-29 fix multiplies by cycles_per_day"

    def test_check_reports_anomaly_for_telegram(self):
        result = _window_result("telegram_mirror._baseline_tg")
        assert result["verdict"] == "ANOMALY"
        assert result["reason"] == "window_mismatch"
        assert result["effective_window_h"] == pytest.approx(7.5)
        assert result["declared_window_h"] == pytest.approx(720.0)
        assert result["deviation"] > 0.98

    def test_check_reports_ok_for_rss_narrative(self):
        result = _window_result("rss_narrative._baseline")
        assert result["verdict"] == "OK"
        assert result["effective_window_h"] == pytest.approx(720.0)
        assert result["deviation"] == pytest.approx(0.0)

    def test_telegram_source_is_unmodified(self):
        # Guard: a later session must not 'helpfully' fix F-06 and quietly
        # destroy this acceptance test. WP-0.2 owns the repair.
        src = (REPO_ROOT / "radar" / "sensors" / "telegram.py").read_text(
            encoding="utf-8")
        assert 'bl["daily_counts"] = bl["daily_counts"][-NARRATIVE_BASELINE_DAYS:]' \
            in src, "F-06 must remain unfixed until WP-0.2"

    def test_detection_survives_a_cadence_change(self, monkeypatch):
        # Even at a 30x slower cadence the window is still 10x short, and
        # the number must be recomputed rather than remembered.
        sensor = registry.get("telegram_mirror")
        monkeypatch.setattr(sensor, "poll_interval", 3600)
        result = _window_result("telegram_mirror._baseline_tg")
        assert result["effective_window_h"] == pytest.approx(30.0)
        assert result["verdict"] == "ANOMALY"


# ── F-08 ACCEPTANCE ─────────────────────────────────────────────────────────
class TestF08Acceptance:
    def test_both_gps_thresholds_are_unit_mismatches(self):
        results = _by_target(wuh.evaluate_units())
        for cid in ("gps_jamming.is_jammed", "gps_jamming.is_critical"):
            result = results[cid]
            assert result["verdict"] == "ANOMALY", cid
            assert result["reason"] == "unit_mismatch", cid

    def test_the_percent_scaled_defaults_are_reported(self):
        results = _by_target(wuh.evaluate_units())
        assert results["gps_jamming.is_jammed"]["threshold_value"] == 3.0
        assert results["gps_jamming.is_critical"]["threshold_value"] == 7.0
        assert results["gps_jamming.is_jammed"]["domain"] == ["ratio", 0.0, 1.0]

    def test_partial_overlap_of_the_tunable_range_is_quantified(self):
        # S5-VERIF-009a nuance: min_value 0.5 means part of the tunable
        # range IS reachable — 2.6% of it. Reporting "0%" would be wrong.
        results = _by_target(wuh.evaluate_units())
        jammed = results["gps_jamming.is_jammed"]
        assert jammed["registry_min"] == 0.5 and jammed["registry_max"] == 20.0
        assert jammed["range_overlap_fraction"] == pytest.approx(0.5 / 19.5)
        critical = results["gps_jamming.is_critical"]
        assert critical["range_overlap_fraction"] == 0.0

    def test_all_other_comparisons_are_consistent(self):
        results = _by_target(wuh.evaluate_units())
        offenders = {t: r["reason"] for t, r in results.items()
                     if r["verdict"] == "ANOMALY"}
        assert set(offenders) == {"gps_jamming.is_jammed",
                                  "gps_jamming.is_critical"}

    def test_gps_jamming_source_is_unmodified(self):
        src = (REPO_ROOT / "radar" / "sensors" / "gps_jamming.py").read_text(
            encoding="utf-8")
        assert '"GPS_JAM_THRESHOLD",          "3.0"' in src


# ── S5-VERIF-007: unit annotations ─────────────────────────────────────────
class TestUnitAnnotation:
    def test_bare_threshold_keys_are_warned(self):
        results = _by_target(wuh.evaluate_units())
        assert results["isr_hotspot.surge"]["verdict"] == "WARN"
        assert results["isr_hotspot.surge"]["reason"] == "missing_unit"

    def test_missing_unit_is_recorded_even_on_an_anomaly(self):
        # The GPS keys are unannotated too; the worse verdict wins but the
        # fact must not vanish.
        results = _by_target(wuh.evaluate_units())
        assert results["gps_jamming.is_jammed"]["unit_declared"] == ""

    def test_literal_comparisons_are_not_charged_for_annotations(self):
        results = _by_target(wuh.evaluate_units())
        assert results["notam.surge"]["verdict"] == "OK"

    def test_an_unresolvable_threshold_is_insufficient_not_ok(self, monkeypatch):
        # A registered key whose default is None (or a key that vanished
        # from the registry) cannot be checked for reachability. That is
        # its own state — never a pass (S5-VERIF-006).
        from radar import config_layered
        monkeypatch.setattr(config_layered, "get_meta", lambda key: None)
        result = _by_target(wuh.evaluate_units())["gps_jamming.is_jammed"]
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == wuh.REASON_VALUE_UNKNOWN

    def test_the_unit_insufficient_reason_is_not_the_window_one(self):
        assert wuh.REASON_VALUE_UNKNOWN != wuh.REASON_CADENCE_UNKNOWN


class TestLedgerRowShape:
    """Guard: renaming a result key must break loudly here, not silently
    produce ledger rows with missing fields."""

    def test_window_rows_carry_every_declared_field(self):
        result = _window_result("telegram_mirror._baseline_tg")
        for field in wuh._WINDOW_MEASURED:  # noqa: SLF001
            assert field in result, field
        row = wuh._ledger_row(result)  # noqa: SLF001
        assert set(row["measured"]) == set(wuh._WINDOW_MEASURED)  # noqa: SLF001
        assert set(row["expected"]) == {"declared_window_h", "declared_key",
                                        "deviation_limit"}

    def test_unit_rows_carry_every_declared_field(self):
        result = _by_target(wuh.evaluate_units())["gps_jamming.is_jammed"]
        for field in wuh._UNIT_MEASURED:  # noqa: SLF001
            assert field in result, field
        row = wuh._ledger_row(result)  # noqa: SLF001
        assert set(row["measured"]) == set(wuh._UNIT_MEASURED)  # noqa: SLF001

    def test_unit_required_only_where_a_unit_can_be_declared(self):
        keyed = wuh._ledger_row(  # noqa: SLF001
            _by_target(wuh.evaluate_units())["gps_jamming.is_jammed"])
        literal = wuh._ledger_row(  # noqa: SLF001
            _by_target(wuh.evaluate_units())["notam.surge"])
        assert keyed["expected"]["unit_required"] is True
        assert literal["expected"]["unit_required"] is False

    def test_every_result_serializes_into_a_ledger_row(self):
        for result in wuh.evaluate():
            row = wuh._ledger_row(result)  # noqa: SLF001
            json.dumps(row)


# ── verdict mapping ─────────────────────────────────────────────────────────
class TestWindowVerdicts:
    def test_undeclared_window_is_a_warn(self):
        result = _window_result("check_host._url_latency_history")
        assert (result["verdict"], result["reason"]) == \
            ("WARN", "undeclared_window")
        assert result["effective_window_h"] == pytest.approx(2.0)

    def test_unbounded_baseline_is_a_warn(self):
        result = _window_result("sensor_zscore_stats")
        assert (result["verdict"], result["reason"]) == \
            ("WARN", "unbounded_baseline")

    def test_time_anchored_baselines_are_ok_by_construction(self):
        for baseline_id in ("checkhost_hod", "bgp_hod", "gdelt_dow"):
            result = _window_result(baseline_id)
            assert (result["verdict"], result["reason"]) == \
                ("OK", "bounded_by_construction"), baseline_id

    def test_every_catalogued_baseline_gets_a_verdict(self):
        results = wuh.evaluate_windows()
        assert len(results) == len(wc.CATALOG)
        assert all(r["verdict"] in ("ANOMALY", "WARN", "INSUFFICIENT", "OK")
                   for r in results)

    def test_deviation_within_tolerance_is_ok(self):
        assert wuh.window_verdict(719.0, 720.0)[0] == "OK"
        assert wuh.window_verdict(600.0, 720.0)[0] == "OK"       # 16.7%
        assert wuh.window_verdict(500.0, 720.0)[0] == "ANOMALY"  # 30.6%

    def test_missing_cadence_is_insufficient_not_ok(self, monkeypatch):
        # A sensor that vanished from the registry must not read as healthy.
        monkeypatch.setattr(wc, "sample_interval_sec", lambda spec: None)
        result = _window_result("telegram_mirror._baseline_tg")
        assert result["verdict"] == "INSUFFICIENT"
        assert result["reason"] == "cadence_unknown"


# ── job / ledger / snapshot wiring (logic lives in l5_common) ──────────────
class TestDailyJob:
    def test_run_appends_and_schedules(self, wuh_db):
        now = time.time()
        assert wuh.run_daily_check_if_due(now=now) is True
        job = wuh_db.l5_job_get(wuh.JOB_ID)
        assert job["next_run_at"] == pytest.approx(now + wuh.JOB_INTERVAL_SEC)
        targets = {r["target"] for r in wuh_db.l5_check_latest(wuh.CHECK_ID,
                                                               limit=200)}
        assert wuh.SUMMARY_TARGET in targets
        assert "telegram_mirror._baseline_tg" in targets
        assert "gps_jamming.is_jammed" in targets

    def test_not_due_is_skipped(self, wuh_db):
        now = time.time()
        wuh.run_daily_check_if_due(now=now)
        assert wuh.run_daily_check_if_due(now=now + 60) is False

    def test_overdue_runs_after_a_restart(self, wuh_db):
        now = time.time()
        wuh_db.l5_job_set(wuh.JOB_ID, last_run_at=now - 10 * DAY,
                          next_run_at=now - 9 * DAY)
        assert wuh.run_daily_check_if_due(now=now) is True

    def test_summary_row_counts_both_axes(self, wuh_db):
        wuh.run_daily_check_if_due(now=time.time())
        rows = [r for r in wuh_db.l5_check_latest(wuh.CHECK_ID, limit=200)
                if r["target"] == wuh.SUMMARY_TARGET]
        measured = json.loads(rows[0]["measured_json"])
        assert measured["ANOMALY"] >= 3          # telegram + 2 GPS keys
        assert measured["windows_total"] == len(wc.CATALOG)
        assert measured["comparisons_total"] == len(wc.THRESHOLD_CATALOG)

    def test_failure_is_contained(self, monkeypatch):
        class _Broken:
            def __getattr__(self, name):
                raise RuntimeError("db down")
        monkeypatch.setattr(wuh, "_db", lambda: _Broken())
        assert wuh.run_daily_check_if_due(now=time.time()) is False


class TestSnapshot:
    def test_snapshot_shape(self, wuh_db):
        snap = wuh.snapshot()
        for field in ("job_id", "job_last_run_at", "job_next_run_at",
                      "windows_total", "comparisons_total", "counts",
                      "window_anomalies", "unit_anomalies", "warns"):
            assert field in snap, field

    def test_snapshot_names_both_defects(self, wuh_db):
        snap = wuh.snapshot()
        window_targets = {a["target"] for a in snap["window_anomalies"]}
        unit_targets = {a["target"] for a in snap["unit_anomalies"]}
        assert "telegram_mirror._baseline_tg" in window_targets
        assert {"gps_jamming.is_jammed", "gps_jamming.is_critical"} <= unit_targets

    def test_snapshot_is_json_serializable(self, wuh_db):
        json.dumps(wuh.snapshot())


# ── wiring guards ───────────────────────────────────────────────────────────
class TestWiring:
    def test_scheduler_runs_the_daily_check(self):
        src = (REPO_ROOT / "radar" / "scheduler.py").read_text(encoding="utf-8")
        assert "window_unit_health" in src

    def test_self_eval_exposes_the_block_and_its_error(self):
        src = (REPO_ROOT / "radar" / "routes" / "conclusions_v2.py").read_text(
            encoding="utf-8")
        assert 'out["window_unit_health"]' in src
        assert 'out["window_unit_health_error"]' in src

    def test_intel_guide_documents_the_block(self):
        src = (REPO_ROOT / "index.html").read_text(encoding="utf-8")
        assert "window_unit_health" in src
