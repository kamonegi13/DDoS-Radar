"""WP-1.3 — window health / unit consistency check (S5-VERIF-007..011).

Two acceptance targets, both repaired by WP-0.2 on 2026-08-07:

  F-06  telegram_mirror capped its rolling baseline at
        NARRATIVE_BASELINE_DAYS *samples* rather than days x
        cycles-per-day. At a 900 s cadence the declared 30-day window was
        really 7.5 hours, so the z-score normalised against the last few
        hours of itself.
  F-08  gps_jamming compared a ratio in [0,1] against thresholds
        defaulting to 3.0 / 7.0, i.e. a percent scale. The comparison
        could never be true, and fetch health stayed green throughout.

Each defect now has a paired class: `...Recovery` asserts the live system
reads healthy on that axis, and `...DetectionCapability` re-proves the
checker against a synthetic replica of the pre-fix shape. The pairing is
the point — an acceptance test that only ever ran against a live defect
would stop meaning anything the moment the defect was fixed, and the
check would quietly become unverifiable.

The check must classify every catalogued baseline and comparison —
including the healthy ones, so "nothing to say" and "not looked at" stay
distinguishable.
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
class TestF06Recovery:
    """WP-0.2 repaired F-06. These now assert the RECOVERY; the detector's
    ability to catch the defect class is preserved by the synthetic spec in
    TestF06DetectionCapability below — a check that can only be validated
    against a live defect stops being validatable the moment it succeeds."""

    def test_real_telegram_baseline_now_holds_the_declared_window(
            self, telegram_baseline_clean):
        sensor_cls = telegram_baseline_clean
        for _ in range(3000):
            sensor_cls._update_baseline_tg("TW", 1.0)
        counts = sensor_cls._baseline_tg["TW"]["daily_counts"]
        assert len(counts) == 30 * 96, "days x cycles_per_day at 900 s"

    def test_real_rss_baseline_caps_at_days_times_cycles(self):
        from radar.sensors.rss_narrative import RssNarrativeSensor
        sensor = RssNarrativeSensor()
        assert sensor.poll_interval == 1800
        for _ in range(2000):
            sensor._update_baseline("TW", 1.0)
        assert len(sensor._baseline["TW"]["daily_counts"]) == 30 * 48, \
            "the 2026-04-29 fix multiplies by cycles_per_day"

    def test_check_now_reports_ok_for_telegram(self):
        # L5 observing the recovery: the window that read 7.5 h now reads
        # 720 h and the axis goes green without the check changing.
        result = _window_result("telegram_mirror._baseline_tg")
        assert result["verdict"] == "OK"
        assert result["effective_window_h"] == pytest.approx(720.0)
        assert result["declared_window_h"] == pytest.approx(720.0)
        assert result["deviation"] == pytest.approx(0.0)

    def test_check_reports_ok_for_rss_narrative(self):
        result = _window_result("rss_narrative._baseline")
        assert result["verdict"] == "OK"
        assert result["effective_window_h"] == pytest.approx(720.0)
        assert result["deviation"] == pytest.approx(0.0)

    def test_telegram_source_carries_the_fix(self):
        # Guard, inverted: the repair must not be reverted, and the old
        # sample-count cap must not reappear.
        src = (REPO_ROOT / "radar" / "sensors" / "telegram.py").read_text(
            encoding="utf-8")
        assert 'bl["daily_counts"] = bl["daily_counts"][-cap:]' in src
        assert "cycles_per_day" in src
        assert 'bl["daily_counts"][-NARRATIVE_BASELINE_DAYS:]' not in src

    def test_recovery_survives_a_cadence_change(self):
        # The repaired cap is derived from the cadence, so a slower poll
        # keeps the window at 30 days instead of stretching it.
        spec = next(s for s in wc.CATALOG
                    if s.baseline_id == "telegram_mirror._baseline_tg")
        assert wc.effective_window_hours(spec, 3600) == pytest.approx(720.0)
        assert wc.effective_window_hours(spec, 300) == pytest.approx(720.0)


class TestF06DetectionCapability:
    """The detector still catches the defect class, proven against a
    synthetic replica of the pre-fix shape rather than the live sensor."""

    def _broken_spec(self):
        return wc.WindowSpec(
            baseline_id="synthetic_broken._baseline", sensor="telegram_mirror",
            kind=wc.KIND_ROLLING_LIST, cap_mode=wc.CAP_FIXED, cap_value=30,
            declared_days=30, declared_key="NARRATIVE_BASELINE_DAYS",
            note="Replica of telegram's pre-WP-0.2 cap (F-06).")

    def test_a_sample_capped_baseline_is_still_an_anomaly(self, monkeypatch):
        spec = self._broken_spec()
        monkeypatch.setattr(wc, "CATALOG", (spec,))
        result = _window_result("synthetic_broken._baseline")
        assert result["verdict"] == "ANOMALY"
        assert result["reason"] == "window_mismatch"
        assert result["effective_window_h"] == pytest.approx(7.5)
        assert result["deviation"] > 0.98

    def test_the_pre_fix_arithmetic_is_unchanged(self):
        spec = self._broken_spec()
        assert wc.cap_samples(spec, 900) == 30
        assert wc.effective_window_hours(spec, 900) == pytest.approx(7.5)


# ── F-08 ACCEPTANCE ─────────────────────────────────────────────────────────
class TestF08Recovery:
    """WP-0.2 repaired F-08; the unit axis observes it. Detection capability
    for the class is preserved by TestF08DetectionCapability below."""

    def test_both_gps_thresholds_are_now_consistent(self):
        results = _by_target(wuh.evaluate_units())
        for cid in ("gps_jamming.is_jammed", "gps_jamming.is_critical"):
            result = results[cid]
            assert result["verdict"] == "OK", cid
            assert result["reason"] == "unit_consistent", cid

    def test_the_ratio_scaled_defaults_are_reported(self):
        results = _by_target(wuh.evaluate_units())
        assert results["gps_jamming.is_jammed"]["threshold_value"] == 0.03
        assert results["gps_jamming.is_critical"]["threshold_value"] == 0.07
        assert results["gps_jamming.is_jammed"]["domain"] == ["ratio", 0.0, 1.0]

    def test_the_whole_tunable_range_is_reachable(self):
        # Was 2.6% (min 0.5, max 20.0) and 0% (min 1.0, max 30.0); the
        # rescaled ranges sit entirely inside the [0,1] domain.
        results = _by_target(wuh.evaluate_units())
        jammed = results["gps_jamming.is_jammed"]
        assert jammed["registry_min"] == 0.005 and jammed["registry_max"] == 0.2
        assert jammed["range_overlap_fraction"] == 1.0
        assert results["gps_jamming.is_critical"]["range_overlap_fraction"] == 1.0

    def test_no_comparison_is_anomalous_any_more(self):
        results = _by_target(wuh.evaluate_units())
        offenders = {t: r["reason"] for t, r in results.items()
                     if r["verdict"] == "ANOMALY"}
        assert offenders == {}

    def test_gps_jamming_source_carries_the_fix(self):
        src = (REPO_ROOT / "radar" / "sensors" / "gps_jamming.py").read_text(
            encoding="utf-8")
        assert '"GPS_JAM_THRESHOLD",          "0.03"' in src
        assert '"GPS_JAM_CRITICAL_THRESHOLD", "0.07"' in src


class TestF08DetectionCapability:
    """The unit checker still catches a percent-vs-ratio comparison, proven
    against a synthetic replica of the pre-fix declaration."""

    def _broken_spec(self):
        return wc.ThresholdComparisonSpec(
            comparison_id="synthetic.percent_vs_ratio", sensor="gps_jamming",
            domain_kind="ratio", domain_lo=0.0, domain_hi=1.0,
            threshold_key="SYNTHETIC_PERCENT_THRESHOLD",
            note="Replica of the pre-WP-0.2 GPS declaration (F-08).")

    def test_a_percent_threshold_on_a_ratio_domain_is_an_anomaly(
            self, monkeypatch):
        from radar import config_layered
        meta = config_layered.ConfigKey(
            key="SYNTHETIC_PERCENT_THRESHOLD", domain="test", default=3.0,
            type_="float", min_value=0.5, max_value=20.0)
        monkeypatch.setattr(config_layered, "get_meta",
                            lambda key: meta if key == meta.key else None)
        monkeypatch.setattr(wc, "THRESHOLD_CATALOG", (self._broken_spec(),))
        result = _by_target(wuh.evaluate_units())["synthetic.percent_vs_ratio"]
        assert result["verdict"] == "ANOMALY"
        assert result["reason"] == "unit_mismatch"
        assert result["range_overlap_fraction"] == pytest.approx(0.5 / 19.5)


# ── S5-VERIF-007: unit annotations ─────────────────────────────────────────
class TestUnitAnnotation:
    def test_bare_threshold_keys_are_warned(self):
        results = _by_target(wuh.evaluate_units())
        assert results["isr_hotspot.surge"]["verdict"] == "WARN"
        assert results["isr_hotspot.surge"]["reason"] == "missing_unit"

    def test_the_repaired_keys_now_declare_their_unit(self):
        # S5-VERIF-007: the absent annotation is how F-08's scale error
        # stayed invisible. WP-0.2 added it to both GPS keys; the rest of
        # the compared thresholds are still bare.
        results = _by_target(wuh.evaluate_units())
        assert results["gps_jamming.is_jammed"]["unit_declared"] == "ratio"
        assert results["isr_hotspot.surge"]["unit_declared"] == ""

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
        # Standing non-OK findings from both axes. telegram is deliberately
        # absent: WP-0.2 repaired it, and OK results are not appended.
        assert "sensor_zscore_stats" in targets      # WARN unbounded
        assert "isr_hotspot.surge" in targets         # WARN missing_unit
        # Both WP-0.2 repairs are absent: OK results are not appended.
        assert "telegram_mirror._baseline_tg" not in targets
        assert "gps_jamming.is_jammed" not in targets

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
        assert measured["ANOMALY"] == 0, \
            "both WP-0.2 repairs landed — nothing should be anomalous"
        assert measured["WARN"] >= 2             # check_host + zscore_stats
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

    def test_snapshot_shows_both_axes_recovered(self, wuh_db):
        # The WP-0.2 endpoint state: F-06 and F-08 both repaired, so the
        # anomaly lists are empty while the standing WARNs remain.
        snap = wuh.snapshot()
        assert snap["window_anomalies"] == []
        assert snap["unit_anomalies"] == []
        assert snap["counts"]["ANOMALY"] == 0
        assert snap["counts"]["WARN"] >= 2

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
