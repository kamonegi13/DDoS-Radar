"""WP-1.4 — safety-gate liveness + label lineage + the L5 heartbeat.

Three defects, one shape: something that is supposed to protect the
conclusions has quietly stopped participating, and nothing says so.

  G-07  the auto-tune governor's recall gate calls an API that does not
        exist. Its `except Exception` returns False — "not red" — so the
        gate fires its fail-open branch on every single invocation and the
        governor has been unguarded since it shipped.
  G-02  per-user ATTENTION thresholds have a full CRUD API and a table.
        Nothing in the evaluation path reads it. An analyst tunes a knob,
        gets a 200, and changes nothing (the G-15 pattern, attention axis).
  G-08  five recall cells have fn=0 and tn=0, so their recall is 1.0 by
        construction. The gate defends a number that cannot move.
  F-16  the baseline's `since` is null, so comparisons span the two known
        label-series breaks as if they were one continuous history.

None of them is repaired here. This check is the instrument, and the
acceptance tests run against the real governor, the real table and the
real baseline file — a check validated only against synthetic data proves
nothing about the system it is meant to watch.
"""
import json
import os
import sys
import time
import types
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.verification import gate_lineage as gl
from radar.verification import l5_common

REPO_ROOT = Path(__file__).resolve().parent.parent
DAY = 86400.0


@pytest.fixture
def gl_db(l5_tmp_db):
    return l5_tmp_db(gl, "l5gate")


def _by_target(results):
    return {r["target"]: r for r in results}


# ── G-07: the recall gate is dead ──────────────────────────────────────────
class TestGateLivenessRecovery:
    """WP-0.2 restored the missing API, so the probe observes the recovery.
    Dead-gate detection stays proven by TestModuleAttrProbe below, which
    exercises both failure stages against synthetic modules."""

    def test_the_real_recall_gate_now_probes_as_alive(self):
        result = _by_target(gl.evaluate_gates())["gate:auto_tune_recall"]
        assert result["verdict"] == "OK", result["evidence"]
        assert result["reason"] == gl.REASON_GATE_ALIVE

    def test_no_failure_stage_is_recorded(self):
        result = _by_target(gl.evaluate_gates())["gate:auto_tune_recall"]
        assert result["failed_stage"] == ""
        assert result["evidence"] == ""
        assert result["consequence"] == ""

    def test_the_probe_still_declares_what_it_requires(self):
        # The declaration is the contract that made the recovery automatic:
        # the probe never changed, the callee did.
        result = _by_target(gl.evaluate_gates())["gate:auto_tune_recall"]
        assert result["requires"] == \
            "scripts.check_recall_baseline.evaluate_against_baseline"

    def test_the_probe_does_not_call_the_governor(self, monkeypatch):
        # A liveness probe that committed a proposal would write
        # threshold_history — the check must not change what it measures.
        from radar.calibration import auto_tune_governor
        monkeypatch.setattr(auto_tune_governor, "commit", _boom)
        monkeypatch.setattr(auto_tune_governor, "_recall_gate_is_red", _boom)
        gl.evaluate_gates()

    def test_every_declared_gate_is_probed(self):
        results = _by_target(gl.evaluate_gates())
        assert set(results) == {f"gate:{p.gate_id}" for p in gl.GATE_PROBES}

    def test_gate_probes_are_well_formed(self):
        for probe in gl.GATE_PROBES:
            assert probe.gate_id and probe.description and probe.consequence
            assert probe.required_module and probe.required_attr


def _boom(*args, **kwargs):
    raise AssertionError("the liveness probe must not invoke the gate")


class TestModuleAttrProbe:
    def test_a_live_module_and_attribute_pass(self):
        alive, evidence = gl.probe_module_attr("json", "dumps")
        assert alive is True
        assert evidence == ""

    def test_a_missing_module_is_reported_as_the_import_stage(self):
        alive, evidence = gl.probe_module_attr("no_such_module_wp14", "x")
        assert alive is False
        assert "import" in evidence
        assert "no_such_module_wp14" in evidence

    def test_a_missing_attribute_is_reported_as_the_attribute_stage(self):
        alive, evidence = gl.probe_module_attr("json", "no_such_attr_wp14")
        assert alive is False
        assert "attribute" in evidence
        assert "no_such_attr_wp14" in evidence

    def test_a_repaired_gate_flips_to_ok_without_probe_changes(self,
                                                              monkeypatch):
        # WP-0.2 will fix G-07 by making the call site match a real API.
        # Whatever shape that takes, the probe must go green on its own.
        fake = types.ModuleType("wp14_fake_gate_module")
        fake.evaluate_against_baseline = lambda **kw: {"status": "PASS"}
        monkeypatch.setitem(sys.modules, "wp14_fake_gate_module", fake)
        probe = gl.GateProbe(
            gate_id="synthetic", description="synthetic gate",
            required_module="wp14_fake_gate_module",
            required_attr="evaluate_against_baseline",
            consequence="none — test double")
        result = gl._evaluate_gate(probe)  # noqa: SLF001
        assert (result["verdict"], result["reason"]) == \
            ("OK", gl.REASON_GATE_ALIVE)


# ── G-02: dead attention knobs ─────────────────────────────────────────────
class TestAttentionOverrideAcceptance:
    def _insert(self, handle, user_id, rule_id, threshold=0.9):
        conn = handle._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                "INSERT INTO user_attention_thresholds "
                "(user_id, rule_id, threshold, set_at) VALUES (?, ?, ?, ?)",
                (user_id, rule_id, threshold, time.time()))

    def test_no_overrides_is_ok_with_a_note(self, gl_db):
        results = _by_target(gl.evaluate_attention_overrides())
        result = results["attention_overrides"]
        assert (result["verdict"], result["reason"]) == \
            ("OK", gl.REASON_NO_OVERRIDES)

    def test_a_stored_override_is_an_anomaly(self, gl_db):
        from radar import attention
        rule_id = attention.all_rules()[0].rule_id
        self._insert(gl_db, 7, rule_id)
        result = _by_target(gl.evaluate_attention_overrides())[
            f"attention_override:7:{rule_id}"]
        assert result["verdict"] == "ANOMALY"
        assert result["reason"] == gl.REASON_OVERRIDE_INEFFECTIVE
        assert result["threshold"] == 0.9

    def test_an_unknown_rule_id_is_a_stale_override(self, gl_db):
        self._insert(gl_db, 7, "rule_that_no_longer_exists")
        result = _by_target(gl.evaluate_attention_overrides())[
            "attention_override:7:rule_that_no_longer_exists"]
        assert result["reason"] == gl.REASON_STALE_OVERRIDE
        assert result["verdict"] == "ANOMALY"

    def test_deleting_the_override_restores_ok(self, gl_db):
        from radar import attention
        rule_id = attention.all_rules()[0].rule_id
        self._insert(gl_db, 7, rule_id)
        conn = gl_db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute("DELETE FROM user_attention_thresholds")
        results = _by_target(gl.evaluate_attention_overrides())
        assert results["attention_overrides"]["verdict"] == "OK"

    def test_every_override_row_gets_its_own_target(self, gl_db):
        from radar import attention
        rules = attention.all_rules()
        self._insert(gl_db, 1, rules[0].rule_id)
        self._insert(gl_db, 2, rules[1].rule_id)
        results = gl.evaluate_attention_overrides()
        assert len(results) == 2
        assert len({r["target"] for r in results}) == 2

    def test_db_failure_is_insufficient_not_ok(self, monkeypatch):
        monkeypatch.setattr(gl, "_db", lambda: _BrokenDB())
        result = _by_target(gl.evaluate_attention_overrides())[
            "attention_overrides"]
        assert result["verdict"] == "INSUFFICIENT"


class _BrokenDB:
    def __getattr__(self, name):
        raise RuntimeError("db down")


# ── G-08 / F-16: recall lineage ────────────────────────────────────────────
DEGENERATE_TARGETS = {
    "recall_cell:eastern_europe:attack_mode",
    "recall_cell:eastern_europe:threat_level",
    "recall_cell:korean_peninsula:attack_mode",
    "recall_cell:middle_east:attack_mode",
    "recall_cell:taiwan_contingency:attack_mode",
}


class TestRecallLineageAcceptance:
    def test_the_real_baseline_has_exactly_five_degenerate_cells(self):
        results = gl.evaluate_recall_lineage()
        degenerate = {r["target"] for r in results
                      if r["reason"] == gl.REASON_DEGENERATE}
        assert degenerate == DEGENERATE_TARGETS, \
            "S5-VERIF-037 corrected 4 -> 5 on 2026-08-06"

    def test_a_cell_with_one_true_negative_is_not_degenerate(self):
        # middle_east/threat_level has fn=0 but tn=1 — recall is not
        # structurally pinned, so it must not be accused.
        targets = {r["target"] for r in gl.evaluate_recall_lineage()}
        assert "recall_cell:middle_east:threat_level" not in targets

    def test_degenerate_cells_are_anomalies_carrying_their_counts(self):
        results = _by_target(gl.evaluate_recall_lineage())
        cell = results["recall_cell:eastern_europe:threat_level"]
        assert cell["verdict"] == "ANOMALY"
        assert (cell["fn"], cell["tn"], cell["recall"]) == (0, 0, 1.0)

    def test_null_since_is_the_unbounded_series_defect(self):
        result = _by_target(gl.evaluate_recall_lineage())["recall_series_window"]
        assert result["verdict"] == "ANOMALY"
        assert result["reason"] == gl.REASON_UNBOUNDED
        assert result["since"] is None

    def test_absent_epoch_field_is_a_structural_warn(self):
        result = _by_target(gl.evaluate_recall_lineage())["recall_epoch_field"]
        assert (result["verdict"], result["reason"]) == \
            ("WARN", gl.REASON_NO_EPOCH)

    def test_detection_is_by_predicate_not_by_count(self, tmp_path):
        # The corrected clause says so explicitly: a hardcoded 5 would rot
        # the moment the baseline is refreshed.
        path = tmp_path / "b.json"
        path.write_text(json.dumps({
            "since": 1.0, "schema_version": 1, "cells": [
                {"scenario_id": "s", "conclusion_type": "c", "fn": 0, "tn": 0,
                 "recall": 1.0},
                {"scenario_id": "s2", "conclusion_type": "c", "fn": 0,
                 "tn": 1, "recall": 1.0},
                {"scenario_id": "s3", "conclusion_type": "c", "fn": 2,
                 "tn": 0, "recall": 0.5},
            ]}), encoding="utf-8")
        results = gl.evaluate_recall_lineage(path=path)
        degenerate = [r for r in results if r["reason"] == gl.REASON_DEGENERATE]
        assert [r["target"] for r in degenerate] == ["recall_cell:s:c"]

    def test_a_bounded_series_is_ok(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps(
            {"since": 1_700_000_000.0, "cells": []}), encoding="utf-8")
        result = _by_target(gl.evaluate_recall_lineage(path=path))[
            "recall_series_window"]
        assert result["verdict"] == "OK"

    def test_an_epoch_field_satisfies_the_lineage_requirement(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps(
            {"since": 1.0, "epoch_id": "e1", "cells": []}), encoding="utf-8")
        result = _by_target(gl.evaluate_recall_lineage(path=path))[
            "recall_epoch_field"]
        assert result["verdict"] == "OK"

    def test_a_missing_baseline_is_insufficient_not_ok(self, tmp_path):
        results = _by_target(gl.evaluate_recall_lineage(
            path=tmp_path / "absent.json"))
        result = results["recall_baseline"]
        assert (result["verdict"], result["reason"]) == \
            ("INSUFFICIENT", gl.REASON_BOOTSTRAP)
        assert len(results) == 1, "do not fabricate findings from no data"

    def test_unreadable_baseline_is_insufficient(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text("{not json", encoding="utf-8")
        result = _by_target(gl.evaluate_recall_lineage(path=path))[
            "recall_baseline"]
        assert result["verdict"] == "INSUFFICIENT"

    @pytest.mark.parametrize("cells", [None, {}, "cells", 7])
    def test_a_non_list_cells_field_degrades_instead_of_crashing(
            self, tmp_path, cells):
        # `"cells": null` used to raise TypeError inside the daily job,
        # taking down the whole check rather than one finding.
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"since": 1.0, "cells": cells}),
                        encoding="utf-8")
        results = _by_target(gl.evaluate_recall_lineage(path=path))
        assert results["recall_baseline"]["verdict"] == "INSUFFICIENT"
        assert results["recall_baseline"]["reason"] == gl.REASON_BOOTSTRAP

    def test_non_dict_cell_entries_are_skipped_not_fatal(self, tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"since": 1.0, "cells": [
            None, "junk", 42,
            {"scenario_id": "s", "conclusion_type": "c", "fn": 0, "tn": 0,
             "recall": 1.0},
        ]}), encoding="utf-8")
        results = gl.evaluate_recall_lineage(path=path)
        degenerate = [r for r in results if r["reason"] == gl.REASON_DEGENERATE]
        assert [r["target"] for r in degenerate] == ["recall_cell:s:c"]

    def test_the_daily_job_survives_a_malformed_baseline(self, gl_db,
                                                         monkeypatch,
                                                         tmp_path):
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"cells": None}), encoding="utf-8")
        monkeypatch.setattr(gl, "RECALL_BASELINE_PATH", path)
        assert gl.run_daily_check_if_due(now=time.time()) is True


# ── the L5 heartbeat ───────────────────────────────────────────────────────
EXPECTED_JOBS = {
    "firing_liveness_daily",
    "config_reachability_daily",
    "window_unit_health_daily",
    "gate_lineage_daily",
    "ops_health_daily",
}


class TestHeartbeat:
    def test_all_known_checks_register_themselves(self):
        # Superset, not equality: _KNOWN_JOBS is a session-lifetime global,
        # so another test registering a throwaway job must not break this
        # one depending on execution order.
        from radar.verification import (config_reachability, firing_monitor,  # noqa: F401
                                        ops_health, window_unit_health)
        assert EXPECTED_JOBS <= {j.job_id for j in l5_common.known_jobs()}

    def test_every_scheduled_check_registers_itself(self):
        # Discovery rather than a reload sandbox: find every module in
        # radar.verification that declares a JOB_ID, and require each to
        # have registered. A fifth check fails this the moment it lands —
        # either because EXPECTED_JOBS is stale or because it forgot to
        # call register_job.
        # Caveat: registration happens at import, so the heartbeat's
        # "cannot vanish" guarantee covers checks the scheduler or
        # self_eval imports (see the ordering note in v2_self_eval).
        import importlib
        import pkgutil

        from radar import verification
        declared = set()
        for module_info in pkgutil.iter_modules(verification.__path__):
            module = importlib.import_module(
                f"radar.verification.{module_info.name}")
            job_id = getattr(module, "JOB_ID", None)
            if job_id:
                declared.add(job_id)
        assert declared == EXPECTED_JOBS
        assert declared <= {j.job_id for j in l5_common.known_jobs()}, \
            "a check declares a JOB_ID but never calls register_job"

    def test_registered_jobs_carry_a_label_and_interval(self):
        for job in l5_common.known_jobs():
            assert job.label and job.interval_sec > 0

    def test_a_job_that_never_ran_is_insufficient(self, gl_db):
        snap = l5_common.heartbeat_snapshot(now=time.time())
        states = {j["job_id"]: j for j in snap["jobs"]}
        assert states["gate_lineage_daily"]["verdict"] == "INSUFFICIENT"
        assert states["gate_lineage_daily"]["reason"] == "never_ran"

    def test_a_fresh_job_is_ok(self, gl_db):
        now = time.time()
        gl_db.l5_job_set("gate_lineage_daily", last_run_at=now - 60,
                         next_run_at=now + DAY)
        snap = l5_common.heartbeat_snapshot(now=now)
        states = {j["job_id"]: j for j in snap["jobs"]}
        assert states["gate_lineage_daily"]["verdict"] == "OK"

    def test_a_job_silent_past_two_intervals_is_stale(self, gl_db):
        now = time.time()
        gl_db.l5_job_set("gate_lineage_daily", last_run_at=now - 3 * DAY,
                         next_run_at=now - 2 * DAY)
        snap = l5_common.heartbeat_snapshot(now=now)
        states = {j["job_id"]: j for j in snap["jobs"]}
        assert states["gate_lineage_daily"]["verdict"] == "WARN"
        assert states["gate_lineage_daily"]["reason"] == "l5_job_stale"

    def test_one_interval_of_silence_is_still_ok(self, gl_db):
        now = time.time()
        gl_db.l5_job_set("gate_lineage_daily", last_run_at=now - 1.5 * DAY,
                         next_run_at=now - 0.5 * DAY)
        snap = l5_common.heartbeat_snapshot(now=now)
        states = {j["job_id"]: j for j in snap["jobs"]}
        assert states["gate_lineage_daily"]["verdict"] == "OK"

    def test_overall_verdict_is_the_worst_present(self, gl_db):
        now = time.time()
        for job_id in EXPECTED_JOBS:
            gl_db.l5_job_set(job_id, last_run_at=now - 60, next_run_at=now + DAY)
        assert l5_common.heartbeat_snapshot(now=now)["verdict"] == "OK"
        gl_db.l5_job_set("gate_lineage_daily", last_run_at=now - 5 * DAY,
                         next_run_at=now)
        assert l5_common.heartbeat_snapshot(now=now)["verdict"] == "WARN"

    def test_a_db_row_for_an_unregistered_job_still_appears(self, gl_db):
        now = time.time()
        gl_db.l5_job_set("some_future_check_daily", last_run_at=now,
                         next_run_at=now + DAY)
        ids = {j["job_id"] for j in l5_common.heartbeat_snapshot(now=now)["jobs"]}
        assert "some_future_check_daily" in ids

    def test_heartbeat_degrades_to_unknown_on_db_failure(self, monkeypatch):
        monkeypatch.setattr(l5_common, "db", lambda: _BrokenDB())
        snap = l5_common.heartbeat_snapshot(now=time.time())
        assert snap["verdict"] == "UNKNOWN"

    def test_heartbeat_is_json_serializable(self, gl_db):
        json.dumps(l5_common.heartbeat_snapshot(now=time.time()))


# ── job / ledger / snapshot ────────────────────────────────────────────────
class TestDailyJob:
    def test_run_appends_and_schedules(self, gl_db):
        now = time.time()
        assert gl.run_daily_check_if_due(now=now) is True
        job = gl_db.l5_job_get(gl.JOB_ID)
        assert job["next_run_at"] == pytest.approx(now + gl.JOB_INTERVAL_SEC)
        targets = {r["target"]
                   for r in gl_db.l5_check_latest(gl.CHECK_ID, limit=200)}
        # The gate is OK now, so it is not appended; the lineage findings
        # remain (G-08 / F-16 are analyst-operations work, not WP-0.2).
        assert "gate:auto_tune_recall" not in targets
        assert DEGENERATE_TARGETS <= targets
        assert l5_common.SUMMARY_TARGET in targets

    def test_stable_findings_do_not_repeat_daily(self, gl_db):
        now = time.time()
        gl.run_daily_check_if_due(now=now)
        before = len(gl_db.l5_check_latest(gl.CHECK_ID, limit=500))
        gl.run_daily_check_if_due(now=now + DAY)
        after = gl_db.l5_check_latest(gl.CHECK_ID, limit=500)
        assert len(after) == before + 1, "only the summary row should recur"
        assert after[0]["target"] == l5_common.SUMMARY_TARGET

    def test_not_due_is_skipped(self, gl_db):
        now = time.time()
        gl.run_daily_check_if_due(now=now)
        assert gl.run_daily_check_if_due(now=now + 60) is False

    def test_failure_is_contained(self, monkeypatch):
        monkeypatch.setattr(gl, "_db", lambda: _BrokenDB())
        assert gl.run_daily_check_if_due(now=time.time()) is False


class TestSnapshot:
    def test_snapshot_shape(self, gl_db):
        snap = gl.snapshot()
        for field in ("job_id", "job_last_run_at", "job_next_run_at", "counts",
                      "dead_gates", "ineffective_overrides", "degenerate_cells",
                      "lineage_findings"):
            assert field in snap, field

    def test_snapshot_reflects_the_gate_recovery(self, gl_db):
        snap = gl.snapshot()
        assert snap["dead_gates"] == [], "WP-0.2 restored the recall gate"
        assert len(snap["degenerate_cells"]) == 5
        reasons = {f["reason"] for f in snap["lineage_findings"]}
        assert gl.REASON_UNBOUNDED in reasons
        assert gl.REASON_NO_EPOCH in reasons

    def test_snapshot_is_json_serializable(self, gl_db):
        json.dumps(gl.snapshot())

    def test_a_failed_job_lookup_is_named_not_mistaken_for_never_ran(
            self, monkeypatch):
        # Two nulls mean "never ran"; a failed query must not borrow that
        # shape (S5-VERIF-006), and this file already models it correctly
        # for the override axis.
        monkeypatch.setattr(gl, "_db", lambda: _BrokenDB())
        snap = gl.snapshot()
        assert "job_lookup_error" in snap
        assert snap["job_lookup_error"]
        assert snap["job_last_run_at"] is None

    def test_a_healthy_lookup_carries_no_error_key(self, gl_db):
        assert "job_lookup_error" not in gl.snapshot()


# ── wiring guards ───────────────────────────────────────────────────────────
class TestWiring:
    def test_scheduler_runs_the_daily_check(self):
        src = (REPO_ROOT / "radar" / "scheduler.py").read_text(encoding="utf-8")
        assert "gate_lineage" in src

    def test_self_eval_exposes_the_block_and_its_error(self):
        src = (REPO_ROOT / "radar" / "routes" / "conclusions_v2.py").read_text(
            encoding="utf-8")
        assert 'out["gate_lineage"]' in src
        assert 'out["gate_lineage_error"]' in src

    def test_self_eval_exposes_the_heartbeat(self):
        src = (REPO_ROOT / "radar" / "routes" / "conclusions_v2.py").read_text(
            encoding="utf-8")
        assert 'out["l5_heartbeat"]' in src
        assert 'out["l5_heartbeat_error"]' in src

    def test_intel_guide_documents_both(self):
        src = (REPO_ROOT / "index.html").read_text(encoding="utf-8")
        assert "gate_lineage" in src
        assert "l5_heartbeat" in src

    def test_s5_clause_records_the_corrected_count(self):
        src = (REPO_ROOT / "docs" / "design" / "v3"
               / "S5-verification.md").read_text(encoding="utf-8")
        assert "8 cell 中 5 件" in src
        assert "eastern_europe" in src

    def test_no_stale_degenerate_count_survives_anywhere(self):
        # The 4-cell figure appeared in two clauses and a defect row; a
        # partial correction is worse than none, because the surviving copy
        # reads as authoritative.
        for rel in (("docs", "design", "v3", "S5-verification.md"),
                    ("docs", "design", "v3", "D2-defects.md")):
            src = REPO_ROOT.joinpath(*rel).read_text(encoding="utf-8")
            assert "8 cell 中 4 件" not in src, rel

    def test_cut07_is_recorded_as_currently_failing(self):
        src = (REPO_ROOT / "docs" / "design" / "v3"
               / "S5-verification.md").read_text(encoding="utf-8")
        assert "CUT-07" in src and "不合格" in src
