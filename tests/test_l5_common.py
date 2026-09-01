"""WP-1.3 — the shared L5 plumbing (radar/verification/l5_common.py).

Extracted at the third copy from firing_monitor, config_reachability and
window_unit_health. Those three test suites cover it end to end; this one
covers the contract directly, because the pieces that are easy to get
subtly wrong — the append decision table, first_detected_at carry-forward,
and the persistent schedule — are shared by every present and future L5
check. A regression here is a regression everywhere at once.
"""
import json
import os
import time

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.database import RadarDB
from radar.verification import l5_common

CHECK = "unit_test_check"
DAY = 86400.0


@pytest.fixture
def handle(tmp_path):
    return RadarDB(str(tmp_path / "l5common" / "radar.db"))


def _rows(handle, target=None):
    rows = handle.l5_check_latest(CHECK, limit=100)
    return [r for r in rows if target is None or r["target"] == target]


def _row(target, verdict, measured=None, expected=None):
    return {"target": target, "verdict": verdict,
            "measured": measured or {"n": 1}, "expected": expected or {"n": 1}}


# ── the append decision table ───────────────────────────────────────────────
class TestShouldAppend:
    """(verdict, previous, transition_only) -> append?

    Census policy (transition_only=False) writes every non-OK result on
    every run; transition policy writes only changes. Both close an
    episode with exactly one OK row.
    """

    def _decide(self, handle, verdict, transition_only, previous_verdict=None):
        target = f"t_{verdict}_{transition_only}_{previous_verdict}"
        if previous_verdict is not None:
            l5_common.append_result(
                handle, check_id=CHECK, ts=1000.0, target=target,
                verdict=previous_verdict, measured={}, expected={})
        should, _ = l5_common._should_append(  # noqa: SLF001
            handle, CHECK, target, verdict, transition_only)
        return should

    @pytest.mark.parametrize("previous", [None, "ANOMALY", "WARN", "OK"])
    def test_census_always_appends_non_ok(self, handle, previous):
        assert self._decide(handle, "ANOMALY", False, previous) is True

    def test_census_skips_ok_with_no_history(self, handle):
        assert self._decide(handle, "OK", False, None) is False

    def test_census_skips_ok_after_ok(self, handle):
        assert self._decide(handle, "OK", False, "OK") is False

    def test_census_appends_ok_after_non_ok(self, handle):
        assert self._decide(handle, "OK", False, "ANOMALY") is True

    def test_transition_appends_first_sighting(self, handle):
        assert self._decide(handle, "ANOMALY", True, None) is True

    def test_transition_skips_an_unchanged_verdict(self, handle):
        assert self._decide(handle, "ANOMALY", True, "ANOMALY") is False

    def test_transition_appends_a_changed_verdict(self, handle):
        assert self._decide(handle, "WARN", True, "ANOMALY") is True

    def test_transition_skips_ok_with_no_history(self, handle):
        assert self._decide(handle, "OK", True, None) is False

    def test_census_policy_issues_no_lookup_for_non_ok(self, handle):
        # The returned row is _UNSET, not None: "not looked at" must stay
        # distinguishable from "looked, found nothing".
        _, previous = l5_common._should_append(  # noqa: SLF001
            handle, CHECK, "t", "ANOMALY", False)
        assert previous is l5_common._UNSET  # noqa: SLF001

    def test_transition_policy_returns_the_row_it_read(self, handle):
        l5_common.append_result(handle, check_id=CHECK, ts=1000.0, target="t",
                                verdict="WARN", measured={}, expected={})
        _, previous = l5_common._should_append(  # noqa: SLF001
            handle, CHECK, "t", "ANOMALY", True)
        assert previous["verdict"] == "WARN"


# ── first_detected_at ───────────────────────────────────────────────────────
class TestCarryForward:
    def test_first_row_anchors_the_episode(self, handle):
        l5_common.append_result(handle, check_id=CHECK, ts=1000.0, target="t",
                                verdict="ANOMALY", measured={}, expected={})
        assert _rows(handle, "t")[0]["first_detected_at"] == 1000.0

    def test_same_verdict_continues_the_episode(self, handle):
        for ts in (1000.0, 2000.0, 3000.0):
            l5_common.append_result(handle, check_id=CHECK, ts=ts, target="t",
                                    verdict="ANOMALY", measured={}, expected={})
        assert {r["first_detected_at"] for r in _rows(handle, "t")} == {1000.0}

    def test_a_changed_verdict_starts_a_new_episode(self, handle):
        l5_common.append_result(handle, check_id=CHECK, ts=1000.0, target="t",
                                verdict="ANOMALY", measured={}, expected={})
        l5_common.append_result(handle, check_id=CHECK, ts=2000.0, target="t",
                                verdict="OK", measured={}, expected={})
        l5_common.append_result(handle, check_id=CHECK, ts=3000.0, target="t",
                                verdict="ANOMALY", measured={}, expected={})
        newest = _rows(handle, "t")[0]
        assert newest["first_detected_at"] == 3000.0, \
            "a recovered-then-broken target must not inherit the old start"

    def test_supplied_previous_is_used_instead_of_a_query(self, handle):
        # record_results threads the row it already read; passing a stale
        # one must be honoured (that is what makes the optimisation real).
        l5_common.append_result(
            handle, check_id=CHECK, ts=5000.0, target="t", verdict="ANOMALY",
            measured={}, expected={},
            previous={"verdict": "ANOMALY", "first_detected_at": 42.0})
        assert _rows(handle, "t")[0]["first_detected_at"] == 42.0

    def test_explicit_none_previous_means_no_history(self, handle):
        l5_common.append_result(handle, check_id=CHECK, ts=5000.0, target="t",
                                verdict="ANOMALY", measured={}, expected={},
                                previous=None)
        assert _rows(handle, "t")[0]["first_detected_at"] == 5000.0

    def test_payloads_are_json_round_tripped(self, handle):
        l5_common.append_result(handle, check_id=CHECK, ts=1.0, target="t",
                                verdict="WARN", measured={"a": [1, 2]},
                                expected={"b": None})
        row = _rows(handle, "t")[0]
        assert json.loads(row["measured_json"]) == {"a": [1, 2]}
        assert json.loads(row["expected_json"]) == {"b": None}

    def test_unserializable_values_degrade_to_str(self, handle):
        # default=str: a check must never lose its whole run because one
        # measured value was an odd type.
        l5_common.append_result(handle, check_id=CHECK, ts=1.0, target="t",
                                verdict="WARN", measured={"x": {1, 2}},
                                expected={})
        assert "measured_json" in _rows(handle, "t")[0]


# ── record_results ──────────────────────────────────────────────────────────
class TestRecordResults:
    def test_counts_every_result_including_skipped_ones(self, handle):
        counts = l5_common.record_results(
            handle, check_id=CHECK, ts=1.0,
            rows=[_row("a", "ANOMALY"), _row("b", "OK"), _row("c", "OK")])
        assert counts == {"ANOMALY": 1, "WARN": 0, "INSUFFICIENT": 0, "OK": 2}
        assert {r["target"] for r in _rows(handle)} == {"a"}

    def test_transition_policy_writes_once_then_stays_quiet(self, handle):
        rows = [_row("a", "ANOMALY")]
        l5_common.record_results(handle, check_id=CHECK, ts=1.0, rows=rows,
                                 transition_only=True)
        l5_common.record_results(handle, check_id=CHECK, ts=2.0, rows=rows,
                                 transition_only=True)
        assert len(_rows(handle, "a")) == 1

    def test_census_policy_writes_every_run(self, handle):
        rows = [_row("a", "ANOMALY")]
        l5_common.record_results(handle, check_id=CHECK, ts=1.0, rows=rows)
        l5_common.record_results(handle, check_id=CHECK, ts=2.0, rows=rows)
        assert len(_rows(handle, "a")) == 2

    def test_recovery_row_closes_the_episode_under_both_policies(self, handle):
        for policy, target in ((False, "census"), (True, "transition")):
            l5_common.record_results(handle, check_id=CHECK, ts=1.0,
                                     rows=[_row(target, "ANOMALY")],
                                     transition_only=policy)
            l5_common.record_results(handle, check_id=CHECK, ts=2.0,
                                     rows=[_row(target, "OK")],
                                     transition_only=policy)
            assert [r["verdict"] for r in _rows(handle, target)] == \
                ["OK", "ANOMALY"], policy

    def test_empty_run_is_all_zeroes(self, handle):
        assert l5_common.record_results(handle, check_id=CHECK, ts=1.0,
                                        rows=[]) == \
            {"ANOMALY": 0, "WARN": 0, "INSUFFICIENT": 0, "OK": 0}


class TestSummaryVerdict:
    def test_anomaly_dominates(self):
        assert l5_common.summary_verdict(
            {"ANOMALY": 1, "WARN": 9, "OK": 5}) == "ANOMALY"

    def test_warn_when_no_anomaly(self):
        assert l5_common.summary_verdict({"ANOMALY": 0, "WARN": 1}) == "WARN"

    def test_ok_when_quiet(self):
        assert l5_common.summary_verdict({"ANOMALY": 0, "WARN": 0}) == "OK"

    def test_insufficient_alone_is_not_a_warn(self):
        # INSUFFICIENT means "cannot say", which is not itself a finding.
        assert l5_common.summary_verdict(
            {"ANOMALY": 0, "WARN": 0, "INSUFFICIENT": 7}) == "OK"


# ── the persistent schedule (defect F-01) ──────────────────────────────────
class TestRunDailyIfDue:
    def _job(self, handle, calls, **kw):
        return l5_common.run_daily_if_due(
            db_fn=lambda: handle, job_id="unit_test_job",
            run_fn=lambda h, ts: calls.append(ts), **kw)

    def test_first_run_executes_and_schedules(self, handle):
        calls = []
        assert self._job(handle, calls, now_ts=1000.0) is True
        assert calls == [1000.0]
        job = handle.l5_job_get("unit_test_job")
        assert (job["last_run_at"], job["next_run_at"]) == (1000.0, 1000.0 + DAY)

    def test_not_due_is_skipped(self, handle):
        calls = []
        self._job(handle, calls, now_ts=1000.0)
        assert self._job(handle, calls, now_ts=1000.0 + 60) is False
        assert len(calls) == 1

    def test_due_after_the_interval(self, handle):
        calls = []
        self._job(handle, calls, now_ts=1000.0)
        assert self._job(handle, calls, now_ts=1000.0 + DAY + 1) is True

    def test_overdue_runs_immediately_after_a_restart(self, handle):
        # F-01: the volatile `_cycle % 24` counter never compensated, so a
        # process restarting inside 24h skipped the job forever.
        calls = []
        handle.l5_job_set("unit_test_job", last_run_at=0.0, next_run_at=1.0)
        assert self._job(handle, calls, now_ts=10 * DAY) is True

    def test_custom_interval_is_honoured(self, handle):
        self._job(handle, [], now_ts=1000.0, interval_sec=60.0)
        assert handle.l5_job_get("unit_test_job")["next_run_at"] == 1060.0

    def test_a_failing_run_fn_is_contained(self, handle):
        def _boom(h, ts):
            raise RuntimeError("check exploded")
        assert l5_common.run_daily_if_due(
            db_fn=lambda: handle, job_id="unit_test_job", run_fn=_boom,
            now_ts=1000.0) is False

    def test_a_failed_run_does_not_advance_the_schedule(self, handle):
        def _boom(h, ts):
            raise RuntimeError("check exploded")
        l5_common.run_daily_if_due(db_fn=lambda: handle, job_id="unit_test_job",
                                   run_fn=_boom, now_ts=1000.0)
        assert handle.l5_job_get("unit_test_job") is None, \
            "a check that never completed must be retried, not marked done"

    def test_an_unavailable_database_is_contained(self):
        def _broken():
            raise RuntimeError("db down")
        assert l5_common.run_daily_if_due(
            db_fn=_broken, job_id="unit_test_job",
            run_fn=lambda h, ts: None, now_ts=1000.0) is False

    def test_default_clock_is_wall_time(self, handle):
        calls = []
        before = time.time()
        self._job(handle, calls)
        assert before <= calls[0] <= time.time()
