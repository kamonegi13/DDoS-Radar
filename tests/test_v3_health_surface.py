"""G-17 at the container layer: HEALTHY over a system that concluded nothing.

The shadow container reported `healthy` for its whole run. `docker ps` said
healthy, `/healthz` answered 200 with `{"status": "ok"}`, and not one tick
had ever completed — every one of them died at its first write and
`tl_observation` was empty the whole time. An operator watching the
orchestrator saw green over a tool that had produced nothing.

That is G-17's exact shape, reproduced one layer up:

    SALUTE and the weather brief return 200 with ROUTINE/CLEAR/NORMAL even
    when the scoring cache is empty, so total data loss and a genuinely
    calm world are indistinguishable.

`read_health` was three literals — `{"status": "ok", "ledger_reachable":
True}` — so the endpoint could not have said anything else. It was not
reading anything.

What this file pins down:

  * the loop's own counters are a MEASUREMENT (`v3/runtime/loop.py`): when
    the last successful tick was, how many failures since, and what the
    last one said;
  * `ops_health` carries them as a fifth monitor, so the fact reaches the
    health probe AND the AP3 self-evaluation from ONE place rather than
    from a mechanism bolted onto the healthcheck (`tick_loop`);
  * `/healthz` distinguishes "the process is up" from "the loop is
    producing", and its HTTP code says which — including the NP5+8 case,
    where "not yet determinable" is a first-class answer that is neither
    `ok` nor a failure;
  * the compose healthcheck asserts the LOOP, because a probe that only
    asserts the process is the probe that reported healthy throughout.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from v3.api import ApiRequest, ReadContext, ReadOnlyLedger, handle
from v3.api.handlers import disclosure as D
from v3.api.request import ANONYMOUS
from v3.ledger import LedgerStore
from v3.runtime import ops_health as O
from v3.runtime.loop import Runtime

NOW = 1_800_000_000.0
INTERVAL = 60.0
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "v3.db"))
    yield instance
    instance.close()


def _healthz(store, *, ops=None, now=NOW):
    return handle(ApiRequest(method="GET", path="/healthz",
                             principal=ANONYMOUS),
                  ReadContext(ledger=ReadOnlyLedger(store), now=now,
                              ops_health=ops))


def _status(loop_status, *, now=NOW, interval_sec=INTERVAL):
    return O.loop_monitor(loop_status, now=now, interval_sec=interval_sec)


def _running(**overrides) -> dict:
    base = {"running": True, "ticks": 10, "errors": 0,
            "last_tick_at": NOW - 5.0, "last_error": "",
            "last_error_at": None, "consecutive_errors": 0,
            "started_at": NOW - 3600.0}
    base.update(overrides)
    return base


# ── 1. the loop measures itself ───────────────────────────────────────────
class TestTheLoopKnowsWhetherItIsProducing:
    """`LoopStatus` had the count and the message but not the CLOCK.

    A count of errors cannot distinguish "one bad tick an hour ago, fine
    since" from "every tick since boot", and those are opposite
    operational facts. `last_tick_at` was already the last SUCCESSFUL
    tick — `run_once` advances it only after the tick returns — so the
    missing halves are when the last failure was and how many have run
    together since the last success.
    """

    def test_a_fresh_runtime_has_never_started_and_never_succeeded(self):
        status = Runtime(lambda now: None, clock=lambda: NOW).status()
        assert status.started_at is None
        assert status.last_tick_at is None
        assert status.consecutive_errors == 0

    def test_start_records_when(self):
        runtime = Runtime(lambda now: None, interval_sec=0.01,
                          clock=lambda: NOW)
        with runtime:
            assert runtime.status().started_at == NOW
        runtime.stop(timeout_sec=5)

    def test_a_failure_records_its_instant_and_runs_a_streak(self):
        runtime = Runtime(lambda now: 1 / 0, clock=lambda: NOW)
        for _ in range(3):
            with pytest.raises(ZeroDivisionError):
                runtime.run_once()

        status = runtime.status()
        assert status.errors == 3
        assert status.consecutive_errors == 3
        assert status.last_error_at == NOW
        assert status.last_tick_at is None, \
            "a tick that raised is not a tick that produced"

    def test_a_success_ends_the_streak_but_not_the_total(self):
        outcomes = iter([ValueError("nope"), None])

        def tick(now):
            result = next(outcomes)
            if result is not None:
                raise result

        runtime = Runtime(tick, clock=lambda: NOW)
        with pytest.raises(ValueError):
            runtime.run_once()
        runtime.run_once()

        status = runtime.status()
        assert status.errors == 1, "the total is history and does not reset"
        assert status.consecutive_errors == 0, \
            "the streak is the live fact and it ended"
        assert status.last_tick_at == NOW

    def test_the_dict_carries_every_field(self):
        payload = Runtime(lambda now: None, clock=lambda: NOW).status(
        ).as_dict()
        for key in ("running", "ticks", "errors", "last_tick_at",
                    "last_error", "last_error_at", "consecutive_errors",
                    "started_at"):
            assert key in payload, key


# ── 2. ops_health carries it (one mechanism, not two) ────────────────────
class TestTheTickLoopIsAnOpsMonitor:
    """Wired into `ops_health` rather than into the healthcheck.

    `v3/runtime/ops_health.py` already IS the operational axis of AP3 —
    the OK/WARN/ANOMALY/INSUFFICIENT/UNSUPPLIED vocabulary, the worst-wins
    fold, the rule that "we cannot tell" never folds to fine. Putting the
    loop's liveness anywhere else would be a second mechanism answering
    the same question, and the two would disagree the first time one was
    edited. Landing it here reaches `/healthz`, `GET /api/v3/self_eval`
    (AP3) and the start-up disclosure from one measurement.
    """

    def test_a_producing_loop_is_ok(self):
        assert _status(_running())["verdict"] == O.OK

    def test_the_container_was_never_producing_and_that_is_an_anomaly(self):
        # THE regression case. This is the shadow container's exact state:
        # the thread alive, every tick raising, not one success, ever.
        monitor = _status(_running(
            ticks=0, errors=57, consecutive_errors=57, last_tick_at=None,
            last_error_at=NOW - 1.0,
            last_error="ProgrammingError: SQLite objects created in a "
                       "thread can only be used in that same thread"))

        assert monitor["verdict"] == O.ANOMALY
        assert monitor["reason"] == O.REASON_LOOP_NEVER_SUCCEEDED
        assert monitor["errors"] == 57
        assert "SQLite objects" in monitor["last_error"], \
            "the cause has to reach the surface, not just a count"

    def test_a_loop_still_inside_its_first_tick_is_insufficient_not_ok(self):
        # NP5+8: a transient inability to conclude is allowed and must be
        # SAID, not rounded to either neighbour. A container killed for
        # being 40 seconds into its first 60-second tick is a container
        # that never gets to finish one.
        monitor = _status(_running(ticks=0, errors=0, last_tick_at=None,
                                   started_at=NOW - 40.0))
        assert monitor["verdict"] == O.INSUFFICIENT
        assert monitor["reason"] == O.REASON_LOOP_STARTING

    def test_a_silent_start_stops_being_excused_once_the_grace_passes(self):
        grace = O.first_tick_grace(INTERVAL)
        monitor = _status(_running(ticks=0, errors=0, last_tick_at=None,
                                   started_at=NOW - (grace + 1.0)))
        assert monitor["verdict"] == O.ANOMALY
        assert monitor["reason"] == O.REASON_LOOP_NEVER_SUCCEEDED

    def test_a_slow_cold_sweep_is_starting_not_degraded(self):
        # MEASURED, not chosen. The shadow container's first tick on an
        # empty ledger has every adapter due at once and was still
        # fetching after fifteen minutes. Judging that by the steady-state
        # budget would call a container degraded for doing exactly what it
        # is supposed to be doing, and an alarm that cries wolf on every
        # cold start is an alarm nobody reads on the day it matters.
        overdue, _ = O.loop_budgets(INTERVAL)
        assert O.first_tick_grace(INTERVAL) > 15 * 60.0 > overdue

        monitor = _status(_running(ticks=0, errors=0, last_tick_at=None,
                                   started_at=NOW - 15 * 60.0))
        assert monitor["verdict"] == O.INSUFFICIENT
        assert monitor["reason"] == O.REASON_LOOP_STARTING
        assert monitor["first_tick_grace_sec"] == O.first_tick_grace(INTERVAL)

    def test_the_grace_never_excuses_a_tick_that_raised(self):
        # The one case that must NOT get the benefit of the doubt: the
        # container's actual state. A raised tick is not a slow tick, and
        # this is the boundary that keeps the longer grace from re-opening
        # the hole it was widened around.
        monitor = _status(_running(ticks=0, errors=1, last_tick_at=None,
                                   started_at=NOW - 1.0))
        assert monitor["verdict"] == O.ANOMALY
        assert monitor["reason"] == O.REASON_LOOP_NEVER_SUCCEEDED

    def test_a_dead_thread_is_an_anomaly_even_with_a_recent_success(self):
        monitor = _status(_running(running=False))
        assert monitor["verdict"] == O.ANOMALY
        assert monitor["reason"] == O.REASON_LOOP_STOPPED

    def test_a_loop_that_was_never_started_says_so(self):
        monitor = _status(_running(running=False, ticks=0, errors=0,
                                   last_tick_at=None, started_at=None))
        assert monitor["verdict"] == O.ANOMALY
        assert monitor["reason"] == O.REASON_LOOP_NOT_STARTED

    def test_overdue_is_a_warning_and_stalled_is_an_anomaly(self):
        overdue, stalled = O.loop_budgets(INTERVAL)
        assert overdue < stalled

        warn = _status(_running(last_tick_at=NOW - (overdue + 1.0)))
        assert warn["verdict"] == O.WARN
        assert warn["reason"] == O.REASON_LOOP_OVERDUE

        anomaly = _status(_running(last_tick_at=NOW - (stalled + 1.0)))
        assert anomaly["verdict"] == O.ANOMALY
        assert anomaly["reason"] == O.REASON_LOOP_STALLED

    def test_the_budgets_follow_the_configured_cadence(self):
        slow_overdue, _ = O.loop_budgets(3600.0)
        fast_overdue, _ = O.loop_budgets(1.0)
        assert slow_overdue > fast_overdue, \
            "a deployment on an hourly cadence is not late at minute five"
        assert fast_overdue >= O.LOOP_MIN_OVERDUE_SEC, \
            "and a one-second cadence must not make every blip an alarm"

    def test_no_status_at_all_is_unsupplied_and_never_ok(self):
        monitor = _status(None)
        assert monitor["verdict"] == O.UNSUPPLIED
        assert monitor["reason"] == O.REASON_LOOP_UNSUPPLIED

    def test_it_is_declared_in_the_absent_probe_like_every_other_monitor(self):
        folded = O.probe_absent(now=NOW)
        assert [row["monitor"] for row in folded["monitors"]] == list(
            O.MONITOR_IDS)
        assert O.MONITOR_LOOP in {row["monitor"] for row in
                                  folded["monitors"]}

    def test_a_dead_loop_drags_the_whole_fold_to_distrust(self):
        folded = O.fold([
            O.monitor(O.MONITOR_BACKUP, O.OK, "backup_fresh"),
            O.monitor(O.MONITOR_CAPACITY, O.OK, "capacity_within_band"),
            _status(_running(ticks=0, errors=9, last_tick_at=None)),
        ], now=NOW)
        assert folded["worst_monitor"] == O.MONITOR_LOOP
        assert folded["worst_band"] == O.BAND_DISTRUST

    def test_the_probe_takes_the_loop_status_from_the_composition_root(
            self, store):
        probed = O.probe(store.path, span_sec=None, now=NOW,
                         loop_status=_running(ticks=0, errors=4,
                                              last_tick_at=None),
                         interval_sec=INTERVAL)
        by_id = {row["monitor"]: row for row in probed["monitors"]}
        assert by_id[O.MONITOR_LOOP]["verdict"] == O.ANOMALY


# ── 3. /healthz stops lying ──────────────────────────────────────────────
class TestHealthzSeparatesUpFromProducing:
    """Four statuses, and each one exists because an orchestrator does
    something different with it.

        ok        200  up and producing.
        starting  200  up, no tick has finished yet, still inside the
                       budget. 200 because restarting a container for
                       being mid-first-tick restarts the thing that is
                       starting. NOT `ok`, so a probe that asserts the
                       loop still refuses it.
        unknown   200  the endpoint answered but this deployment wired no
                       loop probe. A wiring gap is not a failure and is
                       not health either — §NP5+8's "we cannot tell".
        degraded  503  alive and NOT producing. 503 rather than 500: the
                       endpoint worked, the service did not. 500 stays
                       reserved for "the probe itself could not answer",
                       which is a different fact and has to remain
                       distinguishable.
    """

    def test_the_container_state_answers_degraded_not_ok(self, store):
        # The whole defect, end to end, in the state the container was in.
        probe = O.probe(store.path, span_sec=None, now=NOW,
                        loop_status=_running(
                            ticks=0, errors=57, last_tick_at=None,
                            last_error="ProgrammingError: SQLite objects"),
                        interval_sec=INTERVAL)

        response = _healthz(store, ops=probe)
        health = response.as_dict()["health"]

        assert response.status == 503
        assert health["status"] == D.HEALTH_DEGRADED
        assert health["reason"] == O.REASON_LOOP_NEVER_SUCCEEDED
        assert health["tick_loop"]["errors"] == 57
        assert "SQLite objects" in health["tick_loop"]["last_error"]

    def test_a_producing_loop_answers_ok(self, store):
        probe = O.probe(store.path, span_sec=None, now=NOW,
                        loop_status=_running(), interval_sec=INTERVAL)
        response = _healthz(store, ops=probe)
        assert response.status == 200
        assert response.as_dict()["health"]["status"] == D.HEALTH_OK

    def test_a_first_tick_in_flight_answers_starting_with_a_200(self, store):
        probe = O.probe(store.path, span_sec=None, now=NOW,
                        loop_status=_running(ticks=0, errors=0,
                                             last_tick_at=None,
                                             started_at=NOW - 10.0),
                        interval_sec=INTERVAL)
        response = _healthz(store, ops=probe)
        assert response.status == 200
        assert response.as_dict()["health"]["status"] == D.HEALTH_STARTING

    def test_an_unprobed_deployment_says_unknown_rather_than_ok(self, store):
        response = _healthz(store)
        assert response.status == 200
        assert response.as_dict()["health"]["status"] == D.HEALTH_UNKNOWN

    def test_it_is_still_public(self, store):
        assert _healthz(store).status in (200, 503), (
            "R15h is the one route the thing that restarts the process can "
            "reach; an auth failure here would be a 401, not a verdict")

    def test_the_time_since_the_last_success_is_served_not_inferred(
            self, store):
        probe = O.probe(store.path, span_sec=None, now=NOW,
                        loop_status=_running(last_tick_at=NOW - 42.0),
                        interval_sec=INTERVAL)
        loop = _healthz(store, ops=probe).as_dict()["health"]["tick_loop"]
        assert loop["since_last_success_sec"] == pytest.approx(42.0)
        assert loop["overdue_after_sec"] > 0

    def test_an_unreachable_ledger_is_degraded_rather_than_reported_true(
            self, store):
        # `ledger_reachable: True` was a literal. It said the same thing
        # with the file deleted as with it present, which is the same
        # defect as the status field in smaller print.
        store.close()
        Path(store.path).unlink()

        response = _healthz(store)
        health = response.as_dict()["health"]
        assert health["ledger_reachable"] is False
        assert response.status == 503
        assert health["status"] == D.HEALTH_DEGRADED

    def test_the_public_body_does_not_republish_the_whole_ops_fold(
            self, store):
        # `/healthz` is unauthenticated. It carries the loop (which is
        # what a probe needs) and a POINTER to the composite; the monitor
        # bodies stay behind `GET /api/v3/self_eval`.
        probe = O.probe(store.path, span_sec=None, now=NOW,
                        loop_status=_running(), interval_sec=INTERVAL)
        health = _healthz(store, ops=probe).as_dict()["health"]
        assert "monitors" not in health["ops_health"]
        assert health["ops_health"]["worst_monitor"]


# ── 4. the probe the orchestrator actually runs ──────────────────────────
class TestTheComposeHealthcheckAssertsTheLoop:
    """The runbook already said "container Up is not evidence a tick ran".
    The healthcheck did not know that: it opened `/healthz` and accepted
    any 2xx, which is why an hour of failing ticks read as healthy.
    """

    @staticmethod
    def _directives(text: str) -> str:
        """The file with its comment lines removed — what docker READS.

        Same technique as `test_v3_server.py`'s compose assertions, and
        for the same reason: this repository has no YAML dependency, and
        both compose files argue their case in comments, so a naive
        substring search finds a word in the sentence explaining that the
        word is not used.
        """
        return "\n".join(line for line in text.splitlines()
                         if not line.lstrip().startswith("#"))

    @property
    def shadow(self) -> str:
        compose = self._directives(
            (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        return compose.split("v3_shadow:", 1)[1].split("\nvolumes:", 1)[0]

    def test_the_check_reads_the_status_field(self):
        block = self.shadow.split("healthcheck:", 1)[1]
        assert "/healthz" in block
        assert "['health']['status']" in block, \
            "a check that only asserts a 200 accepts `starting` and " \
            "`unknown` as healthy, which is the defect wearing a new hat"

    def test_the_start_period_allows_a_real_first_tick(self):
        grace = re.search(r"start_period:\s*(\d+)s", self.shadow)
        assert grace is not None
        assert int(grace.group(1)) >= 180, \
            "a first tick fetches every enabled adapter; 30s of grace " \
            "marks a legitimately starting container unhealthy"

    def test_v1s_service_definition_is_untouched(self):
        compose = self._directives(
            (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        v1 = compose.split("radar:", 1)[1].split("v3_shadow:", 1)[0]
        assert "8300" not in v1, \
            "the shadow's health surface must not have leaked into v1's " \
            "service definition"
        assert "/healthz" not in v1
