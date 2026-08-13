"""WP-2.5 — the cycle: a pure decision, then a separate execution.

`run_due` is the interesting half. It decides what to fetch and returns
that as values, so these tests reason about scheduling, breakers and
shared quotas without a socket, a database or a clock anywhere in sight.
`execute_plan` is exercised against a temp ledger and an injected fake
session — never the network (§6-1).
"""
import json

import pytest

from v3.adapters.types import (FALLBACK_ON_FAILURE,
                               FALLBACK_ON_FAILURE_OR_EMPTY, AdapterId,
                               NormalizeContext, ObservationDraft,
                               RequestChain, RequestSpec, SourceAdapter)
from v3.fetch import breaker, client, recorder, runner
from v3.fetch.breaker import BreakerState
from v3.fetch.expand import ExpansionInput, ExpansionScope
from v3.fetch.limiter import LimiterState
from v3.fetch.registry import AdapterRegistry
from v3.fetch.state import AdapterState
from v3.kernel import Window
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore

T0 = 1_700_000_000.0


def _drafts(payload, context):
    return (ObservationDraft(signal_source="probe", domain="cyber",
                             country="TW", status="FIRED", raw_score=3.0,
                             value=payload.text()),)


def _adapter(name, *, cadence_sec=3600.0, group="", interval=0.0,
             enabled=True, reason="", normalize=_drafts, requests=None,
             record_body=False):
    return SourceAdapter(
        adapter_id=AdapterId(name), category="cyber",
        requests=requests if requests is not None else (
            (RequestSpec(url=f"https://example.test/{name}"),)
            if enabled else ()),
        cadence=Window.from_days(1.0, cadence_sec=cadence_sec),
        normalize=normalize, freshness_horizon_sec=3600.0,
        rate_limit_group=group, min_interval_sec=interval,
        enabled=enabled, disabled_reason=reason, record_body=record_body)


class _Response:
    def __init__(self, status=200, body=b"payload", headers=None):
        self.status_code = status
        self.content = body
        self.headers = headers or {}


class _Session:
    """Returns queued responses, then REPEATS the last one.

    Repeating matters: 500 and 503 are retryable, so a fake that quietly
    served a 200 on the retry would turn a failure test into a success
    test without saying so.
    """

    def __init__(self, *responses):
        self._queue = list(responses) or [_Response()]
        self._last = self._queue[-1]
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append(url)
        if self._queue:
            self._last = self._queue.pop(0)
        return self._last


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "v3.db"))
    yield instance
    instance.close()


# ── run_due: pure ───────────────────────────────────────────────────────

class TestRunDueIsPure:
    def test_a_never_run_adapter_is_planned(self):
        plan = runner.run_due(T0, [_adapter("alpha")], {})
        assert plan.planned_ids == ("alpha",)
        assert plan.skipped == ()

    def test_an_adapter_inside_its_cadence_is_skipped(self):
        states = {"alpha": AdapterState("alpha", last_run_at=T0)}
        plan = runner.run_due(T0 + 100, [_adapter("alpha")], states)
        assert plan.planned == ()
        assert plan.skipped[0].reason == runner.NOT_DUE

    def test_a_disabled_adapter_is_skipped_with_its_reason(self):
        adapter = _adapter("notam", enabled=False,
                           reason="no free international NOTAM API (K14)")
        plan = runner.run_due(T0, [adapter], {})
        skipped = plan.skipped_for(runner.DISABLED)[0]
        assert "K14" in skipped.detail

    def test_an_open_breaker_blocks_the_fetch(self):
        states = {"alpha": AdapterState(
            "alpha", breaker=BreakerState(state=breaker.OPEN, fail_count=5,
                                          opened_at=T0,
                                          recovery_delay_sec=300.0))}
        plan = runner.run_due(T0 + 10, [_adapter("alpha")], states)
        assert plan.planned == ()
        assert plan.skipped[0].reason == runner.BREAKER_OPEN

    def test_a_half_open_breaker_allows_exactly_one_probe(self):
        states = {"alpha": AdapterState(
            "alpha", breaker=BreakerState(state=breaker.OPEN, fail_count=5,
                                          opened_at=T0,
                                          recovery_delay_sec=300.0))}
        plan = runner.run_due(T0 + 400, [_adapter("alpha")], states)
        assert len(plan.planned) == 1
        assert plan.planned[0].is_probe is True

    def test_a_half_open_probe_is_one_step_not_a_resumption(self):
        """S4-NF-003 says "one trial request" — not the whole sweep.

        Measured on the shadow, 2026-08-13: ct_log's HALF_OPEN "probe"
        was its full 162-step expansion — 319 requests inside ten
        minutes, every fetch_log row marked HALF_OPEN. The single-request
        test above stayed green through all of it, because a one-step
        plan cannot tell a probe from a resumption.
        """
        states = {"multi": AdapterState(
            "multi", breaker=BreakerState(state=breaker.OPEN, fail_count=5,
                                          opened_at=T0,
                                          recovery_delay_sec=300.0))}
        plan = runner.run_due(T0 + 400, [_multi("multi", 5)], states)
        item = plan.planned[0]
        assert item.is_probe is True
        assert len(item.steps) == 1
        assert item.probe_deferred == 4

    def test_a_closed_breaker_plans_the_whole_expansion(self):
        plan = runner.run_due(T0, [_multi("multi", 5)], {})
        item = plan.planned[0]
        assert item.is_probe is False
        assert len(item.steps) == 5
        assert item.probe_deferred == 0

    def test_a_probe_costs_the_budget_one_step_not_the_sweep(self):
        """The truncated probe must also be PRICED as one step, or a
        162-step adapter in HALF_OPEN still evicts everything behind it
        from the tick."""
        states = {"multi": AdapterState(
            "multi", breaker=BreakerState(state=breaker.OPEN, fail_count=5,
                                          opened_at=T0,
                                          recovery_delay_sec=300.0))}
        plan = runner.run_due(T0 + 400, [_multi("multi", 5),
                                         _adapter("beta")], states)
        bounded = runner.apply_budget(plan, max_requests=2)
        assert set(bounded.planned_ids) == {"multi", "beta"}

    def test_the_breaker_is_judged_once_and_carried(self):
        """S4-NF-003: asking twice would spend two probe slots."""
        states = {"alpha": AdapterState(
            "alpha", breaker=BreakerState(state=breaker.OPEN, fail_count=5,
                                          opened_at=T0,
                                          recovery_delay_sec=300.0))}
        plan = runner.run_due(T0 + 400, [_adapter("alpha")], states)
        assert plan.planned[0].breaker is plan.breaker_states["alpha"]

    def test_a_rate_limited_group_is_skipped(self):
        limits = LimiterState().record("peeringdb", T0)
        plan = runner.run_due(
            T0 + 1, [_adapter("pdb", group="peeringdb", interval=10.0)], {},
            limits)
        assert plan.skipped[0].reason == runner.RATE_LIMITED

    def test_two_adapters_sharing_a_quota_do_not_both_plan(self):
        """K01: one account, three sensors — the limiter is per GROUP."""
        adapters = [_adapter("opensky", group="opensky", interval=30.0),
                    _adapter("isr_hotspot", group="opensky", interval=30.0),
                    _adapter("mil_support_air", group="opensky",
                             interval=30.0)]
        plan = runner.run_due(T0, adapters, {})
        assert len(plan.planned) == 1
        assert len(plan.skipped_for(runner.RATE_LIMITED)) == 2

    def test_unthrottled_adapters_all_plan(self):
        adapters = [_adapter("a"), _adapter("b"), _adapter("c")]
        assert len(runner.run_due(T0, adapters, {}).planned) == 3

    def test_a_not_due_adapter_does_not_consume_a_probe_slot(self):
        """Gate order: due-ness before the breaker."""
        states = {"alpha": AdapterState(
            "alpha", last_run_at=T0,
            breaker=BreakerState(state=breaker.OPEN, fail_count=5,
                                 opened_at=T0 - 10_000,
                                 recovery_delay_sec=300.0))}
        plan = runner.run_due(T0 + 10, [_adapter("alpha")], states)
        assert plan.skipped[0].reason == runner.NOT_DUE
        assert plan.breaker_states["alpha"].state == breaker.OPEN

    def test_overdue_is_reported_on_the_plan(self):
        states = {"alpha": AdapterState("alpha", last_run_at=T0)}
        plan = runner.run_due(T0 + 5000, [_adapter("alpha")], states)
        assert plan.planned[0].overdue_by_sec == pytest.approx(1400.0)

    def test_run_due_touches_no_socket(self):
        """Purity, enforced rather than asserted."""
        import socket
        original = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("run_due opened a socket"))
        try:
            plan = runner.run_due(T0, [_adapter("alpha")], {})
        finally:
            socket.socket = original
        assert plan.planned_ids == ("alpha",)

    def test_the_same_inputs_produce_the_same_plan(self):
        adapters = [_adapter("a"), _adapter("b")]
        first = runner.run_due(T0, adapters, {})
        second = runner.run_due(T0, adapters, {})
        assert first.planned_ids == second.planned_ids

    def test_a_non_positive_now_is_refused(self):
        with pytest.raises(DomainError):
            runner.run_due(0.0, [_adapter("a")], {})


# ── execute_plan: the impure half ───────────────────────────────────────

def _multi(name, count, *, cadence_sec=3600.0):
    """An adapter declaring `count` independent requests, so the budget has
    something whose COST differs from its head-count to reason about."""
    return _adapter(name, cadence_sec=cadence_sec, requests=tuple(
        RequestSpec(url=f"https://example.test/{name}/{i}", label=f"r{i}")
        for i in range(count)))


def _plan(adapters, states=None, now=1_800_000_000.0):
    return runner.run_due(now, adapters, states or {}, None, None,
                          freshness={})


class TestTheFetchBudgetBoundsOneTick:
    """G-19. A cold `fetch_schedule` makes every adapter due at once.

    Measured against the deployed geography that is 772 expanded steps in
    one plan, and two shadow runs failed to finish it in twenty-five
    minutes — so the schedule never advanced, every adapter stayed due, and
    the next tick planned the same 772. `apply_budget` is what turns a
    sweep that cannot finish into a sweep that finishes in seven ticks.
    """

    def test_an_over_budget_plan_is_cut_to_the_budget(self):
        plan = _plan([_multi("a", 40), _multi("b", 40), _multi("c", 40)])
        assert sum(len(p.steps) for p in plan.planned) == 120
        bounded = runner.apply_budget(plan, max_requests=80)
        assert sum(len(p.steps) for p in bounded.planned) == 80
        assert [s.adapter_id.value for s in
                bounded.skipped_for(runner.BUDGET_DEFERRED)] == ["c"]

    def test_a_plan_inside_the_budget_is_returned_unchanged(self):
        plan = _plan([_multi("a", 10), _multi("b", 10)])
        assert runner.apply_budget(plan, max_requests=120) is plan

    def test_the_deferred_adapter_says_what_it_cost_and_when_it_last_ran(self):
        """NP6. A deferral an operator cannot open is a deferral that reads
        as a source quietly dropping out of the sweep."""
        plan = _plan([_multi("a", 40), _multi("b", 40)])
        deferred = runner.apply_budget(
            plan, max_requests=40).skipped_for(runner.BUDGET_DEFERRED)
        assert len(deferred) == 1
        assert "40 request(s)" in deferred[0].detail
        assert "80 of a 40 budget" in deferred[0].detail
        assert "never run" in deferred[0].detail

    def test_an_adapter_is_atomic_even_when_it_alone_exceeds_the_budget(self):
        """Half-fetching is the one thing this must not do. `reduce` folds
        across an adapter's payloads, so a `ct_log` that fetched 80 of its
        162 domains would fold a verdict indistinguishable from a complete
        one — G-17 manufactured by the fix for G-19."""
        plan = _plan([_multi("huge", 200)])
        bounded = runner.apply_budget(plan, max_requests=120)
        assert [p.adapter_id.value for p in bounded.planned] == ["huge"]
        assert len(bounded.planned[0].steps) == 200
        assert bounded.skipped_for(runner.BUDGET_DEFERRED) == ()

    def test_at_least_one_adapter_is_always_admitted(self):
        """A budget that could admit nothing is the same livelock wearing
        different clothes."""
        plan = _plan([_multi("a", 90), _multi("b", 90)])
        bounded = runner.apply_budget(plan, max_requests=1)
        assert len(bounded.planned) == 1

    def test_a_non_positive_budget_is_refused(self):
        plan = _plan([_multi("a", 5)])
        with pytest.raises(DomainError, match="livelock"):
            runner.apply_budget(plan, max_requests=0)

    def test_the_longest_waiting_adapter_goes_first(self):
        now = 1_800_000_000.0
        states = {
            "recent": AdapterState(adapter_id="recent").with_run(
                at=now - 4000.0, outcome="ok", breaker=BreakerState()),
            "ancient": AdapterState(adapter_id="ancient").with_run(
                at=now - 90000.0, outcome="ok", breaker=BreakerState()),
        }
        plan = _plan([_multi("recent", 40), _multi("ancient", 40)],
                     states=states, now=now)
        bounded = runner.apply_budget(plan, max_requests=40)
        assert [p.adapter_id.value for p in bounded.planned] == ["ancient"]

    def test_a_never_run_adapter_outranks_one_that_has_run(self):
        """`schedule.overdue_by` is 0.0 for an adapter that has never run,
        so lateness cannot break the cold-start tie and "never spoke" has
        to be its own, stronger claim."""
        now = 1_800_000_000.0
        states = {"seen": AdapterState(adapter_id="seen").with_run(
            at=now - 90000.0, outcome="ok", breaker=BreakerState())}
        plan = _plan([_multi("seen", 40), _multi("fresh", 40)],
                     states=states, now=now)
        bounded = runner.apply_budget(plan, max_requests=40)
        assert [p.adapter_id.value for p in bounded.planned] == ["fresh"]

    def test_running_an_adapter_sends_it_to_the_back_of_the_queue(self):
        """Starvation-freedom, as arithmetic rather than as a cadence
        coincidence: the adapter that just ran is the most recently run and
        therefore sorts last."""
        now = 1_800_000_000.0
        adapters = [_multi(name, 40, cadence_sec=1.0)
                    for name in ("a", "b", "c")]
        states, admitted = {}, []
        for _ in range(3):
            bounded = runner.apply_budget(
                _plan(adapters, states=states, now=now), max_requests=40)
            won = bounded.planned[0].adapter_id.value
            admitted.append(won)
            states[won] = AdapterState(adapter_id=won).with_run(
                at=now, outcome="ok", breaker=BreakerState())
            now += 60.0
        assert sorted(admitted) == ["a", "b", "c"], \
            "every adapter ran within three ticks even at a 1s cadence"

    def test_a_suppression_producer_is_never_deferred(self):
        """Deferring one changes how the adapters that DO run are read: a
        cycle missing its suppressor reports noise as signal."""
        plan = _plan([_multi("gdelt", 100), _multi("space_weather", 100)])
        bounded = runner.apply_budget(plan, max_requests=40,
                                      always_admit=("space_weather",))
        assert "space_weather" in [p.adapter_id.value for p in bounded.planned]
        assert [s.adapter_id.value for s in
                bounded.skipped_for(runner.BUDGET_DEFERRED)] == ["gdelt"]

    def test_the_producer_still_spends_the_budget(self):
        plan = _plan([_multi("space_weather", 30), _multi("a", 30),
                      _multi("b", 30)])
        bounded = runner.apply_budget(plan, max_requests=60,
                                      always_admit=("space_weather",))
        assert sum(len(p.steps) for p in bounded.planned) == 60

    def test_the_admitted_set_keeps_the_plans_own_order(self):
        """The priority order decides ADMISSION only. Execution order is
        `order_producers_first`'s, and re-sorting here would move that
        decision into a function that is not about it."""
        plan = _plan([_multi("z", 10), _multi("a", 10), _multi("m", 200)])
        bounded = runner.apply_budget(plan, max_requests=20)
        assert [p.adapter_id.value for p in bounded.planned] == ["z", "a"]

    def test_the_earlier_skips_survive_the_budget(self):
        plan = _plan([_multi("a", 40), _adapter("off", enabled=False,
                                                reason="no key")])
        bounded = runner.apply_budget(plan, max_requests=40)
        assert [s.adapter_id.value
                for s in bounded.skipped_for(runner.DISABLED)] == ["off"]

    def test_the_budget_does_not_advance_anything(self):
        """PURE. A deferred adapter's `last_run_at` is untouched, which is
        the whole reason it comes back due next tick."""
        now = 1_800_000_000.0
        plan = _plan([_multi("a", 40), _multi("b", 40)], now=now)
        bounded = runner.apply_budget(plan, max_requests=40)
        assert bounded.now == now
        assert all(p.last_run_at is None for p in bounded.planned)


class TestExecutePlan:
    def _run(self, store, adapters, *responses, states=None):
        registry = AdapterRegistry(adapters)
        plan = runner.run_due(T0, adapters, states or {})
        http = client.HttpClient(session=_Session(*responses),
                                 sleeper=lambda _s: None)
        return plan, runner.execute_plan(plan, registry, client=http,
                                         store=store, tick_id="t1")

    def test_observations_reach_the_ledger(self, store):
        _, result = self._run(store, [_adapter("alpha")], _Response())
        assert result.observations_written == 1
        assert store.count_signals() == 1

    def test_the_adapter_never_writes_them_itself(self, store):
        """§2-2: the runner wraps drafts in Evidence and appends."""
        self._run(store, [_adapter("alpha")], _Response())
        row = store.signals_between(T0 - 1, T0 + 1)[0]
        assert row["sensor"] == "alpha"
        assert row["freshness_horizon_sec"] == 3600.0

    def test_every_fetch_is_logged(self, store):
        self._run(store, [_adapter("alpha")], _Response())
        rows = recorder.fetch_log_for(store, "alpha")
        assert len(rows) == 1 and rows[0]["outcome"] == client.OK

    def test_a_failed_fetch_is_logged_and_writes_no_observation(self, store):
        _, result = self._run(store, [_adapter("alpha")], _Response(500))
        assert result.observations_written == 0
        assert recorder.fetch_log_for(store, "alpha")[0]["outcome"] == \
            client.HTTP_ERROR

    def test_a_failure_advances_the_breaker(self, store):
        _, result = self._run(store, [_adapter("alpha")], _Response(500))
        assert result.results[0].state.breaker.fail_count == 1

    def test_five_failures_open_the_breaker(self, store):
        adapters = [_adapter("alpha")]
        states = {}
        for _ in range(5):
            registry = AdapterRegistry(adapters)
            plan = runner.run_due(T0, adapters, states)
            http = client.HttpClient(session=_Session(_Response(500)),
                                     sleeper=lambda _s: None)
            result = runner.execute_plan(plan, registry, client=http,
                                         store=store, tick_id="t")
            states = {r.adapter_id.value: AdapterState(
                r.adapter_id.value, last_run_at=None, breaker=r.state.breaker)
                for r in result.results}
        assert states["alpha"].breaker.state == breaker.OPEN

    def test_state_is_persisted_for_the_next_cycle(self, store):
        self._run(store, [_adapter("alpha")], _Response())
        loaded = recorder.load_states(store)
        assert loaded["alpha"].last_run_at == T0
        assert loaded["alpha"].last_outcome == client.OK

    def test_a_persisted_run_makes_the_next_cycle_skip(self, store):
        """The F-01 loop closed: state survives, so the phase survives."""
        self._run(store, [_adapter("alpha")], _Response())
        states = recorder.load_states(store)
        plan = runner.run_due(T0 + 10, [_adapter("alpha")], states)
        assert plan.skipped[0].reason == runner.NOT_DUE

    def test_the_raw_body_is_stored_only_when_opted_in(self, store):
        self._run(store, [_adapter("plain")], _Response(200, b"hello"))
        assert store._read_connection().execute(
            "SELECT COUNT(*) FROM fetch_body").fetchone()[0] == 0
        self._run(store, [_adapter("kept", record_body=True)],
                  _Response(200, b"hello"))
        assert store._read_connection().execute(
            "SELECT COUNT(*) FROM fetch_body").fetchone()[0] == 1

    def test_normalize_receives_the_fetched_bytes_and_the_context(self, store):
        seen = {}

        def capture(payload, context):
            seen["body"] = payload.body
            seen["now"] = context.now
            seen["adapter"] = context.adapter_id.value
            return ()

        self._run(store, [_adapter("alpha", normalize=capture)],
                  _Response(200, b"upstream"))
        assert seen == {"body": b"upstream", "now": T0, "adapter": "alpha"}

    def test_the_limiter_advances_as_requests_are_made(self, store):
        _, result = self._run(store, [_adapter("alpha", group="g",
                                               interval=5.0)], _Response())
        assert result.limiter_state.as_dict()["g"] == T0


# ── recorder ────────────────────────────────────────────────────────────

class TestRecorder:
    def test_the_liveness_ledger_is_a_query(self, store):
        """§1-7: D1's feed death knowledge becomes recorded fact."""
        recorder.record_fetch(store, "cn_mfa", requested_at=T0,
                              url_sha256="a", outcome="returns_html")
        recorder.record_fetch(store, "ru_mfa", requested_at=T0,
                              url_sha256="b", outcome="geo_block")
        assert recorder.liveness(store) == {"cn_mfa": "returns_html",
                                            "ru_mfa": "geo_block"}

    def test_fetch_log_is_append_only(self, store):
        recorder.record_fetch(store, "a", requested_at=T0, url_sha256="x",
                              outcome="ok")
        with pytest.raises(Exception, match="append-only"):
            store._connection().execute(
                "UPDATE fetch_log SET outcome = 'nope'")

    def test_an_llm_call_round_trips_by_prompt_hash(self, store):
        digest = recorder.record_llm_call(
            store, "llm_intel", prompt="classify this", response='{"x":1}',
            model_id="test-model", temperature=0.0, called_at=T0)
        found = recorder.recorded_response(store, "classify this")
        assert found["prompt_sha256"] == digest
        assert found["response"] == '{"x":1}'
        assert found["model_id"] == "test-model"
        assert found["temperature"] == 0.0

    @pytest.mark.parametrize("field", ["prompt", "response", "model_id"])
    def test_an_incomplete_llm_record_is_refused(self, store, field):
        """S5-VERIF-022: a row missing a field cannot be replayed, and by
        the time anybody notices the exchange is gone."""
        kwargs = {"prompt": "p", "response": "r", "model_id": "m",
                  "temperature": 0.0, "called_at": T0}
        kwargs[field] = ""
        with pytest.raises(DomainError, match="S5-VERIF-022"):
            recorder.record_llm_call(store, "llm_intel", **kwargs)

    def test_an_unrecorded_prompt_returns_none_rather_than_calling_out(
            self, store):
        assert recorder.recorded_response(store, "never asked") is None

    def test_llm_call_is_append_only(self, store):
        recorder.record_llm_call(store, "a", prompt="p", response="r",
                                 model_id="m", temperature=0.1, called_at=T0)
        with pytest.raises(Exception, match="append-only"):
            store._connection().execute("UPDATE llm_call SET response = 'x'")

    def test_a_body_is_stored_once_per_hash(self, store):
        first = recorder.record_body(store, "a", body=b"same", recorded_at=T0)
        second = recorder.record_body(store, "a", body=b"same",
                                      recorded_at=T0 + 1)
        assert first == second
        assert recorder.stored_body(store, first) == b"same"
        assert store._read_connection().execute(
            "SELECT COUNT(*) FROM fetch_body").fetchone()[0] == 1

    def test_state_round_trips(self, store):
        state = AdapterState("alpha", last_run_at=T0, last_outcome="ok",
                             breaker=BreakerState(state=breaker.OPEN,
                                                  fail_count=5, opened_at=T0,
                                                  recovery_delay_sec=600.0))
        recorder.save_state(store, state, updated_at=T0)
        loaded = recorder.load_states(store)["alpha"]
        assert loaded == state


# ── L1 schema v2 and the migration mechanism (ruling 3) ─────────────────

class TestSchemaMigration:
    def test_a_fresh_store_reports_the_current_version(self, store):
        from v3.ledger import schema as schema_module
        assert store.schema_version() == schema_module.SCHEMA_VERSION

    def test_the_three_new_tables_exist(self, store):
        names = {row[0] for row in store._connection().execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"fetch_schedule", "fetch_log", "llm_call"} <= names

    def test_a_v1_store_is_upgraded_in_place(self, tmp_path, monkeypatch):
        """The upgrade path, exercised rather than assumed."""
        from v3.ledger import schema as schema_module
        path = str(tmp_path / "old.db")
        monkeypatch.setattr(schema_module, "MIGRATIONS", ())
        monkeypatch.setattr(schema_module, "SCHEMA_VERSION", 1)
        old = LedgerStore(path)
        assert old.schema_version() == 1
        names = {row[0] for row in old._connection().execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "fetch_log" not in names
        old.close()

        monkeypatch.undo()
        upgraded = LedgerStore(path)
        try:
            assert upgraded.schema_version() == \
                schema_module.SCHEMA_VERSION
            names = {row[0] for row in upgraded._connection().execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"fetch_schedule", "fetch_log", "llm_call"} <= names
        finally:
            upgraded.close()

    def test_reopening_is_idempotent(self, tmp_path):
        path = str(tmp_path / "again.db")
        for _ in range(3):
            instance = LedgerStore(path)
            from v3.ledger import schema as inner_schema
            assert instance.schema_version() == inner_schema.SCHEMA_VERSION
            instance.close()

    def test_a_newer_store_is_refused_rather_than_downgraded(self, tmp_path):
        path = str(tmp_path / "future.db")
        instance = LedgerStore(path)
        instance._connection().execute(
            "UPDATE schema_meta SET value = '99' WHERE key = 'version'")
        instance.close()
        with pytest.raises(RuntimeError, match="newer"):
            LedgerStore(path)

    def test_the_version_matches_the_last_migration(self):
        from v3.ledger import schema as schema_module
        assert schema_module.MIGRATIONS[-1].version == \
            schema_module.SCHEMA_VERSION

    def test_every_new_table_declares_a_retention_policy(self):
        """S3-DATA-044: a table with no policy is a table nobody prunes."""
        from v3.ledger.schema import RETENTION_POLICIES
        declared = {policy.table for policy in RETENTION_POLICIES}
        assert {"fetch_log", "llm_call", "fetch_body",
                "fetch_schedule"} <= declared

    def test_the_retention_horizons_are_the_ruled_ones(self):
        from v3.ledger.schema import RETENTION_POLICIES
        by_table = {policy.table: policy for policy in RETENTION_POLICIES}
        assert by_table["fetch_log"].retention_days == 60
        assert by_table["llm_call"].retention_days == 365
        assert by_table["fetch_body"].retention_days == 7
        assert by_table["fetch_schedule"].is_permanent


# ── review fixes ────────────────────────────────────────────────────────

class TestAppendOnlyIsEnforcedNotAssumed:
    """v2 made the tables append-only by convention; v3 makes it a trigger.

    `llm_call` matters most: it is S5-VERIF-022's replay substrate, so a
    deleted row is a conclusion that can never be reproduced.
    """

    @pytest.mark.parametrize("table", ["fetch_log", "llm_call", "fetch_body"])
    def test_rows_cannot_be_deleted(self, store, table):
        recorder.record_fetch(store, "a", requested_at=T0, url_sha256="x",
                              outcome="ok")
        recorder.record_llm_call(store, "a", prompt="p", response="r",
                                 model_id="m", temperature=0.0, called_at=T0)
        recorder.record_body(store, "a", body=b"b", recorded_at=T0)
        with pytest.raises(Exception, match="retention job"):
            store._connection().execute(f"DELETE FROM {table}")

    @pytest.mark.parametrize("table", ["fetch_log", "llm_call"])
    def test_rows_cannot_be_updated(self, store, table):
        recorder.record_fetch(store, "a", requested_at=T0, url_sha256="x",
                              outcome="ok")
        recorder.record_llm_call(store, "a", prompt="p", response="r",
                                 model_id="m", temperature=0.0, called_at=T0)
        with pytest.raises(Exception, match="append-only"):
            store._connection().execute(
                f"UPDATE {table} SET adapter_id = 'other'")

    def test_the_retention_job_remains_the_one_deleter(self, store):
        """The triggers are flag-guarded, exactly like the v1 tables."""
        recorder.record_fetch(store, "a", requested_at=T0, url_sha256="x",
                              outcome="ok")
        connection = store._connection()
        connection.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('pruning', '1')")
        try:
            connection.execute("DELETE FROM fetch_log")
        finally:
            connection.execute("DELETE FROM schema_meta WHERE key = 'pruning'")
        assert store._read_connection().execute(
            "SELECT COUNT(*) FROM fetch_log").fetchone()[0] == 0

    def test_the_store_reports_the_migrated_schema_version(self, store):
        from v3.ledger import schema as schema_module
        assert store.schema_version() == schema_module.SCHEMA_VERSION


class TestOneAdapterCycleIsOneTransaction:
    """A crash between the log row and the state write used to leave the
    ledger claiming a fetch whose breaker step was lost — so the next
    cycle reasoned from a state that never existed."""

    def test_a_failure_during_the_cycle_leaves_nothing_behind(self, store):
        adapters = [_adapter("alpha")]
        registry = AdapterRegistry(adapters)
        plan = runner.run_due(T0, adapters, {})
        http = client.HttpClient(session=_Session(_Response()),
                                 sleeper=lambda _s: None)

        original = recorder.save_state

        def explode(*args, **kwargs):
            raise RuntimeError("crash between the log row and the state")

        recorder.save_state = explode
        try:
            with pytest.raises(RuntimeError):
                runner.execute_plan(plan, registry, client=http, store=store,
                                    tick_id="t1")
        finally:
            recorder.save_state = original

        # Nothing partial survived: no log row, no observation, no state.
        assert store._read_connection().execute(
            "SELECT COUNT(*) FROM fetch_log").fetchone()[0] == 0
        assert store.count_signals() == 0
        assert recorder.load_states(store) == {}

    def test_a_successful_cycle_commits_all_of_it(self, store):
        adapters = [_adapter("alpha", record_body=True)]
        registry = AdapterRegistry(adapters)
        plan = runner.run_due(T0, adapters, {})
        http = client.HttpClient(session=_Session(_Response(200, b"body")),
                                 sleeper=lambda _s: None)
        runner.execute_plan(plan, registry, client=http, store=store,
                            tick_id="t1")
        read = store._read_connection()
        assert read.execute("SELECT COUNT(*) FROM fetch_log").fetchone()[0] == 1
        assert read.execute(
            "SELECT COUNT(*) FROM fetch_body").fetchone()[0] == 1
        assert read.execute(
            "SELECT COUNT(*) FROM fetch_schedule").fetchone()[0] == 1
        assert store.count_signals() == 1

    def test_the_network_call_happens_outside_the_transaction(self):
        """Holding SQLite's write lock across a remote timeout would block
        every other writer for the duration."""
        import ast
        import inspect
        source = inspect.getsource(runner.execute_plan)
        tree = ast.parse(source.lstrip())
        fetch_lines, transaction_lines = [], []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                attr = getattr(node.func, "attr", "")
                if attr == "fetch":
                    fetch_lines.append(node.lineno)
                if attr == "transaction":
                    transaction_lines.append(node.lineno)
        assert fetch_lines and transaction_lines
        assert max(fetch_lines) < min(transaction_lines)


# ── chains: the fallback runs ONLY when the primary does not answer ─────
#
# WP-2.6 fidelity sweep, ruling 3. The runner used to fetch every declared
# spec unconditionally, so `ioda_bgp`'s Cloudflare fallback ran beside
# IODA rather than instead of it — and a Cloudflare traffic anomaly could
# FIRED-override IODA's OK. A difference in the sensitive direction,
# produced by the kernel rather than by data.

def _chain_adapter(name="ioda_bgp", advance_on=FALLBACK_ON_FAILURE,
                   normalize=None):
    return SourceAdapter(
        adapter_id=AdapterId(name), category="physical",
        requests=(RequestChain(
            alternatives=(RequestSpec(url="https://primary.test/a",
                                      label="primary"),
                          RequestSpec(url="https://fallback.test/b",
                                      label="fallback")),
            advance_on=advance_on,
            reason="K19: production reaches the second source only when the "
                   "first returns None"),),
        cadence=Window.from_days(1.0, cadence_sec=3600.0),
        normalize=normalize or _drafts, freshness_horizon_sec=3600.0)


class TestFallbackChains:
    def _run(self, adapter, *responses, states=None):
        plan = runner.run_due(T0, [adapter], states or {})
        session = _Session(*responses)
        http = client.HttpClient(session=session, sleeper=lambda _s: None)
        return plan, session, http

    def test_a_healthy_primary_means_the_fallback_is_never_fetched(self,
                                                                   store):
        adapter = _chain_adapter()
        plan, session, http = self._run(adapter, _Response(200, b"ok"))
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        assert session.calls == ["https://primary.test/a"]

    def test_a_failing_primary_reaches_the_fallback(self, store):
        adapter = _chain_adapter()
        plan, session, http = self._run(adapter, _Response(404, b""),
                                        _Response(200, b"ok"))
        result = runner.execute_plan(plan, AdapterRegistry([adapter]),
                                     client=http, store=store, tick_id="t1")
        assert session.calls == ["https://primary.test/a",
                                 "https://fallback.test/b"]
        # The source answered, so the cycle succeeded — the primary's
        # failure lives in fetch_log, which is where it belongs.
        assert result.results[0].outcome == client.OK
        assert result.results[0].observations == 1

    def test_the_primarys_failure_is_still_recorded(self, store):
        adapter = _chain_adapter()
        plan, session, http = self._run(adapter, _Response(404, b""),
                                        _Response(200, b"ok"))
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        rows = recorder.fetch_log_for(store, "ioda_bgp")
        # fetch_log_for reads newest-first.
        assert sorted(row["outcome"] for row in rows) == [client.HTTP_ERROR,
                                                          client.OK]

    def test_a_rescued_cycle_does_not_advance_the_breaker(self, store):
        adapter = _chain_adapter()
        plan, session, http = self._run(adapter, _Response(404, b""),
                                        _Response(200, b"ok"))
        result = runner.execute_plan(plan, AdapterRegistry([adapter]),
                                     client=http, store=store, tick_id="t1")
        assert result.results[0].state.breaker.fail_count == 0

    def test_both_failing_is_still_a_failure(self, store):
        adapter = _chain_adapter()
        plan, session, http = self._run(adapter, _Response(404, b""),
                                        _Response(410, b""))
        result = runner.execute_plan(plan, AdapterRegistry([adapter]),
                                     client=http, store=store, tick_id="t1")
        assert result.results[0].outcome != client.OK
        assert result.results[0].observations == 0
        assert result.results[0].state.breaker.fail_count == 1

    def test_only_the_answering_alternative_is_normalized(self, store):
        """The defect exactly: two payloads reaching `normalize`, and the
        FIRED one winning."""
        seen: list = []

        def _record(payload, context):
            seen.append(payload.url)
            return ()

        adapter = _chain_adapter(normalize=_record)
        plan, session, http = self._run(adapter, _Response(200, b"ok"))
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        assert seen == ["https://primary.test/a"]

    def test_an_empty_body_advances_only_when_declared(self, store):
        adapter = _chain_adapter(advance_on=FALLBACK_ON_FAILURE_OR_EMPTY)
        plan, session, http = self._run(adapter, _Response(200, b""),
                                        _Response(200, b"ok"))
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        assert session.calls == ["https://primary.test/a",
                                 "https://fallback.test/b"]

    def test_an_empty_body_is_an_answer_by_default(self, store):
        """K05: HTTP 200 with an empty array is an authoritative success.
        Falling through would let a slower source overwrite a fresh
        negative."""
        adapter = _chain_adapter(advance_on=FALLBACK_ON_FAILURE)
        plan, session, http = self._run(adapter, _Response(200, b""),
                                        _Response(200, b"ok"))
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        assert session.calls == ["https://primary.test/a"]

    def test_the_plan_shows_the_chain_as_one_step(self):
        adapter = _chain_adapter()
        plan = runner.run_due(T0, [adapter], {})
        step = plan.planned[0].steps[0]
        assert step.is_chain and len(step.alternatives) == 2
        assert len(plan.planned[0].requests) == 2


# ── expansion: the plan carries concrete requests ───────────────────────

class TestPlaceholderExpansionInThePlan:
    def _templated(self, name="ripe_bgp", label="stats"):
        return SourceAdapter(
            adapter_id=AdapterId(name), category="cyber",
            requests=(RequestSpec(url="https://ripe.test/stats",
                                  params=(("resource", "{country}"),),
                                  label=label),),
            cadence=Window.from_days(1.0, cadence_sec=3600.0),
            normalize=_drafts, freshness_horizon_sec=3600.0)

    def test_a_supplied_scope_produces_a_concrete_request(self):
        adapter = self._templated()
        plan = runner.run_due(T0, [adapter], {}, expansions={
            "ripe_bgp": ExpansionInput(scopes=(
                ExpansionScope(values={"country": "TW"}, scope_key="TW"),))})
        spec = plan.planned[0].steps[0].primary
        assert spec.param_values("resource") == ("TW",)

    def test_n_scopes_produce_n_steps(self):
        adapter = self._templated(label="stats:{country}")
        plan = runner.run_due(T0, [adapter], {}, expansions={
            "ripe_bgp": ExpansionInput(scopes=tuple(
                ExpansionScope(values={"country": code}, scope_key=code)
                for code in ("TW", "JP", "US")))})
        assert len(plan.planned[0].steps) == 3
        assert [step.scope_key for step in plan.planned[0].steps] == [
            "TW", "JP", "US"]

    def test_a_missing_value_is_a_recorded_skip_not_a_sent_request(self):
        """`{country}` on the wire is a request that answers about nothing
        and records as a success (K02). It must not be reachable."""
        adapter = self._templated()
        plan = runner.run_due(T0, [adapter], {})
        assert plan.planned == ()
        skipped = plan.skipped_for(runner.UNRESOLVED)
        assert len(skipped) == 1
        assert "country" in skipped[0].detail

    def test_one_unsupplied_adapter_does_not_take_the_cycle_down(self):
        good = _adapter("space_weather")
        bad = self._templated()
        plan = runner.run_due(T0, [good, bad], {})
        assert plan.planned_ids == ("space_weather",)
        assert plan.skipped_for(runner.UNRESOLVED)[0].adapter_id.value == \
            "ripe_bgp"

    def test_the_expanded_request_is_what_reaches_the_session(self, store):
        adapter = self._templated()
        plan = runner.run_due(T0, [adapter], {}, expansions={
            "ripe_bgp": ExpansionInput(scopes=(
                ExpansionScope(values={"country": "TW"}, scope_key="TW"),))})
        session = _Session(_Response(200, b"ok"))
        http = client.HttpClient(session=session, sleeper=lambda _s: None)
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        assert session.calls == ["https://ripe.test/stats"]

    def test_run_due_is_still_pure_with_expansion(self):
        adapter = self._templated()
        expansion = {"ripe_bgp": ExpansionInput(scopes=(
            ExpansionScope(values={"country": "TW"}, scope_key="TW"),))}
        first = runner.run_due(T0, [adapter], {}, expansions=expansion)
        second = runner.run_due(T0, [adapter], {}, expansions=expansion)
        assert first.planned[0].steps == second.planned[0].steps


# ── ruling 5: a draft's reason is recorded, once, by the runner ─────────

class TestFiredReasonReachesTheLedger:
    def _adapter_with_reason(self, reason):
        def _normalize(payload, context):
            return (ObservationDraft(
                signal_source="bgp", domain="physical", country="TW",
                status="FIRED", raw_score=1.0, value="bgp=OUTAGE",
                reason=reason, flags={"level": "critical"}),)
        return _adapter("ioda_bgp", normalize=_normalize)

    def test_the_reason_is_stored_under_one_canonical_key(self, store):
        adapter = self._adapter_with_reason("BGP anomaly confirmed")
        plan = runner.run_due(T0, [adapter], {})
        http = client.HttpClient(session=_Session(_Response()),
                                 sleeper=lambda _s: None)
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        row = store.latest_signal_at(T0 + 1, sensor="ioda_bgp",
                                    country="TW", signal_source="bgp")
        flags = json.loads(row["flags"])
        assert flags[runner.FIRED_REASON_FLAG] == "BGP anomaly confirmed"
        assert flags["level"] == "critical"

    def test_no_reason_adds_no_key(self, store):
        adapter = self._adapter_with_reason("")
        plan = runner.run_due(T0, [adapter], {})
        http = client.HttpClient(session=_Session(_Response()),
                                 sleeper=lambda _s: None)
        runner.execute_plan(plan, AdapterRegistry([adapter]), client=http,
                            store=store, tick_id="t1")
        row = store.latest_signal_at(T0 + 1, sensor="ioda_bgp",
                                    country="TW", signal_source="bgp")
        assert runner.FIRED_REASON_FLAG not in json.loads(row["flags"])
