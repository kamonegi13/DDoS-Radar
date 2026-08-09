"""The composition itself. Everything the pure layers deliberately left out.

`v3/runtime/` owns threads, clocks and credentials; this module is the one
that actually takes them and hands the assembled thing a port. The split
is worth stating because it looks redundant: `v3/runtime/` is a set of
functions that CAN be given a store and a clock, and this is the code that
decides which store and which clock. Keeping them apart is what lets the
tick be tested with a dictionary and a fake transport.

Order matters and is not alphabetical:

  1. **the barrier goes up first.** Before a file is opened or a registry
     built, `radar.*` becomes unimportable in this process — because the
     landmine (`Threshold._default_resolver`) is reached from code that
     runs later, and a guard installed after the thing it guards is a
     guard that once was not there.
  2. **the environment is read once.** The names are derived: the server's
     own `KEY_IDS`, plus the config registry's variable keys, plus every
     `key_id` the adapters declare. One snapshot then threads through
     settings, credentials, the resolution chain and the auth surface, so
     four readers cannot disagree about what the environment said.
  3. **the ledger opens after the path has been refused a chance to be
     v1's.** `ServerSettings.__post_init__` does the refusing, so a bad
     path fails before a file is created rather than after a tick wrote.
  4. **auth is composed with whatever key material exists, or without.**
     No key means `build_provider` returns `None` and the session routes
     answer 503. v3 never generates one: production generates AND persists
     its own, and a second writer racing that file logs every live analyst
     out.

Nothing here starts the loop. `compose()` returns a `Deployment` whose
runtime is built and stopped; starting it is the entrypoint's explicit
call, which is the same contract every layer below holds.
"""
from __future__ import annotations

import time
from typing import Callable, Mapping, Optional

from v3.adapters import catalog
from v3.api import registry as api_registry
from v3.api.readonly import ReadOnlyLedger
from v3.api.request import Principal, ReadContext, ScenarioRef
from v3.api.write import WriteContext
from v3.api.writeonly import CommandLedger
from v3.api.ws_publish import UNPUBLISHED_EVENTS
from v3.commands.state import focus_state
from v3.config import registry as config_registry
from v3.fetch.client import HttpClient
from v3.kernel.errors import DomainError
from v3.ledger.store import LedgerStore
from v3.runtime import auth as AUTH
from v3.runtime import chain as CHAIN
from v3.runtime import config as CONFIG
from v3.runtime import geo as GEO
from v3.runtime import health as HEALTH
from v3.runtime import ops_health as OPS
from v3.runtime import scoring as SCORING
from v3.runtime import secrets as SECRETS
from v3.runtime import tick as TICK
from v3.runtime.loop import Runtime
from v3.server import isolation
from v3.server import settings as SETTINGS

#: What this deployment IS, said in every response and in the disclosure.
#: R4: the old system stays authoritative until parity passes, so a v3
#: answer is a second opinion — and a second opinion that does not say so
#: is the shape an operator acts on by mistake.
MODE_SHADOW = "shadow"
MODE_HEADER = "X-Noroshi-Mode"

#: Why the socket channel is not mounted.
#:
#: **The original reason expired in WP-4.3.** It read "there is no socket
#: client in `v3/ui/`", and that was true until `v3/ui/live.js` landed —
#: which was §7-2 #112's own stated release condition. Leaving the sentence
#: as it was would be the thing this project keeps finding: a recorded
#: reason that stopped being true and went on being served. It is served
#: literally, too, in `app_config`, and the page prints it in the connection
#: chip's tooltip — so a stale sentence here is a stale sentence an analyst
#: reads.
#:
#: What remains is not the reader. It is the mount, and the mount is two
#: decisions this module does not get to make on its own: `flask-socketio`
#: is deliberately absent from `requirements-v3.txt`, and
#: `tests/test_v3_server.py::TestDeliberateAbsences` asserts the channel is
#: NOT mounted. Both are reviewable declarations rather than oversights, so
#: the absence stays registered — with the reason it actually has now.
WEBSOCKET_ABSENT = (
    "socket チャネルは合成していない。読み手は WP-4.3 で着地した"
    "（v3/ui/live.js が購読・focus 不一致の破棄・接続 3 値 + 未マウントを"
    "実装する）ため、繰延の理由は「読み手がいない」ではなく「合成の判断が"
    "未了」である: flask-socketio は requirements-v3.txt から意図的に外して"
    "あり、影稼働に並行面を足す判断は parity 側の裁定に属する。"
    "イベント語彙と発行者の有無は v3/api/ws_publish.py の "
    "PUBLISHED_EVENTS / UNPUBLISHED_EVENTS がそのまま正（§7-2 #112）")


def key_names(registry) -> tuple[str, ...]:
    """Every environment name this deployment may read. Derived, not listed.

    Three sources, none of them a hardcoded inventory: the server's own
    settings, the configuration registry's variable keys, and the
    credentials the adapters themselves declare. A key nobody declared
    cannot be picked up, and the answer cannot drift from the declarations
    because it IS the declarations.
    """
    names = set(SETTINGS.KEY_IDS)
    names.update(config_registry.variable_keys())
    names.update(SECRETS.required_key_ids(registry.enabled()))
    return tuple(sorted(names))


class Deployment:
    """One composed, stopped, ready-to-start v3.

    Not a frozen dataclass: it owns a database handle, a thread and a
    `sys.meta_path` entry, and `close()` has to be able to give all three
    back. Everything it exposes is read-only in practice — the mutable
    part is the lifecycle, which is exactly what `v3/runtime/loop.py`
    already owns.
    """

    #: The chain arrives as `config_chain=`, never as `resolver=`. The
    #: discipline gate licenses the keyword `resolver` to exactly one file
    #: (`v3/config/resolution.py`) because a resolver built at an
    #: arbitrary call site is the G-15 shape; this is a constructor
    #: argument rather than an injection, and it is spelled differently so
    #: the gate does not have to distinguish the two by intent.
    def __init__(self, *, settings, store, registry, client, geography,
                 credentials, config_chain, auth_provider, runtime,
                 scenario_ids, bootstrap, barrier, clock):
        self.settings = settings
        self.store = store
        self.registry = registry
        self.client = client
        self.geography = geography
        self.credentials = credentials
        self.resolver = config_chain
        self.auth_provider = auth_provider
        self.runtime = runtime
        self.scenario_ids = tuple(scenario_ids)
        self.bootstrap = dict(bootstrap)
        self._barrier = barrier
        self._clock = clock
        self._closed = False
        #: The last completed tick's sweep coverage (G-19). Held here
        #: because only the layer that ran the tick saw what the tick
        #: PLANNED, and `/healthz` has to be able to say "this deployment
        #: is concluding from 40% of its catalogue" rather than serve the
        #: same body it would serve for a complete sweep. `None` until a
        #: tick finishes, which `sweep_monitor` reports as UNSUPPLIED and
        #: never as OK.
        self._last_sweep: Optional[Mapping] = None

    # ── the tick ────────────────────────────────────────────────────────
    def tick(self, now: Optional[float] = None):
        """One whole tick, in the CALLING thread. What the loop calls.

        `focused_scenario_id` comes from the command fold rather than from
        configuration: focus is a C1 command, its record IS the state
        (`v3/commands/state.py`), and a composition root that carried its
        own copy would be the second source that disagrees.

        The sequence chain's owner is not passed either, for a stronger
        reason: it is MEASURED inside the tick from that tick's own
        observations (`v3/runtime/chain.py`). There is nothing here to
        supply, which is what stops a constant being supplied.
        """
        at = float(self._clock() if now is None else now)
        report = TICK.run_tick(
            now=at, registry=self.registry, store=self.store,
            client=self.client, geography=self.geography,
            scenario_ids=self.scenario_ids, credentials=self.credentials,
            config=self.resolver,
            focused_scenario_id=focus_state(ReadOnlyLedger(self.store),
                                            until=at))
        # Recorded only on the way OUT, so a tick that raised leaves the
        # previous sweep in place rather than replacing it with a half
        # measurement — the health surface would then be reporting coverage
        # for a tick that never concluded.
        self._last_sweep = dict(report.sweep)
        return report

    # ── the API's seams ─────────────────────────────────────────────────
    def scenario_refs(self) -> tuple[ScenarioRef, ...]:
        """What the API is told about the scenarios. Built from the
        geography, because a second reader of deployment data is a second
        ledger that drifts.

        `chain_country` is the DECLARED core country and nothing else. A
        dual-core scenario reports `None` here and is honest about it:
        its owner is whichever belligerent is escalating at the instant
        the question is asked, so a value cached on a deployment-level
        projection would be a stale answer to a live question.
        """
        refs = []
        for scenario_id in self.scenario_ids:
            declared = self.geography.scenarios.get(scenario_id) or {}
            participants = declared.get("participants", {}) or {}
            core = declared.get("core_country")
            refs.append(ScenarioRef(
                scenario_id=scenario_id,
                participants={str(code).upper(): float(row.get("weight", 0.0))
                              for code, row in participants.items()},
                adversaries=GEO.adversaries_of(self.geography, scenario_id),
                roles={str(code).upper(): str(row.get("role", ""))
                       for code, row in participants.items()},
                chain_country=str(core).upper() if core else None))
        return tuple(refs)

    def observed_span_sec(self, now: float) -> Optional[float]:
        """How long this ledger has been accumulating, for the capacity
        monitor. The longest observed scenario span — an under-estimate
        while a scenario is young, which pushes `capacity` towards
        INSUFFICIENT rather than towards a confident projection."""
        spans = [HEALTH.history_span_sec(self.store, scenario_id, now=now)
                 for scenario_id in self.scenario_ids]
        widest = max(spans) if spans else 0.0
        return widest if widest > 0 else None

    def ops_probe(self, now: float) -> dict:
        """The deployment's operational facts, INCLUDING whether the loop
        is producing.

        The loop status is passed here rather than read by a handler for
        the reason every other field on this probe is: only the layer that
        owns the thread can see it. Passing it is what makes "healthy" a
        claim about the tick and not about the process — the distinction
        the shadow container spent an hour failing to make.
        """
        runtime = getattr(self, "runtime", None)
        return OPS.probe(self.settings.ledger_path,
                         span_sec=self.observed_span_sec(now), now=now,
                         loop_status=(None if runtime is None
                                      else runtime.status().as_dict()),
                         sweep=self._last_sweep,
                         interval_sec=self.settings.interval_sec)

    def app_config(self) -> dict:
        """R15c's payload. Deployment facts an analyst may act on.

        The ledger PATH is not here on purpose — a filesystem layout is
        not something a browser needs and is something a reader of the
        page should not be given. The basename is, because "which ledger
        am I looking at" is a real question during a shadow run.
        """
        return {
            "mode": MODE_SHADOW,
            "authoritative": False,
            "authority_note": "v1 が引き続き権威。本配備は parity 通過まで"
                              "並走する影であり、最終判断の根拠にしない",
            "ledger": self.settings.ledger_name,
            "tick_interval_sec": self.settings.interval_sec,
            "scenario_ids": list(self.scenario_ids),
            "adapters_enabled": len(self.registry.enabled()),
            "session_surface": AUTH.disclosure(self.auth_provider),
            "websocket": {"mounted": False, "reason": WEBSOCKET_ABSENT,
                          "unpublished": dict(UNPUBLISHED_EVENTS)},
        }

    def read_context(self, now: Optional[float] = None) -> ReadContext:
        at = float(self._clock() if now is None else now)
        return ReadContext(
            ledger=ReadOnlyLedger(self.store), now=at,
            scenarios=self.scenario_refs(),
            adapters=tuple(sorted(a.adapter_id.value
                                  for a in self.registry.all())),
            app_config=self.app_config(), config=self.resolver,
            auth=self.auth_provider, ops_health=self.ops_probe(at))

    def write_context(self, principal: Principal) -> WriteContext:
        """The write seam. Separate from the read one by construction, so a
        read route cannot receive a writer even by a factory's mistake."""
        return WriteContext(read=self.read_context(),
                            ledger=CommandLedger(self.store),
                            principal=principal)

    def principal_factory(self) -> Callable:
        return AUTH.principal_resolver(self.store, self.auth_provider)

    # ── disclosure ──────────────────────────────────────────────────────
    def scenarios_without_chain_owner(self) -> tuple[str, ...]:
        """Scenarios no measurement can give a sequence-chain owner.

        Not "unconfigured" — that mitigation is retired. The owner is
        chosen per tick from that tick's observations
        (`v3/runtime/chain.py`), so the only scenario left without one is
        a scenario with no candidates at all: it declares no
        `core_country` AND has no `principal_belligerent` participant at
        or above the weight floor. That is a hole in the geography, not a
        missing environment variable, and no amount of evidence fills it.

        The consequence is unchanged and is why this is announced at
        composition: the focused-only bonus fold calls
        `ScoringInputs.chain_country_for`, which RAISES for such a
        scenario. Nothing is focused at start-up, so the tick is fine; the
        first C1 focus command would make every subsequent tick raise, and
        NP3 keeps the loop alive around it, so conclusions quietly stop
        being written. Said at composition, "quietly stops" becomes "was
        told before it could happen".
        """
        return CHAIN.scenarios_without_cores(
            SCORING.scenarios_for(self.geography, self.scenario_ids))

    def announcements(self) -> tuple[str, ...]:
        """One plain sentence per degraded thing (NP6 / AP2 shape)."""
        lines = list(self.credentials.announcement())
        lines.extend(AUTH.announcement(self.auth_provider))
        if not self.bootstrap.get("created"):
            lines.append(
                f"bootstrap: {self.bootstrap.get('reason')} — "
                f"{self.bootstrap.get('note', '既存利用者がいます')}")
        unowned = self.scenarios_without_chain_owner()
        if unowned:
            lines.append(
                f"sequence chain: 所有国の候補が 1 国も無いシナリオ "
                f"{list(unowned)} — core_country が未宣言で、weight "
                f"{CHAIN.CORE_WEIGHT_FLOOR} 以上の "
                f"{CHAIN.PRINCIPAL_BELLIGERENT} 参加国も居ない。"
                f"この状態で focus を設定すると、focused ボーナスの"
                f"畳み込みが chain_country_for で例外を投げ、以後の"
                f"ティックが毎回失敗する（ループは NP3 で生き残るため、"
                f"結論行が静かに増えなくなる）。所有国は毎ティック観測から"
                f"選ぶ（§7-2 #115）ので、これは設定漏れではなく"
                f"シナリオ定義の穴である")
        return tuple(lines)

    def disclosure(self) -> dict:
        """What `--check` prints and what an operator reads before believing
        anything. Includes the absences, because an absence nobody declared
        is indistinguishable from a working part."""
        return {
            "mode": MODE_SHADOW,
            "settings": self.settings.as_dict(),
            "environment_keys": list(key_names(self.registry)),
            "adapters": {"total": len(self.registry),
                         "enabled": len(self.registry.enabled()),
                         "disabled": [a.adapter_id.value
                                      for a in self.registry.disabled()]},
            "scenarios": list(self.scenario_ids),
            "credentials": self.credentials.as_dict(),
            "auth": AUTH.disclosure(self.auth_provider),
            "bootstrap": dict(self.bootstrap),
            "announcements": list(self.announcements()),
            "runtime": self.runtime.status().as_dict(),
            "legacy_modules": list(isolation.legacy_modules()),
            "ops_health": self.ops_probe(float(self._clock())),
            "absent": {
                "websocket": WEBSOCKET_ABSENT,
                "sequence_chain_owner": list(
                    self.scenarios_without_chain_owner()),
                "deferred_p7": sorted(api_registry.deferred_ids()),
                "deferred_p7_detail": {item.p7_id: item.reason
                                       for item in api_registry.DEFERRED},
            },
        }

    # ── lifecycle ───────────────────────────────────────────────────────
    def close(self) -> None:
        """Stop the loop, close the handles, take the barrier down.

        Ordered stop-then-close: `Runtime.stop()` waits for the tick in
        flight, so the ledger's unit of work is never the thing that gets
        interrupted. Idempotent, because a composition that raised
        half-way through still has to be closable.
        """
        if self._closed:
            return
        self._closed = True
        try:
            self.runtime.stop(timeout_sec=30)
        finally:
            for resource in (self.client, self.store):
                closer = getattr(resource, "close", None)
                if callable(closer):
                    closer()
            self._barrier.remove()

    def __enter__(self) -> "Deployment":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _scenarios(geography, declared: tuple[str, ...]) -> tuple[str, ...]:
    """The scenarios this deployment watches. Declared, or every enabled one.

    An unknown id is refused rather than skipped: a deployment that
    watches four of the five scenarios it was told to watch looks exactly
    like a quiet fifth scenario.
    """
    if declared:
        unknown = [name for name in declared
                   if name not in geography.scenarios]
        if unknown:
            raise DomainError(
                f"unknown scenario(s) {unknown} in "
                f"{SETTINGS.SCENARIOS_KEY}; the geography declares "
                f"{sorted(geography.scenarios)}. A scenario silently "
                f"dropped from a sweep reads downstream as a quiet one.")
        return declared
    enabled = tuple(name for name, row in geography.scenarios.items()
                    if bool((row or {}).get("enabled", True)))
    if not enabled:
        raise DomainError(
            "the geography declares no enabled scenario, so a tick would "
            "fetch, write observations and conclude nothing")
    return enabled


def compose(settings=None, *, environment: Optional[Mapping[str, str]] = None,
            registry=None, geography=None, client=None,
            clock: Callable[[], float] = time.time,
            barrier: bool = True) -> Deployment:
    """Build the whole deployment. The only function that assembles v3.

    Every keyword after `settings` is an injection seam for tests and for
    the parity harness — a composition root that could only be exercised
    against the real network and the real `geo_data.json` is a composition
    root nobody tests.
    """
    guard = isolation.LegacyImportBarrier()
    if barrier:
        isolation.assert_legacy_absent("compose")
        guard.install()
    #: What has been opened so far. A composition that raises half-way
    #: through must not leave a database handle and a `sys.meta_path`
    #: entry behind — a test that did would poison every test after it,
    #: and a deployment that did would hold a write lock nobody owns.
    opened: list = []
    try:
        adapters = registry if registry is not None else \
            catalog.build_registry()
        env = dict(environment) if environment is not None else \
            dict(SECRETS.from_environment(key_names(adapters)))
        config = settings if settings is not None else \
            SETTINGS.from_environment(env)
        world = geography if geography is not None else \
            GEO.load(config.geo_path)
        scenario_ids = _scenarios(world, config.scenario_ids)

        credentials = SECRETS.resolve(adapters.enabled(), env)
        transport = client if client is not None else \
            HttpClient(credentials=credentials.material)
        opened.append(transport)
        store = LedgerStore(config.ledger_path)
        opened.append(store)
        resolver = CONFIG.build_resolver(env)
        provider = AUTH.build_provider(env)
        report = AUTH.bootstrap(store, source=env, now=clock())

        deployment = Deployment(
            settings=config, store=store, registry=adapters,
            client=transport, geography=world, credentials=credentials,
            config_chain=resolver, auth_provider=provider, runtime=None,
            scenario_ids=scenario_ids, bootstrap=report, barrier=guard,
            clock=clock)
        deployment.runtime = Runtime(
            tick=deployment.tick, interval_sec=config.interval_sec,
            clock=clock, on_error=_log_tick_failure)
        return deployment
    except BaseException:
        for resource in reversed(opened):
            closer = getattr(resource, "close", None)
            if callable(closer):
                try:
                    closer()
                except BaseException:     # pragma: no cover - best effort
                    pass
        guard.remove()
        raise


def _log_tick_failure(failure: BaseException) -> None:
    """A failed tick is counted by the runtime and printed here.

    Printed rather than swallowed: NP3 says the loop survives a bad tick,
    and `Runtime.status()` carries the count, but a shadow run whose
    failures were only ever a number is a shadow run nobody can debug.
    """
    import logging
    logging.getLogger("v3.server").error("tick failed: %s: %s",
                                         type(failure).__name__, failure)


__all__ = ["Deployment", "compose", "key_names", "MODE_SHADOW", "MODE_HEADER",
           "WEBSOCKET_ABSENT"]
