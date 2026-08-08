"""WP-4.4 — the entrypoint, and the proofs that it cannot touch v1.

Phases 2-4 built a composition root, an API, a frontend and an auth
surface. Nothing called `create_blueprint`, so none of it could run. This
suite is the specification for the thing that does, and the shape of the
specification is set by R4: **the old system stays authoritative until
parity passes**, so a v3 that ran was only acceptable if it could be shown
not to reach v1.

Four proofs carry that, and each is structural rather than a promise:

  1. **the ledger file cannot be a v1 file.** `ServerSettings` refuses
     `radar.db`, its WAL siblings, `convergence_snapshots.db` (A-09's
     second store) and anything under `radar/persistence/`. A typo in an
     env var is the accident this exists for.
  2. **the v1 database is byte-identical after a boot.** A whole tick
     plus a served page plus every public route, against fixtures, and
     then mtime + sha256 of a real v1-shaped file.
  3. **no `radar.*` module is imported, including transitively.** Proved
     twice: by a subprocess that composes and inspects `sys.modules`, and
     by an import barrier the composition root installs, which turns the
     one live landmine — `Threshold._default_resolver` imports
     `radar.config_layered` on a bare registry-backed resolve — from a
     silent v1 boot into a raised error.
  4. **only one module in the reachable graph opens sqlite.** So "no
     writes to any v1 table" is a property of the import graph, not of a
     reviewer's attention.

The fifth thing proved here is that the unsupported invocations fail
loudly. `python -m package.module` boots the parent package first, which
is how the ops_health check nearly started a second app inside the live
container; `v3/server/main.py` therefore refuses to be `__main__` before
it imports anything at all.
"""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from v3.adapters.types import (CYBER, INFO, PHYSICAL, STATUS_FIRED,
                               AdapterId, ObservationDraft, RequestSpec,
                               SourceAdapter)
from v3.api.request import Principal, ReadContext
from v3.api.write import WriteContext
from v3.fetch.registry import AdapterRegistry
from v3.kernel.errors import DomainError
from v3.kernel.window import Window
from v3.runtime import geo as geo_module
from v3.server import composition, isolation, main as main_module, settings \
    as settings_module, ui as ui_module

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER_DIR = REPO_ROOT / "v3" / "server"
NOW = 1_800_000_000.0
SCENARIO = "taiwan_contingency"

GEO_DOC = {
    "ISR_HOTSPOTS": [
        {"name": "Taiwan Strait Median Line", "lat": 24.5, "lng": 120.5,
         "theater": "TW", "radius_km": 200},
    ],
    "CHOKEPOINTS": [{"name": "Bashi Channel", "lat": 21.5, "lng": 121.0,
                     "country": "TW"}],
    "COUNTRY_COORDS": {"TW": {"lat": 23.7, "lng": 121.0, "name": "Taiwan"},
                       "CN": {"lat": 35.0, "lng": 105.0, "name": "China"}},
    "SCENARIOS": {SCENARIO: {
        "participants": {"TW": {"weight": 1.0, "role": "primary_target"},
                         "CN": {"weight": 0.7, "role": "adversary"}}}},
}


# ── fixtures: a registry and a transport that never reach a socket ─────────
class _Payload:
    def __init__(self, url="https://example.test/x"):
        self.url, self.label, self.body = url, "", b"{}"
        self.status, self.content_type = 200, "application/json"

    def json(self):
        return {}


class _Outcome:
    def __init__(self, url):
        self.outcome, self.url, self.status = "ok", url, 200
        self.latency_ms, self.attempts, self.detail = 1.0, 1, ""
        self.body_sha256, self.url_sha256 = "0" * 64, "1" * 64
        self.payload = _Payload(url)
        self.succeeded = True


class _Client:
    def __init__(self):
        self.sent = []

    def fetch(self, spec, *, now, auth=None, **kwargs):
        self.sent.append(spec)
        return _Outcome(spec.url)

    def pause(self, seconds):
        pass

    def close(self):
        pass


def _draft(source, domain, country="TW"):
    return ObservationDraft(
        signal_source=source, domain=domain, country=country,
        status=STATUS_FIRED, raw_score=4.0, value=f"{source} fired",
        reason=f"{source} test firing")


def _adapter(name, category, drafts):
    return SourceAdapter(
        adapter_id=AdapterId(name), category=category,
        cadence=Window.from_days(1.0, cadence_sec=1.0),
        requests=(RequestSpec(url=f"https://{name}.test/x"),),
        normalize=lambda payload, context, _d=drafts: tuple(_d),
        freshness_horizon_sec=86400.0, rate_limit_group=name)


@pytest.fixture
def registry():
    return AdapterRegistry([
        _adapter("threatfox", "cyber", (_draft("threatfox", CYBER),)),
        _adapter("ripe_atlas", "physical", (_draft("ripe_atlas", PHYSICAL),)),
        _adapter("gdelt", "info", (_draft("gdelt", INFO),)),
    ])


@pytest.fixture
def geography():
    return geo_module.from_document(GEO_DOC)


@pytest.fixture
def geo_file(tmp_path):
    path = tmp_path / "geo_data.json"
    path.write_text(json.dumps(GEO_DOC), encoding="utf-8")
    return path


def _run_python(code: str) -> subprocess.CompletedProcess:
    """A fresh interpreter at the repository root.

    Used wherever the property under test is about `sys.modules` or
    `sys.meta_path`: this session imports `radar` during collection of the
    legacy suites, so an in-process assertion about the legacy tree being
    absent would be asserting something about pytest, not about v3.
    """
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, cwd=str(REPO_ROOT), timeout=300)


def _settings(tmp_path, **overrides):
    base = {"ledger_path": str(tmp_path / "v3data" / "noroshi_v3.db"),
            "scenario_ids": (SCENARIO,), "cookie_secure": False}
    base.update(overrides)
    return settings_module.ServerSettings(**base)


@pytest.fixture
def deployment(tmp_path, registry, geography):
    built = composition.compose(
        _settings(tmp_path), environment={}, registry=registry, barrier=False,
        geography=geography, client=_Client(), clock=lambda: NOW)
    try:
        yield built
    finally:
        built.close()


# ── 1. the ledger file cannot be a v1 file ────────────────────────────────
class TestTheLedgerPathCannotBeAV1File:
    @pytest.mark.parametrize("name", ["radar.db", "radar.db-wal",
                                      "radar.db-shm",
                                      "convergence_snapshots.db"])
    def test_a_v1_database_filename_is_refused(self, tmp_path, name):
        with pytest.raises(DomainError) as caught:
            isolation.assert_isolated_ledger(str(tmp_path / name))
        assert name in str(caught.value)

    def test_the_v1_persistence_directory_is_refused_whatever_the_name(
            self, tmp_path):
        path = tmp_path / "radar" / "persistence" / "v3.db"
        with pytest.raises(DomainError):
            isolation.assert_isolated_ledger(str(path))

    def test_settings_refuse_a_v1_ledger_at_construction(self, tmp_path):
        with pytest.raises(DomainError):
            _settings(tmp_path, ledger_path=str(tmp_path / "radar.db"))

    def test_the_v1_port_is_refused(self, tmp_path):
        with pytest.raises(DomainError) as caught:
            _settings(tmp_path, port=isolation.V1_PORT)
        assert str(isolation.V1_PORT) in str(caught.value)

    def test_an_ordinary_v3_path_is_accepted(self, tmp_path):
        resolved = isolation.assert_isolated_ledger(
            str(tmp_path / "v3data" / "noroshi_v3.db"))
        assert resolved.endswith("noroshi_v3.db")

    def test_the_environment_must_supply_a_ledger_path(self):
        with pytest.raises(DomainError) as caught:
            settings_module.from_environment({})
        assert settings_module.LEDGER_PATH_KEY in str(caught.value)

    def test_the_environment_path_is_guarded_too(self, tmp_path):
        with pytest.raises(DomainError):
            settings_module.from_environment(
                {settings_module.LEDGER_PATH_KEY: str(tmp_path / "radar.db")})


# ── 2. the v1 database is byte-identical after a boot ─────────────────────
def _v1_database(directory: Path) -> Path:
    """A real sqlite file, shaped like v1's, in a directory named like v1's."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "radar.db"
    conn = sqlite3.connect(str(path))
    conn.execute("CREATE TABLE threat_levels (id INTEGER PRIMARY KEY, "
                 "scenario TEXT, level INTEGER)")
    conn.execute("INSERT INTO threat_levels (scenario, level) VALUES (?, ?)",
                 (SCENARIO, 4))
    conn.commit()
    conn.close()
    return path


def _fingerprint(path: Path):
    stat = path.stat()
    return (stat.st_mtime_ns, stat.st_size,
            hashlib.sha256(path.read_bytes()).hexdigest())


class TestTheV1DatabaseIsUntouchedByABoot:
    def test_a_whole_boot_leaves_the_v1_file_byte_identical(
            self, tmp_path, registry, geography):
        v1_dir = tmp_path / "radar" / "persistence"
        v1 = _v1_database(v1_dir)
        before = _fingerprint(v1)
        before_listing = sorted(p.name for p in v1_dir.iterdir())

        built = composition.compose(
            _settings(tmp_path), environment={}, registry=registry, barrier=False,
            geography=geography, client=_Client(), clock=lambda: NOW)
        try:
            from v3.server.app import create_app
            built.tick(NOW)
            client = create_app(built).test_client()
            for path in ("/healthz", "/api/v3/app_config", "/api/v3/scenarios",
                         "/", "/v3.css"):
                client.get(path)
        finally:
            built.close()

        assert _fingerprint(v1) == before
        assert sorted(p.name for p in v1_dir.iterdir()) == before_listing

    def test_the_v3_ledger_was_actually_written(self, tmp_path, registry,
                                                geography):
        """The negative proof needs a positive one beside it.

        A boot that wrote nothing anywhere would pass the test above and
        prove nothing at all.
        """
        built = composition.compose(
            _settings(tmp_path), environment={}, registry=registry, barrier=False,
            geography=geography, client=_Client(), clock=lambda: NOW)
        try:
            report = built.tick(NOW)
            assert report.observations_written > 0
        finally:
            built.close()
        assert Path(built.settings.ledger_path).exists()


# ── 3. no radar module, including transitively ────────────────────────────
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestNoLegacyModuleIsReachable:
    def test_composing_imports_no_radar_module(self, tmp_path):
        code = (
            "import sys, json\n"
            "from v3.server import composition, settings\n"
            "from v3.runtime import geo\n"
            f"cfg = settings.ServerSettings(ledger_path={str(tmp_path / 'a.db')!r},"
            f" scenario_ids=({SCENARIO!r},))\n"
            "dep = composition.compose(cfg, environment={})\n"
            "dep.close()\n"
            "print(json.dumps(sorted(m for m in sys.modules "
            "if m == 'radar' or m.startswith('radar.'))))\n")
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True,
                              cwd=str(REPO_ROOT), timeout=300)
        assert proc.returncode == 0, proc.stderr
        assert json.loads(proc.stdout.strip().splitlines()[-1]) == []

    def test_the_server_package_never_names_the_legacy_tree(self):
        """Stronger than the discipline gate, which allows a lazy import."""
        offenders = []
        for path in sorted(SERVER_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            for number, line in enumerate(source.splitlines(), start=1):
                stripped = line.strip()
                if stripped.startswith(("import radar", "from radar")):
                    offenders.append(f"{path.name}:{number}")
        assert offenders == []

    def test_the_discipline_gate_passes_over_the_server_package(self):
        proc = subprocess.run(
            [sys.executable, "scripts/check_kernel_discipline.py", "v3/server"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_the_reachable_graph_has_exactly_two_sqlite_openers(self):
        """"No writes to a v1 table" starts as a property of the graph.

        Two modules in the reachable set can open a database, and both
        take their path from the caller: `v3/ledger/store.py` (the v3
        ledger, whose path this entrypoint refuses to let be a v1 file)
        and `v3/parity/ledger.py` (the harness's own separate file,
        reachable only because `v3/runtime/scoring.py` borrows the parity
        input adapter). The server constructs neither by accident — the
        test below watches every connect during a whole boot.
        """
        code = (
            "import sys\n"
            "import v3.server.composition, v3.server.app, v3.server.main\n"
            "print('\\n'.join(sorted(\n"
            "    getattr(mod, '__file__', '') or ''\n"
            "    for name, mod in sys.modules.items()\n"
            "    if name.startswith('v3.'))))\n")
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True,
                              cwd=str(REPO_ROOT), timeout=300)
        assert proc.returncode == 0, proc.stderr
        openers = []
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            source = Path(line).read_text(encoding="utf-8")
            if "sqlite3.connect" in source:
                openers.append(Path(line).name)
        assert sorted(openers) == ["ledger.py", "store.py"], openers

    def test_the_server_package_constructs_no_second_store(self):
        for path in sorted(SERVER_DIR.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            assert "ParityLedger" not in source, path.name
            assert "sqlite3" not in source, path.name

    def test_every_database_a_boot_opens_is_the_v3_ledger(
            self, tmp_path, registry, geography, monkeypatch):
        """The behavioural half. Watches `sqlite3.connect` for a whole boot."""
        opened = []
        real_connect = sqlite3.connect

        def _watched(target, *args, **kwargs):
            opened.append(str(target))
            return real_connect(target, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", _watched)
        settings = _settings(tmp_path)
        built = composition.compose(
            settings, environment={}, registry=registry, barrier=False,
            geography=geography,
            client=_Client(), clock=lambda: NOW)
        try:
            from v3.server.app import create_app
            built.tick(NOW)
            client = create_app(built).test_client()
            client.get("/healthz")
            client.get("/api/v3/app_config")
        finally:
            built.close()
        assert opened, "the boot opened no database at all"
        # The read handle is a `file:...?mode=ro` URI — same file, and the
        # query string is what makes it unable to write.
        names = {Path(item.split("?", 1)[0]).name for item in opened}
        assert names == {Path(settings.ledger_path).name}, opened


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestTheImportBarrier:
    def test_an_installed_barrier_refuses_the_legacy_tree(self):
        barrier = isolation.LegacyImportBarrier().install()
        try:
            with pytest.raises(isolation.LegacyImportRefused):
                barrier.find_spec("radar.config_layered")
            with pytest.raises(isolation.LegacyImportRefused):
                barrier.find_spec("radar")
        finally:
            barrier.remove()

    def test_the_barrier_lets_everything_else_through(self):
        barrier = isolation.LegacyImportBarrier()
        assert barrier.find_spec("json") is None
        assert barrier.find_spec("radarless") is None

    def test_composition_installs_and_close_removes_it(self, tmp_path):
        """In a SUBPROCESS, and that is not incidental.

        This repository's own pytest session imports `radar` while
        collecting the legacy suites, so by the time any test runs, the
        interpreter is one `compose()` would refuse — correctly. Every
        in-process fixture in this file therefore passes `barrier=False`,
        and the barrier's real behaviour is proved where nothing has
        booted v1: a fresh interpreter.
        """
        code = (
            "import sys\n"
            "from v3.server import composition, isolation, settings\n"
            f"cfg = settings.ServerSettings(ledger_path={str(tmp_path / 'b.db')!r},"
            f" scenario_ids=({SCENARIO!r},))\n"
            "dep = composition.compose(cfg, environment={})\n"
            "installed = any(isinstance(h, isolation.LegacyImportBarrier)\n"
            "                for h in sys.meta_path)\n"
            "dep.close()\n"
            "removed = not any(isinstance(h, isolation.LegacyImportBarrier)\n"
            "                  for h in sys.meta_path)\n"
            "print(installed, removed)\n")
        proc = _run_python(code)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip().splitlines()[-1] == "True True"

    def test_a_bare_registry_backed_resolve_raises_instead_of_booting_v1(
            self, tmp_path):
        """The one live landmine, made loud.

        `Threshold.registry_backed(...).resolve()` with no injected
        resolver terminates in `from radar import config_layered`, which
        boots the Flask app and ~40 threads against the production
        database. Inside a composed deployment it must raise — and the
        proof has to be a subprocess, because a `radar` already in
        `sys.modules` is served from the cache without consulting
        `sys.meta_path` at all.
        """
        code = (
            "from v3.kernel import Threshold\n"
            "from v3.server import composition, settings\n"
            f"cfg = settings.ServerSettings(ledger_path={str(tmp_path / 'c.db')!r},"
            f" scenario_ids=({SCENARIO!r},))\n"
            "dep = composition.compose(cfg, environment={})\n"
            "try:\n"
            "    Threshold.registry_backed('DOMAIN_CAP', unit='score').resolve()\n"
            "    print('NO-RAISE')\n"
            "except BaseException as exc:\n"
            "    print('RAISED', 'radar' in str(exc))\n"
            "finally:\n"
            "    dep.close()\n")
        proc = _run_python(code)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip().splitlines()[-1] == "RAISED True"

    def test_composing_inside_a_process_that_already_booted_v1_is_refused(
            self, tmp_path, registry, geography, monkeypatch):
        monkeypatch.setitem(sys.modules, "radar.fake_marker", object())
        with pytest.raises(DomainError) as caught:
            composition.compose(_settings(tmp_path), environment={},
                                registry=registry, geography=geography,
                                client=_Client(), clock=lambda: NOW)
        assert "radar.fake_marker" in str(caught.value)


# ── 4. the composition itself ─────────────────────────────────────────────
class TestWhatTheEntrypointComposes:
    def test_it_composes_every_named_part(self, deployment):
        for part in ("settings", "store", "registry", "client", "geography",
                     "credentials", "resolver", "runtime", "scenario_ids"):
            assert getattr(deployment, part) is not None, part

    def test_the_read_context_carries_the_chain_and_the_probe(self,
                                                              deployment):
        context = deployment.read_context()
        assert isinstance(context, ReadContext)
        assert context.config is deployment.resolver
        assert context.ops_health is not None
        assert context.scenarios and context.scenarios[0].scenario_id \
            == SCENARIO

    def test_the_write_context_is_a_separate_factory(self, deployment):
        context = deployment.write_context(
            Principal(user_id="u-1", role="analyst"))
        assert isinstance(context, WriteContext)

    def test_the_runtime_owns_exactly_one_thread(self, deployment):
        before = threading.active_count()
        deployment.runtime.start()
        try:
            assert threading.active_count() == before + 1
        finally:
            deployment.runtime.stop(timeout_sec=5)

    def test_the_credential_posture_is_disclosed_not_silent(self, deployment):
        disclosure = deployment.disclosure()
        assert "credentials" in disclosure
        assert "announcements" in disclosure

    def test_no_session_surface_without_key_material(self, deployment):
        assert deployment.auth_provider is None
        assert any("session surface: ABSENT" in line
                   for line in deployment.disclosure()["announcements"])

    def test_a_supplied_key_builds_the_session_surface(self, tmp_path,
                                                       registry, geography):
        from v3.auth import session as SESSION
        built = composition.compose(
            _settings(tmp_path), registry=registry, geography=geography,
            client=_Client(), clock=lambda: NOW, barrier=False,
            environment={SESSION.SIGNING_KEY_ID: "k" * 48})
        try:
            assert built.auth_provider is not None
        finally:
            built.close()

    def test_the_scenarios_default_to_the_geography(self, tmp_path, registry,
                                                    geography):
        built = composition.compose(
            _settings(tmp_path, scenario_ids=()), environment={},
            registry=registry, geography=geography, client=_Client(),
            clock=lambda: NOW, barrier=False)
        try:
            assert built.scenario_ids == (SCENARIO,)
        finally:
            built.close()

    def test_an_unknown_scenario_is_refused_at_composition(self, tmp_path,
                                                           registry,
                                                           geography):
        with pytest.raises(DomainError):
            composition.compose(
                _settings(tmp_path, scenario_ids=("no_such_scenario",)),
                environment={}, registry=registry, geography=geography,
                client=_Client(), clock=lambda: NOW, barrier=False)

    def test_the_environment_is_read_once_and_the_names_are_derivable(
            self, registry):
        names = composition.key_names(registry)
        assert settings_module.LEDGER_PATH_KEY in names
        assert names == tuple(sorted(set(names)))


# ── 5. the web surface ────────────────────────────────────────────────────
@pytest.fixture
def web(deployment):
    from v3.server.app import create_app
    return create_app(deployment).test_client()


class TestTheWebSurface:
    def test_healthz_answers(self, web):
        response = web.get("/healthz")
        assert response.status_code == 200

    def test_the_api_is_mounted_under_its_prefix(self, web):
        """Mounted means routed. `/healthz` is the one public route
        (`routes.py` R15h), so anything else answering 401 rather than 404
        is the proof that the blueprint is registered."""
        assert web.get("/api/v3/app_config").status_code == 401
        assert web.get("/api/v3/not-a-route").status_code == 404

    def test_app_config_says_the_deployment_is_not_authoritative(
            self, deployment):
        config = deployment.app_config()
        assert config["mode"] == composition.MODE_SHADOW
        assert config["authoritative"] is False

    def test_app_config_does_not_leak_the_ledger_path(self, deployment):
        served = json.dumps(deployment.app_config(), ensure_ascii=False)
        assert deployment.settings.ledger_path not in served
        assert deployment.settings.ledger_name in served

    def test_a_protected_route_is_401_without_a_principal(self, web):
        assert web.get("/api/v3/scenarios").status_code == 401

    def test_the_session_routes_are_503_without_key_material(self, web):
        response = web.post("/api/v3/auth/login",
                            json={"user_id": "a", "password": "b"})
        assert response.status_code == 503

    def test_every_response_declares_the_shadow_mode(self, web):
        assert web.get("/healthz").headers.get(composition.MODE_HEADER) \
            == composition.MODE_SHADOW


class TestTheFrontendIsServed:
    def test_the_index_is_served_at_the_root(self, web):
        response = web.get("/")
        assert response.status_code == 200
        assert b"<html lang=\"ja\">" in response.data

    def test_every_asset_on_disk_is_reachable(self, web):
        for name in ui_module.asset_names():
            assert web.get(f"/{name}").status_code == 200, name

    def test_the_asset_list_is_derived_from_the_directory(self):
        names = ui_module.asset_names()
        assert ui_module.INDEX_NAME in names
        assert set(names) == {p.name for p in ui_module.UI_DIR.iterdir()
                              if p.is_file()}

    def test_there_is_no_catch_all_route(self, web):
        assert web.get("/../config.env").status_code in (400, 404)
        assert web.get("/not-an-asset.js").status_code == 404

    def test_a_missing_index_is_a_composition_failure_not_a_404(self,
                                                                tmp_path):
        empty = tmp_path / "ui"
        empty.mkdir()
        with pytest.raises(DomainError):
            ui_module.asset_names(empty)


# ── 6. what is deliberately absent ────────────────────────────────────────
class TestDeliberateAbsences:
    def test_no_socket_channel_is_mounted(self, deployment):
        from v3.server.app import create_app
        app = create_app(deployment)
        assert not hasattr(app, "socketio")
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        assert not any("socket.io" in rule for rule in rules)

    def test_the_absence_is_declared_with_its_reason(self, deployment):
        absent = deployment.disclosure()["absent"]
        assert "websocket" in absent
        assert absent["websocket"]

    def test_the_deferred_p7_entries_are_carried_into_the_disclosure(
            self, deployment):
        from v3.api import registry as api_registry
        absent = deployment.disclosure()["absent"]
        assert set(absent["deferred_p7"]) == set(api_registry.deferred_ids())

    def test_a_scenario_with_no_chain_owner_is_announced_before_it_bites(
            self, deployment):
        """The trap wiring found: focusing a scenario with no chain owner
        makes every later tick raise, and NP3 keeps the loop alive around
        it — so conclusions quietly stop. Said at composition instead."""
        assert deployment.scenarios_without_chain_owner() == (SCENARIO,)
        assert any("sequence chain" in line
                   for line in deployment.announcements())
        assert deployment.disclosure()["absent"]["sequence_chain_owner"] \
            == [SCENARIO]

    def test_supplying_the_owner_clears_the_announcement(self, tmp_path,
                                                         registry, geography):
        built = composition.compose(
            _settings(tmp_path, chain_countries={SCENARIO: "TW"}),
            environment={}, registry=registry, geography=geography,
            client=_Client(), clock=lambda: NOW, barrier=False)
        try:
            assert built.scenarios_without_chain_owner() == ()
            assert not any("sequence chain" in line
                           for line in built.announcements())
        finally:
            built.close()


# ── 7. the invocation guards ──────────────────────────────────────────────
def _invoke(args, env_extra=None):
    env = dict(os.environ)
    env.pop("NOROSHI_V3_LEDGER_PATH", None)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, *args], capture_output=True,
                          text=True, cwd=str(REPO_ROOT), timeout=300, env=env)


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestUnsupportedInvocationsFailLoudly:
    def test_running_the_module_directly_is_refused(self):
        proc = _invoke(["-m", "v3.server.main"])
        assert proc.returncode != 0
        assert "python -m v3.server" in (proc.stdout + proc.stderr)

    def test_running_the_file_as_a_script_is_refused(self):
        proc = _invoke(["v3/server/main.py"])
        assert proc.returncode != 0
        assert "python -m v3.server" in (proc.stdout + proc.stderr)

    def test_the_supported_invocation_composes_and_reports(self, tmp_path):
        proc = _invoke(["-m", "v3.server", "--check"], {
            settings_module.LEDGER_PATH_KEY: str(tmp_path / "check.db")})
        assert proc.returncode == 0, proc.stdout + proc.stderr
        report = json.loads(proc.stdout)
        assert report["legacy_modules"] == []
        assert report["mode"] == composition.MODE_SHADOW

    def test_check_binds_no_port_and_starts_no_loop(self, tmp_path):
        proc = _invoke(["-m", "v3.server", "--check"], {
            settings_module.LEDGER_PATH_KEY: str(tmp_path / "check2.db")})
        report = json.loads(proc.stdout)
        assert report["runtime"]["running"] is False
        assert report["runtime"]["ticks"] == 0

    def test_a_missing_ledger_path_fails_with_the_key_name(self):
        proc = _invoke(["-m", "v3.server", "--check"])
        assert proc.returncode != 0
        assert settings_module.LEDGER_PATH_KEY in (proc.stdout + proc.stderr)


class TestTheDeploymentShapeIsBesideV1NotInsteadOfIt:
    """The compose/image half of the isolation.

    Text assertions rather than a YAML parse: the repository has no YAML
    dependency, and what matters here is the presence or absence of exact
    strings — a shadow service that mounted `radar-data` would contain the
    word, and no amount of structural parsing would make that clearer.
    """

    @staticmethod
    def _directives(path: Path) -> str:
        """The file with its comment lines removed.

        Both files argue their case in comments, so a naive substring
        search finds `radar-data` in the sentence explaining that it is
        not mounted. What is asserted here is what docker READS.
        """
        return "\n".join(
            line for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#"))

    @property
    def compose(self) -> str:
        return self._directives(REPO_ROOT / "docker-compose.yml")

    @property
    def dockerfile(self) -> str:
        return self._directives(REPO_ROOT / "Dockerfile.v3")

    def test_the_shadow_is_behind_a_profile(self):
        assert 'profiles: ["shadow"]' in self.compose

    def test_the_shadow_has_its_own_container_port_and_volume(self):
        text = self.compose
        assert "container_name: noroshi-v3-shadow" in text
        assert '"8300:8300"' in text
        assert "v3-shadow-data:/app/v3data" in text
        assert "v3-shadow-data:" in text

    def test_the_shadow_never_mounts_v1s_volume_or_config_file(self):
        shadow = self.compose.split("v3_shadow:", 1)[1].split("\nvolumes:",
                                                              1)[0]
        assert "radar-data" not in shadow
        assert "./config.env:/app/config.env" not in shadow
        assert "/app/radar" not in shadow

    def test_v1s_own_secrets_are_blanked_in_the_shadow(self):
        """`env_file: config.env` brings the whole file, v1's key included.

        v3 reads neither name, but a shadow container holding the live
        signing key is a container whose compromise forges v1 tokens.
        """
        shadow = self.compose.split("v3_shadow:", 1)[1].split("\nvolumes:",
                                                              1)[0]
        assert "- JWT_SECRET_KEY=\n" in shadow + "\n"
        assert "- DEFAULT_ADMIN_PASSWORD=\n" in shadow + "\n"

    def test_v1s_service_definition_is_untouched(self):
        radar = self.compose.split("radar:", 1)[1].split("v3_shadow:", 1)[0]
        assert '"8000:8000"' in radar
        assert "radar-data:/app/radar/persistence" in radar
        assert "8300" not in radar

    def test_the_v3_image_contains_no_legacy_tree(self):
        text = self.dockerfile
        assert "COPY radar/" not in text
        assert "COPY v3/" in text
        assert "requirements-v3.txt" in text
        assert "requirements.txt" not in text.replace("requirements-v3.txt",
                                                      "")

    def test_the_v3_image_calls_the_factory_and_pins_one_worker(self):
        text = self.dockerfile
        assert main_module.GUNICORN_APP in text
        assert '"-w", "1"' in text
        assert "--preload" not in text


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestTheWsgiFactoryIsAnExplicitCall:
    def test_importing_main_starts_nothing(self):
        proc = _invoke(["-c", "import threading, v3.server.main; "
                              "print(threading.active_count())"])
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "1"

    def test_the_factory_is_named_so_gunicorn_can_call_it(self):
        assert callable(main_module.build_wsgi)
        assert main_module.GUNICORN_APP.endswith("build_wsgi()")
