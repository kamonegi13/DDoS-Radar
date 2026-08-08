"""WP-4.1 — the L6 boundary, and the shape of what it may import.

`v3/api/` is a public surface, which is the kind of package that grows a
framework import, a thread and an environment read without anyone
deciding to add them. The invariants every other v3 package holds apply
here unchanged, and the one apparent exception — a web server — is not
an exception at all:

  * **import is inert.** No thread, no socket, no database, no output.
  * **no environment read.** `v3/runtime/secrets.py` remains the only
    module under `v3/` that may touch `os.environ`; this test proves the
    licence did not widen to the API.
  * **no HTTP client.** The discipline gate's egress closure covers
    `v3/api/` too, with NOTHING added to its allow-list. A server binding
    answers calls; it does not make them, so `v3/fetch/client.py` stays
    the only egress and the gate needs no scoped exemption for this WP.
  * **no legacy import.** Importing `radar.*` boots the Flask app and
    ~40 sensor threads (B-01).
  * **the handler layer runs without a server.** `v3/api/binding.py` is
    the only module that names Flask, and it imports it inside the
    factory, so the whole surface is exercisable with no web framework
    installed.
"""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = REPO_ROOT / "v3" / "api"
BINDING = API_DIR / "binding.py"
GATE = REPO_ROOT / "scripts" / "check_kernel_discipline.py"

_WEB_FRAMEWORKS = frozenset({"flask", "flask_socketio", "werkzeug",
                             "gevent", "eventlet"})


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, cwd=str(REPO_ROOT), timeout=180)


def _modules():
    return [path for path in sorted(API_DIR.rglob("*.py"))
            if path.name != "__init__.py"]


def _module_names():
    names = []
    for path in sorted(API_DIR.rglob("*.py")):
        relative = path.relative_to(REPO_ROOT).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        names.append(".".join(parts))
    return names


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestImportIsInert:
    def test_importing_the_api_starts_no_thread(self):
        proc = _run("import threading, v3.api; print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    def test_importing_the_api_pulls_in_no_legacy_module(self):
        proc = _run("import sys, v3.api; print(any(m == 'radar' or "
                    "m.startswith('radar.') for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    def test_importing_the_api_prints_nothing(self):
        proc = _run("import v3.api")
        assert proc.stdout == "" and proc.stderr == ""

    def test_importing_the_api_pulls_in_no_web_framework(self):
        proc = _run(
            "import sys, v3.api, v3.api.binding; "
            "print(sorted(m for m in sys.modules if m.split('.')[0] in "
            f"{sorted(_WEB_FRAMEWORKS)!r}))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "[]", (
            "importing the API pulled in a web framework; the binding must "
            "import Flask inside its factory so the handler layer stays "
            "testable without a server")

    def test_every_module_is_individually_inert(self):
        for name in _module_names():
            proc = _run(f"import threading; import {name}; "
                        f"print(threading.active_count())")
            assert proc.returncode == 0, f"{name}: {proc.stderr}"
            assert proc.stdout.strip() == "1", name


class TestTheDisciplineGateCoversThisPackage:
    def test_the_gate_passes_over_the_api_package(self):
        proc = subprocess.run([sys.executable, str(GATE), "v3/api"],
                              capture_output=True, text=True,
                              cwd=str(REPO_ROOT), timeout=180)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_the_gate_still_passes_over_all_of_v3(self):
        proc = subprocess.run([sys.executable, str(GATE)],
                              capture_output=True, text=True,
                              cwd=str(REPO_ROOT), timeout=180)
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_the_gate_gained_no_allowance_for_this_package(self):
        source = GATE.read_text(encoding="utf-8")
        assert "v3/api" not in source, (
            "the egress closure was widened for the API. A server binding "
            "needs no HTTP client, so an allowance here would be a hole "
            "with no user.")

    def test_no_module_reads_the_environment(self):
        offences = []
        for path in _modules():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and \
                        node.attr in {"getenv", "environ"}:
                    offences.append(f"{path.name}:{node.lineno}")
        assert offences == [], offences


class TestOnlyTheBindingKnowsAboutTheWeb:
    def test_exactly_one_module_names_a_web_framework(self):
        naming = []
        for path in sorted(API_DIR.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    roots = [(node.module or "").split(".")[0]]
                else:
                    continue
                if _WEB_FRAMEWORKS & set(roots):
                    naming.append(path.name)
        assert sorted(set(naming)) == ["binding.py"], naming

    def test_the_binding_imports_flask_inside_the_factory(self):
        tree = ast.parse(BINDING.read_text(encoding="utf-8"))
        for node in tree.body:
            assert not isinstance(node, (ast.Import, ast.ImportFrom)) or \
                (node.module or "").split(".")[0] not in _WEB_FRAMEWORKS, (
                    "a module-scope Flask import makes the package "
                    "un-importable without a web framework")

    def test_no_handler_imports_the_binding(self):
        for path in (API_DIR / "handlers").glob("*.py"):
            assert "binding" not in path.read_text(encoding="utf-8"), path.name

    def test_the_binding_builds_no_app_at_import(self):
        proc = _run("import v3.api.binding as b; "
                    "print(hasattr(b, 'create_blueprint'))")
        assert proc.stdout.strip() == "True", proc.stderr


class TestTheHandlerLayerNeedsNoServer:
    def test_no_handler_module_imports_a_framework_object(self):
        for path in (API_DIR / "handlers").glob("*.py"):
            source = path.read_text(encoding="utf-8")
            for token in ("request.", "jsonify", "Blueprint", "abort("):
                assert token not in source, (path.name, token)

    def test_a_handler_is_a_plain_callable_of_a_context(self):
        import inspect

        from v3.api import routes as R
        for route in R.ROUTES:
            signature = inspect.signature(route.handler)
            first = list(signature.parameters)[0]
            assert first == "context", route.route_id
