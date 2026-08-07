"""WP-2.5 — the L0 packages' boundary, and the completion condition.

The condition is stated as a structural property: **no outward access
exists that bypasses the fetch kernel.** Two mechanisms prove it, and
neither is a promise:

  * the discipline gate reads every file under `v3/` and fails on an HTTP
    or socket import outside `v3/fetch/client.py` (S4-NF-061's CI branch);
  * these boundary tests show that importing any of the three new packages
    pulls in no legacy module, starts no thread and prints nothing — the
    same contract kernel, ledger, etl, scoring and parity already ship.

The import-inertness half matters as much as the import ban.
`radar/__init__.py` spawns ~40 threads at import, which is how the legacy
test suite came to talk to the production database and how `bg_observer`
came to reach the network without passing a circuit breaker (B-01). A
package that starts nothing has nowhere to hide such a path.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
V3_PACKAGES = ("v3.fetch", "v3.adapters", "v3.matching")


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, cwd=str(REPO_ROOT), timeout=120)


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestImportIsInert:
    @pytest.mark.parametrize("package", V3_PACKAGES)
    def test_importing_pulls_in_no_legacy_module(self, package):
        proc = _run(f"import sys; import {package}; "
                    f"print(any(m == 'radar' or m.startswith('radar.') "
                    f"for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    @pytest.mark.parametrize("package", V3_PACKAGES)
    def test_importing_starts_no_thread(self, package):
        proc = _run(f"import threading, {package}; "
                    f"print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    @pytest.mark.parametrize("package", V3_PACKAGES)
    def test_importing_prints_nothing(self, package):
        proc = _run(f"import {package}")
        assert proc.stdout == "" and proc.stderr == ""

    def test_every_module_is_individually_inert(self):
        modules = []
        for package in ("fetch", "adapters", "matching"):
            directory = REPO_ROOT / "v3" / package
            modules.extend(f"v3.{package}.{path.stem}"
                           for path in sorted(directory.glob("*.py"))
                           if path.stem != "__init__")
        assert modules
        for name in modules:
            proc = _run(f"import sys, threading; import {name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules), threading.active_count())")
            assert proc.stdout.strip() == "False 1", f"{name}: {proc.stderr}"

    def test_importing_the_kernel_opens_no_connection(self):
        """`requests` is imported, never used.

        `connect` is patched rather than the socket class itself: replacing
        the class breaks requests' own import machinery, which would make
        this pass for the wrong reason.
        """
        proc = _run(
            "import socket\n"
            "socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw("
            "AssertionError('a connection was opened at import'))\n"
            "import v3.fetch, v3.adapters, v3.matching\n"
            "print('inert')")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "inert"


class TestNoEgressOutsideTheKernel:
    """The completion condition, checked over the whole of v3/."""

    def test_the_gate_passes_over_all_of_v3(self, discipline_gate):
        assert discipline_gate.main(["v3"]) == 0

    def test_exactly_one_module_imports_an_http_library(self,
                                                        discipline_gate):
        """Forbidden names come from the gate — no second copy to drift."""
        import ast
        forbidden = discipline_gate._HTTP_MODULES
        importers = []
        for path in sorted((REPO_ROOT / "v3").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                else:
                    continue
                if any(m == entry or m.startswith(entry + ".")
                       or entry.startswith(m + ".")
                       for m in modules for entry in forbidden):
                    importers.append(
                        path.relative_to(REPO_ROOT).as_posix())
        assert sorted(set(importers)) == ["v3/fetch/client.py"]

    @pytest.mark.parametrize("library", ["requests", "httpx", "aiohttp",
                                         "socket", "http.client",
                                         "urllib.request", "urllib3", "ssl"])
    def test_the_gate_catches_each_forbidden_library(self, library,
                                                     discipline_gate):
        findings = discipline_gate.scan_source(
            f"import {library}\n", "v3/adapters/sneaky.py")
        assert [f.rule for f in findings] == ["http-outside-fetch-kernel"]

    @pytest.mark.parametrize("statement", [
        "from requests import get",
        "from urllib import request",
        "from http import client",
        "from urllib.request import urlopen",
    ])
    def test_the_gate_catches_from_imports_including_parent_packages(
            self, statement, discipline_gate):
        """`from urllib import request` presents as the module `urllib`,
        which exact matching against `urllib.request` missed entirely."""
        findings = discipline_gate.scan_source(
            statement + "\n", "v3/fetch/runner.py")
        assert [f.rule for f in findings] == ["http-outside-fetch-kernel"]

    def test_no_module_reads_the_environment(self):
        """Credentials arrive from the composition root, never from env.

        Parsed, not grepped: several docstrings here NAME `os.getenv` when
        explaining why they do not call it, and a text search cannot tell
        an explanation from a call.
        """
        import ast
        offenders = []
        for package in ("fetch", "adapters", "matching"):
            for path in sorted((REPO_ROOT / "v3" / package).glob("*.py")):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.Attribute, ast.Call)):
                        continue
                    target = node.func if isinstance(node, ast.Call) else node
                    if not isinstance(target, ast.Attribute):
                        continue
                    base = getattr(target.value, "id", None)
                    if base == "os" and target.attr in ("getenv", "environ"):
                        offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []


class TestTheKernelIsTheOnlyEgress:
    def test_the_client_is_the_only_place_a_session_is_made(self):
        import ast
        constructors = []
        for path in sorted((REPO_ROOT / "v3").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "attr", None)
                if name == "Session":
                    constructors.append(
                        path.relative_to(REPO_ROOT).as_posix())
        assert sorted(set(constructors)) == ["v3/fetch/client.py"]

    def test_adapters_cannot_reach_the_client_through_their_arguments(self):
        """Barrier 1, restated at the package level."""
        from v3.adapters.types import FetchedPayload, NormalizeContext
        import dataclasses
        fields = {f.name for f in dataclasses.fields(FetchedPayload)}
        fields |= {f.name for f in dataclasses.fields(NormalizeContext)}
        assert not (fields & {"client", "session", "store", "ledger"})


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestTheExpanderIsInsideTheKernel:
    """Ruling 4 put placeholder expansion in `v3/fetch`, not in the
    composition root.

    The argument is the client's argument. A substitution each caller
    performs is a substitution each caller can get wrong, and a wrong one
    produces a request that succeeds and answers about nothing — K02
    records AISHub replying HTTP 200 with an empty body to a rejected
    query. One expander means one refusal path.
    """

    def test_it_lives_under_the_fetch_kernel(self):
        assert (REPO_ROOT / "v3" / "fetch" / "expand.py").exists()

    def test_it_imports_no_http_or_socket_library(self):
        import ast
        tree = ast.parse((REPO_ROOT / "v3" / "fetch" / "expand.py")
                         .read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not (imported & {"requests", "httpx", "socket", "ssl",
                                "urllib", "urllib.request", "http.client"})

    def test_importing_it_starts_no_thread(self):
        proc = _run("import threading; before = threading.active_count(); "
                    "import v3.fetch.expand; "
                    "print(threading.active_count() - before)")
        assert proc.returncode == 0 and proc.stdout.strip() == "0"

    def test_expansion_takes_no_credentials(self):
        """A concrete request in a plan is addressable, not authenticated:
        the client is still the only place a secret meets a request."""
        import dataclasses

        from v3.fetch.expand import ExpansionInput, ExpansionScope
        fields = {f.name for f in dataclasses.fields(ExpansionInput)}
        fields |= {f.name for f in dataclasses.fields(ExpansionScope)}
        assert not (fields & {"credentials", "secrets", "key", "token",
                              "client", "session"})


class TestTheFallbackChainIsEvaluatedByTheKernel:
    """Ruling 3. Adapters declare THAT a fallback exists and why; the
    runner decides whether it runs. An adapter that could express HOW
    would be expressing a fetch policy."""

    def test_the_trigger_is_one_of_a_closed_set(self):
        from v3.adapters.types import FALLBACK_TRIGGERS
        assert FALLBACK_TRIGGERS == {"failure", "failure_or_empty"}

    def test_only_the_runner_decides_whether_an_alternative_runs(self):
        import ast
        callers = []
        for path in sorted((REPO_ROOT / "v3").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and \
                        getattr(node.func, "attr", None) == "fetch" and \
                        getattr(getattr(node.func, "value", None), "id",
                                None) == "client":
                    callers.append(path.relative_to(REPO_ROOT).as_posix())
        assert sorted(set(callers)) == ["v3/fetch/runner.py"]
