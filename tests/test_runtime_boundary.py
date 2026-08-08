"""WP-4.1 — the composition root's boundary, and the shape of its licence.

`v3/runtime/` is the ONE package allowed to own threads, clocks and
credentials. Every other v3 invariant still applies to it, and the licence
itself must stay narrow enough to name:

  * **import is still inert.** Owning a thread is not the same as starting
    one at import. `radar/__init__.py` spawns ~40 threads on import, which
    pointed the legacy suite at the production database and let
    `bg_observer` walk past the circuit breaker (B-01). Starting the
    runtime is an explicit call and nothing else does it.
  * **the environment exemption is scoped to ONE FILE**, not to the
    package. `v3/runtime/secrets.py` may read `os.environ`; every other
    module under `v3/` — including its siblings in `v3/runtime/` — still
    fails the discipline gate for it. The test below proves no second
    module benefits, which is the difference between an exemption and a
    hole.
  * **no HTTP library, still.** The composition root injects a
    `HttpClient`; it does not become a second egress.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_DIR = REPO_ROOT / "v3" / "runtime"


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, cwd=str(REPO_ROOT), timeout=180)


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestImportIsStillInert:
    def test_importing_the_runtime_starts_no_thread(self):
        proc = _run("import threading, v3.runtime; "
                    "print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    def test_importing_the_runtime_pulls_in_no_legacy_module(self):
        proc = _run("import sys, v3.runtime; "
                    "print(any(m == 'radar' or m.startswith('radar.') "
                    "for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    def test_importing_the_runtime_prints_nothing(self):
        proc = _run("import v3.runtime")
        assert proc.stdout == "" and proc.stderr == ""

    def test_every_runtime_module_is_individually_inert(self):
        modules = [f"v3.runtime.{path.stem}"
                   for path in sorted(RUNTIME_DIR.glob("*.py"))
                   if path.stem != "__init__"]
        assert modules, "the runtime package has no modules"
        for name in modules:
            proc = _run(f"import sys, threading; import {name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules), threading.active_count())")
            assert proc.stdout.strip() == "False 1", f"{name}: {proc.stderr}"

    def test_importing_the_runtime_opens_no_connection(self):
        proc = _run(
            "import socket\n"
            "socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw("
            "AssertionError('a connection was opened at import'))\n"
            "import v3.runtime\n"
            "print('inert')")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "inert"

    def test_importing_the_runtime_reads_no_environment_variable(self):
        """Import-time credential reads are the G-15 shape, one layer up.

        A composition root that snapshots the environment on import makes
        every test process a configured process, and makes the snapshot
        untestable — which is exactly how 95 of 98 registered keys became
        unreadable in the legacy system.
        """
        proc = _run(
            "import os\n"
            "class Tripwire(dict):\n"
            "    def __getitem__(self, key):\n"
            "        raise AssertionError('os.environ read at import')\n"
            "    def get(self, key, default=None):\n"
            "        raise AssertionError('os.environ read at import')\n"
            "os.environ = Tripwire()\n"
            "import v3.runtime\n"
            "print('inert')")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "inert"


class TestTheEnvironmentExemptionIsScopedToOneFile:
    def test_the_gate_names_exactly_one_environment_owner(self,
                                                          discipline_gate):
        assert discipline_gate._ENV_OWNER == "v3/runtime/secrets.py"

    def test_the_gate_still_passes_over_all_of_v3(self, discipline_gate):
        assert discipline_gate.main(["v3"]) == 0

    def test_the_owner_may_read_the_environment(self, discipline_gate):
        findings = discipline_gate.scan_source(
            "import os\nvalue = os.environ.get('K')\n",
            "v3/runtime/secrets.py")
        assert [f.rule for f in findings] == []

    @pytest.mark.parametrize("path", [
        "v3/runtime/loop.py",
        "v3/runtime/tick.py",
        "v3/runtime/reduce.py",
        "v3/runtime/secrets_helper.py",
        "v3/adapters/sneaky.py",
        "v3/fetch/client.py",
    ])
    def test_no_sibling_inherits_the_exemption(self, path, discipline_gate):
        """Scoped to a file, so a second reader is a new failure.

        The rule set is compared, not the count: `os.environ.get(...)`
        trips both the call check and the attribute check, and pinning the
        multiplicity here would pin an implementation detail of the gate.
        """
        findings = discipline_gate.scan_source(
            "import os\nvalue = os.environ.get('K')\n", path)
        assert findings, f"{path} escaped the environment rule"
        assert {f.rule for f in findings} == {"direct-env-read"}

    def test_exactly_one_module_under_v3_reads_the_environment(self):
        """Parsed, not grepped: several docstrings NAME os.getenv while
        explaining why they do not call it."""
        import ast
        offenders = []
        for path in sorted((REPO_ROOT / "v3").rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                target = node.func if isinstance(node, ast.Call) else node
                if not isinstance(target, ast.Attribute):
                    continue
                if getattr(target.value, "id", None) == "os" and \
                        target.attr in ("getenv", "environ"):
                    offenders.append(
                        path.relative_to(REPO_ROOT).as_posix())
        assert sorted(set(offenders)) == ["v3/runtime/secrets.py"]


class TestTheRuntimeIsNotASecondEgress:
    def test_no_runtime_module_imports_an_http_library(self,
                                                       discipline_gate):
        import ast
        forbidden = discipline_gate._HTTP_MODULES
        importers = []
        for path in sorted(RUNTIME_DIR.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
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
                    importers.append(path.name)
        assert importers == []

    def test_the_runtime_imports_no_legacy_module_at_module_scope(self):
        import ast
        offenders = []
        for path in sorted(RUNTIME_DIR.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                if any(n == "radar" or n.startswith("radar.") for n in names):
                    offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []
