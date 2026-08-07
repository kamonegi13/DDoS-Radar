"""WP-2.8 — the parity harness's package boundary.

The harness is the one v3 component whose job requires running legacy
code, which makes it the most tempting place to `import radar` "just for
the driver". It does not: the legacy functions run in a subprocess, and
the parent process stays as inert as every other v3 package.

That separation is what keeps the kernel discipline gate meaningful over
the whole tree. If this package imported radar, the gate would have to
grow an exemption, and an exemption is how the rule stops applying.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PARITY_DIR = REPO_ROOT / "v3" / "parity"


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, cwd=str(REPO_ROOT), timeout=120)


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestParityImportIsInert:
    def test_importing_the_harness_does_not_import_radar(self):
        proc = _run("import sys; import v3.parity; "
                    "print(any(m == 'radar' or m.startswith('radar.') "
                    "for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    def test_importing_the_harness_spawns_no_threads(self):
        proc = _run("import threading, v3.parity; "
                    "print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    def test_importing_the_harness_prints_nothing(self):
        proc = _run("import v3.parity")
        assert proc.stdout == "" and proc.stderr == ""

    def test_every_parity_module_is_individually_inert(self):
        """Including `_v2_subprocess`, whose radar imports are all in main()."""
        modules = sorted(path.stem for path in PARITY_DIR.glob("*.py")
                         if path.stem != "__init__")
        assert modules
        for name in modules:
            proc = _run(f"import sys; import v3.parity.{name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules))")
            assert proc.stdout.strip() == "False", f"v3.parity.{name}"


class TestNoLegacyImportInTheParentProcess:
    def test_no_module_imports_radar_at_any_scope_except_the_subprocess(self):
        """`_v2_subprocess` is the one file allowed to name radar, and only
        inside functions — which is what makes spawning it necessary."""
        import ast
        offenders = []
        for path in sorted(PARITY_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                else:
                    continue
                for module in modules:
                    if module == "radar" or module.startswith("radar."):
                        if path.name != "_v2_subprocess.py":
                            offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []

    def test_the_subprocess_module_keeps_its_radar_imports_inside_functions(
            self):
        import ast
        source = (PARITY_DIR / "_v2_subprocess.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        module_scope = []
        for node in tree.body:      # top level only
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                name = (node.module if isinstance(node, ast.ImportFrom)
                        else node.names[0].name) or ""
                if name.startswith("radar"):
                    module_scope.append(node.lineno)
        assert module_scope == []

    def test_the_discipline_gate_covers_the_package(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "check_kernel_discipline",
            REPO_ROOT / "scripts" / "check_kernel_discipline.py")
        gate = importlib.util.module_from_spec(spec)
        sys.modules["check_kernel_discipline"] = gate
        spec.loader.exec_module(gate)
        assert gate.main(["v3/parity"]) == 0

    def test_no_module_reads_the_environment(self):
        source = "".join(path.read_text(encoding="utf-8")
                         for path in PARITY_DIR.glob("*.py"))
        assert "os.getenv" not in source
        assert "os.environ" not in source


class TestNoLlmClientAnywhere:
    """S5-VERIF-022 at this level: both sides consume recorded rows.

    Conclusion-level replay of recorded LLM responses is L3's and is
    reported BLOCKED; what this asserts is that the harness cannot reach a
    model even by accident, so a parity number can never depend on a
    sampled generation.
    """

    def test_the_package_imports_no_llm_or_network_client(self):
        source = "".join(path.read_text(encoding="utf-8")
                         for path in PARITY_DIR.glob("*.py"))
        for forbidden in ("import requests", "import httpx", "import openai",
                          "import anthropic", "from ollama", "urllib.request"):
            assert forbidden not in source, forbidden

    def test_the_scope_notes_state_the_llm_position(self):
        from v3.parity import SCOPE_NOTES
        assert any("No LLM is invoked" in note for note in SCOPE_NOTES)
