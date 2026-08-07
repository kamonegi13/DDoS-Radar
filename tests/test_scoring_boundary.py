"""WP-2.4 — the scoring kernel's package boundary.

Same contract every v3 package ships: importing it pulls in no legacy
module, starts no thread and prints nothing. It matters most here. The
scoring layer is the one an engineer is most tempted to let reach for
`radar.config` "just for a default", and importing any `radar.*` module
boots the Flask app, runs migrations and spawns ~30 sensor threads with
live outbound HTTP.

The layer's other guarantee — that scoring reads no configuration at tick
time — is proved in tests/test_scoring_kernel.py::TestPurityAndIdempotence
by breaking the resolver and watching scoring carry on.
"""
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-c", code], capture_output=True,
                          text=True, cwd=str(REPO_ROOT), timeout=120)


@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded")
class TestScoringImportIsInert:
    def test_importing_the_kernel_does_not_import_radar(self):
        proc = _run("import sys; import v3.scoring; "
                    "print(any(m == 'radar' or m.startswith('radar.') "
                    "for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    def test_importing_the_kernel_spawns_no_threads(self):
        proc = _run("import threading, v3.scoring; "
                    "print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    def test_importing_the_kernel_prints_nothing(self):
        proc = _run("import v3.scoring")
        assert proc.stdout == "" and proc.stderr == ""

    def test_every_scoring_module_is_individually_inert(self):
        modules = sorted(
            path.stem for path in (REPO_ROOT / "v3" / "scoring").glob("*.py")
            if path.stem != "__init__")
        assert modules
        for name in modules:
            proc = _run(f"import sys; import v3.scoring.{name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules))")
            assert proc.stdout.strip() == "False", f"v3.scoring.{name}"

    def test_scoring_a_tick_needs_no_legacy_import(self):
        """The whole point: a conclusion, produced in a bare process."""
        proc = _run(
            "import sys\n"
            "from v3.kernel import Ratio\n"
            "from v3.scoring import (Observation, CountryWeight, Participant,"
            " Scenario, ScoringInputs, ScoringSettings, score_tick)\n"
            "obs = Observation(sensor='cf', domain='cyber', status='FIRED',"
            " score=5.0, countries=(CountryWeight('TW', Ratio(1.0)),))\n"
            "scenario = Scenario(scenario_id='s', core_country='TW',"
            " participants=(Participant('TW', Ratio(1.0)),))\n"
            "result = score_tick(ScoringInputs(now=1700000000.0,"
            " observations=(obs,), scenarios=(scenario,),"
            " settings=ScoringSettings(), focused_scenario_id='s'))\n"
            "print(result.results['s'].threat_level.value,"
            " any(m.startswith('radar') for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "3 False"


class TestNoHiddenConfigurationPath:
    def test_the_package_never_imports_the_legacy_config(self):
        """Matched as import statements, not as text.

        The threshold catalogue cites `radar/scoring.py:NNNN` in its
        provenance strings on purpose — that is the disclosure NP6 asks
        for — so a substring search would flag the documentation and miss
        the point.
        """
        import ast
        offenders = []
        for path in sorted((REPO_ROOT / "v3" / "scoring").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                # Every alias, not just the first: `import os, radar.x`
                # put the legacy import in second position and walked
                # straight past a names[0]-only check.
                if isinstance(node, ast.ImportFrom):
                    modules = [node.module or ""]
                elif isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                else:
                    continue
                for module in modules:
                    if module == "radar" or module.startswith("radar."):
                        offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == []

    def test_the_discipline_gate_covers_the_package(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "check_kernel_discipline",
            REPO_ROOT / "scripts" / "check_kernel_discipline.py")
        gate = importlib.util.module_from_spec(spec)
        sys.modules["check_kernel_discipline"] = gate
        spec.loader.exec_module(gate)
        assert gate.main(["v3/scoring"]) == 0

    def test_no_module_reads_the_environment(self):
        source = "".join(path.read_text(encoding="utf-8")
                         for path in (REPO_ROOT / "v3" / "scoring").glob("*.py"))
        assert "os.getenv" not in source
        assert "os.environ" not in source
