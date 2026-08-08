"""WP-3.1 — L3's package boundary and its threshold-fidelity gate.

Same discipline as K, L1 and L2: importing the layer must not boot the
legacy application, must not start a thread, must not read the
environment. Plus the gate that keeps this package's numbers tied to
production's — WP-2.6 and WP-2.7 both found infidelities in values that
looked correctly transcribed, so the comparison is machine-run, not
eyeballed.
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
class TestImportIsInert:
    def test_importing_l3_does_not_import_radar(self):
        proc = _run("import sys; import v3.conclusions; "
                    "print(any(m == 'radar' or m.startswith('radar.') "
                    "for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    def test_importing_l3_spawns_no_threads(self):
        proc = _run("import threading, v3.conclusions; "
                    "print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    def test_importing_l3_prints_nothing(self):
        proc = _run("import v3.conclusions")
        assert proc.stdout == "" and proc.stderr == ""

    def test_every_module_is_individually_inert(self):
        modules = sorted(p.stem for p in
                         (REPO_ROOT / "v3" / "conclusions").glob("*.py")
                         if p.stem != "__init__")
        assert modules
        for name in modules:
            proc = _run(f"import sys; import v3.conclusions.{name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules))")
            assert proc.stdout.strip() == "False", f"v3.conclusions.{name}"

    def test_no_flask_or_orm_is_pulled_in(self):
        proc = _run("import sys; import v3.conclusions; "
                    "print(any(m in sys.modules for m in "
                    "('flask', 'sqlalchemy', 'gevent')))")
        assert proc.stdout.strip() == "False"

    def test_no_http_client_is_reachable_from_this_layer(self):
        # A-06 / v3 invariant: HTTP lives in v3/fetch/client.py only.
        proc = _run("import sys; import v3.conclusions; "
                    "print(any(m in sys.modules for m in "
                    "('requests', 'urllib3', 'httpx')))")
        assert proc.stdout.strip() == "False"


def _load_gate():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_kernel_discipline",
        REPO_ROOT / "scripts" / "check_kernel_discipline.py")
    gate = importlib.util.module_from_spec(spec)
    sys.modules["check_kernel_discipline"] = gate
    spec.loader.exec_module(gate)
    return gate


class TestKernelDiscipline:
    def test_the_discipline_gate_covers_this_package(self):
        assert _load_gate().main(["v3/conclusions"]) == 0

    def test_no_module_reads_the_environment(self):
        gate = _load_gate()
        for path in (REPO_ROOT / "v3" / "conclusions").glob("*.py"):
            findings = gate.scan_source(path.read_text(encoding="utf-8"),
                                        f"v3/conclusions/{path.name}")
            assert not [f for f in findings if f.rule == "direct-env-read"], \
                f"{path.name} reads the environment directly"

    def test_no_module_compares_threat_levels_directly(self):
        gate = _load_gate()
        for path in (REPO_ROOT / "v3" / "conclusions").glob("*.py"):
            findings = gate.scan_source(path.read_text(encoding="utf-8"),
                                        f"v3/conclusions/{path.name}")
            assert not [f for f in findings
                        if f.rule.startswith("threat-level")], path.name


def _load_threshold_gate():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "check_conclusion_thresholds",
        REPO_ROOT / "scripts" / "check_conclusion_thresholds.py")
    gate = importlib.util.module_from_spec(spec)
    sys.modules["check_conclusion_thresholds"] = gate
    spec.loader.exec_module(gate)
    return gate


class TestThresholdFidelity:
    def test_every_pinned_threshold_matches_production(self):
        gate = _load_threshold_gate()
        unregistered = [f for f in gate.compare()
                        if not f["matches"] and not f["registered"]]
        assert unregistered == []

    def test_the_gate_exits_zero_today(self):
        assert _load_threshold_gate().main([]) == 0

    def test_the_comparison_is_by_ast_not_by_substring(self):
        # A docstring mentioning ACTIVE_FLOOR = 9.9 must not be read as an
        # assignment; the parser is what makes that true.
        gate = _load_threshold_gate()
        constants = gate._module_constants("per_domain")
        assert constants["ACTIVE_FLOOR"] == 2.5

    def test_no_pinned_threshold_escapes_both_lists(self):
        # A gate that reports "21 checked, 0 differences" and says nothing
        # about the other 18 reads as coverage. This is what stops a new
        # pinned threshold from being quietly absent from both.
        gate = _load_threshold_gate()
        assert gate.unaccounted_pins() == []

    def test_every_unmappable_entry_states_its_reason(self):
        gate = _load_threshold_gate()
        for name, reason in gate.STRUCTURALLY_UNMAPPABLE.items():
            assert reason.strip(), name

    def test_the_gate_fails_when_a_pin_is_unaccounted(self, monkeypatch):
        gate = _load_threshold_gate()
        monkeypatch.setitem(gate.MAPPING, "__probe__",
                            ("attack_mode", "CYBER_DDOS_FLOOR"))
        from v3.conclusions import thresholds as T
        monkeypatch.setitem(T._PINNED, "__orphan__",
                            T._PINNED["ATTACK_CYBER_DDOS_FLOOR"])
        assert gate.unaccounted_pins() == ["__orphan__"]

    def test_it_is_wired_into_ci(self):
        script = (REPO_ROOT / "scripts" / "check_ci.sh").read_text(
            encoding="utf-8")
        assert "check_conclusion_thresholds.py" in script

    def test_every_mapped_production_constant_exists(self):
        gate = _load_threshold_gate()
        missing = [f for f in gate.compare()
                   if f["production_value"] == "<missing>"]
        assert missing == []


class TestThresholdDisclosure:
    def test_every_pinned_threshold_declares_its_provenance(self):
        from v3.conclusions import thresholds as T
        for name, entry in T.disclosure().items():
            assert entry["provenance_ref"].strip(), name

    def test_the_catalogue_covers_all_four_availability_guards(self):
        from v3.conclusions import thresholds as T
        assert {"UPSTREAM_FAILURE_RATIO", "SENSOR_DEGRADED_RATIO",
                "CALIBRATION_MIN_HISTORY_DAYS"} <= set(T.disclosure())

    def test_no_threshold_is_registry_backed(self):
        # O-18: none of these is a dial an analyst turns between ticks, and
        # a live knob that nothing reads is exactly defect G-15.
        from v3.conclusions.thresholds import _PINNED
        assert not [t for t in _PINNED.values() if t.is_registry_backed]
