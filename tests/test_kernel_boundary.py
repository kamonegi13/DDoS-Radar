"""WP-2.1 K kernel — the package boundary is load-bearing, so it is tested.

Two properties the rest of the rebuild depends on:

  1. Importing the kernel must not boot the legacy application. Every
     `radar.*` import runs radar/__init__.py, which starts the Flask app,
     runs migrations and spawns ~30 sensor threads. If the kernel pulled
     that in, v3 code would inherit the exact defect class it exists to
     remove, and the kernel would be untestable in isolation.

  2. The one permitted legacy dependency — config_layered, for
     Threshold.registry_backed — must stay lazy, i.e. paid only when a
     registry-backed threshold is actually resolved.
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
class TestKernelImportIsInert:
    def test_importing_the_kernel_does_not_import_radar(self):
        proc = _run("import sys; import v3.kernel; "
                    "print(any(m == 'radar' or m.startswith('radar.') "
                    "for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False", \
            "the kernel must not drag in the legacy application"

    def test_importing_the_kernel_spawns_no_threads(self):
        proc = _run("import threading, v3.kernel; "
                    "print(threading.active_count())")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "1", \
            f"expected only the main thread, got {proc.stdout.strip()}"

    def test_importing_the_kernel_prints_nothing(self):
        # The app boot announces itself on stdout/stderr; silence is the
        # observable proof that none of it ran.
        proc = _run("import v3.kernel")
        assert proc.stdout == ""
        assert proc.stderr == ""

    def test_every_kernel_module_is_individually_inert(self):
        modules = sorted(p.stem for p in
                         (REPO_ROOT / "v3" / "kernel").glob("*.py")
                         if p.stem != "__init__")
        assert modules, "no kernel modules found"
        for name in modules:
            proc = _run(f"import sys; import v3.kernel.{name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules))")
            assert proc.stdout.strip() == "False", f"v3.kernel.{name} is not inert"

    def test_the_kernel_is_importable_without_the_repo_root_conftest(self):
        # No pytest fixtures, no gevent patch — plain interpreter.
        proc = _run("from v3.kernel import ThreatLevel, Ratio, Window, "
                    "Threshold, Provenance, Evidence; print('ok')")
        assert proc.stdout.strip() == "ok", proc.stderr


class TestCuratedExports:
    def test_all_six_types_are_exported(self):
        import v3.kernel as kernel
        for name in ("ThreatLevel", "Ratio", "Percentage", "Window",
                     "Threshold", "Provenance", "Evidence"):
            assert name in kernel.__all__, name
            assert hasattr(kernel, name), name

    def test_the_error_hierarchy_is_exported(self):
        import v3.kernel as kernel
        for name in ("KernelError", "DomainError", "UnitMismatchError",
                     "OrderingForbiddenError", "StaleEvidenceError",
                     "ProvenanceRequiredError", "ThresholdResolutionError"):
            assert name in kernel.__all__, name

    def test_every_error_descends_from_kernel_error(self):
        import v3.kernel as kernel
        for name in kernel.__all__:
            attribute = getattr(kernel, name)
            if isinstance(attribute, type) and issubclass(attribute, Exception):
                assert issubclass(attribute, kernel.KernelError), name
