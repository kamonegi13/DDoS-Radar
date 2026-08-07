"""WP-2.3 — the ETL's package boundary.

The ETL is the one v3 component that touches v1 data, which makes it the
most tempting place to `import radar.database` for schema knowledge. It
does not: the v1 schema is described by S3's mapping tables, and the
source is read as plain SQLite.
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
class TestEtlImportIsInert:
    def test_importing_the_etl_does_not_import_radar(self):
        proc = _run("import sys; import v3.etl; "
                    "print(any(m == 'radar' or m.startswith('radar.') "
                    "for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    def test_importing_the_etl_spawns_no_threads(self):
        proc = _run("import threading, v3.etl; "
                    "print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    def test_importing_the_etl_prints_nothing(self):
        proc = _run("import v3.etl")
        assert proc.stdout == "" and proc.stderr == ""

    def test_every_etl_module_is_individually_inert(self):
        modules = sorted(p.stem for p in (REPO_ROOT / "v3" / "etl").glob("*.py")
                         if p.stem != "__init__")
        assert modules
        for name in modules:
            proc = _run(f"import sys; import v3.etl.{name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules))")
            assert proc.stdout.strip() == "False", f"v3.etl.{name}"


class TestSourceSchemaKnowledgeIsDeclarative:
    def test_the_etl_never_imports_the_legacy_database_module(self):
        source = "".join(path.read_text(encoding="utf-8")
                         for path in (REPO_ROOT / "v3" / "etl").glob("*.py"))
        assert "radar.database" not in source
        assert "from radar" not in source

    def test_the_discipline_gate_covers_the_package(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "check_kernel_discipline",
            REPO_ROOT / "scripts" / "check_kernel_discipline.py")
        gate = importlib.util.module_from_spec(spec)
        sys.modules["check_kernel_discipline"] = gate
        spec.loader.exec_module(gate)
        assert gate.main(["v3/etl"]) == 0

    def test_the_run_procedure_is_documented(self):
        from v3.etl import migrate as migrate_module
        doc = sys.modules[migrate_module.__module__].__doc__ or ""
        assert "docker exec" in doc
        assert "backup_radar_db.sh" in doc
        assert "S3-DATA-031" in doc or "scoring loop" in doc
