"""WP-2.2 L1 — package boundary and single-jurisdiction guarantees.

Same discipline as the kernel: importing L1 must not boot the legacy
application, and the store must not quietly grow a second database file
(A-09 found exactly that — `convergence_snapshots.db` living outside the
backup and schema-management story).
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
class TestLedgerImportIsInert:
    def test_importing_the_ledger_does_not_import_radar(self):
        proc = _run("import sys; import v3.ledger; "
                    "print(any(m == 'radar' or m.startswith('radar.') "
                    "for m in sys.modules))")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"

    def test_importing_the_ledger_spawns_no_threads(self):
        proc = _run("import threading, v3.ledger; "
                    "print(threading.active_count())")
        assert proc.stdout.strip() == "1", proc.stderr

    def test_importing_the_ledger_prints_nothing(self):
        proc = _run("import v3.ledger")
        assert proc.stdout == "" and proc.stderr == ""

    def test_every_ledger_module_is_individually_inert(self):
        modules = sorted(p.stem for p in
                         (REPO_ROOT / "v3" / "ledger").glob("*.py")
                         if p.stem != "__init__")
        assert modules
        for name in modules:
            proc = _run(f"import sys; import v3.ledger.{name}; "
                        f"print(any(m.startswith('radar') "
                        f"for m in sys.modules))")
            assert proc.stdout.strip() == "False", f"v3.ledger.{name}"

    def test_no_flask_or_orm_is_pulled_in(self):
        proc = _run("import sys; import v3.ledger; "
                    "print(any(m in sys.modules for m in "
                    "('flask', 'sqlalchemy', 'gevent')))")
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


class TestSingleJurisdiction:
    def test_the_store_creates_exactly_one_database_file(self, tmp_path):
        from v3.ledger import ConclusionRecord, LedgerStore
        target = tmp_path / "store" / "v3.db"
        instance = LedgerStore(str(target))
        try:
            instance.append_conclusion(ConclusionRecord(
                conclusion_id="c1", scenario_id="s", conclusion_type="t",
                observed_at=1_786_000_000.0, confidence=0.5))
        finally:
            instance.close()
        # WAL sidecars belong to the same database; a SECOND .db does not.
        databases = [p.name for p in target.parent.iterdir()
                     if p.suffix == ".db"]
        assert databases == ["v3.db"], \
            f"A-09: a second store appeared: {databases}"

    def test_the_store_never_reads_configuration_from_the_environment(self):
        # Checked by AST, not by substring: prose about "the environment"
        # in a docstring is not an environment read, and a test that
        # cannot tell the difference trains people to weaken it.
        gate = _load_gate()
        for path in (REPO_ROOT / "v3" / "ledger").glob("*.py"):
            findings = gate.scan_source(path.read_text(encoding="utf-8"),
                                        f"v3/ledger/{path.name}")
            assert not [f for f in findings if f.rule == "direct-env-read"], \
                f"{path.name} reads the environment directly"

    def test_no_hardcoded_database_path(self):
        source = "".join(
            path.read_text(encoding="utf-8")
            for path in (REPO_ROOT / "v3" / "ledger").glob("*.py"))
        assert "radar.db" not in source
        assert "persistence/" not in source

    def test_the_kernel_discipline_gate_covers_this_package(self):
        assert _load_gate().main(["v3/ledger"]) == 0
