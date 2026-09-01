"""WP-4.1 completion condition 1 — a read handler cannot reach a writer.

A-01 was `GET /api/threat_data` running the scoring tick: a read with a
side effect, which meant polling could not be stopped, and a scoring
failure flag set by one GET was cleared by the next one. The v2 answer was
a review rule ("do not write from a GET"). This is the v3 answer: the
handler signature will not accept a writer.

Three barriers, deliberately independent, because a single one in Python
is always circumventable by introspection:

  1. **the seam**: `ReadContext` refuses a `LedgerStore` at construction.
     A read handler receives a `ReadContext` or it is not a route.
  2. **the whitelist**: `ReadOnlyLedger` forwards a named set of methods
     and nothing else, so `ledger.append_signal` is an AttributeError
     rather than an append.
  3. **AST proof of the whitelist**: every forwarded method is verified,
     by reading `v3/ledger/store.py`, to use only `_read_connection()`.
     SQLite opens that handle `mode=ro`, so the forwarded methods cannot
     write even if the first two barriers were bypassed.

LIMITATION, stated rather than implied: `ReadOnlyLedger` holds the store
in an attribute, and Python has no attribute a determined caller cannot
reach. Barrier 3 is what makes that not matter — the reachable object's
reachable methods are read-only at the SQLite level.
"""
from __future__ import annotations

import ast
import sqlite3
from pathlib import Path

import pytest

from v3.api.readonly import (READ_METHODS, WRITE_METHODS, ReadOnlyLedger,
                             audit_store_methods)
from v3.api.request import ReadContext
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore

REPO_ROOT = Path(__file__).resolve().parent.parent
STORE_SOURCE = REPO_ROOT / "v3" / "ledger" / "store.py"


@pytest.fixture()
def store(tmp_path):
    handle = LedgerStore(str(tmp_path / "radar.db"))
    yield handle
    handle.close()


class TestTheSeamRefusesAWriter:
    def test_a_read_context_holding_a_writer_fails_to_construct(self, store):
        with pytest.raises(DomainError) as excinfo:
            ReadContext(ledger=store, now=1.0)
        assert "LedgerStore" in str(excinfo.value)

    def test_a_read_context_takes_the_read_only_handle(self, store):
        context = ReadContext(ledger=ReadOnlyLedger(store), now=1.0)
        assert isinstance(context.ledger, ReadOnlyLedger)

    def test_it_refuses_anything_that_merely_looks_like_a_ledger(self):
        class Impostor:
            def latest_tl_at(self, *a, **kw):
                return None

        with pytest.raises(DomainError):
            ReadContext(ledger=Impostor(), now=1.0)


class TestTheWhitelist:
    def test_a_writer_method_is_not_reachable_by_name(self, store):
        ledger = ReadOnlyLedger(store)
        for name in sorted(WRITE_METHODS):
            with pytest.raises(AttributeError) as excinfo:
                getattr(ledger, name)
            assert name in str(excinfo.value)

    def test_a_reader_method_is_reachable_and_works(self, store):
        ledger = ReadOnlyLedger(store)
        assert ledger.count_signals() == 0
        assert ledger.latest_tl_at(1.0, scenario_id="x") is None

    def test_the_two_sets_are_disjoint_and_total(self):
        assert not (READ_METHODS & WRITE_METHODS)
        public = {name for name in dir(LedgerStore)
                  if not name.startswith("_")
                  and callable(getattr(LedgerStore, name, None))}
        unclassified = public - READ_METHODS - WRITE_METHODS
        assert not unclassified, (
            f"LedgerStore grew {sorted(unclassified)} and neither list "
            f"claims it. An unclassified method defaults to nothing here, "
            f"and a default is how G-01 happened.")


class TestTheASTProof:
    """The whitelist is not a promise; it is checked against the source."""

    def test_every_forwarded_method_uses_only_the_read_connection(self):
        report = audit_store_methods()
        assert report["misclassified"] == [], report["misclassified"]

    def test_the_audit_actually_read_the_store_module(self):
        report = audit_store_methods()
        tree = ast.parse(STORE_SOURCE.read_text(encoding="utf-8"))
        methods = [node.name
                   for node in ast.walk(tree)
                   if isinstance(node, ast.FunctionDef)
                   and not node.name.startswith("_")]
        assert set(report["classified"]) >= set(methods) - {"path",
                                                            "schema_version"}

    def test_the_audit_notices_a_writer_added_to_the_whitelist(self):
        report = audit_store_methods(read_methods=READ_METHODS
                                     | {"append_signal"})
        assert "append_signal" in report["misclassified"]


class TestTheSQLiteBarrier:
    """Barrier 3, live: the connection the readers use refuses writes."""

    def test_the_read_connection_rejects_an_insert(self, store):
        connection = store._read_connection()
        with pytest.raises(sqlite3.OperationalError) as excinfo:
            connection.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('x', 'y')")
        assert "readonly" in str(excinfo.value).lower()
