"""WP-4.1d — `LedgerStore` split three ways, and the audits split with it.

WP-4.1c refused to split `store.py` as a drive-by, and the reason was
exact: `readonly.audit_store_methods` and `writeonly.audit_command_writes`
both AST-parse one file for `class LedgerStore`, so moving methods to a
mixin would make **both audits silently stop checking them** — the read
seam would stop forwarding a projection and the write seam would stop
noticing a second writer of `command_record`, with nothing failing either
way. That is the exact failure mode both audits exist to prevent, arriving
through the refactor.

So the split shipped with `v3/api/store_source.py`, and this file is the
proof that the audits followed:

  * they parse every module the class actually spans, not one file;
  * every public method on the runtime class is in the classification;
  * an unfollowable base — a method hidden in a module the chain does not
    reach — RAISES rather than shrinking the count;
  * a chain that returns fewer methods than the recorded floor RAISES,
    whatever the cause.

The last two are mutations. Without them, the tests above would prove
something about today's tree rather than about the check.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from v3.api import store_source as SS
from v3.api.readonly import (READ_METHODS, WRITE_METHODS,
                             audit_store_methods)
from v3.api.writeonly import COMMAND_METHODS, audit_command_writes
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_DIR = REPO_ROOT / "v3" / "ledger"


class TestTheStoreIsSplitAndUnderTheHouseLimit:
    @pytest.mark.parametrize("name", ["store.py", "store_entities.py",
                                      "store_migration.py"])
    def test_each_module_is_within_the_line_limit(self, name):
        lines = (LEDGER_DIR / name).read_text(encoding="utf-8").splitlines()
        assert len(lines) <= 800, f"{name} is {len(lines)} lines"

    def test_the_store_is_one_object_with_one_connection_pair(self, tmp_path):
        """A mixin carries methods, never state. `single jurisdiction`
        (A-09) is about the connection, and the split must not touch it."""
        store = LedgerStore(str(tmp_path / "v3.db"))
        try:
            assert store._read_connection() is not store._connection()
            assert store.entity_marker("s", sensor="x", entity="e") is None
            assert store.checkpoint("conclusions") is None
        finally:
            store.close()

    def test_the_bases_declare_no_state(self):
        """A mixin that took an `__init__` or a `__slots__` would make the
        store two objects wearing one name."""
        from v3.ledger.store_entities import EntityStateMixin
        from v3.ledger.store_migration import MigrationSupportMixin
        for mixin in (EntityStateMixin, MigrationSupportMixin):
            assert "__init__" not in vars(mixin)
            assert "__slots__" not in vars(mixin)
            assert mixin.__bases__ == (object,)


class TestTheAuditFollowsTheClassAcrossModules:
    def test_it_parses_every_module_the_class_spans(self):
        report = SS.coverage()
        assert report["modules"] == ["store.py", "store_entities.py",
                                     "store_migration.py"]

    def test_every_public_runtime_method_is_classified(self):
        """The end-to-end statement: what Python sees and what the audit
        sees are the same set. A method that moved out of view fails here
        even if every other check still passes."""
        runtime = {name for name in dir(LedgerStore)
                   if not name.startswith("_")
                   and callable(getattr(LedgerStore, name, None))}
        classified = set(audit_store_methods()["classified"])
        assert runtime - classified == set(), (
            f"{sorted(runtime - classified)} exist on LedgerStore but the "
            f"audit does not see them — the split hid them")

    def test_the_two_declared_sets_still_partition_the_runtime_class(self):
        runtime = {name for name in dir(LedgerStore)
                   if not name.startswith("_")
                   and callable(getattr(LedgerStore, name, None))}
        assert runtime == (READ_METHODS | WRITE_METHODS)

    def test_methods_from_every_module_appear_in_the_classification(self):
        classified = audit_store_methods()["classified"]
        assert classified["append_signal"] == "writer"        # store.py
        assert classified["entity_marker"] == "reader"        # store_entities
        assert classified["checkpoint"] == "reader"           # store_migration
        assert classified["append_entity_observation"] == "writer"

    def test_the_private_call_graph_still_crosses_module_boundaries(self):
        """`entity_series_values` reads through `_entity_rows`, and both
        moved together. If the fixpoint stopped seeing the helper, the
        public method would be classified a writer by omission — which
        shrinks the read surface with no failure."""
        assert audit_store_methods()["classified"][
            "entity_series_values"] == "reader"

    def test_the_write_audit_still_sees_the_whole_class(self):
        report = audit_command_writes()
        assert report["writers"] == sorted(COMMAND_METHODS)
        assert report["extra_tables"] == []

    def test_the_forwarded_read_set_is_still_correctly_classified(self):
        assert audit_store_methods()["misclassified"] == []


def _write_chain(root: Path, *, hide: bool) -> Path:
    """A miniature `LedgerStore` chain, optionally with a hidden module.

    `hide=True` is the failure being tested: the methods still exist and
    still run — the class inherits them — but the base is imported from
    somewhere the resolver cannot follow, so an audit that parsed only what
    it could reach would report a smaller, clean-looking class.
    """
    (root / "outside").mkdir()
    (root / "outside" / "__init__.py").write_text("", encoding="utf-8")
    (root / "outside" / "hidden.py").write_text(textwrap.dedent('''
        class HiddenMixin:
            def append_command(self, record):
                self._connection().execute(
                    "INSERT INTO command_record (a) VALUES (?)", (1,))

            def sneaky_writer(self, record):
                self._connection().execute(
                    "INSERT INTO command_record (a) VALUES (?)", (2,))
    '''), encoding="utf-8")
    (root / "visible.py").write_text(textwrap.dedent('''
        class VisibleMixin:
            def read_something(self):
                return self._read_connection().execute("SELECT 1")
    '''), encoding="utf-8")
    base_import = ("from outside.hidden import HiddenMixin" if hide
                   else "from v3.ledger.store_entities import EntityStateMixin")
    base_name = "HiddenMixin" if hide else "EntityStateMixin"
    store = root / "store.py"
    store.write_text(textwrap.dedent(f'''
        {base_import}


        class LedgerStore({base_name}):
            def latest_tl_at(self, at_ts):
                return self._read_connection().execute("SELECT 1")
    '''), encoding="utf-8")
    return store


class TestHidingAMethodIsDetected:
    """THE mutation. Both arms, because there are two ways to lose a method:
    move it somewhere unparsed, or remove it outright."""

    def test_an_unfollowable_base_raises_instead_of_shrinking_the_count(
            self, tmp_path):
        store = _write_chain(tmp_path, hide=True)
        with pytest.raises(DomainError) as excinfo:
            SS.resolve_chain(store)
        message = str(excinfo.value)
        assert "HiddenMixin" in message
        assert "invisible" in message

    def test_the_write_audit_refuses_a_chain_it_cannot_follow(self, tmp_path):
        """Without this, `sneaky_writer` — a second writer of
        command_record — would be invisible and the audit would report a
        clean single door."""
        store = _write_chain(tmp_path, hide=True)
        with pytest.raises(DomainError):
            audit_command_writes(source=store)

    def test_the_read_audit_refuses_a_chain_it_cannot_follow(self, tmp_path):
        store = _write_chain(tmp_path, hide=True)
        with pytest.raises(DomainError):
            audit_store_methods(source=store)

    def test_a_followable_base_is_parsed_rather_than_refused(self, tmp_path):
        """The control. The refusal above must be about FOLLOWABILITY, not
        about synthetic chains in general."""
        store = _write_chain(tmp_path, hide=False)
        methods, modules = SS.resolve_chain(store)
        assert "latest_tl_at" in methods
        assert "entity_marker" in methods, \
            "the resolver did not follow the real mixin it was pointed at"
        assert [path.name for path in modules] == ["store.py",
                                                   "store_entities.py"]

    def test_a_chain_below_the_floor_raises(self, tmp_path):
        store = _write_chain(tmp_path, hide=False)
        with pytest.raises(DomainError) as excinfo:
            SS.class_methods(store)
        assert "below the recorded floor" in str(excinfo.value)

    def test_removing_a_method_from_the_real_chain_is_detected(self,
                                                               monkeypatch):
        """The floor exercised against the PRODUCTION chain.

        Raising the floor by one is the same event as losing one method:
        the audited set is smaller than the number this repository last
        agreed it should be, and the build stops.
        """
        monkeypatch.setattr(SS, "METHOD_FLOOR", SS.METHOD_FLOOR + 1)
        with pytest.raises(DomainError) as excinfo:
            SS.class_methods()
        assert "below the recorded floor" in str(excinfo.value)
        assert "store_entities.py" in str(excinfo.value), \
            "the failure must name the modules it did parse"

    def test_losing_a_public_method_is_detected_separately(self,
                                                           monkeypatch):
        monkeypatch.setattr(SS, "PUBLIC_METHOD_FLOOR",
                            SS.PUBLIC_METHOD_FLOOR + 1)
        with pytest.raises(DomainError):
            SS.class_methods()

    def test_both_seams_inherit_the_floor(self, monkeypatch):
        """The floor is not a property of `store_source` alone: the two
        audits must be the ones that fail, since they are what the suites
        call."""
        monkeypatch.setattr(SS, "METHOD_FLOOR", SS.METHOD_FLOOR + 1)
        with pytest.raises(DomainError):
            audit_store_methods()
        with pytest.raises(DomainError):
            audit_command_writes()

    def test_a_renamed_class_raises_rather_than_reporting_nothing(self,
                                                                  tmp_path):
        store = tmp_path / "store.py"
        store.write_text("class SomethingElse:\n    pass\n", encoding="utf-8")
        with pytest.raises(DomainError) as excinfo:
            SS.resolve_chain(store)
        assert "cannot find class" in str(excinfo.value)

    def test_the_recorded_floor_matches_what_the_tree_actually_holds(self):
        """A floor far below reality is a floor that catches nothing. Kept
        equal so any loss is a failure, not just a catastrophic one."""
        report = SS.coverage()
        assert report["methods"] == SS.METHOD_FLOOR
        assert report["public_methods"] == SS.PUBLIC_METHOD_FLOOR
