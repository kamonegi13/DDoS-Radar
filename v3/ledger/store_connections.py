"""The handles, and what makes several of them safe.

Extracted from `store.py` for the 800-line house limit, and the split is
audit-visible rather than incidental: `v3/api/store_source.py` resolves
`LedgerStore`'s declared base chain from the source, so this module is
parsed by both API seams exactly as `store.py` is. A connection method
hidden in a module the chain did not reach would make the read seam stop
forwarding a projection and the write seam stop noticing a writer, with
nothing failing — which is what `store_source.py` exists to refuse.

**Both handles are per-thread, and that is a decision, not symmetry.**
sqlite3 binds a connection to the thread that created it. `LedgerStore` is
constructed on the gunicorn worker's thread, and `v3/runtime/loop.py` runs
the tick — the only writer — on a thread of its own. One shared handle
therefore means every tick dies at its first statement, and both halves of
that have now happened in production: the read handle in e973d31, the
write handle in the very next shadow run, once per tick, for the whole
of it.

`check_same_thread=False` is refused for both. It removes the exception
and puts an unserialised race in its place, which is a worse thing wearing
a quieter face.

**What keeps several WRITE handles safe is not the handles.** SQLite
permits one writer, and two `BEGIN IMMEDIATE`s on one file answer each
other with SQLITE_BUSY rather than with a merge. `transaction()` holds
`self._lock` across a whole BEGIN IMMEDIATE..COMMIT, so at most one write
transaction exists in this process at any instant however many
connections do — and that was ALWAYS what serialised writes here. The
single connection was never the mechanism; it was a coincidence that
looked like one. The invariants that depended on it are unchanged and are
checked in `tests/test_ledger_store.py`:

  * one serialised write transaction (the lock, above);
  * the append-only triggers, which are schema objects and therefore bind
    every handle to the file, not the handle that happened to be first;
  * the retention prune flag's single-`BEGIN IMMEDIATE` invariant — the
    gate opens, the deletes run and the gate closes inside ONE
    `transaction()`, on one connection, under the lock.

A per-thread cache keyed by `threading.get_ident()` rather than
`threading.local()`, because `close()` has to be able to ENUMERATE the
handles it is giving up.
"""
from __future__ import annotations

import sqlite3
import threading
import urllib.parse
from contextlib import contextmanager

#: Both connections wait rather than failing instantly when another holds
#: the write lock. WAL keeps readers unblocked; this covers the window when
#: a writer is committing.
BUSY_TIMEOUT_MS = 5000


def open_write(path: str) -> sqlite3.Connection:
    """One writing connection, with every per-connection pragma set.

    A module function rather than a method because it is called for the
    FIRST handle and for every later one, and the two must not be able to
    drift: `foreign_keys` and `synchronous` are per-CONNECTION settings, so
    a second handle that skipped them would enforce no foreign keys and
    fsync differently from the first — silently, and only on whichever
    thread happened to open it.

    `busy_timeout` is set first on purpose. It governs how the statements
    after it behave when another connection holds the file's write lock,
    so setting it last would leave the pragmas that precede it — the ones
    run while a tick may be committing — failing instantly instead of
    waiting.

    `isolation_level=None`: transactions are explicit here, because the
    retention job must set a flag, delete, and clear the flag as ONE unit.
    Implicit transaction handling cannot express that.

    `journal_mode` is a property of the FILE rather than of the
    connection, so re-declaring it costs nothing and is declared anyway: a
    handle whose mode depended on another handle having been opened first
    is a handle whose behaviour depends on start-up order.
    """
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        # WAL + NORMAL: fsync at checkpoints rather than at every commit.
        # Safe against process crash (WAL replays); the exposure is a power
        # loss losing the last transactions, which for an append-only
        # observation ledger costs one tick, not integrity. FULL would make
        # the 1M-row migration fsync-bound.
        conn.execute("PRAGMA synchronous=NORMAL")
    except BaseException:
        conn.close()
        raise
    return conn


def open_read(path: str) -> sqlite3.Connection:
    """A read-only handle: a query path cannot write even by mistake."""
    # quote(): an unquoted '#' or '?' truncates the URI, so the read
    # connection silently opens a DIFFERENT (empty) database while writes
    # keep succeeding — every read returns nothing and nothing reports
    # why. Third occurrence of this lesson here.
    conn = sqlite3.connect(f"file:{urllib.parse.quote(path)}?mode=ro",
                           uri=True)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    except BaseException:
        conn.close()
        raise
    return conn


class ConnectionMixin:
    """Handle lifecycle and the write gate. Methods only; the state — the
    two caches, their locks and the write lock — is built in
    `LedgerStore.__init__`, so "single jurisdiction" (A-09) is a property
    of one object rather than of one file."""

    def close(self) -> None:
        """Close the CALLER's own handles; other threads' get dereferenced.

        `sqlite3.Connection.close()` is ITSELF thread-gated — verified,
        not supposed — so closing another thread's handle raises the very
        error this store now avoids. Dropping the reference is a real
        close rather than a pretend one: CPython's deallocator runs
        `sqlite3_close_v2` without the same-thread check, synchronously,
        once the refcount falls.

        `self._lock` is deliberately NOT taken. A thread inside
        `transaction()` holds its own local reference to its handle for
        the whole BEGIN..COMMIT, so dropping this store's reference cannot
        close a connection out from under a live transaction; and taking
        the lock would turn "close while a tick is stuck" from an
        unserialised close into a hang. What `close()` therefore does NOT
        do is wait for a thread still mid-write.
        """
        with self._read_conns_lock:
            own_read = self._read_conns.pop(threading.get_ident(), None)
            self._read_conns.clear()
        with self._write_conns_lock:
            own_write = self._write_conns.pop(threading.get_ident(), None)
            self._write_conns.clear()
        for handle in (own_read, own_write):
            if handle is not None:
                handle.close()

    def _connection(self) -> sqlite3.Connection:
        """One writing handle per thread; lazy, cached.

        Handing out a handle is NOT handing out permission to write
        unserialised: `transaction()` is what holds `self._lock`, and it
        is the only sanctioned way in.
        """
        ident = threading.get_ident()
        with self._write_conns_lock:
            existing = self._write_conns.get(ident)
            if existing is not None:
                return existing
            # Opened while holding the lock, unlike the read path: two
            # write handles for ONE thread would be two ways past
            # `self._lock`, and two BEGIN IMMEDIATEs on one file answer
            # each other with SQLITE_BUSY rather than with a merge. An
            # open costs microseconds and happens once per thread.
            conn = open_write(self._path)
            self._write_conns[ident] = conn
            return conn

    def _read_connection(self) -> sqlite3.Connection:
        """One read-only handle per thread; lazy, cached.

        Opened OUTSIDE the lock, unlike the write handle: a duplicate read
        handle is a wasted file descriptor, while a duplicate write handle
        would be a second way past the write gate.
        """
        ident = threading.get_ident()
        with self._read_conns_lock:
            existing = self._read_conns.get(ident)
            if existing is not None:
                return existing
        conn = open_read(self._path)
        with self._read_conns_lock:   # different threads -> different keys
            self._read_conns[ident] = conn
        return conn

    @contextmanager
    def _maybe_transaction(self, connection=None):
        """Join the caller's transaction, or open one.

        The ETL batches a whole chunk into one transaction and passes it
        down; everything else gets its own. The lock is held by whoever
        opened the transaction, and it is not reentrant, so a passed-in
        connection must never re-acquire it — which also means a
        connection must never be passed ACROSS threads: it would be both
        the wrong thread's handle and outside the gate.
        """
        if connection is not None:
            yield connection
            return
        with self.transaction() as own:
            yield own

    @contextmanager
    def transaction(self):
        """One serialised write transaction. Rolls back on any exception.

        Held for the whole unit of work, so a partially applied prune or
        fold cannot survive a failure.

        The lock — not the connection — is what makes "one" true. Handles
        are per-thread, so two threads hold two handles to one file; this
        is where they queue. The connection is resolved BEFORE the lock is
        taken, so opening a handle for a first-time writer never happens
        while the write gate is shut.
        """
        conn = self._connection()
        with self._lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")


__all__ = ["ConnectionMixin", "open_read", "open_write", "BUSY_TIMEOUT_MS"]
