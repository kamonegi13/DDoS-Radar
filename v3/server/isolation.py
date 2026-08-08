"""The guards that keep a running v3 away from the running v1.

R4 is the whole reason this file exists: the old system stays
authoritative until parity passes, so a v3 process that could reach v1's
database or v1's port is a v3 process whose parity measurement is also a
production incident. Three separate accidents are closed here, and each
one has already happened somewhere in this program's history.

**A path typo.** `LedgerStore` refuses to default its path (a default is
how two processes disagree about which database is real), which leaves
exactly one failure mode: a path that is supplied and wrong.
`assert_isolated_ledger` names the v1 files rather than pattern-matching
them, and refuses `radar/persistence/` entirely — including a v3-named
file placed inside it, because the WAL siblings of a database live beside
it and a second writer in that directory is A-09's second store all over
again.

**A port collision.** v1 binds 8000. Refused by name.

**A transitive import.** This is the live one, and it is not hypothetical:
`v3/kernel/threshold.py::_default_resolver` does `from radar import
config_layered`, which runs `radar/__init__.py` — the Flask app, the
migrations and ~40 sensor threads, against the production database. It is
reached whenever a registry-backed `Threshold` resolves with no injected
resolver. The composition root supplies v3's own chain everywhere it
knows about, but "everywhere it knows about" is exactly the assurance a
barrier replaces with a fact. `LegacyImportBarrier` sits on `sys.meta_path`
and raises, so the landmine detonates as a stack trace in a shadow process
instead of a second application inside the live one.

The barrier is installed by the composition root and removed by
`Deployment.close()`. It is not installed at import — this module is as
inert as every other module under `v3/`.
"""
from __future__ import annotations

import sys
from typing import Optional

from v3.kernel.errors import DomainError

#: v1's port, from `docker-compose.yml`. Named rather than derived: v3
#: must not read v1's configuration to find out what to avoid.
V1_PORT = 8000

#: The legacy package. Importing it boots the application.
LEGACY_ROOT = "radar"

#: Every filename that IS a v1 database, including the sqlite sidecars a
#: WAL-mode database writes beside itself, and A-09's second store.
V1_DATABASE_NAMES: frozenset = frozenset({
    "radar.db", "radar.db-wal", "radar.db-shm",
    "convergence_snapshots.db", "convergence_snapshots.db-wal",
    "convergence_snapshots.db-shm",
})

#: v1's persistence directory, as an ordered pair of path components. The
#: whole directory is refused, not just the known filenames: a v3-named
#: file in there shares a directory with v1's WAL, and the backup job
#: (`scripts/backup_radar_db.sh`) copies what it finds.
V1_PERSISTENCE_PARTS: tuple[str, ...] = ("radar", "persistence")


class LegacyImportRefused(DomainError):
    """Raised when a composed v3 process tries to import `radar.*`."""


def assert_isolated_ledger(path: str) -> str:
    """Return the resolved path, or refuse it as a v1 file.

    Refusing rather than correcting: a deployment that meant to write the
    v3 ledger and named `radar.db` has a broken configuration, and
    silently writing somewhere else would leave the operator believing a
    path that is not the one in use.
    """
    import pathlib
    if not isinstance(path, str) or not path.strip():
        raise DomainError(
            "the v3 ledger needs an explicit path: v3 shadow-runs beside "
            "v1 until cutover, so which file this is is a deployment "
            "decision and a default is how two processes come to disagree "
            "about which database is real")
    resolved = pathlib.Path(path).expanduser()
    name = resolved.name
    if name in V1_DATABASE_NAMES:
        raise DomainError(
            f"{name!r} is a v1 database file. v3 runs in shadow (R4): the "
            f"old system stays authoritative until parity passes, so the v3 "
            f"ledger is a SEPARATE file. Refused names: "
            f"{sorted(V1_DATABASE_NAMES)}.")
    parts = tuple(part.lower() for part in resolved.parts)
    for index in range(len(parts) - 1):
        if parts[index:index + 2] == V1_PERSISTENCE_PARTS:
            raise DomainError(
                f"{path!r} is inside v1's persistence directory. The whole "
                f"directory is refused, not only the known filenames: a "
                f"database in there shares a directory with v1's WAL and is "
                f"picked up by the v1 backup job, which is how A-09's second "
                f"store came to exist with its own blind spots.")
    return str(resolved)


def assert_isolated_port(port: int) -> int:
    """Refuse v1's port. A shadow that answers on 8000 is not a shadow."""
    number = int(port)
    if not 1 <= number <= 65535:
        raise DomainError(f"port must be in 1..65535, got {number}")
    if number == V1_PORT:
        raise DomainError(
            f"port {V1_PORT} belongs to the running v1 service "
            f"(docker-compose.yml). v3 runs beside it, on its own port, "
            f"until parity passes (R4).")
    return number


def legacy_modules() -> tuple[str, ...]:
    """Every `radar.*` module already imported into THIS process."""
    return tuple(sorted(
        name for name in list(sys.modules)
        if name == LEGACY_ROOT or name.startswith(LEGACY_ROOT + ".")))


def assert_legacy_absent(where: str = "compose") -> None:
    """Refuse to compose inside a process that already booted v1.

    The shape this prevents is the one the ops_health check found: a
    second application started inside the live container, sharing its
    interpreter, its threads and its database handle.
    """
    loaded = legacy_modules()
    if loaded:
        raise DomainError(
            f"{where}: this process has already imported {list(loaded)}, "
            f"which means the legacy application is booted here (Flask app, "
            f"migrations, ~40 sensor threads, the production database). v3 "
            f"runs as its OWN process on its own port and its own ledger "
            f"file; composing it inside a v1 process is how a shadow run "
            f"becomes a production incident.")


class LegacyImportBarrier:
    """A `sys.meta_path` finder that refuses the legacy tree.

    Placed first, so it is consulted before any real finder and the import
    never happens. It answers `None` for everything else, which is the
    protocol's "not my business" and leaves normal imports untouched.

    Idempotent in both directions: installing twice inserts once, removing
    a barrier that is not installed is a no-op. A composition root that
    raised half-way through must still be closable.
    """

    __slots__ = ("_installed",)

    def __init__(self) -> None:
        self._installed = False

    @property
    def installed(self) -> bool:
        return self._installed and self in sys.meta_path

    def install(self) -> "LegacyImportBarrier":
        if self not in sys.meta_path:
            sys.meta_path.insert(0, self)
        self._installed = True
        return self

    def remove(self) -> "LegacyImportBarrier":
        while self in sys.meta_path:
            sys.meta_path.remove(self)
        self._installed = False
        return self

    def __enter__(self) -> "LegacyImportBarrier":
        return self.install()

    def __exit__(self, *exc) -> None:
        self.remove()

    # ── the finder protocol ────────────────────────────────────────────
    def find_spec(self, fullname: str, path=None,
                  target=None) -> Optional[object]:
        if fullname == LEGACY_ROOT or fullname.startswith(LEGACY_ROOT + "."):
            raise LegacyImportRefused(
                f"import of {fullname!r} was refused: this is a composed v3 "
                f"process and importing radar.* boots the legacy "
                f"application against the production database. The usual "
                f"cause is a registry-backed Threshold resolving with no "
                f"injected resolver — v3/kernel/threshold.py::"
                f"_default_resolver terminates in radar.config_layered. "
                f"Supply the composition root's chain "
                f"(v3/runtime/config.py::build_resolver).")
        return None


__all__ = ["V1_PORT", "V1_DATABASE_NAMES", "V1_PERSISTENCE_PARTS",
           "LEGACY_ROOT", "LegacyImportRefused", "LegacyImportBarrier",
           "assert_isolated_ledger", "assert_isolated_port",
           "assert_legacy_absent", "legacy_modules"]
