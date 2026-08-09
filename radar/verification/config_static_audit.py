"""radar.verification.config_static_audit — static half of WP-1.2.

Answers, for every key in the declarative config registry: *is there any
code path that reads this key through the 3-layer resolution chain* (DB
override -> env -> code default), or is it only ever read through a
channel that bypasses it? That is defect G-15 / S1-CONF-008: an analyst
edits a threshold in SETTINGS, an override row and an audit row are
written, the UI shows the new number — and no consumer ever reads it.

Three channels are extracted from the AST of every production module:

    direct_read       `os.getenv("KEY", ...)` outside radar/config.py.
                      The DB layer is bypassed entirely.
    frozen_constant   the same call at *module scope of radar/config.py*.
                      Re-exported as `from radar.config import KEY`, so the
                      value is frozen for the life of the process. Split out
                      from direct_read because S1 §6.2/§6.3 count them
                      separately — both are bypasses.
    resolution        `get_config("KEY")` anywhere. The only channel a
                      SETTINGS edit can reach.

Everything here is pure: AST + the registry, no DB, no I/O beyond reading
source files. The runtime half (was the key actually read while the
process was alive?) lives in radar/verification/config_reachability.py.

This module is also import-safe on its own: nothing at module scope touches
the DB, the sensors or the app, and ``registry_from_ast()`` reads the
registry from source. That is what lets the CI gate classify the repository
without executing radar/__init__.py, which would migrate and write the
production database and start ~30 sensor threads. Keep it that way — a new
module-scope ``from radar.X import`` here would silently re-arm that.

Limits are surfaced, never dropped (S5-VERIF-006): a call whose key is not
a literal, or whose receiver cannot be resolved to `os` / `config_layered`
through the file's own imports, is reported as a `dynamic_getenv_sites`
entry rather than quietly skipped.
"""
from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from types import MappingProxyType
from typing import Any, Iterable, Mapping, Optional

from radar import config_layered

log = logging.getLogger("radar")

# ── channels ────────────────────────────────────────────────────────────────
CHANNEL_DIRECT_READ = "direct_read"
CHANNEL_FROZEN_CONSTANT = "frozen_constant"
CHANNEL_RESOLUTION = "resolution"
CHANNEL_DYNAMIC = "dynamic"
BYPASS_CHANNELS = (CHANNEL_DIRECT_READ, CHANNEL_FROZEN_CONSTANT)

# ── verdicts ────────────────────────────────────────────────────────────────
CLASS_FULL = "FULL_RESOLUTION"      # resolution reader, no bypass channel
CLASS_PARTIAL = "PARTIAL"           # both — some call sites still bypass
CLASS_BYPASSED = "BYPASSED"         # bypass only: the SETTINGS knob is dead
CLASS_DEAD = "DEAD"                 # registered, zero consumers of any kind
ALL_CLASSES = (CLASS_FULL, CLASS_PARTIAL, CLASS_BYPASSED, CLASS_DEAD)

# radar/config.py is the module whose top level freezes values into
# importable constants; every other module's module-level getenv is counted
# as a direct read to stay aligned with the S1 §6.2 / §6.3 enumeration.
FROZEN_CONSTANT_MODULE = "radar/config.py"
# The resolution machinery itself must read the environment.
EXCLUDED_MODULES = frozenset({"radar/config_layered.py"})

_SKIP_DIRS = frozenset({"__pycache__", "node_modules"})
# Production entrypoints that live outside the package directory.
_EXTRA_FILES = ("radar_api.py", "wsgi.py")

NOTE_SEMANTIC_INVERSION = "semantic_inversion"
# PLUGIN_ENABLED registry default '*' loads every plugin; the direct-read
# default '' loads none. Same type, opposite meaning — flagged by name
# rather than by a general semantics engine (S1-CONF-009).
_SEMANTIC_INVERSION_KEYS = frozenset({"PLUGIN_ENABLED"})

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


# ── data model ──────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Site:
    """One call site touching a config key."""
    key: Optional[str]          # None for dynamic (non-literal) keys
    file: str                   # repo-relative, POSIX separators
    line: int
    channel: str
    default_literal: Any = None
    has_default_literal: bool = False

    @property
    def site(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class KeyClassification:
    key: str
    verdict: str
    direct_read_sites: tuple[Site, ...] = ()
    frozen_constant_sites: tuple[Site, ...] = ()
    resolution_sites: tuple[Site, ...] = ()

    @property
    def bypass_sites(self) -> tuple[Site, ...]:
        return self.direct_read_sites + self.frozen_constant_sites


@dataclass(frozen=True)
class DefaultMismatch:
    """A hardcoded default that contradicts the registry declaration.

    Clearing the DB override reverts to *this* value, not to the one the
    SETTINGS UI advertises (S1-CONF-009).

    For a key declared ``secret``, both values are None and ``redacted`` is
    True: this record travels to /api/v2/self_eval (jwt-only) and into
    l5_check_result, which is retained for a year. The finding — that the
    two defaults disagree, and where — survives redaction intact.
    """
    key: str
    registry_default: Any
    direct_default: Any
    site: str
    channel: str
    note: str = ""
    redacted: bool = False


@dataclass(frozen=True)
class AuditResult:
    keys: Mapping[str, KeyClassification]
    counts: Mapping[str, int]
    default_mismatches: tuple[DefaultMismatch, ...]
    dynamic_getenv_sites: tuple[Site, ...]
    unregistered_resolution_reads: Mapping[str, tuple[Site, ...]]

    @property
    def registered_total(self) -> int:
        return len(self.keys)

    def keys_in_class(self, verdict: str) -> tuple[str, ...]:
        return tuple(sorted(k for k, c in self.keys.items()
                            if c.verdict == verdict))


# ── AST extraction ──────────────────────────────────────────────────────────
#
# Callees are resolved through the file's actual import bindings rather than
# by matching attribute names. Name matching was wrong in both directions:
# `import os as env_mod` made a real bypass invisible, and any object with a
# coincidental `.get_config()` method counted as a resolution reader, which
# would mask one. Anything that *looks* like a config access but cannot be
# resolved is emitted as a dynamic site — surfaced, never dropped.
_CANON_GETENV = "os.getenv"
_CANON_ENVIRON = "os.environ"
_CANON_ENVIRON_GET = "os.environ.get"
_GET_CONFIG_SUFFIX = "config_layered.get_config"

KIND_ENV = "env"
KIND_RESOLUTION = "resolution"
KIND_SUSPECT = "suspect"        # named like a config access, unresolvable


def _import_bindings(tree: ast.Module) -> dict[str, str]:
    """{local name -> dotted canonical} for every import in the file.

    The whole tree is walked, not just the module body, so function-local
    imports bind too.
    """
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    bindings[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    bindings[head] = head
        elif isinstance(node, ast.ImportFrom):
            # `from .config_layered import get_config` yields
            # "config_layered.get_config"; suffix matching below makes the
            # relative and absolute forms equivalent.
            module = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                bindings[local] = f"{module}.{alias.name}" if module \
                    else alias.name
    return bindings


def _dotted(node: ast.AST) -> Optional[str]:
    """`a.b.c` -> 'a.b.c'; anything not a pure name chain -> None."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _resolve(dotted: Optional[str], bindings: dict[str, str]) -> Optional[str]:
    if dotted is None:
        return None
    head, _, rest = dotted.partition(".")
    base = bindings.get(head)
    if base is None:
        return None
    return f"{base}.{rest}" if rest else base


def _tail(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _call_kind(func: ast.AST, bindings: dict[str, str]) -> Optional[str]:
    """What kind of config access this callee is, if any."""
    resolved = _resolve(_dotted(func), bindings)
    if resolved in (_CANON_GETENV, _CANON_ENVIRON_GET):
        return KIND_ENV
    if resolved is not None and resolved.endswith(_GET_CONFIG_SUFFIX):
        return KIND_RESOLUTION
    tail = _tail(func)
    if tail in ("getenv", "get_config"):
        return KIND_SUSPECT
    if tail == "get" and isinstance(func, ast.Attribute) \
            and _tail(func.value) == "environ":
        return KIND_SUSPECT
    return None


def _literal(node: Optional[ast.AST]) -> tuple[bool, Any]:
    if node is None:
        return (False, None)
    try:
        return (True, ast.literal_eval(node))
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return (False, None)


def _default_arg(node: ast.Call) -> Optional[ast.AST]:
    if len(node.args) > 1:
        return node.args[1]
    for kw in node.keywords:
        if kw.arg == "default":
            return kw.value
    return None


def _import_time_node_ids(tree: ast.Module) -> set[int]:
    """ids of nodes evaluated at import (module + class body scope)."""
    found: set[int] = set()

    def walk(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.Lambda)):
                continue
            if isinstance(child, (ast.Call, ast.Subscript)):
                found.add(id(child))
            walk(child)

    walk(tree)
    return found


def _env_channel(node: ast.AST, rel: str, import_time: set[int]) -> str:
    """Which bypass channel an environment read belongs to."""
    if rel == FROZEN_CONSTANT_MODULE and id(node) in import_time:
        return CHANNEL_FROZEN_CONSTANT
    return CHANNEL_DIRECT_READ


def _dynamic(rel: str, line: int) -> Site:
    return Site(key=None, file=rel, line=line, channel=CHANNEL_DYNAMIC)


def _call_site(node: ast.Call, rel: str, import_time: set[int],
               bindings: dict[str, str]) -> Optional[Site]:
    kind = _call_kind(node.func, bindings)
    if kind is None:
        return None
    if kind == KIND_SUSPECT or not node.args:
        return _dynamic(rel, node.lineno)

    ok, key = _literal(node.args[0])
    if not ok or not isinstance(key, str):
        return _dynamic(rel, node.lineno)
    if kind == KIND_RESOLUTION:
        return Site(key=key, file=rel, line=node.lineno,
                    channel=CHANNEL_RESOLUTION)
    has_default, default = _literal(_default_arg(node))
    return Site(key=key, file=rel, line=node.lineno,
                channel=_env_channel(node, rel, import_time),
                default_literal=default, has_default_literal=has_default)


def _subscript_site(node: ast.Subscript, rel: str, import_time: set[int],
                    bindings: dict[str, str]) -> Optional[Site]:
    """`os.environ["KEY"]` used as a read."""
    if isinstance(node.ctx, (ast.Store, ast.Del)):
        return None
    resolved = _resolve(_dotted(node.value), bindings)
    if resolved != _CANON_ENVIRON:
        if _tail(node.value) == "environ" and resolved is None:
            return _dynamic(rel, node.lineno)
        return None
    ok, key = _literal(node.slice)
    if not ok or not isinstance(key, str):
        return _dynamic(rel, node.lineno)
    return Site(key=key, file=rel, line=node.lineno,
                channel=_env_channel(node, rel, import_time))


def extract_sites(source: str, rel_path: str) -> tuple[Site, ...]:
    """Every config-touching call site in one module. Pure; never raises."""
    rel = rel_path.replace(os.sep, "/")
    if rel in EXCLUDED_MODULES:
        return ()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        log.warning("config audit: cannot parse %s: %s", rel, exc)
        return ()

    import_time = _import_time_node_ids(tree)
    bindings = _import_bindings(tree)
    sites: list[Site] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            found = _subscript_site(node, rel, import_time, bindings)
        elif isinstance(node, ast.Call):
            found = _call_site(node, rel, import_time, bindings)
        else:
            continue
        if found is not None:
            sites.append(found)
    return tuple(sorted(sites, key=lambda s: (s.line, s.channel, s.key or "")))


# ── repository scan ─────────────────────────────────────────────────────────
def _python_files(root: Path) -> list[Path]:
    scan_dir = root / "radar"
    if not scan_dir.is_dir():
        scan_dir = root
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(scan_dir):
        dirnames[:] = [d for d in dirnames
                       if d not in _SKIP_DIRS and not d.startswith(".")]
        found.extend(Path(dirpath) / f for f in filenames if f.endswith(".py"))
    found.extend(root / name for name in _EXTRA_FILES
                 if (root / name).is_file())
    return sorted(found)


def _read_source(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        log.warning("config audit: cannot read %s: %s", path, exc)
        return None


def _scan(root: Path) -> tuple[Site, ...]:
    sites: list[Site] = []
    for path in _python_files(root):
        source = _read_source(path)
        if source is None:
            continue
        sites.extend(extract_sites(source, path.relative_to(root).as_posix()))
    return tuple(sites)


# ── registry extraction without importing the application ───────────────────
#
# `import radar.config` executes radar/__init__.py, which migrates and writes
# the database and starts ~30 sensor threads with live outbound HTTP. A CI
# gate must not do that, so the registry is read from the same AST the scan
# already parses. `tests/test_config_static_audit.py::TestRegistryFromAst`
# pins this against the live registry so the two cannot drift.
_REGISTRY_SOURCE = "radar/config.py"
_CONFIG_KEY_FIELDS = ("domain", "default", "type_", "secret", "immutable",
                      "bootstrap")


def _module_constants(tree: ast.Module) -> dict[str, Any]:
    """Module-level `NAME = <literal>` assignments, for default lookups."""
    constants: dict[str, Any] = {}
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1:
            continue
        target = stmt.targets[0]
        if not isinstance(target, ast.Name):
            continue
        ok, value = _literal(stmt.value)
        if ok:
            constants[target.id] = value
    return constants


def _config_key_from_call(node: ast.Call, constants: dict[str, Any]):
    kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
    ok, key = _literal(kwargs.get("key"))
    if not ok or not isinstance(key, str):
        return None
    fields: dict[str, Any] = {}
    for name in _CONFIG_KEY_FIELDS:
        node_value = kwargs.get(name)
        if node_value is None:
            continue
        found, value = _literal(node_value)
        if not found and isinstance(node_value, ast.Name) \
                and node_value.id in constants:
            found, value = True, constants[node_value.id]
        if found:
            fields[name] = value
    return config_layered.ConfigKey(
        key=key, domain=fields.get("domain", ""),
        default=fields.get("default"), type_=fields.get("type_", "str"),
        secret=bool(fields.get("secret", False)),
        immutable=bool(fields.get("immutable", False)),
        bootstrap=bool(fields.get("bootstrap", False)))


def registry_from_ast(root: Optional[Path | str] = None) -> tuple:
    """The declarative registry, read from source. No application import."""
    root_path = Path(root) if root is not None else _REPO_ROOT
    source = _read_source(root_path / _REGISTRY_SOURCE)
    if source is None:
        return ()
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        log.warning("config audit: cannot parse the registry source: %s", exc)
        return ()

    constants = _module_constants(tree)
    keys = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _tail(node.func) == "ConfigKey":
            meta = _config_key_from_call(node, constants)
            if meta is not None:
                keys.append(meta)
    return tuple(keys)


# ── classification ──────────────────────────────────────────────────────────
def _classify_one(key: str, buckets: Mapping[str, list]) -> KeyClassification:
    direct = tuple(buckets[CHANNEL_DIRECT_READ])
    frozen = tuple(buckets[CHANNEL_FROZEN_CONSTANT])
    resolved = tuple(buckets[CHANNEL_RESOLUTION])
    bypassed = bool(direct or frozen)
    if resolved and not bypassed:
        verdict = CLASS_FULL
    elif resolved:
        verdict = CLASS_PARTIAL
    elif bypassed:
        verdict = CLASS_BYPASSED
    else:
        verdict = CLASS_DEAD
    return KeyClassification(key=key, verdict=verdict, direct_read_sites=direct,
                             frozen_constant_sites=frozen,
                             resolution_sites=resolved)


def _mismatch_for(meta, site: Site) -> Optional[DefaultMismatch]:
    if not site.has_default_literal:
        return None
    coerced = config_layered._coerce(site.default_literal, meta.type_)  # noqa: SLF001
    if coerced == meta.default:
        return None
    note = (NOTE_SEMANTIC_INVERSION if meta.key in _SEMANTIC_INVERSION_KEYS
            else "")
    secret = bool(getattr(meta, "secret", False))
    return DefaultMismatch(
        key=meta.key,
        registry_default=None if secret else meta.default,
        direct_default=None if secret else coerced,
        site=site.site, channel=site.channel, note=note, redacted=secret)


def _default_mismatches(metas: Mapping[str, Any],
                        classes: Mapping[str, KeyClassification]
                        ) -> tuple[DefaultMismatch, ...]:
    found: list[DefaultMismatch] = []
    for key, cls in classes.items():
        for site in cls.bypass_sites:
            mismatch = _mismatch_for(metas[key], site)
            if mismatch is not None:
                found.append(mismatch)
    return tuple(sorted(found, key=lambda m: (m.key, m.site)))


def audit(root: Optional[Path | str] = None,
          keys: Optional[Iterable[Any]] = None) -> AuditResult:
    """Classify every registered key. Pure — safe to call from a request."""
    root_path = Path(root) if root is not None else _REPO_ROOT
    metas = {k.key: k for k in (
        list(keys) if keys is not None
        else config_layered.all_keys(include_secrets=True))}

    buckets: dict[str, dict[str, list]] = {
        key: {CHANNEL_DIRECT_READ: [], CHANNEL_FROZEN_CONSTANT: [],
              CHANNEL_RESOLUTION: []} for key in metas}
    dynamic: list[Site] = []
    unregistered: dict[str, list[Site]] = {}

    for site in _scan(root_path):
        if site.channel == CHANNEL_DYNAMIC:
            dynamic.append(site)
        elif site.key in buckets:
            buckets[site.key][site.channel].append(site)
        elif site.channel == CHANNEL_RESOLUTION:
            # S1-CONF-010, the reverse defect: resolved but never
            # registered, so the raw env string is returned uncoerced.
            unregistered.setdefault(site.key, []).append(site)

    classes = {key: _classify_one(key, b) for key, b in buckets.items()}
    counts = {verdict: sum(1 for c in classes.values() if c.verdict == verdict)
              for verdict in ALL_CLASSES}
    return AuditResult(
        keys=MappingProxyType(classes),
        counts=MappingProxyType(counts),
        default_mismatches=_default_mismatches(metas, classes),
        dynamic_getenv_sites=tuple(dynamic),
        unregistered_resolution_reads=MappingProxyType(
            {k: tuple(v) for k, v in unregistered.items()}),
    )


# ── memoised repo audit ─────────────────────────────────────────────────────
# The scan parses every production module, so the daily job and the
# self_eval surface share one result rather than re-parsing per request.
# Source files do not change inside a running container; the cache is
# cleared explicitly by tests and by the CI gate.
_cache_lock = RLock()
_cached: Optional[AuditResult] = None


def audit_cached() -> AuditResult:
    global _cached
    with _cache_lock:
        if _cached is None:
            _cached = audit()
        return _cached


def clear_cache() -> None:
    global _cached
    with _cache_lock:
        _cached = None
