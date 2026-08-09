"""Layered configuration — Phases 9.1 / R1-R6.

Single entry point for every config read in the codebase. Resolves a key
through a 3-layer chain:

    1. **DB override** (mutable keys only, recently-cached)
    2. **Env var**     (populated from config.env at startup)
    3. **Code default** (registered metadata)

Every key is registered once with rich metadata (type, default,
secret/immutable/restart/bootstrap flags, validator, group, impact_level,
apply timing label). The Settings UI is rendered from the registry.

Reachability (WP-1.2, corrected 2026-08-06): this module used to claim
that "CI gates assert no ``os.getenv`` for registered keys outside this
module". **No such gate has ever existed**, and in its absence almost
every registered key came to be read through a channel that bypasses the
chain above (defect G-15 / S1-CONF-008). What exists now is an audit, not
a prohibition: ``radar.verification.config_static_audit`` classifies each
key's read channels and ``radar.verification.config_reachability`` joins
that with the runtime tracker below, reports through ``/api/v2/self_eval``
and fails ``scripts/check_config_reachability.py`` on regression. Routing
the bypassing keys back through ``get_config()`` is separate work; until
then, registration alone does not make a key live.

NP3: never raises on the hot path. NP6: every mutation flows through
``set_config()`` which writes to ``config_change_log`` for audit.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Callable, Optional

log = logging.getLogger("radar.config_layered")


# ── Type registry ──────────────────────────────────────────────────────────


# Verb-based UI groups (R3). Each registered key belongs to exactly one.
GROUP_OPERATE        = "OPERATE"          # weekly+: scenarios, sensors, alert routing
GROUP_TUNE           = "TUNE"             # monthly: thresholds, weights, scoring knobs
GROUP_LLM_HEALTH     = "LLM_HEALTH"       # LLM connection/features/routing/embedding
GROUP_INFRASTRUCTURE = "INFRASTRUCTURE"   # restart-required: ports, proxy, cache, polls
GROUP_ACCESS         = "ACCESS"           # secrets, JWT, admin
GROUP_AUDIT          = "AUDIT"            # read-only ledgers (UI side only — no keys)

ALL_GROUPS = (GROUP_OPERATE, GROUP_TUNE, GROUP_LLM_HEALTH,
              GROUP_INFRASTRUCTURE, GROUP_ACCESS)


# Apply-timing labels (R3 + R5). Plain English so the UI can show
# "saved values take effect…" without per-key UI logic.
TIMING_LIVE_NEXT_TICK   = "Live — next scoring tick (~30s)"
TIMING_LIVE_IMMEDIATE   = "Live — immediate (next API call)"
TIMING_LIVE_NEXT_CYCLE  = "Live — next intel queue cycle"
TIMING_RESTART_REQUIRED = "Restart required — docker compose restart"
TIMING_READ_ONLY        = "Read-only"


@dataclass(frozen=True)
class ConfigKey:
    """Declarative description of one config key."""
    key: str
    domain: str                     # legacy dot-namespace, kept for back-compat
    default: Any
    type_: str                      # 'str' | 'int' | 'float' | 'bool' | 'list[str]' | 'json'
    description: str = ""           # legacy short label (kept for fallback)
    secret: bool = False            # never expose value
    immutable: bool = False         # env-only; DB writes rejected
    restart_required: bool = False  # mutating requires container restart
    bootstrap: bool = False         # needed before DB exists; never DB-overridable
    validator: Optional[Callable[[Any], bool]] = None
    enum: tuple = field(default_factory=tuple)
    # R1 — UI metadata
    group: str = GROUP_OPERATE
    apply_timing: str = TIMING_LIVE_NEXT_TICK
    impact_level: str = "low"       # 'low' | 'med' | 'high' (drives R5 warning)
    impact_warning: str = ""        # shown in modal for impact_level='high'
    unit: str = ""                  # 's', 'min', 'h', 'd', '%', etc. — UI hint
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    # SETTINGS UX redesign (2026-05-05) — three-line explanation block.
    # `description` (above) is kept as the short label; the SETTINGS UI
    # falls back to it when the three-line block is empty.
    what: str = ""                  # what this knob controls (1 sentence)
    why: str  = ""                  # design rationale + observed behaviour
    when: str = ""                  # when an analyst should change it


_REGISTRY: dict[str, ConfigKey] = {}


def register(*keys: ConfigKey) -> None:
    """Register one or more keys. Idempotent."""
    for k in keys:
        _REGISTRY[k.key] = k
    # Bumping cache generation invalidates all cached reads — important
    # if a re-register changes a key's metadata mid-run (test harnesses).
    _bump_cache_gen()


def get_meta(key: str) -> Optional[ConfigKey]:
    return _REGISTRY.get(key)


def all_keys(include_secrets: bool = True,
             group: Optional[str] = None) -> list[ConfigKey]:
    """List registered keys, optionally filtered by group / secret flag."""
    out = []
    for k in _REGISTRY.values():
        if not include_secrets and k.secret:
            continue
        if group is not None and k.group != group:
            continue
        out.append(k)
    out.sort(key=lambda k: (k.group, k.domain, k.key))
    return out


def domains() -> list[str]:
    return sorted({k.domain for k in _REGISTRY.values()})


def groups() -> list[str]:
    """Verb-based groups in display order."""
    return list(ALL_GROUPS)


# ── Type coercion ──────────────────────────────────────────────────────────


_BOOL_TRUE = {"1", "true", "yes", "on"}


def _coerce(value: Any, type_: str) -> Any:
    """Convert env-string / DB-string / native value to the declared type.
    Returns None on coercion failure so callers fall through to default."""
    if value is None:
        return None
    if type_ == "str":
        return str(value)
    if type_ == "int":
        try:
            return int(value)
        except (TypeError, ValueError):
            try:
                return int(float(value))
            except (TypeError, ValueError):
                return None
    if type_ == "float":
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    if type_ == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in _BOOL_TRUE
    if type_ == "list[str]":
        if isinstance(value, list):
            return [str(x) for x in value]
        s = str(value).strip()
        if not s:
            return []
        return [x.strip() for x in s.split(",") if x.strip()]
    if type_ == "json":
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(str(value))
        except (TypeError, ValueError):
            return None
    return value


# ── Hot-path cache (X5 mitigation) ─────────────────────────────────────────
#
# Sensor scoring loops call get_config() many times per second. Without
# caching, every call hits SQLite. We use a process-local cache with:
#   - 30s TTL  → bounded staleness on env-only keys (fine)
#   - generation counter → set_config() / clear_config() / register() bump
#     the generation, invalidating every cached read on the next call
#
# This is monotonically safe under concurrent reads because the cache is
# advisory: stale reads at most return the value that WAS effective up to
# 30s ago, which is the same guarantee scoring already accepts (sensors
# tick at intervals ≥ 30s).


_CACHE_TTL_SEC = 30.0
_cache_lock = RLock()
_cache: dict[str, tuple[float, int, Any]] = {}  # key -> (expires_at, gen, value)
_cache_gen = 0


def _bump_cache_gen() -> None:
    global _cache_gen
    with _cache_lock:
        _cache_gen += 1
        _cache.clear()


def _cache_get(key: str) -> tuple[bool, Any]:
    """Return (hit, value). hit=False on miss / expired / stale generation."""
    with _cache_lock:
        ent = _cache.get(key)
        if ent is None:
            return (False, None)
        expires_at, gen, value = ent
        if gen != _cache_gen:
            return (False, None)
        if time.monotonic() > expires_at:
            return (False, None)
        return (True, value)


def _cache_put(key: str, value: Any) -> None:
    with _cache_lock:
        _cache[key] = (time.monotonic() + _CACHE_TTL_SEC, _cache_gen, value)


def invalidate_cache(key: Optional[str] = None) -> None:
    """Public hook so /api/env_config/reload (legacy) can flush the cache."""
    with _cache_lock:
        if key is None:
            _cache.clear()
        else:
            _cache.pop(key, None)


# ── Runtime read tracker (WP-1.2 / S5-VERIF-014) ───────────────────────────
#
# The static audit can prove that a `get_config()` call site *exists*; only
# this can say whether it was ever *executed*. A registered key that no
# running process ever reads is a dead knob even when the static classifier
# is happy — the "registered but never read" direction of S5-VERIF-014.
#
# In-process and deliberately cheap: one dict update per read under a
# dedicated lock. `config_reachability.flush_read_stats()` merges these
# counters into `config_read_stats` and resets them, so the persisted row
# accumulates across restarts.

_read_lock = RLock()
_read_stats: dict[str, dict] = {}
_unregistered_reads: dict[str, dict] = {}
_read_tracker_started_at = time.time()

# Unregistered keys are unbounded by construction — any string a caller
# passes lands here — so the table is capped and overflow is counted rather
# than silently accepted (a memory leak) or silently dropped (a blind spot).
_UNREGISTERED_READ_CAP = 512
_unregistered_dropped = 0
_unregistered_cap_logged = False


def _record_read(key: str, source: Optional[str], now: float) -> None:
    """Note one resolution of `key`. Never raises — NP3 hot path."""
    global _unregistered_dropped, _unregistered_cap_logged
    with _read_lock:
        registered = key in _REGISTRY
        table = _read_stats if registered else _unregistered_reads
        entry = table.get(key)
        if entry is not None:
            entry["last_read_at"] = now
            entry["read_count"] += 1
            if source is not None:
                entry["last_source"] = source
            return
        if not registered and len(table) >= _UNREGISTERED_READ_CAP:
            _unregistered_dropped += 1
            if not _unregistered_cap_logged:
                _unregistered_cap_logged = True
                log.warning("config read tracker: unregistered-key table hit "
                            "its %d-key cap; further distinct keys are "
                            "counted, not listed", _UNREGISTERED_READ_CAP)
            return
        table[key] = {"first_read_at": now, "last_read_at": now,
                      "read_count": 1, "last_source": source}


def _copy_stats(table: dict) -> dict[str, dict]:
    with _read_lock:
        return {k: dict(v) for k, v in table.items()}


def _merge_into(table: dict, entries: dict) -> None:
    """Fold `entries` back into a live tracker table (caller holds the lock)."""
    for key, entry in entries.items():
        current = table.get(key)
        if current is None:
            table[key] = dict(entry)
            continue
        current["first_read_at"] = min(current["first_read_at"],
                                       entry["first_read_at"])
        current["last_read_at"] = max(current["last_read_at"],
                                      entry["last_read_at"])
        current["read_count"] += entry["read_count"]


def drain_read_stats(now: Optional[float] = None
                     ) -> tuple[dict[str, dict], dict[str, dict]]:
    """Atomically take the counters and start fresh ones.

    One critical section, so a read landing mid-flush is counted in either
    the drained snapshot or the next one — never lost between a copy and a
    later clear.
    """
    global _read_stats, _unregistered_reads, _read_tracker_started_at
    with _read_lock:
        taken = (_read_stats, _unregistered_reads)
        _read_stats = {}
        _unregistered_reads = {}
        _read_tracker_started_at = time.time() if now is None else now
        return taken


def restore_read_stats(registered: dict, unregistered: dict) -> None:
    """Fold a drained snapshot back in after a failed persist."""
    with _read_lock:
        _merge_into(_read_stats, registered)
        _merge_into(_unregistered_reads, unregistered)


def unregistered_read_dropped() -> int:
    """Distinct unregistered keys refused by the cap since the last reset."""
    with _read_lock:
        return _unregistered_dropped


def runtime_read_stats() -> dict[str, dict]:
    """{registered key: {first_read_at, last_read_at, read_count, last_source}}."""
    return _copy_stats(_read_stats)


def unregistered_read_stats() -> dict[str, dict]:
    """Same shape, for keys resolved without a registry entry.

    These are the silent-fallback class of S1-CONF-007/010: the raw env
    string (None when unset) is returned with no type coercion, no range
    check and no DB layer.
    """
    return _copy_stats(_unregistered_reads)


def read_tracker_started_at() -> float:
    """When the in-process counters last started from zero."""
    return _read_tracker_started_at


def reset_read_stats(now: Optional[float] = None) -> None:
    """Drop the in-process counters entirely (test / diagnostic hook)."""
    global _unregistered_dropped, _unregistered_cap_logged
    with _read_lock:
        drain_read_stats(now=now)
        _unregistered_dropped = 0
        _unregistered_cap_logged = False


# ── Read path ──────────────────────────────────────────────────────────────


def _read_db(key: str) -> Any:
    """Read the persisted DB override for a key, or None if missing / DB
    unavailable. NP3."""
    try:
        from radar.database import db
        row = db._get_conn().execute(  # noqa: SLF001
            "SELECT value_json FROM config_runtime_value WHERE config_key=?",
            (key,),
        ).fetchone()
    except Exception as exc:
        log.debug("config DB read for %s failed: %s", key, exc)
        return None
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return None


def _read_env(key: str) -> Any:
    raw = os.getenv(key)
    if raw is None:
        return None
    return raw


def _resolve_with_source(key: str) -> tuple[Any, str]:
    """Resolve `key` and report which layer produced the value."""
    meta = _REGISTRY.get(key)
    if meta is None:
        # Unregistered: the raw env string, uncoerced (S1-CONF-007).
        return (_read_env(key), "unregistered_env")

    # Bootstrap & immutable keys skip the DB layer.
    if not meta.immutable and not meta.bootstrap:
        db_v = _coerce(_read_db(key), meta.type_)
        if db_v is not None:
            return (db_v, "db")

    env_v = _coerce(_read_env(key), meta.type_)
    if env_v is not None:
        return (env_v, "env")

    return (meta.default, "default")


def _resolve_uncached(key: str) -> Any:
    return _resolve_with_source(key)[0]


def get_config(key: str) -> Any:
    """Resolve a key through the 3-layer chain. NP3 — never raises.

    Caches results for 30s. Cache is invalidated on every set_config /
    clear_config / register, so analyst writes propagate immediately.

    Every call is recorded by the read tracker — including cache hits,
    because the audit question is "did anything read this key", not "did
    anything miss the cache". Only a resolved (uncached) read knows which
    layer answered, so cache hits leave `last_source` as it was.
    """
    now = time.time()
    hit, cached = _cache_get(key)
    if hit:
        _record_read(key, None, now)
        return cached
    value, source = _resolve_with_source(key)
    _cache_put(key, value)
    _record_read(key, source, now)
    return value


def is_restart_pending(key: str) -> bool:
    """True iff a key declared ``restart_required=True`` has a DB override
    that differs from the running env value."""
    meta = _REGISTRY.get(key)
    if meta is None or not meta.restart_required:
        return False
    db_v = _coerce(_read_db(key), meta.type_)
    if db_v is None:
        return False
    env_v = _coerce(_read_env(key), meta.type_)
    if env_v is None:
        env_v = meta.default
    return db_v != env_v


def get_value_source(key: str) -> str:
    """Return 'db' | 'env' | 'default' — which layer is providing the
    current effective value. UI shows this so analysts know whether
    their last edit actually landed."""
    meta = _REGISTRY.get(key)
    if meta is None:
        return "env" if os.getenv(key) is not None else "default"
    if not meta.immutable and not meta.bootstrap:
        if _coerce(_read_db(key), meta.type_) is not None:
            return "db"
    if _coerce(_read_env(key), meta.type_) is not None:
        return "env"
    return "default"


# ── Write path ──────────────────────────────────────────────────────────────


def set_config(key: str, value: Any, *,
               by: str, reason: Optional[str] = None,
               request_id: Optional[str] = None) -> tuple[bool, str]:
    """Persist a runtime override + write the audit row.

    Returns ``(ok, message)``. NP3 — never raises.
    """
    meta = _REGISTRY.get(key)
    if meta is None:
        return (False, f"unknown config key {key!r}")
    if meta.secret:
        return (False, f"key {key!r} is secret — refuse to write via UI")
    if meta.immutable:
        return (False, f"key {key!r} is immutable — edit config.env + restart")
    if meta.bootstrap:
        return (False, f"key {key!r} is bootstrap-only — edit config.env + restart")
    coerced = _coerce(value, meta.type_)
    if coerced is None and value is not None and value != "":
        return (False, f"value {value!r} not coercible to {meta.type_}")
    if value == "" and meta.type_ != "str" and meta.type_ != "list[str]":
        # Empty input on a non-string field clears the override.
        return clear_config(key, by=by, reason=reason or "empty value submitted")
    if meta.enum and coerced not in meta.enum:
        return (False, f"value {coerced!r} not in allowed {meta.enum}")
    if meta.min_value is not None and isinstance(coerced, (int, float)) \
            and coerced < meta.min_value:
        return (False, f"value {coerced} below minimum {meta.min_value}")
    if meta.max_value is not None and isinstance(coerced, (int, float)) \
            and coerced > meta.max_value:
        return (False, f"value {coerced} above maximum {meta.max_value}")
    if meta.validator and not meta.validator(coerced):
        return (False, f"value {coerced!r} failed validator")
    if meta.impact_level == "high" and not (reason and reason.strip()):
        return (False,
                f"key {key!r} has high impact — reason field is required")

    old_value = get_config(key)

    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute("""
                CREATE TABLE IF NOT EXISTS config_runtime_value (
                    config_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    set_at     REAL NOT NULL,
                    set_by     TEXT NOT NULL
                )
            """)
            import time as _time
            conn.execute(
                "INSERT INTO config_runtime_value "
                "(config_key, value_json, set_at, set_by) "
                "VALUES (?, ?, ?, ?) "
                "ON CONFLICT(config_key) DO UPDATE SET "
                "  value_json=excluded.value_json, "
                "  set_at=excluded.set_at, set_by=excluded.set_by",
                (key, json.dumps(coerced, default=str), _time.time(), by),
            )
        # Audit unconditionally — separate try so a failed audit doesn't
        # roll back the write.
        try:
            db.config_change_log_append(
                domain=meta.domain,
                config_key=key,
                old_value=old_value,
                new_value=coerced,
                changed_by=by,
                reason=reason,
                request_id=request_id,
            )
        except Exception:
            log.debug("audit append failed for %s", key, exc_info=True)
        invalidate_cache(key)
        return (True, "ok")
    except Exception as exc:
        log.warning("set_config(%s) failed: %s", key, exc)
        return (False, f"db write failed: {exc}")


def clear_config(key: str, *, by: str,
                 reason: Optional[str] = None) -> tuple[bool, str]:
    """Drop the DB override so the key reverts to env / code default."""
    meta = _REGISTRY.get(key)
    if meta is None:
        return (False, f"unknown config key {key!r}")
    if meta.immutable or meta.bootstrap:
        return (False, f"key {key!r} is immutable")
    old_value = get_config(key)
    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute("CREATE TABLE IF NOT EXISTS config_runtime_value ("
                         "config_key TEXT PRIMARY KEY, value_json TEXT NOT NULL,"
                         "set_at REAL NOT NULL, set_by TEXT NOT NULL)")
            conn.execute(
                "DELETE FROM config_runtime_value WHERE config_key=?", (key,),
            )
        try:
            db.config_change_log_append(
                domain=meta.domain, config_key=key,
                old_value=old_value, new_value=None,
                changed_by=by, reason=reason or "cleared override",
            )
        except Exception:
            pass
        invalidate_cache(key)
        return (True, "ok")
    except Exception as exc:
        return (False, f"db delete failed: {exc}")


# ── Bootstrap registration ─────────────────────────────────────────────────


__all__ = [
    "ConfigKey",
    "register",
    "get_meta",
    "all_keys",
    "domains",
    "groups",
    "get_config",
    "set_config",
    "clear_config",
    "is_restart_pending",
    "get_value_source",
    "invalidate_cache",
    # WP-1.2 runtime read tracker
    "runtime_read_stats", "unregistered_read_stats",
    "unregistered_read_dropped", "read_tracker_started_at",
    "drain_read_stats", "restore_read_stats", "reset_read_stats",
    # Group constants
    "GROUP_OPERATE", "GROUP_TUNE", "GROUP_LLM_HEALTH",
    "GROUP_INFRASTRUCTURE", "GROUP_ACCESS", "GROUP_AUDIT", "ALL_GROUPS",
    # Timing labels
    "TIMING_LIVE_NEXT_TICK", "TIMING_LIVE_IMMEDIATE",
    "TIMING_LIVE_NEXT_CYCLE", "TIMING_RESTART_REQUIRED", "TIMING_READ_ONLY",
]
