"""Layered configuration — Phases 9.1 / R1-R6.

Single entry point for every config read in the codebase. Resolves a key
through a 3-layer chain:

    1. **DB override** (mutable keys only, recently-cached)
    2. **Env var**     (populated from config.env at startup)
    3. **Code default** (registered metadata)

Every key is registered once with rich metadata (type, default,
secret/immutable/restart/bootstrap flags, validator, group, impact_level,
apply timing label). The Settings UI is rendered from the registry; CI
gates assert no `os.getenv` for registered keys outside this module.

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
    description: str = ""
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


def _resolve_uncached(key: str) -> Any:
    meta = _REGISTRY.get(key)
    if meta is None:
        return _read_env(key)

    # Bootstrap & immutable keys skip the DB layer.
    if not meta.immutable and not meta.bootstrap:
        db_v = _coerce(_read_db(key), meta.type_)
        if db_v is not None:
            return db_v

    env_v = _coerce(_read_env(key), meta.type_)
    if env_v is not None:
        return env_v

    return meta.default


def get_config(key: str) -> Any:
    """Resolve a key through the 3-layer chain. NP3 — never raises.

    Caches results for 30s. Cache is invalidated on every set_config /
    clear_config / register, so analyst writes propagate immediately.
    """
    hit, cached = _cache_get(key)
    if hit:
        return cached
    value = _resolve_uncached(key)
    _cache_put(key, value)
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
    # Group constants
    "GROUP_OPERATE", "GROUP_TUNE", "GROUP_LLM_HEALTH",
    "GROUP_INFRASTRUCTURE", "GROUP_ACCESS", "GROUP_AUDIT", "ALL_GROUPS",
    # Timing labels
    "TIMING_LIVE_NEXT_TICK", "TIMING_LIVE_IMMEDIATE",
    "TIMING_LIVE_NEXT_CYCLE", "TIMING_RESTART_REQUIRED", "TIMING_READ_ONLY",
]
