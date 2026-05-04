"""Layered configuration — Phase 9.1 (Foundation).

Replaces the flat ``radar/config.py`` import-time mutation pattern with a
3-layer lookup chain that resolves a config key to its effective value:

    1. **DB override** (if mutable & present)  — set by analyst at runtime
    2. **Env var**                              — populated from config.env
       at startup, immutable at runtime
    3. **Code default**                         — declared in this registry

A key is registered once with metadata: type, default, restart-required
flag, secret flag, scope domain (``llm.connection``, ``intel.queue`` …),
and an optional validator.

Why a layer pattern matters
---------------------------
- ``restart`` badges across the SYSTEM tab today exist because there's no
  layer that survives a process restart without re-reading env. With this
  module, mutating an env-only key at runtime simply isn't possible (the
  setter rejects it), and the UI can render that as a read-only field
  with an "edit in config.env" hint.
- Mutable keys ALL flow through ``set_config()`` which audits every change
  via ``db.config_change_log_append()``. This is the structural fix to
  the NP6 violation noted in Phase 9 design.

Design constraints
------------------
- Backward-compatible: ``radar/config.py`` becomes a thin shim (Phase 9.1
  C3) that re-exports module-level constants populated from this layer.
  Existing ``from radar.config import LLM_TIMEOUT`` keeps working.
- NP3: every read path is fault-tolerant. DB lookup failure → falls
  through to env+default. DB lookup result that's None / unparseable →
  same fallback. Never raises on the hot path.
- Secret values (JWT_SECRET_KEY, API tokens) are **NEVER** writable from
  the DB layer — secrets are env-only with ``immutable=True``.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

log = logging.getLogger("radar.config_layered")


# ── Type registry ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ConfigKey:
    """Declarative description of one config key."""
    key: str
    domain: str
    default: Any
    type_: str            # 'str' | 'int' | 'float' | 'bool' | 'list[str]' | 'json'
    description: str = ""
    secret: bool = False           # never expose value in API surface
    immutable: bool = False        # env-only; DB writes rejected
    restart_required: bool = False # mutating requires container restart
    validator: Optional[Callable[[Any], bool]] = None
    enum: tuple = field(default_factory=tuple)  # allowed values for str types


_REGISTRY: dict[str, ConfigKey] = {}


def register(*keys: ConfigKey) -> None:
    """Register one or more keys. Idempotent — re-registering the same key
    overwrites (so config.py shim can register at import without crashing
    on hot reload)."""
    for k in keys:
        _REGISTRY[k.key] = k


def get_meta(key: str) -> Optional[ConfigKey]:
    return _REGISTRY.get(key)


def all_keys() -> list[ConfigKey]:
    return sorted(_REGISTRY.values(), key=lambda k: (k.domain, k.key))


def domains() -> list[str]:
    return sorted({k.domain for k in _REGISTRY.values()})


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


# ── Read path ──────────────────────────────────────────────────────────────


def _read_db(key: str) -> Any:
    """Read the persisted DB override for a key, or None if missing / DB
    unavailable. NP3."""
    try:
        from radar.database import db
        row = db._get_conn().execute(  # noqa: SLF001 — established pattern
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


def get_config(key: str) -> Any:
    """Resolve a key through the 3-layer chain. Returns the typed value or
    the registered default. NP3 — never raises."""
    meta = _REGISTRY.get(key)
    if meta is None:
        # Unknown key — fall back to env-only behavior so callers that
        # haven't migrated to layered config keep working.
        return _read_env(key)

    if not meta.immutable:
        db_v = _coerce(_read_db(key), meta.type_)
        if db_v is not None:
            return db_v

    env_v = _coerce(_read_env(key), meta.type_)
    if env_v is not None:
        return env_v

    return meta.default


def is_restart_pending(key: str) -> bool:
    """True iff a key declared ``restart_required=True`` has a DB override
    that differs from the running env value. The Settings UI badges these
    keys with "restart pending" so analysts know a redeploy is needed
    even though the value was successfully written."""
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


# ── Write path ──────────────────────────────────────────────────────────────


def set_config(key: str, value: Any, *,
               by: str, reason: Optional[str] = None,
               request_id: Optional[str] = None) -> tuple[bool, str]:
    """Persist a runtime override + write the audit row.

    Returns ``(ok, message)``. NP3 — never raises; messages explain validation
    failures so the API surface can return them as 400s.

    Rejected if:
      - key is not registered
      - key is marked secret (UI must never write secrets)
      - key is marked immutable (env-only)
      - value fails coercion for the declared type
      - value fails the optional validator
      - value is not in the enum (when one is declared)
    """
    meta = _REGISTRY.get(key)
    if meta is None:
        return (False, f"unknown config key {key!r}")
    if meta.secret:
        return (False, f"key {key!r} is secret — refuse to write via UI")
    if meta.immutable:
        return (False, f"key {key!r} is immutable — edit config.env + restart")
    coerced = _coerce(value, meta.type_)
    if coerced is None and value is not None:
        return (False, f"value {value!r} not coercible to {meta.type_}")
    if meta.enum and coerced not in meta.enum:
        return (False, f"value {coerced!r} not in allowed {meta.enum}")
    if meta.validator and not meta.validator(coerced):
        return (False, f"value {coerced!r} failed validator")

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
        # roll back the write (NP3 priority order: write > audit > read).
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
    if meta.immutable:
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
        return (True, "ok")
    except Exception as exc:
        return (False, f"db delete failed: {exc}")


# ── Bootstrap registration ─────────────────────────────────────────────────
#
# The full registry is populated at config.py import time (Phase 9.1 C3) so
# circular-import concerns are localized. This module ships an EMPTY
# registry by default; the shim layer is responsible for declaring keys.
#
# Public API:
#   register(*keys)
#   get_meta(key) / all_keys() / domains()
#   get_config(key)
#   set_config(key, value, by=..., reason=..., request_id=...)
#   clear_config(key, by=..., reason=...)
#   is_restart_pending(key)


__all__ = [
    "ConfigKey",
    "register",
    "get_meta",
    "all_keys",
    "domains",
    "get_config",
    "set_config",
    "clear_config",
    "is_restart_pending",
]
