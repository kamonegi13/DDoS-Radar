"""Audit middleware — Phase 9.6 C20.

Decorator-based capture of mutation events on legacy endpoints that
cannot easily be migrated to ``radar/config_layered.py`` in this PR
window (sensor mute / unmute, scenario weight edits, sysconfig 'live'
field edits, threat scoring threshold changes).

Each decorated route writes to ``config_change_log`` after the response
is generated, capturing:

  domain        e.g. 'sensor.mute', 'scenario.weight', 'sysconfig.live'
  config_key    primary key of what was changed (sensor name, scenario
                id, env key)
  old_value     resolved BEFORE the call (best-effort)
  new_value     captured from the request body or response
  changed_by    JWT identity (falls back to 'unknown')
  reason        request body 'reason' field if present
  request_id    request UUID if attached upstream

NP3: middleware errors NEVER block the primary response. The decorator
runs after the response is built; any audit failure is logged and
swallowed.

Usage::

    from radar.audit_middleware import audit

    @bp.route('/api/sensor_config', methods=['POST'])
    @audit(domain='sensor.config',
           key_fn=lambda body, resp: (body or {}).get('name'))
    def sensor_config():
        ...

The ``key_fn`` receives the parsed request body + the JSON response
dict (or None if the response wasn't JSON). Most legacy endpoints
have a single primary identifier in either, so this is enough.
"""
from __future__ import annotations

import functools
import logging
from typing import Callable, Optional

from flask import g, request

log = logging.getLogger("radar.audit_middleware")


def _identity() -> str:
    """Best-effort JWT identity for the audit row. Falls back to
    'unknown' when called outside a JWT context (background workers,
    test harness, etc.)."""
    try:
        from flask_jwt_extended import get_jwt_identity
        return get_jwt_identity() or "unknown"
    except Exception:
        return "unknown"


def _safe_json_body() -> dict:
    """Read the JSON body without raising on missing/malformed."""
    try:
        body = request.get_json(silent=True)
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


def _safe_json_response(resp) -> Optional[dict]:
    """Best-effort JSON parse of a Flask response."""
    try:
        if hasattr(resp, "get_json"):
            return resp.get_json(silent=True)
    except Exception:
        return None
    return None


def audit(*, domain: str,
          key_fn: Optional[Callable] = None,
          old_value_fn: Optional[Callable] = None,
          new_value_fn: Optional[Callable] = None):
    """Decorator factory. Wraps a Flask route to append a row to
    ``config_change_log`` after the route completes successfully.

    domain        required, dotted-path string
    key_fn        (body, resp) -> str; defaults to using request endpoint
    old_value_fn  () -> any; called BEFORE the route runs
    new_value_fn  (body, resp) -> any; defaults to body
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Capture body BEFORE running the route; Flask consumes the
            # request stream during the route, so reading get_json()
            # after may return None.
            body = _safe_json_body()
            old_v = None
            if callable(old_value_fn):
                try:
                    old_v = old_value_fn()
                except Exception:
                    old_v = None
            response = fn(*args, **kwargs)
            try:
                # Only audit successful mutations (2xx).
                if isinstance(response, tuple):
                    resp_obj = response[0] if len(response) > 0 else None
                    status = response[1] if len(response) > 1 else 200
                else:
                    resp_obj = response
                    status = getattr(response, "status_code", 200)
                try:
                    status_int = int(status)
                except (TypeError, ValueError):
                    status_int = 200
                if 200 <= status_int < 300:
                    resp_json = None
                    try:
                        if resp_obj is not None and hasattr(resp_obj, "get_json"):
                            resp_json = resp_obj.get_json(silent=True)
                    except Exception:
                        resp_json = None
                    config_key = (
                        key_fn(body, resp_json)
                        if callable(key_fn) else request.endpoint or "unknown"
                    )
                    new_v = (
                        new_value_fn(body, resp_json)
                        if callable(new_value_fn) else body
                    )
                    reason = (body or {}).get("reason") or None
                    request_id = getattr(g, "request_id", None)
                    from radar.database import db
                    db.config_change_log_append(
                        domain=domain,
                        config_key=str(config_key)[:128] if config_key else "?",
                        old_value=old_v,
                        new_value=new_v,
                        changed_by=_identity(),
                        reason=reason,
                        request_id=request_id,
                    )
            except Exception:
                log.debug("audit middleware suppressed error", exc_info=True)
            return response
        return wrapper
    return decorator


__all__ = ["audit"]
