"""Shadow-write health metrics — process-local counters for Mode B observability.

Mode B (`V2_CONCLUSION_LEDGER_ENABLED=true`, `V2_API_ENABLED=false`) writes
Conclusion rows to the ledger from inside `compute_scenario_score` and
swallows any exception so v1 scoring is never affected. Without explicit
counters the only signal of failure is `log.exception` lines in the
container log — easy to miss in 14 days of shadow observation.

This module provides a process-local registry that each `_maybe_persist_*`
hook updates after every attempt. The aggregated counts are surfaced via
the `/api/v2/admin/shadow_write_metrics` endpoint (admin-only) so the
operator can confirm at a glance:

  - shadow-write is firing on every scoring tick (success increments)
  - the failure rate stays at 0 (or is investigated quickly)
  - which conclusion type is degrading, with the last error class

Counters are intentionally in-process: gunicorn/gevent runs a single
worker for this app (radar_api.py uses gevent monkey-patch at module top
and Flask-SocketIO's worker model), so per-process counters are the
authoritative observation. A restart resets the counters; we record
`_started_at` so the operator can interpret rates.

Thread-safety: a single `threading.Lock` guards all reads/writes.
gevent's monkey-patched lock is cooperative, so this is safe under both
threading and gevent execution.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class _PerTypeMetrics:
    success_count: int = 0
    failure_count: int = 0
    last_success_at: Optional[float] = None
    last_failure_at: Optional[float] = None
    last_failure_kind: Optional[str] = None
    last_failure_message: Optional[str] = None


@dataclass
class _Registry:
    started_at: float = field(default_factory=time.time)
    by_type: Dict[str, _PerTypeMetrics] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


_REGISTRY = _Registry()


def record_success(conclusion_type: str, *, now: Optional[float] = None) -> None:
    """Bump the success counter for a builder. Called after a successful
    save_conclusion.
    """
    ts = time.time() if now is None else now
    with _REGISTRY.lock:
        m = _REGISTRY.by_type.setdefault(conclusion_type, _PerTypeMetrics())
        m.success_count += 1
        m.last_success_at = ts


def record_failure(
    conclusion_type: str,
    exc: BaseException,
    *,
    now: Optional[float] = None,
) -> None:
    """Bump the failure counter and remember the last error so the operator
    can see the degradation kind without grepping logs.
    """
    ts = time.time() if now is None else now
    with _REGISTRY.lock:
        m = _REGISTRY.by_type.setdefault(conclusion_type, _PerTypeMetrics())
        m.failure_count += 1
        m.last_failure_at = ts
        m.last_failure_kind = type(exc).__name__
        # Keep the message short so the admin endpoint stays compact.
        msg = str(exc)
        m.last_failure_message = msg if len(msg) <= 200 else msg[:197] + "..."


def snapshot() -> dict:
    """Return a JSON-serialisable summary of the current registry state.

    Shape (per type):
      {
        "success_count": int,
        "failure_count": int,
        "failure_rate": float | None,   # None if no attempts yet
        "last_success_at": float | None,
        "last_failure_at": float | None,
        "last_failure_kind": str | None,
        "last_failure_message": str | None,
      }
    """
    with _REGISTRY.lock:
        per_type = {}
        for ct, m in _REGISTRY.by_type.items():
            attempts = m.success_count + m.failure_count
            per_type[ct] = {
                "success_count": m.success_count,
                "failure_count": m.failure_count,
                "failure_rate": (m.failure_count / attempts) if attempts else None,
                "last_success_at": m.last_success_at,
                "last_failure_at": m.last_failure_at,
                "last_failure_kind": m.last_failure_kind,
                "last_failure_message": m.last_failure_message,
            }
        return {
            "started_at": _REGISTRY.started_at,
            "uptime_sec": max(0.0, time.time() - _REGISTRY.started_at),
            "by_type": per_type,
        }


def reset_for_tests() -> None:
    """Test-only helper: wipe the registry and reset the start time."""
    global _REGISTRY
    _REGISTRY = _Registry()
