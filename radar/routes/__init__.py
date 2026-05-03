"""radar.routes -- Flask API route handlers (split into sub-modules).

Sub-modules:
  static     – Static file serving (index.html + whitelisted assets)
  core       – /api/app_config, /api/threat_data (main scoring loop)
  admin      – Admin-only endpoints (env_config, sensor_config, persist_save, etc.)
  analytics  – Read-only analytics & report endpoints
  history    – /api/history/* historical analysis endpoints
"""
from __future__ import annotations
import os
import logging
from flask import Blueprint, jsonify
from radar.engine import SensorRegistry, WeightedConvergenceEngine

log = logging.getLogger("radar")

# Project root is two levels up from this file's directory (radar/routes/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

bp = Blueprint('api', __name__)

# These will be set by radar.__init__ after app creation
registry: SensorRegistry = None  # type: ignore
engine: WeightedConvergenceEngine = None  # type: ignore


def init_routes(reg: SensorRegistry, eng: WeightedConvergenceEngine):
    """Called by radar.__init__ to inject singleton instances."""
    global registry, engine
    registry = reg
    engine = eng


def _safe_int(val, default: int, *, min_val: int = 0, max_val: int = 99999) -> int:
    """Safely convert a query parameter to a bounded int."""
    try:
        return max(min_val, min(int(val), max_val))
    except (ValueError, TypeError):
        return default


def _country_param(endpoint_label: str, default: str = "") -> str:
    """Read `?country=` (preferred) or fall back to legacy `?theater=`.

    ADR-V2-006 Safe Rename Pattern A-3: dual-read with SR4 telemetry.
    Records `<endpoint>?theater=` access whenever the legacy alias is used so
    the 90-day sunset PR (A-5) can confirm zero callers depend on it.
    """
    from flask import request
    val = request.args.get("country", "")
    if val:
        return val
    legacy = request.args.get("theater", "")
    if legacy:
        try:
            from radar import legacy_telemetry as _lt
            _lt.record_legacy_access(f"{endpoint_label}?theater=")
        except Exception:
            pass  # Telemetry must never break the request path
        return legacy
    return default


def _require_admin():
    """Check admin authorization via DB role lookup. Returns None if authorized, or a Flask response tuple on failure."""
    from flask_jwt_extended import get_jwt_identity
    from radar.database import db
    try:
        identity = get_jwt_identity()
        if not identity:
            return jsonify({"error": "Authentication required"}), 401
        role = db.user_get_role(identity)
        if role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return None
    except Exception:
        return jsonify({"error": "Authentication required"}), 401


def _require_analyst():
    """Check analyst-or-admin authorization via DB role lookup.

    Used by Tier 1 calibration / shadow-eval / health endpoints which
    should be visible to analysts but not to read-only viewers.
    Returns None if authorized, or a Flask response tuple on failure.
    """
    from flask_jwt_extended import get_jwt_identity
    from radar.database import db
    try:
        identity = get_jwt_identity()
        if not identity:
            return jsonify({"error": "Authentication required"}), 401
        role = db.user_get_role(identity)
        if role not in ("admin", "analyst"):
            return jsonify({"error": "Analyst access required"}), 403
        return None
    except Exception:
        return jsonify({"error": "Authentication required"}), 401


# ── Register all sub-module routes on the shared Blueprint ──────────────────
from radar.routes import static, core, admin, analytics, history, climate, intel, analyst  # noqa: E402,F401
from radar.routes import conclusions_v2  # noqa: E402,F401  -- v2 API skeleton (gated by V2_API_ENABLED)
from radar.routes import sensors_v2  # noqa: E402,F401  -- v2 sensor watchpane backend (gated by V2_API_ENABLED)
from radar.routes import calibration_v2  # noqa: E402,F401  -- v2 auto-tune API surface (Tier 1, gated by V2_API_ENABLED)
from radar.routes import llm_features_v2  # noqa: E402,F401  -- v2 LLM Feature Hub control plane (commit H, gated by V2_API_ENABLED)
from radar.routes import llm_routing_v2   # noqa: E402,F401  -- Phase 8 LLM survey v10 routing override + preflight (gated by V2_API_ENABLED)
from radar.routes import triage_narrative  # noqa: E402,F401  -- v2 triage natural-language narrative endpoint (commit K, gated by V2_API_ENABLED)
from radar.routes import attention_v2  # noqa: E402,F401  -- v2 ATTENTION rules + adaptive learning API (commits M+O)
from radar.routes import decisions as _decisions_routes  # noqa: E402,F401  -- v2 Decision Layer (Phase 1, 2026-04-30)
