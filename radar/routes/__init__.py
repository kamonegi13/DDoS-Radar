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


def _require_admin():
    """Check admin authorization via JWT role. Returns None if authorized, or a Flask response tuple on failure."""
    from flask_jwt_extended import get_jwt
    try:
        claims = get_jwt()
        if claims.get("role") == "admin":
            return None
        return jsonify({"error": "Admin privileges required"}), 403
    except Exception:
        return jsonify({"error": "Authentication required"}), 401


# ── Register all sub-module routes on the shared Blueprint ──────────────────
from radar.routes import static, core, admin, analytics, history, climate, situation  # noqa: E402,F401
