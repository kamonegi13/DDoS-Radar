"""radar.routes.climate -- Strategic Climate Feed API endpoints."""
from __future__ import annotations
import radar.routes as _routes
from flask import jsonify, request
from radar.routes import _safe_int

bp = _routes.bp


@bp.route("/api/climate")
def climate_summary():
    """Full climate state: gauge + feed + calendar context."""
    from radar.climate_state import climate_engine
    return jsonify(climate_engine.get_summary())


@bp.route("/api/climate/feed")
def climate_feed():
    """Filtered climate feed events."""
    from radar.climate_state import climate_engine
    axis = request.args.get("axis", "")
    limit = _safe_int(request.args.get("limit", "50"), 50, min_val=1, max_val=200)
    return jsonify({"feed": climate_engine.get_feed(axis=axis, limit=limit)})
