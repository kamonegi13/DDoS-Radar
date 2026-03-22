"""radar.routes.situation -- Situation Board API endpoints."""
from __future__ import annotations
import radar.routes as _routes
from flask import jsonify, request

bp = _routes.bp


@bp.route("/api/situation")
def situation_board():
    """Per-theater situation summaries with direction vectors and wire."""
    from radar.situation_state import situation_engine
    theater = request.args.get("theater", "")
    return jsonify(situation_engine.get_board(theater_filter=theater))


@bp.route("/api/situation/wire")
def situation_wire():
    """Factual wire items, optionally filtered by theater."""
    from radar.situation_state import situation_engine
    theater = request.args.get("theater", "")
    limit = min(int(request.args.get("limit", "50")), 200)
    return jsonify({"wire": situation_engine.get_wire(theater=theater, limit=limit)})
