"""radar.routes.intel -- LLM Intelligence API endpoints."""
from __future__ import annotations
import time
import radar.routes as _routes
from flask import jsonify, request
from radar.auth import require_role

bp = _routes.bp


@bp.route("/api/intel")
def intel_list():
    """List LLM intel items with optional filters.

    Query params:
        source_type : hacktivist | diplomatic | military | ground_osint
        status      : pending | auto_confirmed | confirmed | rejected | overridden | review_needed
        theater     : e.g. CN-TW
        limit       : max items to return (default 100, max 200)
    """
    from radar.intel_queue import intel_queue
    source_type = request.args.get("source_type", "")
    status      = request.args.get("status", "")
    theater     = request.args.get("theater", "")
    try:
        limit = min(int(request.args.get("limit", "100")), 200)
    except (ValueError, TypeError):
        limit = 100
    items = intel_queue.list_items(
        source_type=source_type or None,
        status=status or None,
        theater=theater or None,
        limit=limit,
    )
    return jsonify({
        "items": items,
        "stats": intel_queue.stats(),
        "ts":    time.time(),
    })


@bp.route("/api/intel/stats")
def intel_stats():
    """Return LLM intel queue statistics and LLM status."""
    from radar.intel_queue import intel_queue
    from radar.llm_client import llm_available
    stats = intel_queue.stats()
    stats["llm_online"] = llm_available()
    return jsonify(stats)


@bp.route("/api/intel/<item_id>/confirm", methods=["POST"])
@require_role("admin", "analyst")
def intel_confirm(item_id: str):
    """Manually confirm a PENDING intel item."""
    from radar.intel_queue import intel_queue
    from flask_jwt_extended import get_jwt_identity
    analyst = get_jwt_identity() or "analyst"
    ok = intel_queue.confirm(item_id, analyst=analyst)
    if not ok:
        return jsonify({"error": "Item not found or not in pending state"}), 400
    return jsonify({"ok": True, "item_id": item_id, "status": "confirmed"})


@bp.route("/api/intel/<item_id>/reject", methods=["POST"])
@require_role("admin", "analyst")
def intel_reject(item_id: str):
    """Reject a PENDING intel item."""
    from radar.intel_queue import intel_queue
    from flask_jwt_extended import get_jwt_identity
    analyst = get_jwt_identity() or "analyst"
    ok = intel_queue.reject(item_id, analyst=analyst)
    if not ok:
        return jsonify({"error": "Item not found or not in pending state"}), 400
    return jsonify({"ok": True, "item_id": item_id, "status": "rejected"})


@bp.route("/api/intel/<item_id>/revert", methods=["POST"])
@require_role("admin", "analyst")
def intel_revert(item_id: str):
    """Revert a confirmed or rejected item back to pending for re-review."""
    from radar.intel_queue import intel_queue
    from flask_jwt_extended import get_jwt_identity
    analyst = get_jwt_identity() or "analyst"
    ok = intel_queue.revert(item_id, analyst=analyst)
    if not ok:
        return jsonify({"error": "Item not found or not in confirmed/rejected state"}), 400
    return jsonify({"ok": True, "item_id": item_id, "status": "pending"})


@bp.route("/api/intel/<item_id>/override", methods=["POST"])
@require_role("admin", "analyst")
def intel_override(item_id: str):
    """Override an AUTO-CONFIRMED item within the override window."""
    from radar.intel_queue import intel_queue
    from flask_jwt_extended import get_jwt_identity
    analyst = get_jwt_identity() or "analyst"
    ok = intel_queue.override(item_id, analyst=analyst)
    if not ok:
        return jsonify({"error": "Item not found, not auto_confirmed, or override window expired"}), 400
    return jsonify({"ok": True, "item_id": item_id, "status": "overridden"})


@bp.route("/api/intel/sources")
def intel_sources():
    """List LLM source credibility data."""
    from radar.intel_queue import intel_queue
    return jsonify({"sources": intel_queue.list_sources()})


@bp.route("/api/llm_models")
def llm_models():
    """Proxy: fetch available models from Ollama at the given host.

    Query params:
        host : Ollama base URL (default: from LLM_HOST config)
    """
    from radar.routes import _require_admin
    auth_err = _require_admin()
    if auth_err:
        return auth_err
    import requests as _req
    from radar.config import LLM_HOST
    host = request.args.get("host", LLM_HOST).rstrip("/")
    try:
        resp = _req.get(f"{host}/api/tags", timeout=5)
        if not resp.ok:
            return jsonify({"ok": False, "models": [], "error": f"HTTP {resp.status_code}"}), 200
        data = resp.json()
        # Ollama returns {"models": [{"name": "llama3.2:3b", ...}, ...]}
        models = [m["name"] for m in data.get("models", []) if m.get("name")]
        return jsonify({"ok": True, "models": sorted(models)})
    except Exception as e:
        return jsonify({"ok": False, "models": [], "error": str(e)}), 200
