"""radar.routes.intel -- LLM Intelligence API endpoints."""
from __future__ import annotations
import os as _os
import time
import radar.routes as _routes
from flask import jsonify, request
from radar.auth import require_role

bp = _routes.bp


def _safe_float_env(name: str, default: float) -> float:
    """Read float env var; return default on missing or non-numeric value.

    Prevents a single misconfigured operator override from 500-ing endpoints
    polled by the HUD on every refresh.
    """
    try:
        raw = _os.getenv(name)
        return float(raw) if raw is not None else default
    except (ValueError, TypeError):
        return default


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
    # Filter out stale terminal-state items from UI display.
    # Rejected/overridden items older than the display TTL are noise.
    # Active/pending items use INTEL_ITEM_TTL (24h) from intel_queue.
    now = time.time()
    try:
        _terminal_hours = int(_os.getenv("INTEL_TERMINAL_DISPLAY_HOURS", "8"))
    except (ValueError, TypeError):
        _terminal_hours = 8
    _TERMINAL_DISPLAY_TTL = _terminal_hours * 3600
    filtered = []
    for it in items:
        age = now - it.get("created_at", it.get("ts", 0))
        if it["status"] in ("rejected", "overridden") and age > _TERMINAL_DISPLAY_TTL:
            continue
        filtered.append(it)
    return jsonify({
        "items": filtered,
        "stats": intel_queue.stats(),
        "ts":    time.time(),
    })


@bp.route("/api/intel/pending/triage")
def intel_pending_triage():
    """Return pending intel items ranked by triage priority.

    Each item is enriched with:
      - priority           : confidence × max_scenario_coupling × age_decay
      - gate_reason        : why the item is pending instead of auto_confirmed
      - source_credibility : current credibility weight of the source
      - ecosystem          : media ecosystem classification
      - corroboration_count: number of corroborating sources
      - top_scenario       : {id, name_en, name_ja, coupling} of best-matching scenario
      - matched_countries  : list of (country, scenario_id, weight) tuples

    Items are sorted by priority descending. The intent is to give analysts a
    single ranked queue so the most operationally significant pending items
    surface first.

    Query params:
        limit  : max items to return (default 50, max 200)
        min_pr : minimum priority threshold (default 0.0)
    """
    from radar.intel_queue import intel_queue, classify_ecosystem
    from radar.scenarios import scenario_store
    from radar.triage import enrich_pending

    try:
        limit = max(1, min(int(request.args.get("limit", "50")), 200))
    except (ValueError, TypeError):
        limit = 50
    try:
        min_priority = float(request.args.get("min_pr", "0"))
    except (ValueError, TypeError):
        min_priority = 0.0
    # Clamp negative or out-of-range thresholds — values outside [0,1] make
    # no sense for the priority formula.
    min_priority = max(0.0, min(min_priority, 1.0))

    pending = intel_queue.list_items(status="pending", limit=200)
    sources = {s["source_id"]: s for s in intel_queue.list_sources()}
    scenarios = scenario_store.scorable()

    now = time.time()
    enriched = enrich_pending(
        pending,
        sources,
        scenarios,
        now=now,
        auto_confirm_threshold=_safe_float_env("LLM_AUTO_CONFIRM_THRESHOLD", 0.80),
        classify_ecosystem=classify_ecosystem,
    )
    enriched = [e for e in enriched if e["priority"] >= min_priority]

    return jsonify({
        "items": enriched[:limit],
        "total_pending": len(pending),
        "shown": min(len(enriched), limit),
        "ts": now,
    })


@bp.route("/api/intel/stats")
def intel_stats():
    """Return LLM intel queue statistics and LLM status.

    Includes `triage_pulse`: a lightweight summary of how many pending items
    are high-priority AND aged past the analyst review SLA. The HUD uses this
    to drive a non-disruptive pulse indicator.
    """
    from radar.intel_queue import intel_queue
    from radar.llm_client import llm_available
    from radar.scenarios import scenario_store
    from radar.triage import compute_pulse

    stats = intel_queue.stats()
    stats["llm_online"] = llm_available()

    pulse_threshold = _safe_float_env("INTEL_PULSE_PRIORITY", 0.50)
    pulse_min_age_h = _safe_float_env("INTEL_PULSE_MIN_AGE_HOURS", 4.0)

    pending = intel_queue.list_items(status="pending", limit=200)
    scenarios = scenario_store.scorable() if scenario_store.loaded else []

    pulse = compute_pulse(
        pending,
        scenarios,
        now=time.time(),
        threshold=pulse_threshold,
        min_age_sec=pulse_min_age_h * 3600.0,
    )
    stats["triage_pulse"] = {
        **pulse,
        "threshold": pulse_threshold,
        "min_age_hours": pulse_min_age_h,
    }
    return jsonify(stats)


def _invalidate_scoring_cache():
    """Reset scoring cache timestamp so the next /api/threat_data re-scores."""
    import radar.state as _st
    from radar.state import _global_cache_lock
    with _global_cache_lock:
        _st.global_cache["time"] = 0


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
    _invalidate_scoring_cache()
    return jsonify({"ok": True, "item_id": item_id, "status": "confirmed"})


@bp.route("/api/intel/<item_id>/reject", methods=["POST"])
@require_role("admin", "analyst")
def intel_reject(item_id: str):
    """Reject a PENDING intel item.

    Optional JSON body: {"classification": "irrelevant"|"false_positive"}
    Default is "irrelevant" (no credibility penalty).
    """
    from radar.intel_queue import intel_queue
    from flask_jwt_extended import get_jwt_identity
    analyst = get_jwt_identity() or "analyst"
    classification = "irrelevant"
    if request.is_json and request.json:
        classification = request.json.get("classification", "irrelevant")
    if classification not in ("irrelevant", "false_positive"):
        classification = "irrelevant"
    ok = intel_queue.reject(item_id, analyst=analyst, classification=classification)
    if not ok:
        return jsonify({"error": "Item not found or not in pending state"}), 400
    _invalidate_scoring_cache()
    return jsonify({"ok": True, "item_id": item_id, "status": "rejected",
                    "classification": classification})


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
    _invalidate_scoring_cache()
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
    _invalidate_scoring_cache()
    return jsonify({"ok": True, "item_id": item_id, "status": "overridden"})


@bp.route("/api/intel/sources")
def intel_sources():
    """List LLM source credibility data."""
    from radar.intel_queue import intel_queue
    return jsonify({"sources": intel_queue.list_sources()})


@bp.route("/api/intel/llm_call_stats")
def intel_llm_call_stats():
    """Aggregate LLM call observability over the given window.

    Lets operators distinguish "sensor never called LLM" from "LLM down" from
    "all results dropped below confidence threshold" from "all parses failed".

    Query params:
        hours  : aggregation window (default 24, max 168)
        recent : if "1", also include the 50 most recent rows
    """
    from radar.database import db
    try:
        hours = min(int(request.args.get("hours", "24")), 168)
    except (ValueError, TypeError):
        hours = 24
    payload = db.llm_call_stats(hours=hours)
    if request.args.get("recent") == "1":
        payload["recent"] = db.llm_call_recent(limit=50)
    return jsonify(payload)


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
    import logging as _logging
    import requests as _req
    import ipaddress as _ipaddr
    import socket as _socket
    import urllib.parse as _urlparse
    from radar.config import LLM_HOST
    host = request.args.get("host", LLM_HOST).rstrip("/")
    # SSRF guard: reject private/link-local/loopback IPs (except configured LLM_HOST)
    if host != LLM_HOST.rstrip("/"):
        try:
            parsed = _urlparse.urlparse(host)
            hostname = parsed.hostname or ""
            if parsed.scheme not in ("http", "https"):
                return jsonify({"ok": False, "models": [], "error": "Only http/https allowed"}), 400
            # Resolve hostname to IP(s) to catch DNS rebinding (e.g. domain→127.0.0.1)
            def _is_blocked(addr):
                return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or not addr.is_global
            try:
                addr = _ipaddr.ip_address(hostname)
                addrs = [addr]
            except ValueError:
                # Not a raw IP — resolve via DNS; check ALL results
                try:
                    resolved = _socket.getaddrinfo(hostname, None, _socket.AF_UNSPEC, _socket.SOCK_STREAM)
                    addrs = []
                    for r in resolved:
                        try:
                            addrs.append(_ipaddr.ip_address(r[4][0]))
                        except (ValueError, IndexError):
                            pass
                    if not addrs:
                        raise OSError("no addresses")
                except (OSError, IndexError, ValueError):
                    return jsonify({"ok": False, "models": [], "error": "Cannot resolve hostname"}), 400
            if any(_is_blocked(a) for a in addrs):
                return jsonify({"ok": False, "models": [], "error": "Private/internal addresses not allowed"}), 400
        except Exception:
            return jsonify({"ok": False, "models": [], "error": "Invalid host URL"}), 400
    try:
        resp = _req.get(f"{host}/api/tags", timeout=5)
        if not resp.ok:
            return jsonify({"ok": False, "models": [], "error": f"HTTP {resp.status_code}"}), 200
        data = resp.json()
        # Ollama returns {"models": [{"name": "llama3.2:3b", ...}, ...]}
        models = [m["name"] for m in data.get("models", []) if m.get("name")]
        return jsonify({"ok": True, "models": sorted(models)})
    except Exception as e:
        _logging.getLogger(__name__).warning("LLM host probe failed: %s", e)
        return jsonify({"ok": False, "models": [], "error": "Failed to connect to LLM host"}), 200
