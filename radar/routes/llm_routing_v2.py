"""LLM Routing override + preflight API endpoints (Phase 8 LLM survey v10).

Exposes the radar.llm_routing layer to the analyst UI so the v10 5-model
stack can be reconfigured without redeploying the image.

Routes
------
  GET  /api/v2/llm_routing                   effective routing snapshot
  GET  /api/v2/llm_routing/overrides         current DB overrides
  POST /api/v2/llm_routing/overrides         upsert one (use_case, slot) override
                                             body: {use_case, slot, model?,
                                                    temperature?, top_p?, top_k?,
                                                    seed?, num_predict?,
                                                    repeat_penalty?,
                                                    thinking_enabled?, reason?}
  DELETE /api/v2/llm_routing/overrides       clear one (use_case, slot)
                                             query: ?use_case=X&slot=primary
  GET  /api/v2/llm_routing/audit             recent override history
  GET  /api/v2/llm_preflight                 ollama reachability + model
                                             availability self-check

Auth model
----------
GET endpoints       → analyst (read-only)
POST/DELETE         → admin (model selection is a runtime configuration change)

NP6: every override change goes through radar.llm_routing.set_override /
clear_override which writes to llm_routing_override_history with the JWT
identity attached.
"""
from __future__ import annotations

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from radar import llm_routing as lr
from radar.conclusions.api import build_error
from radar.llm_routing import UseCase
from radar.routes import _require_admin, _require_analyst, _safe_int, bp
from radar.routes.conclusions_v2 import _v2_enabled_or_503


def _bad_request(error: str, **extra):
    body, status = build_error(400, error, **extra)
    return jsonify(body), status


def _identity() -> str:
    return get_jwt_identity() or "unknown"


@bp.route("/api/v2/llm_routing", methods=["GET"])
@jwt_required()
def v2_llm_routing_list():
    """Effective routing snapshot for every (use_case, slot)."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    return jsonify({
        "effective": lr.list_effective_routing(),
    })


@bp.route("/api/v2/llm_routing/overrides", methods=["GET"])
@jwt_required()
def v2_llm_routing_overrides_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    return jsonify({"overrides": lr.list_overrides()})


@bp.route("/api/v2/llm_routing/overrides", methods=["POST"])
@jwt_required()
def v2_llm_routing_overrides_set():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth

    body = request.get_json(silent=True) or {}
    raw_uc = (body.get("use_case") or "").strip()
    if not raw_uc:
        return _bad_request("use_case is required")
    try:
        uc = UseCase(raw_uc)
    except ValueError:
        return _bad_request(
            f"invalid use_case {raw_uc!r}",
            valid=[u.value for u in UseCase],
        )
    slot = (body.get("slot") or "primary").strip().lower()
    if slot not in ("primary", "secondary"):
        return _bad_request(f"invalid slot {slot!r}",
                            valid=["primary", "secondary"])

    # Pull only the keys the override layer accepts; anything else is ignored.
    payload: dict = {
        k: body.get(k)
        for k in (
            "model", "temperature", "top_p", "top_k", "seed",
            "num_predict", "repeat_penalty", "thinking_enabled",
        )
        if k in body
    }
    # Validate numeric ranges so the resolver doesn't have to defend itself.
    if payload.get("temperature") is not None and not (
        0 <= float(payload["temperature"]) <= 2
    ):
        return _bad_request("temperature must be in [0, 2]")
    if payload.get("top_p") is not None and not (
        0 <= float(payload["top_p"]) <= 1
    ):
        return _bad_request("top_p must be in [0, 1]")

    ok = lr.set_override(
        uc, slot,
        by=_identity(),
        reason=body.get("reason"),
        **payload,
    )
    if not ok:
        return _bad_request("override write failed (check server logs)")
    return jsonify({
        "ok": True,
        "use_case": uc.value, "slot": slot,
        "effective": lr.list_effective_routing(),
    })


@bp.route("/api/v2/llm_routing/overrides", methods=["DELETE"])
@jwt_required()
def v2_llm_routing_overrides_clear():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth
    raw_uc = (request.args.get("use_case") or "").strip()
    if not raw_uc:
        return _bad_request("use_case query param is required")
    try:
        uc = UseCase(raw_uc)
    except ValueError:
        return _bad_request(f"invalid use_case {raw_uc!r}")
    slot = (request.args.get("slot") or "primary").strip().lower()
    if slot not in ("primary", "secondary"):
        return _bad_request(f"invalid slot {slot!r}")
    ok = lr.clear_override(
        uc, slot,
        by=_identity(),
        reason=request.args.get("reason"),
    )
    if not ok:
        return _bad_request("clear failed")
    return jsonify({"ok": True, "use_case": uc.value, "slot": slot})


@bp.route("/api/v2/llm_routing/audit", methods=["GET"])
@jwt_required()
def v2_llm_routing_audit():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    hours = _safe_int(request.args.get("hours"), 720, min_val=1, max_val=8760)
    limit = _safe_int(request.args.get("limit"), 200, min_val=1, max_val=2000)
    return jsonify({
        "history": lr.list_override_history(hours=hours, limit=limit),
    })


# ── Preflight ─────────────────────────────────────────────────────────────


@bp.route("/api/v2/llm_preflight", methods=["GET"])
@jwt_required()
def v2_llm_preflight():
    """Self-diagnosis for the v10 5-model stack.

    Returns:
      ollama: { reachable, version, error }
      models: per (use_case, slot) effective model + availability
      embedding: granite-embedding probe
      go_no_go: boolean — true iff every PRIMARY model is locally available
                AND ollama version >= 0.22.0 (survey v10 prereq)
      missing: list of models the preflight would expect but didn't find
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    import requests
    from radar.config import GLOBAL_PROXIES, LLM_HOST, SSL_VERIFY

    out: dict = {
        "ollama": {"reachable": False, "version": None, "error": None},
        "models": [],
        "embedding": None,
        "go_no_go": False,
        "missing": [],
    }

    # 1. Ollama version probe (NP3 — never raises).
    try:
        v = requests.get(
            f"{LLM_HOST}/api/version",
            timeout=5, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
        )
        if v.status_code == 200:
            out["ollama"]["reachable"] = True
            out["ollama"]["version"] = v.json().get("version")
    except Exception as exc:
        out["ollama"]["error"] = str(exc)

    # 2. Model availability per (use_case, slot).
    try:
        snapshot = lr.list_effective_routing()
    except Exception as exc:
        snapshot = []
        out["snapshot_error"] = str(exc)

    out["models"] = snapshot
    missing = sorted({
        e["model"]
        for e in snapshot
        if e["slot"] == "primary" and not e.get("available")
    })
    out["missing"] = missing

    # 3. Embedding probe (out-of-band; the embedding module is optional).
    try:
        from radar.llm_embedding import embedding_preflight
        out["embedding"] = embedding_preflight()
    except Exception as exc:
        out["embedding"] = {"available": False, "error": str(exc)}

    # 4. Go / No-Go heuristic. Survey v10 §1 requires Ollama >= 0.22.0 and
    #    every PRIMARY model pulled. We deliberately do not require the
    #    SECONDARY models — they are graceful fallbacks, not blockers.
    version = out["ollama"]["version"] or ""
    version_ok = False
    try:
        parts = version.lstrip("v").split(".")
        version_ok = (
            int(parts[0]) > 0 or (
                int(parts[0]) == 0 and int(parts[1]) >= 22
            )
        )
    except Exception:
        pass
    out["go_no_go"] = bool(
        out["ollama"]["reachable"]
        and version_ok
        and not missing
    )
    out["version_ok"] = version_ok
    return jsonify(out)
