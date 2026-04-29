"""LLM Feature Hub API endpoints (commit H).

Exposes radar.llm_features registry to the analyst UI:

  GET  /api/v2/llm_features                list current state for every feature
  GET  /api/v2/llm_features/<key>          single feature + history
  POST /api/v2/llm_features/<key>/set      set state (on/off/shadow); body
                                           {state: str, reason?: str}
  POST /api/v2/llm_features/<key>/clear    clear UI override → revert to env
  POST /api/v2/llm_features/kill_switch    set the global kill switch
                                           {state: 'on' | 'off', reason?: str}
  GET  /api/v2/llm_features/audit          recent state-change history

Auth model:
  - GET endpoints  → analyst (anyone with read access can audit feature state)
  - POST endpoints → admin, EXCEPT non-NP7 narrative features which can be
                     toggled by analyst (per LLMFeature.requires_admin).

NP7: features marked np7_concern (g3b_cluster_annotator and any
future structure-suggesting feature) require admin role even for the
narrow display-tier toggle path; UI applies an extra confirm modal
when the state delta affects scenario structure.

NP6: every state change goes through llm_features.set_state() which
appends an audit row to llm_feature_state_history. Endpoints add the
authenticated identity to the audit trail.
"""
from __future__ import annotations

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from radar import llm_features as lf
from radar.conclusions.api import build_error
from radar.routes import _require_admin, _require_analyst, _safe_int, bp
from radar.routes.calibration_v2 import _wrap, _wrap_error
from radar.routes.conclusions_v2 import _v2_enabled_or_503


def _not_found(error: str, **extra):
    body, status = build_error(404, error, **extra)
    return jsonify(body), status


def _bad_request(error: str, **extra):
    body, status = build_error(400, error, **extra)
    return jsonify(body), status


def _resolve_caller_identity() -> str:
    """Build a 'admin:<name>' or 'analyst:<name>' marker from the JWT.

    Falls back to 'unknown' when identity is missing (NP3 — never
    blocks the audit write itself; identity may genuinely be absent
    in test mode)."""
    identity = get_jwt_identity() or "unknown"
    return identity


def _enforce_feature_admin(feat: lf.LLMFeature):
    """If the feature.requires_admin flag is True, gate the call behind
    admin role. Otherwise an analyst is sufficient. Returns None on
    success, a Flask response tuple otherwise."""
    if feat.requires_admin:
        return _require_admin()
    return _require_analyst()


# ── List + single ───────────────────────────────────────────────────────────


@bp.route("/api/v2/llm_features", methods=["GET"])
@jwt_required()
def v2_llm_features_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    items = lf.list_states()
    return jsonify(_wrap(items, count=len(items)))


@bp.route("/api/v2/llm_features/<key>", methods=["GET"])
@jwt_required()
def v2_llm_features_get(key: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    feat = lf.feature(key)
    if feat is None:
        return _not_found("unknown feature key", key=key)
    state = lf.resolve_state(key)
    history = lf.list_history(hours=720, limit=50)
    history = [h for h in history if h["feature_key"] == key]
    return jsonify(_wrap({
        **feat.to_dict(),
        "current_state": state.value,
        "history": history,
    }))


# ── State mutation ──────────────────────────────────────────────────────────


_VALID_INPUT_STATES = {"on", "off", "shadow"}


@bp.route("/api/v2/llm_features/<key>/set", methods=["POST"])
@jwt_required()
def v2_llm_features_set(key: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    feat = lf.feature(key)
    if feat is None:
        return _not_found("unknown feature key", key=key)
    auth = _enforce_feature_admin(feat)
    if auth is not None:
        return auth

    body = request.get_json(silent=True) or {}
    state = (body.get("state") or "").strip().lower()
    reason = (body.get("reason") or "").strip() or None

    if state not in _VALID_INPUT_STATES:
        return _bad_request(
            "invalid state",
            valid_states=sorted(_VALID_INPUT_STATES),
        )
    if state == "shadow" and not feat.supports_shadow:
        return _bad_request(
            "feature does not support shadow",
            key=key,
        )

    by = _resolve_caller_identity()
    role = "admin" if feat.requires_admin else "analyst"
    actor = f"{role}:{by}"
    ok = lf.set_state(key, lf.FeatureState(state), by=actor, reason=reason)
    if not ok:
        return _wrap_error(500, "set_state_failed", key=key, state=state)
    new_state = lf.resolve_state(key)
    return jsonify(_wrap({
        "key": key,
        "new_state": new_state.value,
        "by": actor,
        "reason": reason,
    }))


@bp.route("/api/v2/llm_features/<key>/clear", methods=["POST"])
@jwt_required()
def v2_llm_features_clear(key: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    feat = lf.feature(key)
    if feat is None:
        return _not_found("unknown feature key", key=key)
    auth = _enforce_feature_admin(feat)
    if auth is not None:
        return auth
    body = request.get_json(silent=True) or {}
    reason = (body.get("reason") or "").strip() or None
    by = _resolve_caller_identity()
    role = "admin" if feat.requires_admin else "analyst"
    actor = f"{role}:{by}"
    ok = lf.clear_override(key, by=actor, reason=reason)
    if not ok:
        return _wrap_error(500, "clear_override_failed", key=key)
    new_state = lf.resolve_state(key)
    return jsonify(_wrap({
        "key": key,
        "new_state": new_state.value,
        "by": actor,
    }))


# ── Kill switch ─────────────────────────────────────────────────────────────


@bp.route("/api/v2/llm_features/kill_switch", methods=["POST"])
@jwt_required()
def v2_llm_features_kill_switch():
    """Global kill switch — admin only. State must be 'on' (engage) or
    'off' (release).

    NP1: the kill switch drops every feature to OFF on the next
    is_enabled() call. Useful as an emergency stop without restarting
    Docker or editing config.env."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth
    body = request.get_json(silent=True) or {}
    state = (body.get("state") or "").strip().lower()
    reason = (body.get("reason") or "").strip() or None
    if state not in ("on", "off"):
        return _bad_request(
            "invalid kill_switch state",
            valid_states=["on", "off"],
        )
    by = _resolve_caller_identity()
    actor = f"admin:{by}"
    ok = lf.set_state(
        "__kill_switch__",
        lf.FeatureState(state),
        by=actor,
        reason=reason,
    )
    if not ok:
        return _wrap_error(500, "kill_switch_failed", state=state)
    return jsonify(_wrap({
        "kill_switch_state": state,
        "by": actor,
        "reason": reason,
    }))


# ── Audit ───────────────────────────────────────────────────────────────────


@bp.route("/api/v2/llm_features/audit", methods=["GET"])
@jwt_required()
def v2_llm_features_audit():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth
    hours = _safe_int(request.args.get("hours"), 720, min_val=1, max_val=2160)
    limit = _safe_int(request.args.get("limit"), 200, min_val=1, max_val=500)
    rows = lf.list_history(hours=hours, limit=limit)
    return jsonify(_wrap(rows, count=len(rows),
                         filters={"hours": hours, "limit": limit}))
