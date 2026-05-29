"""Decision Layer API — analyst response surface.

Endpoint families:
  /api/v2/decisions/triage/*           — TRIAGE Lane operations
  /api/v2/decisions/threshold/*        — TRIAGE per-user thresholds
  /api/v2/decisions/history            — Decision History timeline (AP4)

(The tl_recalibration/* and dual_weight/* governance endpoints were retired
2026-05-29 — they served the §10.5 v1→v2 migration gates, which elapsed
unactioned; TL calibration is now autonomous via the tier governor.)

All POST endpoints record into the unified `decisions` ledger, then
optionally apply side effects (deadline extension, threshold update).
NP6: actor + reason + parameters travel through to the audit trail.

NP1: snooze and dismiss decisions DO NOT silence critical events. The
client-side display layer combines is_active(snooze) with the
critical-event check to decide actual suppression — see
_refreshTriageDisplayMode in radar.js.

NP7: destructive actions (rollback, raise) require a `reason` field
and an `np7_confirmed: true` flag in the body. The endpoint returns
400 if these are missing, so the UI must show the confirm modal
before submitting.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from radar.routes import bp, _require_admin, _require_analyst

log = logging.getLogger("radar.routes.decisions")


# ── auth helpers ────────────────────────────────────────────────────────

def _v2_enabled_or_503():
    from radar import config
    if not getattr(config, "V2_API_ENABLED", True):
        return jsonify({"error": "v2 API disabled (V2_API_ENABLED=false)"}), 503
    return None


def _actor_string() -> str:
    """Return 'admin:<name>' or 'analyst:<name>' for ledger actor."""
    from radar.database import db
    identity = get_jwt_identity() or "unknown"
    try:
        role = db.user_get_role(identity) or "analyst"
    except Exception:
        role = "analyst"
    return f"{role}:{identity}"


def _require_np7_confirm(body: dict, *, action_name: str):
    """Returns None if confirmed, or (response, status) tuple if blocked.
    Used for recall-reducing actions: rollback, raise."""
    if not body.get("np7_confirmed") is True:
        return jsonify({
            "error": "np7_confirmation_required",
            "action": action_name,
            "message": "This action is recall-reducing or destructive. "
                       "Set np7_confirmed=true and provide reason to proceed.",
        }), 400
    if not body.get("reason"):
        return jsonify({
            "error": "reason_required",
            "action": action_name,
            "message": "Recall-reducing actions require a non-empty reason.",
        }), 400
    return None


# ── TRIAGE operations ──────────────────────────────────────────────────

@bp.route("/api/v2/decisions/triage/snooze", methods=["POST"])
@jwt_required()
def triage_snooze():
    """Mute the TRIAGE Lane for N minutes (1..1440). Critical events
    bypass the mute (NP1). Replaces any prior active snooze."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    body = request.get_json(silent=True) or {}
    try:
        minutes = int(body.get("minutes", 30))
    except (ValueError, TypeError):
        minutes = 30
    minutes = max(1, min(minutes, 24 * 60))  # cap at 24h per spec
    until = time.time() + minutes * 60

    from radar.database import db
    decision_id = db.decisions.record(
        decision_type="triage_snooze",
        target_kind="global",
        target_id=None,
        action="snooze",
        actor=_actor_string(),
        reason=body.get("reason"),
        parameters={"minutes": minutes},
        expires_at=until,
    )
    return jsonify({
        "decision_id": decision_id,
        "minutes": minutes,
        "expires_at": until,
    })


@bp.route("/api/v2/decisions/triage/snooze", methods=["DELETE"])
@jwt_required()
def triage_snooze_release():
    """Cancel the active snooze (if any)."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    from radar.database import db
    cur = db.decisions.latest(
        decision_type="triage_snooze", target_kind="global", target_id=None,
    )
    if cur is None:
        return jsonify({"released": False, "reason": "no active snooze"})
    db.decisions.revoke(cur["id"], by=_actor_string(), reason="manual release")
    return jsonify({"released": True, "decision_id": cur["id"]})


@bp.route("/api/v2/decisions/triage/visibility", methods=["POST"])
@jwt_required()
def triage_visibility():
    """Toggle always-visible mode (suppress dormant). Body: {mode: 'default' | 'always'}."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    body = request.get_json(silent=True) or {}
    mode = body.get("mode", "default")
    if mode not in ("default", "always"):
        return jsonify({"error": "mode must be 'default' or 'always'"}), 400

    from radar.database import db
    decision_id = db.decisions.record(
        decision_type="triage_visibility",
        target_kind="user",
        target_id=get_jwt_identity() or "unknown",
        action="set",
        actor=_actor_string(),
        reason=body.get("reason"),
        parameters={"mode": mode},
        expires_at=None,  # persists until next set
    )
    return jsonify({"decision_id": decision_id, "mode": mode})


@bp.route("/api/v2/decisions/triage/dismiss", methods=["POST"])
@jwt_required()
def triage_dismiss():
    """Hide TRIAGE until the next new-fire event. Body: {fingerprint?: str}.
    Stored with a short TTL (24h) — if no new fire happens by then, the
    dismiss expires and TRIAGE re-appears anyway."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    body = request.get_json(silent=True) or {}
    fingerprint = body.get("fingerprint", "")  # opaque id of current top item
    until = time.time() + 24 * 3600

    from radar.database import db
    decision_id = db.decisions.record(
        decision_type="triage_dismiss",
        target_kind="global",
        target_id=None,
        action="dismiss",
        actor=_actor_string(),
        reason=body.get("reason"),
        parameters={"fingerprint": fingerprint},
        expires_at=until,
    )
    return jsonify({
        "decision_id": decision_id,
        "fingerprint": fingerprint,
        "expires_at": until,
    })


@bp.route("/api/v2/decisions/triage/state", methods=["GET"])
@jwt_required()
def triage_state():
    """Current TRIAGE-related decision state for the requesting user.

    Returns:
      {
        snooze: {active, expires_at, minutes} | null,
        visibility: 'default' | 'always',
        dismiss: {active, expires_at, fingerprint} | null,
      }
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    from radar.database import db
    user_id = get_jwt_identity() or "unknown"

    snooze = db.decisions.latest(
        decision_type="triage_snooze", target_kind="global", target_id=None,
    )
    snooze_active = (snooze is not None
                     and snooze.get("expires_at") is not None
                     and snooze["expires_at"] > time.time())
    vis = db.decisions.latest(
        decision_type="triage_visibility", target_kind="user", target_id=user_id,
    )
    dismiss = db.decisions.latest(
        decision_type="triage_dismiss", target_kind="global", target_id=None,
    )
    dismiss_active = (dismiss is not None
                      and dismiss.get("expires_at") is not None
                      and dismiss["expires_at"] > time.time())

    return jsonify({
        "snooze": {
            "active": snooze_active,
            "expires_at": snooze["expires_at"] if snooze_active else None,
            "minutes": (snooze["parameters"].get("minutes")
                        if snooze_active and snooze.get("parameters") else None),
            "decision_id": snooze["id"] if snooze_active else None,
        } if snooze_active else None,
        "visibility": (vis["parameters"].get("mode")
                       if vis and vis.get("parameters") else "default"),
        "dismiss": {
            "active": dismiss_active,
            "expires_at": dismiss["expires_at"] if dismiss_active else None,
            "fingerprint": (dismiss["parameters"].get("fingerprint")
                            if dismiss_active and dismiss.get("parameters") else None),
        } if dismiss_active else None,
    })


# TL-recal & dual-weight governance endpoints RETIRED 2026-05-29: the
# §10.5 migration gates they served elapsed unactioned and TL calibration
# is now autonomous (tier governor). The generic DecisionLedger + triage
# and history endpoints below remain the live AP4 surface.

# ── Per-user TRIAGE thresholds ─────────────────────────────────────────

@bp.route("/api/v2/decisions/threshold", methods=["PUT"])
@jwt_required()
def triage_threshold_set():
    """Set per-user TRIAGE display thresholds.
    Body: { dormant_enter, critical_enter, reason? }
    Both clamped to [0.0, 1.0]; auto-corrected if inverted (handled
    client-side in TriageDisplayMode anyway)."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    body = request.get_json(silent=True) or {}
    try:
        dormant = float(body.get("dormant_enter", 0.40))
        critical = float(body.get("critical_enter", 0.85))
    except (ValueError, TypeError):
        return jsonify({"error": "thresholds must be numeric"}), 400
    dormant = max(0.0, min(dormant, 1.0))
    critical = max(0.0, min(critical, 1.0))

    from radar.database import db
    decision_id = db.decisions.record(
        decision_type="triage_threshold_override",
        target_kind="user",
        target_id=get_jwt_identity() or "unknown",
        action="set",
        actor=_actor_string(),
        reason=body.get("reason"),
        parameters={"dormant_enter": dormant, "critical_enter": critical},
        expires_at=None,
    )
    return jsonify({"decision_id": decision_id,
                    "dormant_enter": dormant, "critical_enter": critical})


@bp.route("/api/v2/decisions/threshold", methods=["GET"])
@jwt_required()
def triage_threshold_get():
    """Returns the analyst's current threshold override or defaults."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    from radar.database import db
    user_id = get_jwt_identity() or "unknown"
    cur = db.decisions.latest(
        decision_type="triage_threshold_override",
        target_kind="user", target_id=user_id,
    )
    if cur and cur.get("parameters"):
        return jsonify({
            "dormant_enter": cur["parameters"].get("dormant_enter", 0.40),
            "critical_enter": cur["parameters"].get("critical_enter", 0.85),
            "set_at": cur.get("decided_at"),
            "is_default": False,
        })
    return jsonify({
        "dormant_enter": 0.40,
        "critical_enter": 0.85,
        "is_default": True,
    })


# ── Decision History (AP4) ─────────────────────────────────────────────

@bp.route("/api/v2/decisions/history", methods=["GET"])
@jwt_required()
def decisions_history():
    """Filtered, time-ordered listing of decisions for the History UI.

    Query params (all optional):
      decision_type, target_kind, target_id, actor, action,
      since_ts (unix sec), until_ts (unix sec),
      limit (default 200, max 1000)
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    args = request.args
    def _f(name):
        v = args.get(name)
        return v if v else None
    try:
        since_ts = float(args["since_ts"]) if args.get("since_ts") else None
        until_ts = float(args["until_ts"]) if args.get("until_ts") else None
        limit = int(args.get("limit", "200"))
    except (ValueError, TypeError):
        return jsonify({"error": "since_ts/until_ts must be numeric, limit must be integer"}), 400

    from radar.database import db
    rows = db.decisions.history(
        decision_type=_f("decision_type"),
        target_kind=_f("target_kind"),
        target_id=_f("target_id"),
        actor=_f("actor"),
        action=_f("action"),
        since_ts=since_ts,
        until_ts=until_ts,
        limit=limit,
    )
    return jsonify({"decisions": rows, "count": len(rows)})


@bp.route("/api/v2/decisions/<decision_id>", methods=["GET"])
@jwt_required()
def decisions_get(decision_id: str):
    """Single decision detail."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    from radar.database import db
    row = db.decisions.get(decision_id)
    if row is None:
        return jsonify({"error": "decision not found"}), 404
    return jsonify(row)


@bp.route("/api/v2/decisions/<decision_id>/revoke", methods=["POST"])
@jwt_required()
def decisions_revoke(decision_id: str):
    """Revoke an active decision without inserting a replacement.

    Used by the [Re-evaluate] button on accepted/extended/raised
    Pending Decisions cards to undo the analyst's prior decision and
    let the data-driven recommendation surface again. The original
    decision row is preserved for audit (NP6) — superseded_by gets a
    synthetic 'revoked:<actor>:<ts>' marker.

    Authorization mirrors the original decision's authorization scope:
    governance decisions (tl_recal_*, dual_weight_*) admin-only;
    operational decisions (triage_*) analyst+admin.

    Body: { reason?: str }
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard

    from radar.database import db
    row = db.decisions.get(decision_id)
    if row is None:
        return jsonify({"error": "decision not found"}), 404

    # Match the auth scope of the original write. Operational decisions
    # can be revoked by any analyst; governance decisions require admin.
    is_governance = row["decision_type"].startswith("tl_recal_") \
                    or row["decision_type"].startswith("dual_weight_")
    auth_err = _require_admin() if is_governance else _require_analyst()
    if auth_err is not None:
        return auth_err

    if row["superseded_by"] is not None:
        return jsonify({
            "error": "already_inactive",
            "message": "decision is already superseded or revoked",
        }), 409

    body = request.get_json(silent=True) or {}
    revoked = db.decisions.revoke(
        decision_id, by=_actor_string(),
        reason=body.get("reason"),
    )
    if not revoked:
        # Race: another writer revoked it between our check and our update.
        return jsonify({"error": "revoke_race"}), 409
    return jsonify({"revoked": True, "decision_id": decision_id})
