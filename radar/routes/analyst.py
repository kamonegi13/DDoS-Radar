"""radar.routes.analyst -- Analyst tradecraft endpoints (F4-F14).

Implements the structured analytic technique surface area added per the
14-feature transparency / bias-mitigation design:

  F4  Hidden Negative Signals      GET  /api/analyst/hidden_signals
  F5  Coverage Gap                 GET  /api/analyst/coverage
  F6  Disconfirming Evidence       GET/POST/DELETE /api/analyst/disconf
  F8  ACH Matrix                   GET/POST    /api/analyst/ach
  F10 Key Assumptions              GET/POST/PATCH /api/analyst/assumptions
  F11 Pre-Mortem                   GET/POST    /api/analyst/premortem
  F13 Dissenting Views             GET/POST    /api/analyst/dissent
  F14 Decision Ledger              GET/POST    /api/analyst/decisions

All write endpoints require analyst-or-admin role (per ADR-006: analyst
judgment support, not substitution). Lock/unlock on assumptions requires
admin specifically.
"""
from __future__ import annotations
import logging
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from radar.database import db as _db
from radar.routes import bp, _require_analyst, _require_admin

log = logging.getLogger("radar")


def _identity_role() -> tuple[str, str, int | None]:
    """Return (username, role, user_id). Empty username if unauthenticated."""
    try:
        username = get_jwt_identity() or ""
    except Exception:
        username = ""
    role = ""
    user_id = None
    if username:
        try:
            role = _db.user_get_role(username) or ""
            row = _db.user_get(username)
            if row:
                user_id = row.get("id")
        except Exception:
            pass
    return username, role, user_id


def _autolog(
    *, decision_type: str, summary: str, scenario_id: str | None,
    detail: dict | None, session_id: str | None,
    username: str, user_id: int | None,
) -> None:
    """Best-effort write-through into decision_ledger (F14).

    Tradecraft write endpoints (F6/F8/F10/F11/F13) call this after their
    primary DB write succeeds so every analyst action lands in one audit
    trail. Failures here never propagate — the primary write already
    succeeded; the ledger entry is supplementary."""
    try:
        sid = (session_id or "").strip() or f"auto:{decision_type}"
        detail_with_marker = dict(detail or {})
        detail_with_marker.setdefault("auto", True)
        _db.decision_log(
            user_id=user_id, username=username, session_id=sid,
            scenario_id=scenario_id,
            decision_type=decision_type, summary=summary,
            detail=detail_with_marker,
        )
    except Exception as e:
        log.debug("[F14] autolog failed for %s: %s", decision_type, e)


def _ach_scenario_id(matrix_id: int) -> str | None:
    """Look up a matrix's scenario_id for autolog tagging."""
    try:
        m = _db.ach_matrix_get(matrix_id)
        if m:
            return m.get("scenario_id")
    except Exception:
        pass
    return None


# ─── F4 Hidden Negative Signals ────────────────────────────────────────────
@bp.route("/api/analyst/hidden_signals", methods=["GET"])
@jwt_required()
def hidden_signals_list():
    err = _require_analyst()
    if err:
        return err
    scenario_id = request.args.get("scenario_id") or None
    try:
        since = float(request.args.get("since", "0")) or None
    except ValueError:
        since = None
    try:
        limit = max(1, min(int(request.args.get("limit", "100")), 1000))
    except ValueError:
        limit = 100
    return jsonify({"items": _db.hidden_signal_list(
        scenario_id=scenario_id, since=since, limit=limit)})


# ─── F5 Coverage Gap ───────────────────────────────────────────────────────
@bp.route("/api/analyst/coverage", methods=["GET"])
@jwt_required()
def coverage_get():
    err = _require_analyst()
    if err:
        return err
    scenario_id = request.args.get("scenario_id", "").strip()
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    return jsonify({
        "scenario_id": scenario_id,
        "sensors": _db.coverage_list(scenario_id),
    })


# ─── F6 Disconfirming Evidence ─────────────────────────────────────────────
@bp.route("/api/analyst/disconf", methods=["GET"])
@jwt_required()
def disconf_list():
    err = _require_analyst()
    if err:
        return err
    scenario_id = request.args.get("scenario_id", "").strip()
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    include_retracted = request.args.get("include_retracted") == "1"
    return jsonify({"items": _db.disconf_list(scenario_id, include_retracted)})


@bp.route("/api/analyst/disconf", methods=["POST"])
@jwt_required()
def disconf_add():
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    scenario_id = (body.get("scenario_id") or "").strip()
    summary = (body.get("summary") or "").strip()
    if not scenario_id or not summary:
        return jsonify({"error": "scenario_id and summary required"}), 400
    source_kind = body.get("source_kind", "manual_note")
    if source_kind not in ("intel_item", "rationale", "manual_note"):
        return jsonify({"error": "invalid source_kind"}), 400
    username, _, user_id = _identity_role()
    strength = int(body.get("strength", 2))
    new_id = _db.disconf_add(
        scenario_id=scenario_id, tagged_by=username,
        source_kind=source_kind, source_ref=body.get("source_ref"),
        summary=summary, strength=strength,
    )
    _autolog(
        decision_type="disconf_add",
        summary=f"Added disconfirming evidence: {summary[:80]}",
        scenario_id=scenario_id,
        detail={
            "disconf_id": new_id, "source_kind": source_kind,
            "source_ref": body.get("source_ref"), "strength": strength,
        },
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"id": new_id})


@bp.route("/api/analyst/disconf/<int:item_id>/retract", methods=["POST"])
@jwt_required()
def disconf_retract(item_id: int):
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    username, _, user_id = _identity_role()
    ok = _db.disconf_retract(item_id, username)
    if ok:
        _autolog(
            decision_type="disconf_retract",
            summary=f"Retracted disconfirming evidence #{item_id}",
            scenario_id=body.get("scenario_id"),
            detail={"disconf_id": item_id},
            session_id=body.get("session_id"),
            username=username, user_id=user_id,
        )
    return jsonify({"ok": ok})


# ─── F8 ACH Matrix ─────────────────────────────────────────────────────────
@bp.route("/api/analyst/ach", methods=["GET"])
@jwt_required()
def ach_list():
    err = _require_analyst()
    if err:
        return err
    scenario_id = request.args.get("scenario_id", "").strip()
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    return jsonify({"matrices": _db.ach_matrix_list(scenario_id)})


@bp.route("/api/analyst/ach", methods=["POST"])
@jwt_required()
def ach_create():
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    scenario_id = (body.get("scenario_id") or "").strip()
    title = (body.get("title") or "").strip()
    if not scenario_id or not title:
        return jsonify({"error": "scenario_id and title required"}), 400
    username, _, user_id = _identity_role()
    mid = _db.ach_matrix_create(scenario_id, title, username)
    _autolog(
        decision_type="ach_create",
        summary=f"Created ACH matrix: {title[:80]}",
        scenario_id=scenario_id,
        detail={"matrix_id": mid, "title": title},
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"id": mid})


@bp.route("/api/analyst/ach/<int:matrix_id>", methods=["GET"])
@jwt_required()
def ach_get(matrix_id: int):
    err = _require_analyst()
    if err:
        return err
    m = _db.ach_matrix_get(matrix_id)
    if not m:
        return jsonify({"error": "matrix not found"}), 404
    return jsonify(m)


@bp.route("/api/analyst/ach/<int:matrix_id>/hypothesis", methods=["POST"])
@jwt_required()
def ach_add_hypothesis(matrix_id: int):
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text required"}), 400
    is_null = bool(body.get("is_null_hypothesis", False))
    new_id = _db.ach_hypothesis_add(
        matrix_id, text,
        is_null=is_null,
        ord_=int(body.get("ord", 0)),
    )
    username, _, user_id = _identity_role()
    _autolog(
        decision_type="ach_hypothesis_add",
        summary=f"Added {'null ' if is_null else ''}hypothesis to ACH #{matrix_id}: {text[:80]}",
        scenario_id=_ach_scenario_id(matrix_id),
        detail={"matrix_id": matrix_id, "hypothesis_id": new_id,
                "is_null": is_null, "text": text},
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"id": new_id})


@bp.route("/api/analyst/ach/<int:matrix_id>/evidence", methods=["POST"])
@jwt_required()
def ach_add_evidence(matrix_id: int):
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    text = (body.get("text") or "").strip()
    if not text:
        return jsonify({"error": "text required"}), 400
    credibility = int(body.get("credibility", 3))
    relevance = int(body.get("relevance", 3))
    new_id = _db.ach_evidence_add(
        matrix_id, text, source_ref=body.get("source_ref"),
        credibility=credibility,
        relevance=relevance,
        ord_=int(body.get("ord", 0)),
    )
    username, _, user_id = _identity_role()
    _autolog(
        decision_type="ach_evidence_add",
        summary=f"Added evidence to ACH #{matrix_id}: {text[:80]}",
        scenario_id=_ach_scenario_id(matrix_id),
        detail={"matrix_id": matrix_id, "evidence_id": new_id,
                "credibility": credibility, "relevance": relevance,
                "source_ref": body.get("source_ref"), "text": text},
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"id": new_id})


@bp.route("/api/analyst/ach/<int:matrix_id>/score", methods=["POST"])
@jwt_required()
def ach_set_score(matrix_id: int):
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    try:
        hyp_id = int(body["hypothesis_id"])
        ev_id = int(body["evidence_id"])
        consistency = int(body["consistency"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "hypothesis_id, evidence_id, consistency required"}), 400
    _db.ach_score_set(matrix_id, hyp_id, ev_id, consistency, body.get("note"))
    username, _, user_id = _identity_role()
    _autolog(
        decision_type="ach_score_set",
        summary=f"ACH #{matrix_id} H{hyp_id}/E{ev_id} consistency={consistency:+d}",
        scenario_id=_ach_scenario_id(matrix_id),
        detail={"matrix_id": matrix_id, "hypothesis_id": hyp_id,
                "evidence_id": ev_id, "consistency": consistency,
                "note": body.get("note")},
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"ok": True})


# ─── F13 Dissenting Views ──────────────────────────────────────────────────
@bp.route("/api/analyst/dissent", methods=["GET"])
@jwt_required()
def dissent_list():
    err = _require_analyst()
    if err:
        return err
    scenario_id = request.args.get("scenario_id", "").strip()
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    include_resolved = request.args.get("include_resolved") == "1"
    return jsonify({"views": _db.dissent_list(scenario_id, include_resolved)})


@bp.route("/api/analyst/dissent", methods=["POST"])
@jwt_required()
def dissent_add():
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    scenario_id = (body.get("scenario_id") or "").strip()
    title = (body.get("title") or "").strip()
    body_text = (body.get("body") or "").strip()
    if not scenario_id or not title or not body_text:
        return jsonify({"error": "scenario_id, title, body required"}), 400
    argues = body.get("argues_for_tl")
    if argues is not None:
        try:
            argues = max(1, min(5, int(argues)))
        except (TypeError, ValueError):
            argues = None
    username, _, user_id = _identity_role()
    new_id = _db.dissent_add(scenario_id, username, title, body_text, argues)
    _autolog(
        decision_type="dissent_add",
        summary=f"Filed dissenting view: {title[:80]}",
        scenario_id=scenario_id,
        detail={"view_id": new_id, "title": title,
                "argues_for_tl": argues},
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"id": new_id})


@bp.route("/api/analyst/dissent/<int:view_id>/resolve", methods=["POST"])
@jwt_required()
def dissent_resolve(view_id: int):
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    username, _, user_id = _identity_role()
    note = body.get("resolution_note") or body.get("note")
    ok = _db.dissent_resolve(view_id, username, note)
    if ok:
        _autolog(
            decision_type="dissent_resolve",
            summary=f"Resolved dissenting view #{view_id}",
            scenario_id=body.get("scenario_id"),
            detail={"view_id": view_id, "note": note},
            session_id=body.get("session_id"),
            username=username, user_id=user_id,
        )
    return jsonify({"ok": ok})


# ─── F10 Key Assumptions ───────────────────────────────────────────────────
@bp.route("/api/analyst/assumptions", methods=["GET"])
@jwt_required()
def assumption_list():
    err = _require_analyst()
    if err:
        return err
    scenario_id = request.args.get("scenario_id", "").strip()
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    include_invalid = request.args.get("include_invalidated", "1") != "0"
    return jsonify({"items": _db.assumption_list(scenario_id, include_invalid)})


@bp.route("/api/analyst/assumptions", methods=["POST"])
@jwt_required()
def assumption_add():
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    scenario_id = (body.get("scenario_id") or "").strip()
    statement = (body.get("statement") or "").strip()
    if not scenario_id or not statement:
        return jsonify({"error": "scenario_id and statement required"}), 400
    username, _, user_id = _identity_role()
    confidence = body.get("confidence", "medium")
    new_id = _db.assumption_add(
        scenario_id, username, statement,
        body.get("rationale"),
        confidence,
    )
    _autolog(
        decision_type="assumption_add",
        summary=f"Added key assumption: {statement[:80]}",
        scenario_id=scenario_id,
        detail={"assumption_id": new_id, "statement": statement,
                "confidence": confidence,
                "rationale": body.get("rationale")},
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"id": new_id})


@bp.route("/api/analyst/assumptions/<int:aid>", methods=["PATCH"])
@jwt_required()
def assumption_edit(aid: int):
    err = _require_analyst()
    if err:
        return err
    username, role, _ = _identity_role()
    body = request.get_json(force=True, silent=True) or {}
    fields = {k: v for k, v in body.items()
              if k in ("statement", "rationale", "confidence")}
    if not fields:
        return jsonify({"error": "no editable fields"}), 400
    try:
        ok = _db.assumption_update(aid, username, fields, role == "admin")
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    if ok:
        _, _, user_id = _identity_role()
        _autolog(
            decision_type="assumption_edit",
            summary=f"Edited key assumption #{aid}",
            scenario_id=body.get("scenario_id"),
            detail={"assumption_id": aid, "fields": fields},
            session_id=body.get("session_id"),
            username=username, user_id=user_id,
        )
    return jsonify({"ok": ok})


@bp.route("/api/analyst/assumptions/<int:aid>/lock", methods=["POST"])
@jwt_required()
def assumption_lock(aid: int):
    err = _require_admin()
    if err:
        return err
    username, _, user_id = _identity_role()
    body = request.get_json(force=True, silent=True) or {}
    lock = bool(body.get("lock", True))
    try:
        ok = _db.assumption_lock(aid, username, is_admin=True, lock=lock)
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    if ok:
        _autolog(
            decision_type="assumption_lock" if lock else "assumption_unlock",
            summary=f"{'Locked' if lock else 'Unlocked'} key assumption #{aid}",
            scenario_id=body.get("scenario_id"),
            detail={"assumption_id": aid, "lock": lock},
            session_id=body.get("session_id"),
            username=username, user_id=user_id,
        )
    return jsonify({"ok": ok})


@bp.route("/api/analyst/assumptions/<int:aid>/invalidate", methods=["POST"])
@jwt_required()
def assumption_invalidate(aid: int):
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    username, _, user_id = _identity_role()
    note = body.get("note")
    ok = _db.assumption_invalidate(aid, username, note)
    if ok:
        _autolog(
            decision_type="assumption_invalidate",
            summary=f"Invalidated key assumption #{aid}",
            scenario_id=body.get("scenario_id"),
            detail={"assumption_id": aid, "note": note},
            session_id=body.get("session_id"),
            username=username, user_id=user_id,
        )
    return jsonify({"ok": ok})


@bp.route("/api/analyst/assumptions/<int:aid>/log", methods=["GET"])
@jwt_required()
def assumption_log(aid: int):
    err = _require_analyst()
    if err:
        return err
    return jsonify({"entries": _db.assumption_change_log(aid)})


# ─── F11 Pre-Mortem ────────────────────────────────────────────────────────
@bp.route("/api/analyst/premortem", methods=["GET"])
@jwt_required()
def premortem_list():
    err = _require_analyst()
    if err:
        return err
    scenario_id = request.args.get("scenario_id", "").strip()
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    include_resolved = request.args.get("include_resolved") == "1"
    return jsonify({"items": _db.premortem_list(scenario_id, include_resolved)})


@bp.route("/api/analyst/premortem", methods=["POST"])
@jwt_required()
def premortem_add():
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    scenario_id = (body.get("scenario_id") or "").strip()
    failure_mode = body.get("failure_mode", "")
    imagined = (body.get("imagined_outcome") or "").strip()
    root_cause = (body.get("root_cause") or "").strip()
    if not scenario_id or not imagined or not root_cause:
        return jsonify({"error": "scenario_id, imagined_outcome, root_cause required"}), 400
    username, _, user_id = _identity_role()
    try:
        new_id = _db.premortem_add(
            scenario_id, username, failure_mode, imagined, root_cause,
            body.get("early_warning"), body.get("mitigation"),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    _autolog(
        decision_type="premortem_add",
        summary=f"Pre-mortem [{failure_mode}]: {imagined[:80]}",
        scenario_id=scenario_id,
        detail={"premortem_id": new_id, "failure_mode": failure_mode,
                "imagined_outcome": imagined, "root_cause": root_cause,
                "early_warning": body.get("early_warning"),
                "mitigation": body.get("mitigation")},
        session_id=body.get("session_id"),
        username=username, user_id=user_id,
    )
    return jsonify({"id": new_id})


@bp.route("/api/analyst/premortem/<int:eid>/resolve", methods=["POST"])
@jwt_required()
def premortem_resolve(eid: int):
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    username, _, user_id = _identity_role()
    ok = _db.premortem_resolve(eid, username)
    if ok:
        _autolog(
            decision_type="premortem_resolve",
            summary=f"Resolved pre-mortem #{eid}",
            scenario_id=body.get("scenario_id"),
            detail={"premortem_id": eid},
            session_id=body.get("session_id"),
            username=username, user_id=user_id,
        )
    return jsonify({"ok": ok})


# ─── F14 Decision Ledger ───────────────────────────────────────────────────
@bp.route("/api/analyst/decisions", methods=["GET"])
@jwt_required()
def decision_list():
    err = _require_analyst()
    if err:
        return err
    session_id = request.args.get("session_id") or None
    scenario_id = request.args.get("scenario_id") or None
    try:
        since = float(request.args.get("since", "0")) or None
    except ValueError:
        since = None
    try:
        limit = max(1, min(int(request.args.get("limit", "200")), 1000))
    except ValueError:
        limit = 200
    return jsonify({"items": _db.decision_list(
        session_id=session_id, scenario_id=scenario_id,
        since=since, limit=limit,
    )})


@bp.route("/api/analyst/decisions", methods=["POST"])
@jwt_required()
def decision_log():
    err = _require_analyst()
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    session_id = (body.get("session_id") or "").strip()
    decision_type = (body.get("decision_type") or "").strip()
    summary = (body.get("summary") or "").strip()
    if not session_id or not decision_type or not summary:
        return jsonify({"error": "session_id, decision_type, summary required"}), 400
    username, _, user_id = _identity_role()
    new_id = _db.decision_log(
        user_id=user_id, username=username, session_id=session_id,
        scenario_id=body.get("scenario_id"),
        decision_type=decision_type, summary=summary,
        detail=body.get("detail") or {},
    )
    return jsonify({"id": new_id})


# ─── F2 Coverage updater hook (called from scoring loop) ───────────────────

def update_coverage_for_scenario(scenario_id: str, registry) -> None:
    """Snapshot current sensor health for the focused scenario into
    scenario_sensor_coverage so the F5 coverage panel has fresh data.
    Best-effort: failures are logged but never raised."""
    if not scenario_id:
        log.debug("[F5] no focused scenario — coverage snapshot skipped")
        return
    try:
        for sensor in registry.all():
            name = getattr(sensor, "name", "") or ""
            if not name:
                continue
            domain = getattr(sensor, "domain", "") or ""
            cb = getattr(sensor, "circuit_breaker", None)
            consecutive = int(getattr(cb, "consecutive_failures", 0)) if cb else 0
            cb_open = bool(getattr(cb, "is_open", False)) if cb else False
            disabled = not bool(getattr(sensor, "enabled", True))
            last_success = getattr(sensor, "last_success_ts", None)
            last_attempt = getattr(sensor, "last_attempt_ts", None)
            import time as _t
            now = _t.time()
            stale_after = 3600.0
            if disabled:
                state = "disabled"
            elif cb_open or consecutive >= 5:
                state = "failing"
            elif last_success and (now - float(last_success)) > stale_after:
                state = "stale"
            elif last_success:
                state = "healthy"
            else:
                state = "unknown"
            _db.coverage_upsert(
                scenario_id=scenario_id, sensor=name, domain=domain,
                last_success=float(last_success) if last_success else None,
                last_attempt=float(last_attempt) if last_attempt else None,
                state=state, consecutive_failures=consecutive,
            )
    except Exception as e:
        # WARNING, not debug: an exception here means the F5 coverage panel
        # silently goes empty (this masked a registry.all() AttributeError
        # for an unknown period before 2026-05-30). Surface it.
        log.warning("[F5] coverage update failed for %s: %s", scenario_id, e)
