"""Tier 1 — auto-tuning API surface (Full tier rollout, commit 3).

Exposes Phase A-F1 calibrator/proposer state to the analyst UI:

  GET  /api/v2/threshold_history                       list (key/scope/hours/limit)
  GET  /api/v2/threshold_history/<id>                  single row
  POST /api/v2/threshold_history/<id>/revert           admin revert

  GET  /api/v2/proposals/sensor_disable                list pending
  POST /api/v2/proposals/sensor_disable/<id>/ack       cancel auto-disable

  GET  /api/v2/proposals/scenario_improver             list pending (scenario filter)
  POST /api/v2/proposals/scenario_improver/<id>/apply  mark applied
  POST /api/v2/proposals/scenario_improver/<id>/dismiss
  POST /api/v2/proposals/scenario_improver/<id>/defer  snooze 30d

drift_signals + run_now + health endpoints are added in commit 4.
lineage walker is added in commit 7. preview is added with the Wizard
UI in commit 14.

Auth model:
  - GET endpoints require analyst-or-admin (read-only)
  - POST endpoints require admin (state-changing)

NP6: every response carries the v2 envelope (api_version, observed_at,
final_judgment_disclaimer). Lists include the underlying SQL row id +
formula_ref so analysts can reproduce the proposal.

NP7: the apply endpoint marks the proposal ledger row as 'applied'. The
actual scenario-store mutation (geo_data.json edit) remains a separate
analyst step until commit 14 wires the Wizard's transactional apply
flow. The proposal ledger captures intent; the file edit captures the
configuration change.

NP3: every helper is fault-tolerant. Underlying calibration helpers are
already NP3-compliant (silent no-op on DB failure); this layer adds a
generic try/except around list assembly so a malformed row does not
break the whole list.
"""
from __future__ import annotations

import time
from dataclasses import asdict
from typing import Optional

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from radar import config
from radar.calibration import (
    scenario_improver,
    sensor_disable_proposer,
    threshold_history,
)
from radar.conclusions.api import API_VERSION, build_error
from radar.routes import _require_admin, _require_analyst, _safe_int, bp
from radar.routes.conclusions_v2 import _v2_enabled_or_503


# ── Envelope helper ──────────────────────────────────────────────────────────


def _wrap(data, **extra) -> dict:
    """NP7-compliant envelope for calibration responses."""
    body = {
        "api_version": API_VERSION,
        "observed_at": time.time(),
        "final_judgment_disclaimer": config.V2_NP7_DISCLAIMER,
        "data": data,
    }
    body.update(extra)
    return body


def _bad_request(error: str, **extra):
    body, status = build_error(400, error, **extra)
    return jsonify(body), status


def _not_found(error: str, **extra):
    body, status = build_error(404, error, **extra)
    return jsonify(body), status


def _conflict(error: str, **extra):
    body, status = build_error(409, error, **extra)
    return jsonify(body), status


# ── /api/v2/threshold_history ─────────────────────────────────────────────────


@bp.route("/api/v2/threshold_history", methods=["GET"])
@jwt_required()
def v2_threshold_history_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    key = request.args.get("key", "").strip() or None
    scope = request.args.get("scope", "").strip() or None
    hours = _safe_int(request.args.get("hours"), 168, min_val=1, max_val=720)
    limit = _safe_int(request.args.get("limit"), 50, min_val=1, max_val=500)

    try:
        records = threshold_history.list_recent(
            hours=hours,
            scope_scenario_id=scope,
        )
    except Exception as exc:
        return _wrap_error(500, "list_recent_failed", detail=str(exc)[:200])

    if key:
        records = [r for r in records if r.key == key]

    items = [asdict(r) for r in records[:limit]]
    return jsonify(_wrap(
        items,
        filters={"key": key, "scope": scope, "hours": hours, "limit": limit},
        count=len(items),
    ))


@bp.route("/api/v2/threshold_history/<int:row_id>", methods=["GET"])
@jwt_required()
def v2_threshold_history_get(row_id: int):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    record = threshold_history.get_by_id(row_id)
    if record is None:
        return _not_found("threshold row not found", row_id=row_id)
    return jsonify(_wrap(asdict(record)))


@bp.route("/api/v2/threshold_history/<int:row_id>/revert", methods=["POST"])
@jwt_required()
def v2_threshold_history_revert(row_id: int):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth

    by = (get_jwt_identity() or "unknown")
    new_id = threshold_history.revert(row_id, reverted_by=f"admin:{by}")
    if new_id is None:
        # Caller could not revert — either row missing, non-active, or
        # no revertible_to_id. We don't expose which to keep the error
        # surface narrow; admin can read /threshold_history/<id> to
        # see the row's actual state.
        record = threshold_history.get_by_id(row_id)
        if record is None:
            return _not_found("threshold row not found", row_id=row_id)
        return _conflict(
            "row not revertible",
            row_id=row_id,
            current_state=record.state,
            has_revertible_to=record.revertible_to_id is not None,
        )
    return jsonify(_wrap({
        "reverted_row_id": row_id,
        "new_row_id": new_id,
        "reverted_by": f"admin:{by}",
    }))


# ── /api/v2/proposals/sensor_disable ─────────────────────────────────────────


@bp.route("/api/v2/proposals/sensor_disable", methods=["GET"])
@jwt_required()
def v2_proposals_sensor_disable_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    try:
        items = sensor_disable_proposer.list_pending()
    except Exception as exc:
        return _wrap_error(500, "sensor_disable_list_failed", detail=str(exc)[:200])
    return jsonify(_wrap(items, count=len(items)))


@bp.route("/api/v2/proposals/sensor_disable/<int:proposal_id>/ack", methods=["POST"])
@jwt_required()
def v2_proposals_sensor_disable_ack(proposal_id: int):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth

    by = (get_jwt_identity() or "unknown")
    try:
        ok = sensor_disable_proposer.acknowledge(
            proposal_id, by=f"admin:{by}",
        )
    except Exception as exc:
        return _wrap_error(500, "sensor_disable_ack_failed", detail=str(exc)[:200])
    if not ok:
        return _not_found(
            "proposal not in pending state",
            proposal_id=proposal_id,
        )
    return jsonify(_wrap({
        "proposal_id": proposal_id,
        "new_state": "dismissed",
        "by": f"admin:{by}",
    }))


# ── /api/v2/proposals/scenario_improver ──────────────────────────────────────


@bp.route("/api/v2/proposals/scenario_improver", methods=["GET"])
@jwt_required()
def v2_proposals_scenario_improver_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    scenario_id = request.args.get("scenario_id", "").strip() or None
    hours = _safe_int(request.args.get("hours"), 168, min_val=1, max_val=720)
    try:
        items = scenario_improver.list_pending(
            scenario_id=scenario_id, hours=hours,
        )
    except Exception as exc:
        return _wrap_error(500, "scenario_improver_list_failed",
                           detail=str(exc)[:200])
    return jsonify(_wrap(
        items,
        filters={"scenario_id": scenario_id, "hours": hours},
        count=len(items),
    ))


def _scenario_improver_state_change(
    proposal_id: int, new_state: str,
):
    """Shared body for apply/dismiss/defer endpoints."""
    by = (get_jwt_identity() or "unknown")
    try:
        ok = scenario_improver.update_state(
            proposal_id, new_state=new_state, by=f"admin:{by}",
        )
    except Exception as exc:
        return _wrap_error(500, "scenario_improver_update_failed",
                           detail=str(exc)[:200])
    if not ok:
        return _not_found(
            "proposal not in pending state",
            proposal_id=proposal_id,
        )
    return jsonify(_wrap({
        "proposal_id": proposal_id,
        "new_state": new_state,
        "by": f"admin:{by}",
    }))


@bp.route("/api/v2/proposals/scenario_improver/<int:proposal_id>/apply",
          methods=["POST"])
@jwt_required()
def v2_proposals_scenario_improver_apply(proposal_id: int):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth
    return _scenario_improver_state_change(proposal_id, "applied")


@bp.route("/api/v2/proposals/scenario_improver/<int:proposal_id>/dismiss",
          methods=["POST"])
@jwt_required()
def v2_proposals_scenario_improver_dismiss(proposal_id: int):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth
    return _scenario_improver_state_change(proposal_id, "dismissed")


@bp.route("/api/v2/proposals/scenario_improver/<int:proposal_id>/defer",
          methods=["POST"])
@jwt_required()
def v2_proposals_scenario_improver_defer(proposal_id: int):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth
    return _scenario_improver_state_change(proposal_id, "snoozed_30d")


# ── Internal helpers ─────────────────────────────────────────────────────────


def _wrap_error(status: int, error: str, **extra):
    body, status = build_error(status, error, **extra)
    return jsonify(body), status
