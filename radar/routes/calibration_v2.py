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

import json
import time
from dataclasses import asdict
from typing import Optional

from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from radar import config
from radar.calibration import (
    drift_watchdog,
    lineage as calibration_lineage,
    run_now as calibration_run_now,
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


@bp.route("/api/v2/threshold_history/<int:row_id>/lineage", methods=["GET"])
@jwt_required()
def v2_threshold_history_lineage(row_id: int):
    """F2-d: walk the derived_from chain (via revertible_to_id) to
    expose ancestors + descendants of a threshold row."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    max_depth = _safe_int(request.args.get("max_depth"), 50,
                          min_val=1, max_val=200)
    graph = calibration_lineage.walk_lineage(row_id, max_depth=max_depth)
    if graph is None:
        return _not_found("threshold row not found", row_id=row_id)
    return jsonify(_wrap(graph.to_dict()))


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


# ── /api/v2/drift_signals (commit 4) ─────────────────────────────────────────


@bp.route("/api/v2/drift_signals", methods=["GET"])
@jwt_required()
def v2_drift_signals_list():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    severity = request.args.get("severity", "").strip() or None
    hours = _safe_int(request.args.get("hours"), 168, min_val=1, max_val=720)
    min_runs = _safe_int(request.args.get("min_consecutive_runs"), 3,
                         min_val=1, max_val=24)
    try:
        items = drift_watchdog.list_unack_events(
            severity=severity,
            min_consecutive_runs=min_runs,
            hours=hours,
        )
    except Exception as exc:
        return _wrap_error(500, "drift_signals_list_failed",
                           detail=str(exc)[:200])
    return jsonify(_wrap(
        items,
        filters={"severity": severity, "hours": hours,
                 "min_consecutive_runs": min_runs},
        count=len(items),
    ))


@bp.route("/api/v2/drift_signals/<int:event_id>/ack", methods=["POST"])
@jwt_required()
def v2_drift_signals_ack(event_id: int):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    # Drift ack is analyst-allowed (per plan §1.2) — analyst seeing the
    # drift surface should be able to clear it without escalating to admin.
    auth = _require_analyst()
    if auth is not None:
        return auth

    by = (get_jwt_identity() or "unknown")
    try:
        ok = drift_watchdog.acknowledge(event_id, by=f"analyst:{by}")
    except Exception as exc:
        return _wrap_error(500, "drift_ack_failed", detail=str(exc)[:200])
    if not ok:
        return _not_found(
            "drift event not in unack state",
            event_id=event_id,
        )
    return jsonify(_wrap({
        "event_id": event_id,
        "new_state": "acknowledged",
        "by": f"analyst:{by}",
    }))


# ── /api/v2/calibration/run_now (commit 4) ───────────────────────────────────


@bp.route("/api/v2/calibration/run_now", methods=["POST"])
@jwt_required()
def v2_calibration_run_now():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_admin()
    if auth is not None:
        return auth

    phase = request.args.get("phase", "").strip()
    if not phase:
        return _bad_request(
            "missing phase argument",
            valid_phases=["tl", "llm_conf", "sensor_disable",
                          "scenario", "drift", "all"],
        )
    try:
        results = calibration_run_now.dispatch(phase)
    except ValueError as exc:
        return _bad_request(str(exc))
    except Exception as exc:
        return _wrap_error(500, "run_now_dispatch_failed",
                           detail=str(exc)[:200])
    payload = {
        "phase": phase,
        "results": [_run_result_to_dict(r) for r in results],
        "n_ok": sum(1 for r in results if r.succeeded),
        "n_err": sum(1 for r in results if not r.succeeded),
    }
    return jsonify(_wrap(payload))


def _run_result_to_dict(r) -> dict:
    return {
        "phase": r.phase,
        "started_at": r.started_at,
        "duration_ms": r.duration_ms,
        "summary": r.summary,
        "error": r.error,
        "succeeded": r.succeeded,
    }


# ── /api/v2/calibration/health (commit 4, AP3) ───────────────────────────────


@bp.route("/api/v2/calibration/health", methods=["GET"])
@jwt_required()
def v2_calibration_health():
    """AP3 self-evaluation: governor + proposer scoreboard.

    Surfaces 7d aggregates so analysts can answer "how reliable is the
    auto-tuner right now?" without reading the threshold_history table.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    hours = _safe_int(request.args.get("hours"), 168, min_val=1, max_val=720)
    cutoff = time.time() - hours * 3600
    try:
        stats = _collect_health_stats(cutoff)
    except Exception as exc:
        return _wrap_error(500, "health_collect_failed",
                           detail=str(exc)[:200])
    stats["window_hours"] = hours
    return jsonify(_wrap(stats))


def _collect_health_stats(cutoff: float) -> dict:
    """Aggregate threshold_history + scenario_proposals + scenario_drift_events
    counts since `cutoff`. NP3: each query is fault-tolerant; one missing
    table does not break the whole snapshot."""
    from radar.database import db as _db
    conn = _db._get_conn()  # noqa: SLF001

    threshold_counts = _safe_count_by(conn,
        "SELECT state, COUNT(*) FROM threshold_history "
        "WHERE emitted_at >= ? GROUP BY state",
        (cutoff,),
    )
    proposal_counts = _safe_count_by(conn,
        "SELECT proposal_type, state, COUNT(*) FROM scenario_proposals "
        "WHERE emitted_at >= ? GROUP BY proposal_type, state",
        (cutoff,), key_columns=2,
    )
    drift_counts = _safe_count_by(conn,
        "SELECT severity, ack_state, COUNT(*) FROM scenario_drift_events "
        "WHERE emitted_at >= ? GROUP BY severity, ack_state",
        (cutoff,), key_columns=2,
    )
    actionable_drift = 0
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM scenario_drift_events "
            "WHERE ack_state='unack' AND consecutive_runs >= 3 "
            "AND emitted_at >= ?",
            (cutoff,),
        ).fetchone()
        actionable_drift = (row[0] if row else 0) or 0
    except Exception:
        actionable_drift = 0
    return {
        "threshold_history": threshold_counts,
        "scenario_proposals": proposal_counts,
        "scenario_drift_events": drift_counts,
        "actionable_drift_count": actionable_drift,
    }


def _safe_count_by(conn, sql: str, params: tuple, *, key_columns: int = 1) -> dict:
    """Run an aggregate query, return {key: count}. Multi-column keys are
    flattened with '|' for JSON-serializable dict keys."""
    try:
        rows = conn.execute(sql, params).fetchall()
    except Exception:
        return {}
    out: dict[str, int] = {}
    for r in rows:
        if key_columns == 1:
            key = str(r[0]) if r[0] is not None else "null"
        else:
            key = "|".join(str(c) if c is not None else "null"
                           for c in r[:key_columns])
        out[key] = int(r[-1] or 0)
    return out


# ── /api/v2/discovery/* (Tier 3, commit 11) ──────────────────────────────────


@bp.route("/api/v2/discovery/cooccurrence", methods=["GET"])
@jwt_required()
def v2_discovery_cooccurrence():
    """Latest cooccurrence matrix snapshot."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    from radar.analytics import cooccurrence as _cc
    snap = _cc.get_latest_snapshot()
    if snap is None:
        return jsonify(_wrap(None, message="no_snapshots_yet"))
    return jsonify(_wrap(snap))


@bp.route("/api/v2/discovery/clusters", methods=["GET"])
@jwt_required()
def v2_discovery_clusters():
    """List recent discovery_cluster rows joined to their run."""
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    hours = _safe_int(request.args.get("hours"), 168, min_val=1, max_val=720)
    limit = _safe_int(request.args.get("limit"), 50, min_val=1, max_val=200)
    cutoff = time.time() - hours * 3600
    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        rows = conn.execute(
            "SELECT c.id, c.run_id, c.cluster_index, c.countries_json, "
            "       c.centroid_json, c.annotation_json, c.annotation_state, "
            "       c.suggested_scenario_id, c.formula_ref, "
            "       r.emitted_at, r.eps, r.min_samples, r.algorithm "
            "FROM discovery_cluster c "
            "JOIN scenario_discovery_run r ON r.id = c.run_id "
            "WHERE r.emitted_at >= ? "
            "ORDER BY r.emitted_at DESC, c.cluster_index ASC "
            "LIMIT ?",
            (cutoff, limit),
        ).fetchall()
    except Exception as exc:
        return _wrap_error(500, "discovery_clusters_failed",
                           detail=str(exc)[:200])

    out = []
    for r in rows:
        try:
            countries = json.loads(r[3] or "[]")
            centroid = json.loads(r[4] or "{}")
            annotation = json.loads(r[5]) if r[5] else None
        except Exception:
            countries, centroid, annotation = [], {}, None
        out.append({
            "id": r[0],
            "run_id": r[1],
            "cluster_index": r[2],
            "countries": countries,
            "centroid": centroid.get("centroid") if isinstance(centroid, dict) else None,
            "annotation": annotation,
            "annotation_state": r[6],
            "suggested_scenario_id": r[7],
            "formula_ref": r[8],
            "run_emitted_at": r[9],
            "run_eps": r[10],
            "run_min_samples": r[11],
            "run_algorithm": r[12],
        })
    return jsonify(_wrap(out, count=len(out),
                         filters={"hours": hours, "limit": limit}))


@bp.route("/api/v2/discovery/clusters/<int:run_id>/replay", methods=["GET"])
@jwt_required()
def v2_discovery_replay(run_id: int):
    """AP4 replay: full snapshot of one discovery_run.

    Returns the run record, all its clusters, and the matrix snapshot
    that fed it — enough for an analyst to reproduce the run end-to-end
    without further queries.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        run = conn.execute(
            "SELECT id, emitted_at, matrix_snapshot_id, algorithm, eps, "
            "       min_samples, n_clusters, n_noise, formula_ref, "
            "       metadata_json "
            "FROM scenario_discovery_run WHERE id=?",
            (run_id,),
        ).fetchone()
        if not run:
            return _not_found("discovery run not found", run_id=run_id)
        clusters = conn.execute(
            "SELECT id, cluster_index, countries_json, centroid_json, "
            "       annotation_json, annotation_state, suggested_scenario_id, "
            "       formula_ref "
            "FROM discovery_cluster WHERE run_id=? ORDER BY cluster_index ASC",
            (run_id,),
        ).fetchall()
        snap = conn.execute(
            "SELECT id, emitted_at, window_days, bucket_hours, cell_count, "
            "       matrix_json, formula_ref, evidence_json "
            "FROM cooccurrence_matrix_snapshot WHERE id=?",
            (run[2],),
        ).fetchone()
    except Exception as exc:
        return _wrap_error(500, "discovery_replay_failed",
                           detail=str(exc)[:200])

    cluster_list = []
    for c in clusters:
        try:
            countries = json.loads(c[2] or "[]")
            centroid = json.loads(c[3] or "{}")
            annotation = json.loads(c[4]) if c[4] else None
        except Exception:
            countries, centroid, annotation = [], {}, None
        cluster_list.append({
            "id": c[0],
            "cluster_index": c[1],
            "countries": countries,
            "centroid": centroid.get("centroid") if isinstance(centroid, dict) else None,
            "annotation": annotation,
            "annotation_state": c[5],
            "suggested_scenario_id": c[6],
            "formula_ref": c[7],
        })

    snapshot_payload = None
    if snap:
        try:
            matrix = json.loads(snap[5] or "{}")
            evidence = json.loads(snap[7] or "{}")
        except Exception:
            matrix, evidence = {}, {}
        snapshot_payload = {
            "id": snap[0],
            "emitted_at": snap[1],
            "window_days": snap[2],
            "bucket_hours": snap[3],
            "cell_count": snap[4],
            "matrix": matrix,
            "formula_ref": snap[6],
            "evidence": evidence,
        }

    try:
        metadata = json.loads(run[9] or "{}")
    except Exception:
        metadata = {}

    return jsonify(_wrap({
        "run": {
            "id": run[0],
            "emitted_at": run[1],
            "matrix_snapshot_id": run[2],
            "algorithm": run[3],
            "eps": run[4],
            "min_samples": run[5],
            "n_clusters": run[6],
            "n_noise": run[7],
            "formula_ref": run[8],
            "metadata": metadata,
        },
        "clusters": cluster_list,
        "snapshot": snapshot_payload,
    }))


# ── Internal helpers ─────────────────────────────────────────────────────────


def _wrap_error(status: int, error: str, **extra):
    body, status = build_error(status, error, **extra)
    return jsonify(body), status
