"""v2 API skeleton — read-only access to the conclusions ledger.

Phase 1 scope (per docs/design/v2-phase1-handoff.md):
  - GET /api/v2/scenarios/<id>/conclusions             — bundle of latest 5 types
  - GET /api/v2/scenarios/<id>/conclusions/<type>      — single domain
  - GET /api/v2/conclusions/<conclusion_id>            — one row by id
  - GET /api/v2/conclusions/<conclusion_id>/audit_trace — formula + sources +
                                                          LLM prompt full text

All endpoints are gated behind `config.V2_API_ENABLED`. When the flag is off,
the routes return 503 so v1 clients aren't tempted to consume v2 prematurely.

NP6 (audit_trace) and NP7 (envelope-level disclaimer) are enforced here
rather than at the dataclass level so that `not_enabled` / `not_found`
responses still carry the disclaimer.
"""

from __future__ import annotations

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from radar.conclusions.api import (
    API_VERSION,
    build_envelope,
    build_error,
    build_unavailable,
)
from radar.conclusions.base import ConclusionType
from radar.conclusions.markdown import render_scenario_markdown
from radar.conclusions.persistence import (
    get_conclusion_by_id,
    latest_conclusion,
)
from radar.routes import _require_admin, _require_analyst, _safe_int, bp


_ALL_TYPES = (
    ConclusionType.THREAT_LEVEL,
    ConclusionType.TREND,
    ConclusionType.PER_DOMAIN,
    ConclusionType.ANOMALY,
    ConclusionType.ATTACK_MODE,
)


def _v2_enabled_or_503():
    """Guard helper. Returns a Flask response if the flag is off, else None."""
    from radar import config
    if not config.V2_API_ENABLED:
        body, status = build_error(
            503,
            "v2 API not enabled",
            detail="Set V2_API_ENABLED=true to opt in (Phase 1 read-only).",
        )
        return jsonify(body), status
    return None


def _parse_conclusion_type(raw: str):
    """Parse a path/query value into a ConclusionType, or return None on miss."""
    try:
        return ConclusionType(raw)
    except ValueError:
        return None


@bp.route("/api/v2/scenarios/<scenario_id>/conclusions", methods=["GET"])
@jwt_required()
def v2_scenario_conclusions(scenario_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db

    conclusions = []
    for ct in _ALL_TYPES:
        c = latest_conclusion(db, scenario_id, ct)
        if c is not None:
            conclusions.append(c)

    if not conclusions:
        return jsonify(build_unavailable(scenario_id, ConclusionType.THREAT_LEVEL,
                                         detail="no conclusions for this scenario yet"))
    return jsonify(build_envelope(scenario_id, conclusions))


@bp.route("/api/v2/scenarios/<scenario_id>/conclusions/<conclusion_type>",
          methods=["GET"])
@jwt_required()
def v2_scenario_conclusion_single(scenario_id: str, conclusion_type: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    ct = _parse_conclusion_type(conclusion_type)
    if ct is None:
        body, status = build_error(
            400,
            "unknown conclusion_type",
            detail=f"valid: {[t.value for t in _ALL_TYPES]}",
        )
        return jsonify(body), status

    from radar.database import db
    c = latest_conclusion(db, scenario_id, ct)
    if c is None:
        return jsonify(build_unavailable(scenario_id, ct))
    return jsonify(build_envelope(scenario_id, [c]))


@bp.route("/api/v2/conclusions/<conclusion_id>", methods=["GET"])
@jwt_required()
def v2_conclusion_by_id(conclusion_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db
    c = get_conclusion_by_id(db, conclusion_id)
    if c is None:
        body, status = build_error(
            404, "conclusion not found", conclusion_id=conclusion_id,
        )
        return jsonify(body), status
    return jsonify(build_envelope(c.scenario_id, [c]))


@bp.route("/api/v2/conclusions/<conclusion_id>/audit_trace", methods=["GET"])
@jwt_required()
def v2_conclusion_audit_trace(conclusion_id: str):
    """NP6 — return the full derivation: formula_ref, threshold_ref, source
    URLs, calibration status, and the resolved LLM prompt text (system + user)
    if a sha256 is linked.

    Phase 1 skeleton: ledger row + LLM prompt full-text resolution. We do
    NOT yet resolve formula_ref to source code (that's Phase 3 — would
    require a code-snippet store keyed by git rev).
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db
    c = get_conclusion_by_id(db, conclusion_id)
    if c is None:
        body, status = build_error(
            404, "conclusion not found", conclusion_id=conclusion_id,
        )
        return jsonify(body), status

    trace = {
        "api_version": API_VERSION,
        "conclusion_id": c.id,
        "scenario_id": c.scenario_id,
        "conclusion_type": c.conclusion_type.value,
        "observed_at": c.observed_at,
        "final_judgment_disclaimer": _disclaimer(),
        "formula_ref": c.formula_ref,
        "threshold_ref": dict(c.threshold_ref),
        "source_urls": list(c.source_urls),
        "calibration_status": dict(c.calibration_status),
        "metadata": dict(c.metadata),
    }
    if c.llm_prompt_sha256:
        trace["llm_prompt"] = _resolve_llm_prompt(db, c.llm_prompt_sha256)
    else:
        trace["llm_prompt"] = None
    return jsonify(trace)


@bp.route("/api/v2/scenarios/<scenario_id>/conclusions.md", methods=["GET"])
@jwt_required()
def v2_scenario_conclusions_markdown(scenario_id: str):
    """Phase 3 — single-file Markdown export of a scenario's latest conclusions.

    Pure text/markdown response (not the JSON envelope) so analysts can pipe
    the body straight into a wiki, ticket, or local file. NP6 disclosure is
    preserved: when ?include_audit=1 each section embeds the resolved LLM
    prompt full text via an expandable <details> block.

    NP7 disclaimer is rendered once at the top as a blockquote — the same
    string shipped in JSON envelopes' final_judgment_disclaimer field.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db

    conclusions = []
    for ct in _ALL_TYPES:
        c = latest_conclusion(db, scenario_id, ct)
        if c is not None:
            conclusions.append(c)

    audit_traces = None
    include_audit = request.args.get("include_audit", "0").lower() in (
        "1", "true", "yes",
    )
    if include_audit:
        audit_traces = {}
        for c in conclusions:
            if c.llm_prompt_sha256:
                audit_traces[c.id] = {
                    "llm_prompt": _resolve_llm_prompt(db, c.llm_prompt_sha256),
                }

    body = render_scenario_markdown(
        scenario_id,
        conclusions,
        disclaimer=_disclaimer(),
        api_version=API_VERSION,
        audit_traces=audit_traces,
    )
    filename = f"{scenario_id}-conclusions.md"
    return (
        body,
        200,
        {
            "Content-Type": "text/markdown; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


def _disclaimer() -> str:
    from radar import config
    return config.V2_NP7_DISCLAIMER


@bp.route("/api/v2/admin/conclusion_diff_stats", methods=["GET"])
def v2_conclusion_diff_stats():
    """Phase 1 priority 6 — rollout monitoring.

    Returns the diff_kind distribution over the last `?window_hours=` hours
    plus the most recent N divergence rows for analyst review. Used to gate
    the v2 default-on flip (ADR-V2-001).

    Analyst-only: this surface exposes raw v1/v2 mismatch detail.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err

    import time as _t
    from radar.database import db

    window_hours = _safe_int(request.args.get("window_hours"), 24,
                             min_val=1, max_val=24 * 30)
    limit = _safe_int(request.args.get("limit"), 50, min_val=1, max_val=500)
    since = _t.time() - window_hours * 3600

    conn = db._get_conn()  # noqa: SLF001
    counts_rows = conn.execute(
        "SELECT diff_kind, COUNT(*) AS n "
        "FROM conclusion_diff_log WHERE sampled_at >= ? "
        "GROUP BY diff_kind",
        (since,),
    ).fetchall()
    counts = {r["diff_kind"]: r["n"] for r in counts_rows}
    total = sum(counts.values())

    recent_rows = conn.execute(
        "SELECT sampled_at, scenario_id, conclusion_type, "
        "       v1_state, v2_state, v2_conclusion_id, diff_kind, metadata "
        "FROM conclusion_diff_log "
        "WHERE diff_kind = 'divergence' AND sampled_at >= ? "
        "ORDER BY sampled_at DESC LIMIT ?",
        (since, limit),
    ).fetchall()

    return jsonify({
        "api_version": API_VERSION,
        "window_hours": window_hours,
        "total_samples": total,
        "diff_kind_counts": counts,
        "match_rate": (counts.get("match", 0) / total) if total else None,
        "recent_divergences": [dict(r) for r in recent_rows],
    })


@bp.route("/api/v2/admin/shadow_write_metrics", methods=["GET"])
def v2_shadow_write_metrics():
    """Mode B observability — process-local counters for the 5 shadow-write
    hooks in compute_scenario_score.

    Unlike most /api/v2 routes this one is NOT gated by V2_API_ENABLED. The
    operator needs to read it during the Shadow phase precisely *because*
    the public v2 API is still off — otherwise there is no way to verify
    that V2_CONCLUSION_LEDGER_ENABLED=true is actually producing rows.
    Admin auth is still required so the surface stays internal.

    Counters are reset on process restart; `started_at` / `uptime_sec` let
    the operator interpret whether a "0 successes" reading means "broken"
    or "just restarted, no scoring tick has run yet".
    """
    auth_err = _require_admin()
    if auth_err is not None:
        return auth_err

    from radar import config
    from radar.conclusions.shadow_metrics import snapshot

    snap = snapshot()
    return jsonify({
        "api_version": API_VERSION,
        "ledger_enabled": config.V2_CONCLUSION_LEDGER_ENABLED,
        "metrics": snap,
        "final_judgment_disclaimer": _disclaimer(),
    })


def _resolve_llm_prompt(db, sha256: str) -> dict:
    """Look up the full prompt text for an audit trace. Returns a dict with
    sha256, model, and the prompt body. If the row is missing (purged or
    flag was off when the call happened) returns sha256 + a missing flag.
    """
    from radar.llm_prompts import get_prompt
    row = get_prompt(db, sha256)
    if row is None:
        return {"sha256": sha256, "missing": True}
    return {
        "sha256": sha256,
        "model": row.get("model"),
        "temperature": row.get("temperature"),
        "prompt_text": row.get("prompt_text"),
        "first_seen_at": row.get("first_seen_at"),
        "last_seen_at": row.get("last_seen_at"),
        "use_count": row.get("use_count"),
    }
