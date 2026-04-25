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

from radar.conclusions.api import (
    API_VERSION,
    build_envelope,
    build_unavailable,
)
from radar.conclusions.base import ConclusionType
from radar.conclusions.persistence import (
    get_conclusion_by_id,
    latest_conclusion,
)
from radar.routes import bp


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
        return jsonify({
            "api_version": API_VERSION,
            "error": "v2 API not enabled",
            "detail": "Set V2_API_ENABLED=true to opt in (Phase 1 read-only).",
        }), 503
    return None


def _parse_conclusion_type(raw: str):
    """Parse a path/query value into a ConclusionType, or return None on miss."""
    try:
        return ConclusionType(raw)
    except ValueError:
        return None


@bp.route("/api/v2/scenarios/<scenario_id>/conclusions", methods=["GET"])
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
def v2_scenario_conclusion_single(scenario_id: str, conclusion_type: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    ct = _parse_conclusion_type(conclusion_type)
    if ct is None:
        return jsonify({
            "api_version": API_VERSION,
            "error": "unknown conclusion_type",
            "detail": f"valid: {[t.value for t in _ALL_TYPES]}",
        }), 400

    from radar.database import db
    c = latest_conclusion(db, scenario_id, ct)
    if c is None:
        return jsonify(build_unavailable(scenario_id, ct))
    return jsonify(build_envelope(scenario_id, [c]))


@bp.route("/api/v2/conclusions/<conclusion_id>", methods=["GET"])
def v2_conclusion_by_id(conclusion_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db
    c = get_conclusion_by_id(db, conclusion_id)
    if c is None:
        return jsonify({
            "api_version": API_VERSION,
            "error": "conclusion not found",
            "conclusion_id": conclusion_id,
        }), 404
    return jsonify(build_envelope(c.scenario_id, [c]))


@bp.route("/api/v2/conclusions/<conclusion_id>/audit_trace", methods=["GET"])
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
        return jsonify({
            "api_version": API_VERSION,
            "error": "conclusion not found",
            "conclusion_id": conclusion_id,
        }), 404

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


def _disclaimer() -> str:
    from radar import config
    return config.V2_NP7_DISCLAIMER


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
