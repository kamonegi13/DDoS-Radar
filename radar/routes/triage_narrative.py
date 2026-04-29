"""LLM-augmented triage narrative endpoint (commit K).

When the 'triage_narrative' Feature Hub key is ON or SHADOW, the
front-end posts triage item descriptors here. We call the LLM with a
strict JSON-output prompt and return one polished sentence per item
to display in the Alert Lane.

Hardening:
  - Feature Hub state gate (is_enabled or is_shadow). When OFF, the
    endpoint returns 503 immediately without an LLM call.
  - Per-item input fields are bounded (type, state, scenario, why
    list); raw LLM is never given user-controlled HTML.
  - LLM response shape validated as JSON {narrative: str ≤ 240 chars}.
    Parse failure → falls back to caller's deterministic narrative.
  - llm_call_log captures prompt sha256 (NP6).
  - SHADOW state: LLM still runs, response is logged, but the
    response body sets `state='shadow'` so the JS can record it
    without surfacing.

The endpoint is intentionally batch-friendly: one POST with N items
keeps round-trips low. Cap of 8 items per request prevents an
unbounded LLM bill on a misfired client.
"""
from __future__ import annotations

import json as _json
import logging

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from radar import llm_features
from radar.routes import _require_analyst, bp
from radar.routes.calibration_v2 import _wrap, _wrap_error
from radar.routes.conclusions_v2 import _v2_enabled_or_503

log = logging.getLogger("radar.routes.triage_narrative")


_MAX_BATCH = 8
_PROMPT_VERSION = "triage_narrative/v1"
_CALLER = "triage_narrative"

_SYSTEM_PROMPT = (
    "You are an OSINT triage analyst assistant. Given a single triage "
    "item, write ONE concise sentence in plain English (≤ 220 characters) "
    "explaining why an analyst should look at it now. Focus on novelty, "
    "confidence trajectory, and elapsed time since last review. NEVER "
    "invent facts not present in the input. NEVER claim a country acted "
    "or did anything; describe only what was observed and ranked. "
    "Respond ONLY with valid JSON."
)


def _build_prompt(item: dict) -> str:
    kind = str(item.get("kindLabel", "EVENT"))[:80]
    scenario = str(item.get("scenario_id", "") or "")[:60]
    confidence = item.get("confidence", None)
    age_minutes = item.get("age_minutes", None)
    rank = item.get("rank", None)
    why = item.get("why", [])
    if not isinstance(why, list):
        why = []
    why_clean = [str(w)[:120] for w in why[:5]]

    lines = [
        "Triage item:",
        f"- type: {kind}",
    ]
    if scenario:
        lines.append(f"- scenario: {scenario}")
    if isinstance(confidence, (int, float)):
        lines.append(f"- confidence: {round(confidence * 100)}%")
    if isinstance(age_minutes, (int, float)):
        lines.append(f"- observed: {int(age_minutes)} minutes ago")
    if isinstance(rank, int):
        lines.append(f"- ranked #{rank}")
    if why_clean:
        lines.append("- ranking reasons: " + "; ".join(why_clean))

    lines.append("")
    lines.append("Respond with JSON: {\"narrative\": \"<one sentence>\"}")
    return "\n".join(lines)


def _validate_narrative(text: str) -> str:
    """Bound the narrative to a sane length and strip control chars.
    Returns "" if the input fails validation."""
    if not isinstance(text, str):
        return ""
    out = text.strip()
    if not out:
        return ""
    # Strip newlines / control chars that would break the single-line
    # display contract.
    out = out.replace("\r", " ").replace("\n", " ")
    out = "".join(ch for ch in out if ch >= " " or ch == "\t")
    out = out[:240]
    return out.strip()


@bp.route("/api/v2/triage/narrate", methods=["POST"])
@jwt_required()
def v2_triage_narrate():
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    auth = _require_analyst()
    if auth is not None:
        return auth

    if not llm_features.is_active("triage_narrative"):
        # Feature is OFF — bail without an LLM call.
        body, status = ({
            "api_version": "2.0",
            "error": "triage_narrative_disabled",
            "feature_state": "off",
        }, 503)
        return jsonify(body), status

    feature_state = ("on" if llm_features.is_enabled("triage_narrative")
                     else "shadow")
    payload = request.get_json(silent=True) or {}
    items = payload.get("items") or []
    if not isinstance(items, list) or not items:
        return _wrap_error(400, "items_required")
    if len(items) > _MAX_BATCH:
        items = items[:_MAX_BATCH]

    try:
        from radar.llm_client import llm_analyze_json
    except Exception as exc:
        return _wrap_error(500, "llm_client_unavailable", detail=str(exc)[:200])

    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict) or "id" not in item:
            continue
        prompt = _build_prompt(item)
        result = llm_analyze_json(
            system=_SYSTEM_PROMPT,
            prompt=prompt,
            temperature=0.2,
            max_tokens=180,
            caller=_CALLER,
        )
        if not result.get("ok"):
            out.append({
                "id": item["id"],
                "narrative": "",
                "ok": False,
                "error": str(result.get("error", "llm_failed"))[:120],
            })
            continue
        narrative = _validate_narrative(
            (result.get("data") or {}).get("narrative", "")
        )
        if not narrative:
            out.append({
                "id": item["id"],
                "narrative": "",
                "ok": False,
                "error": "empty_or_invalid_response",
            })
            continue
        out.append({
            "id": item["id"],
            "narrative": narrative,
            "ok": True,
            "prompt_version": _PROMPT_VERSION,
        })

    return jsonify(_wrap({
        "feature_state": feature_state,
        "results": out,
        "n_items": len(items),
        "n_ok": sum(1 for r in out if r.get("ok")),
    }))
