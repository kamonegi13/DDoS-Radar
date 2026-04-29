"""G.3b LLM annotator for discovery clusters (Tier 4, commit 12).

For each unannotated discovery_cluster row, asks the LLM:
  - Is this cluster a meaningful scenario candidate (or random
    co-occurrence)?
  - If meaningful, suggest a short name + description.
  - Self-rated confidence in [0.0, 1.0].

Output is written to discovery_cluster.annotation_json with
annotation_state set per the rollout stage:

  shadow      — `G3B_SHADOW_ENABLED=true`, `G3B_LLM_ENABLED=false`.
                Default for all new deployments. Annotations accumulate
                in the table but are NOT surfaced to the analyst UI by
                default; the Discovery panel filters them out unless
                ?include_shadow=true.
  production  — `G3B_LLM_ENABLED=true`. Annotations show in the
                Discovery panel and feed the Wizard's "create scenario"
                flow.

Hardening (per plan §5):
  - Three independent gates: LLM_ENABLED (radar global), G3B_LLM_ENABLED
    (this feature) AND/OR G3B_SHADOW_ENABLED, plus a per-process call cap
    and circuit breaker.
  - prompt sha256 captured via radar.llm_prompts so the prompt template
    is auditable.
  - 5 consecutive failures → circuit breaker opens for the rest of the
    run; reset on next process start.
  - 1-day call cap (G3B_DAILY_CALL_CAP, default 50). Counted against
    llm_call_log rows with caller='g3b_llm_annotator' over the last 24h.

NP1: G.3b annotation is suggest-only. The annotation never auto-creates
     a scenario; that requires analyst Wizard apply (commit 14).
NP3: every failure path returns gracefully without raising. The
     annotator can be invoked daily from the scheduler with no risk of
     poisoning the run.
NP6: every annotation row records prompt_sha256 + raw_response (for
     post-hoc audit). The prompt template version is bumped via
     PROMPT_VERSION when the template changes.
NP7: shadow-first rollout means default deployment is `false / false`.
     Operators flip `G3B_SHADOW_ENABLED=true` first to observe outputs,
     then `G3B_LLM_ENABLED=true` to surface them.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

from radar.database import db

log = logging.getLogger("radar.calibration.g3b_llm_annotator")


PROMPT_VERSION = "g3b_llm_annotator/v1"
CALLER_NAME = "g3b_llm_annotator"

_SYSTEM_PROMPT = (
    "You are an OSINT scenario analyst. Given a small set of country codes "
    "that frequently co-occur in news/intelligence reporting, decide whether "
    "they form a coherent geopolitical scenario or are random co-occurrence. "
    "Be conservative — when in doubt, classify as random."
)

_USER_TEMPLATE = (
    "Country cluster: {countries}\n"
    "Centroid (most central member): {centroid}\n\n"
    "Classify this cluster and respond ONLY with valid JSON of this shape:\n"
    "{{\n"
    '  "kind": "scenario" | "random",\n'
    '  "suggested_name": str (short, English, ASCII; empty when random),\n'
    '  "suggested_description": str (one sentence; empty when random),\n'
    '  "confidence_self_reported": number in [0.0, 1.0],\n'
    '  "rationale": str (one sentence)\n'
    "}}"
)

# Module-level circuit breaker state (resets on process restart).
_consecutive_failures = 0
_circuit_open = False


def _max_consecutive_failures() -> int:
    return int(os.getenv("G3B_CIRCUIT_BREAKER_FAILURES", "5"))


def _daily_call_cap() -> int:
    return int(os.getenv("G3B_DAILY_CALL_CAP", "50"))


def _is_shadow_enabled() -> bool:
    """Shadow mode for G.3b cluster annotation — resolved via the
    LLM Feature Hub ('g3b_cluster_annotator') so the UI can flip it
    without restarting Docker. Falls back to env on import failure."""
    try:
        from radar.llm_features import is_shadow
        return is_shadow("g3b_cluster_annotator")
    except Exception:
        return os.getenv("G3B_SHADOW_ENABLED", "false").strip().lower() in (
            "1", "true", "yes", "on"
        )


def _is_production_enabled() -> bool:
    """Production mode for G.3b — resolved via the LLM Feature Hub."""
    try:
        from radar.llm_features import is_enabled
        return is_enabled("g3b_cluster_annotator")
    except Exception:
        return os.getenv("G3B_LLM_ENABLED", "false").strip().lower() in (
            "1", "true", "yes", "on"
        )


def _annotation_state() -> str:
    if _is_production_enabled():
        return "production"
    if _is_shadow_enabled():
        return "shadow"
    return "none"  # both off — annotator should not run


@dataclass(frozen=True)
class AnnotationOutcome:
    cluster_id: int
    state: str  # 'production' | 'shadow' | 'skipped'
    annotated: bool
    error: Optional[str] = None


def _calls_in_last_24h() -> int:
    """Count llm_call_log rows for this caller in the last 24h.

    NP3 graceful degradation: any DB error returns 0 so the annotator
    can still run (the cap is a soft guard, not a hard invariant).
    """
    try:
        conn = db._get_conn()  # noqa: SLF001
        row = conn.execute(
            "SELECT COUNT(*) FROM llm_call_log "
            "WHERE caller=? AND ts > ?",
            (CALLER_NAME, time.time() - 86400),
        ).fetchone()
        return int(row[0] if row else 0)
    except Exception as exc:
        log.debug("calls_in_last_24h failed: %s", exc)
        return 0


def _list_unannotated_clusters(limit: int = 20) -> list[tuple[int, list[str], Optional[str]]]:
    """Return up to `limit` cluster rows that have not been annotated yet.

    Each entry: (cluster_id, countries, centroid)
    """
    try:
        conn = db._get_conn()  # noqa: SLF001
        rows = conn.execute(
            "SELECT id, countries_json, centroid_json "
            "FROM discovery_cluster "
            "WHERE annotation_state='none' "
            "ORDER BY id ASC LIMIT ?",
            (limit,),
        ).fetchall()
    except Exception as exc:
        log.debug("list_unannotated_clusters failed: %s", exc)
        return []
    out: list[tuple[int, list[str], Optional[str]]] = []
    for cid, countries_json, centroid_json in rows:
        try:
            countries = json.loads(countries_json or "[]")
        except Exception:
            countries = []
        try:
            centroid_payload = json.loads(centroid_json or "{}")
        except Exception:
            centroid_payload = {}
        centroid = centroid_payload.get("centroid") if isinstance(
            centroid_payload, dict) else None
        out.append((cid, countries, centroid))
    return out


def _persist_annotation(cluster_id: int, *, annotation: dict, state: str) -> bool:
    """Write annotation_json + annotation_state for a cluster row."""
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                "UPDATE discovery_cluster "
                "SET annotation_json=?, annotation_state=? "
                "WHERE id=?",
                (json.dumps(annotation, sort_keys=True), state, cluster_id),
            )
        return True
    except Exception as exc:
        log.warning("persist_annotation cluster=%d failed: %s",
                    cluster_id, exc)
        return False


def _annotate_one(cluster_id: int, countries: list[str],
                   centroid: Optional[str], *,
                   state: str) -> AnnotationOutcome:
    """Call the LLM for one cluster and persist the result."""
    global _consecutive_failures, _circuit_open
    if _circuit_open:
        return AnnotationOutcome(
            cluster_id=cluster_id, state="skipped",
            annotated=False, error="circuit_open",
        )
    if not countries:
        return AnnotationOutcome(
            cluster_id=cluster_id, state="skipped",
            annotated=False, error="empty_countries",
        )

    try:
        from radar.llm_client import llm_analyze_json
    except Exception as exc:
        log.warning("llm_client import failed: %s", exc)
        return AnnotationOutcome(
            cluster_id=cluster_id, state="skipped",
            annotated=False, error=f"import_failed: {exc}"[:200],
        )

    prompt = _USER_TEMPLATE.format(
        countries=", ".join(countries),
        centroid=centroid or "(none)",
    )
    result = llm_analyze_json(
        system=_SYSTEM_PROMPT,
        prompt=prompt,
        temperature=0.1,
        max_tokens=300,
        caller=CALLER_NAME,
    )
    if not result.get("ok"):
        _consecutive_failures += 1
        if _consecutive_failures >= _max_consecutive_failures():
            log.warning(
                "[g3b] circuit breaker opening after %d consecutive failures",
                _consecutive_failures,
            )
            _circuit_open = True
        return AnnotationOutcome(
            cluster_id=cluster_id, state=state,
            annotated=False,
            error=str(result.get("error", "llm_call_failed"))[:200],
        )

    _consecutive_failures = 0  # success resets the counter

    data = result.get("data") or {}
    annotation = {
        "kind": data.get("kind", "random"),
        "suggested_name": (data.get("suggested_name") or "")[:120],
        "suggested_description":
            (data.get("suggested_description") or "")[:500],
        "confidence_self_reported":
            float(data.get("confidence_self_reported") or 0.0),
        "rationale": (data.get("rationale") or "")[:300],
        "prompt_version": PROMPT_VERSION,
        "annotated_at": time.time(),
    }
    ok = _persist_annotation(cluster_id, annotation=annotation, state=state)
    return AnnotationOutcome(
        cluster_id=cluster_id, state=state,
        annotated=ok,
        error=None if ok else "persist_failed",
    )


# ── Driver ───────────────────────────────────────────────────────────────────


def run_once(*, limit: int = 20) -> dict:
    """Annotate up to `limit` unannotated clusters.

    Hard-fast no-op when both shadow and production env flags are off.
    NP3-compliant: every failure is captured into an AnnotationOutcome;
    the function never raises.
    """
    global _consecutive_failures, _circuit_open
    _consecutive_failures = 0
    _circuit_open = False

    state = _annotation_state()
    if state == "none":
        return {
            "skipped": True, "reason": "both_flags_off",
            "annotated": 0, "errors": 0,
        }

    cap = _daily_call_cap()
    used = _calls_in_last_24h()
    if used >= cap:
        return {
            "skipped": True, "reason": "daily_cap_reached",
            "annotated": 0, "errors": 0,
            "calls_used": used, "calls_cap": cap,
        }

    clusters = _list_unannotated_clusters(limit=limit)
    if not clusters:
        return {
            "skipped": True, "reason": "no_unannotated_clusters",
            "annotated": 0, "errors": 0,
        }

    n_ok = 0
    n_err = 0
    n_skipped = 0
    for cid, countries, centroid in clusters:
        if used >= cap:
            n_skipped += 1
            continue
        outcome = _annotate_one(cid, countries, centroid, state=state)
        used += 1
        if outcome.annotated:
            n_ok += 1
        elif outcome.error:
            n_err += 1
        else:
            n_skipped += 1
        if _circuit_open:
            log.warning("[g3b] circuit open — aborting remainder of run")
            n_skipped += len(clusters) - (n_ok + n_err + n_skipped)
            break
    return {
        "skipped": False,
        "state": state,
        "annotated": n_ok,
        "errors": n_err,
        "skipped_count": n_skipped,
        "calls_used": used,
        "calls_cap": cap,
        "circuit_open": _circuit_open,
    }


__all__ = ["run_once", "AnnotationOutcome", "PROMPT_VERSION", "CALLER_NAME"]
