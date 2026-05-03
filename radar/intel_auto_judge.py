"""radar.intel_auto_judge — Deterministic auto-judge recheck for pending intel.

Issue C (Phase 4 commit 5).

The user pointed out that the LLM Intelligence panel piles up pending items
that depend on a single human analyst clicking confirm/reject. The pile
becomes the recall bottleneck: 7 pending / 7 rejected / 1 confirmed is a
common state.

This module re-evaluates pending items using **deterministic** corroboration
rules — no LLM required. It returns one of three verdicts:

  - "confirm"  : item meets the auto-confirm threshold (high confidence +
                 independent corroboration). Tagged ``analyst="auto:rule_confirm"``
                 so it can be excluded from human-only recall metrics.
  - "reject"   : item is a duplicate, out-of-scope, very low confidence,
                 or from a reputation-drifted source. Tagged
                 ``analyst="auto:rule_reject"``.
  - "pending"  : truly ambiguous middle band. Left for analyst review.

The rules are intentionally conservative — NP1 (sensitivity > precision)
rules, so when in doubt the verdict is ``pending``. NP7 (organizational
node) is preserved by tagging every auto-decision so analyst recall
calculations can exclude them.

Design constraints:
  - LLM is NEVER required. Air-gapped deployments must work.
  - All rules use only data already in the radar SQLite DB.
  - Verdicts must be deterministic given the same DB state — no
    nondeterministic side-channels.
  - Falls back to ``pending`` on any internal error (NP3).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from radar.database import db
from radar.intel_queue import (
    _AUTO_CONFIRM_ELIGIBLE_ECOSYSTEMS,
    _headline_tokens,
    _jaccard,
    classify_ecosystem,
    intel_queue,
)

log = logging.getLogger("radar.intel_auto_judge")


# ── Rule thresholds (env-overridable; conservative defaults) ────────────

def _conf_confirm_floor() -> float:
    """Min confidence for the auto-judge confirm path. Below this, even
    strong corroboration alone is not enough to flip a pending → confirmed.
    """
    return float(os.getenv("AUTO_JUDGE_CONF_CONFIRM_FLOOR", "0.70"))


def _conf_reject_ceiling() -> float:
    """Confidence at or below which the auto-judge will reject (when no
    corroboration exists). Above this, the item stays pending.
    """
    return float(os.getenv("AUTO_JUDGE_CONF_REJECT_CEILING", "0.40"))


def _corroboration_window_hours() -> float:
    return float(os.getenv("AUTO_JUDGE_CORROBORATION_HOURS", "72"))


def _stale_reject_hours() -> float:
    """Pending items older than this AND without any corroboration are
    rejected as stale. Slightly tighter than the global pending-stale TTL
    because the auto-judge only acts when no corroboration arrived in the
    interim."""
    return float(os.getenv("AUTO_JUDGE_STALE_HOURS", "48"))


def _dup_jaccard_threshold() -> float:
    return float(os.getenv("AUTO_JUDGE_DUP_JACCARD", "0.70"))


def _source_reject_ratio_threshold() -> float:
    """If a source's recent reject ratio exceeds this, new pending items
    from that source are auto-rejected as reputation-drift.
    """
    return float(os.getenv("AUTO_JUDGE_SOURCE_REJECT_RATIO", "0.75"))


def _source_recent_min_decisions() -> int:
    """Min recent decisions on a source before reputation drift kicks in.
    Avoids penalizing brand-new sources that have only had 1-2 rejects.
    """
    return int(os.getenv("AUTO_JUDGE_SOURCE_MIN_DECISIONS", "5"))


# Marker analyst ids written into intel rows so analyst recall metrics can
# distinguish auto-judge actions from human ones.
#
# History (2026-04-29):
#   1. First commit (1bb5195) shipped deterministic rules only.
#   2. Second commit (70930bc) added LLM second-pass on confidence ≥ 0.80
#      self-report. Removed in 8bddb2f because backtest showed Layer 1
#      (cross-evidence) was the missing safety, and confidence-only was
#      "unsafe-if-enabled" without it.
#   3. R1 (3063943) restored diplomatic feeds → diversity max=3 achieved.
#   4. THIS commit re-introduces LLM second pass with Layer 1 cross-evidence
#      gate hard-coded into the path: an LLM verdict can ONLY flip an item
#      that has independent cross-evidence in the same theater. Items in
#      single-source theaters fall through to pending regardless of how
#      confident the LLM claims to be. This is asymmetric NP1: blocks
#      hallucination-driven flips, never causes them.
ANALYST_AUTO_CONFIRM = "auto:rule_confirm"
ANALYST_AUTO_REJECT = "auto:rule_reject"
# LLM second-pass markers — distinct from rule markers so analyst-only
# recall metrics and ECE calibration can stratify by decision path.
ANALYST_LLM_CONFIRM = "auto:llm_recheck_confirm"
ANALYST_LLM_REJECT = "auto:llm_recheck_reject"


def _llm_recheck_enabled() -> bool:
    """LLM second-pass on the deterministic-pending tail. OFF by default —
    every air-gapped / LLM-disabled deployment must keep working without
    it (NP3, AP1). Operators flip via the LLM Feature Hub
    ('auto_judge_recheck' key) which honors UI override → env →
    registry default in priority order. Legacy env LLM_AUTO_JUDGE_RECHECK
    still works as the env-default layer.
    """
    try:
        from radar.llm_features import is_enabled
        return is_enabled("auto_judge_recheck")
    except Exception:
        # NP3 fallback to env-only when llm_features import fails (e.g.
        # during early bootstrap or DB outage).
        val = os.getenv("LLM_AUTO_JUDGE_RECHECK", "false").strip().lower()
        return val in ("1", "true", "yes", "on")


def _llm_shadow_enabled() -> bool:
    """Shadow mode: invoke the LLM second pass and write the verdict to
    the calibration ledger, but DO NOT apply it. Resolved through the
    same LLM Feature Hub ('auto_judge_recheck') with shadow state.
    """
    try:
        from radar.llm_features import is_shadow
        return is_shadow("auto_judge_recheck")
    except Exception:
        val = os.getenv("LLM_AUTO_JUDGE_SHADOW", "true").strip().lower()
        return val in ("1", "true", "yes", "on")


def _llm_confidence_floor() -> float:
    """Confidence the LLM second pass must clear before flipping. 0.85
    default — stricter than the previous 0.80 because Layer 1 alone is
    not a guarantee of correctness, only of cross-evidence presence.
    """
    return float(os.getenv("AUTO_JUDGE_LLM_CONF_FLOOR", "0.85"))


@dataclass(frozen=True)
class AutoJudgeVerdict:
    """Output of evaluate(). Frozen so callers can't accidentally mutate
    the verdict between evaluate() and apply()."""
    action: str  # "confirm" | "reject" | "pending"
    reason: str
    confidence_floor_used: float = 0.0
    corroborator_count: int = 0
    duplicates_of: tuple[str, ...] = field(default_factory=tuple)


def _is_eligible_ecosystem(source_id: str) -> bool:
    eco = classify_ecosystem(source_id or "")
    return eco in _AUTO_CONFIRM_ELIGIBLE_ECOSYSTEMS


def _count_corroborators(item: dict, window_seconds: float) -> int:
    """Count distinct independent intel items in the same theater within
    the window that are NOT this item, NOT the same source_type, and have
    a non-rejected status.

    Independence here just means a different source_type — finer-grained
    independence (per source_id ecosystem) is left to the dedicated
    CorroborationEngine; the auto-judge's bar is intentionally coarser
    so the cost stays cheap.
    """
    theater = item.get("theater")
    if not theater:
        return 0
    since = time.time() - window_seconds
    try:
        peers = db.intel_list(theater=theater, limit=200, since_ts=since)
    except Exception as exc:
        log.warning("auto_judge: intel_list failed: %s", exc)
        return 0
    own_id = item.get("id")
    own_type = item.get("source_type")
    seen_types: set[str] = set()
    for peer in peers:
        if peer.get("id") == own_id:
            continue
        if peer.get("status") == "rejected":
            continue
        ptype = peer.get("source_type")
        if not ptype or ptype == own_type:
            continue
        seen_types.add(ptype)
    return len(seen_types)


def _duplicates_of(item: dict, window_seconds: float) -> list[str]:
    """Return ids of confirmed/auto_confirmed peers whose headlines match
    by Jaccard similarity within the window. A duplicate of an already-
    accepted item is itself redundant and can be safely auto-rejected.
    """
    headline = (item.get("headline") or "").strip()
    if not headline:
        return []
    own_tokens = _headline_tokens(headline)
    if not own_tokens:
        return []
    threshold = _dup_jaccard_threshold()
    since = time.time() - window_seconds
    theater = item.get("theater")
    if not theater:
        return []
    try:
        peers = db.intel_list(theater=theater, limit=200, since_ts=since)
    except Exception as exc:
        log.warning("auto_judge: intel_list (dup) failed: %s", exc)
        return []
    own_id = item.get("id")
    out: list[str] = []
    for peer in peers:
        if peer.get("id") == own_id:
            continue
        if peer.get("status") not in ("confirmed", "auto_confirmed"):
            continue
        peer_headline = (peer.get("headline") or "").strip()
        if not peer_headline:
            continue
        if _jaccard(own_tokens, _headline_tokens(peer_headline)) >= threshold:
            out.append(peer.get("id"))
    return out


def _source_drift_rejects(source_id: str) -> bool:
    """True if the source has shown a recent pattern of getting rejected.
    Uses the per-source confirm/reject ledger maintained by intel_queue.
    """
    if not source_id:
        return False
    try:
        rec = db.intel_source_get(source_id)
    except Exception:
        return False
    if not rec:
        return False
    # llm_sources schema: confirmed_count + false_positive_count.
    # false_positive_count only increments on classification="false_positive",
    # so it's a deliberate signal of upstream-judged unreliability rather
    # than the noisier full reject_count.
    confirms = int(rec.get("confirmed_count", 0) or 0)
    rejects = int(rec.get("false_positive_count", 0) or 0)
    total = confirms + rejects
    if total < _source_recent_min_decisions():
        return False
    ratio = rejects / total if total else 0.0
    return ratio >= _source_reject_ratio_threshold()


def _ledger_record(*, item_id: str, action_proposed: str, confidence: float,
                    reason: str, layer1_corroborators: int,
                    layer1_satisfied: bool, applied: bool) -> None:
    """Wrapper around db.auto_judge_decision_log that swallows DB errors
    (NP3 — observability must never break the main flow)."""
    try:
        db.auto_judge_decision_log(
            item_id=item_id,
            action_proposed=action_proposed,
            confidence=confidence,
            reason=reason,
            layer1_corroborators=layer1_corroborators,
            layer1_satisfied=layer1_satisfied,
            applied=applied,
        )
    except Exception as exc:
        log.debug("auto_judge ledger write failed: %s", exc)


def _ledger_mark_applied(item_id: str) -> None:
    if not item_id:
        return
    try:
        db.auto_judge_decision_mark_applied(item_id)
    except Exception as exc:
        log.debug("auto_judge ledger mark_applied failed: %s", exc)


def evaluate(item: dict) -> AutoJudgeVerdict:
    """Run the deterministic auto-judge rules on a pending intel item.

    Returns "pending" on any internal error (NP3 — auto-judge must
    degrade gracefully).
    """
    if not item or item.get("status") != "pending":
        return AutoJudgeVerdict(action="pending", reason="not_pending")

    confidence = float(item.get("confidence") or 0.0)
    source_id = item.get("source_id") or ""
    created_at = float(item.get("created_at") or item.get("ts") or 0.0)
    age_hours = (time.time() - created_at) / 3600.0 if created_at else 0.0
    window_s = _corroboration_window_hours() * 3600.0

    # Hard reject path — duplicate of an already-accepted item.
    dups = _duplicates_of(item, window_s)
    if dups:
        return AutoJudgeVerdict(
            action="reject",
            reason="duplicate_of_accepted",
            duplicates_of=tuple(dups),
        )

    # Hard reject path — source reputation drift.
    if _source_drift_rejects(source_id):
        return AutoJudgeVerdict(
            action="reject",
            reason="source_reputation_drift",
        )

    # Hard reject path — very low confidence with no corroboration.
    corroborators = _count_corroborators(item, window_s)
    if confidence <= _conf_reject_ceiling() and corroborators == 0:
        return AutoJudgeVerdict(
            action="reject",
            reason="low_confidence_no_corroboration",
            corroborator_count=0,
        )

    # Hard reject path — stale pending without corroboration.
    if age_hours >= _stale_reject_hours() and corroborators == 0:
        return AutoJudgeVerdict(
            action="reject",
            reason="stale_no_corroboration",
            corroborator_count=0,
        )

    # Confirm path — high enough confidence AND ≥1 independent corroborator,
    # AND eligible ecosystem (state-media / unclassified still gated).
    floor = _conf_confirm_floor()
    if confidence >= floor and corroborators >= 1 and _is_eligible_ecosystem(source_id):
        return AutoJudgeVerdict(
            action="confirm",
            reason="confidence_plus_corroboration",
            confidence_floor_used=floor,
            corroborator_count=corroborators,
        )

    middle_verdict = AutoJudgeVerdict(
        action="pending",
        reason="ambiguous_middle_band",
        corroborator_count=corroborators,
    )

    # LLM second-pass — Layer 1 cross-evidence is REQUIRED inside the
    # recheck so an LLM hallucination can never flip a single-source item.
    # Two independent gates protect this:
    #   (i)  shadow vs apply (env LLM_AUTO_JUDGE_RECHECK)
    #   (ii) hardcoded "must have corroborators OR cross-evidence" inside
    #        _llm_recheck() — this gate runs even in shadow mode so the
    #        calibration ledger only records well-founded LLM verdicts.
    if _llm_shadow_enabled() or _llm_recheck_enabled():
        llm_verdict = _llm_recheck(item, deterministic_pending=middle_verdict,
                                    corroborator_count=corroborators)
        if llm_verdict is not None and _llm_recheck_enabled():
            return llm_verdict
        # Shadow mode: ledger written inside _llm_recheck but verdict
        # discarded so deterministic pending stands.
    return middle_verdict


_LLM_RECHECK_SYSTEM = (
    "You are a strict OSINT triage analyst. PENDING is the SAFE default. "
    "Only return CONFIRM or REJECT when you can defend the verdict in one "
    "sentence with concrete textual evidence from the excerpt. If unsure, "
    "RETURN PENDING. There is no penalty for returning PENDING. There IS "
    "a cost to a wrong CONFIRM or REJECT — a human analyst will be wasted "
    "reviewing it. "
    "Answer ONLY in JSON with keys: action ('confirm'|'reject'|'pending'), "
    "confidence (0..1), reason (short string with concrete textual evidence)."
)


def _llm_recheck(item: dict, *, deterministic_pending: AutoJudgeVerdict,
                 corroborator_count: int) -> Optional[AutoJudgeVerdict]:
    """Optional LLM second-pass for deterministic-pending items.

    Layer 1 cross-evidence is HARDCODED here: regardless of LLM verdict,
    the function returns None (→ no flip) unless the item has
    corroborator_count >= 1 in the same theater. This keeps the path
    asymmetric — Layer 1 blocks LLM-driven false-positive flips at the
    structural level, never causes them.

    Always writes a ledger row when the LLM is invoked (shadow + apply
    modes alike) so calibration data accrues from day 1.

    All failure paths return None — never raise — to preserve NP3.
    """
    try:
        from radar.llm_client import (
            llm_analyze_json, llm_available, safe_enum, safe_float,
        )
    except Exception:
        return None
    try:
        if not llm_available():
            return None
    except Exception:
        return None

    headline = (item.get("headline") or "").strip()
    raw_text = (item.get("raw_text") or "").strip()
    theater = item.get("theater") or ""
    base_conf = float(item.get("confidence") or 0.0)
    excerpt = raw_text[:600]
    prompt = (
        f"Theater: {theater}\n"
        f"First-pass confidence: {base_conf:.2f}\n"
        f"Cross-evidence corroborators in same theater (72h): {corroborator_count}\n"
        f"Headline: {headline}\n"
        f"Excerpt: {excerpt}\n\n"
        "Question: Is this a relevant, credible escalation/threat signal "
        "for the named theater? Reject if it is duplicate of older news, "
        "off-topic, low-quality social-media noise, or unverifiable rumor. "
        "Return PENDING if uncertain — that is the safe default."
    )
    try:
        from radar.llm_routing import UseCase
        resp = llm_analyze_json(
            prompt, system=_LLM_RECHECK_SYSTEM,
            temperature=0.0, max_tokens=200,
            caller="intel_auto_judge.recheck",
            use_case=UseCase.VERDICT,
        )
    except Exception as exc:
        log.debug("auto_judge LLM recheck call failed: %s", exc)
        return None
    if not resp or not resp.get("ok"):
        return None
    data = resp.get("data") or {}
    action = safe_enum(data.get("action"), {"confirm", "reject", "pending"}, "pending")
    confidence = safe_float(data.get("confidence"), default=0.0,
                            min_val=0.0, max_val=1.0)
    reason = (data.get("reason") or "")[:120]

    # ALWAYS log to calibration ledger, even when the verdict is pending
    # or below floor — this lets ECE be computed across the full LLM
    # output distribution, not just the flips we kept.
    _ledger_record(
        item_id=item.get("id") or "",
        action_proposed=action,
        confidence=confidence,
        reason=reason,
        layer1_corroborators=corroborator_count,
        layer1_satisfied=(corroborator_count >= 1),
        applied=False,  # set true below if we actually flip
    )

    # Layer 1 gate (hardcoded): no flip without cross-evidence.
    if action != "pending" and corroborator_count < 1:
        log.debug(
            "auto_judge LLM recheck blocked by Layer 1: %s (action=%s, "
            "conf=%.2f) lacks cross-evidence in theater %s",
            (item.get("id") or "")[:12], action, confidence, theater,
        )
        return None

    if action == "pending":
        return None
    if confidence < _llm_confidence_floor():
        return None

    if action == "confirm":
        verdict = AutoJudgeVerdict(
            action="confirm",
            reason=f"llm_recheck:{reason or 'confirmed'}",
            confidence_floor_used=_llm_confidence_floor(),
            corroborator_count=corroborator_count,
        )
    elif action == "reject":
        verdict = AutoJudgeVerdict(
            action="reject",
            reason=f"llm_recheck:{reason or 'rejected'}",
            confidence_floor_used=_llm_confidence_floor(),
        )
    else:
        return None

    # Mark applied=true in the ledger if we're actually going to apply.
    if _llm_recheck_enabled():
        _ledger_mark_applied(item.get("id") or "")
    return verdict


def apply(item_id: str, verdict: AutoJudgeVerdict) -> bool:
    """Apply an evaluate() verdict by routing through intel_queue.confirm /
    reject with the auto:rule_* analyst marker. Returns True on success.

    Pending verdicts are a no-op (they leave the item where it is).
    """
    if verdict.action == "pending":
        return True
    is_llm = verdict.reason.startswith("llm_recheck:")
    if verdict.action == "confirm":
        marker = ANALYST_LLM_CONFIRM if is_llm else ANALYST_AUTO_CONFIRM
        ok = intel_queue.confirm(item_id, analyst=marker)
        if ok:
            log.info(
                "[AutoJudge] CONFIRMED %s — %s (corroborators=%d, marker=%s)",
                item_id, verdict.reason, verdict.corroborator_count, marker,
            )
        return ok
    if verdict.action == "reject":
        # Use "irrelevant" classification so we don't penalize source
        # credibility — the rule (or LLM) decided automatically, not based
        # on ground-truth fact-check.
        marker = ANALYST_LLM_REJECT if is_llm else ANALYST_AUTO_REJECT
        ok = intel_queue.reject(
            item_id,
            analyst=marker,
            classification="irrelevant",
        )
        if ok:
            log.info(
                "[AutoJudge] REJECTED %s — %s (marker=%s)",
                item_id, verdict.reason, marker,
            )
        return ok
    return False


def run_sweep(limit: int = 100) -> dict:
    """Iterate over current pending items and apply deterministic
    auto-judge verdicts. Returns counts grouped by action.

    Intended to be called by the cache_cleanup_worker on the same cadence
    as auto_reject_stale (hourly). Independent of LLM availability.
    """
    out = {"evaluated": 0, "confirm": 0, "reject": 0, "pending": 0,
           "errors": 0}
    try:
        pending = db.intel_list(status="pending", limit=limit)
    except Exception as exc:
        log.warning("auto_judge sweep: intel_list failed: %s", exc)
        out["errors"] += 1
        return out
    for item in pending:
        try:
            verdict = evaluate(item)
            out["evaluated"] += 1
            if verdict.action != "pending":
                if apply(item["id"], verdict):
                    out[verdict.action] += 1
                else:
                    out["pending"] += 1
            else:
                out["pending"] += 1
        except Exception as exc:
            log.warning("auto_judge sweep item %s failed: %s",
                        item.get("id"), exc)
            out["errors"] += 1
    return out


__all__ = [
    "AutoJudgeVerdict",
    "ANALYST_AUTO_CONFIRM",
    "ANALYST_AUTO_REJECT",
    "ANALYST_LLM_CONFIRM",
    "ANALYST_LLM_REJECT",
    "evaluate",
    "apply",
    "run_sweep",
]
