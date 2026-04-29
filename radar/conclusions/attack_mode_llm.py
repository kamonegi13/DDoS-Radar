"""LLM augmentation for ATTACK_MODE conclusions — Phase 2 後半 (ADR-V2-005).

The rule-based classifier in `attack_mode.py` is the **authority** for
`state`. This module enriches that conclusion with:

  * `metadata.llm_augmentation.narrative` — short analyst-readable rationale
  * `metadata.llm_augmentation.agreement` — LLM agree/disagree with rule top
  * `metadata.llm_augmentation.suggested_alternative_mode` — LLM proposed mode
  * `metadata.llm_augmentation.key_evidence` — LLM-cited signal facts
  * `confidence` — slight nudge: ±0.10 max from rule baseline, clamped to [0,1]
  * `llm_prompt_sha256` — FK into llm_prompts (NP6)

Design contract:
  1. NP1 (sensitivity): we never *narrow* the rule-based mode. If LLM
     suggests a different mode it is recorded but `state` stays.
  2. NP3 (fault tolerance): any LLM error returns the original conclusion
     unchanged. Persistence path keeps writing the rule row even when LLM
     is offline.
  3. NP6 (transparency): every augmented row carries `llm_prompt_sha256`
     and the raw LLM response in metadata.
  4. NP4 (conclusion maximization): augmentation runs only when rule
     produced a usable state. INSUFFICIENT_DATA rows pass through.

Feature flag: `V2_ATTACK_MODE_LLM_AUGMENT_ENABLED` (default off).
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING

from radar import config
from radar.conclusions.base import Conclusion

if TYPE_CHECKING:
    from radar.scoring import ScenarioState

log = logging.getLogger("radar")


# Confidence nudge ceiling — LLM can shift rule confidence up or down by
# at most this much. Keeps the rule classifier as the dominant signal.
_CONFIDENCE_NUDGE_MAX = 0.10

# Allowed values the LLM may pick for `agreement`. Anything else collapses
# to "unknown" via safe_enum.
_AGREEMENT_VALUES = {"agree", "weak_agree", "weak_disagree", "disagree", "unknown"}

# Allowed mode strings the LLM may suggest as alternative.
_KNOWN_MODES = {
    "DDOS_PRECURSOR",
    "KINETIC_PREPARATION",
    "HYBRID_PRESSURE",
    "INFO_OPS_DOMINANT",
    "INSUFFICIENT_SIGNAL",
}


_SYSTEM_PROMPT = (
    "You are an OSINT escalation analyst. Given a rule-based attack-mode "
    "classification and the underlying domain scores, return strict JSON "
    "evaluating whether the rule conclusion is consistent with the evidence. "
    "Be conservative. If unsure, prefer 'unknown' over guessing."
)


def _build_user_prompt(state: "ScenarioState", rule_state: str,
                       rule_confidence: float, ranked_modes: list[dict]) -> str:
    """Render the deterministic prompt body for a given ScenarioState.

    Order is stable so the sha256 dedupes when the same state recurs.
    """
    domains = state.domains or {}
    cyber = float(domains.get("cyber", 0.0))
    physical = float(domains.get("physical", 0.0))
    info = float(domains.get("info", 0.0))
    active_n = len(state.active_countries)
    ranked_summary = ", ".join(
        f"{m['mode']}({m['confidence']:.2f})" for m in ranked_modes
    )

    return (
        f"scenario_id={state.scenario_id}\n"
        f"rule_top_mode={rule_state}\n"
        f"rule_confidence={rule_confidence:.3f}\n"
        f"ranked_modes=[{ranked_summary}]\n"
        f"domain_scores=cyber:{cyber:.2f},physical:{physical:.2f},info:{info:.2f}\n"
        f"active_countries_n={active_n}\n"
        "\n"
        "Return JSON with keys:\n"
        "  agreement: one of "
        "['agree','weak_agree','weak_disagree','disagree','unknown']\n"
        "  suggested_alternative_mode: one of "
        "['DDOS_PRECURSOR','KINETIC_PREPARATION','HYBRID_PRESSURE',"
        "'INFO_OPS_DOMINANT','INSUFFICIENT_SIGNAL'] or null\n"
        "  narrative: <=240 chars analyst-facing rationale\n"
        "  key_evidence: list[str] (<=4) of short evidence phrases\n"
        "  confidence_adjustment: float in [-0.10, 0.10]\n"
    )


def augment_attack_mode_with_llm(
    rule_conclusion: Conclusion,
    state: "ScenarioState",
) -> Conclusion:
    """Return either an augmented copy of `rule_conclusion` or the original.

    Pure with respect to inputs — never mutates `rule_conclusion` (frozen).
    Errors are swallowed (NP3); on any failure path the original is returned
    so the rule conclusion still persists.
    """
    # Resolved via the LLM Feature Hub. Falls back to the legacy
    # config flag when the registry is unavailable (NP3 import-cycle
    # protection during early bootstrap).
    try:
        from radar.llm_features import is_enabled
        if not is_enabled("attack_mode_augment"):
            return rule_conclusion
    except Exception:
        if not config.V2_ATTACK_MODE_LLM_AUGMENT_ENABLED:
            return rule_conclusion
    if not rule_conclusion.is_available():
        # NP4 + NP1: do not invent an attack mode when rules abstained.
        return rule_conclusion
    # Lazy imports keep this module importable in test contexts that stub
    # out the LLM client.
    from radar.llm_client import (
        llm_analyze_json, llm_available,
        safe_enum, safe_float,
    )
    if not llm_available():
        return rule_conclusion

    ranked = list(rule_conclusion.metadata.get("ranked_modes", []))
    user_prompt = _build_user_prompt(
        state,
        rule_state=str(rule_conclusion.state),
        rule_confidence=rule_conclusion.confidence,
        ranked_modes=ranked,
    )

    result = llm_analyze_json(
        prompt=user_prompt,
        system=_SYSTEM_PROMPT,
        temperature=0.1,
        max_tokens=384,
        caller="attack_mode_llm_augment",
    )
    if not result.get("ok"):
        # NP3: rule row still gets written by caller. Mark the augmentation
        # attempt so analysts can distinguish "LLM offline" from "LLM said
        # nothing useful".
        new_meta = dict(rule_conclusion.metadata)
        new_meta["llm_augmentation"] = {
            "attempted": True,
            "ok": False,
            "error": result.get("error", "unknown"),
        }
        return replace(rule_conclusion, metadata=new_meta)

    data = result.get("data", {}) or {}
    agreement = safe_enum(data.get("agreement"), _AGREEMENT_VALUES, "unknown")
    suggested_raw = data.get("suggested_alternative_mode")
    suggested = (
        suggested_raw if isinstance(suggested_raw, str) and suggested_raw in _KNOWN_MODES
        else None
    )
    narrative = str(data.get("narrative", ""))[:240]
    raw_evidence = data.get("key_evidence", [])
    evidence = []
    if isinstance(raw_evidence, list):
        for item in raw_evidence[:4]:
            if isinstance(item, str) and item.strip():
                evidence.append(item.strip()[:120])
    nudge = safe_float(
        data.get("confidence_adjustment"),
        default=0.0,
        min_val=-_CONFIDENCE_NUDGE_MAX,
        max_val=_CONFIDENCE_NUDGE_MAX,
    )
    new_confidence = max(0.0, min(1.0, rule_conclusion.confidence + nudge))

    new_meta = dict(rule_conclusion.metadata)
    new_meta["llm_augmentation"] = {
        "attempted": True,
        "ok": True,
        "agreement": agreement,
        "suggested_alternative_mode": suggested,
        "narrative": narrative,
        "key_evidence": evidence,
        "confidence_adjustment_applied": round(nudge, 4),
        "confidence_before": round(rule_conclusion.confidence, 4),
    }

    # llm_prompt_sha256 is captured by llm_call_log via _maybe_persist_prompt;
    # we recompute here so the Conclusion row carries the FK directly.
    sha = _last_prompt_sha(user_prompt)
    return replace(
        rule_conclusion,
        confidence=round(new_confidence, 3),
        metadata=new_meta,
        llm_prompt_sha256=sha or rule_conclusion.llm_prompt_sha256,
    )


def _last_prompt_sha(prompt: str) -> str:
    """Return the sha256 of (system, prompt) for FK linkage. Empty on error."""
    try:
        from radar.llm_prompts import compute_prompt_sha256
        return compute_prompt_sha256(prompt, _SYSTEM_PROMPT)
    except Exception:
        return ""
