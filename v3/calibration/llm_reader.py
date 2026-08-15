"""WP-0.4 v2 (0.4d) — Tier 2: a local model as the second reader.

The ladder's middle rung. Tier 1 releases an FN candidate only when two
independent sources converge; everything else would otherwise sit in the
pending queue until a human happened to look, and the ruling is that a
human must never be load-bearing. So a pinned local model reads the
remainder — and it is given exactly two powers:

    agree_confirm    the evidence is a real event and the attribution
                     holds; the candidate may be released as a label.
    route_to_human   anything else — doubt, inconsistency, thin evidence.

**There is no reject.** The asymmetry is measured, not stylistic: a
missed FN inflates recall (the dangerous direction, NP1), while a
spurious one deflates it (the safe one). A model that could drop
candidates would be the detection layer's own blind spots deciding what
the audit is allowed to see — the correlated failure this tier exists to
break.

**Effect is earned, not assumed.** `TIER2_EFFECT_ENABLED` is False, so
verdicts are recorded and measured while changing nothing. Turning it on
is a code change with an ADR behind it, deliberately not a config toggle:
a runtime flag could be flipped before the agreement measurement that is
the whole justification for trusting this rung.

**Reproducibility (NP6).** P7 §4 retired LLM narration because a model
asked twice answered twice differently. The same discipline applies here
and is why every verdict row carries the model id, the prompt template
ref and the raw response: temperature 0 and a JSON schema make the answer
stable in practice, but the 2026-08-15 bench measured one text-level flip
in eleven identical calls, so AP4 replays the STORED verdict and never a
re-execution.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError

#: Whether a verdict may release a label. See the module docstring: this
#: is a constant rather than a config key on purpose.
TIER2_EFFECT_ENABLED = False

AGREE_CONFIRM = "agree_confirm"
ROUTE_TO_HUMAN = "route_to_human"
VERDICTS: tuple[str, ...] = (AGREE_CONFIRM, ROUTE_TO_HUMAN)

#: Why a draft got no verdict this cycle. Never a bare absence: "the
#: model was not asked" and "the model was asked and hedged" are
#: different facts and G-17 is what merging them costs.
SKIP_NO_EGRESS = "llm_not_configured"
SKIP_DISABLED = "llm_disabled"
SKIP_CALL_FAILED = "llm_call_failed"
SKIP_UNPARSEABLE = "llm_answer_unusable"

#: The prompt's identity, versioned like every narrative template so a
#: replay can say WHICH words produced a stored verdict (AP2/AP4).
PROMPT_ID = "calibration.fn_second_reader"
PROMPT_VERSION = "1"
PROMPT_REF = f"{PROMPT_ID}@{PROMPT_VERSION}"

#: Measured into existence on 2026-08-15. Both clauses are bench
#: findings, not taste: asking whether the TOOL detected it made the
#: model route candidates it should have confirmed (that check is Tier
#: 1's ledger comparison, not a reading task), and withholding the
#: attribution convention made it call a correct draft inconsistent
#: (a Chinese exercise attributed to TW in `taiwan_contingency`).
SYSTEM_PROMPT = (
    "あなたは OSINT 警戒システムの較正ラベル第二読者です。FN（検知漏れ）"
    "候補の草稿を審査します。審査対象は 2 点のみです: "
    "(a) 証拠は指定シナリオに関連する実在の軍事・安全保障イベントを示して"
    "いるか。(b) 国の帰属（country）は証拠と整合しているか。"
    "ツールが実際に検知したか否かの確認はあなたの仕事ではありません"
    "（結論台帳との照合は別の機械的検証層が行います）。"
    "country はシナリオ参加国のうち観測が帰属される国であり、イベントの"
    "実行主体国とは限りません（例: 中国が台湾周辺で演習 → "
    "taiwan_contingency では標的国 TW への観測として帰属され得ます）。"
    "不整合とは、証拠の示す事象が指定 country への帰属として参加国名簿の"
    "役割上説明できない場合を指します。"
    "あなたの権限は 2 つだけです: "
    "(1) agree_confirm — (a)(b) の両方が成立する。"
    "(2) route_to_human — (a) または (b) に疑義・不整合・証拠不足がある。"
    "草稿を棄却する権限はありません。判定は JSON のみで出力します。"
    "reason は日本語 1〜2 文で書きます。")

#: The closed vocabulary, enforced at the transport. An answer outside it
#: cannot be produced rather than being caught downstream.
VERDICT_SCHEMA: Mapping[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "event_real": {"type": ["boolean", "null"]},
        "attribution_holds": {"type": ["boolean", "null"]},
        "reason": {"type": "string"},
    },
    "required": ["verdict", "reason", "event_real", "attribution_holds"],
}


def prompt_for(draft: Mapping, *, participants: Mapping) -> str:
    """The user half — the draft as data, deterministically serialised.

    `sort_keys` because the prompt is part of the stored provenance: two
    runs over the same draft must produce the same text, or the ref does
    not identify what was asked.
    """
    payload = {
        "scenario": draft.get("scenario_id"),
        "participants": {str(code): str(role)
                         for code, role in sorted(dict(participants).items())},
        "conclusion_type": draft.get("conclusion_type"),
        "draft_claim": draft.get("reason"),
        "detected_sources": list(draft.get("sources") or []),
        "evidence_url": draft.get("evidence_url"),
        "proposed_by": draft.get("proposed_analyst_id"),
    }
    return json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True)


@dataclass(frozen=True, slots=True)
class Tier2Verdict:
    """One model reading of one draft, with everything a replay needs."""

    draft_id: str
    verdict: str
    reason: str
    model_id: str
    prompt_ref: str
    response_text: str
    event_real: Optional[bool] = None
    attribution_holds: Optional[bool] = None
    effective: bool = False

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise DomainError(
                f"unknown Tier 2 verdict {self.verdict!r}; the vocabulary "
                f"is {list(VERDICTS)}. There is deliberately no reject: a "
                f"model that could drop an FN candidate would let the "
                f"detection layer's blind spots decide what the audit sees")
        for name in ("draft_id", "model_id", "prompt_ref"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(f"a Tier 2 verdict needs a {name}")

    @property
    def releases(self) -> bool:
        """Whether this verdict may turn the draft into a label."""
        return self.effective and self.verdict == AGREE_CONFIRM

    def as_dict(self) -> dict:
        return {"draft_id": self.draft_id, "verdict": self.verdict,
                "reason": self.reason, "model_id": self.model_id,
                "prompt_ref": self.prompt_ref,
                "event_real": self.event_real,
                "attribution_holds": self.attribution_holds,
                "effective": self.effective}


def parse_verdict(data: Mapping, *, draft_id: str, model_id: str,
                  response_text: str) -> Tier2Verdict:
    """The model's JSON as a verdict, or `DomainError`.

    Refuses rather than defaults: an unusable answer must leave the draft
    pending (the safe direction) instead of being read as agreement.
    """
    values = dict(data or {})
    verdict = str(values.get("verdict") or "")
    if verdict not in VERDICTS:
        raise DomainError(
            f"the model answered {verdict!r}, which is not in {list(VERDICTS)}")
    return Tier2Verdict(
        draft_id=str(draft_id), verdict=verdict,
        reason=str(values.get("reason") or ""), model_id=str(model_id),
        prompt_ref=PROMPT_REF, response_text=str(response_text or ""),
        event_real=values.get("event_real"),
        attribution_holds=values.get("attribution_holds"),
        effective=TIER2_EFFECT_ENABLED)


def request_for(draft: Mapping, *, participants: Mapping, model_id: str):
    """The `LlmRequest` for one draft. Deterministic settings, pinned."""
    from v3.fetch.llm import LlmRequest
    return LlmRequest(
        prompt=prompt_for(draft, participants=participants),
        system=SYSTEM_PROMPT, model_id=model_id,
        temperature=0.0, max_tokens=T.S9_TIER2_MAX_TOKENS,
        response_format=VERDICT_SCHEMA, think=T.S9_TIER2_THINK)


def agreement(verdicts: Sequence, human_states: Mapping) -> dict:
    """How often the model and the humans agreed, on drafts both read.

    The measurement that decides whether this rung ever gets effect. Only
    drafts a HUMAN has ruled on are counted — an unadjudicated draft is
    not evidence about the model, and counting it would let the model's
    own volume flatter its score.

    `agree_confirm` is scored against a human `confirmed`, and
    `route_to_human` against a human `rejected`: the model saying "I am
    not sure" about something a person then rejected is the rung working
    as designed, not a miss.
    """
    matched = 0
    agreed = 0
    missed_confirms = 0
    for verdict in verdicts:
        state = human_states.get(verdict.draft_id)
        if state not in ("confirmed", "rejected"):
            continue
        matched += 1
        if verdict.verdict == AGREE_CONFIRM and state == "confirmed":
            agreed += 1
        elif verdict.verdict == ROUTE_TO_HUMAN and state == "rejected":
            agreed += 1
        elif verdict.verdict == ROUTE_TO_HUMAN and state == "confirmed":
            # The safe error: the model hedged on a real miss. Counted
            # apart because it costs analyst time, never recall.
            missed_confirms += 1
    return {
        "compared": matched,
        "agreed": agreed,
        "agreement_rate": (agreed / matched) if matched else None,
        "hedged_on_real_miss": missed_confirms,
        "effect_enabled": TIER2_EFFECT_ENABLED,
        "prompt_ref": PROMPT_REF,
    }


__all__ = ["TIER2_EFFECT_ENABLED", "AGREE_CONFIRM", "ROUTE_TO_HUMAN",
           "VERDICTS", "SKIP_NO_EGRESS", "SKIP_DISABLED",
           "SKIP_CALL_FAILED", "SKIP_UNPARSEABLE", "PROMPT_ID",
           "PROMPT_VERSION", "PROMPT_REF", "SYSTEM_PROMPT",
           "VERDICT_SCHEMA", "prompt_for", "Tier2Verdict", "parse_verdict",
           "request_for", "agreement"]
