"""AP2's plain-language half — template plus slots, no model.

P7 §4 replaces `POST /api/v2/triage/narrate` (LLM-driven, and therefore
different every time it is asked) with a template engine in the backend:
the same conclusion must always produce the same sentence, and the
template must carry an id and a version so AP4 can replay what the analyst
actually read.

This module IS that engine. It is deliberately small and caller-agnostic —
`Template` knows nothing about attention — because P7 §4 requires ONE
implementation shared by R2's `?include=narrative` and R6's row narrative,
and two engines would be two things to disagree about a number.

The slots are filled from the score's own components. Nothing here reads
the ledger, calls a model, or formats a value it was not given, so a
narrative is reproducible from the stored row alone.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from v3.kernel.errors import DomainError

_SLOT = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


@dataclass(frozen=True, slots=True)
class Template:
    """One sentence with named slots, identified and versioned.

    `version` is not decoration: the stored `narrative_template_ref` is
    `id@version`, so a replay can say "this is what the analyst read" even
    after the wording changes, rather than re-rendering today's words over
    yesterday's numbers and calling it history.
    """

    template_id: str
    version: str
    text: str

    def __post_init__(self) -> None:
        for name in ("template_id", "version", "text"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(f"a template needs a non-empty {name}")
        if not _SLOT.search(self.text):
            raise DomainError(
                f"template {self.template_id!r} has no slots: a constant "
                f"sentence describes every row identically, which is a "
                f"narrative that explains nothing")

    @property
    def ref(self) -> str:
        return f"{self.template_id}@{self.version}"

    @property
    def slots(self) -> tuple[str, ...]:
        return tuple(sorted(set(_SLOT.findall(self.text))))

    def render(self, values: Mapping[str, Any]) -> str:
        """Fill every slot, or refuse.

        A missing slot is an error rather than an empty string, because a
        sentence with a hole in it reads as a fact about the finding ("the
        confidence moved by ") rather than as a bug in the tool.
        """
        missing = [name for name in self.slots if name not in values]
        if missing:
            raise DomainError(
                f"template {self.ref} is missing slots {missing}: an unfilled "
                f"slot reads as a statement about the finding rather than as "
                f"a defect in the renderer")
        return _SLOT.sub(lambda match: str(values[match.group(1)]), self.text)


def _hours(seconds) -> str:
    return f"{float(seconds) / 3600.0:.1f}"


#: The attention row's sentence. Japanese, per the UI language contract;
#: the CTI terms AP1 uses (`novelty` etc.) stay in English because
#: `docs/design/ja-localization.md` §2 lists them as not-to-translate.
ROW_TEMPLATE = Template(
    template_id="attention.row", version="1",
    text="{scenario_id} の {subject} を {rank} 位に置きました。"
         "novelty {novelty}（最終変化から {age_hours} 時間 / 上限 "
         "{novelty_horizon_hours} 時間）× confidence_delta {delta}"
         "（{confidence_from} → {confidence}）× analyst_blindness "
         "{blindness}（最終操作から {idle_hours} 時間 / 上限 "
         "{blindness_horizon_hours} 時間）= {score}。")

#: The zero case gets its own sentence rather than the same one with zeros
#: in it: "novelty 0.0 x ... = 0.0" is arithmetic, and what the analyst
#: needs is the reason the tool is not asking them to look.
SILENT_TEMPLATE = Template(
    template_id="attention.silent", version="1",
    text="{scenario_id} の {subject} は注目対象になりませんでした"
         "（理由: {reasons}）。score {score}。")

REASON_TEXT: dict = {
    "conclusion_unavailable": "結論不可（NP5+8 — 不在は R7 と R3 が示します）",
    "beyond_novelty_horizon": "最終変化から 48 時間以上",
    "no_confidence_movement": "確度が動いていない",
    "analyst_acted_recently": "アナリストが直近に操作済み",
}


def _subject(inputs) -> str:
    context = dict(inputs.context)
    return str(context.get("conclusion_type") or inputs.item_kind)


def render_row(*, inputs, provenance, rank: int) -> tuple[str, str]:
    """`(narrative, template_ref)` for one ranked row.

    Returns the ref alongside the text so the caller cannot store one
    without the other — a stored sentence whose template is unknown is a
    sentence nobody can re-derive.
    """
    stated = dict(provenance.inputs)
    horizons = dict(provenance.horizons)
    if provenance.score <= 0.0 and provenance.zero_reasons:
        reasons = "、".join(REASON_TEXT.get(reason, reason)
                            for reason in provenance.zero_reasons)
        return (SILENT_TEMPLATE.render({
            "scenario_id": inputs.scenario_id,
            "subject": _subject(inputs),
            "reasons": reasons,
            "score": f"{provenance.score:.3f}"}), SILENT_TEMPLATE.ref)
    last_changed = stated.get("last_changed_at")
    now = float(stated.get("now") or 0.0)
    age = 0.0 if last_changed is None else max(0.0, now - float(last_changed))
    last_action = stated.get("last_analyst_action_at")
    idle = (horizons["blindness_horizon_sec"] if last_action is None
            else max(0.0, now - float(last_action)))
    previous = stated.get("previous_confidence")
    return (ROW_TEMPLATE.render({
        "scenario_id": inputs.scenario_id,
        "subject": _subject(inputs),
        "rank": rank,
        "novelty": f"{provenance.novelty:.3f}",
        "age_hours": _hours(age),
        "novelty_horizon_hours": _hours(horizons["novelty_horizon_sec"]),
        "delta": f"{provenance.confidence_delta:.3f}",
        "confidence_from": ("なし" if previous is None
                            else f"{float(previous):.3f}"),
        "confidence": f"{float(stated.get('confidence') or 0.0):.3f}",
        "blindness": f"{provenance.analyst_blindness:.3f}",
        "idle_hours": _hours(idle),
        "blindness_horizon_hours": _hours(
            horizons["blindness_horizon_sec"]),
        "score": f"{provenance.score:.4f}"}), ROW_TEMPLATE.ref)


#: The READ-SIDE sentence (WP-4.8d, revised by P9 §1.10 D-25). The v1
#: sentence above is rendered in the tick and STORED; P9 §1.8's audit
#: discipline forbids touching that path for presentation (the C-16
#: clock), so this one is composed at projection time from the same
#: stored numbers. Version 3 replaces the short-lived version 2, which
#: crowned the DOMINANT ranking factor — and the dominant factor is
#: novelty, degenerately 1.0 for every row because `supply.py` feeds it
#: the latest row's write time. Beside a no-change card, "主因は変化の
#: 新しさ" read as nonsense (the ninth review said so). v3 states the
#: SUBSTANCE — which sensor, where — and the two factors that actually
#: discriminate today. The arithmetic stays in `components` (AP1).
ROW_TEMPLATE_V3 = Template(
    template_id="attention.row", version="3",
    text="『{scenario}』の{subject}が注目 {rank} 位 — {substance}。"
         "確度 {confidence_from} → {confidence}、"
         "アナリスト未対応 {idle_hours} 時間。")

#: WP-4.13a (P9 §1.13 D-28): the read-side sentence grows its REASON.
#: v3 stated the facts — confidence from → to, hours unattended — and
#: left the causality to the reader; the 14th review named the gap
#: ("なぜ注目すべきなのかが表現されていない"). A ranked row's score is
#: positive, so all three factors are positive, so the causal claim is
#: always true for any row these templates are allowed to speak for —
#: the caller must NOT use them on a zero-score row, whose stored silent
#: sentence already says why the tool is not asking anyone to look.
#:
#: Two templates rather than one with an optional hole: rows scored
#: before WP-4.11 carry a WRITE instant in `last_changed_at`, and a
#: sentence calling one a state change would be a false statement about
#: the finding. The choice is deterministic on the stored
#: `novelty_basis` marker, so a replay picks the same words (AP4).
NOVELTY_BASIS_KEY = "novelty_basis"
NOVELTY_BASIS_STATE_CHANGE = "state_change"

ROW_TEMPLATE_V4 = Template(
    template_id="attention.row", version="4",
    text="『{scenario}』の{subject}が注目 {rank} 位 — {substance}。"
         "理由: 確度が {confidence_from} → {confidence} と動き、"
         "アナリスト未対応が {idle_hours} 時間続いているため。")

ROW_TEMPLATE_CHANGED = Template(
    template_id="attention.row_changed", version="1",
    text="『{scenario}』の{subject}が注目 {rank} 位 — {substance}。"
         "理由: {age_hours} 時間前に状態が変化し、確度が {confidence_from} "
         "→ {confidence} と動き、アナリスト未対応が {idle_hours} 時間"
         "続いているため。")

#: Conclusion types as analyst words. The raw value is the API's and
#: stays on the wire; this is prose vocabulary, not a state rename.
TYPE_TEXT: dict = {
    "anomaly": "異常検知",
    "threat_level": "脅威レベル",
    "trend": "トレンド",
    "attack_mode": "攻撃様態",
    "per_domain": "ドメイン別状況",
}

def render_row_v3(*, components: Mapping, scenario_label: str,
                  subject: str, rank, substance: str) -> tuple:
    """`(narrative, template_ref)`, composed read-side from stored numbers.

    `substance` is the caller's one-phrase answer to "what IS this" —
    the handler builds it from the conclusion row the item points at.
    The idle time reads from the stored inputs the tick used, so the
    sentence and the tooltip cannot disagree (one clock, AP2).
    """
    stated = dict(components.get("inputs") or {})
    horizons = dict(components.get("horizons") or {})
    now = float(stated.get("now") or 0.0)
    last_action = stated.get("last_analyst_action_at")
    horizon = float(horizons.get("blindness_horizon_sec") or 0.0)
    idle = (horizon if last_action is None
            else max(0.0, now - float(last_action)))
    previous = stated.get("previous_confidence")
    return (ROW_TEMPLATE_V3.render({
        "scenario": scenario_label,
        "subject": TYPE_TEXT.get(subject, subject),
        "rank": rank,
        "substance": substance,
        "confidence_from": ("なし" if previous is None
                            else f"{float(previous):.3f}"),
        "confidence": f"{float(stated.get('confidence') or 0.0):.3f}",
        "idle_hours": _hours(idle)}), ROW_TEMPLATE_V3.ref)


def render_row_v4(*, components: Mapping, scenario_label: str,
                  subject: str, rank, substance: str) -> tuple:
    """`(narrative, template_ref)` with the reason clause (WP-4.13a).

    Composed read-side from stored numbers, like v3, and choosing its
    words from them too: the change instant is spoken only when the
    stored inputs carry the WP-4.11 marker AND an actual instant —
    otherwise the age would be the write-churn artefact D-25(a) named,
    and the sentence falls back to the two factors that are real either
    way. The caller guards score > 0; see the template block comment.
    """
    stated = dict(components.get("inputs") or {})
    horizons = dict(components.get("horizons") or {})
    now = float(stated.get("now") or 0.0)
    last_action = stated.get("last_analyst_action_at")
    horizon = float(horizons.get("blindness_horizon_sec") or 0.0)
    idle = (horizon if last_action is None
            else max(0.0, now - float(last_action)))
    previous = stated.get("previous_confidence")
    values = {
        "scenario": scenario_label,
        "subject": TYPE_TEXT.get(subject, subject),
        "rank": rank,
        "substance": substance,
        "confidence_from": ("なし" if previous is None
                            else f"{float(previous):.3f}"),
        "confidence": f"{float(stated.get('confidence') or 0.0):.3f}",
        "idle_hours": _hours(idle)}
    last_changed = stated.get("last_changed_at")
    if (stated.get(NOVELTY_BASIS_KEY) == NOVELTY_BASIS_STATE_CHANGE
            and last_changed is not None):
        values["age_hours"] = _hours(
            max(0.0, now - float(last_changed)))
        return (ROW_TEMPLATE_CHANGED.render(values),
                ROW_TEMPLATE_CHANGED.ref)
    return (ROW_TEMPLATE_V4.render(values), ROW_TEMPLATE_V4.ref)


def disclosure() -> dict:
    """Every template with its id, version and slots (AP2 / NP6)."""
    return {template.ref: {"template_id": template.template_id,
                           "version": template.version,
                           "slots": list(template.slots),
                           "text": template.text}
            for template in (ROW_TEMPLATE, SILENT_TEMPLATE,
                             ROW_TEMPLATE_V3, ROW_TEMPLATE_V4,
                             ROW_TEMPLATE_CHANGED)}


__all__ = ["Template", "ROW_TEMPLATE", "SILENT_TEMPLATE", "ROW_TEMPLATE_V3",
           "ROW_TEMPLATE_V4", "ROW_TEMPLATE_CHANGED",
           "NOVELTY_BASIS_KEY", "NOVELTY_BASIS_STATE_CHANGE",
           "REASON_TEXT", "TYPE_TEXT",
           "render_row", "render_row_v3", "render_row_v4", "disclosure"]
