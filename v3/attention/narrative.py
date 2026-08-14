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


#: WP-4.8d (P9 §1.6 D-23b) — the READ-SIDE sentence, version 2. The v1
#: sentence above is rendered in the tick and STORED, and P9 §1.8's audit
#: discipline forbids touching the write path for presentation (the C-16
#: clock). So v2 is composed at projection time from the same stored
#: numbers, versioned like every template, and the stored v1 remains the
#: AP4 record of what was written when.
#:
#: Wording: the analyst's language first — the display name, the
#: conclusion type as a word, and the DOMINANT factor as a phrase. The
#: full arithmetic stays in `components`, which the UI already carries in
#: the rank chip's tooltip (AP1: the basis is always one hover away).
ROW_TEMPLATE_V2 = Template(
    template_id="attention.row", version="2",
    text="『{scenario}』の{subject}を {rank} 位に置きました — "
         "主因は{driver}（{driver_term} {driver_value}）。")

#: Conclusion types as analyst words. The raw value is the API's and
#: stays on the wire; this is prose vocabulary, not a state rename.
TYPE_TEXT: dict = {
    "anomaly": "異常検知",
    "threat_level": "脅威レベル",
    "trend": "トレンド",
    "attack_mode": "攻撃様態",
    "per_domain": "ドメイン別状況",
}

DRIVER_TEXT: dict = {
    "novelty": "変化の新しさ",
    "confidence_delta": "確信度の変動",
    "analyst_blindness": "未対応時間の長さ",
}


def dominant_driver(components: Mapping) -> tuple:
    """`(factor_name, value)` — the largest of the three, ties broken by
    the listed order (AP2: two renders of one row name one driver)."""
    ordered = (
        ("novelty", float(components.get("novelty") or 0.0)),
        ("confidence_delta",
         float(components.get("confidence_delta") or 0.0)),
        ("analyst_blindness",
         float(components.get("analyst_blindness") or 0.0)),
    )
    return max(ordered, key=lambda pair: pair[1])


def render_row_v2(*, components: Mapping, scenario_label: str,
                  subject: str, rank) -> tuple:
    """`(narrative, template_ref)`, composed read-side from stored numbers."""
    driver_term, value = dominant_driver(components)
    return (ROW_TEMPLATE_V2.render({
        "scenario": scenario_label,
        "subject": TYPE_TEXT.get(subject, subject),
        "rank": rank,
        "driver": DRIVER_TEXT[driver_term],
        "driver_term": driver_term,
        "driver_value": f"{value:.3f}"}), ROW_TEMPLATE_V2.ref)


def disclosure() -> dict:
    """Every template with its id, version and slots (AP2 / NP6)."""
    return {template.ref: {"template_id": template.template_id,
                           "version": template.version,
                           "slots": list(template.slots),
                           "text": template.text}
            for template in (ROW_TEMPLATE, SILENT_TEMPLATE,
                             ROW_TEMPLATE_V2)}


__all__ = ["Template", "ROW_TEMPLATE", "SILENT_TEMPLATE", "ROW_TEMPLATE_V2",
           "REASON_TEXT", "TYPE_TEXT", "DRIVER_TEXT", "dominant_driver",
           "render_row", "render_row_v2", "disclosure"]
