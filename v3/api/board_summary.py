"""P9 §5 — R1's sentence, composed here rather than in the page.

P9 §1 D-2 is the defect this answers: the board projected twelve fields
per scenario and no sentence, so the analyst's first question ("has
anything changed") was answered with a code (`TL4 / ELEVATED`) instead of
with an answer. R-A puts the sentence first and the numbers under it.

The sentence is built the way every other plain-language surface in v3 is
built — `v3/attention/narrative.py`'s `Template`, which is P7 §4's ONE
engine: an id, a version, named slots, no model. Composing it in the
browser instead would put a derivation in the frontend that the backend
already owns, which is G-09 and is the same defect P5 O-8 removed from
`triage_score.js`.

Three properties are load-bearing, and each is one of this project's
recorded failures:

* **a component this cannot supply is NAMED** (G-17). The ranked list is
  a per-reader projection and the ops fold is a deployment fact; either
  can be unavailable. An unavailable one appears in `inputs.unsupplied`
  with a reason and speaks in the sentence, because a silently dropped
  clause reads as "nothing needs attention".
* **a cold deployment does not report zero change.** "24 時間で変化が
  あったのは 0 件" from a tool that has concluded nothing is the empty
  cache that returned CLEAR. It gets its own template, the way
  `narrative.SILENT_TEMPLATE` gets its own sentence rather than the
  ordinary one with zeros in it.
* **nothing is re-derived here.** The counts come from the R1 rows the
  caller already built, the rank comes from the stored snapshot, and the
  trust band comes from the same fold R7 serves. A second arithmetic
  would be a second answer about one deployment.
"""
from __future__ import annotations

from typing import Mapping, Optional, Sequence

from v3.attention.narrative import Template
from v3.runtime import ops_health as OPS

#: The three things the sentence is made of. Declared as constants so an
#: absence names the same component the presence does.
COMPONENT_CHANGE = "change_24h"
COMPONENT_ATTENTION = "attention"
COMPONENT_TRUST = "trust"
COMPONENTS: tuple[str, ...] = (COMPONENT_CHANGE, COMPONENT_ATTENTION,
                               COMPONENT_TRUST)

#: Why the ranked list could not be read. `ranker_has_not_run` and the
#: rest come from `v3/attention/projection.py`; this one is the case that
#: module never sees, because it is refused before the projection runs.
ATTENTION_NO_READER = "reader_not_identified"

SUMMARY_TEMPLATE = Template(
    template_id="board.summary", version="1",
    text="監視中 {scenario_count} シナリオのうち、直近 24 時間で変化が"
         "あったのは {changed_count} 件（変化なし {unchanged_count} 件 / "
         "比較不能 {undetermined_count} 件）。最優先の注目対象は"
         "{attention}、ツール自己評価は{trust}。")

#: The cold case, with its own sentence rather than the ordinary one
#: carrying zeros. A deployment that has concluded nothing has not
#: observed "no change" — it has not observed.
COLD_TEMPLATE = Template(
    template_id="board.summary.cold", version="1",
    text="結論可能なシナリオがまだありません（監視中 {scenario_count} 件、"
         "うち未観測 {never_observed_count} 件）。最優先の注目対象は"
         "{attention}、ツール自己評価は{trust}。")

#: The trust band's word, matching `v3/ui/strings.js`'s `ui.trust.*` so
#: the sentence and the chip beside it cannot disagree in vocabulary.
BAND_TEXT: dict = {
    OPS.BAND_TRUSTED: "通常",
    OPS.BAND_RESERVED: "留保つき",
    OPS.BAND_DISTRUST: "結論を信じないこと",
}

#: `v3/attention/projection.py`'s empty reasons, said in Japanese. A bare
#: 「なし」 would make "the ranker has not run" and "nothing qualified"
#: look identical, and they are the two facts G-17 is about.
EMPTY_TEXT: dict = {
    "ranker_has_not_run": "順位付けがまだ実行されていません",
    "all_rows_below_min_score": "全行が自分の min_score を下回っています",
    "no_ranked_items": "順位対象がありません",
}

ATTENTION_ABSENT_TEXT: dict = {
    ATTENTION_NO_READER: "注目リストは利用者ごとの射影で、"
                         "この読み取りに利用者がありません",
}


def _counts(rows: Sequence[Mapping]) -> dict:
    """The 24h movement census, read off the rows R1 already built.

    Three buckets, not two. `severity_delta_24h is None` is neither
    "changed" nor "did not change" — folding it into either invents the
    comparison the row explicitly declined to make.
    """
    changed, unchanged, undetermined = [], [], []
    for row in rows:
        delta = row.get("severity_delta_24h")
        if delta is None:
            undetermined.append(row)
        elif delta != 0:
            changed.append(row)
        else:
            unchanged.append(row)
    return {
        "scenario_count": len(rows),
        "concluded_count": sum(1 for row in rows
                               if row.get("threat_level") is not None),
        "never_observed_count": sum(1 for row in rows
                                    if row.get("never_observed")),
        "changed_count": len(changed),
        "unchanged_count": len(unchanged),
        "undetermined_count": len(undetermined),
        "changed_scenario_ids": [str(row.get("scenario_id"))
                                 for row in changed],
    }


def _label_for(rows: Sequence[Mapping], scenario_id: str) -> str:
    """The scenario's Japanese label, from the row that already carries it.

    Not looked up in the geography: R1's rows hold the name and its
    declared source, so reading it here keeps one supply path.
    """
    for row in rows:
        if str(row.get("scenario_id")) == str(scenario_id):
            return str(row.get("display_name_ja") or scenario_id)
    return str(scenario_id)


def _attention_component(rows, payload: Optional[Mapping],
                         absent_reason: Optional[str]) -> tuple[dict, str]:
    """`(disclosure, sentence clause)` for the top ranked row."""
    if payload is None:
        reason = str(absent_reason or ATTENTION_NO_READER)
        text = ATTENTION_ABSENT_TEXT.get(reason, reason)
        return ({"supplied": False, "reason": reason}, f"不明（{text}）")
    ranked = list(payload.get("attention") or ())
    if not ranked:
        reason = str(payload.get("empty_reason") or "no_ranked_items")
        return ({"supplied": False, "reason": reason,
                 "snapshot_id": payload.get("snapshot_id"),
                 "considered": payload.get("considered"),
                 "filtered_below_min_score":
                     payload.get("filtered_below_min_score")},
                f"なし（{EMPTY_TEXT.get(reason, reason)}）")
    top = ranked[0]
    scenario_id = str(top.get("scenario_id"))
    label = _label_for(rows, scenario_id)
    score = float(top.get("score") or 0.0)
    item_kind = str(top.get("item_kind") or "")
    return ({"supplied": True, "reason": None,
             "item_id": top.get("item_id"), "item_kind": item_kind,
             "scenario_id": scenario_id, "rank": top.get("rank_position"),
             "score": score, "snapshot_id": payload.get("snapshot_id"),
             "analyst_state": top.get("analyst_state"),
             "formula_ref": payload.get("formula_ref")},
            f"{label}（{item_kind} / score {score:.4f}）")


def _trust_component(ops_fold: Mapping) -> tuple[dict, str]:
    """`(disclosure, sentence clause)` for AP3's one-word band.

    Always supplied: `ops_health.supplied_or_absent` answers an unprobed
    deployment with every monitor stating why it cannot answer, so the
    band is a MEASURED `reserved` with a named cause rather than a
    missing field. That distinction is the whole of §7-2 #94.
    """
    band = str(ops_fold.get("worst_band") or OPS.BAND_RESERVED)
    monitor = ops_fold.get("worst_monitor")
    reason = ops_fold.get("worst_reason")
    word = BAND_TEXT.get(band, band)
    disclosure_ = {"supplied": True, "reason": reason, "band": band,
                   "worst_monitor": monitor,
                   "worst_verdict": ops_fold.get("worst_verdict"),
                   "failing_count": ops_fold.get("failing_count"),
                   "monitor_count": ops_fold.get("monitor_count")}
    if monitor is None:
        return (disclosure_, word)
    return (disclosure_, f"{word}（{monitor}: {reason}）")


def compose(rows: Sequence[Mapping], *,
            attention: Optional[Mapping] = None,
            attention_absent_reason: Optional[str] = None,
            ops_fold: Optional[Mapping] = None) -> dict:
    """`{text, template_ref, inputs}`. A pure function of served data.

    `rows` are R1's own rows — the same objects the envelope carries — so
    the sentence and the cards under it cannot disagree about a count.
    """
    counts = _counts(rows)
    ops = dict(ops_fold or {})
    attention_disclosure, attention_text = _attention_component(
        rows, attention, attention_absent_reason)
    trust_disclosure, trust_text = _trust_component(ops)

    template = (COLD_TEMPLATE if counts["concluded_count"] == 0
                else SUMMARY_TEMPLATE)
    slots = {**counts, "attention": attention_text, "trust": trust_text}
    slots = {name: slots[name] for name in template.slots}

    components = {
        COMPONENT_CHANGE: {"supplied": True, "reason": None},
        COMPONENT_ATTENTION: attention_disclosure,
        COMPONENT_TRUST: trust_disclosure,
    }
    return {
        "text": template.render(slots),
        "template_ref": template.ref,
        "inputs": {
            **counts,
            "components": components,
            # NAMED, never dropped: the reader must be able to see which
            # part of the answer is missing without diffing two responses.
            "unsupplied": [name for name in COMPONENTS
                           if not components[name]["supplied"]],
            "slots": dict(slots),
        },
    }


def disclosure() -> dict:
    """Every board template with its id, version and slots (AP2 / NP6)."""
    return {template.ref: {"template_id": template.template_id,
                           "version": template.version,
                           "slots": list(template.slots),
                           "text": template.text}
            for template in (SUMMARY_TEMPLATE, COLD_TEMPLATE)}


__all__ = ["SUMMARY_TEMPLATE", "COLD_TEMPLATE", "BAND_TEXT", "EMPTY_TEXT",
           "ATTENTION_ABSENT_TEXT", "COMPONENTS", "COMPONENT_CHANGE",
           "COMPONENT_ATTENTION", "COMPONENT_TRUST", "ATTENTION_NO_READER",
           "compose", "disclosure"]
