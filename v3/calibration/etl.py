"""WP-0.4 v2 — the edges between the ledger and the pure classifier.

`ground_truth.classify` has been complete and tested since WP-3.2, and
nothing ever called it: the labels the cutover calendar (C-15) waits for
never started accumulating. This module is the missing translation layer,
and ONLY that — every judgement stays in `ground_truth`:

    signal_observation row  -> ExternalEvent   (`event_from_signal`)
    conclusion row          -> ToolPosition    (`position_from_conclusion`)
    FALSE_NEGATIVE verdict  -> FnDraft         (`draft_for`)

Tier 1 (`tier1_decision`) is the one NEW rule, and it is a GATE, not a
generator: it decides which FALSE_NEGATIVE verdicts the ETL may submit as
labels (>=2 distinct non-circular sources converge, NP2) and which must
wait as pending drafts for the LLM second reader / the asynchronous human
(ADR-V3-012). It never edits a verdict, so the label that is eventually
written is the classifier's, whichever tier released it.

The source vocabulary here must match `ground_truth`'s identity ladder:
an event source the ladder cannot name would make the severity-floor rule
raise on the very evidence the pipeline is built on, which is why the
ladder gained `auto:rss` / `auto:rss_gdelt` in the same change.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from v3.calibration import ground_truth as GT
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError

#: signal_observation.signal_source -> ExternalEvent.source. Only the two
#: non-circular calibration sources (S1-CALIB-004): llm_intel and
#: sequence_events are consumed by scoring and cannot testify to a miss,
#: and every other sensor is not a graded event source.
EVENT_SOURCE_BY_SIGNAL: Mapping[str, str] = {
    "bg_observer_rss": "rss",
    "gdelt": "gdelt",
}

#: The only status that is an event. OBSERVED is a baseline sample and
#: NO_DATA is an absence report; treating either as evidence would let a
#: quiet day corroborate a miss.
_STATUS_FIRED = "FIRED"


def _flags_of(row: Mapping) -> dict:
    flags = row.get("flags")
    if isinstance(flags, Mapping):
        return dict(flags)
    if isinstance(flags, str) and flags.strip():
        try:
            parsed = json.loads(flags)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def event_from_signal(row: Mapping) -> Optional[GT.ExternalEvent]:
    """One stored observation as classifier evidence, or None.

    None is a scope answer, not an error: most observations are not
    graded events. Suppressed rows are excluded — a row scoring refused
    to admit must not testify in scoring's own audit.
    """
    source = EVENT_SOURCE_BY_SIGNAL.get(str(row.get("signal_source") or ""))
    if source is None:
        return None
    if str(row.get("status") or "") != _STATUS_FIRED:
        return None
    if row.get("suppressed"):
        return None
    observed_at = row.get("observed_at")
    if observed_at is None:
        return None
    flags = _flags_of(row)
    fatalities = flags.get("fatalities")
    if isinstance(fatalities, bool) or not isinstance(fatalities, int):
        fatalities = 0
    confidence = flags.get("extractor_confidence")
    if isinstance(confidence, bool) or \
            not isinstance(confidence, (int, float)):
        confidence = float(row.get("confidence") or 0.0)
    return GT.ExternalEvent(
        source=source,
        severity=float(row.get("raw_score") or 0.0),
        fatalities=max(0, fatalities),
        confidence=float(confidence),
        observed_at=float(observed_at),
        url=row.get("evidence_url") or None)


#: How much of one observation's text a draft carries. The note exists
#: so a second reader can judge whether the event is real; a whole feed
#: item would push the prompt past what the verdict is worth.
EVIDENCE_NOTE_LIMIT = 400


def evidence_note_of(row: Mapping) -> str:
    """The observation's own words, for a reader that cannot fetch a URL.

    Found by deploying (2026-08-15): the draft carried the classifier's
    RULE sentence, the source name and a link — and Tier 2 has no
    network, so it could not assess "is this event real" and routed
    every candidate to a human. The article text was in the ledger the
    whole time, on the row the rule fired from.

    RSS rows carry the extractor's summary in `flags`; GDELT carries a
    rendered `value`. Both are already stored; nothing new is fetched.
    """
    flags = _flags_of(row)
    for candidate in (flags.get("summary"), row.get("value"),
                      flags.get("reason")):
        text = str(candidate or "").strip()
        if text:
            return text[:EVIDENCE_NOTE_LIMIT]
    return ""


def tl_of_state(state) -> Optional[int]:
    """`"TL4"` -> 4, anything else -> None. The verbatim state stays the
    position's `state`; this is only the numeric reading `is_alert`
    compares against the severity ladder."""
    if not isinstance(state, str) or not state.startswith("TL"):
        return None
    try:
        return int(state[2:])
    except ValueError:
        return None


def position_from_conclusion(row: Mapping, *,
                             now: float) -> Optional[GT.ToolPosition]:
    """One stored threat_level conclusion as a classifier position.

    An unavailable conclusion returns None: the tool said "cannot
    conclude", and scoring that as a calm call would let a data outage
    accumulate TRUE_NEGATIVEs — incident #1's perfect record, rebuilt
    out of absences.
    """
    if str(row.get("conclusion_type") or "") != "threat_level":
        return None
    if row.get("conclusion_unavailable_reason"):
        return None
    observed_at = row.get("observed_at")
    if observed_at is None:
        return None
    state = str(row.get("state") or "")
    return GT.ToolPosition(
        conclusion_type="threat_level", tl=tl_of_state(state), state=state,
        observed_at=float(observed_at), now=float(now))


def convergent_sources(position: GT.ToolPosition,
                       events: Iterable[GT.ExternalEvent]) -> tuple:
    """The distinct non-circular sources inside the position's forward
    window — the same evidence set the classifier's FN rules read, so
    the gate and the verdict cannot disagree about what converged."""
    return tuple(sorted({
        event.source for event in events
        if not event.is_circular
        and GT.in_forward_window(observed_at=position.observed_at,
                                 event_at=event.observed_at)}))


def tier1_decision(sources: tuple) -> str:
    """`"auto_confirm"` or `"pending"` — the whole of Tier 1.

    >=2 distinct sources converge -> the label may be written by the
    automated actor (NP2's convergence, applied to ground truth).
    Fewer -> the candidate waits, in the open, as a draft.
    """
    if len(sources) >= T.S9_TIER1_MIN_DISTINCT_SOURCES:
        return "auto_confirm"
    return "pending"


def draft_id_for(*, conclusion_id: str, rule_id: str, epoch_id: str) -> str:
    """One draft per (conclusion, rule, epoch) — a daily re-scan lands on
    the same id, and the pending count stays a set, not a tally."""
    material = f"{conclusion_id}\x1f{rule_id}\x1f{epoch_id}"
    return "fnd_" + hashlib.sha256(material.encode()).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class FnDraft:
    """A FALSE_NEGATIVE candidate Tier 1 could not release.

    Carries everything a later confirm needs to submit the IDENTICAL
    label the classifier proposed — a confirm that recomputed the label
    would be a second judgement wearing the first one's provenance.
    """

    draft_id: str
    scenario_id: str
    conclusion_type: str
    conclusion_id: str
    label: str
    reason: str
    proposed_analyst_id: str
    generator_id: str
    generator_version: str
    rule_id: str
    epoch_id: str
    observed_at: float
    labelled_at: float
    sources: tuple
    evidence_url: Optional[str] = None
    #: The observation's own words (`evidence_note_of`). Empty when the
    #: stored row carried none — an empty note is a fact about the
    #: evidence, and a reader told "no text available" can route on that
    #: rather than guess.
    evidence_note: str = ""

    def __post_init__(self) -> None:
        if self.label != "FALSE_NEGATIVE":
            raise DomainError(
                f"a draft is an FN candidate by definition, got "
                f"{self.label!r}: the other three labels never wait — "
                f"TP/FP/TN are the classifier's own mechanical claims and "
                f"Tier 1 has no jurisdiction over them")
        for name in ("draft_id", "scenario_id", "conclusion_type",
                     "conclusion_id", "reason", "proposed_analyst_id",
                     "generator_id", "generator_version", "rule_id",
                     "epoch_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(f"a draft needs a non-empty {name}")
        object.__setattr__(self, "sources", tuple(self.sources))


def draft_for(verdict: GT.LabelVerdict, *, scenario_id: str,
              conclusion_id: str, observed_at: float, labelled_at: float,
              sources: tuple, evidence_note: str = "") -> FnDraft:
    """The pending row for one withheld FALSE_NEGATIVE verdict."""
    if verdict.label != "FALSE_NEGATIVE" or verdict.provenance is None:
        raise DomainError(
            f"draft_for takes a FALSE_NEGATIVE verdict with provenance, "
            f"got label={verdict.label!r}")
    provenance = verdict.provenance
    return FnDraft(
        draft_id=draft_id_for(conclusion_id=conclusion_id,
                              rule_id=provenance.rule_id,
                              epoch_id=provenance.epoch_id),
        scenario_id=scenario_id, conclusion_type="threat_level",
        conclusion_id=conclusion_id, label="FALSE_NEGATIVE",
        reason=verdict.reason,
        proposed_analyst_id=verdict.analyst_id or "auto:unknown",
        generator_id=provenance.generator_id,
        generator_version=provenance.generator_version,
        rule_id=provenance.rule_id, epoch_id=provenance.epoch_id,
        observed_at=float(observed_at), labelled_at=float(labelled_at),
        sources=tuple(sources), evidence_url=verdict.evidence_url,
        evidence_note=str(evidence_note or "")[:EVIDENCE_NOTE_LIMIT])


__all__ = ["EVENT_SOURCE_BY_SIGNAL", "EVIDENCE_NOTE_LIMIT",
           "evidence_note_of", "event_from_signal", "tl_of_state",
           "position_from_conclusion", "convergent_sources",
           "tier1_decision", "draft_id_for", "FnDraft", "draft_for"]
