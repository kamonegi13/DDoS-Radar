"""The records the ledger accepts, expressed in kernel types.

The API boundary is where a raw float or a bare dict would otherwise slip
in and become a stored "fact" nobody can trace. Both record types below
refuse that at construction: an observation must arrive as kernel
`Evidence` (so it carries its own freshness horizon and source), and a
threat level must arrive as kernel `ThreatLevel` (so the inverted scale
cannot be misread on the way in).
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional

from v3.kernel import Evidence, ThreatLevel
from v3.kernel.errors import DomainError


def _require_text(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(f"{name} must be a non-empty string, got {value!r}")
    return value.strip()


def _optional_number(value, *, name: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(f"{name} must be a number or None, got {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric):
        raise DomainError(
            f"{name} must be finite, got {value!r}: a NaN stored as a fact "
            f"compares False against every later threshold")
    return numeric


@dataclass(frozen=True, slots=True)
class SignalObservation:
    """One sensor signal for one country at one tick (S5-VERIF-018)."""

    tick_id: str
    sensor: str
    signal_source: str
    domain: str
    country: str
    evidence: Evidence
    status: str
    raw_score: Optional[float] = None
    confidence: Optional[float] = None
    flags: Mapping[str, Any] = field(default_factory=dict)
    suppressed: bool = False
    suppress_reason: Optional[str] = None
    evidence_url: Optional[str] = None

    def __init_subclass__(cls, **kwargs):
        raise TypeError("SignalObservation is final.")

    def __post_init__(self) -> None:
        for name in ("tick_id", "sensor", "signal_source", "domain",
                     "country", "status"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        if not isinstance(self.evidence, Evidence):
            raise DomainError(
                f"observation evidence must be a kernel Evidence, got "
                f"{type(self.evidence).__name__}. A bare payload carries no "
                f"observation time and no freshness horizon, which is how "
                f"stale data became a stored fact (B-03).")
        object.__setattr__(self, "raw_score",
                           _optional_number(self.raw_score, name="raw_score"))
        object.__setattr__(
            self, "confidence",
            _optional_number(self.confidence, name="confidence"))
        if not isinstance(self.flags, Mapping):
            raise DomainError(
                f"flags must be a mapping, got {type(self.flags).__name__}")
        # A read-only view: a stored fact must not be editable through the
        # record that describes it.
        object.__setattr__(self, "flags", MappingProxyType(dict(self.flags)))
        if not isinstance(self.suppressed, bool):
            # bool("false") is True, and the migration ETL will be reading
            # exactly that kind of string out of the old rows.
            raise DomainError(
                f"suppressed must be a real bool, got "
                f"{type(self.suppressed).__name__} {self.suppressed!r}; "
                f"coercing would make bool('false') mean True")

    @property
    def observed_at(self) -> float:
        return self.evidence.observed_at

    def flags_json(self) -> str:
        # allow_nan=False: a NaN would serialise to the non-standard
        # `NaN` token, which every strict JSON reader downstream rejects.
        return json.dumps(dict(self.flags), sort_keys=True, default=str,
                          allow_nan=False, ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class TLObservation:
    """One scenario's threat level at one tick. `threat_level=None` is the
    null zone — a first-class state, not a missing row (NP5+8)."""

    tick_id: str
    scenario_id: str
    observed_at: float
    threat_level: Optional[ThreatLevel]
    score: float
    cyber: float = 0.0
    physical: float = 0.0
    info: float = 0.0
    convergence_bonus: float = 0.0
    scoring_mode: str = "full"
    active_countries: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs):
        raise TypeError("TLObservation is final.")

    def __post_init__(self) -> None:
        object.__setattr__(self, "tick_id",
                           _require_text(self.tick_id, name="tick_id"))
        object.__setattr__(self, "scenario_id",
                           _require_text(self.scenario_id, name="scenario_id"))
        observed_at = _optional_number(self.observed_at, name="observed_at")
        if observed_at is None or observed_at <= 0:
            raise DomainError(
                f"observed_at must be a positive timestamp, "
                f"got {self.observed_at!r}")
        object.__setattr__(self, "observed_at", observed_at)
        if self.threat_level is not None and \
                not isinstance(self.threat_level, ThreatLevel):
            raise DomainError(
                f"threat_level must be a kernel ThreatLevel or None (null "
                f"zone), got {type(self.threat_level).__name__}. A raw int "
                f"loses the inverted-scale guard that calibration incident "
                f"#2 turned on.")
        score = _optional_number(self.score, name="score")
        if score is None:
            # 0.0 is a legitimate score, so coercing None to it would turn
            # a missing value into a real measurement.
            raise DomainError("score is required; None is not a score")
        object.__setattr__(self, "score", score)
        for name in ("cyber", "physical", "info", "convergence_bonus"):
            value = _optional_number(getattr(self, name), name=name)
            object.__setattr__(self, name, 0.0 if value is None else value)
        object.__setattr__(self, "active_countries",
                           tuple(self.active_countries))

    @property
    def tl_value(self) -> Optional[int]:
        return None if self.threat_level is None else self.threat_level.value

    def countries_json(self) -> str:
        return json.dumps(list(self.active_countries), allow_nan=False,
                          ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class ConclusionRecord:
    """One conclusion row (S3-DATA-010's shape).

    Explicit fields rather than a **kwargs bag: a bag accepts a typo
    silently and stores a row missing the field the caller thought they
    set. L1 owns storage and retention for these; L3 (WP-3.1) owns the
    semantics.
    """

    conclusion_id: str
    scenario_id: str
    conclusion_type: str
    observed_at: float
    confidence: float
    state: Optional[str] = None
    formula_ref: str = ""
    threshold_ref: str = ""
    source_urls: tuple[str, ...] = ()
    llm_prompt_sha256: Optional[str] = None
    calibration_status: str = ""
    conclusion_unavailable_reason: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs):
        raise TypeError("ConclusionRecord is final.")

    def __post_init__(self) -> None:
        for name in ("conclusion_id", "scenario_id", "conclusion_type"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        observed_at = _optional_number(self.observed_at, name="observed_at")
        if observed_at is None or observed_at <= 0:
            raise DomainError(
                f"observed_at must be a positive timestamp, "
                f"got {self.observed_at!r}")
        object.__setattr__(self, "observed_at", observed_at)
        confidence = _optional_number(self.confidence, name="confidence")
        if confidence is None:
            raise DomainError("confidence is required")
        object.__setattr__(self, "confidence", confidence)
        if not isinstance(self.metadata, Mapping):
            raise DomainError(
                f"metadata must be a mapping, got "
                f"{type(self.metadata).__name__}")
        object.__setattr__(self, "metadata",
                           MappingProxyType(dict(self.metadata)))
        object.__setattr__(self, "source_urls", tuple(self.source_urls))

    def source_urls_json(self) -> str:
        return json.dumps(list(self.source_urls), allow_nan=False,
                          ensure_ascii=False)

    def metadata_json(self) -> str:
        return json.dumps(dict(self.metadata), sort_keys=True, default=str,
                          allow_nan=False, ensure_ascii=False)


def _json(value, *, name: str) -> str:
    """Serialise a before/after value, refusing what cannot round-trip.

    `default=str` is deliberately NOT used here, unlike the observation
    records. An observation's payload is evidence from outside and a
    best-effort stringification of an odd object still carries the
    evidence; a before/after value is compared for equality on the next
    command (the stale-write check), and a value that serialises as
    `"<object at 0x…>"` would compare unequal to itself on every
    subsequent read — a command that could never succeed twice.
    """
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False,
                          ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise DomainError(
            f"{name} must be JSON-serialisable without coercion, got "
            f"{type(value).__name__}: the value is compared against the "
            f"stored one on the next command, so a lossy encoding is a "
            f"command that silently stops being repeatable") from exc


@dataclass(frozen=True, slots=True)
class CommandRecord:
    """One analyst command: the audit row AND the change itself.

    S2-PROP-019 is "one change, one audit row". The usual reading of that
    is a discipline — write the change, then remember to write the audit
    row. G-15 is what the usual reading produces: an override row and an
    audit row were both written honestly, the UI showed the new value, and
    nothing read it.

    So this record is not a note about a change kept beside it. The
    effective state of everything the command surface governs (focus,
    labels, ground truth) is the FOLD of these rows, which means there is
    no way to make the change without the row, and no way for the row to
    describe a change that did not happen.

    `actor_id` / `actor_role` are fields of the stored record rather than
    of the thing a handler builds (`v3.api.write.Change`), so a handler
    cannot record an actor other than the principal the route resolved.
    """

    command_id: str
    action: str
    target_kind: str
    target_id: str
    actor_id: str
    actor_role: str
    issued_at: float
    before: Any = None
    after: Any = None
    reason: Optional[str] = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs):
        raise TypeError("CommandRecord is final.")

    def __post_init__(self) -> None:
        for name in ("command_id", "action", "target_kind", "target_id",
                     "actor_id", "actor_role"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        issued_at = _optional_number(self.issued_at, name="issued_at")
        if issued_at is None or issued_at <= 0:
            raise DomainError(
                f"issued_at must be a positive timestamp, got "
                f"{self.issued_at!r}")
        object.__setattr__(self, "issued_at", issued_at)
        if self.reason is not None:
            object.__setattr__(self, "reason",
                               _require_text(self.reason, name="reason"))
        if not isinstance(self.payload, Mapping):
            raise DomainError(
                f"payload must be a mapping, got "
                f"{type(self.payload).__name__}")
        object.__setattr__(self, "payload",
                           MappingProxyType(dict(self.payload)))
        # Serialise now, at construction, so an unstorable value is a
        # refused record rather than a transaction that fails halfway.
        _json(self.before, name="before")
        _json(self.after, name="after")
        _json(dict(self.payload), name="payload")

    @property
    def changed(self) -> bool:
        """Whether this row actually moved the state it describes."""
        return self.before != self.after

    def before_json(self) -> str:
        return _json(self.before, name="before")

    def after_json(self) -> str:
        return _json(self.after, name="after")

    def payload_json(self) -> str:
        return _json(dict(self.payload), name="payload")

    def as_dict(self) -> dict:
        return {"command_id": self.command_id, "action": self.action,
                "target_kind": self.target_kind, "target_id": self.target_id,
                "actor_id": self.actor_id, "actor_role": self.actor_role,
                "issued_at": self.issued_at, "before": self.before,
                "after": self.after, "reason": self.reason,
                "payload": dict(self.payload)}


@dataclass(frozen=True, slots=True)
class LabelRecord:
    """One label on one conclusion — `analyst_feedback`'s v3 form.

    The four provenance fields are REQUIRED and non-empty, and that is the
    whole point of the type. F-16 is a null in exactly this position: the
    checked-in recall baseline carried `since: null`, so every gate run
    compared across two series breaks and nobody could see it. A label
    that cannot say which generator, which version, which rule and which
    EPOCH produced it is not a weaker label — it is a label that cannot be
    compared with any other, and pooling it is how a recall number becomes
    an artefact (S5-VERIF-032, incidents #1 / #2 / #3).

    L1 enforces PRESENCE. Whether `generator_version` is legitimately
    declared against `epoch_id` is L4's question, answered by
    `v3.calibration.epoch.LabelProvenance`, and `v3/calibration/labels.py`
    is the only module that builds one of these in production — proved by
    AST in `labels.audit_label_construction_sites()`, the same discipline
    `matrix.audit_recall_arithmetic_sites()` uses. The layer rule holds:
    L1 never imports L4, so the check runs the other way round.
    """

    label_id: str
    conclusion_id: str
    scenario_id: str
    conclusion_type: str
    label: str
    analyst_id: str
    observed_at: float
    labelled_at: float
    generator_id: str
    generator_version: str
    rule_id: str
    epoch_id: str
    is_automated: bool = False
    observed_outcome_url: Optional[str] = None
    reason: Optional[str] = None

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "LabelRecord is final: a subclass could default a provenance "
            "field, and a defaulted epoch is an undeclared population.")

    def __post_init__(self) -> None:
        for name in ("label_id", "conclusion_id", "scenario_id",
                     "conclusion_type", "label", "analyst_id",
                     "generator_id", "generator_version", "rule_id",
                     "epoch_id"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        for name in ("observed_at", "labelled_at"):
            value = _optional_number(getattr(self, name), name=name)
            if value is None or value <= 0:
                raise DomainError(
                    f"{name} must be a positive timestamp, got "
                    f"{getattr(self, name)!r}: a label outside every window "
                    f"is a label no measurement can include or exclude")
            object.__setattr__(self, name, value)
        if not isinstance(self.is_automated, bool):
            raise DomainError(
                f"is_automated must be a real bool, got "
                f"{type(self.is_automated).__name__}: `exclude_auto` is a "
                f"filter on this field and a truthy string would place an "
                f"automated label in the human population")
        for name in ("observed_outcome_url", "reason"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise DomainError(f"{name} must be a string or None")

    def as_dict(self) -> dict:
        return {"label_id": self.label_id,
                "conclusion_id": self.conclusion_id,
                "scenario_id": self.scenario_id,
                "conclusion_type": self.conclusion_type,
                "label": self.label, "analyst_id": self.analyst_id,
                "observed_at": self.observed_at,
                "labelled_at": self.labelled_at,
                "generator_id": self.generator_id,
                "generator_version": self.generator_version,
                "rule_id": self.rule_id, "epoch_id": self.epoch_id,
                "is_automated": self.is_automated,
                "observed_outcome_url": self.observed_outcome_url,
                "reason": self.reason}


@dataclass(frozen=True, slots=True)
class ProposalRecord:
    """One emitted proposal. The QUEUE row, never the state.

    There is deliberately no `state` column. S1-CALIB-052 fixes six values
    and production keeps them in a column an UPDATE moves — which is why
    `state_changed_by` marker strings are the only way to tell an analyst
    dismissal from an automatic one (ACCIDENTAL A9), and why S1-CALIB-041
    has no persistent trace of a refusal at all. Here the state is the
    fold of the adjudication commands in `command_record`, so every
    transition carries the actor, the instant and the reason the write
    seam already requires, and a marker string is not load-bearing.

    `epoch_id` is on the row because a proposal is only as comparable as
    the labels that motivated it: applying a proposal generated under a
    quarantined epoch is the mechanism of incident #1, not a variant of it.
    """

    proposal_id: str
    proposal_type: str
    scenario_id: str
    proposal_key: str
    impact: str
    emitted_at: float
    epoch_id: str
    formula_ref: str
    target_country: str = ""
    prior_value: Optional[float] = None
    proposed_value: Optional[float] = None
    direction: str = ""
    sample_n: int = 0
    evidence: Mapping[str, Any] = field(default_factory=dict)
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs):
        raise TypeError("ProposalRecord is final.")

    def __post_init__(self) -> None:
        for name in ("proposal_id", "proposal_type", "scenario_id",
                     "proposal_key", "impact", "epoch_id", "formula_ref"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        emitted = _optional_number(self.emitted_at, name="emitted_at")
        if emitted is None or emitted <= 0:
            raise DomainError(
                f"emitted_at must be a positive timestamp, got "
                f"{self.emitted_at!r}: the auto-dismiss hooks judge by it "
                f"(S1-CALIB-053) and a proposal with no emission instant is "
                f"one they can neither retire nor keep")
        object.__setattr__(self, "emitted_at", emitted)
        for name in ("prior_value", "proposed_value"):
            object.__setattr__(self, name,
                               _optional_number(getattr(self, name),
                                                name=name))
        for name in ("target_country", "direction"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise DomainError(f"{name} must be a string, got {value!r}")
            object.__setattr__(self, name, value.strip())
        if isinstance(self.sample_n, bool) or \
                not isinstance(self.sample_n, int) or self.sample_n < 0:
            raise DomainError(
                f"sample_n must be a non-negative integer, got "
                f"{self.sample_n!r}")
        for name in ("evidence", "payload"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise DomainError(f"{name} must be a mapping")
            object.__setattr__(self, name, MappingProxyType(dict(value)))

    def evidence_json(self) -> str:
        return _json(dict(self.evidence), name="evidence")

    def payload_json(self) -> str:
        return _json(dict(self.payload), name="payload")

    def as_dict(self) -> dict:
        return {"proposal_id": self.proposal_id,
                "proposal_type": self.proposal_type,
                "scenario_id": self.scenario_id,
                "target_country": self.target_country,
                "proposal_key": self.proposal_key,
                "prior_value": self.prior_value,
                "proposed_value": self.proposed_value,
                "direction": self.direction, "impact": self.impact,
                "sample_n": self.sample_n, "emitted_at": self.emitted_at,
                "epoch_id": self.epoch_id, "formula_ref": self.formula_ref,
                "evidence": dict(self.evidence),
                "payload": dict(self.payload)}


#: The three factors AP1 names, in the order the formula multiplies them.
#: Spelled once, here, because the table has a column per factor AND the
#: provenance blob repeats their inputs — two places that must agree about
#: what a factor is called, and a third spelling would make the audit read
#: one name against another.
ATTENTION_FACTORS: tuple[str, ...] = ("novelty", "confidence_delta",
                                      "analyst_blindness")


@dataclass(frozen=True, slots=True)
class AttentionRankRecord:
    """One ranked item in one S8 snapshot, with the factors that ranked it.

    G-03 was that `attention_score` existed only in `triage_score.js`: the
    order an analyst acted on was computed in a browser, from a per-browser
    `localStorage` view timestamp, and left no trace anywhere. So AP4 could
    replay every automated judgement EXCEPT the one that decided what the
    analyst looked at first.

    The three factors are columns rather than keys inside `components`
    because AP1 requires the rationale to be visible, and a factor that is
    only inside a JSON blob is a factor no query can order by, band or
    audit. `components` holds the INPUTS of each factor (the timestamps and
    confidences the factor was computed from), which is what makes the row
    re-derivable rather than merely readable (NP6).
    """

    snapshot_id: str
    computed_at: float
    scenario_id: str
    item_kind: str
    item_id: str
    rank_position: int
    score: float
    novelty: float
    confidence_delta: float
    analyst_blindness: float
    formula_ref: str
    narrative_template_ref: str
    narrative: str
    components: Mapping[str, Any] = field(default_factory=dict)

    def __init_subclass__(cls, **kwargs):
        raise TypeError("AttentionRankRecord is final.")

    def __post_init__(self) -> None:
        for name in ("snapshot_id", "scenario_id", "item_kind", "item_id",
                     "formula_ref", "narrative_template_ref", "narrative"):
            object.__setattr__(self, name,
                               _require_text(getattr(self, name), name=name))
        computed_at = _optional_number(self.computed_at, name="computed_at")
        if computed_at is None or computed_at <= 0:
            raise DomainError(
                f"computed_at must be a positive timestamp, got "
                f"{self.computed_at!r}")
        object.__setattr__(self, "computed_at", computed_at)
        if isinstance(self.rank_position, bool) or \
                not isinstance(self.rank_position, int):
            raise DomainError(
                f"rank_position must be an int, got {self.rank_position!r}")
        if self.rank_position < 1:
            raise DomainError(
                f"rank_position is 1-based, got {self.rank_position}: a rank "
                f"of 0 reads as 'unranked' in one place and 'first' in "
                f"another")
        for name in ("score",) + ATTENTION_FACTORS:
            value = _optional_number(getattr(self, name), name=name)
            if value is None or not (0.0 <= value <= 1.0):
                raise DomainError(
                    f"{name} must be within [0, 1], got "
                    f"{getattr(self, name)!r}. Clamping happens in the pure "
                    f"scorer where it is disclosed; a value arriving here "
                    f"out of range means the scorer was bypassed.")
            object.__setattr__(self, name, value)
        if not isinstance(self.components, Mapping):
            raise DomainError(
                f"components must be a mapping, got "
                f"{type(self.components).__name__}")
        object.__setattr__(self, "components",
                           MappingProxyType(dict(self.components)))
        _json(dict(self.components), name="components")

    def components_json(self) -> str:
        return _json(dict(self.components), name="components")

    def as_dict(self) -> dict:
        return {"snapshot_id": self.snapshot_id,
                "computed_at": self.computed_at,
                "scenario_id": self.scenario_id,
                "item_kind": self.item_kind, "item_id": self.item_id,
                "rank_position": self.rank_position, "score": self.score,
                "novelty": self.novelty,
                "confidence_delta": self.confidence_delta,
                "analyst_blindness": self.analyst_blindness,
                "formula_ref": self.formula_ref,
                "narrative_template_ref": self.narrative_template_ref,
                "narrative": self.narrative,
                "components": dict(self.components)}


__all__ = ["SignalObservation", "TLObservation", "ConclusionRecord",
           "CommandRecord", "LabelRecord", "ProposalRecord",
           "AttentionRankRecord", "ATTENTION_FACTORS"]
