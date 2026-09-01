"""LLM intel extraction: one implementation, five sources. P6 O-17 / §4-1.

Production has eight of these (A-02). The v3 norm stated in
S1-sensors-info-llm §4 表 2 is that S1-INGEST-010..020 become a single
submission layer and **the per-sensor BEHAVIOURAL surface is exactly four
slots**:

    prefilter | prompt body | score_delta formula | domain

`IntelProfile` carries those four and, alongside them, DECLARED DATA the
one extraction implementation interprets — the response-disposition table
(裁定要求 10, ruled 2026-08-08), the carried `llm_fields` keys, the token
budget, the schema keys. The distinction is what the limit is actually
protecting: four slots exist to stop per-sensor BEHAVIOUR proliferating
back into this path, not to cap the number of fields on a dataclass. A
rule table has no branch in which a sensor's habit can hide, which is why
it stays one implementation; a fifth callable would have had one.

Same shape as `RequestSpec` (declared data, not a fetch function) and
`RequestContinuation` (WHICH field is the handle, not HOW to fetch it),
and a callable inside a rule raises for the same reason `.path` does.

Everything that was duplicated eight ways — the country normalisation,
the confidence floor, the relevance disposition, the additive
composition, the thirteen-field envelope — lives here once, because eight
copies is how the floor came to be 0.35 in seven of them and 0.50 in the
eighth
(`convergence_tracker.py:382`), and how `max_tokens` came to span 200-512.

WHERE THE ITEMS GO. O-17 / §4-2: an extracted item is an ordinary L1
observation (`ObservationDraft`, `signal_source="llm_intel"`), not a row
in a second scoring queue. `signal_source` is the literal `llm_intel`
because S1-INTEL-020 pins it as the dedup unit S1-SCORE-008 folds on —
and the L2 side reads that same literal to recover `origin=llm_intel`,
which is what arms the WP-2.4 addendum's age term.

WHAT DOES NOT COME ACROSS. There is no `score_delta` field on an
observation and no bespoke decay: the number an item carries is its
`raw_score`, and its age is `observed_at`. O-17 abolished the second
mechanism; keeping a decayed number here would have rebuilt it.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional, Sequence

from v3.adapters.common import as_float, mapping_or_empty
from v3.adapters.types import (INFO, ObservationDraft, STATUS_FIRED)
from v3.kernel.errors import DomainError

#: S1-INTEL-020 pins the intel signal source to this literal, and
#: `v3/parity/adapter.py` reads it back to recover the observation's
#: origin. One constant, named in both places.
LLM_INTEL_SOURCE = "llm_intel"

#: S1-INGEST-014: the floor seven of the eight production copies use
#: (`ast`-verified at diplomatic.py:479, military_exercise.py:358,
#: apt_intel.py:540, hacktivist_intel_sensor.py:157,
#: hacktivist_news_sensor.py:368, ground_osint_sensor.py:237,
#: rss_narrative.py:527). The eighth, `convergence_tracker.py:382`, uses
#: 0.50 — and is not ported (§4-3), so the divergence leaves with it.
CONFIDENCE_FLOOR = 0.35

#: S1-INGEST-019's envelope limits (`ast`-verified, diplomatic.py:528-550).
CONFIDENCE_DIGITS = 3
RAW_TEXT_LIMIT = 1000
HEADLINE_LIMIT = 100

#: S1-INGEST-017's self-reported relevance vocabulary.
LINK_DIRECT, LINK_INDIRECT, LINK_NONE = "direct", "indirect", "none"

# ── silence reason codes (S1-INGEST-014 / 020) ───────────────────────────
# Kept apart on purpose: "the model saw nothing" is a prompt problem and
# "it scored under the floor" is a threshold problem, and a single
# `dropped` counter makes both undiagnosable.
NO_SIGNAL = "no_escalation_signal"
BELOW_FLOOR = "confidence_below_floor"
NO_PRIMARY_COUNTRY = "primary_country_unresolved"
RELEVANCE_NONE = "relevance_none"
NOT_IN_SCOPE = "primary_country_out_of_scope"


def sanitize(text: str, max_len: int) -> str:
    """S1-INGEST-011: cap the length, then normalise, then de-fang.

    Order transcribed from `radar/llm_client.py:177-183` — truncate FIRST,
    so the cap applies to what the feed sent rather than to what
    normalisation produced.

    NOTE (registered as an expected difference, design sheet §7-2): the
    full prompt-injection phrase corpus (`llm_client.py:61-99`, four
    languages plus chat-template delimiters) is a security control S4
    owns and is NOT transcribed here. This function carries the
    truncation, the NFKC fold and the control-character strip; the
    delimiter tokens are stripped because they are structural rather than
    lexical, and leaving them would let a feed close the system turn.
    """
    if not isinstance(max_len, int) or isinstance(max_len, bool) or \
            max_len <= 0:
        raise DomainError(
            f"sanitize max_len must be a positive integer, got {max_len!r}; "
            f"S1-INGEST-011 requires the cap to be stated at the call site")
    if not text:
        return ""
    clipped = str(text)[:max_len]
    folded = unicodedata.normalize("NFKC", clipped)
    kept = "".join(ch for ch in folded
                   if unicodedata.category(ch) not in ("Cc", "Cf")
                   or ch in "\n\t")
    for delimiter in ("<|im_start|>", "<|im_end|>", "<|system|>", "<|user|>",
                      "[INST]", "[/INST]", "[SYS]", "[/SYS]"):
        kept = kept.replace(delimiter, "[...]")
    return kept


def normalize_countries(data: Mapping, *, primary: str) -> tuple[
        tuple[str, ...], Mapping[str, float]]:
    """S1-INGEST-015: two-letter codes, weights clipped to [0, 1].

    The weight lookup is upper-key then lower-key, defaulting to 1.0 —
    transcribed from diplomatic.py:485-504, whose LLM sometimes answers
    with lowercase keys against uppercase codes. A missing weight
    defaults to 1.0 rather than to 0.0: a model that named a country and
    forgot to weight it named it.

    The primary country is inserted at the FRONT at weight 1.0 when the
    model left it out, so `countries[0]` is always the attribution the
    item is filed under.
    """
    raw_weights = mapping_or_empty(data.get("country_weights"))
    codes: list[str] = []
    for entry in (data.get("countries") or ()):
        code = str(entry or "").strip().upper()
        if len(code) != 2:
            continue          # S1-INGEST-015: only 2-letter codes survive
        if code not in codes:
            codes.append(code)
    if primary and primary not in codes:
        codes.insert(0, primary)
    weights: dict[str, float] = {}
    for code in codes:
        value = raw_weights.get(code)
        if value is None:
            value = raw_weights.get(code.lower())
        numeric = as_float(value, 1.0)
        if numeric is None:
            numeric = 1.0
        weights[code] = max(0.0, min(1.0, float(numeric)))
    if primary and primary in weights and primary not in (
            str(k).strip().upper() for k in raw_weights):
        weights[primary] = 1.0
    return tuple(codes), MappingProxyType(weights)


# ── the response-disposition table (ruled 2026-08-08, 裁定要求 10) ────────
#
# WHAT THIS IS AND WHY IT IS NOT A FIFTH SLOT. The four slots limit
# per-sensor BEHAVIOUR — code that runs inside the extraction path. They
# do not forbid a source from declaring DATA the one extraction
# implementation interprets. `RequestSpec` is that shape already (declared
# data, not a fetch function), and so is `RequestContinuation` (WHICH field
# is the handle, not HOW to fetch it). A disposition rule says which
# extracted VALUE leads to which outcome; the evaluation is here, once.
#
# The invariant being preserved is "one extraction implementation", not
# "four fields on a dataclass". A fifth CALLABLE would have meant eight
# per-sensor dispositions running eight ways, which is A-02 growing back.
# A table cannot: it has no branch to put a sensor's habit in.
DROP = "drop"
CAP = "cap"
ACCEPT = "accept"
DISPOSITIONS: frozenset = frozenset({DROP, CAP, ACCEPT})


@dataclass(frozen=True, slots=True)
class DispositionRule:
    """One extracted field value -> one outcome. Data, never a predicate.

    Production expresses the same thing as `if` statements inside each
    sensor: `military_exercise.py:343-349` drops `event_type == "none"`
    with its own drop code and keeps `status_report` /
    `historical_analysis` at a capped confidence, and every LLM sensor
    drops `theater_link == "none"` and caps `indirect`.
    """

    field: str
    values: tuple[str, ...]
    outcome: str
    #: Required for DROP. S1-INGEST-020 wants to know WHICH silence it
    #: was; collapsing a source's own drop code into a shared one makes
    #: "the model saw nothing" and "this was a weekly tracker" the same
    #: sentence, and they call for opposite responses.
    reason: str = ""
    cap: Optional[float] = None
    #: Also fire for a value outside the declared vocabulary. This is
    #: `safe_enum(value, allowed, default)`: production folds every
    #: unrecognised answer onto ONE member and that member's rule then
    #: applies. Exactly one rule per field may claim it.
    matches_unrecognised: bool = False

    def __post_init__(self) -> None:
        for name in ("field", "outcome", "reason"):
            value = getattr(self, name)
            if callable(value) or not isinstance(value, str):
                raise DomainError(
                    f"DispositionRule.{name} must be a string, got "
                    f"{type(value).__name__}. A callable here would make the "
                    f"table a place to write per-sensor behaviour, which is "
                    f"the eight-copy shape the four-slot limit exists to "
                    f"stop — the same reason RequestContinuation.path is "
                    f"data and not a lookup function.")
        if not self.field.strip():
            raise DomainError("DispositionRule.field must be non-empty")
        if self.outcome not in DISPOSITIONS:
            raise DomainError(
                f"DispositionRule.outcome must be one of "
                f"{sorted(DISPOSITIONS)}, got {self.outcome!r}")
        values = tuple(self.values or ())
        if not values:
            raise DomainError(
                f"DispositionRule for {self.field!r} matches no value; an "
                f"empty rule is indistinguishable from a forgotten one")
        for value in values:
            if callable(value) or not isinstance(value, str) or not value:
                raise DomainError(
                    f"DispositionRule.values must be non-empty strings, got "
                    f"{value!r}")
        object.__setattr__(self, "field", self.field.strip())
        object.__setattr__(self, "values",
                           tuple(v.strip().lower() for v in values))
        if self.outcome == DROP and not self.reason.strip():
            raise DomainError(
                f"a DROP rule for {self.field!r} must name its reason "
                f"(S1-INGEST-020): a cycle that submits nothing has to say "
                f"which silence it was")
        if self.outcome == CAP:
            if isinstance(self.cap, bool) or not isinstance(
                    self.cap, (int, float)):
                raise DomainError(
                    f"a CAP rule for {self.field!r} must state its cap")
            if not 0.0 <= float(self.cap) <= 1.0:
                raise DomainError(
                    f"cap must be within [0,1], got {self.cap}")
            if float(self.cap) < CONFIDENCE_FLOOR:
                # This is what makes ONE evaluation order safe for every
                # source. Production applies its caps at two different
                # points relative to the floor check (`military_exercise
                # .py:348` before, `:385` after), and the two orders agree
                # only while every cap sits at or above the floor: a cap
                # below it would drop items on one ordering and admit them
                # on the other, and the difference would be invisible.
                raise DomainError(
                    f"a cap below the confidence floor ({CONFIDENCE_FLOOR}) "
                    f"makes the evaluation order observable: capping to "
                    f"{self.cap} would itself push an item under the floor. "
                    f"Express that as a DROP with its own reason instead.")
            object.__setattr__(self, "cap", float(self.cap))
        elif self.cap is not None:
            raise DomainError(
                f"only a CAP rule carries a cap; the {self.outcome!r} rule "
                f"for {self.field!r} states one")


def _vocabularies(rules: Sequence[DispositionRule]) -> dict:
    """field -> the closed value set its rules declare, in order."""
    vocabulary: dict = {}
    for rule in rules:
        vocabulary.setdefault(rule.field, [])
        vocabulary[rule.field].extend(rule.values)
    return {field: tuple(values) for field, values in vocabulary.items()}


def apply_dispositions(rules: Sequence[DispositionRule], data: Mapping,
                       confidence: float) -> tuple[Optional[float], str]:
    """Evaluate the table once. `(confidence, "")` or `(None, reason)`.

    Rules are evaluated in DECLARATION order, and the first DROP wins, so
    the adapter's own drop code survives instead of being replaced by a
    later, more generic one.
    """
    vocabulary = _vocabularies(rules)
    result = float(confidence)
    for rule in rules:
        raw = str(data.get(rule.field) or "").strip().lower()
        hit = raw in rule.values or (
            rule.matches_unrecognised and raw not in vocabulary[rule.field])
        if not hit:
            continue
        if rule.outcome == DROP:
            return None, rule.reason
        if rule.outcome == CAP:
            result = min(result, float(rule.cap))
    return result, ""


def relevance_rules(*, indirect_cap: Optional[float]) -> tuple:
    """S1-INGEST-017 as rows: `none` drops, `indirect` caps.

    Every LLM sensor spells this the same way — `safe_enum(theater_link,
    {"direct","indirect","none"}, "none")`, then drop on `none`, then
    `min(confidence, cap)` on `indirect` (`diplomatic.py:507-518`,
    `military_exercise.py:374-385`). The DEFAULT is what makes the enum
    matter: an answer outside the three folds onto `none` and is DROPPED,
    which is the opposite of treating it as a direct link.

    The cap is per-source because production's two capping sensors
    disagree — 0.45 (`diplomatic.py:518`) and 0.50
    (`military_exercise.py:385`) — and a single value would be an
    invention, which P2 §5-C forbids mid-port.
    """
    rules = [DispositionRule(field="theater_link", values=(LINK_NONE,),
                             outcome=DROP, reason=RELEVANCE_NONE,
                             matches_unrecognised=True)]
    if indirect_cap is not None:
        rules.append(DispositionRule(field="theater_link",
                                     values=(LINK_INDIRECT,), outcome=CAP,
                                     cap=indirect_cap))
    else:
        rules.append(DispositionRule(field="theater_link",
                                     values=(LINK_INDIRECT,),
                                     outcome=ACCEPT))
    rules.append(DispositionRule(field="theater_link", values=(LINK_DIRECT,),
                                 outcome=ACCEPT))
    return tuple(rules)


@dataclass(frozen=True, slots=True)
class IntelItem:
    """S1-INGEST-019's thirteen-field envelope, as a value.

    Kept as its own type rather than folded straight into an
    `ObservationDraft` because the envelope IS the contract production
    submits, and WP-2.8 compares against production. `as_draft()` is the
    projection; the envelope is the record.
    """

    source_type: str
    source_id: str
    country: str                    # production's `theater` (§9-DP11)
    countries: tuple[str, ...]
    country_weights: Mapping[str, float]
    ts: float
    confidence: float
    raw_text: str
    raw_url: str
    headline: str
    llm_fields: Mapping[str, Any]
    score_delta: float
    domain: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence",
                           round(float(self.confidence), CONFIDENCE_DIGITS))
        object.__setattr__(self, "raw_text",
                           str(self.raw_text or "")[:RAW_TEXT_LIMIT])
        object.__setattr__(self, "headline",
                           str(self.headline or "")[:HEADLINE_LIMIT])
        object.__setattr__(self, "llm_fields",
                           MappingProxyType(dict(self.llm_fields or {})))
        object.__setattr__(self, "country_weights",
                           MappingProxyType(dict(self.country_weights or {})))
        if self.domain not in ("cyber", "physical", "info"):
            raise DomainError(
                f"intel domain must be cyber/physical/info, got "
                f"{self.domain!r}. `convergence_tracker` emitted a fourth "
                f"value, `mixed` (S1-SENSI-053), which is outside the "
                f"scoring layer's vocabulary — it is not ported (§4-3), and "
                f"the type refuses to let the value back in.")

    def as_draft(self) -> ObservationDraft:
        """The L1 observation this item lands as. O-17 / §4-2.

        `raw_score` is the UNDECAYED `score_delta`, and `observed_at`
        travels in `flags` for the runner to stamp: the age term is L2's
        (WP-2.4 addendum), so pre-decaying here would rebuild the second
        mechanism O-17 removed.
        """
        return ObservationDraft(
            signal_source=LLM_INTEL_SOURCE,
            domain=self.domain,
            country=self.country,
            status=STATUS_FIRED,
            raw_score=float(self.score_delta),
            confidence=float(self.confidence),
            evidence_url=self.raw_url or None,
            value=self.headline,
            reason=str(self.llm_fields.get("gate_reason", "")) or self.headline,
            flags={
                "origin": LLM_INTEL_SOURCE,
                "source_type": self.source_type,
                "source_id": self.source_id,
                "countries": list(self.countries),
                "country_weights": dict(self.country_weights),
                "observed_at": self.ts,
                "raw_text": self.raw_text,
                "llm_fields": dict(self.llm_fields),
                # The undecayed number, named. L2 multiplies it by the
                # age weight; publishing both is what makes the published
                # contribution arguable (NP6).
                "score_delta_raw": float(self.score_delta),
            })


#: The four names S1-sensors-info-llm §4 表 2 pins. Module level rather
#: than a class attribute because `slots=True` turns an annotated class
#: attribute into a descriptor, and the suite needs the tuple.
BEHAVIOURAL_SLOTS: tuple[str, ...] = ("prefilter", "prompt", "score_delta",
                                      "domain")


@dataclass(frozen=True, slots=True)
class IntelProfile:
    """Four BEHAVIOURAL slots, plus declared data the shared code reads.

    The four callables-and-domain are the surface S1-sensors-info-llm §4
    表 2 pins: `prefilter | prompt | score_delta | domain`. Everything
    else on this type is DATA — a table of values, a list of keys, a token
    budget — which the one extraction implementation interprets. That
    distinction is the whole rule: a fifth callable would let a sensor put
    its habits back inside the extraction path (A-02's eight copies), and
    a table cannot, because it has no branch to put them in.

    The suite pins the CALLABLE set, not the field count.
    """

    source_type: str
    #: slot 1 — returns True for an article worth spending a call on.
    prefilter: Callable[[Mapping], bool]
    #: slot 2 — builds (system, user) from one article and its context.
    prompt: Callable[[Mapping, Mapping], tuple[str, str]]
    #: slot 3 — `score_delta` from the model's validated answer.
    score_delta: Callable[[Mapping], float]
    #: slot 4 — the domain the item is counted in.
    domain: str = INFO
    #: DATA, not a slot: the response-disposition table (裁定要求 10,
    #: ruled 2026-08-08). See `DispositionRule`.
    dispositions: tuple = ()
    #: DATA: the key under which the model returns SEVERAL answers rather
    #: than one. `rss_narrative` asks for `clusters` (`rss_narrative
    #: .py:366-380`) because a keyword burst can pool articles on
    #: unrelated topics, and the single-synthesis flow it replaced was
    #: "forced to fabricate a common narrative" (`:307-311`). Empty means
    #: one answer, one item. The NAME is declared; the fan-out is here.
    response_items_key: str = ""
    #: DATA: WHICH key carries the model's own "this is a signal" verdict.
    #: Seven sources call it `escalation_signal`; `hacktivist_news` calls
    #: it `is_active_campaign` (`hacktivist_news_sensor.py:362`) and reads
    #: an ACTIVE CAMPAIGN rather than an escalation. Declaring the NAME is
    #: the `RequestContinuation.path` shape — which field is the handle,
    #: not how to read it — so the one check stays one check.
    signal_field: str = "escalation_signal"
    #: DATA: what to call the silence when that key says no. S1-INGEST-020
    #: — production files it as `not_active_campaign` there and
    #: `no_escalation_signal` elsewhere, and the two point at different
    #: prompts.
    signal_absent_reason: str = NO_SIGNAL
    #: The `llm_fields` keys this source carries through, in order.
    llm_field_keys: tuple[str, ...] = ()
    max_tokens: int = 256
    #: The JSON keys the prompt tells the model to return. Declared so a
    #: prompt and its validator cannot drift apart silently.
    schema_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("prefilter", "prompt", "score_delta"):
            if not callable(getattr(self, name)):
                raise DomainError(f"IntelProfile.{name} must be callable")
        if self.domain not in ("cyber", "physical", "info"):
            raise DomainError(
                f"IntelProfile domain must be cyber/physical/info, got "
                f"{self.domain!r}")
        if callable(self.response_items_key) or not isinstance(
                self.response_items_key, str):
            raise DomainError(
                "IntelProfile.response_items_key must be a string: it names "
                "the key that holds the repeated answers, it does not decide "
                "how to split them")
        for name in ("signal_field", "signal_absent_reason"):
            value = getattr(self, name)
            if callable(value) or not isinstance(value, str) or \
                    not value.strip():
                raise DomainError(
                    f"IntelProfile.{name} must be a non-empty string; it is "
                    f"declared data (which key / which reason), never a "
                    f"predicate")
        rules = tuple(self.dispositions or ())
        seen: dict = {}
        unrecognised: dict = {}
        for rule in rules:
            if not isinstance(rule, DispositionRule):
                raise DomainError(
                    f"dispositions must hold DispositionRule values, got "
                    f"{type(rule).__name__}")
            for value in rule.values:
                key = (rule.field, value)
                if key in seen:
                    raise DomainError(
                        f"two dispositions claim {rule.field}={value!r}; the "
                        f"second would never be reached and the reader could "
                        f"not tell which one is live")
                seen[key] = rule
            if rule.matches_unrecognised:
                if rule.field in unrecognised:
                    raise DomainError(
                        f"two dispositions claim the unrecognised value of "
                        f"{rule.field!r}; production folds it onto exactly "
                        f"one member (`safe_enum`'s default)")
                unrecognised[rule.field] = rule
        object.__setattr__(self, "dispositions", rules)


@dataclass(frozen=True, slots=True)
class ExtractionOutcome:
    """What one extraction produced, including why it produced nothing.

    S1-INGEST-020: a cycle that submits nothing must say which of the
    silences it was. `drops` is a reason -> count map rather than a
    total, because "everything was already deduped" and "every feed is
    dead" call for opposite responses.
    """

    items: tuple[IntelItem, ...] = ()
    drops: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "drops",
                           MappingProxyType(dict(self.drops or {})))

    @property
    def is_silent(self) -> bool:
        return not self.items


def primary_country(data: Mapping) -> str:
    """The item's own country, as every production copy reads it.

    `theater` first, `country` second, upper-cased and stripped — and no
    fallback, because S1-INGEST-016 discards an item whose country the
    model could not name rather than assigning the nearest target.

    Extracted rather than inlined because TWO callers need it now: this
    module's `build_item`, and the stage that builds the per-source
    headline fallback (`v3/runtime/llm_stage.py`), whose text names the
    country. Two spellings of one rule is how the confidence floor came to
    be 0.35 in seven places and 0.50 in an eighth.
    """
    return str(data.get("theater") or data.get("country") or "").strip(
        ).upper()


def explode(profile: IntelProfile, data: Mapping) -> tuple:
    """One model answer -> the answers it actually contains.

    `(data,)` when the profile declares no repeated key. Otherwise the
    list under that key — and when the key is ABSENT, empty, or not a
    list, `(data,)` again, which is production's own legacy fallback
    (`rss_narrative.py:445-449`: "a model that ignores the new schema
    still produces usable output"). Dropping the answer there would make
    a schema the model did not follow indistinguishable from a quiet day.
    """
    if not profile.response_items_key:
        return (data,)
    raw = data.get(profile.response_items_key)
    if not isinstance(raw, (list, tuple)) or not raw:
        return (data,)
    return tuple(entry for entry in raw if isinstance(entry, Mapping))


def build_item(profile: IntelProfile, data: Mapping, article: Mapping, *,
               now: float, scope: Sequence[str] = (),
               source_id: str = "", headline_fallback: str = ""
               ) -> tuple[Optional[IntelItem], str]:
    """The shared half: validate the model's answer into an envelope.

    Returns `(item, drop_reason)`; exactly one of the two is meaningful.
    Clause by clause:

      S1-INGEST-013  a structurally invalid answer skips the article; no
                     fallback value continues
      S1-INGEST-016  a primary country the model could not name, or one
                     outside the scope, discards the item — NEVER a
                     forced assignment to the nearest target, which is
                     the Phase 9-E attribution-pollution incident
      S1-INGEST-017  the disposition table: `theater_link=none` drops,
                     `indirect` caps, and an answer outside the enum
                     folds onto the declared default
      S1-INGEST-014  under the floor is its OWN reason code
      S1-INGEST-018  the score is additive; `profile.score_delta` owns
                     the arithmetic and this layer never multiplies it

    The table is evaluated BEFORE the shared checks, which is where
    production's only source with a non-relevance rule puts it
    (`military_exercise.py:343` runs the `event_type` gate ahead of the
    `escalation_signal` test). It also keeps the more specific silence:
    a source's own drop code says more than `no_escalation_signal`. The
    ordering is safe for the SCORE because no cap may sit below the floor
    (`DispositionRule.__post_init__`); it changes only which reason a
    doubly-disqualified item is filed under (§7-2 #48).
    """
    if not data:
        return None, NO_SIGNAL

    confidence = as_float(data.get("confidence"), 0.0) or 0.0
    clipped, dropped = apply_dispositions(profile.dispositions, data,
                                          float(confidence))
    if clipped is None:
        return None, dropped

    # `not data.get(<field>, False)` — every production copy spells it
    # this way (`diplomatic.py:479`, `military_exercise.py:354`,
    # `rss_narrative.py:473`, `hacktivist_news_sensor.py:362`), so an
    # ABSENT key drops the item. Reading it as `is False` would have
    # admitted every answer that forgot the field, which is the sensitive
    # direction and still a difference.
    if not data.get(profile.signal_field, False):
        return None, profile.signal_absent_reason

    primary = primary_country(data)
    if len(primary) != 2:
        return None, NO_PRIMARY_COUNTRY
    if scope and primary not in {str(c).upper() for c in scope}:
        return None, NOT_IN_SCOPE

    if clipped < CONFIDENCE_FLOOR:
        return None, BELOW_FLOOR

    countries, weights = normalize_countries(data, primary=primary)
    return IntelItem(
        source_type=profile.source_type,
        source_id=source_id or profile.source_type,
        country=primary,
        countries=countries,
        country_weights=weights,
        ts=float(now),
        confidence=float(clipped),
        raw_text=str(article.get("raw_text") or article.get("summary") or ""),
        raw_url=str(article.get("link") or article.get("url") or ""),
        # `data.get("headline", <fallback>)` — the ABSENT key takes the
        # fallback, an empty string does not. Both capping sources spell
        # it that way (`diplomatic.py:539`, `military_exercise.py:413`)
        # and the fallback names the source and the theatre, so an item
        # the model left unheadlined is still identifiable. Reading it as
        # `or` would replace a deliberate empty headline.
        headline=str(data["headline"] if "headline" in data
                     else headline_fallback),
        llm_fields={key: data.get(key)
                    for key in profile.llm_field_keys},
        score_delta=float(profile.score_delta(data)),
        domain=profile.domain,
    ), ""


__all__ = [
    "LLM_INTEL_SOURCE", "CONFIDENCE_FLOOR", "CONFIDENCE_DIGITS",
    "RAW_TEXT_LIMIT", "HEADLINE_LIMIT",
    "LINK_DIRECT", "LINK_INDIRECT", "LINK_NONE",
    "NO_SIGNAL", "BELOW_FLOOR", "NO_PRIMARY_COUNTRY", "RELEVANCE_NONE",
    "NOT_IN_SCOPE",
    "DROP", "CAP", "ACCEPT", "DISPOSITIONS", "DispositionRule",
    "BEHAVIOURAL_SLOTS",
    "apply_dispositions", "relevance_rules",
    "sanitize", "normalize_countries", "explode", "primary_country",
    "IntelItem", "IntelProfile", "ExtractionOutcome", "build_item",
]
