"""The label generator: the twelve guards three incidents paid for.

This is the module D2 D-01 is about. All three calibration disasters were
logic bugs *here* — in the measurement, not in the thing measured — and
all three passed every test while degrading production for weeks. The
memory rule for this codebase is the direct consequence: on any recall or
miss-rate anomaly, suspect the label generator first.

Structure does not fix a label-generator bug. What structure can do is
make the three specific shapes unrepresentable and pin the twelve
remediations so a future edit has to argue with a test:

    001  every TL comparison goes through `severity_of` (6 - TL), and the
         kernel type has no ordering operators at all, so the inverted
         comparison of incident #2 does not type-check.
    002  attribution is restricted to conflict-party roles; supporting
         roles keep the wide net for SENSING only (NP1).
    004  a FALSE_NEGATIVE needs external evidence. `llm_intel` and
         `sequence_events` are the same signals scoring consumes, so they
         cannot reveal what scoring missed — that is circular, and it is
         incident #1's shape.
    005  the alert set is THREAT_LEVEL at severity >= 3 or a real
         ATTACK_MODE state. TREND and PER_DOMAIN are diagnostic and are
         never auto-labelled.
    006  neither FALSE_POSITIVE nor TRUE_NEGATIVE may be declared before
         the horizon elapses, and a claim about an ABSENCE is signed
         `auto:horizon` because no source corroborates it.
    008  graded under-rating: a floor derived from the event's magnitude,
         because a TL=5 tripwire cannot see a TL3 call against 12 dead.
    009  the kinetic tier requires an action verb. A bare weapon noun is
         posture — a weapons test and a weapons strike share the noun.
    010  a three-rung relevance ladder, applied to the ETL and never to
         sensing.
    011  one external event is one trial.
    013  three idempotency keys.
    016  the freshness gate lives in `guards.py`, where every phase meets
         it (E-03); it is listed here because it is one of the twelve.

Everything is pure: events and the tool's position come in as values, a
verdict goes out. No queries, no clock reads — `now` is a parameter, so
a horizon test is reproducible.
"""
from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from v3.calibration import epoch as _epoch
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError
from v3.kernel.threat_level import ThreatLevel

#: This module's identity in a label's provenance (S5-VERIF-032).
GENERATOR_ID = "ground_truth_etl"
GENERATOR_VERSION = "3"

#: S1-CALIB-003. The order encodes NP1: a miss is surfaced before a hit.
RULE_ORDER: tuple[str, ...] = ("FALSE_NEGATIVE", "TRUE_POSITIVE",
                               "FALSE_POSITIVE", "TRUE_NEGATIVE")

#: S1-CALIB-006. An absence claim names no source, because no source
#: corroborates it. Incident #1 signed these `auto:acled` with ACLED
#: unconfigured.
ABSENCE_ANALYST_ID = "auto:horizon"

#: S1-CALIB-002, from `radar/scenarios.py:CONFLICT_PARTY_ROLES`.
CONFLICT_PARTY_ROLES: frozenset = frozenset({
    "adversary", "primary_target", "principal_belligerent", "proxy_front"})

#: S1-CALIB-004: evidence sources that cannot testify to a miss. These are
#: the signals scoring itself consumes — if they fire, the TL rises, so
#: they can never show that the TL failed to rise.
CIRCULAR_EVIDENCE_SOURCES: frozenset = frozenset({
    "llm_intel", "sequence_events"})

#: S1-CALIB-005: conclusion types the auto-labeller may score. TREND and
#: PER_DOMAIN are diagnostic surfaces; labelling them pollutes Design W's
#: primary recall metric.
SCORABLE_TYPES: frozenset = frozenset({"threat_level", "attack_mode"})

#: S1-CALIB-013.
IDEMPOTENCY_KEYS: tuple[str, ...] = (
    "conclusion_id+analyst_id", "rss_episode_note_prefix",
    "day_cap_scenario_label_day")

_ATTACK_MODE_NON_STATES: frozenset = frozenset({"", "INSUFFICIENT_DATA"})

#: TL 5 is NORMAL (DEFCON-style). The pre-2026-07-03 code tested TL == 1,
#: which is CRITICAL — the exact opposite of calm (incident #2).
_TL_NORMAL = 5


# ── 001: severity space ─────────────────────────────────────────────────

def severity_of(threat_level) -> int:
    """severity = 6 - TL. Raises outside 1..5 rather than scoring quietly.

    Incident #2 ran for five weeks because a classifier read 5 as worst.
    An unparsed state string reaching this function must be an error, not
    a silently wrong number — that is precisely how the inversion stayed
    invisible.
    """
    # Delegated to the kernel type rather than re-derived: there is one
    # severity implementation in v3, and it is the one whose class removes
    # the ordering operators entirely. Re-deriving `6 - tl` here would be
    # a second place for incident #2 to happen.
    return ThreatLevel(threat_level).severity()


def expected_severity_floor(*, fatalities: int, confidence: float) -> int:
    """S1-CALIB-008: what the tool should have been showing.

    The ONLY place a TL-to-severity comparison is made in the rule set. A
    binary TL=5 tripwire cannot catch a TL3 call against a mass-casualty
    event; this ladder can.
    """
    if fatalities >= T.GT_FN_FATALITIES:
        return T.SEVERITY_FLOOR_MASS_CASUALTY
    if fatalities >= 1 or confidence >= T.GT_KINETIC_CONFIDENCE_FLOOR:
        return T.SEVERITY_FLOOR_KINETIC
    return T.SEVERITY_FLOOR_ESCALATION


# ── 002: attribution ────────────────────────────────────────────────────

def may_attribute(role: Optional[str]) -> bool:
    """May a participant in this role carry a ground-truth label?

    Incident #3: US / CN / JP appear in headlines about other conflicts
    constantly, and attributing those here fabricates false negatives
    against a correctly calm scenario (12 of Korea's 15).
    """
    return role in CONFLICT_PARTY_ROLES


def may_sense(role: Optional[str]) -> bool:
    """Sensing keeps the wide net (NP1). The gate is for LABELS only."""
    return True


def attributable_countries(participants: dict) -> tuple:
    """Conflict-party countries only, sorted. Empty is a skip, not an error."""
    if not participants:
        return ()
    return tuple(sorted(cc for cc, role in participants.items()
                        if may_attribute(role)))


def anchor_country(*, mentioned: Sequence[str],
                   participants: dict) -> Optional[str]:
    """S1-CALIB-011: one article anchors to at most one country per scenario.

    The FIRST conflict-party country mentioned. Producing one episode per
    mentioned country is what turned a single article into a scoring pass
    over every conclusion in the window.
    """
    for code in mentioned:
        if may_attribute(participants.get(code)):
            return code
    return None


# ── the inputs ──────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class ExternalEvent:
    """One piece of outside-world evidence."""

    source: str
    severity: float
    fatalities: int
    confidence: float
    observed_at: float
    url: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.source, str) or not self.source.strip():
            raise DomainError("an external event needs a source")
        if isinstance(self.fatalities, bool) \
                or not isinstance(self.fatalities, int) \
                or self.fatalities < 0:
            raise DomainError(
                f"fatalities must be a non-negative int, got "
                f"{self.fatalities!r}. S1-CALIB-009: an unstated count is "
                f"0, never 1 — substituting 1 fabricates a death")

    @property
    def is_circular(self) -> bool:
        return self.source in CIRCULAR_EVIDENCE_SOURCES

    @property
    def severity_floor(self) -> int:
        return expected_severity_floor(fatalities=self.fatalities,
                                       confidence=self.confidence)


@dataclass(frozen=True, slots=True)
class ToolPosition:
    """What the tool was saying, and when."""

    conclusion_type: str
    tl: Optional[int]
    state: str
    observed_at: float
    now: float

    @property
    def is_scorable(self) -> bool:
        return self.conclusion_type in SCORABLE_TYPES

    @property
    def horizon_elapsed(self) -> bool:
        return self.now >= self.observed_at + T.GT_FP_TN_HORIZON_SEC


def is_alert(position: ToolPosition) -> bool:
    """S1-CALIB-005's alert set.

    THREAT_LEVEL counts as an alert at severity >= 3, i.e. TL <= 3.
    Incident #2's predecessor wrote `int(state) >= 3`, which excluded
    CRITICAL and SEVERE — the two levels that matter most.
    """
    if position.conclusion_type == "threat_level":
        if position.tl is None:
            # A state that will not reduce to a number is not an alert and
            # not a calm call either: it is unscorable.
            return False
        return severity_of(position.tl) >= T.GT_ALERT_SEVERITY_MIN
    if position.conclusion_type == "attack_mode":
        return (position.state or "").strip() not in _ATTACK_MODE_NON_STATES
    return False


def in_forward_window(*, observed_at: float, event_at: float) -> bool:
    """`[observed_at, observed_at + 72h]`, closed at BOTH ends."""
    return observed_at <= event_at <= observed_at + T.GT_FORWARD_WINDOW_SEC


# ── 007: automated identity ─────────────────────────────────────────────

_IDENTITY_LADDER: tuple = (
    (frozenset({"acled", "gdelt"}), "auto:both"),
    (frozenset({"acled"}), "auto:acled"),
    # WP-0.4 v2 (ADR-V3-012): with ACLED permanently rejected, the FN
    # sources ARE rss-graded + GDELT — the ladder must name them or the
    # severity-floor rule raises on the very evidence the pipeline is
    # built on. Pairs precede singles: the first `required <= present`
    # match wins, and {"gdelt"} is a subset of {"rss", "gdelt"}.
    (frozenset({"rss", "gdelt"}), "auto:rss_gdelt"),
    (frozenset({"gdelt"}), "auto:gdelt"),
    (frozenset({"rss"}), "auto:rss"),
    (frozenset({"llm_intel", "sequence_events"}), "auto:mixed"),
    (frozenset({"llm_intel"}), "auto:llm_intel"),
    (frozenset({"sequence_events"}), "auto:sequence"),
)


def analyst_id_for(sources: Iterable[str]) -> str:
    """S1-CALIB-007: N agreeing automatic sources are ONE voter.

    The contract `distinct_analysts` depends on. Without it, automated
    agreement outvotes human feedback in recall calibration.
    """
    present = frozenset(sources)
    for required, identity in _IDENTITY_LADDER:
        if required <= present:
            return identity
    raise DomainError(
        f"no automated identity covers sources {sorted(present)}; every "
        f"automatic label must declare which source spoke (S1-CALIB-007)")


# ── 009/010: text classification ────────────────────────────────────────
#
# Regexes transcribed from radar/conclusions/rss_extractor.py by reading
# the module, not the clause text.

_KINETIC_VERBS = re.compile(
    r"\b(airstrike|air\s+strike|shelling|drone\s+strike|bombardment|"
    r"bombing|explosion|invasion|incursion|ambush(?:ed)?|torpedo(?:ed)?|"
    r"attack(?:ed|s)?|shoot(?:ing|s|down)?|shot\s+down|"
    r"missiles?\s+(?:strike|attack|barrage|launch(?:ed)?|fired)|"
    r"rockets?\s+(?:strike|attack|barrage|fire[ds]?)|"
    r"artillery\s+(?:fire|strike|barrage|shelling)|"
    r"(?:fires?|fired|launch(?:es|ed)?)\s+(?:\w+\s+){0,2}(?:missiles?|rockets?))\b",
    re.IGNORECASE)

_ESCALATION_VERBS = re.compile(
    r"\b(mobiliz(?:e|es|ed|ing|ation)|"
    r"deploy(?:s|ed|ing|ment)?|"
    r"scrambl(?:e|es|ed|ing)|"
    r"intercept(?:s|ed|ing|ion)?|"
    r"missiles?\s+tests?|weapons?\s+tests?|test\s+launch(?:es)?|"
    r"recall(?:s|ed|ing)?\s+(?:its\s+)?ambassador|"
    r"sever(?:s|ed|ing)?\s+(?:diplomatic\s+)?(?:ties|relations)|"
    r"expel(?:s|led|ling)?\s+(?:the\s+)?diplomat|"
    r"troop\s+buildup|military\s+exercise|war\s+games)\b",
    re.IGNORECASE)

_STRONG_KINETIC = re.compile(
    r"\b(missile|airstrike|air\s+strike|shelling|rocket|drone\s+strike|"
    r"artillery|bombardment|invasion|incursion|shot\s+down|shootdown|"
    r"torpedo)\b",
    re.IGNORECASE)

_MILITARY_ACTORS = re.compile(
    r"\b(troops?|soldiers?|army|navy|air\s+force|military|armed\s+forces|"
    r"marines?|warship|destroyer|frigate|aircraft\s+carrier|fighter\s+jet|"
    r"warplane|bomber|paratroopers?|militia|special\s+forces|coast\s+guard)\b",
    re.IGNORECASE)

_NONCONFLICT_NOISE = re.compile(
    r"\b(typhoon|hurricane|cyclone|earthquake|tsunami|flood(?:s|ing)?|"
    r"landslide|wildfire|volcano|heat\s?wave|blizzard|drought|storm|"
    r"outbreak|epidemic|pandemic|traffic|road\s+accident|car\s+crash|"
    r"bus\s+crash|train\s+crash|derail(?:s|ed|ment)?|ferry|"
    r"capsiz(?:e|ed|ing)|plane\s+crash|air\s+crash|helicopter\s+crash|"
    r"crash(?:es|ed)?|bear|shark|robbery|burglary|homicide|murder|stabbing|"
    r"shooting\s+spree|nightclub|festival|concert|stampede)\b",
    re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class TierVerdict:
    tier: Optional[str]
    severity_floor: int
    fatalities: int


def classify_tier(text: str, *, fatalities: int = 0) -> TierVerdict:
    """S1-CALIB-009: kinetic needs an ACTION, not a weapon noun.

    "New missile unveiled at the parade" and "missiles strike the airfield"
    share a noun and share nothing else. Grading the first as kinetic
    violence is 12 of Korea's 15 false negatives.
    """
    if fatalities < 0:
        raise DomainError("fatalities may not be negative")
    if not text:
        return TierVerdict(tier=None, severity_floor=T.SEVERITY_FLOOR_ESCALATION,
                           fatalities=fatalities)
    if _KINETIC_VERBS.search(text):
        return TierVerdict(
            tier="kinetic",
            severity_floor=expected_severity_floor(
                fatalities=fatalities,
                confidence=confidence_for(tier="kinetic",
                                          fatalities=fatalities)),
            fatalities=fatalities)
    if _ESCALATION_VERBS.search(text) or _STRONG_KINETIC.search(text):
        # Posture. A weapons test, a deployment, a defence-industry
        # unveiling: escalation context, not an act of violence.
        return TierVerdict(tier="posture",
                           severity_floor=T.SEVERITY_FLOOR_ESCALATION,
                           fatalities=fatalities)
    return TierVerdict(tier=None, severity_floor=T.SEVERITY_FLOOR_ESCALATION,
                       fatalities=fatalities)


def confidence_for(*, tier: Optional[str], fatalities: int) -> float:
    """S1-CALIB-009's ladder: 0.85 / 0.60 / 0.40."""
    if fatalities > 0:
        return T.CONFIDENCE_WITH_FATALITIES
    if tier == "kinetic":
        return T.CONFIDENCE_KINETIC
    return T.CONFIDENCE_POSTURE


@dataclass(frozen=True, slots=True)
class RelevanceVerdict:
    qualified: bool
    rung: str
    detail: str


def is_relevant(text: str, *, countries: Sequence[str] = ()) -> RelevanceVerdict:
    """S1-CALIB-010's three rungs, in order.

    1. intrinsically military vocabulary qualifies alone and OVERRIDES the
       noise veto ("missile test proceeds amid typhoon warnings");
    2. a weak kinetic verb qualifies only with a military actor noun or
       two or more recognised countries;
    3. non-conflict noise vetoes anything that qualified via rung 2.
    """
    if not text:
        return RelevanceVerdict(False, "empty", "no text")
    if _STRONG_KINETIC.search(text) or _ESCALATION_VERBS.search(text):
        return RelevanceVerdict(True, "intrinsic",
                                "inherently military vocabulary")
    if not _KINETIC_VERBS.search(text):
        return RelevanceVerdict(False, "no_kinetic_verb",
                                "no kinetic vocabulary at all")
    has_actor = bool(_MILITARY_ACTORS.search(text))
    enough_countries = len(set(countries)) >= \
        T.RELEVANCE_MIN_RECOGNISED_COUNTRIES
    if not (has_actor or enough_countries):
        return RelevanceVerdict(False, "weak_without_context",
                                "weak kinetic verb with no interstate "
                                "framing")
    if _NONCONFLICT_NOISE.search(text):
        return RelevanceVerdict(False, "noise_veto",
                                "non-conflict vocabulary vetoes a rung-2 "
                                "match (the bear-spray incident and the "
                                "typhoon)")
    return RelevanceVerdict(True, "weak_with_context",
                            "weak verb plus interstate framing")


def relevance_applies_to(path: str) -> bool:
    """The ladder gates LABELS. Sensing keeps the wide net (NP1)."""
    return path == "etl"


def mentions_country(text: str, *, alias: str) -> bool:
    """S1-CALIB-010: the trailing boundary is `(?!\\w)`, not `\\b`.

    An alias ending in a period ("U.S.") never forms a `\\b` against
    following whitespace, so the historical `\\b` dropped it silently.
    """
    if not text or not alias:
        return False
    return bool(re.search(r"\b" + re.escape(alias) + r"(?!\w)", text,
                          re.IGNORECASE))


# ── 011/013: episodes and idempotency ───────────────────────────────────

def _utc_day(timestamp: float) -> str:
    return datetime.datetime.fromtimestamp(
        timestamp, datetime.timezone.utc).strftime("%Y-%m-%d")


def episode_key(*, scenario_id: str, country: str, event_at: float) -> str:
    """S1-CALIB-011: the trial unit is (scenario, country, UTC day)."""
    return f"{scenario_id}/{country}/{_utc_day(event_at)}"


def episode_note(scenario_id: str, country: str, event_at: float, *,
                 detail: str = "") -> str:
    """S1-CALIB-013 key 2: the episode stamp is the note's PREFIX."""
    prefix = f"episode={scenario_id}/{country}/{_utc_day(event_at)} "
    return (prefix + detail)[:T.GT_NOTE_TRUNCATE]


def day_cap_key(scenario_id: str, label: str, conclusion_at: float) -> str:
    """S1-CALIB-013 key 3: one world state is one confusion-matrix entry.

    Conclusions arrive about every two minutes. Without this cap, one
    external event pseudo-replicates into hundreds of matrix entries and
    `sample_n` stops meaning anything.
    """
    return f"{scenario_id}/{label}/{_utc_day(conclusion_at)}"


def episode_scoring_passes() -> int:
    """S1-CALIB-012: exactly one scoring pass per episode."""
    return 1


@dataclass(frozen=True, slots=True)
class MergedEpisode:
    severity_floor: int
    event_at: float
    sources: tuple


def merge_episode_evidence(events: Iterable[ExternalEvent]) -> MergedEpisode:
    """S1-CALIB-011: heaviest floor sets the expectation (NP1), earliest
    report time anchors the prior window."""
    materialised = tuple(events)
    if not materialised:
        raise DomainError("an episode with no evidence is not an episode")
    return MergedEpisode(
        severity_floor=max(e.severity_floor for e in materialised),
        event_at=min(e.observed_at for e in materialised),
        sources=tuple(sorted({e.source for e in materialised})))


# ── the classifier ──────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class LabelVerdict:
    """A label, or a recorded reason there is none."""

    label: Optional[str]
    reason: str
    analyst_id: Optional[str]
    provenance: Optional[_epoch.LabelProvenance]
    evidence_url: Optional[str] = None

    def as_dict(self) -> dict:
        return {"label": self.label, "reason": self.reason,
                "analyst_id": self.analyst_id,
                "evidence_url": self.evidence_url,
                "provenance": (self.provenance.as_dict()
                               if self.provenance else None)}


def _provenance(rule_id: str) -> _epoch.LabelProvenance:
    return _epoch.LabelProvenance(
        generator_id=GENERATOR_ID, generator_version=GENERATOR_VERSION,
        rule_id=rule_id, epoch_id=_epoch.CURRENT_EPOCH.epoch_id)


def classify(position: ToolPosition,
             events: Iterable[ExternalEvent]) -> LabelVerdict:
    """S1-CALIB-003: FN > TP > FP > TN, first match wins.

    Returns a verdict with `label=None` when no rule matches. That is not
    a TRUE_NEGATIVE — it is "consistent with the evidence so far, and the
    horizon that would let us claim absence has not elapsed". Collapsing
    the two is how incident #1 manufactured a perfect record.
    """
    if not isinstance(position, ToolPosition):
        raise DomainError(
            f"classify needs a ToolPosition, got {type(position).__name__}")
    if not position.is_scorable:
        return LabelVerdict(None, "type_not_scorable", None, None)

    in_window = tuple(e for e in events
                      if in_forward_window(observed_at=position.observed_at,
                                           event_at=e.observed_at))
    external = tuple(e for e in in_window if not e.is_circular)
    circular = tuple(e for e in in_window if e.is_circular)
    alert = is_alert(position)

    # ── FALSE_NEGATIVE ──────────────────────────────────────────────────
    # Only external evidence may prove a miss (S1-CALIB-004). Production
    # has TWO paths and both run, so both are ported:
    #
    #   ground_truth_etl rule 1 — the TL=5 tripwire: an ACLED event at
    #     severity >= 10. Narrow, and the one the clause cites.
    #   run_rss_etl label_for_threat_level — graded under-rating: the
    #     call's severity below the floor the event's magnitude demands
    #     (S1-CALIB-008). Wider, and the reason the tripwire alone is not
    #     enough — it cannot see a TL3 call against twelve dead.
    #
    # The tripwire is evaluated first so its narrower rule_id survives on
    # the labels it explains; the graded rule catches everything else.
    if position.tl is not None and external:
        tripwire = tuple(e for e in external if e.source == "acled"
                         and e.severity >= T.GT_FN_FATALITIES)
        if position.tl == _TL_NORMAL and tripwire:
            return LabelVerdict(
                "FALSE_NEGATIVE", "calm call against a severe ACLED event",
                analyst_id_for(e.source for e in tripwire),
                _provenance("false_negative_acled_tripwire"),
                evidence_url=max(tripwire, key=lambda e: e.severity).url)
        worst = max(external, key=lambda e: e.severity_floor)
        if severity_of(position.tl) < worst.severity_floor:
            return LabelVerdict(
                "FALSE_NEGATIVE", "external evidence outranks the call",
                analyst_id_for(e.source for e in external),
                _provenance("false_negative_severity_floor"),
                evidence_url=max(external,
                                 key=lambda e: e.severity).url)

    # ── TRUE_POSITIVE ───────────────────────────────────────────────────
    if alert and in_window:
        # Circular sources MAY corroborate a hit — they only cannot
        # evidence a miss.
        return LabelVerdict(
            "TRUE_POSITIVE", "alert with a qualifying event in the window",
            analyst_id_for(e.source for e in in_window),
            _provenance("true_positive_forward_window"),
            evidence_url=max(in_window, key=lambda e: e.severity).url)

    # ── FALSE_POSITIVE / TRUE_NEGATIVE ──────────────────────────────────
    if not position.horizon_elapsed:
        reason = "horizon_not_elapsed"
        if circular and not external and position.tl is not None:
            reason = ("horizon_not_elapsed; the only evidence is circular "
                      "(scoring consumes it, so it cannot reveal a miss)")
        return LabelVerdict(None, reason, None, None)


    if in_window:
        # Events exist but neither branch above claimed them. No label:
        # declaring a TRUE_NEGATIVE here would assert an absence that the
        # window contradicts, and that is incident #1's move.
        if circular and not external:
            return LabelVerdict(
                None,
                "the only evidence in the window is circular (scoring "
                "consumes llm_intel and sequence_events, so they cannot "
                "reveal what scoring missed); no label, and no claim of "
                "absence either",
                None, None)
        return LabelVerdict(None, "events present but no rule matched",
                            None, None)

    if alert:
        return LabelVerdict("FALSE_POSITIVE", "horizon elapsed with no event",
                            ABSENCE_ANALYST_ID,
                            _provenance("false_positive_horizon"))
    return LabelVerdict("TRUE_NEGATIVE", "horizon elapsed with no event",
                        ABSENCE_ANALYST_ID,
                        _provenance("true_negative_horizon"))


__all__ = ["GENERATOR_ID", "GENERATOR_VERSION", "RULE_ORDER",
           "ABSENCE_ANALYST_ID", "CONFLICT_PARTY_ROLES",
           "CIRCULAR_EVIDENCE_SOURCES", "SCORABLE_TYPES",
           "IDEMPOTENCY_KEYS", "severity_of", "expected_severity_floor",
           "may_attribute", "may_sense", "attributable_countries",
           "anchor_country", "ExternalEvent", "ToolPosition", "is_alert",
           "in_forward_window", "analyst_id_for", "TierVerdict",
           "classify_tier", "confidence_for", "RelevanceVerdict",
           "is_relevant", "relevance_applies_to", "mentions_country",
           "episode_key", "episode_note", "day_cap_key",
           "episode_scoring_passes", "MergedEpisode",
           "merge_episode_evidence", "LabelVerdict", "classify"]
