"""Everything the scoring kernel is allowed to know, as explicit arguments.

F-05 is that scoring is not idempotent: the current Z-score helpers write
running statistics while computing, so evaluating the same tick twice gives
two answers, and parity replay is therefore impossible (P1 §6, S1-PIPE-035).
The structural fix is not "remember not to write" — it is that the kernel
has nothing to write to and nothing to read from. No database handle, no
clock, no environment.

So every quantity the formulas need arrives here, including the two that
are usually smuggled in:

    now                the tick instant. Sequence decay and provenance both
                       need a timestamp; taking it from time.time() would
                       make the same input produce different output.
    prior              path-dependent state (previous TL for hysteresis,
                       the sequence chain). S5-VERIF-020 requires these be
                       supplied at the start of a parity run rather than
                       read from live production state.

`prior` is an input AND part of the result, so the state machine step is
visible: score_tick(inputs).next_state feeds the following tick.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Optional

from v3.kernel import Ratio, ThreatLevel
from v3.kernel.errors import DomainError
from v3.scoring.settings import ScoringSettings

CYBER = "cyber"
PHYSICAL = "physical"
INFO = "info"
# Ordered, not a set: domain order decides contribution order in the
# result, and an unordered iteration would make provenance unstable
# between runs on the same input.
DOMAINS: tuple[str, ...] = (CYBER, PHYSICAL, INFO)

STATUS_FIRED = "FIRED"
STATUS_DISABLED = "DISABLED"

ORIGIN_SENSOR = "sensor"
ORIGIN_LLM_INTEL = "llm_intel"
_ORIGINS = frozenset({ORIGIN_SENSOR, ORIGIN_LLM_INTEL})

MODE_FULL = "full"
MODE_LITE = "lite"


def _text(value, *, name: str, allow_empty: bool = False) -> str:
    if value is None and allow_empty:
        return ""
    if not isinstance(value, str):
        raise DomainError(f"{name} must be a string, got "
                          f"{type(value).__name__} {value!r}")
    stripped = value.strip()
    if not stripped and not allow_empty:
        raise DomainError(f"{name} must not be empty")
    return stripped


def _finite(value, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DomainError(f"{name} must be a number, got "
                          f"{type(value).__name__} {value!r}")
    numeric = float(value)
    if math.isnan(numeric) or math.isinf(numeric):
        raise DomainError(
            f"{name} must be finite, got {value!r}: a NaN compares False "
            f"against every threshold, which reads as 'never exceeded' "
            f"rather than as an error (the F-08 failure mode).")
    return numeric


def _ratio(value, *, name: str) -> Ratio:
    """Accept a Ratio, or wrap a bare fraction — never a percentage."""
    if isinstance(value, Ratio):
        return value
    try:
        return Ratio(value)
    except DomainError as exc:
        raise DomainError(f"{name}: {exc}") from exc


def _timestamp(value, *, name: str) -> float:
    numeric = _finite(value, name=name)
    if numeric <= 0:
        raise DomainError(f"{name} must be a positive unix timestamp, "
                          f"got {numeric!r}")
    return numeric


@dataclass(frozen=True, slots=True)
class CountryWeight:
    """One country's share of an observation.

    A plain sensor reading has exactly one of these at weight 1.0. LLM
    intel can name several countries with different weights, which is what
    S1-SCORE-014's primary-country filter and S1-SCORE-009's
    `llm_country_weight` factor operate on.
    """

    country: str
    weight: Ratio = field(default_factory=lambda: Ratio(1.0))

    def __post_init__(self) -> None:
        object.__setattr__(self, "country",
                           _text(self.country, name="country").upper())
        object.__setattr__(self, "weight",
                           _ratio(self.weight, name="country weight"))


@dataclass(frozen=True, slots=True)
class Observation:
    """One sensor's one reading, as the scoring kernel receives it.

    This is the single observation representation. P6 O-14 found the legacy
    system carrying two (RationaleEntry for the engine formulas, Signal for
    the scenario formulas) with S1-SCORE-018 existing only to convert
    between them; with one representation that conversion has nothing left
    to do, while its substantive rules — the admission predicate and the
    empty-field fallbacks — live on in `admits()` and `__post_init__`.
    """

    sensor: str
    domain: str
    status: str
    score: float
    signal_source: str = ""
    countries: tuple[CountryWeight, ...] = ()
    confidence: Ratio = field(default_factory=lambda: Ratio(1.0))
    suppressed: bool = False
    suppress_reason: Optional[str] = None
    origin: str = ORIGIN_SENSOR
    # The structured observed value. Noise-exclusion rules match against
    # THIS, never against a rendered label — DP4 was rules silently dying
    # whenever display wording changed.
    value: str = ""
    # When the observed event happened upstream, NOT when the tick ran.
    # WP-2.4 ADDENDUM (design sheet §9 ruling 1): the age term in
    # `v3.scoring.decay` needs this and the tick's `now`, and nothing else.
    # Production destroys the distinction at exactly this point —
    # radar/routes/core.py:2074 builds the intel Signal with
    # `observed_at=current_time` — so an age recovered downstream there is
    # always zero. Optional, because a sensor reading has no age term
    # (decay.age_weight_for); mandatory for llm_intel, because "no
    # timestamp" would otherwise have to be guessed as fresh or as spent,
    # and both are guesses about the one quantity the term uses.
    observed_at: Optional[float] = None

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Observation is final: a subclass could re-add a second "
            "observation shape, which is the two-representation split P6 "
            "O-14 exists to remove.")

    def __post_init__(self) -> None:
        object.__setattr__(self, "sensor", _text(self.sensor, name="sensor"))
        object.__setattr__(self, "status", _text(self.status, name="status"))
        domain = _text(self.domain, name="domain").lower()
        if domain not in DOMAINS:
            raise DomainError(
                f"unknown domain {self.domain!r}; expected one of "
                f"{list(DOMAINS)}")
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "score", _finite(self.score, name="score"))
        # S1-SCORE-018: an empty signal_source falls back to the sensor
        # name. Left empty it would dedup against every other unlabelled
        # sensor, collapsing independent evidence into one contribution.
        source = _text(self.signal_source, name="signal_source",
                       allow_empty=True)
        object.__setattr__(self, "signal_source", source or self.sensor)
        object.__setattr__(self, "confidence",
                           _ratio(self.confidence, name="confidence"))
        if not isinstance(self.suppressed, bool):
            raise DomainError(
                f"suppressed must be a real bool, got "
                f"{type(self.suppressed).__name__} {self.suppressed!r}; "
                f"coercing would make bool('false') mean True")
        if self.origin not in _ORIGINS:
            raise DomainError(
                f"unknown origin {self.origin!r}; expected one of "
                f"{sorted(_ORIGINS)}")
        countries = tuple(self.countries)
        for entry in countries:
            if not isinstance(entry, CountryWeight):
                raise DomainError(
                    f"observation countries must be CountryWeight values, "
                    f"got {type(entry).__name__}. A bare country string "
                    f"loses the LLM weight that S1-SCORE-009 multiplies in.")
        object.__setattr__(self, "countries", countries)
        object.__setattr__(self, "value",
                           _text(self.value, name="value", allow_empty=True))
        if self.observed_at is not None:
            object.__setattr__(
                self, "observed_at",
                _timestamp(self.observed_at, name="observed_at"))
        elif self.origin == ORIGIN_LLM_INTEL:
            raise DomainError(
                f"{self.sensor!r} is llm_intel and must carry observed_at: "
                f"the age decay (S1-INTEL-020) is computed from it and the "
                f"tick's now. Defaulting it to the tick would read every "
                f"stale item as fresh, which is the direction that reads "
                f"as more threat, not less.")

    @property
    def is_global(self) -> bool:
        """No country named. S1-SCORE-012 decides what that contributes."""
        return not self.countries

    @property
    def is_llm_intel(self) -> bool:
        return self.origin == ORIGIN_LLM_INTEL

    def passes_gate(self) -> bool:
        """S1-PIPE-009's return value: FIRED and not suppressed.

        This is the gate, and it has NO score condition — matching
        `add_rat`'s `return status == "FIRED" and not _is_muted`
        (radar/routes/core.py:997), which CLAUDE.md §5 states as project
        law: sequence-event registration is gated on this and nothing else.

        The distinction from `admits()` is load-bearing. `cf_botnet_overlap`
        deliberately fires with score 0 in the marginal IDF band: it
        contributes nothing numerically, yet still gates its SYNC_DDOS
        chain link. Folding a score test in here would silently delete
        those links.
        """
        return self.status == STATUS_FIRED and not self.suppressed

    def admits(self) -> bool:
        """S1-SCORE-018: does this reading contribute SCORE?

        Gate first, then the score test — a strictly narrower question
        than `passes_gate()`. The two are separate because production
        separates them: contribution admission drops zero-score readings
        (`rat.score <= 0`, radar/scoring.py:83) while the sequence gate
        keeps them.

        The score test is `> 0`. S1-SCORE-018 states the condition as
        `score == 0`, which differs for a negative score; the production
        reading is used because parity is measured against production.
        Recorded as an S1 discrepancy in the WP-2.4 report.
        """
        return self.passes_gate() and self.score > 0


@dataclass(frozen=True, slots=True)
class Participant:
    """A country's membership in a scenario, with its coupling weight."""

    country: str
    weight: Ratio = field(default_factory=lambda: Ratio(1.0))
    role: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "country",
                           _text(self.country, name="participant country"
                                 ).upper())
        object.__setattr__(self, "weight",
                           _ratio(self.weight, name="coupling weight"))
        object.__setattr__(self, "role",
                           _text(self.role, name="role", allow_empty=True))


@dataclass(frozen=True, slots=True)
class Scenario:
    """A scenario as the kernel needs it: who is in it, and how strongly."""

    scenario_id: str
    participants: tuple[Participant, ...] = ()
    enabled: bool = True
    core_country: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_id",
                           _text(self.scenario_id, name="scenario_id"))
        participants = tuple(self.participants)
        seen: set = set()
        for entry in participants:
            if not isinstance(entry, Participant):
                raise DomainError(
                    f"scenario participants must be Participant values, got "
                    f"{type(entry).__name__}")
            if entry.country in seen:
                raise DomainError(
                    f"{self.scenario_id}: duplicate participant "
                    f"{entry.country!r}; two coupling weights for one "
                    f"country makes the contribution order decide the score")
            seen.add(entry.country)
        object.__setattr__(self, "participants", participants)
        if self.core_country is not None:
            object.__setattr__(self, "core_country",
                               _text(self.core_country,
                                     name="core_country").upper())

    @property
    def is_scorable(self) -> bool:
        """S1-SCORE-042: a disabled scenario is not scored."""
        return bool(self.enabled)

    def participant_for(self, country: str) -> Optional[Participant]:
        """S1-SCORE-010 / 011: membership decides contribution, and the
        adversary role is a member like any other (ADR-014)."""
        wanted = country.upper()
        for entry in self.participants:
            if entry.country == wanted:
                return entry
        return None


@dataclass(frozen=True, slots=True)
class SequenceEvent:
    """One link in an escalation chain (S1-SCORE-021 / 022).

    `country` is required and non-empty, which is S1-PIPE-017 enforced by
    the type: an event nobody can attribute cannot later be correlated,
    and a ledger of them is a ledger of noise.

    `justified_by` names the sensors whose ADMITTED observations support
    this event. S1-PIPE-013 makes gating the precondition for registering
    an event and S1-PIPE-014 requires every constituent observation of a
    composite event to have passed — both are checked in
    `sequence.advance()` against the tick's admitted set, so a suppressed
    reading cannot enter the chain by a side door.
    """

    country: str
    event_type: str
    occurred_at: float
    justified_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "country",
                           _text(self.country, name="event country").upper())
        object.__setattr__(self, "event_type",
                           _text(self.event_type, name="event_type"))
        object.__setattr__(self, "occurred_at",
                           _timestamp(self.occurred_at, name="occurred_at"))
        object.__setattr__(
            self, "justified_by",
            tuple(_text(sensor, name="justified_by entry")
                  for sensor in self.justified_by))


@dataclass(frozen=True, slots=True)
class PriorState:
    """State carried from the previous tick — never read from production.

    S5-VERIF-020: hysteresis and the sequence chain both depend on what
    came before. A parity run has to start from a stated point, so these
    are arguments. The kernel returns the successor state rather than
    updating anything, which is what makes a tick replayable.
    """

    previous_tl: Mapping = field(default_factory=dict)
    sequence_events: tuple[SequenceEvent, ...] = ()

    def __post_init__(self) -> None:
        levels = dict(self.previous_tl or {})
        for scenario_id, level in levels.items():
            _text(scenario_id, name="previous_tl scenario_id")
            if level is not None and not isinstance(level, ThreatLevel):
                raise DomainError(
                    f"previous_tl[{scenario_id!r}] must be a kernel "
                    f"ThreatLevel or None, got {type(level).__name__}. A "
                    f"raw int loses the inverted-scale guard, which is "
                    f"exactly what hysteresis reads.")
        object.__setattr__(self, "previous_tl", MappingProxyType(levels))
        events = tuple(self.sequence_events)
        for event in events:
            if not isinstance(event, SequenceEvent):
                raise DomainError(
                    f"sequence_events must be SequenceEvent values, got "
                    f"{type(event).__name__}")
        object.__setattr__(self, "sequence_events", events)

    def tl_for(self, scenario_id: str):
        return self.previous_tl.get(scenario_id)

    def __reduce__(self):
        # mappingproxy is unpicklable; rebuild through the constructor so
        # a restored state is a re-validated one.
        return (type(self), (dict(self.previous_tl), self.sequence_events))


@dataclass(frozen=True, slots=True)
class PatternFlags:
    """Detector verdicts that add a flat bonus (S1-PIPE-026).

    Booleans rather than computations: the detectors behind them read
    sensor-specific fields (CheckHost health, narrative burst state) that
    the kernel has no vocabulary for, so they are produced upstream and
    their *verdict* is the kernel's input. The bonus each one is worth is
    pinned in `thresholds`.
    """

    silent_divergence: bool = False
    context_alignment: bool = False

    def __post_init__(self) -> None:
        for name in ("silent_divergence", "context_alignment"):
            if not isinstance(getattr(self, name), bool):
                raise DomainError(
                    f"{name} must be a real bool, got "
                    f"{type(getattr(self, name)).__name__}")


_NO_FLAGS = PatternFlags()


@dataclass(frozen=True, slots=True)
class ScoringInputs:
    """One tick's complete input. Nothing else reaches the formulas.

    S1-PIPE-025: a tick scores every scorable scenario from ONE observation
    set, so the observations sit here rather than being re-collected per
    scenario — re-collection is how focused and background came to be
    scored against different snapshots.
    """

    now: float
    observations: tuple[Observation, ...]
    scenarios: tuple[Scenario, ...]
    settings: ScoringSettings
    focused_scenario_id: Optional[str] = None
    prior: PriorState = field(default_factory=PriorState)
    arriving_events: tuple[SequenceEvent, ...] = ()
    score_series: Mapping[str, tuple] = field(default_factory=dict)
    pattern_flags: Mapping[str, PatternFlags] = field(default_factory=dict)
    chain_countries: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "now", _timestamp(self.now, name="now"))
        observations = tuple(self.observations)
        for entry in observations:
            if not isinstance(entry, Observation):
                raise DomainError(
                    f"observations must be Observation values, got "
                    f"{type(entry).__name__}")
        object.__setattr__(self, "observations", observations)
        scenarios = tuple(self.scenarios)
        for entry in scenarios:
            if not isinstance(entry, Scenario):
                raise DomainError(
                    f"scenarios must be Scenario values, got "
                    f"{type(entry).__name__}")
        object.__setattr__(self, "scenarios", scenarios)
        if not isinstance(self.settings, ScoringSettings):
            raise DomainError(
                f"settings must be a resolved ScoringSettings, got "
                f"{type(self.settings).__name__}. Thresholds resolve "
                f"OUTSIDE the kernel (P6 O-18): the caller resolves and "
                f"passes values in, so the formulas stay pure.")
        if not isinstance(self.prior, PriorState):
            raise DomainError(
                f"prior must be a PriorState, got {type(self.prior).__name__}")
        if self.focused_scenario_id is not None:
            object.__setattr__(
                self, "focused_scenario_id",
                _text(self.focused_scenario_id, name="focused_scenario_id"))
        arriving = tuple(self.arriving_events)
        for event in arriving:
            if not isinstance(event, SequenceEvent):
                raise DomainError(
                    f"arriving_events must be SequenceEvent values, got "
                    f"{type(event).__name__}")
        object.__setattr__(self, "arriving_events", arriving)
        # A NaN in a score series is the F-08 shape exactly: it survives
        # the regression arithmetic, and `abs(velocity) > EPSILON` is False
        # for NaN, so the bonus silently reads zero instead of erroring.
        validated_series = {}
        for scenario_id, points in dict(self.score_series).items():
            _text(scenario_id, name="score_series scenario_id")
            checked = []
            for point in points:
                if not isinstance(point, (tuple, list)) or len(point) != 2:
                    raise DomainError(
                        f"score_series[{scenario_id!r}] entries must be "
                        f"(observed_at, score) pairs, got {point!r}")
                checked.append((
                    _timestamp(point[0],
                               name=f"score_series[{scenario_id!r}] timestamp"),
                    _finite(point[1],
                            name=f"score_series[{scenario_id!r}] score")))
            validated_series[scenario_id] = tuple(checked)
        object.__setattr__(self, "score_series",
                           MappingProxyType(validated_series))
        chains = {}
        for scenario_id, country in dict(self.chain_countries).items():
            _text(scenario_id, name="chain_countries scenario_id")
            chains[scenario_id] = _text(
                country, name="chain country").upper()
        object.__setattr__(self, "chain_countries", MappingProxyType(chains))
        flags = dict(self.pattern_flags)
        for scenario_id, entry in flags.items():
            if not isinstance(entry, PatternFlags):
                raise DomainError(
                    f"pattern_flags[{scenario_id!r}] must be PatternFlags, "
                    f"got {type(entry).__name__}")
        object.__setattr__(self, "pattern_flags", MappingProxyType(flags))

    def score_series_for(self, scenario_id: str) -> tuple:
        """Past (observed_at, score) pairs, oldest first, from L1.

        Supplied rather than queried: the kernel does not own a ledger
        handle, and a scoring layer that reads history mid-computation is
        the shape S5-VERIF-020 forbids.
        """
        return self.score_series.get(scenario_id, ())

    def pattern_flags_for(self, scenario_id: str) -> PatternFlags:
        return self.pattern_flags.get(scenario_id, _NO_FLAGS)

    def chain_country_for(self, scenario: Scenario) -> str:
        """S1-PIPE-016: whose escalation chain this scenario's bonus reads.

        Supplied by the caller, not derived here. Production picks the
        primary_ec of a dual-core scenario by LIVE average spike
        (radar/routes/core.py:878-881) — "whichever belligerent is
        currently escalating" — which is observation data the orchestrator
        holds and the kernel deliberately does not. Deriving it from
        static coupling weights would be wrong in the case that matters:
        middle_east has IL and IR both at weight 1.0, so any static rule
        picks the same country forever, regardless of who is escalating.

        "Supplied" means MEASURED by the caller, not configured by one.
        `v3/runtime/chain.py` transcribes production's selection and runs
        it against the tick's own observations; a constant of any origin,
        including an operator's environment variable, is the static rule
        this method refuses, wearing a different hat.

        A single-core scenario needs nothing supplied. A dual-core one
        without an explicit choice is an error, not a guess.
        """
        supplied = self.chain_countries.get(scenario.scenario_id)
        if supplied:
            return supplied
        if scenario.core_country:
            return scenario.core_country
        raise DomainError(
            f"{scenario.scenario_id!r} declares no core_country, so its "
            f"sequence chain has no owner. Supply "
            f"chain_countries={{{scenario.scenario_id!r}: <primary_ec>}}: "
            f"the choice depends on which belligerent is currently "
            f"escalating (live spike data), which this layer cannot see.")

    def __reduce__(self):
        # mappingproxy cannot be pickled, and deepcopy follows the same
        # path. Rebuilding through the constructor re-runs validation, so
        # a round-tripped tick is a validated tick.
        return (type(self), (self.now, self.observations, self.scenarios,
                             self.settings, self.focused_scenario_id,
                             self.prior, self.arriving_events,
                             dict(self.score_series),
                             dict(self.pattern_flags),
                             dict(self.chain_countries)))

    @property
    def scorable(self) -> tuple[Scenario, ...]:
        return tuple(s for s in self.scenarios if s.is_scorable)

    def mode_for(self, scenario: Scenario) -> str:
        """S1-SCORE-016: focused is scored full, everything else lite."""
        return (MODE_FULL if scenario.scenario_id == self.focused_scenario_id
                else MODE_LITE)


__all__ = [
    "CYBER", "PHYSICAL", "INFO", "DOMAINS",
    "STATUS_FIRED", "STATUS_DISABLED",
    "ORIGIN_SENSOR", "ORIGIN_LLM_INTEL",
    "MODE_FULL", "MODE_LITE",
    "CountryWeight", "Observation", "Participant", "Scenario",
    "SequenceEvent", "PriorState", "PatternFlags", "ScoringInputs",
]
