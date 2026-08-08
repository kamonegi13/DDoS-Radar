"""Cross-adapter suppression: the join `normalize` structurally cannot reach.

Design sheet §7-2 #35 and #42. Three sources decide whether OTHER sources'
observations mean anything this tick, and `normalize` sees one payload
from one adapter (§2-2 barrier 4), so none of them can be applied where
they are computed:

  * a geomagnetic storm (`space_weather`: Kp >= 6 or an M-class flare)
    makes physical sensors noisy, so IHR's disconnection and delay rows,
    RIPE Atlas and check_host are marked suppressed while it lasts;
  * severe weather over a country (`openweather`) cancels GDELT's tone
    alert outright — production turns the alert into `WEATHER_NOISE` and
    the entry into `SUPPRESSED` with score 0;
  * the same severe weather mutes IODA's BGP degradation for the affected
    countries, and production PRINTS which ones (`core.py:1090`).

**Direction matters.** Not applying a suppression makes v3 louder than
production — a false positive, which NP1 tolerates. Applying one that
production would not makes v3 quieter, which NP1 does not. So the rules
below are transcriptions with their production sites cited, not
generalisations: nothing is suppressed that production does not suppress.

**A suppressed row keeps its score.** `add_rat` stores the caller's number
unchanged and `suppressed` is a separate boolean; exclusion happens at
aggregation (`engine.py:91`, `scoring.py:77`). Zeroing here would be a
second, invisible mechanism doing the same job differently. GDELT is the
one exception and it is production's: its alert is cancelled UPSTREAM of
the score, so the score really is 0 and marking it suppressed as well is
what production writes.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Mapping, Optional, Sequence

from v3.adapters.types import STATUS_SUPPRESSED, ObservationDraft

#: The producers, and the flag on their reduced row that carries the fact.
SPACE_WEATHER = "space_weather"
SPACE_WEATHER_FLAG = "suppress_physical"
OPENWEATHER = "openweather"
OPENWEATHER_FLAG = "is_severe"

#: `radar/routes/core.py:1132`. Verbatim — an analyst greps for it.
SEVERE_WEATHER_REASON = "Severe weather detected"


@dataclass(frozen=True, slots=True)
class Rule:
    """One producer -> one target, with the production site that says so."""

    producer: str
    target_sensor: str
    #: `None` means every row that sensor produced; a name narrows it to
    #: one `signal_source` (IHR emits three rows and production suppresses
    #: two of them).
    target_signal_source: Optional[str]
    #: Global producers (`space_weather` has `country=""`) suppress every
    #: country; per-country producers only their own.
    global_scope: bool
    #: Production marks some targets only when they FIRED — an OK row is
    #: not "suppressed", it is quiet (`core.py:1372`).
    only_when_fired: bool
    #: GDELT alone: production cancels the alert before the score exists.
    zero_score: bool
    production_ref: str
    register_ref: str


RULES: tuple[Rule, ...] = (
    Rule(SPACE_WEATHER, "ihr_health", "bgp", True, False, False,
         "radar/routes/core.py:1495-1515", "§7-2 #35"),
    Rule(SPACE_WEATHER, "ihr_health", "ihr_delay", True, False, False,
         "radar/routes/core.py:1495-1524", "§7-2 #35"),
    Rule(SPACE_WEATHER, "ripe_atlas", "ripe_atlas", True, False, False,
         "radar/routes/core.py:1550", "§7-2 #35"),
    Rule(SPACE_WEATHER, "check_host", "check_host", True, True, False,
         "radar/routes/core.py:1372-1382", "§7-2 #35"),
    Rule(SPACE_WEATHER, "ioda_bgp", None, True, True, False,
         "radar/routes/core.py:1090-1095", "§7-2 #35"),
    Rule(OPENWEATHER, "gdelt", "gdelt", False, False, True,
         "radar/sensors/gdelt.py:58,73,83 / core.py:1132", "§7-2 #42"),
    Rule(OPENWEATHER, "ioda_bgp", None, False, True, False,
         "radar/routes/core.py:1078-1095", "§7-2 #35"),
)


@dataclass(frozen=True, slots=True)
class Suppressors:
    """What the cycle's producers decided, as a lookup. Pure value."""

    #: True when a geomagnetic storm is in progress this tick.
    space_weather_active: bool = False
    space_weather_reason: str = ""
    #: ISO2 -> True where severe weather is over that country.
    severe_weather: Mapping[str, bool] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "severe_weather",
                           dict(self.severe_weather or {}))

    @property
    def weather_muted_countries(self) -> tuple[str, ...]:
        return tuple(sorted(c for c, severe in self.severe_weather.items()
                            if severe))

    def as_dict(self) -> dict:
        return {"space_weather_active": self.space_weather_active,
                "space_weather_reason": self.space_weather_reason,
                "weather_muted": list(self.weather_muted_countries)}


def read_suppressors(drafts_by_adapter: Mapping[str, Sequence]
                     ) -> Suppressors:
    """Read the producers' reduced rows. Nothing is inferred.

    `space_weather`'s two endpoints must already have been folded (the
    reduction ORs them), because a tick that saw only the Kp half would
    read an M-class flare as calm.
    """
    active, reason = False, ""
    for draft in drafts_by_adapter.get(SPACE_WEATHER, ()):
        if draft.flags.get(SPACE_WEATHER_FLAG):
            active = True
            reason = draft.suppress_reason or reason
    severe = {}
    for draft in drafts_by_adapter.get(OPENWEATHER, ()):
        if draft.country:
            severe[draft.country] = bool(draft.flags.get(OPENWEATHER_FLAG))
    return Suppressors(space_weather_active=active,
                       space_weather_reason=reason, severe_weather=severe)


def _fires(rule: Rule, suppressors: Suppressors, country: str) -> bool:
    if rule.producer == SPACE_WEATHER:
        return suppressors.space_weather_active
    return bool(suppressors.severe_weather.get(country))


def _reason_for(rule: Rule, suppressors: Suppressors) -> str:
    if rule.producer == SPACE_WEATHER:
        return suppressors.space_weather_reason or "Geomagnetic storm"
    if rule.target_sensor == "ioda_bgp":
        # `core.py:1090` prints the muted countries in the value; the
        # reason names them too, so the row says WHICH weather muted it.
        return f"Weather-muted: {list(suppressors.weather_muted_countries)}"
    return SEVERE_WEATHER_REASON


def apply(adapter_id: str, drafts: Sequence[ObservationDraft], *,
          suppressors: Suppressors) -> tuple[ObservationDraft, ...]:
    """Mark this adapter's rows according to the cycle's producers.

    Returns new drafts; nothing is mutated. Rows no rule names come back
    untouched, which is most of them — the register lists seven joins, not
    a policy.
    """
    rules = [r for r in RULES if r.target_sensor == adapter_id]
    if not rules:
        return tuple(drafts)
    marked = []
    for draft in drafts:
        applied = None
        for rule in rules:
            if rule.target_signal_source not in (None, draft.signal_source):
                continue
            if rule.only_when_fired and draft.raw_score <= 0.0:
                continue
            if not _fires(rule, suppressors, draft.country):
                continue
            applied = rule
            break
        if applied is None:
            marked.append(draft)
            continue
        flags = {**dict(draft.flags),
                 "suppressed_by": applied.producer,
                 "suppression_ref": applied.production_ref}
        if applied.producer == OPENWEATHER and applied.target_sensor == \
                "ioda_bgp":
            flags["weather_muted"] = list(
                suppressors.weather_muted_countries)
        marked.append(replace(
            draft,
            status=STATUS_SUPPRESSED if applied.zero_score else draft.status,
            raw_score=0.0 if applied.zero_score else draft.raw_score,
            suppressed=True,
            suppress_reason=_reason_for(applied, suppressors),
            flags=flags))
    return tuple(marked)


def suppressed_sensors() -> frozenset:
    return frozenset(rule.target_sensor for rule in RULES)


def registry_disclosure() -> list[dict]:
    """Every join this layer performs and where production performs it."""
    return [{"producer": r.producer, "target": r.target_sensor,
             "signal_source": r.target_signal_source,
             "only_when_fired": r.only_when_fired,
             "zero_score": r.zero_score,
             "production_ref": r.production_ref,
             "register_ref": r.register_ref} for r in RULES]


__all__ = ["Rule", "RULES", "Suppressors", "read_suppressors", "apply",
           "suppressed_sensors", "registry_disclosure", "SPACE_WEATHER",
           "OPENWEATHER", "SEVERE_WEATHER_REASON"]
