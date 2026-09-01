"""The operationally-variable key set, and the refusal for everything else.

P6 O-18 split configuration in two and the evidence for the split is
G-15's measurement: 95 of 98 registered keys went unread for months and
nobody noticed. What NP6 asked for was **disclosure**, not runtime
variability. So:

    (a) operationally variable — this file. Resolvable through the
        3-layer chain, changeable by an analyst, and every one of them has
        a named READER. That last clause is WP-1.2's whole finding: a
        registered key nobody reads is not a feature with a small
        audience, it is a control surface that lies.
    (b) pinned constants — `Threshold.pinned` in the layer that uses them
        (`v3/scoring/thresholds.py`, `v3/conclusions/thresholds.py`,
        `v3/calibration/thresholds.py`). Disclosed, auditable, and moved
        only by editing code, which forces review and re-calibration.

The registry is ASSEMBLED, not re-spelled. The nine group-(a) keys are
already declared beside the formulas that consume them, with the `why`
O-18 requires; copying them here would create a second catalogue to drift
against the first. This module adds the one fact those declarations do
not carry — the consumer — and that fact is what
`tests/test_config_registry.py` executes rather than reads.

**An override attempt on anything else is refused, not ignored.** A
pinned key gets a refusal naming its provenance and saying the change is
a code change; an unknown key gets a refusal saying so. Silently
accepting either would write an audit row for a change that never
happens, which is G-15 with better paperwork.

Nothing here is read at import beyond the pinned catalogues' own
constants: no environment, no ledger, no clock.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from v3.calibration import thresholds as calibration_thresholds
from v3.conclusions import thresholds as conclusion_thresholds
from v3.kernel import Threshold
from v3.kernel.errors import DomainError
from v3.kernel.units import Percentage, Ratio
from v3.scoring import thresholds as scoring_thresholds

#: The function that turns the scoring group's keys into numbers the tool
#: uses. Named as `module:function` so the reachability test can find it
#: rather than trust it.
SCORING_CONSUMER = "v3.scoring.settings:resolve_settings"

#: Units whose values must be whole numbers.
_INTEGER_UNITS = frozenset({"count"})
#: Truthy / falsey spellings accepted from the ENV layer only. A JSON
#: override must send a real boolean — a string there means the caller
#: guessed at the type, and `"false"` is truthy in every language that
#: coerces.
_ENV_TRUE = frozenset({"1", "true", "yes", "on"})
_ENV_FALSE = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True, slots=True)
class RegisteredKey:
    """One operationally-variable key: what it is, and who reads it.

    `consumer` is required and has no default. WP-1.2 measured what the
    alternative costs: a registry whose entries nobody consults looks
    identical, from the settings screen, to one that works.
    """

    threshold: Threshold
    default: Any
    why: str
    consumer: str
    catalogue: str

    def __post_init__(self) -> None:
        if not self.threshold.is_registry_backed:
            raise DomainError(
                f"a registered key must be Threshold.registry_backed; "
                f"{self.threshold} is pinned. O-18 group (b) is disclosed, "
                f"not overridable.")
        for name in ("why", "consumer", "catalogue"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise DomainError(
                    f"RegisteredKey.{name} must be a non-empty string: "
                    f"{self.key!r} would otherwise be a dial with no stated "
                    f"{name}, which is how 95 keys became invisible (G-15)")
        if ":" not in self.consumer:
            raise DomainError(
                f"{self.key}.consumer must be 'module:callable', got "
                f"{self.consumer!r}. The reachability check resolves it; a "
                f"prose description cannot be executed.")

    @property
    def key(self) -> str:
        return self.threshold.key

    @property
    def unit(self) -> str:
        return self.threshold.unit

    def as_dict(self) -> dict:
        return {"key": self.key, "unit": self.unit, "default": self.default,
                "why": self.why, "consumer": self.consumer,
                "catalogue": self.catalogue}


def _from_scoring() -> dict:
    """The nine effective-path dials, taken from where they are declared."""
    return {
        name: RegisteredKey(threshold=declared.threshold,
                            default=declared.default, why=declared.why,
                            consumer=SCORING_CONSUMER,
                            catalogue="v3/scoring/thresholds.py::VARIABLE")
        for name, declared in scoring_thresholds.VARIABLE.items()
    }


#: THE O-18 group (a) set. O-18's target is 20-30 keys; this is nine,
#: and the gap is deliberate rather than unfinished. A key joins when
#: something in v3 reads it, because the reachability test refuses one
#: that nothing does. `NARRATIVE_ZSCORE_FIRST_SIGNAL` (design sheet §7-2
#: #52) is the worked example: it is the most sensitive number in
#: `rss_narrative` and it stays a pinned constant, because the v3
#: narrative reduction has no z-score consumer yet
#: (`v3/runtime/reduce.py::_fold_named_sources` declines to synthesise
#: the verdict for want of an L1 baseline). Registering it now would add
#: exactly the decorative entry this registry exists to make impossible.
VARIABLE_KEYS: dict[str, RegisteredKey] = _from_scoring()


def variable_keys() -> tuple[str, ...]:
    return tuple(sorted(VARIABLE_KEYS))


def is_variable(key: str) -> bool:
    return key in VARIABLE_KEYS


def entry_for(key: str) -> RegisteredKey:
    refuse_if_not_variable(key)
    return VARIABLE_KEYS[key]


def default_of(key: str) -> Any:
    return entry_for(key).default


def pinned_disclosure() -> dict:
    """Every group-(b) constant, from the three catalogues that hold them.

    Served alongside the variable keys (R10/R14) because O-18 requires
    constants to be DISCLOSED even though they are not variable — and
    because the refusal below needs to be able to say "this one is pinned,
    here is its provenance" rather than "unknown key".
    """
    merged: dict = {}
    for label, source in (("scoring", _scoring_pinned()),
                          ("conclusions", conclusion_thresholds.disclosure()),
                          ("calibration", calibration_thresholds.disclosure())):
        for name, body in source.items():
            merged.setdefault(name, {**body, "catalogue": label})
    return merged


def _scoring_pinned() -> dict:
    """`v3/scoring/thresholds.py` has no `disclosure()`; build the same shape.

    Values are unwrapped to plain numbers here. A `Ratio` survives a
    comparison but not `json.dumps`, and this mapping is served (R10) as
    well as read by the refusal below.
    """
    disclosed = {}
    for name in scoring_thresholds.pinned_names():
        declared = scoring_thresholds.pinned_threshold(name)
        resolved = declared.resolve().value
        disclosed[name] = {
            "value": getattr(resolved, "value", resolved),
            "unit": declared.unit,
            "provenance_ref": declared.provenance_ref,
        }
    return disclosed


def variable_disclosure() -> list[dict]:
    """The registry as data (R14's static half)."""
    return [VARIABLE_KEYS[name].as_dict() for name in variable_keys()]


def refuse_if_not_variable(key: str) -> None:
    """Raise unless `key` is in group (a). Never returns False quietly.

    The two refusals differ on purpose. "Pinned" tells the operator that
    the number exists, is disclosed, and moves by code review — which is
    an answer. "Unknown" tells them the name is wrong. Collapsing the two
    into a shrug is how an analyst comes to believe a dial exists.
    """
    if not isinstance(key, str) or not key.strip():
        raise DomainError("a configuration key must be a non-empty string")
    if key in VARIABLE_KEYS:
        return
    pinned = pinned_disclosure().get(key)
    if pinned is not None:
        raise DomainError(
            f"{key!r} is a pinned constant (P6 O-18 group (b)), not an "
            f"operationally variable key. Value {pinned.get('value')!r}, "
            f"provenance: {pinned.get('provenance_ref')}. Changing it is a "
            f"code change, which is the point: it forces review and "
            f"re-calibration. The override is REFUSED rather than recorded, "
            f"because an audit row for a change nothing applies is defect "
            f"G-15 with better paperwork.")
    raise DomainError(
        f"unknown configuration key {key!r}: the operationally variable set "
        f"is {list(variable_keys())} (P6 O-18 group (a)). Everything else is "
        f"a disclosed constant or does not exist.")


def coerce_value(key: str, raw: Any) -> Any:
    """Validate an OVERRIDE value against the key's declared unit.

    Returns a JSON primitive, because the value is stored in an
    append-only command row and compared for equality against a freshly
    folded copy: a type that does not survive `json.dumps`/`loads` would
    compare unequal to itself forever (`v3/commands/state.py`).

    Strict about booleans in both directions. A `bool` key given `1` and a
    numeric key given `True` are both accepted by Python's arithmetic and
    both mean the caller did not know the type — and `GLOBAL_SIGNALS_
    DECOUPLED = 1` reads as "on" while telling `ScoringSettings._flag`
    that its input was never a real bool.
    """
    declared = entry_for(key)
    unit = declared.unit
    if unit == "bool":
        if not isinstance(raw, bool):
            raise DomainError(
                f"{key} is a {unit} key: send a real boolean, not "
                f"{type(raw).__name__} {raw!r}. Coercing would make the "
                f"string 'false' mean True.")
        return raw
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise DomainError(
            f"{key} is a {unit} key and takes a number, got "
            f"{type(raw).__name__} {raw!r}")
    numeric = float(raw)
    if math.isnan(numeric) or math.isinf(numeric):
        raise DomainError(
            f"{key} must be finite, got {raw!r}: a NaN threshold compares "
            f"False against everything, which reads as 'never exceeded' "
            f"rather than as an error")
    if unit == "ratio":
        return float(Ratio(numeric).value)
    if unit == "percent":
        return float(Percentage(numeric).value)
    if unit in _INTEGER_UNITS:
        if numeric != int(numeric):
            raise DomainError(f"{key} is a {unit} key and takes a whole "
                              f"number, got {raw!r}")
        return int(numeric)
    return numeric


def coerce_env_value(key: str, raw: str) -> Any:
    """Parse an ENV-layer string for `key`, or raise.

    Separate from `coerce_value` because the env layer is the one place a
    value legitimately arrives as text. A malformed value raises rather
    than falling through to the default: silently preferring the default
    is how an operator comes to believe the variable they exported is in
    effect.
    """
    declared = entry_for(key)
    text = str(raw).strip()
    if declared.unit == "bool":
        lowered = text.lower()
        if lowered in _ENV_TRUE:
            return True
        if lowered in _ENV_FALSE:
            return False
        raise DomainError(
            f"{key} is a bool key; the environment holds {raw!r}, which is "
            f"neither {sorted(_ENV_TRUE)} nor {sorted(_ENV_FALSE)}. Refused "
            f"rather than defaulted — a value nobody can parse is not the "
            f"same as a value nobody set.")
    try:
        numeric = float(text)
    except (TypeError, ValueError):
        raise DomainError(
            f"{key} is a {declared.unit} key; the environment holds {raw!r}, "
            f"which is not a number") from None
    return coerce_value(key, numeric)


__all__ = ["RegisteredKey", "VARIABLE_KEYS", "SCORING_CONSUMER",
           "variable_keys", "is_variable", "entry_for", "default_of",
           "pinned_disclosure", "variable_disclosure",
           "refuse_if_not_variable", "coerce_value", "coerce_env_value"]
