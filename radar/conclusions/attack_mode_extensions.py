"""Scenario-specific attack mode extensions (ADR-V2-002, Phase 2.5 hook).

Augments the base 5-mode classifier with scenario-tailored modes defined
declaratively in `geo_data.json["SCENARIOS"][<id>]["attack_mode_extensions"]`.

Why scenario_extensions exist (NP1 + analyst pattern learning):
  - The base modes are intentionally generic and miss high-signal patterns
    that only matter inside a specific scenario (e.g. PLA air-incursion is
    only meaningful for taiwan_contingency).
  - Without extensions, those scenarios degrade to the lowest-common base
    mode and the analyst loses scenario-specific context.

Design constraints:
  - Pure function over (scenario_id, ScenarioState). No DB read.
  - Declarative rules — config-only, no per-scenario Python branches. New
    scenarios get extensions by editing geo_data.json, not by editing code.
  - Conservative confidence (NP1) — extensions never push above 0.95 and
    cap their floor at 0.55 so an INSUFFICIENT_SIGNAL base never gets
    silently overridden by an extension claim alone unless the extension
    rule itself fires strongly.
  - Extensions append to the ranked list; they never replace base matches.
    The deriver re-sorts the union by confidence.

Extension schema (geo_data.json):

    "attack_mode_extensions": [
      {
        "mode": "NAVAL_BLOCKADE_PRECURSOR",
        "domain_floors": {"physical": 4.0, "info": 1.0},
        "active_n_min": 3,
        "requires_participant": ["CN"],   # optional — must be active
        "base_confidence": 0.6,
        "rule_summary": "physical>=4 & CN active"
      }
    ]

  - `mode`: extension mode name (must NOT collide with base 5)
  - `domain_floors`: per-domain min score (all must be met)
  - `active_n_min`: min count of active_countries
  - `requires_participant`: ISO-2 codes that must appear in active_countries
  - `base_confidence`: starting confidence (clamped to [0.55, 0.85])
  - `rule_summary`: human-readable rule string for `_ModeMatch.rule`
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Optional

if TYPE_CHECKING:
    from radar.scoring import ScenarioState

log = logging.getLogger("radar")


# Conservative confidence band for extensions. Even a strongly-firing
# extension never claims >0.95 (NP1 — recall over precision; we want the
# analyst to still review). The lower clamp keeps a misconfigured rule
# from showing up as a "weak hint" — declared extensions earn at least
# 0.55 once their conditions are met.
_EXT_CONFIDENCE_FLOOR = 0.55
_EXT_CONFIDENCE_CEIL = 0.95
_EXT_BASE_DEFAULT = 0.60

# Reserved base mode names — extensions must not redefine them.
_RESERVED_MODES = frozenset({
    "DDOS_PRECURSOR",
    "KINETIC_PREPARATION",
    "HYBRID_PRESSURE",
    "INFO_OPS_DOMINANT",
    "INSUFFICIENT_SIGNAL",
})


@dataclass(frozen=True)
class ExtensionMatch:
    """One scenario_extensions rule that fired against the current state."""

    mode: str
    confidence: float
    rule: str


def _coerce_floors(raw: Any) -> dict[str, float]:
    """Coerce JSON dict → dict[str, float]; reject silently on bad shape."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, float] = {}
    for k, v in raw.items():
        if not isinstance(k, str):
            continue
        try:
            out[k] = float(v)
        except (TypeError, ValueError):
            continue
    return out


def _coerce_str_list(raw: Any) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(s for s in raw if isinstance(s, str))


def _load_scenario_extensions(scenario_id: str) -> list[dict[str, Any]]:
    """Read `attack_mode_extensions` from the scenario preset.

    Falls back to [] silently on any I/O / parse failure (NP3 — the deriver
    must keep classifying base modes even when geo_data is missing or the
    scenario has no extensions block).
    """
    try:
        from radar import config  # local import to avoid module-load cycles
        scenarios_raw = config._raw_geo.get("SCENARIOS", {}) if config._raw_geo else {}
    except Exception:
        return []
    raw = scenarios_raw.get(scenario_id) or {}
    exts = raw.get("attack_mode_extensions")
    if not isinstance(exts, list):
        return []
    return [e for e in exts if isinstance(e, dict)]


def _evaluate_one(
    ext: dict[str, Any],
    *,
    cyber: float,
    physical: float,
    info: float,
    active_countries: Iterable[str],
) -> Optional[ExtensionMatch]:
    """Evaluate a single extension rule against domain scores + active set.

    Returns an ExtensionMatch when all configured conditions pass; None
    otherwise. Malformed extensions (missing/non-string mode, reserved
    mode name) are dropped silently — the deriver must not crash on bad
    config.
    """
    mode = ext.get("mode")
    if not isinstance(mode, str) or not mode:
        return None
    if mode in _RESERVED_MODES:
        log.warning(
            "[attack_mode_ext] dropping extension that shadows base mode: %s", mode,
        )
        return None

    floors = _coerce_floors(ext.get("domain_floors"))
    domain_scores = {"cyber": cyber, "physical": physical, "info": info}
    margins: list[float] = []
    for domain, floor in floors.items():
        actual = domain_scores.get(domain, 0.0)
        if actual < floor:
            return None
        if floor > 0:
            margins.append((actual - floor) / floor)

    active_n_min = ext.get("active_n_min")
    if isinstance(active_n_min, (int, float)):
        if len(list(active_countries)) < int(active_n_min):
            return None

    requires = _coerce_str_list(ext.get("requires_participant"))
    if requires:
        active_set = {c.upper() for c in active_countries}
        for cc in requires:
            if cc.upper() not in active_set:
                return None

    base_conf_raw = ext.get("base_confidence", _EXT_BASE_DEFAULT)
    try:
        base_conf = float(base_conf_raw)
    except (TypeError, ValueError):
        base_conf = _EXT_BASE_DEFAULT
    base_conf = max(_EXT_CONFIDENCE_FLOOR, min(0.85, base_conf))

    margin_bonus = 0.0
    if margins:
        margin_bonus = 0.30 * min(1.0, max(margins))

    confidence = round(min(_EXT_CONFIDENCE_CEIL, base_conf + margin_bonus), 3)

    rule_summary = ext.get("rule_summary")
    if not isinstance(rule_summary, str) or not rule_summary:
        rule_summary = f"ext:{mode.lower()} (floors={floors})"

    return ExtensionMatch(mode=mode, confidence=confidence, rule=rule_summary)


def evaluate_extensions(state: "ScenarioState") -> list[ExtensionMatch]:
    """Evaluate every extension declared on the scenario against the state.

    Returns the matches as a flat list. Empty list when:
      - the scenario has no `attack_mode_extensions` block, OR
      - geo_data is unavailable, OR
      - none of the declared extensions fired.

    This function is the Phase 2.5 hook. The base deriver calls it after
    base rules and merges results before re-sorting by confidence.
    """
    exts = _load_scenario_extensions(state.scenario_id)
    if not exts:
        return []

    cyber = float(state.domains.get("cyber", 0.0))
    physical = float(state.domains.get("physical", 0.0))
    info = float(state.domains.get("info", 0.0))

    matches: list[ExtensionMatch] = []
    seen_modes: set[str] = set()
    for ext in exts:
        mode = ext.get("mode")
        if isinstance(mode, str) and mode in seen_modes:
            # First declaration wins — duplicates in config are a typo,
            # not a feature.
            continue
        m = _evaluate_one(
            ext,
            cyber=cyber, physical=physical, info=info,
            active_countries=state.active_countries,
        )
        if m is not None:
            matches.append(m)
            seen_modes.add(m.mode)

    return matches
