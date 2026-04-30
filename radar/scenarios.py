"""radar.scenarios -- Scenario data model, loader, and validator.

Implements the scenario-centric architecture defined in
docs/design/v2-migration.md (current) — the v1 reference at
docs/_archive/scenario-refactor-v1.8.1.md is retained for history.

Layers:
  Layer 1: Static presets from geo_data.json["scenarios"]
  Layer 2: Persistent customizations from SQLite (scenarios + scenario_participants)
  Layer 3: Session overrides (in-memory, applied at request time — Phase 4)
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger("radar")

# ── scenario_id validation ──────────────────────────────────────────────────
_SCENARIO_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,29}$")

RESERVED_IDS = frozenset({
    "default", "none", "null", "all", "test", "admin", "system",
})


class Role(Enum):
    PRIMARY_TARGET = "primary_target"
    PRINCIPAL_BELLIGERENT = "principal_belligerent"
    ADVERSARY = "adversary"
    PRIMARY_ALLY = "primary_ally"
    FORWARD_BASE = "forward_base"
    SECONDARY_ALLY = "secondary_ally"
    EXTENDED_DETERRENCE = "extended_deterrence"
    STRATEGIC_OBSERVER = "strategic_observer"
    PROXY_FRONT = "proxy_front"
    FORCE_PROJECTION = "force_projection"
    SECONDARY_PARTY = "secondary_party"
    SPILLOVER_RISK = "spillover_risk"
    REGIONAL_POWER = "regional_power"


_ROLE_VALUES = frozenset(r.value for r in Role)


class SensorTier(Enum):
    GLOBAL = "global"
    FOCUSED_ONLY = "focused_only"
    BACKGROUND_ELIGIBLE = "background_eligible"


# Single source of truth for the FOCUSED_ONLY sensor names (ADR-002, §6).
# Per-country sensors that target the focused scenario's participants only.
# Keep this in sync with `tier = SensorTier.FOCUSED_ONLY` declarations on
# each sensor class; a startup assertion in radar/__init__.py verifies
# that no sensor has a different tier than what this set implies.
FOCUSED_ONLY_SENSOR_NAMES: frozenset[str] = frozenset({
    "cloudflare_radar", "ioda_bgp", "ripe_bgp", "openweather",
    "check_host", "opensky", "notam", "ripe_atlas",
    "ais_maritime", "isr_hotspot", "nasa_firms", "mil_support_air",
})


@dataclass
class Participant:
    country: str
    weight: float
    role: Role

    def to_dict(self) -> dict:
        return {
            "country": self.country,
            "weight": self.weight,
            "role": self.role.value,
        }


@dataclass
class Scenario:
    id: str
    name_en: str
    name_ja: str
    description_en: str
    description_ja: str
    core_country: Optional[str]
    state: str
    enabled: bool
    tier: int
    participants: dict[str, Participant]
    created_at: float = 0.0
    updated_at: float = 0.0
    updated_by: str = ""
    # Phase 3.1 (problem 49): preset metadata block from geo_data.json
    # explaining why a scenario is `enabled=False` in preset. Surfaced
    # in API responses so analyst UI can warn when admin overrides
    # enable a preset-disabled scenario.
    preset_metadata: Optional[dict] = None

    @property
    def is_scorable(self) -> bool:
        return self.state == "active" and self.enabled

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name_en": self.name_en,
            "name_ja": self.name_ja,
            "description_en": self.description_en,
            "description_ja": self.description_ja,
            "core_country": self.core_country,
            "state": self.state,
            "enabled": self.enabled,
            "tier": self.tier,
            "participants": {
                cc: p.to_dict() for cc, p in self.participants.items()
            },
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "preset_metadata": self.preset_metadata,
        }


# ── Layer 3 session override (ADR-003, ADR-011) ─────────────────────────────

def apply_session_overlay(
    scenario: "Scenario",
    weight_overrides: dict[str, float],
) -> "Scenario":
    """Apply a stateless Layer 3 weight overlay to a scenario.

    Returns a new Scenario with participant weights replaced per
    `weight_overrides`. Override values outside [0.0, 1.0] are silently
    clamped (per ADR-011 edge-case table: in-memory overrides with
    out-of-range values are rejected from scoring).  Unknown countries
    in the overlay are ignored.

    The source scenario is not mutated.
    """
    if not weight_overrides:
        return scenario
    new_parts: dict[str, Participant] = {}
    for cc, p in scenario.participants.items():
        ov = weight_overrides.get(cc.upper())
        if ov is None:
            new_parts[cc] = p
            continue
        try:
            ov_val = float(ov)
        except (TypeError, ValueError):
            new_parts[cc] = p
            continue
        if not (0.0 <= ov_val <= 1.0):
            # Out of range → keep original per ADR-011 reject rule.
            new_parts[cc] = p
            continue
        new_parts[cc] = Participant(
            country=p.country, weight=ov_val, role=p.role)
    # dataclasses.replace-style clone without importing dataclasses.replace
    return Scenario(
        id=scenario.id,
        name_en=scenario.name_en,
        name_ja=scenario.name_ja,
        description_en=scenario.description_en,
        description_ja=scenario.description_ja,
        core_country=scenario.core_country,
        state=scenario.state,
        enabled=scenario.enabled,
        tier=scenario.tier,
        participants=new_parts,
        created_at=scenario.created_at,
        updated_at=scenario.updated_at,
        updated_by=scenario.updated_by,
    )


# ── Validation ──────────────────────────────────────────────────────────────

class ScenarioValidationError(ValueError):
    pass


def validate_scenario_id(scenario_id: str) -> None:
    if not _SCENARIO_ID_RE.match(scenario_id):
        raise ScenarioValidationError(
            f"Invalid scenario_id '{scenario_id}': "
            f"must match {_SCENARIO_ID_RE.pattern}"
        )
    if scenario_id in RESERVED_IDS:
        raise ScenarioValidationError(
            f"scenario_id '{scenario_id}' is a reserved word"
        )
    try:
        from radar.database import db
        conn = db._get_conn()
        row = conn.execute(
            "SELECT id FROM scenario_reserved_ids WHERE id=?", (scenario_id,)
        ).fetchone()
        if row:
            raise ScenarioValidationError(
                f"scenario_id '{scenario_id}' was previously purged and is reserved"
            )
    except ScenarioValidationError:
        raise
    except Exception:
        pass
    if scenario_id.startswith("test_"):
        log.warning("scenario_id '%s' uses test_ prefix (reserved for QA)", scenario_id)


def validate_participant(country: str, data: dict, scenario_id: str) -> Participant:
    role_str = data.get("role", "")
    if role_str not in _ROLE_VALUES:
        raise ScenarioValidationError(
            f"Scenario '{scenario_id}', participant '{country}': "
            f"unknown role '{role_str}'. Valid: {sorted(_ROLE_VALUES)}"
        )
    weight = data.get("weight", 0.0)
    if not isinstance(weight, (int, float)) or weight < 0.0 or weight > 1.0:
        raise ScenarioValidationError(
            f"Scenario '{scenario_id}', participant '{country}': "
            f"weight must be 0.0-1.0, got {weight}"
        )
    return Participant(
        country=country,
        weight=float(weight),
        role=Role(role_str),
    )


def validate_state(state: str, scenario_id: str) -> str:
    valid = ("active", "paused", "archived")
    if state not in valid:
        raise ScenarioValidationError(
            f"Scenario '{scenario_id}': invalid state '{state}', must be one of {valid}"
        )
    return state


# ── Layer 1: Load from geo_data.json ────────────────────────────────────────

def _parse_scenario_json(scenario_id: str, raw: dict) -> Scenario:
    validate_scenario_id(scenario_id)
    state = validate_state(raw.get("state", "active"), scenario_id)

    participants_raw = raw.get("participants", {})
    if not participants_raw:
        raise ScenarioValidationError(
            f"Scenario '{scenario_id}' has no participants"
        )

    participants = {}
    for cc, pdata in participants_raw.items():
        participants[cc] = validate_participant(cc, pdata, scenario_id)

    now = time.time()
    return Scenario(
        id=scenario_id,
        name_en=raw.get("name_en", scenario_id),
        name_ja=raw.get("name_ja", scenario_id),
        description_en=raw.get("description_en", ""),
        description_ja=raw.get("description_ja", ""),
        core_country=raw.get("core_country"),
        state=state,
        enabled=bool(raw.get("enabled", True)),
        tier=int(raw.get("tier", 1)),
        participants=participants,
        created_at=raw.get("created_at", now),
        updated_at=raw.get("updated_at", now),
        preset_metadata=raw.get("_preset_metadata"),
    )


def load_layer1(geo_data: dict) -> dict[str, Scenario]:
    scenarios_raw = geo_data.get("SCENARIOS", {})
    if not scenarios_raw:
        log.warning("[Scenarios] No scenarios found in geo_data.json")
        return {}

    result: dict[str, Scenario] = {}
    for sid, raw in scenarios_raw.items():
        try:
            result[sid] = _parse_scenario_json(sid, raw)
        except ScenarioValidationError as e:
            raise RuntimeError(f"[Scenarios] Failed to load preset: {e}") from e

    log.info(
        "[Scenarios] Layer 1: loaded %d presets from geo_data.json (%s)",
        len(result),
        ", ".join(sorted(result.keys())),
    )
    return result


# ── Layer 2: Merge from SQLite ──────────────────────────────────────────────

def load_layer2(layer1: dict[str, Scenario]) -> dict[str, Scenario]:
    from radar.database import db

    result = dict(layer1)
    conn = db._get_conn()

    try:
        rows = conn.execute("SELECT * FROM scenarios").fetchall()
    except Exception:
        log.debug("[Scenarios] Layer 2: scenarios table not yet available")
        return result

    for row in rows:
        sid = row["id"]
        try:
            state = validate_state(row["state"], sid)
        except ScenarioValidationError as e:
            log.warning("[Scenarios] Layer 2 skip '%s': %s", sid, e)
            continue

        p_rows = conn.execute(
            "SELECT country, weight, role FROM scenario_participants WHERE scenario_id=?",
            (sid,),
        ).fetchall()

        participants = {}
        for pr in p_rows:
            try:
                participants[pr["country"]] = validate_participant(
                    pr["country"],
                    {"weight": pr["weight"], "role": pr["role"]},
                    sid,
                )
            except ScenarioValidationError as e:
                log.warning("[Scenarios] Layer 2 participant skip: %s", e)
                continue

        if not participants and sid not in result:
            log.warning("[Scenarios] Layer 2 skip '%s': no valid participants", sid)
            continue

        if sid in result:
            base = result[sid]
            result[sid] = Scenario(
                id=sid,
                name_en=row["name_en"] or base.name_en,
                name_ja=row["name_ja"] or base.name_ja,
                description_en=row["description_en"] if row["description_en"] is not None else base.description_en,
                description_ja=row["description_ja"] if row["description_ja"] is not None else base.description_ja,
                core_country=row["core_country"] if row["core_country"] is not None else base.core_country,
                state=state,
                enabled=bool(row["enabled"]),
                tier=row["tier"] or base.tier,
                participants=participants if participants else base.participants,
                created_at=row["created_at"] or base.created_at,
                updated_at=row["updated_at"] or base.updated_at,
                updated_by=row["updated_by"] or "",
            )
        else:
            if not participants:
                continue
            result[sid] = Scenario(
                id=sid,
                name_en=row["name_en"],
                name_ja=row["name_ja"],
                description_en=row["description_en"] or "",
                description_ja=row["description_ja"] or "",
                core_country=row["core_country"],
                state=state,
                enabled=bool(row["enabled"]),
                tier=row["tier"] or 1,
                participants=participants,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                updated_by=row["updated_by"] or "",
            )

    db_only = set(r["id"] for r in rows) - set(layer1.keys())
    if db_only:
        log.info("[Scenarios] Layer 2: merged %d DB-only scenarios (%s)",
                 len(db_only), ", ".join(sorted(db_only)))

    return result


# ── Scenario Store (singleton, thread-safe read) ────────────────────────────

class ScenarioStore:
    def __init__(self):
        self._scenarios: dict[str, Scenario] = {}
        # Phase 3.2 (problem 49): retain Layer-1 raw scenarios so the API
        # can compute is_admin_override = (preset.enabled != merged.enabled).
        # Memory cost ~5KB for current 5 scenarios; negligible.
        self._preset_originals: dict[str, Scenario] = {}
        self._loaded = False

    def load(self, geo_data: dict) -> None:
        layer1 = load_layer1(geo_data)
        # Snapshot Layer-1 raw BEFORE Layer-2 merge so override detection
        # can compare preset vs effective. NOTE: Layer-3 session overlays
        # are NOT reflected here (per ADR-011); preset_originals captures
        # the geo_data.json baseline only.
        self._preset_originals = dict(layer1)
        merged = load_layer2(layer1)
        self._scenarios = merged
        self._loaded = True

        scorable = [s for s in merged.values() if s.is_scorable]
        log.info(
            "[Scenarios] Store ready: %d total, %d scorable",
            len(merged), len(scorable),
        )
        # Phase F (2026-04-30): ensure every preset scenario has a row in
        # the scenarios DB table so children tables (conclusions /
        # scenario_proposals / scenario_drift_events / scenario_tl_observation)
        # have a defined parent row. Pre-fix only south_china_sea was
        # registered (because admin had toggled it via the UI); the other
        # 4 preset scenarios produced thousands of orphan child rows.
        try:
            self._upsert_to_db()
        except Exception as exc:
            log.warning("[Scenarios] _upsert_to_db failed (non-fatal): %s", exc)

    def _upsert_to_db(self) -> None:
        """Idempotent INSERT-OR-IGNORE for every preset scenario.

        We do NOT overwrite an existing DB row — admin overrides
        (Layer 2) take precedence over preset (Layer 1). This only
        fills in missing rows so referential integrity holds.
        """
        from radar.database import db
        import time
        conn = db._get_conn()  # noqa: SLF001
        now_ts = time.time()
        with conn.writing():
            for sid, sc in self._scenarios.items():
                state = sc.state.value if hasattr(sc.state, 'value') else str(sc.state)
                # Use INSERT OR IGNORE so existing admin overrides are preserved.
                conn.execute(
                    "INSERT OR IGNORE INTO scenarios "
                    "(id, name_en, name_ja, description_en, description_ja, "
                    " core_country, state, enabled, tier, created_at, "
                    " updated_at, updated_by) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'auto:preset_load')",
                    (sid, sc.name_en, sc.name_ja,
                     getattr(sc, 'description_en', ''),
                     getattr(sc, 'description_ja', ''),
                     sc.core_country, state,
                     1 if sc.enabled else 0,
                     getattr(sc, 'tier', None),
                     now_ts, now_ts),
                )
        # Validate that all participant country codes have coordinates
        from radar.config import COUNTRY_COORDS
        for sc in merged.values():
            missing = [c for c in sc.participants if c not in COUNTRY_COORDS]
            if missing:
                log.warning(
                    "[Scenarios] %s has participants missing from COUNTRY_COORDS: %s "
                    "— map markers will use fallback coordinates",
                    sc.id, ", ".join(missing),
                )

    def get(self, scenario_id: str) -> Optional[Scenario]:
        return self._scenarios.get(scenario_id)

    def all(self) -> dict[str, Scenario]:
        return dict(self._scenarios)

    def is_enabled_overridden(self, scenario_id: str) -> bool:
        """Phase 3.2 (problem 49): True iff the effective `enabled`
        flag differs from the preset (Layer-1) `enabled` flag.

        - True when preset says disabled but admin enabled it (or vice
          versa) — UI should warn analysts.
        - False when preset and effective agree.
        - False when preset doesn't exist (DB-only scenario; no
          override concept).
        - False when scenario doesn't exist in either store.
        """
        preset = self._preset_originals.get(scenario_id)
        current = self._scenarios.get(scenario_id)
        if preset is None or current is None:
            return False
        return preset.enabled != current.enabled

    def preset_enabled(self, scenario_id: str) -> Optional[bool]:
        """Return the Layer-1 preset `enabled` value, or None if no
        preset row exists. Used by API to expose the comparison."""
        preset = self._preset_originals.get(scenario_id)
        return preset.enabled if preset is not None else None

    def preset_metadata(self, scenario_id: str) -> Optional[dict]:
        """Return the Layer-1 preset_metadata dict, or None."""
        preset = self._preset_originals.get(scenario_id)
        return preset.preset_metadata if preset is not None else None

    def scorable(self) -> list[Scenario]:
        return [s for s in self._scenarios.values() if s.is_scorable]

    def get_reserved_ids(self) -> set[str]:
        reserved = set(RESERVED_IDS)
        try:
            from radar.database import db
            conn = db._get_conn()
            rows = conn.execute("SELECT id FROM scenario_reserved_ids").fetchall()
            reserved |= {r["id"] for r in rows}
        except Exception:
            pass
        return reserved

    def reload(self) -> None:
        if not self._loaded:
            return
        # _raw_geo is the source-of-truth geo dict exposed by radar.config
        # (matches what radar/__init__.py passes to load() at startup).
        from radar.config import _raw_geo
        self.load(_raw_geo)

    @property
    def loaded(self) -> bool:
        return self._loaded


scenario_store = ScenarioStore()


# ── Helpers: derive legacy-compatible country lists from a scenario ─────────
# ADR-005 supersedes core_theater with focused_scenario; ADR-014 merges adversaries
# into participants[role=ADVERSARY]. These helpers collapse the mapping into a
# single definition point so per-country sensor pipelines, HOD baseline, and
# scheduler fetch targets can all be driven from the same scenario source.

def derive_country_context(focused: "Scenario") -> dict:
    """Derive per-country context lists from a focused Scenario.

    Returns a dict with:
      - core_theater: focused.core_country (Optional[str], ADR-009)
      - effective_cores: list of countries that act as scoring cores.
        When core_country is set, this is [core_country].
        When core_country is null (dual-core, e.g. middle_east), this is
        the sorted list of PRINCIPAL_BELLIGERENT participants with weight >= 0.9.
      - correlate_targets: participants with non-adversary role, excluding
        core and effective_cores
      - adversary_states: participants with role=ADVERSARY
      - strategic_theaters: all participant countries (superset)
    """
    core = focused.core_country
    parts = focused.participants
    adversaries = [cc for cc, p in parts.items() if p.role == Role.ADVERSARY]

    # ADR-009 extension: when core_country is null, derive effective
    # cores from principal_belligerent participants (weight >= 0.9).
    if core is None:
        effective_cores = sorted(
            cc for cc, p in parts.items()
            if p.role == Role.PRINCIPAL_BELLIGERENT and p.weight >= 0.9
        )
    else:
        effective_cores = [core]

    ec_set = set(effective_cores)
    correlates = [cc for cc, p in parts.items()
                  if p.role != Role.ADVERSARY and cc != core
                  and cc not in ec_set]
    return {
        "core_theater": core,
        "effective_cores": effective_cores,
        "correlate_targets": sorted(correlates),
        "adversary_states": sorted(adversaries),
        "strategic_theaters": sorted(parts.keys()),
    }


def derive_global_fetch_targets() -> dict:
    """Union of all scorable scenarios' participants, for global fetch targets.

    Used by scheduler/HOD baseline/situation.py where we want to cover every
    country any enabled scenario cares about, not just the focused one.
    """
    all_participants: set[str] = set()
    all_adversaries: set[str] = set()
    for sc in scenario_store.scorable():
        all_participants |= set(sc.participants.keys())
        all_adversaries |= {cc for cc, p in sc.participants.items()
                            if p.role == Role.ADVERSARY}
    return {
        "all_participant_countries": sorted(all_participants),
        "all_adversary_countries": sorted(all_adversaries),
    }
