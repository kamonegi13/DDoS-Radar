"""radar.scenarios -- Scenario data model, loader, and validator.

Implements the scenario-centric architecture defined in
docs/design/scenario-refactor.md (Phase 1).

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
        }


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
        self._loaded = False

    def load(self, geo_data: dict) -> None:
        layer1 = load_layer1(geo_data)
        merged = load_layer2(layer1)
        self._scenarios = merged
        self._loaded = True

        scorable = [s for s in merged.values() if s.is_scorable]
        log.info(
            "[Scenarios] Store ready: %d total, %d scorable",
            len(merged), len(scorable),
        )

    def get(self, scenario_id: str) -> Optional[Scenario]:
        return self._scenarios.get(scenario_id)

    def all(self) -> dict[str, Scenario]:
        return dict(self._scenarios)

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
        from radar.config import GEO_DATA
        self.load(GEO_DATA)

    @property
    def loaded(self) -> bool:
        return self._loaded


scenario_store = ScenarioStore()
