"""LLM Feature Hub — single registry + runtime control plane (commit G).

Background
----------
LLM-driven features in DDoS-Radar accumulated organically and ended up
controlled through 8+ independent env flags (LLM_ENABLED,
LLM_AUTO_JUDGE_SHADOW, LLM_AUTO_JUDGE_RECHECK,
V2_ATTACK_MODE_LLM_AUGMENT_ENABLED, G3B_LLM_ENABLED, G3B_SHADOW_ENABLED,
LLM_TRIAGE_NARRATIVE_ENABLED, …) with inconsistent defaults and no UI
surface to inspect them collectively. Operators had to edit config.env
and restart Docker just to flip a narrative-only feature.

This module is the structural fix:

  1. Registry — every LLM feature is declared here once, with tier,
     description, primary env flag, optional shadow flag, default
     state, and NP7 concern marker.

  2. Resolution — `is_enabled(key)` and `is_shadow(key)` honor (in
     order):
       a. Global kill switch (LLM_FEATURE_KILL_SWITCH env or DB row)
       b. Per-feature DB override (set via API by an admin/analyst)
       c. Env flag value
       d. Default state declared in the registry

  3. Persistence — DB tables `llm_feature_state` (current per-feature
     state) and `llm_feature_state_history` (append-only audit trail)
     are populated by the API. Migration v31 creates them.

  4. Audit — every state change writes a history row with actor +
     reason. NP6 transparency satisfied without operator action.

NP integrity
------------
NP1 — kill switch is a single API call (or DB row) that drops every
      feature to OFF immediately. The caller's `is_enabled` returns
      False without a re-restart.
NP3 — every helper is fault-tolerant. DB query failure → falls back
      to env / default. No raise on the hot path.
NP6 — feature_state_history is append-only; every flip records
      old_state, new_state, changed_by, reason. Pair with the API
      audit endpoint (commit H) for full forensic readout.
NP7 — features marked np7_concern=True (G.3b cluster annotation,
      attack_mode augmentation when it nudges confidence) get an
      extra Wizard-style confirm in the UI. Default state is shadow
      regardless of operator preference.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

log = logging.getLogger("radar.llm_features")


class FeatureTier(str, Enum):
    CORE      = "core"        # T0: load-bearing, kill-switch only
    AUGMENT   = "augment"     # T1: decision-augmenting (auto-judge, attack_mode)
    NARRATIVE = "narrative"   # T2: display-only (triage narrative, self-explanation)
    DISCOVERY = "discovery"   # T3: structure-suggesting (G.3b, future scenario discoverers)


class FeatureState(str, Enum):
    OFF         = "off"          # feature inert
    SHADOW      = "shadow"       # runs but does not apply / does not surface
    SHADOW_DUAL = "shadow_dual"  # Phase 9.2: legacy runs AND v10 candidate
                                 # is invoked in parallel for A/B logging.
                                 # Doubles cost during the measurement window
                                 # but is the only way to get true v10
                                 # schema compliance + reproducibility data.
    ON          = "on"           # fully active


@dataclass(frozen=True)
class LLMFeature:
    """Declarative description of one LLM-driven capability."""
    key: str
    tier: FeatureTier
    name: str
    description: str
    env_var: str
    shadow_env_var: Optional[str]
    default_state: FeatureState
    np7_concern: bool
    requires_admin: bool
    supports_shadow: bool

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "tier": self.tier.value,
            "name": self.name,
            "description": self.description,
            "env_var": self.env_var,
            "shadow_env_var": self.shadow_env_var,
            "default_state": self.default_state.value,
            "np7_concern": self.np7_concern,
            "requires_admin": self.requires_admin,
            "supports_shadow": self.supports_shadow,
        }


# ── Registry ─────────────────────────────────────────────────────────────────

# IMPORTANT: changing key here is a breaking change — DB rows in
# llm_feature_state are keyed on this string. Add new features by
# appending; rename via migration only.

LLM_FEATURES: tuple[LLMFeature, ...] = (
    LLMFeature(
        key="sensor_intel_extraction",
        tier=FeatureTier.CORE,
        name="Sensor LLM intel extraction",
        description=(
            "Parses raw OSINT (RSS, Telegram, hacktivist feeds) into "
            "structured intel via LLM. Foundation of the entire "
            "intel pipeline — disabling this means zero new intel "
            "items."
        ),
        env_var="LLM_ENABLED",
        shadow_env_var=None,
        default_state=FeatureState.ON,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=False,
    ),
    LLMFeature(
        key="auto_judge_recheck",
        tier=FeatureTier.AUGMENT,
        name="Auto-judge LLM recheck",
        description=(
            "When the deterministic auto-judge classifier returns "
            "'pending' (ambiguous middle band), the LLM re-evaluates "
            "with full Layer 1 corroborator context. Without this, "
            "ambiguous items wait for human review even when "
            "corroborators clearly resolve them."
        ),
        env_var="LLM_AUTO_JUDGE_RECHECK",
        shadow_env_var="LLM_AUTO_JUDGE_SHADOW",
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=True,
    ),
    LLMFeature(
        key="attack_mode_augment",
        tier=FeatureTier.AUGMENT,
        name="Attack-mode LLM augmentation",
        description=(
            "Adds a narrative + ±0.10 confidence nudge to ATTACK_MODE "
            "conclusions (rule remains authoritative for state). "
            "Helps analysts read the conclusion's reasoning without "
            "drilling into the rationale matrix."
        ),
        env_var="V2_ATTACK_MODE_LLM_AUGMENT_ENABLED",
        shadow_env_var=None,
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=False,
    ),
    LLMFeature(
        key="triage_narrative",
        tier=FeatureTier.NARRATIVE,
        name="Triage natural-language narrative",
        description=(
            "Generates plain-language sentences for the TRIAGE bar "
            "items, replacing the deterministic template version. "
            "Falls back to template on LLM failure (NP3). "
            "Display-only — does NOT influence ranking or scoring."
        ),
        env_var="LLM_TRIAGE_NARRATIVE_ENABLED",
        shadow_env_var=None,
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=False,  # analyst-toggleable (display preference)
        supports_shadow=False,
    ),
    LLMFeature(
        key="g3b_cluster_annotator",
        tier=FeatureTier.DISCOVERY,
        name="G.3b discovery cluster annotation",
        description=(
            "LLM annotates DBSCAN-discovered country clusters with "
            "scenario-name suggestions. NP7 — never auto-creates "
            "scenarios; analyst confirms via Wizard. Hardened with "
            "5-failure circuit breaker, daily call cap, and prompt "
            "sha256 audit."
        ),
        env_var="G3B_LLM_ENABLED",
        shadow_env_var="G3B_SHADOW_ENABLED",
        default_state=FeatureState.OFF,
        np7_concern=True,
        requires_admin=True,
        supports_shadow=True,
    ),
    # ── Phase 8 (LLM survey v10) — model routing ─────────────────────────
    # One feature per use-case bucket so analysts can roll out the v10
    # 5-model stack in the survey-recommended order:
    #   verdict → sensor → ETL → conclusion
    # SHADOW state records what the v10 router would have picked without
    # actually switching models; ON applies the new routing live.
    LLMFeature(
        key="model_routing_verdict",
        tier=FeatureTier.AUGMENT,
        name="Model routing v10 — verdict layer",
        description=(
            "Routes verdict-layer LLM calls (intel auto-judge, queue) to "
            "gemma4:26b primary + mistral-small3.2:24b secondary with "
            "deterministic sampling (temp=0, top_k=1, seed=42). SHADOW "
            "records both v1 and v2 model choices for A/B; ON applies "
            "v2 routing only. First in the survey-recommended rollout "
            "order because verdict re-runs are easiest to verify."
        ),
        env_var="LLM_ROUTING_VERDICT_ENABLED",
        shadow_env_var="LLM_ROUTING_VERDICT_SHADOW",
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=True,
    ),
    LLMFeature(
        key="model_routing_sensor",
        tier=FeatureTier.AUGMENT,
        name="Model routing v10 — sensor extraction",
        description=(
            "Routes sensor-layer OSINT extraction calls to "
            "mistral-small3.2:24b primary + gemma4:26b secondary "
            "(20+ language 1st-class, native function calling). SHADOW "
            "records v2 choice without switching; ON applies v2."
        ),
        env_var="LLM_ROUTING_SENSOR_ENABLED",
        shadow_env_var="LLM_ROUTING_SENSOR_SHADOW",
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=True,
    ),
    LLMFeature(
        key="model_routing_etl",
        tier=FeatureTier.AUGMENT,
        name="Model routing v10 — ETL / discovery layer",
        description=(
            "Routes ETL batch + g3b cluster annotation to gemma4:31b "
            "primary + gpt-oss-safeguard:20b on-demand 2nd opinion "
            "with thinking enabled (<|think|> / Reasoning: high). "
            "SHADOW records v2 choice; ON applies v2."
        ),
        env_var="LLM_ROUTING_ETL_ENABLED",
        shadow_env_var="LLM_ROUTING_ETL_SHADOW",
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=True,
    ),
    LLMFeature(
        key="model_routing_conclusion",
        tier=FeatureTier.NARRATIVE,
        name="Model routing v10 — conclusion + narrative",
        description=(
            "Routes conclusion narrative + display narrative to "
            "gemma4:31b (conclusion) and gemma4:26b (display narrative). "
            "Last in the rollout order because conclusion regressions "
            "are highest visibility."
        ),
        env_var="LLM_ROUTING_CONCLUSION_ENABLED",
        shadow_env_var="LLM_ROUTING_CONCLUSION_SHADOW",
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=True,
    ),
    # ── Phase 8 — embedding-driven dedupe ────────────────────────────────
    # Multilingual OSINT collection produces near-duplicate articles
    # across sources / translations / republications. The radar.llm_embedding
    # module gates on this key — when OFF every embed_text call returns
    # None, so sensors must fall back to substring or hash dedupe.
    LLMFeature(
        key="embedding_dedupe",
        tier=FeatureTier.AUGMENT,
        name="Embedding-based OSINT dedupe",
        description=(
            "Encodes incoming OSINT text via granite-embedding:278m "
            "(IBM, Apache 2.0, 12 languages) so the sensor pipeline can "
            "drop near-duplicate items before they hit the LLM extraction "
            "stage. Russian-language quality is degraded (model card "
            "doesn't list ru as 1st-class); operators must measure during "
            "Phase 1 shadow before promoting to ON."
        ),
        env_var="EMBEDDING_DEDUPE_ENABLED",
        shadow_env_var="EMBEDDING_DEDUPE_SHADOW",
        default_state=FeatureState.OFF,
        np7_concern=False,
        requires_admin=True,
        supports_shadow=True,
    ),
)


_BY_KEY: dict[str, LLMFeature] = {f.key: f for f in LLM_FEATURES}


def feature(key: str) -> Optional[LLMFeature]:
    return _BY_KEY.get(key)


def all_features() -> tuple[LLMFeature, ...]:
    return LLM_FEATURES


# ── Resolution helpers ──────────────────────────────────────────────────────


_ENV_TRUE = {"1", "true", "yes", "on"}


def _env_to_state(value: Optional[str], shadow_value: Optional[str]) -> FeatureState:
    """Map (env_var, shadow_env_var) values to a FeatureState."""
    is_on = (value or "").strip().lower() in _ENV_TRUE
    is_shadow = (shadow_value or "").strip().lower() in _ENV_TRUE
    if is_on:
        return FeatureState.ON
    if is_shadow:
        return FeatureState.SHADOW
    return FeatureState.OFF


def _kill_switch_active() -> bool:
    """Global kill switch — if true, every feature is OFF regardless
    of per-feature state. Checked first by is_enabled / is_shadow.

    Two surfaces:
      LLM_FEATURE_KILL_SWITCH env (operator pre-deployment)
      llm_feature_state row with feature_key='__kill_switch__' and
        state='on' (UI-driven runtime kill).
    """
    if os.getenv("LLM_FEATURE_KILL_SWITCH", "").strip().lower() in _ENV_TRUE:
        return True
    try:
        from radar.database import db
        row = db._get_conn().execute(  # noqa: SLF001
            "SELECT state FROM llm_feature_state "
            "WHERE feature_key='__kill_switch__'"
        ).fetchone()
        if row and (row[0] or "").lower() == "on":
            return True
    except Exception as exc:
        log.debug("kill_switch DB check failed: %s", exc)
    return False


def _read_db_state(key: str) -> Optional[FeatureState]:
    """Read the persisted UI-overridden state for a feature, if any.
    Returns None when no override exists or DB is unavailable."""
    try:
        from radar.database import db
        row = db._get_conn().execute(  # noqa: SLF001
            "SELECT state FROM llm_feature_state WHERE feature_key=?",
            (key,),
        ).fetchone()
    except Exception as exc:
        log.debug("read_db_state(%s) failed: %s", key, exc)
        return None
    if not row:
        return None
    try:
        return FeatureState(row[0])
    except ValueError:
        return None


def resolve_state(key: str) -> FeatureState:
    """Resolve a feature's effective state through the priority chain:
        1. Global kill switch → OFF for all
        2. Per-feature DB override
        3. env_var / shadow_env_var
        4. Registry default

    NP3: any DB failure falls through to env+default; never raises.
    """
    f = _BY_KEY.get(key)
    if f is None:
        # Unknown feature — caller bug, but be NP3 about it.
        return FeatureState.OFF
    if _kill_switch_active():
        return FeatureState.OFF
    db_state = _read_db_state(key)
    if db_state is not None:
        return db_state
    env_val = os.getenv(f.env_var)
    shadow_val = os.getenv(f.shadow_env_var) if f.shadow_env_var else None
    if env_val is None and shadow_val is None:
        return f.default_state
    return _env_to_state(env_val, shadow_val)


def is_enabled(key: str) -> bool:
    """True iff the feature is currently fully active (ON).
    Shadow mode returns False here — callers checking 'should I apply'
    must use is_enabled; callers writing to ledgers without applying
    use is_shadow."""
    return resolve_state(key) == FeatureState.ON


def is_shadow(key: str) -> bool:
    """True iff the feature is in shadow mode (record but do not apply)."""
    return resolve_state(key) == FeatureState.SHADOW


def is_active(key: str) -> bool:
    """True iff the feature is doing anything (ON or SHADOW). Convenience
    alias for callers that want to know whether they should bother
    constructing a payload at all."""
    return resolve_state(key) in (FeatureState.ON, FeatureState.SHADOW)


# ── Persistence (used by API endpoints in commit H) ─────────────────────────


def set_state(key: str, state: FeatureState, *, by: str,
              reason: Optional[str] = None) -> bool:
    """Persist a runtime state override and append to audit history.
    Returns True on success, False on validation/DB error.

    NP6: every transition records old_state, new_state, changed_by,
    reason in llm_feature_state_history. Caller is responsible for
    auth (commit H endpoints check requires_admin)."""
    if key != "__kill_switch__" and key not in _BY_KEY:
        log.warning("set_state: unknown feature key %s", key)
        return False
    if not isinstance(state, FeatureState):
        try:
            state = FeatureState(state)
        except ValueError:
            log.warning("set_state: invalid state %r", state)
            return False
    f = _BY_KEY.get(key)
    if f is not None and state == FeatureState.SHADOW and not f.supports_shadow:
        log.warning("set_state: feature %s does not support shadow", key)
        return False
    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            old_row = conn.execute(
                "SELECT state FROM llm_feature_state WHERE feature_key=?",
                (key,),
            ).fetchone()
            old_state = old_row[0] if old_row else None
            now = time.time()
            conn.execute(
                "INSERT INTO llm_feature_state "
                "(feature_key, state, set_at, set_by, reason) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(feature_key) DO UPDATE SET "
                "  state=excluded.state, set_at=excluded.set_at, "
                "  set_by=excluded.set_by, reason=excluded.reason",
                (key, state.value, now, by, reason),
            )
            conn.execute(
                "INSERT INTO llm_feature_state_history "
                "(feature_key, old_state, new_state, changed_at, "
                " changed_by, reason) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key, old_state, state.value, now, by, reason),
            )
        return True
    except Exception as exc:
        log.warning("set_state(%s, %s) failed: %s", key, state, exc)
        return False


def clear_override(key: str, *, by: str,
                    reason: Optional[str] = None) -> bool:
    """Drop the UI override for a feature so it reverts to env+default.

    Records 'auto' (the conventional UI label) in history.
    """
    if key != "__kill_switch__" and key not in _BY_KEY:
        return False
    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            old_row = conn.execute(
                "SELECT state FROM llm_feature_state WHERE feature_key=?",
                (key,),
            ).fetchone()
            old_state = old_row[0] if old_row else None
            if not old_row:
                return True  # already on env+default
            conn.execute(
                "DELETE FROM llm_feature_state WHERE feature_key=?",
                (key,),
            )
            conn.execute(
                "INSERT INTO llm_feature_state_history "
                "(feature_key, old_state, new_state, changed_at, "
                " changed_by, reason) "
                "VALUES (?, ?, 'auto', ?, ?, ?)",
                (key, old_state, time.time(), by, reason),
            )
        return True
    except Exception as exc:
        log.warning("clear_override(%s) failed: %s", key, exc)
        return False


def list_states() -> list[dict]:
    """Return the full feature catalog with current effective state +
    metadata. Used by the Feature Hub UI."""
    out = []
    for f in LLM_FEATURES:
        eff = resolve_state(f.key)
        db_state = _read_db_state(f.key)
        env_val = os.getenv(f.env_var)
        env_shadow = os.getenv(f.shadow_env_var) if f.shadow_env_var else None
        if db_state is not None:
            source = "ui_override"
        elif env_val is not None or env_shadow is not None:
            source = "env"
        else:
            source = "default"
        out.append({
            **f.to_dict(),
            "current_state": eff.value,
            "source": source,
            "kill_switch_active": _kill_switch_active(),
        })
    return out


def list_history(*, hours: int = 720, limit: int = 200) -> list[dict]:
    """Return recent state-change history rows. NP6 audit trail."""
    cutoff = time.time() - hours * 3600
    try:
        from radar.database import db
        rows = db._get_conn().execute(  # noqa: SLF001
            "SELECT id, feature_key, old_state, new_state, changed_at, "
            "       changed_by, reason "
            "FROM llm_feature_state_history "
            "WHERE changed_at >= ? "
            "ORDER BY changed_at DESC LIMIT ?",
            (cutoff, limit),
        ).fetchall()
    except Exception as exc:
        log.debug("list_history failed: %s", exc)
        return []
    return [
        {
            "id": r[0], "feature_key": r[1],
            "old_state": r[2], "new_state": r[3],
            "changed_at": r[4], "changed_by": r[5], "reason": r[6],
        }
        for r in rows
    ]


__all__ = [
    "FeatureTier",
    "FeatureState",
    "LLMFeature",
    "LLM_FEATURES",
    "feature",
    "all_features",
    "resolve_state",
    "is_enabled",
    "is_shadow",
    "is_active",
    "set_state",
    "clear_override",
    "list_states",
    "list_history",
]
