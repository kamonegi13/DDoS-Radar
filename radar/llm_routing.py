"""LLM Routing — use-case based model selection for the 5-model stack.

Phase 8 (LLM survey v10) — replaces the single-model ``LLM_MODEL`` env var
with use-case-aware routing per the 2026-05 LLM survey:

  - ``mistral-small3.2:24b``    sensor primary, verdict secondary
  - ``gemma4:26b``              sensor secondary, verdict primary, narrative
  - ``gemma4:31b``              conclusion + ETL/discovery primary
  - ``gpt-oss-safeguard:20b``   ETL 2nd opinion (on-demand)
  - ``granite-embedding:278m``  embedding (radar.llm_embedding, separate API)

Three-layer configuration
-------------------------
Resolution chain (highest precedence first):

  1. **DB override** — ``llm_routing_override`` table, set via the analyst
     API (``/api/v2/llm_routing_overrides``). Mirrors the Feature Hub
     pattern: every override row is paired with an audit-history entry.
  2. **Env vars** — operator-set per-use-case knobs that survive image
     redeploys without DB writes. Pattern:

         LLM_ROUTING_<USECASE>_PRIMARY_MODEL    (e.g. gemma4:31b)
         LLM_ROUTING_<USECASE>_PRIMARY_TEMP     (float)
         LLM_ROUTING_<USECASE>_PRIMARY_TOP_P
         LLM_ROUTING_<USECASE>_PRIMARY_TOP_K
         LLM_ROUTING_<USECASE>_PRIMARY_SEED
         LLM_ROUTING_<USECASE>_PRIMARY_THINK    (true|false; toggles <|think|>)

     <USECASE> is one of: SENSOR / VERDICT / CONCLUSION / DISCOVERY / NARRATIVE.

  3. **Code defaults** — the v10 survey-recommended ``ModelChoice`` objects
     in ``_DEFAULT_PRIMARY`` / ``_DEFAULT_SECONDARY``. Final fallback so
     the engine has *something* to call even with empty config.

The chain is applied per parameter (model, temperature, top_p, …) so an
operator can override only the model and keep the survey's sampling, or
keep the model and tune sampling, etc.

Feature Hub gating per use-case key (registered in ``radar.llm_features``):

    +------------------+-----------------------------+
    | UseCase          | Feature Hub key             |
    +==================+=============================+
    | SENSOR_EXTRACT   | model_routing_sensor        |
    | VERDICT          | model_routing_verdict       |
    | CONCLUSION       | model_routing_conclusion    |
    | DISCOVERY        | model_routing_etl           |
    | NARRATIVE        | model_routing_conclusion    |
    +------------------+-----------------------------+

State semantics:
  - **OFF**     → returns the legacy ``LLM_MODEL`` choice (backward compat)
  - **SHADOW**  → returns the legacy choice but records the v2 choice in
                  ``llm_call_log.shadow_model_choice`` so analysts can
                  compare what would have been picked
  - **ON**      → returns the v2 choice (with overrides applied) and
                  records nothing in the shadow field

NP3 fault tolerance: any error in resolution falls back to legacy.
NP6 disclosure: the chosen model + sampling are written to ``llm_call_log``
                (model column) and the ``thinking_trace`` column captures
                the reasoning text when ``<|think|>`` / ``Reasoning: high``
                produced any. ``llm_routing_override_history`` is an
                append-only audit ledger of analyst-driven changes.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from enum import Enum
from typing import Optional

log = logging.getLogger("radar.llm_routing")


class UseCase(str, Enum):
    """Routing buckets per the LLM survey v10 stack."""
    SENSOR_EXTRACT = "sensor_extract"   # OSINT short-text → JSON
    VERDICT        = "verdict"          # auto-judge, queue verdict (deterministic)
    CONCLUSION     = "conclusion"       # narrative / attack_mode augment
    DISCOVERY      = "discovery"        # ETL batch / g3b cluster annotation
    NARRATIVE      = "narrative"        # display-only triage narrative


@dataclass(frozen=True)
class ModelChoice:
    """Resolved (model, sampling, system_prefix) tuple for one call."""
    model: str
    temperature: float
    top_p: float = 1.0
    top_k: int = 0
    seed: Optional[int] = None
    repeat_penalty: float = 1.0
    num_predict: int = 512
    system_prefix: str = ""              # prepended to caller's system prompt
    thinking_enabled: bool = False        # whether to capture thinking_trace
    use_case: Optional[UseCase] = None    # back-reference for logging

    def merge_system(self, system: str) -> str:
        """Return the effective system prompt after prepending prefix."""
        if not self.system_prefix:
            return system
        if not system:
            return self.system_prefix
        return f"{self.system_prefix}\n\n{system}"


# ── Routing table ──────────────────────────────────────────────────────────
#
# The "primary" choice for each use case. Secondary choices live in
# ``_FALLBACK_CHAIN`` and are tried in order if the primary is not pulled
# locally (``llm_available_for_model`` returns False).
#
# Sampling defaults follow the survey v10 recommendations:
#   - Mistral Small 3.2:  temperature=0.1 (sensor) or 0 (verdict deterministic)
#   - Gemma 4:           temperature=1.0, top_p=0.95, top_k=64 (think mode)
#                        or temperature=0, top_k=1 (verdict)
#   - gpt-oss-safeguard: ``Reasoning: high`` system prompt token

_VERDICT_GEMMA = ModelChoice(
    model="gemma4:26b",
    temperature=0.0,
    top_k=1,
    top_p=1.0,
    seed=42,
    repeat_penalty=1.0,
    num_predict=128,
    system_prefix="",                 # thinking OFF — no <|think|> token
    thinking_enabled=False,
    use_case=UseCase.VERDICT,
)

_VERDICT_MISTRAL = ModelChoice(
    model="mistral-small3.2:24b",
    temperature=0.0,
    top_k=1,
    top_p=1.0,
    seed=42,
    num_predict=128,
    system_prefix="",
    thinking_enabled=False,
    use_case=UseCase.VERDICT,
)

_SENSOR_MISTRAL = ModelChoice(
    model="mistral-small3.2:24b",
    temperature=0.1,
    top_p=1.0,
    top_k=0,
    seed=None,
    num_predict=512,
    system_prefix="",
    thinking_enabled=False,
    use_case=UseCase.SENSOR_EXTRACT,
)

_SENSOR_GEMMA = ModelChoice(
    model="gemma4:26b",
    temperature=0.1,
    top_p=0.95,
    top_k=64,
    seed=None,
    num_predict=512,
    system_prefix="",                 # sensor extract: thinking OFF
    thinking_enabled=False,
    use_case=UseCase.SENSOR_EXTRACT,
)

_CONCLUSION_GEMMA31 = ModelChoice(
    model="gemma4:31b",
    temperature=1.0,
    top_p=0.95,
    top_k=64,
    seed=None,
    num_predict=1024,
    system_prefix="<|think|>",        # narrative: thinking ON for reasoning
    thinking_enabled=True,
    use_case=UseCase.CONCLUSION,
)

_CONCLUSION_GEMMA26 = ModelChoice(
    model="gemma4:26b",
    temperature=1.0,
    top_p=0.95,
    top_k=64,
    seed=None,
    num_predict=1024,
    system_prefix="",
    thinking_enabled=False,
    use_case=UseCase.CONCLUSION,
)

_DISCOVERY_GEMMA31 = ModelChoice(
    model="gemma4:31b",
    temperature=0.5,
    top_p=0.95,
    top_k=64,
    seed=None,
    num_predict=1024,
    system_prefix="<|think|>",
    thinking_enabled=True,
    use_case=UseCase.DISCOVERY,
)

_DISCOVERY_GPT_OSS = ModelChoice(
    model="gpt-oss-safeguard:20b",
    temperature=0.5,
    top_p=1.0,
    top_k=0,
    seed=None,
    num_predict=1024,
    system_prefix="Reasoning: high",  # gpt-oss-safeguard policy reasoning
    thinking_enabled=True,
    use_case=UseCase.DISCOVERY,
)

_NARRATIVE_GEMMA26 = ModelChoice(
    model="gemma4:26b",
    temperature=0.7,
    top_p=0.95,
    top_k=64,
    seed=None,
    num_predict=512,
    system_prefix="",
    thinking_enabled=False,
    use_case=UseCase.NARRATIVE,
)


# Primary + fallback chain per use case (Layer 1 code defaults). The
# first model whose tag is pulled locally wins. If none are available,
# falls through to the chain primary (the HTTP call surfaces the error).
_FALLBACK_CHAIN: dict[UseCase, tuple[ModelChoice, ...]] = {
    UseCase.SENSOR_EXTRACT: (_SENSOR_MISTRAL, _SENSOR_GEMMA),
    UseCase.VERDICT:        (_VERDICT_GEMMA, _VERDICT_MISTRAL),
    UseCase.CONCLUSION:     (_CONCLUSION_GEMMA31, _CONCLUSION_GEMMA26),
    UseCase.DISCOVERY:      (_DISCOVERY_GEMMA31, _DISCOVERY_GPT_OSS),
    UseCase.NARRATIVE:      (_NARRATIVE_GEMMA26,),
}


# Env-var prefix per use case. Layer 2 lookups are
#   ``LLM_ROUTING_{prefix}_PRIMARY_*``
#   ``LLM_ROUTING_{prefix}_SECONDARY_*``
_USECASE_ENV_PREFIX: dict[UseCase, str] = {
    UseCase.SENSOR_EXTRACT: "SENSOR",
    UseCase.VERDICT:        "VERDICT",
    UseCase.CONCLUSION:     "CONCLUSION",
    UseCase.DISCOVERY:      "DISCOVERY",
    UseCase.NARRATIVE:      "NARRATIVE",
}


# Map use case → Feature Hub key (registered in radar.llm_features)
_USE_CASE_FEATURE_KEY: dict[UseCase, str] = {
    UseCase.SENSOR_EXTRACT: "model_routing_sensor",
    UseCase.VERDICT:        "model_routing_verdict",
    UseCase.CONCLUSION:     "model_routing_conclusion",
    UseCase.DISCOVERY:      "model_routing_etl",
    UseCase.NARRATIVE:      "model_routing_conclusion",
}


# ── Layer 2: env-var overrides ─────────────────────────────────────────────


def _env_str(name: str) -> Optional[str]:
    """Read an env var and strip whitespace; treat empty as unset."""
    import os
    raw = os.getenv(name)
    if raw is None:
        return None
    raw = raw.strip()
    return raw or None


def _env_float(name: str) -> Optional[float]:
    raw = _env_str(name)
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        log.warning("env %s=%r is not a float; ignoring", name, raw)
        return None


def _env_int(name: str) -> Optional[int]:
    raw = _env_str(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        log.warning("env %s=%r is not an int; ignoring", name, raw)
        return None


def _env_bool(name: str) -> Optional[bool]:
    raw = _env_str(name)
    if raw is None:
        return None
    return raw.lower() in ("1", "true", "yes", "on")


def _apply_env_layer(use_case: UseCase, slot: str, base: ModelChoice) -> ModelChoice:
    """Apply Layer 2 (env-var) overrides on top of a Layer 1 base choice.

    ``slot`` is "PRIMARY" or "SECONDARY" — both share the same env-var
    structure so an operator can override the secondary independently.
    """
    prefix = _USECASE_ENV_PREFIX.get(use_case)
    if not prefix:
        return base
    p = f"LLM_ROUTING_{prefix}_{slot}"

    model = _env_str(f"{p}_MODEL") or base.model
    temperature = _env_float(f"{p}_TEMP")
    top_p = _env_float(f"{p}_TOP_P")
    top_k = _env_int(f"{p}_TOP_K")
    seed = _env_int(f"{p}_SEED")
    num_predict = _env_int(f"{p}_NUM_PREDICT")
    think = _env_bool(f"{p}_THINK")
    repeat_penalty = _env_float(f"{p}_REPEAT_PENALTY")

    # System prefix is derived from `think` + model family. Operators rarely
    # need to override the literal token, so we just toggle:
    #   gemma4*: <|think|>
    #   gpt-oss*: Reasoning: high
    if think is True and model.startswith("gemma4"):
        system_prefix = "<|think|>"
        thinking_enabled = True
    elif think is True and model.startswith("gpt-oss"):
        system_prefix = "Reasoning: high"
        thinking_enabled = True
    elif think is False:
        system_prefix = ""
        thinking_enabled = False
    else:
        # Inherit from base choice when the model didn't change; otherwise
        # default to thinking OFF so verdict-style determinism is preserved.
        if model == base.model:
            system_prefix = base.system_prefix
            thinking_enabled = base.thinking_enabled
        else:
            system_prefix = ""
            thinking_enabled = False

    return ModelChoice(
        model=model,
        temperature=temperature if temperature is not None else base.temperature,
        top_p=top_p if top_p is not None else base.top_p,
        top_k=top_k if top_k is not None else base.top_k,
        seed=seed if seed is not None else base.seed,
        repeat_penalty=(
            repeat_penalty if repeat_penalty is not None else base.repeat_penalty
        ),
        num_predict=num_predict if num_predict is not None else base.num_predict,
        system_prefix=system_prefix,
        thinking_enabled=thinking_enabled,
        use_case=use_case,
    )


# ── Layer 3: DB-backed analyst override ───────────────────────────────────


def _apply_db_layer(use_case: UseCase, slot: str, base: ModelChoice) -> ModelChoice:
    """Read ``llm_routing_override`` for this (use_case, slot) and patch
    ``base`` with any non-NULL columns. Returns ``base`` unchanged on any
    DB error (NP3)."""
    try:
        from radar.database import db
        row = db._get_conn().execute(  # noqa: SLF001
            "SELECT model, temperature, top_p, top_k, seed, "
            "       num_predict, repeat_penalty, thinking_enabled "
            "FROM llm_routing_override "
            "WHERE use_case=? AND slot=?",
            (use_case.value, slot.lower()),
        ).fetchone()
    except Exception as exc:
        log.debug("db_override read failed for %s/%s: %s",
                  use_case.value, slot, exc)
        return base
    if not row:
        return base

    model = row[0] or base.model
    temperature = row[1] if row[1] is not None else base.temperature
    top_p = row[2] if row[2] is not None else base.top_p
    top_k = row[3] if row[3] is not None else base.top_k
    seed = row[4] if row[4] is not None else base.seed
    num_predict = row[5] if row[5] is not None else base.num_predict
    repeat_penalty = row[6] if row[6] is not None else base.repeat_penalty
    db_thinking = row[7]

    if db_thinking is None:
        thinking_enabled = base.thinking_enabled
        system_prefix = base.system_prefix if model == base.model else ""
    elif bool(db_thinking) and model.startswith("gemma4"):
        thinking_enabled = True
        system_prefix = "<|think|>"
    elif bool(db_thinking) and model.startswith("gpt-oss"):
        thinking_enabled = True
        system_prefix = "Reasoning: high"
    else:
        thinking_enabled = False
        system_prefix = ""

    return ModelChoice(
        model=model,
        temperature=temperature,
        top_p=top_p,
        top_k=top_k,
        seed=seed,
        num_predict=num_predict,
        repeat_penalty=repeat_penalty,
        system_prefix=system_prefix,
        thinking_enabled=thinking_enabled,
        use_case=use_case,
    )


def _resolve_layered(use_case: UseCase, slot: str, base: ModelChoice) -> ModelChoice:
    """Apply Layer 2 (env) then Layer 3 (DB) on top of Layer 1 base.
    Order matters: DB wins because the analyst-set override is the most
    specific signal."""
    layered = _apply_env_layer(use_case, slot, base)
    layered = _apply_db_layer(use_case, slot, layered)
    return layered


def configured_chain(use_case: UseCase) -> tuple[ModelChoice, ...]:
    """Public helper: return the (PRIMARY, SECONDARY) chain after Layer 2/3
    overrides are applied. Used by the preflight endpoint and admin UI to
    show analysts the *effective* routing without hitting an LLM."""
    base_chain = _FALLBACK_CHAIN.get(use_case, ())
    out: list[ModelChoice] = []
    slot_names = ("PRIMARY", "SECONDARY")
    for i, base in enumerate(base_chain):
        slot = slot_names[i] if i < len(slot_names) else f"FALLBACK_{i}"
        out.append(_resolve_layered(use_case, slot, base))
    return tuple(out)


# ── Legacy fallback ────────────────────────────────────────────────────────


def _legacy_choice(use_case: Optional[UseCase] = None) -> ModelChoice:
    """Return the pre-Phase-8 single-model choice from ``LLM_MODEL`` env."""
    from radar.config import LLM_MODEL
    return ModelChoice(
        model=LLM_MODEL,
        temperature=0.1,
        top_p=1.0,
        top_k=0,
        seed=None,
        num_predict=512,
        system_prefix="",
        thinking_enabled=False,
        use_case=use_case,
    )


# ── Model availability cache ──────────────────────────────────────────────
#
# Avoid hammering /api/tags on every call — refresh at most once per
# ``_AVAIL_TTL_SEC``. Cleared on import so the first call always probes.

_AVAIL_TTL_SEC = 60.0
_avail_cache: dict[str, tuple[float, bool]] = {}


def _model_available(model: str) -> bool:
    """Best-effort check whether ``model`` is pulled locally on Ollama.

    Returns True when uncertain (fail-open) so a transient /api/tags hiccup
    cannot strand the routing layer. NP3.
    """
    import time
    now = time.time()
    cached = _avail_cache.get(model)
    if cached is not None and (now - cached[0]) < _AVAIL_TTL_SEC:
        return cached[1]
    try:
        import requests
        from radar.config import LLM_HOST, GLOBAL_PROXIES, SSL_VERIFY
        res = requests.get(
            f"{LLM_HOST}/api/tags",
            timeout=5,
            proxies=GLOBAL_PROXIES,
            verify=SSL_VERIFY,
        )
        if res.status_code != 200:
            _avail_cache[model] = (now, True)  # fail-open
            return True
        names = [m.get("name", "") for m in res.json().get("models", [])]
        ok = any(n == model or n.startswith(model.split(":")[0]) for n in names)
        _avail_cache[model] = (now, ok)
        return ok
    except Exception as exc:
        log.debug("model_available probe failed for %s: %s", model, exc)
        _avail_cache[model] = (now, True)  # fail-open on probe failure
        return True


def _resolve_v2_choice(use_case: UseCase) -> ModelChoice:
    """Walk the fallback chain (after Layer 2/3 overrides) and return the
    first available choice. Falls through to the chain's primary when none
    probe positive (the HTTP call itself will then surface a clean error)."""
    chain = configured_chain(use_case)
    if not chain:
        return _legacy_choice(use_case)
    for choice in chain:
        if _model_available(choice.model):
            return choice
    return chain[0]


# ── Public API ──────────────────────────────────────────────────────────


def feature_key_for(use_case: UseCase) -> str:
    """Return the Feature Hub key gating this use case."""
    return _USE_CASE_FEATURE_KEY.get(use_case, "")


@dataclass(frozen=True)
class RoutingResult:
    """Both the active choice (used to build the request) and the
    shadow choice (recorded but not executed)."""
    active: ModelChoice
    shadow_choice: Optional[str]   # model name v2 *would* have picked, when v1 active
    state: str                     # "off" | "shadow" | "on"


def choose_model(use_case: Optional[UseCase]) -> RoutingResult:
    """Resolve which model to actually call for ``use_case``.

    NP3 — never raises. On any failure returns the legacy choice with
    state='off'.
    """
    if use_case is None:
        return RoutingResult(
            active=_legacy_choice(None),
            shadow_choice=None,
            state="off",
        )

    # Resolve Feature Hub state for this use case.
    try:
        from radar.llm_features import resolve_state, FeatureState
        key = feature_key_for(use_case)
        state = resolve_state(key) if key else FeatureState.OFF
    except Exception as exc:
        log.debug("feature_hub resolve failed for %s: %s", use_case, exc)
        return RoutingResult(
            active=_legacy_choice(use_case),
            shadow_choice=None,
            state="off",
        )

    if state.value == "on":
        return RoutingResult(
            active=_resolve_v2_choice(use_case),
            shadow_choice=None,
            state="on",
        )
    if state.value == "shadow":
        # Run legacy but record what v2 would have picked.
        try:
            v2 = _resolve_v2_choice(use_case)
            return RoutingResult(
                active=replace(_legacy_choice(use_case), use_case=use_case),
                shadow_choice=v2.model,
                state="shadow",
            )
        except Exception as exc:
            log.debug("shadow resolve failed for %s: %s", use_case, exc)
            return RoutingResult(
                active=_legacy_choice(use_case),
                shadow_choice=None,
                state="shadow",
            )
    # OFF or unknown
    return RoutingResult(
        active=_legacy_choice(use_case),
        shadow_choice=None,
        state="off",
    )


# ── Override management API (used by the admin route) ─────────────────────


_VALID_SLOTS = ("primary", "secondary")


def _override_row_to_dict(row) -> dict:
    """Map a llm_routing_override row to a JSON-friendly dict."""
    if row is None:
        return {}
    return {
        "use_case": row[1], "slot": row[2],
        "model": row[3], "temperature": row[4],
        "top_p": row[5], "top_k": row[6], "seed": row[7],
        "num_predict": row[8], "repeat_penalty": row[9],
        "thinking_enabled": (
            None if row[10] is None else bool(row[10])
        ),
        "set_at": row[11], "set_by": row[12], "reason": row[13],
    }


def list_overrides() -> list[dict]:
    """Return the current llm_routing_override rows (one per (use_case, slot))."""
    try:
        from radar.database import db
        rows = db._get_conn().execute(  # noqa: SLF001
            "SELECT id, use_case, slot, model, temperature, top_p, top_k, "
            "       seed, num_predict, repeat_penalty, thinking_enabled, "
            "       set_at, set_by, reason "
            "FROM llm_routing_override ORDER BY use_case, slot"
        ).fetchall()
    except Exception as exc:
        log.debug("list_overrides failed: %s", exc)
        return []
    return [_override_row_to_dict(r) for r in rows]


_PATCH_FIELDS = (
    "model", "temperature", "top_p", "top_k", "seed",
    "num_predict", "repeat_penalty", "thinking_enabled",
)


def set_override(
    use_case: UseCase, slot: str, *, by: str,
    reason: Optional[str] = None,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    top_p: Optional[float] = None,
    top_k: Optional[int] = None,
    seed: Optional[int] = None,
    num_predict: Optional[int] = None,
    repeat_penalty: Optional[float] = None,
    thinking_enabled: Optional[bool] = None,
) -> bool:
    """Upsert a routing override + append an audit-history row.

    Any None field means "inherit from env / code default" — the resolver
    only patches non-NULL columns. Returns True on success, False on
    validation/DB error. NP6: every change is recorded.
    """
    import json
    import time

    if not isinstance(use_case, UseCase):
        try:
            use_case = UseCase(use_case)
        except ValueError:
            log.warning("set_override: invalid use_case %r", use_case)
            return False
    slot = (slot or "").strip().lower()
    if slot not in _VALID_SLOTS:
        log.warning("set_override: invalid slot %r", slot)
        return False

    new_payload: dict = {
        "model": model, "temperature": temperature,
        "top_p": top_p, "top_k": top_k, "seed": seed,
        "num_predict": num_predict, "repeat_penalty": repeat_penalty,
        "thinking_enabled": (
            None if thinking_enabled is None else bool(thinking_enabled)
        ),
    }

    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            old_row = conn.execute(
                "SELECT model, temperature, top_p, top_k, seed, "
                "       num_predict, repeat_penalty, thinking_enabled "
                "FROM llm_routing_override "
                "WHERE use_case=? AND slot=?",
                (use_case.value, slot),
            ).fetchone()
            old_payload = None
            if old_row:
                old_payload = {
                    "model": old_row[0], "temperature": old_row[1],
                    "top_p": old_row[2], "top_k": old_row[3],
                    "seed": old_row[4], "num_predict": old_row[5],
                    "repeat_penalty": old_row[6],
                    "thinking_enabled": (
                        None if old_row[7] is None else bool(old_row[7])
                    ),
                }
            now = time.time()
            ti_int = (
                None if thinking_enabled is None
                else (1 if thinking_enabled else 0)
            )
            conn.execute(
                "INSERT INTO llm_routing_override "
                "(use_case, slot, model, temperature, top_p, top_k, "
                " seed, num_predict, repeat_penalty, thinking_enabled, "
                " set_at, set_by, reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(use_case, slot) DO UPDATE SET "
                "  model=excluded.model, temperature=excluded.temperature, "
                "  top_p=excluded.top_p, top_k=excluded.top_k, "
                "  seed=excluded.seed, num_predict=excluded.num_predict, "
                "  repeat_penalty=excluded.repeat_penalty, "
                "  thinking_enabled=excluded.thinking_enabled, "
                "  set_at=excluded.set_at, set_by=excluded.set_by, "
                "  reason=excluded.reason",
                (use_case.value, slot, model, temperature, top_p, top_k,
                 seed, num_predict, repeat_penalty, ti_int,
                 now, by, reason),
            )
            conn.execute(
                "INSERT INTO llm_routing_override_history "
                "(use_case, slot, old_json, new_json, changed_at, "
                " changed_by, reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (use_case.value, slot,
                 json.dumps(old_payload) if old_payload is not None else None,
                 json.dumps(new_payload),
                 now, by, reason),
            )
        return True
    except Exception as exc:
        log.warning("set_override(%s, %s) failed: %s", use_case, slot, exc)
        return False


def clear_override(use_case: UseCase, slot: str, *, by: str,
                   reason: Optional[str] = None) -> bool:
    """Delete an override row + record the deletion in history."""
    import json
    import time
    if not isinstance(use_case, UseCase):
        try:
            use_case = UseCase(use_case)
        except ValueError:
            return False
    slot = (slot or "").strip().lower()
    if slot not in _VALID_SLOTS:
        return False
    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            old_row = conn.execute(
                "SELECT model, temperature, top_p, top_k, seed, "
                "       num_predict, repeat_penalty, thinking_enabled "
                "FROM llm_routing_override "
                "WHERE use_case=? AND slot=?",
                (use_case.value, slot),
            ).fetchone()
            if not old_row:
                return True  # already cleared
            old_payload = {
                "model": old_row[0], "temperature": old_row[1],
                "top_p": old_row[2], "top_k": old_row[3],
                "seed": old_row[4], "num_predict": old_row[5],
                "repeat_penalty": old_row[6],
                "thinking_enabled": (
                    None if old_row[7] is None else bool(old_row[7])
                ),
            }
            conn.execute(
                "DELETE FROM llm_routing_override "
                "WHERE use_case=? AND slot=?",
                (use_case.value, slot),
            )
            conn.execute(
                "INSERT INTO llm_routing_override_history "
                "(use_case, slot, old_json, new_json, changed_at, "
                " changed_by, reason) "
                "VALUES (?, ?, ?, NULL, ?, ?, ?)",
                (use_case.value, slot, json.dumps(old_payload),
                 time.time(), by, reason),
            )
        return True
    except Exception as exc:
        log.warning("clear_override(%s, %s) failed: %s", use_case, slot, exc)
        return False


def list_override_history(*, hours: int = 720, limit: int = 200) -> list[dict]:
    """Return recent llm_routing_override_history rows. NP6 audit trail."""
    import time
    cutoff = time.time() - hours * 3600
    try:
        from radar.database import db
        rows = db._get_conn().execute(  # noqa: SLF001
            "SELECT id, use_case, slot, old_json, new_json, "
            "       changed_at, changed_by, reason "
            "FROM llm_routing_override_history "
            "WHERE changed_at >= ? "
            "ORDER BY changed_at DESC LIMIT ?",
            (cutoff, limit),
        ).fetchall()
    except Exception as exc:
        log.debug("list_override_history failed: %s", exc)
        return []
    return [
        {
            "id": r[0], "use_case": r[1], "slot": r[2],
            "old": r[3], "new": r[4], "changed_at": r[5],
            "changed_by": r[6], "reason": r[7],
        }
        for r in rows
    ]


def list_effective_routing() -> list[dict]:
    """Snapshot of every (use_case, slot) and the *effective* model + sampling
    after Layer 2/3 overrides are applied. Used by the preflight endpoint
    and admin UI so analysts can see exactly what will run without making a
    live LLM call."""
    out: list[dict] = []
    for uc in UseCase:
        chain = configured_chain(uc)
        slots = ("primary", "secondary")
        feature_state = "unknown"
        try:
            from radar.llm_features import resolve_state
            feature_state = resolve_state(feature_key_for(uc)).value
        except Exception:
            pass
        for i, choice in enumerate(chain):
            slot = slots[i] if i < len(slots) else f"fallback_{i}"
            out.append({
                "use_case": uc.value,
                "slot": slot,
                "feature_state": feature_state,
                "model": choice.model,
                "temperature": choice.temperature,
                "top_p": choice.top_p,
                "top_k": choice.top_k,
                "seed": choice.seed,
                "num_predict": choice.num_predict,
                "repeat_penalty": choice.repeat_penalty,
                "thinking_enabled": choice.thinking_enabled,
                "system_prefix": choice.system_prefix,
                "available": _model_available(choice.model),
            })
    return out


__all__ = [
    "UseCase",
    "ModelChoice",
    "RoutingResult",
    "choose_model",
    "configured_chain",
    "feature_key_for",
    "list_overrides",
    "set_override",
    "clear_override",
    "list_override_history",
    "list_effective_routing",
]
