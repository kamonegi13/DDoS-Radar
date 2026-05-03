"""radar.llm_client -- Ollama LLM API client with LLM_ENABLED toggle.

Usage:
    from radar.llm_client import llm_analyze, llm_available
    result = llm_analyze(prompt="...", system="...")
    # Returns {"text": "...", "ok": True} or {"text": "", "ok": False, "error": "..."}

Utilities:
    safe_float(val, default, min_val, max_val) -- type-safe numeric extraction from LLM JSON
    safe_enum(val, allowed, default)           -- validated enum extraction from LLM JSON
    sanitize_llm_input(text, max_len)          -- basic prompt injection mitigation
"""
from __future__ import annotations
import json
import logging
import re
import sys
import time
import unicodedata
import requests
from datetime import date
from radar.config import (
    LLM_ENABLED, LLM_HOST, LLM_MODEL, LLM_TIMEOUT,
    GLOBAL_PROXIES, SSL_VERIFY,
)

log = logging.getLogger("radar")

_TAGS_URL    = f"{LLM_HOST}/api/tags"
_GENERATE_URL = f"{LLM_HOST}/api/generate"

# Known small models that produce lower-quality structured output
_LOW_QUALITY_MODEL_PATTERNS = ("1b", "3b", "0.5b", "1.5b")

# Prompt injection patterns to detect and neutralize in untrusted text.
# Phase 7.5e (audit Security H6) — broadened beyond the original
# English-only pattern set:
#   - English variants tightened (instruction, prompt, system message,
#     act as / pretend / roleplay, jailbreak, reveal/print/show prompt)
#   - Japanese ("無視", "指示", "システムプロンプト", "新しい指示", etc.)
#   - Chinese / Russian basic instruction-override phrases
#   - System / chat delimiter tokens: <|im_start|>, <|system|>, [INST]
#     / [/INST], ###, BEGIN/END markers commonly used in fine-tuned
#     model templates
# Single-pass IGNORECASE regex so the call cost stays at one substitution
# per sanitize_llm_input invocation.
_INJECTION_PATTERNS = re.compile(
    # ── English: instruction overrides ─────────────────────────────────
    # Determiner ("the", "any", "all") may sit between the verb and the
    # target word ("ignore the above instructions").
    r"(ignore(\s+(the|any|all))?\s+(previous|all|prior|above|earlier)|"
    r"forget(\s+(the|any|all))?\s+(previous|all|prior|above|everything)|"
    r"disregard(\s+(the|any|all))?\s+(previous|all|above)|"
    r"instead\s+return|return\s+the\s+following|"
    r"respond\s+with\s*[:{]|reply\s+only\s+with|"
    r"your\s+new\s+instructions|override\s+(previous|all)|"
    r"output\s+the\s+following|new\s+task\s*:|new\s+system\s*:|"
    # ── English: persona / jailbreak vectors ────────────────────────────
    r"act\s+as\s+(a|an|the)|pretend\s+(to\s+be|you\s+are)|"
    r"roleplay\s+as|you\s+are\s+now\s+(a|an)|"
    r"do\s+anything\s+now|jailbreak|developer\s+mode|"
    r"reveal\s+(your\s+)?(prompt|instructions|system\s+message)|"
    r"print\s+(your\s+)?(prompt|instructions|system\s+message)|"
    r"show\s+(me\s+)?(your\s+)?(prompt|instructions|system\s+message)|"
    # ── Japanese ───────────────────────────────────────────────────────
    r"これまでの(指示|命令|プロンプト)を(無視|忘れ)|"
    r"以前の(指示|命令)を(無視|忘れ)|"
    r"新しい指示\s*[::]|新しいタスク\s*[::]|"
    r"システム(プロンプト|メッセージ)を(表示|出力|教え)|"
    # ── Chinese ────────────────────────────────────────────────────────
    r"忽略(以前|之前|上面)的?(指令|指示|提示)|"
    r"忘记(以前|之前|上面)的?(指令|指示|提示)|"
    r"新的?(指令|指示|任务)\s*[::]|"
    # ── Russian ────────────────────────────────────────────────────────
    r"игнорир(уй|овать)\s+(предыдущи|все|выше)|"
    r"забуд(ь|ьте)\s+(предыдущи|все)|"
    r"новая\s+задача\s*:|"
    # ── Template / chat delimiter tokens (any model family) ─────────────
    r"<\|im_(start|end)\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|"
    r"\[/?INST\]|\[/?SYS\]|"
    r"###\s*(system|instruction|new\s+instruction|task)\b|"
    r"begin\s+(system|new)\s+(prompt|instruction)|"
    r"end\s+(system|prompt|instruction))",
    re.IGNORECASE,
)

# Control characters that must never reach the model unchanged.
# Keeps \t (U+0009), \n (U+000A), \r (U+000D); strips everything else
# in the C0 / C1 ranges plus the Unicode bidi-override and zero-width
# joiner family that has been used in homograph-style injection PoCs.
_CONTROL_CHAR_PATTERN = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"        # C0 / DEL / C1
    r"​-‏"                               # zero-width + LRM/RLM
    r"  "                                # line/paragraph sep
    r"‪-‮"                               # explicit bidi overrides
    r"⁠-⁤﻿"                         # word-joiner, BOM
    r"]"
)


# ── Utility helpers ───────────────────────────────────────────────────────────

def safe_float(val, default: float = 0.0, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """Type-safe extraction of a float from LLM JSON output.

    Handles common LLM quirks:
    - String values ("0.85", "high")
    - None / missing
    - Out-of-range numbers

    Returns default if the value cannot be parsed or is out of range.
    """
    if val is None:
        return default
    try:
        f = float(val)
    except (TypeError, ValueError):
        return default
    if f < min_val or f > max_val:
        # Clamp instead of returning default so near-miss values (e.g. 1.001) still work
        return max(min_val, min(max_val, f))
    return f


def safe_enum(val, allowed: set, default: str) -> str:
    """Type-safe extraction of an enum string from LLM JSON output.

    Returns val if it is a string and in allowed, otherwise default.
    Logs unexpected values to help detect model quality degradation.
    """
    if isinstance(val, str) and val in allowed:
        return val
    if val is not None and val != "":
        log.debug(f"[LLM] Unexpected enum value {val!r} (allowed: {allowed}) — using default={default!r}")
    return default


def sanitize_llm_input(text: str, max_len: int = 1000) -> str:
    """Prompt injection mitigation for untrusted external text.

    Phase 7.5e (audit Security H6) hardening — the previous version
    matched only English instruction-override phrases against the raw
    input text, which Unicode homoglyph and control-character tricks
    could trivially bypass. The pipeline is now:

      1. Drop falsy input and truncate to ``max_len`` (keeps the model
         within its context budget regardless of upstream).
      2. NFKC normalisation collapses fullwidth, compatibility, and
         circled forms back to canonical ASCII (e.g. "ｉｇｎｏｒｅ" →
         "ignore", "①" → "1") so a single regex pass covers all
         visually-equivalent variants.
      3. Strip C0 / C1 control characters, the zero-width family, and
         explicit bidi overrides — these are commonly chained with
         homograph attacks to slip an injection past pattern matchers.
      4. Apply the broadened ``_INJECTION_PATTERNS`` regex (English +
         Japanese + Chinese + Russian basics, plus chat-template
         delimiter tokens) and replace matches with ``[...]``.

    Does NOT guarantee safety against all attacks, but raises the bar
    significantly versus the pre-Phase-7.5e version, especially against
    Unicode homoglyph / control-char bypasses that were trivial before.
    """
    if not text:
        return ""
    text = text[:max_len]
    text = unicodedata.normalize("NFKC", text)
    text = _CONTROL_CHAR_PATTERN.sub("", text)
    text = _INJECTION_PATTERNS.sub("[...]", text)
    return text


def today_str() -> str:
    """Return today's UTC date as ISO string for inclusion in LLM prompts."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).date().isoformat()


def _infer_caller() -> str:
    """Infer the immediate caller module name for observability logging.

    Uses inspect.stack() to find the first frame outside radar/llm_client.py
    and returns its module's short name (e.g. "hacktivist_intel_sensor").
    Returns "unknown" if inference fails.
    """
    import inspect
    try:
        for frame_info in inspect.stack()[2:]:
            mod = frame_info.frame.f_globals.get("__name__", "")
            if mod and not mod.endswith("llm_client"):
                return mod.rsplit(".", 1)[-1]
    except Exception:
        pass
    return "unknown"


def _log_call(caller: str, duration_ms: int, outcome: str,
              confidence: float = 0.0, headline: str = "", error: str = "",
              prompt_sha256: str = "",
              model: str = "",
              use_case: str = "",
              shadow_model_choice: str = "",
              thinking_trace: str = ""):
    """Best-effort logging of an LLM call to llm_call_log.
    Verdict (auto_confirmed/pending/discarded_*) is recorded later by intel_queue.
    prompt_sha256 links the call to the persisted llm_prompts row (ADR-V2-009).

    Phase 8 (LLM survey v10):
      - ``model``               : actual model that ran (defaults to LLM_MODEL
                                  when caller didn't go through routing)
      - ``use_case``            : routing bucket name (sensor_extract, verdict, …)
      - ``shadow_model_choice`` : model v2 routing *would* have picked when in
                                  SHADOW state; empty otherwise
      - ``thinking_trace``      : reasoning text captured from <|think|> /
                                  Reasoning: high modes; empty when thinking OFF
    """
    try:
        from radar.database import db
        db.llm_call_log_append(
            caller=caller, model=model or LLM_MODEL, duration_ms=duration_ms,
            outcome=outcome, verdict="", confidence=confidence,
            headline=headline, error=error, prompt_sha256=prompt_sha256,
            use_case=use_case or None,
            shadow_model_choice=shadow_model_choice or None,
            thinking_trace=thinking_trace or None,
        )
    except Exception:
        pass  # never let observability break the main flow


def _maybe_persist_prompt(prompt: str, system: str, temperature: float) -> str:
    """v2.0 shadow-write: store the (system, prompt) pair, return its sha256.
    Returns '' when V2_LLM_PROMPT_PERSISTENCE_ENABLED=False or storage failed.
    Never raises — observability cannot break the LLM call path."""
    try:
        from radar import config
        if not config.V2_LLM_PROMPT_PERSISTENCE_ENABLED:
            return ""
        from radar.database import db
        from radar.llm_prompts import save_prompt
        sha = save_prompt(db, prompt=prompt, system=system,
                          model=LLM_MODEL, temperature=temperature)
        return sha or ""
    except Exception:
        return ""


def record_sensor_drop(reason: str, caller: str = "") -> None:
    """Record a sensor-layer drop verdict on the most recent llm_call_log row.

    Call this immediately after a post-LLM `continue` in a sensor (e.g. when
    event_type=none, theater_link=none, theater not in whitelist) so operators
    can distinguish sensor-layer filtering from intel_queue dedup/low-conf.

    Verdict format: "sensor_filtered:<reason>" — keeps the row identifiable
    in llm_call_stats while leaving the sensor_filter_breakdown tally queryable.
    """
    try:
        from radar.database import db
        if not caller:
            caller = _infer_caller()
        db.llm_call_patch_verdict((caller,), f"sensor_filtered:{reason}", window_sec=60)
    except Exception:
        pass  # observability must never break the main flow


def record_sensor_skip(reason: str, caller: str = "", headline: str = "") -> None:
    """Record a pre-LLM skip event — when a sensor decides not to call the LLM at all.

    Distinct from record_sensor_drop, which patches a real LLM call's verdict.
    Use this at the natural pre-LLM drop points (feed fetch failed, no articles
    after filter, all candidates dedup'd, no country hints matched).

    Inserts a synthetic row with outcome='pre_filter' and verdict='sensor_filtered:
    <reason>' so llm_call_stats surfaces silent sensors with reason breakdowns
    instead of leaving operators to grep logs.
    """
    try:
        from radar.database import db
        if not caller:
            caller = _infer_caller()
        db.llm_call_log_append(
            caller=caller, model=LLM_MODEL, duration_ms=0,
            outcome="pre_filter",
            verdict=f"sensor_filtered:{reason}",
            confidence=0.0,
            headline=headline,
            error="",
        )
    except Exception:
        pass  # observability must never break the main flow


# ── Core API functions ────────────────────────────────────────────────────────

def _global_llm_enabled() -> bool:
    """Resolve the global LLM enable state through the Feature Hub
    ('sensor_intel_extraction' is the registered key for the global
    LLM_ENABLED flag — same default ON, same kill-switch coverage).
    Falls back to the original env on import failure."""
    try:
        from radar.llm_features import is_enabled
        return is_enabled("sensor_intel_extraction")
    except Exception:
        return LLM_ENABLED


def llm_available() -> bool:
    """Check if Ollama is reachable and the configured model is available."""
    if not _global_llm_enabled():
        return False
    try:
        res = requests.get(_TAGS_URL, timeout=5,
                           proxies=GLOBAL_PROXIES, verify=SSL_VERIFY)
        if res.status_code != 200:
            return False
        models = [m.get("name", "") for m in res.json().get("models", [])]
        match = any(m == LLM_MODEL or m.startswith(LLM_MODEL.split(":")[0]) for m in models)
        if match:
            model_lower = LLM_MODEL.lower()
            if any(pat in model_lower for pat in _LOW_QUALITY_MODEL_PATTERNS):
                log.warning(
                    f"[LLM] Model {LLM_MODEL!r} is a small model — structured JSON output quality "
                    "may be degraded. Consider llama3.1:8b or larger for production use."
                )
        return match
    except Exception:
        return False


def _build_options(temperature: float, max_tokens: int,
                   choice=None) -> dict:
    """Merge caller-supplied (temperature, max_tokens) with the routing
    choice's sampling parameters. Choice values win when present.
    """
    opts: dict = {"temperature": temperature, "num_predict": max_tokens}
    if choice is None:
        return opts
    # Routing choice overrides sampling — verdict needs determinism, sensor
    # follows Mistral's recommended low-temperature defaults, etc.
    opts["temperature"] = choice.temperature
    opts["num_predict"] = choice.num_predict or max_tokens
    if choice.top_p and choice.top_p < 1.0:
        opts["top_p"] = choice.top_p
    if choice.top_k:
        opts["top_k"] = choice.top_k
    if choice.seed is not None:
        opts["seed"] = choice.seed
    if choice.repeat_penalty and choice.repeat_penalty != 1.0:
        opts["repeat_penalty"] = choice.repeat_penalty
    return opts


def llm_analyze(prompt: str, system: str = "",
                temperature: float = 0.1, max_tokens: int = 512,
                use_case=None) -> dict:
    """Send a prompt to Ollama and return the response.

    ``use_case`` (radar.llm_routing.UseCase, optional): when provided, the
    Phase 8 routing layer picks the model + sampling. When None, falls back
    to the legacy single-``LLM_MODEL`` path.

    Returns:
        {"ok": True,  "text": "<response text>"}
        {"ok": False, "text": "", "error": "<reason>"}
    """
    if not _global_llm_enabled():
        return {"ok": False, "text": "", "error": "LLM_ENABLED=false"}

    # Resolve routing — never raises; falls through to legacy on failure.
    try:
        from radar.llm_routing import choose_model
        routing = choose_model(use_case)
        choice = routing.active
    except Exception:
        choice = None

    model = choice.model if choice is not None else LLM_MODEL
    eff_system = choice.merge_system(system) if choice is not None else system

    payload: dict = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": _build_options(temperature, max_tokens, choice),
    }
    if eff_system:
        payload["system"] = eff_system

    try:
        res = requests.post(
            _GENERATE_URL,
            json=payload,
            timeout=LLM_TIMEOUT,
            proxies=GLOBAL_PROXIES,
            verify=SSL_VERIFY,
        )
        if res.status_code != 200:
            log.warning(f"[LLM] HTTP {res.status_code}: {res.text[:200]}")
            return {"ok": False, "text": "", "error": f"HTTP {res.status_code}"}
        data = res.json()
        # Some models (e.g. Qwen3.5) put output in "thinking" field instead of "response"
        text = data.get("response", "").strip()
        if not text:
            text = data.get("thinking", "").strip()
        return {"ok": True, "text": text}
    except requests.Timeout:
        log.warning("[LLM] Request timed out")
        return {"ok": False, "text": "", "error": "timeout"}
    except Exception as e:
        log.error(f"[LLM] Request error: {e}")
        return {"ok": False, "text": "", "error": str(e)}


def llm_analyze_json(prompt: str, system: str = "",
                     temperature: float = 0.1, max_tokens: int = 512,
                     caller: str = "",
                     use_case=None) -> dict:
    """Like llm_analyze but forces JSON output via Ollama format param and parses result.

    Logs every call to llm_call_log so operators can distinguish "sensor silent"
    from "LLM unreachable" from "parse failure" without trawling logs.

    caller   : optional explicit name for logging. Inferred from stack if empty.
    use_case : :class:`radar.llm_routing.UseCase` — when set, the Phase 8 routing
               layer picks model + sampling per the LLM survey v10 stack.
               When None, falls back to the legacy single-``LLM_MODEL`` path.

    Returns:
        {"ok": True,  "data": {...}}
        {"ok": False, "data": {}, "error": "<reason>"}
    """
    if not caller:
        caller = _infer_caller()

    # Resolve routing first so logs always carry use_case + active model.
    use_case_str = ""
    shadow_model_choice = ""
    choice = None
    try:
        from radar.llm_routing import choose_model
        routing = choose_model(use_case)
        choice = routing.active
        if use_case is not None:
            use_case_str = use_case.value if hasattr(use_case, "value") else str(use_case)
        if routing.shadow_choice:
            shadow_model_choice = routing.shadow_choice
    except Exception:
        choice = None

    model = choice.model if choice is not None else LLM_MODEL

    if not _global_llm_enabled():
        _log_call(caller, 0, "disabled", error="LLM_ENABLED=false",
                  model=model, use_case=use_case_str,
                  shadow_model_choice=shadow_model_choice)
        return {"ok": False, "data": {}, "error": "LLM_ENABLED=false"}

    eff_system = choice.merge_system(system) if choice is not None else system

    # v2.0 ADR-V2-009: persist (system, prompt) and capture sha256 for FK linking.
    eff_temperature = choice.temperature if choice is not None else temperature
    prompt_sha = _maybe_persist_prompt(prompt, eff_system, eff_temperature)

    # Use format="json" to force Ollama to output valid JSON regardless of model
    payload: dict = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": _build_options(temperature, max_tokens, choice),
    }
    if eff_system:
        payload["system"] = eff_system

    t0 = time.time()
    try:
        res = requests.post(
            _GENERATE_URL,
            json=payload,
            timeout=LLM_TIMEOUT,
            proxies=GLOBAL_PROXIES,
            verify=SSL_VERIFY,
        )
        duration_ms = int((time.time() - t0) * 1000)
        if res.status_code != 200:
            log.warning(f"[LLM] HTTP {res.status_code}: {res.text[:200]}")
            _log_call(caller, duration_ms, "http_error",
                      error=f"HTTP {res.status_code}", prompt_sha256=prompt_sha,
                      model=model, use_case=use_case_str,
                      shadow_model_choice=shadow_model_choice)
            return {"ok": False, "data": {}, "error": f"HTTP {res.status_code}"}
        rj = res.json()
        # Some models put reasoning in the "thinking" field; capture both so the
        # call log records the trace separately from the JSON response (NP6).
        text = rj.get("response", "").strip()
        thinking_text = rj.get("thinking", "").strip()
        if not text and thinking_text:
            text = thinking_text
            thinking_text = ""  # used as response, no separate trace
        thinking_trace = thinking_text if (
            choice is not None and choice.thinking_enabled
        ) else ""
    except requests.Timeout:
        duration_ms = int((time.time() - t0) * 1000)
        log.warning("[LLM] JSON request timed out")
        _log_call(caller, duration_ms, "timeout", error="timeout",
                  prompt_sha256=prompt_sha, model=model,
                  use_case=use_case_str,
                  shadow_model_choice=shadow_model_choice)
        return {"ok": False, "data": {}, "error": "timeout"}
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        log.error(f"[LLM] JSON request error: {e}")
        _log_call(caller, duration_ms, "exception", error=str(e),
                  prompt_sha256=prompt_sha, model=model,
                  use_case=use_case_str,
                  shadow_model_choice=shadow_model_choice)
        return {"ok": False, "data": {}, "error": str(e)}

    # Strip markdown code fences if present
    if "```" in text:
        lines = text.split("\n")
        text = "\n".join(
            ln for ln in lines
            if not ln.strip().startswith("```")
        )
    try:
        data = json.loads(text)
        _log_call(
            caller, duration_ms, "ok",
            confidence=safe_float(data.get("confidence"), 0.0),
            headline=str(data.get("headline", ""))[:200],
            prompt_sha256=prompt_sha,
            model=model, use_case=use_case_str,
            shadow_model_choice=shadow_model_choice,
            thinking_trace=thinking_trace,
        )
        return {"ok": True, "data": data}
    except json.JSONDecodeError:
        # Try to extract JSON object from within the text
        start = text.find("{")
        end   = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end])
                _log_call(
                    caller, duration_ms, "ok",
                    confidence=safe_float(data.get("confidence"), 0.0),
                    headline=str(data.get("headline", ""))[:200],
                    prompt_sha256=prompt_sha,
                    model=model, use_case=use_case_str,
                    shadow_model_choice=shadow_model_choice,
                    thinking_trace=thinking_trace,
                )
                return {"ok": True, "data": data}
            except json.JSONDecodeError:
                pass
        log.warning(f"[LLM] JSON parse failed: {text[:200]}")
        _log_call(caller, duration_ms, "parse_failed",
                  error=text[:200], prompt_sha256=prompt_sha,
                  model=model, use_case=use_case_str,
                  shadow_model_choice=shadow_model_choice)
        return {"ok": False, "data": {}, "error": "json_parse_failed"}
