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

# Prompt injection patterns to detect and neutralize in untrusted text
_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+(previous|all|prior)|forget\s+(previous|all|prior)|disregard\s+(previous|all)|"
    r"instead\s+return|return\s+the\s+following|respond\s+with\s*[:{]|"
    r"your\s+new\s+instructions|override\s+(previous|all)|"
    r"output\s+the\s+following|new\s+task\s*:)",
    re.IGNORECASE,
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
    """Basic prompt injection mitigation for untrusted external text.

    Truncates to max_len and neutralizes common instruction-injection patterns
    by replacing them with [...]. Does NOT guarantee safety against all attacks,
    but raises the bar for opportunistic injection via RSS/Telegram content.
    """
    if not text:
        return ""
    text = text[:max_len]
    text = _INJECTION_PATTERNS.sub("[...]", text)
    return text


def today_str() -> str:
    """Return today's UTC date as ISO string for inclusion in LLM prompts."""
    return date.today().isoformat()


# ── Core API functions ────────────────────────────────────────────────────────

def llm_available() -> bool:
    """Check if Ollama is reachable and the configured model is available."""
    if not LLM_ENABLED:
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


def llm_analyze(prompt: str, system: str = "",
                temperature: float = 0.1, max_tokens: int = 512) -> dict:
    """Send a prompt to Ollama and return the response.

    Returns:
        {"ok": True,  "text": "<response text>"}
        {"ok": False, "text": "", "error": "<reason>"}
    """
    if not LLM_ENABLED:
        return {"ok": False, "text": "", "error": "LLM_ENABLED=false"}

    payload: dict = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    if system:
        payload["system"] = system

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
                     temperature: float = 0.1, max_tokens: int = 512) -> dict:
    """Like llm_analyze but forces JSON output via Ollama format param and parses result.

    Returns:
        {"ok": True,  "data": {...}}
        {"ok": False, "data": {}, "error": "<reason>"}
    """
    if not LLM_ENABLED:
        return {"ok": False, "data": {}, "error": "LLM_ENABLED=false"}

    # Use format="json" to force Ollama to output valid JSON regardless of model
    payload: dict = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    if system:
        payload["system"] = system

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
            return {"ok": False, "data": {}, "error": f"HTTP {res.status_code}"}
        rj = res.json()
        # Some models (e.g. Qwen3.5) put output in "thinking" field instead of "response"
        text = rj.get("response", "").strip()
        if not text:
            text = rj.get("thinking", "").strip()
    except requests.Timeout:
        log.warning("[LLM] JSON request timed out")
        return {"ok": False, "data": {}, "error": "timeout"}
    except Exception as e:
        log.error(f"[LLM] JSON request error: {e}")
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
        return {"ok": True, "data": data}
    except json.JSONDecodeError:
        # Try to extract JSON object from within the text
        start = text.find("{")
        end   = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end])
                return {"ok": True, "data": data}
            except json.JSONDecodeError:
                pass
        log.warning(f"[LLM] JSON parse failed: {text[:200]}")
        return {"ok": False, "data": {}, "error": "json_parse_failed"}
