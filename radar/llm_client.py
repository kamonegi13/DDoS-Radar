"""radar.llm_client -- Ollama LLM API client with LLM_ENABLED toggle.

Usage:
    from radar.llm_client import llm_analyze, llm_available
    result = llm_analyze(prompt="...", system="...")
    # Returns {"text": "...", "ok": True} or {"text": "", "ok": False, "error": "..."}
"""
from __future__ import annotations
import json
import logging
import requests
from radar.config import (
    LLM_ENABLED, LLM_HOST, LLM_MODEL, LLM_TIMEOUT,
    GLOBAL_PROXIES, SSL_VERIFY,
)

log = logging.getLogger("radar")

_TAGS_URL    = f"{LLM_HOST}/api/tags"
_GENERATE_URL = f"{LLM_HOST}/api/generate"


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
        # Accept exact match or model-name prefix (e.g. "llama3.2:3b" matches "llama3.2:3b")
        return any(m == LLM_MODEL or m.startswith(LLM_MODEL.split(":")[0]) for m in models)
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
        text = data.get("response", "").strip()
        return {"ok": True, "text": text}
    except requests.Timeout:
        log.warning("[LLM] Request timed out")
        return {"ok": False, "text": "", "error": "timeout"}
    except Exception as e:
        log.error(f"[LLM] Request error: {e}")
        return {"ok": False, "text": "", "error": str(e)}


def llm_analyze_json(prompt: str, system: str = "",
                     temperature: float = 0.1, max_tokens: int = 512) -> dict:
    """Like llm_analyze but parses the response as JSON.

    Returns:
        {"ok": True,  "data": {...}}
        {"ok": False, "data": {}, "error": "<reason>"}
    """
    result = llm_analyze(prompt, system=system,
                         temperature=temperature, max_tokens=max_tokens)
    if not result["ok"]:
        return {"ok": False, "data": {}, "error": result.get("error", "")}

    text = result["text"]
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
