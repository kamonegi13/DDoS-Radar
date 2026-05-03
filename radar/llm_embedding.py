"""Embedding client for OSINT dedupe / clustering (Phase 8 LLM survey v10).

Dedicated to Ollama's ``/api/embed`` endpoint and the
``granite-embedding:278m`` model recommended by the 2026-05 LLM survey
(IBM, Apache 2.0, 12-language multilingual including ja/zh/ar but NOT
ru — Russian-source dedupe quality must be measured in Phase 1 shadow).

This module is intentionally separate from ``radar.llm_client``:
  - different API path (``/api/embed`` vs ``/api/generate``)
  - different cognitive surface (no thinking modes, no JSON parsing)
  - different cost profile (sub-MB model, batchable, no token-streaming)
  - different failure modes (per-text encode failures don't propagate)

Usage::

    from radar.llm_embedding import embed_text, embed_batch, near_duplicates

    vec = embed_text("Putin signs new mobilization decree")
    pairs = near_duplicates(["text1", "text2", "text3"], threshold=0.95)

The Feature Hub key ``embedding_dedupe`` (default OFF) gates the live
``embed_*`` calls. With the feature OFF every call short-circuits and
returns ``None`` (or an empty list) — sensors must tolerate this so
embedding is purely additive.
"""
from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass
from typing import Optional

import requests

from radar.config import GLOBAL_PROXIES, LLM_HOST, LLM_TIMEOUT, SSL_VERIFY

log = logging.getLogger("radar.llm_embedding")


# Default model from the survey v10. Operators can override via env
# without redeploying — preserves the same Layer 2 contract that
# llm_routing.py uses.
def _embedding_model() -> str:
    import os
    return os.getenv("LLM_EMBEDDING_MODEL", "granite-embedding:278m")


_EMBED_URL = f"{LLM_HOST}/api/embed"

# Tiny in-process LRU so identical strings (same headline reposted across
# sources) are hashed once. ``maxsize`` is conservative because embedding
# inputs are headlines / short summaries (< 1 KB each).
_LRU_CAPACITY = 2048
_lru_order: list[str] = []
_lru_cache: dict[str, list[float]] = {}


def _lru_get(key: str) -> Optional[list[float]]:
    vec = _lru_cache.get(key)
    if vec is None:
        return None
    # Move to most-recent slot.
    try:
        _lru_order.remove(key)
    except ValueError:
        pass
    _lru_order.append(key)
    return vec


def _lru_put(key: str, vec: list[float]) -> None:
    if key in _lru_cache:
        try:
            _lru_order.remove(key)
        except ValueError:
            pass
    elif len(_lru_order) >= _LRU_CAPACITY:
        oldest = _lru_order.pop(0)
        _lru_cache.pop(oldest, None)
    _lru_order.append(key)
    _lru_cache[key] = vec


def _feature_active() -> bool:
    """Resolve the ``embedding_dedupe`` Feature Hub key. NP3."""
    try:
        from radar.llm_features import is_active
        return is_active("embedding_dedupe")
    except Exception:
        return False


@dataclass(frozen=True)
class EmbeddingResult:
    vector: Optional[list[float]]
    duration_ms: int
    error: Optional[str]
    model: str


def embed_text(text: str, *, caller: str = "") -> EmbeddingResult:
    """Encode a single text. Returns ``EmbeddingResult`` with ``vector=None``
    on any failure. NP3 — never raises."""
    model = _embedding_model()
    if not text or not text.strip():
        return EmbeddingResult(None, 0, "empty_input", model)
    if not _feature_active():
        return EmbeddingResult(None, 0, "feature_disabled", model)

    cache_key = f"{model}:{text}"
    cached = _lru_get(cache_key)
    if cached is not None:
        return EmbeddingResult(cached, 0, None, model)

    payload = {"model": model, "input": text}
    t0 = time.time()
    try:
        res = requests.post(
            _EMBED_URL, json=payload, timeout=LLM_TIMEOUT,
            proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
        )
        duration_ms = int((time.time() - t0) * 1000)
        if res.status_code != 200:
            log.warning("[Embed] HTTP %d: %s", res.status_code, res.text[:200])
            return EmbeddingResult(
                None, duration_ms, f"HTTP {res.status_code}", model,
            )
        rj = res.json()
        # Ollama 0.22.x returns ``embeddings: [[...]]`` or ``embedding: [...]``
        vec = rj.get("embeddings")
        if isinstance(vec, list) and vec:
            v = vec[0] if isinstance(vec[0], list) else vec
        else:
            v = rj.get("embedding")
        if not isinstance(v, list) or not v:
            return EmbeddingResult(None, duration_ms, "no_vector", model)
        _lru_put(cache_key, v)
        return EmbeddingResult(v, duration_ms, None, model)
    except requests.Timeout:
        return EmbeddingResult(None, int((time.time() - t0) * 1000),
                               "timeout", model)
    except Exception as exc:
        log.debug("embed_text failed: %s", exc)
        return EmbeddingResult(None, int((time.time() - t0) * 1000),
                               str(exc), model)


def embed_batch(texts: list[str], *, caller: str = "") -> list[Optional[list[float]]]:
    """Encode a batch. Returns a list aligned with ``texts``; failed entries
    are ``None`` so callers can keep their own indices stable."""
    return [embed_text(t, caller=caller).vector for t in texts]


def cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity. Returns 0.0 for inputs of mismatched length or
    zero norm — consistent with "no signal" rather than raising."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    if na <= 0 or nb <= 0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


def near_duplicates(
    texts: list[str], *, threshold: float = 0.95,
    caller: str = "",
) -> list[tuple[int, int, float]]:
    """Pairwise near-dup detection. Returns ``(i, j, sim)`` for every
    ``i < j`` where ``cosine >= threshold``. Skips entries whose
    embedding failed (those rows simply don't match anyone).

    O(N²) — fine for the sensor-side de-dup window (~50 items per cycle).
    For the bg_observer matching pipeline (~1000 items / day) callers
    should batch-encode first and reuse vectors.
    """
    vectors = embed_batch(texts, caller=caller)
    n = len(vectors)
    out: list[tuple[int, int, float]] = []
    for i in range(n):
        vi = vectors[i]
        if vi is None:
            continue
        for j in range(i + 1, n):
            vj = vectors[j]
            if vj is None:
                continue
            sim = cosine(vi, vj)
            if sim >= threshold:
                out.append((i, j, sim))
    return out


def embedding_preflight() -> dict:
    """Check whether the embedding model is pulled locally. Used by
    ``/api/v2/llm_preflight``. NP3 — never raises."""
    model = _embedding_model()
    out = {"model": model, "available": False, "feature_active": False,
           "error": None}
    try:
        out["feature_active"] = _feature_active()
        res = requests.get(
            f"{LLM_HOST}/api/tags",
            timeout=5, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
        )
        if res.status_code == 200:
            names = [m.get("name", "") for m in res.json().get("models", [])]
            out["available"] = any(
                n == model or n.startswith(model.split(":")[0])
                for n in names
            )
    except Exception as exc:
        out["error"] = str(exc)
    return out


__all__ = [
    "EmbeddingResult",
    "embed_text",
    "embed_batch",
    "cosine",
    "near_duplicates",
    "embedding_preflight",
]
