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

import hashlib
import logging
import math
import re
import time
from dataclasses import dataclass
from typing import Optional

import requests

from radar.config import GLOBAL_PROXIES, LLM_HOST, LLM_TIMEOUT, SSL_VERIFY


def _live_timeout() -> int:
    """Phase 9.6 C23 — read LLM_TIMEOUT through layered config; falls
    back to module-level constant captured from env at boot."""
    try:
        from radar.config_layered import get_config
        v = get_config("LLM_TIMEOUT")
        if v is not None:
            return int(v)
    except Exception:
        pass
    return LLM_TIMEOUT


# ── Language detection (Phase 9.2 C8) ──────────────────────────────────────
#
# Lightweight Unicode-block-ratio classifier. Goal is to bucket items for
# the by_language Phase 1 GO rollup (zh/ja/ar/ru thresholds), NOT to
# achieve linguistic accuracy. Order matters: ja overlaps with zh by way
# of CJK ideographs, so kana-presence wins.

_RE_HIRAGANA = re.compile(r"[぀-ゟ゠-ヿ]")          # ja kana
_RE_HANGUL   = re.compile(r"[가-힯]")                        # ko
_RE_HAN      = re.compile(r"[一-鿿]")                        # zh/ja kanji
_RE_CYRILLIC = re.compile(r"[Ѐ-ӿ]")                        # ru/uk
_RE_ARABIC   = re.compile(r"[؀-ۿݐ-ݿ]")           # ar


def detect_lang(text: str) -> str:
    """Return one of {ja, ko, zh, ru, ar, en}. NP3 — never raises."""
    if not text:
        return "en"
    n = max(len(text), 1)
    ja = len(_RE_HIRAGANA.findall(text)) / n
    ko = len(_RE_HANGUL.findall(text))   / n
    han = len(_RE_HAN.findall(text))     / n
    ru = len(_RE_CYRILLIC.findall(text)) / n
    ar = len(_RE_ARABIC.findall(text))   / n
    if ja > 0.05:
        return "ja"
    if ko > 0.10:
        return "ko"
    if han > 0.10:
        return "zh"
    if ru > 0.20:
        return "ru"
    if ar > 0.20:
        return "ar"
    return "en"

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


def _log_embed_call(*, caller: str, model: str, duration_ms: int,
                    text_sha256: Optional[str], vector_dim: Optional[int],
                    cache_hit: bool, outcome: str,
                    error: Optional[str] = None) -> None:
    """Persist one row to llm_embed_call_log. Phase 9.2 C7 — visibility
    into the embedding pipeline that was previously a black box."""
    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                "INSERT INTO llm_embed_call_log "
                "(ts, caller, model, duration_ms, text_sha256, vector_dim, "
                " cache_hit, outcome, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), caller[:64] or "unknown", model[:80],
                 duration_ms, text_sha256, vector_dim,
                 1 if cache_hit else 0, outcome[:24],
                 (error or "")[:300] or None),
            )
    except Exception:
        pass  # NP3 — observability never blocks the primary path


def log_dedup_decision(*, item_id: str, matched_item_id: str,
                       cosine_score: float, threshold: float,
                       applied: bool, item_lang: Optional[str] = None,
                       source: Optional[str] = None) -> None:
    """Phase 9.2 C7 — record a near-duplicate decision so the by_language
    Phase 1 GO rollup can compute precision proxies per language bucket.

    applied=True  → ON state actually dropped the item
    applied=False → SHADOW state recorded the would-be decision only
    """
    try:
        from radar.database import db
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                "INSERT INTO llm_embed_dedup_log "
                "(ts, item_id, matched_item_id, cosine_score, threshold, "
                " applied, item_lang, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), str(item_id)[:128], str(matched_item_id)[:128],
                 float(cosine_score), float(threshold),
                 1 if applied else 0, item_lang, source),
            )
    except Exception:
        pass


def embed_text(text: str, *, caller: str = "") -> EmbeddingResult:
    """Encode a single text. Returns ``EmbeddingResult`` with ``vector=None``
    on any failure. NP3 — never raises. Every call is recorded to
    llm_embed_call_log (Phase 9.2 C7) so the embedding pipeline is no
    longer a black box."""
    model = _embedding_model()
    text_sha = (
        hashlib.sha256(text.encode("utf-8")).hexdigest()
        if text else None
    )

    if not text or not text.strip():
        _log_embed_call(caller=caller, model=model, duration_ms=0,
                        text_sha256=None, vector_dim=None,
                        cache_hit=False, outcome="empty_input")
        return EmbeddingResult(None, 0, "empty_input", model)
    if not _feature_active():
        _log_embed_call(caller=caller, model=model, duration_ms=0,
                        text_sha256=text_sha, vector_dim=None,
                        cache_hit=False, outcome="feature_disabled")
        return EmbeddingResult(None, 0, "feature_disabled", model)

    cache_key = f"{model}:{text}"
    cached = _lru_get(cache_key)
    if cached is not None:
        _log_embed_call(caller=caller, model=model, duration_ms=0,
                        text_sha256=text_sha, vector_dim=len(cached),
                        cache_hit=True, outcome="ok")
        return EmbeddingResult(cached, 0, None, model)

    payload = {"model": model, "input": text}
    t0 = time.time()
    try:
        res = requests.post(
            _EMBED_URL, json=payload, timeout=_live_timeout(),
            proxies=GLOBAL_PROXIES, verify=SSL_VERIFY,
        )
        duration_ms = int((time.time() - t0) * 1000)
        if res.status_code != 200:
            log.warning("[Embed] HTTP %d: %s", res.status_code, res.text[:200])
            _log_embed_call(caller=caller, model=model,
                            duration_ms=duration_ms,
                            text_sha256=text_sha, vector_dim=None,
                            cache_hit=False, outcome="http_error",
                            error=f"HTTP {res.status_code}")
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
            _log_embed_call(caller=caller, model=model,
                            duration_ms=duration_ms,
                            text_sha256=text_sha, vector_dim=None,
                            cache_hit=False, outcome="no_vector")
            return EmbeddingResult(None, duration_ms, "no_vector", model)
        _lru_put(cache_key, v)
        _log_embed_call(caller=caller, model=model, duration_ms=duration_ms,
                        text_sha256=text_sha, vector_dim=len(v),
                        cache_hit=False, outcome="ok")
        return EmbeddingResult(v, duration_ms, None, model)
    except requests.Timeout:
        ms = int((time.time() - t0) * 1000)
        _log_embed_call(caller=caller, model=model, duration_ms=ms,
                        text_sha256=text_sha, vector_dim=None,
                        cache_hit=False, outcome="timeout",
                        error="timeout")
        return EmbeddingResult(None, ms, "timeout", model)
    except Exception as exc:
        ms = int((time.time() - t0) * 1000)
        _log_embed_call(caller=caller, model=model, duration_ms=ms,
                        text_sha256=text_sha, vector_dim=None,
                        cache_hit=False, outcome="exception",
                        error=str(exc))
        log.debug("embed_text failed: %s", exc)
        return EmbeddingResult(None, ms, str(exc), model)


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
    "detect_lang",
    "log_dedup_decision",
]
