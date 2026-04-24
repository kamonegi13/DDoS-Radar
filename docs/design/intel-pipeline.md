# LLM Intel Pipeline

> Ingestion, filtering, dedup, and analyst-review lifecycle for LLM-analyzed intel items.
> Last updated: 2026-04-24

This document is the reference for the intel queue. CLAUDE.md points here instead of inlining the details.

## Pipeline

```
Sensor fetch → llm_analyze_json() (Ollama) → intel_queue.submit()
  confidence < LLM_CONFIDENCE_MIN (0.35)            → discarded
  confidence >= 0.80 AND credibility >= 0.75        → auto_confirmed
  otherwise                                          → pending (analyst review)

Dedup: Jaccard headline similarity >= 0.60
  (same source_type + theater + within 48h)
  same source_id + similar headline    → discard (re-scrape duplicate)
  different source_id + similar headline → replace on higher confidence,
                                            otherwise record as corroboration

Active slots: 2 per group, TTL 24h
```

## Invariants and pitfalls

1. **LLM JSON parsing**: Ollama's `format="json"` does not guarantee valid JSON. A fallback parser exists. Qwen3-family models sometimes emit the payload inside `thinking` rather than `response` — always check both.
2. **Credibility bootstrap**: see commit `44eedbd` — source credibility is seeded by archetype (gov CERT 0.85, defense reporting 0.75, state propaganda 0.60, hacktivist 0.60, default 0.70). Analyst feedback modulates, it does not gate existence.
3. **Dedup cache shape**: LLM sensors use `dict[str, None]` (not `set`) to preserve insertion order for LRU eviction. Do not replace with `set`.
4. **sensor-layer drops**: see commit `c6f2f3e` — when a sensor drops an LLM result before `intel_queue.submit()`, call `record_sensor_drop(reason)` so the diagnostics panel can attribute it.

## Related code

- [radar/intel_queue.py](../../radar/intel_queue.py) — `submit()`, verdict patching, dedup
- [radar/intel_corroboration.py](../../radar/intel_corroboration.py) — cross-source corroboration
- [radar/llm_client.py](../../radar/llm_client.py) — Ollama client, JSON sanitization, `record_sensor_drop()`
