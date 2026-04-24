# Scoring Engine Internals

> Threat scoring formula, thresholds, and known pitfalls.
> Last updated: 2026-04-24

This document is the reference for the DDoS-Radar threat scoring pipeline. CLAUDE.md points here instead of inlining the details so the per-session context stays small.

## Scoring formula

```
Domain weights: cyber=0.50, physical=0.30, info=0.20
Threat levels:
  TL1 (>=9, physical degradation required)
  TL2 (>=6, 2+ domains required)
  TL3 (>=4)
  TL4 (>=2)
  TL5 (<2)
Convergence bonus:
  FULL  (3 domains) +2
  DUAL  (2 domains) +1
  SINGLE          +0
signal_source dedup: same key → MAX (do not sum)
```

Scenario-unit scoring (in-progress refactor) is specified in [scenario-refactor.md](scenario-refactor.md) — in particular ADR-021 (domain weight deprecation in scenario scoring) and §7.3.1 (TL threshold recalibration).

## Pitfalls and invariants

1. **signal_source dedup**: sensors sharing a `signal_source` (IODA / BgpRouting / IHR all report "bgp") must be reduced with MAX, never summed. Any new sensor that adopts an existing `signal_source` inherits this rule automatically — do not add a per-sensor override.
2. **Convergence gating**: TL2 requires 2+ active domains. Cyber-only evidence cannot exceed TL3 regardless of raw score. This is intentional and must not be relaxed without explicit design change.
3. **Thread-local DB**: every thread holds its own SQLite connection. Do NOT share handles across threads — the scoring loop and the background scheduler must each open their own. See [radar/database.py](../../radar/database.py).
4. **Circuit breakers**: a sensor that fails 5 consecutive fetches goes OPEN; recovery uses exponential backoff capped at 3600s. See [radar/sensors/base.py](../../radar/sensors/base.py).

## Related code

- [radar/engine.py](../../radar/engine.py) — `WeightedConvergenceEngine`
- [radar/scoring.py](../../radar/scoring.py) — HOD baseline, adaptive Z-score, sequence scoring, CAC
- [radar/routes/core.py](../../radar/routes/core.py) — scoring loop, `add_rat()` gating
