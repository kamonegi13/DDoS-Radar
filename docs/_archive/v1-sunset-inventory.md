# v1 API Sunset Removal Inventory (ADR-V2-003 / PF7)

**Target sunset date**: 2026-07-26 (T+90d from Mode C activation 2026-04-26).
**Purpose**: Operator checklist. Walk top-to-bottom on sunset day; the actual
removal should be a focused 1-2 hour execution, not a discovery exercise.

## ⏰ When you open this on 2026-07-26 — quick start

1. Confirm today's date is on or after 2026-07-26 UTC (the contract date).
2. Run the pre-flight gate (Appendix bottom of this file):
   ```bash
   docker exec ddos-radar python /app/scripts/list_v1_routes.py --check-stale --max-7d-hits 5
   ```
   exit 0 → proceed; exit 1 → STOP and read the residual-traffic block in §6.
3. Execute the 3 commits in §7 sequentially. Each one is mechanical
   text deletion at known file:line locations, ≤30 minutes total.
4. Rebuild + smoke test (§ Appendix step 5). If healthy, push and
   close ADR-V2-003 by flipping its status to `DONE` in
   `docs/design/v2-migration.md`.

If you came here from a calendar reminder set on 2026-04-29: the
contract was revised that same day to drop `/api/threat_data` from the
sunset list (see banner block immediately below). Only
`/api/scenario/<id>/breakdown` removal + machinery cleanup remain.

## ⚠️ 2026-04-29 contract revision — `/api/threat_data` REMOVED from sunset list

When PF7 inventory work probed the `latestData` consumer surface in
`radar.js`, it surfaced that the v2 successor route promised in
ADR-V2-003 (`/api/v2/scenarios/{id}/conclusions`) **cannot replace**
`/api/threat_data`. The two endpoints have completely incompatible
response shapes:

- `/api/threat_data` returns the HUD/Lane/map kitchen-sink envelope
  (`strategic_alert`, `scenarios`, `focused_scenario`, sensor caches,
  chain log, analytics — consumed at 14+ frontend sites).
- `/api/v2/scenarios/{id}/conclusions` returns ONLY scoring conclusions
  (state / confidence / formula_ref tuples per conclusion type).

The original contract was technically infeasible. Rather than rush a
multi-hour frontend rewrite to invent a non-existent v2 threat_data
successor before 2026-07-26, **`/api/threat_data` is removed from the
sunset list** and stays as a permanent operational endpoint (it is no
longer 'v1' in any meaningful sense — it just happens to predate the
`/api/v2/` scoring surface).

`SUNSETTED_V1_ROUTES` in `radar/conclusions/v1_sunset.py` now only
covers `/api/scenario/<id>/breakdown` (zero production hits, v2
conclusions endpoint is a genuine successor).

**Effect on this inventory**:
- §1.1 row for `/api/threat_data` no longer applies (route stays).
- §6 'frontend is still hitting /api/threat_data' is no longer a
  blocker — the route is permanent. radar.js:3873 stays.
- The 8 frontend `?? legacy_theater_*` fallbacks that were tied to the
  ADR-V2-003 sunset have been dropped early (they were safe to remove
  the moment backend dual-write was confirmed; the sunset wasn't
  actually gating them). Search for the previous `?? *theater` pattern
  in `radar.js` returns only 2 hits now, both on intel_queue row
  display fields which are on the separate SR4 / 2026-10-01 schedule.
- §7 LOC estimate drops from ~1,240 to ~600 (no /api/threat_data
  handler removal, no frontend fetch migration).
- Sunset day commit count drops from 5 to ~3.

**Pre-flight gate** (run on sunset day before any removal):

```bash
docker exec ddos-radar python /app/scripts/list_v1_routes.py --check-stale --max-7d-hits 5
# exit 0 → safe to proceed; exit 1 → abort, residual traffic still hitting v1
```

The two routes scoped for removal are the only ones carrying `Deprecation` /
`Sunset` / `Link` headers. Everything below is what needs to be deleted /
unconditionalized once that gate passes.

---

## Routes to remove (file:line list)

### 1. v1 superseded endpoints (the actual sunset surface)

| Route | File | Line | Notes |
|-------|------|------|-------|
| `GET /api/threat_data` | `radar/routes/core.py` | 502 | Successor: `/api/v2/scenarios/<id>/conclusions` |
| `GET /api/scenario/<id>/breakdown` | `radar/routes/core.py` | 265 | Successor: `/api/v2/scenarios/<id>/conclusions` |

These two are the only routes registered in `SUNSETTED_V1_ROUTES`
(`radar/conclusions/v1_sunset.py:28-39`). Other `/api/*` routes (history,
analyst, analytics, admin, intel) **stay** — they have no v2 successor and
were intentionally not promised a sunset.

### 2. Sunset machinery itself (delete after the routes are gone)

| File | Lines | Action |
|------|-------|--------|
| `radar/conclusions/v1_sunset.py` | full file (122 LOC) | DELETE |
| `radar/__init__.py` | 60-72 | DELETE `_v1_sunset_headers` after_request hook + import |
| `radar/legacy_telemetry.py` | 95-154, 99 (`_V1_SUNSET_KEY_PREFIX`), `summarize_v1_sunset` | Trim v1-sunset-specific helpers; `record_legacy_access` itself stays for SR4 (see §3) |
| `scripts/list_v1_routes.py` | full file (181 LOC) | DELETE — purpose-built for the sunset day pre-flight |
| `radar/scheduler.py` | 274-278 | KEEP the periodic `flush_to_db` (still needed for `theater` SR4) but consider removing the `summarize_v1_sunset` log if it was wired in |

### 3. SR4 `?theater=` legacy query param dual-read (optional, see §1.1 below)

The `?country=` / `?theater=` dual-read is a **separate** Safe Rename Pattern
(ADR-V2-006, A-3) on a different schedule (sunset 2026-10-01 per
`radar.js:147` comment). **Do NOT delete it in this PR** unless its own
telemetry shows zero hits — it covers a wider surface and was promised a
later removal date. Verify before deciding:

```bash
curl -sH "Authorization: Bearer $ADMIN_JWT" http://127.0.0.1:8000/api/admin/legacy_access \
  | jq '.items[] | select(.key | startswith("/api/") and endswith("?theater="))'
```

If clean (0 hits in trailing 30d), it can be folded into the same PR.
Otherwise leave for the 2026-10-01 sunset.

---

## Adapter / compat code to remove (file:line list)

### Backend dual-write payload keys (response shape)

| File | Line | Legacy key | New key | Action |
|------|------|------------|---------|--------|
| `radar/routes/core.py` | 2537, 2540 | `theater_success_rate` | `country_success_rate` | Drop legacy key from check_host envelope |
| `radar/routes/core.py` | 2570, 2572 | `theater_breakdown` | `country_breakdown` | Drop legacy key from telegram_mirror envelope |
| `radar/routes/core.py` | 2583, 2585 | `theater_data` | `country_data` | Drop legacy key from greynoise envelope |
| `radar/routes/core.py` | 2768 | `degraded_theaters` | `degraded_countries` | Confirm `degraded_countries` already dual-written; drop legacy |
| `radar/routes/analytics.py` | 92, 139 | `core_theater` | `core_country` | Drop legacy from `latest_strategic_signals` envelope |
| `radar/routes/analytics.py` | 236 | `theater` | `country` | Drop legacy from `/api/deep_analytics` |
| `radar/routes/analytics.py` | 666-668 | `theater` | `country` | Drop legacy from analytics envelope |

Search anchor for finding all dual-write sites: `git grep -n "ADR-V2-006 A-2"`.

### Backend `?theater=` query param dual-read

(See §1.3 — only delete if SR4 telemetry is clean for this surface.)

| File | Function | Calls `_country_param(...)` |
|------|----------|------------------------------|
| `radar/routes/__init__.py` | `_country_param` (43-62) | Helper to remove if dual-read goes away |
| `radar/routes/intel.py` | `api_intel_list` (33-47) | 1 call site |
| `radar/routes/analytics.py` | sequence_chain, deep_analytics | lines 157, 189 |
| `radar/routes/history.py` | timeseries, hod_baseline, sequence_events, export | lines 45, 79, 150, 194 |

### Intel queue `theater` kwarg fallback

| File | Lines | Action |
|------|-------|--------|
| `radar/intel_queue.py` | 460-477 (submit fallback) | Drop `theater` fallback once all sensors emit `countries=`. Telemetry key prefix `intel_queue.submit:` shows zero hits in the trailing 30d as the cutover gate |
| `radar/intel_queue.py` | 540-545, 631-634 (ex.theater fallback in dedupe) | Drop fallback after submit fallback is gone |
| `radar/intel_queue.py` | 696, 718, 850, 879, 893, 903, 924, 946, 965-967, 1079 | `theater` field in stored intel_queue rows + per-(source_type,theater) caps. Decide whether to rename column or just keep the internal name (zero external surface) |

### theater→country adapter — **does not exist as a discrete module**

There is no `theater_adapter.py` / `v1_compat.py` / `to_v1_response()` file.
The "adapter" is implemented as **dual-write inline** at the response-build
sites listed above (additive keys + legacy keys side-by-side). Removal is
purely "drop the legacy key from the literal dict at each site," not a
module unlink.

This is good news for the sunset day operator — no central refactor, just a
mechanical sed-able pass.

---

## Tests to delete (file list)

| File | LOC | Reason |
|------|-----|--------|
| `test_v1_sunset_headers.py` | 268 | Tests the sunset header machinery itself; module being deleted |
| `test_list_v1_routes.py` | 182 | Tests the pre-flight script; script being deleted |
| `test_country_param_dual_read.py` | 123 | DELETE only if §1.3 dual-read is also removed in this PR; otherwise KEEP |
| `test_legacy_telemetry.py` | 242 | KEEP base SR4 tests; may need light edits if `summarize_v1_sunset` helpers are removed |

Tests to **edit** (do not delete) — they may have v1 endpoint references
that need to be retargeted to the v2 successor:

```bash
# Find any test still hitting /api/threat_data or breakdown:
grep -l "/api/threat_data\|/api/scenario.*breakdown" /Users/juzo1192/git/DDoS-Radar/test_*.py
```

At inventory time: only `test_v1_sunset_headers.py` references these (and is
being deleted).

---

## Config to clean (env var list)

### Becomes unconditional on sunset day (removal of the env var)

| Env var | File | Line | Disposition |
|---------|------|------|-------------|
| `V2_API_ENABLED` | `radar/config.py` | 231 | Default flipped to `true` on 2026-04-26. After sunset, remove the gate entirely (not the flag — *the conditional check*). Drop `_v2_enabled_or_503()` (`radar/routes/conclusions_v2.py:55-65`) and all 4 callers in that file. Drop the example block in `config.env.example` |
| `V2_CONCLUSION_LEDGER_ENABLED` | `radar/config.py` | 213 | Mode B was the rollout mechanism. After sunset, decide: (a) leave default `false` (keep gate as kill-switch) OR (b) make ledger-write unconditional. Recommendation: **keep as kill-switch** — Phase 4 acceptance does not require its removal, and ledger writes are still the source of truth for v2. The 5 `_maybe_persist_*` hooks (`radar/scoring.py:1180-1299`) become single-branch (`if False:` blocks deletable) only if you choose (b) |

### Stays as-is

| Env var | Why it stays |
|---------|--------------|
| `V2_CONCLUSION_DIFF_SAMPLER_ENABLED` | `radar/config.py:239` — already optional, can remain off-by-default for ad-hoc divergence checks |
| `V2_LLM_PROMPT_PERSISTENCE_ENABLED` | `radar/config.py:222` — separate ADR-V2-009 lifecycle |
| `V2_TREND_ENABLED` / `V2_PER_DOMAIN_ENABLED` / `V2_ATTACK_MODE_ENABLED` / `V2_CONTINUITY_LOG_ENABLED` | `radar/config.py:246-249` — per-conclusion-type kill switches by design (ADR-V2-008 §10.3) |

### `config.env.example` lines to clean

```
299  # Required for V2_API_ENABLED to serve any data.
308  V2_API_ENABLED=false
399  V2_CONCLUSION_LEDGER_ENABLED=true
402  #   V2_API_ENABLED=false                     # public API still off
406  #   How to verify: GET /api/v2/admin/shadow_write_metrics (admin auth)
415  #   All Mode B flags + V2_API_ENABLED=true. /api/v2/* routes serve data
```

The Mode A/B/C narrative block (~lines 380-420) becomes historical and can
be collapsed to a single "v2 is the public API; v1 was retired 2026-07-26"
line.

---

## Frontend to simplify (file:line list)

There is **no `if (api_version === 'v1')` fork in the frontend**. The
client was rewritten to call `/api/v2/*` for conclusions/audit/replay
during Phase 1.4 and never branched on api_version.

What remains is **`a ?? b` dual-key reads** of response payloads. Once
backend dual-write is dropped, the `?? legacy` fallbacks become dead.

| File | Line | Pattern | Action |
|------|------|---------|--------|
| `radar.js` | 147-148 | comment block referencing "backend deprecation (sunset 2026-10-01)" | Update comment date OR delete |
| `radar.js` | 166 | `((strat.core_country ?? strat.core_theater) || '').toUpperCase()` | Drop `?? strat.core_theater` |
| `radar.js` | 350-352 | `gn.country_data ?? gn.theater_data` | Drop `?? gn.theater_data` |
| `radar.js` | 669-672 | `tg.country_breakdown ?? tg.theater_breakdown ?? {}` | Drop `?? tg.theater_breakdown` |
| `radar.js` | 1036-1037 | `ch.country_success_rate ?? ch.theater_success_rate` | Drop `?? ch.theater_success_rate` |
| `radar.js` | 4500-4501 | `strat.degraded_countries ?? strat.degraded_theaters` | Drop `?? strat.degraded_theaters` |
| `radar.js` | 1847, 1904, 1928 | `strat.active_theaters` | **CHECK** — there is no dual-write `active_countries` yet. Either backend adds it pre-cutover OR frontend keeps reading `active_theaters` (rename is incomplete here) |

The single `/api/threat_data` reference at `radar.js:3873` (`const apiUrl =
\`/api/threat_data?...\``) must either:

- be migrated to `/api/v2/scenarios/<focus>/conclusions` **before** sunset day, OR
- the frontend stops calling it (already true if v2 fetch at `radar.js:1991`
  has fully replaced this code path — verify by tracing the call site of the
  `apiUrl` variable).

This is the **largest open item**. See "Blockers" below.

---

## Production access pattern (analysis of legacy_access_log)

DB row count: **1**.

```
key:                  v1_sunset_route:/api/threat_data
count:                106
first_seen:           2026-04-26 09:40:39 UTC  (Mode C activation)
last_seen:            2026-04-29 01:38:15 UTC  (less than 24h before this inventory)
```

**Reading the row:**

- 106 hits / ~3 days ≈ **~35 hits/day**, steady. This is almost certainly the
  app's own frontend polling — no external clients.
- `/api/scenario/<id>/breakdown` has **zero hits**. Safe to remove without
  observation.
- `/api/threat_data` is **still being hit by the production frontend**. The
  fetch call at `radar.js:3873` is live. Sunset cannot be a pure "drop the
  route" — the frontend must move first or in the same PR.

**Implication for sunset day**: the `--check-stale --max-7d-hits 5` gate
**will fail at current cadence** unless either (a) the frontend is migrated
off `/api/threat_data` before sunset day, or (b) the gate is run after
deploying a frontend fix.

This is the single most important blocker; see below.

---

## Estimated removal effort (LOC + commit count breakdown)

### LOC to delete

| Surface | Files | LOC removed |
|---------|-------|-------------|
| `radar/conclusions/v1_sunset.py` | 1 | 122 |
| `scripts/list_v1_routes.py` | 1 | 181 |
| `test_v1_sunset_headers.py` | 1 | 268 |
| `test_list_v1_routes.py` | 1 | 182 |
| `_v1_sunset_headers` hook in `radar/__init__.py` | 1 | ~13 |
| `legacy_telemetry.summarize_v1_sunset` + helpers | 1 | ~60 |
| `/api/threat_data` route handler | `radar/routes/core.py` | ~250 (large handler) |
| `/api/scenario/<id>/breakdown` route handler | `radar/routes/core.py` | ~80 |
| Backend dual-write legacy keys (8 sites in core.py + analytics.py) | 2 | ~12 (one line each) |
| Frontend `?? legacy` fallbacks (6 sites in radar.js) | 1 | ~6 |
| `_v2_enabled_or_503` and 4 callers | `radar/routes/conclusions_v2.py` | ~25 |
| `config.env.example` Mode A/B/C block | 1 | ~40 |
| **Total** | **~10 files** | **~1,240 LOC** |

### Commits (recommended sequencing)

The work splits cleanly into **5 atomic commits**, runnable in 1-2 hours
sequentially:

1. **`feat: migrate frontend off /api/threat_data → /api/v2/scenarios/<id>/conclusions`**
   *(prerequisite — must land and deploy before sunset day, or first commit
   on sunset day)*
   `radar.js:3873` + downstream consumer of `latestData`. Verify no
   regressions in HUD/Lane rendering. ~150 LOC churn.

2. **`refactor: drop frontend ?? legacy theater key fallbacks`**
   `radar.js`: 6 sites listed above. Pure deletion. ~6 LOC removed.

3. **`refactor: drop backend dual-write legacy theater keys`**
   `radar/routes/core.py` + `radar/routes/analytics.py`: 8 sites. Drop
   `theater_*` keys, keep `country_*`. ~12 LOC removed.

4. **`feat: remove v1 superseded routes (ADR-V2-003 sunset)`**
   - Delete `radar/conclusions/v1_sunset.py`, `scripts/list_v1_routes.py`,
     `test_v1_sunset_headers.py`, `test_list_v1_routes.py`.
   - Delete `_v1_sunset_headers` after_request hook from `radar/__init__.py`.
   - Delete `/api/threat_data` and `/api/scenario/<id>/breakdown` handlers
     from `radar/routes/core.py`.
   - Delete `summarize_v1_sunset` + `_V1_SUNSET_KEY_PREFIX` from
     `radar/legacy_telemetry.py` (keep `record_legacy_access` for SR4).
   - Delete `_v2_enabled_or_503` and its 4 call sites in
     `radar/routes/conclusions_v2.py`.
   - ~700 LOC removed, all under green CI.

5. **`docs: archive v1-sunset-inventory + close ADR-V2-003`**
   - Move this file to `docs/_archive/v1-sunset-inventory.md`.
   - Update `docs/design/v2-migration.md` Phase 4 row from "進行中" to
     "完了 (2026-07-26)" + bump the legend table.
   - Update `config.env.example` Mode A/B/C narrative.

### Total estimated wall time

| Step | Time |
|------|------|
| Pre-flight `--check-stale` gate | 1 min |
| Commit 1 (frontend migration; should be **done before sunset day**) | 30-60 min if not already done |
| Commits 2-3 (mechanical legacy-key drops) | 15 min |
| Commit 4 (v1 route + machinery removal) | 30 min |
| Commit 5 (docs) | 15 min |
| Container rebuild + smoke (login + v2 fetch + audit_trace) | 15 min |
| **Total** | **~1.5h** if commit 1 is pre-staged; **~2.5h** otherwise |

---

## Blockers / surprises that need attention before sunset day

1. **CRITICAL — frontend is still hitting `/api/threat_data` at ~35
   hits/day.** `radar.js:3873`. The pre-flight `--check-stale` gate will
   **fail at default tolerance (5 hits in 7 days)** because the production
   UI is the caller. Either:
   - migrate the frontend fetch to `/api/v2/scenarios/<focus>/conclusions`
     in a separate PR landing 7+ days before 2026-07-26 (so the 7-day
     window is clean), OR
   - run sunset day commits in this exact order: frontend migration →
     deploy → wait for any cached client tabs to refresh → backend route
     removal. **Inventory recommends the former** so the gate is
     meaningful, not bypassed.

2. **SR4 dual-read for `?theater=` is on a separate clock (2026-10-01).**
   Do not conflate it with the route sunset. The two `legacy_access_log`
   prefixes (`v1_sunset_route:` vs `<endpoint>?theater=` /
   `intel_queue.submit:`) live in the same table but track different
   contracts. Confirm SR4 telemetry separately before bundling it.

3. **`active_theaters` has no `active_countries` dual-write yet** (radar.js
   reads it at lines 1847, 1904, 1928 with no `??` fallback to a country
   key). The Safe Rename Pattern for that field is incomplete. Decide
   pre-sunset:
   - keep `active_theaters` as the canonical key (rename is partial), OR
   - add `active_countries` dual-write in the same backend hot-path commit
     and update frontend in commit 2 above.

4. **`/api/v2/admin/shadow_write_metrics` is intentionally NOT gated by
   `V2_API_ENABLED`** (see `radar/routes/conclusions_v2.py:394-397`
   comment). Confirm whether its `ledger_enabled` field is still useful
   after sunset; if `V2_CONCLUSION_LEDGER_ENABLED` is also retired, the
   route reports a constant `true`. Probably fine to leave as-is.

5. **No discrete `theater_adapter.py` module exists.** The "adapter
   layer" promised in `v2-migration.md` Appendix B is implemented as
   inline dual-write at ~10 sites. This is actually easier to remove
   (no central seam to break), but the operator should not look for a
   single module to delete.

6. **`scenario-refactor.md` is already archived** (per Phase 4 plan,
   `docs/_archive/scenario-refactor-v1.8.1.md`). No additional doc move
   required for that file.

7. **Telemetry inventory is shallow at 1 row**, but that's by design: the
   canonical-key collapse (`<id>` placeholder) means **every** breakdown
   call across all scenarios is one key, and there are 0 hits there. The
   single row is the only signal; trust it.

---

## Appendix: pre-flight commands (copy-paste on sunset day)

```bash
# 1. Telemetry gate (must exit 0)
docker exec ddos-radar python /app/scripts/list_v1_routes.py --check-stale --max-7d-hits 5

# 2. Confirm no test still references /api/threat_data outside the to-be-deleted test
grep -l "/api/threat_data\|/api/scenario.*breakdown" /Users/juzo1192/git/DDoS-Radar/test_*.py

# 3. Confirm frontend has no remaining v1 fetch
grep -n "/api/threat_data\b" /Users/juzo1192/git/DDoS-Radar/radar.js /Users/juzo1192/git/DDoS-Radar/index.html

# 4. Confirm no sensor still emits theater= without countries=
docker exec ddos-radar python -c "
import sqlite3
c = sqlite3.connect('radar/persistence/radar.db')
for r in c.execute('SELECT key, count, last_seen FROM legacy_access_log WHERE key LIKE ? OR key LIKE ?', ('intel_queue.submit:%', '%?theater=')):
    print(r)
"

# 5. Smoke after the removal commits land
curl -sH "Authorization: Bearer $JWT" http://127.0.0.1:8000/api/v2/scenarios/taiwan_contingency/conclusions | jq '.api_version, (.conclusions|length)'
curl -sI -H "Authorization: Bearer $JWT" http://127.0.0.1:8000/api/threat_data  # expect 404
```

---

*Generated 2026-04-29 for the 2026-07-26 v1 sunset routine. Treat as
operator checklist; deviation requires re-reading `docs/design/v2-migration.md`
§Phase 4 first.*
