# Tradecraft Panel QA Guide

Scope: the Analyst Tradecraft surface (`/api/analyst/*` and the F4–F14 UI in
[tradecraft.js](../../tradecraft.js)). This document describes the manual QA
workflow, automated regression tests, and smoke check script that together
gate any deployment that touches the tradecraft layer.

Owner: analyst-facing features under ADR-006 (analyst judgment support, not
substitution).

---

## 1. What the tradecraft panel covers

| Feature | Technique / Source | Endpoint |
|---------|-------------------|----------|
| F4  Hidden Negative Signals    | coverage-gap view                    | `GET /api/analyst/hidden_signals` |
| F5  Coverage Gap               | sensor health per scenario           | `GET /api/analyst/coverage` |
| F6  Disconfirming Evidence     | explicit anti-hypothesis tagging     | `GET/POST/DELETE /api/analyst/disconf` |
| F7  Scenario Comparison        | side-by-side ScenarioState           | `GET /api/scenarios/compare` |
| F8  ACH Matrix                 | Heuer ACH (Tradecraft Primer)        | `GET/POST /api/analyst/ach` |
| F9  What-If Weight Slider      | participant-weight simulation        | `POST /api/scenarios/<id>/whatif_weights` |
| F10 Key Assumptions Check      | KAC; admin-only lock/unlock          | `GET/POST/PATCH /api/analyst/assumptions` |
| F11 Pre-Mortem (Klein, 2007)   | failure-mode enum, imagined outcome  | `GET/POST /api/analyst/premortem` |
| F13 Dissenting Views           | Devil's Advocacy                     | `GET/POST /api/analyst/dissent` |
| F14 Decision Ledger            | per-tab session_id audit trail       | `GET/POST /api/analyst/decisions` |

All write endpoints under `/api/analyst/*` carry a **tab-unit `session_id`**
(UUID generated per browser tab, stored in `sessionStorage`). F14 records one
row per analyst action; F6/F8/F10/F11/F13 write-through into F14 as well so
the ledger is a complete audit of tradecraft activity.

---

## 2. Role gates

| Role    | Read `/api/analyst/*` | Write F6/F8/F10/F11/F13 | Lock/Unlock F10 |
|---------|----------------------|-------------------------|-----------------|
| viewer  | 403                  | 403                     | 403             |
| analyst | 200                  | 200                     | 403 (admin-only)|
| admin   | 200                  | 200                     | 200             |

The gate is enforced in `radar/routes/__init__.py::_require_analyst` and
`_require_admin`, called at the top of every handler.

---

## 3. Decision-ledger write-through

Every tradecraft write endpoint appends a row to `decision_ledger` with
`detail.auto = true`. This gives a single audit stream for all tradecraft
activity without forcing analysts to remember to log each action manually.

**Marker:** `detail.auto === true` distinguishes auto-logged rows from
manual F14 entries. The decisions tab has a toggle
("Show auto-logged tradecraft actions") to filter the view.

**Session scoping:** when the frontend passes `session_id`, it is preserved
verbatim in the auto-logged row. If absent, the backend synthesizes
`auto:<decision_type>` so every row still has a queryable session label.

**Decision types** emitted by write-through:

| Source endpoint                                       | decision_type         |
|-------------------------------------------------------|-----------------------|
| POST `/api/analyst/disconf`                           | `disconf_add`         |
| POST `/api/analyst/disconf/<id>/retract`              | `disconf_retract`     |
| POST `/api/analyst/ach`                               | `ach_create`          |
| POST `/api/analyst/ach/<mid>/hypothesis`              | `ach_hypothesis_add`  |
| POST `/api/analyst/ach/<mid>/evidence`                | `ach_evidence_add`    |
| POST `/api/analyst/ach/<mid>/score`                   | `ach_score_set`       |
| POST `/api/analyst/assumptions`                       | `assumption_add`      |
| PATCH `/api/analyst/assumptions/<id>`                 | `assumption_edit`     |
| POST `/api/analyst/assumptions/<id>/lock` (lock=true) | `assumption_lock`     |
| POST `/api/analyst/assumptions/<id>/lock` (lock=false)| `assumption_unlock`   |
| POST `/api/analyst/assumptions/<id>/invalidate`       | `assumption_invalidate` |
| POST `/api/analyst/premortem`                         | `premortem_add`       |
| POST `/api/analyst/premortem/<id>/resolve`            | `premortem_resolve`   |
| POST `/api/analyst/dissent`                           | `dissent_add`         |
| POST `/api/analyst/dissent/<id>/resolve`              | `dissent_resolve`     |

---

## 4. Automated tests

`test_analyst_permissions.py` (18 tests):

1. **Role gates (7 tests)** — viewer blocked from every endpoint, analyst
   allowed on non-admin endpoints, analyst blocked on `assumption/lock`,
   admin allowed on `assumption/lock`.
2. **Session filter (1)** — posting decisions with session `X` and querying
   with `?session_id=X` returns only those rows.
3. **Write-through (6)** — POSTing to F6/F8/F10/F11/F13 endpoints produces a
   `decision_ledger` row with `detail.auto == true`.
4. **Manual decision purity (1)** — direct POST to `/api/analyst/decisions`
   must NOT be marked `auto=true`.
5. **Ledger immutability (2)** — DELETE and PATCH on
   `/api/analyst/decisions/<id>` return 404/405 (append-only by design).

Run locally:

```bash
python -m pytest tests/test_analyst_permissions.py -v
```

Expected result: **18 passed**.

---

## 5. Post-deploy smoke check

[scripts/smoke_tradecraft.sh](../../scripts/smoke_tradecraft.sh) exercises
every major code path against a running instance. Use it after any
`docker compose build && docker compose up -d` that touches analyst.py,
tradecraft.js, i18n.js, or tradecraft.css.

Prerequisites:

- Three users: `admin`, one analyst, one viewer (create via
  `/api/auth/register` as admin if they don't exist).
- `jq` installed.

```bash
BASE_URL=http://127.0.0.1:8000 \
ADMIN_USER=admin ADMIN_PW='...' \
ANALYST_USER=tc_smoke_analyst ANALYST_PW='...' \
VIEWER_USER=tc_smoke_viewer VIEWER_PW='...' \
SCENARIO_ID=taiwan_contingency \
./scripts/smoke_tradecraft.sh
```

The script checks:

1. Admin/analyst/viewer can all authenticate.
2. Analyst GETs every read endpoint (7 endpoints) → 200.
3. Viewer POSTs to writes (3 probes) → 403.
4. Analyst POSTs a disconf and the F14 query for that session returns
   at least one row with `detail.auto == true`.
5. Analyst lock returns 403, admin lock returns 200.
6. Manual F14 POST produces a row with `detail.auto ≠ true`.

Exit code 0 on success. On failure it prints the HTTP body for debugging.

---

## 6. Manual UI checklist

After a tradecraft-related deploy, walk through the panel as an analyst:

1. Open tradecraft panel; all 10 tabs (F4, F5, F6, F7, F8, F9, F10, F11,
   F13, F14) render without JS console errors.
2. **F6 Disconfirming** — add a note; strength dropdown shows 1–5; row
   appears with correct attribution and timestamp.
3. **F8 ACH** — create a matrix; add hypotheses (including one marked as
   null hypothesis); add evidence with credibility and relevance 1–5;
   click matrix cells to set consistency −2..+2; diagnostic scores update.
4. **F9 What-If** — sliders render from 0.0 to 1.0 for each participant;
   RUN button triggers `/api/scenarios/<id>/whatif_weights`; baseline vs.
   simulated TL and score show deltas; read-only notice visible.
5. **F10 Assumptions** — add an assumption; confidence dropdown shows
   low/medium/high; lock attempt as analyst → 403 error in UI; as admin
   → lock icon appears; change log shows entries with author, action,
   timestamp.
6. **F11 Pre-Mortem** — add an entry with failure_mode = FP/FN/bias;
   imagined outcome, root cause, early warning, mitigation fields render;
   resolve confirmation dialog appears; resolved rows are visually dimmed.
7. **F13 Dissent** — file a dissenting view; argues_for_tl dropdown 1–5
   with "none"; resolve button adds resolution note.
8. **F14 Decisions** — toggle "Show auto-logged tradecraft actions" hides
   rows with the `auto` badge; manual entries still show; rationale
   appears under summary in mini-meta.
9. **Language switch** — toggle EN↔JA; every label in the tradecraft
   panel is translated; no raw i18n keys like `panel.tradecraft…` leak.

---

## 7. Known gotchas

- **Docker layer cache trap**: frontend files (tradecraft.js, i18n.js,
  tradecraft.css, index.html) must be rebuilt explicitly after edits.
  Always use `docker compose build --no-cache` for tradecraft-touching
  deploys.
- **Session ID scope**: the `session_id` is per-tab. Opening the panel in
  a new tab gets a new UUID. This is intentional (F14 design choice).
- **Auto-logged detail payload**: includes a fixed `auto: true` plus the
  endpoint-specific payload (ids, text, credibility/relevance, etc.).
  Consumers should treat it as opaque JSON — new fields may be added.
- **DB presets vs store**: preset scenarios live in the in-memory
  `ScenarioStore`, not the DB table. `db.scenario_list()` only returns
  admin-created scenarios; use `scenario_store.all()` for the full set.

---

## 8. Related documents

- [docs/design/v2-migration.md](./v2-migration.md) — current v2.0 design (the
  scenario-unit refactor that the tradecraft layer operates on top of).
- [docs/_archive/scenario-refactor-v1.8.1.md](../_archive/scenario-refactor-v1.8.1.md)
  — frozen v1 reference, retained for history only.
- [CLAUDE.md](../../CLAUDE.md) — project-wide conventions, i18n rules,
  layer boundaries.
