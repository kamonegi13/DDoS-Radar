"""Pure scenario-mutation primitive for analyst-confirmed and (Phase 3+)
auto-applied scenario_improver / scenario_structure_proposer proposals.

Background — the seam this closes
---------------------------------
Until 2026-05-08 the analyst Apply route
(``POST /api/v2/proposals/scenario_improver/<id>/apply``) only flipped
the proposal ledger row to ``state='applied'`` via
``scenario_improver.update_state()``. **It did not mutate the
scenarios / scenario_participants tables.** The wizard button thus
recorded an analyst's decision without acting on it.

This module provides the missing primitive. Both the analyst route
(refactored in Phase 1) and the future tier-governor-gated auto-apply
path (Phase 3) call ``apply_scenario_improver_proposal`` so the
mutation is identical regardless of who triggered it.

The mutation goes through the existing ``db.scenario_upsert`` API,
which already:
- writes the layer-2 override (scenarios + scenario_participants)
- records the change in ``scenario_change_log`` (NP6 audit)
- is the same code path the admin scenario edit endpoints use

After mutation we call ``_reload_scenario_store_and_invalidate_cache``
so the next scoring pass picks up the new participant set.

Supported proposal types
------------------------
- ``weight_too_low``    : participants[target].weight ← suggested.weight
- ``weight_too_high``   : participants[target].weight ← suggested.weight
- ``missing_participant``: add participants[target] = {weight, role}
- ``dormant_participant``: participants[target].weight ← suggested.weight_to
- ``role_reclassify``   : participants[target].role ← suggested.role_to

NEVER auto-applied (NP7 — organizational scenario lifecycle):
- ``scenario_discovery`` — proposes new scenarios
- diagnostic types (``sensor_gap_detected``, ``scenario_dormant``,
  ``needs_more_data``) — informational, no apply path
- ``sensor_disable`` — governed by Phase D pipeline, not this seam

NP3 contract: every helper returns an ``ApplyResult`` with ``ok=False``
on every error path. The proposal ledger row is left untouched on
failure so the analyst (or auto-apply caller) can retry.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("radar.calibration.scenario_apply")


_SUPPORTED_TYPES = frozenset({
    "weight_too_low",
    "weight_too_high",
    "missing_participant",
    "dormant_participant",
    "role_reclassify",
})


@dataclass(frozen=True)
class ApplyResult:
    ok: bool
    proposal_id: int
    proposal_type: str = ""
    scenario_id: str = ""
    target_country: Optional[str] = None
    mutation: Optional[dict] = None  # {"old": ..., "new": ...}
    error: Optional[str] = None


def _reload_scenario_store_and_invalidate_cache() -> None:
    """Mirror of ``radar.routes.admin._scenario_reload_and_invalidate_cache``.

    Duplicated rather than imported to avoid pulling routes into the
    calibration package (cyclic risk: routes → calibration → routes).
    Both copies must do exactly the same thing; if the admin one
    changes (e.g. additional cache layers), update this one too.
    """
    try:
        from radar.scenarios import scenario_store
        from radar import state as _st
        from radar.state import _global_cache_lock
        scenario_store.reload()
        with _global_cache_lock:
            if isinstance(_st.global_cache, dict):
                _st.global_cache["time"] = 0
    except Exception as exc:
        log.warning("scenario_store reload failed (non-fatal): %s", exc)


def apply_scenario_improver_proposal(
    proposal_id: int, *, applied_by: str,
) -> ApplyResult:
    """Apply a pending scenario_proposals row to the live scenario_store.

    Loads the proposal, computes the mutation against the current
    scenario state (NOT against the state at emit time — guards may
    have shifted), invokes ``db.scenario_upsert`` to persist, reloads
    scenario_store, then marks the proposal ``state='applied'``.

    Returns an ``ApplyResult`` describing what happened. ``ok=False``
    cases:
      - proposal not found
      - proposal not in 'pending' state
      - proposal_type not in _SUPPORTED_TYPES
      - target scenario missing or not active
      - mutation rejected by validate_participant
      - DB write failed
    """
    from radar.database import db
    conn = db._get_conn()  # noqa: SLF001

    # ── 1. Load proposal row ──────────────────────────────────────────
    try:
        prow = conn.execute(
            "SELECT id, scenario_id, proposal_type, target_country, "
            "       suggested_value_json, state "
            "FROM scenario_proposals WHERE id=?",
            (int(proposal_id),),
        ).fetchone()
    except Exception as exc:
        return ApplyResult(ok=False, proposal_id=proposal_id,
                           error=f"db_read_failed: {exc}")
    if prow is None:
        return ApplyResult(ok=False, proposal_id=proposal_id,
                           error="proposal_not_found")
    if prow["state"] != "pending":
        return ApplyResult(
            ok=False, proposal_id=proposal_id,
            proposal_type=prow["proposal_type"],
            scenario_id=prow["scenario_id"],
            target_country=prow["target_country"],
            error=f"proposal_not_pending (state={prow['state']})",
        )
    ptype = prow["proposal_type"]
    if ptype not in _SUPPORTED_TYPES:
        return ApplyResult(
            ok=False, proposal_id=proposal_id,
            proposal_type=ptype,
            scenario_id=prow["scenario_id"],
            target_country=prow["target_country"],
            error=f"unsupported_proposal_type ({ptype})",
        )
    try:
        suggested = json.loads(prow["suggested_value_json"] or "{}")
    except Exception as exc:
        return ApplyResult(ok=False, proposal_id=proposal_id,
                           proposal_type=ptype,
                           scenario_id=prow["scenario_id"],
                           target_country=prow["target_country"],
                           error=f"suggested_value_json_invalid: {exc}")

    # ── 2. Load target scenario (must be active) ──────────────────────
    sc = db.scenario_get(prow["scenario_id"])
    if sc is None:
        return ApplyResult(ok=False, proposal_id=proposal_id,
                           proposal_type=ptype,
                           scenario_id=prow["scenario_id"],
                           target_country=prow["target_country"],
                           error="scenario_not_found")
    if sc.get("state") != "active":
        return ApplyResult(
            ok=False, proposal_id=proposal_id,
            proposal_type=ptype, scenario_id=prow["scenario_id"],
            target_country=prow["target_country"],
            error=f"scenario_not_active (state={sc.get('state')})",
        )

    # ── 3. Compute mutation ───────────────────────────────────────────
    target = prow["target_country"]
    participants = dict(sc.get("participants") or {})
    mutation_old: dict = {}
    mutation_new: dict = {}

    if ptype in ("weight_too_low", "weight_too_high"):
        if not target:
            return _err(proposal_id, ptype, prow,
                        "target_country_required")
        if target not in participants:
            return _err(proposal_id, ptype, prow,
                        f"target_not_a_participant ({target})")
        new_w = suggested.get("weight")
        if not isinstance(new_w, (int, float)):
            return _err(proposal_id, ptype, prow,
                        "suggested.weight not numeric")
        mutation_old = {target: dict(participants[target])}
        participants[target] = {
            "weight": float(new_w),
            "role": participants[target].get("role"),
        }
        mutation_new = {target: dict(participants[target])}

    elif ptype == "missing_participant":
        if not target:
            return _err(proposal_id, ptype, prow,
                        "target_country_required")
        if target in participants:
            return _err(proposal_id, ptype, prow,
                        "target_already_participant")
        new_w = suggested.get("weight", 0.30)
        new_role = suggested.get("role", "strategic_observer")
        mutation_old = {target: None}
        participants[target] = {"weight": float(new_w),
                                "role": str(new_role)}
        mutation_new = {target: dict(participants[target])}

    elif ptype == "dormant_participant":
        if not target or target not in participants:
            return _err(proposal_id, ptype, prow,
                        "target_not_a_participant")
        new_w = suggested.get("weight_to")
        if not isinstance(new_w, (int, float)):
            return _err(proposal_id, ptype, prow,
                        "suggested.weight_to not numeric")
        mutation_old = {target: dict(participants[target])}
        participants[target] = {
            "weight": float(new_w),
            "role": participants[target].get("role"),
        }
        mutation_new = {target: dict(participants[target])}

    elif ptype == "role_reclassify":
        if not target or target not in participants:
            return _err(proposal_id, ptype, prow,
                        "target_not_a_participant")
        new_role = suggested.get("role_to")
        if not new_role or not isinstance(new_role, str):
            return _err(proposal_id, ptype, prow,
                        "suggested.role_to required")
        mutation_old = {target: dict(participants[target])}
        participants[target] = {
            "weight": participants[target].get("weight"),
            "role": str(new_role),
        }
        mutation_new = {target: dict(participants[target])}

    # ── 4. Validate mutated participants ──────────────────────────────
    try:
        from radar.scenarios import validate_participant
        for cc, pdata in participants.items():
            validate_participant(cc, pdata, prow["scenario_id"])
    except Exception as exc:
        return _err(proposal_id, ptype, prow,
                    f"validation_failed: {exc}")

    # ── 5. Persist via scenario_upsert ────────────────────────────────
    merged = {
        "name_en":        sc.get("name_en") or prow["scenario_id"],
        "name_ja":        sc.get("name_ja") or prow["scenario_id"],
        "description_en": sc.get("description_en") or "",
        "description_ja": sc.get("description_ja") or "",
        "core_country":   sc.get("core_country"),
        "state":          sc.get("state", "active"),
        "enabled":        bool(sc.get("enabled", True)),
        "tier":           sc.get("tier", 1),
        "participants":   participants,
    }
    try:
        db.scenario_upsert(prow["scenario_id"], merged,
                           changed_by=applied_by)
    except Exception as exc:
        return _err(proposal_id, ptype, prow,
                    f"scenario_upsert_failed: {exc}")

    # ── 6. Reload scenario_store ──────────────────────────────────────
    _reload_scenario_store_and_invalidate_cache()

    # ── 7. Mark proposal applied ──────────────────────────────────────
    try:
        with conn.writing():
            conn.execute(
                "UPDATE scenario_proposals SET state='applied', "
                "state_changed_at=?, state_changed_by=? "
                "WHERE id=? AND state='pending'",
                (time.time(), applied_by, int(proposal_id)),
            )
    except Exception as exc:
        # Mutation already persisted; the ledger flip failure leaves
        # the row at 'pending'. NP3-tolerant: log + return ok=False so
        # the caller knows. The scenario itself is now correct.
        log.warning("ledger flip failed after successful mutation: %s",
                    exc)
        return ApplyResult(
            ok=False, proposal_id=proposal_id,
            proposal_type=ptype, scenario_id=prow["scenario_id"],
            target_country=target,
            mutation={"old": mutation_old, "new": mutation_new},
            error=f"ledger_flip_failed_after_mutation: {exc}",
        )

    log.info(
        "[ScenarioApply] applied proposal_id=%d type=%s scenario=%s "
        "target=%s by=%s",
        proposal_id, ptype, prow["scenario_id"], target, applied_by,
    )
    return ApplyResult(
        ok=True, proposal_id=proposal_id,
        proposal_type=ptype, scenario_id=prow["scenario_id"],
        target_country=target,
        mutation={"old": mutation_old, "new": mutation_new},
    )


def _err(proposal_id, ptype, prow, msg) -> ApplyResult:
    return ApplyResult(
        ok=False, proposal_id=proposal_id,
        proposal_type=ptype, scenario_id=prow["scenario_id"],
        target_country=prow["target_country"], error=msg,
    )
