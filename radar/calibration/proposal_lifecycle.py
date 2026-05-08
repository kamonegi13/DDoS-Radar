"""Mechanical lifecycle transitions for scenario_proposals.

The original 2026-05-07 backlog audit identified two pending-decision
states whose resolution is **mechanical**, not statistical, and
therefore can be automated without waiting for data accumulation:

  D1: pending proposal on an inactive (paused / archived) scenario
      → auto-dismiss with state_changed_by='auto:inactive_scenario'
      The wizard cannot apply such a proposal (apply path checks
      scenario state), so it is a dead-letter. Operator's choice to
      pause/archive the scenario is the judgment; this module just
      propagates it.

  D2: a new pending proposal of the same (scenario_id, proposal_type,
      target_country) as an existing pending row supersedes the older
      → mark the older with state='superseded' and
      state_changed_by=f'auto:supersede_by_id_<new_id>'.
      Mechanical: a calibrator emitting a fresh row is, by
      construction, the new authoritative version.

Both transitions write through to the schema's existing state vocab
(``CHECK (state IN ('pending','applied','dismissed','snoozed_30d',
'reverted','superseded'))`` per migration v28) so no migration is
needed. NP6 trail: every transition records ``state_changed_by`` so
``GET /api/v2/threshold_history/<id>/lineage`` and the SETTINGS
audit.feedback / audit.changes pages can reconstruct who or what
moved a proposal.

NP3: every helper swallows DB errors and returns 0. The scheduler
hook treats the count as informational.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("radar.calibration.proposal_lifecycle")


_INACTIVE_SCENARIO_STATES = ("paused", "archived")


def auto_dismiss_inactive_scenario_proposals() -> int:
    """Mark every ``pending`` scenario_proposal whose target scenario
    is paused / archived as ``dismissed``. Returns the number of rows
    transitioned. Idempotent — second call within the same tick is a
    no-op because the WHERE clause re-checks state='pending'."""
    from radar.database import db
    try:
        conn = db._get_conn()  # noqa: SLF001
        # SQLite UPDATE … FROM is supported since 3.33; older builds
        # would need the IN-subquery dance, which we use to stay
        # portable.
        rows = conn.execute(
            "SELECT sp.id FROM scenario_proposals sp "
            "JOIN scenarios s ON s.id = sp.scenario_id "
            "WHERE sp.state='pending' "
            "AND s.state IN ('paused','archived')"
        ).fetchall()
        ids = [int(r[0]) for r in rows]
        if not ids:
            return 0
        now = time.time()
        with conn.writing():
            placeholders = ",".join("?" for _ in ids)
            conn.execute(
                "UPDATE scenario_proposals SET state='dismissed', "
                "state_changed_at=?, "
                "state_changed_by='auto:inactive_scenario' "
                f"WHERE id IN ({placeholders}) AND state='pending'",
                (now, *ids),
            )
        return len(ids)
    except Exception as exc:
        log.warning("auto_dismiss_inactive_scenario_proposals failed: %s",
                    exc)
        return 0


# ── D4: reprocess existing pending through the Phase 3 gate ──────────────────
#
# Phase 3 wired the auto-apply gate at the *emit* point (scenario_improver._emit).
# Rows that were already in state='pending' before the flag was flipped on
# never re-enter that path — the dedup window blocks the proposer from
# re-emitting them, so they sit in the ledger forever even when the tier
# governor has reached a level that would have auto-applied them.
#
# D4 (2026-05-08) drips those existing rows through the same gate the new
# emissions go through. The drip rate is intentionally slow:
#
# - REPROCESS_MAX_PER_TICK caps applies per scheduler call so a sudden
#   T1 → T3 promotion doesn't fire a flood. Tier governor metrics
#   (revert_rate, diff_log_match_rate) need a tick or two to react before
#   the next batch.
#
# - REPROCESS_MAX_AGE_DAYS skips chronic-pending territory. A proposal
#   that's sat unresolved for 30+ days has become an analyst-decision
#   problem, not a calibrator-decision problem; the followup_watch
#   ``proposal.chronic_pending`` watch flags those for human attention.
#
# Skips happen silently (NP3) — no failures or noise. Applies log via
# the underlying scenario_improver._maybe_auto_apply path.

REPROCESS_MAX_AGE_DAYS = 30.0
REPROCESS_MAX_PER_TICK = 3


def reprocess_pending_through_gate() -> dict:
    """Drip existing pending scenario_proposals through the Phase 3
    auto-apply gate. NP3-tolerant — returns a benign summary on any
    error so the scheduler never crashes."""
    summary = {
        "flag_off": False,
        "checked": 0,
        "applied": 0,
        "skipped_type": 0,
        "skipped_age": 0,
        "skipped_state_changed": 0,
        "errors": 0,
    }
    try:
        from radar.calibration.scenario_improver import (
            _auto_apply_enabled,
            _impact_for_type,
            _maybe_auto_apply,
        )
        from radar.calibration._proposal_writer import ProposalEvent
        from radar.database import db
    except Exception as exc:
        log.warning("reprocess: import failed: %s", exc)
        summary["errors"] = 1
        return summary

    if not _auto_apply_enabled():
        summary["flag_off"] = True
        return summary

    try:
        conn = db._get_conn()  # noqa: SLF001
        cutoff = time.time() - REPROCESS_MAX_AGE_DAYS * 86400.0
        rows = list(conn.execute(
            "SELECT id, scenario_id, proposal_type, target_country, "
            "       suggested_value_json, evidence_json, formula_ref, "
            "       sample_n, why_string, evidence_strength, "
            "       vitality_state, emitted_at "
            "FROM scenario_proposals "
            "WHERE state='pending' "
            "ORDER BY emitted_at ASC LIMIT ?",
            # Over-fetch so type-skip and age-skip don't starve the
            # rate-limited apply slot.
            (REPROCESS_MAX_PER_TICK * 8,),
        ))
    except Exception as exc:
        log.warning("reprocess: ledger read failed: %s", exc)
        summary["errors"] += 1
        return summary

    for r in rows:
        if summary["applied"] >= REPROCESS_MAX_PER_TICK:
            break

        # Skip NP7-bound + diagnostic types — those go through D1/D3
        # or stay analyst-only. _impact_for_type returns None for
        # anything outside {weight_too_low, missing_participant,
        # role_reclassify, weight_too_high, dormant_participant}.
        if _impact_for_type(r["proposal_type"]) is None:
            summary["skipped_type"] += 1
            continue

        # Skip stale rows — they're chronic_pending watch territory.
        if r["emitted_at"] < cutoff:
            summary["skipped_age"] += 1
            continue

        # Re-check state right before apply: another hook (D1/D2/D3)
        # might have moved the row in this same tick.
        try:
            current = conn.execute(
                "SELECT state FROM scenario_proposals WHERE id=?",
                (r["id"],),
            ).fetchone()
        except Exception:
            summary["errors"] += 1
            continue
        if not current or current["state"] != "pending":
            summary["skipped_state_changed"] += 1
            continue

        summary["checked"] += 1

        try:
            import json as _json
            event = ProposalEvent(
                scenario_id=r["scenario_id"],
                proposal_type=r["proposal_type"],
                target_country=r["target_country"],
                suggested_value=_json.loads(
                    r["suggested_value_json"] or "{}"),
                evidence=_json.loads(r["evidence_json"] or "{}"),
                formula_ref=r["formula_ref"] or "reprocessed",
                sample_n=int(r["sample_n"] or 0),
                why_string=r["why_string"] or "reprocessed",
            )
        except Exception as exc:
            log.debug("reprocess: synth event failed for id=%d: %s",
                      r["id"], exc)
            summary["errors"] += 1
            continue

        # Run the gate. _maybe_auto_apply is silent on skip
        # (evidence floor, tier blocked, role protected) and writes
        # state='applied' on success.
        try:
            _maybe_auto_apply(
                int(r["id"]), event,
                evidence_strength=r["evidence_strength"],
                vitality_state=r["vitality_state"],
            )
        except Exception as exc:
            log.debug("reprocess: gate raised for id=%d: %s",
                      r["id"], exc)
            summary["errors"] += 1
            continue

        # Did it apply? Re-read state.
        try:
            after = conn.execute(
                "SELECT state FROM scenario_proposals WHERE id=?",
                (r["id"],),
            ).fetchone()
            if after and after["state"] == "applied":
                summary["applied"] += 1
        except Exception:
            summary["errors"] += 1

    return summary


_DIAGNOSTIC_PROPOSAL_TYPES = (
    "sensor_gap_detected",
    "scenario_dormant",
    "needs_more_data",
)

DIAGNOSTIC_AUTO_ACK_DAYS = 7.0


def auto_acknowledge_diagnostic_proposals(
    *, stale_days: float = DIAGNOSTIC_AUTO_ACK_DAYS,
) -> int:
    """D3 — auto-acknowledge diagnostic-only scenario_proposals.

    The Wizard's Diagnostic tab labels these types "informational
    only — no Apply path". They sit at ``state='pending'`` forever
    because there is no ledger transition that resolves them. After
    ``stale_days`` we mark them as ``dismissed`` with
    ``state_changed_by='auto:diagnostic_acknowledged'`` so:

      - the wizard's pending lists self-clear
      - the AUTO-TUNE chip's pending count reflects only items that
        actually need analyst action
      - the followup_watch ``proposal.chronic_pending`` watch isn't
        polluted by informational rows that were never going to be
        actioned

    NP6 trail: each row's ``state_changed_by`` distinguishes
    ``auto:diagnostic_acknowledged`` from ``auto:inactive_scenario``
    (D1) and ``auto:supersede_by_id_*`` (D2) so audit forensics can
    tell which mechanical hook handled each lifecycle event.

    Returns the number of rows transitioned. Idempotent.
    """
    from radar.database import db
    try:
        conn = db._get_conn()  # noqa: SLF001
        cutoff = time.time() - max(0.0, float(stale_days)) * 86400.0
        placeholders = ",".join("?" for _ in _DIAGNOSTIC_PROPOSAL_TYPES)
        rows = conn.execute(
            f"SELECT id FROM scenario_proposals "
            f"WHERE state='pending' "
            f"AND proposal_type IN ({placeholders}) "
            f"AND emitted_at < ?",
            (*_DIAGNOSTIC_PROPOSAL_TYPES, cutoff),
        ).fetchall()
        ids = [int(r[0]) for r in rows]
        if not ids:
            return 0
        now = time.time()
        with conn.writing():
            id_placeholders = ",".join("?" for _ in ids)
            conn.execute(
                "UPDATE scenario_proposals SET state='dismissed', "
                "state_changed_at=?, "
                "state_changed_by='auto:diagnostic_acknowledged' "
                f"WHERE id IN ({id_placeholders}) AND state='pending'",
                (now, *ids),
            )
        return len(ids)
    except Exception as exc:
        log.warning(
            "auto_acknowledge_diagnostic_proposals failed: %s", exc,
        )
        return 0


def supersede_duplicate_pending(
    *,
    scenario_id: str,
    proposal_type: str,
    target_country: "str | None",
    new_proposal_id: int,
) -> int:
    """Mark every existing ``pending`` proposal of the same
    (scenario_id, proposal_type, target_country) as the freshly
    inserted one as ``superseded``.

    Called by ``_proposal_writer.emit()`` immediately after the
    INSERT for the new proposal. The new row is excluded by id so
    the call is safe even if the caller passes the new row's id
    before the SELECT runs — the AND state='pending' guard does the
    real work.

    Returns the number of rows transitioned. NP3-tolerant — DB
    errors return 0 without raising so a write-time hook cannot
    block the proposer.
    """
    from radar.database import db
    try:
        conn = db._get_conn()  # noqa: SLF001
        if target_country is None:
            where_target = "AND target_country IS NULL"
            extra_params: tuple = ()
        else:
            where_target = "AND target_country = ?"
            extra_params = (target_country,)
        rows = conn.execute(
            "SELECT id FROM scenario_proposals "
            "WHERE state='pending' AND scenario_id = ? "
            "AND proposal_type = ? "
            f"{where_target} AND id != ?",
            (scenario_id, proposal_type, *extra_params, int(new_proposal_id)),
        ).fetchall()
        ids = [int(r[0]) for r in rows]
        if not ids:
            return 0
        now = time.time()
        marker = f"auto:supersede_by_id_{int(new_proposal_id)}"
        with conn.writing():
            placeholders = ",".join("?" for _ in ids)
            conn.execute(
                "UPDATE scenario_proposals SET state='superseded', "
                "state_changed_at=?, state_changed_by=? "
                f"WHERE id IN ({placeholders}) AND state='pending'",
                (now, marker, *ids),
            )
        return len(ids)
    except Exception as exc:
        log.warning("supersede_duplicate_pending failed: %s", exc)
        return 0
