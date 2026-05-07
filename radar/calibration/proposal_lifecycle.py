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
