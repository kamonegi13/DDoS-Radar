"""Decision Layer — unified ledger for analyst decisions.

Records analyst responses to advisory output across TRIAGE, calibration
governance, and threshold operations. Sits beside (not above) existing
distributed implementations like attention_snooze and
scenario_proposals.state_changed_by; the Decision History UI merges
all stores into a single timeline (AP4).

Decision lifecycle:
  1. Caller invokes record() with decision_type + target + action
  2. Any prior active decision for the same (decision_type, target_kind,
     target_id) gets superseded_by set to the new id (single-writer
     guarantee — only one current decision per target+type)
  3. New row inserted with superseded_by=NULL
  4. expires_at (if set) eventually crosses now → decision is inactive
     even though superseded_by is still NULL

Active decision predicate:
  superseded_by IS NULL AND (expires_at IS NULL OR expires_at > now)

NP6: every decision carries actor + reason + parameters JSON, so the
audit trail is complete from inside this table alone.

NP7: callers responsible for confirming destructive actions (rollback,
raise) before invoking record() — the ledger does not enforce policy,
it records facts.

NP1: snooze decisions DO NOT silence critical events. is_snoozed()
returns the raw expiry; consumers must combine with their own
critical-event check before suppressing UI. See triage display layer.
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from typing import Any, Optional

log = logging.getLogger("radar.decisions")


_VALID_TARGET_KINDS = frozenset({"global", "scenario", "conclusion", "user"})
_VALID_ACTIONS = frozenset({
    "accept", "extend", "raise", "rollback",
    "snooze", "dismiss", "set", "apply",
})


def _new_decision_id() -> str:
    """Compact opaque id. Hex-only, 16 chars (~64 bits) for human
    legibility in audit logs."""
    return "dec_" + secrets.token_hex(8)


class DecisionLedger:
    """Thin wrapper over the `decisions` table.

    Held by radar.database.RadarDB instances; access via db.decisions.
    All public methods are thread-safe via the underlying connection's
    cooperative locking (same as other RadarDB methods).
    """

    def __init__(self, db) -> None:
        self._db = db

    # ── write ──────────────────────────────────────────────────────────

    def record(
        self,
        *,
        decision_type: str,
        target_kind: str,
        target_id: Optional[str],
        action: str,
        actor: str,
        reason: Optional[str] = None,
        parameters: Optional[dict[str, Any]] = None,
        expires_at: Optional[float] = None,
        now: Optional[float] = None,
    ) -> str:
        """Append a new decision and supersede any prior current decision
        for the same (decision_type, target_kind, target_id) tuple.

        Returns the new decision_id.
        """
        if not decision_type:
            raise ValueError("decision_type required")
        if target_kind not in _VALID_TARGET_KINDS:
            raise ValueError(f"invalid target_kind: {target_kind!r}")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"invalid action: {action!r}")
        if not actor:
            raise ValueError("actor required")

        ts = now if (now is not None) else time.time()
        params_json = json.dumps(parameters, separators=(",", ":")) if parameters else None
        new_id = _new_decision_id()

        conn = self._db._get_conn()
        with conn.writing():
            # Supersede any prior current decision with same key tuple.
            # NULL-safe match for target_id via IS / IS NOT semantics.
            if target_id is None:
                conn.execute(
                    "UPDATE decisions SET superseded_by = ? "
                    "WHERE decision_type = ? "
                    "  AND target_kind = ? "
                    "  AND target_id IS NULL "
                    "  AND superseded_by IS NULL",
                    (new_id, decision_type, target_kind),
                )
            else:
                conn.execute(
                    "UPDATE decisions SET superseded_by = ? "
                    "WHERE decision_type = ? "
                    "  AND target_kind = ? "
                    "  AND target_id = ? "
                    "  AND superseded_by IS NULL",
                    (new_id, decision_type, target_kind, target_id),
                )
            conn.execute(
                "INSERT INTO decisions "
                "(id, decision_type, target_kind, target_id, action, "
                " actor, reason, parameters, decided_at, expires_at, "
                " superseded_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                (new_id, decision_type, target_kind, target_id, action,
                 actor, reason, params_json, ts, expires_at),
            )
        return new_id

    # ── read ───────────────────────────────────────────────────────────

    def latest(
        self,
        *,
        decision_type: str,
        target_kind: str,
        target_id: Optional[str],
    ) -> Optional[dict[str, Any]]:
        """Return the most recent NOT-superseded decision for the tuple,
        or None. Does not check expiry — caller decides whether expired
        decisions are interesting."""
        conn = self._db._get_conn()
        if target_id is None:
            row = conn.execute(
                "SELECT * FROM decisions "
                "WHERE decision_type = ? "
                "  AND target_kind = ? "
                "  AND target_id IS NULL "
                "  AND superseded_by IS NULL "
                "ORDER BY decided_at DESC LIMIT 1",
                (decision_type, target_kind),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM decisions "
                "WHERE decision_type = ? "
                "  AND target_kind = ? "
                "  AND target_id = ? "
                "  AND superseded_by IS NULL "
                "ORDER BY decided_at DESC LIMIT 1",
                (decision_type, target_kind, target_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def is_active(
        self,
        *,
        decision_type: str,
        target_kind: str,
        target_id: Optional[str],
        now: Optional[float] = None,
    ) -> bool:
        """True iff a current (not superseded) decision exists AND its
        expires_at (if set) is still in the future."""
        d = self.latest(
            decision_type=decision_type,
            target_kind=target_kind,
            target_id=target_id,
        )
        if d is None:
            return False
        ts = now if (now is not None) else time.time()
        if d["expires_at"] is not None and d["expires_at"] <= ts:
            return False
        return True

    def history(
        self,
        *,
        decision_type: Optional[str] = None,
        target_kind: Optional[str] = None,
        target_id: Optional[str] = None,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        since_ts: Optional[float] = None,
        until_ts: Optional[float] = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Filtered chronological listing for the Decision History UI.

        All filters are AND-combined; passing none returns the most
        recent `limit` rows across the entire ledger.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if decision_type is not None:
            clauses.append("decision_type = ?")
            params.append(decision_type)
        if target_kind is not None:
            clauses.append("target_kind = ?")
            params.append(target_kind)
        if target_id is not None:
            clauses.append("target_id = ?")
            params.append(target_id)
        if actor is not None:
            clauses.append("actor = ?")
            params.append(actor)
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if since_ts is not None:
            clauses.append("decided_at >= ?")
            params.append(since_ts)
        if until_ts is not None:
            clauses.append("decided_at <= ?")
            params.append(until_ts)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 1000)))

        rows = self._db._get_conn().execute(
            "SELECT * FROM decisions" + where
            + " ORDER BY decided_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get(self, decision_id: str) -> Optional[dict[str, Any]]:
        row = self._db._get_conn().execute(
            "SELECT * FROM decisions WHERE id = ?", (decision_id,),
        ).fetchone()
        return self._row_to_dict(row) if row else None

    # ── invalidation ───────────────────────────────────────────────────

    def revoke(self, decision_id: str, *, by: str,
               reason: Optional[str] = None) -> bool:
        """Mark a decision as no-longer-current without inserting a
        replacement. Sets superseded_by to a synthetic 'revoked:<by>'
        marker (id is preserved so audit trail still resolves).

        Returns True if the row was updated.
        """
        conn = self._db._get_conn()
        marker = f"revoked:{by}:{int(time.time())}"
        with conn.writing():
            cur = conn.execute(
                "UPDATE decisions SET superseded_by = ? "
                "WHERE id = ? AND superseded_by IS NULL",
                (marker, decision_id),
            )
            return cur.rowcount > 0

    # ── helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(row) -> dict[str, Any]:
        if row is None:
            return None  # type: ignore[return-value]
        d = dict(row)
        # Parse parameters JSON for the caller.
        p = d.get("parameters")
        if p:
            try:
                d["parameters"] = json.loads(p)
            except (ValueError, TypeError):
                d["parameters"] = None
        return d
