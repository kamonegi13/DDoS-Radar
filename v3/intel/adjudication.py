"""P7 R11 / C3 — the intel queue's adjudication state.

WP-2.7 landed LLM intel as ORDINARY L1 observations under O-17: one
`signal_observation` row with `signal_source="llm_intel"`, scored by the
same kernel as every other row. That was the right call — production's
second scoring queue is where the intel pipeline's defects lived — but it
left the analyst's half unbuilt, which is why R11 and C3 were deferred
with the note "キューの裁定状態を持つ表がまだ無い".

There is still no such table. The adjudication state is the fold of
`command_record` for `target_kind="intel"`, exactly as a proposal's state
is, so there is ONE mechanism for "an analyst decided something" and the
decision trail (R9) already projects it.

**The identity is the ledger's own row id.** `signal_observation` is
append-only and its primary key never moves, so an adjudication targets a
row rather than a content hash that a re-extraction could collide with.

**What each verb actually does, and what reads it:**

    confirm   the item leaves the pending queue. Read by R11's `?state=`
              filter, which is the analyst's work list.
    reject    the item leaves the queue AND stops scoring —
              `v3/runtime/scoring.py::observations_at` drops the row.
              That is the reader that makes 'reject' mean what it says.
    revert    both effects are undone. Legal only from a decided state;
              production lets a revert of a never-decided item update zero
              rows and report success, which loses the analyst's action.

`override` is NOT here, and the blocker is named rather than papered
over: production's override rewrites the extracted fields, and v3's L1 is
append-only, so an override would have to emit a corrected observation —
a write from the command surface into the observation ledger, which is a
different slice with its own provenance question ("who is the sensor for
this row?"). Shipping the verb without that would be a knob that records
a correction nothing reads, which is defect G-15 (§7-2 #104).
"""
from __future__ import annotations

from typing import Optional

from v3.kernel.errors import DomainError

TARGET_INTEL = "intel"

INTEL_CONFIRM = "intel.confirm"
INTEL_REJECT = "intel.reject"
INTEL_REVERT = "intel.revert"

ACTIONS: tuple[str, ...] = (INTEL_CONFIRM, INTEL_REJECT, INTEL_REVERT)

#: The queue's states. `pending` has no row — an item nobody has judged is
#: pending by construction, so it cannot be emitted into some other state
#: by accident (the same property `proposal_state` relies on).
STATE_PENDING = "pending"
STATE_CONFIRMED = "confirmed"
STATE_REJECTED = "rejected"
STATES: tuple[str, ...] = (STATE_PENDING, STATE_CONFIRMED, STATE_REJECTED)

_STATE_FOR: dict = {INTEL_CONFIRM: STATE_CONFIRMED,
                    INTEL_REJECT: STATE_REJECTED,
                    INTEL_REVERT: STATE_PENDING}

#: S1-INTEL-020's literal, and the only `signal_source` R11 projects.
INTEL_SIGNAL_SOURCE = "llm_intel"


def _rows(ledger, item_id: Optional[str], until: Optional[float]) -> list:
    rows = ledger.command_records(target_kind=TARGET_INTEL,
                                  target_id=item_id, until=until)
    return [row for row in rows if row["action"] in ACTIONS]


def intel_state(ledger, item_id, *, until: Optional[float] = None) -> dict:
    """The adjudication of one item. Always a dict; `pending` when unjudged."""
    folded = _rows(ledger, str(item_id), until)
    if not folded:
        return {"item_id": str(item_id), "state": STATE_PENDING,
                "actor_id": None, "at": None, "reason": None}
    return folded[-1]["after"]


def adjudicated(ledger, *, until: Optional[float] = None) -> dict:
    """`{item_id: state}` for every item anyone has judged.

    One pass over the command rows rather than a fold per item: the
    scoring tick asks this once per tick, and a per-row query would make
    the honest implementation look expensive enough to justify a cached
    copy — which is the state O-16 exists to remove.
    """
    states: dict = {}
    for row in _rows(ledger, None, until):
        after = row["after"] or {}
        states[str(row["target_id"])] = after.get("state", STATE_PENDING)
    return states


def rejected_ids(ledger, *, until: Optional[float] = None) -> frozenset:
    """THE scoring reader. `reject` means the row stops contributing.

    Called by `v3/runtime/scoring.py::observations_at`, which is the one
    place the ledger becomes kernel input — so "rejected intel does not
    score" is a single edge rather than a convention every caller keeps.
    """
    return frozenset(item_id for item_id, state in
                     adjudicated(ledger, until=until).items()
                     if state == STATE_REJECTED)


def resolve_intel(ledger, *, target_id, actor_id, until, config=None):
    return intel_state(ledger, target_id, until=until)


def _apply(action: str):
    def apply(before, *, target_id, payload, actor_id, at, config=None):
        current = (before or {}).get("state", STATE_PENDING)
        if action == INTEL_REVERT and current == STATE_PENDING:
            raise DomainError(
                "未裁定の項目は revert できません。本番はこの操作を 0 行に"
                "一致させて成功を返すため、アナリストが『戻した』と信じた"
                "操作が記録されません（S1-CALIB-052 と同型の穴）")
        if action != INTEL_REVERT and current == _STATE_FOR[action]:
            raise DomainError(
                f"この項目は既に {current} です。同じ裁定を二度書くと"
                f"判断履歴に意味の無い行が積み上がります")
        return {"item_id": str(target_id), "state": _STATE_FOR[action],
                "actor_id": str(actor_id), "at": float(at),
                "reason": payload.get("reason"),
                "previous_state": current}
    apply.__name__ = f"apply_{action.replace('.', '_')}"
    apply.__doc__ = (
        f"The {action!r} edge. Illegal transitions raise rather than "
        f"matching zero rows and reporting success.")
    return apply


apply_confirm = _apply(INTEL_CONFIRM)
apply_reject = _apply(INTEL_REJECT)
apply_revert = _apply(INTEL_REVERT)


__all__ = ["TARGET_INTEL", "INTEL_CONFIRM", "INTEL_REJECT", "INTEL_REVERT",
           "ACTIONS", "STATES", "STATE_PENDING", "STATE_CONFIRMED",
           "STATE_REJECTED", "INTEL_SIGNAL_SOURCE", "intel_state",
           "adjudicated", "rejected_ids", "resolve_intel", "apply_confirm",
           "apply_reject", "apply_revert"]
