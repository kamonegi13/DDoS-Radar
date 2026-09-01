"""WP-0.4 v2 (0.4e) — adjudicating an FN draft, as a fold.

Tier 3 is asynchronous by ruling (ADR-V3-012), so a draft may wait
indefinitely. What it may NOT do is wait invisibly: every unadjudicated
draft widens the published recall interval, and an analyst's verdict is
the only thing that narrows it back.

Two verdicts, and the asymmetry between them is the point:

    confirm   the candidate is a real miss. A FALSE_NEGATIVE label is
              materialised under the ANALYST's identity (the human-only
              series is exactly this population), so the draft leaves the
              pending set by gaining a label.
    reject    the candidate is not a miss. NO label is written — the
              tool's silence about this conclusion is what "not a miss"
              means — but the draft leaves the pending set all the same,
              because a rejected candidate that stayed pending would
              widen the interval forever on the strength of a question
              somebody already answered.

Both are folds over `command_record`, per the house rule: the state IS
the log. A rejected draft can be confirmed later and vice versa — the
latest row wins and the earlier one stays as the record that somebody
changed their mind.
"""
from __future__ import annotations

from typing import Optional

from v3.kernel.errors import DomainError

DRAFT_CONFIRM = "calibration.draft_confirm"
DRAFT_REJECT = "calibration.draft_reject"

DRAFT_ACTIONS: tuple[str, ...] = (DRAFT_CONFIRM, DRAFT_REJECT)

TARGET_DRAFT = "calibration_draft"

#: 0.4e's second half — the sampled audit of AUTOMATED labels. Two
#: verdicts and no third: an auditor either agrees the generator got
#: this one right or says it did not, and "unsure" is the absence of a
#: row (the same shape the draft queue uses for "nobody has decided").
LABEL_AUDIT_CORRECT = "calibration.label_audit_correct"
LABEL_AUDIT_INCORRECT = "calibration.label_audit_incorrect"

AUDIT_ACTIONS: tuple[str, ...] = (LABEL_AUDIT_CORRECT,
                                  LABEL_AUDIT_INCORRECT)

TARGET_LABEL = "calibration_label"

#: The three states a draft can be in. `pending` is the absence of a row,
#: never a value anything writes — there is nowhere for "nobody has
#: decided" to be recorded wrongly, which is the same shape C4 uses.
STATE_PENDING = "pending"
STATE_CONFIRMED = "confirmed"
STATE_REJECTED = "rejected"

_STATE_OF: dict = {DRAFT_CONFIRM: STATE_CONFIRMED,
                   DRAFT_REJECT: STATE_REJECTED}


def draft_state(ledger, draft_id: str, *,
                until: Optional[float] = None) -> Optional[dict]:
    """The latest adjudication of one draft, or None if nobody has ruled.

    NOT per-actor, unlike C4's ack: an ack is one analyst's reading list,
    but an adjudication changes the label population every reader's
    recall is computed from. Two analysts disagreeing must therefore
    resolve to ONE state — the later row — rather than to a state that
    depends on who is asking.
    """
    rows = [row for row in ledger.command_records(
        target_kind=TARGET_DRAFT, target_id=str(draft_id), until=until)
        if row["action"] in DRAFT_ACTIONS]
    return dict(rows[-1]["after"]) if rows else None


def state_name(state: Optional[dict]) -> str:
    if not state:
        return STATE_PENDING
    return str(state.get("state") or STATE_PENDING)


def rejected_draft_ids(ledger, *, until: Optional[float] = None) -> set:
    """Drafts whose LATEST verdict is `reject`.

    This — and only this — is what the pending projection subtracts, and
    the asymmetry is load-bearing. A rejected draft will never gain a
    label, so leaving it pending would widen the recall interval forever
    on a question somebody answered. A CONFIRMED draft is different: its
    label is written by the next S9 cycle, and until that row exists the
    miss it represents is in no denominator. Subtracting it at confirm
    time would leave a window in which the finding counts neither as
    pending nor as an FN — recall would read BETTER for having been
    adjudicated, which is the dangerous direction NP1 forbids. So a
    confirm leaves the pending set by GAINING ITS LABEL, never by being
    ruled on; and if that write never happens the draft stays pending,
    which is the safe way to be wrong.

    The latest row wins, so a reject that was later confirmed is not in
    this set.
    """
    verdicts: dict = {}
    for row in ledger.command_records(target_kind=TARGET_DRAFT,
                                      until=until):
        if row["action"] in DRAFT_ACTIONS:
            verdicts[str(row["target_id"])] = row["action"]
    return {draft_id for draft_id, action in verdicts.items()
            if action == DRAFT_REJECT}


def resolve_draft(ledger, *, target_id, actor_id, until, config=None):
    return draft_state(ledger, target_id, until=until)


# ── the sampled audit (0.4e) ────────────────────────────────────────────
def label_audit_state(ledger, label_id: str, *,
                      until: Optional[float] = None) -> Optional[dict]:
    """The latest audit verdict on one label, or None.

    Not per-actor, for the same reason `draft_state` is not: the error
    rate this feeds is a property of the generator, and a rate that
    depended on who was asking could not gate anything.
    """
    rows = [row for row in ledger.command_records(
        target_kind=TARGET_LABEL, target_id=str(label_id), until=until)
        if row["action"] in AUDIT_ACTIONS]
    return dict(rows[-1]["after"]) if rows else None


def resolve_label_audit(ledger, *, target_id, actor_id, until,
                        config=None):
    return label_audit_state(ledger, target_id, until=until)


def _apply_audit(action: str):
    def apply(before, *, target_id, payload, actor_id, at, config=None):
        reason = payload.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise DomainError(
                "監査には理由が必要です: the error rate this feeds can "
                "freeze the automated label series, and a freeze whose "
                "evidence is a bare verdict cannot be reviewed")
        return {"label_id": str(target_id),
                "verdict": ("correct" if action == LABEL_AUDIT_CORRECT
                            else "incorrect"),
                "actor_id": actor_id, "at": float(at),
                "reason": reason.strip()}
    apply.__name__ = f"apply_{action.replace('.', '_')}"
    apply.__doc__ = (
        f"WP-0.4 v2's {action!r}. Pure. An auditor who changes their "
        f"mind writes a second row and the fold takes it; the first "
        f"stays as the record that the reading changed.")
    return apply


apply_label_audit_correct = _apply_audit(LABEL_AUDIT_CORRECT)
apply_label_audit_incorrect = _apply_audit(LABEL_AUDIT_INCORRECT)


def _apply_draft(action: str):
    def apply(before, *, target_id, payload, actor_id, at, config=None):
        reason = payload.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise DomainError(
                "裁定には理由が必要です: an adjudication without a reason "
                "cannot be audited after the fact, and the label "
                "population it changes is the recall chain's input (G-01)")
        return {"draft_id": str(target_id), "state": _STATE_OF[action],
                "actor_id": actor_id, "at": float(at),
                "reason": reason.strip()}
    apply.__name__ = f"apply_{action.replace('.', '_')}"
    apply.__doc__ = (
        f"WP-0.4 v2's {action!r}. Pure: `(before, payload) -> after`. The "
        f"previous verdict is not consulted — an analyst who confirms "
        f"what they had rejected has changed their mind, and the earlier "
        f"row is the history of that.")
    return apply


apply_draft_confirm = _apply_draft(DRAFT_CONFIRM)
apply_draft_reject = _apply_draft(DRAFT_REJECT)


__all__ = ["DRAFT_CONFIRM", "DRAFT_REJECT", "DRAFT_ACTIONS", "TARGET_DRAFT",
           "LABEL_AUDIT_CORRECT", "LABEL_AUDIT_INCORRECT", "AUDIT_ACTIONS",
           "TARGET_LABEL", "label_audit_state", "resolve_label_audit",
           "apply_label_audit_correct", "apply_label_audit_incorrect",
           "STATE_PENDING", "STATE_CONFIRMED", "STATE_REJECTED",
           "draft_state", "state_name", "rejected_draft_ids",
           "resolve_draft", "apply_draft_confirm", "apply_draft_reject"]
