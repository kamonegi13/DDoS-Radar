"""P7 C4 — the analyst's half of the attention list, as folds.

Same discipline as `v3/commands/state.py` and split out of it for the
800-line house limit: effective state IS the command log, and the read
projection calls these same functions, so a change that is not a row is
not a change.

Two folds, and both are PER ACTOR:

    item_state        one item's ack / snooze / dismiss for one analyst.
    thresholds_for    that analyst's attention thresholds, defaults filled.

Per-actor is not a stylistic choice here, it is the correction of two
production defects at once. Ack lived in `localStorage`
(`radar.js:5995`), so it was per-BROWSER, invisible to the server, and
lost when a cache was cleared; snooze and dismiss lived in the decision
ledger as `target_kind="global"`, so one analyst muting the lane muted it
for everybody. Neither is a decision that should be shared by accident,
and both are decisions AP4 has to be able to replay — which needs them on
the server with an actor on them.

`thresholds_for` is the G-02 answer. Production stores per-user thresholds
its evaluation path never reads. Here this function is what the ranking
projection calls AND what `commit()` verifies the effect against, so a
threshold that stopped being read would fail the command that set it.
"""
from __future__ import annotations

from typing import Optional

from v3.attention import thresholds as T
from v3.kernel.errors import DomainError

# ── the closed action vocabulary ────────────────────────────────────────
ATTENTION_ACK = "attention.ack"
ATTENTION_SNOOZE = "attention.snooze"
ATTENTION_DISMISS = "attention.dismiss"
ATTENTION_THRESHOLDS = "attention.thresholds"

ITEM_ACTIONS: tuple[str, ...] = (ATTENTION_ACK, ATTENTION_SNOOZE,
                                 ATTENTION_DISMISS)

TARGET_ATTENTION = "attention"
TARGET_ATTENTION_THRESHOLDS = "attention_thresholds"

#: The per-actor states an item can be in. `active` is the absence of a
#: row rather than a value anything writes — there is nowhere for "the
#: analyst has not decided" to be recorded wrongly.
STATE_ACTIVE = "active"
STATE_ACKED = "acked"
STATE_SNOOZED = "snoozed"
STATE_DISMISSED = "dismissed"

_STATE_OF: dict = {ATTENTION_ACK: STATE_ACKED,
                   ATTENTION_SNOOZE: STATE_SNOOZED,
                   ATTENTION_DISMISS: STATE_DISMISSED}

#: Transcribed from production, which is the only reason these numbers
#: have these values. `radar/routes/decisions.py:81-118` defaults a triage
#: snooze to 30 minutes and clamps the request to [1, 1440]; the dismiss
#: at `:170-204` is a hardcoded 24h with no caller control.
SNOOZE_DEFAULT_MINUTES = 30.0
SNOOZE_MIN_MINUTES = 1.0
SNOOZE_MAX_MINUTES = 1440.0
DISMISS_SEC = 24 * 3600.0


def _rows(ledger, *, target_kind: str, target_id: str, actor_id: str,
          until: Optional[float]) -> list:
    return [row for row in ledger.command_records(
        target_kind=target_kind, target_id=target_id, actor_id=actor_id,
        until=until)]


def item_state(ledger, item_id: str, *, actor_id: str,
               until: Optional[float] = None) -> Optional[dict]:
    """One analyst's decision about one item, or None if they made none.

    Folds all three actions together for the reason `config_state` folds
    both of its own: a fold that saw only `attention.ack` would report a
    dismissed item as acknowledged, and the two mean opposite things about
    whether the analyst wants to see it again.
    """
    rows = _rows(ledger, target_kind=TARGET_ATTENTION, target_id=item_id,
                 actor_id=actor_id, until=until)
    folded = [row for row in rows if row["action"] in ITEM_ACTIONS]
    return folded[-1]["after"] if folded else None


def in_force(state: Optional[dict], *, now: float) -> bool:
    """Whether a decision still holds at `now`.

    An expiry that has passed is not a decision that was revoked — the row
    stays, and this returns False. Production's snooze reads the same way
    (`decisions.py:230`), and the distinction matters to AP4: "the analyst
    snoozed this and it lapsed" and "the analyst never snoozed it" are
    different histories.
    """
    if not state:
        return False
    expires_at = state.get("expires_at")
    if expires_at is None:
        return True
    return float(now) < float(expires_at)


def state_name(state: Optional[dict], *, now: float) -> str:
    if state and in_force(state, now=now):
        return str(state.get("state") or STATE_ACTIVE)
    return STATE_ACTIVE


def resolve_item(ledger, *, target_id, actor_id, until, config=None):
    return item_state(ledger, target_id, actor_id=actor_id, until=until)


def _snooze_minutes(payload) -> float:
    raw = payload.get("minutes")
    if raw is None:
        return SNOOZE_DEFAULT_MINUTES
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        raise DomainError(f"minutes must be a number, got {raw!r}")
    minutes = float(raw)
    if not (SNOOZE_MIN_MINUTES <= minutes <= SNOOZE_MAX_MINUTES):
        raise DomainError(
            f"minutes must be within [{SNOOZE_MIN_MINUTES}, "
            f"{SNOOZE_MAX_MINUTES}], got {minutes}. An unbounded snooze is a "
            f"mute nobody remembers setting, which is the failure NP1 makes "
            f"expensive.")
    return minutes


def _apply_item(action: str):
    def apply(before, *, target_id, payload, actor_id, at, config=None):
        expires_at = None
        if action == ATTENTION_SNOOZE:
            expires_at = float(at) + _snooze_minutes(payload) * 60.0
        elif action == ATTENTION_DISMISS:
            expires_at = float(at) + DISMISS_SEC
        return {"item_id": str(target_id), "state": _STATE_OF[action],
                "actor_id": actor_id, "at": float(at),
                "expires_at": expires_at,
                "reason": payload.get("reason") or None}
    apply.__name__ = f"apply_{action.replace('.', '_')}"
    apply.__doc__ = (
        f"P7 C4's {action!r}. Pure: `(before, payload) -> after`. The "
        f"previous decision is not consulted because any of the three "
        f"replaces any other — an analyst who dismisses something they had "
        f"acknowledged has changed their mind, and the earlier row is the "
        f"history of that.")
    return apply


apply_ack = _apply_item(ATTENTION_ACK)
apply_snooze = _apply_item(ATTENTION_SNOOZE)
apply_dismiss = _apply_item(ATTENTION_DISMISS)


# ── the per-user thresholds (the G-02 answer) ───────────────────────────
def thresholds_for(ledger, *, actor_id: str,
                   until: Optional[float] = None) -> dict:
    """THE per-user thresholds, defaults filled — and THE reader.

    `v3/attention/projection.py` calls this to decide what surfaces, and
    the C4 threshold command verifies its effect against it. One function,
    so "the evaluation path reads the analyst's threshold" is a single
    edge rather than a claim: a resolver that ignored the ledger would
    return the default here and the command would be refused by `commit()`.
    """
    resolved = dict(T.PER_USER_KEYS)
    rows = [row for row in ledger.command_records(
        target_kind=TARGET_ATTENTION_THRESHOLDS, actor_id=actor_id,
        until=until) if row["action"] == ATTENTION_THRESHOLDS]
    if rows:
        stored = rows[-1]["after"] or {}
        for key in T.PER_USER_KEYS:
            if key in stored:
                resolved[key] = float(stored[key])
    return resolved


def resolve_thresholds(ledger, *, target_id, actor_id, until, config=None):
    return thresholds_for(ledger, actor_id=actor_id, until=until)


def apply_thresholds(before, *, target_id, payload, actor_id, at,
                     config=None):
    """Set one or more per-user thresholds. Unknown keys are refused.

    Refused rather than ignored, because `PUT /api/auth/settings` accepting
    unknown keys in silence is how a setting comes to be believed in. The
    refusal names the admissible keys and says why the list is short.
    """
    values = payload.get("thresholds")
    if not isinstance(values, dict) or not values:
        raise DomainError(
            f"a threshold command needs a non-empty `thresholds` object; "
            f"the per-user keys are {sorted(T.PER_USER_KEYS)}")
    updated = dict(before or T.PER_USER_KEYS)
    for key, value in values.items():
        updated[key] = T.coerce_per_user(key, value)
    return {key: float(updated[key]) for key in sorted(T.PER_USER_KEYS)}


__all__ = ["ATTENTION_ACK", "ATTENTION_SNOOZE", "ATTENTION_DISMISS",
           "ATTENTION_THRESHOLDS", "ITEM_ACTIONS", "TARGET_ATTENTION",
           "TARGET_ATTENTION_THRESHOLDS", "STATE_ACTIVE", "STATE_ACKED",
           "STATE_SNOOZED", "STATE_DISMISSED", "SNOOZE_DEFAULT_MINUTES",
           "SNOOZE_MIN_MINUTES", "SNOOZE_MAX_MINUTES", "DISMISS_SEC",
           "item_state", "in_force", "state_name", "resolve_item",
           "apply_ack", "apply_snooze", "apply_dismiss", "thresholds_for",
           "resolve_thresholds", "apply_thresholds"]
