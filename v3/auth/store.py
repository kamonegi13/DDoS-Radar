"""The user store: a fold of `command_record`, like everything else here.

There is no `user` table. That is the point — the proposal lifecycle, the
configuration override layer and the attention list all resolve their
state from the command log, and a second mechanism for users would be a
second thing to keep in step. Registration, a role change, a password
change, a deactivation and a session revocation are five edges on one
state, and the state is the latest row across them (the shape
`config_state` and `proposal_state` already use).

Consequences worth naming:

* **effect verification works unchanged.** `commit()` re-folds after
  appending and refuses if the state did not become what the command
  claimed, so "the login path reads this password" is proven by the write
  rather than asserted by it.
* **the trail is free.** "Who made this person an admin, and when" is a
  row on the same ledger R9 already projects (AP4).
* **the credential lives in the log**, which is why `v3.commands.spec`
  redacts secret-named fields at the ONE projection point, and why the
  suite sweeps every action's record through R9 looking for the material.

`sessions_not_before` is on the state rather than in a separate revocation
list, and it carries the whole of S1-SVC-006 (b). Production also keeps a
JTI blacklist for (a); v3 does not, and the difference is registered
(§7-2 #102): a per-token blacklist revokes one browser, and every v3 path
that revokes — logout, password change, role change, deactivation —
revokes the user's standing rather than one device.
"""
from __future__ import annotations

from typing import Optional

from v3.kernel.roles import ROLES, ROLE_VIEWER
from v3.auth import password as P
from v3.kernel.errors import DomainError

TARGET_USER = "user"

USER_REGISTER = "user.register"
USER_PASSWORD_SET = "user.password.set"
USER_ROLE_SET = "user.role.set"
USER_DEACTIVATE = "user.deactivate"
USER_SESSIONS_REVOKE = "user.sessions.revoke"

ACTIONS: tuple[str, ...] = (USER_REGISTER, USER_PASSWORD_SET, USER_ROLE_SET,
                            USER_DEACTIVATE, USER_SESSIONS_REVOKE)

#: What a projection may show. Everything else on the state is credential
#: material, and this tuple is what `public_view` is allowed to copy —
#: an allow-list rather than a deny-list, because the failure mode of a
#: deny-list is that a field added later is public by default.
PUBLIC_FIELDS: tuple[str, ...] = ("user_id", "role", "active", "created_at",
                                  "created_by", "updated_at", "updated_by",
                                  "credential_algorithm",
                                  "credential_set_at", "credential_upgradable",
                                  "sessions_not_before", "access_not_before")


def _rows(ledger, user_id: Optional[str], until: Optional[float]) -> list:
    rows = ledger.command_records(target_kind=TARGET_USER, target_id=user_id,
                                  until=until)
    return [row for row in rows if row["action"] in ACTIONS]


def user_state(ledger, user_id: str, *,
               until: Optional[float] = None) -> Optional[dict]:
    """The user, or None if never registered. Folded across all five edges.

    A fold that saw one action would report a deactivated user as active
    and a changed password as the old one; both are the class of bug this
    whole surface exists to end.
    """
    folded = _rows(ledger, str(user_id), until)
    return folded[-1]["after"] if folded else None


def user_ids(ledger, *, until: Optional[float] = None) -> tuple[str, ...]:
    return tuple(sorted({row["target_id"] for row in _rows(ledger, None,
                                                           until)}))


def users(ledger, *, until: Optional[float] = None) -> list[dict]:
    """Every user, public view only. Never a credential (S1-SVC-008)."""
    listed = []
    for user_id in user_ids(ledger, until=until):
        state = user_state(ledger, user_id, until=until)
        if state is not None:
            listed.append(public_view(state))
    return listed


def user_count(ledger, *, until: Optional[float] = None) -> int:
    return len(user_ids(ledger, until=until))


def public_view(state) -> dict:
    """The state minus its credential. The only shape a response carries."""
    if state is None:
        return {}
    credential = state.get("credential") or {}
    view = {name: state.get(name) for name in PUBLIC_FIELDS}
    view["credential_algorithm"] = credential.get("algorithm")
    view["credential_set_at"] = credential.get("set_at")
    view["credential_upgradable"] = P.needs_upgrade(credential)
    return view


def credential_of(state) -> Optional[dict]:
    return None if state is None else state.get("credential")


def resolve_user(ledger, *, target_id, actor_id, until, config=None):
    """THE read seam for every user command — one projection, as always."""
    return user_state(ledger, str(target_id), until=until)


def _require_role(role) -> str:
    if role not in ROLES:
        raise DomainError(
            f"unknown role {role!r}: roles are the closed set "
            f"{sorted(ROLES)} (v3/api/vocabulary.py). A role invented at a "
            f"call site is a privilege nobody declared.")
    return role


def _require_existing(before, user_id: str) -> dict:
    if before is None or not before.get("user_id"):
        raise DomainError(f"利用者 {user_id} は存在しません")
    return dict(before)


def _touched(state: dict, *, actor_id: str, at: float) -> dict:
    state["updated_at"] = float(at)
    state["updated_by"] = str(actor_id)
    return state


def apply_register(before, *, target_id, payload, actor_id, at, config=None):
    """Create the identity and its first credential in ONE row.

    One row because `_audit_discipline` allows exactly one per request,
    and because the two halves are not separately meaningful: an identity
    with no credential cannot log in and would be a user nothing reads.
    """
    if before is not None:
        raise DomainError(
            f"利用者 {target_id} は既に登録されています"
            f"（重複登録は現行系でも 409）")
    role = _require_role(payload.get("role", ROLE_VIEWER))
    credential = P.derive(payload.get("password"), at=float(at))
    return _touched({
        "user_id": str(target_id), "role": role, "active": True,
        "created_at": float(at), "created_by": str(actor_id),
        "credential": credential,
        # Registration itself is a revocation boundary: nothing could have
        # been issued before it, and stating it keeps the field non-null
        # for every user so the comparison has no "missing" branch.
        "sessions_not_before": float(at),
        "access_not_before": float(at),
    }, actor_id=actor_id, at=at)


def apply_password_set(before, *, target_id, payload, actor_id, at,
                       config=None):
    """Set a credential and revoke the user's standing (S1-SVC-007).

    The operator's own session is untouched, because what moves is the
    TARGET's `sessions_not_before` — an admin resetting somebody else's
    password does not log themselves out.
    """
    state = _require_existing(before, target_id)
    state["credential"] = P.derive(payload.get("new_password"), at=float(at))
    state["sessions_not_before"] = float(at)
    state["access_not_before"] = float(at)
    return _touched(state, actor_id=actor_id, at=at)


def apply_role_set(before, *, target_id, payload, actor_id, at, config=None):
    """Change standing, and make the change reach tokens already issued.

    S1-SVC-011's v3 norm makes the token's claim the primary source of the
    role, which alone would mean a demotion took up to an access token's
    lifetime to bite — strictly worse than production, which re-reads the
    database every request. Bumping `sessions_not_before` buys the same
    property without the per-request read: the old token stops verifying,
    the client refreshes, and the new token carries the new role.
    """
    state = _require_existing(before, target_id)
    if str(actor_id) == str(target_id):
        raise DomainError(
            "自分自身の役割は変更できません"
            "（最後の admin を失う事故の防止 — S1-SVC-008）")
    state["role"] = _require_role(payload.get("role"))
    # ACCESS tokens only. The refresh token survives so the client
    # re-authenticates silently and the next access token carries the new
    # role; revoking it too would make every promotion a forced re-login.
    state["access_not_before"] = float(at)
    return _touched(state, actor_id=actor_id, at=at)


def apply_deactivate(before, *, target_id, payload, actor_id, at,
                     config=None):
    """Deactivation, not deletion. The rows stay; the standing goes.

    Production DELETEs the user row and its settings row in two statements
    outside a transaction (ACCIDENTAL A3), which can leave an orphan. Here
    there is nothing to delete — the log is append-only — so the failure
    mode does not exist, and "who was this and what did they decide"
    survives the removal, which is what a decision trail is for.
    """
    state = _require_existing(before, target_id)
    if str(actor_id) == str(target_id):
        raise DomainError("自分自身を無効化することはできません")
    state["active"] = False
    state["sessions_not_before"] = float(at)
    state["access_not_before"] = float(at)
    return _touched(state, actor_id=actor_id, at=at)


def apply_sessions_revoke(before, *, target_id, payload, actor_id, at,
                          config=None):
    """Logout. Revokes the user's standing at this instant, not one token.

    Production revokes the presented access token's JTI and clears the
    refresh cookie, leaving the refresh token itself valid for the rest of
    its 24 hours (ACCIDENTAL A2). Here both die, because both are compared
    against the same `sessions_not_before`.
    """
    state = _require_existing(before, target_id)
    state["sessions_not_before"] = float(at)
    state["access_not_before"] = float(at)
    return _touched(state, actor_id=actor_id, at=at)


__all__ = ["TARGET_USER", "USER_REGISTER", "USER_PASSWORD_SET",
           "USER_ROLE_SET", "USER_DEACTIVATE", "USER_SESSIONS_REVOKE",
           "ACTIONS", "PUBLIC_FIELDS", "user_state", "user_ids", "users",
           "user_count", "public_view", "credential_of", "resolve_user",
           "apply_register", "apply_password_set", "apply_role_set",
           "apply_deactivate", "apply_sessions_revoke"]
