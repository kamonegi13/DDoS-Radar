"""Who may write to the calibration system, and who is a machine.

G-01, measured: `POST /api/v2/conclusions/<id>/feedback` carries
`@jwt_required()` and nothing else, while three sibling endpoints in the
same file call `_require_analyst` / `_require_admin`. A feedback label is
the first input of the calibration chain — label → recall metric →
threshold calibrator — and all three calibration disasters began with
contaminated labels. The authorisation hole is not incidental to this
layer; it is a hole in its front door.

The repair is not "remember to call the check". It is that a calibration
write takes an `Authorisation`, and only `authorize()` can mint one. A
function that writes without a permit does not compile into existence:
there is no code path that reaches the write without holding the token.

The second requirement (P4 S9) is identity: an auto-tune proposal must
carry its generator, so an automated label can never be mistaken for an
analyst's. S1-CALIB-007 already encodes the "one vote per source" rule in
production by prefix convention (`auto:`); here the prefix is a
consequence of the constructor rather than a naming habit, and an
`Actor.analyst()` whose id looks automated is refused outright.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from v3.kernel.errors import DomainError

#: The prefix production uses for automated label sources (S1-CALIB-007).
AUTOMATED_PREFIX = "auto:"

# ── the ladder ──────────────────────────────────────────────────────────
VIEWER = "viewer"
ANALYST = "analyst"
ADMIN = "admin"

_RANK: dict[str, int] = {VIEWER: 0, ANALYST: 1, ADMIN: 2}

#: Every action that touches calibration state, with the rank it needs.
#: S2-PROP-021 raises feedback to analyst; the rest follow the sibling
#: endpoints that already gated correctly.
ACTIONS: dict[str, str] = {
    "submit_label": ANALYST,
    "generate_proposal": ANALYST,
    "apply_proposal": ANALYST,
    "reject_proposal": ANALYST,
    "record_threshold_change": ANALYST,
    "revert_threshold_change": ANALYST,
    "advance_tier": ADMIN,
    "declare_epoch": ADMIN,
}


def _text(value, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(f"{name} must be a non-empty string, got {value!r}")
    return value.strip()


@dataclass(frozen=True, slots=True)
class Actor:
    """A human analyst or a named automated generator.

    Built through `analyst()` / `admin()` / `automated()`, never by
    assembling the fields by hand: the whole point is that "an automated
    writer" and "a person" are distinguishable without reading a string
    convention correctly.
    """

    actor_id: str
    role: str
    generator_id: Optional[str] = None
    generator_version: Optional[str] = None

    def __init_subclass__(cls, **kwargs):
        raise TypeError(
            "Actor is final: a subclass could present an automated writer "
            "as a human one, which is the confusion S1-CALIB-007's "
            "one-vote-per-source rule exists to prevent.")

    def __post_init__(self) -> None:
        object.__setattr__(self, "actor_id",
                           _text(self.actor_id, name="actor_id"))
        if self.role not in _RANK:
            raise DomainError(
                f"unknown role {self.role!r}; expected one of "
                f"{sorted(_RANK)}")
        if self.is_automated:
            if not self.generator_id or not self.generator_version:
                raise DomainError(
                    "an automated actor must name its generator and "
                    "version: an auto-tune proposal whose origin is not "
                    "recorded is indistinguishable from an analyst's "
                    "judgement in the ledger (P4 S9)")
        elif self.generator_id or self.generator_version:
            raise DomainError(
                "a human actor must not carry a generator identity; that "
                "is what makes the two kinds of writer distinguishable")

    @property
    def is_automated(self) -> bool:
        return self.actor_id.startswith(AUTOMATED_PREFIX)

    @classmethod
    def analyst(cls, actor_id: str) -> "Actor":
        return cls(actor_id=_reject_automated_id(actor_id), role=ANALYST)

    @classmethod
    def admin(cls, actor_id: str) -> "Actor":
        return cls(actor_id=_reject_automated_id(actor_id), role=ADMIN)

    @classmethod
    def viewer(cls, actor_id: str) -> "Actor":
        return cls(actor_id=_reject_automated_id(actor_id), role=VIEWER)

    @classmethod
    def automated(cls, generator_id: str, generator_version: str, *,
                  role: str = ANALYST) -> "Actor":
        """A generator acting on its own behalf.

        The id is DERIVED from the generator name, so an automated writer
        cannot present itself under a person's identifier.
        """
        gid = _text(generator_id, name="generator_id")
        if gid.startswith(AUTOMATED_PREFIX):
            raise DomainError(
                f"generator_id {gid!r} already carries the {AUTOMATED_PREFIX!r} "
                f"prefix; pass the bare generator name — the prefix is "
                f"applied here so it cannot be forgotten or forged")
        return cls(actor_id=f"{AUTOMATED_PREFIX}{gid}", role=role,
                   generator_id=gid,
                   generator_version=_text(generator_version,
                                           name="generator_version"))

    @property
    def rank(self) -> int:
        return _RANK[self.role]

    def as_dict(self) -> dict:
        return {"actor_id": self.actor_id, "role": self.role,
                "generator_id": self.generator_id,
                "generator_version": self.generator_version,
                "is_automated": self.is_automated}


def _reject_automated_id(actor_id: str) -> str:
    value = _text(actor_id, name="actor_id")
    if value.startswith(AUTOMATED_PREFIX):
        raise DomainError(
            f"actor_id {value!r} uses the {AUTOMATED_PREFIX!r} prefix, "
            f"which is reserved for automated generators "
            f"(S1-CALIB-007): a human writer under that prefix would be "
            f"counted as one machine vote instead of one analyst vote, "
            f"and the distinction is the only thing keeping automated "
            f"labels from outvoting human ones in recall calibration")
    return value


class UnauthorizedError(DomainError):
    """A calibration write attempted without sufficient authority."""


_PERMIT_TOKEN = object()


@dataclass(frozen=True, slots=True)
class Authorisation:
    """Proof that `actor` may perform `action`. Minted only by authorize()."""

    actor: Actor
    action: str
    _token: object = field(default=None, repr=False, compare=False)

    def __init_subclass__(cls, **kwargs):
        raise TypeError("Authorisation is final: a subclass could mint "
                        "itself, which is the whole defect (G-01).")

    def __post_init__(self) -> None:
        if self._token is not _PERMIT_TOKEN:
            raise DomainError(
                "Authorisation must come from authorize(): a permit a "
                "caller can construct is not a permit, it is a comment. "
                "G-01 is what a missing call site costs.")

    def permits(self, action: str) -> bool:
        return self.action == action

    def require(self, action: str) -> "Authorisation":
        """Assert this permit is for `action`, so a permit for a cheap
        action cannot be presented at an expensive door."""
        if not self.permits(action):
            raise UnauthorizedError(
                f"this authorisation is for {self.action!r}, not "
                f"{action!r}")
        return self

    def as_dict(self) -> dict:
        return {"actor": self.actor.as_dict(), "action": self.action}


def authorize(actor: Actor, action: str) -> Authorisation:
    """The only door. Fails closed on anything it does not recognise."""
    if not isinstance(actor, Actor):
        raise UnauthorizedError(
            f"authorize needs an Actor, got {type(actor).__name__}")
    if action not in ACTIONS:
        # ADR-V3-006: v3 fails closed. An unknown action is refused rather
        # than defaulted to the cheapest rank — DP15 records what the
        # opposite choice cost (unknown `applied_by` classified as the
        # LOOSEST impact while being described as "conservative").
        raise UnauthorizedError(
            f"{action!r} is not a declared calibration action; declare it "
            f"in authority.ACTIONS with the rank it needs. Unknown "
            f"actions are refused, not defaulted (ADR-V3-006)")
    required = ACTIONS[action]
    if actor.rank < _RANK[required]:
        raise UnauthorizedError(
            f"{actor.actor_id!r} has role {actor.role!r}; {action!r} "
            f"requires {required!r} or above. A calibration write is an "
            f"input to the recall chain, and every calibration disaster "
            f"so far began with a contaminated input (G-01)")
    return Authorisation(actor=actor, action=action, _token=_PERMIT_TOKEN)


def actions_requiring(role: str) -> tuple:
    return tuple(sorted(a for a, r in ACTIONS.items() if r == role))


__all__ = ["Actor", "Authorisation", "authorize", "UnauthorizedError",
           "ACTIONS", "VIEWER", "ANALYST", "ADMIN", "AUTOMATED_PREFIX",
           "actions_requiring"]
