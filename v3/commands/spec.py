"""The command registry: every action the write surface admits.

Same partition discipline as `v3.api.registry` and `v3.conclusions.registry`.
An action a handler can name but the registry does not declare is not a
command — it is a `DomainError` at `commit()`, which means "the surface
grew a verb" is a red build rather than a discovery.

Each spec pairs the two halves of a change:

    resolve   what the state IS, read through the read seam. THE SAME
              function the read projection calls, so a command cannot
              project one state and write against another (there is only
              one projection to be right or wrong about).
    apply     what the state BECOMES, as a pure function of
              `(before, payload)`. No clock, no ledger, no I/O.

`requires_reason` is not decoration. The two actions that feed the
calibration chain demand a stated basis, because all three calibration
disasters were label contamination and an unexplained label is
indistinguishable from a mistaken one after the fact.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from v3.commands import state as S
from v3.kernel.errors import DomainError

TARGET_KINDS: frozenset = frozenset({S.TARGET_SCENARIO, S.TARGET_CONCLUSION})


@dataclass(frozen=True, slots=True)
class Target:
    """What a command acts on. Two fields, both required, no default."""

    kind: str
    id: str

    def __post_init__(self) -> None:
        if self.kind not in TARGET_KINDS:
            raise DomainError(
                f"unknown target kind {self.kind!r}: the command surface "
                f"acts on {sorted(TARGET_KINDS)}. An unregistered kind is a "
                f"row nothing folds, i.e. a change with no state.")
        if not isinstance(self.id, str) or not self.id.strip():
            raise DomainError("a command target needs a non-empty id")

    def as_dict(self) -> dict:
        return {"kind": self.kind, "id": self.id}


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """One action, and the single pair of functions that define it."""

    action: str
    target_kind: str
    resolve: Callable
    apply: Callable
    requires_reason: bool
    effect_key: str
    summary: str

    def __post_init__(self) -> None:
        if self.target_kind not in TARGET_KINDS:
            raise DomainError(f"unknown target kind {self.target_kind!r}")
        for name in ("resolve", "apply"):
            if not callable(getattr(self, name)):
                raise DomainError(
                    f"{self.action}.{name} must be callable: a spec without "
                    f"both halves cannot verify its own effect")
        if not self.effect_key.strip():
            raise DomainError(
                f"{self.action} must name the field its effect is reported "
                f"under; an unnamed effect is one the caller cannot read "
                f"back, which is what G-15 looked like from outside")


SPECS: tuple[CommandSpec, ...] = (
    CommandSpec(
        action=S.FOCUS_SET,
        target_kind=S.TARGET_SCENARIO,
        resolve=S.resolve_focus,
        apply=S.apply_focus,
        requires_reason=False,
        effect_key="focused_scenario",
        summary="P7 C1 — focus registration, moved off the read path "
                "(PROP-001). Focus is what C-lite spends sensor budget on, "
                "so it is server state, not a client preference."),
    CommandSpec(
        action=S.CONCLUSION_LABEL,
        target_kind=S.TARGET_CONCLUSION,
        resolve=S.resolve_labels,
        apply=S.apply_label,
        requires_reason=True,
        effect_key="labels",
        summary="P7 C2 — the G-01 endpoint. Analyst feedback is the "
                "calibration chain's input; a reason is required because "
                "an unexplained label cannot be audited after the fact."),
    CommandSpec(
        action=S.GROUND_TRUTH_ASSERT,
        target_kind=S.TARGET_SCENARIO,
        resolve=S.resolve_ground_truth,
        apply=S.apply_ground_truth,
        requires_reason=True,
        effect_key="ground_truth",
        summary="P7 C9 — human ground truth, S9's teacher signal. Same "
                "reason requirement, same chain."),
)

ACTIONS: tuple[str, ...] = tuple(spec.action for spec in SPECS)


def spec_for(action: str) -> CommandSpec:
    for spec in SPECS:
        if spec.action == action:
            return spec
    raise DomainError(
        f"unknown command action {action!r}: the write surface admits "
        f"{list(ACTIONS)}. An action outside the registry has no resolver, "
        f"so nothing could check that it had the effect it claimed.")


def find(action: str) -> Optional[CommandSpec]:
    for spec in SPECS:
        if spec.action == action:
            return spec
    return None


__all__ = ["Target", "CommandSpec", "SPECS", "ACTIONS", "TARGET_KINDS",
           "spec_for", "find"]
