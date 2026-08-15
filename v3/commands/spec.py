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

from v3.auth import store as U
from v3.intel import adjudication as I
from v3.commands import attention as A
from v3.commands import calibration as C
from v3.commands import state as S
from v3.kernel.errors import DomainError

TARGET_KINDS: frozenset = frozenset({S.TARGET_SCENARIO, S.TARGET_CONCLUSION,
                                     S.TARGET_CONFIG, S.TARGET_PROPOSAL,
                                     A.TARGET_ATTENTION,
                                     A.TARGET_ATTENTION_THRESHOLDS,
                                     C.TARGET_DRAFT,
                                     U.TARGET_USER, I.TARGET_INTEL})

#: Field names whose VALUE must never reach a projection, at any depth.
#: WP-4.1g. The user store is a fold of `command_record` like every other
#: state here, and R9 projects that table — so a credential would be
#: served to every reader of the decision trail unless the redaction were
#: structural. It is applied at the ONE place rows become a response
#: (`v3/api/handlers/decisions.py`), by key name and recursively, and
#: `tests/test_api_auth.py` sweeps every registered action's record
#: through R9 looking for the material rather than trusting the list.
SECRET_FIELD_NAMES: frozenset = frozenset({
    "password", "new_password", "old_password", "credential",
    "new_credential",
    "password_hash", "hash", "salt", "secret", "token", "access_token",
    "refresh_token", "key"})

REDACTED = "[redacted]"


def redact(value):
    """A copy with every secret-named field replaced. Never mutates.

    Returns a new structure because the caller is projecting a row that
    other readers (the folds) still need intact — a redactor that edited
    in place would corrupt the state on the way to displaying it.
    """
    if isinstance(value, dict):
        return {key: (REDACTED if key in SECRET_FIELD_NAMES
                      else redact(item)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


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
    CommandSpec(
        action=S.CONFIG_OVERRIDE,
        target_kind=S.TARGET_CONFIG,
        resolve=S.resolve_config,
        apply=S.apply_config_override,
        requires_reason=True,
        effect_key="config",
        summary="P7 C7 — an operationally variable key changes (O-18 group "
                "(a)). THE G-15 endpoint: an override IS a command, so it "
                "gets an actor, a reason and a before/after row, and its "
                "`resolve` is the full 3-layer chain — which makes commit's "
                "effect check a proof that the resolution path reads the "
                "override rather than a claim that it does."),
    CommandSpec(
        action=S.CONFIG_CLEAR,
        target_kind=S.TARGET_CONFIG,
        resolve=S.resolve_config,
        apply=S.apply_config_clear,
        requires_reason=True,
        effect_key="config",
        summary="P7 C7's second half — the override is removed and the key "
                "returns to env-or-default. A reason is required for the "
                "same reason it is on the way in: reverting a dial during "
                "an incident is a decision, and an unexplained one cannot "
                "be audited afterwards."),
    # ── WP-3.3 / P7 C5 — proposal adjudication ──────────────────────────
    #
    # Three of the lifecycle's five edges. `proposal.revive` and
    # `proposal.supersede` are deliberately NOT here: they are automatic
    # transitions the calibration pass makes, and an analyst-facing verb
    # for them would let a human write a row the state machine believes an
    # automaton wrote (production can only tell the two apart by a marker
    # string inside `state_changed_by` — ACCIDENTAL A9).
    CommandSpec(
        action=S.PROPOSAL_APPLY,
        target_kind=S.TARGET_PROPOSAL,
        resolve=S.resolve_proposal,
        apply=S.apply_proposal_apply,
        requires_reason=True,
        effect_key="proposal",
        summary="P7 C5 — an analyst applies a calibration proposal. A "
                "reason is required because applying one moves a threshold "
                "the tool concludes with, and all three calibration "
                "disasters were changes whose basis nobody could recover."),
    CommandSpec(
        action=S.PROPOSAL_DISMISS,
        target_kind=S.TARGET_PROPOSAL,
        resolve=S.resolve_proposal,
        apply=S.apply_proposal_dismiss,
        requires_reason=True,
        effect_key="proposal",
        summary="P7 C5's refusal. Production lets a dismissal of a "
                "non-pending proposal match zero rows and report success, "
                "so the analyst believes they decided something that was "
                "never recorded; here the illegal edge raises."),
    CommandSpec(
        action=S.PROPOSAL_DEFER,
        target_kind=S.TARGET_PROPOSAL,
        resolve=S.resolve_proposal,
        apply=S.apply_proposal_defer,
        requires_reason=True,
        effect_key="proposal",
        summary="P7 C5's 'not now'. NOTE (裁定要求 11, ruled 2026-08-08): "
                "production's revival restores `pending` without moving "
                "`emitted_at` while auto-dismiss reads `emitted_at`, so with "
                "snooze and staleness both at 30 days a deferred proposal is "
                "dismissed on the first tick after it revives. v3 preserves "
                "that behaviour (§7-2 #82) rather than diverging before the "
                "parity window opens."),
    # ── WP-4.1f / P7 C4 — the attention list's analyst half ─────────────
    CommandSpec(
        action=A.ATTENTION_ACK,
        target_kind=A.TARGET_ATTENTION,
        resolve=A.resolve_item,
        apply=A.apply_ack,
        requires_reason=False,
        effect_key="attention_item",
        summary="P7 C4 — the analyst has dealt with this row. Per-actor, "
                "on the server: production kept it in `localStorage`, so it "
                "was per-browser, invisible to the tool and lost with the "
                "cache. It has a reader in two places — R6 annotates the "
                "row, and the next ranking's `analyst_blindness` drops "
                "because the command row IS the evidence somebody looked."),
    CommandSpec(
        action=A.ATTENTION_SNOOZE,
        target_kind=A.TARGET_ATTENTION,
        resolve=A.resolve_item,
        apply=A.apply_snooze,
        requires_reason=False,
        effect_key="attention_item",
        summary="P7 C4 — not now, for a bounded while. Per-actor, where "
                "production's triage snooze was `target_kind='global'` and "
                "one analyst muting the lane muted it for everyone."),
    CommandSpec(
        action=A.ATTENTION_DISMISS,
        target_kind=A.TARGET_ATTENTION,
        resolve=A.resolve_item,
        apply=A.apply_dismiss,
        requires_reason=False,
        effect_key="attention_item",
        summary="P7 C4 — not this, for 24h (production's fixed TTL). Also "
                "per-actor, and also annotation rather than removal: R6 "
                "still returns the row, because a row that vanishes makes "
                "'I dealt with it' and 'I never saw it' look identical."),
    # ── WP-0.4 v2 (0.4e) — the analyst's half of the FN draft queue ─────
    CommandSpec(
        action=C.DRAFT_CONFIRM,
        target_kind=C.TARGET_DRAFT,
        resolve=C.resolve_draft,
        apply=C.apply_draft_confirm,
        requires_reason=True,
        effect_key="draft",
        summary="WP-0.4 v2 — the candidate is a real miss. Materialises a "
                "FALSE_NEGATIVE label under the ANALYST's identity, which "
                "is the population the human-only series (C-12) is made "
                "of. NOT per-actor: an adjudication changes the label set "
                "every reader's recall is computed from, so two analysts "
                "disagreeing must resolve to one state (the later row).",),
    CommandSpec(
        action=C.DRAFT_REJECT,
        target_kind=C.TARGET_DRAFT,
        resolve=C.resolve_draft,
        apply=C.apply_draft_reject,
        requires_reason=True,
        effect_key="draft",
        summary="WP-0.4 v2 — the candidate is not a miss. Writes NO label "
                "(the tool's silence about that conclusion is what 'not a "
                "miss' means) but DOES leave the pending set: a rejected "
                "draft that stayed pending would widen the published "
                "recall interval forever on a question already answered.",),
    CommandSpec(
        action=A.ATTENTION_THRESHOLDS,
        target_kind=A.TARGET_ATTENTION_THRESHOLDS,
        resolve=A.resolve_thresholds,
        apply=A.apply_thresholds,
        requires_reason=False,
        effect_key="thresholds",
        summary="P7 C4's threshold half — THE G-02 endpoint. Production "
                "stores per-user thresholds that its evaluation path never "
                "reads. Here `resolve` is the function the R6 projection "
                "itself calls, so commit()'s effect check is a proof that "
                "the ranking reads the analyst's floor rather than a claim "
                "that it does."),
    # ── WP-4.1g / P7 C13 — identity, credentials and standing ───────────
    #
    # Five edges on ONE state, resolved by ONE function, exactly like the
    # proposal lifecycle. There is no `user` table: a second store holding
    # the same facts would be a second thing to disagree with the audit
    # trail, and the questions such a table would answer — who, when, why,
    # and what it was before — are already columns on `command_record`.
    CommandSpec(
        action=U.USER_REGISTER,
        target_kind=U.TARGET_USER,
        resolve=U.resolve_user,
        apply=U.apply_register,
        requires_reason=False,
        effect_key="user",
        summary="P7 C13 — an identity and its first credential. The reader "
                "is the login path, which resolves the credential from this "
                "same fold, so the effect check proves the credential is "
                "where authentication looks for it."),
    CommandSpec(
        action=U.USER_PASSWORD_SET,
        target_kind=U.TARGET_USER,
        resolve=U.resolve_user,
        apply=U.apply_password_set,
        requires_reason=False,
        effect_key="user",
        summary="P7 C13 — a credential changes and the user's sessions are "
                "revoked in the same row (S1-SVC-007). Production needs two "
                "writes for that and does them outside a transaction."),
    CommandSpec(
        action=U.USER_ROLE_SET,
        target_kind=U.TARGET_USER,
        resolve=U.resolve_user,
        apply=U.apply_role_set,
        requires_reason=True,
        effect_key="user",
        summary="P7 C13 — a change of standing. A reason is required "
                "because a privilege granted without a recorded basis "
                "cannot be reviewed afterwards, and because this is the "
                "row an incident review starts from."),
    CommandSpec(
        action=U.USER_DEACTIVATE,
        target_kind=U.TARGET_USER,
        resolve=U.resolve_user,
        apply=U.apply_deactivate,
        requires_reason=True,
        effect_key="user",
        summary="P7 C13 — deactivation rather than deletion. The decision "
                "trail keeps what this person decided; production DELETEs "
                "the row and orphans the settings row (ACCIDENTAL A3)."),
    CommandSpec(
        action=U.USER_SESSIONS_REVOKE,
        target_kind=U.TARGET_USER,
        resolve=U.resolve_user,
        apply=U.apply_sessions_revoke,
        requires_reason=False,
        effect_key="user",
        summary="P7 C13 — logout. Revokes the user's standing at this "
                "instant rather than one token's JTI, so the refresh token "
                "dies with the access token (production leaves it alive for "
                "the rest of its 24 hours — ACCIDENTAL A2)."),
    # ── WP-4.1g / P7 C3 — intel adjudication ────────────────────────────
    #
    # Three of production's four verbs. `override` is deliberately absent
    # and §7-2 #104 says why: it rewrites the extracted fields, v3's L1 is
    # append-only, and a correction nothing reads is G-15.
    CommandSpec(
        action=I.INTEL_CONFIRM,
        target_kind=I.TARGET_INTEL,
        resolve=I.resolve_intel,
        apply=I.apply_confirm,
        requires_reason=False,
        effect_key="intel_item",
        summary="P7 C3 — the analyst has judged this item good. Its reader "
                "is R11's `?state=` filter, which IS the work queue: a "
                "confirmed item leaves it."),
    CommandSpec(
        action=I.INTEL_REJECT,
        target_kind=I.TARGET_INTEL,
        resolve=I.resolve_intel,
        apply=I.apply_reject,
        requires_reason=True,
        effect_key="intel_item",
        summary="P7 C3 — the item stops scoring. Two readers: R11's queue "
                "and `v3/runtime/scoring.py::observations_at`, which drops "
                "the row. A reason is required because rejecting intel "
                "removes evidence from a conclusion (NP1)."),
    CommandSpec(
        action=I.INTEL_REVERT,
        target_kind=I.TARGET_INTEL,
        resolve=I.resolve_intel,
        apply=I.apply_revert,
        requires_reason=True,
        effect_key="intel_item",
        summary="P7 C3 — undo. Illegal from `pending`, where production "
                "matches zero rows and reports success."),
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
           "SECRET_FIELD_NAMES", "REDACTED", "redact", "spec_for", "find"]
