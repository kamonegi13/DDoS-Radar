"""WP-0.4 v2 (0.4e) — the bridge a human label crosses to reach recall.

The defect this closes, found while wiring the S9 runner: **an analyst's
label never entered the recall arithmetic**. C2 (`conclusion.label`) and
the C4-shaped commands write `command_record` rows, and every recall
number is computed from `calibration_label` — a table whose only writer
was the automated ETL. So `EpochStamp(exclude_auto=True)`, the human-only
series C-12 requires computed beside the all-labels one, was structurally
empty: not "no analyst has labelled anything" but "no analyst CAN".

That is this project's signature defect exactly (see the measurement-vs-
verification note): the surface that was checked sat next to the surface
that mattered. The bridge is deliberately a RECONCILER rather than a
second write inside the command handler:

* one door — `labels.record` stays the only construction site, and the
  command path stays a pure append with no second storage effect to keep
  in a transaction with the first;
* self-healing — a materialisation that failed, or a row written while
  this code did not yet exist, is picked up by the next S9 cycle rather
  than lost;
* idempotent — `label_id_for(conclusion_id, analyst_id, labelled_at)` is
  deterministic and the append is INSERT OR IGNORE, so re-running over
  the same commands converges.

The analyst's identity is the command row's `actor_id`, and `Actor.analyst`
refuses an `auto:`-prefixed one, so a machine cannot arrive here wearing a
person's clothes.
"""
from __future__ import annotations

from typing import Optional, Sequence

from v3.calibration import authority as A
from v3.calibration import labels as L
from v3.calibration.epoch import CURRENT_EPOCH, LabelProvenance
from v3.commands import calibration as C
from v3.kernel.errors import DomainError

#: The generator identity a human label carries. Declared on the current
#: epoch (`epoch.py`: `human_anchor:1`) since WP-3.2 — the design always
#: expected these rows; nothing had ever written one.
HUMAN_GENERATOR_ID = "human_anchor"
HUMAN_GENERATOR_VERSION = "1"

#: Why this label exists, in the `rule_id` slot. Two values, because the
#: two human paths are different evidence: a direct C2 judgement on a
#: conclusion, and a verdict on a machine-proposed FN candidate.
RULE_ANALYST_FEEDBACK = "human_analyst_feedback"
RULE_DRAFT_CONFIRM = "human_draft_confirm"

CONCLUSION_LABEL_ACTION = "conclusion.label"


def _provenance(rule_id: str) -> LabelProvenance:
    return LabelProvenance(
        generator_id=HUMAN_GENERATOR_ID,
        generator_version=HUMAN_GENERATOR_VERSION,
        rule_id=rule_id, epoch_id=CURRENT_EPOCH.epoch_id)


def _submit(store, *, actor_id: str, rule_id: str, conclusion_id: str,
            scenario_id: str, conclusion_type: str, label: str,
            observed_at: float, labelled_at: float,
            observed_outcome_url: Optional[str],
            reason: Optional[str], now: float) -> bool:
    """Write one human label. True if it was new.

    Goes through `authority.authorize` even though the route that
    produced the command was already gated: the permit is what
    `labels.record` demands, and a materialiser that could skip it would
    be a second door into the label population (G-01's shape).
    """
    actor = A.Actor.analyst(actor_id)
    built = L.record(
        authorisation=A.authorize(actor, L.SUBMIT_LABEL),
        provenance=_provenance(rule_id),
        conclusion_id=conclusion_id, scenario_id=scenario_id,
        conclusion_type=conclusion_type, label=label,
        observed_at=float(observed_at), labelled_at=float(labelled_at),
        observed_outcome_url=observed_outcome_url, reason=reason)
    return bool(store.append_label(built, now=float(now)))


def materialise_feedback(store, *, now: float,
                         since: Optional[float] = None) -> int:
    """C2 analyst labels -> `calibration_label`. Returns the new count.

    Every submission is materialised, not only the newest per analyst:
    `latest_per_subject` already folds relabels to the latest, and
    dropping the superseded rows here would delete the forensic record
    of an analyst who changed their mind — the one thing all three
    calibration incidents needed and did not have.
    """
    written = 0
    for row in store.command_records(action=CONCLUSION_LABEL_ACTION,
                                     until=float(now)):
        payload = row.get("payload") or {}
        label = payload.get("label")
        if label not in L.COUNTED_LABELS:
            continue
        actor_id = str(row.get("actor_id") or "")
        if not actor_id or actor_id.startswith(A.AUTOMATED_PREFIX):
            # An automated writer on the C2 path is not a human label and
            # must not enter the human-only series. Skipped loudly-by-
            # counting rather than coerced into an `auto:` label.
            continue
        conclusion_id = str(row.get("target_id") or "")
        stored = store.conclusion_by_id(conclusion_id)
        if stored is None:
            continue
        labelled_at = float(row["issued_at"])
        if since is not None and labelled_at < float(since):
            continue
        observed_at = stored.get("observed_at")
        if observed_at is None:
            continue
        if _submit(store, actor_id=actor_id,
                   rule_id=RULE_ANALYST_FEEDBACK,
                   conclusion_id=conclusion_id,
                   scenario_id=str(stored["scenario_id"]),
                   conclusion_type=str(stored["conclusion_type"]),
                   label=str(label), observed_at=float(observed_at),
                   labelled_at=labelled_at,
                   observed_outcome_url=payload.get(
                       "observed_outcome_url"),
                   reason=payload.get("reason"), now=now):
            written += 1
    return written


def materialise_confirmed_drafts(store, *, now: float,
                                 draft_ids: Optional[Sequence] = None
                                 ) -> int:
    """Confirmed FN drafts -> `calibration_label`. Returns the new count.

    The label is the CLASSIFIER's verdict carried verbatim out of the
    draft (label, rule_id, evidence url) but written under the ANALYST's
    identity: what the human supplied is the judgement that the machine's
    candidate was real, not a re-derivation of it. A confirm that
    recomputed the label would be a second judgement wearing the first
    one's provenance.
    """
    wanted = None if draft_ids is None else {str(x) for x in draft_ids}
    drafts = {row["draft_id"]: row
              for row in store.fn_drafts(epoch_id=CURRENT_EPOCH.epoch_id)}
    written = 0
    for draft_id, draft in drafts.items():
        if wanted is not None and draft_id not in wanted:
            continue
        state = C.draft_state(store, draft_id, until=float(now))
        if C.state_name(state) != C.STATE_CONFIRMED:
            continue
        actor_id = str(state.get("actor_id") or "")
        if not actor_id or actor_id.startswith(A.AUTOMATED_PREFIX):
            raise DomainError(
                f"draft {draft_id!r} was confirmed by {actor_id!r}, which "
                f"is not a human identity: Tier 3 is the human tier, and "
                f"an automated confirm here would enter the human-only "
                f"series (ADR-V3-012's series separation)")
        if _submit(store, actor_id=actor_id, rule_id=RULE_DRAFT_CONFIRM,
                   conclusion_id=str(draft["conclusion_id"]),
                   scenario_id=str(draft["scenario_id"]),
                   conclusion_type=str(draft["conclusion_type"]),
                   label=str(draft["label"]),
                   observed_at=float(draft["observed_at"]),
                   labelled_at=float(state["at"]),
                   observed_outcome_url=draft.get("evidence_url"),
                   reason=state.get("reason"), now=now):
            written += 1
    return written


def pending_drafts(store, *, now: float,
                   epoch_id: Optional[str] = None) -> tuple:
    """THE definition of pending, and there is only one of it.

    A draft is pending when it has no FALSE_NEGATIVE label AND has not
    been rejected. The two exits are deliberately different: a Tier 1 /
    Tier 2 release or a human confirm leaves by GAINING A LABEL, so the
    finding moves straight from the interval's width into its
    denominator with no gap; a reject leaves by the command fold,
    because it will never gain a label and would otherwise widen the
    interval forever on an answered question. See
    `commands/calibration.py::rejected_draft_ids` for why a confirm must
    NOT be subtracted here.
    """
    epoch = epoch_id or CURRENT_EPOCH.epoch_id
    unlabelled = store.unlabelled_fn_drafts(epoch_id=epoch)
    if not unlabelled:
        return ()
    rejected = C.rejected_draft_ids(store, until=float(now))
    return tuple(draft for draft in unlabelled
                 if draft["draft_id"] not in rejected)


def pending_draft_counts(store, *, now: float,
                         epoch_id: Optional[str] = None) -> dict:
    """`pending_drafts` per (scenario_id, conclusion_type) — the width of
    the published interval, cell by cell."""
    counts: dict = {}
    for draft in pending_drafts(store, now=now, epoch_id=epoch_id):
        key = (draft["scenario_id"], draft["conclusion_type"])
        counts[key] = counts.get(key, 0) + 1
    return counts


__all__ = ["HUMAN_GENERATOR_ID", "HUMAN_GENERATOR_VERSION",
           "RULE_ANALYST_FEEDBACK", "RULE_DRAFT_CONFIRM",
           "CONCLUSION_LABEL_ACTION", "materialise_feedback",
           "materialise_confirmed_drafts", "pending_drafts",
           "pending_draft_counts"]
