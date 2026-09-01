"""WP-0.4 v2 (0.4e) — the sampled audit, and the freeze it can trigger.

ADR-V3-012 lets C-15's valid cells be counted on the ALL-LABELS series —
Tier 1's automatic confirms included — on two conditions. The recall
interval is one. This module is the other: the automated label
population is only admissible while a sample of it has been checked and
found right often enough.

The shape is deliberately the opposite of "review everything". Full
manual confirmation was rejected because it makes a human load-bearing
(and because the human reads the same OSINT the tool does, so the value
they add is catching the GENERATOR misbehaving, not supplying new
knowledge). Catching a misbehaving generator is what a sample is for.

    which rows       `is_sampled` — a deterministic hash of the label id.
                     No stored sampling state, no clock, so the same
                     population always yields the same audit list and an
                     auditor cannot be handed a different sample by
                     asking twice.
    the verdict      one command per audited label (`calibration.audit_*`),
                     folded latest-wins like every other decision here.
    the consequence  `freeze_verdict`. Above the measured error ceiling
                     the automated series STOPS GROWING: the runner
                     writes no new automatic labels and every FN
                     candidate waits as a draft instead.

**A freeze stops the future, never the past.** Stored labels are
append-only and stay; what changes is that nothing new joins them and
every consumer is told. Deleting them would destroy the evidence the
error rate was measured from, which is the one thing all three
calibration incidents needed afterwards and did not have.

**Thawing is not a button.** A freeze says this generator's output is
not trustworthy at the measured rate; the remedy is to fix the generator
and declare a new epoch, which is what `LabelEpoch` already models. So
there is deliberately no `unfreeze` command — an operator who could
clear the flag without changing anything would be clearing the
measurement, not the problem.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from v3.calibration import recall as R
from v3.calibration import thresholds as T
from v3.commands import calibration as C

AUDIT_CORRECT = "correct"
AUDIT_INCORRECT = "incorrect"


def is_sampled(label_id: str, *,
               percent: Optional[float] = None) -> bool:
    """Whether this label is in the audit sample. Deterministic.

    Hashed rather than random so the sample is a property of the label
    population and not of when somebody asked — an auditor who reloads
    must see the same list, and a measurement taken over a sample that
    moves is not one anybody can reproduce (NP6).
    """
    share = T.S9_AUDIT_SAMPLE_PCT if percent is None else float(percent)
    if share <= 0:
        return False
    if share >= 100:
        return True
    digest = hashlib.sha256(str(label_id).encode()).hexdigest()
    return (int(digest[:8], 16) % 100) < share


def sample_of(labels: Sequence) -> tuple:
    """The audit list: automated labels the sampler selected.

    Human labels are excluded — the audit measures the GENERATOR, and
    asking an analyst to re-check analysts' work would fold the two
    populations the series separation exists to keep apart.
    """
    return tuple(row for row in labels
                 if row.get("is_automated")
                 and is_sampled(str(row.get("label_id") or "")))


def audit_verdicts(ledger, *, until: Optional[float] = None) -> dict:
    """`{label_id: "correct"|"incorrect"}` — the latest verdict per label."""
    found: dict = {}
    for row in ledger.command_records(target_kind=C.TARGET_LABEL,
                                      until=until):
        if row["action"] == C.LABEL_AUDIT_CORRECT:
            found[str(row["target_id"])] = AUDIT_CORRECT
        elif row["action"] == C.LABEL_AUDIT_INCORRECT:
            found[str(row["target_id"])] = AUDIT_INCORRECT
    return found


@dataclass(frozen=True, slots=True)
class AuditState:
    """What the audit knows, and what follows from it."""

    sampled: int
    audited: int
    incorrect: int
    error_rate: Optional[float]
    frozen: bool
    reason: str

    def as_dict(self) -> dict:
        return {"sampled": self.sampled, "audited": self.audited,
                "incorrect": self.incorrect, "error_rate": self.error_rate,
                "frozen": self.frozen, "reason": self.reason,
                "sample_pct": T.S9_AUDIT_SAMPLE_PCT,
                "max_error_rate": T.S9_AUDIT_MAX_ERROR_RATE,
                "min_sample": T.S9_AUDIT_MIN_SAMPLE}


#: The reasons, named so a caller can branch on them and a reader can
#: tell "nobody has audited yet" from "audited and fine" — G-17 applied
#: to the audit's own state.
REASON_NO_SAMPLE = "no_automated_labels_sampled"
REASON_UNDER_SAMPLE = "audited_below_minimum_sample"
REASON_WITHIN_TOLERANCE = "error_rate_within_tolerance"
REASON_OVER_TOLERANCE = "error_rate_exceeds_tolerance"


def evaluate(labels: Sequence, verdicts: Mapping) -> AuditState:
    """The audit's whole state, from the labels and the fold.

    A too-small sample does NOT freeze. That direction is chosen: one
    wrong label out of two audited is a 50% error rate and no evidence
    at all, and freezing on it would let a single mis-click stop the
    calendar. The under-sampled state is disclosed instead, which is the
    honest reading — "not yet measured" rather than "fine".
    """
    sampled = sample_of(labels)
    audited = [verdicts[str(row["label_id"])] for row in sampled
               if str(row["label_id"]) in verdicts]
    incorrect = sum(1 for verdict in audited if verdict == AUDIT_INCORRECT)
    if not sampled:
        return AuditState(0, 0, 0, None, False, REASON_NO_SAMPLE)
    if len(audited) < T.S9_AUDIT_MIN_SAMPLE:
        return AuditState(len(sampled), len(audited), incorrect, None,
                          False, REASON_UNDER_SAMPLE)
    rate = incorrect / len(audited)
    over = rate > T.S9_AUDIT_MAX_ERROR_RATE
    return AuditState(
        len(sampled), len(audited), incorrect, rate, over,
        REASON_OVER_TOLERANCE if over else REASON_WITHIN_TOLERANCE)


def state_for(store, *, stamp, until: Optional[float] = None) -> AuditState:
    """`evaluate` over one epoch window's labels. The one caller-facing
    entry, so the runner and the reliability read cannot disagree about
    which population was measured."""
    labels = store.labels_in_epoch(
        epoch_id=stamp.epoch_id, since=stamp.since, until=stamp.until)
    return evaluate(labels, audit_verdicts(store, until=until))


__all__ = ["AUDIT_CORRECT", "AUDIT_INCORRECT", "REASON_NO_SAMPLE",
           "REASON_UNDER_SAMPLE", "REASON_WITHIN_TOLERANCE",
           "REASON_OVER_TOLERANCE", "is_sampled", "sample_of",
           "audit_verdicts", "AuditState", "evaluate", "state_for"]
