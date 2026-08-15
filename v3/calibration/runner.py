"""WP-0.4 v2 — S9's driver: the slow cycle that makes labels accumulate.

P4 §S9 puts calibration on its own cadence, deliberately outside the
forward tick ("前向きの流れとは別の遅い周期"), and this module keeps that
literal: nothing here is imported by `v3/runtime/tick.py`, so the C-16
clock does not see it. The composition wires it as a SECOND `Runtime`
whose tick is `maybe_run` — an hourly wake that consults the persisted
last-run instant (`calibration_run`, the F-01 lesson: a schedule survives
a restart, a process counter does not) and runs the daily cycle when due.

One cycle (`s9_cycle`):

    positions   threat_level conclusions of the lookback window
                (attack_mode is OUT of measurement — ADR-V3-012)
    events      graded observations of the scenario's conflict-party
                countries (`etl.event_from_signal`)
    verdicts    `ground_truth.classify` — every judgement is the pure
                classifier's
    releases    TP/FP/TN submit directly under the automated actor;
                FALSE_NEGATIVE passes Tier 1 (`etl.tier1_decision`):
                convergent -> submit, single-source -> pending draft

Idempotence end to end: label ids and draft ids are deterministic and the
appends are INSERT OR IGNORE, so the daily re-scan of a sliding window
converges instead of double-counting — a re-run changes nothing, which is
what makes a crashed cycle safe to simply run again.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from v3.calibration import authority as A
from v3.calibration import etl as ETL
from v3.calibration import ground_truth as GT
from v3.calibration import labels as L
from v3.calibration import thresholds as T
from v3.kernel.errors import DomainError

#: The one automated writer this runner presents. Its generator identity
#: equals the classifier's, because the judgement being recorded is the
#: classifier's — Tier 1 released it, it did not make it.
_ACTOR = A.Actor.automated(GT.GENERATOR_ID, GT.GENERATOR_VERSION)


@dataclass(frozen=True, slots=True)
class S9Report:
    """What one cycle did — stored verbatim in `calibration_run` (AP4)."""

    ran_at: float
    window_start: float
    window_end: float
    scenarios: int
    positions: int
    labels_new: dict = field(default_factory=dict)
    labels_existing: int = 0
    drafts_new: int = 0
    drafts_existing: int = 0
    pending_total: int = 0
    unlabelled: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"ran_at": self.ran_at, "window_start": self.window_start,
                "window_end": self.window_end, "scenarios": self.scenarios,
                "positions": self.positions,
                "labels_new": dict(self.labels_new),
                "labels_existing": self.labels_existing,
                "drafts_new": self.drafts_new,
                "drafts_existing": self.drafts_existing,
                "pending_total": self.pending_total,
                "unlabelled": dict(self.unlabelled)}


def _attributable_countries(ref) -> tuple:
    """The scenario's conflict-party countries (S1-CALIB-002): the only
    ones a ground-truth event may anchor to. `ref` is a ScenarioRef-shaped
    object with `.scenario_id` and `.roles`."""
    roles = getattr(ref, "roles", None) or {}
    return tuple(sorted(code for code, role in roles.items()
                        if GT.may_attribute(role)))


def _labelled_at_for(verdict: GT.LabelVerdict, position: GT.ToolPosition,
                     events: tuple) -> float:
    """A DETERMINISTIC judgement instant, so a re-run converges on the
    same label id (`labels.label_id_for` keys on it).

    Evidence-backed labels date from the newest evidence in the window;
    absence labels (FP/TN) date from the horizon's edge — the first
    instant the claim became makeable.
    """
    in_window = tuple(
        e for e in events
        if GT.in_forward_window(observed_at=position.observed_at,
                                event_at=e.observed_at))
    if verdict.label in ("FALSE_NEGATIVE", "TRUE_POSITIVE") and in_window:
        return max(e.observed_at for e in in_window)
    return position.observed_at + T.GT_FP_TN_HORIZON_SEC


def s9_cycle(store, *, now: float, scenarios: Sequence) -> S9Report:
    """One full calibration pass. Pure orchestration over the store."""
    window_start = float(now) - T.S9_POSITION_LOOKBACK_SEC
    labels_new: dict = {}
    labels_existing = 0
    drafts_new = 0
    drafts_existing = 0
    positions_seen = 0
    unlabelled: dict = {}

    for ref in scenarios:
        scenario_id = getattr(ref, "scenario_id", None)
        if not scenario_id:
            continue
        countries = _attributable_countries(ref)
        if not countries:
            unlabelled["no_conflict_party"] = \
                unlabelled.get("no_conflict_party", 0) + 1
            continue
        events = []
        for country in countries:
            for row in store.signals_between(window_start, float(now),
                                             country=country):
                event = ETL.event_from_signal(row)
                if event is not None:
                    events.append(event)
        events = tuple(events)

        rows = store.conclusions_between(
            scenario_id=str(scenario_id), conclusion_type="threat_level",
            start=window_start, end=float(now))
        for row in rows:
            position = ETL.position_from_conclusion(row, now=float(now))
            if position is None:
                unlabelled["position_unscorable"] = \
                    unlabelled.get("position_unscorable", 0) + 1
                continue
            positions_seen += 1
            verdict = GT.classify(position, events)
            if verdict.label is None:
                unlabelled[verdict.reason] = \
                    unlabelled.get(verdict.reason, 0) + 1
                continue
            conclusion_id = str(row["id"])
            labelled_at = _labelled_at_for(verdict, position, events)

            if verdict.label == "FALSE_NEGATIVE":
                sources = ETL.convergent_sources(position, events)
                if ETL.tier1_decision(sources) == "pending":
                    draft = ETL.draft_for(
                        verdict, scenario_id=str(scenario_id),
                        conclusion_id=conclusion_id,
                        observed_at=position.observed_at,
                        labelled_at=labelled_at, sources=sources)
                    if store.append_fn_draft(draft, now=float(now)):
                        drafts_new += 1
                    else:
                        drafts_existing += 1
                    continue

            built = L.record(
                authorisation=A.authorize(_ACTOR, L.SUBMIT_LABEL),
                provenance=verdict.provenance,
                conclusion_id=conclusion_id, scenario_id=str(scenario_id),
                conclusion_type="threat_level", label=verdict.label,
                observed_at=position.observed_at, labelled_at=labelled_at,
                observed_outcome_url=verdict.evidence_url,
                reason=verdict.reason)
            if store.append_label(built, now=float(now)):
                labels_new[verdict.label] = \
                    labels_new.get(verdict.label, 0) + 1
            else:
                labels_existing += 1

    pending = store.pending_fn_draft_counts(
        epoch_id=_current_epoch_id())
    return S9Report(
        ran_at=float(now), window_start=window_start,
        window_end=float(now), scenarios=len(tuple(scenarios)),
        positions=positions_seen, labels_new=labels_new,
        labels_existing=labels_existing, drafts_new=drafts_new,
        drafts_existing=drafts_existing,
        pending_total=sum(pending.values()), unlabelled=unlabelled)


def _current_epoch_id() -> str:
    from v3.calibration.epoch import CURRENT_EPOCH
    return CURRENT_EPOCH.epoch_id


def maybe_run(store, *, now: float, scenarios: Sequence,
              interval_sec: Optional[float] = None) -> Optional[S9Report]:
    """Run the daily cycle if it is due, else do nothing. The Runtime tick.

    Due-ness reads the PERSISTED last run, so a restart neither skips a
    day nor doubles one. The first ever wake runs immediately — the
    C-15 calendar starts at the first stored label, and waiting a full
    interval before the first cycle would push that instant a day out
    for no reason.
    """
    gap = T.S9_RUN_INTERVAL_SEC if interval_sec is None else \
        float(interval_sec)
    if gap <= 0:
        raise DomainError(f"interval_sec must be positive, got {gap}")
    last = store.latest_s9_run_at()
    if last is not None and float(now) - last < gap:
        return None
    report = s9_cycle(store, now=now, scenarios=scenarios)
    store.append_s9_run(
        ran_at=report.ran_at, window_start=report.window_start,
        window_end=report.window_end, outcome="completed",
        report=report.as_dict())
    return report


__all__ = ["S9Report", "s9_cycle", "maybe_run"]
