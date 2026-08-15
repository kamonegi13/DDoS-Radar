"""WP-0.4 v2 (0.4e) — the human half: labels that reach recall, and Tier 3.

The defect this file exists to keep closed: **an analyst's label reached
no measurement**. C2 wrote `command_record`; every recall number reads
`calibration_label`; nothing bridged them, so the human-only series
(`exclude_auto=True`, which C-12 requires computed beside the all-labels
one) was structurally empty — not "nobody has labelled" but "nobody can".

Also pinned here, and load-bearing for NP1:

* a REJECTED draft leaves the pending set (an answered question must not
  widen the interval forever);
* a CONFIRMED draft does NOT leave it until its label exists — otherwise
  recall would read better for the mere act of adjudication, which is
  the dangerous direction;
* an automated actor can never write into the human-only series.
"""
from __future__ import annotations

import pytest

from tests.conclusions_fixtures import healthy, provenance
from v3.calibration import human as HUMAN
from v3.calibration import labels as L
from v3.calibration import runner as RUNNER
from v3.calibration.epoch import CURRENT_EPOCH, EpochStamp
from v3.commands import calibration as C
from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.ledger.records import CommandRecord, Evidence, SignalObservation

NOW = 1_786_100_000.0
HOUR = 3600.0
DAY = 86400.0
EPOCH = CURRENT_EPOCH.epoch_id
SCENARIO = "taiwan_contingency"


class _Ref:
    def __init__(self):
        self.scenario_id = SCENARIO
        self.roles = {"TW": "primary_target", "CN": "adversary"}


REFS = (_Ref(),)


@pytest.fixture()
def store(tmp_path):
    handle = LedgerStore(str(tmp_path / "human.db"))
    yield handle
    handle.close()


def _conclusion(store, *, observed_at=NOW - 2 * HOUR, state="TL5"):
    record = to_record(Conclusion(
        scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
        observed_at=observed_at, confidence=0.5,
        provenance=provenance("tl@S1-CONC-001"), input_health=healthy(),
        state=state, threshold_ref={}, source_urls=(),
        calibration_status={}))
    store.append_conclusion(record)
    return record.conclusion_id if hasattr(record, "conclusion_id") \
        else record.id


def _signal(store, *, at, source="bg_observer_rss", country="TW"):
    flags = ({"fatalities": 12, "extractor_confidence": 0.9}
             if source == "bg_observer_rss" else {})
    store.append_signal(SignalObservation(
        tick_id=f"tick-{at:.0f}-{source}", sensor=source,
        signal_source=source, domain="info", country=country,
        evidence=Evidence.observe({}, source=source, observed_at=at,
                                  freshness_horizon_sec=30 * DAY),
        status="FIRED", raw_score=6.0, confidence=0.7, flags=flags,
        evidence_url=f"https://example.invalid/{source}"), at)


def _command(store, *, action, target_kind, target_id, actor_id, payload,
             at=NOW):
    store.append_command(CommandRecord(
        command_id=f"cmd-{action}-{target_id}-{at:.0f}", action=action,
        target_kind=target_kind, target_id=target_id, actor_id=actor_id,
        actor_role="analyst", issued_at=at, before={}, after=payload,
        payload=payload, reason=payload.get("reason") or "test"))


class TestAnalystLabelsReachRecall:
    def test_a_c2_label_becomes_a_calibration_label(self, store):
        conclusion_id = _conclusion(store)
        _command(store, action=HUMAN.CONCLUSION_LABEL_ACTION,
                 target_kind="conclusion", target_id=conclusion_id,
                 actor_id="analyst-1",
                 payload={"label": "FALSE_NEGATIVE",
                          "reason": "見逃していた",
                          "observed_outcome_url": "https://x.invalid/1"})
        assert HUMAN.materialise_feedback(store, now=NOW) == 1
        rows = store.labels_in_epoch(epoch_id=EPOCH, since=0, until=NOW)
        assert len(rows) == 1
        assert rows[0]["label"] == "FALSE_NEGATIVE"
        assert rows[0]["analyst_id"] == "analyst-1"
        assert rows[0]["is_automated"] is False
        assert rows[0]["generator_id"] == HUMAN.HUMAN_GENERATOR_ID

    def test_the_human_only_series_is_no_longer_structurally_empty(
            self, store):
        conclusion_id = _conclusion(store)
        _command(store, action=HUMAN.CONCLUSION_LABEL_ACTION,
                 target_kind="conclusion", target_id=conclusion_id,
                 actor_id="analyst-1",
                 payload={"label": "TRUE_POSITIVE", "reason": "当たり"})
        HUMAN.materialise_feedback(store, now=NOW)
        stamp = EpochStamp(epoch_id=EPOCH, since=CURRENT_EPOCH.started_at,
                           until=NOW, exclude_auto=True)
        cells = L.cells_for(store, stamp=stamp)
        assert len(cells) == 1
        assert cells[0].tp == 1

    def test_materialisation_is_idempotent(self, store):
        conclusion_id = _conclusion(store)
        _command(store, action=HUMAN.CONCLUSION_LABEL_ACTION,
                 target_kind="conclusion", target_id=conclusion_id,
                 actor_id="analyst-1",
                 payload={"label": "TRUE_POSITIVE", "reason": "r"})
        assert HUMAN.materialise_feedback(store, now=NOW) == 1
        assert HUMAN.materialise_feedback(store, now=NOW + HOUR) == 0
        assert store.count_labels() == 1

    def test_a_relabel_keeps_both_rows_and_the_fold_takes_the_latest(
            self, store):
        conclusion_id = _conclusion(store)
        for at, label in ((NOW - HOUR, "TRUE_POSITIVE"),
                          (NOW, "FALSE_POSITIVE")):
            _command(store, action=HUMAN.CONCLUSION_LABEL_ACTION,
                     target_kind="conclusion", target_id=conclusion_id,
                     actor_id="analyst-1", at=at,
                     payload={"label": label, "reason": "r"})
        assert HUMAN.materialise_feedback(store, now=NOW) == 2
        # Both survive as the forensic record...
        assert store.count_labels() == 2
        # ...and the cell counts the newer judgement only.
        cells = L.cells_for(store, stamp=EpochStamp(
            epoch_id=EPOCH, since=CURRENT_EPOCH.started_at, until=NOW,
            exclude_auto=True))
        assert (cells[0].tp, cells[0].fp) == (0, 1)

    def test_an_automated_actor_never_enters_the_human_series(self, store):
        conclusion_id = _conclusion(store)
        _command(store, action=HUMAN.CONCLUSION_LABEL_ACTION,
                 target_kind="conclusion", target_id=conclusion_id,
                 actor_id="auto:something",
                 payload={"label": "TRUE_POSITIVE", "reason": "r"})
        assert HUMAN.materialise_feedback(store, now=NOW) == 0
        assert store.count_labels() == 0

    def test_an_unknown_label_is_skipped_not_coerced(self, store):
        conclusion_id = _conclusion(store)
        _command(store, action=HUMAN.CONCLUSION_LABEL_ACTION,
                 target_kind="conclusion", target_id=conclusion_id,
                 actor_id="analyst-1",
                 payload={"label": "PROBABLY", "reason": "r"})
        assert HUMAN.materialise_feedback(store, now=NOW) == 0

    def test_the_s9_cycle_reconciles_human_labels(self, store):
        conclusion_id = _conclusion(store)
        _command(store, action=HUMAN.CONCLUSION_LABEL_ACTION,
                 target_kind="conclusion", target_id=conclusion_id,
                 actor_id="analyst-1",
                 payload={"label": "TRUE_POSITIVE", "reason": "r"})
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.human_labels_new == 1


class TestTier3Adjudication:
    def _pending_draft(self, store):
        _conclusion(store)
        _signal(store, at=NOW - HOUR, source="bg_observer_rss")
        RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        drafts = store.fn_drafts(epoch_id=EPOCH)
        assert len(drafts) == 1
        return drafts[0]["draft_id"]

    def test_a_rejected_draft_leaves_the_pending_set(self, store):
        draft_id = self._pending_draft(store)
        assert len(HUMAN.pending_drafts(store, now=NOW)) == 1
        _command(store, action=C.DRAFT_REJECT,
                 target_kind=C.TARGET_DRAFT, target_id=draft_id,
                 actor_id="analyst-1",
                 payload={"reason": "誤検出", "state": "rejected"})
        assert HUMAN.pending_drafts(store, now=NOW) == ()
        # ...and no label was written: silence IS "not a miss".
        assert store.count_labels() == 0

    def test_a_confirmed_draft_stays_pending_until_its_label_exists(
            self, store):
        draft_id = self._pending_draft(store)
        _command(store, action=C.DRAFT_CONFIRM,
                 target_kind=C.TARGET_DRAFT, target_id=draft_id,
                 actor_id="analyst-1",
                 payload={"reason": "実際の見逃し", "state": "confirmed",
                          "actor_id": "analyst-1", "at": NOW})
        # THE guard: adjudication alone must not narrow the interval, or
        # recall would improve for the act of being looked at.
        assert len(HUMAN.pending_drafts(store, now=NOW)) == 1
        assert HUMAN.materialise_confirmed_drafts(store, now=NOW) == 1
        assert HUMAN.pending_drafts(store, now=NOW) == ()

    def test_a_confirmed_draft_becomes_the_analysts_own_label(self, store):
        draft_id = self._pending_draft(store)
        _command(store, action=C.DRAFT_CONFIRM,
                 target_kind=C.TARGET_DRAFT, target_id=draft_id,
                 actor_id="analyst-7",
                 payload={"reason": "実際の見逃し", "state": "confirmed",
                          "actor_id": "analyst-7", "at": NOW})
        HUMAN.materialise_confirmed_drafts(store, now=NOW)
        rows = store.labels_in_epoch(epoch_id=EPOCH, since=0, until=NOW + DAY)
        assert [(r["label"], r["analyst_id"], r["is_automated"])
                for r in rows] == [("FALSE_NEGATIVE", "analyst-7", False)]
        # The classifier's rule_id is NOT reused: the human supplied the
        # judgement that the candidate was real.
        assert rows[0]["rule_id"] == HUMAN.RULE_DRAFT_CONFIRM

    def test_the_latest_verdict_wins(self, store):
        draft_id = self._pending_draft(store)
        _command(store, action=C.DRAFT_REJECT, target_kind=C.TARGET_DRAFT,
                 target_id=draft_id, actor_id="analyst-1", at=NOW,
                 payload={"reason": "誤検出", "state": "rejected"})
        _command(store, action=C.DRAFT_CONFIRM, target_kind=C.TARGET_DRAFT,
                 target_id=draft_id, actor_id="analyst-1", at=NOW + HOUR,
                 payload={"reason": "やはり見逃し", "state": "confirmed",
                          "actor_id": "analyst-1", "at": NOW + HOUR})
        # No longer rejected, so pending again until the label lands.
        assert len(HUMAN.pending_drafts(store, now=NOW + 2 * HOUR)) == 1
        assert C.state_name(C.draft_state(
            store, draft_id, until=NOW + 2 * HOUR)) == C.STATE_CONFIRMED

    def test_an_automated_confirm_is_refused(self, store):
        draft_id = self._pending_draft(store)
        _command(store, action=C.DRAFT_CONFIRM, target_kind=C.TARGET_DRAFT,
                 target_id=draft_id, actor_id="auto:llm",
                 payload={"reason": "同意", "state": "confirmed",
                          "actor_id": "auto:llm", "at": NOW})
        with pytest.raises(DomainError):
            HUMAN.materialise_confirmed_drafts(store, now=NOW)

    def test_an_adjudication_requires_a_reason(self):
        with pytest.raises(DomainError):
            C.apply_draft_confirm(None, target_id="d1", payload={},
                                  actor_id="analyst-1", at=NOW)

    def test_a_pending_draft_with_no_verdict_reads_pending(self, store):
        draft_id = self._pending_draft(store)
        assert C.state_name(C.draft_state(store, draft_id)) == \
            C.STATE_PENDING
