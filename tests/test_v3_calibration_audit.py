"""WP-0.4 v2 (0.4e) — the sampled audit and the freeze it can trigger.

ADR-V3-012 lets C-15's valid cells be counted on the all-labels series
on two conditions, and this file pins the second one. What must hold:

* the sample is DETERMINISTIC — an auditor who reloads sees the same
  list, because a rate measured over a moving sample is not one anybody
  can reproduce (NP6);
* only AUTOMATED labels are sampled — the audit measures the generator,
  and re-checking analysts' work would fold the two series apart;
* a small sample does NOT freeze: one wrong out of two is a 50% rate and
  no evidence, and the under-sampled state is disclosed instead of being
  read as either fine or broken;
* a freeze stops the FUTURE — no new automatic labels, every FN
  candidate waits — and never deletes the past, which is the evidence
  the rate was measured from.
"""
from __future__ import annotations

import pytest

from tests.conclusions_fixtures import healthy, provenance
from v3.calibration import audit as AUDIT
from v3.calibration import runner as RUNNER
from v3.calibration import thresholds as T
from v3.calibration.epoch import CURRENT_EPOCH
from v3.commands import calibration as C
from v3.conclusions import Conclusion, THREAT_LEVEL, to_record
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.ledger.records import CommandRecord, Evidence, SignalObservation

#: Far enough past the epoch's start that a label dated (now - horizon -
#: the 2-day band) still falls INSIDE the epoch window. A closer clock
#: silently pushed every label out of the window this file measures —
#: correct behaviour, and a trap worth naming.
NOW = 1_787_000_000.0
HOUR = 3600.0
DAY = 86400.0
EPOCH = CURRENT_EPOCH.epoch_id
SCENARIO = "taiwan_contingency"


class _Ref:
    scenario_id = SCENARIO
    roles = {"TW": "primary_target", "CN": "adversary"}


REFS = (_Ref(),)


@pytest.fixture()
def store(tmp_path):
    handle = LedgerStore(str(tmp_path / "audit.db"))
    yield handle
    handle.close()


def _label_row(label_id, *, automated=True, label="TRUE_NEGATIVE"):
    return {"label_id": label_id, "is_automated": automated,
            "label": label, "scenario_id": SCENARIO,
            "conclusion_type": "threat_level", "conclusion_id": "c",
            "analyst_id": "auto:ground_truth_etl", "rule_id": "r",
            "observed_at": NOW}


def _sampled_ids(count):
    """Enough ids to find `count` that the hash actually selects."""
    found = []
    index = 0
    while len(found) < count:
        candidate = f"lbl_{index}"
        if AUDIT.is_sampled(candidate):
            found.append(candidate)
        index += 1
    return found


def _audit_command(store, label_id, *, verdict, at=NOW, actor="analyst-1"):
    action = (C.LABEL_AUDIT_CORRECT if verdict == "correct"
              else C.LABEL_AUDIT_INCORRECT)
    store.append_command(CommandRecord(
        command_id=f"cmd-{label_id}-{at:.0f}", action=action,
        target_kind=C.TARGET_LABEL, target_id=label_id, actor_id=actor,
        actor_role="analyst", issued_at=at, before={},
        after={"label_id": label_id, "verdict": verdict},
        payload={"reason": "監査"}, reason="監査"))


class TestTheSampleIsDeterministic:
    def test_the_same_label_is_always_in_or_always_out(self):
        for index in range(50):
            label_id = f"lbl_{index}"
            assert AUDIT.is_sampled(label_id) == AUDIT.is_sampled(label_id)

    def test_the_share_is_roughly_the_pinned_percentage(self):
        chosen = sum(1 for i in range(2000)
                     if AUDIT.is_sampled(f"lbl_{i}"))
        # A hash, not a quota: assert the band, not an exact count.
        assert 0.12 * 2000 < chosen < 0.28 * 2000
        assert T.S9_AUDIT_SAMPLE_PCT == 20.0

    def test_zero_percent_samples_nothing_and_full_samples_all(self):
        assert AUDIT.is_sampled("x", percent=0) is False
        assert AUDIT.is_sampled("x", percent=100) is True

    def test_only_automated_labels_are_sampled(self):
        ids = _sampled_ids(3)
        labels = [_label_row(ids[0]), _label_row(ids[1], automated=False)]
        sampled = AUDIT.sample_of(labels)
        assert [row["label_id"] for row in sampled] == [ids[0]]


class TestTheFreezeNeedsEvidence:
    def _state(self, *, audited, incorrect):
        ids = _sampled_ids(audited)
        labels = [_label_row(label_id) for label_id in ids]
        verdicts = {}
        for position, label_id in enumerate(ids):
            verdicts[label_id] = ("incorrect" if position < incorrect
                                  else "correct")
        return AUDIT.evaluate(labels, verdicts)

    def test_nothing_sampled_is_not_a_pass(self):
        state = AUDIT.evaluate([], {})
        assert state.frozen is False
        assert state.error_rate is None
        assert state.reason == AUDIT.REASON_NO_SAMPLE

    def test_a_small_sample_never_freezes_however_bad(self):
        state = self._state(audited=2, incorrect=2)
        assert state.frozen is False
        assert state.error_rate is None
        assert state.reason == AUDIT.REASON_UNDER_SAMPLE

    def test_a_measured_rate_within_tolerance_does_not_freeze(self):
        state = self._state(audited=10, incorrect=1)
        assert state.error_rate == pytest.approx(0.1)
        assert state.frozen is False
        assert state.reason == AUDIT.REASON_WITHIN_TOLERANCE

    def test_the_boundary_passes(self):
        # `>` freezes, so a rate exactly at the ceiling is admissible —
        # the same convention DESIGN_W_MAX_DROP uses.
        assert T.S9_AUDIT_MAX_ERROR_RATE == 0.1
        assert self._state(audited=10, incorrect=1).frozen is False

    def test_above_the_ceiling_freezes(self):
        state = self._state(audited=10, incorrect=2)
        assert state.error_rate == pytest.approx(0.2)
        assert state.frozen is True
        assert state.reason == AUDIT.REASON_OVER_TOLERANCE


class TestTheFoldReadsTheCommands:
    def test_a_verdict_is_read_back(self, store):
        _audit_command(store, "lbl_x", verdict="incorrect")
        assert AUDIT.audit_verdicts(store) == {"lbl_x": "incorrect"}

    def test_the_latest_verdict_wins(self, store):
        _audit_command(store, "lbl_x", verdict="incorrect", at=NOW)
        _audit_command(store, "lbl_x", verdict="correct", at=NOW + HOUR)
        assert AUDIT.audit_verdicts(store) == {"lbl_x": "correct"}
        # ...and the earlier reading survives as the record it changed.
        assert len(store.command_records(target_kind=C.TARGET_LABEL)) == 2

    def test_an_audit_without_a_reason_is_refused(self):
        with pytest.raises(DomainError):
            C.apply_label_audit_incorrect(None, target_id="lbl_x",
                                          payload={},
                                          actor_id="analyst-1", at=NOW)


class TestAFrozenSeriesStopsGrowing:
    """Exercised against REAL stored labels, not synthetic ids: the
    freeze is only meaningful if the sampler, the fold and the runner
    agree about which rows they are talking about."""

    def _grow_the_series(self, store, *, count=90):
        """Enough automatic labels for the sampler to select >= the
        minimum.

        Every conclusion sits in the band the cycle can actually label:
        older than the 7-day FP/TN horizon (so absence is claimable) and
        newer than the 9-day lookback (so the cycle still reads it).
        That band is 2 days wide, hence the half-hour spacing.
        """
        for index in range(count):
            self._conclusion(
                store,
                observed_at=NOW - T.GT_FP_TN_HORIZON_SEC - 60.0
                - index * 1800.0,
                state="TL5")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new.get("TRUE_NEGATIVE", 0) >= 60, report

    def _freeze(self, store):
        """Condemn every sampled label. Returns how many were judged."""
        labels = store.labels_in_epoch(epoch_id=EPOCH, since=0.0,
                                       until=NOW + DAY)
        sampled = AUDIT.sample_of(labels)
        assert len(sampled) >= T.S9_AUDIT_MIN_SAMPLE, (
            f"only {len(sampled)} sampled; grow the series")
        for row in sampled:
            _audit_command(store, str(row["label_id"]), verdict="incorrect")
        return len(sampled)

    def _conclusion(self, store, *, observed_at, state="TL5"):
        store.append_conclusion(to_record(Conclusion(
            scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
            observed_at=observed_at, confidence=0.5,
            provenance=provenance("tl"), input_health=healthy(),
            state=state, threshold_ref={}, source_urls=(),
            calibration_status={})))

    def _signal(self, store, *, at, source="bg_observer_rss"):
        flags = ({"fatalities": 12, "extractor_confidence": 0.9,
                  "summary": "missile launch"}
                 if source == "bg_observer_rss" else {})
        store.append_signal(SignalObservation(
            tick_id=f"tick-{at:.0f}-{source}", sensor=source,
            signal_source=source, domain="info", country="TW",
            evidence=Evidence.observe({}, source=source, observed_at=at,
                                      freshness_horizon_sec=30 * DAY),
            status="FIRED", raw_score=6.0, confidence=0.7, flags=flags,
            evidence_url="https://example.invalid/a"), at)

    def test_an_unfrozen_cycle_writes_automatic_labels(self, store):
        self._conclusion(store, observed_at=NOW - 8 * DAY, state="TL5")
        report = RUNNER.s9_cycle(store, now=NOW, scenarios=REFS)
        assert report.labels_new.get("TRUE_NEGATIVE") == 1
        assert report.audit["frozen"] is False

    def test_a_healthy_audit_leaves_the_series_growing(self, store):
        self._grow_the_series(store)
        labels = store.labels_in_epoch(epoch_id=EPOCH, since=0.0,
                                       until=NOW + DAY)
        for row in AUDIT.sample_of(labels):
            _audit_command(store, str(row["label_id"]), verdict="correct")
        self._conclusion(store, observed_at=NOW - 8 * DAY, state="TL2")
        report = RUNNER.s9_cycle(store, now=NOW + HOUR, scenarios=REFS)
        assert report.audit["frozen"] is False
        assert report.audit["error_rate"] == 0.0
        assert report.labels_new.get("FALSE_POSITIVE") == 1

    def test_a_frozen_cycle_writes_none_and_says_why(self, store):
        self._grow_the_series(store)
        before = store.count_labels()
        self._freeze(store)

        self._conclusion(store, observed_at=NOW - 8 * DAY, state="TL2")
        report = RUNNER.s9_cycle(store, now=NOW + HOUR, scenarios=REFS)
        assert report.audit["frozen"] is True
        assert report.audit["error_rate"] == pytest.approx(1.0)
        assert report.labels_new == {}
        assert report.unlabelled.get("series_frozen", 0) >= 1
        # The past is untouched: it is the evidence the rate was
        # measured from.
        assert store.count_labels() == before

    def test_a_frozen_cycle_keeps_fn_candidates_as_drafts(self, store):
        self._grow_the_series(store)
        self._freeze(store)

        # Two converging sources: Tier 1 would normally auto-confirm.
        self._conclusion(store, observed_at=NOW - 2 * HOUR, state="TL5")
        self._signal(store, at=NOW - HOUR, source="bg_observer_rss")
        self._signal(store, at=NOW - HOUR, source="gdelt")
        report = RUNNER.s9_cycle(store, now=NOW + HOUR, scenarios=REFS)
        assert report.labels_new.get("FALSE_NEGATIVE") is None
        assert report.drafts_new == 1, "the candidate is kept, not dropped"
