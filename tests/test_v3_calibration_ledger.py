"""WP-3.3 — the label ledger and the proposal queue, on a real store.

WP-3.2 built the type system for comparing labels and had nowhere to read
from; WP-4.1c deferred five API reads and C4/C5 on the same absence. This
suite covers the storage that closes it, and the two properties that
matter more than the columns:

  * **an unstamped label cannot exist.** Not "is rejected by a validator" —
    cannot be constructed (`LabelRecord`), cannot be written (NOT NULL +
    CHECK), and cannot be built anywhere but `v3/calibration/labels.py`
    (AST). F-16 is a null in exactly this position.
  * **two epochs cannot be pooled.** There is no cross-epoch reader on the
    store at all, so the mistake is not guarded against, it is unavailable.

The proposal half is the same discipline applied to state: there is no
state COLUMN, so there is no UPDATE that can move one, and an analyst
transition from a non-pending state raises instead of silently matching no
row (S1-CALIB-052 / ACCIDENTAL A9).
"""
from __future__ import annotations

import sqlite3

import pytest

from v3.calibration import labels as LBL
from v3.calibration import lifecycle as L
from v3.calibration import matrix as M
from v3.calibration import queue as Q
from v3.calibration.authority import (Actor, UnauthorizedError, authorize)
from v3.calibration.epoch import (CURRENT_EPOCH, EpochMismatchError,
                                  EpochStamp, LabelProvenance)
from v3.calibration.guards import (PHASE_APPLICATION, PHASE_GENERATION,
                                   GuardRequest, ProposalDraft, SystemState,
                                   evaluate)
from v3.calibration.proposals import Proposal
from v3.commands import state as CS
from v3.kernel import Provenance
from v3.kernel.errors import DomainError
from v3.ledger.records import LabelRecord, ProposalRecord
from v3.ledger.store import LedgerStore

EPOCH = CURRENT_EPOCH.epoch_id
SINCE = CURRENT_EPOCH.started_at + 86400.0
NOW = SINCE + 30 * 86400.0
SCENARIO = "taiwan_contingency"
THREAT_LEVEL = "threat_level"


@pytest.fixture()
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "calib.db"))
    yield instance
    instance.close()


def _provenance(generator="rss_etl", version="3", rule="fn_graded_floor"):
    return LabelProvenance(generator_id=generator, generator_version=version,
                           rule_id=rule, epoch_id=EPOCH)


def _analyst(actor_id="u-1"):
    return authorize(Actor.analyst(actor_id), LBL.SUBMIT_LABEL)


def _write(store, *, label="TRUE_POSITIVE", conclusion_id="c-1",
           analyst="u-1", observed_at=None, labelled_at=None,
           scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
           authorisation=None, provenance=None):
    return LBL.submit(
        store,
        authorisation=authorisation or _analyst(analyst),
        provenance=provenance or _provenance(),
        conclusion_id=conclusion_id, scenario_id=scenario_id,
        conclusion_type=conclusion_type, label=label,
        observed_at=SINCE + 100.0 if observed_at is None else observed_at,
        labelled_at=SINCE + 200.0 if labelled_at is None else labelled_at,
        now=NOW)


def _stamp(*, exclude_auto=False, since=None, until=None):
    return EpochStamp(epoch_id=EPOCH,
                      since=SINCE if since is None else since,
                      until=NOW if until is None else until,
                      exclude_auto=exclude_auto)


# ── the label ledger ────────────────────────────────────────────────────
class TestALabelCannotExistWithoutItsEpoch:
    def test_a_blank_epoch_is_refused_by_the_type(self):
        with pytest.raises(DomainError, match="epoch_id"):
            LabelRecord(label_id="l", conclusion_id="c", scenario_id="s",
                        conclusion_type=THREAT_LEVEL, label="TRUE_POSITIVE",
                        analyst_id="u", observed_at=1.0, labelled_at=1.0,
                        generator_id="g", generator_version="1",
                        rule_id="r", epoch_id="  ")

    def test_the_database_refuses_one_too(self, store):
        """The type is the first door; this is the second.

        Both, because the ETL that writes labels in production is a script
        and a script is exactly the caller that reaches for raw SQL.
        """
        with pytest.raises(sqlite3.IntegrityError):
            with store.transaction() as conn:
                conn.execute(
                    "INSERT INTO calibration_label (label_id, conclusion_id, "
                    "scenario_id, conclusion_type, label, analyst_id, "
                    "observed_at, labelled_at, recorded_at, generator_id, "
                    "generator_version, rule_id, epoch_id) "
                    "VALUES ('x','c','s','threat_level','TRUE_POSITIVE','u',"
                    "1.0,1.0,1.0,'g','1','r','')")

    def test_an_undeclared_generator_version_cannot_be_stamped(self):
        """S5-VERIF-032: a generator change advances the epoch."""
        with pytest.raises(DomainError, match="not declared against epoch"):
            LabelProvenance(generator_id="rss_etl", generator_version="99",
                            rule_id="r", epoch_id=EPOCH)

    def test_only_one_module_builds_a_label_record(self):
        assert LBL.unexpected_construction_sites() == ()
        assert LBL.audit_label_construction_sites()

    def test_the_audit_would_notice_a_second_construction_site(self, tmp_path):
        rogue = tmp_path / "v3fake"
        (rogue / "sub").mkdir(parents=True)
        (rogue / "sub" / "shortcut.py").write_text(
            "from v3.ledger.records import LabelRecord\n"
            "row = LabelRecord(label_id='x')\n", encoding="utf-8")
        assert LBL.unexpected_construction_sites(rogue) != ()


class TestOnlyAnAnalystMayLabel:
    def test_a_viewer_is_refused(self):
        with pytest.raises(UnauthorizedError, match="requires 'analyst'"):
            authorize(Actor.viewer("v-1"), LBL.SUBMIT_LABEL)

    def test_a_permit_for_another_action_is_refused(self, store):
        elsewhere = authorize(Actor.analyst("u-1"), "apply_proposal")
        with pytest.raises(UnauthorizedError, match="not 'submit_label'"):
            _write(store, authorisation=elsewhere)

    def test_an_actor_object_is_not_a_permit(self, store):
        with pytest.raises(DomainError, match="needs an Authorisation"):
            LBL.record(authorisation=Actor.analyst("u-1"),
                       provenance=_provenance(), conclusion_id="c",
                       scenario_id=SCENARIO, conclusion_type=THREAT_LEVEL,
                       label="TRUE_POSITIVE", observed_at=SINCE + 1,
                       labelled_at=SINCE + 2)

    def test_an_automated_writer_carries_its_generator_identity(self, store):
        actor = Actor.automated("rss_etl", "3")
        record = _write(store, authorisation=authorize(actor,
                                                       LBL.SUBMIT_LABEL))
        assert record.analyst_id == "auto:rss_etl"
        assert record.is_automated is True
        assert store.labels_for_conclusion("c-1")[0]["is_automated"] is True

    def test_an_automated_writer_cannot_sign_another_generators_label(
            self, store):
        actor = Actor.automated("ground_truth_etl", "3")
        with pytest.raises(DomainError, match="identifies as"):
            _write(store, authorisation=authorize(actor, LBL.SUBMIT_LABEL),
                   provenance=_provenance(generator="rss_etl", version="3"))

    def test_a_label_outside_the_vocabulary_is_refused(self, store):
        with pytest.raises(DomainError, match="unknown label"):
            _write(store, label="UNCLEAR")


class TestTheLedgerIsAppendOnly:
    def test_a_relabel_is_a_new_row_and_both_survive(self, store):
        _write(store, label="TRUE_POSITIVE", labelled_at=SINCE + 200.0)
        _write(store, label="FALSE_POSITIVE", labelled_at=SINCE + 300.0)
        rows = store.labels_for_conclusion("c-1")
        assert [row["label"] for row in rows] == ["TRUE_POSITIVE",
                                                  "FALSE_POSITIVE"]

    def test_the_fold_takes_the_latest_per_analyst(self, store):
        _write(store, label="TRUE_POSITIVE", labelled_at=SINCE + 200.0)
        _write(store, label="FALSE_POSITIVE", labelled_at=SINCE + 300.0)
        folded = LBL.latest_per_subject(store.labels_for_conclusion("c-1"))
        assert [row["label"] for row in folded] == ["FALSE_POSITIVE"]

    def test_an_update_is_refused_by_the_database(self, store):
        _write(store)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            with store.transaction() as conn:
                conn.execute("UPDATE calibration_label SET label = 'FALSE_POSITIVE'")

    def test_a_delete_is_refused_by_the_database(self, store):
        _write(store)
        with pytest.raises(sqlite3.IntegrityError, match="never deleted"):
            with store.transaction() as conn:
                conn.execute("DELETE FROM calibration_label")

    def test_replaying_the_same_label_is_a_no_op(self, store):
        first = _write(store)
        assert store.append_label(first, now=NOW) is False
        assert store.count_labels() == 1

    def test_two_judgements_under_one_identity_are_refused(self, store):
        first = _write(store)
        forged = LabelRecord(
            label_id=first.label_id, conclusion_id=first.conclusion_id,
            scenario_id=first.scenario_id,
            conclusion_type=first.conclusion_type, label="FALSE_NEGATIVE",
            analyst_id=first.analyst_id, observed_at=first.observed_at,
            labelled_at=first.labelled_at, generator_id=first.generator_id,
            generator_version=first.generator_version,
            rule_id=first.rule_id, epoch_id=first.epoch_id)
        with pytest.raises(DomainError, match="already exists"):
            store.append_label(forged, now=NOW)


class TestTwoEpochsCannotBePooled:
    def test_the_store_has_no_cross_epoch_reader(self, store):
        with pytest.raises(TypeError):
            store.labels_in_epoch(since=SINCE, until=NOW)   # no epoch_id

    def test_an_empty_epoch_id_is_refused(self, store):
        with pytest.raises(DomainError, match="needs an epoch_id"):
            store.labels_in_epoch(epoch_id="  ", since=SINCE, until=NOW)

    def test_a_read_returns_only_its_own_epoch(self, store):
        _write(store, conclusion_id="c-1")
        _write(store, conclusion_id="c-2", analyst="u-2",
               provenance=LabelProvenance(generator_id="rss_etl",
                                          generator_version="2",
                                          rule_id="r",
                                          epoch_id="e2026_07_04"))
        rows = store.labels_in_epoch(epoch_id=EPOCH, since=SINCE, until=NOW)
        assert [row["conclusion_id"] for row in rows] == ["c-1"]

    def test_the_aggregation_refuses_a_foreign_row(self):
        row = {"conclusion_id": "c", "analyst_id": "u", "labelled_at": 1.0,
               "epoch_id": "e2026_07_04", "scenario_id": SCENARIO,
               "conclusion_type": THREAT_LEVEL, "label": "TRUE_POSITIVE",
               "id": 1}
        with pytest.raises(EpochMismatchError):
            LBL.cells_from_rows([row], epoch_id=EPOCH)


class TestTheCellsTheRecallChainReads:
    def _population(self, store):
        for index, label in enumerate(
                ["TRUE_POSITIVE", "TRUE_POSITIVE", "FALSE_NEGATIVE",
                 "FALSE_POSITIVE", "TRUE_NEGATIVE"]):
            _write(store, conclusion_id=f"c-{index}", label=label,
                   observed_at=SINCE + 100.0 + index)

    def test_the_four_counters_and_the_analyst_count(self, store):
        self._population(store)
        cell = LBL.cells_for(store, stamp=_stamp())[0]
        assert (cell.tp, cell.fp, cell.tn, cell.fn) == (2, 1, 1, 1)
        assert cell.distinct_analysts == 1
        assert cell.epoch_id == EPOCH

    def test_recall_is_computed_from_the_stored_labels(self, store):
        self._population(store)
        cell = LBL.cells_for(store, stamp=_stamp())[0]
        assert cell.recall == pytest.approx(2 / 3)

    def test_exclude_auto_drops_the_automated_population(self, store):
        self._population(store)
        _write(store, conclusion_id="c-auto", label="TRUE_POSITIVE",
               authorisation=authorize(Actor.automated("rss_etl", "3"),
                                       LBL.SUBMIT_LABEL))
        with_auto = LBL.cells_for(store, stamp=_stamp())[0]
        without = LBL.cells_for(store, stamp=_stamp(exclude_auto=True))[0]
        assert with_auto.tp == 3 and without.tp == 2
        assert with_auto.distinct_analysts == 2

    def test_a_label_outside_the_vocabulary_still_counts_the_analyst(self):
        """S1-CALIB-026 MUST: dropped from the four counters, kept in
        `distinct_analysts`.

        The write door refuses such a label, so the only way one exists is
        a migrated production row — which is exactly the population the
        ETL will carry in, and dropping the analyst entirely would make
        their participation invisible to the coverage half of the metric.
        """
        rows = [
            {"id": 1, "conclusion_id": "c-1", "analyst_id": "u-1",
             "scenario_id": SCENARIO, "conclusion_type": THREAT_LEVEL,
             "label": "TRUE_POSITIVE", "labelled_at": 1.0,
             "epoch_id": EPOCH},
            {"id": 2, "conclusion_id": "c-2", "analyst_id": "u-2",
             "scenario_id": SCENARIO, "conclusion_type": THREAT_LEVEL,
             "label": "UNCLEAR", "labelled_at": 2.0, "epoch_id": EPOCH},
        ]
        cell = LBL.cells_from_rows(rows, epoch_id=EPOCH)[0]
        assert (cell.tp, cell.fp, cell.tn, cell.fn) == (1, 0, 0, 0)
        assert cell.distinct_analysts == 2

    def test_the_window_is_closed_at_both_ends(self, store):
        _write(store, conclusion_id="early", observed_at=SINCE - 1.0)
        _write(store, conclusion_id="edge", observed_at=SINCE)
        _write(store, conclusion_id="late", observed_at=NOW + 1.0)
        rows = store.labels_in_epoch(epoch_id=EPOCH, since=SINCE, until=NOW)
        assert [row["conclusion_id"] for row in rows] == ["edge"]

    def test_a_degenerate_population_cannot_become_evidence(self, store):
        """Incident #1's shape: no negative of either kind was observed."""
        _write(store, conclusion_id="c-1", label="TRUE_POSITIVE")
        _write(store, conclusion_id="c-2", label="TRUE_POSITIVE",
               observed_at=SINCE + 101.0)
        with pytest.raises(M.DegenerateEvidenceError):
            LBL.evidence_for(store, stamp=_stamp())

    def test_a_measurable_population_becomes_evidence(self, store):
        self._population(store)
        evidence = LBL.evidence_for(store, stamp=_stamp())
        assert evidence.cell_count == 1
        assert evidence.pooled_recall == pytest.approx(2 / 3)
        assert evidence.stamp.epoch_id == EPOCH


# ── the proposal lifecycle ──────────────────────────────────────────────
class TestTheStateMachineIsTheClause:
    def test_there_are_exactly_six_states(self):
        assert set(L.STATES) == {"pending", "applied", "dismissed",
                                 "snoozed_30d", "reverted", "superseded"}

    def test_the_four_look_alike_states_do_not_exist(self):
        assert L.FORBIDDEN_STATES.isdisjoint(L.STATES)

    def test_reverted_is_declared_and_unreachable(self):
        """S1-CALIB-052: no path writes `reverted` to the proposal ledger."""
        assert L.REVERTED in L.STATES
        assert L.REVERTED not in L._RESULT_OF.values()
        assert L.vocabulary_disclosure()["unreachable_states"] == ["reverted"]

    def test_pending_is_the_empty_fold(self):
        assert L.state_of(None) == L.PENDING
        assert L.state_of({}) == L.PENDING

    def test_an_analyst_transition_is_legal_from_pending_only(self):
        assert L.may_transition(action=L.PROPOSAL_APPLY, current=L.PENDING)
        assert not L.may_transition(action=L.PROPOSAL_APPLY,
                                    current=L.DISMISSED)

    def test_an_illegal_transition_raises_rather_than_matching_no_row(self):
        applied = L.apply_adjudication(None, action=L.PROPOSAL_APPLY,
                                       actor_id="u", at=NOW)
        with pytest.raises(L.TransitionRefusedError, match="is legal from"):
            L.apply_adjudication(applied, action=L.PROPOSAL_DISMISS,
                                 actor_id="u", at=NOW + 1)

    def test_supersede_may_retire_a_snoozed_proposal(self):
        snoozed = L.apply_adjudication(None, action=L.PROPOSAL_DEFER,
                                       actor_id="u", at=NOW)
        after = L.apply_adjudication(snoozed, action=L.PROPOSAL_SUPERSEDE,
                                     actor_id="auto:emitter", at=NOW + 1)
        assert after["state"] == L.SUPERSEDED

    def test_an_identity_depends_on_the_epoch_it_was_generated_under(self):
        common = {"proposal_type": L.TYPE_TL_THRESHOLD,
                  "scenario_id": SCENARIO, "proposal_key": "tl.x"}
        assert L.proposal_id_for(epoch_id=EPOCH, **common) != \
            L.proposal_id_for(epoch_id="e2026_07_04", **common)

    def test_an_undeclared_proposal_type_has_no_identity(self):
        with pytest.raises(DomainError, match="unknown proposal type"):
            L.proposal_id_for(proposal_type="weight_slightly_off",
                              scenario_id=SCENARIO, proposal_key="k",
                              epoch_id=EPOCH)


class TestTheAutoDismissHooks:
    def test_an_inactive_scenario_dismisses_with_no_time_condition(self):
        assert L.auto_dismiss_marker(
            proposal_type=L.TYPE_WEIGHT_TOO_LOW, emitted_at=NOW,
            now=NOW, scenario_active=False) == L.MARKER_INACTIVE_SCENARIO

    def test_a_diagnostic_type_retires_after_seven_days(self):
        assert L.auto_dismiss_marker(
            proposal_type=L.TYPE_SENSOR_GAP, emitted_at=NOW,
            now=NOW + L.DIAGNOSTIC_STALE_SEC + 1,
            scenario_active=True) == L.MARKER_DIAGNOSTIC_ACK
        assert L.auto_dismiss_marker(
            proposal_type=L.TYPE_SENSOR_GAP, emitted_at=NOW,
            now=NOW + L.DIAGNOSTIC_STALE_SEC, scenario_active=True) is None

    def test_an_actionable_type_retires_after_thirty(self):
        assert L.auto_dismiss_marker(
            proposal_type=L.TYPE_WEIGHT_TOO_HIGH, emitted_at=NOW,
            now=NOW + L.ACTIONABLE_STALE_SEC + 1,
            scenario_active=True) == L.MARKER_TIMEOUT_NO_ACTION


class TestDeferIsStructurallyBroken:
    """S1-CALIB-054 / DP6 (HIGH). Preserved, and proved.

    The clause says the interaction is untested in production. It is the
    one place a DEFECT-PRESERVE ruling has an operational cost an analyst
    would notice — Defer silently means "dismiss in 30 days" — so the port
    reproduces it and the suite states it, rather than quietly repairing
    it here. Registered as §7-2 #82 and escalated as 裁定要求 11.
    """

    def test_a_deferred_proposal_dies_on_the_tick_after_it_revives(self):
        assert L.defer_survives_revival(
            emitted_at=NOW, deferred_at=NOW,
            proposal_type=L.TYPE_WEIGHT_TOO_LOW) is False

    def test_the_snooze_and_the_staleness_window_are_the_same_length(self):
        assert L.SNOOZE_SEC == L.ACTIONABLE_STALE_SEC

    def test_a_diagnostic_type_is_not_saved_by_its_shorter_window_either(self):
        assert L.defer_survives_revival(
            emitted_at=NOW, deferred_at=NOW,
            proposal_type=L.TYPE_SENSOR_GAP) is False

    def test_it_is_alive_for_zero_ticks_not_for_none(self):
        """The boundary is an equality, which is why the defect is easy to
        miss: at exactly the revival instant the proposal is still live."""
        assert L.revival_boundary_is_equality(
            emitted_at=NOW, deferred_at=NOW,
            proposal_type=L.TYPE_WEIGHT_TOO_LOW) is True


# ── the queue ───────────────────────────────────────────────────────────
def _evidence():
    cells = (M.ConfusionCell(scenario_id=SCENARIO,
                             conclusion_type=THREAT_LEVEL, tp=20, fp=4,
                             tn=6, fn=10, distinct_analysts=3,
                             epoch_id=EPOCH),)
    return M.CalibrationEvidence.from_cells(cells, stamp=_stamp())


def _proposal(value=2.5):
    return Proposal(
        key=f"tl_thresholds.{SCENARIO}.tl2", scope_scenario_id=SCENARIO,
        band="tl2", prior_value=3.0, proposed_value=value,
        direction="looser", impact="low", sample_n=40,
        formula_ref="v3.calibration.proposals/v1#tl2_looser",
        provenance=Provenance(
            formula_ref="v3.calibration.proposals/v1#tl2_looser",
            computed_at=NOW, inputs={"recall": 0.66}, source_refs=()))


def _permit(phase=PHASE_GENERATION, *, tier=3):
    action = {PHASE_GENERATION: "generate_proposal",
              PHASE_APPLICATION: "apply_proposal"}[phase]
    request = GuardRequest(
        phase=phase,
        authorisation=authorize(Actor.analyst("u-1"), action),
        draft=ProposalDraft(proposal_type=L.TYPE_TL_THRESHOLD,
                            scenario_id=SCENARIO, target_country=None,
                            direction="looser", impact="low",
                            prior_value=3.0, proposed_value=2.5),
        evidence=_evidence(),
        state=SystemState(now=NOW, tier=tier, last_applied_at=None,
                          motivating_at=NOW - 3600.0, high_applied_at=None,
                          recall_status=M.OK, target_role=None,
                          threshold_key="tl2", scope_scenario_id=SCENARIO))
    ruling = evaluate(request)
    assert ruling.allowed, ruling.blocked_by
    return ruling.permit()


class TestNothingReachesTheQueueWithoutAPermit:
    def test_emission_requires_the_generation_permit(self, store):
        with pytest.raises(DomainError, match="needs a Permit"):
            Q.emit(store, _proposal(), permit=object(), epoch_id=EPOCH,
                   emitted_at=NOW)

    def test_an_application_permit_is_not_a_generation_permit(self, store):
        from v3.calibration.guards import GuardRefusedError
        with pytest.raises(GuardRefusedError, match="phase"):
            Q.emit(store, _proposal(), permit=_permit(PHASE_APPLICATION),
                   epoch_id=EPOCH, emitted_at=NOW)

    def test_a_permitted_proposal_lands_in_the_queue(self, store):
        record = Q.emit(store, _proposal(), permit=_permit(), epoch_id=EPOCH,
                        emitted_at=NOW, now=NOW)
        stored = store.proposal_by_id(record.proposal_id)
        assert stored["proposed_value"] == 2.5
        assert stored["epoch_id"] == EPOCH
        assert stored["evidence"]["recall"] == 0.66

    def test_re_emitting_the_same_proposal_does_not_stack(self, store):
        Q.emit(store, _proposal(), permit=_permit(), epoch_id=EPOCH,
               emitted_at=NOW, now=NOW)
        Q.emit(store, _proposal(), permit=_permit(), epoch_id=EPOCH,
               emitted_at=NOW + 60.0, now=NOW)
        assert store.count_proposals() == 1

    def test_one_identity_cannot_stand_for_two_changes(self, store):
        Q.emit(store, _proposal(2.5), permit=_permit(), epoch_id=EPOCH,
               emitted_at=NOW, now=NOW)
        with pytest.raises(DomainError, match="already exists"):
            Q.emit(store, _proposal(2.9), permit=_permit(), epoch_id=EPOCH,
                   emitted_at=NOW, now=NOW)

    def test_a_raw_dict_is_not_a_proposal(self, store):
        with pytest.raises(DomainError, match="takes a Proposal"):
            Q.record_for({"key": "x"}, epoch_id=EPOCH, emitted_at=NOW)

    def test_the_queue_is_append_only(self, store):
        Q.emit(store, _proposal(), permit=_permit(), epoch_id=EPOCH,
               emitted_at=NOW, now=NOW)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            with store.transaction() as conn:
                conn.execute("UPDATE calibration_proposal SET impact = 'high'")


class TestARefusalLeavesARow:
    """S1-CALIB-041's repair. Production leaves no persistent trace."""

    def _blocked(self):
        request = GuardRequest(
            phase=PHASE_GENERATION,
            authorisation=authorize(Actor.analyst("u-1"),
                                    "generate_proposal"),
            draft=ProposalDraft(proposal_type=L.TYPE_TL_THRESHOLD,
                                scenario_id=SCENARIO, target_country=None,
                                direction="looser", impact="low",
                                prior_value=3.0, proposed_value=2.5),
            evidence=None,
            state=SystemState(now=NOW, tier=3, last_applied_at=None,
                              motivating_at=NOW - 3600.0,
                              high_applied_at=None, recall_status=M.OK,
                              target_role=None, threshold_key="tl2",
                              scope_scenario_id=SCENARIO))
        return evaluate(request)

    def test_the_refusal_is_persistable_and_names_the_guard(self):
        ruling = self._blocked()
        assert ruling.allowed is False
        record = Q.refusal_record(ruling, proposal_id="prop_x")
        assert record["proposal_id"] == "prop_x"
        assert record["blocked_by"]

    def test_an_allowed_ruling_cannot_be_filed_as_a_refusal(self):
        with pytest.raises(DomainError, match="ALLOWED"):
            Q.refusal_record(_permit_ruling(), proposal_id="prop_x")


def _permit_ruling():
    request = GuardRequest(
        phase=PHASE_GENERATION,
        authorisation=authorize(Actor.analyst("u-1"), "generate_proposal"),
        draft=ProposalDraft(proposal_type=L.TYPE_TL_THRESHOLD,
                            scenario_id=SCENARIO, target_country=None,
                            direction="looser", impact="low",
                            prior_value=3.0, proposed_value=2.5),
        evidence=_evidence(),
        state=SystemState(now=NOW, tier=3, last_applied_at=None,
                          motivating_at=NOW - 3600.0, high_applied_at=None,
                          recall_status=M.OK, target_role=None,
                          threshold_key="tl2", scope_scenario_id=SCENARIO))
    return evaluate(request)


class TestTheQueueProjection:
    """P7 R13's read: the emitted row plus its folded state."""

    def _emit(self, store):
        return Q.emit(store, _proposal(), permit=_permit(), epoch_id=EPOCH,
                      emitted_at=NOW, now=NOW)

    def _adjudicate(self, store, record, *, action, at, actor="u-1",
                    reason="演習後の再評価"):
        from v3.ledger.records import CommandRecord
        before = CS.proposal_state(store, record.proposal_id, until=at)
        after = CS.resolve_proposal and L.apply_adjudication(
            before, action=action, actor_id=actor, at=at, reason=reason)
        store.append_command(CommandRecord(
            command_id=f"cmd-{action}-{at}", action=action,
            target_kind=CS.TARGET_PROPOSAL, target_id=record.proposal_id,
            actor_id=actor, actor_role="analyst", issued_at=at,
            before=before, after=after, reason=reason))
        return after

    def test_a_fresh_proposal_reads_pending(self, store):
        self._emit(store)
        entry = Q.entries(store, store, now=NOW + 10)[0]
        assert entry["state"] == L.PENDING
        assert entry["is_terminal"] is False
        assert entry["adjudications"] == []

    def test_an_adjudication_moves_the_projected_state(self, store):
        record = self._emit(store)
        self._adjudicate(store, record, action=L.PROPOSAL_DISMISS,
                         at=NOW + 100)
        entry = Q.entries(store, store, now=NOW + 200)[0]
        assert entry["state"] == L.DISMISSED
        assert entry["is_terminal"] is True
        assert [a["action"] for a in entry["adjudications"]] == \
            [L.PROPOSAL_DISMISS]

    def test_the_projection_replays_to_an_earlier_instant(self, store):
        record = self._emit(store)
        self._adjudicate(store, record, action=L.PROPOSAL_DISMISS,
                         at=NOW + 100)
        earlier = Q.entries(store, store, now=NOW + 200, at=NOW + 50)[0]
        assert earlier["state"] == L.PENDING

    def test_the_state_filter_reads_the_fold_not_a_column(self, store):
        record = self._emit(store)
        assert len(Q.entries(store, store, now=NOW + 10,
                             state=L.PENDING)) == 1
        self._adjudicate(store, record, action=L.PROPOSAL_APPLY, at=NOW + 100)
        assert Q.entries(store, store, now=NOW + 200,
                         state=L.PENDING) == ()
        assert len(Q.entries(store, store, now=NOW + 200,
                             state=L.APPLIED)) == 1

    def test_the_pending_count_is_the_cap_input(self, store):
        self._emit(store)
        assert Q.pending_count(store, store, now=NOW + 10,
                               scenario_id=SCENARIO) == 1

    def test_an_unknown_state_filter_is_refused(self, store):
        with pytest.raises(DomainError, match="unknown state filter"):
            Q.entries(store, store, now=NOW, state="accepted")

    def test_who_moved_it_is_a_field_not_a_marker_string(self, store):
        record = self._emit(store)
        self._adjudicate(store, record, action=L.PROPOSAL_DISMISS,
                         at=NOW + 100, actor="auto:timeout_no_action")
        entry = Q.entries(store, store, now=NOW + 200)[0]
        adjudication = entry["adjudications"][0]
        assert adjudication["actor_id"] == "auto:timeout_no_action"
        assert adjudication["reason"]


class TestTheStoreIsStillOneAuditedObject:
    def test_the_new_module_is_on_the_audited_base_chain(self):
        from v3.api import store_source
        assert "store_calibration.py" in store_source.coverage()["modules"]

    def test_every_new_method_is_classified_by_the_read_seam(self):
        from v3.api import readonly, store_source
        public = store_source.public_methods(store_source.class_methods())
        assert public - readonly.READ_METHODS - readonly.WRITE_METHODS == set()

    def test_the_writes_are_not_reachable_through_the_read_only_ledger(self,
                                                                      store):
        from v3.api.readonly import ReadOnlyLedger
        wrapper = ReadOnlyLedger(store)
        for name in ("append_label", "append_proposal"):
            with pytest.raises(AttributeError):
                getattr(wrapper, name)
        assert callable(wrapper.labels_in_epoch)
        assert callable(wrapper.proposals_between)
