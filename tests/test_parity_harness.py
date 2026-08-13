"""WP-2.8 — the harness end to end, on synthetic fixtures.

These tests actually spawn the legacy driver and run the REAL
`radar.scoring` functions against the same ledger window v3 reads, which
makes them the first place the two implementations have ever been
compared. They are correspondingly the most valuable tests in the package
and the slowest: the subprocess is spawned once per test that needs it.

The 30-day production run is documented in `v3.parity.PROCEDURE` and is
not executed here — the window does not open until 2026-09-05.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from v3.kernel import Evidence, Ratio, ThreatLevel
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore, SignalObservation
from v3.parity import (ParityLedger, RunIdentity, SCOPE_NOTES, run_parity)
from v3.parity.compare import MATCH, THREAT_LEVEL, TickKey, compare_tick
from v3.parity.conditions import (BLOCKED, CONDITIONS, FAIL, NOT_MEASURED,
                                  PASS)
from v3.parity.ledger import MismatchEvidence
from v3.scoring import Participant, Scenario

# The harness spawns subprocesses, and pytest runs under gevent's
# monkey-patched threading (root conftest.py), so every spawn warns about
# fork() in a multi-threaded process. The warning is about the TEST
# process, not the harness: `subprocess.run` execs immediately.
pytestmark = pytest.mark.filterwarnings(
    "ignore:This process .* is multi-threaded")

REPO_ROOT = Path(__file__).resolve().parent.parent
T0 = 1_700_000_000.0
TICK = 120.0
HORIZON = 600.0


def taiwan() -> Scenario:
    return Scenario(
        scenario_id="taiwan_contingency", core_country="TW",
        participants=(Participant("TW", Ratio(1.0), "primary_target"),
                      Participant("US", Ratio(0.8), "primary_ally"),
                      Participant("JP", Ratio(0.8), "forward_base")))


def _observation(tick_index, sensor, domain, score, country="TW", *,
                 source=None, status="FIRED", suppressed=False):
    at = T0 + tick_index * TICK
    return SignalObservation(
        tick_id=f"t{tick_index}", sensor=sensor,
        signal_source=source or sensor, domain=domain, country=country,
        evidence=Evidence.observe({"v": score}, observed_at=at,
                                  freshness_horizon_sec=HORIZON,
                                  source=sensor),
        status=status, raw_score=score, confidence=1.0,
        suppressed=suppressed)


def _confirm_intel(store, *, at):
    """Adjudicate every LLM intel row in the store as `confirmed`.

    Through the ordinary command seam rather than by writing a row, so the
    fixture exercises the same fold the scoring predicate reads.
    """
    from v3.api.readonly import ReadOnlyLedger
    from v3.api.request import Principal, ReadContext
    from v3.api.write import Change, WriteContext
    from v3.api.writeonly import CommandLedger
    from v3.commands import spec as SPEC
    from v3.intel import adjudication as INTEL

    reader = ReadOnlyLedger(store)
    context = WriteContext(
        read=ReadContext(ledger=reader, now=at), ledger=CommandLedger(store),
        principal=Principal(user_id="parity-fixture", role="analyst"))
    for row in store.signals_between(at - HORIZON, at):
        if not INTEL.is_intel_row(row):
            continue
        context.commit(Change(
            action=INTEL.INTEL_CONFIRM,
            target=SPEC.Target(kind=INTEL.TARGET_INTEL, id=str(row["id"])),
            payload={}, reason="parity fixture: adjudicated so both systems "
                               "admit the row"))


@pytest.fixture
def seeded(tmp_path):
    """A ledger with a rising then falling signal series."""
    store = LedgerStore(str(tmp_path / "v3.db"))
    # Ticks 0-2: quiet cyber. 3-5: cyber + physical strong (should escalate).
    # 6-8: quiet again (hysteresis should slow the descent).
    plan = [
        (0, [("ioda", "cyber", 1.0)]),
        (1, [("ioda", "cyber", 1.0)]),
        (2, [("ioda", "cyber", 4.0), ("isr", "physical", 4.0)]),
        (3, [("ioda", "cyber", 6.0), ("isr", "physical", 6.0)]),
        (4, [("ioda", "cyber", 6.0), ("isr", "physical", 6.0)]),
        (5, [("ioda", "cyber", 1.0)]),
        (6, [("ioda", "cyber", 1.0)]),
        (7, [("ioda", "cyber", 1.0)]),
    ]
    for index, entries in plan:
        at = T0 + index * TICK
        for sensor, domain, score in entries:
            # `now=at` is the documented replay-seeding path: freshness is
            # evaluated at the observation's own instant rather than
            # against the wall clock, which a fixture can never satisfy.
            store.append_signal(_observation(index, sensor, domain, score),
                                now=at)
    yield store, tmp_path
    store.close()


@pytest.fixture
def parity_ledger(tmp_path):
    ledger = ParityLedger(str(tmp_path / "parity.db"))
    yield ledger
    ledger.close()


def _run(store, parity, **kwargs):
    return run_parity(
        store=store, parity_ledger=parity, scenarios=(taiwan(),),
        start=T0, end=T0 + 7 * TICK, tick_interval_sec=TICK,
        legacy_code_version="fixture-legacy", v3_code_version="fixture-v3",
        now=T0, **kwargs)


# ── the legacy driver's isolation, which everything else rests on ────────

class TestLegacySandbox:
    def test_the_subprocess_does_not_boot_the_application(self, seeded,
                                                          parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        sandbox = run.sandbox
        assert sandbox.booted_application is False
        assert sandbox.thread_count == 1
        assert not any(m.startswith("radar.routes") or
                       m.startswith("radar.sensors")
                       for m in sandbox.radar_modules)

    def test_only_the_scoring_dependency_chain_loads(self, seeded,
                                                     parity_ledger):
        """Against the driver's own declared set, not a second copy of it.

        A transcription here would let the declaration grow without the
        suite noticing, which is exactly the drift the declaration exists
        to catch.
        """
        from v3.parity.driver_v2 import EXPECTED_MODULES
        store, _ = seeded
        run = _run(store, parity_ledger)
        assert set(run.sandbox.radar_modules) <= EXPECTED_MODULES

    def test_the_only_database_call_attempted_is_a_refused_read(
            self, seeded, parity_ledger):
        """Reported, not implied-away.

        `radar/scenarios.py:232` consults the reserved-identifier table
        while parsing a Scenario. The stub refuses it and the legacy code
        carries on; no write is attempted anywhere. Asserting exactly this
        set means a NEW database call appearing in the scoring path fails
        the suite instead of passing silently.
        """
        store, _ = seeded
        run = _run(store, parity_ledger)
        assert set(run.sandbox.database_attempts) == {"_get_conn"}

    def test_the_production_database_is_untouched(self, seeded, parity_ledger):
        """S5-VERIF-021, checked against the real file's mtime."""
        production = REPO_ROOT / "radar" / "persistence" / "radar.db"
        before = production.stat().st_mtime if production.exists() else None
        store, _ = seeded
        _run(store, parity_ledger)
        after = production.stat().st_mtime if production.exists() else None
        assert before == after

    def test_a_booted_run_would_be_rejected(self):
        """The verification is real, not decorative."""
        from v3.parity.driver_v2 import SandboxEvidence
        evidence = SandboxEvidence(radar_modules=("radar", "radar.routes.core"))
        assert evidence.booted_application is True


class TestSubprocessIsInertWhenImported:
    def test_importing_the_driver_module_pulls_no_radar(self):
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys, v3.parity._v2_subprocess; "
             "print(any(m.startswith('radar') for m in sys.modules))"],
            capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=120)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"


# ── the two systems, compared ────────────────────────────────────────────

class TestBothSidesAgree:
    def test_the_scoring_core_reaches_full_agreement(self, seeded,
                                                     parity_ledger):
        """The payoff: v3's ported formulas against the real legacy ones."""
        store, _ = seeded
        run = _run(store, parity_ledger)
        summary = run.report.summary
        assert summary.both_present > 0
        assert summary.one_side_missing == 0
        assert summary.agreement_rate == pytest.approx(1.0)
        assert summary.insensitive == 0

    def test_the_series_actually_moves(self, seeded, parity_ledger):
        """A comparison over a flat TL5 series would prove nothing."""
        store, _ = seeded
        run = _run(store, parity_ledger)
        levels = {reading.threat_level.value
                  for _, reading in run.v3_result.series_for(
                      "taiwan_contingency")}
        assert len(levels) > 1

    def test_hysteresis_shows_up_on_both_sides_identically(self, seeded,
                                                           parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        v3_series = [r.threat_level.value for _, r in
                     run.v3_result.series_for("taiwan_contingency")]
        legacy_series = [r.threat_level.value for _, r in
                         run.legacy_result.series_for("taiwan_contingency")]
        assert v3_series == legacy_series

    def test_contributing_sets_agree_too(self, seeded, parity_ledger):
        """S5-VERIF-028: agreeing TLs on disagreeing evidence is chance."""
        store, _ = seeded
        run = _run(store, parity_ledger)
        assert run.report.summary.jaccard_median == pytest.approx(1.0)
        assert run.report.summary.jaccard_p05 == pytest.approx(1.0)

    def test_both_sides_report_their_formula_reference(self, seeded,
                                                       parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        assert "radar/scoring.py" in run.legacy_result.formula_ref
        assert "v3.scoring" in run.v3_result.formula_ref


class TestDisagreementIsDetected:
    """The judgement pipeline on a disagreeing series.

    Driven from constructed readings rather than from the two drivers,
    because the drivers AGREE — which is the desired state, and leaves no
    way to exercise the failure path through them. Both sides receive the
    same settings by construction in `run_parity`, so there is no knob
    that makes real disagreement appear either.
    """

    def _summary_for(self, scenario_id, legacy_levels, v3_levels):
        from v3.parity.compare import Reading
        from v3.parity.summary import summarise
        comparisons = []
        for index, (legacy, v3) in enumerate(zip(legacy_levels, v3_levels)):
            comparisons.append(compare_tick(
                TickKey(scenario_id, THREAT_LEVEL, T0 + index * TICK),
                Reading(threat_level=ThreatLevel(legacy)),
                Reading(threat_level=ThreatLevel(v3))))
        return summarise(comparisons)

    def _report(self, legacy_levels, v3_levels, *, extra=None,
                null_zone=None, attribution=None):
        from v3.parity.report import ParityContext, build_report
        from v3.parity.summary import summarise
        summaries = {"taiwan_contingency": self._summary_for(
            "taiwan_contingency", legacy_levels, v3_levels)}
        summaries.update(extra or {})
        zones = null_zone or {
            scenario_id: {"legacy_longest_sec": 0.0, "v3_longest_sec": 0.0}
            for scenario_id in summaries}
        return build_report(ParityContext(
            tick_interval_sec=TICK,
            threat_level_summary=summarise([]),
            scenario_summaries=summaries, null_zone=zones,
            difference_attribution=attribution))

    def test_a_quieter_v3_fails_c03_however_high_the_rate(self):
        """NP1: one insensitive disagreement blocks at 0.99 agreement."""
        legacy = [3] * 99 + [2]
        v3 = [3] * 99 + [4]
        report = self._report(legacy, v3)
        scoped = report.context.scenario_summaries["taiwan_contingency"]
        assert scoped.agreement_rate == pytest.approx(0.99)
        assert scoped.insensitive == 1
        verdict = report.verdict_for("C-03")
        assert verdict.status == FAIL
        assert "insensitive" in verdict.detail

    def test_a_louder_v3_fails_only_as_an_unregistered_difference(self):
        """NP1's asymmetry survives ADR-V3-011, in its new shape.

        A sensitive difference still has to be ATTRIBUTED — §5-C rule 1
        leaves exactly two options, revert the code or register the entry
        in §7-2, and "leave it silently" is not one of them. What the
        direction buys is that the resulting failure is waivable, because
        sensitive and neutral entries take batch approval.
        """
        legacy = [3] * 99 + [4]
        v3 = [3] * 99 + [2]
        report = self._report(legacy, v3)
        scoped = report.context.scenario_summaries["taiwan_contingency"]
        assert scoped.sensitive == 1
        verdict = report.verdict_for("C-03")
        assert verdict.status == FAIL
        assert verdict.evidence["unregistered_insensitive"] == 0
        assert verdict.waive(reason="§7-2 batch approval").waived is True

    def test_a_registered_louder_v3_passes(self):
        legacy = [3] * 99 + [4]
        v3 = [3] * 99 + [2]
        report = self._report(legacy, v3, attribution={
            "taiwan_contingency": {"unregistered": 0,
                                   "insensitive_unjustified": 0}})
        assert report.verdict_for("C-03").status == PASS

    def test_a_low_agreement_rate_fails_c03(self):
        legacy = [3] * 50 + [4] * 50
        v3 = [3] * 50 + [2] * 50
        report = self._report(legacy, v3)
        scoped = report.context.scenario_summaries["taiwan_contingency"]
        assert scoped.agreement_rate == pytest.approx(0.5)
        assert report.verdict_for("C-03").status == FAIL

    def test_full_agreement_passes_c03(self):
        report = self._report([3] * 20, [3] * 20)
        assert report.verdict_for("C-03").status == PASS

    def test_a_sick_scenario_cannot_hide_behind_a_healthy_one(self):
        """C-03 is judged per scenario, never on the pool.

        A small scenario at 0.75 agreement disappears inside a large one
        at 1.0 when the rates are pooled — 396/400 overall clears 0.95
        while one scenario is badly broken.
        """
        sick = self._summary_for("korea", [3] * 300 + [4] * 100,
                                 [3] * 300 + [2] * 100)
        report = self._report([3] * 400, [3] * 400, extra={"korea": sick})
        assert sick.agreement_rate == pytest.approx(0.75)
        verdict = report.verdict_for("C-03")
        assert verdict.status == FAIL
        assert "korea" in verdict.detail
        rates = verdict.evidence["per_scenario_agreement"]
        assert rates["taiwan_contingency"] == pytest.approx(1.0)
        assert rates["korea"] == pytest.approx(0.75)

    def test_the_verdict_lists_every_scenario_rate(self):
        healthy = self._summary_for("korea", [3] * 20, [3] * 20)
        report = self._report([3] * 20, [3] * 20, extra={"korea": healthy})
        verdict = report.verdict_for("C-03")
        assert verdict.status == PASS
        assert set(verdict.evidence["per_scenario_agreement"]) == {
            "taiwan_contingency", "korea"}

    def test_c09_no_longer_measures_against_the_legacy_null_zone(self):
        """ADR-V3-011 replaced 「旧系と同等以下」 with an absolute bar.

        v1's null zone is the artefact of having ONE unavailable reason
        (F-12), so matching it is agreement with a defect rather than a
        health property. korea's v3 zone is ten times its own legacy
        figure here and still passes: seven days is the bar.
        """
        healthy = self._summary_for("korea", [3] * 20, [3] * 20)
        report = self._report(
            [3] * 20, [3] * 20, extra={"korea": healthy},
            null_zone={
                "taiwan_contingency": {"legacy_longest_sec": 5000.0,
                                       "v3_longest_sec": 0.0},
                "korea": {"legacy_longest_sec": 100.0,
                          "v3_longest_sec": 1000.0}})
        assert report.verdict_for("C-09").status == PASS

    def test_a_null_zone_past_the_absolute_bar_fails(self):
        healthy = self._summary_for("korea", [3] * 20, [3] * 20)
        report = self._report(
            [3] * 20, [3] * 20, extra={"korea": healthy},
            null_zone={
                "taiwan_contingency": {"v3_longest_sec": 0.0},
                "korea": {"v3_longest_sec": 8 * 86_400.0}})
        verdict = report.verdict_for("C-09")
        assert verdict.status == FAIL
        assert "korea" in verdict.detail
        assert verdict.evidence["per_series"]["korea"][
            "v3_longest_sec"] == 8 * 86_400.0

    def test_a_uniformly_better_null_zone_passes(self):
        healthy = self._summary_for("korea", [3] * 20, [3] * 20)
        report = self._report(
            [3] * 20, [3] * 20, extra={"korea": healthy},
            null_zone={
                "taiwan_contingency": {"legacy_longest_sec": 5000.0,
                                       "v3_longest_sec": 100.0},
                "korea": {"legacy_longest_sec": 100.0,
                          "v3_longest_sec": 100.0}})
        assert report.verdict_for("C-09").status == PASS


class TestWaivers:
    """P2 §5 marks four conditions override-forbidden; the type enforces it.

    The directional refusal (C-03's insensitive half, C-17's register)
    lives in `test_parity_conditions.py`.
    """

    def _failed(self, condition_id):
        from v3.parity.conditions import ConditionVerdict
        return ConditionVerdict(condition_id, FAIL, "for the test")

    @pytest.mark.parametrize("condition_id",
                             ["C-02", "C-08", "C-14", "C-17"])
    def test_the_forbidden_four_cannot_be_waived(self, condition_id):
        with pytest.raises(DomainError, match="override-forbidden"):
            self._failed(condition_id).waive(reason="we accept the risk")

    def test_a_waivable_condition_can_be_waived_with_a_reason(self):
        waived = self._failed("C-03").waive(
            reason="registered intentional difference, P2 §5-C")
        assert waived.waived is True
        assert "P2" in waived.waiver_reason

    def test_a_waiver_never_becomes_a_pass(self):
        waived = self._failed("C-03").waive(reason="registered difference")
        assert waived.status == FAIL

    def test_a_waiver_requires_a_written_reason(self):
        with pytest.raises(DomainError, match="written reason"):
            self._failed("C-03").waive(reason="   ")

    def test_only_a_failure_can_be_waived(self):
        from v3.parity.conditions import ConditionVerdict
        with pytest.raises(DomainError, match="nothing to waive"):
            ConditionVerdict("C-03", PASS, "fine").waive(reason="why")


# ── the parity ledger ────────────────────────────────────────────────────

class TestParityLedgerRecording:
    def test_every_verdict_is_recorded(self, seeded, parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        assert parity_ledger.count(run.parity_run_id) == \
            run.report.summary.total_keys

    def test_the_run_resolves_to_its_window_and_versions(self, seeded,
                                                         parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        row = parity_ledger.run(run.parity_run_id)
        assert row["window_start"] == T0
        assert row["legacy_code_version"] == "fixture-legacy"
        assert row["v3_code_version"] == "fixture-v3"
        assert row["input_snapshot_id"]
        assert json.loads(row["provenance"])["formula_ref"]

    def test_the_snapshot_id_is_content_derived(self, seeded, parity_ledger):
        from v3.parity.adapter import LedgerInputAdapter
        store, _ = seeded
        adapter = LedgerInputAdapter(store, tick_interval_sec=TICK)
        first = adapter.snapshot_id(T0, T0 + 7 * TICK)
        assert first == adapter.snapshot_id(T0, T0 + 7 * TICK)
        store.append_signal(_observation(9, "extra", "info", 2.0),
                            now=T0 + 9 * TICK)
        assert adapter.snapshot_id(T0, T0 + 9 * TICK) != first

    def test_results_are_append_only(self, seeded, parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        rows = parity_ledger.observations(run.parity_run_id)
        with pytest.raises(Exception, match="append-only"):
            parity_ledger._conn.execute(
                "UPDATE parity_observation SET is_match = 0 WHERE id = ?",
                (rows[0]["id"],))
        with pytest.raises(Exception, match="append-only"):
            parity_ledger._conn.execute(
                "DELETE FROM parity_observation WHERE id = ?",
                (rows[0]["id"],))

    def test_a_run_cannot_be_rewritten(self, seeded, parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        with pytest.raises(Exception, match="append-only"):
            parity_ledger._conn.execute(
                "UPDATE parity_run SET window_start = 0 WHERE "
                "parity_run_id = ?", (run.parity_run_id,))

    def test_evidence_naming_only_the_formulas_is_refused(self,
                                                          parity_ledger):
        """Two version strings are not a route to a cause."""
        run_id = parity_ledger.open_run(RunIdentity(
            window_start=T0, window_end=T0 + 600, tick_interval_sec=TICK,
            input_snapshot_id="s", legacy_code_version="a",
            v3_code_version="b"), started_at=T0)
        from v3.parity.compare import Reading
        mismatch = compare_tick(TickKey("s", THREAT_LEVEL, T0),
                                Reading(threat_level=ThreatLevel(2)),
                                Reading(threat_level=ThreatLevel(4)))
        with pytest.raises(DomainError):
            parity_ledger.record_comparison(
                run_id, mismatch, sampled_at=T0,
                evidence=MismatchEvidence(legacy_formula_ref="l",
                                          v3_formula_ref="v"))

    def test_a_mismatch_without_evidence_is_refused(self, parity_ledger):
        """S5-VERIF-030: no rate without a route to the cause."""
        run_id = parity_ledger.open_run(RunIdentity(
            window_start=T0, window_end=T0 + 600, tick_interval_sec=TICK,
            input_snapshot_id="s", legacy_code_version="a",
            v3_code_version="b"), started_at=T0)
        mismatch = compare_tick(
            TickKey("s", THREAT_LEVEL, T0),
            __import__("v3.parity.compare", fromlist=["Reading"]).Reading(
                threat_level=ThreatLevel(2)),
            __import__("v3.parity.compare", fromlist=["Reading"]).Reading(
                threat_level=ThreatLevel(4)))
        with pytest.raises(DomainError, match="formula version tags"):
            parity_ledger.record_comparison(run_id, mismatch, sampled_at=T0)

    def test_a_mismatch_with_evidence_is_accepted(self, parity_ledger):
        run_id = parity_ledger.open_run(RunIdentity(
            window_start=T0, window_end=T0 + 600, tick_interval_sec=TICK,
            input_snapshot_id="s", legacy_code_version="a",
            v3_code_version="b"), started_at=T0)
        from v3.parity.compare import Reading
        mismatch = compare_tick(TickKey("s", THREAT_LEVEL, T0),
                                Reading(threat_level=ThreatLevel(2)),
                                Reading(threat_level=ThreatLevel(4)))
        parity_ledger.record_comparison(
            run_id, mismatch, sampled_at=T0,
            evidence=MismatchEvidence(
                legacy_formula_ref="legacy@1", v3_formula_ref="v3@1",
                effective_thresholds={"domain_cap": 6.0}))
        stored = parity_ledger.observations(run_id, only_mismatches=True)
        assert len(stored) == 1
        evidence = parity_ledger.evidence_for(stored[0]["id"])
        assert evidence["evidence"]["legacy_formula_ref"] == "legacy@1"

    def test_a_verdict_for_an_unknown_run_is_refused(self, parity_ledger):
        from v3.parity.compare import Reading
        match = compare_tick(TickKey("s", THREAT_LEVEL, T0),
                             Reading(threat_level=ThreatLevel(3)),
                             Reading(threat_level=ThreatLevel(3)))
        with pytest.raises(DomainError, match="unknown parity_run_id"):
            parity_ledger.record_comparison("nope", match, sampled_at=T0)

    def test_the_ledger_is_a_separate_file_from_the_observation_store(
            self, seeded, parity_ledger):
        store, _ = seeded
        assert Path(parity_ledger.path) != Path(store.path)

    def test_a_run_identity_without_versions_is_refused(self):
        with pytest.raises(DomainError):
            RunIdentity(window_start=T0, window_end=T0 + 1,
                        tick_interval_sec=TICK, input_snapshot_id="",
                        legacy_code_version="a", v3_code_version="b")


# ── the seventeen conditions (ADR-V3-011) ────────────────────────────────

class TestConditionReport:
    def test_all_seventeen_are_judged(self, seeded, parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert len(report.verdicts) == 17
        assert {v.condition_id for v in report.verdicts} == \
            {c.condition_id for c in CONDITIONS}

    def test_every_verdict_is_one_of_the_four_states(self, seeded,
                                                     parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert all(v.status in (PASS, FAIL, BLOCKED, NOT_MEASURED)
                   for v in report.verdicts)

    def test_ten_conditions_are_blocked_on_missing_layers(self, seeded,
                                                          parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert set(report.blocked) >= {"C-01", "C-02", "C-05", "C-06",
                                       "C-07", "C-08", "C-12", "C-13",
                                       "C-14", "C-15"}

    def test_layer_blocked_conditions_name_the_work_package(self, seeded,
                                                            parity_ledger):
        """The nine that wait on a layer say which one."""
        store, _ = seeded
        report = _run(store, parity_ledger).report
        for condition_id in ("C-01", "C-02", "C-05", "C-06", "C-07", "C-08",
                             "C-12", "C-13", "C-14", "C-15"):
            verdict = report.verdict_for(condition_id)
            assert verdict.status == BLOCKED
            assert "WP-" in verdict.evidence["blocked_on"]

    def test_data_blocked_conditions_say_what_to_supply(self, seeded,
                                                        parity_ledger):
        """C-10/C-11 are judgeable — they just need the ETL report."""
        store, _ = seeded
        report = _run(store, parity_ledger).report
        for condition_id in ("C-10", "C-11"):
            verdict = report.verdict_for(condition_id)
            assert verdict.status == BLOCKED
            assert "reconcil" in verdict.detail.lower()
            assert "blocked_on" not in verdict.evidence

    def test_agreement_conditions_pass_on_the_agreeing_fixture(self, seeded,
                                                               parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert report.verdict_for("C-03").status == PASS
        assert report.verdict_for("C-09").status == PASS

    def test_migration_conditions_block_without_an_etl_report(self, seeded,
                                                              parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert report.verdict_for("C-10").status == BLOCKED
        assert report.verdict_for("C-11").status == BLOCKED

    def test_migration_conditions_are_answerable_when_supplied(
            self, seeded, parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger, migration_report={
            "row_count_mismatches": [], "tables_compared": 40,
            "unclassified_tables": [],
            "census_rows_compared": 1_691, "census_mismatches": []}).report
        assert report.verdict_for("C-10").status == PASS
        assert report.verdict_for("C-11").status == PASS

    def test_a_sampled_migration_report_no_longer_answers_c10_or_c11(
            self, seeded, parity_ledger):
        """The pre-ADR-V3-011 report shape: a fixed table count and a
        sample hash. Both are now NOT_MEASURED rather than PASS — the
        first cannot see a table that appeared after it was written
        (WP-2.3 F-1), the second was superseded by a full census."""
        store, _ = seeded
        report = _run(store, parity_ledger, migration_report={
            "row_count_mismatches": [], "sample_hash_mismatches": []}).report
        assert report.verdict_for("C-10").status == NOT_MEASURED
        assert report.verdict_for("C-11").status == NOT_MEASURED

    def test_a_migration_mismatch_fails_the_condition(self, seeded,
                                                      parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger, migration_report={
            "row_count_mismatches": ["conclusions"], "tables_compared": 40,
            "unclassified_tables": []}).report
        verdict = report.verdict_for("C-10")
        assert verdict.status == FAIL and "conclusions" in verdict.detail

    def test_the_running_system_conditions_are_not_answered_by_a_replay(
            self, seeded, parity_ledger):
        """P2 §5-D: this harness projects stored rows into the kernel, so
        it cannot speak for the tick loop, and C-17 is not about it at
        all. Neither may drift into a PASS because a parity run went
        well."""
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert report.verdict_for("C-16").status == NOT_MEASURED
        assert report.verdict_for("C-17").status == FAIL
        assert "V3-SEC-01" in report.verdict_for("C-17").detail

    def test_cutover_is_not_ready_while_anything_is_blocked(self, seeded,
                                                            parity_ledger):
        """A blocked condition is not a passed one."""
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert report.is_cutover_ready is False
        assert "C-17" in report.unmet_override_forbidden

    def test_the_scope_limitations_travel_with_the_report(self, seeded,
                                                          parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger).report
        assert report.notes == SCOPE_NOTES
        assert any("S1-PIPE-026" in note for note in report.notes)
        assert any("LLM" in note for note in report.notes)

    def test_the_report_serialises(self, seeded, parity_ledger):
        store, _ = seeded
        report = _run(store, parity_ledger).report
        payload = json.loads(report.to_json())
        assert len(payload["conditions"]) == 17
        assert payload["cutover_ready"] is False
        assert "not_measured" in payload
        assert "unmet_override_forbidden" in payload


class TestProcedureIsDocumented:
    def test_the_run_procedure_names_the_window_opening_date(self):
        from v3.parity import PROCEDURE
        assert "2026-09-05" in PROCEDURE
        assert "SEPARATE file" in PROCEDURE
        assert "only_mismatches" in PROCEDURE


# ── the widened fixtures (the headline agreement, under load) ────────────

class TestAgreementOnHarderFixtures:
    """The narrow fixture proves little. These exercise the branches where
    the two implementations could actually diverge, and each asserts
    element-wise TL agreement against the REAL legacy scoring."""

    def _store(self, tmp_path, plan, name="v3.db"):
        store = LedgerStore(str(tmp_path / name))
        for index, entries in plan:
            at = T0 + index * TICK
            for row in entries:
                store.append_signal(_observation(index, **row), now=at)
        return store

    def _agree(self, store, parity, scenarios, **kwargs):
        run = run_parity(
            store=store, parity_ledger=parity, scenarios=scenarios,
            start=T0, end=T0 + 7 * TICK, tick_interval_sec=TICK,
            legacy_code_version="fx", v3_code_version="fx", now=T0, **kwargs)
        for scenario in scenarios:
            v3_series = [r.threat_level.value for _, r in
                         run.v3_result.series_for(scenario.scenario_id)]
            legacy_series = [r.threat_level.value for _, r in
                             run.legacy_result.series_for(
                                 scenario.scenario_id)]
            assert v3_series == legacy_series, scenario.scenario_id
            assert v3_series
        return run

    def test_suppressed_rows_are_excluded_identically(self, tmp_path,
                                                      parity_ledger):
        plan = [(i, [{"sensor": "ioda", "domain": "cyber", "score": 8.0,
                      "suppressed": i % 2 == 0},
                     {"sensor": "isr", "domain": "physical", "score": 5.0}])
                for i in range(8)]
        run = self._agree(self._store(tmp_path, plan), parity_ledger,
                          (taiwan(),))
        assert run.report.summary.agreement_rate == pytest.approx(1.0)

    def test_a_non_fired_row_is_excluded_identically(self, tmp_path,
                                                     parity_ledger):
        plan = [(i, [{"sensor": "ioda", "domain": "cyber", "score": 8.0,
                      "status": "CLEAR" if i % 2 else "FIRED"}])
                for i in range(8)]
        self._agree(self._store(tmp_path, plan), parity_ledger, (taiwan(),))

    def test_three_domain_convergence_agrees(self, tmp_path, parity_ledger):
        plan = [(i, [{"sensor": "ioda", "domain": "cyber", "score": 3.0},
                     {"sensor": "isr", "domain": "physical", "score": 3.0},
                     {"sensor": "rss", "domain": "info", "score": 3.0}])
                for i in range(8)]
        run = self._agree(self._store(tmp_path, plan), parity_ledger,
                          (taiwan(),))
        # Full convergence tier: 3 domains -> +2.0
        first = run.v3_result.series_for("taiwan_contingency")[0][1]
        assert first.threat_level.value <= 3

    def test_the_scenario_specific_convergence_branch_agrees(
            self, tmp_path, parity_ledger):
        """Both sides must read the SAME flag — the v2 side takes it off
        radar.config, which the driver now mirrors."""
        from v3.scoring import ScoringSettings
        plan = [(i, [{"sensor": "ioda", "domain": "cyber", "score": 3.0},
                     {"sensor": "isr", "domain": "physical", "score": 3.0},
                     {"sensor": "rss", "domain": "info", "score": 3.0}])
                for i in range(8)]
        store = self._store(tmp_path, plan)
        self._agree(store, parity_ledger, (taiwan(),),
                    settings=ScoringSettings(
                        convergence_scenario_specific=True))

    def test_a_global_country_signal_agrees(self, tmp_path, parity_ledger):
        plan = [(i, [{"sensor": "glob", "domain": "info", "score": 6.0,
                      "country": "GLOBAL"},
                     {"sensor": "ioda", "domain": "cyber", "score": 4.0}])
                for i in range(8)]
        self._agree(self._store(tmp_path, plan), parity_ledger, (taiwan(),))

    def test_a_coupled_global_signal_agrees(self, tmp_path, parity_ledger):
        from v3.scoring import ScoringSettings
        plan = [(i, [{"sensor": "glob", "domain": "info", "score": 6.0,
                      "country": "GLOBAL"},
                     {"sensor": "ioda", "domain": "cyber", "score": 4.0}])
                for i in range(8)]
        self._agree(self._store(tmp_path, plan), parity_ledger, (taiwan(),),
                    settings=ScoringSettings(global_signals_decoupled=False))

    def test_a_same_source_dedup_collision_agrees(self, tmp_path,
                                                  parity_ledger):
        """Two sensors sharing one signal_source on the same country must
        fold to the max on BOTH sides (S1-SCORE-008)."""
        plan = [(i, [{"sensor": "ioda_bgp", "domain": "cyber", "score": 2.0,
                      "source": "bgp"},
                     {"sensor": "ripe_bgp", "domain": "cyber", "score": 5.0,
                      "source": "bgp"},
                     {"sensor": "isr", "domain": "physical", "score": 3.0}])
                for i in range(8)]
        run = self._agree(self._store(tmp_path, plan), parity_ledger,
                          (taiwan(),))
        contributions = run.v3_result.readings[
            TickKey("taiwan_contingency", THREAT_LEVEL, T0)].contributing
        bgp = [c for c in contributions if c.signal_source == "bgp"]
        assert len(bgp) == 1

    def test_two_scenarios_agree_independently(self, tmp_path,
                                               parity_ledger):
        korea = Scenario(
            scenario_id="korea_peninsula", core_country="KR",
            participants=(Participant("KR", Ratio(1.0), "primary_target"),
                          Participant("JP", Ratio(0.6), "forward_base")))
        plan = [(i, [{"sensor": "ioda", "domain": "cyber", "score": 5.0,
                      "country": "TW"},
                     {"sensor": "isr", "domain": "physical", "score": 4.0,
                      "country": "KR"},
                     {"sensor": "rss", "domain": "info", "score": 2.0,
                      "country": "JP"}])
                for i in range(8)]
        run = self._agree(self._store(tmp_path, plan), parity_ledger,
                          (taiwan(), korea))
        assert set(run.report.context.scenario_summaries) == {
            "taiwan_contingency", "korea_peninsula"}
        for summary in run.report.context.scenario_summaries.values():
            assert summary.agreement_rate == pytest.approx(1.0)


class TestSlowSensorIsNotDroppedFromEarlyTicks:
    """The circular-lookback defect, reproduced.

    A sensor with a long freshness horizon whose last observation predates
    the window contributes no in-window row. Deriving the lookback from
    in-window rows therefore never sees its horizon, so it is missing from
    the early ticks — on BOTH sides, which raises the agreement rate while
    hiding a detection gap.
    """

    def test_a_slow_sensor_observed_before_the_window_is_still_in_force(
            self, tmp_path):
        from v3.parity.adapter import LedgerInputAdapter
        store = LedgerStore(str(tmp_path / "v3.db"))
        slow_at = T0 - 20 * 86400.0          # 20 days before the window
        store.append_signal(SignalObservation(
            tick_id="slow", sensor="slow_sensor", signal_source="slow",
            domain="physical", country="TW",
            evidence=Evidence.observe({"v": 5.0}, observed_at=slow_at,
                                      freshness_horizon_sec=30 * 86400.0,
                                      source="slow_sensor"),
            status="FIRED", raw_score=5.0), now=slow_at)
        store.append_signal(_observation(0, "fast", "cyber", 2.0), now=T0)

        adapter = LedgerInputAdapter(store, tick_interval_sec=TICK)
        first_tick = next(adapter.ticks(T0, T0 + TICK))
        assert "slow_sensor" in first_tick.sensors
        assert "fast" in first_tick.sensors
        store.close()

    def test_the_lookback_bound_comes_from_the_whole_ledger(self, tmp_path):
        store = LedgerStore(str(tmp_path / "v3.db"))
        slow_at = T0 - 20 * 86400.0
        store.append_signal(SignalObservation(
            tick_id="slow", sensor="slow_sensor", signal_source="slow",
            domain="physical", country="TW",
            evidence=Evidence.observe({"v": 5.0}, observed_at=slow_at,
                                      freshness_horizon_sec=30 * 86400.0,
                                      source="slow_sensor"),
            status="FIRED", raw_score=5.0), now=slow_at)
        assert store.max_freshness_horizon() == pytest.approx(30 * 86400.0)
        store.close()

    def test_an_empty_ledger_falls_back_to_the_retention_window(self,
                                                               tmp_path):
        from v3.ledger.schema import SIGNAL_RETENTION_DAYS
        from v3.parity.adapter import LedgerInputAdapter
        store = LedgerStore(str(tmp_path / "empty.db"))
        assert store.max_freshness_horizon() is None
        adapter = LedgerInputAdapter(store, tick_interval_sec=TICK)
        assert adapter._lookback_horizon() == pytest.approx(
            SIGNAL_RETENTION_DAYS * 86400.0)
        store.close()

    def test_a_genuinely_stale_sensor_is_still_dropped(self, tmp_path):
        """The fix widens the read, it does not disable freshness (B-03)."""
        from v3.parity.adapter import LedgerInputAdapter
        store = LedgerStore(str(tmp_path / "v3.db"))
        dead_at = T0 - 20 * 86400.0
        store.append_signal(SignalObservation(
            tick_id="dead", sensor="dead_sensor", signal_source="dead",
            domain="physical", country="TW",
            evidence=Evidence.observe({"v": 5.0}, observed_at=dead_at,
                                      freshness_horizon_sec=HORIZON,
                                      source="dead_sensor"),
            status="FIRED", raw_score=5.0), now=dead_at)
        store.append_signal(_observation(0, "fast", "cyber", 2.0), now=T0)
        adapter = LedgerInputAdapter(store, tick_interval_sec=TICK)
        first_tick = next(adapter.ticks(T0, T0 + TICK))
        assert "dead_sensor" not in first_tick.sensors
        store.close()


class TestEvidenceIsPopulatedPerComparison:
    def test_a_mismatch_row_names_both_sides_contributors(self,
                                                          parity_ledger):
        from v3.parity.compare import Contributor, Reading
        from v3.parity.run import _evidence

        class _Side:
            def __init__(self, readings, ref):
                self.readings = readings
                self.formula_ref = ref
                self.thresholds = {"domain_cap": 6.0}

        key = TickKey("taiwan_contingency", THREAT_LEVEL, T0)
        legacy = _Side({key: Reading(
            threat_level=ThreatLevel(2),
            contributing=(Contributor("ioda", "bgp", "TW"),))}, "legacy@1")
        v3 = _Side({key: Reading(
            threat_level=ThreatLevel(4),
            contributing=(Contributor("isr", "isr", "JP"),))}, "v3@1")

        evidence = _evidence(key, v3, legacy)
        assert evidence.legacy_contributions == (("ioda", "bgp", "TW"),)
        assert evidence.v3_contributions == (("isr", "isr", "JP"),)
        assert evidence.is_traceable

    def test_a_recorded_mismatch_carries_both_contributor_lists(
            self, seeded, parity_ledger):
        """Through the real run: every stored verdict has real evidence."""
        store, _ = seeded
        run = _run(store, parity_ledger)
        rows = parity_ledger.observations(run.parity_run_id)
        evidence = parity_ledger.evidence_for(rows[2]["id"])["evidence"]
        assert evidence["legacy_formula_ref"]
        assert evidence["v3_formula_ref"]
        assert evidence["effective_thresholds"]
        # The seeded window fires, so contributions are not empty.
        assert evidence["v3_contributions"] or evidence["legacy_contributions"]


class TestBulkRecording:
    def _mismatch(self, index):
        from v3.parity.compare import Reading
        return compare_tick(
            TickKey("s", THREAT_LEVEL, T0 + index),
            Reading(threat_level=ThreatLevel(2)),
            Reading(threat_level=ThreatLevel(4)))

    def _run_id(self, parity_ledger):
        return parity_ledger.open_run(RunIdentity(
            window_start=T0, window_end=T0 + 6000, tick_interval_sec=TICK,
            input_snapshot_id="s", legacy_code_version="a",
            v3_code_version="b"), started_at=T0)

    def _evidence(self):
        return MismatchEvidence(legacy_formula_ref="l", v3_formula_ref="v",
                                effective_thresholds={"domain_cap": 6.0})

    def test_a_batch_is_written(self, parity_ledger):
        run_id = self._run_id(parity_ledger)
        written = parity_ledger.record_comparisons(
            run_id, ((self._mismatch(i), self._evidence()) for i in range(50)),
            sampled_at=T0)
        assert written == 50
        assert parity_ledger.count(run_id) == 50

    def test_an_empty_batch_is_a_no_op(self, parity_ledger):
        run_id = self._run_id(parity_ledger)
        assert parity_ledger.record_comparisons(run_id, (), sampled_at=T0) == 0

    def test_a_bad_verdict_aborts_the_whole_batch(self, parity_ledger):
        """An append-only ledger cannot be tidied up after a partial write."""
        run_id = self._run_id(parity_ledger)
        entries = [(self._mismatch(i), self._evidence()) for i in range(10)]
        entries.append((self._mismatch(99), None))      # no evidence
        with pytest.raises(DomainError):
            parity_ledger.record_comparisons(run_id, entries, sampled_at=T0)
        assert parity_ledger.count(run_id) == 0

    def test_an_unknown_run_is_refused_before_any_write(self, parity_ledger):
        with pytest.raises(DomainError, match="unknown parity_run_id"):
            parity_ledger.record_comparisons(
                "nope", [(self._mismatch(0), self._evidence())],
                sampled_at=T0)


class TestParityLedgerReadPath:
    def test_queries_use_a_read_only_connection(self, parity_ledger):
        run_id = self._open(parity_ledger)
        assert parity_ledger.run(run_id) is not None
        connection = parity_ledger._read_connection()
        with pytest.raises(Exception, match="readonly|read-only"):
            connection.execute(
                "INSERT INTO parity_meta (key, value) VALUES ('x','y')")

    def test_the_read_connection_is_reused(self, parity_ledger):
        self._open(parity_ledger)
        assert parity_ledger._read_connection() is \
            parity_ledger._read_connection()

    def _open(self, parity_ledger):
        return parity_ledger.open_run(RunIdentity(
            window_start=T0, window_end=T0 + 600, tick_interval_sec=TICK,
            input_snapshot_id="s", legacy_code_version="a",
            v3_code_version="b"), started_at=T0)


class TestDriverHardening:
    def test_an_unexpected_radar_module_is_rejected(self):
        from v3.parity.driver_v2 import EXPECTED_MODULES
        assert "radar.scoring" in EXPECTED_MODULES
        assert "radar.routes.core" not in EXPECTED_MODULES

    def test_the_allowlist_is_checked_on_every_run(self, seeded,
                                                   parity_ledger):
        store, _ = seeded
        run = _run(store, parity_ledger)
        from v3.parity.driver_v2 import EXPECTED_MODULES
        assert set(run.sandbox.radar_modules) <= EXPECTED_MODULES

    def test_a_timeout_reports_the_window_shape(self, seeded):
        """Diagnostics parity with the exit-code path."""
        from v3.parity import driver_v2
        store, _ = seeded
        with pytest.raises(RuntimeError, match="timed out"):
            driver_v2.replay(store, (taiwan(),), start=T0,
                             end=T0 + 7 * TICK, tick_interval_sec=TICK,
                             timeout_sec=0.001)


class TestIntelRowsAreAgedOnBothSides:
    """§7-2 #38, repaired: the two sides received asymmetric input.

    The L1 row's `raw_score` is the UNDECAYED `score_delta` by design — v3
    carries the item's own `observed_at` and applies the age term once, in
    L2 (`v3/scoring/decay.py`, the WP-2.4 addendum). Production applies it
    upstream instead, inside `intel_queue.get_active_rationale`, and hands
    the scoring layer a number that has ALREADY been multiplied
    (`radar/routes/core.py:1925` / `:2078`). Replaying the ledger row into
    the legacy driver raw therefore fed production's scoring core an input
    production never gives it, and every window containing an intel row
    disagreed in the insensitive direction for a reason that had nothing to
    do with either implementation.

    The fixture holds ONE six-hour-old intel row scored 6.0. Half a tau of
    age weighs it to 3.64, which is below TL3's floor of 4.0 and above
    TL4's of 2.0 — so an undecayed legacy side reads TL3 where v3 reads
    TL4, and the disagreement is visible in the series rather than in the
    third decimal place.
    """

    #: 48h. The row has to outlive its own age for the tick to see it at
    #: all; production's TTL cut is the same 48h and is WP-4.1's (§7-2 #37).
    HORIZON_SEC = 48 * 3600.0
    AGE_SEC = 6 * 3600.0          # half of the pinned tau (12h)
    SCORE = 6.0

    def _intel_store(self, tmp_path):
        store = LedgerStore(str(tmp_path / "intel.db"))
        observed = T0 - self.AGE_SEC
        store.append_signal(SignalObservation(
            tick_id="intel-0", sensor="llm_intel", signal_source="llm_intel",
            domain="info", country="TW",
            evidence=Evidence.observe(
                {"headline": "aged report"}, observed_at=observed,
                freshness_horizon_sec=self.HORIZON_SEC, source="llm_intel"),
            status="FIRED", raw_score=self.SCORE, confidence=1.0),
            now=observed)
        # The item is CONFIRMED, because neither system scores an
        # unadjudicated one (§7-2 #105): production selects
        # `auto_confirmed`/`confirmed` and v3 admits `confirmed`. A pending
        # fixture row would be a window in which both sides correctly
        # conclude nothing, which is not what this test is measuring.
        _confirm_intel(store, at=observed)
        return store

    def test_an_aged_intel_row_reads_the_same_on_both_sides(self, tmp_path,
                                                            parity_ledger):
        store = self._intel_store(tmp_path)
        run = run_parity(
            store=store, parity_ledger=parity_ledger, scenarios=(taiwan(),),
            start=T0, end=T0 + 3 * TICK, tick_interval_sec=TICK,
            legacy_code_version="fx", v3_code_version="fx", now=T0)
        v3_series = [r.threat_level.value for _, r in
                     run.v3_result.series_for("taiwan_contingency")]
        legacy_series = [r.threat_level.value for _, r in
                         run.legacy_result.series_for("taiwan_contingency")]
        assert v3_series == legacy_series
        assert run.report.summary.agreement_rate == pytest.approx(1.0)
        store.close()

    def test_the_age_actually_moves_the_verdict(self, tmp_path,
                                                parity_ledger):
        """Without this, agreement above could be agreement on a no-op.

        Six hours of decay has to be worth a whole threat level, or the
        first test would pass just as well against the defect it exists to
        pin.
        """
        store = self._intel_store(tmp_path)
        run = run_parity(
            store=store, parity_ledger=parity_ledger, scenarios=(taiwan(),),
            start=T0, end=T0 + 3 * TICK, tick_interval_sec=TICK,
            legacy_code_version="fx", v3_code_version="fx", now=T0)
        levels = {r.threat_level.value for _, r in
                  run.legacy_result.series_for("taiwan_contingency")}
        # Undecayed the score is 6.0 -> TL3 (floor 4.0). Decayed it is 3.64
        # -> TL4 (floor 2.0). Reading TL3 here means the legacy side never
        # applied the term.
        assert levels == {4}, (
            f"legacy read {levels}; TL3 means the driver fed "
            f"radar.scoring an undecayed intel score")
        store.close()

    def test_reaching_for_the_production_term_did_not_widen_the_sandbox(
            self, tmp_path, parity_ledger):
        """Calling `_age_weight` imports `radar.intel_queue`. Cost, measured.

        The module was reviewed before being admitted to `EXPECTED_MODULES`
        (one logger, one Lock, module-level data, and an `IntelQueue()` with
        no `__init__`). This asserts the review was right rather than
        trusting it: still one thread, still no application boot, and still
        the single refused database read.
        """
        store = self._intel_store(tmp_path)
        run = run_parity(
            store=store, parity_ledger=parity_ledger, scenarios=(taiwan(),),
            start=T0, end=T0 + TICK, tick_interval_sec=TICK,
            legacy_code_version="fx", v3_code_version="fx", now=T0)
        assert "radar.intel_queue" in run.sandbox.radar_modules
        assert run.sandbox.thread_count == 1
        assert run.sandbox.booted_application is False
        assert set(run.sandbox.database_attempts) == {"_get_conn"}
        store.close()

    def test_the_undecayed_number_is_what_the_ledger_stores(self, tmp_path):
        """The repair is in the driver, not in what L1 keeps.

        Storing a pre-decayed number would rebuild the bespoke decay O-17
        removed, and would make the row's meaning depend on when it was
        written rather than on when the event happened.
        """
        store = self._intel_store(tmp_path)
        rows = store.signals_between(T0 - self.AGE_SEC - 1, T0)
        assert [row["raw_score"] for row in rows] == [self.SCORE]
        store.close()


class TestTheDriverUsesProductionsOwnDecay:
    """S5-VERIF-031 again: call the real term, never re-derive it.

    The clause's cited counterexample is a hand-copied `derive_tl` that
    stopped tracking its original. An `exp(-age/tau)` written here would be
    the same mistake with a different formula — and a worse one, because
    the copy would be inside the harness that exists to detect drift.
    """

    def _decay_source(self):
        import ast
        tree = ast.parse((REPO_ROOT / "v3" / "parity" /
                          "_v2_subprocess.py").read_text(encoding="utf-8"))
        function = next(node for node in ast.walk(tree)
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "_intel_age_weight")
        body = function.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)):
            body = body[1:]
        return "\n".join(ast.unparse(node) for node in body)

    def test_the_production_function_is_called(self):
        code = self._decay_source()
        assert "_age_weight" in code
        assert "intel_queue" in code

    def test_no_second_exponential_is_written(self):
        code = self._decay_source()
        for forbidden in ("exp(", "math.", "43200", "12 * 3600", "tau"):
            assert forbidden not in code, forbidden

    def test_both_sides_spell_the_intel_source_the_same_way(self):
        """One literal, two readers, compared rather than trusted.

        The v3 projection recovers `origin` from this string
        (`v3/parity/adapter.py`) and the driver selects rows to age by it.
        If they drifted, intel would be aged on one side only — which is
        precisely the defect being repaired, reintroduced by a typo.
        """
        from v3.parity import _v2_subprocess
        from v3.scoring.inputs import ORIGIN_LLM_INTEL
        assert _v2_subprocess.LLM_INTEL_SIGNAL_SOURCE == ORIGIN_LLM_INTEL


class TestSubprocessUsesTheRealConverter:
    def test_no_local_admission_predicate_is_written(self):
        """S5-VERIF-031: the predicate must not be copied into the harness.

        Parsed, with the docstring dropped — the docstring DESCRIBES the
        predicate on purpose, and a text search cannot tell an explanation
        from a reimplementation. That is the same distinction the WP-2.4
        severity check had to learn.
        """
        import ast
        tree = ast.parse((REPO_ROOT / "v3" / "parity" /
                          "_v2_subprocess.py").read_text(encoding="utf-8"))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "_build_signals")
        statements = function.body
        if (statements and isinstance(statements[0], ast.Expr)
                and isinstance(statements[0].value, ast.Constant)):
            statements = statements[1:]          # drop the docstring
        code = "\n".join(ast.unparse(node) for node in statements)
        assert "FIRED" not in code
        assert "<= 0" not in code
        assert "suppressed or" not in code
        assert "rationale_to_signal" in code

    def test_the_real_converter_is_what_rejects_rows(self, tmp_path,
                                                     parity_ledger):
        """A suppressed row and a zero-score row both vanish on both sides."""
        store = LedgerStore(str(tmp_path / "v3.db"))
        for index in range(4):
            at = T0 + index * TICK
            store.append_signal(_observation(
                index, "sup", "cyber", 9.0, suppressed=True), now=at)
            store.append_signal(_observation(index, "real", "cyber", 3.0),
                                now=at)
        run = run_parity(
            store=store, parity_ledger=parity_ledger, scenarios=(taiwan(),),
            start=T0, end=T0 + 3 * TICK, tick_interval_sec=TICK,
            legacy_code_version="fx", v3_code_version="fx", now=T0)
        for reading in run.legacy_result.readings.values():
            assert all(c.sensor != "sup" for c in reading.contributing)
        assert run.report.summary.agreement_rate == pytest.approx(1.0)
        store.close()
