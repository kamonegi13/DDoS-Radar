"""WP-3.2 conditions 1 and 3 — one guard evaluator, and a door with a lock.

E-03: production's integrated guard function `evaluate_for_country` is
never called from production. The real `weight_too_high` path calls four
helpers separately. The three-flag expression inside the integrated guard
is therefore a specification that only the test suite executes — the
tested expression and the running expression are different expressions.
DP7 records it; G-07 is the same defect one layer down, where the recall
gate called a function that did not exist and swallowed the ImportError.

G-01: the feedback endpoint has no role gate at all.

The tests below check both by shape rather than by behaviour where they
can, because a behavioural test of a guard is exactly what production
already had.
"""
from __future__ import annotations

import ast
import inspect
import pathlib

import pytest

from v3.calibration import authority as A
from v3.calibration import epoch as E
from v3.calibration import guards as G
from v3.calibration import matrix as M
from v3.kernel.errors import DomainError


# ── fixtures ────────────────────────────────────────────────────────────

def _stamp():
    started = E.epoch("e2026_08_02").started_at
    return E.EpochStamp(epoch_id="e2026_08_02", since=started + 1.0,
                        until=started + 100000.0, exclude_auto=False)


def _evidence(tp=20, fp=4, tn=6, fn=5):
    cell = M.ConfusionCell(scenario_id="taiwan_contingency",
                           conclusion_type="threat_level", tp=tp, fp=fp,
                           tn=tn, fn=fn, distinct_analysts=3,
                           epoch_id="e2026_08_02")
    return M.CalibrationEvidence.from_cells((cell,), stamp=_stamp())


def _permit(action="generate_proposal", role="analyst"):
    actor = A.Actor.analyst("a.tanaka") if role == "analyst" \
        else A.Actor.admin("root")
    return A.authorize(actor, action)


def _state(**kw):
    base = dict(now=1_785_700_000.0, tier=3, last_applied_at=None,
                motivating_at=1_785_699_000.0, high_applied_at=None,
                recall_status=M.OK, target_role="strategic_observer",
                threshold_key="tl_thresholds.taiwan_contingency.tl1_total",
                scope_scenario_id="taiwan_contingency")
    base.update(kw)
    return G.SystemState(**base)


def _draft(**kw):
    base = dict(proposal_type="weight_too_low", scenario_id="taiwan_contingency",
                target_country="TW", direction="looser", impact="low",
                prior_value=9.0, proposed_value=8.55)
    base.update(kw)
    return G.ProposalDraft(**base)


def _request(**kw):
    base = dict(phase=G.PHASE_GENERATION, authorisation=_permit(),
                draft=_draft(), evidence=_evidence(), state=_state())
    base.update(kw)
    return G.GuardRequest(**base)


# ── condition 1: one evaluator ──────────────────────────────────────────

class TestThereIsOneGuardEvaluator:

    def test_all_three_phases_are_evaluated_by_the_same_function(self):
        for phase in G.PHASES:
            ruling = G.evaluate(_request(
                phase=phase,
                authorisation=_permit(G.ACTION_FOR_PHASE[phase])))
            assert isinstance(ruling, G.Ruling)

    def test_every_guard_predicate_is_referenced_exactly_once(self):
        # E-03's shape: a guard body that exists and is not wired in. If a
        # predicate is defined and never named in GUARDS, it is dead
        # specification; if it is named twice, one of the two is the copy
        # that will drift.
        source = pathlib.Path(inspect.getfile(G)).read_text(encoding="utf-8")
        tree = ast.parse(source)
        defined = {n.name for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)
                   and n.name.startswith("_guard_")}
        assert defined, "no guard predicates found"
        used = [n.id for n in ast.walk(tree)
                if isinstance(n, ast.Name) and n.id.startswith("_guard_")]
        for name in defined:
            assert used.count(name) == 1, (
                f"{name} is referenced {used.count(name)} times; a guard "
                f"defined-but-unwired is E-03, a guard wired twice is the "
                f"drift that follows")

    def test_no_guard_predicate_is_defined_outside_the_evaluator_module(self):
        package = pathlib.Path(inspect.getfile(G)).parent
        for path in sorted(package.glob("*.py")):
            if path.name == "guards.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            names = [n.name for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef)
                     and n.name.startswith("_guard_")]
            assert not names, f"{path.name} defines guards: {names}"

    def test_every_guard_declares_the_phases_it_applies_to(self):
        for guard in G.GUARDS:
            assert guard.phases, f"{guard.guard_id} applies to no phase"
            assert set(guard.phases) <= set(G.PHASES)

    def test_every_guard_cites_a_clause(self):
        for guard in G.GUARDS:
            assert guard.clause.startswith(("S1-CALIB-", "S5-VERIF-",
                                            "ADR-V3-"))

    def test_the_registry_is_the_only_list_of_guards(self):
        assert G.guard_ids() == tuple(sorted(g.guard_id for g in G.GUARDS))

    def test_every_guard_runs_even_after_one_fires(self):
        ruling = G.evaluate(_request(evidence=None, state=_state(tier=0)))
        evaluated = {v.guard_id for v in ruling.verdicts}
        applicable = {g.guard_id for g in G.GUARDS
                      if G.PHASE_GENERATION in g.phases}
        assert evaluated == applicable

    def test_the_first_firing_guard_owns_the_outcome(self):
        ruling = G.evaluate(_request(evidence=None, state=_state(tier=0)))
        fired = [v.guard_id for v in ruling.verdicts if v.fired]
        assert ruling.blocked_by == fired[0]


class TestThePermitCannotBeMintedElsewhere:
    """The structural half of "generation, application and rejection all
    go through the evaluator": they need something only it produces."""

    def test_an_allowed_ruling_yields_a_permit(self):
        ruling = G.evaluate(_request())
        assert ruling.allowed is True
        assert isinstance(ruling.permit(), G.Permit)

    def test_a_blocked_ruling_refuses_to_yield_a_permit(self):
        ruling = G.evaluate(_request(state=_state(tier=0)))
        assert ruling.allowed is False
        with pytest.raises(G.GuardRefusedError):
            ruling.permit()

    def test_a_permit_cannot_be_constructed_directly(self):
        with pytest.raises(DomainError, match="evaluate"):
            G.Permit(phase=G.PHASE_GENERATION, ruling_id="x", _token=None)

    def test_a_relaxing_subclass_of_the_permit_is_refused(self):
        with pytest.raises(TypeError, match="final"):
            class Loose(G.Permit):
                pass

    def test_a_permit_names_the_phase_it_was_granted_for(self):
        ruling = G.evaluate(_request(phase=G.PHASE_APPLICATION,
                                     authorisation=_permit("apply_proposal")))
        assert ruling.permit().phase == G.PHASE_APPLICATION

    def test_a_generation_permit_is_refused_at_the_application_door(self):
        permit = G.evaluate(_request()).permit()
        with pytest.raises(G.GuardRefusedError, match="phase"):
            permit.require(G.PHASE_APPLICATION)


# ── condition 3: authorisation ──────────────────────────────────────────

class TestCalibrationWritesRequireAnalyst:

    def test_a_viewer_cannot_submit_a_label(self):
        with pytest.raises(A.UnauthorizedError, match="analyst"):
            A.authorize(A.Actor.viewer("guest"), "submit_label")

    @pytest.mark.parametrize("action", sorted(A.ACTIONS))
    def test_no_calibration_action_is_open_to_a_viewer(self, action):
        with pytest.raises(A.UnauthorizedError):
            A.authorize(A.Actor.viewer("guest"), action)

    def test_an_undeclared_action_is_refused_not_defaulted(self):
        # DP15's inverse: production defaults an unknown applied_by to the
        # LOOSEST impact and calls it conservative.
        with pytest.raises(A.UnauthorizedError, match="not a declared"):
            A.authorize(A.Actor.admin("root"), "quietly_retune_everything")

    def test_tier_advancement_needs_admin(self):
        with pytest.raises(A.UnauthorizedError):
            A.authorize(A.Actor.analyst("a.tanaka"), "advance_tier")
        assert A.authorize(A.Actor.admin("root"), "advance_tier")

    def test_the_evaluator_refuses_a_request_with_no_authorisation(self):
        with pytest.raises(DomainError, match="[Aa]uthorisation"):
            G.evaluate(_request(authorisation=None))

    def test_the_evaluator_refuses_a_permit_for_a_different_action(self):
        with pytest.raises(A.UnauthorizedError):
            G.evaluate(_request(phase=G.PHASE_APPLICATION,
                                authorisation=_permit("generate_proposal")))

    def test_an_authorisation_cannot_be_forged(self):
        with pytest.raises(DomainError, match="authorize"):
            A.Authorisation(actor=A.Actor.analyst("x"),
                            action="submit_label", _token=None)


class TestAutomatedWritersAreDistinguishable:

    def test_an_automated_actor_carries_its_generator(self):
        actor = A.Actor.automated("tl_threshold_calibrator", "v1")
        assert actor.actor_id == "auto:tl_threshold_calibrator"
        assert actor.is_automated is True

    def test_a_human_cannot_take_an_auto_prefixed_identity(self):
        with pytest.raises(DomainError, match="reserved"):
            A.Actor.analyst("auto:tl_threshold_calibrator")

    def test_an_automated_actor_without_a_version_is_refused(self):
        with pytest.raises(DomainError, match="generator"):
            A.Actor(actor_id="auto:x", role="analyst")

    def test_a_human_actor_may_not_carry_a_generator_identity(self):
        with pytest.raises(DomainError, match="generator"):
            A.Actor(actor_id="a.tanaka", role="analyst", generator_id="x",
                    generator_version="1")

    def test_the_prefix_is_applied_by_the_constructor_not_the_caller(self):
        with pytest.raises(DomainError, match="prefix"):
            A.Actor.automated("auto:tl_threshold_calibrator", "v1")


# ── the guards themselves ───────────────────────────────────────────────

class TestGuardsFailClosed:
    """ADR-V3-006. Production's recall gate does the opposite (DP18)."""

    def test_a_guard_that_raises_blocks_rather_than_allows(self):
        broken = G.Guard(guard_id="explodes", clause="S1-CALIB-031",
                         describes="a guard whose predicate throws",
                         phases=G.PHASES,
                         predicate=lambda req: (_ for _ in ()).throw(
                             RuntimeError("boom")))
        ruling = G.evaluate(_request(), guards=G.GUARDS + (broken,))
        assert ruling.allowed is False
        assert ruling.blocked_by == "explodes"

    def test_the_error_is_disclosed_not_swallowed(self):
        broken = G.Guard(guard_id="explodes", clause="S1-CALIB-031",
                         describes="throws", phases=G.PHASES,
                         predicate=lambda req: (_ for _ in ()).throw(
                             RuntimeError("boom")))
        ruling = G.evaluate(_request(), guards=G.GUARDS + (broken,))
        verdict = next(v for v in ruling.verdicts if v.guard_id == "explodes")
        assert "boom" in verdict.detail

    def test_the_recall_gate_is_live_and_denies_on_a_red_status(self):
        # G-07 / DP18: production's recall gate calls a function that does
        # not exist, catches the ImportError, and returns "not red".
        ruling = G.evaluate(_request(state=_state(recall_status=M.DEGRADED)))
        assert ruling.blocked_by == "recall_degraded"

    def test_the_recall_gate_denies_when_recall_is_unmeasurable(self):
        ruling = G.evaluate(_request(
            state=_state(recall_status=M.INSUFFICIENT_DATA)))
        assert ruling.blocked_by == "recall_degraded"

    def test_the_recall_gate_denies_on_a_degenerate_status(self):
        ruling = G.evaluate(_request(state=_state(recall_status=M.DEGENERATE)))
        assert ruling.blocked_by == "recall_degraded"


class TestEvidenceGuards:

    def test_a_proposal_with_no_evidence_at_all_is_refused(self):
        ruling = G.evaluate(_request(evidence=None))
        assert ruling.blocked_by == "no_evidence"

    def test_a_sample_below_thirty_is_insufficient(self):
        ruling = G.evaluate(_request(evidence=_evidence(tp=5, fp=2, tn=2,
                                                        fn=2)))
        assert ruling.blocked_by == "insufficient_feedback"

    def test_the_sample_boundary_of_thirty_passes(self):
        # S1-CALIB-014 / 062: `== 30` is on the passing side.
        ruling = G.evaluate(_request(evidence=_evidence(tp=15, fp=5, tn=5,
                                                        fn=5)))
        assert ruling.allowed is True

    def test_evidence_without_a_conclusive_cell_is_refused(self):
        # Thin positives: tp+fn < 5 everywhere.
        ruling = G.evaluate(_request(
            evidence=_evidence(tp=2, fp=20, tn=8, fn=1)))
        assert ruling.blocked_by == "no_conclusive_cell"


class TestFreshnessGuard:
    """S1-CALIB-016, incident #3's repair."""

    def test_an_adjustment_with_no_motivating_label_is_refused(self):
        ruling = G.evaluate(_request(state=_state(motivating_at=None)))
        assert ruling.blocked_by == "no_motivating_evidence"

    def test_evidence_older_than_the_last_change_is_stale(self):
        ruling = G.evaluate(_request(state=_state(
            motivating_at=1000.0, last_applied_at=2000.0)))
        assert ruling.blocked_by == "no_new_evidence"

    def test_the_equality_boundary_is_on_the_refusing_side(self):
        # "One motivating-evidence state justifies at most one adjustment."
        ruling = G.evaluate(_request(state=_state(
            motivating_at=2000.0, last_applied_at=2000.0)))
        assert ruling.blocked_by == "no_new_evidence"

    def test_strictly_newer_evidence_passes(self):
        ruling = G.evaluate(_request(state=_state(
            motivating_at=2001.0, last_applied_at=2000.0)))
        assert ruling.allowed is True

    def test_the_first_ever_adjustment_passes(self):
        ruling = G.evaluate(_request(state=_state(last_applied_at=None)))
        assert ruling.allowed is True


class TestTierAndCooldownGuards:

    def test_tier_zero_blocks_every_impact(self):
        for impact in ("low", "med", "high"):
            ruling = G.evaluate(_request(draft=_draft(impact=impact),
                                         state=_state(tier=0)))
            assert ruling.blocked_by == "tier_gate"

    @pytest.mark.parametrize("tier,impact,allowed", [
        (1, "low", True), (1, "med", False), (1, "high", False),
        (2, "low", True), (2, "med", True), (2, "high", False),
        (3, "low", True), (3, "med", True), (3, "high", True),
    ])
    def test_the_tier_table(self, tier, impact, allowed):
        ruling = G.evaluate(_request(draft=_draft(impact=impact),
                                     state=_state(tier=tier)))
        assert (ruling.blocked_by != "tier_gate") is allowed

    def test_an_unknown_impact_is_refused_rather_than_treated_as_low(self):
        with pytest.raises(DomainError):
            _draft(impact="mild")

    def test_a_high_application_starts_a_cooldown_that_stops_low_and_med(self):
        now = 1_785_700_000.0
        state = _state(now=now, high_applied_at=now - 3600.0)
        for impact in ("low", "med"):
            ruling = G.evaluate(_request(draft=_draft(impact=impact),
                                         state=state))
            assert ruling.blocked_by == "high_cooldown"

    def test_high_itself_is_exempt_from_the_high_cooldown(self):
        now = 1_785_700_000.0
        ruling = G.evaluate(_request(
            draft=_draft(impact="high", proposal_type="weight_too_high",
                         direction="tighter"),
            state=_state(now=now, high_applied_at=now - 3600.0,
                         motivating_at=now - 100.0)))
        assert ruling.blocked_by != "high_cooldown"

    def test_the_cooldown_expires_after_twenty_four_hours(self):
        now = 1_785_700_000.0
        ruling = G.evaluate(_request(state=_state(
            now=now, high_applied_at=now - 24.0 * 3600.0)))
        assert ruling.blocked_by != "high_cooldown"


class TestProtectedRoleGuard:
    """S1-CALIB-035, the 2026-04-29 accident."""

    @pytest.mark.parametrize("role", sorted(G.PROTECTED_ROLES))
    def test_a_recall_reducing_proposal_never_touches_a_protected_role(
            self, role):
        ruling = G.evaluate(_request(
            draft=_draft(proposal_type="weight_too_high", impact="high",
                         direction="tighter"),
            state=_state(target_role=role,
                         motivating_at=1_785_699_000.0)))
        assert ruling.blocked_by == "protected_role"

    def test_a_recall_increasing_proposal_may_touch_a_protected_role(self):
        ruling = G.evaluate(_request(
            draft=_draft(proposal_type="weight_too_low", impact="low"),
            state=_state(target_role="primary_target")))
        assert ruling.allowed is True

    def test_the_protected_set_matches_production(self):
        assert G.PROTECTED_ROLES == frozenset({
            "primary_target", "principal_belligerent", "adversary",
            "core_country"})


class TestRefusalsAreRecorded:
    """DP9 / E-05: production leaves no trace when a guard stops a
    proposal — no row, no `rejection_reason` column, and the alternative
    event writer is never called from production."""

    def test_a_refusal_produces_a_persistable_record(self):
        ruling = G.evaluate(_request(state=_state(tier=0)))
        record = ruling.as_record()
        assert record["allowed"] is False
        assert record["blocked_by"] == "tier_gate"
        assert record["clause"].startswith("S1-CALIB-")

    def test_the_record_names_every_guard_that_was_evaluated(self):
        ruling = G.evaluate(_request(state=_state(tier=0)))
        record = ruling.as_record()
        assert len(record["verdicts"]) == len(
            [g for g in G.GUARDS if G.PHASE_GENERATION in g.phases])

    def test_an_allowed_ruling_is_recorded_too(self):
        # "Why did it publish" is as much a question as "why did it not".
        record = G.evaluate(_request()).as_record()
        assert record["allowed"] is True and record["blocked_by"] is None

    def test_the_record_carries_the_actor(self):
        record = G.evaluate(_request()).as_record()
        assert record["actor"]["actor_id"] == "a.tanaka"

    def test_the_record_carries_the_evidence_epoch(self):
        record = G.evaluate(_request()).as_record()
        assert record["epoch_id"] == "e2026_08_02"
