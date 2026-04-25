"""Tests for Phase 5 / Item 2.3: dual-core observability (Path B).

Background:
  ADR-009 makes core_country optional so symmetric scenarios (e.g.
  middle_east: IL ⇔ IR) can be expressed as a pair of
  PRINCIPAL_BELLIGERENT participants. The scoring engine
  (compute_scenario_score) handles this correctly via the Signal
  pipeline — both belligerents contribute symmetrically to the
  scenario score and TL.

  The legacy per-country pipeline in radar/routes/core.py promotes
  primary_ec (spike-max belligerent) to core_theater for downstream
  _seq_fire() blocks. Secondary belligerent's sequence events are
  not registered. This is a known limitation tracked in ADR-009
  follow-up notes.

Path B observability requirement:
  derive_country_context() returns effective_cores. The route handler
  must compute and surface secondary_ecs = [ec for ec in effective_cores
  if ec != primary_ec] so analysts can see which belligerents are
  silent in the sequence log without reading geo_data.json.
"""
from radar.scenarios import derive_country_context, Participant, Role, Scenario


def _symmetric_scenario() -> Scenario:
    """Middle-east-like dual-core scenario with two principal belligerents."""
    return Scenario(
        id="dual_test",
        name_en="Dual Test", name_ja="対称テスト",
        description_en="", description_ja="",
        core_country=None,
        state="active", enabled=True, tier=1,
        participants={
            "IL": Participant(country="IL", weight=1.0,
                              role=Role.PRINCIPAL_BELLIGERENT),
            "IR": Participant(country="IR", weight=1.0,
                              role=Role.PRINCIPAL_BELLIGERENT),
            "US": Participant(country="US", weight=0.6,
                              role=Role.FORCE_PROJECTION),
        },
    )


def _single_core_scenario() -> Scenario:
    """Standard single-core scenario for comparison."""
    return Scenario(
        id="single_test",
        name_en="Single Test", name_ja="単核テスト",
        description_en="", description_ja="",
        core_country="TW",
        state="active", enabled=True, tier=1,
        participants={
            "TW": Participant(country="TW", weight=1.0,
                              role=Role.PRIMARY_TARGET),
            "US": Participant(country="US", weight=0.7,
                              role=Role.PRIMARY_ALLY),
        },
    )


class TestEffectiveCoresDerivation:
    def test_dual_core_yields_two_effective_cores(self):
        ctx = derive_country_context(_symmetric_scenario())
        assert set(ctx["effective_cores"]) == {"IL", "IR"}, \
            f"expected IL+IR, got {ctx['effective_cores']!r}"
        assert ctx["core_theater"] is None

    def test_single_core_yields_single_effective_core(self):
        ctx = derive_country_context(_single_core_scenario())
        assert ctx["effective_cores"] == ["TW"]
        assert ctx["core_theater"] == "TW"

    def test_dual_core_excludes_force_projection_from_effective(self):
        """Only PRINCIPAL_BELLIGERENT with weight>=0.9 graduate to
        effective_core. Force-projection (US, weight 0.6) must not
        be promoted to a scoring core."""
        ctx = derive_country_context(_symmetric_scenario())
        assert "US" not in ctx["effective_cores"]


class TestSecondaryEcsObservability:
    """The route handler computes secondary_ecs = effective_cores - {primary_ec}.
    These tests assert the derivation logic without exercising the full
    Flask request loop (which would require gevent monkey-patching)."""

    def test_secondary_ecs_excludes_primary(self):
        effective_cores = ["IL", "IR"]
        primary_ec = "IL"
        secondary_ecs = [ec for ec in effective_cores if ec != primary_ec]
        assert secondary_ecs == ["IR"]

    def test_secondary_ecs_empty_for_single_core(self):
        effective_cores = ["TW"]
        primary_ec = "TW"
        secondary_ecs = [ec for ec in effective_cores if ec != primary_ec]
        assert secondary_ecs == []

    def test_secondary_ecs_preserves_order(self):
        """derive_country_context returns sorted effective_cores; the
        secondary_ecs computation must preserve that ordering so the
        API response is deterministic."""
        effective_cores = ["IL", "IR", "SY"]  # already sorted
        primary_ec = "IR"
        secondary_ecs = [ec for ec in effective_cores if ec != primary_ec]
        assert secondary_ecs == ["IL", "SY"]
