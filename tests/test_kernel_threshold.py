"""WP-2.1 K kernel — Threshold carries its resolution path (G-15 / G-04).

G-15: 95 of 98 registered config keys were read through `os.getenv` or an
import-time constant, so a SETTINGS edit wrote an override row, showed the
new value, and changed nothing. G-04 is the same defect on one key
(GPS_JAM_THRESHOLD) where the sensor bypassed a registry entry that
existed.

P6 O-18 rules that the answer is not "register everything" — the evidence
says almost nothing needs runtime variability. Thresholds split in two:
a small operationally-variable set resolved through the 3-layer registry,
and everything else pinned as a constant that must still disclose where
its value came from. Threshold expresses both, and neither form lets you
read a value without also learning how it was resolved.
"""
import time

import pytest

from v3.kernel import Percentage, Ratio, Threshold
from v3.kernel.errors import (DomainError, ProvenanceRequiredError,
                              ThresholdResolutionError, UnitMismatchError)


def _resolver(value, source="db"):
    """Stand-in for the 3-layer registry — keeps tests off the real app."""
    def _resolve(key):
        return (value, source)
    return _resolve


class TestPinnedConstruction:
    def test_pinned_requires_provenance(self):
        with pytest.raises(ProvenanceRequiredError) as exc:
            Threshold.pinned(0.03, unit="ratio", provenance_ref="")
        assert "provenance" in str(exc.value).lower()

    def test_pinned_rejects_a_missing_provenance_argument(self):
        with pytest.raises(TypeError):
            Threshold.pinned(0.03, unit="ratio")

    def test_pinned_with_provenance_resolves(self):
        threshold = Threshold.pinned(
            0.03, unit="ratio",
            provenance_ref="S1-SENSOR-014: 3% of tracked aircraft")
        resolved = threshold.resolve()
        assert resolved.value == Ratio(0.03)
        assert resolved.source == "pinned"
        assert "S1-SENSOR-014" in resolved.provenance_ref

    def test_pinned_validates_against_its_declared_unit(self):
        with pytest.raises(DomainError):
            Threshold.pinned(3.0, unit="ratio", provenance_ref="ref")

    def test_unknown_unit_is_refused(self):
        with pytest.raises(DomainError) as exc:
            Threshold.pinned(1.0, unit="furlongs", provenance_ref="ref")
        assert "furlongs" in str(exc.value)


class TestRegistryBackedConstruction:
    def test_registry_backed_records_its_key(self):
        threshold = Threshold.registry_backed("GPS_JAM_THRESHOLD",
                                              unit="ratio")
        assert threshold.key == "GPS_JAM_THRESHOLD"

    def test_registry_backed_requires_a_key(self):
        with pytest.raises(DomainError):
            Threshold.registry_backed("", unit="ratio")

    def test_resolution_records_the_layer_that_answered(self):
        threshold = Threshold.registry_backed("GPS_JAM_THRESHOLD",
                                              unit="ratio")
        resolved = threshold.resolve(resolver=_resolver(0.05, source="db"))
        assert resolved.value == Ratio(0.05)
        assert resolved.source == "db"
        assert resolved.key == "GPS_JAM_THRESHOLD"

    def test_resolution_stamps_the_time(self):
        threshold = Threshold.registry_backed("K", unit="ratio")
        before = time.time()
        resolved = threshold.resolve(resolver=_resolver(0.05))
        assert before <= resolved.resolved_at <= time.time()

    def test_a_value_outside_the_unit_domain_raises(self):
        threshold = Threshold.registry_backed("K", unit="ratio")
        with pytest.raises(DomainError):
            threshold.resolve(resolver=_resolver(3.0))

    def test_an_unresolvable_key_raises_rather_than_defaulting(self):
        # Silently falling back is how a dead knob looks healthy.
        threshold = Threshold.registry_backed("K", unit="ratio")
        with pytest.raises(ThresholdResolutionError):
            threshold.resolve(resolver=_resolver(None))

    def test_a_failing_resolver_is_surfaced(self):
        def _boom(key):
            raise RuntimeError("registry unavailable")

        threshold = Threshold.registry_backed("K", unit="ratio")
        with pytest.raises(ThresholdResolutionError) as exc:
            threshold.resolve(resolver=_boom)
        assert "registry unavailable" in str(exc.value)


class TestNoUnprovenancedValueAccess:
    """The value is reachable only together with its resolution record."""

    def test_there_is_no_public_value_attribute(self):
        threshold = Threshold.pinned(0.03, unit="ratio",
                                     provenance_ref="ref")
        assert not hasattr(threshold, "value")

    def test_there_is_no_instance_dict_to_smuggle_one_in(self):
        threshold = Threshold.pinned(0.03, unit="ratio",
                                     provenance_ref="ref")
        assert not hasattr(threshold, "__dict__")

    def test_float_conversion_is_refused(self):
        threshold = Threshold.pinned(0.03, unit="ratio",
                                     provenance_ref="ref")
        with pytest.raises(TypeError):
            float(threshold)

    def test_the_resolved_record_carries_every_provenance_field(self):
        resolved = Threshold.pinned(
            0.03, unit="ratio", provenance_ref="ADR-V3-00X").resolve()
        for field in ("value", "source", "key", "provenance_ref",
                      "resolved_at", "unit"):
            assert hasattr(resolved, field), field

    def test_the_resolved_record_is_immutable(self):
        resolved = Threshold.pinned(0.03, unit="ratio",
                                    provenance_ref="ref").resolve()
        with pytest.raises(Exception):
            resolved.value = Ratio(0.9)


class TestComparisonRequiresUnits:
    def _ratio_threshold(self):
        return Threshold.pinned(0.03, unit="ratio", provenance_ref="ref")

    def test_a_unit_typed_observation_compares(self):
        assert self._ratio_threshold().exceeded_by(Ratio(0.08)) is True
        assert self._ratio_threshold().exceeded_by(Ratio(0.01)) is False

    def test_the_boundary_counts_as_exceeded(self):
        # `>=` semantics, matching how the sensors phrase it.
        assert self._ratio_threshold().exceeded_by(Ratio(0.03)) is True

    def test_a_raw_float_is_refused(self):
        with pytest.raises(UnitMismatchError) as exc:
            self._ratio_threshold().exceeded_by(0.08)
        assert "unit" in str(exc.value).lower()

    def test_the_wrong_unit_type_is_refused(self):
        with pytest.raises(UnitMismatchError):
            self._ratio_threshold().exceeded_by(Percentage(8.0))

    def test_a_dimensionless_unit_requires_an_explicit_declaration(self):
        threshold = Threshold.pinned(3, unit="count", provenance_ref="ref")
        with pytest.raises(UnitMismatchError):
            threshold.exceeded_by(5)
        assert threshold.exceeded_by(5, unit="count") is True

    def test_a_mismatched_explicit_unit_is_refused(self):
        threshold = Threshold.pinned(3, unit="count", provenance_ref="ref")
        with pytest.raises(UnitMismatchError):
            threshold.exceeded_by(5, unit="ratio")

    def test_comparison_uses_the_resolver_for_registry_keys(self):
        threshold = Threshold.registry_backed("K", unit="ratio")
        assert threshold.exceeded_by(
            Ratio(0.08), resolver=_resolver(0.05)) is True
        assert threshold.exceeded_by(
            Ratio(0.02), resolver=_resolver(0.05)) is False


class TestO18Duality:
    """Both halves of the P6 O-18 ruling must be expressible."""

    def test_the_operationally_variable_form_is_registry_backed(self):
        threshold = Threshold.registry_backed("GPS_JAM_THRESHOLD",
                                              unit="ratio")
        assert threshold.is_registry_backed is True
        assert threshold.key == "GPS_JAM_THRESHOLD"

    def test_the_constant_form_carries_disclosure_not_variability(self):
        threshold = Threshold.pinned(
            0.03, unit="ratio",
            provenance_ref="S1-SENSOR-014 derivation note")
        assert threshold.is_registry_backed is False
        assert threshold.provenance_ref

    def test_a_pinned_threshold_never_consults_a_resolver(self):
        def _must_not_be_called(key):
            raise AssertionError("a pinned threshold must not hit the registry")

        threshold = Threshold.pinned(0.03, unit="ratio",
                                     provenance_ref="ref")
        assert threshold.resolve(resolver=_must_not_be_called).source == "pinned"


class TestHistoricalDefect:
    """G-04 reproduced: the registry entry the sensor bypassed."""

    def test_the_bypass_has_no_expressible_form(self):
        # There is no constructor that takes a value with no provenance and
        # no key — the two shapes are the whole API surface.
        constructors = {name for name in dir(Threshold)
                        if not name.startswith("_")}
        assert {"pinned", "registry_backed"} <= constructors
        assert "from_env" not in constructors
        assert "from_getenv" not in constructors

    def test_a_registry_backed_threshold_reflects_an_override(self):
        threshold = Threshold.registry_backed("GPS_JAM_THRESHOLD",
                                              unit="ratio")
        # The analyst's edit lands in the DB layer...
        overridden = threshold.resolve(resolver=_resolver(0.05, source="db"))
        assert overridden.value == Ratio(0.05)
        assert overridden.source == "db", \
            "G-15: the whole point is that the DB layer is actually read"

    def test_the_percent_scaled_default_cannot_be_pinned_as_a_ratio(self):
        with pytest.raises(DomainError):
            Threshold.pinned(3.0, unit="ratio", provenance_ref="the F-08 value")


class TestDefaultResolverIntegration:
    """The one permitted legacy dependency, exercised for real.

    Kept separate because it boots the legacy app (importing radar.* does
    that); the rest of the kernel suite never touches it. tests/test_
    kernel_boundary.py proves the import stays lazy.
    """

    def test_a_real_registry_key_resolves_through_the_three_layer_chain(self):
        import radar.config  # noqa: F401 - populates the registry
        threshold = Threshold.registry_backed("SIGNAL_LEDGER_RETENTION_DAYS",
                                              unit="d")
        resolved = threshold.resolve()
        assert resolved.value == 60
        assert resolved.source in ("db", "env", "default")
        assert resolved.key == "SIGNAL_LEDGER_RETENTION_DAYS"

    def test_an_unregistered_key_raises_rather_than_returning_none(self):
        import radar.config  # noqa: F401
        threshold = Threshold.registry_backed("NO_SUCH_KEY_WP21", unit="d")
        with pytest.raises(ThresholdResolutionError):
            threshold.resolve()

    def test_the_kernel_catches_the_stale_gps_override_still_in_the_db(self):
        """A live finding, pinned as a test.

        WP-0.2 moved GPS_JAM_THRESHOLD to the ratio scale in the sensor,
        the module constant, the registry default and config.env. But
        migration v49 (2026-05-04) had already seeded
        `config_runtime_value` from the environment of the day, capturing
        the percent-scaled 3.0 — and the DB layer outranks env and default
        in the 3-layer chain. So the registry still answers 3.0.

        The sensor is unaffected today only because it direct-reads the
        environment (that is G-04, the bypass). The moment the K layer
        routes this key through resolution — which is the entire point of
        fixing G-04 — the stale row would hand F-08 straight back.

        The kernel refuses it: 3.0 is not a ratio. This test therefore
        documents the trap AND proves the type stops it. When the stale
        rows are cleared, the assertion below flips to the happy path and
        this test should be updated to assert Ratio(0.03).
        """
        import radar.config  # noqa: F401
        from radar import config_layered

        live_value = config_layered.get_config("GPS_JAM_THRESHOLD")
        threshold = Threshold.registry_backed("GPS_JAM_THRESHOLD",
                                              unit="ratio")
        if live_value == 3.0:
            with pytest.raises(DomainError) as exc:
                threshold.resolve()
            assert "percentage" in str(exc.value), \
                "the error must name the scale confusion, not just the range"
        else:
            assert threshold.resolve().value == Ratio(0.03)

    def test_a_ratio_threshold_never_accepts_a_percent_scaled_value(self):
        # The general form of the trap above, independent of live state.
        threshold = Threshold.registry_backed("ANY_KEY", unit="ratio")
        with pytest.raises(DomainError):
            threshold.resolve(resolver=_resolver(3.0, source="db"))


class TestNonFiniteValuesAreRefused:
    """A NaN threshold or observation compares False against everything,
    so the check reads as "not exceeded" forever — a silent永久 non-firing
    of exactly the F-08 kind. Zero-variance baselines produce NaN z-scores
    in practice, so this is not hypothetical."""

    @pytest.mark.parametrize("bad", [float("nan"), float("inf"),
                                     float("-inf")])
    def test_pinned_refuses_non_finite(self, bad):
        with pytest.raises(DomainError):
            Threshold.pinned(bad, unit="z", provenance_ref="ref")

    @pytest.mark.parametrize("bad", [float("nan"), float("inf")])
    def test_resolution_refuses_non_finite(self, bad):
        threshold = Threshold.registry_backed("K", unit="z")
        with pytest.raises(DomainError):
            threshold.resolve(resolver=_resolver(bad))

    @pytest.mark.parametrize("bad", [float("nan"), float("inf")])
    def test_observations_refuse_non_finite(self, bad):
        threshold = Threshold.pinned(2.0, unit="z", provenance_ref="ref")
        with pytest.raises(DomainError):
            threshold.exceeded_by(bad, unit="z")

    def test_the_zero_variance_zscore_scenario(self):
        # std == 0 -> z = 0/0 -> NaN. Without this guard the comparison
        # returns False and the detector never fires again.
        nan_z = float("nan")
        threshold = Threshold.pinned(2.0, unit="z", provenance_ref="S1-X")
        with pytest.raises(DomainError) as exc:
            threshold.exceeded_by(nan_z, unit="z")
        assert "nan" in str(exc.value).lower()

    def test_finite_values_still_work(self):
        threshold = Threshold.pinned(2.0, unit="z", provenance_ref="ref")
        assert threshold.exceeded_by(3.0, unit="z") is True
        assert threshold.exceeded_by(1.0, unit="z") is False
