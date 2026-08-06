"""WP-2.1 K kernel — Ratio / Percentage make F-08 unrepresentable.

F-08: gps_jamming computed `bad / total`, a fraction in [0,1], and compared
it against GPS_JAM_THRESHOLD, which defaulted to 3.0 on a percent scale.
The comparison could never be true. The sensor fetched successfully and
detected nothing for its entire life, and fetch health stayed green
throughout — nothing in the language or the review process objected to
`0.08 >= 3.0`, because both sides are floats.

Two distinct types with no implicit conversion make that expression a
TypeError. Same-unit comparison stays available, because comparing two
ratios is exactly what a threshold check legitimately does.
"""
import pytest

from v3.kernel import Percentage, Ratio
from v3.kernel.errors import DomainError, UnitMismatchError


class TestRatioConstruction:
    @pytest.mark.parametrize("value", [0.0, 0.5, 1.0, 0.08])
    def test_valid_domain(self, value):
        assert Ratio(value).value == value

    @pytest.mark.parametrize("value", [-0.01, 1.01, 3.0, 100.0])
    def test_outside_zero_to_one_raises(self, value):
        with pytest.raises(DomainError) as exc:
            Ratio(value)
        assert "[0, 1]" in str(exc.value)

    @pytest.mark.parametrize("value", ["0.5", None, [0.5]])
    def test_non_numeric_raises(self, value):
        with pytest.raises(DomainError):
            Ratio(value)

    def test_integers_are_accepted_as_numbers(self):
        assert Ratio(1).value == 1.0

    def test_bool_is_rejected(self):
        with pytest.raises(DomainError):
            Ratio(True)

    def test_nan_is_rejected(self):
        with pytest.raises(DomainError):
            Ratio(float("nan"))

    def test_is_immutable(self):
        with pytest.raises(Exception):
            Ratio(0.5).value = 0.9


class TestPercentageConstruction:
    @pytest.mark.parametrize("value", [0.0, 3.0, 50.0, 100.0])
    def test_valid_domain(self, value):
        assert Percentage(value).value == value

    @pytest.mark.parametrize("value", [-0.1, 100.1, 1000.0])
    def test_outside_zero_to_hundred_raises(self, value):
        with pytest.raises(DomainError) as exc:
            Percentage(value)
        assert "[0, 100]" in str(exc.value)


class TestExplicitConversion:
    def test_ratio_to_percentage(self):
        assert Ratio(0.08).to_percentage() == Percentage(8.0)

    def test_percentage_to_ratio(self):
        assert Percentage(8.0).to_ratio() == Ratio(0.08)

    def test_round_trip_is_lossless_at_the_boundaries(self):
        for value in (0.0, 0.5, 1.0):
            assert Ratio(value).to_percentage().to_ratio() == Ratio(value)

    def test_conversion_is_the_only_bridge(self):
        # There is no implicit coercion anywhere: the bridge is a method
        # call you can grep for in review.
        assert not hasattr(Ratio(0.5), "__int__")
        assert not hasattr(Ratio(0.5), "__float__")


class TestCrossUnitOperationsRaise:
    """The F-08 shape, in every form it could take."""

    def test_comparison_against_the_other_unit_raises(self):
        with pytest.raises(UnitMismatchError):
            Ratio(0.08) >= Percentage(3.0)

    def test_reverse_comparison_raises(self):
        with pytest.raises(UnitMismatchError):
            Percentage(3.0) <= Ratio(0.08)

    @pytest.mark.parametrize("op", ["__lt__", "__le__", "__gt__", "__ge__"])
    def test_every_ordering_operator_raises_across_units(self, op):
        with pytest.raises(UnitMismatchError):
            getattr(Ratio(0.5), op)(Percentage(50.0))

    def test_equality_across_units_raises_rather_than_returning_false(self):
        # Silently False would be worse than a raise: it reads as "these
        # differ" when the real answer is "this question is malformed".
        with pytest.raises(UnitMismatchError):
            Ratio(0.5) == Percentage(50.0)

    def test_comparison_against_a_raw_float_raises(self):
        with pytest.raises(UnitMismatchError):
            Ratio(0.08) >= 3.0

    def test_equality_against_a_raw_float_raises(self):
        with pytest.raises(UnitMismatchError):
            Ratio(0.08) == 0.08

    def test_arithmetic_across_units_raises(self):
        with pytest.raises(UnitMismatchError):
            Ratio(0.5) + Percentage(50.0)

    def test_arithmetic_with_a_raw_float_raises(self):
        with pytest.raises(UnitMismatchError):
            Ratio(0.5) + 0.5

    def test_multiplication_by_a_raw_float_raises(self):
        with pytest.raises(UnitMismatchError):
            Ratio(0.5) * 2.0


class TestSameUnitOperations:
    def test_ordering_within_a_unit_is_allowed(self):
        assert Ratio(0.08) > Ratio(0.03)
        assert Ratio(0.01) < Ratio(0.03)
        assert Percentage(8.0) > Percentage(3.0)

    def test_equality_within_a_unit(self):
        assert Ratio(0.5) == Ratio(0.5)
        assert Ratio(0.5) != Ratio(0.6)

    def test_addition_within_a_unit(self):
        assert Ratio(0.2) + Ratio(0.3) == Ratio(0.5)

    def test_subtraction_within_a_unit(self):
        assert Ratio(0.5) - Ratio(0.2) == Ratio(0.3)

    def test_addition_that_leaves_the_domain_raises(self):
        with pytest.raises(DomainError):
            Ratio(0.8) + Ratio(0.5)

    def test_subtraction_below_the_domain_raises(self):
        with pytest.raises(DomainError):
            Ratio(0.2) - Ratio(0.5)

    def test_sorting_within_a_unit_works(self):
        values = sorted([Ratio(0.5), Ratio(0.1), Ratio(0.9)])
        assert values == [Ratio(0.1), Ratio(0.5), Ratio(0.9)]

    def test_hashable_within_a_unit(self):
        assert len({Ratio(0.5), Ratio(0.5), Ratio(0.6)}) == 2


class TestHistoricalDefect:
    """F-08 reproduced: the exact comparison, now a type error."""

    def test_the_gps_jamming_comparison_no_longer_type_checks(self):
        jam_ratio = Ratio(0.08)              # 8 bad of 100 aircraft
        shipped_threshold = Percentage(3.0)  # "3.0" meant 3 percent
        with pytest.raises(UnitMismatchError) as exc:
            _ = jam_ratio >= shipped_threshold
        assert "Ratio" in str(exc.value) and "Percentage" in str(exc.value)

    def test_the_repaired_comparison_is_expressible_and_fires(self):
        jam_ratio = Ratio(0.08)
        threshold = Percentage(3.0).to_ratio()   # explicit, reviewable
        assert jam_ratio >= threshold

    def test_the_percent_scaled_default_cannot_even_be_built_as_a_ratio(self):
        # `Ratio(3.0)` — the shipped default read as a fraction — is a
        # domain error, so the mistake dies at construction.
        with pytest.raises(DomainError):
            Ratio(3.0)


class TestNoStateSmuggling:
    @pytest.mark.parametrize("value", [Ratio(0.5), Percentage(50.0)])
    def test_has_no_dict(self, value):
        # The mixin needs its own __slots__ = (); without it every unit
        # instance silently carries a __dict__ and object.__setattr__
        # succeeds on a "frozen" type.
        assert not hasattr(value, "__dict__")

    @pytest.mark.parametrize("value", [Ratio(0.5), Percentage(50.0)])
    def test_arbitrary_attributes_are_refused(self, value):
        with pytest.raises(AttributeError):
            object.__setattr__(value, "smuggled", 1)


class TestReflectedArithmetic:
    """`0.5 + ratio` must fail the same way `ratio + 0.5` does — same
    exception type, so a caller's `except UnitMismatchError` cannot be
    silently escaped by operand order."""

    @pytest.mark.parametrize("expression", [
        lambda: 0.5 + Ratio(0.5),
        lambda: 0.5 - Ratio(0.5),
        lambda: 0.5 / Ratio(0.5),
        lambda: 2.0 * Ratio(0.5),
        lambda: 50.0 + Percentage(50.0),
    ])
    def test_reflected_operations_raise_unit_mismatch(self, expression):
        with pytest.raises(UnitMismatchError):
            expression()

    def test_the_message_names_the_operands_in_the_written_order(self):
        with pytest.raises(UnitMismatchError) as exc:
            _ = 0.5 + Ratio(0.5)
        message = str(exc.value)
        assert "float" in message and "Ratio" in message

    def test_reflected_and_forward_raise_the_same_type(self):
        with pytest.raises(UnitMismatchError) as forward:
            Ratio(0.5) + 0.5
        with pytest.raises(UnitMismatchError) as reflected:
            0.5 + Ratio(0.5)
        assert type(forward.value) is type(reflected.value)
