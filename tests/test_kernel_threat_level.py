"""WP-2.1 K kernel — ThreatLevel makes the TL-inversion incident unrepresentable.

Calibration incident #2 (2026-08-02): the TL scale is DEFCON-style — TL1 is
CRITICAL and TL5 is NORMAL — so "higher TL = worse" is exactly backwards.
Code that compared TL values directly inverted the entire calibration, and
the mistake survived review because `tl_a > tl_b` reads as obviously
correct in Python.

The kernel's answer is not a docstring saying "do not compare TLs". That
approach was already tried in this repository and broken (F-06 hid behind
a false docstring). Here the comparison operators raise, and `severity()`
is the only way to get an orderable number.
"""
import pytest

from v3.kernel import ThreatLevel
from v3.kernel.errors import DomainError, OrderingForbiddenError

CRITICAL = 1
NORMAL = 5


class TestConstruction:
    @pytest.mark.parametrize("value", [1, 2, 3, 4, 5])
    def test_valid_levels(self, value):
        assert ThreatLevel(value).value == value

    @pytest.mark.parametrize("value", [0, 6, -1, 100])
    def test_out_of_range_raises(self, value):
        with pytest.raises(DomainError) as exc:
            ThreatLevel(value)
        assert "1..5" in str(exc.value)

    @pytest.mark.parametrize("value", [1.0, "1", None, [1]])
    def test_non_integer_raises(self, value):
        with pytest.raises(DomainError):
            ThreatLevel(value)

    def test_bool_is_not_an_integer_here(self):
        # bool is a subclass of int; True would silently become TL1 = CRITICAL.
        with pytest.raises(DomainError):
            ThreatLevel(True)

    def test_is_immutable(self):
        tl = ThreatLevel(3)
        with pytest.raises(Exception):
            tl.value = 1

    def test_has_no_dict_for_smuggling_state(self):
        assert not hasattr(ThreatLevel(3), "__dict__")


class TestSeverityIsTheOnlyOrdering:
    @pytest.mark.parametrize("tl,severity", [(1, 5), (2, 4), (3, 3),
                                             (4, 2), (5, 1)])
    def test_severity_is_six_minus_tl(self, tl, severity):
        assert ThreatLevel(tl).severity() == severity

    def test_critical_is_the_most_severe(self):
        assert ThreatLevel(CRITICAL).severity() > ThreatLevel(NORMAL).severity()

    def test_is_more_severe_than_uses_the_right_direction(self):
        assert ThreatLevel(1).is_more_severe_than(ThreatLevel(5)) is True
        assert ThreatLevel(5).is_more_severe_than(ThreatLevel(1)) is False

    def test_is_more_severe_than_rejects_foreign_types(self):
        with pytest.raises(TypeError):
            ThreatLevel(1).is_more_severe_than(1)

    def test_worst_of_picks_the_lowest_number(self):
        levels = [ThreatLevel(4), ThreatLevel(2), ThreatLevel(5)]
        assert ThreatLevel.worst_of(levels) == ThreatLevel(2)

    def test_worst_of_rejects_an_empty_sequence(self):
        with pytest.raises(ValueError):
            ThreatLevel.worst_of([])


class TestOrderingIsForbidden:
    """Every operator that could express the inversion must raise."""

    @pytest.mark.parametrize("op", ["__lt__", "__le__", "__gt__", "__ge__"])
    def test_comparison_operators_raise(self, op):
        with pytest.raises(OrderingForbiddenError) as exc:
            getattr(ThreatLevel(1), op)(ThreatLevel(5))
        assert "severity()" in str(exc.value), \
            "the error must name the correct alternative"

    def test_less_than_raises(self):
        with pytest.raises(OrderingForbiddenError):
            ThreatLevel(1) < ThreatLevel(5)

    def test_greater_than_raises(self):
        with pytest.raises(OrderingForbiddenError):
            ThreatLevel(1) > ThreatLevel(5)

    def test_comparison_against_a_raw_int_raises(self):
        with pytest.raises(OrderingForbiddenError):
            ThreatLevel(1) < 5

    def test_sorting_raises(self):
        with pytest.raises(OrderingForbiddenError):
            sorted([ThreatLevel(3), ThreatLevel(1)])

    def test_min_raises(self):
        with pytest.raises(OrderingForbiddenError):
            min(ThreatLevel(3), ThreatLevel(1))

    def test_max_raises(self):
        with pytest.raises(OrderingForbiddenError):
            max(ThreatLevel(3), ThreatLevel(1))

    def test_int_conversion_raises(self):
        # int(tl) would let the value escape into a bare comparison.
        with pytest.raises(OrderingForbiddenError):
            int(ThreatLevel(3))

    def test_float_conversion_raises(self):
        with pytest.raises(OrderingForbiddenError):
            float(ThreatLevel(3))


class TestEqualityIsAllowed:
    def test_same_level_is_equal(self):
        assert ThreatLevel(3) == ThreatLevel(3)

    def test_different_level_is_not_equal(self):
        assert ThreatLevel(3) != ThreatLevel(4)

    def test_foreign_types_are_not_equal(self):
        assert (ThreatLevel(3) == 3) is False

    def test_is_hashable(self):
        assert len({ThreatLevel(1), ThreatLevel(1), ThreatLevel(2)}) == 2


class TestHistoricalDefect:
    """Calibration incident #2, reproduced as a type error."""

    def test_the_inversion_that_broke_calibration_cannot_be_written(self):
        # The original mistake: treating a HIGHER TL as MORE severe.
        critical = ThreatLevel(1)   # CRITICAL
        calm = ThreatLevel(5)       # NORMAL
        with pytest.raises(OrderingForbiddenError):
            _ = critical < calm     # reads as "critical is less severe" — wrong

    def test_the_correct_comparison_is_available_and_right(self):
        critical = ThreatLevel(1)
        calm = ThreatLevel(5)
        assert critical.severity() > calm.severity()
        assert critical.is_more_severe_than(calm)

    def test_a_threshold_style_check_must_go_through_severity(self):
        # "alert when at least SEVERE" — SEVERE is TL2, severity 4.
        alert_floor = ThreatLevel(2).severity()
        assert ThreatLevel(1).severity() >= alert_floor
        assert ThreatLevel(3).severity() < alert_floor


class TestBlessedSortIdiom:
    """Sorting is legitimate; the type just refuses to guess the direction.
    `severity_key` is the single documented way to do it."""

    def test_severity_key_sorts_least_severe_first(self):
        levels = [ThreatLevel(1), ThreatLevel(5), ThreatLevel(3)]
        ordered = sorted(levels, key=ThreatLevel.severity_key)
        assert ordered == [ThreatLevel(5), ThreatLevel(3), ThreatLevel(1)]

    def test_severity_key_reversed_puts_the_worst_first(self):
        levels = [ThreatLevel(5), ThreatLevel(1), ThreatLevel(3)]
        ordered = sorted(levels, key=ThreatLevel.severity_key, reverse=True)
        assert ordered[0] == ThreatLevel(1)

    def test_severity_key_works_with_max(self):
        assert max([ThreatLevel(4), ThreatLevel(2)],
                   key=ThreatLevel.severity_key) == ThreatLevel(2)

    def test_severity_key_rejects_foreign_values(self):
        with pytest.raises(TypeError):
            sorted([1, 2], key=ThreatLevel.severity_key)
