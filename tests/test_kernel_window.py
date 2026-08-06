"""WP-2.1 K kernel — Window makes F-06 unrepresentable.

F-06: telegram declared a 30-day baseline and capped the list at
NARRATIVE_BASELINE_DAYS *samples*. At a 900 s cadence that is 7.5 hours,
so the z-score normalised each reading against the last few hours of
itself. The bug is a units error hiding in an integer: 30 days and 30
samples are both `30`.

Window refuses to be built from a bare sample count. The cadence is a
required argument, the sample count is derived, and changing cadence
produces a new Window rather than mutating one — so a cap computed at
import cannot survive a cadence change (the false-negative shape the L5
verifier was later built to catch).
"""
import pytest

from v3.kernel import Window
from v3.kernel.errors import DomainError

DAY_SEC = 86400.0


class TestConstruction:
    def test_from_days_is_the_blessed_constructor(self):
        window = Window.from_days(30, cadence_sec=900)
        assert window.declared_days == 30
        assert window.cadence_sec == 900

    def test_a_bare_sample_count_is_refused(self):
        # The F-06 shape: `Window(30)` meaning "thirty samples".
        with pytest.raises(TypeError):
            Window(30)

    def test_positional_construction_is_refused(self):
        # Keyword-only fields: `Window(30, 900)` cannot be mistaken for
        # "30 samples at slot 900".
        with pytest.raises(TypeError):
            Window(30, 900)

    def test_from_samples_raises_and_points_at_from_days(self):
        with pytest.raises(DomainError) as exc:
            Window.from_samples(30)
        message = str(exc.value)
        assert "from_days" in message
        assert "F-06" in message

    def test_keyword_construction_is_explicit_enough_to_allow(self):
        window = Window(declared_days=30, cadence_sec=900)
        assert window.effective_samples == 2880

    @pytest.mark.parametrize("days", [0, -1, -0.5])
    def test_non_positive_days_raises(self, days):
        with pytest.raises(DomainError):
            Window.from_days(days, cadence_sec=900)

    @pytest.mark.parametrize("cadence", [0, -1])
    def test_non_positive_cadence_raises(self, cadence):
        with pytest.raises(DomainError):
            Window.from_days(30, cadence_sec=cadence)

    def test_cadence_longer_than_the_window_raises(self):
        # One sample cannot describe a 30-day window.
        with pytest.raises(DomainError) as exc:
            Window.from_days(1, cadence_sec=2 * DAY_SEC)
        assert "at least one sample" in str(exc.value)

    @pytest.mark.parametrize("value", ["30", None, [30]])
    def test_non_numeric_raises(self, value):
        with pytest.raises(DomainError):
            Window.from_days(value, cadence_sec=900)

    def test_is_immutable(self):
        window = Window.from_days(30, cadence_sec=900)
        with pytest.raises(Exception):
            window.cadence_sec = 1800

    def test_has_no_dict(self):
        assert not hasattr(Window.from_days(30, cadence_sec=900), "__dict__")


class TestDerivedQuantities:
    def test_effective_samples_is_days_times_cycles_per_day(self):
        assert Window.from_days(30, cadence_sec=900).effective_samples == 2880
        assert Window.from_days(30, cadence_sec=1800).effective_samples == 1440
        assert Window.from_days(30, cadence_sec=3600).effective_samples == 720

    def test_effective_seconds_matches_the_declaration(self):
        window = Window.from_days(30, cadence_sec=900)
        assert window.effective_seconds == pytest.approx(30 * DAY_SEC)

    def test_effective_days_matches_the_declaration(self):
        for cadence in (300, 900, 1800, 3600):
            window = Window.from_days(30, cadence_sec=cadence)
            assert window.effective_days == pytest.approx(30, abs=0.01)

    def test_a_cadence_that_does_not_divide_the_day_still_holds(self):
        # 7000 s does not divide 86400; the floor must not lose more than
        # one cadence per day.
        window = Window.from_days(10, cadence_sec=7000)
        assert window.effective_days == pytest.approx(10, abs=0.6)

    def test_at_least_one_sample_per_day(self):
        assert Window.from_days(30, cadence_sec=DAY_SEC).effective_samples == 30


class TestCadenceChangeMakesANewWindow:
    def test_with_cadence_returns_a_new_window(self):
        original = Window.from_days(30, cadence_sec=900)
        changed = original.with_cadence(3600)
        assert changed is not original
        assert original.cadence_sec == 900, "the original must be untouched"
        assert changed.cadence_sec == 3600

    def test_the_declared_window_survives_a_cadence_change(self):
        original = Window.from_days(30, cadence_sec=900)
        changed = original.with_cadence(3600)
        assert changed.declared_days == 30
        assert changed.effective_days == pytest.approx(30, abs=0.01)
        assert changed.effective_samples != original.effective_samples

    def test_with_cadence_validates(self):
        with pytest.raises(DomainError):
            Window.from_days(30, cadence_sec=900).with_cadence(0)


class TestEquality:
    def test_same_declaration_is_equal(self):
        assert Window.from_days(30, cadence_sec=900) == \
            Window.from_days(30, cadence_sec=900)

    def test_different_cadence_is_not_equal(self):
        assert Window.from_days(30, cadence_sec=900) != \
            Window.from_days(30, cadence_sec=1800)

    def test_is_hashable(self):
        assert len({Window.from_days(30, cadence_sec=900),
                    Window.from_days(30, cadence_sec=900)}) == 1


class TestHistoricalDefect:
    """F-06 reproduced: the 30-that-meant-samples."""

    def test_the_sample_cap_cannot_be_expressed_as_a_window(self):
        with pytest.raises(DomainError) as exc:
            Window.from_samples(30)
        assert "cadence" in str(exc.value)

    def test_the_broken_and_correct_windows_are_distinguishable(self):
        correct = Window.from_days(30, cadence_sec=900)
        # What telegram actually held: 30 samples at 900 s.
        broken_seconds = 30 * 900
        assert correct.effective_seconds == pytest.approx(30 * DAY_SEC)
        assert broken_seconds == 27000          # 7.5 hours
        assert correct.effective_seconds / broken_seconds == pytest.approx(96)

    def test_the_repaired_cap_is_what_the_type_computes(self):
        # The WP-0.2 fix, expressed as the type would have from the start.
        assert Window.from_days(30, cadence_sec=900).effective_samples == 2880


class TestMultiDayCadence:
    """A cadence at or beyond a day used to floor to "1 sample per day"
    before multiplying, so a 5-day cadence reported 30 samples for a
    30-day window when the truth is 6 — the same shape as F-06, one level
    up."""

    @pytest.mark.parametrize("days,cadence_days,expected_samples", [
        (30, 1, 30),
        (30, 2, 15),
        (30, 5, 6),
        (30, 7, 4),      # floor(30/7)
        (14, 7, 2),
    ])
    def test_samples_at_multi_day_cadences(self, days, cadence_days,
                                           expected_samples):
        window = Window.from_days(days, cadence_sec=cadence_days * DAY_SEC)
        assert window.effective_samples == expected_samples

    @pytest.mark.parametrize("cadence_sec,expected_samples", [
        (300, 30 * 288), (900, 30 * 96), (1800, 30 * 48), (3600, 30 * 24),
    ])
    def test_sub_day_cadences_are_unchanged(self, cadence_sec,
                                            expected_samples):
        window = Window.from_days(30, cadence_sec=cadence_sec)
        assert window.effective_samples == expected_samples

    def test_effective_days_follows_the_corrected_count(self):
        window = Window.from_days(30, cadence_sec=5 * DAY_SEC)
        assert window.effective_days == pytest.approx(30, abs=0.01)

    def test_a_cadence_that_does_not_divide_the_window_floors_honestly(self):
        window = Window.from_days(30, cadence_sec=7 * DAY_SEC)
        assert window.effective_samples == 4
        assert window.effective_days == pytest.approx(28)
