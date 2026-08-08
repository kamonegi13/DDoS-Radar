"""WP-3.2 condition 2 — label epochs are first class, and a comparison
across two of them cannot be expressed.

F-16 is the live defect: `docs/baselines/recall_metrics.json` carries
`since: null`, so the CI gate compares across the 2026-07-04 and
2026-08-02 series breaks. WP-1.4 could DETECT that; the rule against it
existed only as procedure. S5-VERIF-032/033/036 require code enforcement.

The tests below are written against the strongest available reading of
"mechanically refused": not "compare() raises when the epochs differ" —
that is a check someone can forget to call — but "there is no way to hand
compare() two snapshots from different epochs, because compare() has no
parameter that accepts them".
"""
from __future__ import annotations

import pytest

from v3.calibration import epoch as E
from v3.kernel.errors import DomainError


class TestEpochRegistry:
    """An epoch id is a registered fact, not a free string."""

    def test_the_three_known_epochs_are_registered(self):
        ids = set(E.registered_epoch_ids())
        assert {"pre_2026_07_04", "e2026_07_04", "e2026_08_02"} <= ids

    def test_the_current_epoch_is_the_attribution_repair(self):
        assert E.CURRENT_EPOCH.epoch_id == "e2026_08_02"

    def test_an_unregistered_epoch_id_is_refused(self):
        with pytest.raises(DomainError, match="not a registered label epoch"):
            E.epoch("e2027_01_01")

    def test_epochs_are_ordered_by_start_and_the_order_is_total(self):
        starts = [E.epoch(i).started_at for i in E.registered_epoch_ids()]
        assert len(set(starts)) == len(starts)

    def test_the_two_incident_epochs_carry_the_reason_they_broke(self):
        assert "TL" in E.epoch("e2026_07_04").reason
        assert "attribution" in E.epoch("e2026_08_02").reason

    def test_the_pre_restart_population_is_quarantined(self):
        assert E.epoch("pre_2026_07_04").is_quarantined is True
        assert E.CURRENT_EPOCH.is_quarantined is False


class TestLabelProvenance:
    """S5-VERIF-032: structured columns, never free text."""

    def test_a_label_carries_generator_identity_and_an_epoch(self):
        prov = E.LabelProvenance(
            generator_id="rss_etl", generator_version="3",
            rule_id="kinetic_tier", epoch_id="e2026_08_02")
        assert prov.epoch.epoch_id == "e2026_08_02"

    def test_an_unregistered_epoch_cannot_be_stamped_on_a_label(self):
        with pytest.raises(DomainError, match="not a registered label epoch"):
            E.LabelProvenance(generator_id="rss_etl", generator_version="3",
                              rule_id="kinetic_tier", epoch_id="made_up")

    @pytest.mark.parametrize("field", ["generator_id", "generator_version",
                                       "rule_id"])
    def test_every_provenance_column_is_required(self, field):
        kwargs = dict(generator_id="rss_etl", generator_version="3",
                      rule_id="kinetic_tier", epoch_id="e2026_08_02")
        kwargs[field] = ""
        with pytest.raises(DomainError):
            E.LabelProvenance(**kwargs)

    def test_provenance_is_frozen(self):
        prov = E.LabelProvenance(generator_id="rss_etl",
                                 generator_version="3",
                                 rule_id="r", epoch_id="e2026_08_02")
        with pytest.raises((AttributeError, DomainError)):
            prov.epoch_id = "pre_2026_07_04"

    def test_a_relaxing_subclass_is_refused(self):
        with pytest.raises(TypeError, match="final"):
            class Looser(E.LabelProvenance):
                pass

    def test_a_round_trip_revalidates(self):
        import copy
        prov = E.LabelProvenance(generator_id="rss_etl",
                                 generator_version="3",
                                 rule_id="r", epoch_id="e2026_08_02")
        assert copy.deepcopy(prov) == prov


class TestSnapshotCarriesItsEpoch:
    """S5-VERIF-033: a baseline knows the epoch it was computed under."""

    def test_a_snapshot_requires_an_epoch(self):
        started = E.epoch("e2026_08_02").started_at
        snap = E.EpochStamp(epoch_id="e2026_08_02", since=started + 1.0,
                            until=started + 2.0, exclude_auto=False)
        assert snap.epoch.epoch_id == "e2026_08_02"

    def test_since_may_not_be_null(self):
        # The exact shape of F-16: `since: null` is all-history, which is
        # how the gate straddled two series breaks for a month.
        with pytest.raises(DomainError, match="since"):
            started = E.epoch("e2026_08_02").started_at
            E.EpochStamp(epoch_id="e2026_08_02", since=None,
                         until=started + 2.0, exclude_auto=False)

    def test_a_window_that_predates_its_own_epoch_is_refused(self):
        started = E.epoch("e2026_08_02").started_at
        with pytest.raises(DomainError, match="predates"):
            E.EpochStamp(epoch_id="e2026_08_02", since=started - 86400.0,
                         until=started + 10.0, exclude_auto=False)

    def test_a_window_inside_its_epoch_is_accepted(self):
        started = E.epoch("e2026_08_02").started_at
        stamp = E.EpochStamp(epoch_id="e2026_08_02", since=started + 1.0,
                             until=started + 100.0, exclude_auto=False)
        assert stamp.since > started


class TestCrossEpochComparisonIsUnrepresentable:
    """The heart of condition 2."""

    def _stamp(self, epoch_id: str, *, exclude_auto: bool = False):
        started = E.epoch(epoch_id).started_at
        return E.EpochStamp(epoch_id=epoch_id, since=started + 1.0,
                            until=started + 1000.0, exclude_auto=exclude_auto)

    def test_two_stamps_of_the_same_epoch_align(self):
        pair = E.AlignedPair(baseline=self._stamp("e2026_08_02"),
                             current=self._stamp("e2026_08_02"))
        assert pair.epoch.epoch_id == "e2026_08_02"

    def test_two_stamps_of_different_epochs_cannot_form_a_pair(self):
        with pytest.raises(E.EpochMismatchError) as exc:
            E.AlignedPair(baseline=self._stamp("e2026_07_04"),
                          current=self._stamp("e2026_08_02"))
        assert "Re-baseline" in str(exc.value)

    def test_a_quarantined_epoch_cannot_form_a_pair_even_with_itself(self):
        with pytest.raises(E.EpochMismatchError, match="quarantined"):
            E.AlignedPair(baseline=self._stamp("pre_2026_07_04"),
                          current=self._stamp("pre_2026_07_04"))

    def test_exclude_auto_must_match_between_the_two_sides(self):
        # S1-CALIB-029: the current side INHERITS the baseline's flag. If
        # they disagree, the comparison is between two populations.
        with pytest.raises(E.EpochMismatchError, match="exclude_auto"):
            E.AlignedPair(baseline=self._stamp("e2026_08_02",
                                               exclude_auto=True),
                          current=self._stamp("e2026_08_02",
                                              exclude_auto=False))

    def test_the_comparison_entry_point_accepts_only_an_aligned_pair(self):
        # Structural, not behavioural: if `compare` grew a (baseline,
        # current) overload, the refusal above could be bypassed without
        # any test failing.
        import inspect
        params = list(inspect.signature(E.aligned_windows).parameters)
        assert params[0] == "pair"
        assert "baseline" not in params and "current" not in params

    def test_an_aligned_pair_cannot_be_forged_by_mutation(self):
        pair = E.AlignedPair(baseline=self._stamp("e2026_08_02"),
                             current=self._stamp("e2026_08_02"))
        with pytest.raises((AttributeError, DomainError)):
            pair.baseline = self._stamp("e2026_07_04")

    def test_a_round_tripped_pair_is_revalidated(self):
        import copy
        pair = E.AlignedPair(baseline=self._stamp("e2026_08_02"),
                             current=self._stamp("e2026_08_02"))
        assert copy.deepcopy(pair).epoch == pair.epoch

    def test_a_relaxing_subclass_of_the_pair_is_refused(self):
        with pytest.raises(TypeError, match="final"):
            class Loose(E.AlignedPair):
                pass


class TestEpochAdvance:
    """A generator change must move the epoch, or the guard is theatre."""

    def test_changing_the_generator_semantics_requires_a_new_epoch(self):
        # The registry records which generator versions belong to which
        # epoch. A version outside the epoch's declared set is refused, so
        # a semantics change that forgets to advance the epoch cannot be
        # stamped onto a label.
        with pytest.raises(DomainError, match="generator_version"):
            E.LabelProvenance(generator_id="rss_etl",
                              generator_version="99",
                              rule_id="kinetic_tier",
                              epoch_id="e2026_08_02")

    def test_the_registry_names_the_generators_of_each_epoch(self):
        assert "rss_etl:3" in E.epoch("e2026_08_02").generators
