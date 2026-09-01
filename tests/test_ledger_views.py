"""WP-2.2 L1 — the TL stream and its derived views (P6 O-16).

The current system grew four TL lanes (observation series, history, the
change-gated rows inside the conclusions ledger, and a continuity log) and
then three compensating mechanisms on top, because thinning the stream
broke chronic detection, and the fix for that missed flapping, and the fix
for THAT was a duty-cycle correction.

O-16 rules that there is one unthinned stream and everything else is a
query over it. So these tests check two things at once: that each derived
view computes what it claims, and that no view needs state of its own.
"""
import pytest

from v3.kernel import ThreatLevel, Window
from v3.ledger import LedgerStore, TLObservation, views

NOW = 1_786_000_000.0
HOUR = 3600.0
DAY = 86400.0


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "v3.db"))
    yield instance
    instance.close()


def _seed(store, series, scenario_id="taiwan", start=NOW, step=HOUR):
    """series: list of TL ints, None means INSUFFICIENT (null-zone)."""
    for index, level in enumerate(series):
        store.append_tl(TLObservation(
            tick_id=f"tick{index}", scenario_id=scenario_id,
            observed_at=start + index * step,
            threat_level=None if level is None else ThreatLevel(level),
            score=float(10 * index)))


class TestStreamIsUnthinned:
    def test_every_tick_is_stored_even_when_unchanged(self, store):
        _seed(store, [3, 3, 3, 3])
        assert store.count_tl() == 4, \
            "O-16: no change-gate — repeated values are still observations"

    def test_a_null_zone_tick_is_stored_not_skipped(self, store):
        _seed(store, [3, None, 3])
        assert store.count_tl() == 3

    def test_the_stored_level_round_trips_as_a_kernel_type(self, store):
        _seed(store, [2])
        row = store.latest_tl_at(NOW, scenario_id="taiwan")
        assert row["threat_level"] == ThreatLevel(2)

    def test_a_raw_int_level_is_refused_at_the_boundary(self, store):
        with pytest.raises(Exception):
            store.append_tl(TLObservation(
                tick_id="x", scenario_id="taiwan", observed_at=NOW,
                threat_level=3, score=1.0))   # not a ThreatLevel

    def test_null_zone_is_representable_as_none(self, store):
        _seed(store, [None])
        assert store.latest_tl_at(NOW, scenario_id="taiwan")["threat_level"] \
            is None


class TestLatestTlAtT:
    def test_returns_the_level_in_force(self, store):
        _seed(store, [5, 4, 2])
        row = store.latest_tl_at(NOW + HOUR, scenario_id="taiwan")
        assert row["threat_level"] == ThreatLevel(4)

    def test_scenarios_are_independent(self, store):
        _seed(store, [5], scenario_id="taiwan")
        _seed(store, [1], scenario_id="korea")
        assert store.latest_tl_at(NOW, scenario_id="korea")["threat_level"] \
            == ThreatLevel(1)

    def test_before_the_series_returns_nothing(self, store):
        _seed(store, [3])
        assert store.latest_tl_at(NOW - 1, scenario_id="taiwan") is None


class TestDerivedViews:
    """Each view is a pure read; none of them writes or caches."""

    def test_series_between_returns_the_window(self, store):
        _seed(store, [5, 4, 3, 2, 1])
        rows = views.series_between(store, "taiwan", start=NOW + HOUR,
                                    end=NOW + 3 * HOUR)
        assert [row["threat_level"].value for row in rows] == [4, 3, 2]

    def test_trend_over_a_kernel_window(self, store):
        # Severity rises from TL5 (severity 1) to TL1 (severity 5).
        _seed(store, [5, 4, 3, 2, 1], step=HOUR)
        window = Window.from_days(1, cadence_sec=HOUR)
        trend = views.trend_over(store, "taiwan", window=window,
                                 now=NOW + 4 * HOUR)
        assert trend["direction"] == "worsening"
        assert trend["first_severity"] == 1
        assert trend["last_severity"] == 5
        assert trend["samples"] == 5

    def test_trend_is_improving_when_severity_falls(self, store):
        _seed(store, [1, 2, 3, 4, 5])
        window = Window.from_days(1, cadence_sec=HOUR)
        trend = views.trend_over(store, "taiwan", window=window,
                                 now=NOW + 4 * HOUR)
        assert trend["direction"] == "improving"

    def test_trend_is_flat_when_unchanged(self, store):
        _seed(store, [3, 3, 3])
        window = Window.from_days(1, cadence_sec=HOUR)
        assert views.trend_over(store, "taiwan",
                                window=Window.from_days(1, cadence_sec=HOUR),
                                now=NOW + 2 * HOUR)["direction"] == "flat"

    def test_trend_requires_a_kernel_window(self, store):
        _seed(store, [3])
        with pytest.raises(TypeError):
            views.trend_over(store, "taiwan", window=86400, now=NOW)

    def test_trend_reports_insufficient_rather_than_guessing(self, store):
        window = Window.from_days(1, cadence_sec=HOUR)
        trend = views.trend_over(store, "taiwan", window=window, now=NOW)
        assert trend["direction"] == "insufficient"
        assert trend["samples"] == 0

    def test_null_zone_spans_are_derived_not_logged(self, store):
        _seed(store, [3, None, None, 3, None])
        spans = views.null_zone_spans(store, "taiwan", now=NOW + 5 * HOUR)
        assert len(spans) == 2
        assert spans[0]["length_sec"] == pytest.approx(2 * HOUR)
        assert spans[0]["ongoing"] is False
        assert spans[1]["ongoing"] is True

    def test_a_stream_with_no_null_zone_yields_no_spans(self, store):
        _seed(store, [3, 3, 3])
        assert views.null_zone_spans(store, "taiwan",
                                     now=NOW + 3 * HOUR) == []

    def test_chronic_detection_uses_the_unthinned_stream(self, store):
        # 40 consecutive null-zone ticks over 40 hours.
        _seed(store, [None] * 40)
        chronic = views.chronic_null_zone(store, "taiwan",
                                          threshold_sec=24 * HOUR,
                                          now=NOW + 40 * HOUR)
        assert chronic["is_chronic"] is True
        assert chronic["longest_span_sec"] >= 24 * HOUR

    def test_a_brief_null_zone_is_not_chronic(self, store):
        _seed(store, [3, None, 3])
        chronic = views.chronic_null_zone(store, "taiwan",
                                          threshold_sec=24 * HOUR,
                                          now=NOW + 3 * HOUR)
        assert chronic["is_chronic"] is False

    def test_history_projection_reproduces_a_thinned_view(self, store):
        # O-16 parity requirement: the thinned history the old lanes stored
        # must be derivable from the unthinned stream.
        _seed(store, [5, 5, 4, 4, 4, 2])
        transitions = views.transitions_only(store, "taiwan",
                                             now=NOW + 6 * HOUR)
        assert [row["threat_level"].value for row in transitions] == [5, 4, 2]

    def test_transitions_include_a_return_to_a_previous_level(self, store):
        _seed(store, [3, 5, 3])
        transitions = views.transitions_only(store, "taiwan",
                                             now=NOW + 3 * HOUR)
        assert [row["threat_level"].value for row in transitions] == [3, 5, 3]

    def test_transitions_treat_null_zone_as_its_own_state(self, store):
        _seed(store, [3, None, None, 3])
        transitions = views.transitions_only(store, "taiwan",
                                             now=NOW + 4 * HOUR)
        levels = [None if row["threat_level"] is None
                  else row["threat_level"].value for row in transitions]
        assert levels == [3, None, 3]


class TestViewsAreSideEffectFree:
    def _fingerprint(self, store):
        return (store.count_tl(), store.count_signals())

    def test_no_view_writes(self, store):
        _seed(store, [5, None, 3, 3, 1])
        before = self._fingerprint(store)
        window = Window.from_days(1, cadence_sec=HOUR)
        views.series_between(store, "taiwan", start=NOW, end=NOW + 5 * HOUR)
        views.trend_over(store, "taiwan", window=window, now=NOW + 4 * HOUR)
        views.null_zone_spans(store, "taiwan", now=NOW + 5 * HOUR)
        views.chronic_null_zone(store, "taiwan", threshold_sec=HOUR,
                                now=NOW + 5 * HOUR)
        views.transitions_only(store, "taiwan", now=NOW + 5 * HOUR)
        assert self._fingerprint(store) == before

    def test_views_hold_no_module_state(self):
        caches = [name for name, value in vars(views).items()
                  if isinstance(value, (dict, list)) and
                  not name.startswith("__")]
        assert caches == [], f"derived views must be stateless: {caches}"

    def test_repeated_calls_return_equal_results(self, store):
        _seed(store, [5, 4, 3])
        window = Window.from_days(1, cadence_sec=HOUR)
        first = views.trend_over(store, "taiwan", window=window,
                                 now=NOW + 2 * HOUR)
        second = views.trend_over(store, "taiwan", window=window,
                                  now=NOW + 2 * HOUR)
        assert first == second
