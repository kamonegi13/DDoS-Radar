"""WP-0.2 F-06 regression — telegram's rolling baseline holds its window.

The bug: `_update_baseline_tg` capped `daily_counts` at
NARRATIVE_BASELINE_DAYS *samples*. The sensor polls every 900 s, so the
declared 30-day window was really 30 x 900 s = 7.5 hours, and the z-score
normalised each reading against the last few hours of itself. Burst
detection was structurally dead — and silent, because the sensor fetched
fine and the flag simply never fired.

rss_narrative had the identical bug and was fixed on 2026-04-29 by
deriving the cap from cycles-per-day; the fix was never carried across.
This is that carry-across, plus the test that was missing (telegram had
no test at all, which is why it survived).

Note for the operator: the *real* accumulation is calendar-bound — the
baseline only reaches 30 days of history after 30 days of running. These
tests prove the cap arithmetic; the observation itself is a later check
(P3 WP-0.2 検証手順 records this explicitly).
"""
import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.sensors.telegram import (NARRATIVE_BASELINE_DAYS,
                                    TELEGRAM_MIRROR_POLL, TelegramMirrorSensor)


@pytest.fixture
def clean_baseline():
    """_baseline_tg is CLASS state shared by every instance — restore it."""
    saved = TelegramMirrorSensor._baseline_tg
    TelegramMirrorSensor._baseline_tg = {}
    yield TelegramMirrorSensor
    TelegramMirrorSensor._baseline_tg = saved


def _counts(sensor_cls, theater="TW"):
    return sensor_cls._baseline_tg[theater]["daily_counts"]


class TestBaselineCap:
    def test_cap_is_days_times_cycles_per_day(self, clean_baseline):
        # 30 days x floor(86400/900) = 30 x 96 = 2880 samples.
        expected = NARRATIVE_BASELINE_DAYS * (86400 // TELEGRAM_MIRROR_POLL)
        for _ in range(3000):
            clean_baseline._update_baseline_tg("TW", 1.0)
        assert len(_counts(clean_baseline)) == expected == 2880

    def test_the_old_sample_cap_is_gone(self, clean_baseline):
        for _ in range(200):
            clean_baseline._update_baseline_tg("TW", 1.0)
        assert len(_counts(clean_baseline)) == 200, \
            "must not truncate at NARRATIVE_BASELINE_DAYS raw samples (F-06)"

    def test_effective_window_matches_the_declaration(self, clean_baseline):
        for _ in range(3000):
            clean_baseline._update_baseline_tg("TW", 1.0)
        effective_h = len(_counts(clean_baseline)) * TELEGRAM_MIRROR_POLL / 3600
        assert effective_h == pytest.approx(NARRATIVE_BASELINE_DAYS * 24)

    def test_the_oldest_samples_are_the_ones_dropped(self, clean_baseline):
        for i in range(3000):
            clean_baseline._update_baseline_tg("TW", float(i))
        counts = _counts(clean_baseline)
        assert counts[-1] == 2999.0
        assert counts[0] == float(3000 - len(counts))

    def test_under_the_cap_nothing_is_dropped(self, clean_baseline):
        for i in range(50):
            clean_baseline._update_baseline_tg("TW", float(i))
        assert _counts(clean_baseline) == [float(i) for i in range(50)]

    def test_each_country_keeps_its_own_series(self, clean_baseline):
        for _ in range(10):
            clean_baseline._update_baseline_tg("TW", 1.0)
        for _ in range(5):
            clean_baseline._update_baseline_tg("UA", 2.0)
        assert len(_counts(clean_baseline, "TW")) == 10
        assert len(_counts(clean_baseline, "UA")) == 5

    def test_last_updated_advances(self, clean_baseline):
        clean_baseline._update_baseline_tg("TW", 1.0)
        assert clean_baseline._baseline_tg["TW"]["last_updated"] > 0


class TestCapFollowsTheLiveCadence:
    """The cap must track the instance's live poll_interval, not a constant
    frozen at import. They agree today; they would not if this sensor ever
    gained the adaptive polling ct_log and ooni use, and the L5 window
    verifier reads the live attribute — a frozen cap would make it report
    OK for a window that had silently shrunk."""

    def test_a_slower_cadence_shrinks_the_sample_cap(self, clean_baseline):
        for _ in range(5000):
            clean_baseline._update_baseline_tg("TW", 1.0, 3600)
        # 30 d x 24 cycles/day at an hourly poll.
        assert len(_counts(clean_baseline)) == 30 * 24

    def test_a_faster_cadence_grows_the_sample_cap(self, clean_baseline):
        for _ in range(10000):
            clean_baseline._update_baseline_tg("TW", 1.0, 300)
        assert len(_counts(clean_baseline)) == 30 * 288

    def test_the_window_stays_thirty_days_at_any_cadence(self, clean_baseline):
        for interval in (300, 900, 1800, 3600):
            TelegramMirrorSensor._baseline_tg = {}
            for _ in range(20000):
                clean_baseline._update_baseline_tg("TW", 1.0, interval)
            window_h = len(_counts(clean_baseline)) * interval / 3600
            assert window_h == pytest.approx(NARRATIVE_BASELINE_DAYS * 24), \
                f"window drifted at a {interval}s cadence"

    def test_the_instance_passes_its_live_interval(self, clean_baseline,
                                                   monkeypatch):
        # Mutating the instance attribute must change the cap — the guard
        # against the frozen-constant false negative.
        sensor = TelegramMirrorSensor()
        monkeypatch.setattr(sensor, "poll_interval", 3600)
        for _ in range(5000):
            sensor._update_baseline_tg("TW", 1.0, sensor.poll_interval)
        assert len(_counts(clean_baseline)) == 30 * 24

    def test_the_call_site_forwards_the_live_interval(self):
        import inspect
        src = inspect.getsource(TelegramMirrorSensor.fetch)
        assert "_update_baseline_tg(theater, normalized, self.poll_interval)" \
            in src, "the cap must be derived from the live cadence"

    def test_the_default_keeps_the_classmethod_callable(self, clean_baseline):
        clean_baseline._update_baseline_tg("TW", 1.0)
        assert len(_counts(clean_baseline)) == 1


class TestDegenerateConfiguration:
    def test_zero_days_does_not_disable_truncation(self, clean_baseline,
                                                   monkeypatch):
        # `list[-0:]` is the WHOLE list: a days=0 misconfiguration would
        # silently turn the baseline into an unbounded accumulator.
        import radar.sensors.telegram as tg
        monkeypatch.setattr(tg, "NARRATIVE_BASELINE_DAYS", 0)
        for _ in range(500):
            clean_baseline._update_baseline_tg("TW", 1.0, 900)
        counts = _counts(clean_baseline)
        assert len(counts) == 96, "floors at one day's worth of cycles"
        assert len(counts) < 500

    def test_a_zero_poll_interval_does_not_divide_by_zero(self,
                                                         clean_baseline):
        clean_baseline._update_baseline_tg("TW", 1.0, 0)
        assert len(_counts(clean_baseline)) == 1


class TestParityWithRssNarrative:
    """The two sensors share the defect's shape; they must now share the fix."""

    def test_both_derive_the_cap_from_cycles_per_day(self, clean_baseline):
        from radar.sensors.rss_narrative import RssNarrativeSensor
        rss = RssNarrativeSensor()
        for _ in range(3000):
            rss._update_baseline("TW", 1.0)
            clean_baseline._update_baseline_tg("TW", 1.0)

        rss_window_h = (len(rss._baseline["TW"]["daily_counts"])
                        * rss.poll_interval / 3600)
        tg_window_h = len(_counts(clean_baseline)) * TELEGRAM_MIRROR_POLL / 3600
        assert rss_window_h == tg_window_h == NARRATIVE_BASELINE_DAYS * 24
