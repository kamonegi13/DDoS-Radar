"""WP-4.1b ruling 1 — the same-phase read the migrated buckets need.

`baseline_stat.bucket` holds the v1 RAW EPOCH hour (or day) because that
is what the migration copied, and production's query is not an equality
on that column: it is a modulo over it —

    hod_same_hour        `(hour_bucket/3600)%24 = ? AND hour_bucket < ?`
                         (`radar/database.py:3213-3224`)
    gdelt_dow_same_weekday
                         `weekday = ? AND day_bucket < ?`
                         (`radar/database.py:3303-3310`)

L1 exposed exact-match reads only, so the question could not be asked and
seven adapters withheld a score. Re-bucketing was rejected (ruling 1): it
discards 28 migrated days AND turns a rolling window into an unwindowed
cumulative statistic, which is F-06 reintroduced at the storage layer.

So the read moves here, and the WINDOW production actually applies moves
with it — the window is enforced on the WRITE side (`hod_record` deletes
everything outside the newest `max_entries` buckets), never on the read.
Transcribing only the read would have produced a statistic over an
ever-growing history that no longer matches production after 28 days.
"""
import datetime

import pytest

from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.ledger.baselines import record_bucket_sample

NOW = 1_786_000_000.0
HOUR = 3600
DAY = 86400


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "phase.db"))
    yield instance
    instance.close()


def _hour_bucket(ts: float) -> int:
    return int(ts // HOUR) * HOUR


def _seed_hours(store, *, count, value_of, baseline_id="bgp_hod",
                sensor="bgp_hod", country="TW", start=NOW):
    """`count` consecutive hourly buckets ending just before `start`."""
    base = _hour_bucket(start)
    for index in range(1, count + 1):
        bucket = base - index * HOUR
        store.upsert_baseline_value(baseline_id=baseline_id, sensor=sensor,
                                    country=country, bucket=bucket,
                                    value=value_of(index))


class TestTheSamePhaseRead:
    def test_only_the_same_hour_of_day_is_returned(self, store):
        _seed_hours(store, count=72, value_of=lambda i: float(i))
        current = _hour_bucket(NOW)
        values = store.baseline_phase_values(
            "bgp_hod", sensor="bgp_hod", country="TW",
            phase=(current // HOUR) % 24, divisor=HOUR, modulus=24,
            before_bucket=current)
        # 72 hours back = three samples at the same hour of day.
        assert values == [72.0, 48.0, 24.0]

    def test_the_current_bucket_is_excluded(self, store):
        """`hour_bucket < ?`. Production records the current hour BEFORE
        reading, so a read that included it would compare the reading with
        itself and drive every Z-score toward zero."""
        current = _hour_bucket(NOW)
        store.upsert_baseline_value(baseline_id="bgp_hod", sensor="bgp_hod",
                                    country="TW", bucket=current, value=99.0)
        _seed_hours(store, count=48, value_of=lambda i: 1.0)
        values = store.baseline_phase_values(
            "bgp_hod", sensor="bgp_hod", country="TW",
            phase=(current // HOUR) % 24, divisor=HOUR, modulus=24,
            before_bucket=current)
        assert 99.0 not in values

    def test_another_country_is_not_mixed_in(self, store):
        _seed_hours(store, count=24, value_of=lambda i: 5.0, country="TW")
        _seed_hours(store, count=24, value_of=lambda i: 9.0, country="CN")
        current = _hour_bucket(NOW)
        values = store.baseline_phase_values(
            "bgp_hod", sensor="bgp_hod", country="TW",
            phase=(current // HOUR) % 24, divisor=HOUR, modulus=24,
            before_bucket=current)
        assert values == [5.0]

    def test_an_empty_history_is_an_empty_list_not_a_zero(self, store):
        """A zero would be a measured quiet hour; nothing is nothing."""
        assert store.baseline_phase_values(
            "bgp_hod", sensor="bgp_hod", country="TW", phase=0,
            divisor=HOUR, modulus=24, before_bucket=_hour_bucket(NOW)) == []

    def test_the_read_connection_cannot_write(self, store):
        """Same discipline as every other read: `mode=ro`."""
        _seed_hours(store, count=24, value_of=lambda i: 1.0)
        before = store.read_baseline("bgp_hod", sensor="bgp_hod",
                                     country="TW",
                                     bucket=_hour_bucket(NOW) - 24 * HOUR)
        store.baseline_phase_values(
            "bgp_hod", sensor="bgp_hod", country="TW", phase=0,
            divisor=HOUR, modulus=24, before_bucket=_hour_bucket(NOW))
        after = store.read_baseline("bgp_hod", sensor="bgp_hod",
                                    country="TW",
                                    bucket=_hour_bucket(NOW) - 24 * HOUR)
        assert before == after

    @pytest.mark.parametrize("kwargs", [
        {"phase": -1, "divisor": HOUR, "modulus": 24},
        {"phase": 24, "divisor": HOUR, "modulus": 24},
        {"phase": 0, "divisor": 0, "modulus": 24},
        {"phase": 0, "divisor": HOUR, "modulus": 0},
    ])
    def test_an_impossible_phase_raises_rather_than_returning_nothing(
            self, store, kwargs):
        """An out-of-range phase matches no row, so a silent empty list is
        indistinguishable from a cold baseline — and a cold baseline is
        exactly the state that makes an adapter withhold a score."""
        with pytest.raises(DomainError):
            store.baseline_phase_values("bgp_hod", sensor="bgp_hod",
                                        country="TW",
                                        before_bucket=_hour_bucket(NOW),
                                        **kwargs)


class TestTheDayOfWeekPhaseIsDerivable:
    """Production stores `weekday` as its own column; the migration copied
    only `day_bucket`. The two are the same fact, and this is the proof —
    without it the gdelt read would be a guess about epoch day zero."""

    @pytest.mark.parametrize("offset_days", list(range(0, 400, 7)) +
                             list(range(1, 30)))
    def test_the_weekday_column_equals_the_derived_phase(self, offset_days):
        from v3.runtime.baselines import weekday_phase, weekday_of

        ts = NOW + offset_days * DAY
        day_bucket = int(ts // DAY) * DAY
        production = datetime.datetime.fromtimestamp(
            ts, tz=datetime.timezone.utc).weekday()
        assert weekday_of(day_bucket) == production
        assert (int(day_bucket) // DAY) % 7 == weekday_phase(production)

    def test_same_weekday_rows_come_back_for_that_weekday(self, store):
        from v3.runtime.baselines import weekday_of, weekday_phase

        base = int(NOW // DAY) * DAY
        for index in range(1, 29):
            store.upsert_baseline_value(
                baseline_id="gdelt_dow", sensor="gdelt_dow", country="TW",
                bucket=base - index * DAY, value=float(index))
        weekday = weekday_of(base)
        values = store.baseline_phase_values(
            "gdelt_dow", sensor="gdelt_dow", country="TW",
            phase=weekday_phase(weekday), divisor=DAY, modulus=7,
            before_bucket=base)
        assert values == [28.0, 21.0, 14.0, 7.0]


class TestTheWriteSideWindow:
    """`hod_record` is where production's window lives: an INSERT OR
    REPLACE followed by a DELETE of everything outside the newest
    `max_entries` buckets (`radar/database.py:3173-3191`)."""

    def test_a_sample_is_recorded_at_its_bucket(self, store):
        bucket = _hour_bucket(NOW)
        assert record_bucket_sample(store, baseline_id="bgp_hod",
                                    sensor="bgp_hod", country="TW",
                                    bucket=bucket, value=12.0,
                                    max_entries=672, now=NOW) is True
        row = store.read_baseline("bgp_hod", sensor="bgp_hod", country="TW",
                                  bucket=bucket)
        assert row["mean"] == 12.0

    def test_the_newest_bucket_is_not_rewritten_within_the_same_hour(
            self, store):
        """`if _last_bucket != _hour_bucket` (`bgp_routing.py:64-66`). The
        second cycle inside one UTC hour records nothing, so the hour's
        sample is the first reading of that hour, not the last."""
        bucket = _hour_bucket(NOW)
        record_bucket_sample(store, baseline_id="bgp_hod", sensor="bgp_hod",
                             country="TW", bucket=bucket, value=12.0,
                             max_entries=672, now=NOW)
        assert record_bucket_sample(store, baseline_id="bgp_hod",
                                    sensor="bgp_hod", country="TW",
                                    bucket=bucket, value=99.0,
                                    max_entries=672, now=NOW) is False
        row = store.read_baseline("bgp_hod", sensor="bgp_hod", country="TW",
                                  bucket=bucket)
        assert row["mean"] == 12.0

    def test_the_oldest_buckets_fall_out_of_the_window(self, store):
        """Without this the statistic keeps every sample it ever saw —
        a declared 28-day window that the mechanism does not hold (F-06)."""
        base = _hour_bucket(NOW)
        for index in range(10):
            record_bucket_sample(store, baseline_id="bgp_hod",
                                 sensor="bgp_hod", country="TW",
                                 bucket=base + index * HOUR,
                                 value=float(index), max_entries=4, now=NOW)
        kept = store.baseline_bucket_count("bgp_hod", sensor="bgp_hod",
                                           country="TW")
        assert kept == 4
        assert store.read_baseline("bgp_hod", sensor="bgp_hod", country="TW",
                                   bucket=base) is None
        assert store.read_baseline("bgp_hod", sensor="bgp_hod", country="TW",
                                   bucket=base + 9 * HOUR) is not None

    def test_the_window_is_per_country(self, store):
        """`WHERE theater=?` on both the INSERT and the DELETE. A shared
        cap would let a busy country evict a quiet one's whole history."""
        base = _hour_bucket(NOW)
        for index in range(6):
            for country in ("TW", "CN"):
                record_bucket_sample(store, baseline_id="bgp_hod",
                                     sensor="bgp_hod", country=country,
                                     bucket=base + index * HOUR,
                                     value=1.0, max_entries=4, now=NOW)
        assert store.baseline_bucket_count("bgp_hod", sensor="bgp_hod",
                                           country="TW") == 4
        assert store.baseline_bucket_count("bgp_hod", sensor="bgp_hod",
                                           country="CN") == 4

    def test_recording_is_not_a_read_path(self, store):
        """F-05 / S5-VERIF-019: the statistic moves in its own stage. The
        read must never advance it, so the recorder takes the value from
        its caller and never derives one from the ledger."""
        import inspect

        source = inspect.getsource(record_bucket_sample)
        assert "latest_signal_at" not in source
        assert "signals_between" not in source
