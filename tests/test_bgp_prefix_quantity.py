"""D2 H-05 — the quantity `ripe_bgp` measures, and the history behind it.

`radar/sensors/bgp_routing.py` read `announced_prefixes` and `seen_ases`,
two keys `country-routing-stats` has never returned, so `pfx_now` was 0 on
every cycle and every one of the 5,398 rows in the live `bgp_hod` table
was 0.0. Both branches of the detector were unreachable, and v3
transcribed the same read.

The quantity therefore has no production behaviour to inherit. It is
CHOSEN — `v4_prefixes_ris + v6_prefixes_ris` and `asns_ris` — and this
module is where the choice is held to account:

  agreement   production and v3 hold one copy each of the rule, because
              neither system may import the other. A sweep over generated
              payloads pins them equal, and mutating either side's
              constants must break it.
  sentinel    the `_stats` variants answer **-1** when the registry view
              is unavailable. Reading a sentinel as a number is H-05 one
              level up.
  absence     a missing field yields None and then NO_DATA, never 0.
              `.get(key, 0)` translating "not answered" into "announces
              nothing" is the whole of H-05.
  resolution  without a `starttime` RIPE answers `1w`, so the reading
              would be a weekly figure stored in an hourly bucket.
  epoch       the backfill must not merge real values with the dead
              zeros, and must not declare a short bucket warm.

The fixtures under `tests/fixtures/adapters/ripe_bgp/` are REAL captured
responses. The one they replaced was hand-written around
`announced_prefixes`, which is how a port reproduced a defect and passed
its own tests.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import random
import sqlite3

import pytest

from radar.sensors import bgp_routing as production
from v3.adapters.cyber import ripe_bgp as v3_adapter
from v3.runtime import expansion

REPO = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures" / "adapters" / "ripe_bgp"
HOUR = 3600


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def _backfill():
    """The script, loaded by path — `scripts/` is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        "backfill_bgp_hod", REPO / "scripts" / "backfill_bgp_hod.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backfill = _backfill()


#: One real stats entry, verbatim, sentinels included.
REAL_ENTRY = {
    "timeline": [{"starttime": "2026-08-01T00:00:00",
                  "endtime": "2026-08-01T01:00:00"}],
    "v4_prefixes_ris": 9601, "v6_prefixes_ris": 1204, "asns_ris": 245,
    "v4_prefixes_stats": -1, "v6_prefixes_stats": -1, "asns_stats": 467,
    "stats_date": "2026-08-01T00:00:00",
}


# ── 1. the choice ───────────────────────────────────────────────────────

class TestTheQuantityIsTheRisView:
    def test_the_count_is_v4_plus_v6(self):
        assert production.prefix_count(REAL_ENTRY) == 9601 + 1204
        assert v3_adapter.prefix_count(REAL_ENTRY) == 9601 + 1204

    def test_the_as_count_is_the_ris_view(self):
        assert production.as_count(REAL_ENTRY) == 245
        assert v3_adapter.as_count(REAL_ENTRY) == 245

    def test_a_v6_only_withdrawal_moves_the_count(self):
        """NP1's reason for summing both families rather than taking v4.

        A country whose v6 announcements vanish is having an outage, and a
        v4-only detector reports a perfectly steady network through it.
        """
        withdrawn = {**REAL_ENTRY, "v6_prefixes_ris": 0}
        assert production.prefix_count(withdrawn) < production.prefix_count(
            REAL_ENTRY)
        assert v3_adapter.prefix_count(withdrawn) < v3_adapter.prefix_count(
            REAL_ENTRY)

    def test_a_fractional_reading_is_not_truncated(self):
        """RIPE reports 9599.5 for an hour whose count changed within it.

        Rounding here would quantise exactly the movement the Z reads, and
        the ledger column is REAL for that reason.
        """
        entry = {**REAL_ENTRY, "v4_prefixes_ris": 9599.5}
        assert production.prefix_count(entry) == 9599.5 + 1204
        assert v3_adapter.prefix_count(entry) == 9599.5 + 1204


class TestTheSentinelIsNeverRead:
    def test_the_stats_variants_are_not_the_source(self):
        """`v4_prefixes_stats: -1` on every entry of every country sampled.

        If the `_stats` family were the source, a -1 would arrive as a
        prefix count of minus one and the Z-score would read it.
        """
        assert "v4_prefixes_stats" not in production.RIS_PREFIX_KEYS
        assert "v6_prefixes_stats" not in production.RIS_PREFIX_KEYS
        assert production.RIS_ASN_KEY != "asns_stats"
        assert tuple(v3_adapter.RIS_PREFIX_KEYS) == tuple(
            production.RIS_PREFIX_KEYS)

    def test_the_coercion_is_the_same_on_both_sides(self):
        """The divergence the sweep found once and now pins.

        Production refused a numeric STRING while v3's `as_float` coerced
        it, so one system would have read 9601 where the other read
        NO_DATA — two transcriptions of one rule quietly becoming two
        rules, which is the shape H-05 itself has.
        """
        for value in ("9601", "9601.5", True, False, None, "n/a", "",
                      float("nan"), float("inf"), [], {}, -1, 0, 9601.5):
            entry = {"v4_prefixes_ris": value}
            assert production.prefix_count(entry) == v3_adapter.prefix_count(
                entry), value

    def test_a_negative_ris_value_is_absent_not_a_measurement(self):
        """Defence in depth: should RIS ever adopt the same sentinel, a
        negative prefix count must not become a number either."""
        entry = {"v4_prefixes_ris": -1, "v6_prefixes_ris": -1,
                 "asns_ris": -1}
        assert production.prefix_count(entry) is None
        assert v3_adapter.prefix_count(entry) is None
        assert production.as_count(entry) is None
        assert v3_adapter.as_count(entry) is None

    def test_only_the_sentinel_bearing_family_is_dropped(self):
        entry = {"v4_prefixes_ris": 100, "v6_prefixes_ris": -1}
        assert production.prefix_count(entry) == 100
        assert v3_adapter.prefix_count(entry) == 100


class TestAbsenceIsNotZero:
    def test_a_missing_field_is_none_on_both_sides(self):
        assert production.prefix_count({}) is None
        assert v3_adapter.prefix_count({}) is None
        assert production.as_count({}) is None
        assert v3_adapter.as_count({}) is None

    def test_the_dead_key_is_not_a_fallback(self):
        """Reading `announced_prefixes` again — even as a fallback — would
        re-open the branch H-05 came through."""
        assert production.prefix_count({"announced_prefixes": 8100}) is None
        assert v3_adapter.prefix_count({"announced_prefixes": 8100}) is None
        assert production.as_count({"seen_ases": 402}) is None
        assert v3_adapter.as_count({"seen_ases": 402}) is None

    def test_v3_reports_no_data_rather_than_zero_prefixes(self):
        from tests.test_adapters_cyber_fidelity import context, synthetic
        body = json.dumps({"data": {"resource": "TW", "stats": [
            {"stats_date": "2026-08-01T00:00:00"}]}}).encode()
        draft = v3_adapter.normalize(synthetic(body), context("ripe_bgp"))[0]
        assert draft.status == "NO_DATA"
        assert "announced_prefixes" not in draft.flags

    @pytest.mark.parametrize("path", [
        ("radar", "sensors", "bgp_routing.py"),
        ("v3", "adapters", "cyber", "ripe_bgp.py"),
        ("scripts", "backfill_bgp_hod.py"),
    ])
    def test_no_code_path_fetches_a_dead_key_off_a_payload(self, path):
        """Checked on the AST, not the text: both files DISCUSS the dead
        keys at length, and a prose match would pass whatever the code
        did — which is the shape of check that let H-05 live."""
        import ast
        tree = ast.parse((REPO.joinpath(*path)).read_text())
        offenders = [
            node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get" and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in ("announced_prefixes", "seen_ases")]
        assert offenders == []


# ── 2. the two copies agree ─────────────────────────────────────────────

def _generated_entry(rng: random.Random) -> dict:
    """A payload shaped like RIPE's, with fields present at random."""
    entry: dict = {"stats_date": "2026-08-01T00:00:00"}
    for key in ("v4_prefixes_ris", "v6_prefixes_ris", "asns_ris"):
        roll = rng.random()
        if roll < 0.15:
            continue                                   # absent
        elif roll < 0.25:
            entry[key] = -1                            # sentinel
        elif roll < 0.45:
            # The shapes that separate two transcriptions of one rule: a
            # numeric STRING is the one that found a real divergence
            # (production refused it, v3's `as_float` coerced it), and it
            # was invisible until the generator produced one.
            entry[key] = rng.choice(
                [None, "", "n/a", True, False, "9601", "9601.5", "-1",
                 float("nan"), float("inf"), [], {}])
        else:
            entry[key] = round(rng.uniform(0, 20000), 1)
    for key in ("v4_prefixes_stats", "v6_prefixes_stats", "asns_stats"):
        entry[key] = rng.choice([-1, -1, round(rng.uniform(0, 20000))])
    if rng.random() < 0.3:
        entry["announced_prefixes"] = round(rng.uniform(0, 20000))
        entry["seen_ases"] = round(rng.uniform(0, 500))
    return entry


class TestTheTwoCopiesAgree:
    """Neither system may import the other, so the rule exists twice.

    A sweep is the only thing that keeps two transcriptions of one rule
    from becoming two rules — and a second H-05 would be exactly that.
    """

    @pytest.mark.parametrize("seed", [11, 2027, 90210])
    def test_a_sweep_finds_no_disagreement(self, seed):
        rng = random.Random(seed)
        for _ in range(4000):
            entry = _generated_entry(rng)
            assert production.prefix_count(entry) == v3_adapter.prefix_count(
                entry), entry
            assert production.as_count(entry) == v3_adapter.as_count(
                entry), entry

    def test_the_declared_window_is_the_same_number(self):
        assert (production.STATS_WINDOW_DAYS
                == v3_adapter.STATS_WINDOW_DAYS)
        assert (v3_adapter.LOOKBACK_SEC
                == production.STATS_WINDOW_SEC)

    def test_the_expected_resolution_is_the_same_string(self):
        assert (production.EXPECTED_RESOLUTION
                == v3_adapter.EXPECTED_RESOLUTION == "1h")


#: Plausible transcription slips, applied to v3's constants. The sweep
#: above must catch every one, or it is decorative.
MUTANTS = {
    "v4_only": ("RIS_PREFIX_KEYS", ("v4_prefixes_ris",)),
    "v6_only": ("RIS_PREFIX_KEYS", ("v6_prefixes_ris",)),
    "stats_variant": ("RIS_PREFIX_KEYS", ("v4_prefixes_stats",
                                          "v6_prefixes_stats")),
    "legacy_key": ("RIS_PREFIX_KEYS", ("announced_prefixes",)),
    "reversed_order_with_extra": ("RIS_PREFIX_KEYS",
                                  ("v6_prefixes_ris", "v4_prefixes_ris",
                                   "asns_ris")),
    "asn_stats_variant": ("RIS_ASN_KEY", "asns_stats"),
    "asn_legacy_key": ("RIS_ASN_KEY", "seen_ases"),
}


class TestTheMutantsAreCaught:
    @pytest.mark.parametrize("name", sorted(MUTANTS))
    def test_a_mutated_constant_disagrees_with_production(self, name,
                                                          monkeypatch):
        attribute, value = MUTANTS[name]
        monkeypatch.setattr(v3_adapter, attribute, value)
        rng = random.Random(4242)
        for _ in range(4000):
            entry = _generated_entry(rng)
            if (production.prefix_count(entry) != v3_adapter.prefix_count(
                    entry) or production.as_count(entry)
                    != v3_adapter.as_count(entry)):
                return
        pytest.fail(f"mutant {name!r} was never caught: the sweep does not "
                    f"constrain {attribute}")


# ── 3. the request has to come back hourly ──────────────────────────────

class TestTheRequestAsksForAnHourlyResolution:
    """Without a `starttime` RIPE answers `resolution: 1w`.

    `stats[-1]` would then be a weekly figure up to six days stale, and
    an hourly `bgp_hod` bucket filled from it holds the same number for
    ~168 buckets — standard deviation 0, floored to 1.0 — before stepping
    by whatever the week moved. The Z reads that step as a hundred sigma.
    """

    def test_production_sends_a_starttime(self):
        source = (REPO / "radar" / "sensors" / "bgp_routing.py").read_text()
        assert '"starttime": _starttime' in source

    def test_the_window_start_is_the_declared_lookback(self):
        now = 1_786_000_000.0
        assert production.window_start_iso(now) == "2026-08-02T07:06:40Z"

    def test_v3_declares_the_placeholder(self):
        params = dict(v3_adapter.RIPE_BGP_ADAPTER.requests[0].params)
        assert params["starttime"] == "{since_iso}"

    def test_the_composition_root_supplies_it(self):
        """A placeholder nothing fills is `UNRESOLVED` — the adapter is
        skipped and the cycle records an input-health failure."""
        windows = expansion._time_windows(1_786_000_000.0)
        assert windows["ripe_bgp"] == {"since_iso": "2026-08-02T07:06:40Z"}

    def test_the_supplied_lookback_is_the_adapters_own_constant(self):
        assert (expansion.RIPE_BGP_LOOKBACK_SEC
                == v3_adapter.LOOKBACK_SEC)


class TestANonHourlyAnswerCannotPoisonTheHourlySeries:
    """The guard that catches losing our own `starttime`.

    Without it RIPE answers `1w`; 672 buckets of one weekly figure
    followed by a step is a hundred-sigma Z on a network that did
    nothing. Both systems disclose the reading and withhold the sample.
    """

    BODY = {"data": {"resource": "TW", "resolution": "1w", "stats": [
        {"v4_prefixes_ris": 9607, "v6_prefixes_ris": 1206, "asns_ris": 242,
         "stats_date": "2026-08-03T00:00:00"}]}}

    def _draft(self, resolution):
        from tests.test_adapters_cyber_fidelity import context, synthetic
        body = json.loads(json.dumps(self.BODY))
        body["data"]["resolution"] = resolution
        return v3_adapter.normalize(
            synthetic(json.dumps(body).encode()), context("ripe_bgp"))[0]

    def test_v3_withholds_the_sample_and_names_the_silence(self):
        draft = self._draft("1w")
        assert "announced_prefixes" not in draft.flags
        assert draft.flags["hod_verdict"] == v3_adapter.PENDING_RESOLUTION
        assert draft.flags["resolution"] == "1w"

    def test_v3_still_discloses_the_measurement(self):
        """Withheld from the SERIES, not hidden from the analyst."""
        draft = self._draft("1w")
        assert draft.flags["prefixes_measured"] == 9607 + 1206
        assert draft.flags["v4_prefixes"] == 9607

    def test_nothing_can_record_the_withheld_sample(self):
        """`record_phase_samples` keys on the flag the guard removes, so
        the write stops without a branch anyone has to remember."""
        from v3.runtime import record
        assert record.PHASE_SAMPLES["bgp_hod"][2] == "announced_prefixes"
        assert "announced_prefixes" not in self._draft("1d").flags

    def test_an_hourly_answer_is_unaffected(self):
        draft = self._draft("1h")
        assert draft.flags["announced_prefixes"] == 9607 + 1206
        assert draft.flags["hod_verdict"] == v3_adapter.PENDING_HOD

    def test_production_returns_stale_resolution_before_it_records(self):
        """Production reaches the same place by an early return: the
        record-and-score block is below it."""
        source = (REPO / "radar" / "sensors" / "bgp_routing.py").read_text()
        stale = source.index('"status": "STALE_RESOLUTION"')
        records = source.index('_db.hod_record("bgp_hod"')
        assert stale < records
        assert 'if _resolution != EXPECTED_RESOLUTION:' in source


# ── 4. the trend was dead too ───────────────────────────────────────────

class TestTheTrendReadsTheRepairedQuantity:
    def test_a_real_series_no_longer_regresses_over_zeros(self):
        stats = _load("country_routing_stats.json")["data"]["stats"]
        trend = production.BgpRoutingSensor._compute_trend(stats)
        assert trend["trend_entries"] == len(stats)
        assert trend["prefix_trend"] != 0.0

    def test_an_entry_with_no_ris_view_is_dropped_not_zeroed(self):
        """One fabricated zero drags a slope to WITHDRAWING and reports an
        outage nobody observed."""
        good = [{"v4_prefixes_ris": 1000 + 100 * i, "v6_prefixes_ris": 0,
                 "asns_ris": 10} for i in range(6)]
        trend = production.BgpRoutingSensor._compute_trend(
            good + [{"stats_date": "x"}])
        assert trend["trend_entries"] == 6
        assert trend["trend_label"] == "GROWING"
        zeroed = production.BgpRoutingSensor._compute_trend(
            good + [{"v4_prefixes_ris": 0, "v6_prefixes_ris": 0}])
        assert zeroed["trend_label"] == "WITHDRAWING"

    def test_too_few_usable_entries_is_insufficient_not_stable(self):
        trend = production.BgpRoutingSensor._compute_trend(
            [{"stats_date": "x"}, {"v4_prefixes_ris": 5}])
        assert trend["trend_label"] == "INSUFFICIENT_DATA"

    def test_v3_carries_only_usable_entries_in_the_series(self):
        from tests.test_adapters_cyber_fidelity import context, synthetic
        body = json.dumps({"data": {"resource": "TW", "resolution": "1h",
                                    "stats": [{"v4_prefixes_ris": 10},
                                              {"stats_date": "x"},
                                              {"v4_prefixes_ris": 12}]}}
                          ).encode()
        draft = v3_adapter.normalize(synthetic(body), context("ripe_bgp"))[0]
        assert draft.flags["prefix_series"] == [10.0, 12.0]


# ── 5. the backfill expands run-length encoding ─────────────────────────

class TestTheBackfillExpandsTheTimeline:
    """One `stats` entry is one VALUE, not one point in time.

    `timeline` lists every interval that value held over — an entry
    spanning 06:00-07:00, 09:00 and 13:00-14:00 is five hours of history.
    A reader that takes `timeline[0].starttime` gets one of the five and
    files the value under the wrong hour for the other four, which for an
    hour-of-day baseline means the bucket does not measure its own hour.
    """

    def test_a_real_day_expands_to_twenty_four_gapless_hours(self):
        samples = backfill.expand_timeline(
            _load("country_routing_stats_rle_day.json")["data"])
        assert len(samples) == 24
        buckets = sorted(samples)
        assert buckets[-1] - buckets[0] == 23 * HOUR
        assert all(b - a == HOUR
                   for a, b in zip(buckets, buckets[1:]))

    def test_every_hour_of_day_appears_exactly_once(self):
        samples = backfill.expand_timeline(
            _load("country_routing_stats_rle_day.json")["data"])
        hours = sorted((bucket // HOUR) % 24 for bucket in samples)
        assert hours == list(range(24))

    def test_a_later_interval_of_one_entry_is_not_filed_under_the_first(self):
        """The failure the expansion exists to prevent, stated as a case."""
        data = {"stats": [
            {"v4_prefixes_ris": 100, "v6_prefixes_ris": 0,
             "timeline": [{"starttime": "2026-08-01T06:00:00",
                           "endtime": "2026-08-01T07:00:00"},
                          {"starttime": "2026-08-01T13:00:00",
                           "endtime": "2026-08-01T14:00:00"}]}]}
        samples = backfill.expand_timeline(data)
        hours = sorted((bucket // HOUR) % 24 for bucket in samples)
        assert hours == [6, 7, 13, 14]

    def test_an_entry_with_no_ris_view_contributes_no_sample(self):
        data = {"stats": [{"stats_date": "x", "timeline": [
            {"starttime": "2026-08-01T06:00:00",
             "endtime": "2026-08-01T06:00:00"}]}]}
        assert backfill.expand_timeline(data) == {}

    def test_the_expanded_value_is_the_repaired_quantity(self):
        samples = backfill.expand_timeline(
            _load("country_routing_stats_rle_day.json")["data"])
        entry = _load("country_routing_stats_rle_day.json"
                      )["data"]["stats"][0]
        first = min(samples)
        assert samples[first] == production.prefix_count(entry)


# ── 6. the epoch ────────────────────────────────────────────────────────

def _ledger(tmp_path, rows=()) -> sqlite3.Connection:
    connection = sqlite3.connect(str(tmp_path / "radar.db"))
    connection.execute(
        "CREATE TABLE bgp_hod (theater TEXT NOT NULL, "
        "hour_bucket INTEGER NOT NULL, prefix_count REAL NOT NULL, "
        "PRIMARY KEY (theater, hour_bucket))")
    connection.executemany(
        "INSERT INTO bgp_hod VALUES (?,?,?)", rows)
    connection.commit()
    return connection


BASE = 1_786_000_000 // HOUR * HOUR


class TestTheDeadEpochIsNotMergedWithRealValues:
    def test_the_zero_rows_are_removed(self, tmp_path):
        dead = [("TW", BASE - n * HOUR, 0.0) for n in range(1, 30)]
        connection = _ledger(tmp_path, dead)
        try:
            report = backfill.write_country(
                connection, "TW",
                {BASE - n * HOUR: 10800.0 for n in range(1, 10)})
            assert report["zero_rows_deleted"] == 29
            remaining = connection.execute(
                "SELECT COUNT(*) FROM bgp_hod WHERE prefix_count = 0.0"
            ).fetchone()[0]
            assert remaining == 0
        finally:
            connection.close()

    def test_surviving_zeros_silence_the_repaired_detector(self):
        """Why the epoch and the key fix are ONE change — measured.

        The direction is worth stating precisely, because it is not the
        one the shape suggests: merging the dead zeros does NOT fire a
        false positive. It drags the pooled mean BELOW every real
        reading, so a genuine withdrawal scores a large POSITIVE Z and
        the verdict goes quiet. Insensitive, which is the direction NP1
        exists to refuse, and invisible from the outside because the row
        keeps reporting NORMAL.
        """
        from v3.runtime import verdicts
        real = tuple([10800.0] * 28)
        withdrawal = 8640.0                       # a genuine -20%
        assert verdicts.bgp_is_anomaly(
            verdicts.bgp_hod_verdict(real, withdrawal)) is True
        merged = real + tuple([0.0] * 28)
        stat = verdicts.bgp_hod_verdict(merged, withdrawal)
        assert stat.valid is True and stat.z > 0
        assert verdicts.bgp_is_anomaly(stat) is False

    def test_the_ledger_as_found_could_not_fire_at_all(self):
        """5,398 rows of 0.0 — the state this repair starts from."""
        from v3.runtime import verdicts
        zeros = tuple([0.0] * 28)
        stat = verdicts.bgp_hod_verdict(zeros, 10800.0)
        assert stat.valid is True and verdicts.bgp_is_anomaly(stat) is False
        warmup = verdicts.bgp_warmup_verdict(zeros, 10800.0)
        assert warmup.valid is True and warmup.anomaly is False
        assert warmup.drop_ratio is None

    def test_real_rows_outside_the_backfilled_window_are_kept(self, tmp_path):
        live = [("TW", BASE + HOUR, 11000.0)]
        connection = _ledger(tmp_path, live)
        try:
            backfill.write_country(connection, "TW",
                                   {BASE - HOUR: 10800.0})
            kept = connection.execute(
                "SELECT prefix_count FROM bgp_hod WHERE hour_bucket = ?",
                (BASE + HOUR,)).fetchone()
            assert kept[0] == 11000.0
        finally:
            connection.close()

    def test_the_window_cap_is_productions_bucket_count(self, tmp_path):
        connection = _ledger(tmp_path)
        try:
            backfill.write_country(
                connection, "TW",
                {BASE - n * HOUR: 10800.0 + n for n in range(1, 900)})
            assert connection.execute(
                "SELECT COUNT(*) FROM bgp_hod").fetchone()[0] == \
                backfill.HOD_MAX_ENTRIES
        finally:
            connection.close()

    def test_the_cap_is_productions_own_number(self):
        assert backfill.HOD_MAX_ENTRIES == 672
        assert backfill.HOD_MIN_SAME_HOUR == v3_adapter.HOD_MIN_SAME_HOUR


class TestAnAllZeroSeriesIsRefused:
    """K02 meets H-05: `resource=ZZ` answers HTTP 200, `status: ok`,
    `resolution: 1h`, and `v4_prefixes_ris: 0` for every hour (measured).

    A typo in `--countries` would otherwise install 672 fabricated zeros
    — the exact state this script exists to remove — and the resulting
    baseline is indistinguishable from a calm world.
    """

    def test_the_refusal_exists_and_names_the_cause(self):
        assert issubclass(backfill.AllZeroSeries, backfill.BackfillError)
        source = (REPO / "scripts" / "backfill_bgp_hod.py").read_text()
        assert "if not any(samples.values()):" in source

    def test_an_unknown_code_answers_with_zeros_not_an_error(self):
        """The upstream behaviour, pinned as a fixture-free fact: the
        expansion of RIPE's ZZ answer is all zeros and nothing about the
        response says it was rejected."""
        data = {"resolution": "1h", "stats": [
            {"v4_prefixes_ris": 0, "v6_prefixes_ris": 0, "asns_ris": 0,
             "v4_prefixes_stats": -1, "asns_stats": 0,
             "timeline": [{"starttime": "2026-08-07T00:00:00",
                           "endtime": "2026-08-07T23:00:00"}]}]}
        samples = backfill.expand_timeline(data)
        assert len(samples) == 24
        assert set(samples.values()) == {0.0}
        assert not any(samples.values())

    def test_a_single_real_sample_is_enough_to_pass(self):
        """Not "no zeros allowed" — KP legitimately reports 3 or 4."""
        assert any({0: 0.0, 3600: 3.0}.values())


class TestTheBackfillIsIdempotent:
    def test_a_second_run_changes_nothing(self, tmp_path):
        connection = _ledger(
            tmp_path, [("TW", BASE - n * HOUR, 0.0) for n in range(1, 5)])
        try:
            samples = {BASE - n * HOUR: 10800.0 + n for n in range(1, 40)}
            backfill.write_country(connection, "TW", samples)
            first = connection.execute(
                "SELECT theater, hour_bucket, prefix_count FROM bgp_hod "
                "ORDER BY hour_bucket").fetchall()
            backfill.write_country(connection, "TW", samples)
            second = connection.execute(
                "SELECT theater, hour_bucket, prefix_count FROM bgp_hod "
                "ORDER BY hour_bucket").fetchall()
            assert first == second
        finally:
            connection.close()


class TestTheWarmPredicateIsNotBypassed:
    def test_a_short_bucket_is_reported_short(self, tmp_path):
        """Requirement 3: the report must not claim a bucket is warm."""
        rows = [("TW", BASE - day * 24 * HOUR, 10800.0)
                for day in range(1, 4)]          # 3 samples, one hour only
        connection = _ledger(tmp_path, rows)
        try:
            stats = backfill.bucket_distribution(connection, "TW")
            assert stats["warm_buckets"] == 0
            assert stats["cold_buckets"] == 24
            assert stats["max_samples"] == 3
        finally:
            connection.close()

    def test_a_bucket_reaching_the_minimum_is_reported_warm(self, tmp_path):
        rows = [("TW", BASE - day * 24 * HOUR, 10800.0)
                for day in range(1, 1 + backfill.HOD_MIN_SAME_HOUR)]
        connection = _ledger(tmp_path, rows)
        try:
            stats = backfill.bucket_distribution(connection, "TW")
            assert stats["warm_buckets"] == 1
            assert stats["cold_buckets"] == 23
        finally:
            connection.close()


# ── 7. the contract is enforced when the script runs, not only in a test ─

class TestTheQuantityContractIsEnforcedAtRunTime:
    def test_it_passes_as_the_tree_stands(self):
        backfill._assert_quantity_agrees()

    def test_it_refuses_when_the_two_sides_name_different_fields(
            self, monkeypatch):
        monkeypatch.setattr(backfill, "RIS_PREFIX_KEYS",
                            ("v4_prefixes_stats",))
        with pytest.raises(backfill.BackfillError, match="H-05"):
            backfill._assert_quantity_agrees()

    def test_it_reads_production_without_importing_it(self):
        """`radar/__init__.py` builds a Flask app and starts worker threads
        at import; a backfill that boots the application is a backfill that
        writes through a second, live connection."""
        source = (REPO / "scripts" / "backfill_bgp_hod.py").read_text()
        assert "import radar" not in source
        assert "from radar" not in source
        assert backfill._production_constants()["RIS_ASN_KEY"] == "asns_ris"

    def test_the_current_hour_is_left_to_the_live_sensor(self):
        source = (REPO / "scripts" / "backfill_bgp_hod.py").read_text()
        assert "since <= bucket < until" in source
