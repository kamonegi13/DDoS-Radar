"""WP-4.1b — the baselines are supplied, and the verdicts they gated fire.

Three obligations:

  naming      the adapters' `baseline_refs` and the migrated `baseline_id`s
              are DIFFERENT strings for two of the four phase baselines.
              That is how `cf_attack_share_baseline` could sit beside a
              populated `hod` series and look like an empty baseline. The
              mapping is pinned against the ETL's own table rather than
              restated, so a rename breaks a build instead of orphaning a
              baseline in silence.
  account     every declared baseline is answered, withheld with a reason,
              or unanswerable with a reason. "No supply wired" is never an
              acceptable entry.
  verdicts    §7-2 #9 is about SCORES, not storage. Each baseline that
              became live is checked by making its consumer produce the
              score production produces.
"""
import ast
import math
import pathlib
import random

import pytest

from v3.adapters.catalog import build_registry
from v3.adapters.types import (INFO, PHYSICAL, CYBER, STATUS_FIRED,
                               STATUS_OBSERVED, STATUS_OK, ObservationDraft)
from v3.etl.mapping import MIGRATABLE
from v3.ledger import LedgerStore
from v3.runtime import baselines, record, reduce as R, verdicts

NOW = 1_786_000_000.0
HOUR = 3600.0
DAY = 86400.0
REPO = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "supply.db"))
    yield instance
    instance.close()


def _seed_phase(store, baseline, *, country, values, now=NOW):
    """`len(values)` same-phase buckets, one per period, ending before now."""
    base = baseline.bucket_of(now)
    for index, value in enumerate(values, start=1):
        store.upsert_baseline_value(
            baseline_id=baseline.baseline_id, sensor=baseline.sensor,
            country=country, bucket=base - index * baseline.divisor
            * baseline.modulus, value=float(value), now=now)


# ── naming ──────────────────────────────────────────────────────────────

class TestTheNamesAreReconciled:
    def test_every_migrated_phase_baseline_matches_the_etl(self):
        """The ETL is the authority on what was actually written."""
        for ref, baseline in baselines.PHASE_BASELINES.items():
            if baseline.migrated_from is None:
                continue
            mapping = MIGRATABLE[baseline.migrated_from]
            assert mapping.target == "baseline", ref
            assert mapping.baseline_id == baseline.baseline_id, ref
            # The ETL writes `sensor = source_table` (`etl/migrate.py:183`).
            assert mapping.source_table == baseline.sensor, ref

    def test_the_two_names_that_differ_are_the_ones_recorded(self):
        """Stated as data so the next reader does not have to notice it."""
        differing = {ref for ref, b in baselines.PHASE_BASELINES.items()
                     if ref != b.baseline_id}
        assert differing == {"gdelt_dow_tone", "cf_attack_share_baseline"}

    def test_the_etl_writes_sensor_from_the_source_table(self):
        """Pinned by AST, because the mapping above is only true while
        that line says what it says."""
        source = (REPO / "v3" / "etl" / "migrate.py").read_text()
        tree = ast.parse(source)
        found = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", "")
            if name != "upsert_baseline_value":
                continue
            for keyword in node.keywords:
                if keyword.arg == "sensor":
                    assert ast.unparse(keyword.value) == \
                        "mapping.source_table"
                    found = True
        assert found, "the ETL no longer writes baselines through this call"

    def test_no_declared_baseline_is_missing_from_every_register(self):
        registry = build_registry()
        declared = set(baselines.declared_names(registry.all()))
        accounted = (baselines.supplied_names()
                     | set(baselines.UNANSWERABLE)
                     | set(baselines.VERDICT_WITHHELD))
        assert declared <= accounted

    def test_no_register_entry_is_for_a_baseline_nobody_declares(self):
        """The other direction: a supply wired for a name no adapter uses
        is a baseline that will never be read, and it looks identical to
        one that is."""
        registry = build_registry()
        declared = set(baselines.declared_names(registry.all()))
        for name in baselines.supplied_names():
            assert name in declared, name


# ── the account ─────────────────────────────────────────────────────────

class TestTheAccountIsStillHonest:
    def test_every_unanswered_baseline_has_a_measured_reason(self):
        report = baselines.coverage(build_registry().all())
        for name in report["unanswered"]:
            assert report["reasons"][name] != "no supply wired", name
            assert len(report["reasons"][name]) > 40, name

    def test_a_readable_baseline_whose_consumer_still_withholds_counts_as_unanswered(
            self):
        """§7-2 #9's condition is the SCORE, and the separation survives
        its last occupant.

        `cf_attack_share_baseline` sat in `withheld` for a phase: its rows
        were readable while the quantity they judge was neither computed
        nor fetched. WP-4.1d closed it, so the mapping is empty — but the
        DISTINCTION is what the entry turns on, and a `coverage()` that
        counted storage as an answer would retire a family half-wired.
        A withheld baseline must never be reported as answered.
        """
        report = baselines.coverage(build_registry().all())
        assert baselines.VERDICT_WITHHELD == {}
        assert report["withheld"] == {}
        assert set(report["withheld"]) & set(report["answered"]) == set()
        assert set(report["withheld"]) <= set(report["unanswered"])

    def test_the_baselines_that_went_live_are_answered(self):
        report = baselines.coverage(build_registry().all())
        assert {"bgp_hod", "checkhost_hod", "gdelt_dow_tone",
                "ct_log_known_ca_per_domain", "ct_log_domain_first_observed",
                "checkhost_latency_history", "ais_vessel_history"} <= set(
                    report["answered"])


# ── the shared statistic, swept against production's arithmetic ─────────

def _production_hod_zscore(values, current, min_samples, std_floor):
    """`radar/scoring.py:484-497`, transcribed line for line."""
    n = len(values)
    if n < min_samples:
        return 0.0, False, n
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std = variance ** 0.5
    std = max(std, std_floor)
    return (current - mean) / std, True, n


class TestTheStatisticMatchesProduction:
    @pytest.mark.parametrize("floor,minimum", [(0.15, 7), (0.05, 7),
                                               (1.0, 7), (0.5, 3)])
    def test_a_random_sweep_agrees_on_every_input(self, floor, minimum):
        rng = random.Random(20260808)
        disagreements = []
        for _ in range(20000):
            n = rng.randint(0, 30)
            values = [rng.uniform(-50, 5000) for _ in range(n)]
            current = rng.uniform(-50, 5000)
            mine = verdicts.phase_zscore(values, current,
                                         min_samples=minimum,
                                         std_floor=floor)
            z, valid, count = _production_hod_zscore(values, current,
                                                     minimum, floor)
            if mine.valid != valid or mine.n != count:
                disagreements.append((values, current))
                continue
            if valid and not math.isclose(mine.z, z, rel_tol=1e-12,
                                          abs_tol=1e-12):
                disagreements.append((values, current))
        assert not disagreements, disagreements[:3]

    def test_the_variance_is_the_population_one(self):
        """n-1 would shrink every Z and make every threshold harder to
        reach — the insensitive direction C-02/C-03 treat as blocking."""
        values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]
        stat = verdicts.phase_zscore(values, 4.0, min_samples=7,
                                     std_floor=0.0)
        assert math.isclose(stat.z, 0.0, abs_tol=1e-12)
        stat = verdicts.phase_zscore(values, 0.0, min_samples=7,
                                     std_floor=0.0)
        assert math.isclose(stat.z, -4.0 / 2.0, rel_tol=1e-12)

    def test_warmup_returns_no_z_rather_than_zero(self):
        stat = verdicts.phase_zscore([1.0, 2.0], 99.0, min_samples=7,
                                     std_floor=0.15)
        assert stat.valid is False and stat.z is None and stat.n == 2


# ── the verdicts that went live ─────────────────────────────────────────

def _bgp_draft(country="TW", prefixes=1000):
    return ObservationDraft(
        signal_source="bgp", domain=CYBER, country=country,
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"prefixes={prefixes}",
        flags={"announced_prefixes": prefixes,
               "hod_verdict": "pending_l1_bgp_hod"})


def _R(adapter_id, drafts, history):
    return R.reduce_drafts(adapter_id, drafts, baselines=history, now=NOW)


class TestRipeBgpNowScores:
    def test_a_collapse_against_the_same_hour_history_fires_at_one(self):
        history = {"bgp_hod": {"TW": tuple([1000.0] * 10)}}
        out = R.reduce_drafts("ripe_bgp", [_bgp_draft(prefixes=100)],
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_FIRED
        assert out[0].raw_score == verdicts.BGP_ANOMALY_SCORE
        assert out[0].value == "ANOMALY"
        assert "hod_verdict" not in out[0].flags

    def test_a_normal_reading_is_ok_and_no_longer_observed(self):
        history = {"bgp_hod": {"TW": tuple([1000.0 + i for i in range(10)])}}
        out = R.reduce_drafts("ripe_bgp", [_bgp_draft(prefixes=1005)],
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_OK and out[0].raw_score == 0.0

    def test_the_standard_deviation_floor_is_one_prefix(self):
        """A country whose prefix count never moves has std 0; without the
        floor the first change is an infinite Z."""
        history = {"bgp_hod": {"TW": tuple([1000.0] * 10)}}
        out = R.reduce_drafts("ripe_bgp", [_bgp_draft(prefixes=999)],
                              baselines=history, now=NOW)
        assert out[0].flags["hod_z"] == -1.0
        assert out[0].status == STATUS_OK

    def test_the_anomaly_threshold_is_two_sigma_not_three(self):
        """A boundary case, because a ladder is only pinned at its edge:
        z = -2.5 fires at production's -2.0 and would not at -3.0."""
        history = {"bgp_hod": {"TW": tuple([990.0, 1010.0] * 5)}}
        out = _R("ripe_bgp", [_bgp_draft(prefixes=975)], history)
        assert out[0].flags["hod_z"] == -2.5
        assert out[0].status == STATUS_FIRED

    def test_below_seven_samples_the_verdict_is_still_withheld(self):
        """Production's warm-up branch uses an in-process hourly baseline
        v3 does not have; withholding is visible, inventing is not."""
        history = {"bgp_hod": {"TW": (1000.0, 1000.0)}}
        out = R.reduce_drafts("ripe_bgp", [_bgp_draft(prefixes=1)],
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_OBSERVED
        assert out[0].flags["hod_verdict"].startswith("pending_l1_")


def _check_host_drafts(country="TW", rates=(1.0, 1.0, 1.0), latency=100.0):
    return [ObservationDraft(
        signal_source="check_host", domain=PHYSICAL, country=country,
        status=STATUS_OBSERVED, raw_score=0.0, value=f"success={rate:.0%}",
        flags={"success_rate": rate, "avg_latency_ms": latency,
               "url": f"https://site{index}.tw",
               "ok_nodes": 5, "total_nodes": 5,
               "asphyxiation_verdict": "pending_l1_latency_history"})
        for index, rate in enumerate(rates)]


class TestCheckHostNowScores:
    def test_a_blackout_scores_three(self):
        history = {"checkhost_hod": {"TW": tuple([1.0] * 10)}}
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(rates=(0.0, 0.0, 0.0)),
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_FIRED and out[0].raw_score == 3.0
        assert out[0].flags["status"] == "BLACKOUT"

    def test_a_partial_is_capped_at_one(self):
        history = {"checkhost_hod": {"TW": tuple([1.0] * 10)}}
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(rates=(1.0, 0.0, 0.0)),
                              baselines=history, now=NOW)
        assert out[0].raw_score == 1.0
        assert out[0].flags["status"] == "PARTIAL"

    def test_an_anomalous_but_high_rate_stays_ok(self):
        """The Z branch ANDs an absolute rate; without it a maintenance
        window at an always-perfect hour becomes an outage."""
        history = {"checkhost_hod": {"TW": tuple([1.0] * 10)}}
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(rates=(1.0, 1.0, 0.9)),
                              baselines=history, now=NOW)
        assert out[0].flags["status"] == "OK" and out[0].raw_score == 0.0

    def test_warmup_uses_the_absolute_thresholds_rather_than_withholding(
            self):
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(rates=(0.0, 0.0, 0.0)),
                              baselines={"checkhost_hod": {"TW": ()}},
                              now=NOW)
        assert out[0].flags["status"] == "BLACKOUT"
        assert out[0].flags["hod_n"] == 0

    def test_the_partial_threshold_is_two_sigma(self):
        """z = -3.33 with a rate of 33% is PARTIAL, not BLACKOUT (the
        absolute rate is above 30%) and not OK (z is past -2)."""
        history = {"checkhost_hod": {"TW": tuple([0.8, 1.2] * 5)}}
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(rates=(1.0, 0.0, 0.0)),
                              baselines=history, now=NOW)
        assert out[0].flags["status"] == "PARTIAL"

    def test_blackout_needs_three_sigma_as_well_as_a_low_rate(self):
        """z = -2.5 at 0% is PARTIAL: the BLACKOUT rung wants -3."""
        history = {"checkhost_hod": {"TW": tuple([0.6, 1.4] * 5)}}
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(rates=(0.0, 0.0, 0.0)),
                              baselines=history, now=NOW)
        assert out[0].flags["hod_z"] == -2.5
        assert out[0].flags["status"] == "PARTIAL"

    def test_a_rate_at_the_partial_cutoff_is_not_partial(self):
        """`success_rate < 0.8`, strictly. At exactly 80% the country is
        OK however anomalous the hour makes it look."""
        history = {"checkhost_hod": {"TW": tuple([1.0] * 10)}}
        out = R.reduce_drafts(
            "check_host",
            _check_host_drafts(rates=(1.0, 1.0, 1.0, 1.0, 0.0)),
            baselines=history, now=NOW)
        assert out[0].flags["success_rate"] == 0.8
        assert out[0].flags["status"] == "OK"

    def test_five_samples_are_not_seven_and_the_answer_differs(self):
        """A country whose success rate is normally 20% makes 33% look
        healthy in Z terms. Production does not believe a five-sample
        baseline: below seven it uses the absolute thresholds, and 33% is
        PARTIAL there. Lowering the minimum would report OK."""
        history = {"checkhost_hod": {"TW": tuple([0.2] * 5)}}
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(rates=(1.0, 0.0, 0.0)),
                              baselines=history, now=NOW)
        assert out[0].flags["hod_n"] == 5
        assert out[0].flags["status"] == "PARTIAL"

    def test_asphyxiation_is_decided_per_url_and_or_ed(self):
        history = {"checkhost_hod": {"TW": ()},
                   "checkhost_latency_history": {
                       "https://site0.tw": [{"value": 10.0},
                                            {"value": 10.0},
                                            {"value": 10.0}]}}
        drafts = _check_host_drafts(rates=(1.0, 1.0, 1.0), latency=500.0)
        out = R.reduce_drafts("check_host", drafts, baselines=history,
                              now=NOW)
        assert out[0].flags["asphyxiation"] is True
        assert "asphyxiation_verdict" not in out[0].flags

    def test_two_samples_are_not_a_baseline(self):
        history = {"checkhost_hod": {"TW": ()},
                   "checkhost_latency_history": {
                       "https://site0.tw": [{"value": 10.0},
                                            {"value": 10.0}]}}
        out = R.reduce_drafts("check_host",
                              _check_host_drafts(latency=500.0),
                              baselines=history, now=NOW)
        assert out[0].flags["asphyxiation"] is False


class TestGdeltNowDecidesTheDayOfWeekArm:
    def _draft(self, tone=-2.0, status=STATUS_OBSERVED):
        return ObservationDraft(
            signal_source="gdelt", domain=INFO, country="TW",
            status=status, raw_score=0.0, value=f"tone={tone:.3f}",
            flags={"tone": tone, "dow_verdict": "pending_l1_dow_baseline"})

    def test_an_anomalous_weekday_tone_fires(self):
        history = {"gdelt_dow_tone": {"TW": (1.0, 1.0, 1.0, 1.0)}}
        out = R.reduce_drafts("gdelt", [self._draft(tone=-5.0)],
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_FIRED and out[0].raw_score == 1.0
        assert out[0].flags["is_alert"] is True
        assert "dow_verdict" not in out[0].flags

    def test_a_normal_weekday_tone_is_ok_not_observed(self):
        history = {"gdelt_dow_tone": {"TW": (1.0, 1.0, 1.0, 1.0)}}
        out = R.reduce_drafts("gdelt", [self._draft(tone=1.1)],
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_OK
        assert out[0].flags["status"] == "NORMAL"

    def test_a_row_that_already_fired_is_not_re_decided(self):
        """`is_alert` is an OR and the fixed arm fires in the adapter;
        re-deciding could only ever turn a firing off."""
        history = {"gdelt_dow_tone": {"TW": (1.0, 1.0, 1.0, 1.0)}}
        out = R.reduce_drafts("gdelt",
                              [self._draft(tone=1.1, status=STATUS_FIRED)],
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_FIRED

    def test_the_alert_threshold_is_two_sigma(self):
        history = {"gdelt_dow_tone": {"TW": (0.5, 1.5, 0.5, 1.5)}}
        out = R.reduce_drafts("gdelt", [self._draft(tone=-0.25)],
                              baselines=history, now=NOW)
        assert out[0].flags["dow_z"] == -2.5
        assert out[0].status == STATUS_FIRED

    def test_a_tone_just_inside_two_sigma_does_not_alert(self):
        history = {"gdelt_dow_tone": {"TW": (0.5, 1.5, 0.5, 1.5)}}
        out = R.reduce_drafts("gdelt", [self._draft(tone=0.05)],
                              baselines=history, now=NOW)
        assert out[0].flags["dow_z"] == -1.9
        assert out[0].status == STATUS_OK

    def test_the_half_point_floor_keeps_a_flat_baseline_from_exploding(
            self):
        """Four identical tones have std 0; without the 0.5 floor the
        next reading is an unbounded Z and every day is an alert."""
        history = {"gdelt_dow_tone": {"TW": (1.0, 1.0, 1.0, 1.0)}}
        out = R.reduce_drafts("gdelt", [self._draft(tone=0.0)],
                              baselines=history, now=NOW)
        assert out[0].flags["dow_z"] == -2.0
        assert out[0].status == STATUS_OK

    def test_below_three_samples_the_fixed_arm_alone_decides(self):
        history = {"gdelt_dow_tone": {"TW": (1.0, 1.0)}}
        out = R.reduce_drafts("gdelt", [self._draft(tone=-5.0)],
                              baselines=history, now=NOW)
        assert out[0].status == STATUS_OK
        assert out[0].flags["dow_n"] == 2


class TestCtLogNowReachesScoreThree:
    def _draft(self, candidates=(), wildcard=0):
        return ObservationDraft(
            signal_source="ct_log", domain=CYBER, country="TW",
            status=STATUS_FIRED if wildcard else STATUS_OBSERVED,
            raw_score=2.0 if wildcard else 0.0, value="",
            flags={"watched_domains": ["gov.tw"],
                   "untrusted_ca_candidates": list(candidates),
                   "untrusted_ca_candidate_count": len(candidates),
                   "wildcard_count": wildcard,
                   "untrusted_ca_verdict": "pending_l1_known_ca_ledger",
                   "warmup_verdict": "pending_l1_domain_first_observed"})

    def _supply(self, first_seen=NOW - 30 * DAY, known=()):
        return {"ct_log_known_ca_per_domain": {"gov.tw": tuple(known)},
                "ct_log_domain_first_observed": {"gov.tw": first_seen}}

    def test_an_unknown_ca_out_of_warmup_scores_three(self):
        candidate = {"domain": "gov.tw", "ca_normalized": "shady ca"}
        out = R.reduce_drafts("ct_log", [self._draft([candidate])],
                              baselines=self._supply(), now=NOW)
        assert out[0].raw_score == 3.0 and out[0].status == STATUS_FIRED
        assert out[0].flags["untrusted_ca_count"] == 1
        assert "untrusted_ca_verdict" not in out[0].flags

    def test_a_ca_the_domain_has_used_before_does_not_fire(self):
        candidate = {"domain": "gov.tw", "ca_normalized": "Shady CA"}
        out = R.reduce_drafts(
            "ct_log", [self._draft([candidate])],
            baselines=self._supply(known=("shady ca",)), now=NOW)
        assert out[0].raw_score == 0.0

    def test_nothing_fires_while_the_domain_is_in_warmup(self):
        candidate = {"domain": "gov.tw", "ca_normalized": "shady ca"}
        out = R.reduce_drafts(
            "ct_log", [self._draft([candidate])],
            baselines=self._supply(first_seen=NOW - 1 * DAY), now=NOW)
        assert out[0].raw_score == 0.0
        assert out[0].flags["warmup_active"] is True

    def test_a_domain_never_seen_before_is_in_warmup(self):
        candidate = {"domain": "gov.tw", "ca_normalized": "shady ca"}
        out = R.reduce_drafts("ct_log", [self._draft([candidate])],
                              baselines={"ct_log_known_ca_per_domain": {},
                                         "ct_log_domain_first_observed": {}},
                              now=NOW)
        assert out[0].raw_score == 0.0

    def test_untrusted_outranks_wildcard_rather_than_adding_to_it(self):
        candidate = {"domain": "gov.tw", "ca_normalized": "shady ca"}
        out = R.reduce_drafts("ct_log",
                              [self._draft([candidate], wildcard=1)],
                              baselines=self._supply(), now=NOW)
        assert out[0].raw_score == 3.0

    def test_a_wildcard_alone_still_scores_two(self):
        out = R.reduce_drafts("ct_log", [self._draft(wildcard=1)],
                              baselines=self._supply(), now=NOW)
        assert out[0].raw_score == 2.0


class TestAisNowDetectsDarkGaps:
    def _draft(self, reports):
        return ObservationDraft(
            signal_source="ais_maritime", domain=PHYSICAL, country="TW",
            status=STATUS_OK, raw_score=0.0, value="",
            flags={"chokepoint": "Taiwan Strait", "stationary_anomalies": [],
                   "vessels_examined": len(reports),
                   "vessel_reports": list(reports),
                   "dark_gap_detection": "pending_l1_vessel_history"})

    def test_an_hour_of_silence_near_the_chokepoint_fires(self):
        reports = [{"mmsi": "1", "last_ts": NOW, "lat": 25.0, "lng": 121.0,
                    "dist_km": 10.0}]
        out = R.reduce_drafts(
            "ais_maritime", [self._draft(reports)],
            baselines={"ais_vessel_history": {
                "1": [{"value": NOW - 2 * HOUR,
                       "payload": {"last_ts": NOW - 2 * HOUR}}]}},
            now=NOW)
        assert out[0].status == STATUS_FIRED
        assert out[0].flags["dark_gap_count"] == 1
        assert "dark_gap_detection" not in out[0].flags

    def test_a_first_sighting_is_not_a_gap(self):
        """`self._vessel_history.get(mmsi)` misses on a new hull, so
        production skips it; treating it as a gap makes the first cycle
        after any restart a fleet-wide alert."""
        reports = [{"mmsi": "new", "last_ts": NOW, "lat": 25.0,
                    "lng": 121.0, "dist_km": 10.0}]
        out = R.reduce_drafts("ais_maritime", [self._draft(reports)],
                              baselines={"ais_vessel_history": {}}, now=NOW)
        assert out[0].flags["dark_gap_count"] == 0
        assert out[0].status == STATUS_OK

    def test_a_gap_far_from_the_chokepoint_is_not_a_gap(self):
        reports = [{"mmsi": "1", "last_ts": NOW, "lat": 0.0, "lng": 0.0,
                    "dist_km": 500.0}]
        out = R.reduce_drafts(
            "ais_maritime", [self._draft(reports)],
            baselines={"ais_vessel_history": {
                "1": [{"value": NOW - 2 * HOUR,
                       "payload": {"last_ts": NOW - 2 * HOUR}}]}},
            now=NOW)
        assert out[0].flags["dark_gap_count"] == 0


# ── the write side, and the round trip ──────────────────────────────────

class TestTheCycleAdvancesItsOwnBaselines:
    def _write(self, store, *, sensor, signal_source, country, flags,
               now=NOW, domain=CYBER):
        from v3.kernel import Evidence
        from v3.ledger.records import SignalObservation
        store.append_signal(SignalObservation(
            tick_id=f"t{int(now)}", sensor=sensor,
            signal_source=signal_source, domain=domain, country=country,
            evidence=Evidence.observe(flags, observed_at=now,
                                      freshness_horizon_sec=86400.0,
                                      source=sensor),
            status="OBSERVED", raw_score=0.0, flags=flags), now=now)

    def test_a_cycle_records_the_hour_it_measured(self, store):
        self._write(store, sensor="ripe_bgp", signal_source="bgp",
                    country="TW", flags={"announced_prefixes": 1234})
        written = record.record_cycle(store, now=NOW, countries=["TW"])
        assert written["bgp_hod"] == 1
        baseline = baselines.PHASE_BASELINES["bgp_hod"]
        row = store.read_baseline(baseline.baseline_id,
                                  sensor=baseline.sensor, country="TW",
                                  bucket=baseline.bucket_of(NOW))
        assert row["mean"] == 1234.0

    def test_the_read_at_the_top_never_sees_the_write_at_the_bottom(
            self, store):
        """The current bucket is excluded, so a reading is not compared
        with itself even though both happen in one cycle."""
        self._write(store, sensor="ripe_bgp", signal_source="bgp",
                    country="TW", flags={"announced_prefixes": 1234})
        record.record_cycle(store, now=NOW, countries=["TW"])
        supplied = baselines.phase_history(store, now=NOW, countries=["TW"])
        assert supplied["bgp_hod"]["TW"] == ()

    def test_the_next_day_reads_what_this_one_wrote(self, store):
        self._write(store, sensor="ripe_bgp", signal_source="bgp",
                    country="TW", flags={"announced_prefixes": 1234})
        record.record_cycle(store, now=NOW, countries=["TW"])
        supplied = baselines.phase_history(store, now=NOW + DAY,
                                           countries=["TW"])
        assert supplied["bgp_hod"]["TW"] == (1234.0,)

    def test_a_first_observed_marker_is_written_once_and_stays(self, store):
        self._write(store, sensor="ct_log", signal_source="ct_log",
                    country="TW",
                    flags={"watched_domains": ["gov.tw"],
                           "untrusted_ca_candidates": []})
        record.record_cycle(store, now=NOW, countries=["TW"])
        record.record_cycle(store, now=NOW + DAY, countries=["TW"])
        first = store.entity_marker("ct_log_domain_first_observed",
                                    sensor="ct_log", entity="gov.tw")
        assert first["first_seen"] == NOW

    def test_a_ca_that_fired_becomes_known_and_does_not_fire_twice(
            self, store):
        candidate = {"domain": "gov.tw", "ca_normalized": "shady ca"}
        self._write(store, sensor="ct_log", signal_source="ct_log",
                    country="TW",
                    flags={"watched_domains": ["gov.tw"],
                           "untrusted_ca_candidates": [candidate]})
        record.record_cycle(store, now=NOW, countries=["TW"])
        supplied = baselines.entity_history(store)
        assert supplied["ct_log_known_ca_per_domain"]["gov.tw"] == \
            ("shady ca",)

    def test_the_vessel_snapshot_round_trips(self, store):
        reports = [{"mmsi": "1", "last_ts": NOW - 60, "lat": 25.0,
                    "lng": 121.0, "dist_km": 3.0}]
        self._write(store, sensor="ais_maritime",
                    signal_source="ais_maritime", country="TW",
                    domain=PHYSICAL, flags={"vessel_reports": reports})
        record.record_cycle(store, now=NOW, countries=["TW"])
        supplied = baselines.entity_history(store)
        rows = supplied["ais_vessel_history"]["1"]
        assert rows[0]["payload"]["last_ts"] == NOW - 60

    def test_the_latency_history_round_trips_per_url(self, store):
        self._write(store, sensor="check_host", signal_source="check_host",
                    country="TW", domain=PHYSICAL,
                    flags={"url_latency": {"https://a.tw": 12.0,
                                           "https://b.tw": 40.0}})
        record.record_cycle(store, now=NOW, countries=["TW"])
        supplied = baselines.entity_history(store)
        history = supplied["checkhost_latency_history"]
        assert set(history) == {"https://a.tw", "https://b.tw"}
        assert history["https://a.tw"][0]["value"] == 12.0

    def test_the_cloudflare_baseline_id_receives_avg_spike_and_nothing_else(
            self):
        """Writing a DIFFERENT quantity into the migrated `hod` series
        would corrupt 28 days of history that means `avg_spike`. WP-4.1d
        made v3 compute the SAME quantity (`v3/runtime/spike.py`
        transcribing `core.py:762-817`), so the series can advance —
        pinned to that flag, on that signal source, so a later rename
        cannot quietly point it at a neighbouring number."""
        assert record.PHASE_SAMPLES["cf_attack_share_baseline"] == (
            "cloudflare_radar", "cf_spike_core", "avg_spike")


# ── §7-2 #73: the registered claim, measured ────────────────────────────

class TestTheCheckHostCooldownClaim:
    def test_production_takes_the_first_three_urls_every_cycle(self):
        """The register says production ROTATES a country's URLs. It does
        not: the slice is `urls[:3]` in list order, so URL four is never
        queried there either."""
        source = (REPO / "radar" / "sensors" / "checkhost.py").read_text()
        tree = ast.parse(source)
        slices = [ast.unparse(node.iter) for node in ast.walk(tree)
                  if isinstance(node, ast.For)
                  and isinstance(node.iter, ast.Subscript)]
        assert "urls[:3]" in slices

    def test_the_expander_selects_the_same_three(self):
        from v3.adapters.physical.check_host import MAX_URLS_PER_COUNTRY
        assert MAX_URLS_PER_COUNTRY == 3

    def test_the_cooldown_is_shorter_than_either_systems_cadence(self):
        """A 300s cooldown cannot fire on a 600s schedule, so the branch
        v3 does not implement is one production does not take either."""
        source = (REPO / "radar" / "sensors" / "checkhost.py").read_text()
        tree = ast.parse(source)
        cooldown = next(
            node.value.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(getattr(t, "id", "") == "_URL_COOLDOWN_SEC"
                    for t in node.targets))
        # `int(os.getenv("CHECKHOST_POLL_INTERVAL", "600"))` — the
        # default is the inner call's second argument.
        poll = next(
            node.value.args[0].args[1].value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(getattr(t, "id", "") == "CHECKHOST_POLL_INTERVAL"
                    for t in node.targets))
        from v3.adapters.physical.check_host import CHECK_HOST_ADAPTER
        assert cooldown < int(poll)
        assert cooldown < CHECK_HOST_ADAPTER.cadence.cadence_sec
