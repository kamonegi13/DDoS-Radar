"""§7-2 #135 — `ripe_bgp`'s warm-up verdict, v3's own, in the sensitive
direction.

Four obligations, and the fourth is the one that makes this a design
rather than a port:

  derivation  the statistic reads L1 and nothing else. No in-process
              structure, nothing that dies on restart — re-implementing
              A-03 in a new file would be the same defect with a newer
              date on it.
  cold start  a ledger with NO history withholds. G-17: an empty cache
              must not read as a calm world, so "some history, not yet
              seven same-hour samples" and "nothing at all" are two
              different answers with two different names.
  band        production's, 0-1 (`core.py:1148`). v3 reaches the verdict
              by another route; it does not invent another scale.
  strictness  the warm-up rule must fire LESS readily than the seven-
              sample rule, or v3 has built something that concludes more
              from less. Swept, not asserted.

Plus the finding this work turned up, pinned so it cannot be forgotten:
the quantity all of this judges is dead on both sides of the port.
"""
import ast
import inspect
import math
import pathlib
import random

import pytest

from v3.adapters.cyber import ripe_bgp
from v3.adapters.types import (CYBER, PHYSICAL, STATUS_FIRED,
                               STATUS_OBSERVED, STATUS_OK, ObservationDraft)
from v3.ledger import LedgerStore
from v3.runtime import attribution, baselines, record
from v3.runtime import reduce as R
from v3.runtime import reduce_info, verdicts

NOW = 1_786_000_000.0
HOUR = 3600.0
REPO = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "warmup.db"))
    yield instance
    instance.close()


def _draft(country="TW", prefixes=1000, series=None):
    return ObservationDraft(
        signal_source="bgp", domain=CYBER, country=country,
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"prefixes={prefixes}",
        flags={"announced_prefixes": prefixes, "seen_ases": 40,
               "entries": 3, "prefix_series": list(series or ()),
               "hod_verdict": "pending_l1_bgp_hod"})


def _fold(drafts, *, same_hour=(), pooled=None, country="TW"):
    """The fold as the cycle calls it: same-hour history cold by default."""
    history = {"bgp_hod": {country: tuple(same_hour)}}
    if pooled is not None:
        history["bgp_hod_pooled"] = {country: tuple(pooled)}
    return R.reduce_drafts("ripe_bgp", drafts, baselines=history, now=NOW)


#: A pooled series that is stable enough for a 20% drop to clear -3.0.
STABLE = tuple([1000.0 + (index % 3) for index in range(30)])


# ── 1. the statistic itself ─────────────────────────────────────────────

class TestTheWarmupStatisticIsPure:
    def test_it_opens_nothing(self):
        """A fold that read a database could not be replayed, and replay
        is what the parity harness rests on."""
        source = inspect.getsource(verdicts.bgp_warmup_verdict)
        assert "store" not in source and "self" not in source
        for banned in ("import ", "open(", "time.time", "sqlite"):
            assert banned not in source

    def test_the_module_holds_no_mutable_state(self):
        """A03 was an instance dict. A module-level dict would be the same
        defect with a longer lifetime, so the module carries none."""
        tree = ast.parse(pathlib.Path(verdicts.__file__).read_text())
        mutable = []
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            if not isinstance(node.value, (ast.Dict, ast.List, ast.Set)):
                continue
            mutable += [target.id
                        for target in getattr(node, "targets", [])
                        if isinstance(target, ast.Name)
                        and not target.id.isupper()
                        and target.id != "__all__"]
        assert mutable == [], mutable

    def test_the_same_reading_twice_gives_the_same_answer(self):
        first = verdicts.bgp_warmup_verdict(STABLE, 800.0)
        second = verdicts.bgp_warmup_verdict(STABLE, 800.0)
        assert first == second


class TestTheConstantsAreProductions(object):
    def test_the_minimum_is_production_s_own(self):
        """`HOD_MIN_SAME_HOUR` = 7, asked of the pooled series instead of
        the same-hour one — the pool, not the number, is what changed."""
        assert verdicts.BGP_WARMUP_MIN_SAMPLES == 7
        assert (verdicts.BGP_WARMUP_MIN_SAMPLES
                == verdicts.BGP_HOD_MIN_SAMPLES == ripe_bgp.HOD_MIN_SAME_HOUR)

    def test_the_standard_deviation_floor_is_production_s_own(self):
        assert verdicts.BGP_WARMUP_STD_FLOOR == 1.0
        assert (verdicts.BGP_WARMUP_STD_FLOOR
                == verdicts.BGP_HOD_STD_FLOOR == ripe_bgp.HOD_STDDEV_FLOOR)

    def test_the_drop_threshold_is_production_s_warmup_threshold(self):
        """`BgpRoutingSensor.BGP_DROP_THRESHOLD`, read out of production
        rather than restated — it is used in EXACTLY this branch."""
        source = (REPO / "radar" / "sensors" / "bgp_routing.py").read_text()
        tree = ast.parse(source)
        found = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(
                    node.targets[0], ast.Name):
                if node.targets[0].id == "BGP_DROP_THRESHOLD":
                    found["value"] = node.value.value
        assert found["value"] == 0.15
        assert verdicts.BGP_WARMUP_DROP_THRESHOLD == found["value"]
        assert ripe_bgp.DROP_THRESHOLD == found["value"]

    def test_the_widened_threshold_is_the_stricter_tier_of_the_same_ladder(self):
        """-3.0 is not a new number in this system: it is what the same
        Z-statistic calls a BLACKOUT for `check_host`."""
        assert verdicts.BGP_WARMUP_ANOMALY_Z == -3.0
        assert (verdicts.BGP_WARMUP_ANOMALY_Z
                == verdicts.CHECKHOST_BLACKOUT_Z)
        assert verdicts.BGP_WARMUP_ANOMALY_Z < verdicts.BGP_HOD_ANOMALY_Z

    def test_the_band_is_production_s_zero_to_one(self):
        """`core.py:1148` — `1 if bgp_anomaly else 0`. v3 may reach the
        verdict another way; it may not invent another scale."""
        assert verdicts.BGP_ANOMALY_SCORE == 1.0
        fired = _fold([_draft(prefixes=700)], pooled=STABLE)[0]
        assert fired.raw_score == 1.0
        calm = _fold([_draft(prefixes=1000)], pooled=STABLE)[0]
        assert calm.raw_score == 0.0


class TestBothGuardsMustAgree:
    def test_a_deep_drop_with_a_quiet_series_fires(self):
        stat = verdicts.bgp_warmup_verdict(STABLE, 700.0)
        assert stat.valid and stat.anomaly
        assert stat.z < verdicts.BGP_WARMUP_ANOMALY_Z
        assert stat.drop_ratio > verdicts.BGP_WARMUP_DROP_THRESHOLD

    def test_a_significant_but_small_movement_does_not_fire(self):
        """The Z guard alone would call this an anomaly; the drop guard is
        what stops a 0.5% wobble on a very stable country becoming one.
        This is the case production's warm path DOES fire on, and the
        whole of why the warm-up rule is the stricter of the two."""
        stat = verdicts.bgp_warmup_verdict(STABLE, 990.0)
        assert stat.z < verdicts.BGP_WARMUP_ANOMALY_Z
        assert stat.drop_ratio < verdicts.BGP_WARMUP_DROP_THRESHOLD
        assert stat.anomaly is False

    def test_a_large_drop_in_a_wildly_noisy_series_does_not_fire(self):
        """And the Z guard is what stops a country that swings 40% every
        hour firing on its ordinary swing."""
        noisy = tuple([1000.0, 600.0] * 8)
        stat = verdicts.bgp_warmup_verdict(noisy, 600.0)
        assert stat.drop_ratio > verdicts.BGP_WARMUP_DROP_THRESHOLD
        assert stat.z > verdicts.BGP_WARMUP_ANOMALY_Z
        assert stat.anomaly is False

    def test_a_rise_never_fires(self):
        """A country does not get into trouble by announcing MORE routes;
        the drop ratio floors at zero rather than going negative."""
        stat = verdicts.bgp_warmup_verdict(STABLE, 5000.0)
        assert stat.drop_ratio == 0.0 and stat.anomaly is False

    def test_a_zero_mean_yields_no_ratio_rather_than_a_zero_one(self):
        """A 0.0 drop ratio is the claim `nothing dropped`. With a mean of
        zero there is no ratio to state, and stating one would be the
        G-17 shape at the level of a single number."""
        stat = verdicts.bgp_warmup_verdict(tuple([0.0] * 10), 0.0)
        assert stat.valid is True
        assert stat.drop_ratio is None
        assert stat.anomaly is False


# ── 2. the cold-start truth ─────────────────────────────────────────────

class TestTheColdStartIsWithheldNotSynthesised:
    def test_an_empty_ledger_withholds(self):
        stat = verdicts.bgp_warmup_verdict((), 1.0)
        assert stat.valid is False and stat.n == 0 and stat.anomaly is False
        assert stat.z is None and stat.drop_ratio is None

    def test_six_samples_withhold_and_seven_decide(self):
        assert verdicts.bgp_warmup_verdict(tuple([1000.0] * 6),
                                           1.0).valid is False
        assert verdicts.bgp_warmup_verdict(tuple([1000.0] * 7),
                                           1.0).valid is True

    def test_the_fold_leaves_a_cold_row_observed_with_a_marker(self):
        out = _fold([_draft(prefixes=1)], pooled=())[0]
        assert out.status == STATUS_OBSERVED and out.raw_score == 0.0
        assert out.flags["hod_verdict"] == reduce_info.BGP_PENDING_COLD
        assert "is_anomaly" not in out.flags

    def test_the_two_silences_have_two_names(self):
        """`fewer than seven SAME-HOUR samples` and `fewer than seven
        samples of any hour` are different facts. One name for both is how
        a warm-up that never ends looks like a warm-up that just started."""
        cold = _fold([_draft(prefixes=1)], pooled=())[0]
        warm = _fold([_draft(prefixes=1)], pooled=STABLE)[0]
        assert cold.flags["hod_verdict"] == "pending_l1_bgp_hod_cold"
        assert "hod_verdict" not in warm.flags

    def test_an_unsupplied_baseline_is_not_a_cold_one(self):
        """`bgp_hod` absent means L1 was never read. The draft comes back
        exactly as it went in, still carrying L0's own marker."""
        out = R.reduce_drafts("ripe_bgp", [_draft()], baselines={}, now=NOW)
        assert out[0].status == STATUS_OBSERVED
        assert out[0].flags["hod_verdict"] == "pending_l1_bgp_hod"

    def test_no_score_is_ever_synthesised_from_nothing(self):
        """The property, over the whole space: with fewer than seven
        pooled samples, no reading of any size produces a score."""
        rng = random.Random(20260809)
        for _ in range(4000):
            n = rng.randint(0, 6)
            pool = tuple(rng.uniform(0.0, 50_000.0) for _ in range(n))
            reading = rng.uniform(0.0, 50_000.0)
            stat = verdicts.bgp_warmup_verdict(pool, reading)
            assert stat.anomaly is False and stat.valid is False


# ── 3. the warm path still owns the decision when it can make one ───────

class TestTheWarmPathTakesPrecedence:
    def test_seven_same_hour_samples_use_the_same_hour_statistic(self):
        """The pooled series says ANOMALY, the same-hour series says
        NORMAL, and the same-hour series wins because it is the one
        production uses when it can."""
        out = _fold([_draft(prefixes=700)],
                    same_hour=tuple([700.0] * 10), pooled=STABLE)[0]
        assert out.status == STATUS_OK
        assert out.flags["hod_n"] == 10
        assert reduce_info.BGP_ROUTE not in out.flags

    def test_the_route_is_named_on_the_row_when_it_is_not_production_s(self):
        out = _fold([_draft(prefixes=700)], pooled=STABLE)[0]
        assert out.flags[reduce_info.BGP_ROUTE] == "warmup_pooled_all_hours"
        assert out.flags["hod_z"] is None and out.flags["hod_n"] == 0
        assert out.flags["warmup_n"] == len(STABLE)
        assert out.flags["warmup_drop_ratio"] > 0.15

    def test_the_warm_path_row_never_claims_the_warmup_route(self):
        out = _fold([_draft(prefixes=100)],
                    same_hour=tuple([1000.0] * 10), pooled=STABLE)[0]
        assert out.status == STATUS_FIRED
        assert reduce_info.BGP_ROUTE not in out.flags
        assert "warmup_n" not in out.flags


# ── 4. strictness — swept, not asserted ─────────────────────────────────

def _same_hour_of(series, phase=0, modulus=24):
    return tuple(value for index, value in enumerate(series)
                 if index % modulus == phase)


def _world(rng, *, hours, level=None, diurnal=None, noise=None):
    """One synthetic country: a level, a diurnal shape, within-hour noise."""
    level = rng.uniform(50.0, 40_000.0) if level is None else level
    diurnal = (rng.uniform(0.0, 0.25) if diurnal is None else diurnal) * level
    noise = (rng.uniform(0.01, 0.10) if noise is None else noise) * level
    return [max(0.0, level + diurnal * math.sin(
        2 * math.pi * (hour % 24) / 24.0) + rng.gauss(0.0, noise))
        for hour in range(hours)], level, noise


class TestTheWarmupRuleIsTheStricterOfTheTwo:
    """The comparison is only meaningful where BOTH rules can decide.

    The first sweep found this and it is a design point rather than a bug:
    where the same-hour subset holds fewer than seven samples the warm
    rule does not DECLINE to fire, it is WITHHELD — so "warm-up fired,
    warm did not" is not evidence of laxity there, it is the entire
    purpose of the branch. Strictness is therefore swept on worlds long
    enough for the warm rule to answer, and the recall the branch buys is
    measured separately, on worlds where it cannot.
    """

    def test_the_sweep_never_finds_a_world_where_warmup_fires_alone(self):
        """4,000 synthetic countries, each with at least seven same-hour
        samples so the warm rule can answer. Both rules see the SAME
        world — the warm rule on the same-hour subset, the warm-up rule on
        the whole series. The warm-up rule may never be the only one that
        fires; if it ever is, v3 concludes more from less evidence, which
        is the one thing option (c) was not allowed to do."""
        rng = random.Random(4_135)
        warm_fires = warmup_fires = both = 0
        for _ in range(4000):
            hours = rng.choice((192, 240, 384, 672))
            series, level, noise = _world(rng, hours=hours)
            phase = hours % 24
            same_hour = _same_hour_of(series, phase=phase)
            assert len(same_hour) >= verdicts.BGP_HOD_MIN_SAMPLES
            reading = max(0.0, level * rng.uniform(0.0, 1.4)
                          + rng.gauss(0.0, noise))
            warm = verdicts.bgp_is_anomaly(
                verdicts.bgp_hod_verdict(same_hour, reading))
            cold = verdicts.bgp_warmup_verdict(tuple(series), reading)
            warm_fires += warm
            warmup_fires += cold.anomaly
            both += warm and cold.anomaly
            assert not (cold.anomaly and not warm), {
                "level": level, "reading": reading, "z": cold.z,
                "drop": cold.drop_ratio, "n_same_hour": len(same_hour)}
        assert warm_fires > 200, warm_fires
        assert warmup_fires > 0, "a rule that never fires is not a rule"
        assert warmup_fires < warm_fires
        assert both == warmup_fires

    def test_the_branch_buys_recall_where_the_warm_rule_is_withheld(self):
        """NP1's side of the ledger, measured. Worlds of 8 to 160 hours —
        a newly registered scenario's first week — where the same-hour
        subset is short of seven. Before #135 every one of these was
        WITHHELD, whatever the reading; after it, a real collapse is
        caught while the same-hour baseline fills."""
        rng = random.Random(9_135)
        withheld_before = caught = collapses = 0
        for _ in range(4000):
            hours = rng.randint(8, 160)
            series, level, noise = _world(rng, hours=hours, noise=0.02)
            phase = hours % 24
            same_hour = _same_hour_of(series, phase=phase)
            if len(same_hour) >= verdicts.BGP_HOD_MIN_SAMPLES:
                continue
            withheld_before += 1
            collapse = rng.random() < 0.5
            # A "normal" reading stays inside 2% of level and the noise is
            # 2% of it, so three sigma of ordinary movement is 8% — well
            # under the 15% drop guard. Anything the rule fires on here is
            # a genuine collapse, which is what makes `assert collapse` a
            # precision claim rather than an artefact of the generator.
            reading = max(0.0, level * (rng.uniform(0.0, 0.5) if collapse
                                        else rng.uniform(0.98, 1.02))
                          + rng.gauss(0.0, noise))
            collapses += collapse
            stat = verdicts.bgp_warmup_verdict(tuple(series), reading)
            if stat.anomaly:
                caught += 1
                assert collapse, {"reading": reading, "level": level,
                                  "z": stat.z, "drop": stat.drop_ratio}
        assert withheld_before > 3000, withheld_before
        assert caught > 0.5 * collapses, (caught, collapses)

    def test_the_naive_choice_would_have_failed_that_sweep(self):
        """The counterfactual, constructed rather than searched, so the
        widened threshold is shown to be load-bearing: the SAME pooled
        statistic at production's -2.0 fires on a world where the warm
        rule does not, purely because the current hour is a normally quiet
        one and pooling folds that offset into the reading."""
        quiet_hour, hours, amplitude, within = 18, 240, 250.0, 100.0
        # Ten whole days, so the shape and the alternation both cancel and
        # the pooled mean is exactly the level. The alternation gives each
        # hour-of-day a within-hour sigma of exactly `within`.
        series = [1000.0
                  + amplitude * math.sin(2 * math.pi * (hour % 24) / 24.0)
                  + (within if (hour // 24) % 2 == 0 else -within)
                  for hour in range(hours)]
        same_hour = _same_hour_of(series, phase=quiet_hour)
        hour_mean = sum(same_hour) / len(same_hour)
        reading = hour_mean - 1.9 * within        # 1.9 sigma: warm says no

        warm = verdicts.bgp_hod_verdict(same_hour, reading)
        assert warm.valid and math.isclose(warm.z, -1.9, rel_tol=1e-9)
        assert verdicts.bgp_is_anomaly(warm) is False

        naive = verdicts.phase_zscore(
            tuple(series), reading,
            min_samples=verdicts.BGP_WARMUP_MIN_SAMPLES,
            std_floor=verdicts.BGP_WARMUP_STD_FLOOR)
        assert naive.z < verdicts.BGP_HOD_ANOMALY_Z, naive.z

        chosen = verdicts.bgp_warmup_verdict(tuple(series), reading)
        assert chosen.z is not None and chosen.z == naive.z
        assert chosen.drop_ratio > verdicts.BGP_WARMUP_DROP_THRESHOLD
        assert chosen.anomaly is False, (
            "the widened Z is what declines this; if it ever fires, the "
            "warm-up rule has become the laxer of the two")


# ── 5. the supply is the ledger's, and only the ledger's ────────────────

class TestTheSupplyIsL1:
    def test_the_pooled_read_names_no_new_baseline(self):
        """`bgp_hod_pooled` is a second READ of one series, not a second
        dependency. Declaring it would make `coverage()` count one
        dependency twice and the family look further from done."""
        assert baselines.POOLED_PHASE_READS == {"bgp_hod_pooled": "bgp_hod"}
        assert "bgp_hod_pooled" not in baselines.supplied_names()
        assert ripe_bgp.RIPE_BGP_ADAPTER.baseline_refs == ("bgp_hod",)

    def test_the_coverage_account_is_unchanged_by_this_work(self):
        from v3.adapters.catalog import ALL_ADAPTERS
        account = baselines.coverage(ALL_ADAPTERS)
        assert "bgp_hod" in account["answered"]
        assert "bgp_hod_pooled" not in account["declared"]
        assert account["withheld"] == {}

    def test_the_pooled_read_returns_every_bucket_the_phase_read_skips(
            self, store):
        baseline = baselines.PHASE_BASELINES["bgp_hod"]
        base = baseline.bucket_of(NOW)
        for index in range(1, 31):
            store.upsert_baseline_value(
                baseline_id=baseline.baseline_id, sensor=baseline.sensor,
                country="TW", bucket=int(base - index * HOUR),
                value=1000.0 + index, now=NOW)
        supplied = baselines.for_cycle(store, now=NOW, countries=("TW",))
        assert len(supplied["bgp_hod_pooled"]["TW"]) == 30
        assert len(supplied["bgp_hod"]["TW"]) == 1
        # oldest first: the oldest bucket is 30 hours back, value 1030.
        assert supplied["bgp_hod_pooled"]["TW"] == tuple(
            float(1000 + index) for index in range(30, 0, -1))

    def test_the_current_bucket_is_excluded_from_both(self, store):
        """A reading compared with itself pulls every Z toward zero on
        exactly the tick that mattered."""
        baseline = baselines.PHASE_BASELINES["bgp_hod"]
        base = baseline.bucket_of(NOW)
        store.upsert_baseline_value(
            baseline_id=baseline.baseline_id, sensor=baseline.sensor,
            country="TW", bucket=int(base), value=7.0, now=NOW)
        supplied = baselines.for_cycle(store, now=NOW, countries=("TW",))
        assert supplied["bgp_hod_pooled"]["TW"] == ()

    def test_a_country_with_no_rows_gets_an_empty_series_not_a_missing_key(
            self, store):
        supplied = baselines.for_cycle(store, now=NOW, countries=("TW", "CN"))
        assert supplied["bgp_hod_pooled"] == {"TW": (), "CN": ()}

    def test_the_verdict_survives_a_restart_because_the_store_does(
            self, tmp_path):
        """The A-03 test. Production's warm-up baseline is re-seeded on the
        first reading after a restart, so its drop ratio is exactly 0 —
        the defect this design exists not to repeat."""
        path = str(tmp_path / "restart.db")
        first = LedgerStore(path)
        baseline = baselines.PHASE_BASELINES["bgp_hod"]
        base = baseline.bucket_of(NOW)
        for index in range(1, 11):
            first.upsert_baseline_value(
                baseline_id=baseline.baseline_id, sensor=baseline.sensor,
                country="TW", bucket=int(base - index * HOUR),
                value=1000.0, now=NOW)
        first.close()
        second = LedgerStore(path)
        try:
            supplied = baselines.for_cycle(second, now=NOW,
                                           countries=("TW",))
            out = R.reduce_drafts("ripe_bgp", [_draft(prefixes=700)],
                                  baselines=supplied, now=NOW)
        finally:
            second.close()
        assert out[0].status == STATUS_FIRED and out[0].raw_score == 1.0

    def test_the_baseline_write_is_unchanged_by_a_warmup_fire(self):
        """`record_phase_samples` reads `announced_prefixes` off the
        stored row and never looks at its status, so a row that now FIRES
        contributes the same sample it did when it was OBSERVED. The fold
        must therefore not strip the key it feeds on."""
        assert record.PHASE_SAMPLES["bgp_hod"] == ("ripe_bgp", "bgp",
                                                   "announced_prefixes")
        for pooled in ((), STABLE):
            out = _fold([_draft(prefixes=700)], pooled=pooled)[0]
            assert out.flags["announced_prefixes"] == 700


# ── 6. the per-country readers ──────────────────────────────────────────

class TestEveryPerCountryReaderIsStillFed:
    def test_ripe_bgp_is_a_focused_only_sensor_and_keeps_its_country(self):
        """Measured against production rather than assumed: `add_rat`
        gives a rationale entry a country only for these twelve names
        (`core.py:2039-2041`), so `ripe_bgp` is one of the rows whose
        country actually reaches a scenario score.

        Read by AST rather than imported: importing `radar.scenarios`
        pulls `radar.database`, which opens and touches the live
        `radar/persistence/radar.db` at import time. A test has no
        business writing to the production ledger to look up a frozenset.
        """
        tree = ast.parse(
            (REPO / "radar" / "scenarios.py").read_text())
        names = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.AnnAssign):
                continue
            if getattr(node.target, "id", None) != "FOCUSED_ONLY_SENSOR_NAMES":
                continue
            for element in ast.walk(node.value):
                if isinstance(element, ast.Constant) and isinstance(
                        element.value, str):
                    names.add(element.value)
        assert len(names) == 12, sorted(names)
        assert "ripe_bgp" in names
        assert "bgp" not in attribution.COUNTRYLESS_SOURCES
        assert "ripe_bgp" not in attribution.BY_ADAPTER

    def test_attribution_leaves_a_fired_warmup_row_alone(self):
        fired = _fold([_draft(prefixes=700)], pooled=STABLE)
        out = attribution.collapse("ripe_bgp", fired, cores=("TW",))
        assert out == tuple(fired)
        assert out[0].country == "TW" and out[0].raw_score == 1.0
        assert attribution.COUNTRY_SCORE not in out[0].flags

    def test_suppression_has_no_rule_that_could_have_eaten_it(self):
        from v3.runtime import suppression
        assert not [rule for rule in suppression.RULES
                    if rule.target_sensor == "ripe_bgp"]

    def test_the_row_still_dedups_against_ioda_bgp_by_max(self):
        """S1-SCORE-008, and the reader consequence worth naming: the
        dedup key is `(signal_source, country)` with no domain in it, so
        whichever of `ripe_bgp` (cyber) and `ioda_bgp` (physical) scores
        higher decides which domain absorbs the point. A warm-up fire can
        now win that contest — the same way a warm fire already could."""
        from v3.scoring.contributions import Contribution, dedup_max

        def contribution(sensor, domain, score):
            return Contribution(
                sensor=sensor, signal_source="bgp", domain=domain,
                country="TW", role="primary_target", raw_score=score,
                llm_country_weight=1.0, participant_weight=1.0, score=score,
                trace=f"{sensor} {score:.2f}")

        ripe = contribution("ripe_bgp", CYBER, 1.0)
        ioda = contribution("ioda_bgp", PHYSICAL, 0.5)
        kept = dedup_max([ioda, ripe])
        assert len(kept) == 1 and kept[0].sensor == "ripe_bgp"
        assert kept[0].domain == CYBER

    def test_no_pending_marker_occupies_a_key_read_as_a_boolean(self):
        """The `gps_jamming` / `check_host` lesson: a marker on a key a
        consumer reads as a bool is `permanently firing`. `is_anomaly` is
        ABSENT while withheld, never a string and never False."""
        cold = _fold([_draft(prefixes=1)], pooled=())[0]
        assert "is_anomaly" not in cold.flags
        assert isinstance(cold.flags["hod_verdict"], str)
        decided = _fold([_draft(prefixes=700)], pooled=STABLE)[0]
        assert decided.flags["is_anomaly"] is True
        assert "hod_verdict" not in decided.flags


# ── 7. the finding: the judged quantity is dead on BOTH sides ───────────

class TestTheMeasuredQuantityIsDead:
    """`announced_prefixes` is not a key RIPE returns.

    `country-routing-stats` answers with `v4_prefixes_ris` /
    `v6_prefixes_ris` / `asns_ris` per `stats_date`. Production's
    `latest.get("announced_prefixes", 0)` therefore reads 0 forever, its
    hour-of-day Z is `(0-0)/max(0,1.0)` = 0.0, its drop ratio is 0.0, and
    BOTH of its branches are unreachable — measured against the live
    ledger, where all 5,398 `bgp_hod` rows across eight countries and the
    full 672-bucket window are 0.0.

    v3 transcribes the same read, so parity is preserved and the defect is
    production's. It is pinned here rather than repaired because reading a
    different quantity under the same `baseline_id` would corrupt the
    migrated series AND be an unregistered difference in what is measured.
    When someone fixes the key, these tests fail and point at §7-2 #135.
    """

    CURRENT_SHAPE = {"data": {"resource": "TW", "stats": [
        {"timeline": [{"starttime": "2026-08-03T00:00:00"}],
         "v4_prefixes_ris": 9607, "v6_prefixes_ris": 1206,
         "asns_ris": 242, "v4_prefixes_stats": -1,
         "v6_prefixes_stats": -1, "asns_stats": 465,
         "stats_date": "2026-08-03T00:00:00"}]}}

    def test_production_reads_a_key_the_current_payload_does_not_have(self):
        source = (REPO / "radar" / "sensors" / "bgp_routing.py").read_text()
        assert 'latest.get("announced_prefixes", 0)' in source
        assert "announced_prefixes" not in self.CURRENT_SHAPE["data"][
            "stats"][0]

    def test_v3_transcribes_the_same_read_and_therefore_the_same_zero(self):
        import json

        from tests.test_adapters_cyber_fidelity import context, synthetic
        body = json.dumps(self.CURRENT_SHAPE).encode()
        draft = ripe_bgp.normalize(synthetic(body), context("ripe_bgp"))[0]
        assert draft.flags["announced_prefixes"] == 0
        assert draft.flags["seen_ases"] == 0

    def test_an_all_zero_history_can_reach_neither_verdict(self):
        """Which is the state of the live ledger, and the reason #135's
        rule cannot fire today for a reason that has nothing to do with
        #135. A dead measurement is not a calm world."""
        zeros = tuple([0.0] * 30)
        warm = verdicts.bgp_hod_verdict(zeros, 0.0)
        assert warm.valid is True and verdicts.bgp_is_anomaly(warm) is False
        cold = verdicts.bgp_warmup_verdict(zeros, 0.0)
        assert cold.valid is True and cold.anomaly is False
        assert cold.drop_ratio is None
