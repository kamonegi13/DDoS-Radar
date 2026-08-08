"""WP-4.1d — the DDoS origin spike: fetched, computed, judged, and ranked by.

§7-2 #9's last withheld member (`cloudflare_radar`) and §7-2 #116 (the
chain owner ranked by admitted evidence rather than production's
`avg_spike`) were waiting on the SAME missing thing: the adapter declared
four requests and none of them was the per-target attack-ORIGIN
distribution, so the raw material for `avg_spike` was not in the ledger at
all.

Four obligations, in the order the value travels:

  declaration  the origin endpoints production calls, with production's
               parameters, expanded once per target country.
  arithmetic   `avg_spike` transcribed from `radar/routes/core.py:762-817`
               — floors, the 25x cap, the 1% inclusion gate, the 5%
               denominator floor — verified against an independent
               re-typing of the production loop over a random sweep, and
               against mutants of itself.
  verdict      the HOD Z ladder (`core.py:1006-1018`) that `cf_spike_core`
               was withholding, warm-up branch included.
  ranking      `v3/runtime/chain.py` ranks by the measured quantity when
               it exists, by admitted evidence when it does not, and SAYS
               WHICH (NP6 applies to the ranking too).

Every production citation here is AST-verified rather than quoted: the
sweep that produced this work found the register's own "90-day origin
baseline" to be `BASELINE_DATE_RANGE`, which ships as 28 days.
"""
import ast
import json
import math
import pathlib
import random

import pytest

from v3.adapters.cyber import cloudflare_radar as CF
from v3.adapters.types import (CYBER, FetchedPayload, NormalizeContext,
                               ObservationDraft, STATUS_FIRED,
                               STATUS_OBSERVED, STATUS_OK)
from v3.ledger import LedgerStore
from v3.runtime import baselines as B
from v3.runtime import chain as CHAIN
from v3.runtime import record as REC
from v3.runtime import reduce as R
from v3.runtime import spike as S

NOW = 1_786_000_000.0
HOUR = 3600.0
REPO = pathlib.Path(__file__).resolve().parents[1]
CORE = REPO / "radar" / "routes" / "core.py"


@pytest.fixture
def store(tmp_path):
    instance = LedgerStore(str(tmp_path / "spike.db"))
    yield instance
    instance.close()


def _context(countries=("TW", "JP")):
    return NormalizeContext(adapter_id=CF.CLOUDFLARE_RADAR, now=NOW,
                            countries=tuple(countries))


def _origin_payload(label, country, distribution):
    rows = [{"origin1": code, "value": pct}
            for code, pct in distribution.items()]
    url = (f"https://api.cloudflare.com/client/v4/radar/attacks/"
           f"layer3/top/locations/origin?location={country}")
    return FetchedPayload(url=url, status=200, fetched_at=NOW,
                          content_type="application/json", label=label,
                          body=json.dumps({"result": {"top_0": rows}}).encode())


def _origin_drafts(country, *, l3, l7, base_l3, base_l7):
    """The four per-target origin rows `normalize` produces for a country."""
    made = []
    for label, distribution in ((CF.ORIGIN_L3, l3), (CF.ORIGIN_L7, l7),
                                (CF.ORIGIN_L3_BASELINE, base_l3),
                                (CF.ORIGIN_L7_BASELINE, base_l7)):
        if distribution is None:
            continue
        made.extend(CF.normalize(_origin_payload(label, country, distribution),
                                 _context((country,))))
    return tuple(made)


# ── an independent re-typing of production's loop, for the sweep ─────────

def _production_avg_spike(o_l3, o_l7, b_l3, b_l7, adversary_states):
    """`radar/routes/core.py:762-817`, re-typed from the source.

    Deliberately written in production's own shape (accumulators, not
    comprehensions) so that a transcription error in `v3/runtime/spike.py`
    cannot be reproduced here by copying it.
    """
    target_weighted_spike = 0.0
    total_local_pct = 0.0
    target_l3_spike_sum = 0.0
    target_l7_spike_sum = 0.0
    all_origin_codes = set(o_l3) | set(o_l7)
    has_baseline = bool(b_l3 or b_l7)
    for code in all_origin_codes:
        local_l3_pct, local_l7_pct = o_l3.get(code, 0.0), o_l7.get(code, 0.0)
        current_local_pct = max(local_l3_pct, local_l7_pct)
        is_adversary_origin = code in adversary_states
        _floor_new = 0.5 if is_adversary_origin else 3.0
        _floor_exist = 0.5 if is_adversary_origin else 2.0
        base_l3 = max(b_l3.get(code, _floor_new),
                      _floor_new if code not in b_l3 else _floor_exist)
        base_l7 = max(b_l7.get(code, _floor_new),
                      _floor_new if code not in b_l7 else _floor_exist)
        l3_spike = (local_l3_pct / base_l3) if local_l3_pct > 0 else 0.0
        l7_spike = (local_l7_pct / base_l7) if local_l7_pct > 0 else 0.0
        spike_factor = min(max(l3_spike, l7_spike), 25.0)
        if has_baseline and current_local_pct >= 1.0:
            target_weighted_spike += spike_factor * current_local_pct
            target_l3_spike_sum += l3_spike * current_local_pct
            target_l7_spike_sum += l7_spike * current_local_pct
            total_local_pct += current_local_pct
    avg_l3 = target_l3_spike_sum / max(total_local_pct, 5.0)
    avg_l7 = target_l7_spike_sum / max(total_local_pct, 5.0)
    return (round(target_weighted_spike / max(total_local_pct, 5.0), 2),
            avg_l3, avg_l7)


def _production_spike_ladder(hod_z, hod_valid, hod_n, core_spike):
    """`core.py:1007-1018`, re-typed."""
    if hod_valid:
        score = ((1 if hod_z > 1.5 else 0) + (1 if hod_z > 2.5 else 0)
                 + (1 if hod_z > 3.5 else 0))
        return score, hod_z > 1.5
    score = ((1 if core_spike > 2.0 else 0) + (1 if core_spike > 4.0 else 0)
             + (1 if core_spike > 6.0 else 0))
    return score, core_spike > 2.0


# ══ 1. the declaration ═══════════════════════════════════════════════════

class TestTheOriginRequestIsDeclared:
    """§7-2 #116's stated obstacle: the endpoint was never fetched."""

    def test_production_calls_both_origin_endpoints_per_target(self):
        source = CORE.read_text()
        assert "layer3/top/locations/origin" in source
        assert "layer7/top/locations/origin" in source

    def test_the_adapter_now_declares_all_four_origin_requests(self):
        labels = {spec.label for spec in CF.CLOUDFLARE_RADAR_ADAPTER.requests}
        assert {CF.ORIGIN_L3, CF.ORIGIN_L7, CF.ORIGIN_L3_BASELINE,
                CF.ORIGIN_L7_BASELINE} <= labels

    def test_each_origin_request_is_addressed_to_one_target(self):
        for spec in CF.CLOUDFLARE_RADAR_ADAPTER.requests:
            if spec.label in CF.ORIGIN_LABELS:
                assert spec.param_values("location") == ("{country}",)

    def test_the_current_window_is_productions_current_date_range(self):
        specs = {s.label: s for s in CF.CLOUDFLARE_RADAR_ADAPTER.requests}
        for label in (CF.ORIGIN_L3, CF.ORIGIN_L7):
            assert specs[label].param_values("dateRange") == (
                CF.DEFAULT_DATE_RANGE,)

    def test_the_baseline_window_is_28_days_not_90(self):
        """The register (and #116's own entry) called this a 90-day
        baseline. `radar/config.py:148` ships `BASELINE_DATE_RANGE` as
        28d, read here from the source rather than from the value the
        port happened to write."""
        tree = ast.parse((REPO / "radar" / "config.py").read_text())
        default = next(
            node.value.args[1].value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(getattr(t, "id", "") == "BASELINE_DATE_RANGE"
                    for t in node.targets))
        assert default == "28d"
        assert CF.BASELINE_DATE_RANGE == default
        specs = {s.label: s for s in CF.CLOUDFLARE_RADAR_ADAPTER.requests}
        for label in (CF.ORIGIN_L3_BASELINE, CF.ORIGIN_L7_BASELINE):
            assert specs[label].param_values("dateRange") == (default,)

    def test_the_parameter_order_is_productions(self):
        """`{"location": t, "dateRange": ..., "format": "json"}` — a dict
        literal, so insertion order IS the sent order, and the WP-2.6
        sweep found a reordered table."""
        specs = {s.label: s for s in CF.CLOUDFLARE_RADAR_ADAPTER.requests}
        for label in CF.ORIGIN_LABELS:
            assert [key for key, _ in specs[label].params] == [
                "location", "dateRange", "format"]

    def test_the_origin_requests_inherit_the_bearer_token(self):
        """No per-request auth override: the adapter's own applies, and
        `Auth-Key` is what a 403-as-quiet-day looked like (§7-2 #7)."""
        for spec in CF.CLOUDFLARE_RADAR_ADAPTER.requests:
            assert spec.auth is None
        assert CF.CF_AUTH.name == "Authorization"
        assert CF.CLOUDFLARE_RADAR_ADAPTER.rate_limit_group == "cloudflare"
        assert CF.CLOUDFLARE_RADAR_ADAPTER.min_interval_sec == \
            CF.CF_MIN_INTERVAL_SEC


class TestTheOriginRequestExpandsPerCountry:
    def test_the_adapter_is_country_scoped_now(self):
        from v3.runtime.expansion import COUNTRY_SCOPED
        assert "cloudflare_radar" in COUNTRY_SCOPED

    def test_four_global_requests_stay_one_each_and_origins_fan_out(self):
        from v3.fetch.expand import (ExpansionInput, ExpansionScope,
                                     expand_requests)
        scopes = tuple(ExpansionScope(scope_key=c, values={"country": c})
                       for c in ("TW", "JP", "CN"))
        steps = expand_requests(CF.CLOUDFLARE_RADAR_ADAPTER.requests,
                                ExpansionInput(scopes=scopes))
        by_label: dict = {}
        for step in steps:
            by_label.setdefault(step.primary.label, []).append(step)
        for label in ("l3", "l7", "hijacks", "leaks"):
            assert len(by_label[label]) == 1, (
                f"{label} carries no placeholder; three scopes must not "
                f"become three identical rate-limited requests")
        for label in CF.ORIGIN_LABELS:
            assert len(by_label[label]) == 3
            assert {s.scope_key for s in by_label[label]} == {"TW", "JP", "CN"}

    def test_an_expanded_origin_request_names_its_target(self):
        from v3.fetch.expand import (ExpansionInput, ExpansionScope,
                                     expand_requests)
        steps = expand_requests(
            CF.CLOUDFLARE_RADAR_ADAPTER.requests,
            ExpansionInput(scopes=(ExpansionScope(scope_key="TW",
                                                  values={"country": "TW"}),)))
        origin = next(s for s in steps if s.primary.label == CF.ORIGIN_L3)
        assert origin.primary.param_values("location") == ("TW",)


# ══ 2. normalize ═════════════════════════════════════════════════════════

class TestNormalizeReadsTheOriginDistribution:
    def test_one_draft_per_payload_about_the_TARGET_country(self):
        drafts = CF.normalize(
            _origin_payload(CF.ORIGIN_L3, "TW", {"CN": 40.0, "RU": 10.0}),
            _context(("TW", "JP")))
        assert len(drafts) == 1
        assert drafts[0].country == "TW"
        assert drafts[0].signal_source == CF.ORIGIN_SIGNALS[CF.ORIGIN_L3]
        assert drafts[0].flags["origins"] == {"CN": 40.0, "RU": 10.0}

    def test_the_row_carries_no_verdict_of_its_own(self):
        """It is an input to the fold, not a claim: the spike verdict
        needs the baseline half, and `normalize` sees one payload."""
        draft = CF.normalize(
            _origin_payload(CF.ORIGIN_L3, "TW", {"CN": 40.0}),
            _context(("TW",)))[0]
        assert draft.status == STATUS_OBSERVED and draft.raw_score == 0.0

    def test_the_window_travels_with_the_row(self):
        current = CF.normalize(_origin_payload(CF.ORIGIN_L3, "TW",
                                               {"CN": 1.0}),
                               _context(("TW",)))[0]
        baseline = CF.normalize(_origin_payload(CF.ORIGIN_L3_BASELINE, "TW",
                                                {"CN": 1.0}),
                                _context(("TW",)))[0]
        assert current.flags["window"] == CF.DEFAULT_DATE_RANGE
        assert baseline.flags["window"] == CF.BASELINE_DATE_RANGE
        assert current.signal_source != baseline.signal_source

    def test_parse_origins_fallbacks_are_reused_not_rewritten(self):
        """`share_of`'s `or` chain and `location_of`'s key ladder are
        production's `parse_origins` (`scoring.py:659-668`); a second copy
        here is a second thing to keep in step (DP4)."""
        payload = FetchedPayload(
            url="https://api.cloudflare.com/client/v4/radar/attacks/layer7/"
                "top/locations/origin?location=TW",
            status=200, fetched_at=NOW, label=CF.ORIGIN_L7,
            body=json.dumps({"result": {"top_0": [
                {"location": "CN", "value": 0, "count": 7},
                {"clientCountryAlpha2": "RU"}]}}).encode())
        origins = CF.normalize(payload, _context(("TW",)))[0].flags["origins"]
        assert origins == {"CN": 7.0, "RU": 1.0}

    def test_a_payload_whose_target_cannot_be_read_makes_no_claim(self):
        payload = FetchedPayload(
            url="https://api.cloudflare.com/client/v4/radar/attacks/layer3/"
                "top/locations/origin",
            status=200, fetched_at=NOW, label=CF.ORIGIN_L3,
            body=b'{"result": {"top_0": []}}')
        assert CF.normalize(payload, _context(("TW", "JP"))) == ()


# ══ 3. the arithmetic ════════════════════════════════════════════════════

class TestTheArithmeticIsProductions:
    def test_a_worked_case(self):
        result = S.origin_spike(
            current_l3={"CN": 40.0}, current_l7={"CN": 10.0},
            baseline_l3={"CN": 4.0}, baseline_l7={"CN": 5.0},
            adversaries=("CN",))
        # l3_spike = 40/4 = 10; l7_spike = 10/5 = 2; factor = 10
        # current_local_pct = 40 -> weighted = 400, total = 40
        assert result.avg_spike == 10.0
        assert math.isclose(result.avg_l3_spike, 10.0)
        assert math.isclose(result.avg_l7_spike, 2.0)
        assert result.total_local_pct == 40.0

    def test_the_denominator_floor_is_five_percent(self):
        """`max(total_local_pct, 5.0)` — without it a single 1% origin at
        a 2x spike reports 2x on 1% of traffic."""
        result = S.origin_spike(current_l3={"CN": 1.0}, current_l7={},
                                baseline_l3={"CN": 0.5}, baseline_l7={},
                                adversaries=("CN",))
        # factor = 1/0.5 = 2 -> weighted 2.0; total 1.0 -> /5.0
        assert result.avg_spike == 0.4

    def test_the_spike_multiplier_is_capped_at_25(self):
        result = S.origin_spike(current_l3={"CN": 90.0}, current_l7={},
                                baseline_l3={"CN": 0.01}, baseline_l7={},
                                adversaries=("CN",))
        assert result.avg_spike == round(25.0 * 90.0 / 90.0, 2) == 25.0

    def test_origins_below_one_percent_do_not_aggregate(self):
        result = S.origin_spike(current_l3={"CN": 0.9}, current_l7={},
                                baseline_l3={"CN": 0.1}, baseline_l7={},
                                adversaries=("CN",))
        assert result.avg_spike == 0.0 and result.total_local_pct == 0.0

    def test_the_adversary_floor_is_lower_than_the_ordinary_one(self):
        """KP at baseline 0.1% -> 2% is a 4x spike for an adversary and a
        sub-1x reading for anyone else (`core.py:772-777`)."""
        adversary = S.origin_spike(current_l3={"KP": 2.0}, current_l7={},
                                   baseline_l3={"KP": 0.1}, baseline_l7={},
                                   adversaries=("KP",))
        ordinary = S.origin_spike(current_l3={"KP": 2.0}, current_l7={},
                                  baseline_l3={"KP": 0.1}, baseline_l7={},
                                  adversaries=())
        assert adversary.avg_spike > ordinary.avg_spike
        assert S.ADVERSARY_FLOOR < S.EXISTING_ACTOR_FLOOR < S.NEW_ACTOR_FLOOR

    def test_an_empty_baseline_suppresses_the_computation(self):
        """`core.py:762-765`: an empty baseline puts every origin at the
        minimum floor and manufactures 90x false positives."""
        result = S.origin_spike(current_l3={"CN": 40.0}, current_l7={},
                                baseline_l3={}, baseline_l7={},
                                adversaries=("CN",))
        assert result.has_baseline is False
        assert result.avg_spike == 0.0

    def test_a_new_actor_is_one_absent_from_BOTH_baselines(self):
        result = S.origin_spike(current_l3={"CN": 10.0}, current_l7={},
                                baseline_l3={}, baseline_l7={"CN": 9.0},
                                adversaries=())
        assert result.origins["CN"]["is_new_actor"] is False


class TestTheSweepAgreesWithProduction:
    @pytest.mark.parametrize("seed", [20260808, 4711, 90210])
    def test_a_random_sweep_agrees_on_every_input(self, seed):
        rng = random.Random(seed)
        codes = ["CN", "RU", "KP", "IR", "US", "JP", "DE", "BR"]
        disagreements = []
        for _ in range(4000):
            # The ceiling varies so that low-traffic targets — where the
            # 5% denominator floor is what BINDS — are swept as often as
            # busy ones. A sweep over busy targets alone leaves that
            # constant unconstrained, which the mutants then prove.
            ceiling = rng.choice([0.8, 3.0, 60.0])

            def distribution(chance=0.7, top=ceiling):
                return {code: round(rng.uniform(0.0, top), 3)
                        for code in codes if rng.random() < chance}
            o_l3, o_l7 = distribution(), distribution()
            b_l3, b_l7 = distribution(0.5), distribution(0.5)
            adversaries = tuple(c for c in codes if rng.random() < 0.3)
            mine = S.origin_spike(current_l3=o_l3, current_l7=o_l7,
                                  baseline_l3=b_l3, baseline_l7=b_l7,
                                  adversaries=adversaries)
            avg, avg_l3, avg_l7 = _production_avg_spike(
                o_l3, o_l7, b_l3, b_l7, set(adversaries))
            if (mine.avg_spike != avg
                    or not math.isclose(mine.avg_l3_spike, avg_l3,
                                        rel_tol=1e-12, abs_tol=1e-12)
                    or not math.isclose(mine.avg_l7_spike, avg_l7,
                                        rel_tol=1e-12, abs_tol=1e-12)):
                disagreements.append((o_l3, o_l7, b_l3, b_l7, adversaries,
                                      mine.avg_spike, avg))
        assert not disagreements, disagreements[:2]


#: Each mutant is a plausible transcription slip, applied to the module
#: constant itself. The sweep above must catch every one of them, or the
#: sweep is decorative and the constants are unconstrained.
MUTANTS = {
    "cap_removed": ("SPIKE_CAP", 1e9),
    "cap_at_20": ("SPIKE_CAP", 20.0),
    "denominator_floor_removed": ("DENOMINATOR_FLOOR", 0.0),
    "denominator_floor_at_one": ("DENOMINATOR_FLOOR", 1.0),
    "inclusion_gate_off": ("INCLUSION_PCT", 0.0),
    "inclusion_gate_at_two": ("INCLUSION_PCT", 2.0),
    "adversary_floor_raised": ("ADVERSARY_FLOOR", 3.0),
    "new_actor_floor_lowered": ("NEW_ACTOR_FLOOR", 2.0),
    "existing_floor_raised": ("EXISTING_ACTOR_FLOOR", 3.0),
    "rounding_widened": ("ROUND_DIGITS", 6),
    "z_threshold_raised": ("Z_THRESHOLDS", (2.0, 2.5, 3.5)),
    "warmup_threshold_raised": ("WARMUP_THRESHOLDS", (3.0, 4.0, 6.0)),
    "warmup_minimum_lowered": ("HOD_MIN_SAMPLES", 3),
    "std_floor_lowered": ("HOD_STD_FLOOR", 0.01),
}


class TestTheMutantsAreCaught:
    @staticmethod
    def _inputs(rng, codes):
        ceiling = rng.choice([0.8, 3.0, 60.0])

        def distribution(chance, top):
            return {c: round(rng.uniform(0.0, top), 3) for c in codes
                    if rng.random() < chance}
        return (distribution(0.8, ceiling), distribution(0.8, ceiling),
                distribution(0.6, 20.0), distribution(0.6, 20.0),
                tuple(c for c in codes if rng.random() < 0.4))

    @staticmethod
    def _ladder_disagrees():
        """A deterministic probe either side of every declared threshold.

        Deterministic on purpose: a random stream that happens not to land
        between 1.5 and 2.0 sigma would report a threshold mutant as
        uncaught for reasons that have nothing to do with the threshold.
        """
        probes = [([0.0] * 7, round(target * 0.15, 9))
                  for target in (1.4, 1.6, 2.4, 2.6, 3.4, 3.6)]
        probes += [([0.0] * samples, spike)
                   for samples in (0, 2, 6, 7)
                   for spike in (1.9, 2.1, 4.1, 6.1)]
        for history, spike in probes:
            verdict = S.spike_verdict(history, spike)
            reference = S.phase_zscore(history, spike, min_samples=7,
                                       std_floor=0.15)
            score, fired = _production_spike_ladder(
                reference.z if reference.valid else 0.0, reference.valid,
                reference.n, spike)
            if (verdict.score, verdict.fired) != (float(score), fired):
                return True
        return False

    @pytest.mark.parametrize("name", sorted(MUTANTS))
    def test_a_mutated_constant_disagrees_with_production(self, name,
                                                          monkeypatch):
        attribute, value = MUTANTS[name]
        monkeypatch.setattr(S, attribute, value)
        if self._ladder_disagrees():
            return
        rng = random.Random(31337)
        codes = ["CN", "RU", "KP", "US", "JP"]
        for _ in range(2000):
            o_l3, o_l7, b_l3, b_l7, adversaries = self._inputs(rng, codes)
            try:
                mutated = S.origin_spike(current_l3=o_l3, current_l7=o_l7,
                                         baseline_l3=b_l3, baseline_l7=b_l7,
                                         adversaries=adversaries)
            except ZeroDivisionError:
                return          # a floor of zero divides by an empty tick
            avg, _, _ = _production_avg_spike(o_l3, o_l7, b_l3, b_l7,
                                              set(adversaries))
            if mutated.avg_spike != avg:
                return
        pytest.fail(f"mutant {name!r} was never caught: the sweep does not "
                    f"constrain that constant")


# ══ 4. the verdict that was withheld ═════════════════════════════════════

class TestTheSpikeVerdictIsLive:
    def test_the_thresholds_are_productions(self):
        assert S.Z_THRESHOLDS == (1.5, 2.5, 3.5)
        assert S.WARMUP_THRESHOLDS == (2.0, 4.0, 6.0)
        from radar.config import HOD_MIN_SAME_HOUR
        assert S.HOD_MIN_SAMPLES == HOD_MIN_SAME_HOUR

    @pytest.mark.parametrize("z,score,fired", [
        (1.4, 0, False), (1.6, 1, True), (2.6, 2, True), (3.6, 3, True)])
    def test_the_z_ladder(self, z, score, fired):
        history = [0.0] * 7
        # mean 0, std floored at 0.15 -> current = z * 0.15
        verdict = S.spike_verdict(history, round(z * S.HOD_STD_FLOOR, 6))
        assert verdict.valid is True
        assert verdict.score == score and verdict.fired is fired

    @pytest.mark.parametrize("spike,score,fired", [
        (1.9, 0, False), (2.1, 1, True), (4.1, 2, True), (6.1, 3, True)])
    def test_the_warmup_ladder(self, spike, score, fired):
        verdict = S.spike_verdict([1.0, 2.0], spike)
        assert verdict.valid is False
        assert verdict.score == score and verdict.fired is fired

    def test_warmup_is_below_seven_same_hour_samples(self):
        assert S.spike_verdict([1.0] * 6, 9.0).valid is False
        assert S.spike_verdict([1.0] * 7, 9.0).valid is True

    def test_the_standard_deviation_floor_is_015(self):
        """A perfectly flat baseline would otherwise divide by zero and
        make every reading infinitely anomalous."""
        assert S.HOD_STD_FLOOR == 0.15
        verdict = S.spike_verdict([2.0] * 7, 2.15)
        assert math.isclose(verdict.z, 1.0, rel_tol=1e-9)

    def test_the_printed_value_and_reason_are_productions(self):
        verdict = S.spike_verdict([0.0] * 7, 1.0)
        assert verdict.value == f"HOD Z={verdict.z:.2f} (1.00x, n=7)"
        assert verdict.reason.startswith(f"HOD Z-score={verdict.z:.2f}")
        warm = S.spike_verdict([0.0], 3.0)
        assert warm.value == f"3.00x (HOD warmup 1/{S.HOD_MIN_SAMPLES})"
        assert warm.reason == ("Core theater spike exceeds 2x baseline "
                               "(HOD warmup)")

    def test_a_quiet_reading_carries_no_reason(self):
        assert S.spike_verdict([0.0], 1.0).reason == ""

    @pytest.mark.parametrize("seed", [11, 22])
    def test_the_ladder_sweep_agrees_with_production(self, seed):
        rng = random.Random(seed)
        for _ in range(5000):
            history = [rng.uniform(0.0, 25.0)
                       for _ in range(rng.randint(0, 20))]
            current = round(rng.uniform(0.0, 25.0), 2)
            mine = S.spike_verdict(history, current)
            score, fired = _production_spike_ladder(
                mine.z if mine.valid else 0.0, mine.valid, mine.n, current)
            assert (mine.score, mine.fired) == (float(score), fired)


# ══ 5. the fold: four payloads become production's one entry ═════════════

def _reduce(drafts, baselines=None):
    return R.reduce_drafts("cloudflare_radar", drafts,
                           baselines=dict(baselines or {}), now=NOW)


class TestTheFoldProducesProductionsEntry:
    def test_the_four_origin_rows_become_one_cf_spike_core(self):
        drafts = _origin_drafts("TW", l3={"CN": 40.0}, l7={"CN": 10.0},
                                base_l3={"CN": 4.0}, base_l7={"CN": 5.0})
        reduced = _reduce(drafts, {B.ADVERSARY_ORIGINS: ("CN",)})
        sources = [d.signal_source for d in reduced]
        assert sources == [CF.SPIKE_SIGNAL]
        assert reduced[0].country == "TW"
        assert reduced[0].flags["avg_spike"] == 10.0

    def test_the_intermediate_rows_do_not_reach_the_ledger(self):
        """L1 is UNIQUE on `(tick_id, sensor, signal_source, country)` and
        production writes ONE rationale entry per country per cycle
        (`core.py:1025`); four OBSERVED inputs beside it would be four
        rows production never wrote."""
        reduced = _reduce(_origin_drafts("TW", l3={"CN": 40.0},
                                         l7={}, base_l3={"CN": 4.0},
                                         base_l7={}))
        assert not any(d.signal_source in CF.ORIGIN_SIGNALS.values()
                       for d in reduced)

    def test_the_bgp_fold_still_happens_beside_it(self):
        bgp = ObservationDraft(signal_source=CF.BGP_HIJACK_SIGNAL,
                               domain=CYBER, country="TW",
                               status=STATUS_FIRED, raw_score=1.0,
                               flags={"count": 2, "ongoing": 1})
        reduced = _reduce((bgp,) + _origin_drafts(
            "TW", l3={"CN": 40.0}, l7={}, base_l3={"CN": 4.0}, base_l7={}))
        assert {d.signal_source for d in reduced} == {
            CF.BGP_HIJACK_SIGNAL, CF.SPIKE_SIGNAL}

    def test_the_verdict_fires_with_the_score_production_gives(self):
        history = tuple([0.5] * 7)
        drafts = _origin_drafts("TW", l3={"CN": 40.0}, l7={},
                                base_l3={"CN": 1.0}, base_l7={})
        reduced = _reduce(drafts, {
            B.ADVERSARY_ORIGINS: ("CN",),
            "cf_attack_share_baseline": {"TW": history}})
        row = reduced[0]
        assert row.status == STATUS_FIRED
        assert row.raw_score == 3.0
        assert row.flags["hod_n"] == 7

    def test_a_cold_baseline_takes_productions_warmup_branch(self):
        drafts = _origin_drafts("TW", l3={"CN": 40.0}, l7={},
                                base_l3={"CN": 1.0}, base_l7={})
        reduced = _reduce(drafts, {B.ADVERSARY_ORIGINS: ("CN",),
                                   "cf_attack_share_baseline": {"TW": ()}})
        assert reduced[0].status == STATUS_FIRED
        assert reduced[0].flags["hod_n"] == 0
        assert "HOD warmup" in reduced[0].value

    def test_a_quiet_country_is_OK_not_withheld(self):
        drafts = _origin_drafts("TW", l3={"CN": 4.0}, l7={},
                                base_l3={"CN": 4.0}, base_l7={})
        row = _reduce(drafts, {"cf_attack_share_baseline": {"TW": ()}})[0]
        assert row.status == STATUS_OK and row.raw_score == 0.0
        assert not any(str(v).startswith("pending_l1_")
                       for v in row.flags.values())

    def test_the_disclosure_carries_the_whole_derivation(self):
        drafts = _origin_drafts("TW", l3={"CN": 40.0}, l7={"CN": 10.0},
                                base_l3={"CN": 4.0}, base_l7={"CN": 5.0})
        flags = _reduce(drafts, {B.ADVERSARY_ORIGINS: ("CN",)})[0].flags
        for key in ("avg_spike", "avg_l3_spike", "avg_l7_spike",
                    "total_local_pct", "has_baseline", "origins",
                    "origin_baseline", "adversary_origins", "hod_z",
                    "hod_n"):
            assert key in flags, key
        assert flags["origins"]["CN"]["spike_factor"] == 10.0

    def test_two_countries_fold_independently(self):
        drafts = (_origin_drafts("TW", l3={"CN": 40.0}, l7={},
                                 base_l3={"CN": 4.0}, base_l7={})
                  + _origin_drafts("JP", l3={"CN": 4.0}, l7={},
                                   base_l3={"CN": 4.0}, base_l7={}))
        reduced = {d.country: d for d in _reduce(drafts)}
        assert reduced["TW"].flags["avg_spike"] > \
            reduced["JP"].flags["avg_spike"]

    def test_a_country_with_no_current_payload_makes_no_row(self):
        """A fetch that did not happen is not a measurement of calm."""
        drafts = _origin_drafts("TW", l3=None, l7=None,
                                base_l3={"CN": 4.0}, base_l7=None)
        assert _reduce(drafts) == ()


class TestTheStoredBaselineIsTheFallback:
    """Production keeps the origin baseline in the DB and refreshes it
    only when it is over a day old (`core.py:738-742`), and its fetch
    helper preserves a stale entry when a call comes back empty
    (`scoring.py:648-654`). A v3 cycle whose baseline request failed must
    therefore fall back rather than compute against nothing — computing
    against nothing is the `has_baseline` guard, which reports 0.0."""

    def test_an_empty_baseline_payload_falls_back_to_the_stored_one(self):
        drafts = _origin_drafts("TW", l3={"CN": 40.0}, l7={},
                                base_l3={}, base_l7={})
        stored = {"TW": [{"observed_at": NOW - HOUR,
                          "payload": {"l3": {"CN": 4.0}, "l7": {}}}]}
        row = _reduce(drafts, {B.ADVERSARY_ORIGINS: ("CN",),
                               "cf_origin_baseline": stored})[0]
        assert row.flags["has_baseline"] is True
        assert row.flags["avg_spike"] == 10.0
        assert row.flags["baseline_source"] == "stored"

    def test_a_fresh_baseline_beats_the_stored_one(self):
        drafts = _origin_drafts("TW", l3={"CN": 40.0}, l7={},
                                base_l3={"CN": 8.0}, base_l7={})
        stored = {"TW": [{"observed_at": NOW - HOUR,
                          "payload": {"l3": {"CN": 1.0}, "l7": {}}}]}
        row = _reduce(drafts, {B.ADVERSARY_ORIGINS: ("CN",),
                               "cf_origin_baseline": stored})[0]
        assert row.flags["avg_spike"] == 5.0
        assert row.flags["baseline_source"] == "fetched"

    def test_no_baseline_anywhere_reports_productions_zero(self):
        drafts = _origin_drafts("TW", l3={"CN": 40.0}, l7={},
                                base_l3={}, base_l7={})
        row = _reduce(drafts, {B.ADVERSARY_ORIGINS: ("CN",)})[0]
        assert row.flags["has_baseline"] is False
        assert row.flags["avg_spike"] == 0.0
        assert row.status == STATUS_OK


# ══ 6. the ledger: the baseline is stored, the HOD series advances ══════

class TestTheBaselineIsSupplied:
    def test_the_adapter_declares_both_baselines_it_needs(self):
        assert set(CF.CLOUDFLARE_RADAR_ADAPTER.baseline_refs) == {
            "cf_attack_share_baseline", "cf_origin_baseline"}

    def test_the_origin_baseline_is_a_per_country_entity_series(self):
        entry = B.ENTITY_BASELINES["cf_origin_baseline"]
        assert entry.entity_kind == "country"
        assert entry.per_entity == 1, (
            "production holds ONE snapshot per target (`baseline_set`), "
            "not a series; a deeper series would be a window production "
            "does not have")

    def test_the_retention_policy_did_not_have_to_move(self):
        """The 28-day window lives in the QUERY STRING, not in the
        ledger: what is stored is one daily-refreshed snapshot per
        target, so `entity_observation`'s 30-day horizon is already an
        order of magnitude longer than the row's lifetime."""
        from v3.ledger.schema import (ENTITY_SERIES_RETENTION_DAYS,
                                      RETENTION_POLICIES)
        policy = next(p for p in RETENTION_POLICIES
                      if p.table == "entity_observation")
        assert policy.retention_days == ENTITY_SERIES_RETENTION_DAYS == 30
        assert CF.CLOUDFLARE_RADAR_ADAPTER.cadence.cadence_sec <= 86400.0

    def test_the_withheld_verdict_is_gone_from_the_account(self):
        from v3.adapters.catalog import build_registry
        report = B.coverage(build_registry().all())
        assert "cf_attack_share_baseline" in report["answered"]
        assert "cf_origin_baseline" in report["answered"]
        assert report["withheld"] == {}

    def test_the_family_row_still_has_unanswered_members(self):
        """§7-2 #9 is a family. Its cloudflare member closing does not
        make the row retirable on its own."""
        from v3.adapters.catalog import build_registry
        report = B.coverage(build_registry().all())
        assert report["unanswered"]


class TestTheCycleRecordsWhatTheNextOneReads:
    def _write_spike_row(self, store, *, country="TW", avg=4.0, now=NOW,
                         baseline=None):
        from v3.kernel import Evidence
        from v3.ledger.records import SignalObservation
        flags = {"avg_spike": avg,
                 "origin_baseline": baseline if baseline is not None
                 else {"l3": {"CN": 4.0}, "l7": {}}}
        store.append_signal(SignalObservation(
            tick_id=f"t{int(now)}", sensor="cloudflare_radar",
            signal_source=CF.SPIKE_SIGNAL, domain="cyber", country=country,
            evidence=Evidence.observe(flags, observed_at=now,
                                      freshness_horizon_sec=86400.0,
                                      source="cloudflare_radar"),
            status="OBSERVED", raw_score=0.0, flags=flags), now=now)

    def test_the_hod_sample_is_the_avg_spike_just_written(self, store):
        self._write_spike_row(store, avg=4.25, now=NOW - 1)
        written = REC.record_cycle(store, now=NOW, countries=["TW"])
        assert written["cf_attack_share_baseline"] == 1
        entry = B.PHASE_BASELINES["cf_attack_share_baseline"]
        row = store.read_baseline(entry.baseline_id, sensor=entry.sensor,
                                  country="TW", bucket=entry.bucket_of(NOW))
        assert row is not None and row["mean"] == 4.25

    def test_the_hour_is_sampled_once(self, store):
        """`record_hod_sample` skips a bucket it already holds
        (`scoring.py:466-470`) — the hour's sample is its FIRST reading."""
        self._write_spike_row(store, avg=4.0, now=NOW - 2)
        REC.record_cycle(store, now=NOW, countries=["TW"])
        self._write_spike_row(store, avg=9.0, now=NOW - 1)
        again = REC.record_cycle(store, now=NOW + 60, countries=["TW"])
        assert again["cf_attack_share_baseline"] == 0

    def test_the_origin_baseline_snapshot_is_stored(self, store):
        self._write_spike_row(store, now=NOW - 1,
                              baseline={"l3": {"CN": 4.0}, "l7": {"RU": 2.0}})
        written = REC.record_cycle(store, now=NOW, countries=["TW"])
        assert written["cf_origin_baseline"] == 1
        read = B.entity_history(store)["cf_origin_baseline"]
        assert read["TW"][0]["payload"] == {"l3": {"CN": 4.0},
                                            "l7": {"RU": 2.0}}

    def test_only_one_snapshot_per_target_is_kept(self, store):
        self._write_spike_row(store, now=NOW - 2)
        REC.record_cycle(store, now=NOW - 1, countries=["TW"])
        self._write_spike_row(store, now=NOW,
                              baseline={"l3": {"CN": 9.0}, "l7": {}})
        REC.record_cycle(store, now=NOW + 1, countries=["TW"])
        read = B.entity_history(store)["cf_origin_baseline"]
        assert len(read["TW"]) == 1
        assert read["TW"][0]["payload"]["l3"] == {"CN": 9.0}

    def test_an_absent_baseline_writes_nothing_rather_than_an_empty_one(
            self, store):
        self._write_spike_row(store, now=NOW - 1, baseline={})
        written = REC.record_cycle(store, now=NOW, countries=["TW"])
        assert written["cf_origin_baseline"] == 0


# ══ 7. the ranking, and which quantity it used ═══════════════════════════

DUAL = "middle_east"


def _scenario(cores=("IL", "IR")):
    from v3.scoring import Participant, Scenario
    return Scenario(
        scenario_id=DUAL,
        participants=tuple(Participant(country=c, weight=1.0,
                                       role=CHAIN.PRINCIPAL_BELLIGERENT)
                           for c in cores))


def _obs(country, score, sensor="cloudflare_radar"):
    from v3.kernel import Ratio
    from v3.scoring import CountryWeight, Observation
    return Observation(sensor=sensor, domain="cyber", status="FIRED",
                       score=score, signal_source=sensor,
                       countries=(CountryWeight(country=country,
                                                weight=Ratio(1.0)),))


class TestTheChainOwnerIsRankedByAvgSpike:
    def test_the_measured_spike_decides_when_it_exists(self):
        scenario = _scenario()
        # The admitted evidence favours IL; the measured spike favours IR.
        observations = (_obs("IL", 9.0), _obs("IR", 1.0))
        spikes = {"IL": 1.0, "IR": 8.0}
        assert CHAIN.chain_owner(scenario, observations, spikes=spikes) == "IR"

    def test_a_core_without_a_reading_scores_zero_as_production_does(self):
        """`target_details.get(ec, {}).get('avg_spike', 0)` — production's
        own default for a target it has no row for."""
        scenario = _scenario()
        spikes = {"IR": 0.4}
        assert CHAIN.chain_owner(_scenario(), (), spikes=spikes) == "IR"
        assert CHAIN.escalation_intensity((), "IL", spikes=spikes) == 0.0
        assert scenario  # the same scenario object is reusable

    def test_no_measured_spike_anywhere_falls_back_to_admitted_evidence(self):
        observations = (_obs("IL", 9.0), _obs("IR", 1.0))
        assert CHAIN.chain_owner(_scenario(), observations, spikes={}) == "IL"

    def test_the_fallback_is_not_a_constant(self):
        """The WP-4.4 ruling forbade a static answer; the fallback is
        still a live measurement, just a different one."""
        assert CHAIN.chain_owner(
            _scenario(), (_obs("IL", 1.0), _obs("IR", 9.0)), spikes={}) == "IR"

    def test_a_tie_resolves_the_way_productions_max_does(self):
        """`max` returns the FIRST maximal element and production's core
        list is sorted, so a quiet tick picks alphabetically."""
        assert CHAIN.chain_owner(_scenario(), (),
                                 spikes={"IL": 2.0, "IR": 2.0}) == "IL"

    def test_which_quantity_was_used_is_disclosed(self):
        measured = CHAIN.rankings((_scenario(),), (), spikes={"IR": 3.0})
        assert measured[DUAL]["basis"] == CHAIN.BASIS_AVG_SPIKE
        assert measured[DUAL]["values"] == {"IL": 0.0, "IR": 3.0}
        assert measured[DUAL]["owner"] == "IR"
        fallback = CHAIN.rankings((_scenario(),), (_obs("IL", 2.0),),
                                  spikes={})
        assert fallback[DUAL]["basis"] == CHAIN.BASIS_ADMITTED_EVIDENCE
        assert fallback[DUAL]["production_ref"]

    def test_the_disclosure_names_production_for_the_measured_basis(self):
        measured = CHAIN.rankings((_scenario(),), (), spikes={"IR": 3.0})
        assert "core.py:817" in measured[DUAL]["production_ref"]

    def test_a_scenario_with_no_cores_is_absent_from_both(self):
        from v3.scoring import Participant, Scenario
        hollow = Scenario(scenario_id="hollow",
                          participants=(Participant(country="TW", weight=0.4,
                                                    role="forward_base"),))
        assert CHAIN.chain_owners((hollow,), (), spikes={"TW": 9.0}) == {}
        assert CHAIN.rankings((hollow,), (), spikes={"TW": 9.0}) == {}


class TestTheRankingReadsTheLedger:
    def test_assemble_ranks_by_the_spike_row_it_finds(self, store, tmp_path):
        from v3.kernel import Evidence
        from v3.ledger.records import SignalObservation
        from v3.runtime.scoring import assemble
        from v3.scoring import ScoringSettings

        for country, avg, score in (("IL", 1.0, 9.0), ("IR", 8.0, 1.0)):
            flags = {"avg_spike": avg}
            store.append_signal(SignalObservation(
                tick_id="t1", sensor="cloudflare_radar",
                signal_source=CF.SPIKE_SIGNAL, domain="cyber",
                country=country,
                evidence=Evidence.observe(flags, observed_at=NOW - 10,
                                          freshness_horizon_sec=86400.0,
                                          source="cloudflare_radar"),
                status="FIRED", raw_score=score, flags=flags), now=NOW - 10)
        inputs = assemble(now=NOW, store=store, settings=ScoringSettings(),
                          scenarios=(_scenario(),))
        assert inputs.chain_countries[DUAL] == "IR"

    def test_the_spike_read_is_the_ticks_window_only(self, store):
        from v3.runtime.scoring import spike_intensity
        from v3.kernel import Evidence
        from v3.ledger.records import SignalObservation
        stale = {"avg_spike": 9.0}
        store.append_signal(SignalObservation(
            tick_id="t0", sensor="cloudflare_radar",
            signal_source=CF.SPIKE_SIGNAL, domain="cyber", country="IL",
            evidence=Evidence.observe(stale, observed_at=NOW - 100000,
                                      freshness_horizon_sec=86400.0,
                                      source="cloudflare_radar"),
            status="FIRED", raw_score=1.0, flags=stale), now=NOW - 100000)
        assert spike_intensity(store, now=NOW, tick_interval_sec=900.0) == {}


# ══ 8. end to end: the fetch has a consumer ══════════════════════════════

GEO_DOC = {
    "COUNTRY_COORDS": {"IL": {"lat": 31.0, "lng": 35.0, "name": "Israel"},
                       "IR": {"lat": 32.0, "lng": 53.0, "name": "Iran"}},
    "SCENARIOS": {DUAL: {"participants": {
        "IL": {"weight": 1.0, "role": "principal_belligerent"},
        "IR": {"weight": 1.0, "role": "principal_belligerent"},
        "CN": {"weight": 0.6, "role": "adversary"}}}},
}

#: IR is being hit four times harder than IL, from the same origin, in a
#: cycle where the ADMITTED EVIDENCE is deliberately equal — so only the
#: measured spike can decide, and the assertion cannot pass by accident.
_CURRENT = {"IL": {"CN": 8.0}, "IR": {"CN": 32.0}}
_BASELINE = {"IL": {"CN": 8.0}, "IR": {"CN": 8.0}}


class _SpikeClient:
    """Answers Cloudflare's eight requests. Never touches a socket."""

    def __init__(self):
        self.sent = []

    def fetch(self, spec, *, now, auth=None, **kwargs):
        self.sent.append(spec)
        target = dict(spec.params).get("location", "")
        if spec.label in (CF.ORIGIN_L3, CF.ORIGIN_L7):
            body = _CURRENT.get(target, {})
        elif spec.label in (CF.ORIGIN_L3_BASELINE, CF.ORIGIN_L7_BASELINE):
            body = _BASELINE.get(target, {})
        else:
            body = {}
        rows = [{"origin1": code, "value": pct} for code, pct in body.items()]
        payload = FetchedPayload(
            url=spec.url + (f"?location={target}" if target else ""),
            status=200, fetched_at=NOW, content_type="application/json",
            label=spec.label,
            body=json.dumps({"result": {"top_0": rows}}).encode())
        return type("Outcome", (), {
            "outcome": "ok", "url": payload.url, "status": 200,
            "latency_ms": 1.0, "attempts": 1, "detail": "",
            "body_sha256": "0" * 64, "url_sha256": "1" * 64,
            "payload": payload, "succeeded": True})()

    def pause(self, seconds):
        pass


@pytest.fixture
def deployment(tmp_path):
    from v3.config.resolution import ConfigResolver
    from v3.fetch.registry import AdapterRegistry
    from v3.runtime import geo as geo_module
    instance = LedgerStore(str(tmp_path / "e2e.db"))
    yield (instance, AdapterRegistry([CF.CLOUDFLARE_RADAR_ADAPTER]),
           geo_module.from_document(GEO_DOC), ConfigResolver())
    instance.close()


class TestTheWholeThingRuns:
    """A fetch with no consumer is not shipped. This is the consumer.

    One tick, the real adapter, a fake transport: the origin requests go
    out addressed to each participant, the fold turns four payloads into
    production's one `cf_spike_core` row, the row reaches L1, the recorder
    stores the baseline the NEXT cycle falls back to, and the chain owner
    is ranked by the number that came out of it.
    """

    @staticmethod
    def _run(deployment, now=NOW):
        from v3.runtime import tick as tick_module
        store, registry, geography, resolver = deployment
        return store, tick_module.run_tick(
            now=now, registry=registry, store=store, client=_SpikeClient(),
            geography=geography, scenario_ids=(DUAL,), config=resolver)

    def test_the_origin_requests_go_out_once_per_participant(self,
                                                            deployment):
        from v3.runtime import tick as tick_module
        store, registry, geography, _ = deployment
        client = _SpikeClient()
        tick_module.run_tick(now=NOW, registry=registry, store=store,
                             client=client, geography=geography,
                             scenario_ids=(DUAL,))
        origin = [s for s in client.sent if s.label in CF.ORIGIN_LABELS]
        # four origin declarations x three participants
        assert len(origin) == 12
        assert {dict(s.params)["location"] for s in origin} == {"IL", "IR",
                                                               "CN"}
        # the four that carry no placeholder are still sent ONCE
        assert len([s for s in client.sent
                    if s.label not in CF.ORIGIN_LABELS]) == 4

    def test_the_spike_row_reaches_the_ledger(self, deployment):
        store, report = self._run(deployment)
        row = store.latest_signal_at(NOW, sensor="cloudflare_radar",
                                     country="IR",
                                     signal_source=CF.SPIKE_SIGNAL)
        assert row is not None
        flags = json.loads(row["flags"])
        assert flags["avg_spike"] == 4.0
        assert flags["baseline_source"] == "fetched"
        assert report.observations_written > 0

    def test_none_of_the_intermediate_rows_reach_the_ledger(self,
                                                            deployment):
        store, _ = self._run(deployment)
        sources = {r["signal_source"] for r in
                   store.signals_between(NOW - 1, NOW + 1)}
        assert not sources & set(CF.ORIGIN_SIGNALS.values())
        assert CF.SPIKE_SIGNAL in sources

    def test_the_declared_adversary_reaches_the_floor(self, deployment):
        """`geo`'s role, through the composition root, into the arithmetic
        that decides whether a 2% origin is an attack."""
        store, _ = self._run(deployment)
        row = store.latest_signal_at(NOW, sensor="cloudflare_radar",
                                     country="IR",
                                     signal_source=CF.SPIKE_SIGNAL)
        assert json.loads(row["flags"])["adversary_origins"] == ["CN"]

    def test_the_cycle_stores_the_baseline_the_next_one_falls_back_to(
            self, deployment):
        store, _ = self._run(deployment)
        stored = B.entity_history(store)["cf_origin_baseline"]
        assert stored["IR"][0]["payload"]["l3"] == {"CN": 8.0}

    def test_the_hod_series_advances_from_the_row_just_written(self,
                                                               deployment):
        store, _ = self._run(deployment)
        entry = B.PHASE_BASELINES["cf_attack_share_baseline"]
        row = store.read_baseline(entry.baseline_id, sensor=entry.sensor,
                                  country="IR",
                                  bucket=entry.bucket_of(NOW))
        assert row is not None and row["mean"] == 4.0

    def test_the_chain_owner_is_the_country_with_the_measured_spike(
            self, deployment):
        store, report = self._run(deployment)
        assert report.chain_owners[DUAL] == "IR"
        assert report.chain_ranking[DUAL]["basis"] == CHAIN.BASIS_AVG_SPIKE
        # IL is at its own baseline (8/8 = 1.0x); IR is at four times its
        # own (32/8), and both denominators are above the 5% floor.
        assert report.chain_ranking[DUAL]["values"] == {"IL": 1.0, "IR": 4.0}
        assert report.as_dict()["chain_ranking"][DUAL]["owner"] == "IR"

    def test_a_tick_that_measured_nothing_discloses_the_fallback(
            self, deployment):
        """The registered residual of §7-2 #116, made visible rather than
        assumed: with no origin payload there is no spike, and the report
        says which quantity ranked instead."""
        from v3.fetch.registry import AdapterRegistry
        from v3.runtime import tick as tick_module
        store, _, geography, resolver = deployment
        empty = AdapterRegistry([])
        report = tick_module.run_tick(
            now=NOW, registry=empty, store=store, client=_SpikeClient(),
            geography=geography, scenario_ids=(DUAL,), config=resolver)
        assert report.chain_ranking[DUAL]["basis"] == \
            CHAIN.BASIS_ADMITTED_EVIDENCE
        assert report.chain_owners[DUAL] == "IL"      # the tie, alphabetical
