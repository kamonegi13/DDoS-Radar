"""WP-2.6 — the seven cyber adapters, against recorded payloads.

Same discipline as the physical suite: fixtures are the upstream, no test
reaches the network, and every assertion traces to an S1 clause or to the
consumer in `radar/routes/core.py` that the port has to reproduce.
"""
import ast
import json
from email.utils import format_datetime
from datetime import datetime, timezone
from pathlib import Path

import pytest

from v3.adapters.cyber import (apt_intel, cloudflare_radar, ct_log, greynoise,
                               ooni_censorship, ripe_bgp, threatfox)
from v3.adapters.types import (AdapterId, FetchedPayload, NormalizeContext,
                               STATUS_FIRED, STATUS_NO_DATA, STATUS_OBSERVED,
                               STATUS_OK, STATUS_SUPPRESSED)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adapters"
T0 = 1_700_000_000.0


def legacy_source(relative_path: str) -> str:
    """The text of a live module, read but never imported.

    `ast`/text rather than `import` because importing `radar.*` drags in
    the whole legacy package — configuration, database handles and all —
    and the discipline gate forbids it at test time.
    """
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def literal_in(relative_path: str, name: str):
    """A named literal from anywhere in a module — module level or class body.

    Class level matters: `nasa_firms._THEATER_RADIUS` and
    `checkhost.CHECKHOST_NODES` are attributes, not globals, and a helper
    that only walked `ast.Assign` at module scope would report them
    missing rather than compare them.
    """
    for node in ast.walk(ast.parse(legacy_source(relative_path))):
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == name \
                    and node.value is not None:
                return ast.literal_eval(node.value)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == name:
                    return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a literal in {relative_path}")


def dict_containing(relative_path: str, key: str) -> dict:
    """The first dict literal in a module that carries `key`.

    Several legacy values live inside a function rather than at module
    scope — the AISHub query string, IHR's per-endpoint parameters — so
    there is no name to look up. Locating them by a key they contain is
    still a comparison against the live source, which is the property that
    matters: the test fails when production changes, not when someone
    remembers to update a copy.

    Values that are literals come back evaluated; values that are
    expressions come back as their source text (`"cp_lat - 0.5"`), which is
    still enough to pin a constant embedded in one.
    """
    for node in ast.walk(ast.parse(legacy_source(relative_path))):
        if not isinstance(node, ast.Dict):
            continue
        entries = {}
        for name_node, value_node in zip(node.keys, node.values):
            if not (isinstance(name_node, ast.Constant)
                    and isinstance(name_node.value, str)):
                continue
            try:
                entries[name_node.value] = ast.literal_eval(value_node)
            except ValueError:
                entries[name_node.value] = ast.unparse(value_node)
        if key in entries:
            return entries
    raise AssertionError(f"no dict literal with key {key!r} in {relative_path}")


def legacy_literal(module: str, name: str):
    """A module-level literal read out of a live sensor, without importing it."""
    return literal_in(f"radar/sensors/{module}.py", name)


def payload(adapter: str, name: str, *, url="https://upstream.test/x",
            label="", status=200, content_type="application/json"
            ) -> FetchedPayload:
    body = (FIXTURES / adapter / name).read_bytes()
    return FetchedPayload(url=url, status=status, body=body, fetched_at=T0,
                          content_type=content_type, label=label)


def context(adapter_id: str, **overrides) -> NormalizeContext:
    base = {"adapter_id": AdapterId(adapter_id), "now": T0,
            "countries": ("TW",)}
    base.update(overrides)
    return NormalizeContext(**base)


def synthetic(body: bytes, *, label="", url="https://upstream.test/x",
              content_type="application/json") -> FetchedPayload:
    """A payload built in the test rather than recorded.

    Used only where the assertion is about a COUNT or an AGE — a fixture
    would have to be regenerated to change either, and an age fixture
    would additionally have to move whenever `T0` did.
    """
    return FetchedPayload(url=url, status=200, body=body, fetched_at=T0,
                          content_type=content_type, label=label)


# ── greynoise (K11, K15) ────────────────────────────────────────────────

class TestGreynoise:
    def test_noise_dominant_traffic_suppresses_its_own_entry(self):
        draft = greynoise.normalize(
            payload("greynoise", "gnql_stats.json",
                    url="https://api.greynoise.io/v2/experimental/gnql/"
                        "stats?query=x", label="gnql:TW"),
            context("greynoise"))[0]
        assert draft.status == STATUS_SUPPRESSED
        assert draft.suppressed is True
        assert draft.flags["noise_class"] == "NOISE_DOMINANT"

    def test_a_suppressor_never_adds_score(self):
        for name in ("gnql_stats.json", "gnql_stats_targeted.json"):
            draft = greynoise.normalize(
                payload("greynoise", name, label="gnql:TW"),
                context("greynoise"))[0]
            assert draft.raw_score == 0.0

    def test_targeted_traffic_does_not_suppress(self):
        draft = greynoise.normalize(
            payload("greynoise", "gnql_stats_targeted.json",
                    label="gnql:TW"), context("greynoise"))[0]
        assert draft.flags["noise_class"] == "TARGETED"
        assert draft.suppressed is False

    @pytest.mark.parametrize("body", [b"not json at all", b"null", b"[]",
                                      b'{"stats": "unexpected"}',
                                      b'{"stats": {"classifications": 7}}'])
    def test_an_unobtainable_ratio_is_unknown_with_suppression_off(self, body):
        """NP1: "could not measure" must never become "this is noise".

        Unobtainable means the shape the ratio is read from was not
        there. Each of these bodies is one production reaches through its
        `except Exception: return {}` (`radar/sensors/greynoise.py:204`),
        which becomes `noise_ratio=None` and UNKNOWN (`:229-240`).
        """
        broken = FetchedPayload(url="https://x.test", status=200, body=body,
                                fetched_at=T0, label="gnql:TW")
        draft = greynoise.normalize(broken, context("greynoise"))[0]
        assert draft.flags["noise_class"] == "UNKNOWN"
        assert draft.flags["noise_ratio"] is None
        assert draft.flags["suppress_confidence"] is False
        assert draft.value == "UNKNOWN"

    @pytest.mark.parametrize("body", [b"{}", b'{"stats": {}}',
                                      b'{"stats": {"classifications": []}}'])
    def test_an_empty_distribution_is_a_measured_zero_not_unknown(self, body):
        """Production divides through `.get(..., default)`, so an absent
        or empty `classifications` is `total=0` -> `noise_ratio=0.0`
        (`radar/sensors/greynoise.py:192-197`) -> TARGETED, and the value
        string carries the percentage (`radar/routes/core.py:1393`).

        The port answered UNKNOWN here, which reports "we could not look"
        about a request that answered — and `value` is what
        `noise_excl_match` matches on (`core.py:950`), so the two strings
        are not interchangeable.
        """
        answered = FetchedPayload(url="https://x.test", status=200, body=body,
                                  fetched_at=T0, label="gnql:TW")
        draft = greynoise.normalize(answered, context("greynoise"))[0]
        assert draft.flags["noise_class"] == "TARGETED"
        assert draft.flags["noise_ratio"] == 0.0
        assert draft.value == "TARGETED noise=0%"

    def test_the_ratio_is_benign_over_total(self):
        assert greynoise.noise_ratio_of(
            [{"classification": "benign", "count": 380},
             {"classification": "malicious", "count": 90},
             {"classification": "unknown", "count": 30}]) == 0.76

    def test_malicious_ips_is_total_minus_benign_not_a_rounded_ratio(self):
        """`malicious = total - noise` off the SUMMED benign count
        (`radar/sensors/greynoise.py:193-196`). Reconstructing benign as
        `round(ratio * total)` from the already-rounded ratio drifts: at
        this scale it reports 333 addresses that were never benign."""
        body = json.dumps({"stats": {"classifications": [
            {"classification": "benign", "count": 333_333},
            {"classification": "malicious", "count": 666_667}]}}).encode()
        draft = greynoise.normalize(synthetic(body, label="gnql:TW"),
                                    context("greynoise"))[0]
        assert draft.flags["total_ips"] == 1_000_000
        assert draft.flags["malicious_ips"] == 666_667

    def test_the_query_does_not_filter_on_classification(self):
        """Filtering `classification:malicious` excludes benign, and the
        ratio is benign/total — so the filter pins it at 0 forever."""
        query = greynoise.GREYNOISE_ADAPTER.requests[0].param_values(
            "query")[0]
        assert "classification" not in query

    @pytest.mark.parametrize("ratio,expected", [
        (0.9, "NOISE_DOMINANT"), (0.5, "MIXED"), (0.1, "TARGETED"),
        (None, "UNKNOWN")])
    def test_the_classification_ladder(self, ratio, expected):
        assert greynoise.classify(ratio) == expected


# ── threatfox (K10) ─────────────────────────────────────────────────────

class TestThreatfox:
    def _drafts(self, name="get_iocs.json"):
        return threatfox.normalize(
            payload("threatfox", name, label="get_iocs"),
            context("threatfox", countries=("TW", "JP"),
                    country_names={"TW": "Taiwan", "JP": "Japan"}))

    def test_an_apt_tagged_ioc_fires_and_scores_one(self):
        by_country = {draft.country: draft for draft in self._drafts()}
        assert by_country["TW"].status == STATUS_FIRED
        assert by_country["TW"].raw_score == 1.0

    def test_a_country_name_tag_counts_the_same_as_an_apt_tag(self):
        """A11, preserved: no threshold, no weighting — and note the
        consequence. An IoC tagged `apt` counts for EVERY country in
        scope, so Japan's count includes the Taiwan-tagged APT indicator
        as well as its own. The design sheet rules this ACCIDENTAL and
        ports it unchanged; the test states the over-count so a later
        ruling has something concrete to overturn."""
        by_country = {draft.country: draft for draft in self._drafts()}
        assert by_country["JP"].flags["count"] == 2
        assert by_country["TW"].flags["count"] == 1

    def test_a_country_with_no_hits_still_gets_an_observation(self):
        """"Nothing seen" and "not looked at" must be distinguishable."""
        drafts = threatfox.normalize(
            payload("threatfox", "no_result.json", label="get_iocs"),
            context("threatfox", countries=("TW",),
                    country_names={"TW": "Taiwan"}))
        assert drafts[0].status == STATUS_OK
        assert drafts[0].raw_score == 0.0

    def test_a_failed_query_status_yields_nothing(self):
        broken = FetchedPayload(
            url="https://x.test", status=200, fetched_at=T0,
            body=b'{"query_status": "illegal_search_term", "data": []}')
        assert threatfox.normalize(broken, context("threatfox")) == ()


# ── ooni (K04, K15) ─────────────────────────────────────────────────────

class TestOoni:
    def _draft(self, name="aggregation.json"):
        return ooni_censorship.normalize(
            payload("ooni_censorship", name,
                    url="https://api.ooni.io/api/v1/aggregation?probe_cc=CN",
                    label="aggregation"),
            context("ooni_censorship", countries=("CN",)))[0]

    def test_heavy_censorship_scores_two(self):
        draft = self._draft()
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 2.0
        assert draft.flags["is_heavy"] is True

    def test_a_quiet_country_does_not_fire(self):
        draft = self._draft("aggregation_normal.json")
        assert draft.status == STATUS_OK
        assert draft.raw_score == 0.0

    def test_the_country_comes_from_the_query_string(self):
        assert self._draft().country == "CN"

    def test_the_surge_condition_declares_its_missing_history(self):
        """The marker gets its OWN key. `anomaly_surge` is a bool in
        production (`radar/sensors/ooni.py:156-157,171`), and a non-empty
        string under that name reads as `True` to anything that treats it
        as the bool it is declared to be — a surge asserted on every
        country, forever. Absent means "not stated", which is the fact."""
        flags = self._draft().flags
        assert "anomaly_surge" not in flags
        assert flags["anomaly_surge_verdict"] == "pending_l1_prev_anomaly_count"
        assert "ooni_prev_anomaly_count" in \
            ooni_censorship.OONI_CENSORSHIP_ADAPTER.baseline_refs

    @pytest.mark.parametrize("anomaly,confirmed,expected", [
        (0.5, 0.0, "HEAVY_CENSORSHIP"), (0.0, 0.2, "HEAVY_CENSORSHIP"),
        (0.25, 0.0, "CENSORSHIP_DETECTED"), (0.0, 0.06, "CENSORSHIP_DETECTED"),
        (0.1, 0.01, "NORMAL")])
    def test_the_verdict_ladder(self, anomaly, confirmed, expected):
        assert ooni_censorship.verdict(anomaly, confirmed)[2] == expected

    def test_a_surge_alone_counts_as_censoring(self):
        assert ooni_censorship.verdict(0.0, 0.0, surging=True)[0] is True


# ── cloudflare_radar (DP8, A9) ──────────────────────────────────────────

class TestCloudflareRadar:
    def test_hijacks_below_confidence_fifty_are_dropped(self):
        records = cloudflare_radar.normalize_hijacks(
            payload("cloudflare_radar", "bgp_hijacks.json", label="hijacks"))
        assert [record["victim_country"] for record in records] == ["TW"]

    def test_leaks_are_not_confidence_filtered(self):
        """A9's asymmetry, preserved: a leak is a routing fact, a hijack
        is an accusation of intent."""
        records = cloudflare_radar.normalize_leaks(
            payload("cloudflare_radar", "bgp_leaks.json", label="leaks"))
        assert len(records) == 1
        assert "confidence" not in records[0]

    def test_country_codes_are_upper_cased(self):
        records = cloudflare_radar.normalize_hijacks(
            payload("cloudflare_radar", "bgp_hijacks.json", label="hijacks"))
        assert records[0]["hijacker_country"] == "CN"

    def test_an_ongoing_hijack_fires_and_scores_one(self):
        drafts = cloudflare_radar.normalize(
            payload("cloudflare_radar", "bgp_hijacks.json", label="hijacks"),
            context("cloudflare_radar", countries=("TW", "JP")))
        by_country = {draft.country: draft for draft in drafts}
        assert by_country["TW"].status == STATUS_FIRED
        assert by_country["TW"].raw_score == 1.0
        assert by_country["JP"].status == STATUS_OK

    def test_the_legacy_signal_source_name_is_kept_for_dedup(self):
        drafts = cloudflare_radar.normalize(
            payload("cloudflare_radar", "bgp_hijacks.json", label="hijacks"),
            context("cloudflare_radar"))
        assert drafts[0].signal_source == "cf_bgp_hijack"

    def test_attack_shares_are_reported_not_judged(self):
        """The spike verdict compares against a time-series baseline that
        L2 excludes as a derived-observation producer."""
        drafts = cloudflare_radar.normalize(
            payload("cloudflare_radar", "l3_top_locations.json", label="l3"),
            context("cloudflare_radar"))
        assert drafts[0].status == STATUS_OBSERVED
        assert drafts[0].flags["share_pct"] == pytest.approx(34.5)

    def test_the_country_ladder_is_the_one_production_reads_with(self):
        """`parse_origins` (`radar/scoring.py:659-666`) is the ONLY reader
        of these rows in `radar/`, and it names three keys before falling
        back to "the first value that is two upper-case characters".

        The port read `targetCountryAlpha2` and nothing else — a key that
        appears nowhere in `radar/`. Cloudflare renaming it, or answering
        with `location` (which the ladder exists for), would have left
        every row unattributed and the adapter reporting success with no
        observations: silence that looks like a quiet day (NP1).
        """
        source = legacy_source("radar/scoring.py")
        assert 'o.get("origin1") or o.get("location") or ' \
               'o.get("clientCountryAlpha2")' in source
        assert list(cloudflare_radar.LOCATION_KEYS) == [
            "origin1", "location", "clientCountryAlpha2"]
        for key in cloudflare_radar.LOCATION_KEYS:
            assert cloudflare_radar.location_of({key: "TW", "value": "1"}) \
                == "TW"
        # the trailing scan, which is what resolves `targetCountryAlpha2`
        assert cloudflare_radar.location_of(
            {"targetCountryAlpha2": "TW", "rank": 1}) == "TW"

    def test_a_row_with_no_share_figure_weighs_one_not_zero(self):
        """`float(o.get("value") or o.get("count") or 1.0)`
        (`radar/scoring.py:663`). The `or` chain falls through a zero, so
        "Cloudflare listed this location without a share" is 1.0, not the
        0.0 all-clear the port substituted."""
        assert cloudflare_radar.share_of({"location": "TW"}) == 1.0
        assert cloudflare_radar.share_of(
            {"location": "TW", "value": 0, "count": 7}) == 7.0
        assert cloudflare_radar.share_of({"location": "TW", "value": 0}) == 1.0

    def test_bgp_events_are_always_asked_for_one_day(self):
        specs = {spec.label: spec
                 for spec in cloudflare_radar.CLOUDFLARE_RADAR_ADAPTER.requests}
        assert specs["hijacks"].param_values("dateRange") == ("1d",)
        assert specs["leaks"].param_values("dateRange") == ("1d",)

    # ── the leak threshold (core.py:1156) ───────────────────────────────
    @staticmethod
    def _leaks(count: int, country="cn") -> FetchedPayload:
        return synthetic(json.dumps({"result": {"asn_leaks": [
            {"id": index, "leak_asn": 4809 + index, "leak_country": country,
             "leaked_prefix_count": 3, "origin_asn": 3462, "peer_count": 2}
            for index in range(count)]}}).encode(), label="leaks")

    def _leak_draft(self, count: int):
        return cloudflare_radar.normalize(
            self._leaks(count),
            context("cloudflare_radar", countries=("CN",)))[0]

    def test_one_route_leak_does_not_fire(self):
        """core.py:1156 combines both endpoints into ONE verdict:
        `len(_hijack_ongoing) > 0 or len(_core_leaks) >= 3`. A single route
        leak is routine — treating it as a firing signal loosens the
        threshold by two events, which is an unregistered sensitivity
        change (P2 §5-C) and not a small one."""
        draft = self._leak_draft(1)
        assert draft.status == STATUS_OK
        assert draft.raw_score == 0.0
        assert draft.flags["count"] == 1

    def test_two_route_leaks_do_not_fire_either(self):
        assert self._leak_draft(2).status == STATUS_OK

    def test_three_route_leaks_fire_and_score_one(self):
        draft = self._leak_draft(3)
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 1.0
        assert draft.flags["count"] == 3

    def test_the_recorded_single_leak_fixture_reads_ok(self):
        """The shipped fixture holds exactly one leak, which is what the
        loosened rule fired on."""
        draft = cloudflare_radar.normalize(
            payload("cloudflare_radar", "bgp_leaks.json", label="leaks"),
            context("cloudflare_radar", countries=("CN",)))[0]
        assert draft.flags["count"] == 1
        assert draft.status == STATUS_OK

    def test_an_ongoing_hijack_alone_still_fires(self):
        """The hijack half of the disjunction has no count threshold."""
        draft = cloudflare_radar.normalize(
            payload("cloudflare_radar", "bgp_hijacks.json", label="hijacks"),
            context("cloudflare_radar", countries=("TW",)))[0]
        assert draft.status == STATUS_FIRED
        assert draft.flags["ongoing"] == 1

    def test_the_two_bgp_payloads_do_not_collide_on_one_ledger_key(self):
        """The L1 key is `(tick_id, sensor, signal_source, country)`
        (`v3/ledger/schema.py:157`) and `append_signal` calls
        `_require_same_tick` on a collision, which RAISES when the two
        rows differ and silently DROPS when they match (S5-VERIF-019).

        The port gave both payloads `cf_bgp_hijack` on the theory that
        S1-SCORE-008's MAX fold would reassemble
        `ongoing > 0 or leaks >= 3`. Nothing reaches that fold: one tick,
        one country, one adapter, two payloads — so the leak row was lost
        or fatal every cycle. The disjunction is a WP-4.1 reduction over
        the two keys, not something L1 performs.
        """
        scope = context("cloudflare_radar", countries=("CN",))
        hijack = cloudflare_radar.normalize(
            payload("cloudflare_radar", "bgp_hijacks.json", label="hijacks"),
            scope)[0]
        leak = cloudflare_radar.normalize(self._leaks(3), scope)[0]
        # one tick, one adapter, one country — the collision's preconditions
        assert hijack.country == leak.country == "CN"
        assert hijack.status != leak.status      # so `_require_same_tick` raises
        assert hijack.signal_source != leak.signal_source
        assert hijack.signal_source == "cf_bgp_hijack"     # core.py:1165
        assert leak.signal_source == "cf_bgp_leak"


# ── ripe_bgp (DP3, DP4) ─────────────────────────────────────────────────

class TestRipeBgp:
    def _draft(self, name="country_routing_stats.json"):
        return ripe_bgp.normalize(
            payload("ripe_bgp", name, label="routing_stats"),
            context("ripe_bgp", countries=()))[0]

    def test_the_country_comes_from_the_body(self):
        assert self._draft().country == "TW"

    def test_the_latest_sample_is_reported_with_the_series(self):
        flags = self._draft().flags
        assert flags["announced_prefixes"] == 6100
        assert flags["prefix_series"] == [8100, 8150, 6100]

    def test_the_verdict_is_not_this_layers_to_make(self):
        """DP4: the hour-of-day Z-score exists three times in the legacy
        system. §3-2 collapses it into L1 + L2's trend module."""
        draft = self._draft()
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["hod_verdict"] == "pending_l1_bgp_hod"
        assert ripe_bgp.RIPE_BGP_ADAPTER.baseline_refs == ("bgp_hod",)

    def test_an_empty_series_is_no_data_rather_than_zero_prefixes(self):
        draft = self._draft("country_routing_stats_empty.json")
        assert draft.status == STATUS_NO_DATA
        assert draft.country == "KP"

    def test_the_bgp_signal_source_is_shared_for_dedup(self):
        assert self._draft().signal_source == "bgp"

    def test_the_baseline_constants_are_pinned_for_the_l1_job(self):
        assert (ripe_bgp.HOD_MIN_SAME_HOUR, ripe_bgp.HOD_ANOMALY_Z,
                ripe_bgp.HOD_STDDEV_FLOOR) == (7, -2.0, 1.0)
        assert ripe_bgp.DROP_THRESHOLD == 0.15


# ── ct_log (K05, A18) ───────────────────────────────────────────────────

class TestCtLog:
    #: The request that was actually sent. Both event dicts key on the
    #: WATCHED domain (`radar/sensors/ct_log.py:307,329`), which is the
    #: query parameter, not anything in the response.
    CERTSPOTTER_URL = ("https://api.certspotter.com/v1/issuances"
                       "?domain=mofa.gov.tw&expand=dns_names&expand=issuer")
    CRTSH_URL = "https://crt.sh/?Identity=mofa.gov.tw&output=json"

    def _draft(self, name, label, *, now=T0):
        url = self.CRTSH_URL if label == "crtsh" else self.CERTSPOTTER_URL
        return ct_log.normalize(
            payload("ct_log", name, label=label, url=url),
            context("ct_log", now=now))[0]

    def test_certspotter_and_crtsh_normalize_to_one_shape(self):
        for name, label in (("certspotter_issuances.json", "certspotter"),
                            ("crtsh_rows.json", "crtsh")):
            records = ct_log.certificates(payload("ct_log", name, label=label))
            assert records[0]["issuer"] == "let's encrypt"
            assert "mofa.gov.tw" in records[0]["dns_names"]

    def test_a_wildcard_at_a_government_tld_fires_and_scores_two(self):
        draft = self._draft("certspotter_wildcard_gov.json", "certspotter")
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 2.0
        assert draft.flags["wildcard_tld_detected"] is True

    def test_a_wildcard_inside_a_sub_namespace_does_not_fire(self):
        """`*.api.mofa.gov.tw` is ordinary infrastructure; `*.gov.tw` is a
        claim over the whole namespace."""
        assert ct_log.is_gov_tld_wildcard("*.gov.tw") is True
        assert ct_log.is_gov_tld_wildcard("*.api.mofa.gov.tw") is False
        assert ct_log.is_gov_tld_wildcard("mofa.gov.tw") is False

    def test_an_empty_two_hundred_is_an_authoritative_answer(self):
        """K05. "No certificates were issued" is evidence; falling
        through to the next source discards it."""
        empty = FetchedPayload(url="https://api.certspotter.com/v1/issuances",
                               status=200, body=b"[]", fetched_at=T0,
                               label="certspotter")
        drafts = ct_log.normalize(empty, context("ct_log"))
        assert len(drafts) == 1
        assert drafts[0].status == STATUS_OK
        assert drafts[0].flags["total_recent"] == 0

    def test_the_issuer_normalizer_prefers_o_then_cn_then_the_raw_dn(self):
        assert ct_log.parse_issuer("C=US, O=Let's Encrypt, CN=R3")[1] == \
            "let's encrypt"
        assert ct_log.parse_issuer("C=CN, CN=Some Internal CA")[1] == \
            "some internal ca"
        assert ct_log.parse_issuer("weird issuer")[1] == "weird issuer"
        assert ct_log.parse_issuer("")[1] == "unknown"

    def test_an_unnameable_issuer_is_dropped_rather_than_called_untrusted(self):
        blank = FetchedPayload(
            url="https://crt.sh/", status=200, fetched_at=T0, label="crtsh",
            body=b'[{"issuer_name": "", "common_name": "x.gov.tw", '
                 b'"name_value": "x.gov.tw", "not_before": "2026-08-01"}]')
        assert ct_log.certificates(blank) == []

    def test_a_state_ca_is_not_in_the_trusted_ledger(self):
        assert ct_log.is_globally_trusted("digicert inc") is True
        assert ct_log.is_globally_trusted("cnnic china") is False

    def test_gov_count_is_not_emitted_at_all(self):
        """A18 / §7-2 expected difference #6: it was 0 in every cycle for
        every country — a retired concept whose field outlived it."""
        draft = self._draft("certspotter_issuances.json", "certspotter")
        assert "gov_count" not in draft.flags
        assert "gov_count" not in draft.value

    # ── the untrusted-CA candidate path (S1-SENS-018 priority 3) ────────
    def test_an_untrusted_candidate_without_a_wildcard_is_observed_not_ok(self):
        """A measured-but-unjudged signal must not report OK.

        S1-SENS-018 ranks UNTRUSTED_CA (3) above WILDCARD (2), and the
        recorded CertSpotter fixture holds an "Internal Authority" issuer
        for `mail.mofa.gov.tw`. The untrusted verdict itself needs the
        per-domain known-CA ledger and the warmup marker, both L1's
        (`radar/sensors/ct_log.py:315-326`), so this layer cannot fire —
        but OK would say "measured, nothing wrong" about the one
        certificate in the payload that is not unremarkable. That is the
        blind-spot shape STATUS_OBSERVED exists to prevent (NP1).
        """
        draft = self._draft("certspotter_issuances.json", "certspotter")
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0

    def test_the_observed_draft_carries_the_candidates_it_could_not_judge(self):
        """The event dict is production's, key for key
        (`radar/sensors/ct_log.py:328-336`): `domain` is the WATCHED
        domain, the certificate's own name is `common_name`, and the
        issuer travels twice — normalized for comparison, raw for
        display. The port emitted `{domain: <the cert's CN>, ca_raw: ...}`,
        which puts a certificate subject under the name an analyst reads
        as "which of our domains".
        """
        draft = self._draft("certspotter_issuances.json", "certspotter")
        candidates = draft.flags["untrusted_ca_candidates"]
        assert len(candidates) == 1
        assert candidates[0] == {
            "domain": "mofa.gov.tw",            # the query, not the cert
            "country": "TW",
            "ca_normalized": "some internal authority",
            "ca_raw": "C=CN, O=Some Internal Authority, CN=Internal CA",
            "common_name": "mail.mofa.gov.tw",
            "not_before": "2026-08-02T00:00:00"}
        assert draft.flags["untrusted_ca_candidate_count"] == 1
        assert draft.flags["untrusted_ca_verdict"] == \
            "pending_l1_known_ca_ledger"

    def test_the_value_string_does_not_claim_zero_untrusted_cas(self):
        """`untrusted_ca=0` is the same all-clear in text that OK is in
        status: the count is not zero, it is unknown."""
        draft = self._draft("certspotter_issuances.json", "certspotter")
        assert "untrusted_ca=0" not in draft.value
        assert "pending" in draft.value

    def test_only_trusted_issuers_still_report_ok(self):
        draft = self._draft("crtsh_rows.json", "crtsh")
        assert draft.status == STATUS_OK
        assert draft.flags["untrusted_ca_candidates"] == []
        assert "untrusted_ca=0" in draft.value

    def test_the_wildcard_case_is_unchanged(self):
        draft = self._draft("certspotter_wildcard_gov.json", "certspotter")
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 2.0
        assert "untrusted_ca=0" in draft.value

    def test_a_wildcard_outranks_a_pending_untrusted_candidate(self):
        """Legacy scores the untrusted CA 3 and the wildcard 2; with the
        untrusted verdict pending, the wildcard is the only rule this
        layer can actually decide, so it keeps FIRED/2.0 rather than
        inventing a 3 the L1 ledger has not supported."""
        both = synthetic(
            json.dumps([{"id": "1", "dns_names": ["*.gov.tw"],
                         "not_before": "2026-08-06T00:00:00Z",
                         "issuer": {"name": "C=CN, O=Some Internal "
                                            "Authority, CN=Internal CA"}}]
                       ).encode(), label="certspotter")
        draft = ct_log.normalize(both, context("ct_log"))[0]
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 2.0
        assert draft.flags["untrusted_ca_candidate_count"] == 1

    def test_the_ledger_sizes_are_what_the_code_holds(self):
        """S1-SENS-018 says 44 CAs and 23 gov TLDs; the ledgers hold 43
        and 22. Recorded as errata rather than rounded to the prose."""
        assert len(ct_log.TRUSTED_CA_SUBSTRINGS) == 43
        assert len(ct_log.GOV_TLD_WILDCARD_TARGETS) == 22


# ── apt_intel (K09, DP9) ────────────────────────────────────────────────

class TestAptIntel:
    def _drafts(self, name, label="cisa_advisories"):
        return apt_intel.normalize(
            payload("apt_intel", name, label=label,
                    content_type="application/rss+xml"),
            context("apt_intel"))

    def test_a_live_feed_yields_candidate_articles(self):
        drafts = self._drafts("cisa_advisories.xml")
        assert len(drafts) == 2
        assert drafts[0].status == STATUS_OBSERVED
        assert drafts[0].flags["awaiting"] == "llm_extraction (WP-2.7)"

    def test_a_dead_url_serving_html_is_distinguishable_from_an_empty_feed(
            self):
        """DP9's repair. The legacy strict-only parser collapsed both into
        one log line, so a broken URL looked like a quiet authority."""
        html = self._drafts("dead_feed.html")[0]
        assert html.status == STATUS_NO_DATA
        assert html.flags["outcome"] == "returns_html"

        empty = FetchedPayload(url="https://x.test/rss", status=200,
                               fetched_at=T0, label="jpcert",
                               body=b'<?xml version="1.0"?><rss><channel>'
                                    b'</channel></rss>')
        result = apt_intel.normalize(empty, context("apt_intel"))[0]
        assert result.flags["outcome"] == "rss_empty"

    def test_promotional_items_are_discarded(self):
        assert apt_intel.is_discarded("Webinar: how we blocked it") is True
        assert apt_intel.is_discarded("Download PDF of Advisory") is False

    def test_the_download_word_alone_is_not_a_discard_marker(self):
        """The download phrases are deliberately multi-word: CISA's own
        advisories link "Download PDF", and a bare `download` rule ate
        them."""
        assert "download" not in apt_intel.DISCARD_KEYWORDS
        assert all(len(phrase.split()) > 1 for phrase in
                   apt_intel.DISCARD_KEYWORDS if "download" in phrase)

    def test_the_dedup_key_is_the_legacy_one(self):
        """RULING B. B-05 moves the dedup set to L1, and the docstring's
        own justification is that a different key makes the migrated
        history useless — which is what the port shipped. Legacy is
        `f"cert-{source_name}-{title[:60]}"` (`apt_intel.py:173-175`) and
        `source_name` is the `_CERT_SOURCES` **key**, so it is
        UPPER_SNAKE. The port dropped the separator and lower-cased the
        source, so every migrated row would have been unmatchable.

        This test previously pinned the port's own output. A test that
        pins an unverified value proves only that the code has not
        changed — it cannot notice that the value was wrong to begin
        with, which is exactly how this survived review.
        """
        import hashlib
        title = "Critical Advisory On Widget"
        expected = hashlib.md5(
            f"cert-CISA_ADVISORIES-{title[:60]}".encode(),
            usedforsecurity=False).hexdigest()
        assert apt_intel.dedup_key("cisa_advisories", title) == expected

    def test_the_stored_summary_is_truncated_at_five_hundred(self):
        """RULING A. Legacy stores `summary[:500]` (`:292`). The LLM stage
        is the consumer and `llm_call` records the prompt for
        S5-VERIF-022 replay, so carrying 1000 changes both the prompt and
        what parity replays against."""
        feed = self._articles(
            ("Advisory on remote code execution", "y" * 900))
        article = apt_intel.normalize(
            feed, context("apt_intel"))[0].flags["article"]
        assert len(article["summary"]) == 500
        assert article["summary"] == "y" * 500

    def test_the_moved_cisa_url_is_the_one_declared(self):
        """K09: the advisories feed moved, and CISA 403s script agents."""
        assert "cybersecurity-advisories" in apt_intel.CISA_ADVISORIES_URL
        agent = apt_intel.APT_INTEL_ADAPTER.requests[0].headers["User-Agent"]
        assert agent.startswith("Mozilla/")

    def test_the_feed_roster_is_the_post_audit_five(self):
        names = [name for name, _ in apt_intel.FEEDS]
        assert names == ["cisa_advisories", "cisa_alerts", "jpcert",
                         "ncsc_uk", "cert_bund"]
        urls = " ".join(url for _, url in apt_intel.FEEDS)
        for removed in ("enisa", "bsi.bund", "cyber.gov.au"):
            assert removed not in urls

    def test_it_stops_where_the_llm_begins(self):
        """O-17: extraction is ONE adapter in v3, not eight prompts."""
        drafts = self._drafts("cisa_advisories.xml")
        assert all(draft.raw_score == 0.0 for draft in drafts)
        assert all(draft.status != STATUS_FIRED for draft in drafts)

    # ── the 168-hour article window (legacy apt_intel.py:224,278-279) ───
    @staticmethod
    def _feed(*published: str) -> FetchedPayload:
        items = "".join(
            f"<item><title>Advisory number {index}</title>"
            f"<link>https://cert.test/{index}</link>"
            f"<description>Vulnerability notice.</description>"
            f"<pubDate>{stamp}</pubDate></item>"
            for index, stamp in enumerate(published))
        return synthetic(
            f'<?xml version="1.0"?><rss version="2.0"><channel>{items}'
            f'</channel></rss>'.encode(), label="cisa_advisories",
            content_type="application/rss+xml")

    @staticmethod
    def _rfc822(hours_before_now: float) -> str:
        moment = datetime.fromtimestamp(T0 - hours_before_now * 3600.0,
                                        tz=timezone.utc)
        return format_datetime(moment)

    @classmethod
    def _articles(cls, *items: tuple[str, str]) -> FetchedPayload:
        """`(title, description)` pairs, all dated one hour before `T0`."""
        stamp = cls._rfc822(1.0)
        body = "".join(
            f"<item><title>{title}</title>"
            f"<link>https://cert.test/{index}</link>"
            f"<description>{summary}</description>"
            f"<pubDate>{stamp}</pubDate></item>"
            for index, (title, summary) in enumerate(items))
        return synthetic(
            f'<?xml version="1.0"?><rss version="2.0"><channel>{body}'
            f'</channel></rss>'.encode(), label="cisa_advisories",
            content_type="application/rss+xml")

    def _titles(self, feed: FetchedPayload, **overrides) -> list[str]:
        return [draft.flags["article"]["title"]
                for draft in apt_intel.normalize(
                    feed, context("apt_intel", **overrides))]

    def _scoped(self, feed: FetchedPayload) -> list[str]:
        """`_titles` with Taiwan named, which is what opens slot 2."""
        return self._titles(feed, countries=("TW",),
                            country_names={"TW": "Taiwan"})

    def test_a_fresh_article_is_kept(self):
        assert self._titles(self._feed(self._rfc822(1.0))) == \
            ["Advisory number 0"]

    def test_an_article_older_than_the_window_is_dropped(self):
        """`ARTICLE_AGE_WINDOW_HOURS` was declared, documented and
        exported without ever being compared against anything — so the
        selection that feeds WP-2.7's LLM stage resurrected advisories of
        arbitrary age and inflated the volume the LLM ever sees."""
        assert self._titles(self._feed(self._rfc822(200.0))) == []

    def test_the_boundary_is_inclusive_at_exactly_the_window(self):
        """Legacy drops on `pub_ts < cutoff`, so an article landing
        exactly on the cutoff survives."""
        window = float(apt_intel.ARTICLE_AGE_WINDOW_HOURS)
        assert self._titles(self._feed(self._rfc822(window))) != []
        assert self._titles(self._feed(self._rfc822(window + 0.01))) == []

    def test_an_unparseable_date_is_kept(self):
        """Legacy keeps what it cannot date (`pub_ts > 0 and ...`). A feed
        with an eccentric date format must not go silently blind."""
        assert self._titles(self._feed("last tuesday-ish")) == \
            ["Advisory number 0"]

    def test_a_missing_date_is_kept(self):
        feed = synthetic(
            b'<?xml version="1.0"?><rss version="2.0"><channel><item>'
            b'<title>Undated advisory</title><link>https://cert.test/u</link>'
            b'</item></channel></rss>', label="cisa_advisories",
            content_type="application/rss+xml")
        assert self._titles(feed) == ["Undated advisory"]

    def test_an_iso_8601_date_is_understood(self):
        """JPCERT's RDF carries `dc:date`, which is ISO-8601, not RFC822."""
        fresh = datetime.fromtimestamp(T0 - 3600.0, tz=timezone.utc)
        assert self._titles(self._feed(fresh.isoformat())) != []
        stale = datetime.fromtimestamp(T0 - 400 * 3600.0, tz=timezone.utc)
        assert self._titles(self._feed(stale.isoformat())) == []

    def test_a_stale_article_still_consumes_its_dedup_slot(self):
        """Legacy adds the title key to `seen_titles` BEFORE the age
        check (`apt_intel.py:259-263` then `:278`), so a stale item
        suppresses a later republication of the same title. The ordering
        is pinned rather than assumed — moving the age check above the
        dedup set would quietly resurrect those republications."""
        stale, fresh = self._rfc822(200.0), self._rfc822(1.0)
        feed = synthetic(
            f'<?xml version="1.0"?><rss version="2.0"><channel>'
            f'<item><title>Same Advisory</title>'
            f'<link>https://cert.test/a</link><pubDate>{stale}</pubDate></item>'
            f'<item><title>Same Advisory</title>'
            f'<link>https://cert.test/b</link><pubDate>{fresh}</pubDate></item>'
            f'</channel></rss>'.encode(), label="cisa_advisories",
            content_type="application/rss+xml")
        assert self._titles(feed) == []

    def test_a_discarded_item_also_consumes_its_dedup_slot(self):
        """RULING #1. Legacy enters the key at `:259-263`, BEFORE the
        discard ledger at `:285` and the noise prefixes at `:289`, so a
        promotional item suppresses a later legitimate item carrying the
        same title. Keeping that item — as the port did — widens the
        candidate set the LLM stage consumes, which is a sensitivity
        difference, not a tidier implementation."""
        feed = self._articles(
            ("Vendor Advisory Roundup", "Register now for our webinar."),
            ("Vendor Advisory Roundup", "CVE-2026-1 under active attack."))
        assert self._titles(feed) == []

    # ── the two-slot selection (legacy apt_intel.py:294-308) ────────────
    def test_an_item_matching_neither_ledger_is_excluded(self):
        """RULING #3, the headline. Legacy falls off the end of both
        `if`s without appending, so an item that is neither advisory
        language nor a named country never reaches the LLM. Taking the
        first N survivors instead — as the port did — is a strictly wider
        candidate set: an unregistered sensitive difference AND a bigger
        bill at the stage WP-2.7 is about to build."""
        feed = self._articles(
            ("Office relocation notice", "Our lobby moves next month."))
        assert self._scoped(feed) == []

    def test_slot_one_takes_five_advisory_matches_at_most(self):
        feed = self._articles(*[
            (f"Advisory {index}", "Remote code execution reported.")
            for index in range(8)])
        assert len(self._scoped(feed)) == apt_intel.KEYWORD_ARTICLE_LIMIT == 5

    def test_slot_two_takes_two_country_only_matches_at_most(self):
        feed = self._articles(*[
            (f"Taiwan ministry budget summary {index}",
             "Annual publication.") for index in range(5)])
        assert len(self._scoped(feed)) == apt_intel.COUNTRY_ARTICLE_LIMIT == 2

    def test_the_combined_cap_is_five_plus_two(self):
        feed = self._articles(
            *[(f"Advisory {index}", "Remote code execution reported.")
              for index in range(8)],
            *[(f"Taiwan ministry budget summary {index}", "Annual note.")
              for index in range(4)])
        selected = self._scoped(feed)
        assert len(selected) == apt_intel.MAX_ARTICLES_PER_FEED == 7

    def test_slot_one_articles_come_before_slot_two_articles(self):
        """Legacy returns `keyword_articles + theater_only_articles`, not
        feed order. The LLM stage reads the list in order and the caps bite
        upstream, so the order is part of what gets analysed."""
        feed = self._articles(
            ("Taiwan ministry budget summary", "Annual publication."),
            ("Advisory on remote code execution", "Patch immediately."))
        assert self._scoped(feed) == ["Advisory on remote code execution",
                                      "Taiwan ministry budget summary"]

    def test_an_advisory_match_never_falls_through_to_slot_two(self):
        """`continue` fires on the slot-1 branch whether or not slot 1 had
        room (`:298`). So once five advisories are in, a sixth advisory
        that also names Taiwan is dropped rather than demoted — it does
        not get to spend a slot-2 seat."""
        feed = self._articles(
            *[(f"Advisory {index}", "Remote code execution reported.")
              for index in range(5)],
            ("Taiwan advisory on remote code execution", "Sixth."),
            ("Taiwan ministry budget summary", "Annual publication."))
        selected = self._scoped(feed)
        assert "Taiwan advisory on remote code execution" not in selected
        assert "Taiwan ministry budget summary" in selected

    def test_slot_two_stays_shut_when_no_country_is_named(self):
        """Legacy guards on `theater_names` being non-empty (`:301`)."""
        feed = self._articles(
            ("Taiwan ministry budget summary", "Annual publication."))
        assert self._titles(feed) == []

    def test_a_country_outside_the_feeds_hints_does_not_open_slot_two(self):
        """Legacy intersects the feed's `theater_hints` with the scenario
        countries before resolving names (`:344-345`, `:352`). CISA hints
        do not include Germany."""
        feed = self._articles(
            ("Germany ministry budget summary", "Annual publication."))
        assert self._titles(feed, countries=("DE",),
                            country_names={"DE": "Germany"}) == []

    def test_a_discard_keyword_in_the_summary_excludes_the_item(self):
        """Legacy tests the discard ledger against title AND summary
        (`text_lower`, `:281`/`:285`) — the port tested the title alone,
        so marketing copy in a description walked straight through."""
        feed = self._articles(
            ("Critical infrastructure vulnerability",
             "Register now for our webinar."))
        assert self._scoped(feed) == []

    def test_a_noise_title_prefix_excludes_an_otherwise_valid_item(self):
        feed = self._articles(
            ("Weekly Report: critical vulnerability roundup", "Digest."))
        assert self._scoped(feed) == []

    def test_the_ledgers_are_the_legacy_ones(self):
        """The port shipped an invented discard list that shared five
        phrases with legacy's and differed in nine. A hand-written filter
        is a hand-written sensitivity change."""
        assert "volt typhoon" in apt_intel.ADVISORY_KEYWORDS
        assert "注意喚起" in apt_intel.ADVISORY_KEYWORDS      # JPCERT
        assert "schwachstelle" in apt_intel.ADVISORY_KEYWORDS  # CERT-Bund
        for phrase in ("we prevented", "our platform detected", "how we",
                       "product update", "whitepaper", "ebook", "join us"):
            assert phrase in apt_intel.DISCARD_KEYWORDS
        for invented in ("free trial", "contact sales", "request a demo",
                         "sign up", "learn how", "white paper"):
            assert invented not in apt_intel.DISCARD_KEYWORDS
        assert apt_intel.NOISE_TITLE_PREFIXES == ("weekly report",)

    # ── transcription, checked against the live sensor (RULING C) ───────
    def test_every_declared_url_is_the_live_sensors_url(self):
        """RULING C: `_CERT_SOURCES` is canonical. Fetching a different
        document makes every other fidelity property of this adapter
        moot — the selection can be perfect and still be selecting from
        the wrong feed."""
        sources = legacy_literal("apt_intel", "_CERT_SOURCES")
        live = [(name.lower(), meta["url"]) for name, meta in sources.items()]
        assert list(apt_intel.FEEDS) == live      # order included

    def test_the_ncsc_feed_is_the_news_feed_not_the_abandoned_one(self):
        """Legacy's comment records why it moved: the report feed was
        research papers and "almost never matched". The port declared the
        abandoned one."""
        urls = dict(apt_intel.FEEDS)
        assert urls["ncsc_uk"].endswith("news-rss-feed.xml")
        assert "report-rss-feed" not in " ".join(urls.values())

    def test_the_theater_hints_are_the_live_sensors(self):
        sources = legacy_literal("apt_intel", "_CERT_SOURCES")
        live = {name.lower(): tuple(meta["theater_hints"])
                for name, meta in sources.items()}
        assert apt_intel.FEED_THEATER_HINTS == live

    def test_the_request_headers_are_the_live_sensors(self):
        """K09: CISA sits behind Akamai. Legacy's comment says it is the
        realistic UA **plus** Accept/Accept-Language that passes the
        check; the port sent a different platform's UA and dropped both
        other headers."""
        live = legacy_literal("apt_intel", "_BROWSER_HEADERS")
        for spec in apt_intel.APT_INTEL_ADAPTER.requests:
            assert dict(spec.headers) == live

    def test_the_authorities_are_the_live_sensors(self):
        """Legacy names the authority in both LLM prompts (`:396`,
        `:474`) and in the submitted intel item (`:583`). It exists only
        in `_CERT_SOURCES`, so if it does not travel with the article,
        WP-2.7 has to re-derive a table the port already read."""
        sources = legacy_literal("apt_intel", "_CERT_SOURCES")
        assert apt_intel.FEED_AUTHORITIES == \
            {name.lower(): meta["authority"] for name, meta in sources.items()}

    def test_the_article_carries_its_authority(self):
        feed = self._articles(
            ("Advisory on remote code execution", "Patch immediately."))
        article = apt_intel.normalize(
            feed, context("apt_intel"))[0].flags["article"]
        assert article["authority"] == "CISA (US)"

    def test_region_is_deliberately_not_carried(self):
        """Nothing in the live sensor reads `region`. Same disposition as
        `gov_count` (A18): a field with no consumer is not carried
        forward just because it was in the table."""
        feed = self._articles(
            ("Advisory on remote code execution", "Patch immediately."))
        article = apt_intel.normalize(
            feed, context("apt_intel"))[0].flags["article"]
        assert "region" not in article

    def test_the_legacy_source_names_cover_every_feed(self):
        """The dedup key is rebuilt from the `_CERT_SOURCES` key, so a
        feed missing from the map would silently key on its v3 label and
        orphan that feed's migrated history."""
        sources = legacy_literal("apt_intel", "_CERT_SOURCES")
        assert apt_intel.LEGACY_SOURCE_NAMES == \
            {name.lower(): name for name in sources}

    def test_an_item_with_no_alphanumeric_title_is_still_considered(self):
        """Legacy only dedups when `title_key` is truthy (`:260-263`); an
        item whose title normalizes to nothing still reaches the ledgers
        and can be selected on its summary. The port skipped it outright,
        which is an insensitive difference — the blocking direction."""
        feed = self._articles(
            ("...", "Remote code execution under active attack."))
        assert self._scoped(feed) == ["..."]


# ── transcription pins, checked against the live source (WP-2.6 sweep) ──
#
# The apt_intel sweep established the rule these enforce: a value that
# looks correctly transcribed is not evidence that it was. Each test below
# compares a v3 literal against the legacy source PARSED AT TEST TIME, so
# the pin fails when production moves — which is the failure a hand-copied
# expected value cannot produce.

class TestCyberTranscriptionPins:
    def test_the_cloudflare_egress_pacing_is_the_live_one(self):
        """`rate_limit_group="cloudflare"` with no interval paces nothing:
        `runner.py:133-144` only spaces when `min_interval_sec > 0`, and
        four CF endpoints fire per cycle against a documented ~4/s cap."""
        live = literal_in("radar/scoring.py", "_CF_MIN_INTERVAL")
        assert cloudflare_radar.CF_MIN_INTERVAL_SEC == live == 0.35
        assert cloudflare_radar.CLOUDFLARE_RADAR_ADAPTER.min_interval_sec \
            == live

    def test_the_bgp_event_list_is_not_truncated(self):
        """`core.py:467-468` and `:2712-2716` carry `cf_bgp_hijacks` /
        `cf_bgp_leaks` whole. The port held a `[:10]` with no counterpart
        anywhere in production — the apt_intel truncation-width shape."""
        events = [{"leak_asn": 1000 + n, "leak_country": "tw",
                   "leaked_prefix_count": 42, "origin_asn": 3462,
                   "peer_count": 3} for n in range(14)]
        body = json.dumps({"result": {"asn_leaks": events}}).encode()
        draft = cloudflare_radar.normalize(
            synthetic(body, label="leaks"), context("cloudflare_radar"))[0]
        assert len(draft.flags["events"]) == 14
        assert draft.flags["count"] == 14

    def test_the_prefix_series_carries_every_sample(self):
        """`_compute_trend` regresses over the WHOLE array
        (`bgp_routing.py:81,119`) and reports `trend_entries = len(stats)`
        (`:140`). A least-squares slope is window-dependent, so a `[-24:]`
        here hands L2 a different WITHDRAWING/STABLE/GROWING label than
        production computes from the same response."""
        assert '"trend_entries": len(stats)' in \
            legacy_source("radar/sensors/bgp_routing.py")
        stats = [{"announced_prefixes": 1000 + n, "seen_ases": 50 + n}
                 for n in range(31)]
        body = json.dumps({"data": {"resource": "TW", "stats": stats}}).encode()
        draft = ripe_bgp.normalize(synthetic(body), context("ripe_bgp"))[0]
        assert len(draft.flags["prefix_series"]) == 31
        assert len(draft.flags["ases_series"]) == 31
        assert draft.flags["entries"] == 31

    def test_the_threatfox_value_is_one_literal_on_both_branches(self):
        """`core.py:1190` passes `"APT C2 Hit"` unconditionally — the OK
        entry carries it too. `value` is what `noise_excl_match` matches on
        (`core.py:950`), so a second literal on the quiet branch silently
        unmatches every migrated exclusion rule."""
        line = next(text for text in
                    legacy_source("radar/routes/core.py").splitlines()
                    if 'add_rat("threatfox"' in text)
        assert f'"{threatfox.RATIONALE_VALUE}"' in line
        assert "no hits" not in line

        body = json.dumps({"query_status": "ok", "data": []}).encode()
        drafts = threatfox.normalize(
            synthetic(body), context("threatfox", countries=("TW",),
                                     country_names={"TW": "Taiwan"}))
        assert drafts[0].status == STATUS_OK
        assert drafts[0].value == threatfox.RATIONALE_VALUE == "APT C2 Hit"

    def test_the_unknown_country_name_is_the_legacy_default(self):
        """`COUNTRY_COORDS.get(code, {}).get("name", "Unknown").lower()`
        (`threatfox.py:59`). The port defaulted to `""`, which its own tag
        guard then skips — a silently deleted literal."""
        assert '"name", "Unknown"' in \
            legacy_source("radar/sensors/threatfox.py")
        assert threatfox.UNKNOWN_COUNTRY_NAME == "Unknown"
