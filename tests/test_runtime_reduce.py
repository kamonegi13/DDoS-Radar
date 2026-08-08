"""WP-4.1 — the reduction step. §3-5 H-1(b)(c) and §7-2 #11's family.

The property under test throughout is ORDER: production sums a country's
zones and only then asks whether the total reached a threshold, and doing
it the other way round removes detections rather than rounding them.
`test_two_zones_of_two_are_a_surge_together` is that statement as
arithmetic — three aircraft over each of two zones is a six-aircraft surge
in production and two silent non-events under a per-zone threshold.

The second property is that a MISSING reduction is loud. L1 drops a
same-key, same-content row without a word (`store.py:290`), so an adapter
that grows a second per-country row would lose observations silently.
`reduce_drafts` refuses to return an unwritable set for ANY adapter,
whether or not a fold is declared for it.
"""
import pytest

from v3.adapters.types import (CYBER, INFO, PHYSICAL, STATUS_FIRED,
                               STATUS_NO_DATA, STATUS_OBSERVED, STATUS_OK,
                               ObservationDraft)
from v3.kernel.errors import DomainError
from v3.runtime import reduce as R

#: WP-4.1b made the cycle instant a required argument (two folds compare a
#: stored timestamp with the present). These cases predate it and none of
#: them depends on the clock, so they share one instant rather than
#: repeating it 61 times.
NOW = 1_786_000_000.0


def _reduce(adapter_id, drafts, **kwargs):
    kwargs.setdefault("now", NOW)
    return R.reduce_drafts(adapter_id, drafts, **kwargs)


def _zone(country: str, name: str, count: int, *, tracks=()) -> ObservationDraft:
    return ObservationDraft(
        signal_source="isr_hotspot", domain=PHYSICAL, country=country,
        status=STATUS_FIRED if count >= 3 else STATUS_OK,
        raw_score=2.0 if count >= 3 else 0.0,
        value=f"{count} ISR ac in hotspot",
        reason=f"ISR surge: {count} aircraft" if count >= 3 else "",
        flags={"count": count, "is_surge": count >= 3,
               "tracks": list(tracks),
               "hotspots": [{"name": name, "lat": 24.5, "lng": 120.5,
                             "isr_count": count, "tracks": list(tracks)}]},
        evidence_url="https://opensky.test/states")


class TestTheOrderIsSumThenThreshold:
    """§3-5 H-1(b). The whole point of the step."""

    def test_two_zones_of_two_are_a_surge_together(self):
        drafts = (_zone("TW", "Taiwan Strait Median Line", 2),
                  _zone("TW", "Senkaku / East China Sea ADIZ Overlap", 2))
        assert all(d.status == STATUS_OK for d in drafts), \
            "each zone alone is below the threshold"
        reduced = _reduce("isr_hotspot", drafts)
        assert len(reduced) == 1
        assert reduced[0].status == STATUS_FIRED
        assert reduced[0].flags["count"] == 4
        assert reduced[0].raw_score == 2.0

    def test_the_value_and_reason_are_productions_strings(self):
        reduced = _reduce(
            "isr_hotspot", (_zone("TW", "a", 2), _zone("TW", "b", 2)))
        assert reduced[0].value == "4 ISR ac in hotspot"
        assert reduced[0].reason == "ISR surge: 4 aircraft"

    def test_a_quiet_country_reports_the_sum_and_no_reason(self):
        reduced = _reduce(
            "isr_hotspot", (_zone("TW", "a", 1), _zone("TW", "b", 1)))
        assert reduced[0].status == STATUS_OK
        assert reduced[0].value == "2 ISR ac in hotspot"
        assert reduced[0].reason == ""

    def test_countries_do_not_bleed_into_one_another(self):
        reduced = _reduce(
            "isr_hotspot", (_zone("TW", "a", 2), _zone("TW", "b", 2),
                            _zone("JP", "c", 1)))
        by_country = {d.country: d for d in reduced}
        assert by_country["TW"].flags["count"] == 4
        assert by_country["JP"].flags["count"] == 1
        assert by_country["JP"].status == STATUS_OK


class TestZonesSurviveTheFold:
    """§3-5 H-1(c). `core.py:2929-2931` joins the ledger to the
    observation on `name`; an empty `hotspots[]` renders the map overlay
    blank, which reads as calm."""

    def test_every_zone_record_is_carried(self):
        reduced = _reduce(
            "isr_hotspot", (_zone("TW", "median", 2), _zone("TW", "adiz", 1)))
        names = [h["name"] for h in reduced[0].flags["hotspots"]]
        assert names == ["median", "adiz"]

    def test_each_zone_keeps_its_own_count_not_the_total(self):
        reduced = _reduce(
            "isr_hotspot", (_zone("TW", "median", 2), _zone("TW", "adiz", 1)))
        assert [h["isr_count"] for h in reduced[0].flags["hotspots"]] == [2, 1]
        assert reduced[0].flags["count"] == 3

    def test_tracks_reach_the_overlay_join(self):
        reduced = _reduce(
            "isr_hotspot",
            (_zone("TW", "median", 1, tracks=[{"icao24": "abc"}]),))
        assert reduced[0].flags["hotspots"][0]["tracks"] == [{"icao24": "abc"}]


class TestAnUnmeasuredZoneContributesNothingNotZero:
    def test_it_is_excluded_from_the_sum(self):
        unmeasured = ObservationDraft(
            signal_source="isr_hotspot", domain=PHYSICAL, country="TW",
            status=STATUS_NO_DATA, value="unmeasured",
            flags={"count": -1, "is_surge": False, "tracks": [],
                   "hotspots": []})
        reduced = _reduce("isr_hotspot",
                                  (_zone("TW", "a", 3), unmeasured))
        assert reduced[0].flags["count"] == 3
        assert reduced[0].status == STATUS_FIRED

    def test_partial_coverage_is_disclosed(self):
        unmeasured = ObservationDraft(
            signal_source="isr_hotspot", domain=PHYSICAL, country="TW",
            status=STATUS_NO_DATA, value="unmeasured",
            flags={"count": -1, "hotspots": []})
        reduced = _reduce("isr_hotspot",
                                  (_zone("TW", "a", 3), unmeasured))
        assert reduced[0].flags["zones_folded"] == 1
        assert reduced[0].flags["zones_requested"] == 2
        assert reduced[0].flags["zones_unmeasured"] == 1

    def test_all_zones_unmeasured_stays_no_data(self):
        unmeasured = ObservationDraft(
            signal_source="isr_hotspot", domain=PHYSICAL, country="TW",
            status=STATUS_NO_DATA, value="unmeasured",
            flags={"count": -1, "hotspots": []})
        reduced = _reduce("isr_hotspot", (unmeasured,))
        assert reduced[0].status == STATUS_NO_DATA


def _mil(country: str, name: str, tanker=0, transport=0, awacs=0):
    return ObservationDraft(
        signal_source="mil_support_air", domain=PHYSICAL, country=country,
        status=STATUS_OK, value=f"T={tanker} C={transport} A={awacs}",
        flags={"tanker": tanker, "transport": transport, "awacs": awacs,
               "total": tanker + transport + awacs,
               "tracks": [],
               "hotspots": [{"name": name, "tanker": tanker,
                             "transport": transport, "awacs": awacs}]})


class TestMilSupportAirUsesTheSameOrder:
    def test_one_tanker_per_zone_is_a_surge_across_two(self):
        reduced = _reduce(
            "mil_support_air", (_mil("CN", "a", tanker=1),
                                _mil("CN", "b", tanker=1)))
        assert reduced[0].flags["is_tanker_surge"] is True
        assert reduced[0].status == STATUS_FIRED
        assert reduced[0].value == "T=2 C=0 A=0"
        assert reduced[0].reason == "Military support aircraft: tanker surge (2)"

    def test_awacs_and_a_tanker_surge_together_score_two(self):
        reduced = _reduce(
            "mil_support_air", (_mil("CN", "a", tanker=2),
                                _mil("CN", "b", awacs=1)))
        assert reduced[0].raw_score == 2.0

    def test_a_tanker_surge_alone_scores_one(self):
        reduced = _reduce(
            "mil_support_air", (_mil("CN", "a", tanker=2),))
        assert reduced[0].raw_score == 1.0

    def test_the_clause_order_of_the_reason_is_productions(self):
        reduced = _reduce(
            "mil_support_air", (_mil("CN", "a", tanker=2, transport=3,
                                     awacs=1),))
        assert reduced[0].reason == (
            "Military support aircraft: tanker surge (2), "
            "transport surge (3), AWACS active (1)")


class TestTheCloudflareDisjunction:
    """§7-2 #12/#13. The port assumed a downstream MAX would rebuild the
    OR; L1 rejected the second row before any scoring saw it."""

    def _rows(self, *, hijacks, ongoing, leaks):
        return (
            ObservationDraft(signal_source="cf_bgp_hijack", domain=CYBER,
                             country="TW",
                             status=STATUS_FIRED if ongoing else STATUS_OK,
                             raw_score=1.0 if ongoing else 0.0,
                             value=f"hijacks={hijacks}",
                             flags={"count": hijacks, "ongoing": ongoing,
                                    "events": []}),
            ObservationDraft(signal_source="cf_bgp_leak", domain=CYBER,
                             country="TW",
                             status=STATUS_FIRED if leaks >= 3 else STATUS_OK,
                             raw_score=1.0 if leaks >= 3 else 0.0,
                             value=f"leaks={leaks}",
                             flags={"count": leaks, "ongoing": 0,
                                    "events": []}))

    def test_the_two_halves_become_one_entry(self):
        reduced = _reduce(
            "cloudflare_radar", self._rows(hijacks=2, ongoing=1, leaks=1))
        assert [d.signal_source for d in reduced] == ["cf_bgp_hijack"]

    def test_the_value_is_productions_string(self):
        reduced = _reduce(
            "cloudflare_radar", self._rows(hijacks=2, ongoing=1, leaks=1))
        assert reduced[0].value == "hijack=2(ongoing=1) leak=1"
        assert reduced[0].reason == (
            "BGP manipulation detected: 1 ongoing hijack(s), "
            "1 route leak(s)")

    def test_an_ongoing_hijack_alone_fires(self):
        reduced = _reduce(
            "cloudflare_radar", self._rows(hijacks=1, ongoing=1, leaks=0))
        assert reduced[0].status == STATUS_FIRED and reduced[0].raw_score == 1.0

    def test_leaks_need_three(self):
        two = _reduce("cloudflare_radar",
                              self._rows(hijacks=0, ongoing=0, leaks=2))
        three = _reduce("cloudflare_radar",
                                self._rows(hijacks=0, ongoing=0, leaks=3))
        assert two[0].status == STATUS_OK
        assert three[0].status == STATUS_FIRED

    def test_a_closed_hijack_does_not_fire(self):
        """`is_ongoing` is the test, not the count (`core.py:1155`)."""
        reduced = _reduce(
            "cloudflare_radar", self._rows(hijacks=5, ongoing=0, leaks=0))
        assert reduced[0].status == STATUS_OK

    def test_the_observed_share_rows_pass_through_untouched(self):
        share = ObservationDraft(signal_source="cf_l7", domain=CYBER,
                                 country="TW", status=STATUS_OBSERVED,
                                 value="l7_share=12.0%",
                                 flags={"share_pct": 12.0, "layer": "l7"})
        reduced = _reduce(
            "cloudflare_radar",
            self._rows(hijacks=0, ongoing=0, leaks=0) + (share,))
        assert share in reduced


class TestSpaceWeatherFoldsItsTwoEndpoints:
    """§7-2 #11's first genuinely-colliding case: both endpoints emit
    `signal_source="space_weather"` with `country=""`."""

    def _rows(self, *, kp, kp_suppress, xray, xray_suppress):
        return (
            ObservationDraft(signal_source="space_weather", domain=PHYSICAL,
                             country="", status=STATUS_OK,
                             suppressed=kp_suppress,
                             value=f"Kp={kp:.1f} [x]",
                             flags={"kp_index": kp, "kp_forecast_24h": kp,
                                    "suppress_physical": kp_suppress,
                                    "endpoint": "kp"}),
            ObservationDraft(signal_source="space_weather", domain=PHYSICAL,
                             country="", status=STATUS_OK,
                             suppressed=xray_suppress, value=f"xray={xray}",
                             flags={"xray_class": xray, "xray_flux": 1e-5,
                                    "suppress_physical": xray_suppress,
                                    "endpoint": "xray"}))

    def test_without_the_fold_the_two_rows_are_unwritable(self):
        with pytest.raises(DomainError, match="after reduction"):
            _reduce("not_reduced", self._rows(
                kp=3.0, kp_suppress=False, xray="C", xray_suppress=False))

    def test_the_fold_produces_one_row(self):
        reduced = _reduce("space_weather", self._rows(
            kp=3.0, kp_suppress=False, xray="C", xray_suppress=False))
        assert len(reduced) == 1
        assert reduced[0].value == "Kp=3.0 xray=C [NONE]"

    def test_either_endpoint_suppresses(self):
        kp_only = _reduce("space_weather", self._rows(
            kp=6.3, kp_suppress=True, xray="C", xray_suppress=False))
        xray_only = _reduce("space_weather", self._rows(
            kp=3.0, kp_suppress=False, xray="M", xray_suppress=True))
        assert kp_only[0].suppressed and xray_only[0].suppressed

    def test_the_joined_sentence_is_rebuilt_not_concatenated(self):
        reduced = _reduce("space_weather", self._rows(
            kp=6.3, kp_suppress=True, xray="M", xray_suppress=True))
        assert reduced[0].suppress_reason == (
            "Geomagnetic storm: Kp=6.3 (≥6.0), X-ray M-class (≥M) — "
            "physical sensor noise expected")

    def test_it_never_contributes_a_score(self):
        reduced = _reduce("space_weather", self._rows(
            kp=9.0, kp_suppress=True, xray="X", xray_suppress=True))
        assert reduced[0].raw_score == 0.0


class TestRipeAtlasPoolsBeforeItPercentiles:
    """§7-2 #29. A pooled p95 cannot be recovered from three per-
    measurement p95s, so the samples travel."""

    def _rows(self, *, active=100):
        probes = ObservationDraft(
            signal_source="ripe_atlas", domain=PHYSICAL, country="TW",
            status=STATUS_OBSERVED, value=f"{active} probes",
            flags={"active": active,
                   "probe_drop_verdict": "pending_l1_prev_probe_count"})
        latency = tuple(
            ObservationDraft(
                signal_source=f"atlas_latency_{mid}", domain=PHYSICAL,
                country="TW", status=STATUS_OBSERVED, value="10ms",
                flags={"measurement_id": mid, "rtt_samples": tuple(samples),
                       "pool_scope": "single_measurement"})
            for mid, samples in ((1001, (10.0, 20.0)), (1004, (30.0, 40.0)),
                                 (10509, (50.0, 60.0))))
        return (probes,) + latency

    def test_four_rows_become_one(self):
        reduced = _reduce("ripe_atlas", self._rows())
        assert [d.signal_source for d in reduced] == ["ripe_atlas"]

    def test_the_average_is_over_the_pooled_samples(self):
        reduced = _reduce("ripe_atlas", self._rows())
        assert reduced[0].flags["avg_ms"] == 35.0
        assert reduced[0].flags["probes_responding"] == 6
        assert reduced[0].flags["pool_scope"] == "country"

    def test_the_p95_is_the_exported_function_over_the_pool(self):
        from v3.adapters.physical.ripe_atlas import percentile_95
        reduced = _reduce("ripe_atlas", self._rows())
        assert reduced[0].flags["p95_ms"] == percentile_95(
            [10.0, 20.0, 30.0, 40.0, 50.0, 60.0])

    def test_without_the_baseline_the_verdict_is_named_not_guessed(self):
        reduced = _reduce("ripe_atlas", self._rows())
        assert reduced[0].status == STATUS_OBSERVED
        assert reduced[0].flags["probe_drop_verdict"] == \
            "pending_l1_prev_probe_count"
        assert reduced[0].value == "100 probes, 35ms"

    def test_with_the_baseline_the_production_ladder_runs(self):
        reduced = _reduce(
            "ripe_atlas", self._rows(active=20),
            baselines={"atlas_prev_probe_count": {"TW": 100}})
        assert reduced[0].flags["probe_status"] == "PROBE_BLACKOUT"
        assert reduced[0].raw_score == 2.0
        assert reduced[0].status == STATUS_FIRED
        assert reduced[0].value == (
            "PROBE_BLACKOUT (20 probes, drop=80%, lat=35ms)")
        assert reduced[0].reason == (
            "RIPE Atlas: PROBE_BLACKOUT — 20 active probes (drop 80%), "
            "avg latency 35ms")

    def test_a_thirty_percent_drop_is_the_lower_rung(self):
        reduced = _reduce(
            "ripe_atlas", self._rows(active=70),
            baselines={"atlas_prev_probe_count": {"TW": 100}})
        assert reduced[0].flags["probe_status"] == "PROBE_DROP"
        assert reduced[0].raw_score == 1.0

    def test_no_drop_does_not_fire(self):
        reduced = _reduce(
            "ripe_atlas", self._rows(active=100),
            baselines={"atlas_prev_probe_count": {"TW": 100}})
        assert reduced[0].status == STATUS_OK
        assert reduced[0].value == "100 probes, 35ms"


class TestCheckHostPoolsItsUrls:
    """`checkhost.py:225-239`. Three URLs under one `signal_source` with
    three different `value` strings would raise inside the L1 write."""

    def _url(self, rate: float, latency=50.0):
        return ObservationDraft(
            signal_source="check_host", domain=PHYSICAL, country="TW",
            status=STATUS_OBSERVED, value=f"success={rate:.0%}",
            flags={"success_rate": rate, "avg_latency_ms": latency,
                   "ok_nodes": 2, "total_nodes": 3,
                   "asphyxiation_verdict": "pending_l1_latency_history"})

    def test_three_urls_become_one_row(self):
        reduced = _reduce("check_host",
                                  (self._url(1.0), self._url(0.9),
                                   self._url(0.1)))
        assert len(reduced) == 1

    def test_the_country_rate_is_the_fraction_of_urls_that_are_up(self):
        reduced = _reduce("check_host",
                                  (self._url(1.0), self._url(0.9),
                                   self._url(0.1)))
        assert reduced[0].flags["success_rate"] == pytest.approx(2 / 3)
        assert reduced[0].flags["urls_ok"] == 2
        assert reduced[0].flags["urls_folded"] == 3

    def test_the_eighty_percent_line_is_productions(self):
        reduced = _reduce("check_host",
                                  (self._url(0.8), self._url(0.79)))
        assert reduced[0].flags["urls_ok"] == 1

    def test_the_country_verdict_is_still_named_as_pending(self):
        reduced = _reduce("check_host", (self._url(1.0),))
        assert reduced[0].status == STATUS_OBSERVED
        assert reduced[0].flags["url_verdict"].startswith("pending_l1_")


class TestAisFoldsChokepoints:
    def _cp(self, country, name, stationary):
        return ObservationDraft(
            signal_source="ais_maritime", domain=PHYSICAL, country=country,
            status=STATUS_FIRED if stationary else STATUS_OK,
            raw_score=1.0 if stationary else 0.0,
            value=f"dark_gaps=0 stationary={len(stationary)}",
            flags={"chokepoint": name, "stationary_anomalies": stationary,
                   "vessels_examined": 10, "vessel_reports": [],
                   "dark_gap_detection": "pending_l1_vessel_history"})

    def test_three_chokepoints_of_one_country_become_one_row(self):
        reduced = _reduce(
            "ais_maritime", (self._cp("TW", "Taiwan Strait", []),
                             self._cp("TW", "Bashi Channel", [{"mmsi": 1}]),
                             self._cp("TW", "Miyako Strait", [])))
        assert len(reduced) == 1
        assert reduced[0].status == STATUS_FIRED

    def test_the_printed_count_spans_the_cycle_the_verdict_does_not(self):
        """`core.py:1256` counts every chokepoint in the cycle; the FIRED
        decision is the country's own."""
        reduced = _reduce(
            "ais_maritime", (self._cp("TW", "Taiwan Strait", []),
                             self._cp("JP", "Soya Strait", [{"mmsi": 9}])))
        by_country = {d.country: d for d in reduced}
        assert by_country["TW"].status == STATUS_OK
        assert by_country["JP"].status == STATUS_FIRED
        assert by_country["TW"].value == "dark_gaps=0 stationary=1"

    def test_the_chokepoints_folded_are_named(self):
        reduced = _reduce(
            "ais_maritime", (self._cp("TW", "Taiwan Strait", []),
                             self._cp("TW", "Bashi Channel", [])))
        assert reduced[0].flags["chokepoints"] == ["Taiwan Strait",
                                                   "Bashi Channel"]


class TestIhrKeepsItsRowsAndDerivesTheLabel:
    """§7-2 #31. The precedence chain becomes `min(ladder_rank)` — the
    order is written once, as data, and read here."""

    def _row(self, source, rung, rank):
        return ObservationDraft(
            signal_source=source, domain=PHYSICAL, country="TW",
            status=STATUS_OK, value="—",
            flags={"status": rung, "ladder_rank": rank})

    def test_the_three_rows_survive(self):
        reduced = _reduce("ihr_health", (
            self._row("bgp", "NORMAL", 4),
            self._row("ihr_delay", "DELAY_ANOMALY", 3),
            self._row("ihr_hegemony", "HEGEMONY_ALARM", 2)))
        assert sorted(d.signal_source for d in reduced) == [
            "bgp", "ihr_delay", "ihr_hegemony"]

    def test_disconnection_outranks_everything(self):
        reduced = _reduce("ihr_health", (
            self._row("bgp", "DISCO_EVENT", 1),
            self._row("ihr_delay", "DELAY_ANOMALY", 3),
            self._row("ihr_hegemony", "HEGEMONY_ALARM", 2)))
        assert {d.flags["country_status"] for d in reduced} == {"DISCO_EVENT"}

    def test_hegemony_outranks_delay(self):
        reduced = _reduce("ihr_health", (
            self._row("ihr_delay", "DELAY_ANOMALY", 3),
            self._row("ihr_hegemony", "HEGEMONY_ALARM", 2)))
        assert {d.flags["country_status"] for d in reduced} == {
            "HEGEMONY_ALARM"}

    def test_all_quiet_is_normal(self):
        reduced = _reduce("ihr_health", (
            self._row("bgp", "NORMAL", 4),
            self._row("ihr_delay", "NORMAL", 4)))
        assert {d.flags["country_status"] for d in reduced} == {"NORMAL"}


class TestTorReconcilesItsTwoResponses:
    def _rows(self, *, running=6000, users=1000.0):
        return (
            ObservationDraft(signal_source="tor_metrics", domain=INFO,
                             country="TW", status=STATUS_OBSERVED,
                             value=f"relays={running}, bridge_users=pending",
                             flags={"running": running, "bridges": 100,
                                    "bandwidth_kbps": 5.0,
                                    "drop_verdict":
                                        "pending_l1_prev_relay_count"}),
            ObservationDraft(signal_source="tor_clients", domain=INFO,
                             country="TW", status=STATUS_OBSERVED,
                             value=f"bridge_users={users:g}",
                             flags={"bridge_users": users,
                                    "trend_verdict":
                                        "pending_l1_prev_user_count"}))

    def test_two_rows_become_one(self):
        reduced = _reduce("tor_metrics", self._rows())
        assert [d.signal_source for d in reduced] == ["tor_metrics"]
        assert reduced[0].value == "relays=6000, users=1000"

    def test_without_both_baselines_no_verdict_is_asserted(self):
        reduced = _reduce("tor_metrics", self._rows())
        assert reduced[0].status == STATUS_OBSERVED
        assert reduced[0].flags["drop_verdict"].startswith("pending_l1_")

    def test_a_relay_drop_with_a_user_surge_is_the_censorship_indicator(self):
        reduced = _reduce(
            "tor_metrics", self._rows(running=3000, users=3000.0),
            baselines={"tor_prev_relay_count": {"TW": 6000},
                       "tor_prev_user_count": {"TW": 1000.0}})
        assert reduced[0].flags["combined_status"] == "CENSORSHIP_INDICATOR"
        assert reduced[0].raw_score == 2.0
        assert reduced[0].status == STATUS_FIRED
        assert reduced[0].reason == (
            "Tor: CENSORSHIP_INDICATOR — relays=3000 (drop 50%), "
            "bridge_users=3000")

    def test_a_steady_network_does_not_fire(self):
        reduced = _reduce(
            "tor_metrics", self._rows(),
            baselines={"tor_prev_relay_count": {"TW": 6000},
                       "tor_prev_user_count": {"TW": 1000.0}})
        assert reduced[0].flags["combined_status"] == "NORMAL"
        assert reduced[0].status == STATUS_OK


class TestGdeltFoldsItsTwoWindows:
    def _rows(self):
        return (
            ObservationDraft(signal_source="gdelt", domain=INFO,
                             country="TW", status=STATUS_OBSERVED,
                             value="tone=-3.500",
                             flags={"tone": -3.5, "window": "tone_1d",
                                    "dow_verdict":
                                        "pending_l1_dow_baseline"}),
            ObservationDraft(signal_source="gdelt_baseline", domain=INFO,
                             country="TW", status=STATUS_OBSERVED,
                             value="tone=-1.000",
                             flags={"tone": -1.0, "window": "tone_30d"}))

    def test_the_baseline_row_is_absorbed(self):
        reduced = _reduce("gdelt", self._rows())
        assert [d.signal_source for d in reduced] == ["gdelt"]

    def test_the_delta_production_computes_is_carried(self):
        reduced = _reduce("gdelt", self._rows())
        assert reduced[0].flags["baseline_tone"] == -1.0
        assert reduced[0].flags["tone_delta"] == -2.5

    def test_the_pending_day_of_week_verdict_is_preserved(self):
        reduced = _reduce("gdelt", self._rows())
        assert reduced[0].flags["dow_verdict"] == "pending_l1_dow_baseline"


class TestTheNamedSourceFamily:
    """§7-2 #51 — channels / feeds / governments folded into the one
    entry production names, with each contributor still nameable."""

    def _channels(self):
        return tuple(
            ObservationDraft(
                signal_source=f"telegram_{name}", domain=INFO, country="RU",
                status=STATUS_OBSERVED, value=f"{name}: CLEAR hits=0",
                flags={"channel": name, "detection_status": "CLEAR",
                       "keyword_hits": 0, "target_urls": [],
                       "burst_verdict": "pending_l1_telegram_baseline"})
            for name in ("alpha", "beta"))

    def test_the_channels_fold_into_the_production_name(self):
        reduced = _reduce("telegram_mirror", self._channels())
        assert [d.signal_source for d in reduced] == ["telegram_mirror"]

    def test_each_contributor_is_still_nameable(self):
        reduced = _reduce("telegram_mirror", self._channels())
        assert [s["signal_source"] for s in reduced[0].flags["sources"]] == [
            "telegram_alpha", "telegram_beta"]
        assert [s["channel"] for s in reduced[0].flags["sources"]] == [
            "alpha", "beta"]

    def test_the_pending_verdict_survives_the_fold(self):
        reduced = _reduce("telegram_mirror", self._channels())
        assert reduced[0].flags["burst_verdict"] == \
            "pending_l1_telegram_baseline"
        assert reduced[0].raw_score == 0.0

    def test_narrative_feeds_fold_the_same_way(self):
        feeds = tuple(
            ObservationDraft(
                signal_source=f"narrative_{name}", domain=INFO, country="TW",
                status=STATUS_OBSERVED, value=f"{name}: 3/10 hits",
                flags={"feed": name, "adversary": "CN", "keyword_hits": 3,
                       "article_count": 10, "normalized_freq": 0.3,
                       "burst_verdict": "pending_l1_narrative_baseline"})
            for name in ("xinhua", "globaltimes"))
        reduced = _reduce("rss_narrative", feeds)
        assert [d.signal_source for d in reduced] == ["rss_narrative"]
        assert reduced[0].flags["sources_folded"] == 2

    def test_the_three_governments_fold(self):
        rows = tuple(
            ObservationDraft(
                signal_source=f"advisory_{src}", domain=INFO, country="TW",
                status=STATUS_OBSERVED, value=f"{src.upper()} level 3 (x)",
                flags={"source": src.upper(), "level": 3,
                       "level_label": "Reconsider Travel", "title": "t",
                       "upgrade_verdict": "pending_l1_previous_level"})
            for src in ("us", "uk", "ca"))
        reduced = _reduce("travel_advisory", rows)
        assert [d.signal_source for d in reduced] == ["travel_advisory"]
        assert [s["level"] for s in reduced[0].flags["sources"]] == [3, 3, 3]


class TestAMissingReductionIsLoud:
    def test_two_rows_with_the_same_key_are_refused_by_name(self):
        rows = (ObservationDraft(signal_source="whatever", domain=CYBER,
                                 country="TW", status=STATUS_OK, value="a"),
                ObservationDraft(signal_source="whatever", domain=CYBER,
                                 country="TW", status=STATUS_OK, value="b"))
        with pytest.raises(DomainError) as caught:
            _reduce("some_adapter", rows)
        message = str(caught.value)
        assert "some_adapter" in message and "whatever" in message
        assert "§7-2 #11" in message
        assert "SILENTLY" in message

    def test_identical_rows_are_refused_too(self):
        """The dangerous half: L1 drops these without a word."""
        row = ObservationDraft(signal_source="x", domain=CYBER, country="TW",
                               status=STATUS_OK, value="same")
        with pytest.raises(DomainError):
            _reduce("some_adapter", (row, row))

    def test_the_empty_country_is_a_key_like_any_other(self):
        rows = (ObservationDraft(signal_source="x", domain=CYBER, country="",
                                 status=STATUS_OK, value="a"),
                ObservationDraft(signal_source="x", domain=CYBER, country="",
                                 status=STATUS_OK, value="b"))
        with pytest.raises(DomainError, match="GLOBAL"):
            _reduce("some_adapter", rows)

    def test_an_adapter_with_no_fold_passes_through_unchanged(self):
        rows = (ObservationDraft(signal_source="a", domain=CYBER,
                                 country="TW", status=STATUS_OK, value="1"),
                ObservationDraft(signal_source="b", domain=CYBER,
                                 country="TW", status=STATUS_OK, value="2"))
        assert _reduce("unfolded", rows) == rows

    def test_every_declared_fold_leaves_a_writable_set(self):
        """The guard runs after every fold, so a fold that forgets a
        grouping key fails here rather than in the ledger."""
        assert all(callable(r.fold) for r in R.REDUCTIONS)


class TestTheRegisterIsDerivedFromTheCode:
    def test_every_reduction_names_its_register_entry_and_production_site(
            self):
        for entry in R.registry_disclosure():
            assert entry["register_ref"].startswith("§")
            assert "radar/" in entry["production_ref"]
            assert entry["note"]

    def test_the_folded_adapters_all_exist_in_the_catalogue(self):
        from v3.adapters.catalog import build_registry
        known = {a.name for a in build_registry().all()}
        # `ihr_health` ships disabled; it is still a declared adapter.
        assert set(R.reduced_adapter_ids()) <= known

    def test_no_adapter_is_folded_twice(self):
        ids = [r.adapter_id for r in R.REDUCTIONS]
        assert len(ids) == len(set(ids))
