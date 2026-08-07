"""D1 §4's twenty external-API facts, as identifiers that tests can pin.

Design sheet §3-1 assigns each fact an ID; §6-2 rules that one fact
becomes one test, with the fact written into the test's name.

The reason is stated in D1 itself: **most of this knowledge exists only in
comments and branches**. A comment that stops being true stays green. A
test that stops being true fails, which is the whole difference between
recording knowledge and merely writing it down — and this knowledge is
expensive to rediscover, because each item was learned from an upstream
misbehaving in production.

`knowledge_refs` on an adapter and `KNOWLEDGE_TESTS` here are compared by
a meta-test: a fact claimed by an adapter with no test, or a test naming a
fact no adapter claims, fails the suite. Same shape as the ETL's
`S3_MIGRATE_35` registry and L2's clause registry, and for the same
reason — a transcription nobody compares is a transcription that drifts.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class KnowledgeItem:
    """One external-API fact, and the batch that owns porting it."""

    key: str
    summary: str
    batch: str          # "WP-2.6" | "WP-2.7"


WP26 = "WP-2.6"
WP27 = "WP-2.7"

#: Transcribed from the design sheet §3-1. The summaries are English
#: renderings; the IDs and their assignment to batches are the contract.
KNOWLEDGE: dict[str, KnowledgeItem] = {
    item.key: item for item in (
        KnowledgeItem("K01", "OpenSky: OAuth2, one limiter shared by three "
                             "adapters, and 429 retried only when "
                             "Retry-After is <= 120s", WP26),
        KnowledgeItem("K02", "AISHub answers a rate limit with HTTP 200 and "
                             "an empty body, not an error code", WP26),
        KnowledgeItem("K03", "check-host is a two-stage API (request_id, "
                             "wait, result); latency must not be penalised, "
                             "because the small hours of UTC are a "
                             "maintenance window", WP26),
        KnowledgeItem("K04", "OONI degrades after three consecutive empty "
                             "cycles", WP26),
        KnowledgeItem("K05", "CT log: multiple sources, and a 200 with an "
                             "empty array is an authoritative success", WP26),
        KnowledgeItem("K06", "IHR is reached at www.ihr.live; the iijlab "
                             "host redirects", WP26),
        KnowledgeItem("K07", "Diplomatic RSS liveness ledger "
                             "(JP_MOFA / CN_MFA / RU_MFA / KCNA)", WP27),
        KnowledgeItem("K08", "Two-stage parsing and a five-way feed "
                             "post-mortem classification", WP27),
        KnowledgeItem("K09", "CISA's RSS URLs rot; the advisories feed has "
                             "moved", WP26),
        KnowledgeItem("K10", "ThreatFox requires Auth-Key on get_iocs too",
                      WP26),
        KnowledgeItem("K11", "GreyNoise: v2 GNQL answers 410, community keys "
                             "have a daily quota, enterprise branches",
                      WP26),
        KnowledgeItem("K12", "gpsjam publishes a manifest; the newest "
                             "available day is found there, and it lags",
                      WP26),
        KnowledgeItem("K13", "t.me/s/ needs a user-agent pool and "
                             "exponential backoff on 403/429", WP27),
        KnowledgeItem("K14", "No free international NOTAM API exists", WP26),
        KnowledgeItem("K15", "Courtesy delays: RIPE 0.3s, GDELT 0.5s, "
                             "GreyNoise 0.5s, PeeringDB 10s, OONI 0.5s",
                      WP26),
        KnowledgeItem("K16", "USGS nuclear-test candidate criteria: "
                             "magnitude >= 4.0, shallow, inside an "
                             "adversary's territory", WP26),
        KnowledgeItem("K17", "NOAA space weather: Kp >= 6 or X-ray class M+ "
                             "suppresses false positives", WP26),
        KnowledgeItem("K18", "GDELT tone carries a day-of-week bias, so the "
                             "baseline is per weekday", WP27),
        KnowledgeItem("K19", "IODA and Cloudflare Radar are a two-source "
                             "pair", WP26),
        KnowledgeItem("K20", "Travel advisories: three governments, three "
                             "formats (RSS / Atom / HTML)", WP27),
    )
}

KNOWLEDGE_KEYS: tuple[str, ...] = tuple(sorted(KNOWLEDGE))

WP26_KNOWLEDGE: frozenset = frozenset(
    key for key, item in KNOWLEDGE.items() if item.batch == WP26)
WP27_KNOWLEDGE: frozenset = frozenset(
    key for key, item in KNOWLEDGE.items() if item.batch == WP27)

#: §6-2's one-fact-one-test mapping for the WP-2.6 batch. The value is the
#: test function name that pins the fact; the meta-test checks it exists.
KNOWLEDGE_TESTS: dict[str, str] = {
    "K01": "test_k01_opensky_three_adapters_share_one_rate_limit_group",
    "K02": "test_k02_aishub_rate_limit_is_http_200_with_empty_body",
    "K03": "test_k03_checkhost_two_stage_request_id_flow_and_no_latency_penalty",
    "K04": "test_k04_ooni_degrades_after_three_empty_cycles",
    "K05": "test_k05_ct_log_empty_200_is_authoritative_success",
    "K06": "test_k06_ihr_is_reached_at_the_www_ihr_live_mirror",
    "K09": "test_k09_cisa_advisory_feed_url_is_the_moved_one",
    "K10": "test_k10_threatfox_sends_auth_key_on_get_iocs",
    "K11": "test_k11_greynoise_gnql_failure_is_permanent_and_still_a_success",
    "K12": "test_k12_gpsjam_discovers_the_newest_day_from_the_manifest",
    "K14": "test_k14_notam_is_disabled_because_no_free_api_exists",
    "K15": "test_k15_courtesy_delays_are_declared_not_slept",
    "K16": "test_k16_usgs_nuclear_candidate_needs_magnitude_depth_and_territory",
    "K17": "test_k17_space_weather_suppresses_at_kp_six_or_xray_class_m",
    "K19": "test_k19_ioda_falls_back_to_cloudflare_radar",
}


def unknown_refs(refs) -> frozenset:
    """Knowledge references that name no D1 §4 item."""
    return frozenset(ref for ref in refs if ref not in KNOWLEDGE)


__all__ = ["KnowledgeItem", "KNOWLEDGE", "KNOWLEDGE_KEYS", "KNOWLEDGE_TESTS",
           "WP26_KNOWLEDGE", "WP27_KNOWLEDGE", "WP26", "WP27",
           "unknown_refs"]
