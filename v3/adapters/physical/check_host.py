"""`check_host` — S1-SENS-038/039/040, D1 §4 K03. Three expensive facts.

K03 is three pieces of knowledge that cost real incidents to learn:

1. **Two-stage API.** The first request returns a `request_id`; the
   measurement is fetched from a second URL five seconds later. That is a
   CONTINUATION, not a fallback — "A then B(A)" — and the model had no way
   to say it until `RequestContinuation` existed. Declared as two
   independent requests, `{request_id}` had no value at plan time and the
   whole adapter was skipped as `unresolved_placeholder` every cycle.
2. **`null` means pending, not failed.** A node that has not answered yet
   appears as `null` — at the node level or as an element inside its list.
   Counting those as failures dilutes the success rate systematically and
   manufactures blackouts. GAP-S2 records that nothing tested this.
3. **Latency must not be penalised.** Intercontinental checks exceed
   3000 ms when everything is healthy, and the small hours of UTC are a
   maintenance window; that is why the country verdict is normalised by
   hour-of-day rather than compared to a fixed floor.

The asphyxiation rule (S1-SENS-039) is the CDN-mask detector: a success
rate at 99-100% while latency triples means the edge is answering and
what is behind it is not. Its rolling average is computed BEFORE the
current sample is appended, so a spike cannot contaminate the baseline it
is measured against — an ordering that is easy to "clean up" into
uselessness, so it is stated and tested.

**Two dependencies are declared rather than implemented.** The country
verdict needs the `checkhost_hod` baseline (DP4 puts the hour-of-day
Z-score in one place: L1 plus L2's trend module), and the asphyxiation
rule needs the per-URL latency history that lived in a class variable
(DP3). Until that wiring lands, per-URL results are reported and the
country verdict is OBSERVED rather than guessed.
"""
from __future__ import annotations

from v3.adapters.common import as_float, as_int, load_json, mapping_or_empty
from v3.adapters.types import (AdapterId, NormalizeContext, ObservationDraft,
                               PHYSICAL, RequestContinuation, RequestSpec,
                               ResponseValue, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.kernel import Window

CHECK_HOST = AdapterId("check_host")

_CHECK_URL = "https://check-host.net/check-http"
_RESULT_URL = "https://check-host.net/check-result/{request_id}"

#: Five seconds between the two stages (K03). Declared, not slept.
RESULT_DELAY_SEC = 5.0
MAX_NODES = 5
#: The five vantage points, in `radar/sensors/checkhost.py:16-17`'s order.
#: They are the measurement's aperture — `summarise_nodes` labels results
#: JP/US/DE/NL/FR — so they are declared here rather than left to the
#: server's choice.
NODES: tuple = ("jp1.node.check-host.net", "us1.node.check-host.net",
                "de1.node.check-host.net", "nl1.node.check-host.net",
                "fr1.node.check-host.net")
MAX_URLS_PER_COUNTRY = 3
URL_COOLDOWN_SEC = 300.0
#: A single responding node is not evidence; two is the floor.
MIN_RESPONDING_CHECKS = 2
#: Per-URL verdict cutoffs (S1-SENS-038).
URL_OK_RATE = 0.8
URL_PARTIAL_RATE = 0.3
#: Asphyxiation (S1-SENS-039).
LATENCY_HISTORY_LEN = 12
LATENCY_MIN_SAMPLES = 3
ASPHYXIATION_MIN_RATE = 0.99
ASPHYXIATION_LATENCY_FACTOR = 3.0
#: `CHECKHOST_TIMEOUT_MS` — the label boundary, NOT a scoring input.
NODE_TIMEOUT_MS = 3000.0

_CADENCE = Window.from_days(1.0, cadence_sec=600.0)
_FRESHNESS_HORIZON_SEC = 1800.0


def summarise_nodes(node_results) -> dict:
    """Per-node check arrays -> `{ok, considered, pending, success_rate, ...}`.

    The array is `[ok_flag, seconds, status_msg, http_code, ip]`. Success
    is `ok_flag == 1` AND (no HTTP code, or a code below 400) — a node
    that connected and got a 503 did not reach a working service.
    """
    total_nodes = 0
    ok_nodes = 0
    pending = 0
    latencies: list[float] = []
    per_node: dict[str, str] = {}

    for node, checks in mapping_or_empty(node_results).items():
        label = str(node).split(".")[0][:3].upper()
        if not isinstance(checks, list):
            per_node[label] = "PENDING"          # K03: not a failure
            pending += 1
            continue
        for check in checks:
            if check is None:
                per_node[label] = "PENDING"      # K03, the inner shape
                pending += 1
                continue
            if not isinstance(check, list) or len(check) < 2:
                continue
            total_nodes += 1
            http_code = as_int(check[3], None) if len(check) > 3 else None
            is_ok = bool(check[0] == 1
                         and (http_code is None or http_code < 400))
            ok_nodes += 1 if is_ok else 0
            seconds = as_float(check[1], None)
            if seconds is not None and seconds > 0:
                milliseconds = seconds * 1000.0
                latencies.append(milliseconds)
                per_node[label] = ("TIMEOUT" if milliseconds > NODE_TIMEOUT_MS
                                   else "OK" if is_ok else "FAIL")
            else:
                per_node[label] = "OK" if is_ok else "FAIL"

    success_rate = (round(ok_nodes / total_nodes, 3)
                    if total_nodes >= MIN_RESPONDING_CHECKS else None)
    # `ok_nodes` / `total_nodes` are production's names for these two
    # counts (`radar/sensors/checkhost.py:159-160`) and they are read by
    # name downstream: `radar.js:1167` renders `${r.ok_nodes}/${r.total_nodes}`
    # behind an `!== undefined` guard, so a renamed field does not show an
    # error — it shows an empty string where the node tally used to be.
    return {"ok_nodes": ok_nodes, "total_nodes": total_nodes,
            "pending": pending,
            "success_rate": success_rate,
            "avg_latency_ms": (round(sum(latencies) / len(latencies))
                               if latencies else None),
            "node_ok": per_node}


def url_status(success_rate) -> str:
    """The PER-URL verdict — `radar/sensors/checkhost.py:165-167`.

    An unmeasurable URL is `BLACKOUT`, not `UNKNOWN`: production's
    expression is `"OK" if success_rate and success_rate >= 0.8 else
    "PARTIAL" if success_rate and success_rate >= 0.3 else "BLACKOUT"`,
    and `None` fails both guards. `UNKNOWN` belongs to the COUNTRY
    verdict, one level up (`:244-245`), where it means "no URL returned a
    usable result at all". Conflating the two turned a URL that could not
    be reached into a URL nobody asked about — the quieter of the two, and
    the wrong one.
    """
    if success_rate is None:
        return "BLACKOUT"
    if success_rate >= URL_OK_RATE:
        return "OK"
    return "PARTIAL" if success_rate >= URL_PARTIAL_RATE else "BLACKOUT"


def is_asphyxiation(success_rate, avg_latency_ms, rolling_avg_ms) -> bool:
    """S1-SENS-039. The caller supplies the rolling average from L1.

    The parameter exists so the ordering rule survives the move: the
    baseline passed in is the history BEFORE this sample, which is what
    keeps a spike from raising the bar it is being measured against.
    """
    if success_rate is None or avg_latency_ms is None:
        return False
    if rolling_avg_ms is None:
        return False                      # fewer than three samples
    return bool(success_rate >= ASPHYXIATION_MIN_RATE
                and avg_latency_ms > rolling_avg_ms
                * ASPHYXIATION_LATENCY_FACTOR)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """Stage-two result payload -> one observation per country.

    The stage-one payload carries a `request_id` and no measurement, so
    it produces nothing — production discards it the same way
    (`radar/sensors/checkhost.py:60-63` reads the handle and nothing
    else). The two stages are joined by `RequestContinuation`, declared
    below: the adapter says WHICH field carries the handle and HOW LONG
    the upstream needs, and the kernel decides when to decode and how to
    wait.
    """
    if payload.label == "request":
        return ()
    country = (context.countries[0] if len(context.countries) == 1 else "")
    if not country:
        return ()
    summary = summarise_nodes(load_json(payload))
    rate = summary["success_rate"]
    if rate is None:
        return (ObservationDraft(
            signal_source="check_host", domain=PHYSICAL, country=country,
            status=STATUS_NO_DATA, raw_score=0.0,
            value="UNKNOWN",
            # `reason` is a declared field now. It used to be improvised
            # into `flags` under an ad-hoc key, because the draft had
            # nowhere else to put it — one adapter inventing a convention
            # is how the next five invent five more.
            reason="fewer than two responding checks",
            flags={**summary, "url_status": url_status(rate)},
            evidence_url=payload.url),)

    return (ObservationDraft(
        signal_source="check_host", domain=PHYSICAL, country=country,
        # The BLACKOUT/PARTIAL verdict is hour-of-day normalised against
        # `checkhost_hod` (S1-SENS-040), which is L1's. Reporting the
        # measured rate is honest; reporting OK would not be.
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"success={rate:.0%}",
        # The pending marker goes in its OWN key. `asphyxiation` is a
        # bool in production (`radar/sensors/checkhost.py:147-151`) and is
        # read as one (`core.py`: `if chk.get("asphyxiation")`), so a
        # non-empty string there is not "undecided", it is "asphyxiating",
        # forever. §7-2 #8's `untrusted_ca_verdict` set the convention: a
        # verdict this layer cannot reach is ABSENT from the field that
        # carries verdicts and NAMED in a sibling.
        flags={**summary, "url_status": url_status(rate),
               "asphyxiation_verdict": "pending_l1_latency_history"},
        evidence_url=payload.url),)


#: The two headers production sends on BOTH stages
#: (`radar/sensors/checkhost.py:51-52, 69-70`). check-host.net answers
#: HTML without the Accept header, and HTML that parses to no nodes is
#: indistinguishable here from a country whose nodes all answered.
_HEADERS: dict = {"Accept": "application/json",
                  "User-Agent": "OSINT-Radar/9.0"}

#: Stage one: ask for the check. `node[]` once per node, in the order
#: `radar/sensors/checkhost.py:16-17,46-47` declares them. The WP-2.6 port
#: could declare none of them: check-host.net then picks its own nodes, so
#: "five continents agree the site is down" became "some nodes somewhere",
#: and the per-node JP/US/DE/NL/FR labels the verdict is built from had
#: nothing behind them.
_REQUEST_SPEC = RequestSpec(
    url=_CHECK_URL, expect_content="json",
    params=(("host", "{target_url}"), ("max_nodes", str(MAX_NODES)))
           + tuple(("node[]", node) for node in NODES),
    headers=_HEADERS, label="request")

#: Stage two: collect it. `{request_id}` is filled from stage one's body,
#: not from the caller — which is the whole reason `RequestContinuation`
#: exists. Declared as two independent requests, this one had no address
#: at plan time and the adapter was skipped as `unresolved_placeholder`
#: every cycle.
_RESULT_SPEC = RequestSpec(url=_RESULT_URL, expect_content="json",
                           headers=_HEADERS, label="result")

CHECK_HOST_ADAPTER = SourceAdapter(
    adapter_id=CHECK_HOST, category=PHYSICAL,
    requests=(RequestContinuation(
        first=_REQUEST_SPEC, then=_RESULT_SPEC,
        carries=(ResponseValue(placeholder="request_id",
                               path=("request_id",)),),
        delay_sec=RESULT_DELAY_SEC,
        reason="check-host.net dispatches the check and answers with a "
               "handle; the measurement itself exists only at "
               "check-result/{request_id}, and only after the nodes have "
               "had time to report (radar/sensors/checkhost.py:60-72)"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="check_host",
    knowledge_refs=("K03",),
    baseline_refs=("checkhost_hod", "checkhost_latency_history"))

__all__ = ["CHECK_HOST", "CHECK_HOST_ADAPTER", "normalize",
           "summarise_nodes", "url_status", "is_asphyxiation",
           "RESULT_DELAY_SEC", "MAX_NODES", "NODES", "MIN_RESPONDING_CHECKS",
           "URL_OK_RATE", "URL_PARTIAL_RATE", "LATENCY_HISTORY_LEN",
           "LATENCY_MIN_SAMPLES", "ASPHYXIATION_MIN_RATE",
           "ASPHYXIATION_LATENCY_FACTOR", "URL_COOLDOWN_SEC",
           "MAX_URLS_PER_COUNTRY", "NODE_TIMEOUT_MS"]
