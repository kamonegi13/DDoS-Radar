"""`ct_log` — S1-SENS-015..018, D1 §4 K05. Certificates nobody should hold.

The signal (ADR-024) is not certificate volume; it is **who issued**.
Score 3 when an untrusted CA issues for a watched government domain whose
history is a single commercial CA. Score 2 when a wildcard appears at a
government TLD itself — `*.gov.tw` is not a hosting convenience.

Only the second of those is decidable at L0: the first needs the
per-domain CA ledger and the warmup marker that live in L1. So an
untrusted issuer leaves here as an OBSERVED **candidate** rather than as
OK — see `normalize`. An adapter that measures a signal and then reports
the all-clear because it cannot judge it is the blind-spot shape NP1
exists to forbid.

That gap is **registered as design sheet §7-2 expected difference #8**:
while the untrusted verdict stays pending, a payload the live system
scores 3 scores at most 2 here. The direction is **insensitive** — the
class that blocks cutover under C-02/C-03 — so it is on the register
rather than waiting to see whether the L1 wiring lands first. WP-4.1's
composition root supplies those baselines (the same structural gap as
§3-5 H-1: `normalize` is pure and reads only `NormalizeContext`), and the
entry retires when it does.

K05, the fact that keeps multi-sourcing correct: **HTTP 200 with an empty
array is an authoritative success**, not a miss. "No certificates were
issued for this domain" is an answer, and falling through to the next
source after receiving it turns a working chain into a duplicated query
and, worse, lets a slower source's staleness overwrite a fresh negative.

Two counting errata found while porting (reported, not silently fixed):
S1-SENS-018 states 44 trusted CAs and 23 government TLDs; the ledgers
actually hold 43 and 22.

The wildcard rule is exact-match on the TLD after stripping `*.`:
`*.gov.tw` fires, `*.api.mofa.gov.tw` does not. A wildcard inside a
sub-namespace is ordinary infrastructure; one at the TLD is a claim over
the whole namespace.

`gov_count` is NOT emitted. It was 0 for every country in every cycle (a
retired concept whose field outlived it, A18) and design sheet §7-2
registers its removal as expected difference #6.
"""
from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

from v3.adapters.common import (country_of, list_or_empty, load_json,
                                mapping_or_empty)
from v3.adapters.types import (AdapterId, AUTH_API_KEY, AuthRequirement,
                               CYBER, NormalizeContext, ObservationDraft,
                               RequestChain, RequestSpec, SourceAdapter,
                               STATUS_FIRED, STATUS_OBSERVED, STATUS_OK)
from v3.kernel import Window

CT_LOG = AdapterId("ct_log")

_CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
_CRTSH_URL = "https://crt.sh/"

#: `CT_LOG_OBSERVATION_WINDOW_HOURS` (`radar/config.py:529`). Applied to
#: `not_before`, not to fetch time — a certificate issued last month and
#: returned by today's query is not evidence about today.
OBSERVATION_WINDOW_HOURS = 24
MAX_OBSERVATIONS_PER_DOMAIN = 200
WARMUP_DAYS = 14
MAX_QUERIES_PER_COUNTRY = 2
INTER_QUERY_SLEEP_SEC = 4.0
#: CertSpotter's anonymous tier is 30 requests/hour, so the honest group
#: interval is 3600/30 = 120s. `INTER_QUERY_SLEEP_SEC` (4s) was the legacy
#: politeness sleep BETWEEN successive domain queries inside one sweep;
#: declaring it as `min_interval_sec` told the limiter this source
#: tolerates 900 requests/hour. Measured on the shadow (2026-08-13): ~106
#: requests/hour sent, 314 of 636 answered 429 in six hours. NOTE the
#: limiter paces when a SWEEP may start, not the requests inside one — a
#: 162-step sweep still bursts past the quota within its tick, which is a
#: sizing question for the expansion (裁定要求), not for this constant.
ANON_QUOTA_MIN_INTERVAL_SEC = 120.0
#: Source parking (S1-SENS-016): five straight failures, half an hour off
#: — but never the last healthy source.
PARKING_FAILURES = 5
PARKING_COOLDOWN_SEC = 1800.0
DEGRADED_AFTER_CYCLES = 3
DEGRADED_CADENCE_SEC = 14400.0

#: 22 entries (S1-SENS-018 says 23 — errata). Exact match after `*.`.
GOV_TLD_WILDCARD_TARGETS: frozenset = frozenset({
    "gov", "mil", "gov.tw", "gov.uk", "go.jp", "gov.ru", "gov.cn",
    "gov.kr", "gov.il", "gov.ua", "gov.in", "gov.au", "gov.ph", "gov.pk",
    "gov.by", "gov.ge", "gov.vn", "gov.ir", "gov.lv", "gov.pl", "gov.ro",
    "gov.se"})

#: 43 entries (S1-SENS-018 says 44 — errata). Substring match, lowercase.
#: Adversary-state CAs are deliberately absent: this list answers "is this
#: issuer unremarkable", and a state CA issuing for another state's
#: ministry is the opposite of unremarkable.
TRUSTED_CA_SUBSTRINGS: frozenset = frozenset({
    "let's encrypt", "isrg root", "r3", "r10", "r11", "r12", "r13", "r14",
    "e1", "e5", "e6", "e7", "e8",
    "digicert", "sectigo", "comodo", "globalsign", "entrust", "identrust",
    "godaddy", "starfield", "ssl.com", "amazon", "microsoft",
    "google trust", "gts ca", "cloudflare", "verisign", "thawte",
    "geotrust", "usertrust", "aaa certificate", "baltimore cybertrust",
    "quovadis",
    "swisssign", "actalis", "harica", "buypass", "zerossl", "d-trust",
    "telia", "atos trustcenter", "trustwave"})

#: Widths, transcribed. `CertObservation` caps issuer and CN at 200 when
#: the observation is built (`ct_log_sources/buffer.py:223-224`); the
#: event dicts cap again at 120 (`radar/sensors/ct_log.py:311,332-333`)
#: and `recent_certs` at 100 (`:345-346`). The port emitted whole records
#: at every one of these points. A width is not cosmetic here: these
#: strings reach `noise_excl_match` and the analyst surface, and a
#: migrated exclusion rule written against a 120-character issuer stops
#: matching a 400-character one.
OBSERVATION_FIELD_CHARS = 200
EVENT_FIELD_CHARS = 120
RECENT_CERT_FIELD_CHARS = 100
#: `aggregate_untrusted[:10]` / `aggregate_wildcard_events[:5]` /
#: `aggregate_recent_certs[:5]` (`radar/sensors/ct_log.py:534-536`).
MAX_UNTRUSTED_EVENTS = 10
MAX_WILDCARD_EVENTS = 5
MAX_RECENT_CERTS = 5

#: The query parameter each source names the watched domain with —
#: CertSpotter's `domain`, crt.sh's `Identity`. The event dicts key on the
#: WATCHED domain (`ct_log.py:308,329`), not on the certificate's CN,
#: and the watched domain is only recoverable from the request that was
#: actually sent.
WATCHED_DOMAIN_PARAMS: tuple[str, ...] = ("domain", "Identity")

_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)
_FRESHNESS_HORIZON_SEC = 6 * 3600.0


def parse_issuer(raw) -> tuple[str, str]:
    """DN -> `(raw, normalized)`. `O=` beats `CN=` beats the whole string.

    Returns `("unknown", "unknown")` for an empty DN, and the caller drops
    those: an issuer nobody can name cannot be compared against a ledger
    of names, and treating it as untrusted would fire on every parse
    failure.
    """
    text = str(raw or "").strip()
    if not text:
        return ("unknown", "unknown")
    organisation = ""
    common_name = ""
    for part in text.split(","):
        key, _, value = part.strip().partition("=")
        cleaned = value.strip().strip("'\"")
        if key.strip().upper() == "O" and not organisation:
            organisation = cleaned
        elif key.strip().upper() == "CN" and not common_name:
            common_name = cleaned
    normalized = (organisation or common_name or text).strip("'\"").lower()
    return (text, normalized or "unknown")


def is_globally_trusted(issuer_raw: str) -> bool:
    """Substring match against the RAW DN — `_is_globally_trusted`'s rule.

    `radar/sensors/ct_log.py:315` passes `obs.issuer_raw`, and `:86-92`
    lower-cases the whole distinguished name before searching. The port
    passed the NORMALIZED form instead, which is only the `O=` component:
    `C=US, O=Internet Security Research Group, CN=R11` normalizes to
    `internet security research group`, which contains none of the 43
    ledger entries, while the raw DN contains `r11`. Every such
    certificate became an untrusted-CA candidate — a fabricated finding
    on the most ordinary issuer on the public web.
    """
    haystack = (issuer_raw or "").lower()
    return any(entry in haystack for entry in TRUSTED_CA_SUBSTRINGS)


def parse_not_before(raw) -> float:
    """`_parse_iso_to_ts` (`ct_log_sources/buffer.py:233-241`), transcribed.

    `0.0` for anything that does not parse, and the caller DROPS those:
    `make_observation` returns None when `nb_ts <= 0` (`buffer.py:218-219`),
    because an observation whose freshness cannot be established cannot be
    placed inside or outside the 24h window.
    """
    text = str(raw or "")
    if not text:
        return 0.0
    try:
        clean = text.replace("T", " ").split(".")[0].rstrip("Z").strip()
        return datetime.fromisoformat(clean).replace(
            tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return 0.0


def to_iso(stamp: float) -> str:
    """`_ts_to_iso` (`radar/sensors/ct_log.py:94-106`), transcribed."""
    if not stamp:
        return ""
    try:
        return datetime.fromtimestamp(stamp, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return ""


def watched_domain(payload) -> str:
    """The domain the request asked about, from the URL that was sent."""
    try:
        query = parse_qs(urlparse(getattr(payload, "url", "") or "").query)
    except ValueError:
        return ""
    for name in WATCHED_DOMAIN_PARAMS:
        for value in query.get(name, ()):
            if value:
                return str(value).strip().lower()
    return ""


def is_gov_tld_wildcard(subject: str) -> bool:
    """`*.gov.tw` -> True; `*.api.mofa.gov.tw` -> False."""
    name = str(subject or "").strip().lower()
    if not name.startswith("*."):
        return False
    return name[2:] in GOV_TLD_WILDCARD_TARGETS


def certificates(payload) -> list[dict]:
    """CertSpotter issuances or crt.sh rows -> one `CertObservation` shape.

    The 200 cap is the SOURCE cap and is applied to the raw rows, before
    anything is parsed — `certs[:200]` in both sources
    (`ct_log_sources/certspotter.py:188`, `crtsh.py:98`). The 24h window
    is applied later, by the buffer at drain time (`buffer.py:349-355`);
    `recent()` is that step. Order matters and is production's: cap, then
    window, then the second (now redundant) 200 in `_inspect_domain`.

    Two drop rules, both production's: an issuer that normalizes to
    `unknown` (`certspotter.py:196-197`, `crtsh.py:100-101`) and a
    `not_before` that does not parse (`buffer.py:218-219`). The second was
    missing entirely, so certificates of unknown age counted toward
    `total_recent` and could carry a wildcard verdict.
    """
    document = load_json(payload)
    rows = list_or_empty(document)[:MAX_OBSERVATIONS_PER_DOMAIN]
    domain = watched_domain(payload)
    records: list[dict] = []
    for row in rows:
        entry = mapping_or_empty(row)
        if not entry:
            continue
        if "dns_names" in entry:                      # CertSpotter
            names = [str(name) for name in list_or_empty(entry.get("dns_names"))
                     if isinstance(name, str)]
            issuer_field = entry.get("issuer")
            issuer_raw = (mapping_or_empty(issuer_field).get("name")
                          if isinstance(issuer_field, dict) else issuer_field)
            common = next((name for name in names
                           if not name.startswith("*.")),
                          names[0] if names else "")
            serial = str(entry.get("id") or "")
        else:                                          # crt.sh
            sans = str(entry.get("name_value") or "")
            names = [line for line in sans.split("\n") if line]
            issuer_raw = entry.get("issuer_name")
            # `cert.get("common_name") or cert.get("name_value")`
            # (`crtsh.py:102`) — the fallback is the WHOLE multi-line SAN
            # blob, capped at 200 below, not its first line.
            common = str(entry.get("common_name") or sans or "").strip()
            serial = str(entry.get("serial_number") or "")
        raw, normalized = parse_issuer(issuer_raw)
        if normalized == "unknown":
            continue                     # unnameable issuer: dropped
        stamp = parse_not_before(entry.get("not_before"))
        if stamp <= 0.0:
            continue                     # undatable: dropped (buffer.py:219)
        records.append({
            "domain": domain,
            "common_name": common[:OBSERVATION_FIELD_CHARS],
            # `make_observation` strips and lower-cases every SAN
            # (`buffer.py:221`); the wildcard detector compares against
            # that form.
            "dns_names": [name.strip().lower() for name in names if name],
            "not_before_ts": stamp,
            "not_before": to_iso(stamp),
            "issuer_raw": raw[:OBSERVATION_FIELD_CHARS],
            "issuer": normalized,
            "serial": serial.lower()})
    return records


def recent(records, now: float) -> list[dict]:
    """The 24h `not_before` window, then the second 200 cap.

    `buffer.drain_for_scoring` drops everything older than the window
    before `_inspect_domain` ever sees it (`buffer.py:349-355`), and
    `_inspect_domain` then reads `observations[:200]`
    (`radar/sensors/ct_log.py:287`) and skips anything still older
    (`:288-289`, its own defence in depth). The port applied neither, so
    a certificate issued a year ago counted toward `total_recent` and
    could raise the wildcard verdict on its own — the sensor's whole
    premise is that a certificate appeared TODAY.
    """
    cutoff = now - OBSERVATION_WINDOW_HOURS * 3600.0
    return [record for record in records
            if record["not_before_ts"] >= cutoff][:MAX_OBSERVATIONS_PER_DOMAIN]


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One domain's certificates -> one observation for its country.

    An empty array is a real answer (K05) and produces an OK observation
    rather than nothing — silence and "no certificates" are different,
    and only the second one is evidence.

    Untrusted-CA detection needs the per-domain known-CA ledger and the
    first-observation marker (the only two things this sensor persists,
    and S3 lists them for L0). Those tables are declared as baselines; the
    wildcard rule needs no history and is computed here.

    Hence three outcomes rather than two. A certificate from an issuer
    the trusted ledger does not recognise is a **candidate**: legacy would
    weigh it against that domain's CA history and its warmup marker
    (`radar/sensors/ct_log.py:315-326`) and score it 3, and this layer
    holds neither table. Reporting OK for it would say "measured, nothing
    wrong" about the one certificate in the payload that is not
    unremarkable — so the candidates travel out as OBSERVED, the way
    `ripe_bgp` reports a series it cannot Z-score. No FIRED path is
    invented: a verdict this layer cannot reach must not be manufactured
    from the half of the rule it can see.

    Priority follows S1-SENS-018 as far as it can be followed. UNTRUSTED_
    CA outranks WILDCARD there, but with the untrusted verdict pending,
    the wildcard is the only rule decidable here, so a wildcard still
    fires at 2.0 even when candidates are present. The candidate count
    rides along in the flags so the two are never confused.

    `wildcard_count` counts matching NAMES, not certificates
    (`radar/sensors/ct_log.py:300-313` increments inside the loop over
    `[common_name] + subject_alt_names`), so one certificate claiming
    `*.gov.tw` and `*.gov.uk` counts twice and produces two events. The
    port counted certificates, which reads the same on the common case
    and undercounts exactly the certificate that is most worth reading.
    """
    # `country_of` reads the label's trailing `:{country}` segment. The
    # single-country context fallback alone was the shadow's measured
    # silence (2026-08-13): the runtime supplies the whole watch scope
    # (~21 countries), so `countries[0] if len == 1` was unresolvable on
    # every production payload and every draft was silently ().
    country = country_of(payload, context)
    if not country:
        return ()
    domain = watched_domain(payload)
    records = recent(certificates(payload), context.now)

    wildcard_events: list[dict] = []
    for record in records:
        for name in [record["common_name"], *record["dns_names"]]:
            if not is_gov_tld_wildcard(name):
                continue
            wildcard_events.append({
                "domain": domain or record["domain"],
                "wildcard_subject": str(name or "").strip().lower(),
                "issuer": record["issuer_raw"][:EVENT_FIELD_CHARS],
                "not_before": record["not_before"]})
    untrusted_candidates = [record for record in records
                            if not is_globally_trusted(record["issuer_raw"])]

    wildcard_count = len(wildcard_events)
    fired = wildcard_count > 0
    # `untrusted_count = len(aggregate_untrusted[:10])` (`ct_log.py:534,537`)
    # — production's count is the CAPPED list's length, not the raw one.
    candidates = untrusted_candidates[:MAX_UNTRUSTED_EVENTS]
    candidate_count = len(candidates)
    if fired:
        status, score = STATUS_FIRED, 2.0
    elif candidate_count:
        status, score = STATUS_OBSERVED, 0.0
    else:
        status, score = STATUS_OK, 0.0
    # `country_status` (`ct_log.py:541-548`). WARMUP is not reachable
    # here: it needs the per-domain first-observation marker, which is L1's
    # (§7-2 #8), so the label stops at the two rules this layer can decide.
    label = "WILDCARD_TLD_DETECTED" if fired else "NORMAL"
    # `untrusted_ca=0` is the same all-clear in text that OK is in status.
    # The count is not zero when candidates exist; it is unknown.
    untrusted_field = f"pending({candidate_count})" if candidate_count else "0"
    return (ObservationDraft(
        signal_source="ct_log", domain=CYBER, country=country,
        status=status, raw_score=score,
        value=(f"untrusted_ca={untrusted_field} "
               f"wildcard_tld={wildcard_count} obs_certs={len(records)}"),
        # `_ct_reason`'s wildcard branch (`radar/routes/core.py:1858-1862`).
        # The untrusted branch outranks it there and is unreachable while
        # §7-2 #8 stands.
        reason=(f"CT Log: wildcard certificate at gov-TLD level "
                f"({wildcard_count} subj) [{label}]" if fired else ""),
        flags={"total_recent": len(records),
               "wildcard_count": wildcard_count,
               "wildcard_tld_detected": fired,
               "wildcard_tld_events": wildcard_events[:MAX_WILDCARD_EVENTS],
               # `recent_certs` is NOT the first five certificates: the
               # append sits inside the untrusted-CA branch, after the
               # trusted / known-CA / warmup `continue`s
               # (`radar/sensors/ct_log.py:343-347`), so it is the first
               # five ANOMALOUS ones. The port emitted whole records for
               # the first five of everything, which is a different set
               # under a name an analyst reads as "what fired".
               "recent_certs": [
                   {"name": record["common_name"][:RECENT_CERT_FIELD_CHARS],
                    "issuer": record["issuer_raw"][:RECENT_CERT_FIELD_CHARS],
                    "not_before": record["not_before"]}
                   for record in candidates][:MAX_RECENT_CERTS],
               "untrusted_ca_candidates": [
                   {"domain": domain or record["domain"],
                    "country": country,
                    "ca_normalized": record["issuer"],
                    "ca_raw": record["issuer_raw"][:EVENT_FIELD_CHARS],
                    "common_name": record["common_name"][:EVENT_FIELD_CHARS],
                    "not_before": record["not_before"]}
                   for record in candidates],
               "untrusted_ca_candidate_count": candidate_count,
               # Score 3 needs the per-domain CA history and the warmup
               # marker; both are L1 tables (S3 lists them for L0).
               "untrusted_ca_verdict": "pending_l1_known_ca_ledger",
               # `watched_domains` / `warmup_active` are production output
               # fields (`ct_log.py:561,563`) the port dropped silently.
               # The first is recoverable from the request. The second is
               # a BOOL there, and `core.py:1836` reads it as one, so the
               # pending marker gets its own key and `warmup_active` stays
               # ABSENT: `False` would read as "out of warmup", which is
               # half of the rule that scores 3, and the marker string
               # would read as True forever.
               "watched_domains": [domain] if domain else [],
               "warmup_verdict": "pending_l1_domain_first_observed",
               "country_status": label,
               "scoring_model": "adr_024_signal_redesign"},
        evidence_url=payload.url),)


CT_LOG_ADAPTER = SourceAdapter(
    adapter_id=CT_LOG, category=CYBER,
    requests=(RequestChain(
        alternatives=(
            RequestSpec(url=_CERTSPOTTER_URL, expect_content="json",
                        # `expand` TWICE — `ct_log_sources/certspotter.py:268`
                        # sends `"expand": ["dns_names", "issuer"]`. The
                        # WP-2.6 port could only declare one, and without
                        # `issuer` every certificate parses to `unknown`
                        # and is dropped: the adapter was permanently
                        # silent, which is the failure NP1 forbids.
                        params=(("domain", "{domain}"),
                                ("include_subdomains", "true"),
                                ("match_wildcards", "true"),
                                ("expand", "dns_names"),
                                ("expand", "issuer")),
                        headers={"User-Agent":
                                 "OSINT-Radar/8.0 (CT-anomaly-detector)",
                                 "Accept": "application/json"},
                        # The trailing `:{country}` is how `normalize`
                        # attributes the payload — the greynoise
                        # `gnql:{country}` convention, resolved at
                        # expansion (`expand.py` templates labels too).
                        label="certspotter:{country}"),
            RequestSpec(url=_CRTSH_URL, expect_content="json",
                        params=(("Identity", "{domain}"), ("output", "json"),
                                ("exclude", "expired")),
                        headers={"Accept": "application/json"},
                        label="crtsh:{country}")),
        reason="K05 / radar/sensors/ct_log.py:144-152 — CertSpotter became "
               "primary after crt.sh's chronic instability; crt.sh is "
               "reached only for what CertSpotter rejects (some ccTLD gov "
               "domains 403). Fetching both unconditionally doubles a "
               "rate-limited free-tier query and lets the slower source's "
               "staleness overwrite a fresh negative.",
        label="ct"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    # Optional in production: `ct_log_sources/certspotter.py:274` adds the
    # bearer only `if self._api_token`. Declared mandatory, the fetch
    # aborted with AUTH_MISSING before the socket opened and the free tier
    # — which works tokenless at 30 req/hr — was never reached.
    auth=AuthRequirement(kind=AUTH_API_KEY, key_id="CERTSPOTTER_API_TOKEN",
                         name="Authorization",
                         value_template="Bearer {secret}", optional=True,
                         note="optional: the free tier works without one, "
                              "at 30 requests/hour"),
    rate_limit_group="ct_log", min_interval_sec=ANON_QUOTA_MIN_INTERVAL_SEC,
    knowledge_refs=("K05",),
    baseline_refs=("ct_log_known_ca_per_domain",
                   "ct_log_domain_first_observed"))

__all__ = ["CT_LOG", "CT_LOG_ADAPTER", "normalize", "parse_issuer",
           "is_globally_trusted", "is_gov_tld_wildcard", "certificates",
           "recent", "parse_not_before", "to_iso", "watched_domain",
           "GOV_TLD_WILDCARD_TARGETS", "TRUSTED_CA_SUBSTRINGS",
           "OBSERVATION_WINDOW_HOURS", "MAX_OBSERVATIONS_PER_DOMAIN",
           "WARMUP_DAYS", "PARKING_FAILURES", "PARKING_COOLDOWN_SEC",
           "DEGRADED_AFTER_CYCLES", "DEGRADED_CADENCE_SEC",
           "MAX_QUERIES_PER_COUNTRY", "INTER_QUERY_SLEEP_SEC",
           "ANON_QUOTA_MIN_INTERVAL_SEC",
           "OBSERVATION_FIELD_CHARS", "EVENT_FIELD_CHARS",
           "RECENT_CERT_FIELD_CHARS", "MAX_UNTRUSTED_EVENTS",
           "MAX_WILDCARD_EVENTS", "MAX_RECENT_CERTS",
           "WATCHED_DOMAIN_PARAMS"]
