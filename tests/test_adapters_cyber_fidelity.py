"""WP-2.6 remediation — the cyber adapters' fidelity pins.

Separate from `test_adapters_cyber.py` because these are not behaviour
tests. Each one holds a value that a previous port got wrong SILENTLY:
a ledger key, a filter that was never applied, a truncation width, a
field that was dropped. None of those announce themselves at run time —
a renamed `signal_source` still writes a row, a missing 24h window still
returns certificates, a 400-character issuer string still renders — so
the only place they can fail is here.

The discipline is `apt_intel`'s: compare against the live source PARSED
AT TEST TIME, never against a value copied into the test. A hand-copied
expected value cannot fail when production moves, which is exactly the
failure these exist to catch.
"""
import ast
import json
from pathlib import Path

import pytest

from v3.adapters.cyber import (apt_intel, cloudflare_radar, ct_log, greynoise,
                               ooni_censorship, ripe_bgp, threatfox)
from v3.adapters.types import (AdapterId, FetchedPayload, NormalizeContext,
                               STATUS_FIRED, STATUS_OBSERVED, STATUS_OK)

REPO_ROOT = Path(__file__).resolve().parent.parent
T0 = 1_700_000_000.0
CORE = "radar/routes/core.py"


def legacy_source(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def synthetic(body: bytes, *, label="", url="https://upstream.test/x",
              now=T0) -> FetchedPayload:
    return FetchedPayload(url=url, status=200, body=body, fetched_at=now,
                          content_type="application/json", label=label)


def context(adapter_id: str, **overrides) -> NormalizeContext:
    base = {"adapter_id": AdapterId(adapter_id), "now": T0,
            "countries": ("TW",)}
    base.update(overrides)
    return NormalizeContext(**base)


# ── production's effective signal_source, read out of core.py ───────────

def production_signal_sources() -> dict:
    """`{add_rat sensor name: effective signal_source}` for every call.

    `radar/scoring.py:81` resolves the effective key as
    `rat.signal_source or rat.sensor` — the first positional argument
    unless an explicit kwarg overrides it. Both forms ship: `ripe_bgp`
    and `ioda_bgp` pass `signal_source="bgp"` so the three routing
    sensors dedup as one; everyone else takes their own name.
    """
    tree = ast.parse(legacy_source(CORE))
    names: dict = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "add_rat" and node.args):
            continue
        first = node.args[0]
        if not (isinstance(first, ast.Constant)
                and isinstance(first.value, str)):
            continue
        override = ""
        for keyword in node.keywords:
            if keyword.arg == "signal_source" and \
                    isinstance(keyword.value, ast.Constant):
                override = keyword.value.value
        names[first.value] = override or first.value
    return names


def _resolve(module, value) -> str:
    """One `signal_source=` expression, as the key it will produce.

    A module constant resolves through the module, so a named key
    (`BGP_LEAK_SIGNAL`) pins as tightly as an inline literal. An f-string
    comes back as its template, because `cf_{label}` is a FAMILY of keys
    and the family is what has to be checked.
    """
    if isinstance(value, ast.Constant):
        return value.value
    if isinstance(value, ast.Name):
        resolved = getattr(module, value.id, None)
        if isinstance(resolved, str):
            return resolved
        return f"<param:{value.id}>"
    return ast.unparse(value)


def declared_signal_sources(module) -> set:
    """Every `signal_source=` an adapter's module can put on a draft.

    Two hops, because `cloudflare_radar` passes the key down into a
    shared helper: an `ObservationDraft(signal_source=<name>)` where the
    name is that helper's PARAMETER is resolved by reading what every
    call site supplies for it. Stopping at the first hop would report the
    parameter's name and pin nothing.
    """
    tree = ast.parse(Path(module.__file__).read_text("utf-8"))
    # helper functions that take a `signal_source` argument, and where
    parameters: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            names = [argument.arg for argument in node.args.args]
            if "signal_source" in names:
                parameters[node.name] = names.index("signal_source")

    found: set = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id == "ObservationDraft":
            for keyword in node.keywords:
                if keyword.arg == "signal_source":
                    found.add(_resolve(module, keyword.value))
        elif node.func.id in parameters:
            index = parameters[node.func.id]
            if len(node.args) > index:
                found.add(_resolve(module, node.args[index]))
            for keyword in node.keywords:
                if keyword.arg == "signal_source":
                    found.add(_resolve(module, keyword.value))
    return {entry for entry in found if not entry.startswith("<param:")}


#: What each module may emit, and the production `add_rat` entry it has to
#: correspond to. `None` means "no production entry" — an invention this
#: port made, which is a §7-2 registration rather than a transcription.
EXPECTED_SIGNAL_SOURCES: dict = {
    "greynoise": {"greynoise": "greynoise"},
    "threatfox": {"threatfox": "threatfox"},
    "ooni_censorship": {"ooni_censorship": "ooni_censorship"},
    "ripe_bgp": {"bgp": "ripe_bgp"},
    "ct_log": {"ct_log": "ct_log"},
    "cloudflare_radar": {"cf_bgp_hijack": "cf_bgp_hijack",
                         "cf_bgp_leak": None,
                         "f'cf_{payload.label}'": None},
    # apt_intel has no `add_rat` entry at all: it feeds the LLM
    # extraction stage (O-17 / WP-2.7), not the rationale table.
    "apt_intel": {"apt_intel": None},
}

MODULES = {"greynoise": greynoise, "threatfox": threatfox,
           "ooni_censorship": ooni_censorship, "ripe_bgp": ripe_bgp,
           "ct_log": ct_log, "cloudflare_radar": cloudflare_radar,
           "apt_intel": apt_intel}


class TestSignalSourceIsProductionsKey:
    """R1. The ledger key is `(tick_id, sensor, signal_source, country)`
    (`v3/ledger/schema.py:157`) and WP-2.8 joins parity on it, so a
    "semantic" rename invented during the port is not cosmetic: it stops
    deduping against its own history and it stops matching production."""

    @pytest.mark.parametrize("name", sorted(EXPECTED_SIGNAL_SOURCES))
    def test_every_declared_key_is_the_one_production_writes(self, name):
        expected = EXPECTED_SIGNAL_SOURCES[name]
        assert declared_signal_sources(MODULES[name]) == set(expected), (
            f"{name}: the set of signal_source values `normalize` can emit "
            f"changed. Every key must either be a production `add_rat` "
            f"entry or carry a §7-2 registration.")

    @pytest.mark.parametrize("name", sorted(EXPECTED_SIGNAL_SOURCES))
    def test_each_key_matches_its_production_add_rat_entry(self, name):
        production = production_signal_sources()
        for key, sensor in EXPECTED_SIGNAL_SOURCES[name].items():
            if sensor is None:
                continue
            assert production.get(sensor) == key, (
                f"{name} emits signal_source={key!r}; production's "
                f"add_rat({sensor!r}, ...) resolves to "
                f"{production.get(sensor)!r} "
                f"(`rat.signal_source or rat.sensor`, radar/scoring.py:81)")

    def test_ripe_bgp_shares_the_explicit_bgp_key(self):
        """`add_rat("ripe_bgp", ..., signal_source="bgp")`
        (`core.py:1148`), the same key `ioda_bgp` passes (`:1103`), so
        S1-SCORE-008 folds the routing sensors by MAX instead of counting
        one outage three times."""
        production = production_signal_sources()
        assert production["ripe_bgp"] == "bgp"
        assert production["ioda_bgp"] == "bgp"
        draft = ripe_bgp.normalize(
            synthetic(json.dumps({"data": {"resource": "TW",
                                   "resolution": "1h", "stats": [
                {"v4_prefixes_ris": 860, "v6_prefixes_ris": 40,
                 "asns_ris": 40, "v4_prefixes_stats": -1}]}}).encode()),
            context("ripe_bgp"))[0]
        assert draft.signal_source == "bgp"

    def test_the_two_cloudflare_bgp_keys_are_distinct(self):
        """`append_signal` INSERT-OR-IGNOREs on the ledger key and then
        calls `_require_same_tick`, which raises `DomainError` when the
        content differs and silently drops when it matches
        (S5-VERIF-019). Two payloads, one tick, one country: sharing a
        key is either a crash or a lost row, never the MAX fold the port
        assumed."""
        assert cloudflare_radar.BGP_HIJACK_SIGNAL != \
            cloudflare_radar.BGP_LEAK_SIGNAL
        assert cloudflare_radar.BGP_HIJACK_SIGNAL == \
            production_signal_sources()["cf_bgp_hijack"]


# ── ct_log: the window, the cap, and the order between them ─────────────

CERTSPOTTER_URL = ("https://api.certspotter.com/v1/issuances"
                   "?domain=mofa.gov.tw&expand=dns_names&expand=issuer")


def issuance(index: int, *, not_before: str, issuer: str, names=("x.gov.tw",)):
    return {"id": str(index), "dns_names": list(names),
            "not_before": not_before, "issuer": {"name": issuer}}


def iso_at(offset_hours: float) -> str:
    """An ISO `not_before` `offset_hours` from T0, in production's dialect."""
    return ct_log.to_iso(T0 + offset_hours * 3600.0)


TRUSTED_DN = "C=US, O=Internet Security Research Group, CN=R11"


class TestCtLogObservationWindow:
    def test_the_window_and_the_cap_are_the_live_constants(self):
        assert ct_log.OBSERVATION_WINDOW_HOURS == 24
        assert 'CT_LOG_OBSERVATION_WINDOW_HOURS", "24"' in \
            legacy_source("radar/config.py")
        assert "for cert in certs[:200]:" in \
            legacy_source("radar/sensors/ct_log_sources/certspotter.py")
        assert "for cert in certs[:200]:" in \
            legacy_source("radar/sensors/ct_log_sources/crtsh.py")
        assert ct_log.MAX_OBSERVATIONS_PER_DOMAIN == 200

    def test_a_certificate_older_than_the_window_is_not_recent(self):
        """`buffer.drain_for_scoring` drops everything older than the
        window before `_inspect_domain` ever counts it
        (`ct_log_sources/buffer.py:348-355`), and `_inspect_domain` skips
        it again (`radar/sensors/ct_log.py:288-289`). The port applied
        neither: a certificate issued a year ago counted toward
        `total_recent`, and — the part that matters — could raise the
        gov-TLD wildcard verdict on its own. The whole premise of this
        sensor is that a certificate appeared TODAY."""
        body = json.dumps([
            issuance(1, not_before=iso_at(-1), issuer=TRUSTED_DN),
            issuance(2, not_before=iso_at(-23.9), issuer=TRUSTED_DN),
            issuance(3, not_before=iso_at(-25), issuer=TRUSTED_DN),
            issuance(4, not_before=iso_at(-24 * 365), issuer=TRUSTED_DN),
        ]).encode()
        draft = ct_log.normalize(
            synthetic(body, label="certspotter", url=CERTSPOTTER_URL),
            context("ct_log"))[0]
        assert draft.flags["total_recent"] == 2

    def test_an_old_wildcard_no_longer_fires(self):
        body = json.dumps([issuance(1, not_before=iso_at(-48),
                                    issuer=TRUSTED_DN,
                                    names=("*.gov.tw",))]).encode()
        draft = ct_log.normalize(
            synthetic(body, label="certspotter", url=CERTSPOTTER_URL),
            context("ct_log"))[0]
        assert draft.status == STATUS_OK
        assert draft.flags["wildcard_count"] == 0

    def test_an_undatable_certificate_is_dropped(self):
        """`make_observation` returns None when `not_before` does not
        parse (`ct_log_sources/buffer.py:218-219`) — an observation whose
        freshness cannot be established cannot be placed inside or
        outside the window, so it is not evidence about either."""
        body = json.dumps([
            issuance(1, not_before="", issuer=TRUSTED_DN),
            issuance(2, not_before="not a date", issuer=TRUSTED_DN),
            issuance(3, not_before=iso_at(-1), issuer=TRUSTED_DN),
        ]).encode()
        records = ct_log.certificates(
            synthetic(body, label="certspotter", url=CERTSPOTTER_URL))
        assert [record["serial"] for record in records] == ["3"]

    def test_the_source_cap_runs_before_the_window(self):
        """Production's order, not the other way round: both sources cut
        the RAW rows at 200 (`certspotter.py:188`, `crtsh.py:98`) and the
        window is applied afterwards, by the buffer. 201 rows of which
        only the last is recent therefore yield nothing — which is
        production's behaviour, and is why the source cap is worth
        pinning rather than assuming."""
        rows = [issuance(n, not_before=iso_at(-100), issuer=TRUSTED_DN)
                for n in range(200)]
        rows.append(issuance(999, not_before=iso_at(-1), issuer=TRUSTED_DN))
        draft = ct_log.normalize(
            synthetic(json.dumps(rows).encode(), label="certspotter",
                      url=CERTSPOTTER_URL),
            context("ct_log"))[0]
        assert draft.flags["total_recent"] == 0

    def test_the_iso_renderer_is_the_live_one(self):
        assert '"%Y-%m-%dT%H:%M:%S"' in legacy_source("radar/sensors/ct_log.py")
        assert ct_log.to_iso(0) == ""
        assert ct_log.to_iso(1_700_000_000.0) == "2023-11-14T22:13:20"
        assert ct_log.parse_not_before("2023-11-14T22:13:20Z") == \
            1_700_000_000.0
        assert ct_log.parse_not_before("2023-11-14 22:13:20.456") == \
            1_700_000_000.0
        assert ct_log.parse_not_before("nonsense") == 0.0


class TestCtLogTrustMatching:
    def test_trust_is_matched_against_the_raw_distinguished_name(self):
        """`_is_globally_trusted(ca_raw)` (`radar/sensors/ct_log.py:315`),
        lower-casing the WHOLE DN (`:86-92`). The port passed the
        normalized form, which is only the `O=` component — so Let's
        Encrypt's own `O=Internet Security Research Group` matched none
        of the 43 ledger entries while its raw DN contains `r11`. Every
        such certificate became an untrusted-CA candidate: a fabricated
        finding on the most ordinary issuer on the public web."""
        assert "_is_globally_trusted(ca_raw)" in \
            legacy_source("radar/sensors/ct_log.py")
        raw, normalized = ct_log.parse_issuer(TRUSTED_DN)
        assert normalized == "internet security research group"
        assert ct_log.is_globally_trusted(raw) is True
        assert ct_log.is_globally_trusted(normalized) is False

    def test_an_ordinary_issuer_produces_no_candidate(self):
        body = json.dumps([issuance(1, not_before=iso_at(-1),
                                    issuer=TRUSTED_DN)]).encode()
        draft = ct_log.normalize(
            synthetic(body, label="certspotter", url=CERTSPOTTER_URL),
            context("ct_log"))[0]
        assert draft.status == STATUS_OK
        assert draft.flags["untrusted_ca_candidate_count"] == 0

    def test_the_trusted_ledger_is_the_live_one(self):
        tree = ast.parse(legacy_source("radar/config.py"))
        for node in ast.walk(tree):
            target = None
            if isinstance(node, ast.AnnAssign):
                target = node.target
            elif isinstance(node, ast.Assign) and node.targets:
                target = node.targets[0]
            if isinstance(target, ast.Name) and \
                    target.id == "CT_LOG_TRUSTED_CAS_GLOBAL":
                live = set(ast.literal_eval(node.value))
                break
        else:                                            # pragma: no cover
            raise AssertionError("CT_LOG_TRUSTED_CAS_GLOBAL not found")
        assert set(ct_log.TRUSTED_CA_SUBSTRINGS) == live


class TestCtLogOutputShape:
    def _draft(self, rows):
        return ct_log.normalize(
            synthetic(json.dumps(rows).encode(), label="certspotter",
                      url=CERTSPOTTER_URL), context("ct_log"))[0]

    def test_a_wildcard_is_counted_per_matching_name(self):
        """`wildcard_count += 1` sits inside the loop over
        `[common_name] + subject_alt_names`
        (`radar/sensors/ct_log.py:300-313`), so one certificate claiming
        two government namespaces counts twice and produces two events.
        The port counted certificates, which reads identically on the
        ordinary case and undercounts exactly the certificate most worth
        reading."""
        draft = self._draft([issuance(
            1, not_before=iso_at(-1), issuer=TRUSTED_DN,
            names=("*.gov.tw", "*.gov.uk", "www.mofa.gov.tw"))])
        assert draft.flags["wildcard_count"] == 2
        assert [event["wildcard_subject"]
                for event in draft.flags["wildcard_tld_events"]] == \
            ["*.gov.tw", "*.gov.uk"]
        assert draft.status == STATUS_FIRED
        assert draft.raw_score == 2.0

    def test_the_wildcard_event_carries_productions_keys(self):
        draft = self._draft([issuance(
            1, not_before=iso_at(-1), issuer=TRUSTED_DN,
            names=("www.mofa.gov.tw", "*.gov.tw"))])
        assert draft.flags["wildcard_tld_events"] == [{
            "domain": "mofa.gov.tw",           # the WATCHED domain (:307)
            "wildcard_subject": "*.gov.tw",
            "issuer": TRUSTED_DN,
            "not_before": iso_at(-1)}]

    def test_a_wildcard_only_certificate_counts_twice_as_production_does(self):
        """Not a bug being ported blind — a consequence being preserved.
        CertSpotter picks the first NON-wildcard SAN as the common name
        and falls back to `dns_names[0]` when there is none
        (`ct_log_sources/certspotter.py:203-212`), so a certificate whose
        only subject is `*.gov.tw` appears in `[common_name] + SANs`
        twice and `_inspect_domain` counts both (`ct_log.py:300-313`).
        The verdict is unaffected (any count above zero fires); the
        number an analyst reads is not, so it is pinned rather than
        quietly corrected."""
        draft = self._draft([issuance(1, not_before=iso_at(-1),
                                      issuer=TRUSTED_DN,
                                      names=("*.gov.tw",))])
        assert draft.flags["wildcard_count"] == 2
        assert draft.status == STATUS_FIRED

    def test_recent_certs_holds_the_anomalous_ones_not_the_first_five(self):
        """The `recent_certs.append` sits inside the untrusted-CA branch,
        after the trusted / known-CA / warmup `continue`s
        (`radar/sensors/ct_log.py:343-347`). The port emitted the first
        five certificates of everything under a name an analyst reads as
        "what fired"."""
        rows = [issuance(n, not_before=iso_at(-1), issuer=TRUSTED_DN)
                for n in range(4)]
        rows.append(issuance(9, not_before=iso_at(-1),
                             issuer="C=CN, O=Some Internal Authority"))
        draft = self._draft(rows)
        assert draft.flags["recent_certs"] == [{
            "name": "x.gov.tw", "issuer": "C=CN, O=Some Internal Authority",
            "not_before": iso_at(-1)}]

    def test_the_event_widths_are_productions(self):
        """200 at observation build (`buffer.py:223-224`), 120 in the
        event dicts (`ct_log.py:311,332-333`), 100 in `recent_certs`
        (`:345-346`). These strings reach `noise_excl_match` and the
        analyst surface; a migrated exclusion rule written against a
        120-character issuer stops matching a 400-character one."""
        assert (ct_log.OBSERVATION_FIELD_CHARS, ct_log.EVENT_FIELD_CHARS,
                ct_log.RECENT_CERT_FIELD_CHARS) == (200, 120, 100)
        long_dn = "O=" + "z" * 400
        long_cn = "y" * 400 + ".gov.tw"
        draft = self._draft([issuance(1, not_before=iso_at(-1),
                                      issuer=long_dn, names=(long_cn,))])
        candidate = draft.flags["untrusted_ca_candidates"][0]
        assert len(candidate["ca_raw"]) == ct_log.EVENT_FIELD_CHARS
        assert len(candidate["common_name"]) == ct_log.EVENT_FIELD_CHARS
        recent = draft.flags["recent_certs"][0]
        assert len(recent["issuer"]) == ct_log.RECENT_CERT_FIELD_CHARS
        assert len(recent["name"]) == ct_log.RECENT_CERT_FIELD_CHARS

    def test_the_untrusted_candidate_count_is_the_capped_length(self):
        """`untrusted_count = len(aggregate_untrusted[:10])`
        (`radar/sensors/ct_log.py:534,537`) — production's count is the
        CAPPED list's length, so the value string reads 10 and not 14."""
        rows = [issuance(n, not_before=iso_at(-1),
                         issuer=f"C=CN, O=Authority {n}") for n in range(14)]
        draft = self._draft(rows)
        assert draft.flags["untrusted_ca_candidate_count"] == 10
        assert len(draft.flags["untrusted_ca_candidates"]) == 10
        assert "untrusted_ca=pending(10)" in draft.value

    def test_the_watched_domain_comes_from_the_request(self):
        """Both event dicts key on the WATCHED domain, not the
        certificate's subject (`ct_log.py:308,329`). It is only knowable
        from the request that was sent, so it is read back off the URL."""
        assert ct_log.WATCHED_DOMAIN_PARAMS == ("domain", "Identity")
        assert ct_log.watched_domain(
            synthetic(b"[]", url=CERTSPOTTER_URL)) == "mofa.gov.tw"
        assert ct_log.watched_domain(synthetic(
            b"[]", url="https://crt.sh/?Identity=MOFA.gov.TW&output=json")) \
            == "mofa.gov.tw"
        draft = self._draft([issuance(1, not_before=iso_at(-1),
                                      issuer=TRUSTED_DN)])
        assert draft.flags["watched_domains"] == ["mofa.gov.tw"]

    def test_a_multi_country_scope_attributes_nothing(self):
        """Production knows which country a domain belongs to from
        `CT_LOG_WATCHED_DOMAINS` (`radar/sensors/ct_log.py:492-497`), a
        configuration table nothing under `v3/` may read. The country
        therefore arrives as the expansion scope, and a scope holding
        more than one country means the mapping is unknown — so nothing
        is emitted. Picking the first would attribute a certificate to a
        country that was never queried, and a wrong country reaches the
        convergence count as corroboration."""
        rows = [issuance(1, not_before=iso_at(-1), issuer=TRUSTED_DN,
                         names=("*.gov.tw",))]
        assert ct_log.normalize(
            synthetic(json.dumps(rows).encode(), label="certspotter",
                      url=CERTSPOTTER_URL),
            context("ct_log", countries=("TW", "JP"))) == ()

    def test_warmup_is_named_as_pending_and_never_asserted_false(self):
        """`warmup_active` is a BOOL in production (`ct_log.py:563`) and
        `core.py:1836` reads it as one. `False` would say "out of
        warmup", which is half of the rule that scores 3; the marker
        string would read as True forever. So the field is ABSENT and the
        reason is named beside it."""
        draft = self._draft([issuance(1, not_before=iso_at(-1),
                                      issuer=TRUSTED_DN)])
        assert "warmup_active" not in draft.flags
        assert draft.flags["warmup_verdict"] == \
            "pending_l1_domain_first_observed"
        assert "ct_log_domain_first_observed" in \
            ct_log.CT_LOG_ADAPTER.baseline_refs

    def test_the_wildcard_reason_is_productions_sentence(self):
        """`_ct_reason`'s wildcard branch (`radar/routes/core.py:1858-
        1862`). The port emitted no `fired_reason` at all, which empties
        the sentence an analyst reads next to the verdict."""
        draft = self._draft([issuance(
            1, not_before=iso_at(-1), issuer=TRUSTED_DN,
            names=("www.mofa.gov.tw", "*.gov.tw"))])
        assert draft.reason == ("CT Log: wildcard certificate at gov-TLD "
                                "level (1 subj) [WILDCARD_TLD_DETECTED]")
        assert draft.flags["country_status"] == "WILDCARD_TLD_DETECTED"

    def test_expand_is_still_declared_twice(self):
        """`"expand": ["dns_names", "issuer"]`
        (`ct_log_sources/certspotter.py:243-248`). Without `issuer` every
        certificate parses to `unknown` and is dropped, so the adapter is
        permanently silent while reporting success."""
        certspotter = ct_log.CT_LOG_ADAPTER.requests[0].alternatives[0]
        assert certspotter.param_values("expand") == ("dns_names", "issuer")
        assert certspotter.params == (
            ("domain", "{domain}"), ("include_subdomains", "true"),
            ("match_wildcards", "true"), ("expand", "dns_names"),
            ("expand", "issuer"))
        assert '"expand": ["dns_names", "issuer"]' in \
            legacy_source("radar/sensors/ct_log_sources/certspotter.py")


# ── apt_intel: the selection ledgers, compared whole ────────────────────

def legacy_literal(relative_path: str, name: str):
    for node in ast.walk(ast.parse(legacy_source(relative_path))):
        target = None
        if isinstance(node, ast.AnnAssign):
            target = node.target
        elif isinstance(node, ast.Assign) and node.targets:
            target = node.targets[0]
        if isinstance(target, ast.Name) and target.id == name:
            return ast.literal_eval(node.value)
    raise AssertionError(f"{name} is not a literal in {relative_path}")


class TestAptIntelLedgersMatchWhole:
    """The shipped membership checks name a dozen phrases out of 88. A
    ledger that agrees on the phrases someone thought to list and differs
    on the rest is exactly the failure the port already made once — an
    invented discard list sharing five phrases with legacy's and
    differing in nine. These compare the WHOLE table, in order, against
    the live sensor parsed at test time."""

    @pytest.mark.parametrize("legacy,ported", [
        ("_ADVISORY_KEYWORDS", "ADVISORY_KEYWORDS"),
        ("_DISCARD_KEYWORDS", "DISCARD_KEYWORDS"),
        ("_NOISE_TITLE_PREFIXES", "NOISE_TITLE_PREFIXES")])
    def test_the_ledger_is_the_live_one_entry_for_entry(self, legacy, ported):
        live = legacy_literal("radar/sensors/apt_intel.py", legacy)
        assert tuple(getattr(apt_intel, ported)) == tuple(live)

    def test_apt_intel_never_fires(self):
        """An advisory becomes a signal only after the LLM stage
        attributes it (O-17 / WP-2.7), so this adapter has no FIRED path
        and no `add_rat` entry to correspond to."""
        assert "apt_intel" not in production_signal_sources()
        source = Path(apt_intel.__file__).read_text("utf-8")
        assert "STATUS_FIRED" not in source


# ── ooni ────────────────────────────────────────────────────────────────

class TestOoniFidelity:
    OONI_URL = "https://api.ooni.io/api/v1/aggregation?probe_cc=CN"

    def _draft(self, document):
        return ooni_censorship.normalize(
            synthetic(json.dumps(document).encode(), label="aggregation",
                      url=self.OONI_URL),
            context("ooni_censorship", countries=("CN",)))

    def test_an_empty_result_array_is_a_measured_quiet_country(self):
        """`data.get("result", [])` and then `censorship_data[code] = ...`
        unconditionally (`radar/sensors/ooni.py:128,164-175`). Seven days
        with no OONI measurements is an answer; the port returned
        nothing, which makes "quiet" and "never asked" the same absence
        in the ledger — the one shape NP1 refuses."""
        for document in ({"result": []}, {}, {"result": None}):
            drafts = self._draft(document)
            assert len(drafts) == 1
            assert drafts[0].status == STATUS_OK
            assert drafts[0].value == "anomaly=0.0% confirmed=0.0% [NORMAL]"
            assert drafts[0].flags["total_measurements"] == 0

    def test_a_body_that_is_not_an_object_still_yields_nothing(self):
        """Production's `except` path around `res.json()` drops the
        country entirely (`radar/sensors/ooni.py:121-126`)."""
        for body in (b"not json", b"[]", b"null"):
            assert ooni_censorship.normalize(
                synthetic(body, label="aggregation", url=self.OONI_URL),
                context("ooni_censorship", countries=("CN",))) == ()

    def test_the_fired_reason_is_productions_sentence(self):
        """`_ooni_reason` (`radar/routes/core.py:1703-1705`). It is also
        the string the Tor cross-confirmation appends to (`:1876-1880`),
        so an empty one loses that text as well."""
        drafts = self._draft({"result": [
            {"measurement_count": 100, "anomaly_count": 50,
             "confirmed_count": 20, "failure_count": 1}]})
        assert drafts[0].status == STATUS_FIRED
        assert drafts[0].raw_score == 2.0
        assert drafts[0].reason == ("OONI: Internet censorship detected "
                                    "(anomaly=50.0%, confirmed=20.0%)")

    def test_a_quiet_country_carries_no_reason(self):
        drafts = self._draft({"result": [
            {"measurement_count": 100, "anomaly_count": 1,
             "confirmed_count": 0, "failure_count": 0}]})
        assert drafts[0].status == STATUS_OK
        assert drafts[0].reason == ""

    def test_the_reason_template_matches_the_live_one(self):
        source = legacy_source(CORE)
        assert "OONI: Internet censorship detected " in source
        assert "(anomaly={_ooni_anomaly_rate:.1%}, " \
               "confirmed={_ooni_confirmed_rate:.1%})" in source


# ── threatfox ───────────────────────────────────────────────────────────

class TestThreatfoxFidelity:
    def test_the_post_body_is_json_not_a_query_string(self):
        """`requests.post(url, json=payload)` with
        `payload = {"query": "get_iocs", "days": 1}`
        (`radar/sensors/threatfox.py:20,42`). abuse.ch does not read a
        query string, so the port's form was an error response the layer
        above reads as a quiet day."""
        spec = threatfox.THREATFOX_ADAPTER.requests[0]
        assert spec.method == "POST"
        assert dict(spec.body) == {"query": "get_iocs", "days": 1}
        assert spec.body_content_type == "application/json"
        assert spec.params == ()
        assert spec.body_bytes() == b'{"query": "get_iocs", "days": 1}'
        source = legacy_source("radar/sensors/threatfox.py")
        assert 'payload = {"query": "get_iocs", "days": 1}' in source
        assert "requests.post(url, json=payload" in source

    def test_the_credential_stays_mandatory(self):
        """R3. Production SKIPS the call when no key is configured and
        then calls `log_fetch(True, ...)` with zero hits
        (`radar/sensors/threatfox.py:34-38`) — a keyless run recorded as
        a success that found nothing. K10 says a keyless `get_iocs` is a
        401, so there is no anonymous mode to fall back to; reproducing
        the skip would reproduce the silent failure. AUTH_MISSING says
        "could not ask", which is the fact."""
        auth = threatfox.THREATFOX_ADAPTER.auth
        assert auth.is_required is True
        assert auth.optional is False
        assert (auth.name, auth.value_template) == ("Auth-Key", "{secret}")
        source = legacy_source("radar/sensors/threatfox.py")
        assert "if not tf_api_key:" in source
        assert "self.log_fetch(True, 0, 0, 0, \"\")" in source

    def test_the_fired_reason_is_carried_on_both_branches(self):
        """`core.py:1190` passes `"Known APT infra matched"`
        unconditionally, exactly as it passes `"APT C2 Hit"`. The port
        dropped it, which empties both the analyst sentence and the
        `detail.fired_reason` `hidden_signal_log` records (`:988`)."""
        line = next(text for text in legacy_source(CORE).splitlines()
                    if 'add_rat("threatfox"' in text)
        assert f'"{threatfox.RATIONALE_REASON}"' in line
        body = json.dumps({"query_status": "ok", "data": [
            {"tags": ["apt41"]}]}).encode()
        drafts = threatfox.normalize(
            synthetic(body, label="get_iocs"),
            context("threatfox", countries=("TW", "JP"),
                    country_names={"TW": "Taiwan", "JP": "Japan"}))
        assert {draft.status for draft in drafts} == {STATUS_FIRED}
        assert {draft.reason for draft in drafts} == \
            {"Known APT infra matched"}


# ── cloudflare_radar record defaults ────────────────────────────────────

class TestCloudflareRecordDefaults:
    def test_the_hijack_defaults_are_productions(self):
        """`prefix` defaults to `""` and `is_ongoing` to `False`
        (`radar/sensors/cloudflare.py:92,97`). `None` in their place
        travels into the flags and reaches the analyst as a missing field
        rather than an empty one."""
        body = json.dumps({"result": {"asn_hijacks": [
            {"confidence": 90, "victim_country": "tw"}]}}).encode()
        record = cloudflare_radar.normalize_hijacks(
            synthetic(body, label="hijacks"))[0]
        assert record["prefix"] == ""
        assert record["is_ongoing"] is False

    def test_the_leak_counts_default_to_zero(self):
        """`leaked_prefix_count` and `peer_count` default to 0
        (`radar/sensors/cloudflare.py:118,120`)."""
        body = json.dumps({"result": {"asn_leaks": [
            {"leak_asn": 4809, "leak_country": "tw"}]}}).encode()
        record = cloudflare_radar.normalize_leaks(
            synthetic(body, label="leaks"))[0]
        assert record["leaked_prefix_count"] == 0
        assert record["peer_count"] == 0


# ── the withheld verdicts, named where a consumer will look ─────────────

class TestWithheldVerdictsAreNamedNotAsserted:
    """R2. Four adapters withhold a score because the baseline the verdict
    needs is L1's and L1 is not wired yet. Each one reports what it
    measured as OBSERVED and names the missing table — it does not report
    OK, which would read as "measured, nothing wrong", and it does not
    invent the verdict from the half of the rule it can see.

    Every marker lives in a key of its OWN. A `pending_*` string is
    truthy, so putting it under the field whose type a consumer depends on
    turns "undecided" into a permanent assertion.
    """

    def test_ripe_bgp_withholds_the_hour_of_day_verdict(self):
        draft = ripe_bgp.normalize(
            synthetic(json.dumps({"data": {"resource": "TW",
                                   "resolution": "1h", "stats": [
                {"v4_prefixes_ris": 860, "v6_prefixes_ris": 40,
                 "asns_ris": 40, "v4_prefixes_stats": -1}]}}).encode()),
            context("ripe_bgp"))[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["hod_verdict"] == "pending_l1_bgp_hod"
        assert "is_anomaly" not in draft.flags
        assert ripe_bgp.RIPE_BGP_ADAPTER.baseline_refs == ("bgp_hod",)

    def test_cloudflare_withholds_the_attack_share_spike_verdict(self):
        draft = cloudflare_radar.normalize(
            synthetic(json.dumps({"result": {"top_0": [
                {"targetCountryAlpha2": "TW", "value": "34.5"}]}}).encode(),
                label="l3"),
            context("cloudflare_radar"))[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert "cf_attack_share_baseline" in \
            cloudflare_radar.CLOUDFLARE_RADAR_ADAPTER.baseline_refs

    def test_ooni_withholds_the_surge_condition(self):
        draft = ooni_censorship.normalize(
            synthetic(json.dumps({"result": [
                {"measurement_count": 100, "anomaly_count": 1}]}).encode(),
                label="aggregation",
                url="https://api.ooni.io/api/v1/aggregation?probe_cc=CN"),
            context("ooni_censorship", countries=("CN",)))[0]
        assert "anomaly_surge" not in draft.flags
        assert draft.flags["anomaly_surge_verdict"] == \
            "pending_l1_prev_anomaly_count"

    def test_ct_log_withholds_the_untrusted_ca_verdict(self):
        draft = ct_log.normalize(
            synthetic(json.dumps([issuance(
                1, not_before=iso_at(-1),
                issuer="C=CN, O=Some Internal Authority")]).encode(),
                label="certspotter", url=CERTSPOTTER_URL),
            context("ct_log"))[0]
        assert draft.status == STATUS_OBSERVED
        assert draft.raw_score == 0.0
        assert draft.flags["untrusted_ca_verdict"] == \
            "pending_l1_known_ca_ledger"
        assert "untrusted_ca=0" not in draft.value
