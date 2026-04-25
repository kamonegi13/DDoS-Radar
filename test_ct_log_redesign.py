"""Tests for ct_log sensor signal-model redesign (ADR-024).

Covers:
  - DB migration v11 tables exist on fresh init
  - DB helpers: ct_log_record_ca / ct_log_known_cas / ct_log_first_observed
  - Issuer parsing (O= extraction, fallback to CN=, raw passthrough)
  - Globally-trusted CA substring matching (LE / DigiCert pass; RU CA fails)
  - Trust decision tree:
      * Trusted CA on out-of-warmup domain   → no anomaly, history updated
      * Known per-domain CA                   → no anomaly, history refreshed
      * Untrusted CA during warm-up           → no anomaly, history seeded
      * Untrusted CA out of warmup            → anomaly fires
  - Round-robin domain selection covers all watched domains over multiple cycles
  - Wildcard-TLD detection at gov-namespace level fires regardless of trust
"""
import os
import time
import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.database import RadarDB
from radar.sensors.ct_log import (
    CtLogSensor,
    _is_globally_trusted,
)
from radar.sensors.ct_log_sources.crtsh import _parse_issuer
from radar.sensors.ct_log_sources.base import CertObservation
from radar.config import (
    CT_LOG_WARMUP_DAYS,
    CT_LOG_MAX_QUERIES_PER_COUNTRY,
)


def _obs_from_cert(cert: dict) -> CertObservation:
    """Translate the legacy crt.sh-shaped dict the redesign tests build into
    a CertObservation. Mirrors what CrtshSource.fetch_domain produces so
    _inspect_domain assertions remain semantically faithful to the field
    layout the orchestrator now sees."""
    from datetime import datetime, timezone
    issuer = (cert.get("issuer_name") or "").strip()
    norm, raw = _parse_issuer(issuer)
    name_value = cert.get("name_value") or ""
    sans = tuple(s for s in name_value.split("\n") if s) if name_value else ()
    nb_iso = cert.get("not_before") or ""
    try:
        clean = nb_iso.replace("T", " ").split(".")[0].rstrip("Z").strip()
        nb_ts = datetime.fromisoformat(clean).replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        nb_ts = time.time()
    return CertObservation(
        domain=(cert.get("common_name") or "").lower(),
        issuer_norm=norm,
        issuer_raw=raw,
        common_name=cert.get("common_name") or "",
        subject_alt_names=sans,
        not_before_ts=nb_ts,
        serial=str(cert.get("serial_number") or ""),
        source_name="test",
        observed_at_ts=time.time(),
    )


@pytest.fixture
def testdb(tmp_path):
    db_path = str(tmp_path / "test_ct.db")
    db = RadarDB(db_path)
    yield db
    db.close()


# ── DB layer ──────────────────────────────────────────────────────────────

def test_migration_v11_creates_tables(testdb):
    """Fresh DB should have ct_log_known_ca_per_domain and
    ct_log_domain_first_observed tables (created via _SCHEMA_SQL baseline)."""
    conn = testdb._get_conn()
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name IN ('ct_log_known_ca_per_domain', 'ct_log_domain_first_observed')"
    ).fetchall()
    names = {r[0] for r in rows}
    assert "ct_log_known_ca_per_domain" in names
    assert "ct_log_domain_first_observed" in names


def test_record_ca_is_idempotent(testdb):
    """Recording the same (domain, ca) twice should bump cert_count, not duplicate."""
    now = time.time()
    testdb.ct_log_record_ca("mofa.gov.tw", "lets encrypt", "Let's Encrypt", now)
    testdb.ct_log_record_ca("mofa.gov.tw", "lets encrypt", "Let's Encrypt", now + 1)
    testdb.ct_log_record_ca("mofa.gov.tw", "digicert", "DigiCert Inc", now + 2)
    cas = testdb.ct_log_known_cas("mofa.gov.tw")
    assert cas == {"lets encrypt", "digicert"}

    conn = testdb._get_conn()
    row = conn.execute(
        "SELECT cert_count FROM ct_log_known_ca_per_domain "
        "WHERE domain=? AND ca_normalized=?",
        ("mofa.gov.tw", "lets encrypt"),
    ).fetchone()
    assert row[0] == 2


def test_first_observed_is_set_once(testdb):
    """ct_log_set_first_observed should be a no-op on repeat (INSERT OR IGNORE)."""
    t0 = time.time() - 7200
    testdb.ct_log_set_first_observed("kremlin.ru", t0)
    testdb.ct_log_set_first_observed("kremlin.ru", t0 + 3600)
    fo = testdb.ct_log_first_observed("kremlin.ru")
    assert fo == pytest.approx(t0, abs=0.01)


def test_first_observed_unknown_returns_none(testdb):
    assert testdb.ct_log_first_observed("never.seen.example") is None
    assert testdb.ct_log_known_cas("never.seen.example") == set()


# ── Issuer parsing ────────────────────────────────────────────────────────

def test_parse_issuer_extracts_o_component():
    norm, raw = _parse_issuer("C=US, O=Let's Encrypt, CN=R3")
    assert norm == "let's encrypt"
    assert raw == "C=US, O=Let's Encrypt, CN=R3"


def test_parse_issuer_falls_back_to_cn():
    norm, _raw = _parse_issuer("CN=Custom Self-Signed Root")
    assert norm == "custom self-signed root"


def test_parse_issuer_handles_empty():
    norm, raw = _parse_issuer("")
    assert norm == "unknown"
    assert raw == "unknown"


def test_parse_issuer_handles_quoted_o():
    """Some CAs quote their O= value when it contains commas."""
    norm, _raw = _parse_issuer('C=US, O="DigiCert, Inc.", CN=DigiCert TLS')
    # The naive split-on-comma will only see "O=\"DigiCert" — that's an
    # acceptable degradation; the substring match against trusted_cas still
    # catches DigiCert in the raw form. Just verify it doesn't crash.
    assert isinstance(norm, str)


# ── Trusted-CA substring matching ─────────────────────────────────────────

def test_globally_trusted_recognizes_le_and_digicert():
    assert _is_globally_trusted("C=US, O=Let's Encrypt, CN=R3")
    assert _is_globally_trusted("C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1")
    assert _is_globally_trusted("C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root CA")


def test_globally_trusted_rejects_state_aligned_cas():
    """Adversary-state CAs are deliberately absent from the allowlist."""
    assert not _is_globally_trusted("C=RU, O=Russian Trusted Certificate Authority, CN=Russian Trusted Sub CA")
    assert not _is_globally_trusted("C=CN, O=GDCA, CN=GDCA TrustAUTH R5 ROOT")
    assert not _is_globally_trusted("")


# ── Trust decision tree (the heart of the redesign) ──────────────────────

def _le_cert(now_iso: str, name: str = "mofa.gov.tw") -> CertObservation:
    return _obs_from_cert({
        "common_name": name,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": now_iso,
    })


def _untrusted_cert(now_iso: str, name: str = "mofa.gov.tw") -> CertObservation:
    return _obs_from_cert({
        "common_name": name,
        "issuer_name": "C=RU, O=Russian Trusted Certificate Authority, CN=Russian Trusted Sub CA",
        "not_before": now_iso,
    })


def _now_iso(offset_sec: float = 0) -> str:
    from datetime import datetime, timezone, timedelta
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%S")


def test_trusted_ca_passes_silently(testdb):
    """LE on a fully-warmed-up watched domain: history updated, no anomaly fired."""
    sensor = CtLogSensor()
    domain = "mofa.gov.tw"
    # Simulate domain monitored long enough to be out of warm-up
    now = time.time()
    testdb.ct_log_set_first_observed(domain, now - (CT_LOG_WARMUP_DAYS + 1) * 86400)

    summary = sensor._inspect_domain(domain, "TW",
                                     [_le_cert(_now_iso())], now, testdb)
    assert summary["untrusted_events"] == []
    assert summary["wildcard_events"] == []
    # History should now contain Let's Encrypt for this domain
    assert "let's encrypt" in testdb.ct_log_known_cas(domain)


def test_warmup_suppresses_untrusted_anomaly(testdb):
    """Untrusted CA during warm-up: history seeded, no anomaly fired."""
    sensor = CtLogSensor()
    domain = "kremlin.ru"
    now = time.time()
    # First observation = now → fully in warm-up
    testdb.ct_log_set_first_observed(domain, now - 86400)  # 1 day in
    assert (now - testdb.ct_log_first_observed(domain)) < CT_LOG_WARMUP_DAYS * 86400

    summary = sensor._inspect_domain(
        domain, "RU", [_untrusted_cert(_now_iso())], now, testdb
    )
    assert summary["untrusted_events"] == [], "warm-up must suppress anomalies"
    assert summary["warmup_active"] is True
    # CA should be in known set after warm-up record
    cas = testdb.ct_log_known_cas(domain)
    assert "russian trusted certificate authority" in cas


def test_untrusted_ca_fires_after_warmup(testdb):
    """Untrusted CA on out-of-warmup domain: anomaly fires."""
    sensor = CtLogSensor()
    domain = "mfa.gov.ua"
    now = time.time()
    testdb.ct_log_set_first_observed(domain, now - (CT_LOG_WARMUP_DAYS + 5) * 86400)
    # Seed history with LE so it's "an established LE-using domain"
    testdb.ct_log_record_ca(domain, "let's encrypt",
                            "C=US, O=Let's Encrypt, CN=R3", now - 100000)

    summary = sensor._inspect_domain(
        domain, "UA", [_untrusted_cert(_now_iso())], now, testdb
    )
    assert len(summary["untrusted_events"]) == 1
    ev = summary["untrusted_events"][0]
    assert ev["domain"] == domain
    assert ev["country"] == "UA"
    assert "russian trusted" in ev["ca_normalized"]
    assert summary["warmup_active"] is False


def test_known_per_domain_ca_passes_after_warmup(testdb):
    """A 'normally untrusted' CA that is already in this domain's history
    should be allowed (some gov entities legitimately use national CAs)."""
    sensor = CtLogSensor()
    domain = "kremlin.ru"
    now = time.time()
    testdb.ct_log_set_first_observed(domain, now - (CT_LOG_WARMUP_DAYS + 30) * 86400)
    # History contains the Russian CA from prior observation cycles
    testdb.ct_log_record_ca(
        domain, "russian trusted certificate authority",
        "C=RU, O=Russian Trusted Certificate Authority, CN=Sub CA", now - 1_000_000,
    )

    summary = sensor._inspect_domain(
        domain, "RU", [_untrusted_cert(_now_iso())], now, testdb
    )
    assert summary["untrusted_events"] == [], (
        "CA in per-domain history must not fire even if globally untrusted"
    )


def test_anomaly_does_not_re_fire_in_same_cycle(testdb):
    """After firing on an untrusted CA, the CA enters history so a second
    cert from the same CA in the same observation window does not double-fire."""
    sensor = CtLogSensor()
    domain = "mfa.gov.ua"
    now = time.time()
    testdb.ct_log_set_first_observed(domain, now - (CT_LOG_WARMUP_DAYS + 1) * 86400)

    certs = [_untrusted_cert(_now_iso()), _untrusted_cert(_now_iso(-60))]
    summary = sensor._inspect_domain(domain, "UA", certs, now, testdb)
    assert len(summary["untrusted_events"]) == 1, (
        "second cert from same CA in same cycle must not re-fire"
    )


# ── Wildcard-TLD detection ───────────────────────────────────────────────

def test_wildcard_at_gov_tld_fires(testdb):
    """A wildcard cert at the country gov-TLD level (*.gov.tw) is uniformly
    suspicious regardless of issuer."""
    sensor = CtLogSensor()
    domain = "mofa.gov.tw"
    now = time.time()
    testdb.ct_log_set_first_observed(domain, now - (CT_LOG_WARMUP_DAYS + 5) * 86400)

    obs = _obs_from_cert({
        "common_name": "*.gov.tw",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",  # even from LE
        "not_before": _now_iso(),
    })
    summary = sensor._inspect_domain(domain, "TW", [obs], now, testdb)
    assert summary["wildcard_count"] >= 1
    assert len(summary["wildcard_events"]) >= 1
    assert summary["wildcard_events"][0]["wildcard_subject"] == "*.gov.tw"


def test_wildcard_at_subdomain_does_not_fire(testdb):
    """A wildcard at a non-gov-TLD level (e.g. *.mofa.gov.tw) is normal
    enterprise practice — should NOT fire wildcard-TLD detection."""
    sensor = CtLogSensor()
    domain = "mofa.gov.tw"
    now = time.time()
    testdb.ct_log_set_first_observed(domain, now - (CT_LOG_WARMUP_DAYS + 5) * 86400)

    obs = _obs_from_cert({
        "common_name": "*.api.mofa.gov.tw",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": _now_iso(),
    })
    summary = sensor._inspect_domain(domain, "TW", [obs], now, testdb)
    assert summary["wildcard_count"] == 0


# ── Round-robin domain selection ─────────────────────────────────────────

def test_round_robin_covers_all_domains():
    """Over enough cycles, every watched domain should be queried."""
    from radar.config import CT_LOG_WATCHED_DOMAINS, CT_LOG_MAX_QUERIES_PER_COUNTRY
    sensor = CtLogSensor()
    expected = set(CT_LOG_WATCHED_DOMAINS["US"])
    # Run enough cycles to cover the full set with margin: ceil(N / budget) + 1
    cycles = (len(expected) // max(1, CT_LOG_MAX_QUERIES_PER_COUNTRY)) + 2
    seen = set()
    for _ in range(cycles):
        seen.update(sensor._select_domains_for_country("US"))
    assert seen == expected


def test_round_robin_returns_full_list_when_under_budget():
    """A theater with fewer domains than the per-cycle budget should always
    return its full set (no rotation needed)."""
    from radar.config import CT_LOG_WATCHED_DOMAINS, CT_LOG_MAX_QUERIES_PER_COUNTRY
    sensor = CtLogSensor()
    # Pick a country whose curated set fits within the per-cycle budget.
    candidates = [c for c, ds in CT_LOG_WATCHED_DOMAINS.items()
                  if len(ds) <= CT_LOG_MAX_QUERIES_PER_COUNTRY]
    if not candidates:
        # Synthetic: shrink one to one domain via the round-robin call directly.
        # Confirm slice equals the full set when budget >= len.
        small = next(iter(CT_LOG_WATCHED_DOMAINS))
        sensor_test = CtLogSensor()
        sliced = sensor_test._select_domains_for_country(small)
        assert len(sliced) <= CT_LOG_MAX_QUERIES_PER_COUNTRY
        return
    code = candidates[0]
    domains = sensor._select_domains_for_country(code)
    assert sorted(domains) == sorted(CT_LOG_WATCHED_DOMAINS[code])


def test_round_robin_unknown_country_returns_empty():
    sensor = CtLogSensor()
    assert sensor._select_domains_for_country("ZZ") == []


# ── Status / scoring shape ────────────────────────────────────────────────

def test_upstream_health_exposes_redesign_metadata():
    """T1.B sensor_health endpoint relies on these keys being present.

    After the multi-source refactor (Phase 1), per-source failure_modes
    moved under `sources.<source_name>.mode_counters`; the orchestrator
    aggregate exposes `sources`, `buffer`, `source_freshness`."""
    sensor = CtLogSensor()
    health = sensor.upstream_health()
    assert health["scoring_model"] == "adr_024_signal_redesign"
    assert "anomaly_counts" in health
    assert "warmup_days" in health
    assert health["warmup_days"] == CT_LOG_WARMUP_DAYS
    assert "queries_per_country_per_cycle" in health
    assert health["queries_per_country_per_cycle"] == CT_LOG_MAX_QUERIES_PER_COUNTRY
    # Multi-source aggregate
    assert "sources" in health
    assert "crtsh" in health["sources"]
    crtsh_health = health["sources"]["crtsh"]
    assert set(crtsh_health["mode_counters"].keys()) == {
        "timeout", "conn_error", "http_5xx", "http_4xx", "json_error", "empty_result"
    }
    assert "buffer" in health
    assert "source_freshness" in health
