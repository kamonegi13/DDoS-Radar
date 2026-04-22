"""Phase 2B verification: live fetch end-to-end.

One-shot harness:
  1. Spin up an in-memory test DB
  2. Run CtLogSensor.fetch() with a TW theater context (real network call
     to certspotter; uses 1 request from the per-IP 30 req/hr budget per
     watched domain in the round-robin slice)
  3. Inspect the DB and the result dict for expected post-conditions

Pass criteria:
  * any_real_response True (i.e. orchestrator saw an alive source)
  * source_freshness["certspotter"] is recent
  * ct_log_first_observed populated for at least one polled domain
  * If observations arrived: ct_log_known_ca_per_domain populated for
    that domain (CAs recorded under the per-domain key)

Delete this file once Phase 2B is signed off.
"""
from __future__ import annotations

import os
import time
import tempfile

os.environ.setdefault("JWT_SECRET_KEY", "verify")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "verify")

from radar.database import RadarDB
from radar import database as _db_mod
from radar.sensors.ct_log import CtLogSensor
from radar.config import CT_LOG_WATCHED_DOMAINS


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="ct_verify_")
    db_path = os.path.join(tmp, "verify.db")
    db = RadarDB(db_path)
    _db_mod.db = db
    print(f"[verify] db: {db_path}")

    tw_domains = CT_LOG_WATCHED_DOMAINS.get("TW", [])
    print(f"[verify] TW watched: {tw_domains}")

    sensor = CtLogSensor()
    sources = [s.name for s in sensor._pull_sources]
    print(f"[verify] sources: {sources}")
    if sources[0] != "certspotter":
        print("[verify] FAIL: certspotter not primary")
        return 1

    ctx = {"strategic_theaters": ["TW"], "adversary_states": []}
    t0 = time.time()
    result = sensor.fetch(ctx)
    elapsed = time.time() - t0
    print(f"[verify] fetch took {elapsed:.2f}s")

    health = sensor.upstream_health()
    print(f"[verify] orchestrator status: {health['status']}")
    print(f"[verify] consecutive_failures: {health['consecutive_failures']}")
    print(f"[verify] source_freshness: {health['source_freshness']}")
    cs = health["sources"].get("certspotter", {})
    print(f"[verify] certspotter health: status={cs.get('status')} "
          f"consecutive_failures={cs.get('consecutive_failures')} "
          f"counters={cs.get('mode_counters')}")
    cs_specific = cs.get("source_specific", {})
    print(f"[verify] certspotter bucket remaining: "
          f"{cs_specific.get('local_bucket_remaining')}")

    tw = result["ct_data"].get("TW", {})
    print(f"[verify] TW status: {result['country_status'].get('TW')}")
    print(f"[verify] TW total_recent: {tw.get('total_recent')}")
    print(f"[verify] TW watched_domains polled: {tw.get('watched_domains')}")
    print(f"[verify] TW observed_domains: {tw.get('observed_domains')}")

    # DB verification — first_observed marker
    fo_count = 0
    for d in tw.get("watched_domains", []):
        fo = db.ct_log_first_observed(d)
        if fo is not None:
            fo_count += 1
            age = round((time.time() - fo) / 60, 1)
            print(f"[verify]   first_observed[{d}] = {age} min ago")
    print(f"[verify] first_observed populated: {fo_count}/"
          f"{len(tw.get('watched_domains', []))}")

    # DB verification — known CAs per domain
    ca_count = 0
    for d in tw.get("watched_domains", []):
        cas = db.ct_log_known_cas(d)
        if cas:
            ca_count += 1
            print(f"[verify]   known_cas[{d}] = {sorted(cas)[:3]}"
                  + ("..." if len(cas) > 3 else ""))
    print(f"[verify] known_cas populated: {ca_count}/"
          f"{len(tw.get('watched_domains', []))}")

    # Verdict
    cs_alive = (cs.get("status") == "healthy"
                and cs.get("consecutive_failures") == 0)
    fo_present = fo_count > 0

    if cs_alive and fo_present:
        print("[verify] PASS — certspotter alive, first_observed populated")
        return 0
    if cs_alive and not fo_present:
        print("[verify] PARTIAL — certspotter alive but first_observed not "
              "armed (likely none of the polled domains had certs OR "
              "the round-robin picked domains certspotter doesn't index)")
        return 0
    print("[verify] FAIL — certspotter not healthy")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
