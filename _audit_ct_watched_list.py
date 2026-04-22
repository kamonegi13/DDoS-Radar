"""Phase 2D: watched-list audit against both CT pull sources.

For each watched domain, probe certspotter then crt.sh and record:
  * which source(s) answered with a 200-class response
  * which source(s) returned None (transport failure or CB-open)
  * source-specific failure modes (403 region-block, 5xx, timeout, ...)
  * how many observations each source surfaced for the apex query

Intended to be run on demand — NOT in CI. The certspotter free tier is
30 req/hr/IP, so a full sweep across all 27 watched countries (~243
domains) takes ~8h real-time. Default scope is a small handful of
countries; pass --country TW,UA,JP,... to widen.

Output: prints a human-readable per-domain table and writes a JSON
report to docs/reports/ct_log_watched_audit_<UTCDATE>.json. The report
feeds the follow-up decision matrix:

  certspotter OK + crtsh OK  → keep as-is
  certspotter OK + crtsh err → keep; crt.sh fallback may underperform
  certspotter err + crtsh OK → expected fallback path; document why
  certspotter err + crtsh err → candidate for removal from watched list
                                 (likely never indexed, or geo-restricted
                                 from both sources)

Delete this file once Phase 2D follow-up actions are landed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "audit")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "audit")

from radar.config import CT_LOG_WATCHED_DOMAINS, CERTSPOTTER_API_TOKEN
from radar.sensors.ct_log_sources.certspotter import CertspotterSource
from radar.sensors.ct_log_sources.crtsh import CrtshSource


def _probe(source, domain: str) -> dict:
    """Probe a single (source, domain) and report outcome."""
    t0 = time.time()
    try:
        result = source.fetch_domain(domain)
    except Exception as e:
        return {
            "outcome": "exception",
            "elapsed_sec": round(time.time() - t0, 2),
            "obs_count": 0,
            "error": f"{type(e).__name__}: {e}"[:200],
        }
    elapsed = round(time.time() - t0, 2)
    if result is None:
        # Hard failure / CB-open / rate-limited — pull mode-counters from
        # health() to attribute the cause.
        h = source.health()
        modes = {k: v for k, v in h.get("mode_counters", {}).items() if v}
        ss = h.get("source_specific", {})
        suffix = []
        if ss.get("rate_limited"):
            suffix.append(
                f"rate_limited({int(ss.get('rate_limited_remaining_sec', 0))}s)"
            )
        if ss.get("cb_open"):
            suffix.append(
                f"cb_open({int(ss.get('cb_open_remaining_sec', 0))}s)"
            )
        return {
            "outcome": "transport_fail",
            "elapsed_sec": elapsed,
            "obs_count": 0,
            "mode_counters": modes,
            "flags": suffix,
        }
    return {
        "outcome": "ok",
        "elapsed_sec": elapsed,
        "obs_count": len(result),
    }


def _classify(cs: dict, crt: dict) -> str:
    cs_ok = cs["outcome"] == "ok"
    crt_ok = crt["outcome"] == "ok"
    if cs_ok and crt_ok:
        return "BOTH_OK"
    if cs_ok and not crt_ok:
        return "CERTSPOTTER_ONLY"
    if not cs_ok and crt_ok:
        return "CRTSH_ONLY"
    return "BOTH_FAIL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--country", default="TW",
        help="Comma-separated ISO2 codes (e.g. 'TW,UA,JP'). Default: TW.",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Probe every watched country. Slow — respects rate limits.",
    )
    parser.add_argument(
        "--limit-per-country", type=int, default=0,
        help="Cap domains per country (0 = no cap).",
    )
    parser.add_argument(
        "--inter-domain-sleep", type=float, default=2.0,
        help="Seconds between probes (within a single source). Default: 2.0.",
    )
    parser.add_argument(
        "--report-dir", default="docs/reports",
        help="Where to write the JSON report.",
    )
    args = parser.parse_args()

    if args.all:
        countries = sorted(CT_LOG_WATCHED_DOMAINS.keys())
    else:
        countries = [c.strip().upper() for c in args.country.split(",") if c.strip()]
        countries = [c for c in countries if c in CT_LOG_WATCHED_DOMAINS]
    if not countries:
        print("No matching countries in CT_LOG_WATCHED_DOMAINS", file=sys.stderr)
        return 1

    cs_source = CertspotterSource(api_token=CERTSPOTTER_API_TOKEN)
    crt_source = CrtshSource()

    print(f"[audit] countries: {countries}")
    print(f"[audit] certspotter authenticated: {bool(CERTSPOTTER_API_TOKEN)}")
    print(f"[audit] inter-domain sleep: {args.inter_domain_sleep}s")
    print()

    by_country: dict[str, list[dict]] = {}
    summary_counts = {
        "BOTH_OK": 0, "CERTSPOTTER_ONLY": 0,
        "CRTSH_ONLY": 0, "BOTH_FAIL": 0,
    }

    for code in countries:
        domains = CT_LOG_WATCHED_DOMAINS[code]
        if args.limit_per_country > 0:
            domains = domains[:args.limit_per_country]
        rows = []
        for domain in domains:
            cs_result = _probe(cs_source, domain)
            time.sleep(args.inter_domain_sleep)
            # Only probe crt.sh when certspotter didn't give us
            # actionable data — saves crt.sh's slow round-trip when
            # the primary already answered. The audit specifically
            # cares about coverage gaps, so failed/empty cs results
            # always trigger the crt.sh probe.
            if cs_result["outcome"] == "ok" and cs_result["obs_count"] > 0:
                crt_result = {"outcome": "skipped", "obs_count": 0}
            else:
                crt_result = _probe(crt_source, domain)
                time.sleep(args.inter_domain_sleep)
            klass = _classify(
                cs_result,
                crt_result if crt_result["outcome"] != "skipped"
                else {"outcome": "ok", "obs_count": 1},
            )
            summary_counts[klass] = summary_counts.get(klass, 0) + 1
            row = {
                "country": code,
                "domain": domain,
                "class": klass,
                "certspotter": cs_result,
                "crtsh": crt_result,
            }
            rows.append(row)
            cs_tag = (f"ok({cs_result['obs_count']})"
                      if cs_result["outcome"] == "ok"
                      else cs_result["outcome"])
            crt_tag = (f"ok({crt_result['obs_count']})"
                       if crt_result["outcome"] == "ok"
                       else crt_result["outcome"])
            print(f"[{code}] {domain:<32} cs={cs_tag:<22} crt={crt_tag:<22} → {klass}")
        by_country[code] = rows

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "countries": countries,
        "summary_counts": summary_counts,
        "results_by_country": by_country,
    }
    out_dir = Path(args.report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M")
    out_path = out_dir / f"ct_log_watched_audit_{stamp}.json"
    out_path.write_text(json.dumps(report, indent=2))

    print()
    print(f"[audit] report: {out_path}")
    print(f"[audit] summary: {summary_counts}")
    if summary_counts.get("BOTH_FAIL", 0) > 0:
        print("[audit] BOTH_FAIL domains (candidates for removal/investigation):")
        for code, rows in by_country.items():
            for r in rows:
                if r["class"] == "BOTH_FAIL":
                    print(f"          {code} {r['domain']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
