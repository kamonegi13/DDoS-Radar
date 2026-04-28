#!/usr/bin/env python3
"""Audit intel-submitting sensors — α (implementation) vs β (base rate).

Reads the production radar SQLite DB and answers: for each sensor that
contributes to the LLM intel queue, why is its output volume low?

  α = sensor is broken / pre-filter too strict / config missing
  β = sensor is healthy, world is just quiet right now

The two have different remediations: α gets a code/config fix, β gets
patience. Without separating them we waste effort on the wrong one.

Signals examined:
  - llm_intel rows submitted in last 7d / 24h / 1h, per source_type
  - llm_call_log per caller × outcome (ok / pre_filter / parse_failed /
    timeout / disabled), surfacing whether the sensor is even reaching
    the LLM in the first place
  - llm_sources credibility distribution (sources that submitted a row
    at least once but never became confirmed)

Read-only — no DB writes, no LLM calls.

Usage:
    docker exec ddos-radar python scripts/audit_intel_sensors.py
    docker exec ddos-radar python scripts/audit_intel_sensors.py --json
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter, defaultdict


# Sensors that submit to intel_queue. Update if a new contributor is added.
INTEL_SENSORS: tuple[str, ...] = (
    "apt_intel",
    "diplomatic",
    "military_exercise",
    "rss_narrative",
    "ground_osint",
    "hacktivist_intel",
    "hacktivist_news",
)


def _now() -> float:
    return time.time()


def _open(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def per_sensor_call_log(conn: sqlite3.Connection, hours: int) -> dict:
    """Per-caller × per-outcome counts from llm_call_log over last `hours`."""
    cutoff = _now() - hours * 3600
    out: dict = defaultdict(lambda: defaultdict(int))
    for row in conn.execute(
        "SELECT caller, outcome, COUNT(*) FROM llm_call_log "
        "WHERE ts > ? GROUP BY caller, outcome",
        (cutoff,),
    ):
        out[row[0] or "<unknown>"][row[1] or "<unknown>"] = int(row[2])
    return {k: dict(v) for k, v in out.items()}


def per_sensor_pre_filter_reasons(conn: sqlite3.Connection, hours: int) -> dict:
    """Top pre_filter verdict reasons per caller. Helps the operator see
    whether a high pre_filter ratio is α (url stale, parser broken) or
    β (filter rejecting healthy-but-irrelevant articles).
    """
    cutoff = _now() - hours * 3600
    out: dict = defaultdict(lambda: defaultdict(int))
    for row in conn.execute(
        "SELECT caller, verdict, COUNT(*) FROM llm_call_log "
        "WHERE ts > ? AND outcome='pre_filter' "
        "GROUP BY caller, verdict",
        (cutoff,),
    ):
        out[row[0] or "<unknown>"][row[1] or "<unknown>"] = int(row[2])
    return {k: dict(v) for k, v in out.items()}


def per_source_type_intel(conn: sqlite3.Connection, hours: int) -> dict:
    cutoff = _now() - hours * 3600
    out: dict = defaultdict(lambda: defaultdict(int))
    for row in conn.execute(
        "SELECT source_type, status, COUNT(*) FROM llm_intel "
        "WHERE created_at > ? GROUP BY source_type, status",
        (cutoff,),
    ):
        out[row[0] or "<unknown>"][row[1] or "<unknown>"] = int(row[2])
    return {k: dict(v) for k, v in out.items()}


def diversity_now(conn: sqlite3.Connection, hours: int) -> dict:
    cutoff = _now() - hours * 3600
    by_theater: dict[str, set[str]] = defaultdict(set)
    rows = conn.execute(
        "SELECT theater, source_type FROM llm_intel WHERE created_at > ?",
        (cutoff,),
    ).fetchall()
    for theater, src in rows:
        by_theater[theater or "<none>"].add(src or "<none>")
    if not by_theater:
        return {"theaters": 0, "avg_distinct": 0.0,
                "max_distinct": 0, "single_source_theaters": 0}
    return {
        "theaters": len(by_theater),
        "avg_distinct": round(sum(len(s) for s in by_theater.values())
                              / len(by_theater), 2),
        "max_distinct": max(len(s) for s in by_theater.values()),
        "single_source_theaters": sum(1 for s in by_theater.values() if len(s) == 1),
    }


def classify(call_log_7d: dict, intel_7d: dict, sensor: str) -> tuple[str, str]:
    """Classify a sensor as α (implementation problem) / β (base rate) /
    healthy / unknown. Heuristic, intentionally conservative.

    α signals: caller has llm_call_log entries dominated by pre_filter,
        timeout, or parse_failed. The LLM either never fired or returned
        garbage. Code/config is the cause.
    β signals: caller has llm_call_log dominated by 'ok' but llm_intel
        items are still scarce — the LLM is running, classifying inputs,
        and just not finding many candidates worth submitting. World is
        quiet OR the LLM's confidence floor LLM_CONFIDENCE_MIN is too high.
    healthy: caller has 'ok' and llm_intel rows accumulating across
        multiple statuses (pending / confirmed / rejected / auto_*).
    unknown: not enough log activity to classify (no calls in 7d, no rows).
    """
    calls = call_log_7d.get(sensor, {})
    total_calls = sum(calls.values())
    if total_calls == 0:
        return ("unknown", "no llm_call_log activity in 7d")

    ok = calls.get("ok", 0)
    pre = calls.get("pre_filter", 0)
    parse_fail = calls.get("parse_failed", 0)
    timeout = calls.get("timeout", 0)
    disabled = calls.get("disabled", 0)
    other_err = calls.get("error", 0) + calls.get("http_error", 0)

    pre_ratio = pre / total_calls
    err_ratio = (parse_fail + timeout + other_err) / total_calls
    ok_ratio = ok / total_calls

    # Map sensor name → source_type — most sensors share their name; rss_narrative
    # tags as 'narrative', others identical.
    src_type = {
        "rss_narrative": "narrative",
        "military_exercise": "military",
        "diplomatic": "diplomatic",
        "apt_intel": "apt_intel",
        "ground_osint": "ground_osint",
        "hacktivist_intel": "hacktivist",
        "hacktivist_news": "hacktivist",
    }.get(sensor, sensor)
    intel_count = sum(intel_7d.get(src_type, {}).values())

    if disabled > 0 and disabled / total_calls > 0.5:
        return ("α", f"sensor mostly disabled ({disabled}/{total_calls})")
    if err_ratio >= 0.20:
        return ("α", f"errors {err_ratio*100:.0f}% (parse/timeout/http) — investigate stack trace")
    # When pre_filter dominates we want to look at the *reason* breakdown,
    # not just the ratio. The sensor itself (since 2026-04-29) writes
    # specific verdict tags that distinguish β-base-rate ('no_kw_match_healthy_feed',
    # 'rss_empty') from α-implementation ('feed_url_stale_html', 'feed_unparseable',
    # 'no_articles_post_filter' on legacy callers). Caller of this function
    # passes the per-sensor verdict counts via call_log_7d when available.
    if pre_ratio >= 0.95:
        return ("α", f"pre_filter rejecting {pre_ratio*100:.0f}% — LLM never invoked "
                      "(check verdict reasons for url_stale vs base_rate)")
    if ok_ratio >= 0.50 and intel_count == 0:
        return ("β?", f"LLM running ({ok}/{total_calls} ok) but submitting 0 rows — base rate or "
                       "LLM_CONFIDENCE_MIN too high")
    if ok_ratio >= 0.50 and intel_count > 0:
        return ("healthy", f"ok={ok}, intel rows in 7d={intel_count}")
    if pre_ratio > 0.50:
        return ("α", f"pre_filter blocking majority ({pre_ratio*100:.0f}%)")
    return ("unknown", f"mixed signal: ok={ok} pre={pre} err={parse_fail+timeout+other_err}")


def render(call_log_7d, intel_7d, intel_24h, divers_7d, divers_24h, classifications,
           pre_reasons_7d=None):
    out = []
    out.append("=" * 76)
    out.append(" Intel Sensor Audit — α (implementation) / β (base rate) classification")
    out.append("=" * 76)

    out.append("\n[Per-sensor LLM call_log breakdown — last 7 days]")
    out.append("  sensor                | total | ok    | pre_f | err   | classification")
    out.append("  ----------------------|-------|-------|-------|-------|----------------")
    for s in INTEL_SENSORS:
        c = call_log_7d.get(s, {})
        total = sum(c.values())
        ok = c.get("ok", 0)
        pre = c.get("pre_filter", 0)
        err = c.get("parse_failed", 0) + c.get("timeout", 0) + c.get("error", 0) + c.get("http_error", 0)
        klass, reason = classifications.get(s, ("?", "?"))
        out.append(
            f"  {s:21s} | {total:>5d} | {ok:>5d} | {pre:>5d} | {err:>5d} | "
            f"{klass:>8s}  ({reason})"
        )

    out.append("\n[Intel submissions per source_type — last 7 days]")
    out.append("  source_type      | pending | confirmed | auto_conf | rejected | total")
    out.append("  -----------------|---------|-----------|-----------|----------|------")
    all_types = sorted(intel_7d.keys())
    if not all_types:
        out.append("  (no intel rows in 7d)")
    for st in all_types:
        b = intel_7d[st]
        total = sum(b.values())
        out.append(
            f"  {st:16s} | {b.get('pending', 0):>7d} | "
            f"{b.get('confirmed', 0):>9d} | "
            f"{b.get('auto_confirmed', 0):>9d} | "
            f"{b.get('rejected', 0):>8d} | {total:>5d}"
        )

    out.append("\n[Source diversity — Layer 1 prerequisite]")
    out.append(f"  7-day window:  theaters={divers_7d['theaters']:>3d}  "
               f"avg_distinct={divers_7d['avg_distinct']:.2f}  "
               f"max_distinct={divers_7d['max_distinct']}  "
               f"single_src_theaters={divers_7d['single_source_theaters']}")
    out.append(f"  24h window:    theaters={divers_24h['theaters']:>3d}  "
               f"avg_distinct={divers_24h['avg_distinct']:.2f}  "
               f"max_distinct={divers_24h['max_distinct']}  "
               f"single_src_theaters={divers_24h['single_source_theaters']}")

    if pre_reasons_7d:
        out.append("\n[Pre-filter verdict reasons — last 7 days]")
        out.append("  (helps tell α=url-stale / α=parser-bug from β=base-rate)")
        for sensor in INTEL_SENSORS:
            reasons = pre_reasons_7d.get(sensor, {})
            if not reasons:
                continue
            top = sorted(reasons.items(), key=lambda kv: -kv[1])[:6]
            out.append(f"  {sensor}:")
            for verdict, count in top:
                # Annotate verdict tags with quick α/β hints.
                hint = ""
                vlow = verdict.lower()
                if "stale_html" in vlow or "unparseable" in vlow:
                    hint = "  ← α (url stale / parser bug)"
                elif "fetch_failed" in vlow:
                    hint = "  ← α (404/timeout — check feed URL)"
                elif "no_kw_match_healthy_feed" in vlow or "rss_empty" in vlow:
                    hint = "  ← β (feed healthy, content irrelevant)"
                elif "no_telegram_entries" in vlow or "no_burst" in vlow:
                    hint = "  ← α-or-β (depends on cycle warmup)"
                out.append(f"    {count:>5d}  {verdict}{hint}")

    out.append("\n[Diagnosis summary]")
    alpha = [s for s, (k, _) in classifications.items() if k == "α"]
    beta = [s for s, (k, _) in classifications.items() if k.startswith("β")]
    healthy = [s for s, (k, _) in classifications.items() if k == "healthy"]
    unknown = [s for s, (k, _) in classifications.items() if k == "unknown"]
    out.append(f"  α (broken/misconfigured): {len(alpha):>2d}  {alpha}")
    out.append(f"  β (base rate / LLM picky): {len(beta):>2d}  {beta}")
    out.append(f"  healthy:                   {len(healthy):>2d}  {healthy}")
    out.append(f"  unknown:                   {len(unknown):>2d}  {unknown}")

    out.append("\n[Next-step guide]")
    if alpha:
        out.append(f"  α sensors → investigate code: pre_filter logic, country tags, language")
        out.append(f"     allow-list, RSS feed URLs, credentials. Target: drop pre_filter ratio")
        out.append(f"     below 80% so the LLM gets a fair sample.")
    if beta:
        out.append(f"  β? sensors → either base rate is genuinely low (accept), or")
        out.append(f"     LLM_CONFIDENCE_MIN ({0.35} default) is filtering too hard.")
        out.append(f"     Inspect a few discarded items by lowering CONFIDENCE_MIN to 0.20")
        out.append(f"     temporarily and re-running this audit.")
    if not alpha and not beta:
        out.append(f"  All sensors classified healthy or unknown — no action needed.")
    if divers_7d["max_distinct"] < 2:
        out.append(f"  Diversity = 1 in 7d. Even after α fixes, Layer 1 needs ≥2 distinct")
        out.append(f"  source_types per theater. Watch this metric weekly.")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default="radar/persistence/radar.db")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    try:
        conn = _open(args.db)
    except sqlite3.OperationalError as exc:
        print(f"could not open db {args.db!r}: {exc}", file=sys.stderr)
        return 2

    call_log_7d = per_sensor_call_log(conn, hours=7 * 24)
    pre_reasons_7d = per_sensor_pre_filter_reasons(conn, hours=7 * 24)
    intel_7d = per_source_type_intel(conn, hours=7 * 24)
    intel_24h = per_source_type_intel(conn, hours=24)
    divers_7d = diversity_now(conn, hours=7 * 24)
    divers_24h = diversity_now(conn, hours=24)

    classifications: dict[str, tuple[str, str]] = {
        s: classify(call_log_7d, intel_7d, s) for s in INTEL_SENSORS
    }

    if args.json:
        print(json.dumps({
            "call_log_7d": call_log_7d,
            "pre_filter_reasons_7d": pre_reasons_7d,
            "intel_7d": intel_7d,
            "intel_24h": intel_24h,
            "diversity_7d": divers_7d,
            "diversity_24h": divers_24h,
            "classifications": {k: {"class": v[0], "reason": v[1]}
                                for k, v in classifications.items()},
        }, indent=2))
    else:
        print(render(call_log_7d, intel_7d, intel_24h,
                     divers_7d, divers_24h, classifications,
                     pre_reasons_7d=pre_reasons_7d))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
