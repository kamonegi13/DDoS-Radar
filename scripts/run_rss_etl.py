#!/usr/bin/env python3
"""RSS / news-wire correlator — OPSEC-friendly ground-truth ETL (B1).

Pulls public RSS feeds via anonymous HTTP GET, runs the deterministic
regex extractor in ``radar/conclusions/rss_extractor.py``, and labels
recent v2 conclusions whose participant countries match a kinetic event
in the feed window. No API keys, no registrations, no per-deployment
identifiers exposed to upstream sources — the only side-channel is the
HTTP request itself (User-Agent, source IP).

LLM augmentation is **optional** (NP3 + project policy: features must
not require an LLM to function). With ``--use-llm`` the extractor asks
the configured Ollama instance for structured output; on any failure
it transparently falls back to the regex baseline. The CI gate must
pass without an LLM reachable.

Default RSS feed list intentionally diverse (BBC / Reuters / AP / Al
Jazeera / TASS / Xinhua) to balance Western and non-Western framings;
override with ``--feeds-file`` (one URL per line).

Usage:
    python scripts/run_rss_etl.py                       # default feeds, regex only
    python scripts/run_rss_etl.py --use-llm             # regex + opt LLM
    python scripts/run_rss_etl.py --scenario taiwan_contingency
    python scripts/run_rss_etl.py --feeds-file my_feeds.txt --dry-run
    python scripts/run_rss_etl.py --force                # bypass V2_GROUND_TRUTH_ETL_ENABLED
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from typing import Iterable, Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault(
    "V2_NP7_DISCLAIMER",
    "This output is one node in your intelligence process.",
)

from email.utils import parsedate_to_datetime  # noqa: E402

from radar import config  # noqa: E402
from radar.conclusions.base import ConclusionType  # noqa: E402
from radar.conclusions.feedback import AnalystFeedback, save_feedback  # noqa: E402
from radar.conclusions.ground_truth_etl import (  # noqa: E402
    expected_tl_floor,
    has_existing_auto_feedback,
    label_for_threat_level,
    list_conclusions_in_window,
)
from radar.conclusions.rss_extractor import extract_kinetic  # noqa: E402
from radar.database import RadarDB  # noqa: E402
from radar.scenarios import scenario_store  # noqa: E402

log = logging.getLogger("rss_etl")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# Conservative default RSS list. Mix of Western, non-Western, and regional
# wires so framing biases partially cancel. Override with --feeds-file.
#
# Kept in sync with config.BG_OBSERVER_FEEDS (the curated, verified-live set
# the scheduler-driven path uses). The old Reuters/AP URLs were dropped
# 2026-05-29 — both 404 now; the surviving wires below all return content.
DEFAULT_FEEDS: tuple[str, ...] = (
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "http://www.xinhuanet.com/english/rss/worldrss.xml",
    "https://www.scmp.com/rss/91/feed",
    "http://tass.com/rss/v2.xml",
    "https://www.channelnewsasia.com/rssfeeds/8395986",
    "https://www.japantimes.co.jp/feed/",
    "https://en.yna.co.kr/RSS/news.xml",
    "http://www.taipeitimes.com/xml/index.rss",
)

# Generic User-Agent. Defends against trivial fingerprinting; nothing
# conclusive against a determined upstream observer.
_HTTP_USER_AGENT = "Mozilla/5.0 (compatible; news-aggregator)"
_HTTP_TIMEOUT_SEC = 15


def fetch_feed(url: str) -> list[dict]:
    """Anonymous GET + minimal RSS/Atom parse. Returns one dict per item
    with keys: title, summary, link, published_unix.

    Defensive: any HTTP / parse failure returns []. The pipeline is
    designed to keep producing useful auto-labels even when a couple of
    upstream feeds are flaky or unreachable.
    """
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": _HTTP_USER_AGENT, "Accept": "*/*"},
        )
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SEC) as resp:
            body = resp.read()
    except Exception as e:  # noqa: BLE001
        log.warning("[rss_etl] fetch failed %s: %s", url, e)
        return []

    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        log.warning("[rss_etl] XML parse failed %s: %s", url, e)
        return []

    items: list[dict] = []
    # RSS 2.0
    for item in root.iter("item"):
        items.append({
            "title": (item.findtext("title") or "").strip(),
            "summary": (item.findtext("description") or "").strip(),
            "link": (item.findtext("link") or "").strip(),
            "published": (item.findtext("pubDate") or "").strip(),
        })
    # Atom — namespaces vary, scan loosely
    for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
        title = entry.find("{http://www.w3.org/2005/Atom}title")
        summary = entry.find("{http://www.w3.org/2005/Atom}summary")
        link_el = entry.find("{http://www.w3.org/2005/Atom}link")
        href = link_el.attrib.get("href", "") if link_el is not None else ""
        items.append({
            "title": (title.text or "").strip() if title is not None else "",
            "summary": (summary.text or "").strip() if summary is not None else "",
            "link": href,
            "published": "",
        })
    return items


def fetch_all(feeds: Iterable[str]) -> list[dict]:
    out: list[dict] = []
    for url in feeds:
        out.extend(fetch_feed(url))
    return out


def _participants_for(scenario_id: str) -> list[str]:
    sc = scenario_store.get(scenario_id)
    if sc is None:
        return []
    return sorted(sc.participants.keys())


def _llm_invoke():
    """Return a callable(prompt) → str, or None when no LLM is reachable.

    Probes radar.llm_client lazily so the runner can still load on a
    fresh checkout that lacks Ollama / the LLM client module.
    """
    try:
        from radar.llm_client import invoke as _invoke  # type: ignore
        return _invoke
    except Exception:  # noqa: BLE001
        return None


def _parse_published(item: dict, *, fallback: float) -> float:
    """Best-effort event timestamp for an RSS item.

    Uses the RFC-822 ``pubDate``/``published`` field when present; falls
    back to ``fallback`` (the scan's ``until`` bound ≈ now) when the feed
    omits or malforms it. The event time is what lets us ask *what was the
    tool saying around when this happened* — the basis of FALSE_NEGATIVE
    detection. A missing date degrades to "current news", which is the
    correct assumption for a live RSS pull.
    """
    raw = (item.get("published") or "").strip()
    if not raw:
        return fallback
    try:
        dt = parsedate_to_datetime(raw)
        if dt is None:
            return fallback
        return dt.timestamp()
    except (TypeError, ValueError, OverflowError):
        return fallback


def run_etl(
    db: RadarDB,
    *,
    feeds: Iterable[str],
    since: float,
    until: float,
    scenario_filter: Optional[str] = None,
    limit: int = 1000,
    dry_run: bool = False,
    use_llm: bool = False,
    window_hours: Optional[int] = None,
) -> dict:
    """Drive one RSS pass — TL-comparison ground-truth labeling.

    For each THREAT_LEVEL conclusion in the scan window, find external
    kinetic events (from the RSS feed) that landed in a participant country
    inside the conclusion's forward window, and compare the tool's threat
    level against the minimum level those events warranted
    (``expected_tl_floor``). Under-rating → FALSE_NEGATIVE (the NP1-critical
    miss); meeting/exceeding the floor → TRUE_POSITIVE.

    This replaces the previous blanket-TRUE_POSITIVE stamping, which labeled
    every country-matching conclusion of any type as a TP and pinned recall
    at 1.0 regardless of tool quality (audit 2026-05-29). RSS is the only
    high-volume *external* (sensor-independent) evidence stream, so it is the
    one source that can legitimately reveal the tool's blind spots.
    """
    items = fetch_all(feeds)
    if not items:
        log.warning("[rss_etl] all feeds empty / unreachable — no-op")
        return {"feeds_fetched": 0, "matched_items": 0, "persisted": 0}

    window_h = (
        window_hours if window_hours is not None
        else config.GROUND_TRUTH_WINDOW_HOURS
    )

    llm_invoke = _llm_invoke() if use_llm else None
    if use_llm and llm_invoke is None:
        log.info(
            "[rss_etl] --use-llm requested but radar.llm_client not loadable; "
            "falling back to regex baseline."
        )

    # THREAT_LEVEL only, newest-first: the RSS feed is current news, so only
    # recent conclusions (whose forward window overlaps those events) can be
    # labeled. Scanning newest-first keeps the limit budget on the rows that
    # can actually match, instead of the oldest diagnostic rows.
    conclusions = list_conclusions_in_window(
        db, since=since, until=until, limit=limit,
        conclusion_type=ConclusionType.THREAT_LEVEL.value,
        newest_first=True,
    )
    if scenario_filter:
        conclusions = [c for c in conclusions if c.scenario_id == scenario_filter]

    # Extract once per RSS item, carrying an event timestamp. De-dup by text
    # (many headlines repeat across feeds).
    matches: list[tuple] = []  # (KineticMatch, event_at)
    seen_summaries: set[str] = set()
    for item in items:
        text = (item.get("title", "") + " — " + item.get("summary", "")).strip()
        if not text or text in seen_summaries:
            continue
        seen_summaries.add(text)
        result = extract_kinetic(text, use_llm=use_llm, llm_invoke=llm_invoke)
        if result is not None:
            event_at = _parse_published(item, fallback=until)
            matches.append((result, event_at))

    counts = {
        "feeds_fetched": len(items),
        "matched_items": len(matches),
        "scanned": len(conclusions),
        "persisted": 0,
        "already_persisted": 0,
        "no_match": 0,
        "skipped_non_threat_level": 0,
        "skipped_non_numeric_tl": 0,
        "label_TRUE_POSITIVE": 0,
        "label_FALSE_NEGATIVE": 0,
        "dry_run_skipped_write": 0,
    }

    analyst_id = "auto:rss"
    now_ts = time.time()

    for c in conclusions:
        # Only THREAT_LEVEL conclusions carry a level we can score against an
        # external event. TREND / PER_DOMAIN / ATTACK_MODE are diagnostic
        # surfaces — labeling them inflated the ledger without feeding recall.
        if c.conclusion_type is not ConclusionType.THREAT_LEVEL:
            counts["skipped_non_threat_level"] += 1
            continue
        try:
            tool_tl = int(c.state or "")
        except (TypeError, ValueError):
            counts["skipped_non_numeric_tl"] += 1
            continue

        countries = _participants_for(c.scenario_id)
        if not countries:
            continue

        # Events that fell in a participant country inside this conclusion's
        # forward window [observed_at, observed_at + window_h]. The conclusion
        # is a pre-event assessment; an escalation it should have anticipated.
        forward_end = c.observed_at + window_h * 3600.0
        relevant = [
            m for (m, event_at) in matches
            if m.country in countries and c.observed_at <= event_at <= forward_end
        ]
        if not relevant:
            counts["no_match"] += 1
            continue

        # Worst event drives the expectation (NP1 — be sensitive to the most
        # severe thing the tool should have caught).
        floors = [
            expected_tl_floor(fatalities=m.fatalities, confidence=m.confidence)
            for m in relevant
        ]
        expected_floor = max(floors)
        worst = relevant[floors.index(expected_floor)]
        label = label_for_threat_level(
            tool_tl=tool_tl, expected_floor=expected_floor,
        )

        if has_existing_auto_feedback(db, c.id, analyst_id):
            counts["already_persisted"] += 1
            continue
        if dry_run:
            counts["dry_run_skipped_write"] += 1
            counts[f"label_{label.value}"] += 1
            continue
        save_feedback(db, AnalystFeedback(
            conclusion_id=c.id,
            label=label,
            analyst_id=analyst_id,
            observed_at=now_ts,
            observed_outcome_url=None,
            notes=(
                f"rss/{worst.source}: {worst.country} "
                f"fatalities={worst.fatalities} expected_TL>={expected_floor} "
                f"tool_TL={tool_tl} ({worst.summary[:90]})"
            ),
        ))
        counts["persisted"] += 1
        counts[f"label_{label.value}"] += 1

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", default=None, help="DB path")
    parser.add_argument("--since", type=float, default=None,
                        help="Earliest observed_at to scan (default: 14d ago)")
    parser.add_argument("--until", type=float, default=None,
                        help="Latest observed_at to scan (default: now)")
    parser.add_argument("--scenario", default=None)
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--feeds-file", default=None,
                        help="Override default feed list (one URL per line)")
    parser.add_argument("--use-llm", action="store_true",
                        help="Try LLM augmentation; falls back to regex if unavailable")
    parser.add_argument("--force", action="store_true",
                        help="Run even if V2_GROUND_TRUTH_ETL_ENABLED=false")
    args = parser.parse_args()

    if not config.V2_GROUND_TRUTH_ETL_ENABLED and not args.force:
        log.warning(
            "V2_GROUND_TRUTH_ETL_ENABLED is false; exiting (use --force to override)"
        )
        return 0

    if args.feeds_file:
        with open(args.feeds_file, "r", encoding="utf-8") as f:
            feeds = tuple(line.strip() for line in f if line.strip() and not line.startswith("#"))
    else:
        feeds = DEFAULT_FEEDS

    now = time.time()
    since = args.since if args.since is not None else now - 14 * 86400
    until = args.until if args.until is not None else now

    if args.db:
        os.environ["RADAR_DB_PATH"] = args.db
    db = RadarDB(os.environ.get("RADAR_DB_PATH", "radar/persistence/radar.db"))

    if not scenario_store.loaded:
        from radar.config import _raw_geo
        scenario_store.load(_raw_geo)

    summary = run_etl(
        db, feeds=feeds, since=since, until=until,
        scenario_filter=args.scenario, limit=args.limit,
        dry_run=args.dry_run, use_llm=args.use_llm,
    )
    log.info("RSS ETL summary: %s", summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
