"""`apt_intel` — S1-SENS-019..021, D1 §4 K09. Government CERT advisories.

Five feeds, and the ledger of which ones are alive is itself the asset.
K09: **CISA's advisory feed URL rots.** It moved to
`/cybersecurity-advisories/`, and CISA sits behind Akamai, which answers
403 to script user-agents — so the request carries a browser one, with
the Accept and Accept-Language headers legacy's note says are part of
what passes the check. Three other feeds were removed in the 2026-04
audit for good reasons worth not re-learning: ENISA retired its RSS, BSI
moved to WID, and ACSC geo-blocks non-Australian addresses.

**Everything transcribable in this module is pinned against the live
sensor**, which the suite parses with `ast` rather than trusting a copy.
That is not ceremony: the port shipped an invented discard ledger, four
invented feed URLs, a different platform's user-agent, a dedup key
missing its separator and its case, and a summary width of its own. Each
looked like a transcription and was not, and none of them would have
announced itself — they would have shown up as parity noise attributed
to something else.

DP9: the legacy sensor parsed with a strict XML parser only, and had no
liveness diagnosis — so a dead URL serving an HTML error page and a feed
that genuinely published nothing produced the same log line. Here parsing
goes through the ONE shared parser (`v3/fetch/parse.py`), which classifies
`returns_html` / `rss_empty` / `unparseable` separately. An adapter cannot
choose a parser, and that is the point (A-02: four copies of RSS parsing,
tolerant behaviour in exactly one of them).

**Scope boundary.** The legacy sensor also ran a two-stage LLM gate and
submitted intel items. O-17 rules that LLM extraction is ONE adapter in
v3 (`v3/adapters/llm/`, WP-2.7) rather than eight copies of a prompt, so
this adapter stops where the LLM begins: it fetches, classifies feed
liveness, selects candidate articles, and lands them as observations for
the extraction stage to pick up. The selection rules below are the
legacy ones, because they decide what the LLM ever sees.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from v3.adapters.types import (AdapterId, CYBER, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.fetch import parse
from v3.kernel import Window

APT_INTEL = AdapterId("apt_intel")

#: K09 — the moved CISA path, and the four feeds that survived the audit.
#: **Transcribed from `_CERT_SOURCES` (`radar/sensors/apt_intel.py:64-100`)
#: and pinned against it by a test that parses the live sensor.** The port
#: originally declared four URLs of its own, including the NCSC *report*
#: feed that legacy deliberately abandoned ("research papers, almost never
#: matched"). Fetching a different document makes every other fidelity
#: property of this adapter moot.
CISA_ADVISORIES_URL = (
    "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml")
FEEDS: tuple[tuple[str, str], ...] = (
    ("cisa_advisories", CISA_ADVISORIES_URL),
    ("cisa_alerts", "https://www.cisa.gov/cybersecurity-advisories/alerts.xml"),
    ("jpcert", "https://www.jpcert.or.jp/rss/jpcert.rdf"),
    ("ncsc_uk", "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"),
    ("cert_bund", "https://wid.cert-bund.de/content/public/buergercert/rss"),
)
#: v3 label -> the `_CERT_SOURCES` key. Legacy hashes the dict KEY, which
#: is UPPER_SNAKE, so the dedup key cannot be rebuilt from v3's label.
LEGACY_SOURCE_NAMES: dict = {
    "cisa_advisories": "CISA_ADVISORIES",
    "cisa_alerts": "CISA_ALERTS",
    "jpcert": "JPCERT",
    "ncsc_uk": "NCSC_UK",
    "cert_bund": "CERT_BUND",
}
#: `_BROWSER_HEADERS` (`radar/sensors/apt_intel.py:182-190`), transcribed
#: whole. CISA sits behind Akamai, and legacy's note is explicit that it
#: is the realistic desktop UA **together with** Accept and
#: Accept-Language that passes the check — so all three travel, and the
#: platform in the UA string is the one that is known to work.
_BROWSER_HEADERS: dict = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/121.0.0.0 Safari/537.36"),
    "Accept": "application/rss+xml, application/xml, text/xml, */*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ja;q=0.8,de;q=0.7",
}

#: 168 hours. The docstring in the legacy sensor says 72 and the code says
#: 168; the code is what ran.
ARTICLE_AGE_WINDOW_HOURS = 168
KEYWORD_ARTICLE_LIMIT = 5
COUNTRY_ARTICLE_LIMIT = 2
MAX_ARTICLES_PER_FEED = KEYWORD_ARTICLE_LIMIT + COUNTRY_ARTICLE_LIMIT
#: `summary[:500]` (`radar/sensors/apt_intel.py:292`). This is the text the
#: LLM stage prompts with, and `llm_call` records that prompt for
#: S5-VERIF-022 replay — so a wider slice silently changes both the
#: analysis and what parity replays against.
SUMMARY_CHARS = 500
#: A19: the legacy floor is a literal copy of `LLM_CONFIDENCE_MIN`'s
#: default rather than a read of it, so changing the setting moved only
#: one of them. Named once here.
CONFIDENCE_FLOOR = 0.35

#: The ONE `signal_source` every row of this family carries — the article
#: rows and the feed-liveness rows alike. Named rather than repeated
#: because `v3/runtime/reduce_cyber.py::_fold_apt_intel` folds on it, and a
#: literal in two modules is two chances for the fold to stop matching
#: what it folds.
SIGNAL_SOURCE = "apt_intel"

#: What the folded row is waiting for, in the row itself. `apt_intel` has
#: no `IntelProfile` (`v3/adapters/llm/extraction.py`) yet, so the selected
#: articles reach no model — and a row that carried candidates with nothing
#: saying why they are still candidates would read as a finished pipeline.
AWAITING = "llm_extraction (WP-2.7)"

#: Slot 1's ledger (`_ADVISORY_KEYWORDS`, legacy lines 106-134), matched
#: against title + summary. Transcribed rather than curated: the list is
#: multilingual on purpose (JPCERT titles are Japanese, CERT-Bund's are
#: German), and "blocked" / "prevented" / "stopped" are deliberately
#: ABSENT — those describe a resolved incident, not an active threat.
ADVISORY_KEYWORDS: tuple[str, ...] = (
    # advisory / warning language (government-style)
    "advisory", "alert", "warning", "actively exploiting",
    "active exploitation", "under active attack", "observed in the wild",
    "in the wild", "immediate action", "patch immediately",
    "emergency directive",
    # vulnerability / exploit language
    "vulnerability", "vulnerabilities", "cve-", "zero-day", "0-day",
    "remote code execution", "rce", "authentication bypass",
    "privilege escalation", "exploit", "exploited", "compromise",
    "intrusion", "backdoor", "ransomware",
    # Japanese advisory terms (JPCERT)
    "注意喚起", "脆弱性", "緊急",
    # German advisory terms (CERT-Bund)
    "schwachstelle", "schwachstellen", "sicherheitslücke", "kritisch",
    # named state actors
    "volt typhoon", "salt typhoon", "hafnium", "flax typhoon",
    "fancy bear", "cozy bear", "apt28", "apt29", "sandworm", "turla",
    "lazarus", "kimsuky", "andariel", "bluenoroff",
    "charming kitten", "muddy water", "apt35", "apt34",
    "apt41", "gothic panda", "bronze silhouette",
    "state-sponsored", "nation-state", "state actor",
    # sector targeting
    "critical infrastructure", "industrial control", "scada", "ics",
    "water treatment", "power grid", "energy sector", "defense contractor",
    "telecommunications", "financial sector",
    # pre-conflict TTP language
    "pre-positioning", "living off the land", "lotl",
    "persistence", "lateral movement", "command and control")

#: `_DISCARD_KEYWORDS` (legacy lines 140-144), matched against title +
#: summary. Multi-word on purpose: a bare "download" would eat CISA's own
#: "Download PDF" links. Transcribed, not rewritten — the port originally
#: shipped an invented list sharing five phrases with this one and
#: differing in nine, which is a hand-written sensitivity change.
DISCARD_KEYWORDS: tuple[str, ...] = (
    "we blocked", "we prevented", "we stopped", "our platform detected",
    "our product", "how we", "case study", "product update", "webinar",
    "whitepaper", "ebook", "free download", "register now", "join us")

#: `_NOISE_TITLE_PREFIXES` (legacy lines 152-154), matched with
#: `startswith` against the title alone. JPCERT's Weekly Report is a fixed
#: digest of consumer-software CVEs and never carries APT attribution.
NOISE_TITLE_PREFIXES: tuple[str, ...] = ("weekly report",)

#: `_CERT_SOURCES[*]["authority"]`. Legacy puts this in BOTH LLM prompts
#: ("Advisory source: {authority}", legacy lines 396 and 474) and in the
#: submitted intel item (line 583), so it is load-bearing for WP-2.7 and
#: exists nowhere else — it has to travel with the article.
#:
#: `_CERT_SOURCES[*]["region"]` is deliberately NOT ported: nothing reads
#: it in the live sensor. Same disposition as `gov_count` (A18) — a field
#: that outlived its concept is not carried forward silently.
FEED_AUTHORITIES: dict = {
    "cisa_advisories": "CISA (US)",
    "cisa_alerts": "CISA (US)",
    "jpcert": "JPCERT/CC (JP)",
    "ncsc_uk": "NCSC (UK)",
    "cert_bund": "CERT-Bund (DE)",
}

#: `_CERT_SOURCES[*]["theater_hints"]` (legacy lines 64-100). Slot 2 only
#: opens for a country this feed plausibly covers, intersected with the
#: scenario's countries — CISA does not get a German seat.
FEED_THEATER_HINTS: dict = {
    "cisa_advisories": ("US", "UA", "TW", "JP", "KR", "AU"),
    "cisa_alerts": ("US", "UA", "TW", "JP", "KR", "AU"),
    "jpcert": ("JP", "TW", "KR", "KP"),
    "ncsc_uk": ("GB", "UA", "IL", "IR"),
    "cert_bund": ("DE", "UA", "PL"),
}

_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)
_FRESHNESS_HORIZON_SEC = 24 * 3600.0


def dedup_key(source_name: str, title: str) -> str:
    """`md5(f"cert-{SOURCE}-{title[:60]}")` — legacy's key, exactly.

    Kept identical because the deduplication set moves to L1 (B-05: it was
    process-local, so a restart re-submitted everything it had already
    seen). A different key would make the migrated history useless — and
    two things make it different if they are not watched. The separator
    (`_article_hash`, `radar/sensors/apt_intel.py:173-175`) and the CASE:
    legacy passes the `_CERT_SOURCES` dict key, which is `CISA_ADVISORIES`,
    not this adapter's `cisa_advisories` label. Both are restored here;
    the port had neither, so every migrated row would have been
    unmatchable by the very key that exists to match them.
    """
    legacy_name = LEGACY_SOURCE_NAMES.get(source_name, source_name)
    seed = f"cert-{legacy_name}-{str(title or '')[:60]}"
    return hashlib.md5(seed.encode("utf-8"),
                       usedforsecurity=False).hexdigest()


def is_discarded(text: str) -> bool:
    """Marketing or resolved-incident copy. Reads title AND summary.

    Legacy builds `text_lower = (title + " " + summary).lower()` once
    (`radar/sensors/apt_intel.py:281`) and tests the discard ledger
    against it (`:285`). Testing the title alone lets a description full
    of marketing copy through, which is how the port widened the set.
    """
    lowered = str(text or "").lower()
    return any(phrase in lowered for phrase in DISCARD_KEYWORDS)


def is_noise_title(title: str) -> bool:
    """A routine digest, recognised by its title prefix (`:289`)."""
    lowered = str(title or "").strip().lower()
    return any(lowered.startswith(prefix) for prefix in NOISE_TITLE_PREFIXES)


def is_advisory(text: str) -> bool:
    """Slot 1's test: advisory language anywhere in title + summary."""
    lowered = str(text or "").lower()
    return any(keyword in lowered for keyword in ADVISORY_KEYWORDS)


def theater_names(feed: str, context: NormalizeContext) -> tuple[str, ...]:
    """Lower-cased names of the countries slot 2 may match on.

    Legacy narrows twice: the feed's own `theater_hints` intersected with
    the scenario's countries (`:344-345`), then resolved to names through
    the geographic ledger (`:162-170`, dropping codes that have no name).
    Both narrowings are kept. The names arrive through
    `NormalizeContext.country_names` because nothing under `v3/` reads
    configuration — the composition root supplies the ledger.
    """
    hints = FEED_THEATER_HINTS.get(feed, ())
    scope = context.countries
    resolved = []
    for code in hints:
        if scope and code not in scope:
            continue
        name = str(context.country_names.get(code, "")).strip().lower()
        if name:
            resolved.append(name)
    return tuple(resolved)


def normalize_title(title: str) -> str:
    """Lower-cased alphanumerics of the first 60 characters."""
    return "".join(character for character in str(title or "")[:60].lower()
                   if character.isalnum())


def published_timestamp(published_raw: str) -> float:
    """RFC822 first, ISO-8601 second, `0.0` when neither parses.

    Both dialects appear across the five feeds: `pubDate` is RFC822 and
    JPCERT's RDF carries an ISO-8601 `dc:date`, which is why legacy tries
    them in this order (`radar/sensors/apt_intel.py:266-276`) and why the
    order is kept.

    A naive timestamp is read as UTC. Legacy calls `.timestamp()` on it,
    which reads it in the host's local zone — so the same recorded feed
    dated differently depending on where the process ran. Normalization of
    a recorded payload has to reproduce exactly (that is what makes the
    fixture suite and parity replay mean anything), so the zone is pinned
    rather than inherited. Feeds emitting a zone — which is all five in
    practice — are unaffected.

    **Ruled (2026-08-07)**: keep the pinned zone. Reproducibility across
    hosts outranks bug-compatibility with a host-local read; the exposure
    is a window-edge shift for a feed that stops emitting a zone, none
    currently do, and it is deliberately below the §7-2 registration bar.
    """
    text = str(published_raw or "").strip()
    if not text:
        return 0.0
    moment = None
    try:
        moment = parsedate_to_datetime(text)              # RFC822
    except (TypeError, ValueError, OverflowError):
        try:
            moment = datetime.fromisoformat(              # ISO-8601
                text.replace("Z", "+00:00"))
        except (TypeError, ValueError, OverflowError):
            return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def is_within_age_window(published_raw: str, now: float,
                         window_hours: int = ARTICLE_AGE_WINDOW_HOURS) -> bool:
    """Legacy's `not (pub_ts > 0 and pub_ts < cutoff)`.

    An article nobody can date is KEPT. Dropping it would make an
    eccentric date format indistinguishable from a quiet authority, which
    is the same class of blindness DP9 records for the parser — and NP1
    prefers a stale candidate to a dropped one.

    The boundary is inclusive: an article landing exactly on the cutoff
    survives, because the comparison is strict.
    """
    stamp = published_timestamp(published_raw)
    if stamp <= 0.0:
        return True
    return stamp >= now - window_hours * 3600.0


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One CERT feed -> candidate articles, plus its liveness verdict.

    A feed that returns HTML or nothing produces a NO_DATA observation
    naming the cause. That is DP9's repair: the difference between "this
    URL is dead" and "this authority published nothing today" is the
    difference between a broken sensor and a quiet week.

    Selection is legacy's, in legacy's order, because it decides what the
    LLM stage ever sees (`radar/sensors/apt_intel.py:248-308`):

      1. the title key enters the dedup set FIRST, before any filter, so
         a stale or promotional item consumes the slot and a later item
         carrying the same title stays suppressed (`:259-263`). An item
         whose title normalizes to nothing is not deduped and not
         skipped — it still reaches the ledgers on its summary.
      2. the age window, against `context.now` (`:278`)
      3. the discard ledger and the noise-title prefixes (`:285`, `:289`)
      4. **slot 1** — up to five items matching `ADVISORY_KEYWORDS`. The
         branch `continue`s whether or not slot 1 had room, so a sixth
         advisory is dropped rather than demoted into slot 2 (`:294-298`)
      5. **slot 2** — up to two items that match no advisory keyword but
         name a country this feed covers (`:300-303`)
      6. the loop stops only when BOTH slots are full (`:305-306`), and
         the result is `slot 1 + slot 2`, not feed order (`:308`)

    An item matching neither ledger is EXCLUDED. Taking the first seven
    survivors instead — which is what the port originally did — is a
    strictly wider candidate set, and a wider set is both an unregistered
    sensitivity difference and a larger bill at the LLM stage.

    The stored summary is `SUMMARY_CHARS` wide, legacy's 500 (`:292`).
    """
    result = parse.parse_feed(payload.body, http_status=payload.status,
                              content_type=payload.content_type)
    source_name = payload.label or "cert"
    if not result.is_alive:
        return (ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=CYBER, country="",
            status=STATUS_NO_DATA, raw_score=0.0,
            value=f"{source_name}: {result.outcome}",
            flags={"feed": source_name, "outcome": result.outcome,
                   "detail": result.detail, "parse_stage": result.stage},
            evidence_url=payload.url),)

    keyword_articles: list[dict] = []
    country_articles: list[dict] = []
    seen: set[str] = set()
    names = theater_names(source_name, context)
    for item in result.items:
        key = normalize_title(item.title)
        if key and key in seen:
            continue
        if key:
            seen.add(key)                 # entered BEFORE every filter
        if not is_within_age_window(item.published_raw, context.now):
            continue                      # older than the window; slot spent
        text = f"{item.title} {item.summary}"
        if is_discarded(text) or is_noise_title(item.title):
            continue
        article = {"title": item.title, "link": item.link,
                   "summary": item.summary[:SUMMARY_CHARS],
                   "published": item.published_raw,
                   "authority": FEED_AUTHORITIES.get(source_name, ""),
                   "dedup_key": dedup_key(source_name, item.title)}
        if is_advisory(text):
            if len(keyword_articles) < KEYWORD_ARTICLE_LIMIT:
                keyword_articles.append(article)
            continue                      # never demoted into slot 2
        if names and any(name in text.lower() for name in names):
            if len(country_articles) < COUNTRY_ARTICLE_LIMIT:
                country_articles.append(article)
        if (len(keyword_articles) >= KEYWORD_ARTICLE_LIMIT
                and len(country_articles) >= COUNTRY_ARTICLE_LIMIT):
            break
    selected = keyword_articles + country_articles

    return tuple(
        ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=CYBER, country="",
            # Not FIRED: an advisory becomes a signal only after the LLM
            # stage attributes it (WP-2.7). Landing it as OBSERVED keeps
            # the article in the ledger with its provenance intact.
            #
            # These rows are PER ARTICLE and they all share this one
            # `signal_source` and no country, so they collide on L1's
            # `UNIQUE (tick_id, sensor, signal_source, country)`. They are
            # folded to the single row production has by
            # `v3/runtime/reduce_cyber.py::_fold_apt_intel` (§7-2 #137);
            # `article` is the key that fold groups on, so it stays a whole
            # dict rather than being flattened into sibling flags.
            status=STATUS_OBSERVED, raw_score=0.0,
            value=article["title"][:200],
            flags={"feed": source_name, "article": {**article,
                                                    "feed": source_name},
                   "awaiting": AWAITING,
                   "confidence_floor": CONFIDENCE_FLOOR},
            evidence_url=article["link"] or payload.url)
        for article in selected)


APT_INTEL_ADAPTER = SourceAdapter(
    adapter_id=APT_INTEL, category=CYBER,
    requests=tuple(
        RequestSpec(url=url, expect_content="xml",
                    headers=_BROWSER_HEADERS, label=name)
        for name, url in FEEDS),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="cert_rss", knowledge_refs=("K09",),
    baseline_refs=("apt_intel_dedup",))

__all__ = ["APT_INTEL", "APT_INTEL_ADAPTER", "normalize", "dedup_key",
           "SIGNAL_SOURCE", "AWAITING",
           "is_discarded", "is_noise_title", "is_advisory", "theater_names",
           "normalize_title", "published_timestamp",
           "is_within_age_window", "FEEDS",
           "CISA_ADVISORIES_URL", "ARTICLE_AGE_WINDOW_HOURS",
           "KEYWORD_ARTICLE_LIMIT", "COUNTRY_ARTICLE_LIMIT",
           "MAX_ARTICLES_PER_FEED", "SUMMARY_CHARS", "CONFIDENCE_FLOOR",
           "ADVISORY_KEYWORDS", "DISCARD_KEYWORDS", "NOISE_TITLE_PREFIXES",
           "FEED_THEATER_HINTS", "FEED_AUTHORITIES", "LEGACY_SOURCE_NAMES"]
