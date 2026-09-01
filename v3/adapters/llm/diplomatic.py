"""`diplomatic` — S1-SENSI-032/034 + INGEST-*, D1 §4 K07/K08.

Official-statement coverage for eleven country/organisation slots. §3-3
records that this sensor has no defect of its own and is instead the
EXTRACTION SOURCE for the shared tolerant parser (§1-7): production's
`_parse_xml_tolerant` and `_classify_feed` live only here, which is why
the same malformed feed parses or does not depending on which sensor
happened to fetch it. In v3 the parser is `v3/fetch/parse.py`, once, and
an adapter cannot choose one (§2-2 barrier 2).

**K07 — the liveness ledger is the asset, and it exists only as a
comment.** Seven primary MFA/NATO endpoints have been retired or moved,
each with its own cause, and the replacement strategy is a Google News
boolean query per country. D1 calls this the most expensive knowledge in
the system to rediscover, because every entry was learned from a feed
failing in production. `FEED_POST_MORTEM` below turns the comment into
data a test can pin — a comment that stops being true stays green.

**K08 — five ways for a feed to be dead, and `unknown` is not one of
them.** `_classify_feed` (`diplomatic.py:225-259`) returns
`rss_with_items` / `rss_empty` / `returns_html` / `unparseable` /
`unknown`. The shared parser keeps the first four and replaces the
catch-all with `http_error`, `geo_block` and `entity_attack`, because
`unknown` is where a cause goes to stop being investigated (§7-2 #49).

**Slot 3 is the interesting one.** When the keyword and theatre slots are
both empty, production sends the MOST RECENT article anyway
(`:336-341`), so a feed whose statements are all in Japanese still
reaches the model. Dropping that fallback while porting would be a silent
recall loss on exactly the non-English sources the sensor exists to read.
"""
from __future__ import annotations

import hashlib
from email.utils import parsedate_to_datetime

from v3.adapters.llm import extraction as ex
from v3.adapters.types import (AdapterId, INFO, LLM, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.fetch import parse
from v3.kernel import Window

DIPLOMATIC = AdapterId("diplomatic")

#: `_GNEWS_BASE` (`radar/sensors/diplomatic.py:66`). The query is
#: percent-encoded in the source and stays that way: re-encoding it here
#: would double-escape the `+` separators and return a different corpus.
GNEWS_BASE = ("https://news.google.com/rss/search?q={q}&hl=en&gl=US&"
              "ceid=US:en")

#: `_DIPLOMATIC_SOURCES` (`:68-135`), transcribed and pinned. `country` is
#: the ISSUER (it lands in `llm_fields.source_country`) and `theaters` is
#: the closed set the model must choose from — an answer outside it is
#: discarded (`:495`), so both halves decide what the system can conclude.
DIPLOMATIC_SOURCES: dict = {
    "US_STATE": {
        "url": GNEWS_BASE.format(
            q='site:state.gov+OR+%22State+Department%22+press'),
        "country": "US",
        "theaters": ["TW", "UA", "KP", "IR", "IL", "JP", "PH"],
    },
    "JP_MOFA": {
        "url": GNEWS_BASE.format(q='Japan+foreign+minister'),
        "country": "JP",
        "theaters": ["TW", "JP", "KP", "CN"],
    },
    "CN_MFA": {
        "url": GNEWS_BASE.format(q='China+foreign+ministry+spokesperson'),
        "country": "CN",
        "theaters": ["TW", "JP", "PH", "IN"],
    },
    "TW_MOFA": {
        "url": GNEWS_BASE.format(q='Taiwan+MOFA+statement'),
        "country": "TW",
        "theaters": ["TW"],
    },
    "RU_MFA_TASS": {
        "url": "https://tass.com/rss/v2.xml",
        "country": "RU",
        "theaters": ["UA", "IR", "IL", "SY", "KP"],
    },
    "RU_MFA_GNEWS": {
        "url": GNEWS_BASE.format(q='Russia+MFA+Lavrov+foreign+ministry'),
        "country": "RU",
        "theaters": ["UA", "IR", "IL", "SY", "KP"],
    },
    "KCNA_WATCH": {
        "url": "https://kcnawatch.org/feed/",
        "country": "KP",
        "theaters": ["KP", "JP"],
    },
    "NK_NEWS": {
        "url": "https://www.nknews.org/feed/",
        "country": "KP",
        "theaters": ["KP", "JP", "KR"],
    },
    "NATO": {
        "url": GNEWS_BASE.format(q='NATO+Secretary+General+statement'),
        "country": "NATO",
        "theaters": ["UA"],
    },
    "IL_MFA": {
        "url": GNEWS_BASE.format(q='Israel+foreign+ministry+statement'),
        "country": "IL",
        "theaters": ["IL", "IR", "LB", "SY"],
    },
    "IR_MFA": {
        "url": GNEWS_BASE.format(q='Iran+foreign+ministry'),
        "country": "IR",
        "theaters": ["IR", "IL", "SY", "LB"],
    },
}

#: **K07.** The 2026-04-29 audit, as data. In production this survives
#: only as a comment block (`:38-65`) — which is precisely D1's complaint:
#: knowledge that lives in a comment stops being true without anything
#: failing. Each entry is `original endpoint -> cause`, and the causes are
#: the same vocabulary the shared parser reports.
FEED_POST_MORTEM: dict = {
    "US_STATE": ("state.gov/press-releases/feed/", parse.RETURNS_HTML,
                 "URL stale"),
    "JP_MOFA": ("mofa.go.jp/rss/rss.xml", parse.HTTP_ERROR,
                "404 / WAF against a datacentre IP"),
    "CN_MFA": ("fmprc.gov.cn/mfa_eng/rss.xml", parse.RETURNS_HTML,
               "RSS discontinued"),
    "TW_MOFA": ("en.mofa.gov.tw/rss.aspx", parse.RETURNS_HTML,
                "SPA migration"),
    "RU_MFA": ("mid.ru/en/rss.xml", parse.RETURNS_HTML,
               "broken / geo-blocked"),
    "KCNA_WATCH": ("kcnawatch.org/feed/", parse.RSS_EMPTY, "intermittent"),
    "NATO": ("nato.int/cps/en/natolive/news_rss", parse.HTTP_ERROR,
             "404, RSS discontinued"),
}

#: `_ESC_KEYWORDS` (`:138-147`), whole and in order. The last six are
#: transliterated place names, present because the escalation vocabulary
#: alone misses statements that name only a geography.
ESC_KEYWORDS: tuple[str, ...] = (
    "military", "warning", "condemn", "sanction", "expel", "recall",
    "sovereignty", "incursion", "invasion", "threat", "provocation",
    "mobilize", "deploy", "exercise", "posture", "ultimatum", "ceasefire",
    "missile", "nuclear", "blockade", "strait", "escalat", "conflict",
    "aggression", "violation", "retaliat",
    "taiwan strait", "south china sea", "senkaku", "diaoyu",
    "korean peninsula", "indo-pacific",
)

#: `_BROWSER_HEADERS` (`:161-169`), all three. The note in `apt_intel`
#: applies here too: it is the realistic desktop UA TOGETHER WITH Accept
#: and Accept-Language that passes the checks these hosts run.
BROWSER_HEADERS: dict = {
    "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/126.0.0.0 Safari/537.36"),
    "Accept": "application/rss+xml, application/xml, text/xml, */*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ja;q=0.8",
}

#: `_parse_articles(max_age_h=48)` (`:262`). The docstring one line above
#: says 24h and the default says 48; the DEFAULT is what runs, and no
#: caller overrides it (`:389`).
ARTICLE_AGE_WINDOW_HOURS = 48
KEYWORD_ARTICLE_LIMIT = 5
THEATER_ARTICLE_LIMIT = 2
SUMMARY_CHARS = 400
TITLE_SANITIZE_CHARS = 120

#: `super().__init__("diplomatic", "info", _POLL_INTERVAL)` (`:348`),
#: `_POLL_INTERVAL` = 3600 (`:33`). Sensor and item share the domain here,
#: unlike `military_exercise`.
SENSOR_DOMAIN = INFO
ITEM_DOMAIN = INFO
_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)
_FRESHNESS_HORIZON_SEC = 24 * 3600.0

SIGNAL_SOURCE = "diplomatic"
SOURCE_TYPE = "diplomatic"
#: `max_tokens=256` (`:469`).
MAX_TOKENS = 256

#: S1-SENSI-034: the four-way urgency map (`:526`), with `low` as
#: `safe_enum`'s default (`:525`).
URGENCY_SCORE: dict = {"critical": 3.0, "high": 2.0, "medium": 1.5,
                       "low": 1.0}
URGENCY_DEFAULT = "low"
#: `min(confidence, 0.45)` (`:518`) — NOT military_exercise's 0.50.
INDIRECT_CAP = 0.45


def dedup_key(source_name: str, title: str) -> str:
    """`_article_hash` (`:155-158`) — md5 of `dipl-{source}-{title[:60]}`.

    The prefix differs from `military_exercise`'s `mil-`, so the two
    sensors can process the same syndicated article independently. Using
    one prefix for both would silently suppress the second.
    """
    raw = f"dipl-{source_name}-{str(title or '')[:60]}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


def normalize_title(title: str) -> str:
    """`title.lower()[:60]` keeping alphanumerics (`:296`)."""
    return "".join(character for character in str(title or "")[:60].lower()
                   if character.isalnum())


def published_timestamp(published_raw: str) -> float:
    """`parsedate_to_datetime(pubdate).timestamp()`, 0.0 on failure (`:304-308`)."""
    text = str(published_raw or "").strip()
    if not text:
        return 0.0
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    if moment is None:
        return 0.0
    if moment.tzinfo is None:
        from datetime import timezone
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def is_within_age_window(published_raw: str, now: float,
                         window_hours: int = ARTICLE_AGE_WINDOW_HOURS) -> bool:
    """`not (pub_ts > 0 and pub_ts < cutoff)` (`:311-312`)."""
    stamp = published_timestamp(published_raw)
    if stamp <= 0.0:
        return True
    return stamp >= now - window_hours * 3600.0


def feed_theaters(source_name: str, context: NormalizeContext) -> tuple:
    """This feed's theatres narrowed to the participant union (`:377`).

    An empty union means no narrowing at all; a feed left with no theatre
    is not fetched (`:378-379`).
    """
    declared = tuple(DIPLOMATIC_SOURCES.get(source_name, {}).get(
        "theaters", ()))
    scope = tuple(context.countries)
    if not scope:
        return declared
    return tuple(code for code in declared if code in scope)


def theater_names(source_name: str, context: NormalizeContext) -> tuple:
    """`COUNTRY_COORDS[code]["name"].lower()` per theatre (`:188-196`)."""
    names = []
    for code in feed_theaters(source_name, context):
        name = str(context.country_names.get(code, "")).strip().lower()
        if name:
            names.append(name)
    return tuple(names)


def matches_keyword(text: str) -> bool:
    """`any(kw in text_lower for kw in _ESC_KEYWORDS)` (`:322`).

    Note the keywords are already lower case in the ledger and the text is
    lowered by the caller — production does NOT lower the keywords here
    (unlike `military_exercise`, which does). Same result, and the
    difference is recorded so a later reader does not "fix" one of them.
    """
    lowered = str(text or "").lower()
    return any(keyword in lowered for keyword in ESC_KEYWORDS)


def _candidate(item, source_name: str, theaters: tuple, country: str) -> dict:
    return {"title": item.title,
            "summary": item.summary[:SUMMARY_CHARS],
            "link": item.link,
            "published": item.published_raw,
            "country": country,
            "theaters": list(theaters),
            "dedup_key": dedup_key(source_name, item.title)}


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One diplomatic feed -> its candidates, or its cause of death.

    Selection is production's three slots (`:284-341`):

      1. the normalised title enters the dedup set BEFORE any filter
      2. the 48h age window
      3. the most-recent article is tracked for slot 3 REGARDLESS of
         whether it matches anything, and the comparison is strict `>`
         so the FIRST article wins a tie (which every undated feed is,
         since an unparseable date is 0.0)
      4. **slot 1** — up to five escalation-keyword matches; the branch
         `continue`s whether or not slot 1 had room
      5. **slot 2** — up to two articles naming a theatre but no keyword
      6. **slot 3** — if slots 1 and 2 are BOTH empty, the most-recent
         article with a title is sent anyway. This is what keeps a
         non-English feed from being invisible, and dropping it would be
         a silent recall loss on the sources the sensor exists to read
    """
    result = parse.parse_feed(payload.body, http_status=payload.status,
                              content_type=payload.content_type)
    source_name = payload.label or "diplomatic"
    if not result.is_alive:
        # K08's repair. Production reaches five reasons here — and one of
        # them is `unknown`, which is where a cause goes to stop being
        # investigated. The shared parser names `http_error` and
        # `geo_block` instead (§7-2 #49).
        return (ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=SENSOR_DOMAIN, country="",
            status=STATUS_NO_DATA, raw_score=0.0,
            value=f"{source_name}: {result.outcome}",
            flags={"feed": source_name, "outcome": result.outcome,
                   "detail": result.detail, "parse_stage": result.stage,
                   "post_mortem": list(FEED_POST_MORTEM.get(source_name, ()))},
            evidence_url=payload.url),)

    theaters = feed_theaters(source_name, context)
    if not theaters:
        return ()

    names = theater_names(source_name, context)
    country = str(DIPLOMATIC_SOURCES.get(source_name, {}).get("country", ""))
    keyword_articles: list = []
    theater_articles: list = []
    fallback = None
    fallback_stamp = None
    seen: set = set()
    for item in result.items:
        key = normalize_title(item.title)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        if not is_within_age_window(item.published_raw, context.now):
            continue
        article = _candidate(item, source_name, theaters, country)
        stamp = published_timestamp(item.published_raw)
        if fallback is None or stamp > fallback_stamp:
            fallback, fallback_stamp = article, stamp
        text_lower = f"{item.title} {item.summary}".lower()
        if matches_keyword(text_lower):
            if len(keyword_articles) < KEYWORD_ARTICLE_LIMIT:
                keyword_articles.append(article)
            continue
        if names and any(name in text_lower for name in names):
            if len(theater_articles) < THEATER_ARTICLE_LIMIT:
                theater_articles.append(article)
        if (len(keyword_articles) >= KEYWORD_ARTICLE_LIMIT
                and len(theater_articles) >= THEATER_ARTICLE_LIMIT):
            break

    selected = keyword_articles + theater_articles
    slot = "keyword_or_theater"
    if not selected and fallback and fallback["title"]:
        selected = [fallback]
        slot = "most_recent_fallback"

    return tuple(
        ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=SENSOR_DOMAIN, country="",
            status=STATUS_OBSERVED, raw_score=0.0,
            value=article["title"][:200],
            flags={"feed": source_name, "article": article,
                   "selection_slot": slot,
                   "awaiting": "llm_extraction",
                   "item_domain": ITEM_DOMAIN},
            evidence_url=article["link"] or payload.url)
        for article in selected)


# ── the LLM half ─────────────────────────────────────────────────────────

def prefilter(article) -> bool:
    """Slot 1. Selection already happened in `normalize`; a call on an
    article with no text cannot answer anything and still costs."""
    return bool(str(article.get("title") or "").strip()
                or str(article.get("summary") or "").strip())


def prompt(article, context) -> tuple[str, str]:
    """Slot 2. `diplomatic.py:429-466`, transcribed.

    The BIAS CHECK block carries the concrete example that makes it
    work — "EU sanctions on Russia is 'direct' for UA, but 'none' for
    TW" — and removing the example is how a general instruction stops
    being followed.
    """
    theaters = ", ".join(context.get("theaters") or ())
    system = (
        "You are a diplomatic intelligence analyst. "
        "Analyze this official government statement for escalation signals "
        f"relevant to any of these theaters: {theaters}. "
        "Respond ONLY with a JSON object, no explanation.")
    user = (
        f"Today's date: {context.get('today', '')}\n"
        f"Source: {context.get('country', '')} official diplomatic "
        f"statements\n"
        f"Relevant theaters: {theaters}\n\n"
        f"Statement:\n"
        f"{ex.sanitize(article.get('title', ''), TITLE_SANITIZE_CHARS)}\n"
        f"{ex.sanitize(article.get('summary', ''), SUMMARY_CHARS)}\n\n"
        "Return a JSON object:\n"
        "{\n"
        '  "headline": "One-sentence escalation summary (max 100 chars)",\n'
        '  "escalation_signal": true or false,\n'
        '  "geographic_focus": "What country or region does this statement '
        'specifically address?",\n'
        '  "theater": "Theater code from the list above, or null",\n'
        '  "countries": ["ISO codes of ALL countries explicitly addressed"],\n'
        '  "country_weights": {"ISO": 0.0-1.0 relevance weight per country},\n'
        '  "theater_link": "direct|indirect|none — does the statement '
        'specifically address this theater?",\n'
        '  "diplomatic_action": "warning|condemnation|sanction|expulsion|'
        'military_posture|ceasefire|statement|none",\n'
        '  "target_country": "Country being addressed or criticized",\n'
        '  "urgency": "critical|high|medium|low",\n'
        '  "confidence": 0.0\n'
        "}\n"
        "BIAS CHECK — before assigning theater, ask yourself:\n"
        "- Does the statement EXPLICITLY name or address the theater "
        "country/region?\n"
        "- Or am I inferring a connection because the issuing country is an "
        "adversary?\n"
        "- A statement about EU sanctions on Russia is 'direct' for UA, but "
        "'none' for TW.\n"
        "Set theater_link='direct' ONLY when the statement explicitly "
        "addresses the theater.\n"
        "Set theater_link='indirect' for strategic inference only — "
        "confidence will be reduced.\n"
        "Set theater=null and theater_link='none' if no specific theater is "
        "addressed.\n\n"
        "Confidence guide:\n"
        "- 0.80-0.95: Explicit military warning, sanction announcement, or "
        "expulsion\n"
        "- 0.65-0.79: Strong condemnation or direct posturing language\n"
        "- 0.40-0.64: Relevant but ambiguous diplomatic language\n"
        "- <0.40: Routine statement, no escalation signal — set "
        "escalation_signal=false, theater=null")
    return system, user


def score_delta(data) -> float:
    """Slot 3. S1-SENSI-034 — the four-way urgency map (`:525-526`).

    Not additive, unlike `military_exercise`: a diplomatic item's score
    is its urgency and nothing else. An unrecognised urgency scores as
    `low` rather than dropping the item.
    """
    urgency = str(data.get("urgency") or "").strip().lower()
    if urgency not in URGENCY_SCORE:
        urgency = URGENCY_DEFAULT
    return URGENCY_SCORE[urgency]


def headline_fallback(source_name: str, theater: str) -> str:
    """`f"Diplomatic escalation signal: {source} / {theater}"` (`:539`).

    Used only when the model omitted `headline` entirely — an empty
    string it chose deliberately is kept as an empty string.
    """
    return f"Diplomatic escalation signal: {source_name} / {theater}"


#: S1-INGEST-017's rows only. Unlike `military_exercise`, this source has
#: no event-type gate — `diplomatic_action` is carried through as a field
#: and never used to drop or cap (`:543`).
DISPOSITIONS: tuple = ex.relevance_rules(indirect_cap=INDIRECT_CAP)

PROFILE = ex.IntelProfile(
    source_type=SOURCE_TYPE,
    prefilter=prefilter, prompt=prompt, score_delta=score_delta,
    domain=ITEM_DOMAIN,
    dispositions=DISPOSITIONS,
    llm_field_keys=("diplomatic_action", "target_country", "urgency",
                    "source_country", "geographic_focus", "theater_link",
                    "escalation_signal"),
    max_tokens=MAX_TOKENS,
    schema_keys=("headline", "escalation_signal", "geographic_focus",
                 "theater", "countries", "country_weights", "theater_link",
                 "diplomatic_action", "target_country", "urgency",
                 "confidence"))


DIPLOMATIC_ADAPTER = SourceAdapter(
    adapter_id=DIPLOMATIC, category=LLM,
    requests=tuple(
        RequestSpec(url=meta["url"], expect_content="xml",
                    headers=BROWSER_HEADERS, label=name)
        for name, meta in DIPLOMATIC_SOURCES.items()),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="diplomatic_rss",
    knowledge_refs=("K07", "K08"),
    baseline_refs=("diplomatic_dedup",))

__all__ = ["DIPLOMATIC", "DIPLOMATIC_ADAPTER", "PROFILE", "normalize",
           "prefilter", "prompt", "score_delta", "headline_fallback",
           "dedup_key", "normalize_title", "published_timestamp",
           "is_within_age_window", "feed_theaters", "theater_names",
           "matches_keyword", "DIPLOMATIC_SOURCES", "FEED_POST_MORTEM",
           "ESC_KEYWORDS", "BROWSER_HEADERS", "GNEWS_BASE",
           "ARTICLE_AGE_WINDOW_HOURS", "KEYWORD_ARTICLE_LIMIT",
           "THEATER_ARTICLE_LIMIT", "SUMMARY_CHARS", "SIGNAL_SOURCE",
           "SOURCE_TYPE", "MAX_TOKENS", "URGENCY_SCORE", "INDIRECT_CAP",
           "DISPOSITIONS", "SENSOR_DOMAIN", "ITEM_DOMAIN"]
