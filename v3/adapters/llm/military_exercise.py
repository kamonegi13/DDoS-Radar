"""`military_exercise` — S1-SENSI-035..037 + INGEST-*. Defence wires.

Seven defence RSS feeds, each covering a declared set of theatres, read
for exercise and deployment posture. The adapter half ends where the
model begins (§4-1, and the shape `apt_intel` already ships): it fetches,
classifies feed liveness, selects the candidate articles the model will
ever see, and lands them as observations. `PROFILE` is this source's four
behavioural slots plus its declared dispositions; the extraction half is
`v3/adapters/llm/extraction.py`, once, for all of them.

**A6 — the domain is `physical`, and that is a top-of-ladder gate.**
S1-SENSI-037 fixes an RSS-derived, model-judged item into the physical
domain, and S1-SCORE-004's TL1 gate has a `physical >= 3.0` floor. A
wire story the model rated `critical` + `strategic` scores 3.0 exactly
(2.5 + 0.5), so ONE such item reaches the floor that opens the highest
threat level. §3-3 rules the current behaviour is kept and the question
is deferred past cutover (ADR-V3-004's posture); it is stated here rather
than left for someone to rediscover from a TL1 they cannot explain.

**S1-SENSI-035 as data, not as a branch.** The event-type gate — drop
`none`, keep `status_report` / `historical_analysis` at a capped
confidence — is the reason the disposition table exists (裁定要求 10).
Production writes it as two `if`s inside the sensor
(`military_exercise.py:343-349`); here it is two rows the shared
extraction evaluates. Keeping the cap rather than dropping is deliberate
and NP1's: a weekly fleet tracker is never auto-confirmed, but it stays
in front of an analyst.

**The candidate selection IS the sensor.** Two slots, five plus two, and
a sixth keyword article is discarded rather than demoted
(`military_exercise.py:182-194`). Widening that is both an unregistered
sensitivity difference and a larger bill at the model.
"""
from __future__ import annotations

import hashlib
from email.utils import parsedate_to_datetime

from v3.adapters.llm import extraction as ex
from v3.adapters.types import (AdapterId, INFO, LLM, NormalizeContext,
                               ObservationDraft, PHYSICAL, RequestSpec,
                               SourceAdapter, STATUS_NO_DATA, STATUS_OBSERVED)
from v3.fetch import parse
from v3.kernel import Window

MILITARY_EXERCISE = AdapterId("military_exercise")

#: `_MILITARY_SOURCES` (`radar/sensors/military_exercise.py:40-78`),
#: transcribed and pinned against the live sensor. Both halves are
#: load-bearing: the URL decides what is read, and `theaters` decides
#: which model answers survive — an article whose theatre is not in its
#: FEED's list is discarded (`:365`), so widening a list admits
#: attributions production refuses and narrowing one silently blinds a
#: theatre.
#:
#: TASS's list is the one with a written reason: restricting it to `UA`
#: "forced Iran/ME articles into UA theater" (`:62-63`), which is
#: attribution pollution arriving through a feed table.
MILITARY_SOURCES: dict = {
    "PACOM_NEWS": {
        "url": "https://www.pacom.mil/Media/News/rss/",
        "org": "USINDOPACOM",
        "theaters": ["TW", "JP", "KP", "PH"],
    },
    "USNI_NEWS": {
        "url": "https://news.usni.org/feed",
        "org": "USNI",
        "theaters": ["TW", "JP", "KP", "UA", "IR", "IL"],
    },
    "DEFENSE_NEWS": {
        "url": "https://www.defensenews.com/arc/outboundfeeds/rss/",
        "org": "DefenseNews",
        "theaters": ["TW", "UA", "KP", "JP", "IL", "IR"],
    },
    "PLA_DAILY": {
        "url": "https://eng.chinamil.com.cn/rss/rss.xml",
        "org": "PLA",
        "theaters": ["TW", "JP", "PH", "IN"],
    },
    "TASS_MILITARY": {
        "url": "https://tass.com/rss/v2.xml",
        "org": "TASS",
        "theaters": ["UA", "IR", "IL", "SY", "KP"],
    },
    "JANES": {
        "url": "https://www.janes.com/feeds/news",
        "org": "Janes",
        "theaters": ["TW", "UA", "KP", "JP", "IR"],
    },
    "STARS_STRIPES": {
        "url": "https://www.stripes.com/arcio/rss/",
        "org": "Stars&Stripes",
        "theaters": ["JP", "KP", "TW", "UA"],
    },
}

#: `_EXERCISE_KEYWORDS` (`:81-91`), whole and in order. This list decides
#: slot 1, i.e. which five articles per feed are worth a model call.
EXERCISE_KEYWORDS: tuple[str, ...] = (
    "exercise", "drill", "maneuver", "deployment", "troops", "warship",
    "carrier strike", "amphibious", "live fire", "combat readiness",
    "mobilization", "military operation", "force posture", "air defense",
    "naval blockade", "submarine", "ballistic missile", "hypersonic",
    "military exercise", "joint exercise", "combined exercise",
    "PLA exercise", "PLAAF", "PLAN", "PLARF",
    "encirclement", "combat patrol", "warplane", "fighter jet",
    "destroyer", "frigate", "aircraft carrier",
    "forward deploy", "preposition", "staging area",
)

#: `_parse_articles(max_age_h=48)` (`:131`), and the two slot widths
#: (`:184`, `:190`).
ARTICLE_AGE_WINDOW_HOURS = 48
KEYWORD_ARTICLE_LIMIT = 5
THEATER_ARTICLE_LIMIT = 2
#: `summary[:400]` (`:179`) and `article_text[:1000]` (`:411`).
SUMMARY_CHARS = 400
TITLE_SANITIZE_CHARS = 120

#: `_fetch_rss` headers (`:120`). Not the browser string `apt_intel`
#: needs — these seven do not sit behind Akamai — but not the library
#: default either.
USER_AGENT = "Mozilla/5.0 (OSINT-Radar/8.0)"

#: `super().__init__("military_exercise", "info", _POLL_INTERVAL)` (`:203`)
#: with `_POLL_INTERVAL` = 3600 (`:37`). The SENSOR is `info`; the ITEMS
#: are `physical` (SENSI-037). Two different facts that have been
#: confused before, so both are named.
SENSOR_DOMAIN = INFO
ITEM_DOMAIN = PHYSICAL
_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)
_FRESHNESS_HORIZON_SEC = 24 * 3600.0

SIGNAL_SOURCE = "military_exercise"
SOURCE_TYPE = "military"

#: `max_tokens=300` (`:315`). One of the eight values A-02 measured
#: drifting across 200-512; pinned to this source's own.
MAX_TOKENS = 300

#: S1-SENSI-036: `base + scale_bonus`, additive rather than multiplicative
#: so the ceiling is a sum and not a product (`:396-401`).
URGENCY_BASE: dict = {"critical": 2.5, "high": 2.0, "medium": 1.5,
                      "low": 1.0}
SCALE_BONUS: dict = {"strategic": 0.5, "operational": 0.2, "tactical": 0.0}
URGENCY_DEFAULT = "low"
SCALE_DEFAULT = "tactical"
SCORE_DIGITS = 1

#: `_EVENT_TYPES` (`:335-338`). The full vocabulary has to be declared,
#: not just the two rules that act: `safe_enum` folds every unrecognised
#: answer onto `none`, and `none` is a DROP — so an undeclared member
#: would be discarded as though the model had said nothing.
EVENT_TYPES: tuple[str, ...] = ("new_deployment", "exercise_start",
                                "readiness_elevation", "status_report",
                                "historical_analysis", "none")
#: `min(confidence, 0.50)` for the two reporting types (`:348`) and for an
#: indirect theatre link (`:385`).
REPORT_CONFIDENCE_CAP = 0.50
INDIRECT_CAP = 0.50
#: `record_sensor_drop("event_type_none")` (`:345`) — this source's own
#: silence code, which S1-INGEST-020 requires to survive.
DROP_EVENT_TYPE_NONE = "event_type_none"


def dedup_key(source_name: str, title: str) -> str:
    """`_article_hash` (`:109-112`) — md5 of `mil-{source}-{title[:60]}`.

    The separator and the 60-character cut are both part of the key, and
    the source name is the UPPER_SNAKE dict key rather than a label of
    our own. A key that differs from production's is a dedup ledger that
    cannot be carried across the cutover.
    """
    raw = f"mil-{source_name}-{str(title or '')[:60]}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


def normalize_title(title: str) -> str:
    """`title.lower()[:60]` keeping alphanumerics (`:163`)."""
    return "".join(character for character in str(title or "")[:60].lower()
                   if character.isalnum())


def published_timestamp(published_raw: str) -> float:
    """`parsedate_to_datetime(pubdate).timestamp()`, 0.0 on failure (`:169-174`).

    A naive timestamp is read as UTC rather than in the host's local zone,
    for the reason `apt_intel.published_timestamp` records: a recorded
    payload has to normalize identically wherever the process runs, or the
    fixture suite and parity replay stop meaning anything.
    """
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
    """`not (pub_ts > 0 and pub_ts < cutoff)` (`:176-177`).

    An article nobody can date is KEPT — dropping it would make an odd
    date format indistinguishable from a quiet week, and NP1 prefers a
    stale candidate to a dropped one.
    """
    stamp = published_timestamp(published_raw)
    if stamp <= 0.0:
        return True
    return stamp >= now - window_hours * 3600.0


def feed_theaters(source_name: str, context: NormalizeContext) -> tuple:
    """This feed's theatres, narrowed to the participant union (`:227`).

    `[t for t in meta["theaters"] if t in strategic or not strategic]` —
    an EMPTY union means no narrowing at all, not an empty result, and a
    feed left with no theatre is not fetched (`:228-229`). The scope is
    per-FEED, which is why it travels into `build_item` as `scope` rather
    than being folded into the shared country check: `theater_mismatch`
    here is a legitimate discard, not the abolished A9 one.
    """
    declared = tuple(MILITARY_SOURCES.get(source_name, {}).get("theaters", ()))
    scope = tuple(context.countries)
    if not scope:
        return declared
    return tuple(code for code in declared if code in scope)


def theater_names(source_name: str, context: NormalizeContext) -> tuple:
    """`COUNTRY_COORDS[code]["name"].lower()` per theatre (`:98-106`).

    The geographic ledger arrives through `NormalizeContext` because
    nothing under `v3/` reads configuration. A code with no name
    contributes nothing — production appends only truthy names.
    """
    names = []
    for code in feed_theaters(source_name, context):
        name = str(context.country_names.get(code, "")).strip().lower()
        if name:
            names.append(name)
    return tuple(names)


def matches_keyword(text: str) -> bool:
    """Slot 1's gate — `any(kw in text_lower for kw in kw_lower)` (`:183`)."""
    lowered = str(text or "").lower()
    return any(keyword.lower() in lowered for keyword in EXERCISE_KEYWORDS)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One defence feed -> its candidate articles, or its cause of death.

    Selection is production's, in production's order (`:152-196`):

      1. the normalised title enters the dedup set BEFORE any filter, so a
         stale item consumes the slot and a later item with the same title
         stays suppressed
      2. the 48h age window, against `context.now`
      3. **slot 1** — up to five keyword matches. The branch `continue`s
         whether or not slot 1 had room, so a sixth keyword article is
         DROPPED rather than demoted into slot 2
      4. **slot 2** — up to two articles that match no keyword but name
         one of this feed's theatres
      5. the loop stops only when BOTH slots are full, and the result is
         `slot 1 + slot 2` rather than feed order
    """
    result = parse.parse_feed(payload.body, http_status=payload.status,
                              content_type=payload.content_type)
    source_name = payload.label or "military"
    if not result.is_alive:
        # `_fetch_rss` returns "" for every non-200 including 429, and
        # `_parse_articles("")` returns [] — production cannot tell a
        # rate limit from an empty week. Here the cause is named.
        return (ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=SENSOR_DOMAIN, country="",
            status=STATUS_NO_DATA, raw_score=0.0,
            value=f"{source_name}: {result.outcome}",
            flags={"feed": source_name, "outcome": result.outcome,
                   "detail": result.detail, "parse_stage": result.stage},
            evidence_url=payload.url),)

    theaters = feed_theaters(source_name, context)
    if not theaters:
        # `:228-229` — a feed whose theatres are all outside the union is
        # skipped entirely. Which requests to issue is the composition
        # root's call (§1-2), so this layer states the fact rather than
        # inventing candidates the model would be billed for.
        return ()

    names = theater_names(source_name, context)
    organisation = str(MILITARY_SOURCES.get(source_name, {}).get("org", ""))
    keyword_articles: list = []
    theater_articles: list = []
    seen: set = set()
    for item in result.items:
        key = normalize_title(item.title)
        if key and key in seen:
            continue
        if key:
            seen.add(key)                     # entered BEFORE every filter
        if not is_within_age_window(item.published_raw, context.now):
            continue
        article = {
            "title": item.title,
            "summary": item.summary[:SUMMARY_CHARS],
            "link": item.link,
            "published": item.published_raw,
            "org": organisation,
            "theaters": list(theaters),
            "dedup_key": dedup_key(source_name, item.title),
        }
        text_lower = f"{item.title} {item.summary}".lower()
        if matches_keyword(text_lower):
            if len(keyword_articles) < KEYWORD_ARTICLE_LIMIT:
                keyword_articles.append(article)
            continue                          # never demoted into slot 2
        if names and any(name in text_lower for name in names):
            if len(theater_articles) < THEATER_ARTICLE_LIMIT:
                theater_articles.append(article)
        if (len(keyword_articles) >= KEYWORD_ARTICLE_LIMIT
                and len(theater_articles) >= THEATER_ARTICLE_LIMIT):
            break

    return tuple(
        ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=SENSOR_DOMAIN, country="",
            # OBSERVED: an article becomes a signal only once the model
            # has attributed it. The row keeps the candidate and its
            # provenance in the ledger meanwhile.
            status=STATUS_OBSERVED, raw_score=0.0,
            value=article["title"][:200],
            flags={"feed": source_name, "article": article,
                   "awaiting": "llm_extraction",
                   "item_domain": ITEM_DOMAIN},
            evidence_url=article["link"] or payload.url)
        for article in keyword_articles + theater_articles)


# ── the LLM half: four slots and a disposition table ─────────────────────

def prefilter(article) -> bool:
    """Slot 1. `normalize` has already applied production's selection, so
    the model-side prefilter only refuses an article with no text at all —
    a call on an empty string cannot answer anything and still costs."""
    return bool(str(article.get("title") or "").strip()
                or str(article.get("summary") or "").strip())


def prompt(article, context) -> tuple[str, str]:
    """Slot 2. `military_exercise.py:257-312`, transcribed.

    The prompt is the measurement. Its BIAS CHECK block is what keeps a
    Mediterranean exercise from being filed under TW because it "signals
    deterrence", and its confidence guide is what the 0.35 floor is
    calibrated against — a paraphrase changes the distribution of answers
    while leaving every threshold intact.
    """
    theaters = ", ".join(context.get("theaters") or ())
    system = (
        "You are a military intelligence analyst. "
        "Analyze this defense/military news item for exercise and deployment "
        f"escalation signals relevant to any of these theaters: {theaters}. "
        "Respond ONLY with a JSON object, no explanation.")
    user = (
        f"Today's date: {context.get('today', '')}\n"
        f"Source: {context.get('org', '')} defense news\n"
        f"Relevant theaters: {theaters}\n\n"
        f"Article:\n"
        f"{ex.sanitize(article.get('title', ''), TITLE_SANITIZE_CHARS)}\n"
        f"{ex.sanitize(article.get('summary', ''), SUMMARY_CHARS)}\n\n"
        "Return a JSON object:\n"
        "{\n"
        '  "headline": "One-sentence escalation summary (max 100 chars)",\n'
        '  "escalation_signal": true or false,\n'
        '  "event_type": "new_deployment|exercise_start|readiness_elevation|'
        'status_report|historical_analysis|none",\n'
        '  "geographic_location": "Where is this event physically taking '
        'place? (region/sea/country name)",\n'
        '  "theater": "Theater code from the list above, or null",\n'
        '  "countries": ["ISO codes of ALL countries where forces are '
        'located or moving"],\n'
        '  "country_weights": {"ISO": 0.0-1.0 relevance weight per country},\n'
        '  "theater_link": "direct|indirect|none — is the '
        'geographic_location IN the theater, or only indirectly related?",\n'
        '  "exercise_type": "live_fire|amphibious|naval|air|cyber|combined|'
        'deployment|none",\n'
        '  "force_type": "naval|air|ground|rocket|cyber|combined",\n'
        '  "scale": "strategic|operational|tactical",\n'
        '  "urgency": "critical|high|medium|low",\n'
        '  "confidence": 0.0\n'
        "}\n"
        "BIAS CHECK — before assigning theater, ask yourself:\n"
        "- Where are the forces PHYSICALLY located or moving to?\n"
        "- Does the article NAME a location within the theater, or am I "
        "INFERRING a connection?\n"
        "- Would an analyst in that theater consider this a local event, or "
        "a distant one?\n"
        "- 'Signals deterrence globally' or 'demonstrates alliance "
        "commitment' is NOT a direct theater link.\n"
        "- If the event is in a DIFFERENT region (e.g. Iran/Middle East vs "
        "Ukraine), do NOT force it into the closest available theater — set "
        "theater=null instead.\n"
        "Set theater_link='direct' ONLY when forces are physically in/near "
        "the theater.\n"
        "Set theater_link='indirect' if the connection is strategic "
        "inference only — confidence will be reduced.\n"
        "Set theater=null and theater_link='none' if no specific theater is "
        "relevant.\n\n"
        "event_type rules (CRITICAL — read carefully):\n"
        "- new_deployment: New orders, units moving NOW to a contested "
        "area\n"
        "- exercise_start: Exercise commencing now or within 48h\n"
        "- readiness_elevation: Explicit alert level or readiness change\n"
        "- status_report: Weekly/periodic tracker, scheduled summary, "
        "current disposition "
        "(confidence will be capped at 0.50 — surfaces for analyst review)\n"
        "- historical_analysis: Analysis of past events, retrospective "
        "reporting "
        "(confidence will be capped at 0.50 — surfaces for analyst review)\n"
        "- none: No military activity signal (use <0.30)\n"
        "Confidence guide (lowered floor — analyst-review-first posture):\n"
        "- 0.80-0.95: Active live-fire exercise near theater OR new forward "
        "deployment orders\n"
        "- 0.60-0.79: Exercise announcement with clear theater relevance\n"
        "- 0.40-0.59: Clear military activity but indirect theater link OR "
        "routine posture change\n"
        "- 0.35-0.39: Weak but traceable signal — brief mention of "
        "theater-relevant forces\n"
        "- <0.35: No signal, unrelated to any listed theater — set "
        "escalation_signal=false, theater=null\n"
        "USNI Fleet Tracker weekly reports are status_report, not "
        "new_deployment. "
        "Default to escalation_signal=true whenever the article names a "
        "theater-relevant force or location, even if the event is routine — "
        "analysts will triage.")
    return system, user


def score_delta(data) -> float:
    """Slot 3. S1-SENSI-036 — `round(base + bonus, 1)` (`:396-401`).

    `safe_enum`'s defaults are part of the arithmetic: an unrecognised
    urgency scores as `low` and an unrecognised scale earns no bonus,
    rather than dropping the item. The ceiling is 3.0, which is exactly
    the TL1 physical gate (A6).
    """
    urgency = str(data.get("urgency") or "").strip().lower()
    scale = str(data.get("scale") or "").strip().lower()
    if urgency not in URGENCY_BASE:
        urgency = URGENCY_DEFAULT
    if scale not in SCALE_BONUS:
        scale = SCALE_DEFAULT
    return round(URGENCY_BASE[urgency] + SCALE_BONUS[scale], SCORE_DIGITS)


#: S1-SENSI-035 and S1-INGEST-017, as rows the shared extraction reads.
#: The event-type rules come FIRST so this source's own drop code
#: (`event_type_none`) survives instead of being replaced by the generic
#: `no_escalation_signal` — production's order, and the more specific
#: silence (S1-INGEST-020).
DISPOSITIONS: tuple = (
    ex.DispositionRule(field="event_type", values=("none",), outcome=ex.DROP,
                       reason=DROP_EVENT_TYPE_NONE, matches_unrecognised=True),
    ex.DispositionRule(field="event_type",
                       values=("status_report", "historical_analysis"),
                       outcome=ex.CAP, cap=REPORT_CONFIDENCE_CAP),
    ex.DispositionRule(field="event_type",
                       values=("new_deployment", "exercise_start",
                               "readiness_elevation"),
                       outcome=ex.ACCEPT),
) + ex.relevance_rules(indirect_cap=INDIRECT_CAP)

PROFILE = ex.IntelProfile(
    source_type=SOURCE_TYPE,
    prefilter=prefilter, prompt=prompt, score_delta=score_delta,
    domain=ITEM_DOMAIN,
    dispositions=DISPOSITIONS,
    llm_field_keys=("exercise_type", "event_type", "force_type", "scale",
                    "urgency", "source_org", "geographic_location",
                    "theater_link", "escalation_signal"),
    max_tokens=MAX_TOKENS,
    schema_keys=("headline", "escalation_signal", "event_type",
                 "geographic_location", "theater", "countries",
                 "country_weights", "theater_link", "exercise_type",
                 "force_type", "scale", "urgency", "confidence"))


MILITARY_EXERCISE_ADAPTER = SourceAdapter(
    adapter_id=MILITARY_EXERCISE, category=LLM,
    requests=tuple(
        RequestSpec(url=meta["url"], expect_content="xml",
                    headers={"User-Agent": USER_AGENT}, label=name)
        for name, meta in MILITARY_SOURCES.items()),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="defence_rss",
    baseline_refs=("military_exercise_dedup",))

__all__ = ["MILITARY_EXERCISE", "MILITARY_EXERCISE_ADAPTER", "PROFILE",
           "normalize", "prefilter", "prompt", "score_delta",
           "dedup_key", "normalize_title", "published_timestamp",
           "is_within_age_window", "feed_theaters", "theater_names",
           "matches_keyword", "MILITARY_SOURCES", "EXERCISE_KEYWORDS",
           "ARTICLE_AGE_WINDOW_HOURS", "KEYWORD_ARTICLE_LIMIT",
           "THEATER_ARTICLE_LIMIT", "SUMMARY_CHARS", "USER_AGENT",
           "SIGNAL_SOURCE", "SOURCE_TYPE", "MAX_TOKENS", "URGENCY_BASE",
           "SCALE_BONUS", "EVENT_TYPES", "REPORT_CONFIDENCE_CAP",
           "INDIRECT_CAP", "DROP_EVENT_TYPE_NONE", "DISPOSITIONS",
           "SENSOR_DOMAIN", "ITEM_DOMAIN"]
