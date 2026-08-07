"""`rss_narrative` — S1-SENSI-005..011 + INGEST-*. State media, counted.

Adversary state wires (TASS, RIA, Xinhua, Global Times, Mehr, Tasnim,
KCNA) read not for what they say but for how OFTEN they say it: a
z-score on escalation-vocabulary frequency against a 30-day baseline,
which is what separates routine propaganda from a narrative burst.

**The feed ledger is not in the sensor.** It is
`geo_data.json::ADVERSARY_NARRATIVE_SOURCES`, reached through
`radar/config.py:99,117`, and auditing the sensor alone would have found
nothing. Nine feeds across five adversaries — and TASS appears TWICE,
once for RU and once for BY, which means a Russian burst raises Belarus's
count too. That is deployment data, transcribed here because it decides
what is fetched; the two much larger ledgers it uses (`TACTICAL_KEYWORDS`,
110 countries; `NARRATIVE_GEO_TERMS`, 36) arrive through
`NormalizeContext` instead, because a copy of those under `v3/` would be
a second ledger to keep in step.

**A8 — the threshold that fires hardest is the one nobody can see.**
When the baseline is a flat stream of zeros, the first non-zero reading
IS the burst, and production reports it as `NARRATIVE_ZSCORE_FIRST_SIGNAL`
(default 3.0 — CRITICAL) rather than as z=0. The value is read straight
from the environment at the comparison site (`rss_narrative.py:610`) and
appears in no registry, so the single most sensitive number in the sensor
is invisible to the settings surface. §3-3 rules it must become an
operator-variable key (O-18's (a) group); until that registry lands it is
a pinned `Threshold` with its origin stated (§7-2 #52).

**Two-tier matching, and the second tier needs TWO terms.** A phrase
match is one hit; atomic single words need two DISTINCT terms in one
article before it counts (`:206-214`). Production's comment says why —
single-word matches inflate the baseline, and an inflated baseline is a
burst that never fires.

**The denominator is never filtered.** The geographic filter removes an
article about another monitored theatre from `keyword_hits` but NOT from
`article_count` (`:190-204`). Filtering both would let the ratio stay
constant while the evidence disappeared.
"""
from __future__ import annotations

import re

from v3.adapters.llm import extraction as ex
from v3.adapters.types import (AdapterId, INFO, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.fetch import parse
from v3.kernel import Threshold, Window

RSS_NARRATIVE = AdapterId("rss_narrative")

#: `geo_data.json::ADVERSARY_NARRATIVE_SOURCES`, flattened to
#: `(adversary, feed_name, url)` and pinned against the file by a test.
#: TASS is listed twice on purpose — it is RU's wire and BY's only
#: source, so a Russian burst raises Belarus's count as well.
FEEDS: tuple[tuple[str, str, str], ...] = (
    ("RU", "tass", "https://tass.com/rss/v2.xml"),
    ("RU", "ria", "https://ria.ru/export/rss2/archive/index.xml"),
    ("CN", "xinhua", "https://www.xinhuanet.com/english/rss/worldrss.xml"),
    ("CN", "globaltimes", "https://www.globaltimes.cn/rss/outbrain.xml"),
    ("IR", "mehr", "https://en.mehrnews.com/rss"),
    ("IR", "tasnim", "https://www.tasnimnews.com/en/rss"),
    ("KP", "kcna", "https://kcnawatch.org/newstream/rss/"),
    ("BY", "tass", "https://tass.com/rss/v2.xml"),
)

#: `_TERM_STOPWORDS` (`radar/sensors/rss_narrative.py:15-24`). The last
#: five — `policy`, `relations`, `tensions`, `crisis`, `operations` — are
#: not grammar; they are words that appear in too many news contexts to
#: discriminate, and dropping them from this set would make every article
#: a hit.
TERM_STOPWORDS: frozenset = frozenset({
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for",
    "of", "is", "are", "was", "were", "be", "by", "with", "from",
    "this", "that", "as", "it", "its", "has", "have", "had",
    "near", "over", "after", "before", "during", "amid",
    "new", "old", "all", "any", "no", "not", "but",
    "policy", "relations", "tensions", "crisis", "operations",
})
#: `len(tok) >= 4` (`:48`).
MIN_ATOMIC_LENGTH = 4
#: `len(matches) >= 2` (`:213`) — an article needs TWO distinct atomic
#: terms to count. One would inflate the baseline, and an inflated
#: baseline is a burst that never fires.
MIN_ATOMIC_MATCHES = 2
#: `len(t_lower) >= 6` decides substring vs word-boundary matching for a
#: geo term (`:82-85`).
GEO_SUBSTRING_MIN_LENGTH = 6

GEO_MATCH, GEO_OTHER, GEO_GENERIC = "match", "other", "generic"

#: `max_articles: int = 4` (`:222`) and `_LLM_POOL_CAP` (`:293`).
BURST_ARTICLE_LIMIT = 4
LLM_POOL_CAP = 6
#: `desc[:300]` (`:275`).
BURST_SUMMARY_CHARS = 300

#: `super().__init__("rss_narrative", "info", 1800)` (`:129`).
_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 2 * 3600.0
#: DP6's twin again: `NARRATIVE_BASELINE_DAYS` days at this cadence.
#: Production computes `days * cycles_per_day` by hand (`:627`); the
#: window holds both facts and derives one from the other.
BASELINE_DAYS = 30
BASELINE_WINDOW = Window.from_days(BASELINE_DAYS, cadence_sec=1800.0)
#: `if len(daily) < 7` (`:596`).
ZSCORE_MIN_SAMPLES = 7

ZSCORE_ALERT = 2.0
ZSCORE_CRITICAL = 3.0

#: **A8.** `float(os.getenv("NARRATIVE_ZSCORE_FIRST_SIGNAL", "3.0"))`
#: (`:610`) — read at the comparison site, in no registry, and it is the
#: most sensitive number the sensor has: it turns the first non-zero
#: reading against a silent baseline into a CRITICAL burst.
FIRST_SIGNAL_ZSCORE = Threshold.pinned(
    3.0, unit="score",
    provenance_ref="radar/sensors/rss_narrative.py:610 — "
                   "NARRATIVE_ZSCORE_FIRST_SIGNAL, read from the "
                   "environment at the comparison site and absent from "
                   "every registry (A8). It fires when the baseline is a "
                   "flat stream of zeros: the first activity IS the burst, "
                   "and without this branch it would be reported as z=0. "
                   "Design sheet §3-3 rules it must become an "
                   "operator-variable key (O-18 group (a)); pinned to the "
                   "deployed default until that registry lands (§7-2 #52).")

SIGNAL_SOURCE = "rss_narrative"
SOURCE_TYPE = "narrative"
#: `max_tokens=512` (`:409`) — the largest of the eight, because this one
#: asks the model to CLUSTER several articles rather than judge one.
MAX_TOKENS = 512

#: `_NARRATIVE_TYPES` / `_URGENCY_TYPES` (`:284-289`).
NARRATIVE_TYPES: tuple[str, ...] = (
    "pre-operation_conditioning", "threat_escalation",
    "response_to_incident", "propaganda_routine", "unknown",
)
URGENCY_TYPES: tuple[str, ...] = ("critical", "high", "medium", "low")
#: `:541-552`. `pre-operation_conditioning` outscores `threat_escalation`
#: — conditioning an audience BEFORE an operation is the earlier
#: indicator, which is the whole premise of watching state media.
TYPE_BASE: dict = {
    "pre-operation_conditioning": 2.5,
    "threat_escalation": 2.0,
    "response_to_incident": 1.5,
    "propaganda_routine": 0.5,
    "unknown": 1.0,
}
URGENCY_BONUS: dict = {"critical": 0.5, "high": 0.2, "medium": 0.0,
                       "low": 0.0}
NARRATIVE_TYPE_DEFAULT = "unknown"
URGENCY_DEFAULT = "medium"
SCORE_DIGITS = 1

USER_AGENT = "Mozilla/5.0 (OSINT-Radar/8.0)"

_WORD = re.compile(r"[a-z]+")


def expand_keywords(keywords) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """`_expand_keywords` (`:26-51`) — `(phrases, atomic_terms)`.

    A phrase is an entry containing a space OR a hyphen. Atomic terms are
    every word of four or more characters from EVERY entry, stopwords
    removed, deduplicated and sorted — including words taken out of the
    phrases, which is what gives the second tier its recall when an
    article paraphrases the official wording.
    """
    phrases: list = []
    atomic: set = set()
    for keyword in keywords or ():
        lowered = str(keyword or "").lower().strip()
        if not lowered:
            continue
        if " " in lowered or "-" in lowered:
            phrases.append(lowered)
        for token in _WORD.findall(lowered):
            if len(token) >= MIN_ATOMIC_LENGTH and token not in TERM_STOPWORDS:
                atomic.add(token)
    return tuple(phrases), tuple(sorted(atomic))


def geo_pattern(terms):
    """`_get_geo_regex` (`:69-90`) — one alternation per country.

    A term with a space, or six characters or more, is matched as a
    SUBSTRING; a short single word gets `\\b` boundaries. The asymmetry is
    deliberate: "Kyiv" inside "Kyivan" is a false positive, while
    "Taiwan Strait" inside a longer phrase is not.
    """
    parts: list = []
    for term in terms or ():
        lowered = str(term or "").lower().strip()
        if not lowered:
            continue
        if " " in lowered or len(lowered) >= GEO_SUBSTRING_MIN_LENGTH:
            parts.append(re.escape(lowered))
        else:
            parts.append(r"\b" + re.escape(lowered) + r"\b")
    if not parts:
        return None
    return re.compile("|".join(parts))


def classify_geo(text_lower: str, country: str, geo_terms) -> str:
    """`_classify_article_geo` (`:92-127`) — `match` / `other` / `generic`.

    The CURRENT country is tested first, so an article naming both
    theatres counts for this one. `generic` is not `other`: an article
    with no monitored geography at all is ambiguous, and ambiguity is
    counted rather than discarded (NP1).
    """
    current = geo_pattern(geo_terms.get(country, ()))
    if current and current.search(text_lower):
        return GEO_MATCH
    for code, terms in geo_terms.items():
        if code == country:
            continue
        other = geo_pattern(terms)
        if other and other.search(text_lower):
            return GEO_OTHER
    return GEO_GENERIC


def normalize_title(title: str) -> str:
    """`title.lower()[:60]` keeping alphanumerics (`:175`)."""
    return "".join(character for character in str(title or "")[:60].lower()
                   if character.isalnum())


def _article_is_hit(text_lower: str, phrases, atomic_re) -> bool:
    if any(phrase in text_lower for phrase in phrases):
        return True
    if atomic_re is None:
        return False
    return len(set(atomic_re.findall(text_lower))) >= MIN_ATOMIC_MATCHES


def _atomic_regex(atomic):
    if not atomic:
        return None
    return re.compile(r"\b(?:" + "|".join(re.escape(term) for term in atomic)
                      + r")\b")


def count_keywords(items, keywords, *, country: str = "",
                   geo_terms=None) -> tuple[int, int]:
    """`_count_keywords_in_rss` (`:148-216`) — `(keyword_hits, articles)`.

    The DENOMINATOR is never filtered. An article about another monitored
    theatre is removed from `keyword_hits` and still counted in
    `article_count`, because filtering both would leave the ratio
    unchanged while the evidence vanished — the z-score would go on
    reporting a steady rate for a wire that had stopped saying anything.
    """
    phrases, atomic = expand_keywords(keywords)
    atomic_re = _atomic_regex(atomic)
    use_geo = bool(geo_terms and country)
    seen: set = set()
    hits = 0
    articles = 0
    for item in items:
        key = normalize_title(item.title)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        articles += 1                     # unfiltered denominator
        text_lower = f"{item.title} {item.summary}".lower()
        if use_geo and classify_geo(text_lower, country,
                                    geo_terms) == GEO_OTHER:
            continue
        if _article_is_hit(text_lower, phrases, atomic_re):
            hits += 1
    return hits, articles


def burst_articles(items, keywords, *, country: str = "", geo_terms=None,
                   limit: int = BURST_ARTICLE_LIMIT) -> tuple:
    """`_get_burst_articles` (`:218-281`) — the pool the model reads.

    The SAME two-tier gate as the counter, on purpose: production's
    comment records that a different gate made burst-detected articles
    come back empty when only atomic terms had matched.
    """
    phrases, atomic = expand_keywords(keywords)
    atomic_re = _atomic_regex(atomic)
    use_geo = bool(geo_terms and country)
    seen: set = set()
    selected: list = []
    for item in items:
        key = normalize_title(item.title)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        text_lower = f"{item.title} {item.summary}".lower()
        if use_geo and classify_geo(text_lower, country,
                                    geo_terms) == GEO_OTHER:
            continue
        if _article_is_hit(text_lower, phrases, atomic_re):
            selected.append({"title": item.title,
                             "summary": item.summary[:BURST_SUMMARY_CHARS],
                             "link": item.link})
        if len(selected) >= limit:
            break
    return tuple(selected)


def burst_status(z_score: float) -> str:
    """`:707-711`, exported so WP-4.1's reduction calls it rather than
    writing the ladder a second time (DP4)."""
    if z_score >= ZSCORE_CRITICAL:
        return "CRITICAL_BURST"
    if z_score >= ZSCORE_ALERT:
        return "BURST"
    return "NORMAL"


def first_signal_zscore(today: float, mean: float, std: float) -> float:
    """A8's branch (`:605-613`), as a function.

    `std == 0 and mean == 0 and today > 0` is a baseline that has never
    seen activity, and the first activity is the burst. Returning 0.0
    there — which is what the arithmetic gives — reports silence on the
    single most informative reading the sensor can take.
    """
    if std > 0:
        return (today - mean) / std
    if today > 0 and mean == 0:
        return FIRST_SIGNAL_ZSCORE.resolve().value
    return 0.0


def feed_source(feed_name: str) -> str:
    """Per-feed row name. §7-2 #51's family — L1 is `UNIQUE (tick_id,
    sensor, signal_source, country)` and one theatre is counted against
    several feeds in one tick, so the rows cannot share a name. Production
    has none to borrow: it folds the feeds together BEFORE naming the
    entry `narrative_{theater}`."""
    return f"narrative_{feed_name}"


def adversary_of(feed_name: str, url: str) -> tuple:
    """Every adversary this URL is a wire for. TASS answers for RU AND BY."""
    return tuple(sorted({adversary for adversary, name, feed_url in FEEDS
                         if name == feed_name and feed_url == url}))


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One adversary wire -> one counted row per watched country.

    The verdict is NOT reached here: the z-score needs a 30-day baseline
    L1 does not yet supply, and the burst status needs every feed of a
    theatre joined (§7-2 #9 and #11's families). What lands is the
    measurement — hits, articles, the normalised frequency and the
    matched article pool — which is exactly what the reduction needs and
    nothing it would have to recompute.
    """
    result = parse.parse_feed(payload.body, http_status=payload.status,
                              content_type=payload.content_type)
    feed_name = str(payload.label or "").split(":", 1)[-1].strip() or "feed"
    if not result.is_alive:
        return (ObservationDraft(
            signal_source=feed_source(feed_name), domain=INFO, country="",
            status=STATUS_NO_DATA, raw_score=0.0,
            value=f"{feed_name}: {result.outcome}",
            flags={"feed": feed_name, "outcome": result.outcome,
                   "detail": result.detail, "parse_stage": result.stage},
            evidence_url=payload.url),)

    drafts: list = []
    for country in context.countries:
        keywords = context.tactical_keywords.get(country) or \
            context.tactical_keywords.get("DEFAULT") or ()
        if not keywords:
            continue
        hits, articles = count_keywords(result.items, keywords,
                                        country=country,
                                        geo_terms=context.geo_terms)
        pool = burst_articles(result.items, keywords, country=country,
                              geo_terms=context.geo_terms)
        normalized = hits / articles if articles else 0.0
        drafts.append(ObservationDraft(
            signal_source=feed_source(feed_name), domain=INFO,
            country=country,
            status=STATUS_OBSERVED, raw_score=0.0,
            value=f"{feed_name}: {hits}/{articles} hits",
            flags={
                "feed": feed_name,
                "adversary": list(adversary_of(feed_name, payload.url)),
                "keyword_hits": hits,
                "article_count": articles,
                "normalized_freq": round(normalized, 5),
                "burst_articles": list(pool),
                # §7-2 #9's discipline: `z_score` is a NUMBER downstream
                # and `status` a closed vocabulary, so neither may carry a
                # marker. They are ABSENT and a sibling names why.
                "burst_verdict": "pending_l1_narrative_baseline",
            },
            evidence_url=payload.url))
    return tuple(drafts)


# ── the LLM half: a clustering answer, exploded into items ──────────────

def prefilter(article) -> bool:
    return bool(str(article.get("title") or "").strip())


def prompt(article, context) -> tuple[str, str]:
    """Slot 2. `rss_narrative.py:352-408`, transcribed.

    This prompt is unlike the other seven: it reads a POOL and returns
    SEVERAL answers. The system half exists because the flow it replaced
    pooled articles that merely shared tactical keywords — "naval port
    call + AI scholar + destroyer drill" — and the single-synthesis model
    was "forced to fabricate a common narrative" across them (`:307-311`).
    "NEVER fabricate" is therefore load-bearing text, not emphasis.

    `article` is the POOL here (`{"pool": [...]}`), because the unit the
    model judges is the burst rather than the article.
    """
    pool = list(article.get("pool") or ())[:LLM_POOL_CAP]
    articles_text = "\n\n".join(
        f"[{i + 1}] {ex.sanitize(entry.get('title', ''), 120)}\n"
        f"{ex.sanitize(entry.get('summary', ''), 200)}"
        for i, entry in enumerate(pool))
    system = (
        "You are a strategic intelligence analyst specializing in "
        "information warfare and pre-conflict narrative patterns. "
        "Analyze adversary media articles that triggered a statistical "
        "keyword burst. Group the articles by thematic coherence: "
        "articles on unrelated topics MUST go in separate clusters. "
        "NEVER fabricate a common narrative across unrelated articles. "
        "Respond ONLY with a JSON object, no explanation.")
    user = (
        f"Today's date: {context.get('today', '')}\n"
        f"Theater: {context.get('country', '')}\n"
        f"Z-score: {float(context.get('z_score', 0.0)):.2f} "
        f"(statistical keyword burst; {len(pool)} articles)\n"
        f"Sources: {context.get('sources', '')}\n\n"
        f"Articles:\n\n{articles_text}\n\n"
        "Return a JSON object:\n"
        "{\n"
        '  "clusters": [\n'
        "    {\n"
        '      "article_indices": [1, 3],\n'
        '      "headline": "One-sentence summary of THIS cluster\'s '
        'narrative (max 100 chars)",\n'
        '      "narrative_type": "pre-operation_conditioning|'
        'threat_escalation|response_to_incident|propaganda_routine|'
        'unknown",\n'
        '      "dominant_theme": "Key theme of THIS cluster only",\n'
        '      "escalation_signal": true or false,\n'
        '      "countries": ["ISO codes addressed in this cluster"],\n'
        '      "country_weights": {"ISO": 0.0-1.0},\n'
        '      "urgency": "critical|high|medium|low",\n'
        '      "confidence": 0.0-1.0\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "Clustering rules:\n"
        "- ONE cluster if all articles share a coherent theme.\n"
        "- MULTIPLE clusters when articles cover distinctly different "
        "topics\n"
        "  (e.g. some about naval activity, others about diplomatic "
        "pressure).\n"
        "- article_indices are 1-based and must reference articles listed "
        "above.\n"
        "- An article may belong to multiple clusters only when it "
        "genuinely\n"
        "  bridges themes; otherwise assign to exactly one cluster.\n"
        "- Off-topic articles that do NOT support any narrative theme "
        "should\n"
        "  be omitted from all clusters rather than forced into one.\n\n"
        "narrative_type guide:\n"
        "- pre-operation_conditioning: Preparing audience for imminent "
        "military action\n"
        "- threat_escalation: Adversary amplifying a genuine current "
        "escalation\n"
        "- response_to_incident: Reactive coverage of an already-occurred "
        "incident\n"
        "- propaganda_routine: Matches source's baseline framing with no "
        "new trigger.\n"
        "  Classify by departure from baseline patterns, not origin "
        "country.\n\n"
        "IMPORTANT: The 'Theater' label above is for CONTEXT only. "
        "Assign 'countries' based on the article content, NOT the Theater "
        "label. "
        "If articles discuss a DIFFERENT region than the labeled Theater, "
        "set countries to that region's ISO codes.\n\n"
        "Confidence (per cluster):\n"
        "- 0.75+: Strong pre-operation conditioning with specific new "
        "trigger\n"
        "- 0.60-0.74: Elevated narrative with clear new escalatory "
        "framing\n"
        "- <0.55: Routine burst, no new trigger — set "
        "escalation_signal=false")
    return system, user


def score_delta(data) -> float:
    """Slot 3. `:541-552` — `round(type_base + urgency_bonus, 1)`.

    `pre-operation_conditioning` scores ABOVE `threat_escalation`:
    conditioning an audience before an operation is the earlier
    indicator, which is the entire premise of watching state media.
    Both defaults are `safe_enum`'s (`unknown` -> 1.0, `medium` -> 0.0).
    """
    narrative = str(data.get("narrative_type") or "").strip().lower()
    if narrative not in TYPE_BASE:
        narrative = NARRATIVE_TYPE_DEFAULT
    urgency = str(data.get("urgency") or "").strip().lower()
    if urgency not in URGENCY_BONUS:
        urgency = URGENCY_DEFAULT
    return round(TYPE_BASE[narrative] + URGENCY_BONUS[urgency], SCORE_DIGITS)


def headline_fallback(country: str, dominant_theme: str) -> str:
    """`f"Narrative burst: {theater} — {dominant_theme[:60]}"` (`:479`).

    Applied when the model returned an EMPTY headline, not only an absent
    one (`if not headline:`), which is this source's own rule.
    """
    return f"Narrative burst: {country} — {str(dominant_theme or '')[:60]}"


#: This source asks for `theater_link` nowhere, so it declares no
#: relevance rules — attaching them would drop every cluster.
DISPOSITIONS: tuple = ()

PROFILE = ex.IntelProfile(
    source_type=SOURCE_TYPE,
    prefilter=prefilter, prompt=prompt, score_delta=score_delta,
    domain=INFO,
    dispositions=DISPOSITIONS,
    #: One response, several answers — and an answer that ignores the
    #: schema falls back to being ONE cluster, which is production's
    #: legacy path (`:445-449`) rather than a discard.
    response_items_key="clusters",
    llm_field_keys=("narrative_type", "dominant_theme", "z_score",
                    "burst_status", "sources", "escalation_signal",
                    "article_count"),
    max_tokens=MAX_TOKENS,
    schema_keys=("article_indices", "headline", "narrative_type",
                 "dominant_theme", "escalation_signal", "countries",
                 "country_weights", "urgency", "confidence"))


RSS_NARRATIVE_ADAPTER = SourceAdapter(
    adapter_id=RSS_NARRATIVE, category=INFO,
    # One request per DISTINCT url; TASS is declared once even though the
    # ledger lists it for two adversaries, because §2-1 rules that a
    # declaration whose text does not change is fetched once.
    requests=tuple(
        RequestSpec(url=url, expect_content="xml",
                    headers={"User-Agent": USER_AGENT},
                    label=f"feed:{name}")
        for url, name in dict(
            (url, name) for _adversary, name, url in FEEDS).items()),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="narrative_rss",
    knowledge_refs=("K08",),
    baseline_refs=("narrative_keyword_frequency",))

__all__ = ["RSS_NARRATIVE", "RSS_NARRATIVE_ADAPTER", "PROFILE", "normalize",
           "prefilter", "prompt", "score_delta", "headline_fallback",
           "expand_keywords", "geo_pattern", "classify_geo",
           "normalize_title", "count_keywords", "burst_articles",
           "burst_status", "first_signal_zscore", "feed_source",
           "adversary_of", "FEEDS", "TERM_STOPWORDS", "MIN_ATOMIC_LENGTH",
           "MIN_ATOMIC_MATCHES", "GEO_SUBSTRING_MIN_LENGTH", "GEO_MATCH",
           "GEO_OTHER", "GEO_GENERIC", "BURST_ARTICLE_LIMIT",
           "LLM_POOL_CAP", "BURST_SUMMARY_CHARS", "BASELINE_DAYS",
           "BASELINE_WINDOW", "ZSCORE_MIN_SAMPLES", "ZSCORE_ALERT",
           "ZSCORE_CRITICAL", "FIRST_SIGNAL_ZSCORE", "SIGNAL_SOURCE",
           "SOURCE_TYPE", "MAX_TOKENS", "NARRATIVE_TYPES", "URGENCY_TYPES",
           "TYPE_BASE", "URGENCY_BONUS", "NARRATIVE_TYPE_DEFAULT",
           "URGENCY_DEFAULT", "USER_AGENT"]
