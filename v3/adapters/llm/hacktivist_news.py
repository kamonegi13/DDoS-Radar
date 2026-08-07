"""`hacktivist_news` — S1-SENSI-041..043 + INGEST-*. Observers observed.

Five security-news wires, read for hacktivist campaign reporting. The
sensor's premise is that journalists who watch private Telegram channels
publish what they find, so this is an "observation of observers" layer
that trades hours of latency for journalist verification.

**A9 — the discard this port ABOLISHES.** Production drops an item whose
model-assigned country is outside the participant union
(`hacktivist_news_sensor.py:392-398`, `record_sensor_drop(
"theater_not_strategic")`) — and it is the only one of the eight LLM
sensors that does. It also contradicts its OWN prompt, which tells the
model in capitals: "Do NOT force-assign a theater from that list... If
the targeted country is not in the list, still return its ISO code — the
system will handle filtering." The prompt promises Python will filter;
the Python throws the item away. §3-3 rules the prompt is right and the
discard goes (§7-2 #3, sensitive direction), so **`scope` is NOT passed
for this source**. Passing it would resurrect the discard through the
shared check, which is the same outcome by a different door.

**The signal field is not `escalation_signal`.** It is
`is_active_campaign` (`:362`) — "is this an ONGOING campaign", not "is
this an escalation" — and its silence is filed as `not_active_campaign`.
Declared on the profile rather than special-cased in the extraction.

**A preserved defect, stated so it is not mistaken for a port error.**
`attack_type` defaults to `"DDoS"` (`:411-414`), so a model answer that
omits or garbles the field earns `type_bonus = 0.5` — the SAME bonus as
a confirmed DDoS campaign, and the largest in the table. A malformed
response therefore scores higher than a correctly-reported data leak
(0.2). Ported as production has it (§3-5 H-4): changing a default while
porting is exactly the tidying that turns a transcription into a rewrite,
and the alternative — a conservative `"none"` — is a registered change
somebody has to approve, not a silent fix.
"""
from __future__ import annotations

import hashlib
import re
from email.utils import parsedate_to_datetime

from v3.adapters.llm import extraction as ex
from v3.adapters.types import (AdapterId, INFO, LLM, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.fetch import parse
from v3.kernel import Window

HACKTIVIST_NEWS = AdapterId("hacktivist_news")

#: `_NEWS_SOURCES` (`radar/sensors/hacktivist_news_sensor.py:41-63`).
#: No `theaters` key: these wires cover the world, and the target country
#: comes from the article rather than from the feed.
NEWS_SOURCES: dict = {
    "BLEEPING_COMPUTER": {
        "url": "https://www.bleepingcomputer.com/feed/",
        "org": "BleepingComputer",
    },
    "THE_RECORD": {
        "url": "https://therecord.media/feed",
        "org": "TheRecord",
    },
    "THE_HACKER_NEWS": {
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "org": "TheHackerNews",
    },
    "CYBERSCOOP": {
        "url": "https://cyberscoop.com/feed/",
        "org": "CyberScoop",
    },
    "DARK_READING": {
        "url": "https://www.darkreading.com/rss.xml",
        "org": "DarkReading",
    },
}

#: `_HACKTIVIST_KEYWORDS` (`:66-83`), whole and in order. The first
#: fourteen are GROUP NAMES, and a group that stops being listed stops
#: being seen — the list is a threat-actor roster, not a style choice.
HACKTIVIST_KEYWORDS: tuple[str, ...] = (
    "noname057", "killnet", "cyber army of russia", "anonymous sudan",
    "dragonforce", "mysterious team", "it army of ukraine",
    "darkstorm", "siegedsec", "indian cyber force", "ghostclan",
    "people's cyber army", "xaknet", "sylhet gang",
    "ddos attack", "ddos campaign", "distributed denial",
    "hacktivist", "hacktivism", "hacktivist group",
    "defacement", "data leak", "hack-and-leak",
    "claimed responsibility", "attack claimed", "targeted by",
    "cyberattack on", "cyber attack on", "took down", "knocked offline",
    "government websites", "government sites",
    "critical infrastructure attack",
    "ddosia", "botnet attack", "http flood", "layer 7",
)

#: `_DISCARD_KEYWORDS` (`:86-89`) — marketing and how-to language, which
#: matches the campaign vocabulary without reporting a campaign.
DISCARD_KEYWORDS: tuple[str, ...] = (
    "how to protect", "best practices", "product review",
    "webinar", "ebook", "whitepaper", "sponsored",
)

#: `_parse_articles(max_age_h=48)` (`:118`) and `len(articles) >= 5`
#: (`:203`). ONE slot here, unlike `diplomatic`'s three.
ARTICLE_AGE_WINDOW_HOURS = 48
ARTICLE_LIMIT = 5
#: `summary_clean[:500]` (`:198`) — 500, not `diplomatic`'s 400.
SUMMARY_CHARS = 500
TITLE_SANITIZE_CHARS = 120

USER_AGENT = "Mozilla/5.0 (OSINT-Radar/8.0)"

#: `super().__init__("hacktivist_news", "info", _POLL_INTERVAL)` (`:215`),
#: `_POLL_INTERVAL` = 1800 (`:37`).
SENSOR_DOMAIN = INFO
ITEM_DOMAIN = INFO
_CADENCE = Window.from_days(1.0, cadence_sec=1800.0)
_FRESHNESS_HORIZON_SEC = 24 * 3600.0

SIGNAL_SOURCE = "hacktivist_news"
SOURCE_TYPE = "hacktivist"
#: `max_tokens=250` (`:352`).
MAX_TOKENS = 250

#: `is_active_campaign` (`:362`), and its silence code (`:367`).
SIGNAL_FIELD = "is_active_campaign"
DROP_NOT_ACTIVE = "not_active_campaign"

#: S1-SENSI-043's scoring (`:417-424`). `urgency` defaults to **medium**
#: here (`:407-410`), not to `low` as in the two RSS sensors.
URGENCY_BASE: dict = {"critical": 2.0, "high": 1.5, "medium": 1.0,
                      "low": 0.5}
URGENCY_DEFAULT = "medium"
#: `attack_type` defaults to **DDoS** — see the module docstring and
#: §3-5 H-4. Named as a constant so the hazard has somewhere to be
#: pointed at, and so changing it is a one-line, reviewable act.
TYPE_BONUS: dict = {"DDoS": 0.5, "combined": 0.5, "defacement": 0.3,
                    "data_leak": 0.2, "none": 0.0}
ATTACK_TYPE_DEFAULT = "DDoS"
SCORE_DIGITS = 1

#: The tags production strips before matching (`:184-186`). A feed that
#: wraps its summary in markup would otherwise hide every keyword inside
#: an attribute.
_TAG = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")


def dedup_key(source_name: str, title: str) -> str:
    """`_article_hash` (`:96-98`) — md5 of `hacknews-{source}-{title[:60]}`."""
    raw = f"hacknews-{source_name}-{str(title or '')[:60]}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()


def normalize_title(title: str) -> str:
    """`title.lower()[:60]` keeping alphanumerics (`:158`)."""
    return "".join(character for character in str(title or "")[:60].lower()
                   if character.isalnum())


def strip_markup(summary: str) -> str:
    """`re.sub("<[^>]+>", " ")` then whitespace-collapse (`:184-186`)."""
    text = _TAG.sub(" ", str(summary or ""))
    return _WHITESPACE.sub(" ", text).strip()


def published_timestamp(published_raw: str) -> float:
    """RFC822 first, then ISO-8601 (`:166-177`).

    The second attempt exists because two of the five wires publish Atom,
    whose `published` element is ISO-8601 — without it every Atom article
    dated to 0.0 and survived the age window by accident rather than by
    rule.
    """
    text = str(published_raw or "").strip()
    if not text:
        return 0.0
    from datetime import datetime, timezone
    moment = None
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, OverflowError):
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except (TypeError, ValueError, OverflowError):
            return 0.0
    if moment is None:
        return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def is_within_age_window(published_raw: str, now: float,
                         window_hours: int = ARTICLE_AGE_WINDOW_HOURS) -> bool:
    """`not (pub_ts > 0 and pub_ts < cutoff)` (`:180-181`)."""
    stamp = published_timestamp(published_raw)
    if stamp <= 0.0:
        return True
    return stamp >= now - window_hours * 3600.0


def is_discarded(text: str) -> bool:
    """The hard discard (`:190-191`), applied BEFORE the keyword gate."""
    lowered = str(text or "").lower()
    return any(keyword in lowered for keyword in DISCARD_KEYWORDS)


def matches_keyword(text: str) -> bool:
    """`any(kw in text_lower for kw in kw_lower)` (`:194`)."""
    lowered = str(text or "").lower()
    return any(keyword in lowered for keyword in HACKTIVIST_KEYWORDS)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One security wire -> up to five campaign candidates.

    Order is production's (`:138-205`):

      1. the normalised title enters the dedup set BEFORE any filter
      2. the 48h age window
      3. markup is stripped from the summary, and the STRIPPED text is
         what both gates read
      4. the marketing discard, FIRST — an "how to protect against DDoS
         campaigns" piece matches the campaign vocabulary without
         reporting one
      5. the hacktivist keyword requirement
      6. five articles, then stop

    Production reports ~2% keyword match against healthy feeds and its
    own comment says so (`:257-263`): that is the base rate, not a broken
    filter, and a port that widened the gate to "fix" the yield would be
    changing what the sensor measures.
    """
    result = parse.parse_feed(payload.body, http_status=payload.status,
                              content_type=payload.content_type)
    source_name = payload.label or "hacktivist_news"
    if not result.is_alive:
        return (ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=SENSOR_DOMAIN, country="",
            status=STATUS_NO_DATA, raw_score=0.0,
            value=f"{source_name}: {result.outcome}",
            flags={"feed": source_name, "outcome": result.outcome,
                   "detail": result.detail, "parse_stage": result.stage},
            evidence_url=payload.url),)

    organisation = str(NEWS_SOURCES.get(source_name, {}).get("org", ""))
    selected: list = []
    seen: set = set()
    for item in result.items:
        key = normalize_title(item.title)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        if not is_within_age_window(item.published_raw, context.now):
            continue
        summary = strip_markup(item.summary)
        text = f"{item.title} {summary}"
        if is_discarded(text):
            continue
        if not matches_keyword(text):
            continue
        selected.append({"title": item.title,
                         "summary": summary[:SUMMARY_CHARS],
                         "link": item.link,
                         "published": item.published_raw,
                         "org": organisation,
                         "dedup_key": dedup_key(source_name, item.title)})
        if len(selected) >= ARTICLE_LIMIT:
            break

    return tuple(
        ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=SENSOR_DOMAIN, country="",
            status=STATUS_OBSERVED, raw_score=0.0,
            value=article["title"][:200],
            flags={"feed": source_name, "article": article,
                   "awaiting": "llm_extraction",
                   "item_domain": ITEM_DOMAIN},
            evidence_url=article["link"] or payload.url)
        for article in selected)


# ── the LLM half ─────────────────────────────────────────────────────────

def prefilter(article) -> bool:
    return bool(str(article.get("title") or "").strip()
                or str(article.get("summary") or "").strip())


def prompt(article, context) -> tuple[str, str]:
    """Slot 2. `hacktivist_news_sensor.py:305-345`, transcribed.

    The IMPORTANT block is the one that matters most here: it tells the
    model the theatre list is CONTEXT ONLY and that an out-of-list country
    should still be returned because "the system will handle filtering".
    A9 is the record of the system not handling it, and the abolished
    discard is what makes this paragraph true rather than a promise.

    `theaters_str` is `"any"` when the union is empty (`:303`) — a word
    the model can read, rather than an empty list it would fill in.
    """
    theaters = context.get("theaters") or ()
    theaters_str = ", ".join(sorted(theaters)) if theaters else "any"
    system = (
        "You are a cyber threat intelligence analyst specializing in "
        "hacktivist groups and DDoS campaigns. Analyze this security "
        "news article for active hacktivist threat intelligence. "
        "Respond ONLY with a JSON object, no explanation.")
    user = (
        f"Today's date: {context.get('today', '')}\n"
        f"Source: {context.get('org', '')} security news\n"
        f"Active strategic theaters: {theaters_str}\n\n"
        f"Article:\n"
        f"{ex.sanitize(article.get('title', ''), TITLE_SANITIZE_CHARS)}\n"
        f"{ex.sanitize(article.get('summary', ''), SUMMARY_CHARS)}\n\n"
        "Return a JSON object:\n"
        "{\n"
        '  "headline": "One-sentence threat summary (max 100 chars)",\n'
        '  "is_active_campaign": true or false,\n'
        '  "group_name": "Hacktivist group name or unknown",\n'
        '  "theater": "ISO country code of PRIMARY target, or null",\n'
        '  "countries": ["ISO codes of ALL targeted countries"],\n'
        '  "country_weights": {"ISO": 0.0-1.0 relevance weight per country},\n'
        '  "attack_type": "DDoS|defacement|data_leak|combined|none",\n'
        '  "target_sector": "government|military|financial|telecom|'
        'energy|media|transport|healthcare|unknown",\n'
        '  "urgency": "critical|high|medium|low",\n'
        '  "confidence": 0.0\n'
        "}\n"
        "is_active_campaign = true ONLY if the article describes an "
        "ONGOING or RECENT (within 48h) hacktivist campaign — not a "
        "historical retrospective or generic trend piece.\n"
        "theater must be null if no specific target country is named.\n"
        "IMPORTANT: The 'active strategic theaters' list is for CONTEXT only. "
        "Do NOT force-assign a theater from that list. Assign theater based "
        "solely on the country ACTUALLY targeted in the article. If the "
        "targeted country is not in the list, still return its ISO code — "
        "the system will handle filtering.\n"
        "Confidence guide:\n"
        "- 0.80-0.95: Named group + named target + confirmed ongoing attack\n"
        "- 0.65-0.79: Named group + target country, attack reported\n"
        "- 0.40-0.64: Campaign mentioned but details vague\n"
        "- <0.40: No actionable intelligence")
    return system, user


def score_delta(data) -> float:
    """Slot 3. S1-SENSI-043 — `round(base + type_bonus, 1)` (`:417-424`).

    Both defaults are part of the arithmetic, and they are not the ones
    the sibling sensors use: `urgency` defaults to `medium` (1.0) rather
    than `low`, and `attack_type` defaults to **DDoS** (+0.5) rather than
    to nothing. See the module docstring — a malformed answer scores 1.5,
    which is more than a correctly-reported low-urgency data leak (0.7).
    """
    urgency = str(data.get("urgency") or "").strip().lower()
    matched = [key for key in URGENCY_BASE if key.lower() == urgency]
    base = URGENCY_BASE[matched[0]] if matched else URGENCY_BASE[
        URGENCY_DEFAULT]
    attack = str(data.get("attack_type") or "")
    if attack not in TYPE_BONUS:
        attack = ATTACK_TYPE_DEFAULT
    return round(base + TYPE_BONUS[attack], SCORE_DIGITS)


def headline_fallback(group_name: str, country: str) -> str:
    """`f"Hacktivist campaign: {group_name} / {theater}"` (`:441`).

    The `?` is production's own placeholder for an unnamed group
    (`data.get('group_name', '?')`), and it is kept: an item headlined
    "Hacktivist campaign: ? / TW" says the group was not identified,
    where "unknown" would read as a group called unknown.
    """
    return f"Hacktivist campaign: {group_name or '?'} / {country}"


#: EMPTY on purpose. This source has no `theater_link` field at all — the
#: prompt never asks for one (`:311-330`) — so `relevance_rules` must NOT
#: be attached: every rule set that declares `theater_link` drops an
#: answer that does not carry it, and attaching one here would discard
#: every item this sensor produces.
DISPOSITIONS: tuple = ()

PROFILE = ex.IntelProfile(
    source_type=SOURCE_TYPE,
    prefilter=prefilter, prompt=prompt, score_delta=score_delta,
    domain=ITEM_DOMAIN,
    dispositions=DISPOSITIONS,
    signal_field=SIGNAL_FIELD,
    signal_absent_reason=DROP_NOT_ACTIVE,
    llm_field_keys=("group_name", "attack_type", "target_sector", "urgency",
                    "source_org", "news_source"),
    max_tokens=MAX_TOKENS,
    schema_keys=("headline", "is_active_campaign", "group_name", "theater",
                 "countries", "country_weights", "attack_type",
                 "target_sector", "urgency", "confidence"))


HACKTIVIST_NEWS_ADAPTER = SourceAdapter(
    adapter_id=HACKTIVIST_NEWS, category=LLM,
    requests=tuple(
        RequestSpec(url=meta["url"], expect_content="xml",
                    headers={"User-Agent": USER_AGENT}, label=name)
        for name, meta in NEWS_SOURCES.items()),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="security_news_rss",
    knowledge_refs=("K08",),
    baseline_refs=("hacktivist_news_dedup",))

__all__ = ["HACKTIVIST_NEWS", "HACKTIVIST_NEWS_ADAPTER", "PROFILE",
           "normalize", "prefilter", "prompt", "score_delta",
           "headline_fallback", "dedup_key", "normalize_title",
           "strip_markup", "published_timestamp", "is_within_age_window",
           "is_discarded", "matches_keyword", "NEWS_SOURCES",
           "HACKTIVIST_KEYWORDS", "DISCARD_KEYWORDS", "ARTICLE_LIMIT",
           "ARTICLE_AGE_WINDOW_HOURS", "SUMMARY_CHARS", "USER_AGENT",
           "SIGNAL_SOURCE", "SOURCE_TYPE", "MAX_TOKENS", "SIGNAL_FIELD",
           "DROP_NOT_ACTIVE", "URGENCY_BASE", "URGENCY_DEFAULT",
           "TYPE_BONUS", "ATTACK_TYPE_DEFAULT", "DISPOSITIONS",
           "SENSOR_DOMAIN", "ITEM_DOMAIN"]
