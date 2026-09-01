"""`telegram_mirror` — S1-SENSI-012..018, D1 §4 K13. The public preview.

`t.me/s/{channel}` serves a channel's recent posts as HTML with no login
and no phone number, which is the whole reason this sensor exists. What
it reads is hacktivist target declarations: URLs, attack verbs, and the
frequency of both.

**DP6 — the twin of F-06, and the reason this port exists as written.**
Production capped the z-score baseline at `NARRATIVE_BASELINE_DAYS`
ENTRIES while polling every 900 seconds, so a declared 30-day window held
30 samples — about seven and a half hours. The z-score normalised a burst
against the burst, and the sensor could not see the thing it measures.
Production repaired it on 2026-08-07 by multiplying days by cycles per
day; v3 expresses the window as a kernel `Window` instead, so the same
mistake cannot be spelled: `Window.from_days(30, cadence_sec=900)` KNOWS
how many samples that is (`BASELINE_WINDOW.effective_samples`), and a
count and a duration can never disagree again.

**K13 — the preview is defended, and the defence is data.** A bare
library user-agent draws 403; the sensor rotates through five realistic
strings and backs off exponentially on 403/429
(`radar/sensors/telegram.py:41-48, 87-119`). In v3 the pool is DECLARED
here and the retry/backoff is the kernel's (§1-5, `v3/fetch/policy.py`) —
"how to fetch" is exactly what an adapter may not write. The rotation
across the pool needs a per-request choice the declaration model has no
slot for, so it lands with the composition root (§7-2 #50).

**Three ways to read nothing, and production tells them apart.** A
redirect that lost its `/s/` segment means the channel admin disabled the
preview (the channel list is stale); 403/429 means Telegram is
throttling; an exception means the network is broken. Before 2026-04-29
all three returned `""` and were indistinguishable — the same shape as
every silence NP1 is written against.

**One payload is one CHANNEL; production reports per THEATER.** The
z-score, the four-way status ladder and the staged claim confidence all
need the channels of a theatre joined together, and `normalize` sees one
body (§2-2 barrier 1). Each channel lands under its own `signal_source`
because L1 is `UNIQUE (tick_id, sensor, signal_source, country)` and two
rows under one name with matching scores are dropped in SILENCE
(`store.py:290`). §7-2 #51; WP-4.1's reduction retires it.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime

from v3.adapters.types import (AdapterId, INFO, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.kernel import Window

TELEGRAM_MIRROR = AdapterId("telegram_mirror")

#: `TELEGRAM_PREVIEW_URL` (`radar/sensors/telegram.py:57`). The `/s/`
#: segment is the whole trick: without it the URL serves the app-install
#: page rather than the posts.
PREVIEW_URL = "https://t.me/s/{channel}"

#: **K13.** `_SCRAPER_UA_POOL` (`:41-48`), all five, in order. These are
#: not decoration: `t.me` answers a library user-agent with 403, and a
#: 403 that leaves the previous reading in place is indistinguishable
#: from a channel that went quiet.
USER_AGENT_POOL: tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 "
    "Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
)
#: `Accept-Language` travels with the agent (`:97`).
ACCEPT_LANGUAGE = "en-US,en;q=0.9"

#: `TELEGRAM_ATTACK_KEYWORDS` (`:17-21`), the deployed default. The
#: matching RULES matter as much as the list: a two-character keyword is
#: skipped entirely (`"op"` matched everything), a phrase or a hashtag is
#: matched as a substring, and a bare word is matched on `\b` boundaries
#: so "target" does not fire on "targeting" (`:196-206`).
ATTACK_KEYWORDS: tuple[str, ...] = (
    "target", "attack", "ddos", "http flood", "under attack", "down",
    "offline", "op", "#target",
)
#: `if len(kw) <= 2: continue` (`:198`).
MIN_KEYWORD_LENGTH = 3

#: `TELEGRAM_POST_MAX_AGE_H` (`:30`). Raised from 8h to 48h on
#: 2026-04-29 because hacktivist channels post in bursts then go silent
#: for 24-72h, and an 8h window dropped **100%** of posts on every
#: currently-active channel while the channels themselves were healthy.
POST_MAX_AGE_HOURS = 48

#: `_MIN_CONTENT_LEN` (`:76`) and the marker a real post page carries
#: (`:110`). A page under the threshold, or one without the marker, is a
#: login gate or an empty channel rather than a quiet one.
MIN_CONTENT_LEN = 2000
POST_MARKER = "tgme_widget_message_wrap"

#: The government-target patterns (`:185-188`), and the narrower set the
#: staged confidence uses (`:437-440`). They DIFFER — the second has only
#: three entries — and collapsing them would raise the confidence of a
#: bank or telecom target to a government one.
GOV_TARGET_PATTERNS: tuple[str, ...] = (
    ".gov", ".mil", ".parliament", ".bundestag", ".elysee", ".president",
    "bank", "energy", "telecom",
)
GOV_CONFIDENCE_PATTERNS: tuple[str, ...] = (".gov", ".mil", ".parliament")
#: `gov_targets[:10]` (`:210`).
TARGET_LIMIT = 10

#: The staged claim confidence (`:37-40`). Each stage is a different kind
#: of corroboration, which is why they are separate numbers rather than a
#: single threshold.
CONF_DECLARATION_ONLY = 0.2
CONF_WITH_GOV_TARGETS = 0.4
CONF_WITH_ZSCORE_BURST = 0.6
#: `TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD` (`:22`).
CLAIM_CONFIDENCE_THRESHOLD = 0.5

#: `NARRATIVE_ZSCORE_ALERT` / `_CRITICAL` (`radar/config.py:358-359`).
ZSCORE_ALERT = 2.0
ZSCORE_CRITICAL = 3.0
#: `_compute_zscore_tg` refuses under seven samples (`:277`).
ZSCORE_MIN_SAMPLES = 7

#: `TELEGRAM_MIRROR_POLL` (`:16`).
_CADENCE = Window.from_days(1.0, cadence_sec=900.0)
_FRESHNESS_HORIZON_SEC = 2 * 3600.0

#: **DP6, expressed by type.** `NARRATIVE_BASELINE_DAYS` = 30
#: (`radar/config.py:360`) at the 900s cadence. Production had to compute
#: `days * cycles_per_day` by hand at the one call site that truncates the
#: list, and got it wrong for as long as the sensor existed; here the
#: window IS both facts and `effective_samples` derives one from the
#: other. F-06 and DP6 are the same defect twice, and this is the type
#: that makes it unspellable.
BASELINE_DAYS = 30
BASELINE_WINDOW = Window.from_days(BASELINE_DAYS, cadence_sec=900.0)

SIGNAL_SOURCE = "telegram_mirror"
#: Per-channel row names. §7-2 #51: a CONSTRAINT, not a choice — L1
#: refuses two rows under one name in one tick, and when their scores
#: match (the quiet case) it drops the second in silence rather than
#: raising. Retired when WP-4.1's reduction folds channels into the
#: per-theatre row production reports.
CHANNEL_SOURCE_PREFIX = "telegram_"

_MESSAGE_SPLIT = re.compile(r'<div[^>]*class="[^"]*tgme_widget_message_wrap')
_TIME_ATTR = re.compile(r'<time[^>]*datetime="([^"]+)"')
_MESSAGE_TEXT = re.compile(
    r'<div[^>]*class="[^"]*tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
    re.DOTALL)
_TAG = re.compile(r"<[^>]+>")
_ENTITY = re.compile(r"&[a-zA-Z0-9#]+;")
_WHITESPACE = re.compile(r"\s+")
_URL = re.compile(r'https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s<"\']*)?')

#: `text[:1500].strip()` (`:371`) and the snippet geometry (`:220-230`).
EXCERPT_CHARS = 1500
SNIPPET_LEAD = 60
SNIPPET_TRAIL = 100

#: `det_status` (`:376-377`).
INTENT_DETECTED = "INTENT_DETECTED"
TARGETS_FOUND = "TARGETS_FOUND"
CLEAR = "CLEAR"

#: The reason a body carries no posts. Distinct values because production
#: distinguishes them in its log and NOT in its return value (`:80-119`) —
#: which is the half of the repair that was missing.
PREVIEW_DISABLED = "preview_disabled_by_admin"
NO_POST_CONTENT = "no_post_content"
TOO_SHORT = "body_below_min_content_len"
NO_RECENT_POSTS = "no_posts_within_window"


def channel_source(channel: str) -> str:
    return f"{CHANNEL_SOURCE_PREFIX}{channel}"


def parse_posts(html: str, now: float,
                max_age_hours: int = POST_MAX_AGE_HOURS) -> tuple:
    """`_parse_html_posts` (`:127-174`) — `({"text","ts"}, ...)`.

    Three details are load-bearing. The split is on the message-wrapper
    div, so a post is delimited by markup rather than by a parser. A post
    with no `<time datetime=...>` is SKIPPED, not dated to now — an
    undatable post would otherwise always be inside the window. And when
    the text div is missing, the WHOLE part is used as the text
    (`raw_text = text_match.group(1) if text_match else part`), which
    keeps a post whose markup changed rather than losing it.

    The text is lower-cased here, and every downstream comparison relies
    on that: the keyword ledger is lower case and nothing lowers it again.
    """
    cutoff = now - max_age_hours * 3600
    posts: list = []
    for part in _MESSAGE_SPLIT.split(html or "")[1:]:
        stamp = _TIME_ATTR.search(part)
        if not stamp:
            continue
        try:
            moment = datetime.fromisoformat(
                stamp.group(1).replace("Z", "+00:00")).timestamp()
        except (ValueError, OSError):
            continue
        if moment < cutoff:
            continue
        found = _MESSAGE_TEXT.search(part)
        raw = found.group(1) if found else part
        clean = _WHITESPACE.sub(
            " ", _ENTITY.sub(" ", _TAG.sub(" ", raw))).lower().strip()
        if clean:
            posts.append({"text": clean, "ts": moment})
    return tuple(posts)


def keyword_hit(text: str, keyword: str) -> bool:
    """`:200-206`. A phrase or hashtag matches as a substring; a bare word
    matches on `\\b` boundaries so "target" does not fire on "targeting"."""
    if len(keyword) <= MIN_KEYWORD_LENGTH - 1:
        return False
    if " " in keyword or keyword.startswith("#"):
        return keyword in text
    return bool(re.search(r"\b" + re.escape(keyword) + r"\b", text))


def matched_keywords(text: str,
                     keywords: tuple = ATTACK_KEYWORDS) -> tuple:
    return tuple(keyword for keyword in keywords
                 if keyword_hit(text, keyword))


def count_keyword_hits(text: str,
                       keywords: tuple = ATTACK_KEYWORDS) -> int:
    """`_count_keyword_hits` (`:328-337`) — the z-score's numerator.

    Counts OCCURRENCES, not keywords: a post naming ten targets is ten
    hits. The phrase branch uses `str.count` and the word branch uses
    `re.findall`, which is production's asymmetry and is preserved.
    """
    total = 0
    for keyword in keywords:
        if len(keyword) <= MIN_KEYWORD_LENGTH - 1:
            continue
        if " " in keyword or keyword.startswith("#"):
            total += text.count(keyword)
        else:
            total += len(re.findall(r"\b" + re.escape(keyword) + r"\b", text))
    return total


def government_targets(text: str) -> tuple:
    """`_parse_posts`'s URL half (`:183-189`, `:210`).

    The pattern list includes `bank`, `energy` and `telecom`, so
    "government targets" here means critical infrastructure broadly. The
    STAGED CONFIDENCE uses a narrower list of three, and the two are kept
    apart on purpose.
    """
    urls = _URL.findall(text or "")
    hits = [url for url in urls
            if any(pattern in url for pattern in GOV_TARGET_PATTERNS)]
    return tuple(hits[:TARGET_LIMIT])


def has_government_confidence_target(targets) -> bool:
    """`:437-440` — the NARROW list. A bank is a target; a ministry is
    corroboration."""
    return any(any(pattern in url for pattern in GOV_CONFIDENCE_PATTERNS)
               for url in targets)


def snippet(text: str, keywords) -> str:
    """`_extract_snippet` (`:212-231`) — 60 characters of lead, 100 of
    trail, whitespace collapsed, wrapped in ellipses. The FIRST matching
    keyword wins, in the order given."""
    for keyword in keywords:
        if len(keyword) <= MIN_KEYWORD_LENGTH - 1:
            continue
        if " " in keyword or keyword.startswith("#"):
            found = re.search(re.escape(keyword), text)
        else:
            found = re.search(r"\b" + re.escape(keyword) + r"\b", text)
        if found:
            start = max(0, found.start() - SNIPPET_LEAD)
            end = min(len(text), found.start() + len(keyword) + SNIPPET_TRAIL)
            return f"...{_WHITESPACE.sub(' ', text[start:end].strip())}..."
    return ""


def detection_status(has_intent: bool, targets) -> str:
    """`:376-377`. Intent outranks targets; neither is CLEAR."""
    if has_intent:
        return INTENT_DETECTED
    if targets:
        return TARGETS_FOUND
    return CLEAR


def theater_status(z_score: float, has_intent: bool, has_targets: bool
                   ) -> str:
    """The four-way ladder (`:420-431`), exported for WP-4.1's reduction.

    A burst OUTRANKS a declaration: frequency corroborates in a way a
    single post cannot. The join that can evaluate it needs every channel
    of a theatre plus the L1 baseline, so it is not called here — but it
    must not be written twice, which is what DP4 cost.
    """
    if z_score >= ZSCORE_CRITICAL:
        return "CRITICAL_BURST"
    if z_score >= ZSCORE_ALERT:
        return "BURST"
    if has_intent:
        return INTENT_DETECTED
    if has_targets:
        return TARGETS_FOUND
    return CLEAR


def claim_confidence(is_burst: bool, has_intent: bool,
                     gov_target_found: bool) -> float:
    """The staged confidence (`:441-449`), exported for the same reason.

    Zero when nothing was declared — not a floor, an absence. Production
    rounds to three places at the call site (`:462`).
    """
    if is_burst:
        return CONF_WITH_ZSCORE_BURST
    if has_intent and gov_target_found:
        return CONF_WITH_GOV_TARGETS
    if has_intent:
        return CONF_DECLARATION_ONLY
    return 0.0


def content_hash(channel: str, country: str, snippet_text: str,
                 targets) -> str:
    """`_log_detection`'s dedup fingerprint (`:245-249`).

    sha256 of `channel:theater:snippet[:200]:first-five-targets`, first 32
    hex characters. Reproduced exactly because it is what suppresses a
    pinned post from being re-logged every fifteen minutes, and a
    different fingerprint means the ledger fills with one post.
    """
    raw = (f"{channel}:{country}:{str(snippet_text or '')[:200]}:"
           f"{','.join(list(targets)[:5])}")
    return hashlib.sha256(raw.encode(),
                          usedforsecurity=False).hexdigest()[:32]


def _no_data(channel: str, url: str, reason: str) -> ObservationDraft:
    return ObservationDraft(
        signal_source=channel_source(channel), domain=INFO, country="",
        status=STATUS_NO_DATA, raw_score=0.0, value=f"{channel}: {reason}",
        flags={"channel": channel, "reason": reason}, evidence_url=url)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One channel preview -> one evidence row.

    The verdict is NOT reached here. The status ladder starts with a
    z-score against a 30-day baseline this layer does not hold, and the
    aggregation is per THEATRE across channels — both belong to WP-4.1
    (§7-2 #9 and #11's families). What lands is what was measured: the
    keyword hits, the government targets, the snippet, and the per-channel
    detection status, which needs nothing but this body.
    """
    channel = str(payload.label or "").split(":", 1)[-1].strip()
    if not channel:
        return ()
    body = payload.text()

    if payload.status in (403, 429):
        # K13: Telegram throttling, which the kernel retries with backoff.
        # Reported as its own cause because "we were refused" and "the
        # channel is quiet" are different facts.
        return (_no_data(channel, payload.url, f"http_{payload.status}"),)
    if payload.status >= 400:
        return (_no_data(channel, payload.url, f"http_{payload.status}"),)
    if "/s/" not in payload.url and payload.url.rstrip("/").endswith(
            f"/{channel}"):
        # The admin disabled the web preview and `t.me/s/x` redirected to
        # `t.me/x`. The channel LIST is stale, which is an operator
        # action, not an outage (`:101-107`).
        return (_no_data(channel, payload.url, PREVIEW_DISABLED),)
    if len(body) <= MIN_CONTENT_LEN:
        return (_no_data(channel, payload.url, TOO_SHORT),)
    if POST_MARKER not in body:
        return (_no_data(channel, payload.url, NO_POST_CONTENT),)

    posts = parse_posts(body, context.now)
    if not posts:
        return (_no_data(channel, payload.url, NO_RECENT_POSTS),)

    text = " ".join(post["text"] for post in posts)
    targets = government_targets(text)
    keywords = matched_keywords(text)
    hits = count_keyword_hits(text)
    has_intent = bool(keywords)
    status = detection_status(has_intent, targets)
    excerpt = text[:EXCERPT_CHARS].strip()
    # `snippet` is computed only when there is something to point at
    # (`:373`), and it falls back to the FULL keyword ledger when nothing
    # matched but a target did.
    evidence = (snippet(text, keywords or ATTACK_KEYWORDS)
                if (has_intent or targets) else "")

    return (ObservationDraft(
        signal_source=channel_source(channel), domain=INFO, country="",
        # OBSERVED: the four-way ladder needs the z-score, and the
        # z-score needs a 30-day baseline L1 does not yet supply. OK here
        # would read as "measured, nothing wrong" on a channel that may
        # be mid-burst.
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"{channel}: {status} hits={hits}",
        flags={
            "channel": channel,
            "detection_status": status,
            "keywords_matched": list(keywords),
            "keyword_hits": hits,
            "target_urls": list(targets),
            "gov_confidence_target": has_government_confidence_target(
                targets),
            "snippet": evidence,
            "text_excerpt": excerpt,
            "posts_in_window": len(posts),
            "content_hash": content_hash(channel, "", evidence, targets),
            # §7-2 #9's discipline: the keys a consumer reads as their
            # declared types stay ABSENT, and a sibling names why.
            "burst_verdict": "pending_l1_telegram_baseline",
            "claim_confidence_verdict": "pending_wp41_theater_join",
        },
        evidence_url=payload.url),)


TELEGRAM_MIRROR_ADAPTER = SourceAdapter(
    adapter_id=TELEGRAM_MIRROR, category=INFO,
    requests=(
        RequestSpec(url=PREVIEW_URL, expect_content="any",
                    headers={"User-Agent": USER_AGENT_POOL[0],
                             "Accept-Language": ACCEPT_LANGUAGE},
                    label="channel:{channel}"),),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="telegram_preview",
    knowledge_refs=("K13",),
    baseline_refs=("telegram_keyword_frequency",))

__all__ = ["TELEGRAM_MIRROR", "TELEGRAM_MIRROR_ADAPTER", "normalize",
           "parse_posts", "keyword_hit", "matched_keywords",
           "count_keyword_hits", "government_targets",
           "has_government_confidence_target", "snippet",
           "detection_status", "theater_status", "claim_confidence",
           "content_hash", "channel_source",
           "PREVIEW_URL", "USER_AGENT_POOL", "ACCEPT_LANGUAGE",
           "ATTACK_KEYWORDS", "MIN_KEYWORD_LENGTH", "POST_MAX_AGE_HOURS",
           "MIN_CONTENT_LEN", "POST_MARKER", "GOV_TARGET_PATTERNS",
           "GOV_CONFIDENCE_PATTERNS", "TARGET_LIMIT",
           "CONF_DECLARATION_ONLY", "CONF_WITH_GOV_TARGETS",
           "CONF_WITH_ZSCORE_BURST", "CLAIM_CONFIDENCE_THRESHOLD",
           "ZSCORE_ALERT", "ZSCORE_CRITICAL", "ZSCORE_MIN_SAMPLES",
           "BASELINE_DAYS", "BASELINE_WINDOW", "SIGNAL_SOURCE",
           "CHANNEL_SOURCE_PREFIX", "EXCERPT_CHARS",
           "INTENT_DETECTED", "TARGETS_FOUND", "CLEAR",
           "PREVIEW_DISABLED", "NO_POST_CONTENT", "TOO_SHORT",
           "NO_RECENT_POSTS"]
