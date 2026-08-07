"""`bg_observer_rss` — S1-SENSI-026..030. The wire, read without a model.

The one adapter that needs no key, no registration and no LLM: public RSS
over anonymous GET, a deterministic regex extractor (`kinetic.py`), and a
verdict that an air-gapped deployment can still reach (SENSI-026). It
exists because the intel pipeline's sources are UA/RU/IL-heavy, so the
Taiwan / Korea / South China Sea scenarios were receiving ~0 intel rows in
a 24h window — a geographic blind spot that looked like calm.

**Broadcast, not round-robin** (SENSI-027). Every fetched item is
evaluated against the WHOLE participant union, and one item that names
three participants produces three rows. The predecessor kept matches for
one country per cycle and discarded eight ninths of what it had already
paid to fetch; the gain from broadcasting is structural rather than
statistical, which is why it is a MUST rather than a tuning.

**DP1/B-01 disappears structurally.** Production owns a private daemon
thread (`bg_observer.py:144-155`) that never consults the breaker and
never reports success or failure to it, so the breaker for this sensor
is permanently closed and an RSS outage never throttles anything. There
is no thread here: §1-2 gives the composition root the threads and §1-5
gives the kernel the breaker, so the bypass has nowhere to live.

**A10 — "fetched and empty" is not a failure.** `_fetch_all` counts an
empty feed as `failed` (`background_observer.py:259-265`), which merges
"this feed returned zero items today" with "this feed has been serving an
HTML error page for six weeks". `classify_feed` returns §1-7's cause, and
the two are different outcomes rather than one counter.

**One row per country, per payload.** L1 is `UNIQUE (tick_id, sensor,
signal_source, country)` and SENSI-028 requires ONE `signal_source` for
every signal, so the N items that name one country in one feed cannot each
be a row. They are folded by MAX here — which is the fold
`dedup_by_source_country_max` (`radar/scoring.py:1424-1432`) applies
downstream anyway, so the score is unchanged. The fold across the nine
FEEDS still belongs to WP-4.1 (§7-2 #11's family), because `normalize`
sees one payload.
"""
from __future__ import annotations

from v3.adapters.info import kinetic
from v3.adapters.types import (AdapterId, INFO, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_FIRED)
from v3.fetch import parse
from v3.kernel import Window

BG_OBSERVER_RSS = AdapterId("bg_observer_rss")

#: The DEPLOYED feed ledger (`config.env:187`), not `config.py:654-661`'s
#: three-entry default.
#:
#: This distinction is the whole point. The default list is BBC / Al
#: Jazeera / AP — three Western wires — and the sensor exists to correct a
#: Western-source bias. The deployment adds SCMP, TASS, Xinhua, CNA, Japan
#: Times, Yonhap and Taipei Times, i.e. exactly the six that make the
#: Taiwan and Korea scenarios visible. Transcribing the code default would
#: have removed two thirds of the feeds and every non-Western one, and the
#: result would have read as "the wire is quiet about Taiwan".
#:
#: Pinned rather than read: nothing under `v3/` reads the environment
#: (O-18 rules that "register everything" is the wrong repair), and this
#: is the deployed value — the same basis on which `gdelt`'s tone
#: threshold is pinned.
#:
#: THREE ENTRIES ARE PLAINTEXT HTTP. `config.py:648-653` records that the
#: default list was made TLS-only precisely so a network-path adversary
#: could not inject RSS into the analysis pipeline — and the deployment
#: re-added three HTTP sources over that ruling, one of them the Xinhua
#: entry the comment says was removed for exactly this reason. Ported as
#: deployed and registered as a preserved defect (§7-2 #46) rather than
#: silently upgraded to `https://`: an upgrade that 404s would remove the
#: feed, which is the insensitive direction, and the scheme is a security
#: decision S4 owns. `PLAINTEXT_FEEDS` names them so the repair has a
#: list to work from rather than a re-audit.
FEEDS: tuple[str, ...] = (
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

#: The three that travel in the clear (§7-2 #46), named rather than
#: rediscovered.
PLAINTEXT_FEEDS: tuple[str, ...] = tuple(
    url for url in FEEDS if url.startswith("http://"))

#: `config.py:648-653`'s TLS-only default, kept as data so the suite can
#: assert the shipped ledger is the deployed one and not this.
CODE_DEFAULT_FEEDS: tuple[str, ...] = (
    "https://feeds.bbci.co.uk/news/world/rss.xml",
    "https://www.aljazeera.com/xml/rss/all.xml",
    "https://apnews.com/rss/apf-topnews",
)

#: `sensor="bg_observer_rss"`, `signal_source="bg_observer"`
#: (`background_observer.py:392-393`). They differ, and the ledger's dedup
#: identity is the SECOND one — SENSI-028 requires every signal to share
#: it so several articles about one country fold to one contribution.
SIGNAL_SOURCE = "bg_observer"

#: `User-Agent` and `Accept` from `background_observer.py:155,168`. The
#: agent string is not decoration: several of the nine wires answer a bare
#: urllib agent with 403, and a refused feed is indistinguishable from a
#: quiet one once the count reaches zero.
USER_AGENT = "Mozilla/5.0 (compatible; news-aggregator)"

#: `BG_OBSERVER_INTERVAL_SEC` = 300 (`config.env:184`, and the code
#: default agrees).
_CADENCE = Window.from_days(1.0, cadence_sec=300.0)
#: `BG_OBSERVER_SIGNAL_TTL_SEC` = 1800 (`config.env:185`). In production
#: this is the lifetime of an entry in a process-memory deque; here it is
#: the L1 freshness horizon, which is the same fact told to a store that
#: survives a restart. SENSI-029 records why the number matters: an
#: implementation that emptied the buffer on read gave signals a real life
#: of one scoring tick, the documented 30 minutes was fiction, and the
#: 5-minute cycle aliased against the 2-minute tick until the focused
#: scenario's TL strobed between TL4 and TL5.
_FRESHNESS_HORIZON_SEC = 1800.0

#: `background_observer.py:356` composes the analysed text this way, and
#: the separator is added unconditionally — an item with no summary ends
#: in a dangling em dash after `.strip()`. Reproduced because the excerpt
#: is capped at 240 characters and a different separator shifts the cut.
_TEXT_SEPARATOR = " — "


def item_text(title: str, summary: str) -> str:
    """`(title + " — " + summary).strip()` — `background_observer.py:356`."""
    return f"{title or ''}{_TEXT_SEPARATOR}{summary or ''}".strip()


def classify_feed(payload) -> str:
    """§1-7's death cause for one feed body, or `ok`.

    Exported because the fetch kernel writes `fetch_log.outcome` and this
    is the classification that belongs there: A10's repair is that
    "returned zero items" and "has been serving HTML since June" stop
    being one counter. WP-4.1 wires it (§7-2 #45); calling `parse_feed`
    twice would be a second parse of the same bytes, so the runner is
    given the function rather than the adapter given a ledger handle.
    """
    return parse.parse_feed(payload.body, http_status=payload.status,
                            content_type=payload.content_type).outcome


def _display(match) -> str:
    """`background_observer.py:394-397`, character for character."""
    return (f"rss:{match.country} fatalities={match.fatalities} "
            f"conf={match.confidence:.2f}")


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One feed body -> at most one row per participant it named.

    A dead feed produces NO rows. Production's answer to a dead feed is a
    `feeds_failed` counter in the cycle record, never a signal, and
    inventing an observation here would put a row in the ledger that the
    system it is being compared against never emits. The cause is not
    lost: `classify_feed` names it for `fetch_log`.
    """
    result = parse.parse_feed(payload.body, http_status=payload.status,
                              content_type=payload.content_type)
    if not result.is_alive:
        return ()

    participants = tuple(context.countries)
    if not participants:
        # SENSI-027: a cycle with no participants is recorded with a
        # reason and fetches nothing. There is nothing to attribute a
        # story to, and attributing it to "everyone" is the Phase 9-E
        # attribution pollution in another costume.
        return ()

    # country -> (raw_score, match, link). MAX per country, which is the
    # fold `dedup_by_source_country_max` applies downstream regardless.
    best: dict = {}
    seen_items = 0
    for item in result.items:
        text = item_text(item.title, item.summary)
        if not text:
            continue
        seen_items += 1
        for match in kinetic.extract_all(text,
                                         allowed_countries=participants):
            score = kinetic.raw_score(match)
            current = best.get(match.country)
            if current is None or score > current[0]:
                best[match.country] = (score, match, item.link)

    drafts = []
    for country in sorted(best):
        score, match, link = best[country]
        drafts.append(ObservationDraft(
            signal_source=SIGNAL_SOURCE, domain=INFO, country=country,
            # FIRED for every match. Production enqueues a Signal for
            # every match and the scoring layer admits it — there is no
            # OBSERVED tier here and no baseline being waited on, which
            # is what makes this adapter useful while the L1 wiring for
            # the others is still pending.
            status=STATUS_FIRED, raw_score=score,
            value=_display(match), reason=match.summary,
            flags={
                "fatalities": match.fatalities,
                "extractor_confidence": match.confidence,
                "extractor": match.source,
                "summary": match.summary,
                "items_in_feed": seen_items,
                # SENSI-030: the coverage gap is reported, never fatal. A
                # participant with no alias produces no match, and the
                # only way to tell that apart from "the wire said nothing
                # about them" is to publish the gap.
                "alias_gap": list(kinetic.uncovered(participants)),
            },
            # NP6: the story behind the number. Production drops the link
            # (`evidence_url=None`, `background_observer.py:398`) and
            # keeps only the display string, so an analyst cannot reach
            # the article the score came from. §7-2 #47.
            evidence_url=link or payload.url))
    return tuple(drafts)


def _feed_request(url: str) -> RequestSpec:
    """One wire. The label is the URL so `fetch_log` names the feed."""
    return RequestSpec(url=url, expect_content="any",
                       headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
                       label=f"feed:{url}")


BG_OBSERVER_RSS_ADAPTER = SourceAdapter(
    adapter_id=BG_OBSERVER_RSS, category=INFO,
    requests=tuple(_feed_request(url) for url in FEEDS),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="bg_observer_rss",
    knowledge_refs=("K08",))

__all__ = ["BG_OBSERVER_RSS", "BG_OBSERVER_RSS_ADAPTER", "normalize",
           "classify_feed", "item_text", "FEEDS", "CODE_DEFAULT_FEEDS",
           "PLAINTEXT_FEEDS", "SIGNAL_SOURCE", "USER_AGENT"]
