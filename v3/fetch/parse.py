"""The ONE feed parser, with the death causes made explicit.

Design sheet §1-7. A-02 measured the alternative: RSS fetch/parse is
duplicated 4-5 times across the legacy sensors and **only `diplomatic` has
the tolerant two-stage parser**. The same malformed feed therefore parses
or does not depending on which sensor happened to fetch it — which is not
a property of the feed.

Two decisions carry the weight:

  * **Two stages, always.** `defusedxml` first (it refuses entity-expansion
    attacks, which an XML parser pointed at the open internet must), then
    `lxml` with `recover=True` for feeds that are merely broken. A feed
    being malformed is the normal case, not the exception: D1 §4 records
    JP_MOFA returning 404/WAF, CN_MFA returning HTML, RU_MFA geo-blocking
    and KCNA intermittently empty.
  * **A dead feed gets a cause, not an absence.** "Fetched and found
    nothing" and "has been returning an HTML error page for six weeks" are
    different facts, and collapsing them is how a source dies unnoticed.
    The cause lands in `fetch_log.outcome`, so the liveness ledger D1
    describes is a query rather than a second table.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Imported at module scope on purpose. Both were previously imported
# inside the parse function under a blanket `except Exception`, so a
# missing dependency was indistinguishable from a malformed feed: every
# recoverable feed would have been reported UNPARSEABLE and the recall
# loss would have been silent. `lxml` was in fact undeclared — present
# only as a transitive dependency of pytrends — so that was not a
# hypothetical. Now it is declared in requirements.txt and its absence
# stops the process at import.
from defusedxml import ElementTree as safe_etree
from defusedxml.common import DefusedXmlException
from lxml import etree

# ── outcomes (§1-7's five death causes, plus success) ────────────────────
OK = "ok"
RETURNS_HTML = "returns_html"
RSS_EMPTY = "rss_empty"
UNPARSEABLE = "unparseable"
HTTP_ERROR = "http_error"
GEO_BLOCK = "geo_block"
#: A payload that tried to make the parser do something. Distinct from
#: UNPARSEABLE because it is not a broken feed — it is an attack, and
#: burying it in an `unparseable` free-text detail loses the signal.
ENTITY_ATTACK = "entity_attack"

DEATH_CAUSES: frozenset = frozenset(
    {RETURNS_HTML, RSS_EMPTY, UNPARSEABLE, HTTP_ERROR, GEO_BLOCK,
     ENTITY_ATTACK})

STAGE_STRICT = "strict"
STAGE_RECOVER = "recover"
STAGE_NONE = "none"

# Markers that distinguish a geo-block from an ordinary 403. Kept short and
# lowercase; matched against a decoded prefix of the body.
_GEO_MARKERS = ("not available in your country", "geo", "region",
                "unavailable in your location")
_HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body")
_ITEM_TAGS = ("item", "entry")


@dataclass(frozen=True, slots=True)
class FeedItem:
    """One entry, with only the fields every feed dialect agrees on."""

    title: str = ""
    link: str = ""
    summary: str = ""
    guid: str = ""
    published_raw: str = ""


@dataclass(frozen=True, slots=True)
class ParseResult:
    """What the feed turned out to be."""

    outcome: str
    items: tuple[FeedItem, ...] = ()
    stage: str = STAGE_NONE
    detail: str = ""

    @property
    def is_alive(self) -> bool:
        return self.outcome == OK

    @property
    def is_dead(self) -> bool:
        """True for every classified death cause.

        `rss_empty` counts as dead here on purpose. An intermittently
        empty feed (KCNA) is a liveness problem, and the legacy system's
        habit of counting "fetched, zero items" as a plain success is what
        let it look healthy while producing nothing.
        """
        return self.outcome in DEATH_CAUSES


def _decoded_prefix(body: bytes, limit: int = 2048) -> str:
    return body[:limit].decode("utf-8", "replace").strip().lower()


def _looks_like_html(body: bytes) -> bool:
    prefix = _decoded_prefix(body, 512)
    return any(marker in prefix for marker in _HTML_MARKERS)


def _looks_geo_blocked(body: bytes) -> bool:
    prefix = _decoded_prefix(body)
    return any(marker in prefix for marker in _GEO_MARKERS)


def _local_name(tag) -> str:
    """Tag without its namespace. Atom and RSS differ only in namespace."""
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].lower()


def _text_of(element, *names: str) -> str:
    for child in element:
        if _local_name(getattr(child, "tag", "")) in names:
            if child.text:
                return child.text.strip()
            # Atom <link href="..."/> carries no text.
            href = child.get("href") if hasattr(child, "get") else None
            if href:
                return href.strip()
    return ""


def _items_from(root) -> tuple[FeedItem, ...]:
    collected = []
    for element in root.iter():
        if _local_name(getattr(element, "tag", "")) not in _ITEM_TAGS:
            continue
        collected.append(FeedItem(
            title=_text_of(element, "title"),
            link=_text_of(element, "link"),
            summary=_text_of(element, "description", "summary", "content"),
            guid=_text_of(element, "guid", "id"),
            published_raw=_text_of(element, "pubdate", "published",
                                   "updated", "date")))
    return tuple(collected)


def parse_feed(body: bytes, *, http_status: int = 200,
               content_type: Optional[str] = None) -> ParseResult:
    """Classify and parse one feed body. Never raises on bad input.

    Order matters: HTTP status is checked before content, because a 403
    that happens to contain valid XML is still a refusal, and a body that
    parses is not evidence the request succeeded.
    """
    if http_status == 451:
        return ParseResult(outcome=GEO_BLOCK,
                           detail="HTTP 451 (legally unavailable)")
    if http_status == 403 and _looks_geo_blocked(body):
        return ParseResult(outcome=GEO_BLOCK,
                           detail="HTTP 403 with a region marker in the body")
    if http_status >= 400:
        return ParseResult(outcome=HTTP_ERROR, detail=f"HTTP {http_status}")
    if not body.strip():
        return ParseResult(outcome=RSS_EMPTY, detail="empty body")
    if _looks_like_html(body) or (
            content_type and "html" in content_type.lower()):
        # CN_MFA retired its RSS and serves the website instead; the
        # request succeeds and contains no feed at all (D1 §4 K07).
        return ParseResult(outcome=RETURNS_HTML,
                           detail="body is an HTML document, not a feed")

    # ── stage 1: strict, and safe against entity expansion ──────────────
    try:
        root = safe_etree.fromstring(body)
        items = _items_from(root)
        return ParseResult(
            outcome=OK if items else RSS_EMPTY, items=items,
            stage=STAGE_STRICT,
            detail="" if items else "parsed, but contains no items")
    except DefusedXmlException as attack:
        # Short-circuit: an entity-expansion or external-reference payload
        # must NEVER reach stage 2. lxml with recover=True would happily
        # return a tree, the result would be reported OK, and the one
        # thing worth knowing — that an upstream sent a billion-laughs
        # bomb — would survive only as free text nobody reads.
        return ParseResult(
            outcome=ENTITY_ATTACK, stage=STAGE_STRICT,
            detail=f"{type(attack).__name__}: refused before recovery; "
                   f"this payload is hostile, not merely malformed")
    except Exception as strict_error:  # noqa: BLE001 - stage 2 decides
        strict_detail = f"{type(strict_error).__name__}: {strict_error}"

    # ── stage 2: recover what a merely-broken feed still contains ───────
    try:
        parser = etree.XMLParser(recover=True, resolve_entities=False,
                                 no_network=True)
        root = etree.fromstring(body, parser=parser)
        if root is None:
            return ParseResult(outcome=UNPARSEABLE, stage=STAGE_RECOVER,
                               detail=f"strict: {strict_detail}; "
                                      f"recover: produced no tree")
        items = _items_from(root)
        return ParseResult(
            outcome=OK if items else UNPARSEABLE, items=items,
            stage=STAGE_RECOVER,
            detail=(f"recovered after strict failure ({strict_detail})"
                    if items else
                    f"strict: {strict_detail}; recover: no items"))
    except Exception as recover_error:  # noqa: BLE001 - classified below
        return ParseResult(
            outcome=UNPARSEABLE, stage=STAGE_RECOVER,
            detail=f"strict: {strict_detail}; "
                   f"recover: {type(recover_error).__name__}: {recover_error}")


__all__ = ["parse_feed", "ParseResult", "FeedItem", "DEATH_CAUSES",
           "OK", "RETURNS_HTML", "RSS_EMPTY", "UNPARSEABLE", "HTTP_ERROR",
           "GEO_BLOCK", "ENTITY_ATTACK", "STAGE_STRICT", "STAGE_RECOVER",
           "STAGE_NONE"]
