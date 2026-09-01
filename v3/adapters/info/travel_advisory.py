"""`travel_advisory` — S1-SENSI-022..025, D1 §4 K20. Three governments.

Three states publish travel advisories in three formats, and the reason
to read all three is INDEPENDENCE: when Washington, London and Ottawa
raise a country's level in the same week, the raise is not a domestic
political act. A single-source upgrade is noted as possibly one.

**K20 — three governments, three formats.** US State publishes RSS, the
UK FCDO publishes Atom, and Canada GAC DISCONTINUED its feed, so its
advisories are scraped out of an HTML table (`_SOURCES`,
`radar/sensors/travel_advisory.py:31-48`). Each has its own level
vocabulary and its own mapping onto the 1-4 scale — the UK never says
"level 3", it says "advise against all but essential travel" — and a
port that reads one vocabulary against another source reports zero
advisories from a feed that is working.

**A3 — the fallback this port ABOLISHES (裁定要求 4, ruled).** The FCDO
parser ends with `if "travel" in text_lower: return 2` (`:341-343`),
which matches almost every entry in a feed whose every title contains the
word "travel". The result is a level-2 advisory manufactured for
practically every country the UK publishes, and those fabricated levels
enter the convergence count — where NP2 says a false corroboration is
worse than none, because it makes a single source look like two. v3
returns 0 (`UNKNOWN`). §7-2 #4, direction **insensitive**, and it is the
one entry in the register that could touch C-02/C-03: the ruling
(§9 裁定 4) is that a parser-gives-up verdict is noise, not recall.

**A1 — the first sighting can never be an upgrade.** `prev.get(code,
level)` seeds the previous level with the CURRENT one (`:129`, `:288`),
so `upgraded` is False the first time a country is seen and after every
restart. **A2 — and the memory is a process dictionary** (`:76-78`), so
"every restart" means "every deploy". Both are declared as an L1 baseline
here and the verdict is withheld rather than computed against a default
that manufactures calm (§7-2 #9's family).
"""
from __future__ import annotations

import re

from v3.adapters.types import (AdapterId, INFO, NormalizeContext,
                               ObservationDraft, RequestSpec, SourceAdapter,
                               STATUS_NO_DATA, STATUS_OBSERVED)
from v3.kernel import Window

TRAVEL_ADVISORY = AdapterId("travel_advisory")

#: `_SOURCES` (`:31-48`). The `accept` header is per-source because the
#: three formats differ, and Canada is a scrape rather than a feed.
SOURCES: dict = {
    "US": {
        "name": "US State Department",
        "url": "https://travel.state.gov/_res/rss/TAsTWs.xml",
        "accept": "application/xml, text/xml, */*",
    },
    "UK": {
        "name": "UK FCDO",
        "url": "https://www.gov.uk/foreign-travel-advice.atom",
        "accept": "application/atom+xml, application/xml, */*",
    },
    "CA": {
        "name": "Canada GAC",
        "url": "https://travel.gc.ca/travelling/advisories",
        "accept": "text/html, */*",
        "html_scrape": True,
    },
}

#: `_FCDO_LEVEL_MAP` (`:51-56`). Both the singular and plural verb forms
#: are listed because the FCDO uses both, and dropping either halves what
#: the UK source detects.
FCDO_LEVEL_MAP: dict = {
    "advise against all travel": 4,
    "advise against all but essential travel": 3,
    "advises against all travel": 4,
    "advises against all but essential travel": 3,
}
#: `_GAC_LEVEL_MAP` (`:59-64`).
GAC_LEVEL_MAP: dict = {
    "avoid all travel": 4,
    "avoid non-essential travel": 3,
    "exercise a high degree of caution": 2,
    "take normal security precautions": 1,
}
#: The GAC icon filenames (`:258-263`) — the level is encoded twice, and
#: the icon is what survives a wording change in the table.
GAC_ICON_LEVEL_MAP: dict = {
    "do-not-travel": 4,
    "reconsider-travel": 3,
    "increased-caution": 2,
    "normal-precautions": 1,
}
#: FCDO severity hints (`:337-340`), which run BEFORE the abolished
#: fallback and are kept.
FCDO_EXTREME_HINTS: tuple[str, ...] = ("extreme risk", "war zone",
                                       "armed conflict")
FCDO_HIGH_HINTS: tuple[str, ...] = ("high risk", "significant risk")

LEVEL_LABELS: dict = {
    1: "NORMAL_PRECAUTIONS",
    2: "INCREASED_CAUTION",
    3: "RECONSIDER_TRAVEL",
    4: "DO_NOT_TRAVEL",
}
UNKNOWN_LABEL = "UNKNOWN"

#: S1-SENSI-025's two thresholds, both hard-coded in production.
CONVERGENCE_MIN_SOURCES = 2
CONVERGENCE_MIN_LEVEL = 3

#: `super().__init__("travel_advisory", "info", 3600)` (`:74`).
_CADENCE = Window.from_days(1.0, cadence_sec=3600.0)
_FRESHNESS_HORIZON_SEC = 24 * 3600.0

SIGNAL_SOURCE = "travel_advisory"
#: Per-source row names. §7-2 #51's family and a CONSTRAINT: one country
#: is reported by all three governments in one tick, and L1 is
#: `UNIQUE (tick_id, sensor, signal_source, country)`. Production folds
#: the three BEFORE naming the entry, so there is no name to borrow.
SOURCE_PREFIX = "advisory_"

#: `title[:200]` (`:133`).
TITLE_CHARS = 200

_GAC_ROW = re.compile(
    r'<tr[^>]*>.*?'
    r'<a\s+href="/destinations/[^"]*">([^<]+)</a>'
    r'.*?</td>\s*<td[^>]*>([^<]+)</td>'
    r'\s*<td[^>]*>([^<]*)</td>'
    r'.*?</tr>',
    re.DOTALL | re.IGNORECASE)


def source_of(label: str) -> str:
    return str(label or "").split(":", 1)[-1].strip().upper()


def row_source(source_key: str) -> str:
    return f"{SOURCE_PREFIX}{source_key.lower()}"


def level_label(level: int) -> str:
    """`_level_label` (`:365-373`). Anything outside 1-4 is UNKNOWN — and
    with A3 abolished, UNKNOWN is now reachable, which is the point."""
    return LEVEL_LABELS.get(level, UNKNOWN_LABEL)


def extract_tag(xml: str, tag: str) -> str:
    """`_extract_tag` (`:301-313`), CDATA unwrapping included.

    A string search rather than a parse, transcribed as production has it:
    it takes the FIRST occurrence of the tag in the item fragment, which
    is what makes an Atom `<title>` inside a nested element pick the outer
    one. Replacing it with a real parser would change which text is read.
    """
    start = xml.find(f"<{tag}>")
    end = xml.find(f"</{tag}>")
    if start < 0 or end <= start:
        return ""
    content = xml[start + len(tag) + 2:end]
    if content.startswith("<![CDATA["):
        content = content[9:]
        if content.endswith("]]>"):
            content = content[:-3]
    return content.strip()


def parse_level_us(text: str) -> int:
    """`_parse_level` (`:316-327`) — the numeral OR the phrase.

    Both arms matter: the RSS title carries "Level 3: Reconsider Travel"
    but a re-issued advisory sometimes carries only the phrase.
    """
    upper = str(text or "").upper()
    if "LEVEL 4" in upper or "DO NOT TRAVEL" in upper:
        return 4
    if "LEVEL 3" in upper or "RECONSIDER TRAVEL" in upper:
        return 3
    if "LEVEL 2" in upper or "INCREASED CAUTION" in upper:
        return 2
    if "LEVEL 1" in upper or "NORMAL PRECAUTIONS" in upper:
        return 1
    return 0


def parse_level_fcdo(text: str) -> int:
    """`_parse_level_fcdo` (`:330-344`) **without its last fallback**.

    A3 / 裁定要求 4, ruled. Production ends with
    `if "travel" in text_lower: return 2` — and every entry in a feed
    called "foreign travel advice" contains the word. The effect is a
    level-2 advisory manufactured for practically every country the UK
    publishes, and those levels are counted as CORROBORATION by
    S1-SENSI-025. NP2: a false corroboration is worse than none, because
    it makes one source look like two.

    Everything above the fallback is kept — the four phrases and both
    severity-hint tiers — so a genuine FCDO warning still parses.
    """
    lowered = str(text or "").lower()
    for phrase, level in FCDO_LEVEL_MAP.items():
        if phrase in lowered:
            return level
    if any(hint in lowered for hint in FCDO_EXTREME_HINTS):
        return 4
    if any(hint in lowered for hint in FCDO_HIGH_HINTS):
        return 3
    # §7-2 #4: production returns 2 here. 0 means "this parser did not
    # reach a verdict", which is a fact; 2 was a guess wearing a level.
    return 0


def parse_level_gac(text: str) -> int:
    """`_parse_level_gac` (`:347-362`) — phrases first, then numerals."""
    lowered = str(text or "").lower()
    for phrase, level in GAC_LEVEL_MAP.items():
        if phrase in lowered:
            return level
    for level in (4, 3, 2, 1):
        if f"risk level {level}" in lowered:
            return level
    return 0


def match_country(title: str, targets, country_names) -> str:
    """`_match_country_code` (`:376-388`) — targets first, then everyone.

    The two-pass shape is production's and it matters: a title naming two
    countries resolves to the WATCHED one rather than to whichever comes
    first in the geographic ledger. The fallback pass is what lets an
    advisory for an unwatched country still be attributed, which the
    convergence count needs when the target set is narrow.
    """
    upper = str(title or "").upper()
    for code in targets or ():
        name = str(country_names.get(code, "")).upper()
        if name and name in upper:
            return code
    for code, name in country_names.items():
        if str(name).upper() and str(name).upper() in upper:
            return code
    return ""


def parse_gac_rows(html: str) -> tuple:
    """`_parse_gac_html`'s row scan (`:244-298`) — `(name, risk, date, row)`.

    Canada discontinued its feed, so this table IS the source. The icon
    filename is a second encoding of the same level and production falls
    back to it when the text does not parse (`:279-285`); the raw row is
    returned so that fallback stays available.
    """
    return tuple((match.group(1).strip(), match.group(2).strip(),
                  match.group(3).strip(), match.group(0))
                 for match in _GAC_ROW.finditer(html or ""))


def gac_level(risk_text: str, row_html: str) -> int:
    """Text first, then the icon (`:277-285`)."""
    level = parse_level_gac(risk_text)
    if level:
        return level
    for icon, icon_level in GAC_ICON_LEVEL_MAP.items():
        if icon in (row_html or ""):
            return icon_level
    return 0


def converge(levels_by_source) -> dict:
    """S1-SENSI-025, as a pure function for WP-4.1's reduction.

    `{source: level}` for ONE country ->
    `{level, convergence_count, converged, single_source_warning, label}`.

    The count is of sources reporting level >= 3, and `converged` needs
    two of them. A single source at level 3 or above raises the
    single-source warning instead — the flag that says "this upgrade may
    be a domestic political act", which is the entire reason three
    governments are read rather than one.

    Exported rather than inlined because the join lives in WP-4.1 and
    DP4 is the record of what a second copy of one rule costs.
    """
    reported = {source: int(level)
                for source, level in (levels_by_source or {}).items()
                if int(level) > 0}
    if not reported:
        return {"level": 0, "convergence_count": 0, "converged": False,
                "single_source_warning": False, "label": UNKNOWN_LABEL,
                "sources": ()}
    level = max(reported.values())
    raised = tuple(sorted(source for source, value in reported.items()
                          if value >= CONVERGENCE_MIN_LEVEL))
    return {
        "level": level,
        "convergence_count": len(raised),
        "converged": len(raised) >= CONVERGENCE_MIN_SOURCES,
        "single_source_warning": len(raised) == 1,
        "label": level_label(level),
        "sources": tuple(sorted(reported)),
    }


def _draft(source_key: str, country: str, level: int, title: str,
           published: str, url: str) -> ObservationDraft:
    return ObservationDraft(
        signal_source=row_source(source_key), domain=INFO, country=country,
        # OBSERVED: `upgraded` needs the previous level, which A1/A2 kept
        # in a process dictionary seeded with the CURRENT reading — so
        # production's first sighting, and every sighting after a restart,
        # reported no upgrade. Withheld rather than computed against a
        # default that manufactures calm.
        status=STATUS_OBSERVED, raw_score=0.0,
        value=f"{source_key} level {level} ({level_label(level)})",
        flags={
            "source": source_key,
            "source_name": SOURCES.get(source_key, {}).get("name", ""),
            "level": level,
            "level_label": level_label(level),
            "title": str(title or "")[:TITLE_CHARS],
            "pub_date": published,
            # §7-2 #9's discipline: `upgraded` is read as a bool and
            # `prev_level` as a number, so neither may carry a marker.
            "upgrade_verdict": "pending_l1_previous_level",
            "convergence_verdict": "pending_wp41_source_join",
        },
        evidence_url=url)


def normalize(payload, context: NormalizeContext
              ) -> tuple[ObservationDraft, ...]:
    """One government's publication -> one row per country it named."""
    source_key = source_of(payload.label)
    if source_key not in SOURCES:
        return ()
    if payload.status != 200:
        # `!= 200` including 429 (`:96-102`). Production returns
        # `(data, False)` for both and the caller cannot tell them apart;
        # the status travels here.
        return (ObservationDraft(
            signal_source=row_source(source_key), domain=INFO, country="",
            status=STATUS_NO_DATA, raw_score=0.0,
            value=f"{source_key}: http_{payload.status}",
            flags={"source": source_key, "reason": f"http_{payload.status}"},
            evidence_url=payload.url),)

    text = payload.text()
    targets = tuple(context.countries) + tuple(context.adversaries)
    drafts: list = []
    seen: set = set()

    if SOURCES[source_key].get("html_scrape"):
        for name, risk, published, row in parse_gac_rows(text):
            country = match_country(name, targets, context.country_names)
            if not country or country in seen:
                continue
            level = gac_level(risk, row)
            if level <= 0:
                continue
            seen.add(country)
            drafts.append(_draft(source_key, country, level,
                                 f"{name} - {risk}", published, payload.url))
        return tuple(drafts)

    # `if "<entry>" in text` decides the dialect (`:106-112`) — Atom's
    # summary/updated against RSS's description/pubDate. Reading one
    # dialect's tags out of the other returns empty strings, and empty
    # strings parse to level 0, i.e. a working feed reporting nothing.
    if "<entry>" in text:
        fragments = text.split("<entry>")[1:]
        title_tag, body_tag, date_tag = "title", "summary", "updated"
    elif "<item>" in text:
        fragments = text.split("<item>")[1:]
        title_tag, body_tag, date_tag = "title", "description", "pubDate"
    else:
        return ()

    for fragment in fragments:
        title = extract_tag(fragment, title_tag)
        body = extract_tag(fragment, body_tag)
        published = extract_tag(fragment, date_tag)
        combined = f"{title} {body}"
        level = (parse_level_fcdo(combined) if source_key == "UK"
                 else parse_level_us(combined))
        country = match_country(title, targets, context.country_names)
        if not country or level <= 0 or country in seen:
            continue
        seen.add(country)
        drafts.append(_draft(source_key, country, level, title, published,
                             payload.url))
    return tuple(drafts)


TRAVEL_ADVISORY_ADAPTER = SourceAdapter(
    adapter_id=TRAVEL_ADVISORY, category=INFO,
    requests=tuple(
        RequestSpec(url=meta["url"], expect_content="any",
                    headers={"Accept": meta["accept"]},
                    label=f"source:{key}")
        for key, meta in SOURCES.items()),
    cadence=_CADENCE, normalize=normalize,
    freshness_horizon_sec=_FRESHNESS_HORIZON_SEC,
    rate_limit_group="travel_advisory",
    knowledge_refs=("K20",),
    baseline_refs=("travel_advisory_previous_level",))

__all__ = ["TRAVEL_ADVISORY", "TRAVEL_ADVISORY_ADAPTER", "normalize",
           "extract_tag", "parse_level_us", "parse_level_fcdo",
           "parse_level_gac", "gac_level", "parse_gac_rows",
           "match_country", "converge", "level_label", "row_source",
           "source_of", "SOURCES", "FCDO_LEVEL_MAP", "GAC_LEVEL_MAP",
           "GAC_ICON_LEVEL_MAP", "FCDO_EXTREME_HINTS", "FCDO_HIGH_HINTS",
           "LEVEL_LABELS", "UNKNOWN_LABEL", "CONVERGENCE_MIN_SOURCES",
           "CONVERGENCE_MIN_LEVEL", "SIGNAL_SOURCE", "SOURCE_PREFIX",
           "TITLE_CHARS"]
