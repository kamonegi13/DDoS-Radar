"""RSS / news-wire kinetic-event extractor — regex baseline (NP3, no LLM dep).

Used by the optional B1 ETL path to convert public RSS feed items into
``ExternalEvent`` candidates that the ground-truth classifier can mix
with ACLED / GDELT (or use standalone in OPSEC-conscious deployments
that disable both).

Design contract:
    1. **Deterministic baseline.** A regex+keyword extractor produces
       a ``KineticMatch`` (country + fatalities + summary) directly
       from the headline + summary text. No external dependencies.
    2. **Optional LLM augmentation.** When ``use_llm=True`` and the
       configured LLM client succeeds, structured output replaces the
       regex match. On any LLM failure / parse error / unavailable
       client the function transparently falls back to the regex
       result. Tests pin the LLM-disabled path so CI never depends on
       a model being reachable.
    3. **No silent escalation.** When neither regex nor LLM finds a
       fatality count or a recognized country, ``extract_kinetic``
       returns ``None`` — the caller drops the RSS item. The pipeline
       prefers under-reporting to fabrication.

The extractor is pure (no IO, no DB) so it can be unit-tested without a
live RSS fetcher. The fetcher lives separately in
``scripts/run_rss_etl.py``.
"""

from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass
from typing import Optional, Sequence

log = logging.getLogger("rss_extractor")


# Match counted casualties: "12 killed", "killed at least 5", "five dead",
# "12 fatalities", "death toll rose to 30". Word-form numbers up to twenty
# are recognized; larger word forms are dropped (under-report rather than
# guess). Numeric + word-form variants kept separate to keep the regex
# auditable.
_NUMERIC_FATALITIES = re.compile(
    r"\b(?:at\s+least\s+)?(\d{1,4})\s+(?:people\s+)?(?:reported\s+)?"
    r"(?:dead|killed|deaths?|fatalit(?:y|ies)|casualt(?:y|ies))\b",
    re.IGNORECASE,
)
_NUMERIC_FATALITIES_INVERTED = re.compile(
    r"\b(?:kill(?:s|ed|ing)?|dead|deaths?|fatalit(?:y|ies)|"
    r"toll(?:\s+(?:rose|reached|climbed))?(?:\s+to)?)\s+"
    r"(?:at\s+least\s+)?(\d{1,4})\b",
    re.IGNORECASE,
)
_WORD_FATALITIES = re.compile(
    r"\b(?:at\s+least\s+)?(one|two|three|four|five|six|seven|eight|nine|ten|"
    r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|"
    r"nineteen|twenty)"
    # Allow up to 4 modifier words ("Russian soldiers", "civilians reported")
    # between the number and the fatality verb so common phrasings parse.
    r"(?:\s+\S+){0,4}\s+"
    r"(?:dead|killed|deaths?|fatalit(?:y|ies))\b",
    re.IGNORECASE,
)
_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
}

# Kinetic ACTION vocabulary — an act of violence happened or is happening.
# Used as a confirmation filter: if no fatality regex matches but a kinetic
# action appears alongside a country mention we can still record a low-
# severity match. Bare weapon nouns ("missile", "rocket", "artillery") are
# deliberately NOT sufficient here: a weapons test, deployment, or
# defense-industry unveiling mentions the same nouns without any violence,
# and belongs to the escalation (posture) tier below. The 2026-08-02 audit
# found 12/15 korean_peninsula FALSE_NEGATIVEs were posture articles graded
# as kinetic violence through this list's bare nouns.
_KINETIC_VERBS = re.compile(
    r"\b(airstrike|air\s+strike|shelling|drone\s+strike|bombardment|"
    r"bombing|explosion|invasion|incursion|ambush(?:ed)?|torpedo(?:ed)?|"
    r"attack(?:ed|s)?|shoot(?:ing|s|down)?|shot\s+down|"
    r"missiles?\s+(?:strike|attack|barrage|launch(?:ed)?|fired)|"
    r"rockets?\s+(?:strike|attack|barrage|fire[ds]?)|"
    r"artillery\s+(?:fire|strike|barrage|shelling)|"
    r"(?:fires?|fired|launch(?:es|ed)?)\s+(?:\w+\s+){0,2}(?:missiles?|rockets?))\b",
    re.IGNORECASE,
)

# Diplomatic / mobilization verbs that signal escalation without a
# fatality count. NP1 (recall over precision): low-confidence early
# warning is worth more than under-reporting. Kept conservative — only
# verbs with strong inter-state escalation semantics. Citizen-X words
# like "protest" or "rally" are deliberately excluded — they fire
# constantly in non-escalatory contexts.
_ESCALATION_VERBS = re.compile(
    r"\b(mobiliz(?:e|es|ed|ing|ation)|"
    r"deploy(?:s|ed|ing|ment)?|"
    r"scrambl(?:e|es|ed|ing)|"
    r"intercept(?:s|ed|ing|ion)?|"
    r"missiles?\s+tests?|weapons?\s+tests?|test\s+launch(?:es)?|"
    r"recall(?:s|ed|ing)?\s+(?:its\s+)?ambassador|"
    r"sever(?:s|ed|ing)?\s+(?:diplomatic\s+)?(?:ties|relations)|"
    r"expel(?:s|led|ling)?\s+(?:the\s+)?diplomat|"
    r"troop\s+buildup|military\s+exercise|war\s+games)\b",
    re.IGNORECASE,
)

# ── escalation-relevance gate (ground-truth labeling only) ─────────────────
#
# Added 2026-07-04: production ground truth was contaminated by domestic
# accidents and natural disasters in participant countries (a bear-spray
# incident and a typhoon were labeled as taiwan_contingency escalation
# evidence). Labels demand higher precision than sensing: a wrong label
# corrupts the recall metric, while a missed label merely shrinks sample
# size. The gate is therefore applied by the ETL runners only — the
# bg_observer sensing path keeps the wider net (NP1).

# Inherently military kinetic vocabulary — sufficient escalation context
# on its own. Deliberately excludes ambiguous verbs like "attack" /
# "shooting" / "explosion", which fire on street crime and accidents.
_STRONG_KINETIC = re.compile(
    r"\b(missile|airstrike|air\s+strike|shelling|rocket|drone\s+strike|"
    r"artillery|bombardment|invasion|incursion|shot\s+down|shootdown|"
    r"torpedo)\b",
    re.IGNORECASE,
)

# Military-actor nouns that upgrade a weak kinetic verb into plausible
# interstate-escalation context.
_MILITARY_ACTORS = re.compile(
    r"\b(troops?|soldiers?|army|navy|air\s+force|military|armed\s+forces|"
    r"marines?|warship|destroyer|frigate|aircraft\s+carrier|fighter\s+jet|"
    r"warplane|bomber|paratroopers?|militia|special\s+forces|coast\s+guard)\b",
    re.IGNORECASE,
)

# Non-conflict noise: disasters, accidents, wildlife, street crime, civic
# events. These veto a match unless inherently military vocabulary is also
# present ("missile test proceeds amid typhoon warnings" stays relevant).
_NONCONFLICT_NOISE = re.compile(
    r"\b(typhoon|hurricane|cyclone|earthquake|tsunami|flood(?:s|ing)?|"
    r"landslide|wildfire|volcano|heat\s?wave|blizzard|drought|storm|"
    r"outbreak|epidemic|pandemic|traffic|road\s+accident|car\s+crash|"
    r"bus\s+crash|train\s+crash|derail(?:s|ed|ment)?|ferry|"
    r"capsiz(?:e|ed|ing)|plane\s+crash|air\s+crash|helicopter\s+crash|"
    r"crash(?:es|ed)?|bear|shark|robbery|burglary|homicide|murder|stabbing|"
    r"shooting\s+spree|nightclub|festival|concert|stampede)\b",
    re.IGNORECASE,
)


def is_escalation_relevant(text: str) -> bool:
    """True iff ``text`` plausibly describes interstate-escalation activity,
    as opposed to a disaster / accident / crime that merely happened in a
    monitored country.

    Decision ladder (NP6 — auditable in one read):
      1. Inherently military vocabulary (strong kinetic or escalation verb)
         qualifies outright and overrides the noise veto.
      2. A weak kinetic verb ("attack", "shooting", …) qualifies only with
         a military actor noun or ≥2 recognized countries in the text
         (interstate framing).
      3. Non-conflict noise vocabulary vetoes anything that qualified via
         the weak path.

    Used by the ground-truth ETL runners to gate evidence BEFORE labeling;
    not applied to the bg_observer sensing path.
    """
    if not text:
        return False
    has_strong = bool(
        _STRONG_KINETIC.search(text) or _ESCALATION_VERBS.search(text)
    )
    if has_strong:
        return True
    if not _KINETIC_VERBS.search(text):
        return False
    has_context = bool(_MILITARY_ACTORS.search(text)) or (
        len(_detect_all_countries(text)) >= 2
    )
    if not has_context:
        return False
    return not _NONCONFLICT_NOISE.search(text)


# ISO-2 country code → list of search aliases. Kept conservative — only
# names whose appearance in a news headline reliably implicates the
# country itself, not a citizen-of-X mention. Edit this map carefully:
# adding a permissive alias bloats false positives.
#
# Coverage invariant (ADR-V2-015 Phase 2): every country that appears as
# a participant in any geo_data.json scenario MUST have an alias entry.
# Verified at startup + CI by `verify_alias_coverage()` below.
_COUNTRY_ALIASES: dict[str, tuple[str, ...]] = {
    "TW": ("Taiwan", "Taiwanese"),
    "CN": ("China", "Chinese", "PRC", "PLA"),
    "JP": ("Japan", "Japanese"),
    "KR": ("South Korea", "Republic of Korea", "ROK"),
    "KP": ("North Korea", "DPRK", "Pyongyang"),
    "US": ("United States", "U.S.", "American forces", "U.S. forces", "Pentagon"),
    "RU": ("Russia", "Russian", "Moscow", "Kremlin"),
    "UA": ("Ukraine", "Ukrainian", "Kyiv", "Kiev"),
    "IL": ("Israel", "Israeli", "IDF"),
    "IR": ("Iran", "Iranian", "IRGC", "Tehran"),
    "LB": ("Lebanon", "Lebanese", "Beirut", "Hezbollah"),
    "YE": ("Yemen", "Yemeni", "Houthi", "Sanaa", "Sana'a"),
    "PH": ("Philippines", "Filipino", "Manila"),
    "VN": ("Vietnam", "Vietnamese", "Hanoi"),
    "GB": ("United Kingdom", "Britain", "British", "London"),
    "FR": ("France", "French", "Paris"),
    "DE": ("Germany", "German", "Berlin"),
    "PL": ("Poland", "Polish", "Warsaw"),
    "SY": ("Syria", "Syrian", "Damascus"),
    "IQ": ("Iraq", "Iraqi", "Baghdad"),
    "SA": ("Saudi Arabia", "Saudi", "Riyadh"),
    # ADR-V2-015 Phase 2 — coverage of all v2 scenario participants:
    "AU": ("Australia", "Australian", "Canberra"),
    "BY": ("Belarus", "Belarusian", "Minsk", "Lukashenko"),
    "EE": ("Estonia", "Estonian", "Tallinn"),
    "FI": ("Finland", "Finnish", "Helsinki"),
    "GU": ("Guam",),
    "LT": ("Lithuania", "Lithuanian", "Vilnius"),
    "LV": ("Latvia", "Latvian", "Riga"),
    "MD": ("Moldova", "Moldovan", "Chisinau", "Transnistria"),
    "MY": ("Malaysia", "Malaysian", "Kuala Lumpur", "Putrajaya"),
    "RO": ("Romania", "Romanian", "Bucharest"),
    "SK": ("Slovakia", "Slovak", "Bratislava"),
}


def verify_alias_coverage(participants: set[str]) -> list[str]:
    """Return ISO-2 codes that appear in `participants` but have no alias.

    Used by the CI gate (`scripts/check_ci.sh`) and the bg_observer
    startup self-check to enforce the "every scenario participant has
    an alias" invariant declared in ADR-V2-015 Phase 2.
    """
    return sorted(c for c in participants if c not in _COUNTRY_ALIASES)


def _detect_all_countries(
    text: str, allowed: Optional[Sequence[str]] = None,
) -> list[str]:
    """Return every ISO-2 code whose alias appears in `text`, deduped.

    Multi-country variant of ``_detect_country`` (ADR-V2-015 Phase 3).
    Used by ``extract_kinetic_regex_all`` to recover signals from
    headlines like "Russia–Ukraine border clash" where the single-
    country detector would arbitrarily return only one. Order is the
    iteration order of ``_COUNTRY_ALIASES``, which is dict-insertion
    (Python 3.7+) and therefore deterministic.
    """
    if not text:
        return []
    candidates = (
        _COUNTRY_ALIASES.items() if allowed is None
        else ((c, _COUNTRY_ALIASES[c]) for c in allowed if c in _COUNTRY_ALIASES)
    )
    found: list[str] = []
    seen: set[str] = set()
    for cc, aliases in candidates:
        if cc in seen:
            continue
        for alias in aliases:
            # Trailing boundary is a (?!\w) lookahead, not \b: aliases that
            # end in a period ("U.S.") never form a \b against following
            # whitespace, so the historical \b silently dropped them.
            if re.search(r"\b" + re.escape(alias) + r"(?!\w)", text,
                         re.IGNORECASE):
                found.append(cc)
                seen.add(cc)
                break
    return found


def _has_escalation_verb(text: str) -> bool:
    return bool(text and _ESCALATION_VERBS.search(text))


@dataclass(frozen=True)
class KineticMatch:
    """Result of extracting a kinetic event from RSS text.

    ``confidence`` is the extractor's self-reported certainty in [0, 1].
    Regex baseline currently emits 0.6 (kinetic verb + country) up to
    0.85 (numeric fatality count + country). LLM augmentation, when
    enabled, may emit higher values but is clamped to 0.95.
    """
    country: str
    fatalities: int
    summary: str
    source: str  # "regex" or "llm"
    confidence: float


def _detect_country(text: str, allowed: Optional[Sequence[str]] = None) -> Optional[str]:
    """Find the first country whose alias appears in `text`.

    `allowed` is an optional whitelist of ISO-2 codes. When provided, only
    those countries are considered (lets the caller scope to a scenario's
    participants without rewriting the alias map).
    """
    if not text:
        return None
    candidates = (
        _COUNTRY_ALIASES.items() if allowed is None
        else ((c, _COUNTRY_ALIASES[c]) for c in allowed if c in _COUNTRY_ALIASES)
    )
    for cc, aliases in candidates:
        for alias in aliases:
            # Leading \b keeps "Iran" from matching inside "Iranian";
            # trailing (?!\w) instead of \b so period-final aliases
            # ("U.S.") match before whitespace.
            if re.search(r"\b" + re.escape(alias) + r"(?!\w)", text,
                         re.IGNORECASE):
                return cc
    return None


def _detect_fatalities(text: str) -> Optional[int]:
    """Return the highest fatality count found in `text`, or None.

    Multiple regexes run; we take max() so headlines like
    "Strike kills 5; toll rose to 30" report the larger figure.
    """
    if not text:
        return None
    counts: list[int] = []
    for m in _NUMERIC_FATALITIES.finditer(text):
        try:
            counts.append(int(m.group(1)))
        except (ValueError, IndexError):
            pass
    for m in _NUMERIC_FATALITIES_INVERTED.finditer(text):
        try:
            counts.append(int(m.group(1)))
        except (ValueError, IndexError):
            pass
    for m in _WORD_FATALITIES.finditer(text):
        word = m.group(1).lower()
        if word in _WORDS:
            counts.append(_WORDS[word])
    return max(counts) if counts else None


def _has_kinetic_verb(text: str) -> bool:
    return bool(text and _KINETIC_VERBS.search(text))


def extract_kinetic_regex(
    text: str,
    *,
    allowed_countries: Optional[Sequence[str]] = None,
) -> Optional[KineticMatch]:
    """Deterministic regex+keyword extractor. No LLM, no IO.

    Returns None when:
      - no recognized country alias appears, OR
      - none of {fatality count, kinetic verb, escalation verb} appears.

    Severity / confidence ladder (NP1 — recall over precision; ADR-V2-015 Phase 6):
      - fatality count present:    confidence 0.85, fatalities = parsed number
      - kinetic action, no count:  confidence 0.60, fatalities = 0
        (strike / bombing / invasion — violence happened, deaths unstated;
        pre-2026-08-02 this tier fabricated fatalities=1)
      - escalation posture only:   confidence 0.40, fatalities = 0
        (mobilization / diplomatic break / weapons test / deployment etc.)
    Downstream severity floors key on (fatalities, confidence) — see
    ground_truth_etl.expected_severity_floor.
    """
    if not text:
        return None
    country = _detect_country(text, allowed=allowed_countries)
    if country is None:
        return None
    fatalities = _detect_fatalities(text)
    has_kinetic = _has_kinetic_verb(text)
    has_escalation = _has_escalation_verb(text)
    if fatalities is None and not has_kinetic and not has_escalation:
        return None
    if fatalities is not None:
        return KineticMatch(
            country=country,
            fatalities=int(fatalities),
            summary=text.strip()[:240],
            source="regex",
            confidence=0.85,
        )
    if has_kinetic:
        return KineticMatch(
            country=country,
            fatalities=0,
            summary=text.strip()[:240],
            source="regex",
            confidence=0.60,
        )
    # Escalation verb only (low-confidence early warning per NP1).
    return KineticMatch(
        country=country,
        fatalities=0,
        summary=text.strip()[:240],
        source="regex",
        confidence=0.40,
    )


def extract_kinetic_regex_all(
    text: str,
    *,
    allowed_countries: Optional[Sequence[str]] = None,
) -> list[KineticMatch]:
    """Multi-country variant of ``extract_kinetic_regex`` (ADR-V2-015 Phase 3).

    Returns one ``KineticMatch`` per detected country. The kinetic /
    escalation gate is shared across all countries in the same text:
    if the verb is present at all, every detected country emits a
    match. This is intentional — a single article like "Russia attacks
    Ukraine, kills 12" describes an event involving both countries; the
    scoring layer's per-scenario participant filter still routes each
    country's contribution to the correct scenario.

    Returns ``[]`` if no country is detected or no verb / fatality is
    present.
    """
    if not text:
        return []
    countries = _detect_all_countries(text, allowed=allowed_countries)
    if not countries:
        return []
    fatalities = _detect_fatalities(text)
    has_kinetic = _has_kinetic_verb(text)
    has_escalation = _has_escalation_verb(text)
    if fatalities is None and not has_kinetic and not has_escalation:
        return []
    summary = text.strip()[:240]
    if fatalities is not None:
        return [
            KineticMatch(country=c, fatalities=int(fatalities),
                         summary=summary, source="regex", confidence=0.85)
            for c in countries
        ]
    if has_kinetic:
        return [
            KineticMatch(country=c, fatalities=0,
                         summary=summary, source="regex", confidence=0.60)
            for c in countries
        ]
    return [
        KineticMatch(country=c, fatalities=0,
                     summary=summary, source="regex", confidence=0.40)
        for c in countries
    ]


def extract_kinetic(
    text: str,
    *,
    allowed_countries: Optional[Sequence[str]] = None,
    use_llm: bool = False,
    llm_invoke=None,
) -> Optional[KineticMatch]:
    """Public extractor: regex baseline with optional LLM augmentation.

    When ``use_llm=True`` and ``llm_invoke`` is callable, the function
    asks the LLM for a structured extraction and prefers it when its
    output validates. Any exception, malformed JSON, or missing field
    falls back to the regex result — the LLM never *replaces* the
    deterministic baseline, only refines it. This keeps the gate
    runnable in offline / OPSEC-strict environments where no model is
    reachable.

    `llm_invoke` signature: callable(prompt: str) -> str. Pass
    ``radar.llm_client.invoke`` (or a test stub) to enable.
    """
    baseline = extract_kinetic_regex(text, allowed_countries=allowed_countries)
    if not use_llm or llm_invoke is None:
        return baseline

    try:
        import json as _json
        prompt = _build_llm_prompt(text, allowed_countries)
        raw = llm_invoke(prompt)
        if not isinstance(raw, str) or not raw.strip():
            return baseline
        parsed = _json.loads(raw.strip())
        country = parsed.get("country")
        fatalities = parsed.get("fatalities")
        if not isinstance(country, str) or country not in _COUNTRY_ALIASES:
            return baseline
        if not isinstance(fatalities, int) or fatalities < 0:
            return baseline
        if allowed_countries is not None and country not in allowed_countries:
            return baseline
        confidence = parsed.get("confidence", 0.80)
        if not isinstance(confidence, (int, float)):
            confidence = 0.80
        confidence = max(0.0, min(0.95, float(confidence)))
        return KineticMatch(
            country=country,
            fatalities=fatalities,
            summary=text.strip()[:240],
            source="llm",
            confidence=confidence,
        )
    except Exception as e:  # noqa: BLE001 — LLM path is best-effort
        log.debug("[rss_extractor] LLM augmentation failed, using regex: %s", e)
        return baseline


def _build_llm_prompt(text: str, allowed: Optional[Sequence[str]]) -> str:
    """Render the extraction prompt. Kept simple + auditable per NP6.
    Output contract: a single JSON object with keys
    {country: ISO-2, fatalities: int >= 0, confidence: float in [0,1]}.
    """
    allowed_clause = (
        f"Country must be one of: {', '.join(allowed)}. "
        if allowed else
        "Country must be a known ISO-2 code. "
    )
    return (
        "Extract the kinetic event details from the following news text. "
        + allowed_clause +
        "If no country can be identified, return {}. "
        "If no fatalities are stated, set fatalities to 0. "
        "Reply with ONLY a single JSON object on one line, no prose. "
        "Schema: {\"country\": ISO-2 string, \"fatalities\": non-negative int, "
        "\"confidence\": 0.0-1.0}.\n\nText:\n"
        + text.strip()[:1200]
    )


# ── CLI gate for CI (ADR-V2-015 Phase 2) ──────────────────────────────────


def _cli_check_coverage() -> int:
    """Verify alias coverage against geo_data.json scenario participants.

    Exit 0 = all participants covered. Exit 1 = at least one uncovered
    code (printed). Wired into ``scripts/check_ci.sh`` so a new scenario
    participant added without a matching alias breaks CI before merge.
    """
    import json
    import pathlib
    repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
    geo_path = repo_root / "geo_data.json"
    if not geo_path.exists():
        print(f"[rss_extractor] geo_data.json not found at {geo_path}",
              file=sys.stderr)
        return 1
    with geo_path.open() as f:
        geo = json.load(f)
    participants: set[str] = set()
    for sid, sc in geo.get("SCENARIOS", {}).items():
        for cc in sc.get("participants", {}).keys():
            participants.add(cc)
    gap = verify_alias_coverage(participants)
    if gap:
        print(
            f"[rss_extractor] alias coverage gap — these participants "
            f"have no alias entry: {gap}\n"
            f"  Add entries to _COUNTRY_ALIASES in "
            f"radar/conclusions/rss_extractor.py",
            file=sys.stderr,
        )
        return 1
    print(
        f"[rss_extractor] alias coverage OK — "
        f"{len(participants)} participants, {len(_COUNTRY_ALIASES)} aliases",
    )
    return 0


if __name__ == "__main__":
    # Note: prefer ``scripts/check_alias_coverage.py`` for CI invocation —
    # that script avoids importing the full radar package (which would
    # trigger DB / sensor startup) and only depends on this module's
    # ``verify_alias_coverage`` function.
    args = sys.argv[1:]
    if args and args[0] == "--check-coverage":
        sys.exit(_cli_check_coverage())
    print("usage: python -m radar.conclusions.rss_extractor --check-coverage",
          file=sys.stderr)
    sys.exit(2)
