"""The deterministic kinetic-event extractor. One implementation.

`bg_observer_rss` is the only adapter that reads a news wire with no model
behind it (S1-SENSI-026: no API key, no LLM, works air-gapped), and the
verdict it reaches comes entirely from this vocabulary. The tables ARE the
sensor: a dropped alias is a country that stops being seen, a widened verb
is a wire story that starts scoring, and neither shows up as an error.

Every table here is transcribed from `radar/conclusions/rss_extractor.py`
and compared against the live module by `ast` in the suite, because the
failure mode of a paraphrased ledger is silence, and the WP-2.6 sweep
found 97 infidelities of exactly that shape.

WHY IT LIVES UNDER `v3/adapters/`. The extractor is pure — `re` and
nothing else — and its only consumer today is the adapter next door.
S1-SENSI-028 assigns the extractor BODY to the conclusions layer, which
lands in a later WP; when it does, it must import from here rather than
transcribe the tables a second time. A-02 is the record of what a second
copy costs: eight LLM skeletons whose `max_tokens` drifted across 200-512
because nothing compared them.

WHAT IS DELIBERATELY ABSENT. `is_escalation_relevant` — the disaster /
accident / street-crime veto — is NOT here. It gates GROUND-TRUTH LABELS
in the ETL runners and `rss_extractor.py:169-170` states plainly that it
is "not applied to the bg_observer sensing path". Sensing keeps the wider
net (NP1); labelling wants precision. Importing the veto into the sensing
path would silently narrow recall, which is the direction NP1 forbids.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Sequence

#: `rss_extractor.py:197-231`. ISO2 -> the aliases whose appearance in a
#: headline implicates the COUNTRY rather than a citizen of it. The
#: coverage invariant (ADR-V2-015 Phase 2) is that every scenario
#: participant has an entry; `uncovered()` below is how that is checked.
COUNTRY_ALIASES: dict = {
    "TW": ("Taiwan", "Taiwanese"),
    "CN": ("China", "Chinese", "PRC", "PLA"),
    "JP": ("Japan", "Japanese"),
    "KR": ("South Korea", "Republic of Korea", "ROK"),
    "KP": ("North Korea", "DPRK", "Pyongyang"),
    "US": ("United States", "U.S.", "American forces", "U.S. forces",
           "Pentagon"),
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

#: `rss_extractor.py:44-64`. Three patterns rather than one because the
#: comment there says so: "kept separate to keep the regex auditable".
NUMERIC_FATALITIES = re.compile(
    r"\b(?:at\s+least\s+)?(\d{1,4})\s+(?:people\s+)?(?:reported\s+)?"
    r"(?:dead|killed|deaths?|fatalit(?:y|ies)|casualt(?:y|ies))\b",
    re.IGNORECASE)
NUMERIC_FATALITIES_INVERTED = re.compile(
    r"\b(?:kill(?:s|ed|ing)?|dead|deaths?|fatalit(?:y|ies)|"
    r"toll(?:\s+(?:rose|reached|climbed))?(?:\s+to)?)\s+"
    r"(?:at\s+least\s+)?(\d{1,4})\b",
    re.IGNORECASE)
WORD_FATALITIES = re.compile(
    r"\b(?:at\s+least\s+)?(one|two|three|four|five|six|seven|eight|nine|ten|"
    r"eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|"
    r"nineteen|twenty)"
    r"(?:\s+\S+){0,4}\s+"
    r"(?:dead|killed|deaths?|fatalit(?:y|ies))\b",
    re.IGNORECASE)

#: `rss_extractor.py:65-70`. Word forms stop at twenty on purpose — larger
#: ones are dropped rather than guessed, which under-reports the count and
#: never invents one.
WORDS: dict = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20,
}

#: `rss_extractor.py:81-90`. Bare weapon nouns are NOT here: the 2026-08-02
#: audit found 12 of 15 korean_peninsula false negatives were posture
#: articles that this list's bare nouns had graded as violence. A missile
#: named without a strike verb belongs to the escalation tier below.
KINETIC_VERBS = re.compile(
    r"\b(airstrike|air\s+strike|shelling|drone\s+strike|bombardment|"
    r"bombing|explosion|invasion|incursion|ambush(?:ed)?|torpedo(?:ed)?|"
    r"attack(?:ed|s)?|shoot(?:ing|s|down)?|shot\s+down|"
    r"missiles?\s+(?:strike|attack|barrage|launch(?:ed)?|fired)|"
    r"rockets?\s+(?:strike|attack|barrage|fire[ds]?)|"
    r"artillery\s+(?:fire|strike|barrage|shelling)|"
    r"(?:fires?|fired|launch(?:es|ed)?)\s+(?:\w+\s+){0,2}(?:missiles?|rockets?))\b",
    re.IGNORECASE)

#: `rss_extractor.py:98-109`. Posture without a body count. "protest" and
#: "rally" are excluded deliberately — they fire constantly outside any
#: escalation.
ESCALATION_VERBS = re.compile(
    r"\b(mobiliz(?:e|es|ed|ing|ation)|"
    r"deploy(?:s|ed|ing|ment)?|"
    r"scrambl(?:e|es|ed|ing)|"
    r"intercept(?:s|ed|ing|ion)?|"
    r"missiles?\s+tests?|weapons?\s+tests?|test\s+launch(?:es)?|"
    r"recall(?:s|ed|ing)?\s+(?:its\s+)?ambassador|"
    r"sever(?:s|ed|ing)?\s+(?:diplomatic\s+)?(?:ties|relations)|"
    r"expel(?:s|led|ling)?\s+(?:the\s+)?diplomat|"
    r"troop\s+buildup|military\s+exercise|war\s+games)\b",
    re.IGNORECASE)

#: `rss_extractor.py:388` — the stored excerpt's cap.
SUMMARY_LIMIT = 240

#: The three tiers, as `(confidence, raw_score)`. S1-SENSI-028 and
#: `background_observer.py:387-391`. The top tier is a function of the
#: count, so it is computed rather than tabled; the two lower ones are
#: constants and are named here so the suite can pin them against the
#: clause instead of against a copy of the expression.
CONFIDENCE_FATALITIES = 0.85
CONFIDENCE_KINETIC = 0.60
CONFIDENCE_ESCALATION = 0.40
SCORE_KINETIC = 0.45
SCORE_ESCALATION = 0.25
SCORE_FATALITY_BASE = 0.4
SCORE_PER_FATALITY = 0.05
SCORE_CAP = 1.0


@dataclass(frozen=True, slots=True)
class KineticMatch:
    """One country's reading of one wire story. `rss_extractor.py:283-296`."""

    country: str
    fatalities: int
    summary: str
    source: str
    confidence: float


def alias_hit(text: str, alias: str) -> bool:
    """`\\b<alias>(?!\\w)` — `rss_extractor.py:271-272`.

    The trailing boundary is a lookahead and NOT `\\b`. An alias ending in
    a period ("U.S.") never forms a `\\b` against following whitespace, so
    the historical `\\b` dropped it silently — the United States stopped
    being detected by one of its five aliases and nothing reported a
    change.
    """
    return bool(re.search(r"\b" + re.escape(alias) + r"(?!\w)", text,
                          re.IGNORECASE))


def detect_countries(text: str,
                     allowed: Optional[Sequence[str]] = None) -> tuple:
    """Every ISO2 whose alias appears, deduped — `rss_extractor.py:244-276`.

    Order is `COUNTRY_ALIASES`' insertion order, which is what makes the
    result deterministic; iterating a set here would make the same feed
    produce a different first country between runs.
    """
    if not text:
        return ()
    if allowed is None:
        candidates = tuple(COUNTRY_ALIASES.items())
    else:
        candidates = tuple((code, COUNTRY_ALIASES[code]) for code in allowed
                           if code in COUNTRY_ALIASES)
    found: list = []
    for code, aliases in candidates:
        if code in found:
            continue
        if any(alias_hit(text, alias) for alias in aliases):
            found.append(code)
    return tuple(found)


def detect_fatalities(text: str) -> Optional[int]:
    """The HIGHEST count any pattern found — `rss_extractor.py:323-346`.

    `max`, not first: "Strike kills 5; toll rose to 30" reports 30. None
    means no count was stated, which stays distinct from zero all the way
    to the score — zero deaths and an unstated toll are different facts
    and the tier ladder treats them differently.
    """
    if not text:
        return None
    counts: list = []
    for pattern in (NUMERIC_FATALITIES, NUMERIC_FATALITIES_INVERTED):
        for match in pattern.finditer(text):
            try:
                counts.append(int(match.group(1)))
            except (ValueError, IndexError):
                pass
    for match in WORD_FATALITIES.finditer(text):
        word = match.group(1).lower()
        if word in WORDS:
            counts.append(WORDS[word])
    return max(counts) if counts else None


def has_kinetic_verb(text: str) -> bool:
    return bool(text and KINETIC_VERBS.search(text))


def has_escalation_verb(text: str) -> bool:
    return bool(text and ESCALATION_VERBS.search(text))


def extract_all(text: str,
                allowed_countries: Optional[Sequence[str]] = None) -> tuple:
    """One match per detected country — `rss_extractor.py:410-455`.

    The verb gate is shared across every country in the text on purpose:
    "Russia attacks Ukraine, kills 12" is one event involving both, and
    the per-scenario participant filter downstream routes each country's
    contribution. Splitting the gate per country would drop the attacker
    from an article that names only the victim's casualties.
    """
    if not text:
        return ()
    countries = detect_countries(text, allowed=allowed_countries)
    if not countries:
        return ()
    fatalities = detect_fatalities(text)
    kinetic = has_kinetic_verb(text)
    escalation = has_escalation_verb(text)
    if fatalities is None and not kinetic and not escalation:
        return ()
    summary = text.strip()[:SUMMARY_LIMIT]
    if fatalities is not None:
        count, confidence = int(fatalities), CONFIDENCE_FATALITIES
    elif kinetic:
        count, confidence = 0, CONFIDENCE_KINETIC
    else:
        count, confidence = 0, CONFIDENCE_ESCALATION
    return tuple(KineticMatch(country=code, fatalities=count,
                              summary=summary, source="regex",
                              confidence=confidence)
                 for code in countries)


def raw_score(match: KineticMatch) -> float:
    """S1-SENSI-028's three-tier map — `background_observer.py:387-391`.

    Written as a ladder over CONFIDENCE rather than over the tier that
    produced it, exactly as production does, so an extractor that later
    emits an intermediate confidence lands on the same rung in both
    systems.
    """
    if match.confidence >= CONFIDENCE_FATALITIES:
        return min(SCORE_CAP,
                   SCORE_FATALITY_BASE + SCORE_PER_FATALITY * match.fatalities)
    if match.confidence >= CONFIDENCE_KINETIC:
        return SCORE_KINETIC
    return SCORE_ESCALATION


def uncovered(participants) -> tuple:
    """Participants with no alias — `rss_extractor.py:234-241`.

    Reported, never fatal: an uncovered country simply produces no match,
    and having SOME observation beats having none (NP1). The gap belongs
    in the cycle record so it is visible rather than inferred.
    """
    return tuple(sorted(code for code in set(participants)
                        if code not in COUNTRY_ALIASES))


__all__ = ["COUNTRY_ALIASES", "WORDS", "KineticMatch", "SUMMARY_LIMIT",
           "NUMERIC_FATALITIES", "NUMERIC_FATALITIES_INVERTED",
           "WORD_FATALITIES", "KINETIC_VERBS", "ESCALATION_VERBS",
           "CONFIDENCE_FATALITIES", "CONFIDENCE_KINETIC",
           "CONFIDENCE_ESCALATION", "SCORE_KINETIC", "SCORE_ESCALATION",
           "SCORE_FATALITY_BASE", "SCORE_PER_FATALITY", "SCORE_CAP",
           "alias_hit", "detect_countries", "detect_fatalities",
           "has_kinetic_verb", "has_escalation_verb", "extract_all",
           "raw_score", "uncovered"]
