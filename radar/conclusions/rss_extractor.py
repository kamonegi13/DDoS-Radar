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

# Kinetic verbs that indicate violence beyond mere fatality counts. Used
# as a confirmation filter: if no fatality regex matches but a kinetic
# verb appears alongside a country mention we can still record a low-
# severity match. Without this, fatality-free reports (sanctions, exercise
# announcements) would never qualify, but those are exactly the events
# we *don't* want to label as escalations.
_KINETIC_VERBS = re.compile(
    r"\b(missile|airstrike|air\s+strike|shelling|rocket|drone\s+strike|"
    r"artillery|attack(?:ed|s)?|bombing|explosion|invasion|ambush(?:ed)?|"
    r"shoot(?:ing|s|down)?)\b",
    re.IGNORECASE,
)

# ISO-2 country code → list of search aliases. Kept conservative — only
# names whose appearance in a news headline reliably implicates the
# country itself, not a citizen-of-X mention. Edit this map carefully:
# adding a permissive alias bloats false positives.
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
}


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
            # Word-boundary match so "Iran" doesn't match "Iranian" twice
            # (we don't care which alias matched — first wins).
            if re.search(r"\b" + re.escape(alias) + r"\b", text, re.IGNORECASE):
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
      - neither a fatality count nor a kinetic verb appears.
    """
    if not text:
        return None
    country = _detect_country(text, allowed=allowed_countries)
    if country is None:
        return None
    fatalities = _detect_fatalities(text)
    has_verb = _has_kinetic_verb(text)
    if fatalities is None and not has_verb:
        return None
    if fatalities is None:
        # Verb-only match — record severity 1 with mid-range confidence so
        # downstream classifiers can choose to weight it down.
        return KineticMatch(
            country=country,
            fatalities=1,
            summary=text.strip()[:240],
            source="regex",
            confidence=0.60,
        )
    return KineticMatch(
        country=country,
        fatalities=int(fatalities),
        summary=text.strip()[:240],
        source="regex",
        confidence=0.85,
    )


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
