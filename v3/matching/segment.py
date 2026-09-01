"""Script-aware segmentation — the whole of F-09's repair.

The defect is one line: `re.findall(r"[a-z]{3,}", headline.lower())`
(intel_queue.py:341). A Japanese, Chinese, Russian or Arabic headline
matches nothing, `_jaccard` returns 0.0 against the empty set, and those
sources can never be recorded as corroborating one another (:697-702).
D2 rates it CRITICAL and NP2-direct: the convergence input is
structurally restricted to the Anglosphere, in a tool whose premise is
multilingual OSINT.

The repair has two halves, and only the second is interesting:

  * a character class of `[a-z]` cannot be widened into correctness. The
    normalizer works by Unicode CATEGORY (strip P* and S*), so a dash, an
    ellipsis, a CJK interpunct and a bracket are all handled without
    anybody enumerating them.
  * splitting on whitespace is a writing-system assumption, not a
    universal. Han, Kana, Hangul and Thai do not space their words. Those
    runs are segmented into character bigrams — the standard technique in
    CJK information retrieval, and specifically chosen because it needs no
    morphological dictionary, no model, and no network. It is a pure
    function of the string, which is what parity replay requires.

Everything here is deterministic and side-effect free. Ruling 2 defines
F-09's closure as exactly this: non-Latin headlines stop tokenizing to
nothing. Cross-language matching (Tier 2) is a separate, default-off
enhancement, because it would make the answer depend on a model response
and S5-VERIF-022 would then have to record every one.
"""
from __future__ import annotations

import unicodedata

from v3.kernel.errors import DomainError

#: A token from a spaced script needs at least this many characters. The
#: legacy floor of 3 was a Latin assumption: Cyrillic and Arabic carry
#: meaning in two-character words ("МИД"), and excluding them would be a
#: milder version of the same bias the defect is about.
MIN_WORD_LENGTH = 2

#: Runs in these scripts are segmented into character n-grams of this
#: size rather than on whitespace.
NGRAM_SIZE = 2

# Codepoint ranges for the writing systems that do not delimit words with
# spaces. `unicodedata` exposes no script property, so the ranges are
# stated here rather than guessed from category (Han and Latin are both
# category Lo/Lu and would be indistinguishable).
_UNSPACED_RANGES: tuple[tuple[int, int], ...] = (
    (0x3040, 0x309F),   # Hiragana
    (0x30A0, 0x30FF),   # Katakana
    (0x31F0, 0x31FF),   # Katakana phonetic extensions
    (0x3400, 0x4DBF),   # CJK Unified Ideographs Extension A
    (0x4E00, 0x9FFF),   # CJK Unified Ideographs
    (0xF900, 0xFAFF),   # CJK Compatibility Ideographs
    (0x1100, 0x11FF),   # Hangul Jamo
    (0x3130, 0x318F),   # Hangul Compatibility Jamo
    (0xAC00, 0xD7AF),   # Hangul Syllables
    (0x0E00, 0x0E7F),   # Thai
    (0x0E80, 0x0EFF),   # Lao
    (0x1780, 0x17FF),   # Khmer
)


def is_unspaced(character: str) -> bool:
    """True when this character belongs to a script without word spaces."""
    codepoint = ord(character)
    return any(low <= codepoint <= high for low, high in _UNSPACED_RANGES)


def normalize(text: str) -> str:
    """NFKC, casefold, and strip punctuation/symbols BY CATEGORY.

    Category-based stripping is the point: the legacy tokenizer's
    character class silently discarded every script it did not enumerate,
    and any hand-maintained list of "punctuation to remove" would develop
    the same blind spots. `P*` and `S*` cover the em dash, the ellipsis,
    the CJK interpunct and the corner bracket without naming any of them.

    Stripped characters become spaces rather than vanishing, so that
    `台湾・海峡` cannot produce the bigram `湾海` across the break — a
    match on a boundary that is not there.
    """
    if not isinstance(text, str):
        raise DomainError(
            f"matching operates on text, got {type(text).__name__}. A "
            f"non-string here means a caller passed a payload where a "
            f"headline belongs.")
    folded = unicodedata.normalize("NFKC", text).casefold()
    # casefold can re-introduce composed forms (ß -> ss); normalize again
    # so the result is canonical regardless of the input's spelling.
    folded = unicodedata.normalize("NFKC", folded)
    return "".join(
        " " if unicodedata.category(character)[0] in ("P", "S", "Z", "C")
        else character
        for character in folded)


def _runs(text: str) -> list[tuple[bool, str]]:
    """Split into maximal runs of one segmentation class.

    A run boundary is either a script change or whitespace. Both matter:
    without the script boundary, `台湾PLA` would produce the bigram `湾p`,
    which is a token neither language contains.
    """
    runs: list[tuple[bool, str]] = []
    current: list[str] = []
    current_class: bool | None = None
    for character in text:
        if character.isspace():
            if current:
                runs.append((bool(current_class), "".join(current)))
                current, current_class = [], None
            continue
        character_class = is_unspaced(character)
        if current_class is None or character_class == current_class:
            current.append(character)
            current_class = character_class
            continue
        runs.append((bool(current_class), "".join(current)))
        current, current_class = [character], character_class
    if current:
        runs.append((bool(current_class), "".join(current)))
    return runs


def tokens(text: str) -> frozenset[str]:
    """The token set used for similarity. Non-empty for every script.

    Spaced runs contribute whole words of at least `MIN_WORD_LENGTH`;
    unspaced runs contribute character bigrams. A one-character unspaced
    run contributes itself, because it has no bigram and dropping it would
    lose the only content there is.
    """
    normalized = normalize(text)
    collected: set[str] = set()
    for unspaced, run in _runs(normalized):
        if not unspaced:
            if len(run) >= MIN_WORD_LENGTH:
                collected.add(run)
            continue
        if len(run) < NGRAM_SIZE:
            collected.add(run)
            continue
        collected.update(run[index:index + NGRAM_SIZE]
                         for index in range(len(run) - NGRAM_SIZE + 1))
    return frozenset(collected)


__all__ = ["normalize", "tokens", "is_unspaced", "MIN_WORD_LENGTH",
           "NGRAM_SIZE"]
