"""WP-2.5 — F-09 Tier 1: language-independent matching.

The defect's definition is precise and so is its resolution test: the
current tokenizer is `re.findall(r"[a-z]{3,}", headline.lower())`, so a
Japanese, Chinese, Russian or Arabic headline produces **zero tokens**,
Jaccard against an empty set is 0.0, and those sources can therefore never
be recorded as corroborating one another. D2 rates it CRITICAL and a
direct NP2 hit — the convergence input is structurally biased toward the
Anglosphere.

Ruling 2 defines resolution as: non-Latin headlines stop producing empty
token sets. Every script below is tested for exactly that, plus the
determinism the parity harness needs.
"""
import pytest

from v3.matching import (MatchVerdict, jaccard, normalize, same_event, tokens)

# Real-shaped headlines, one per script the current tokenizer silently drops.
JAPANESE = "台湾海峡で中国軍の大規模演習、自衛隊が警戒監視を強化"
CHINESE = "解放军在台湾海峡举行大规模军事演习"
RUSSIAN = "МИД России заявил о готовности к переговорам по Украине"
ARABIC = "وزارة الخارجية تعلن عن إجراءات جديدة بشأن الملاحة البحرية"
KOREAN = "북한 미사일 발사에 한미일 공동 대응 협의"
THAI = "กองทัพเรือไทยเพิ่มการลาดตระเวนในทะเลอันดามัน"
ENGLISH = "Taiwan reports large-scale PLA exercise near the median line"


class TestTheDefectItself:
    """S1: every one of these produced an empty set before."""

    @pytest.mark.parametrize("headline,label", [
        (JAPANESE, "Japanese"), (CHINESE, "Chinese"), (RUSSIAN, "Russian"),
        (ARABIC, "Arabic"), (KOREAN, "Korean"), (THAI, "Thai"),
        (ENGLISH, "English"),
    ])
    def test_every_script_produces_a_non_empty_token_set(self, headline,
                                                         label):
        assert tokens(headline), f"{label} tokenized to nothing"

    @pytest.mark.parametrize("headline", [JAPANESE, CHINESE, RUSSIAN, ARABIC,
                                          KOREAN, THAI])
    def test_the_legacy_tokenizer_would_have_produced_nothing(self, headline):
        """Pins the defect so the fix cannot be reverted unnoticed."""
        import re
        assert re.findall(r"[a-z]{3,}", headline.lower()) == []

    @pytest.mark.parametrize("headline", [JAPANESE, CHINESE, RUSSIAN, ARABIC,
                                          KOREAN, THAI, ENGLISH])
    def test_a_headline_corroborates_itself(self, headline):
        """The floor: identical text must match in every script."""
        assert jaccard(headline, headline) == pytest.approx(1.0)

    def test_two_non_latin_sources_can_corroborate_each_other(self):
        """The NP2 consequence, not just the tokenizer's output.

        Two Russian outlets reporting the same event must be able to
        record each other as corroboration — impossible before, because
        both sides were empty sets.
        """
        tass = "МИД России заявил о готовности к переговорам"
        interfax = "МИД России заявил о готовности к переговорам по Украине"
        assert jaccard(tass, interfax) > 0.5
        assert same_event(tass, interfax).same_event is True


class TestNormalization:
    def test_nfkc_folds_full_width_to_half_width(self):
        assert normalize("ＴＡＩＷＡＮ") == normalize("taiwan")

    def test_case_is_folded(self):
        assert normalize("Taiwan STRAIT") == normalize("taiwan strait")

    def test_german_sharp_s_folds(self):
        """casefold, not lower — lower() leaves ß alone."""
        assert normalize("STRASSE") == normalize("straße")

    def test_punctuation_is_removed_by_category_not_by_charclass(self):
        """P* and S* go, including marks no ASCII class would list."""
        assert tokens("taiwan—strait…report") == tokens("taiwan strait report")
        assert tokens("台湾・海峡「演習」") == tokens("台湾 海峡 演習")

    def test_digits_survive(self):
        assert "2026" in tokens("exercise 2026 begins")

    def test_empty_and_whitespace_yield_no_tokens(self):
        assert tokens("") == frozenset()
        assert tokens("   \n\t ") == frozenset()

    def test_punctuation_only_yields_no_tokens(self):
        assert tokens("!!! --- ...") == frozenset()


class TestWordBoundaryScripts:
    def test_latin_words_are_whitespace_segmented(self):
        assert "taiwan" in tokens(ENGLISH)
        assert "exercise" in tokens(ENGLISH)

    def test_minimum_length_is_two_not_three(self):
        """The old floor of 3 was a Latin assumption.

        Cyrillic and Arabic carry meaning in two-letter words; excluding
        them re-creates a milder version of the same bias.
        """
        assert "on" in tokens("on the strait")
        assert "мид" in tokens(RUSSIAN)

    def test_single_characters_are_dropped(self):
        assert tokens("a b c") == frozenset()

    def test_cyrillic_is_word_segmented_not_bigrammed(self):
        result = tokens("МИД России")
        assert "россии" in result

    def test_arabic_is_word_segmented(self):
        assert any(len(token) > 2 for token in tokens(ARABIC))

    def test_hyphenated_latin_splits(self):
        assert "large" in tokens("large-scale") and "scale" in tokens(
            "large-scale")


class TestBigramScripts:
    def test_han_is_bigrammed(self):
        result = tokens("台湾海峡")
        assert result == frozenset({"台湾", "湾海", "海峡"})

    def test_kana_is_bigrammed(self):
        assert "ミサ" in tokens("ミサイル")

    def test_hangul_is_bigrammed(self):
        assert "북한" in tokens("북한")

    def test_thai_is_bigrammed(self):
        assert tokens(THAI)

    def test_a_lone_ideograph_survives_as_itself(self):
        """A one-character run has no bigram; dropping it would lose it."""
        assert tokens("中") == frozenset({"中"})

    def test_bigrams_do_not_span_a_punctuation_break(self):
        """`台湾・海峡` must not produce the cross-boundary bigram 湾海."""
        assert "湾海" not in tokens("台湾・海峡")

    def test_bigrams_do_not_span_a_script_change(self):
        result = tokens("台湾PLA演習")
        assert "湾p" not in result and "a演" not in result
        assert "pla" in result


class TestMixedScript:
    def test_a_mixed_headline_yields_both_kinds_of_token(self):
        result = tokens("台湾海峡でPLAが演習")
        assert "pla" in result              # Latin run, word-segmented
        assert "台湾" in result              # Han run, bigrammed

    def test_a_shared_acronym_links_two_scripts(self):
        """The one cross-language link Tier 1 legitimately provides."""
        assert jaccard("PLA exercise near Taiwan", "台湾近海でPLAが演習") > 0.0


class TestJaccardAndVerdict:
    def test_identical_sets_score_one(self):
        assert jaccard("taiwan strait", "strait taiwan") == pytest.approx(1.0)

    def test_disjoint_sets_score_zero(self):
        assert jaccard("taiwan strait", "baltic pipeline") == 0.0

    def test_two_empty_texts_are_not_declared_the_same_event(self):
        """Empty-vs-empty is an absence of evidence, not agreement.

        The parity comparator treats two empty contributor sets as
        agreement because both systems genuinely saw nothing. Here the
        question is different — 'are these the same event?' — and two
        headlines that tokenize to nothing are not evidence of anything.
        """
        verdict = same_event("...", "!!!")
        assert verdict.similarity == 0.0
        assert verdict.same_event is False

    def test_the_verdict_carries_no_score(self):
        """S5 owns what a match is worth (O-17)."""
        verdict = same_event(JAPANESE, JAPANESE)
        assert isinstance(verdict, MatchVerdict)
        assert not hasattr(verdict, "score")

    def test_the_threshold_is_explicit(self):
        pair = ("taiwan strait exercise", "taiwan strait report")
        assert same_event(*pair, threshold=0.1).same_event is True
        assert same_event(*pair, threshold=0.99).same_event is False

    def test_an_out_of_range_threshold_is_refused(self):
        from v3.kernel.errors import DomainError
        with pytest.raises(DomainError):
            same_event("a", "b", threshold=1.5)

    def test_tier_two_is_recorded_as_not_applied(self):
        """Ruling 2: Tier 2 is off, and the report says so rather than
        leaving the reader to assume cross-language matching happened."""
        verdict = same_event(RUSSIAN, CHINESE)
        assert verdict.tier == 1
        assert verdict.tier2_skipped_reason


class TestDeterminism:
    """Parity replay depends on this being a pure function of the string."""

    @pytest.mark.parametrize("headline", [JAPANESE, CHINESE, RUSSIAN, ARABIC,
                                          KOREAN, THAI, ENGLISH])
    def test_repeated_calls_agree(self, headline):
        assert tokens(headline) == tokens(headline)

    def test_token_sets_are_frozen(self):
        with pytest.raises(AttributeError):
            tokens(ENGLISH).add("x")

    def test_ordering_of_input_words_does_not_change_the_set(self):
        assert tokens("alpha beta gamma") == tokens("gamma alpha beta")

    def test_no_module_level_state_leaks_between_calls(self):
        first = tokens(JAPANESE)
        tokens(ENGLISH)
        assert tokens(JAPANESE) == first

    def test_a_non_string_is_refused(self):
        from v3.kernel.errors import DomainError
        with pytest.raises(DomainError):
            tokens(None)
