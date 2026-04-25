"""Tests for rss_narrative geographic relevance filter."""
import pytest
from radar.sensors.rss_narrative import (
    RssNarrativeSensor,
    _classify_article_geo,
    _geo_regex_cache,
)

# ── Test fixtures ────────────────────────────────────────────────────────────

# Minimal GEO_TERMS for testing (mirrors real structure)
_TEST_GEO_TERMS = {
    "UA": [
        "ukraine", "ukrainian", "kyiv", "kiev", "kharkiv", "kharkov",
        "odesa", "odessa", "zaporizhzhia", "zaporozhye", "crimea",
        "donbas", "donbass", "donetsk", "luhansk", "lugansk",
        "kherson", "mariupol", "azov",
    ],
    "IR": [
        "iran", "iranian", "tehran", "irgc", "revolutionary guard",
        "strait of hormuz", "persian gulf", "natanz", "khamenei",
    ],
    "TW": [
        "taiwan", "taiwanese", "taipei", "taiwan strait", "formosa",
        "penghu", "kinmen",
    ],
    "IL": [
        "israel", "israeli", "tel aviv", "jerusalem", "gaza",
        "west bank", "golan", "idf", "hezbollah", "hamas",
    ],
    "CN": [
        "china", "chinese", "beijing", "shanghai", "pla",
        "people's liberation army", "south china sea",
    ],
    "RU": [
        "russia", "russian", "moscow", "kremlin", "putin",
    ],
}


def _build_rss_xml(articles: list[dict]) -> str:
    """Build minimal RSS 2.0 XML for testing."""
    items = ""
    for art in articles:
        title = art.get("title", "")
        desc = art.get("desc", "")
        link = art.get("link", "")
        items += (
            f"<item>"
            f"<title>{title}</title>"
            f"<description>{desc}</description>"
            f"<link>{link}</link>"
            f"</item>"
        )
    return f'<?xml version="1.0"?><rss><channel>{items}</channel></rss>'


# ── _classify_article_geo unit tests ────────────────────────────────────────

class TestClassifyArticleGeo:
    """Unit tests for the article-level geographic classification."""

    def setup_method(self):
        # Clear compiled regex cache between tests to avoid cross-contamination
        _geo_regex_cache.clear()

    def test_match_returns_match(self):
        text = "ukraine forces advance near kyiv amid escalation"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "match"

    def test_other_returns_other(self):
        text = "iran irgc conducts military exercises in persian gulf"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "other"

    def test_generic_returns_generic(self):
        text = "global nuclear tensions rise amid arms race concerns"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "generic"

    def test_both_countries_returns_match(self):
        """Article mentioning both current and other theater → match (current takes priority)."""
        text = "ukraine and iran both face escalating security challenges"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "match"
        assert _classify_article_geo(text, "IR", _TEST_GEO_TERMS) == "match"

    def test_empty_terms_degrades_gracefully(self):
        """Theater with no GEO_TERMS entry → can only be 'other' or 'generic'."""
        text = "iran conducts military exercises near tehran"
        # "XX" has no GEO_TERMS → can't match. IR terms exist → "other"
        assert _classify_article_geo(text, "XX", _TEST_GEO_TERMS) == "other"

    def test_empty_terms_generic_article(self):
        """Theater with no GEO_TERMS + generic article → 'generic'."""
        text = "worldwide military spending reaches record levels"
        assert _classify_article_geo(text, "XX", _TEST_GEO_TERMS) == "generic"

    def test_word_boundary_prevents_substring(self):
        """Short terms must not match inside longer unrelated words."""
        # "iran" should not match "miranda" or "mirando"
        text = "commander miranda announces new strategic review"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "generic"

    def test_word_boundary_matches_standalone(self):
        """Short terms DO match when they appear as standalone words."""
        text = "iran announces new military doctrine"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "other"
        assert _classify_article_geo(text, "IR", _TEST_GEO_TERMS) == "match"

    def test_multi_word_term_matches(self):
        """Multi-word geographic terms match as substrings."""
        text = "naval exercises in the south china sea escalate tensions"
        assert _classify_article_geo(text, "CN", _TEST_GEO_TERMS) == "match"

    def test_transliteration_variant_matches(self):
        """TASS-style Russian transliterations should match UA theater."""
        text = "fighting intensifies near zaporozhye as forces advance"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "match"

    def test_transliteration_kharkov(self):
        text = "russian troops advance on kharkov front"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "match"

    def test_case_insensitive(self):
        """Input is already lowered by caller, but terms are stored lowercase."""
        text = "forces deployed near kyiv in response to escalation"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "match"

    def test_taiwan_strait(self):
        text = "pla vessels cross median line in taiwan strait"
        assert _classify_article_geo(text, "TW", _TEST_GEO_TERMS) == "match"

    def test_israel_gaza(self):
        text = "idf operations in gaza strip continue amid ceasefire talks"
        assert _classify_article_geo(text, "IL", _TEST_GEO_TERMS) == "match"
        # For UA theater, this is about IL → "other"
        assert _classify_article_geo(text, "UA", _TEST_GEO_TERMS) == "other"


# ── _count_keywords_in_rss with geo filter ──────────────────────────────────

class TestCountKeywordsGeoFilter:
    """Tests for keyword counting with geographic relevance filter."""

    def setup_method(self):
        _geo_regex_cache.clear()

    def test_excludes_other_country_articles(self):
        """Iran articles matching UA keywords should NOT count as UA hits."""
        xml = _build_rss_xml([
            {"title": "Ukraine escalation continues near Kyiv",
             "desc": "Military measures intensify"},
            {"title": "Iran escalation in Persian Gulf",
             "desc": "Military measures by IRGC forces"},
            {"title": "Global escalation fears grow",
             "desc": "Military measures worldwide"},
        ])
        keywords = ["escalation", "military measures"]
        hits, count = RssNarrativeSensor._count_keywords_in_rss(
            xml, keywords,
            current_country="UA",
            all_geo_terms=_TEST_GEO_TERMS,
        )
        # Article 1: UA match → counted
        # Article 2: IR (other) → excluded from hits
        # Article 3: generic → counted
        assert hits == 2
        assert count == 3  # denominator always unfiltered

    def test_article_count_always_unfiltered(self):
        """article_count must include ALL articles regardless of geo filter."""
        xml = _build_rss_xml([
            {"title": "Iran crisis deepens", "desc": "Tehran responds"},
            {"title": "China military exercise", "desc": "PLA conducts drills"},
            {"title": "Generic world news", "desc": "No geography here"},
        ])
        keywords = ["crisis", "military exercise"]
        hits, count = RssNarrativeSensor._count_keywords_in_rss(
            xml, keywords,
            current_country="UA",
            all_geo_terms=_TEST_GEO_TERMS,
        )
        # All 3 are "other" (IR, CN) or keyword miss — UA gets 0 hits
        # But article_count must be 3
        assert count == 3
        assert hits == 0

    def test_backward_compat_no_geo(self):
        """Without geo params, all keyword matches count (legacy behavior)."""
        # Use a multi-word phrase so it matches via phrase tier (not atomic)
        xml = _build_rss_xml([
            {"title": "Iran military measures in Persian Gulf", "desc": "IRGC forces"},
            {"title": "Ukraine military measures near Kyiv", "desc": "Operations"},
        ])
        keywords = ["military measures"]
        hits_no_geo, count_no_geo = RssNarrativeSensor._count_keywords_in_rss(
            xml, keywords,
        )
        hits_with_geo, count_with_geo = RssNarrativeSensor._count_keywords_in_rss(
            xml, keywords,
            current_country="UA",
            all_geo_terms=_TEST_GEO_TERMS,
        )
        # Without geo: both articles count
        assert hits_no_geo == 2
        assert count_no_geo == 2
        # With geo: only UA article counts
        assert hits_with_geo == 1
        assert count_with_geo == 2  # denominator unchanged

    def test_empty_xml(self):
        hits, count = RssNarrativeSensor._count_keywords_in_rss(
            "", ["escalation"],
            current_country="UA",
            all_geo_terms=_TEST_GEO_TERMS,
        )
        assert hits == 0
        assert count == 0


# ── _get_burst_articles with geo filter ─────────────────────────────────────

class TestGetBurstArticlesGeoFilter:
    """Tests for burst article collection with geographic filter."""

    def setup_method(self):
        _geo_regex_cache.clear()

    def test_burst_excludes_other_country(self):
        """Burst articles should only include geo-relevant articles."""
        xml = _build_rss_xml([
            {"title": "Ukraine offensive operations near Donbas",
             "desc": "Escalation continues", "link": "https://example.com/1"},
            {"title": "Iran military measures in Persian Gulf",
             "desc": "Escalation in Hormuz", "link": "https://example.com/2"},
            {"title": "Global escalation fears",
             "desc": "Military measures worldwide", "link": "https://example.com/3"},
        ])
        keywords = ["escalation", "military measures", "offensive operations"]
        articles = RssNarrativeSensor._get_burst_articles(
            xml, keywords, max_articles=4,
            current_country="UA",
            all_geo_terms=_TEST_GEO_TERMS,
        )
        # Article 1: UA → included
        # Article 2: IR → excluded
        # Article 3: generic → included
        assert len(articles) == 2
        assert "Ukraine" in articles[0]["title"]
        assert "Global" in articles[1]["title"]

    def test_burst_backward_compat(self):
        """Without geo params, all matching articles are returned."""
        xml = _build_rss_xml([
            {"title": "Iran military measures", "desc": "IRGC forces"},
            {"title": "Ukraine military measures", "desc": "Kyiv ops"},
        ])
        keywords = ["military measures"]
        articles = RssNarrativeSensor._get_burst_articles(xml, keywords)
        assert len(articles) == 2


# ── Integration-style test ──────────────────────────────────────────────────

class TestGeoFilterIntegration:
    """End-to-end validation of the geo filter in a realistic scenario."""

    def setup_method(self):
        _geo_regex_cache.clear()

    def test_tass_mixed_articles_ua_country(self):
        """Simulate a TASS feed with articles about multiple regions.
        Only UA-relevant and generic articles should count for UA theater."""
        xml = _build_rss_xml([
            # UA-relevant
            {"title": "Russian forces advance near Zaporizhzhia",
             "desc": "Offensive operations continue in eastern Ukraine"},
            # IR-relevant (should be excluded from UA)
            {"title": "IRGC announces new missile capability",
             "desc": "Iran military measures in response to sanctions"},
            # IL-relevant (should be excluded from UA)
            {"title": "IDF operations in Gaza continue",
             "desc": "Escalation in the Middle East"},
            # Generic (should count for UA)
            {"title": "Nuclear escalation fears grow worldwide",
             "desc": "Military measures being considered globally"},
            # UA-relevant (TASS transliteration, phrase match via "offensive operations")
            {"title": "Offensive operations near Kharkov intensifies",
             "desc": "Mobilization of additional forces"},
        ])
        keywords = ["escalation", "military measures", "offensive operations",
                     "mobilization"]

        hits, count = RssNarrativeSensor._count_keywords_in_rss(
            xml, keywords,
            current_country="UA",
            all_geo_terms=_TEST_GEO_TERMS,
        )
        # Articles 1, 4, 5 → match or generic → 3 hits
        # Articles 2, 3 → other → excluded from hits
        # article_count = 5 (always total)
        assert hits == 3
        assert count == 5

        # Also verify burst articles
        burst = RssNarrativeSensor._get_burst_articles(
            xml, keywords, max_articles=10,
            current_country="UA",
            all_geo_terms=_TEST_GEO_TERMS,
        )
        assert len(burst) == 3
        titles = [a["title"] for a in burst]
        assert any("Zaporizhzhia" in t for t in titles)
        assert any("Kharkov" in t or "Offensive" in t for t in titles)
        assert any("Nuclear" in t for t in titles)
        # Iran and Gaza articles must NOT be in burst pool
        assert not any("IRGC" in t for t in titles)
        assert not any("Gaza" in t for t in titles)
