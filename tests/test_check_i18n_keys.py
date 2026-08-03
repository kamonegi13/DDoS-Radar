"""Tests for scripts/check_i18n_keys.py — Japanese-only UI audit.

Pins the parser/scanner contracts so a refactor of the regexes can't
silently start letting unknown keys through, and pins the
untranslated-value detector — the gate that stops an English string from
reaching the analyst (docs/design/ja-localization.md §6).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from check_i18n_keys import (  # noqa: E402
    Report,
    _needs_translation,
    parse_strings,
    scan_html,
    scan_js,
)


def parse_strings_keys(path):
    """Keys only — these tests predate the (keys, untranslated) tuple."""
    return parse_strings(path)[0]


# ── parse_strings_keys ────────────────────────────────────────────────────


def test_parse_strings_keys_extracts_keys_inside_strings_block(tmp_path):
    src = tmp_path / "i18n.js"
    src.write_text(
        """
const STRINGS = {
    'foo.bar': 'val 1',
    'foo.baz': 'val 2',
    'foo.qux': 'val 3',
};
""",
        encoding="utf-8",
    )
    keys = parse_strings_keys(src)
    assert keys == {"foo.bar", "foo.baz", "foo.qux"}


def test_parse_strings_keys_handles_double_quoted_keys(tmp_path):
    src = tmp_path / "i18n.js"
    src.write_text(
        """
const STRINGS = {
    "with.double": 'val',
    'with.single': 'val',
};
""",
        encoding="utf-8",
    )
    keys = parse_strings_keys(src)
    assert keys == {"with.double", "with.single"}


def test_parse_strings_keys_returns_empty_when_no_strings_block(tmp_path):
    src = tmp_path / "i18n.js"
    src.write_text("const FOO = { 'a': 'A' };", encoding="utf-8")
    assert parse_strings_keys(src) == set()


# ── scan_html ──────────────────────────────────────────────────────────────


def test_scan_html_extracts_all_data_i18n_variants(tmp_path):
    p = tmp_path / "index.html"
    p.write_text(
        """
<div data-i18n="plain.key">x</div>
<div data-i18n-html="html.key">x</div>
<div data-i18n-tip="tip.key">x</div>
<input data-i18n-ph="ph.key">
<div data-i18n='single.quote.key'>x</div>
""",
        encoding="utf-8",
    )
    keys = scan_html(p)
    assert keys == {
        "plain.key", "html.key", "tip.key", "ph.key", "single.quote.key",
    }


def test_scan_html_ignores_lookalike_attrs(tmp_path):
    p = tmp_path / "index.html"
    p.write_text(
        """
<div data-i18n-something-else="not.captured">x</div>
<div data-other="ignored">x</div>
""",
        encoding="utf-8",
    )
    assert scan_html(p) == set()


# ── scan_js ────────────────────────────────────────────────────────────────


def test_scan_js_captures_string_literal_t_calls(tmp_path, monkeypatch):
    import check_i18n_keys
    monkeypatch.setattr(check_i18n_keys, "_REPO_ROOT", tmp_path)

    p = tmp_path / "code.js"
    p.write_text(
        """
function render() {
    const a = _t('alpha.one');
    const b = _t("beta.two", {n: 2});
    const c = _t('gamma.three');
}
""",
        encoding="utf-8",
    )
    refs, opaque = scan_js(p)
    assert refs == {"alpha.one", "beta.two", "gamma.three"}
    assert opaque == []


def test_scan_js_flags_template_literal_calls_as_opaque(tmp_path, monkeypatch):
    import check_i18n_keys
    monkeypatch.setattr(check_i18n_keys, "_REPO_ROOT", tmp_path)

    p = tmp_path / "code.js"
    p.write_text(
        """
const a = _t(`prefix.${id}`);
const b = _t(varName);
const c = _t('static.key');
""",
        encoding="utf-8",
    )
    refs, opaque = scan_js(p)
    assert refs == {"static.key"}
    assert len(opaque) == 2
    line_nos = sorted(ln for _, ln in opaque)
    assert line_nos == [2, 3]


def test_scan_js_excludes_function_t_definition(tmp_path, monkeypatch):
    """`function _t(key, ...)` must not register as an opaque call site."""
    import check_i18n_keys
    monkeypatch.setattr(check_i18n_keys, "_REPO_ROOT", tmp_path)

    p = tmp_path / "code.js"
    p.write_text(
        """
function _t(key, params) {
    return key;
}
const a = _t('real.key');
""",
        encoding="utf-8",
    )
    refs, opaque = scan_js(p)
    assert "real.key" in refs
    assert opaque == []


def test_scan_js_does_not_match_other_t_named_functions(tmp_path, monkeypatch):
    """`my_t('x')` and `_test('x')` must NOT register."""
    import check_i18n_keys
    monkeypatch.setattr(check_i18n_keys, "_REPO_ROOT", tmp_path)

    p = tmp_path / "code.js"
    p.write_text(
        """
const a = my_t('not.captured');
const b = _test('not.captured');
const c = abc_t('not.captured');
""",
        encoding="utf-8",
    )
    refs, _ = scan_js(p)
    assert refs == set()


# ── untranslated-value detection ──────────────────────────────────────────


@pytest.mark.parametrize("value", [
    "Threat Level",
    "Open the audit-trace drilldown",
    "No feedback yet for this conclusion",
    "Acknowledge",
])
def test_needs_translation_flags_english_prose(value):
    assert _needs_translation("some.key", value) is True


@pytest.mark.parametrize("value", [
    "\u8105\u5a01\u30ec\u30d9\u30eb",                    # plain Japanese
    "TL3 \u306b\u4e0a\u6607",                        # mixed
    "recall \u304c\u4f4e\u4e0b",                      # keeps an English term
])
def test_needs_translation_accepts_japanese(value):
    assert _needs_translation("some.key", value) is False


@pytest.mark.parametrize("value", [
    "CRITICAL",          # DEFCON-style level name (\u00a72)
    "SHA-256",           # acronym
    "{n}",               # bare placeholder
    "\u25b6",                 # symbol only
    "42",                # number
    "Recall (TP/(TP+FN))",   # formula built from kept-English terms
])
def test_needs_translation_accepts_codes_and_symbols(value):
    assert _needs_translation("some.key", value) is False


def test_needs_translation_honours_explicit_key_allowlist():
    """Identifier-shaped values are exempted per key, not by regex — a
    pattern loose enough to pass `eps={eps}` would also pass real English."""
    assert _needs_translation("discovery.panel.eps", "eps={eps}") is False
    assert _needs_translation("some.other.key", "eps={eps}") is True


def test_parse_strings_reports_untranslated_values(tmp_path):
    p = tmp_path / "i18n.js"
    p.write_text(
        "const STRINGS = {\n"
        "    'a.ok': '\u8105\u5a01\u30ec\u30d9\u30eb',\n"
        "    'a.code': 'CRITICAL',\n"
        "    'a.bad': 'Threat Level',\n"
        "};\n",
        encoding="utf-8",
    )
    keys, untranslated = parse_strings(p)
    assert keys == {"a.ok", "a.code", "a.bad"}
    assert untranslated == [("a.bad", "Threat Level")]


# ── Report (derived sets + JA-only shell) ─────────────────────────────────


def test_report_undefined_refs_are_referenced_minus_defined():
    r = Report(
        defined_keys=frozenset({"a", "b", "c"}),
        referenced_keys=frozenset({"a", "x", "y"}),
    )
    assert r.undefined_refs == {"x", "y"}


def test_report_unused_keys_are_defined_minus_referenced():
    r = Report(
        defined_keys=frozenset({"a", "b", "c"}),
        referenced_keys=frozenset({"a", "x"}),
    )
    assert r.unused_keys == {"b", "c"}


def test_report_ja_only_requires_no_en_guide_and_lang_ja():
    base = dict(defined_keys=frozenset(), referenced_keys=frozenset())
    assert Report(**base, guide_en_count=0, html_lang_ja=True).ja_only_ok
    assert not Report(**base, guide_en_count=1, html_lang_ja=True).ja_only_ok
    assert not Report(**base, guide_en_count=0, html_lang_ja=False).ja_only_ok


def test_report_translation_ok_is_false_when_untranslated_present():
    base = dict(defined_keys=frozenset(), referenced_keys=frozenset())
    assert Report(**base).translation_ok is True
    assert Report(**base, untranslated=(("k", "English"),)).translation_ok is False


def test_report_to_dict_shape():
    r = Report(
        defined_keys=frozenset({"a", "b"}),
        referenced_keys=frozenset({"a", "x"}),
        opaque_calls=(("file.js", 10),),
        untranslated=(("k", "English"),),
        guide_en_count=0,
        html_lang_ja=True,
    )
    d = r.to_dict()
    assert d["defined_count"] == 2
    assert d["referenced_count"] == 2
    assert d["undefined_refs"] == ["x"]
    assert d["unused_keys"] == ["b"]
    assert d["opaque_calls"] == [{"file": "file.js", "line": 10}]
    assert d["untranslated"] == [{"key": "k", "value": "English"}]
    assert d["guide_en_blocks"] == 0
    assert d["html_lang_ja"] is True
    assert d["ja_only_ok"] is True
    assert d["translation_ok"] is False


# ── End-to-end against live tree ───────────────────────────────────────────


def test_live_tree_has_zero_undefined_refs():
    """Regression: undefined_refs (referenced but missing from STRINGS) stays
    at zero. If this fails, either fix the missing key or the call site.
    """
    from check_i18n_keys import build_report
    report = build_report()
    assert report.undefined_refs == frozenset(), (
        f"Undefined STRINGS refs found: {sorted(report.undefined_refs)}"
    )


def test_live_tree_has_no_untranslated_strings():
    """Regression: every STRINGS value is Japanese or a recognized code.
    A failure here means a string would reach the analyst in English."""
    from check_i18n_keys import build_report
    report = build_report()
    assert report.translation_ok, (
        "Untranslated STRINGS values: "
        f"{[k for k, _ in report.untranslated][:10]}"
    )


def test_live_tree_is_japanese_only_shell():
    """Regression: the bilingual guide stays retired and <html lang="ja">."""
    from check_i18n_keys import build_report
    report = build_report()
    assert report.guide_en_count == 0, (
        f"{report.guide_en_count} .guide-lang-en block(s) came back"
    )
    assert report.html_lang_ja, '<html lang="ja"> missing'
