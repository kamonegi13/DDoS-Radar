"""Tests for scripts/check_i18n_keys.py — EN-only UI + GUIDE parity audit.

Pins the parser/scanner contracts so a refactor of the regexes can't
silently start letting unknown keys through. The GUIDE parity check is
also pinned because long-form prose is the one place we still demand
hand-curated bilingual coverage (CLAUDE.md §3.2).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from check_i18n_keys import (  # noqa: E402
    Report,
    count_guide_blocks,
    parse_strings_keys,
    scan_html,
    scan_js,
)


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


# ── count_guide_blocks (GUIDE parity) ──────────────────────────────────────


def test_count_guide_blocks_paired(tmp_path):
    p = tmp_path / "index.html"
    p.write_text(
        """
<div class="guide-lang-en" lang="en">EN content</div>
<div class="guide-lang-ja" lang="ja" style="display:none;">JA content</div>
<div class="guide-lang-en" lang="en">More EN</div>
<div class="guide-lang-ja" lang="ja">More JA</div>
""",
        encoding="utf-8",
    )
    en, ja, en_lang, ja_lang = count_guide_blocks(p)
    assert en == 2
    assert ja == 2
    assert en_lang == 2
    assert ja_lang == 2


def test_count_guide_blocks_detects_orphan(tmp_path):
    p = tmp_path / "index.html"
    p.write_text(
        """
<div class="guide-lang-en" lang="en">EN content</div>
<div class="guide-lang-ja" lang="ja">JA content</div>
<div class="guide-lang-ja" lang="ja">orphan JA</div>
""",
        encoding="utf-8",
    )
    en, ja, _en_lang, _ja_lang = count_guide_blocks(p)
    assert en == 1
    assert ja == 2


def test_count_guide_blocks_handles_multi_class(tmp_path):
    p = tmp_path / "index.html"
    p.write_text(
        """
<div class="guide-section guide-lang-en" lang="en">EN</div>
<div class="guide-lang-ja some-other-class" lang="ja">JA</div>
""",
        encoding="utf-8",
    )
    en, ja, _en_lang, _ja_lang = count_guide_blocks(p)
    assert en == 1
    assert ja == 1


def test_count_guide_blocks_lang_attribute_required(tmp_path):
    """WCAG 3.1.2 — guide blocks without the matching `lang` attribute are
    counted under the block totals but excluded from the with-lang totals,
    so the `guide_lang_attr_ok` gate fires."""
    p = tmp_path / "index.html"
    p.write_text(
        """
<div class="guide-lang-en" lang="en">EN with lang</div>
<div class="guide-lang-en">EN missing lang</div>
<div class="guide-lang-ja" lang="ja">JA with lang</div>
<div class="guide-lang-ja">JA missing lang</div>
""",
        encoding="utf-8",
    )
    en, ja, en_lang, ja_lang = count_guide_blocks(p)
    assert (en, ja) == (2, 2)
    assert (en_lang, ja_lang) == (1, 1)


# ── Report (derived sets + parity) ────────────────────────────────────────


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


def test_report_guide_parity_flags_imbalance():
    matched = Report(
        defined_keys=frozenset(), referenced_keys=frozenset(),
        guide_en_count=10, guide_ja_count=10,
    )
    assert matched.guide_parity_ok is True

    skewed = Report(
        defined_keys=frozenset(), referenced_keys=frozenset(),
        guide_en_count=10, guide_ja_count=11,
    )
    assert skewed.guide_parity_ok is False


def test_report_to_dict_shape():
    r = Report(
        defined_keys=frozenset({"a", "b"}),
        referenced_keys=frozenset({"a", "x"}),
        opaque_calls=(("file.js", 10),),
        guide_en_count=3, guide_ja_count=3,
    )
    d = r.to_dict()
    assert d["defined_count"] == 2
    assert d["referenced_count"] == 2
    assert d["undefined_refs"] == ["x"]
    assert d["unused_keys"] == ["b"]
    assert d["opaque_calls"] == [{"file": "file.js", "line": 10}]
    assert d["guide_en_blocks"] == 3
    assert d["guide_ja_blocks"] == 3
    assert d["guide_parity_ok"] is True


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


def test_live_tree_has_balanced_guide_parity():
    """Regression: every .guide-lang-en block needs a sibling .guide-lang-ja."""
    from check_i18n_keys import build_report
    report = build_report()
    assert report.guide_parity_ok, (
        f"INTEL GUIDE parity broken: "
        f"{report.guide_en_count} EN vs {report.guide_ja_count} JA"
    )
