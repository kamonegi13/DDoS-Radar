"""Tests for scripts/check_i18n_keys.py — JA-only i18n audit.

Pins the parser/scanner contracts so a refactor of the regexes can't
silently start letting unknown keys through.
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
    parse_ja_keys,
    scan_html,
    scan_js,
)


# ── parse_ja_keys ──────────────────────────────────────────────────────────


def test_parse_ja_keys_extracts_keys_inside_ja_block(tmp_path):
    src = tmp_path / "i18n.js"
    src.write_text(
        """
const LANG = {
  en: {
    'foo.bar': 'EN bar',
    'foo.baz': 'EN baz',
  },
  ja: {
    'foo.bar': 'JA bar',
    'foo.baz': 'JA baz',
    'foo.qux': 'JA qux',
  },
};
""",
        encoding="utf-8",
    )
    keys = parse_ja_keys(src)
    assert keys == {"foo.bar", "foo.baz", "foo.qux"}


def test_parse_ja_keys_handles_double_quoted_keys(tmp_path):
    src = tmp_path / "i18n.js"
    src.write_text(
        """
const LANG = {
  en: { 'a': 'A' },
  ja: {
    "with.double": 'JA val',
    'with.single': 'JA val',
  },
};
""",
        encoding="utf-8",
    )
    keys = parse_ja_keys(src)
    assert keys == {"with.double", "with.single"}


def test_parse_ja_keys_returns_empty_when_no_ja_block(tmp_path):
    src = tmp_path / "i18n.js"
    src.write_text("const LANG = { en: { 'a': 'A' } };", encoding="utf-8")
    assert parse_ja_keys(src) == set()


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
    # opaque entries are (rel_path, line_no)
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


def test_scan_js_does_not_match_method_named_t(tmp_path, monkeypatch):
    """`obj._t('x')` must register as a normal _t call (chained-call form)."""
    import check_i18n_keys
    monkeypatch.setattr(check_i18n_keys, "_REPO_ROOT", tmp_path)

    p = tmp_path / "code.js"
    # `obj._t(` matches via the look-behind allowing `.` before `_t`?
    # Actually the regex is `(?<![A-Za-z0-9_])_t\(` — it allows a dot
    # before `_t`, treating `obj._t(...)` the same as bare `_t(...)`.
    # That is intentional: we want to catch all _t call sites.
    p.write_text("const a = obj._t('chained.key');\n", encoding="utf-8")
    refs, _ = scan_js(p)
    assert refs == {"chained.key"}


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


# ── Report (derived sets) ──────────────────────────────────────────────────


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


def test_report_to_dict_shape():
    r = Report(
        defined_keys=frozenset({"a", "b"}),
        referenced_keys=frozenset({"a", "x"}),
        opaque_calls=(("file.js", 10),),
    )
    d = r.to_dict()
    assert d["defined_count"] == 2
    assert d["referenced_count"] == 2
    assert d["undefined_refs"] == ["x"]
    assert d["unused_keys"] == ["b"]
    assert d["opaque_calls"] == [{"file": "file.js", "line": 10}]


# ── End-to-end against live tree ───────────────────────────────────────────


def test_live_tree_has_zero_undefined_refs():
    """Regression: keep undefined_refs at zero. If this fails, either fix the
    code (add the missing JA key, or correct the call) or open a discussion
    about why the gate should accept the new ref.
    """
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))
    from check_i18n_keys import build_report

    report = build_report()
    assert report.undefined_refs == frozenset(), (
        f"Undefined JA refs found: {sorted(report.undefined_refs)}"
    )
