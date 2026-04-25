"""Static UI integrity checks.

Guards the classes of bugs that surfaced during the EVIDENCE/CHAIN UI polish
(Phase A, 2026-04): i18n keys referenced from markup / JS but missing in
one language dictionary, and vice versa.

Intentionally narrow scope — these are cheap structural checks, not visual
or behavioral tests. Visual regression for a live-data radar dashboard would
require freezing every sensor feed, which defeats the tool's purpose.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parent
I18N = ROOT / "i18n.js"
HTML = ROOT / "index.html"
JS = ROOT / "radar.js"

# Keys that are constructed at runtime from enum-like values and cannot be
# seen by a static scanner. Listed here so the test stays strict for
# literal-string keys while permitting these intentional dynamic patterns.
_DYNAMIC_PREFIXES = (
    "badge.",          # chain event badges (dynamic type)
    "dir.",            # direction labels keyed on enum value
    "cip.role.",       # participant role labels
    "sensor.",         # sensor names keyed from health report
    "sitrep.",         # sitrep sections keyed from template vars
    "chain.c2sync.",   # C2 sync branches
    "chain.llm_intel.",
)


def _extract_lang_keys(block: str) -> set[str]:
    """Pull the set of literal keys defined inside one LANG.<code> block."""
    return set(re.findall(r"'([A-Za-z0-9_.\-]+)'\s*:", block))


def _load_i18n() -> tuple[set[str], set[str]]:
    src = I18N.read_text(encoding="utf-8")
    # Split into en / ja halves. The file has `en: {` then `  },` then `ja: {`.
    m_en = re.search(r"\n  en:\s*\{(.*?)\n  \},\n", src, re.DOTALL)
    m_ja = re.search(r"\n  ja:\s*\{(.*?)\n  \},?\n", src, re.DOTALL)
    assert m_en, "Could not locate LANG.en block in i18n.js"
    assert m_ja, "Could not locate LANG.ja block in i18n.js"
    return _extract_lang_keys(m_en.group(1)), _extract_lang_keys(m_ja.group(1))


def _extract_html_keys() -> set[str]:
    html = HTML.read_text(encoding="utf-8")
    patterns = [
        r'data-i18n="([A-Za-z0-9_.\-]+)"',
        r'data-i18n-html="([A-Za-z0-9_.\-]+)"',
        r'data-i18n-tip="([A-Za-z0-9_.\-]+)"',
        r'data-i18n-ph="([A-Za-z0-9_.\-]+)"',
    ]
    keys: set[str] = set()
    for pat in patterns:
        keys.update(re.findall(pat, html))
    return keys


def _extract_js_keys() -> set[str]:
    js = JS.read_text(encoding="utf-8")
    # Match _t('key') or _t("key"); skip template literals and concatenations
    keys = set(re.findall(r"_t\(\s*['\"]([A-Za-z0-9_.\-]+)['\"]", js))
    # Drop runtime-constructed key bases. Two patterns:
    #   1. literal prefixes for known dynamic groups
    #   2. strings ending in "." which are concatenated with a runtime suffix
    return {
        k for k in keys
        if not k.startswith(_DYNAMIC_PREFIXES)
        and not k.endswith(".")
        and not k.endswith("_")
    }


def test_i18n_en_ja_symmetric() -> None:
    en, ja = _load_i18n()
    en_only = sorted(en - ja)
    ja_only = sorted(ja - en)
    assert not en_only, f"{len(en_only)} key(s) defined in EN but missing in JA: {en_only[:20]}"
    assert not ja_only, f"{len(ja_only)} key(s) defined in JA but missing in EN: {ja_only[:20]}"


def test_html_keys_defined_in_both_languages() -> None:
    en, ja = _load_i18n()
    html_keys = _extract_html_keys()
    missing_en = sorted(html_keys - en)
    missing_ja = sorted(html_keys - ja)
    assert not missing_en, f"HTML references {len(missing_en)} key(s) not in EN: {missing_en[:20]}"
    assert not missing_ja, f"HTML references {len(missing_ja)} key(s) not in JA: {missing_ja[:20]}"


def test_js_literal_keys_defined_in_both_languages() -> None:
    en, ja = _load_i18n()
    js_keys = _extract_js_keys()
    missing_en = sorted(js_keys - en)
    missing_ja = sorted(js_keys - ja)
    assert not missing_en, f"radar.js references {len(missing_en)} key(s) not in EN: {missing_en[:20]}"
    assert not missing_ja, f"radar.js references {len(missing_ja)} key(s) not in JA: {missing_ja[:20]}"


# Phrases that contradict NP4 (結論最大化 — the tool DOES emit the maximum
# technically derivable assessment) or NP7 (組織内ノード — the tool is one
# input to an organizational process, not something that needs human
# approval before action). The pre-v2 P5 ("ツールは判断しない") was
# explicitly retired by CLAUDE.md; this guard prevents its language from
# silently re-entering UI copy via doc edits or i18n drift.
#
# Each entry is (regex_pattern, brief_reason) — regex is matched
# case-insensitively against index.html and i18n.js raw bytes. Add new
# patterns sparingly: false positives are worse than misses here, because
# this test's job is to flag specific framings that the new tool-purpose
# definition rules out, not to police general writing style.
_FORBIDDEN_PHRASES: tuple[tuple[str, str], ...] = (
    (r"avoid(?:ing)?\s+over[- ]reliance",
     "implies tool output should be discounted; contradicts NP4"),
    (r"advisory only",
     "pre-v2 P5 framing — replaced by NP4 + NP7"),
    (r"tool\s+does\s+not\s+(?:decide|judge|assess|conclude)",
     "explicit former-P5 phrase retired by CLAUDE.md"),
    (r"must\s+be\s+validated\s+by\s+a\s+human",
     "inverts NP7 — the tool is a node, not an artifact awaiting approval"),
    (r"automated\s+assessments\s+must\s+be",
     "former-P5 framing of mandatory human gating"),
    (r"過度な?の?依存",
     "implies tool over-trust risk; contradicts NP4 (Japanese)"),
    (r"ツールは判断しない",
     "pre-v2 P5 phrase explicitly retired (Japanese)"),
    (r"あくまで助言",
     "pre-v2 P5 'advisory only' framing (Japanese)"),
    (r"アナリストによって検証されなければ",
     "inverts NP7 — tool gated on human approval (Japanese)"),
)


def test_forbidden_phrase_patterns_match_their_intended_strings() -> None:
    """Self-test: each forbidden pattern must hit a representative bad string.

    A "no matches found" pass on the real UI is meaningful only if the
    patterns themselves are known-good. This guards against silent regex
    rot — e.g. a typo in a Japanese pattern that no longer matches anything.
    """
    canaries = (
        ("avoid(?:ing)?\\s+over[- ]reliance", "avoiding over-reliance"),
        ("advisory only", "advisory only"),
        (r"tool\s+does\s+not\s+(?:decide|judge|assess|conclude)",
         "tool does not decide"),
        (r"must\s+be\s+validated\s+by\s+a\s+human",
         "must be validated by a human analyst"),
        (r"automated\s+assessments\s+must\s+be",
         "automated assessments must be reviewed"),
        ("過度な?の?依存", "過度な依存"),
        ("ツールは判断しない", "ツールは判断しない"),
        ("あくまで助言", "あくまで助言"),
        ("アナリストによって検証されなければ",
         "アナリストによって検証されなければなりません"),
    )
    for pattern, sample in canaries:
        assert re.search(pattern, sample, re.IGNORECASE), (
            f"forbidden-phrase pattern /{pattern}/ failed to match its "
            f"own canary {sample!r} — the pattern is broken, not the UI"
        )


def test_no_forbidden_pre_v2_p5_phrases_in_ui() -> None:
    """UI copy must not re-introduce the retired P5 ('tool does not decide')
    framing — NP4 and NP7 in CLAUDE.md replaced it.

    Scope: index.html + i18n.js. Other docs (e.g. v2-migration.md) may
    discuss the retired phrasing in historical context; this test is
    deliberately narrow to user-visible UI copy.
    """
    sources = {
        "index.html": HTML.read_text(encoding="utf-8"),
        "i18n.js": I18N.read_text(encoding="utf-8"),
    }
    violations: list[str] = []
    for name, body in sources.items():
        for pattern, reason in _FORBIDDEN_PHRASES:
            for m in re.finditer(pattern, body, re.IGNORECASE):
                line_no = body.count("\n", 0, m.start()) + 1
                violations.append(
                    f"{name}:{line_no}  /{pattern}/  → {reason}\n"
                    f"    matched: {m.group(0)!r}"
                )
    assert not violations, (
        "Forbidden NP4/NP7-violating UI copy detected:\n  "
        + "\n  ".join(violations)
    )
