"""L7 discipline gates: the frontend does not score, and does not go stale.

WP-4.2's two named traps are both defect classes rather than single bugs,
so both are answered with gates rather than with careful coding.

**G-09 — the browser re-deriving a threat level.** v1's What-If panel
re-implemented score composition, the domain caps and the TL ladder in
JavaScript, and its domain caps did not match the backend's. An analyst
was therefore shown differences that did not exist. The remedy is not "be
careful"; the remedy is that a re-derivation must be *detectable*, and this
module detects it three independent ways:

  1. `TestNoBackendConstantIsCopied` reads the backend's own scoring and
     conclusion threshold catalogues **by import**, not by transcription,
     and refuses any of those values appearing as a literal in `v3/ui/`.
     Values that are structurally ambiguous (small integers) are excluded
     from the numeric sweep and covered by the other two gates instead;
     every exclusion is written down with a reason.
  2. `TestNoLadderNameIsPresent` refuses the backend's constant NAMES.
     Someone porting the ladder copies its names with it.
  3. `tests/ui_v3/test_no_derivation.js` is the behavioural half: it feeds
     the view models a payload whose server-supplied TL deliberately
     contradicts its score, and requires the server's TL to be what the
     screen shows. A ladder of any shape fails it, in any syntax.

**G-10 — "data updated, display silently stale".** The v1 redraw-skip
signature was a four-field list that omitted map overlays, participants and
the correlation map. `TestChangeDetectionIsWholeValue` requires that no
`v3/ui` module enumerate fields for change detection, and the Node suite
mutates every leaf of a deep payload to prove the signature is a whole-value
fold.

The remaining classes pin P8's dispositions: what §7 retires must not
exist, colours must come from `:root`, and every user-visible string must go
through the dictionary.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
UI_DIR = REPO_ROOT / "v3" / "ui"
UI_JS = sorted(p for p in UI_DIR.glob("*.js"))
UI_TEST_DIR = REPO_ROOT / "tests" / "ui_v3"


def _sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in UI_JS}


def _blank_but_keep_lines(match: re.Match) -> str:
    """Replace a comment with the same number of newlines it occupied.

    Line numbers survive stripping, so an offence can still be reported at
    the line it is on.
    """
    return "\n" * match.group(0).count("\n")


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments so prose about a value is not a value.

    Deliberately crude: it does not understand a string containing `//`.
    Over-stripping can only make a gate blind to something it has removed,
    never more permissive about code it still sees — and the module
    docstrings here quote backend constant names and Japanese clause text on
    purpose, so leaving them in would make several gates unusable.
    """
    text = re.sub(r"/\*.*?\*/", _blank_but_keep_lines, text, flags=re.S)
    text = re.sub(r"(?m)//.*$", "", text)
    return text


def _strip_string_literals(text: str) -> str:
    """Blank out the contents of string literals.

    The numeric sweep looks for a backend threshold being USED, and a number
    inside a string cannot be arithmetic — it is a message, a placeholder or
    a worked example. Leaving them in would make the dictionary collide with
    the threshold catalogue on every round number in Japanese prose, and a
    gate that cries wolf gets an allowance added rather than a bug fixed.
    """
    return re.sub(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"", "''", text)


def _code_only(text: str) -> str:
    return _strip_string_literals(_strip_comments(text))


# ── the backend's numbers, read from the backend ──────────────────────────

def _backend_thresholds() -> dict[str, float]:
    """Every scoring / conclusion threshold, imported rather than copied.

    WP-2.6 found 97 transcription infidelities in numbers that looked
    correctly copied, which is why this gate reads the live modules instead
    of restating their values.
    """
    import v3.conclusions.thresholds as conclusion_thresholds
    import v3.scoring.thresholds as scoring_thresholds

    values: dict[str, float] = {}
    for name, entry in conclusion_thresholds.disclosure().items():
        if isinstance(entry.get("value"), (int, float)):
            values[name] = float(entry["value"])
    for name in dir(scoring_thresholds):
        if not name.isupper():
            continue
        value = getattr(scoring_thresholds, name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        values[name] = float(value)
    return values


#: The ladder proper. Named separately because these five are what G-09
#: actually duplicated, and because the name gate below is about them.
LADDER_NAMES = (
    "TL1_SCORE_FLOOR", "TL2_SCORE_FLOOR", "TL3_SCORE_FLOOR", "TL4_SCORE_FLOOR",
    "TL1_PHYSICAL_FLOOR", "TL2_MIN_DOMAINS",
    "CONVERGENCE_FULL_BONUS", "CONVERGENCE_DUAL_BONUS",
    "DOMAIN_ACTIVE_FLOOR", "DOMAIN_ELEVATED_FLOOR", "DOMAIN_MAGNITUDE_DENOM",
)

#: Values excluded from the numeric sweep, each with the reason.
#:
#: An integer below this bound carries no information about where it came
#: from: `2` is a backend `TL2_MIN_DOMAINS` and also an array index, a
#: radix and a rounding digit. Sweeping them produces noise, not signal, so
#: small integers are covered by the NAME gate and the behavioural Node
#: gate instead. Everything at or above the bound, and every value with a
#: fractional part, is swept.
SMALL_INTEGER_BOUND = 20

#: Literals that survive the sweep and are nonetheless legitimate. Kept as
#: an explicit list rather than a clever pattern: a rule loose enough to
#: pass `900` also passes a domain cap.
ALLOWED_LITERALS: dict[tuple[str, float], str] = {
    ("freshness.js", 900.0):
        "FRESHNESS_AGING_SEC — one scoring cadence. A display band for the "
        "staleness badge; nothing downstream of a conclusion reads it. "
        "Registered in wp25-l0-adapter-design.md §7-2 #96.",
    ("freshness.js", 3600.0):
        "FRESHNESS_STALE_SEC — four cadences. Same reason as the above.",
    ("format.js", 3600.0): "seconds per hour, for rendering a duration.",
    ("format.js", 86400.0): "seconds per day, for rendering a duration.",
    ("format.js", 1000.0): "milliseconds per second, for Date construction.",
    ("render.js", 100.0): "percent, for a CSS bar width.",
    ("app.js", 100.0): "page size for the decision-ledger read (R9 `limit`).",
    ("client.js", 300.0):
        "the top of the HTTP 2xx range, in `status >= 200 && status < 300`.",
}


def _numeric_literals(text: str) -> set[float]:
    out: set[float] = set()
    # Decimal and hexadecimal, but not identifiers containing digits.
    for match in re.finditer(r"(?<![\w.$])(0[xX][0-9a-fA-F]+|\d+\.?\d*(?:[eE][-+]?\d+)?)",
                             text):
        raw = match.group(1)
        try:
            out.add(float(int(raw, 16)) if raw.lower().startswith("0x") else float(raw))
        except ValueError:
            continue
    return out


class TestNoBackendConstantIsCopied:
    """No scoring or conclusion threshold value appears in the frontend."""

    def test_the_backend_catalogue_is_readable(self):
        values = _backend_thresholds()
        assert len(values) > 40, "the threshold catalogues did not load"
        # If the ladder is ever renamed, this gate must be updated with it
        # rather than silently sweeping nothing.
        for name in LADDER_NAMES:
            assert name in values, f"{name} vanished from the backend catalogue"

    def test_no_distinctive_backend_value_is_a_frontend_literal(self):
        values = _backend_thresholds()
        swept = {
            value: name for name, value in values.items()
            if value != int(value) or abs(value) >= SMALL_INTEGER_BOUND
        }
        assert swept, "the sweep set is empty — the filter is wrong"

        offences: list[str] = []
        for filename, source in _sources().items():
            for literal in _numeric_literals(_code_only(source)):
                if literal not in swept:
                    continue
                if (filename, literal) in ALLOWED_LITERALS:
                    continue
                offences.append(
                    f"{filename} contains {literal!r}, which is the backend's "
                    f"{swept[literal]}. Scoring is not re-implemented in the "
                    f"browser (P8 rule 3 / G-09). If the value is a display "
                    f"constant that only happens to collide, add it to "
                    f"ALLOWED_LITERALS with the reason.")
        assert not offences, "\n".join(offences)

    def test_every_allowance_is_still_needed(self):
        """An allowance that no longer matches anything is stale scaffolding."""
        sources = _sources()
        stale = [
            f"{filename}:{literal}"
            for (filename, literal) in ALLOWED_LITERALS
            if filename not in sources
            or literal not in _numeric_literals(_code_only(sources[filename]))
        ]
        assert not stale, (
            f"these allowances match nothing any more and should be deleted: "
            f"{stale}. Migration scaffolding that outlives its migration is "
            f"how the v1->v2 teardown found a capped tier governor.")


class TestNoLadderNameIsPresent:
    """The backend's constant names do not appear in the frontend."""

    def test_no_ladder_constant_name_is_referenced(self):
        offences = []
        for filename, source in _sources().items():
            body = _strip_comments(source)
            for name in LADDER_NAMES:
                if name in body:
                    offences.append(f"{filename} references {name}")
        assert not offences, (
            f"{offences} — a threat level is read from the projection, never "
            f"recomputed from the thresholds that produced it.")

    def test_no_module_assigns_a_threat_level_from_a_comparison(self):
        """`tl = score >= X ? ... : ...` in any spelling."""
        pattern = re.compile(
            r"(?:threat_?[Ll]evel|\btl\b)\s*=\s*[^;=\n]*[<>]=?", re.I)
        offences = []
        for filename, source in _sources().items():
            for lineno, line in enumerate(_strip_comments(source).splitlines(), 1):
                if pattern.search(line):
                    offences.append(f"{filename}:{lineno}: {line.strip()}")
        assert not offences, (
            f"a threat level assigned from a comparison is a ladder: {offences}")

    #: Quantities the backend decides. Comparing one against a literal is a
    #: threshold, and a threshold in the browser is a threshold that can
    #: disagree with the backend's.
    SCORING_QUANTITIES = (
        "score", "raw_score", "base_score", "total_score",
        "convergence_bonus", "severity", "threat_level", "threatLevel",
        "confidence", "domain_score", "importance",
    )

    def test_no_scoring_quantity_is_compared_against_a_literal(self):
        """`scenario.score >= 9.0` in any spelling, either way round.

        Added after a mutation test: a ladder written as a chain of
        `if (score >= N)` guards assigning to a locally-named variable
        slipped past the assignment gate above, because the assignment
        target was `derivedTl` and the comparison sat to its left. The
        behavioural suite caught it, and so should a syntactic gate.
        """
        names = "|".join(self.SCORING_QUANTITIES)
        forward = re.compile(rf"\b(?:{names})\b\s*[<>]=?\s*-?\d", re.I)
        reverse = re.compile(rf"-?\d+(?:\.\d+)?\s*[<>]=?\s*[\w.]*\b(?:{names})\b", re.I)
        offences = []
        for filename, source in _sources().items():
            for lineno, line in enumerate(_strip_comments(source).splitlines(), 1):
                if forward.search(line) or reverse.search(line):
                    offences.append(f"{filename}:{lineno}: {line.strip()}")
        assert not offences, (
            f"a scoring quantity compared against a literal is a threshold, "
            f"and the browser holds none: {offences}")

    def test_the_tl_band_lookup_contains_no_comparison(self):
        """`format.tlBand` must stay a table, not become a ladder."""
        source = _strip_comments((UI_DIR / "format.js").read_text(encoding="utf-8"))
        start = source.index("function tlBand")
        body = source[start:source.index("\n    }", start)]
        for operator in ("<", ">", ">=", "<="):
            assert operator not in body, (
                f"tlBand contains {operator!r}; it maps the integer the server "
                f"sent and must not compare it")


class TestChangeDetectionIsWholeValue:
    """G-10: nothing enumerates the fields that count as a change."""

    def test_the_signature_is_computed_over_an_opaque_value(self):
        source = _strip_comments((UI_DIR / "freshness.js").read_text(encoding="utf-8"))
        assert "function signatureOf" in source
        # A field list is the defect. If a future edit reintroduces one, it
        # will name the fields v1 named.
        for field in ("map_overlay", "participants", "correlation",
                      "scoring_summary", "target_summary"):
            assert field not in source, (
                f"freshness.js mentions {field!r}. The v1 signature was a "
                f"list of fields and the ones it omitted went silently "
                f"undrawn (G-10); the v3 signature folds the whole value and "
                f"therefore names no field at all.")

    def test_the_freshness_badge_is_never_behind_the_redraw_gate(self):
        """Staleness must not be suppressible by the thing it warns about.

        If a section's badge were written after its `shouldRender` guard, a
        skipped redraw would leave a badge asserting the data is current —
        G-10 with an extra step, and worse than G-10 because the screen
        would be actively claiming freshness rather than merely failing to
        update. Every `board-/lane-/face-freshness` write must therefore
        appear BEFORE the `shouldRender` call in its function.
        """
        source = _strip_comments((UI_DIR / "app.js").read_text(encoding="utf-8"))
        for function in re.findall(r"function render\w+\([^)]*\)\s*\{(.*?)\n    \}",
                                   source, flags=re.S):
            badge = function.find("-freshness'")
            gate = function.find("shouldRender")
            if badge == -1:
                continue
            assert gate == -1 or badge < gate, (
                "a freshness badge is written after the redraw gate; a "
                "skipped redraw would leave it claiming the data is current")

    def test_every_view_goes_through_the_detector(self):
        """No module may keep its own private "did it change" flag."""
        offences = []
        for filename, source in _sources().items():
            if filename == "freshness.js":
                continue
            body = _strip_comments(source)
            if re.search(r"\blast(?:Rendered|Payload|Hash|Sig)\b", body):
                offences.append(filename)
        assert not offences, (
            f"{offences} keep a private redraw signature. There is one change "
            f"detector and it folds whole values.")


class TestRetiredSurfacesAreAbsent:
    """P8 §7's abolitions are enforced, not merely asserted in a document."""

    #: (token, what P8 §7 said about it)
    RETIRED = (
        ("watchpane", "Watchpane abolished — sensor liveness is L5's job"),
        ("wp_alarm", "the Watchpane alarm DSL went with the Watchpane"),
        ("salute", "SALUTE export dropped — one report surface (P7 R12), and "
                   "SALUTE was a G-17 participant"),
        ("weather_brief", "weather brief dropped with SALUTE"),
        ("sitrep", "sitrep demand is met by R2 + R12"),
        ("daily_summary", "dropped with the report consolidation"),
        ("spof", "SPOF panel dropped — a second scoring engine (DP12)"),
        ("cooccurrence", "discovery frozen"),
        ("corr_heatmap", "correlation heatmap frozen with discovery"),
        ("threat_terrain", "threat terrain dropped — calibration found no signal"),
        ("coordination_link", "coordination links dropped for the same reason"),
        ("sensor_ring", "sensor rings dropped — duplicate of the contribution view"),
        ("threat_halo", "threat halo dropped — duplicate of TL"),
        ("blockade", "blockade index is DDoS-era legacy (DP15)"),
        ("l7_vector", "L3/L7 vector switching is DDoS-era legacy (DP15)"),
        ("triage_score", "ranking is the server's ledger now (P5 O-8)"),
        ("self_explanation", "the narrative engine moved to the backend (P7 §4)"),
        ("hud_v2_overlay", "there is no v1 to overlay in v3"),
        ("ip_check", "dropped — no output mapping"),
        ("deep_analytics", "dropped — no UI route existed"),
    )

    @pytest.mark.parametrize("token,reason", RETIRED)
    def test_retired_surface_is_absent(self, token, reason):
        offences = []
        for path in list(UI_JS) + sorted(UI_DIR.glob("*.html")) \
                + sorted(UI_DIR.glob("*.css")):
            body = _strip_comments(path.read_text(encoding="utf-8")).lower()
            if token in body:
                offences.append(path.name)
        assert not offences, f"{token!r} appears in {offences}: {reason}"

    def test_the_retired_list_covers_every_abolition_in_p8_section_7(self):
        """The list above is checked against the document it implements."""
        p8 = (REPO_ROOT / "docs" / "design" / "v3" / "P8-ui-derivation.md")
        text = p8.read_text(encoding="utf-8")
        # Rows marked 廃止 (abolished) in §7's disposition table.
        abolished = [
            line for line in text.splitlines()
            if line.startswith("|") and "廃止" in line
        ]
        assert len(abolished) >= 6, (
            "P8 §7's abolition rows could not be found — if the table moved, "
            "this gate has stopped checking anything")


class TestColoursComeFromTheRootPalette:
    """CLAUDE.md: colours are `:root` custom properties, never literals."""

    HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
    FUNC = re.compile(r"\b(?:rgba?|hsla?)\s*\(")

    def test_no_colour_literal_in_the_stylesheet_outside_root(self):
        css_files = sorted(UI_DIR.glob("*.css"))
        assert css_files, "the v3 stylesheet is missing"
        for path in css_files:
            body = _strip_comments(path.read_text(encoding="utf-8"))
            # Everything outside the `:root {...}` block must use var().
            without_root = re.sub(r":root\s*\{.*?\}", " ", body, flags=re.S)
            assert not self.HEX.search(without_root), (
                f"{path.name} has a hex colour outside :root: "
                f"{self.HEX.search(without_root).group(0)}")
            assert not self.FUNC.search(without_root), (
                f"{path.name} has an rgb()/hsl() literal outside :root")

    def test_no_colour_literal_in_any_frontend_module(self):
        for filename, source in _sources().items():
            body = _strip_comments(source)
            # Hash-prefixed hex would also match a fragment id or a sha, so
            # only flag values that look like colours in a style context.
            for match in re.finditer(r"(?:color|background|border|fill|stroke)"
                                     r"\s*[:=]\s*['\"]?(#[0-9a-fA-F]{3,8})", body):
                pytest.fail(f"{filename} sets a colour literal {match.group(1)}")


class TestDictionaryDisciplineIsMechanised:
    """Every user-visible string goes through the dictionary (CLAUDE.md §1)."""

    def test_the_i18n_audit_covers_the_v3_dictionary(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_i18n_keys.py", "--json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=180)
        assert result.returncode == 0, result.stdout + result.stderr
        report = json.loads(result.stdout)
        assert "v3" in report, (
            "the i18n audit does not know about the v3 dictionary; a "
            "greenfield surface with no key audit is how untranslated "
            "strings and dead keys accumulated in v1")
        v3 = report["v3"]
        assert v3["undefined_refs"] == [], (
            f"these keys render as the key string at runtime: "
            f"{v3['undefined_refs']}")
        assert v3["unused_keys"] == [], (
            f"these keys are defined and never used: {v3['unused_keys']}. "
            f"P8 §8 ports the dictionary by pruning it, so an unused key in "
            f"a greenfield table is a key that should not have been ported.")
        assert v3["untranslated"] == [], v3["untranslated"]

    def test_no_module_emits_prose_directly(self):
        """A user-facing sentence in JS is a string that cannot be audited."""
        # Japanese characters outside the dictionary file mean a sentence was
        # written where a key belongs.
        japanese = re.compile(r"[぀-ヿ一-鿿]")
        offences = []
        for filename, source in _sources().items():
            if filename == "strings.js":
                continue
            for lineno, line in enumerate(
                    _strip_comments(source).splitlines(), 1):
                if japanese.search(line):
                    offences.append(f"{filename}:{lineno}: {line.strip()[:70]}")
        assert not offences, (
            f"Japanese prose outside the dictionary: {offences}. DP17 is "
            f"exactly this — strings that bypass the dictionary cannot be "
            f"audited and drift out of the terminology contract.")


class TestPanelChromeContract:
    """docs/design/panel-chrome.md, applied to a surface with no panels.

    The contract binds floating and dockable panels: a rule rooted at a
    panel's id leaks into the children of the shared chrome that
    `createFloatingPanel` injects. P8 §7 retires the panel accumulation, so
    v3 has no floating panels and the contract has nothing to leak into —
    which is a claim that has to be checked rather than assumed, since a
    panel added later would silently be outside the factory.

    Two gates, therefore: the contract's own documented audit (its selector
    is specifically `#…-panel`), and a check that the v3 shell does not
    hand-author the chrome markup — the violation D1-frontend found in
    twenty-one places in v1's index.html.
    """

    FORBIDDEN = ("font-family", "font-size", "font-weight", "color",
                 "letter-spacing", "padding")

    #: The chrome classes `createFloatingPanel` owns. Hand-authoring them is
    #: how v1 ended up with panels that never went through the factory.
    CHROME_CLASSES = ("draggable-panel", "panel-header-unified", "drag-handle",
                      "panel-content")

    def test_no_panel_rooted_rule_declares_chrome_properties(self):
        """The audit command panel-chrome.md itself names."""
        for path in sorted(UI_DIR.glob("*.css")):
            body = path.read_text(encoding="utf-8")
            for match in re.finditer(r"(?m)^#([a-z][\w-]*-panel)\s*\{([^}]*)\}", body):
                selector, block = match.group(1), match.group(2)
                for prop in self.FORBIDDEN:
                    assert not re.search(rf"(?m)^\s*{prop}\s*:", block), (
                        f"{path.name}: #{selector} declares {prop}, which "
                        f"leaks into the shared panel chrome "
                        f"(docs/design/panel-chrome.md)")

    def test_the_shell_does_not_hand_author_panel_chrome(self):
        for path in sorted(UI_DIR.glob("*.html")) + sorted(UI_DIR.glob("*.css")) \
                + list(UI_JS):
            body = path.read_text(encoding="utf-8")
            for chrome_class in self.CHROME_CLASSES:
                assert chrome_class not in body, (
                    f"{path.name} hand-authors {chrome_class!r}. A panel is "
                    f"built by `createFloatingPanel` or it is not a panel; v3 "
                    f"has neither (P8 §7 retires the panel accumulation).")


class TestNodeSuitesRun:
    """The pure-module suites run as part of the Python suite.

    They existed before WP-4.2 and were wired into nothing — six files, 160
    assertions, executed only when somebody remembered. A test nobody runs
    is documentation.
    """

    SUITES = sorted(p.name for p in UI_TEST_DIR.glob("test_*.js"))

    def test_there_are_suites_to_run(self):
        assert self.SUITES, "no v3 UI node suites found"

    @pytest.mark.parametrize("suite", SUITES)
    def test_suite_passes(self, suite):
        result = subprocess.run(
            ["node", str(UI_TEST_DIR / suite)],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stdout + result.stderr

    def test_every_module_has_a_suite(self):
        """Including the DOM layer. Especially the DOM layer.

        v1's split was pure modules at 160 tests and radar.js at zero, and
        every "the screen silently stopped showing it" defect lived in the
        untested half. `test_app_smoke.js` boots the real `app.js` against a
        minimal DOM and a stub transport so the wiring is executed too.
        """
        modules = {p.stem for p in UI_JS} - {"strings"}
        covered = {
            name[len("test_"):-len(".js")].removesuffix("_smoke")
            for name in self.SUITES
        }
        missing = sorted(modules - covered)
        assert not missing, (
            f"these modules have no Node suite: {missing}. P1 §11's whole "
            f"argument is that pure-core + thin DOM is what made the six v1 "
            f"pure modules testable while radar.js stayed at 0%.")


class TestTheWiringResolves:
    """Every element the DOM layer reaches for exists in the shell.

    A mistyped id makes `getElementById` return null, `setHtml` do nothing,
    and the section render as blank — with no error anywhere. That is the
    same failure shape as G-10 (the data arrived; the screen did not change)
    reached by a different route, so it gets the same treatment: a gate.
    """

    def _declared_ids(self) -> set[str]:
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        return set(re.findall(r'\bid="([^"]+)"', html))

    #: Every file that writes the document. `gate.js` joined `app.js` when
    #: the login gate landed (§7-2 #99): the gate is a feature with its own
    #: elements, and one 900-line DOM file for both would be the panel
    #: accumulation P8 §7 retired wearing a different spelling. The check
    #: follows the DOM rather than following one filename — `surfaces.js`
    #: joined on the same argument in WP-4.3 (the map, SETTINGS, the two
    #: presentation state machines and the live chip), and `views.js` on
    #: the same argument again in WP-4.3a (which view is on screen).
    DOM_FILES = ("app.js", "gate.js", "surfaces.js", "views.js")

    def test_every_id_the_dom_layer_touches_is_declared_in_the_shell(self):
        declared = self._declared_ids()
        offences = []
        for name in self.DOM_FILES:
            source = (UI_DIR / name).read_text(encoding="utf-8")
            used = set(re.findall(r"\$\('([^']+)'\)", source))
            used |= set(re.findall(r"setHtml\('([^']+)'", source))
            used |= set(re.findall(r"setHidden\('([^']+)'", source))
            used |= set(re.findall(r"setText\('([^']+)'", source))
            offences += [f"{name}: {missing}"
                         for missing in sorted(used - declared)]
        assert not offences, (
            f"the DOM layer addresses element ids that index.html does not "
            f"declare: {offences}. Each one renders as silence.")

    def test_every_dom_file_is_listed_in_the_shell(self):
        """A DOM file nobody loads is a feature that silently does not run."""
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        loaded = set(re.findall(r'<script src="([^"]+)"', html))
        missing = sorted(set(self.DOM_FILES) - loaded)
        assert not missing, missing

    def test_every_deferred_surface_has_a_slot_in_the_shell(self):
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        slots = set(re.findall(r'data-deferred="([^"]+)"', html))
        client = (UI_DIR / "client.js").read_text(encoding="utf-8")
        declared = set(re.findall(r"^\s{8}(R\d+|C\d+):", client, re.M))
        missing = sorted(declared - slots)
        assert not missing, (
            f"these P7 entries are declared deferred but the shell gives them "
            f"nowhere to say so: {missing}. An unserved surface that says "
            f"nothing is indistinguishable from one with no data.")


class TestTheViewSplitIsStructural:
    """P9 §2 R-B: one view, one question — enforced from the markup.

    WP-4.2 satisfied every clause in this file and still produced a screen
    an analyst could not read, because "the situation board is Tier 0" was
    a claim about intent rather than about structure: all five stages were
    siblings under one `<main>`, so nothing stopped an audit table from
    sitting under the ten-second board (D-1). These gates make the split a
    property of the document.

    The second gate is D-6's. WP-4.2 scattered `data-deferred` fragments
    through the operational views, where "this is not built yet" and "there
    is nothing to report" render identically; P9 §3.3 collects them into
    one table at the end of the verification view, and this is what keeps
    them there.
    """

    #: (element id, the view that must contain it). Ids rather than
    #: classes: an id is what the DOM layer writes into, so a surface that
    #: moved without its gate being updated fails here rather than
    #: appearing in the wrong view.
    HOMES = (
        ("board-summary", "view-situation"),
        ("board-cards", "view-situation"),
        ("lane-rows", "view-situation"),
        ("onboarding-card", "view-situation"),
        ("face-sections", "view-scenario"),
        # P9 §3.4: the tile map is the primary visual of the geographic face
        # and the marker list is its accessible twin. Both belong to the
        # scenario view; a tile map that drifted onto the board would put a
        # Tier 1 surface under the ten-second question again (D-1).
        ("geo-tilemap", "view-scenario"),
        ("geo-markers", "view-scenario"),
        ("feedback-slot", "view-scenario"),
        ("proposal-rows", "view-scenario"),
        ("derivation-body", "view-verify"),
        ("selfeval-components", "view-verify"),
        ("sensor-rows", "view-verify"),
        ("decision-rows", "view-verify"),
        ("whatif-body", "view-verify"),
        ("settings-rows", "view-verify"),
        ("groundtruth-rows", "view-verify"),
    )

    def _spans(self) -> dict[str, tuple[int, int]]:
        """Where each view container starts and ends in the document.

        The three containers are siblings and the last one ends at
        `</main>`, so their extents are the gaps between their opening
        tags. Crude on purpose: a real parser would also accept a nested
        view, and a nested view is not a thing this design has.
        """
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        starts = [(m.start(), m.group(1))
                  for m in re.finditer(r'<div id="(view-[\w-]+)"', html)]
        assert len(starts) == 3, (
            f"expected exactly three view containers, found {starts}")
        end_of_main = html.index("</main>")
        bounds = {}
        for index, (offset, name) in enumerate(starts):
            end = starts[index + 1][0] if index + 1 < len(starts) else end_of_main
            bounds[name] = (offset, end)
        return bounds

    @pytest.mark.parametrize("element_id,view", HOMES)
    def test_each_surface_is_inside_the_view_that_answers_its_question(
            self, element_id, view):
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        spans = self._spans()
        assert view in spans, f"{view} is not a view container any more"
        position = html.index(f'id="{element_id}"')
        start, end = spans[view]
        assert start < position < end, (
            f'#{element_id} is not inside #{view}. P9 R-B: one view answers '
            f'one question, and a Tier 2 table under the ten-second board is '
            f'diagnosis D-1 rather than an arrangement.')

    def test_no_deferred_fragment_survives_outside_the_verification_view(self):
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        start, end = self._spans()["view-verify"]
        stray = [m.group(1) for m in re.finditer(r'data-deferred="([^"]+)"', html)
                 if not start < m.start() < end]
        assert not stray, (
            f"these deferred slots are outside the verification view: {stray}. "
            f"P9 §3.3 collects them into 未着地の機能 — a placeholder in an "
            f"operational view reads as a broken feature (D-6).")

    def test_the_navigation_offers_exactly_two_destinations(self):
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        nav = html[html.index('<nav id="view-nav"'):html.index("</nav>")]
        links = re.findall(r'<a id="(nav-[\w-]+)"', nav)
        assert links == ["nav-situation", "nav-verify"], (
            f"the top navigation is {links}. P9 §3.2 fixes it at two items; "
            f"the scenario face is entered from a card or a lane row, "
            f"because a view ABOUT something is reached through the thing "
            f"it is about.")


class TestMetaLanguageIsAbsent:
    """P9 §1.2 D-8/D-9, ruling R-D: the shell speaks content words only.

    WP-4.3 printed the analyst loop's own definition — stage numbers, the
    question lines, the 目標 N 秒 acceptance targets — as page chrome, and
    the owner review read it exactly as designed and exactly wrongly:
    "what is this supposed to be telling me". The design document's
    vocabulary belongs to the design document. These gates make the
    regression mechanical rather than a matter of taste.
    """

    def test_no_stage_number_chrome_survives_in_the_shell(self):
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        for token in ("stage-n", "stage-question"):
            assert token not in html, (
                f"`{token}` is back in index.html. The numbered-loop chrome "
                f"is diagnosis D-8/D-9 (P9 §1.2): the loop's stages are "
                f"parallel questions, not steps, and a number tells a "
                f"reader to walk them in order.")

    def test_no_question_line_keys_survive_in_the_dictionary(self):
        strings = (UI_DIR / "strings.js").read_text(encoding="utf-8")
        stray = re.findall(r"'(ui\.stage\.\w+_q)'", strings)
        assert not stray, (
            f"question-line keys {stray} are back in strings.js. The loop's "
            f"questions live in the onboarding card and in P9 §6, not as "
            f"section subtitles (R-D).")

    def test_no_second_target_is_printed_anywhere(self):
        """目標 N 秒 is an acceptance criterion, not screen copy."""
        for name in ("strings.js",):
            text = (UI_DIR / name).read_text(encoding="utf-8")
            hits = re.findall(r"目標\s*\d+\s*秒", text)
            assert not hits, (
                f"{name} prints {hits}. The 10-/30-second targets are how "
                f"P9 §6 judges the screen, not what the screen says — a "
                f"tool describing its own design intent is D-8.")

    def test_the_onboarding_list_is_unordered(self):
        html = (UI_DIR / "index.html").read_text(encoding="utf-8")
        body = html[html.index('id="onboarding-body"'):]
        body = body[:body.index("</section>")]
        assert "<ol" not in body, (
            "the onboarding card numbers its entries again. They are "
            "parallel ways into one screen (D-9); use <ul>.")
