/**
 * Noroshi v3 L7 — the internal vocabulary, defined where it is used.
 *
 * P9 §2 R-C and §4. Diagnosis D-2 is that the board and the lane print the
 * tool's own ontology — TL, severity, 結論不可, scoring_mode, null-zone,
 * drift, recall, 収斂 — with no definition anywhere on the screen. "TL4 /
 * ELEVATED" is a CODE, not an answer, and a reader who cannot decode it
 * cannot audit the derivation behind it: NP6 says disclose the derivation,
 * and a disclosure nobody can read is not one.
 *
 * Two rules, both from §4:
 *
 * **The definition is one sentence and it lives in the dictionary.** This
 * module holds term ids and the markup around them; every word an analyst
 * reads comes from `strings.js` under the `term.*` namespace, so the
 * terminology contract (docs/design/ja-localization.md) covers the
 * definitions as well as the labels.
 *
 * **The marker appears at a term's FIRST occurrence per view, and nowhere
 * else.** Five cards each carrying a ⓘ beside their threat level is five
 * times the ink for one fact, and P9 §4 rules it out explicitly. That makes
 * "first" a property of a rendering pass rather than of a string, so the
 * marker is issued by a small per-view tracker (`createMarkers`) that the
 * DOM layer creates once per view and threads through the builders. A
 * builder called without one renders no markers at all — which is what
 * keeps every existing test of those builders true.
 *
 * The chapter pointer §4 asks for ("詳細: INTEL GUIDE Ch.N") is deliberately
 * absent: the INTEL GUIDE lives in the v1 shell (`index.html` at the repo
 * root), which this deployment does not serve, and its Ch.2 threat-level
 * text describes v1's score ladder rather than v3's. Pointing an analyst at
 * a chapter they cannot open, about a ladder that is not the one that
 * produced the number in front of them, is worse than a definition that
 * stands alone.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiTerms = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var S = (typeof require === 'function')
        ? require('./strings')
        : (typeof window !== 'undefined' ? window.NoroshiStrings : null);
    var Fmt = (typeof require === 'function')
        ? require('./format')
        : (typeof window !== 'undefined' ? window.NoroshiFormat : null);

    var _t = S.t;
    var esc = Fmt.escHtml;

    /**
     * P9 §4's initial set, in full. Each id maps to its definition key —
     * written as a full literal so `scripts/check_i18n_keys.py` resolves it
     * without a prefix wildcard.
     *
     * `convergence` has no marker site on any v3 surface today: no screen
     * prints the word 収斂, and P9 §7 forbids this slice from adding a
     * display. It is defined here because §4 names it in the minimum set,
     * and because the term arrives with the first surface that shows a
     * multi-domain agreement rather than with a later edit to this table.
     */
    var TERMS = {
        tl: 'term.tl',
        severity: 'term.severity',
        inconclusive: 'term.inconclusive',
        null_zone: 'term.null_zone',
        scoring_mode: 'term.scoring_mode',
        drift: 'term.drift',
        recall: 'term.recall',
        convergence: 'term.convergence',
    };

    //: The AP3 component ids that ARE terms. `ops_health` and `freshness`
    //: are named in Japanese on screen (稼働監視 / データ鮮度) and need no
    //: gloss; the other three are the English reliability vocabulary
    //: ja-localization §2 keeps untranslated, which is exactly the case
    //: R-C exists for.
    var COMPONENT_TERMS = {
        recall: 'recall',
        null_zone: 'null_zone',
        drift: 'drift',
    };

    //: The marker glyph. A symbol, not prose — it carries no language and
    //: therefore no dictionary entry (CLAUDE.md §1 governs words).
    var MARKER = 'ⓘ';

    function definitionKey(term) {
        return Object.prototype.hasOwnProperty.call(TERMS, term)
            ? TERMS[term] : null;
    }

    function definitionOf(term) {
        var key = definitionKey(term);
        return key === null ? null : _t(key);
    }

    /**
     * The marker for one term, in one view.
     *
     * `aria-describedby` rather than `aria-label`: the marker's own name is
     * "definition", and the definition itself belongs to the term it sits
     * beside. The described element is present in the document and hidden
     * visually (never with `hidden`, which would take it out of the
     * accessibility tree along with the pixels), and the same sentence is
     * on `title` so a pointer reaches it too.
     *
     * The id is scoped by view because the three view containers coexist in
     * the document — a term marked in 状況 and again in 検証 would otherwise
     * mint the same id twice.
     */
    function markerHtml(term, scope) {
        var key = definitionKey(term);
        if (key === null) return '';
        var id = 'term-def-' + String(scope || 'view') + '-' + term;
        var text = _t(key);
        return '<span class="term-marker">'
            + '<span class="term-info" role="note" tabindex="0" '
            + 'aria-describedby="' + esc(id) + '" title="' + esc(text) + '">'
            + esc(MARKER) + '</span>'
            + '<span class="term-def" id="' + esc(id) + '">' + esc(text) + '</span>'
            + '</span>';
    }

    /**
     * A per-view marker issuer.
     *
     * Stateful by necessity — "first occurrence" is a fact about a pass over
     * the cards, not about any one card — and the state is nothing but the
     * set of terms already marked, which `marked()` exposes so a test can
     * assert on it instead of parsing HTML.
     */
    function createMarkers(scope) {
        var seen = Object.create(null);
        return {
            scope: scope,
            mark: function (term) {
                if (definitionKey(term) === null) return '';
                if (seen[term] === true) return '';
                seen[term] = true;
                return markerHtml(term, scope);
            },
            marked: function () { return Object.keys(seen).sort(); },
        };
    }

    /**
     * The no-op issuer, for builders called without a view.
     *
     * A null object rather than a `null` check at each of the dozen call
     * sites: the builders stay branch-free, and a caller that forgets to
     * pass one gets a card with no markers rather than a thrown TypeError
     * halfway through the board.
     */
    var NONE = {
        scope: null,
        mark: function () { return ''; },
        marked: function () { return []; },
    };

    function markersOf(candidate) {
        return (candidate && typeof candidate.mark === 'function')
            ? candidate : NONE;
    }

    /** The term behind an AP3 component id, or null. */
    function componentTerm(componentId) {
        return Object.prototype.hasOwnProperty.call(COMPONENT_TERMS, componentId)
            ? COMPONENT_TERMS[componentId] : null;
    }

    return {
        TERMS: TERMS,
        COMPONENT_TERMS: COMPONENT_TERMS,
        MARKER: MARKER,
        NONE: NONE,
        definitionKey: definitionKey,
        definitionOf: definitionOf,
        markerHtml: markerHtml,
        createMarkers: createMarkers,
        markersOf: markersOf,
        componentTerm: componentTerm,
    };
});
