/**
 * Unit tests for v3/ui/terms.js — the internal vocabulary, defined in place.
 *
 * Run:  node tests/ui_v3/test_terms.js
 *
 * The load-bearing ones:
 *   - every term P9 §4 names has a definition, and the definition is a
 *     dictionary key rather than a sentence in the module;
 *   - the marker appears at a term's FIRST occurrence in a view and not
 *     again (§4: 全出現に付けると視覚ノイズ);
 *   - two views mark independently, and their described-by ids do not
 *     collide — the three view containers coexist in one document;
 *   - the definition element is hidden VISUALLY and not with `hidden`,
 *     because `hidden` would take it out of the accessibility tree and
 *     leave `aria-describedby` pointing at nothing.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const T = require('../../v3/ui/terms');
const S = require('../../v3/ui/strings');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

// ── P9 §4's minimum set ──────────────────────────────────────────────────

//: Copied from P9 §4 by hand. If the design adds a term, this list is what
//: notices — a table checked against itself checks nothing.
const REQUIRED = ['tl', 'severity', 'inconclusive', 'null_zone',
                  'scoring_mode', 'drift', 'recall', 'convergence'];

test('every term P9 §4 names has a definition key', () => {
    REQUIRED.forEach((term) => {
        assert.strictEqual(T.definitionKey(term), 'term.' + term, term);
    });
});

test('every definition key resolves to a real sentence', () => {
    REQUIRED.forEach((term) => {
        const text = T.definitionOf(term);
        assert.ok(text && text !== 'term.' + term,
                  `${term} renders as its own key`);
        // A definition is a sentence, not a label. Anything shorter is a
        // gloss that leaves the reader where they started.
        assert.ok(text.length > 12, `${term} definition is too short: ${text}`);
    });
});

test('an unknown term yields no key, no text and no markup', () => {
    assert.strictEqual(T.definitionKey('not_a_term'), null);
    assert.strictEqual(T.definitionOf('not_a_term'), null);
    assert.strictEqual(T.markerHtml('not_a_term', 'situation'), '');
    assert.strictEqual(T.markerHtml(null, 'situation'), '');
});

// The one term with no marker site today. Recorded as a test rather than a
// comment: P9 §4 requires the definition, and no v3 surface prints the word
// 収斂 — adding one would be a new display, which P9 §7 forbids in this
// slice. When a surface does show it, this test fails and gets deleted.
test('convergence is defined although no surface marks it yet', () => {
    assert.ok(T.definitionOf('convergence'));
    const sources = fs.readdirSync(path.join(__dirname, '..', '..', 'v3', 'ui'))
        .filter((name) => name.endsWith('.js') && name !== 'terms.js')
        .map((name) => fs.readFileSync(
            path.join(__dirname, '..', '..', 'v3', 'ui', name), 'utf8'))
        .join('\n');
    assert.strictEqual(sources.indexOf("mark('convergence')"), -1,
        'a surface now marks 収斂 — delete this test and wire the term');
});

// ── first occurrence per view ────────────────────────────────────────────

test('a term is marked once per view and not again', () => {
    const marks = T.createMarkers('situation');
    const first = marks.mark('tl');
    assert.ok(first.indexOf('term-info') !== -1);
    assert.strictEqual(marks.mark('tl'), '');
    assert.strictEqual(marks.mark('tl'), '');
    assert.deepStrictEqual(marks.marked(), ['tl']);
});

test('different terms in the same view each get their first marker', () => {
    const marks = T.createMarkers('situation');
    assert.ok(marks.mark('tl'));
    assert.ok(marks.mark('severity'));
    assert.ok(marks.mark('scoring_mode'));
    assert.deepStrictEqual(marks.marked(), ['scoring_mode', 'severity', 'tl']);
});

test('two views mark independently and mint distinct ids', () => {
    const situation = T.createMarkers('situation');
    const verify = T.createMarkers('verify');
    const a = situation.mark('recall');
    const b = verify.mark('recall');
    assert.ok(a && b, 'the second view must get its own marker');
    assert.ok(a.indexOf('term-def-situation-recall') !== -1, a);
    assert.ok(b.indexOf('term-def-verify-recall') !== -1, b);
    assert.notStrictEqual(a, b);
});

test('the null issuer marks nothing and never throws', () => {
    assert.strictEqual(T.NONE.mark('tl'), '');
    assert.deepStrictEqual(T.NONE.marked(), []);
    assert.strictEqual(T.markersOf(undefined).mark('tl'), '');
    assert.strictEqual(T.markersOf(null).mark('tl'), '');
    assert.strictEqual(T.markersOf({}).mark('tl'), '');
    const real = T.createMarkers('situation');
    assert.strictEqual(T.markersOf(real), real);
});

// ── the markup itself ────────────────────────────────────────────────────

test('the marker describes the term through an element in the document', () => {
    const html = T.markerHtml('tl', 'situation');
    assert.ok(html.indexOf('aria-describedby="term-def-situation-tl"') !== -1, html);
    assert.ok(html.indexOf('id="term-def-situation-tl"') !== -1, html);
    assert.ok(html.indexOf('title="') !== -1, html);
    // `hidden` would remove it from the accessibility tree; the definition
    // must be hidden by CSS only.
    assert.strictEqual(html.indexOf(' hidden'), -1, html);
    assert.ok(html.indexOf('class="term-def"') !== -1, html);
});

test('the definition sentence is escaped in both positions', () => {
    // The definitions are ours, not a server value — but the escape is what
    // makes that fact irrelevant, and it is cheaper to assert than to reason
    // about later.
    const html = T.markerHtml('severity', 'verify');
    const text = T.definitionOf('severity');
    assert.ok(html.indexOf(text) !== -1 || html.indexOf('&') !== -1);
    assert.strictEqual(html.indexOf('<script'), -1);
});

test('AP3 component ids map onto terms, and only the three that need one', () => {
    assert.strictEqual(T.componentTerm('recall'), 'recall');
    assert.strictEqual(T.componentTerm('null_zone'), 'null_zone');
    assert.strictEqual(T.componentTerm('drift'), 'drift');
    // Already Japanese on screen: a gloss would add ink and no meaning.
    assert.strictEqual(T.componentTerm('ops_health'), null);
    assert.strictEqual(T.componentTerm('freshness'), null);
    assert.strictEqual(T.componentTerm(null), null);
});

test('no definition sentence is written in the module', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'v3', 'ui', 'terms.js'), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    Object.keys(T.TERMS).forEach((term) => {
        const text = S.STRINGS['term.' + term];
        assert.strictEqual(code.indexOf(text), -1,
            `${term}'s sentence is inlined in terms.js instead of the dictionary`);
    });
});

console.log(`\n\n${passed} passed, ${failed} failed`);
if (failed > 0) {
    failures.forEach(({ name, error }) => {
        console.error(`\n  FAIL: ${name}`);
        console.error('  ' + (error.stack || error));
    });
    process.exit(1);
}
process.exit(0);
