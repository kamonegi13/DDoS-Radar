/**
 * Unit tests for v3/ui/format.js — display formatting.
 *
 * Run:  node tests/ui_v3/test_format.js
 */
'use strict';

const assert = require('assert');
const F = require('../../v3/ui/format');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

// ── TL band: a lookup, and the DEFCON direction ──────────────────────────

test('TL1 is the worst band and TL5 the calmest (DEFCON scale)', () => {
    assert.strictEqual(F.tlBand(1).band, 'critical');
    assert.strictEqual(F.tlBand(5).band, 'normal');
});

test('every TL band names a :root custom property, never a colour literal', () => {
    [1, 2, 3, 4, 5].forEach(tl => {
        assert.ok(/^--color-/.test(F.tlBand(tl).cssVar), `TL${tl}`);
    });
    assert.ok(/^--color-/.test(F.tlBand(null).cssVar));
});

test('an unknown TL is neutral, not calm', () => {
    [null, undefined, 0, 6, 'x', NaN].forEach(bad => {
        const b = F.tlBand(bad);
        assert.strictEqual(b.band, 'unknown', String(bad));
        assert.strictEqual(b.tl, null);
        assert.notStrictEqual(b.band, 'normal');
    });
});

test('severityOf inverts TL exactly once', () => {
    assert.strictEqual(F.severityOf(1), 5);
    assert.strictEqual(F.severityOf(5), 1);
    assert.strictEqual(F.severityOf(null), null);
});

test('severity ordering matches "worse is greater"', () => {
    assert.ok(F.severityOf(1) > F.severityOf(3));
    assert.ok(F.severityOf(3) > F.severityOf(5));
});

// ── trend: positive severity delta means WORSE ───────────────────────────

test('a positive severity delta is escalation, not improvement', () => {
    const t = F.trendOf(2);
    assert.strictEqual(t.direction, 'escalating');
    assert.strictEqual(t.glyph, '▲');
});

test('a negative severity delta is de-escalation', () => {
    assert.strictEqual(F.trendOf(-1).direction, 'deescalating');
});

test('zero is flat and null is unknown — they are different', () => {
    assert.strictEqual(F.trendOf(0).direction, 'flat');
    assert.strictEqual(F.trendOf(null).direction, 'unknown');
    assert.strictEqual(F.trendOf(null).delta, null);
});

// ── missing numbers never become zero (S1-UI-052) ────────────────────────

test('num renders absence as the absent mark, never 0', () => {
    assert.strictEqual(F.num(null), F.ABSENT);
    assert.strictEqual(F.num(undefined), F.ABSENT);
    assert.strictEqual(F.num(NaN), F.ABSENT);
    assert.strictEqual(F.num(Infinity), F.ABSENT);
    assert.notStrictEqual(F.num(null), '0');
    assert.strictEqual(F.num(0), '0');            // a real zero still prints
    assert.strictEqual(F.num(1.234, 2), '1.23');
});

test('signed keeps the direction visible', () => {
    assert.strictEqual(F.signed(2), '+2');
    assert.strictEqual(F.signed(-2), '-2');
    assert.strictEqual(F.signed(0), '0');
    assert.strictEqual(F.signed(null), F.ABSENT);
    assert.strictEqual(F.signed(-1.5, 1), '-1.5');
});

// ── duration returns keys, not prose ─────────────────────────────────────

test('duration returns a dictionary key and its slot, never a sentence', () => {
    assert.deepStrictEqual(F.duration(30), { key: 'ui.duration.seconds', vars: { n: 30 } });
    assert.deepStrictEqual(F.duration(90), { key: 'ui.duration.minutes', vars: { n: 1 } });
    assert.deepStrictEqual(F.duration(7200), { key: 'ui.duration.hours', vars: { n: 2 } });
    assert.deepStrictEqual(F.duration(172800), { key: 'ui.duration.days', vars: { n: 2 } });
    assert.strictEqual(F.duration(null).key, 'ui.duration.unknown');
    assert.strictEqual(F.duration(-5).key, 'ui.duration.unknown');
});

test('utcStamp is UTC and absent-safe', () => {
    assert.strictEqual(F.utcStamp(0), '1970-01-01T00:00:00Z');
    assert.strictEqual(F.utcStamp(null), F.ABSENT);
});

// ── sanitisation (S1-UI-041) ─────────────────────────────────────────────

test('escHtml neutralises every markup-significant character', () => {
    assert.strictEqual(F.escHtml('<script>alert("x")</script>'),
        '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;');
    assert.strictEqual(F.escHtml("it's & so"), 'it&#39;s &amp; so');
    assert.strictEqual(F.escHtml(null), '');
    assert.strictEqual(F.escHtml(undefined), '');
});

test('escHtml escapes the ampersand first, so entities are not double-decoded', () => {
    assert.strictEqual(F.escHtml('&lt;'), '&amp;lt;');
});

test('safeUrl passes http/https and rejects every other scheme', () => {
    assert.strictEqual(F.safeUrl('https://example.test/a'), 'https://example.test/a');
    assert.strictEqual(F.safeUrl('http://example.test/a'), 'http://example.test/a');
    ['javascript:alert(1)', 'data:text/html,<x>', 'file:///etc/passwd',
     'vbscript:x', '//example.test', 'example.test', '', null, 42,
    ].forEach(bad => {
        assert.strictEqual(F.safeUrl(bad), null, String(bad));
    });
});

test('safeUrl rejects a URL with an embedded space or control character', () => {
    assert.strictEqual(F.safeUrl('https://example.test/a b'), null);
    assert.strictEqual(F.safeUrl('https://example.test/a\nb'), null);
    // ...but an ordinary URL with a trailing slash is fine.
    assert.strictEqual(F.safeUrl('https://example.test/'), 'https://example.test/');
});

test('safeUrl is case-insensitive about the scheme but keeps the URL verbatim', () => {
    assert.strictEqual(F.safeUrl(' HTTPS://Example.test/A '), 'HTTPS://Example.test/A');
});

// ── Report ───────────────────────────────────────────────────────────────

console.log(`\n\n${passed} passed, ${failed} failed`);
if (failed > 0) {
    failures.forEach(({ name, error }) => {
        console.error(`\n  FAIL: ${name}`);
        console.error('  ' + (error.stack || error));
    });
    process.exit(1);
}
process.exit(0);
