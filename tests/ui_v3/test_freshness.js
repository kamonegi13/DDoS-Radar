/**
 * Unit tests for v3/ui/freshness.js — change detection and staleness.
 *
 * Run:  node tests/ui_v3/test_freshness.js
 *
 * These tests exist because of G-10. The v1 redraw-skip signature was a
 * hand-written list of four fields, and map overlays / participants / the
 * correlation map were not on it — so "data updated, display silently
 * stale" was a live defect class rather than a hypothetical one. The
 * central test here is `test_every_leaf_change_is_detected`: it mutates
 * EVERY leaf of a deep payload one at a time and requires the signature
 * to move for each. A field list cannot pass that test; only a whole-value
 * fold can.
 */
'use strict';

const assert = require('assert');
const {
    signatureOf, createChangeDetector, omitVolatile, VOLATILE_KEYS,
    freshnessOf, FRESHNESS_AGING_SEC, FRESHNESS_STALE_SEC,
    FRESH, AGING, STALE, FAILED, UNKNOWN,
} = require('../../v3/ui/freshness');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

// ── signatureOf: the whole value, not a field list ───────────────────────

const DEEP_PAYLOAD = {
    scenario_id: 'taiwan_contingency',
    observed_at: 1800000000,
    data_freshness_sec: 12.5,
    conclusions: [
        {
            conclusion_id: 'c-1', conclusion_type: 'threat_level',
            state: '3', confidence: 0.72, unavailable_reason: null,
            calibration_status: { status: 'OK', recall: 0.81 },
            source_urls: ['https://example.test/a'],
            metadata: { per_domain: { cyber: 4.1, physical: 0.0, information: 2.2 } },
        },
    ],
    participants: { TW: { weight: 1.0, role: 'primary_target' } },
    map_overlay: { markers: [{ country: 'TW', lat: 23.7, lon: 121.0 }] },
    correlation: { pairs: [['TW', 'CN', 2.5]] },
    nested: { a: { b: { c: [1, 2, { d: true }] } } },
};

/** Every path to a leaf in `value`, as arrays of keys/indices. */
function leafPaths(value, prefix) {
    prefix = prefix || [];
    if (Array.isArray(value)) {
        return value.reduce(
            (acc, v, i) => acc.concat(leafPaths(v, prefix.concat(i))), []);
    }
    if (value && typeof value === 'object') {
        return Object.keys(value).reduce(
            (acc, k) => acc.concat(leafPaths(value[k], prefix.concat(k))), []);
    }
    return [prefix];
}

function mutateAt(value, path) {
    const clone = JSON.parse(JSON.stringify(value));
    let cursor = clone;
    for (let i = 0; i < path.length - 1; i += 1) cursor = cursor[path[i]];
    const key = path[path.length - 1];
    const old = cursor[key];
    if (typeof old === 'number') cursor[key] = old + 1;
    else if (typeof old === 'string') cursor[key] = old + 'X';
    else if (typeof old === 'boolean') cursor[key] = !old;
    else cursor[key] = 'was-null';
    return clone;
}

test('every_leaf_change_is_detected (G-10)', () => {
    const base = signatureOf(DEEP_PAYLOAD);
    const paths = leafPaths(DEEP_PAYLOAD);
    assert.ok(paths.length > 20, `expected a deep payload, got ${paths.length} leaves`);
    const missed = [];
    paths.forEach(p => {
        if (signatureOf(mutateAt(DEEP_PAYLOAD, p)) === base) missed.push(p.join('.'));
    });
    assert.deepStrictEqual(missed, [],
        'these leaves changed without moving the signature — G-10 exactly');
});

test('signature is stable across key ordering', () => {
    assert.strictEqual(signatureOf({ a: 1, b: 2 }), signatureOf({ b: 2, a: 1 }));
});

test('signature distinguishes types that stringify alike', () => {
    assert.notStrictEqual(signatureOf({ a: 1 }), signatureOf({ a: '1' }));
    assert.notStrictEqual(signatureOf({ a: null }), signatureOf({ a: 'null' }));
    assert.notStrictEqual(signatureOf({ a: false }), signatureOf({ a: 0 }));
    assert.notStrictEqual(signatureOf([1, 2]), signatureOf({ 0: 1, 1: 2 }));
});

test('signature distinguishes absent key from null value', () => {
    assert.notStrictEqual(signatureOf({ a: 1 }), signatureOf({ a: 1, b: null }));
});

test('array order matters', () => {
    assert.notStrictEqual(signatureOf([1, 2, 3]), signatureOf([3, 2, 1]));
});

test('undefined values are recorded, not dropped', () => {
    assert.notStrictEqual(signatureOf({ a: undefined }), signatureOf({}));
});

// ── omitVolatile: an EXCLUSION list, not an inclusion list ───────────────

test('the clock fields are removed at any depth', () => {
    const stripped = omitVolatile({
        served_at: 1, data_freshness_sec: 2, fetchedAt: 3, servedAt: 4,
        keep: 'me',
        nested: { served_at: 1, alsoKeep: true },
        list: [{ data_freshness_sec: 9, deep: 'kept' }],
    });
    assert.deepStrictEqual(stripped, {
        keep: 'me', nested: { alsoKeep: true }, list: [{ deep: 'kept' }],
    });
});

test('omitVolatile removes ONLY the named clock fields', () => {
    const payload = { a: 1, observed_at: 5, at: 7, score: 3, error: null };
    assert.deepStrictEqual(omitVolatile(payload), payload,
        'observed_at and everything else must survive');
});

test('the volatile set is small, named, and exported for review', () => {
    assert.deepStrictEqual(VOLATILE_KEYS.slice().sort(),
        ['data_freshness_sec', 'fetchedAt', 'servedAt', 'served_at']);
});

test('a change anywhere but the clock still moves the signature', () => {
    const d = createChangeDetector();
    const base = { body: { served_at: 1, data_freshness_sec: 1, deep: { x: 1 } } };
    d.shouldRender('v', base);
    // only the clock moved
    assert.strictEqual(d.shouldRender('v', {
        body: { served_at: 999, data_freshness_sec: 999, deep: { x: 1 } },
    }).render, false, 'a ticking clock alone must not force a redraw');
    // something real moved, buried three levels down
    assert.strictEqual(d.shouldRender('v', {
        body: { served_at: 999, data_freshness_sec: 999, deep: { x: 2 } },
    }).render, true, 'a real change must always force one');
});

test('omitVolatile does not mutate its input', () => {
    const payload = { served_at: 1, keep: { served_at: 2, x: 3 } };
    const before = JSON.stringify(payload);
    omitVolatile(payload);
    assert.strictEqual(JSON.stringify(payload), before);
});

test('omitVolatile survives a cycle', () => {
    const a = { x: 1 };
    a.self = a;
    assert.doesNotThrow(() => omitVolatile(a));
});

// ── createChangeDetector ─────────────────────────────────────────────────

test('first render always happens', () => {
    const d = createChangeDetector();
    assert.strictEqual(d.shouldRender('board', { x: 1 }).render, true);
});

test('unchanged payload skips, changed payload renders', () => {
    const d = createChangeDetector();
    d.shouldRender('board', { x: 1 });
    assert.strictEqual(d.shouldRender('board', { x: 1 }).render, false);
    assert.strictEqual(d.shouldRender('board', { x: 2 }).render, true);
});

test('views are independent', () => {
    const d = createChangeDetector();
    d.shouldRender('board', { x: 1 });
    assert.strictEqual(d.shouldRender('lane', { x: 1 }).render, true);
});

test('invalidate drops one view signature and states the reason (S1-UI-012)', () => {
    const d = createChangeDetector();
    d.shouldRender('board', { x: 1 });
    d.invalidate('board', 'focus_changed');
    const r = d.shouldRender('board', { x: 1 });
    assert.strictEqual(r.render, true);
    assert.strictEqual(r.reason, 'invalidated');
    assert.strictEqual(r.detail, 'focus_changed');
});

test('invalidateAll drops every view (focus / login / replay)', () => {
    const d = createChangeDetector();
    d.shouldRender('board', { x: 1 });
    d.shouldRender('lane', { y: 1 });
    d.invalidateAll('replay_applied');
    assert.strictEqual(d.shouldRender('board', { x: 1 }).render, true);
    assert.strictEqual(d.shouldRender('lane', { y: 1 }).render, true);
});

test('invalidation requires a reason (NP6)', () => {
    const d = createChangeDetector();
    assert.throws(() => d.invalidateAll(''), /reason/);
    assert.throws(() => d.invalidate('board'), /reason/);
});

test('a skip is recorded so "we skipped" is observable, not silent', () => {
    const d = createChangeDetector();
    d.shouldRender('board', { x: 1 });
    const r = d.shouldRender('board', { x: 1 });
    assert.strictEqual(r.render, false);
    assert.strictEqual(r.reason, 'unchanged');
    assert.strictEqual(typeof r.signature, 'string');
    assert.deepStrictEqual(d.lastSignature('board'), r.signature);
});

// ── freshnessOf ──────────────────────────────────────────────────────────

const NOW = 1800000000;

test('fresh when the projection is young and the fetch succeeded', () => {
    const f = freshnessOf({ observedAt: NOW - 5, now: NOW, fetchOk: true });
    assert.strictEqual(f.level, FRESH);
    assert.strictEqual(f.ageSec, 5);
});

test('aging and stale bands use the declared, exported boundaries', () => {
    assert.strictEqual(
        freshnessOf({ observedAt: NOW - FRESHNESS_AGING_SEC, now: NOW, fetchOk: true }).level,
        AGING);
    assert.strictEqual(
        freshnessOf({ observedAt: NOW - FRESHNESS_STALE_SEC, now: NOW, fetchOk: true }).level,
        STALE);
});

test('a failed fetch is FAILED even when the held data is young (DP2)', () => {
    const f = freshnessOf({
        observedAt: NOW - 1, now: NOW, fetchOk: false, errorCode: 'network',
    });
    assert.strictEqual(f.level, FAILED);
    assert.strictEqual(f.errorCode, 'network');
    // The held age is still reported: S1-UI-008 keeps the last good data,
    // DP2 requires the age to be visible at the same time.
    assert.strictEqual(f.ageSec, 1);
});

test('a failed fetch never reports FRESH even at age zero', () => {
    const f = freshnessOf({ observedAt: NOW, now: NOW, fetchOk: false });
    assert.notStrictEqual(f.level, FRESH);
});

test('missing observed_at is UNKNOWN, not zero (no fabricated freshness)', () => {
    const f = freshnessOf({ observedAt: null, now: NOW, fetchOk: true });
    assert.strictEqual(f.level, UNKNOWN);
    assert.strictEqual(f.ageSec, null);
});

test('a future observed_at clamps to zero rather than going negative', () => {
    assert.strictEqual(
        freshnessOf({ observedAt: NOW + 30, now: NOW, fetchOk: true }).ageSec, 0);
});

test('freshness carries the boundary it used, so the tooltip can show it (NP6)', () => {
    const f = freshnessOf({ observedAt: NOW - 5, now: NOW, fetchOk: true });
    assert.strictEqual(f.boundaries.aging_sec, FRESHNESS_AGING_SEC);
    assert.strictEqual(f.boundaries.stale_sec, FRESHNESS_STALE_SEC);
});

test('every level maps to a dictionary key, never a bare English word', () => {
    [FRESH, AGING, STALE, FAILED, UNKNOWN].forEach(level => {
        const f = freshnessOf({
            observedAt: level === UNKNOWN ? null : NOW,
            now: NOW,
            fetchOk: level !== FAILED,
            forceLevel: level,
        });
        assert.ok(/^ui\.freshness\./.test(f.labelKey),
            `level ${level} produced labelKey ${f.labelKey}`);
    });
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
