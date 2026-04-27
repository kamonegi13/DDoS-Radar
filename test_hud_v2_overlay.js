/**
 * Unit tests for hud_v2_overlay.js — pure HUD↔v2 reconciler.
 *
 * Run:   node test_hud_v2_overlay.js
 * Exit code 0 = all green, 1 = at least one failure.
 *
 * Mirrors the KISS pattern of test_wp_alarm.js (no jest, no jsdom).
 */
'use strict';

const assert = require('assert');
const { applyOverlay, parseKvState } = require('./hud_v2_overlay');

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
    try {
        fn();
        passed += 1;
        process.stdout.write('.');
    } catch (e) {
        failed += 1;
        failures.push({ name, error: e });
        process.stdout.write('F');
    }
}

// ─── Fixtures ────────────────────────────────────────────────────────────────

const v1Strat = Object.freeze({
    threat_level: 5,
    domains: Object.freeze({
        cyber:    { score: 2.0, status: 'WATCH' },
        physical: { score: 0.0, status: 'NORMAL' },
        info:     { score: 0.0, status: 'NORMAL' },
    }),
    analytics: Object.freeze({ direction_summary: { dominant_direction: 'UNKNOWN' } }),
});

function tlConclusion(tl, opts) {
    return Object.assign({
        conclusion_type: 'threat_level',
        state: String(tl),
        conclusion_unavailable_reason: null,
        confidence: 0.8,
    }, opts || {});
}

function pdConclusion(statusKv, scores, opts) {
    return Object.assign({
        conclusion_type: 'per_domain',
        state: statusKv,
        conclusion_unavailable_reason: null,
        confidence: 0.8,
        metadata: { domain_scores: scores },
    }, opts || {});
}

// ─── parseKvState ────────────────────────────────────────────────────────────

test('parseKvState parses 3-key v2 string', () => {
    const r = parseKvState('cyber=ACTIVE;physical=STABLE;info=INSUFFICIENT_SIGNAL');
    assert.deepStrictEqual(r, {
        cyber: 'ACTIVE', physical: 'STABLE', info: 'INSUFFICIENT_SIGNAL',
    });
});

test('parseKvState handles whitespace around keys/values', () => {
    const r = parseKvState(' cyber = ACTIVE ; physical = STABLE ');
    assert.deepStrictEqual(r, { cyber: 'ACTIVE', physical: 'STABLE' });
});

test('parseKvState drops malformed pairs silently', () => {
    const r = parseKvState('cyber=ACTIVE;junk;=VALUE;key=');
    assert.deepStrictEqual(r, { cyber: 'ACTIVE' });
});

test('parseKvState returns {} for non-string input', () => {
    assert.deepStrictEqual(parseKvState(null), {});
    assert.deepStrictEqual(parseKvState(undefined), {});
    assert.deepStrictEqual(parseKvState(42), {});
    assert.deepStrictEqual(parseKvState({}), {});
});

// ─── applyOverlay — no-op paths ──────────────────────────────────────────────

test('applyOverlay returns strat unchanged when byType is empty', () => {
    const r = applyOverlay(v1Strat, {});
    assert.strictEqual(r, v1Strat);
});

test('applyOverlay returns strat unchanged when byType is null', () => {
    const r = applyOverlay(v1Strat, null);
    assert.strictEqual(r, v1Strat);
});

test('applyOverlay returns strat unchanged when neither TL nor per_domain present', () => {
    const r = applyOverlay(v1Strat, { trend: { state: 'short_term=STABLE' } });
    assert.strictEqual(r, v1Strat);
});

test('applyOverlay propagates null/undefined strat', () => {
    assert.strictEqual(applyOverlay(null, { threat_level: tlConclusion(3) }), null);
    assert.strictEqual(applyOverlay(undefined, {}), undefined);
});

test('applyOverlay treats unavailable TL conclusion as no-op', () => {
    const r = applyOverlay(v1Strat, {
        threat_level: tlConclusion(3, { conclusion_unavailable_reason: 'insufficient_data' }),
    });
    assert.strictEqual(r, v1Strat);
});

test('applyOverlay treats non-numeric TL state as no-op', () => {
    const r = applyOverlay(v1Strat, { threat_level: tlConclusion('not_a_number') });
    assert.strictEqual(r, v1Strat);
});

// ─── applyOverlay — TL override ──────────────────────────────────────────────

test('applyOverlay overrides TL when v2 has a numeric available conclusion', () => {
    const r = applyOverlay(v1Strat, { threat_level: tlConclusion(3) });
    assert.strictEqual(r.threat_level, 3);
});

test('applyOverlay returns NEW object on TL override (immutability)', () => {
    const r = applyOverlay(v1Strat, { threat_level: tlConclusion(3) });
    assert.notStrictEqual(r, v1Strat);
    assert.strictEqual(v1Strat.threat_level, 5, 'input must be untouched');
});

test('applyOverlay preserves non-overridden fields on TL override', () => {
    const r = applyOverlay(v1Strat, { threat_level: tlConclusion(2) });
    assert.deepStrictEqual(r.domains, v1Strat.domains);
    assert.deepStrictEqual(r.analytics, v1Strat.analytics);
});

// ─── applyOverlay — per_domain override ──────────────────────────────────────

test('applyOverlay overrides domains when v2 per_domain is available', () => {
    const r = applyOverlay(v1Strat, {
        per_domain: pdConclusion(
            'cyber=STABLE;physical=INSUFFICIENT_SIGNAL;info=INSUFFICIENT_SIGNAL',
            { cyber: 1.0, physical: 0.0, info: 0.0 },
        ),
    });
    assert.deepStrictEqual(r.domains.cyber, { score: 1.0, status: 'STABLE' });
    assert.deepStrictEqual(r.domains.physical, { score: 0.0, status: 'INSUFFICIENT_SIGNAL' });
    assert.deepStrictEqual(r.domains.info, { score: 0.0, status: 'INSUFFICIENT_SIGNAL' });
});

test('applyOverlay falls back to v1 score when v2 metadata.domain_scores key is missing', () => {
    // metadata.domain_scores omits "info" entirely — fallback should keep v1 score (0.0)
    const r = applyOverlay(v1Strat, {
        per_domain: pdConclusion(
            'cyber=ACTIVE;physical=STABLE;info=ACTIVE',
            { cyber: 3.0, physical: 1.0 },
        ),
    });
    assert.strictEqual(r.domains.info.score, 0.0);
    assert.strictEqual(r.domains.info.status, 'ACTIVE');  // status from kv-state still applied
});

test('applyOverlay falls back to v1 status when v2 kv-state omits a domain', () => {
    const r = applyOverlay(v1Strat, {
        per_domain: pdConclusion(
            'cyber=ACTIVE;physical=STABLE',  // info omitted
            { cyber: 3.0, physical: 1.0, info: 0.5 },
        ),
    });
    assert.strictEqual(r.domains.info.status, 'NORMAL');  // v1 fallback
    assert.strictEqual(r.domains.info.score, 0.5);  // v2 score still applied
});

test('applyOverlay handles missing metadata gracefully', () => {
    const r = applyOverlay(v1Strat, {
        per_domain: pdConclusion('cyber=STABLE;physical=STABLE;info=STABLE', undefined, {
            metadata: undefined,
        }),
    });
    // All scores fall back to v1, statuses come from kv
    assert.strictEqual(r.domains.cyber.score, 2.0);
    assert.strictEqual(r.domains.cyber.status, 'STABLE');
});

test('applyOverlay treats unavailable per_domain conclusion as no-op for domains', () => {
    const r = applyOverlay(v1Strat, {
        per_domain: pdConclusion(
            'cyber=ACTIVE',
            { cyber: 9.9 },
            { conclusion_unavailable_reason: 'insufficient_data' },
        ),
    });
    assert.deepStrictEqual(r, v1Strat);
});

// ─── applyOverlay — combined override ────────────────────────────────────────

test('applyOverlay overrides both TL and per_domain in one pass', () => {
    const r = applyOverlay(v1Strat, {
        threat_level: tlConclusion(2),
        per_domain: pdConclusion(
            'cyber=ACTIVE;physical=ELEVATED;info=STABLE',
            { cyber: 3.5, physical: 2.0, info: 0.5 },
        ),
    });
    assert.strictEqual(r.threat_level, 2);
    assert.strictEqual(r.domains.cyber.status, 'ACTIVE');
    assert.strictEqual(r.domains.physical.score, 2.0);
});

test('applyOverlay does not mutate v1 domain objects', () => {
    const r = applyOverlay(v1Strat, {
        per_domain: pdConclusion(
            'cyber=ACTIVE;physical=STABLE;info=STABLE',
            { cyber: 9.9, physical: 1.1, info: 0.5 },
        ),
    });
    assert.strictEqual(v1Strat.domains.cyber.score, 2.0);
    assert.strictEqual(v1Strat.domains.cyber.status, 'WATCH');
    assert.notStrictEqual(r.domains, v1Strat.domains);
    assert.notStrictEqual(r.domains.cyber, v1Strat.domains.cyber);
});

test('applyOverlay handles strat without domains property', () => {
    const bare = { threat_level: 5 };
    const r = applyOverlay(bare, {
        per_domain: pdConclusion(
            'cyber=ACTIVE;physical=STABLE;info=STABLE',
            { cyber: 3.0, physical: 1.0, info: 0.5 },
        ),
    });
    assert.deepStrictEqual(r.domains.cyber, { score: 3.0, status: 'ACTIVE' });
    assert.deepStrictEqual(r.domains.physical, { score: 1.0, status: 'STABLE' });
});

// ─── Report ──────────────────────────────────────────────────────────────────

console.log(`\n\n${passed} passed, ${failed} failed`);
if (failed > 0) {
    failures.forEach(({ name, error }) => {
        console.error(`\n  FAIL: ${name}`);
        console.error('  ' + (error.stack || error));
    });
    process.exit(1);
}
process.exit(0);
