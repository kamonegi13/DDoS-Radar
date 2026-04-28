/**
 * Unit tests for triage_score.js — pure attention_score / ranking.
 *
 * Run:  node test_triage_score.js
 * Exit code 0 = all green, 1 = at least one failure.
 *
 * Mirrors the KISS pattern of test_wp_alarm.js / test_hud_v2_overlay.js.
 */
'use strict';

const assert = require('assert');
const {
    computeAttentionScore, rankItems,
    NOVELTY_HORIZON_SEC, BLINDNESS_HORIZON_SEC, MIN_FIRE_THRESHOLD,
} = require('./triage_score');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1_800_000_000;  // fixed clock for deterministic ramps

function _conclusion(opts) {
    return Object.assign({
        id: 'c-1',
        conclusion_type: 'attack_mode',
        state: 'KINETIC_PREPARATION',
        confidence: 0.7,
        observed_at: NOW,
        conclusion_unavailable_reason: null,
        metadata: {},
    }, opts || {});
}

// ── computeAttentionScore — boundaries / no-op cases ──────────────────────

test('returns 0 score when conclusion has no id', () => {
    const r = computeAttentionScore(_conclusion({ id: null }), null, null, NOW);
    assert.strictEqual(r.score, 0);
    assert.ok(r.why.some(w => /no conclusion id/.test(w)));
});

test('returns 0 when conclusion is unavailable', () => {
    const r = computeAttentionScore(
        _conclusion({ conclusion_unavailable_reason: 'insufficient_data' }),
        null, null, NOW,
    );
    assert.strictEqual(r.score, 0);
});

test('returns 0 for null/undefined conclusion', () => {
    assert.strictEqual(computeAttentionScore(null, null, null, NOW).score, 0);
    assert.strictEqual(computeAttentionScore(undefined, null, null, NOW).score, 0);
});

test('returns 0 when conclusion id is in ackedIds', () => {
    const acked = new Set(['c-1']);
    const r = computeAttentionScore(_conclusion(), null, { ackedIds: acked }, NOW);
    assert.strictEqual(r.score, 0);
    assert.ok(r.why.some(w => /acknowledged/.test(w)));
});

// ── novelty component ─────────────────────────────────────────────────────

test('novelty = 1 when no history (first fire)', () => {
    const r = computeAttentionScore(_conclusion(), null, null, NOW);
    assert.strictEqual(r.components.novelty, 1.0);
});

test('novelty ramps to 0 over 48h since last fire', () => {
    const r24 = computeAttentionScore(
        _conclusion(), { lastFireTs: NOW - 24 * 3600 }, null, NOW,
    );
    const r48 = computeAttentionScore(
        _conclusion(), { lastFireTs: NOW - 48 * 3600 }, null, NOW,
    );
    const r60 = computeAttentionScore(
        _conclusion(), { lastFireTs: NOW - 60 * 3600 }, null, NOW,
    );
    assert.ok(Math.abs(r24.components.novelty - 0.5) < 0.01);
    assert.strictEqual(r48.components.novelty, 0);
    assert.strictEqual(r60.components.novelty, 0);  // clamped, no negative
});

// ── confidence_delta component ────────────────────────────────────────────

test('confDelta defaults to current confidence when no prior', () => {
    const r = computeAttentionScore(_conclusion({ confidence: 0.6 }), null, null, NOW);
    assert.ok(Math.abs(r.components.confDelta - 0.6) < 0.001);
});

test('confDelta is absolute change since prior', () => {
    const r = computeAttentionScore(
        _conclusion({ confidence: 0.9 }),
        { prevConfidence: 0.5 },
        null, NOW,
    );
    assert.ok(Math.abs(r.components.confDelta - 0.4) < 0.001);
});

test('confDelta on a drop is also positive', () => {
    const r = computeAttentionScore(
        _conclusion({ confidence: 0.3 }),
        { prevConfidence: 0.8 },
        null, NOW,
    );
    assert.ok(Math.abs(r.components.confDelta - 0.5) < 0.001);
});

test('confDelta clamps to [0,1]', () => {
    const high = computeAttentionScore(
        _conclusion({ confidence: 2.0 }),  // out-of-range input
        { prevConfidence: -0.5 },
        null, NOW,
    );
    assert.ok(high.components.confDelta <= 1);
});

// ── analyst_blindness component ───────────────────────────────────────────

test('blindness = 1 when no view recorded', () => {
    const r = computeAttentionScore(_conclusion(), null, null, NOW);
    assert.strictEqual(r.components.blindness, 1.0);
});

test('blindness = 0 right after view', () => {
    const r = computeAttentionScore(
        _conclusion(), null, { lastViewTs: NOW }, NOW,
    );
    assert.strictEqual(r.components.blindness, 0);
});

test('blindness ramps to 1 over 6h since last view', () => {
    const r3h = computeAttentionScore(
        _conclusion(), null, { lastViewTs: NOW - 3 * 3600 }, NOW,
    );
    const r6h = computeAttentionScore(
        _conclusion(), null, { lastViewTs: NOW - 6 * 3600 }, NOW,
    );
    const r12h = computeAttentionScore(
        _conclusion(), null, { lastViewTs: NOW - 12 * 3600 }, NOW,
    );
    assert.ok(Math.abs(r3h.components.blindness - 0.5) < 0.01);
    assert.strictEqual(r6h.components.blindness, 1);
    assert.strictEqual(r12h.components.blindness, 1);  // clamped
});

// ── score = product of components, bounded [0,1] ──────────────────────────

test('score is the product of all three components', () => {
    const r = computeAttentionScore(
        _conclusion({ confidence: 0.5 }),
        { lastFireTs: NOW - 24 * 3600, prevConfidence: 0.0 },
        { lastViewTs: NOW - 3 * 3600 },
        NOW,
    );
    // novelty 0.5, confDelta 0.5, blindness 0.5 → 0.125
    assert.ok(Math.abs(r.score - 0.125) < 0.01);
});

test('score is 0 when any component is 0', () => {
    // Just-viewed → blindness=0 → score=0
    const r = computeAttentionScore(
        _conclusion(), null, { lastViewTs: NOW }, NOW,
    );
    assert.strictEqual(r.score, 0);
});

// ── rankItems ─────────────────────────────────────────────────────────────

test('rankItems sorts by score descending and assigns ranks', () => {
    const a = { conclusion: _conclusion({ id: 'a', confidence: 0.9 }) };
    const b = { conclusion: _conclusion({ id: 'b', confidence: 0.5 }) };
    const c = { conclusion: _conclusion({ id: 'c', confidence: 0.7 }) };
    const ranked = rankItems([a, b, c], null, NOW);
    assert.deepStrictEqual(ranked.map(e => e.conclusion.id), ['a', 'c', 'b']);
    assert.deepStrictEqual(ranked.map(e => e.rank), [1, 2, 3]);
});

test('rankItems drops items below MIN_FIRE_THRESHOLD', () => {
    // Just-viewed scenario → blindness 0 → score 0 → drops
    const a = {
        conclusion: _conclusion({ id: 'a', confidence: 0.9 }),
    };
    const ranked = rankItems([a], { lastViewTs: NOW }, NOW);
    assert.strictEqual(ranked.length, 0);
});

test('rankItems treats acked entries as zero-score', () => {
    const a = { conclusion: _conclusion({ id: 'a', confidence: 0.9 }) };
    const b = { conclusion: _conclusion({ id: 'b', confidence: 0.5 }) };
    const ranked = rankItems([a, b], { ackedIds: new Set(['a']) }, NOW);
    assert.deepStrictEqual(ranked.map(e => e.conclusion.id), ['b']);
});

test('rankItems returns empty array on non-array input', () => {
    assert.deepStrictEqual(rankItems(null), []);
    assert.deepStrictEqual(rankItems(undefined), []);
    assert.deepStrictEqual(rankItems({}), []);
});

test('rankItems output is a new array (does not mutate input)', () => {
    const input = [{ conclusion: _conclusion() }];
    const out = rankItems(input, null, NOW);
    assert.notStrictEqual(out, input);
    assert.strictEqual(input.length, 1);
    assert.strictEqual(input[0].rank, undefined);
});

// ── why string contains the rationale (NP6 / AP1 transparency) ────────────

test('why list always includes novelty / confDelta / blindness lines', () => {
    const r = computeAttentionScore(
        _conclusion(),
        { lastFireTs: NOW - 12 * 3600, prevConfidence: 0.4 },
        { lastViewTs: NOW - 4 * 3600 },
        NOW,
    );
    assert.ok(r.why.some(w => /novelty/.test(w)));
    assert.ok(r.why.some(w => /Δconf/.test(w)));
    assert.ok(r.why.some(w => /blindness/.test(w)));
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
