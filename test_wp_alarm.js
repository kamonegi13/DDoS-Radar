/**
 * Unit tests for wp_alarm.js — pure evaluator + normaliser.
 *
 * Run:   node test_wp_alarm.js
 * Exit code 0 = all green, 1 = at least one failure.
 *
 * No external test framework — KISS, matches project's "外部フレームワーク不使用"
 * frontend stance. Mirrors the AAA structure used in test_engine.py.
 */
'use strict';

const assert = require('assert');
const { normalizeAlarm, alarmMatches, alarmDescribe } = require('./wp_alarm');

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

// ─── normalizeAlarm ─────────────────────────────────────────────────────────

test('normalizeAlarm: rejects null/undefined/non-object', () => {
    assert.strictEqual(normalizeAlarm(null), null);
    assert.strictEqual(normalizeAlarm(undefined), null);
    assert.strictEqual(normalizeAlarm('not-an-object'), null);
    assert.strictEqual(normalizeAlarm(42), null);
});

test('normalizeAlarm: rejects unknown field', () => {
    const r = normalizeAlarm({ field: 'bogus', op: '>', value: 50 });
    assert.strictEqual(r, null);
});

test('normalizeAlarm: rejects unknown op for numeric field', () => {
    const r = normalizeAlarm({ field: 'score', op: '~~', value: 50 });
    assert.strictEqual(r, null);
});

test('normalizeAlarm: rejects numeric op on status field', () => {
    const r = normalizeAlarm({ field: 'status', op: '>', value: 'FIRED' });
    assert.strictEqual(r, null);
});

test('normalizeAlarm: rejects non-finite numeric value', () => {
    assert.strictEqual(normalizeAlarm({ field: 'score', op: '>', value: 'foo' }), null);
    assert.strictEqual(normalizeAlarm({ field: 'score', op: '>', value: NaN }), null);
    assert.strictEqual(normalizeAlarm({ field: 'score', op: '>', value: Infinity }), null);
});

test('normalizeAlarm: rejects unknown status value', () => {
    const r = normalizeAlarm({ field: 'status', op: '==', value: 'WHATEVER' });
    assert.strictEqual(r, null);
});

test('normalizeAlarm: accepts valid numeric alarm with defaults', () => {
    const r = normalizeAlarm({ field: 'score', op: '>=', value: 50 });
    assert.deepStrictEqual(r, {
        field: 'score', op: '>=', value: 50,
        last_fired_ts: 0, is_active: false, notify: true,
    });
});

test('normalizeAlarm: coerces numeric strings', () => {
    const r = normalizeAlarm({ field: 'value', op: '<', value: '123.4' });
    assert.strictEqual(r.value, 123.4);
});

test('normalizeAlarm: uppercases status value', () => {
    const r = normalizeAlarm({ field: 'status', op: '==', value: 'fired' });
    assert.strictEqual(r.value, 'FIRED');
});

test('normalizeAlarm: preserves notify=false (opt-out)', () => {
    const r = normalizeAlarm({ field: 'score', op: '>', value: 1, notify: false });
    assert.strictEqual(r.notify, false);
});

// ─── alarmMatches: numeric (score / value / delta) ──────────────────────────

const baseEnv = (latestValue, currRaw, status, suppressed) => ({
    observations: [{ value: latestValue, delta_vs_baseline: latestValue - 10 }],
    current: { raw_value: currRaw, status, suppressed: !!suppressed },
});

test('alarmMatches: returns false on null alarm or env', () => {
    assert.strictEqual(alarmMatches(null, baseEnv(50, 100, 'FIRED')), false);
    assert.strictEqual(alarmMatches({ field: 'score', op: '>', value: 1 }, null), false);
});

test('alarmMatches: score > threshold (true case)', () => {
    const a = normalizeAlarm({ field: 'score', op: '>', value: 40 });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED')), true);
});

test('alarmMatches: score > threshold (false case)', () => {
    const a = normalizeAlarm({ field: 'score', op: '>', value: 60 });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED')), false);
});

test('alarmMatches: score >= boundary inclusive', () => {
    const a = normalizeAlarm({ field: 'score', op: '>=', value: 50 });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED')), true);
});

test('alarmMatches: value < threshold uses current.raw_value', () => {
    const a = normalizeAlarm({ field: 'value', op: '<', value: 200 });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED')), true);
});

test('alarmMatches: delta uses observations[last].delta_vs_baseline', () => {
    const a = normalizeAlarm({ field: 'delta', op: '>', value: 30 });
    // baseEnv(50,...) → delta=40 → 40 > 30 → true
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED')), true);
    const a2 = normalizeAlarm({ field: 'delta', op: '>', value: 50 });
    assert.strictEqual(alarmMatches(a2, baseEnv(50, 100, 'FIRED')), false);
});

test('alarmMatches: missing observations returns false (no spurious fire)', () => {
    const a = normalizeAlarm({ field: 'score', op: '>', value: 0 });
    const env = { observations: [], current: { raw_value: 100, status: 'FIRED' } };
    assert.strictEqual(alarmMatches(a, env), false);
});

test('alarmMatches: non-finite actual returns false', () => {
    const a = normalizeAlarm({ field: 'value', op: '>', value: 0 });
    const env = { observations: [{ value: 1 }], current: { raw_value: 'NaN-string', status: 'FIRED' } };
    assert.strictEqual(alarmMatches(a, env), false);
});

// ─── alarmMatches: status ───────────────────────────────────────────────────

test('alarmMatches: status == FIRED matches current.status', () => {
    const a = normalizeAlarm({ field: 'status', op: '==', value: 'FIRED' });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED')), true);
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'NORMAL')), false);
});

test('alarmMatches: status case-insensitive match (current.status lowercase)', () => {
    const a = normalizeAlarm({ field: 'status', op: '==', value: 'FIRED' });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'fired')), true);
});

test('alarmMatches: status SUPPRESSED takes precedence over status field', () => {
    const a = normalizeAlarm({ field: 'status', op: '==', value: 'SUPPRESSED' });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED', true)), true);
});

test('alarmMatches: status != NORMAL fires when FIRED', () => {
    const a = normalizeAlarm({ field: 'status', op: '!=', value: 'NORMAL' });
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'FIRED')), true);
    assert.strictEqual(alarmMatches(a, baseEnv(50, 100, 'NORMAL')), false);
});

test('alarmMatches: status with no current returns false', () => {
    const a = normalizeAlarm({ field: 'status', op: '==', value: 'FIRED' });
    const env = { observations: [{ value: 1 }], current: null };
    assert.strictEqual(alarmMatches(a, env), false);
});

// ─── alarmDescribe ──────────────────────────────────────────────────────────

test('alarmDescribe: renders human-readable predicate', () => {
    const a = normalizeAlarm({ field: 'score', op: '>=', value: 50 });
    assert.strictEqual(alarmDescribe(a), 'score >= 50');
});

test('alarmDescribe: empty for null alarm', () => {
    assert.strictEqual(alarmDescribe(null), '');
});

// ─── Summary ────────────────────────────────────────────────────────────────

console.log('\n');
if (failures.length) {
    console.log('FAILURES:');
    for (const f of failures) {
        console.log('  - ' + f.name);
        console.log('    ' + f.error.message);
    }
}
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
