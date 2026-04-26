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
const {
    normalizeAlarm, alarmMatches, alarmDescribe,
    loadStateFromRaw, evaluateAlarmsEdge, applyAlarmToState,
} = require('./wp_alarm');

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

// ─── loadStateFromRaw: state migration / hardening ──────────────────────────

test('loadStateFromRaw: null/empty returns empty state with version stamp', () => {
    const s = loadStateFromRaw(null, 2);
    assert.deepStrictEqual(s, { version: 2, sensors: [] });
    const s2 = loadStateFromRaw('', 2);
    assert.deepStrictEqual(s2, { version: 2, sensors: [] });
});

test('loadStateFromRaw: malformed JSON yields empty state (no throw)', () => {
    const s = loadStateFromRaw('{not json', 2);
    assert.deepStrictEqual(s, { version: 2, sensors: [] });
});

test('loadStateFromRaw: missing sensors array yields empty state', () => {
    const s = loadStateFromRaw(JSON.stringify({ foo: 'bar' }), 2);
    assert.deepStrictEqual(s, { version: 2, sensors: [] });
});

test('loadStateFromRaw: drops malformed rows (no name string)', () => {
    const raw = JSON.stringify({ sensors: [
        { name: 'good_sensor', scope: 'focused' },
        { scope: 'focused' },                              // no name
        null,                                              // null row
        { name: 42 },                                      // wrong type
    ]});
    const s = loadStateFromRaw(raw, 2);
    assert.strictEqual(s.sensors.length, 1);
    assert.strictEqual(s.sensors[0].name, 'good_sensor');
});

test('loadStateFromRaw: v1 row (no alarm field) migrates to v2 with alarm=null', () => {
    const raw = JSON.stringify({ sensors: [
        { name: 'cyber_signal', scope: 'focused', added_at: 1700000000000 },
    ]});
    const s = loadStateFromRaw(raw, 2);
    assert.strictEqual(s.version, 2);
    assert.strictEqual(s.sensors[0].alarm, null);
    assert.strictEqual(s.sensors[0].added_at, 1700000000000);
});

test('loadStateFromRaw: v2 row with valid alarm normalises through', () => {
    const raw = JSON.stringify({ sensors: [
        { name: 's1', scope: 'global', alarm: { field: 'score', op: '>=', value: 70 } },
    ]});
    const s = loadStateFromRaw(raw, 2);
    assert.deepStrictEqual(s.sensors[0].alarm, {
        field: 'score', op: '>=', value: 70,
        last_fired_ts: 0, is_active: false, notify: true,
    });
});

test('loadStateFromRaw: v2 row with invalid alarm survives with alarm=null', () => {
    const raw = JSON.stringify({ sensors: [
        { name: 's1', scope: 'focused', alarm: { field: 'bogus', op: '>', value: 1 } },
    ]});
    const s = loadStateFromRaw(raw, 2);
    assert.strictEqual(s.sensors[0].alarm, null);
});

test('loadStateFromRaw: defaults scope to focused when missing', () => {
    const raw = JSON.stringify({ sensors: [{ name: 's1' }]});
    const s = loadStateFromRaw(raw, 2);
    assert.strictEqual(s.sensors[0].scope, 'focused');
});

test('loadStateFromRaw: returns NEW state object (immutability)', () => {
    const input = { sensors: [{ name: 's1', scope: 'focused' }] };
    const raw = JSON.stringify(input);
    const s = loadStateFromRaw(raw, 2);
    // Mutating the input should never affect the result.
    input.sensors[0].name = 'mutated';
    assert.strictEqual(s.sensors[0].name, 's1');
});

// ─── evaluateAlarmsEdge: rising / falling edges ─────────────────────────────

const obsMap = (entries) => {
    const m = new Map();
    for (const [k, v] of entries) m.set(k, v);
    return m;
};

test('evaluateAlarmsEdge: no alarm rows → no change, same reference', () => {
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm: null, added_at: 0 },
    ]};
    const result = evaluateAlarmsEdge(state, new Map(), 1234);
    assert.strictEqual(result.changed, false);
    assert.strictEqual(result.nextState, state);  // identity preserved
    assert.deepStrictEqual(result.rising, []);
    assert.deepStrictEqual(result.falling, []);
});

test('evaluateAlarmsEdge: false→true rising edge emits row & stamps ts', () => {
    const alarm = normalizeAlarm({ field: 'score', op: '>=', value: 40 });
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm, added_at: 0 },
    ]};
    const obs = obsMap([['s1::focused', baseEnv(50, 100, 'FIRED')]]);
    const result = evaluateAlarmsEdge(state, obs, 9999);
    assert.strictEqual(result.changed, true);
    assert.strictEqual(result.rising.length, 1);
    assert.strictEqual(result.rising[0].alarm.is_active, true);
    assert.strictEqual(result.rising[0].alarm.last_fired_ts, 9999);
});

test('evaluateAlarmsEdge: stays-true (no edge) → no rising emit', () => {
    const alarm = { ...normalizeAlarm({ field: 'score', op: '>=', value: 40 }),
                    is_active: true, last_fired_ts: 5000 };
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm, added_at: 0 },
    ]};
    const obs = obsMap([['s1::focused', baseEnv(50, 100, 'FIRED')]]);  // still ≥40
    const result = evaluateAlarmsEdge(state, obs, 9999);
    assert.strictEqual(result.changed, false);
    assert.strictEqual(result.rising.length, 0);
});

test('evaluateAlarmsEdge: true→false falling edge reported separately', () => {
    const alarm = { ...normalizeAlarm({ field: 'score', op: '>=', value: 40 }),
                    is_active: true, last_fired_ts: 5000 };
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm, added_at: 0 },
    ]};
    const obs = obsMap([['s1::focused', baseEnv(10, 100, 'NORMAL')]]);  // now <40
    const result = evaluateAlarmsEdge(state, obs, 9999);
    assert.strictEqual(result.changed, true);
    assert.strictEqual(result.falling.length, 1);
    assert.strictEqual(result.rising.length, 0);
    assert.strictEqual(result.falling[0].alarm.is_active, false);
    // last_fired_ts NOT updated on falling edge
    assert.strictEqual(result.falling[0].alarm.last_fired_ts, 5000);
});

test('evaluateAlarmsEdge: never mutates original state object', () => {
    const alarm = normalizeAlarm({ field: 'score', op: '>=', value: 40 });
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm, added_at: 0 },
    ]};
    const stateCopy = JSON.parse(JSON.stringify(state));
    evaluateAlarmsEdge(state, obsMap([['s1::focused', baseEnv(50, 100, 'FIRED')]]), 1);
    assert.deepStrictEqual(state, stateCopy);  // input untouched
});

test('evaluateAlarmsEdge: missing observation env keeps row inactive (no spurious fire)', () => {
    const alarm = normalizeAlarm({ field: 'score', op: '>=', value: 40 });
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm, added_at: 0 },
    ]};
    const result = evaluateAlarmsEdge(state, new Map(), 1);
    assert.strictEqual(result.changed, false);
    assert.strictEqual(result.rising.length, 0);
});

test('evaluateAlarmsEdge: multiple rows — independent edges', () => {
    const aHigh = normalizeAlarm({ field: 'score', op: '>=', value: 40 });
    const aLow  = { ...normalizeAlarm({ field: 'score', op: '>=', value: 90 }),
                    is_active: true, last_fired_ts: 1 };
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm: aHigh, added_at: 0 },  // will rise
        { name: 's2', scope: 'focused', alarm: aLow,  added_at: 0 },  // will fall
        { name: 's3', scope: 'focused', alarm: null,  added_at: 0 },  // no alarm
    ]};
    const obs = obsMap([
        ['s1::focused', baseEnv(50, 100, 'FIRED')],   // 50 ≥ 40 → rise
        ['s2::focused', baseEnv(50, 100, 'FIRED')],   // 50 < 90 → fall
        ['s3::focused', baseEnv(99, 100, 'FIRED')],
    ]);
    const result = evaluateAlarmsEdge(state, obs, 1234);
    assert.strictEqual(result.rising.length, 1);
    assert.strictEqual(result.rising[0].name, 's1');
    assert.strictEqual(result.falling.length, 1);
    assert.strictEqual(result.falling[0].name, 's2');
});

test('evaluateAlarmsEdge: accepts plain object instead of Map', () => {
    const alarm = normalizeAlarm({ field: 'score', op: '>=', value: 40 });
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm, added_at: 0 },
    ]};
    const obs = { 's1::focused': baseEnv(50, 100, 'FIRED') };
    const result = evaluateAlarmsEdge(state, obs, 1);
    assert.strictEqual(result.changed, true);
    assert.strictEqual(result.rising.length, 1);
});

// ─── applyAlarmToState: row alarm setter ────────────────────────────────────

test('applyAlarmToState: sets candidate alarm on target row only', () => {
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm: null, added_at: 0 },
        { name: 's2', scope: 'focused', alarm: null, added_at: 0 },
    ]};
    const a = normalizeAlarm({ field: 'score', op: '>=', value: 70 });
    const next = applyAlarmToState(state, 0, a);
    assert.deepStrictEqual(next.sensors[0].alarm, a);
    assert.strictEqual(next.sensors[1].alarm, null);
});

test('applyAlarmToState: null candidate clears alarm', () => {
    const a = normalizeAlarm({ field: 'score', op: '>=', value: 70 });
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm: a, added_at: 0 },
    ]};
    const next = applyAlarmToState(state, 0, null);
    assert.strictEqual(next.sensors[0].alarm, null);
});

test('applyAlarmToState: out-of-range idx returns same reference', () => {
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm: null, added_at: 0 },
    ]};
    assert.strictEqual(applyAlarmToState(state,  5, null), state);
    assert.strictEqual(applyAlarmToState(state, -1, null), state);
    assert.strictEqual(applyAlarmToState(state, 1.5, null), state);
});

test('applyAlarmToState: never mutates input', () => {
    const state = { version: 2, sensors: [
        { name: 's1', scope: 'focused', alarm: null, added_at: 0 },
    ]};
    const snapshot = JSON.parse(JSON.stringify(state));
    const a = normalizeAlarm({ field: 'score', op: '>=', value: 70 });
    applyAlarmToState(state, 0, a);
    assert.deepStrictEqual(state, snapshot);
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
