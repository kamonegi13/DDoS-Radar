/**
 * Unit tests for map_dim.js — pure focus-change dim state machine.
 *
 * Run:   node test_map_dim.js
 * Exit code 0 = green, 1 = at least one failure.
 *
 * Mirrors the KISS pattern of test_wp_alarm.js / test_hud_v2_overlay.js
 * / test_triage_score.js. Uses an injected fake timer so tests don't
 * depend on real wall-clock time.
 */
'use strict';

const assert = require('assert');
const MapDim = require('./map_dim');

let passed = 0, failed = 0;
const failures = [];
function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}


// Fake timer factory: returns {setTimeout, clearTimeout, run} — `run(ms)`
// advances virtual time by `ms` and fires every callback whose deadline
// has elapsed.
function makeFakeTimers() {
    let nextId = 1;
    const queue = new Map();  // id → {deadline, cb}
    let now = 0;

    function setTimeout_(cb, ms) {
        const id = nextId++;
        queue.set(id, { deadline: now + ms, cb: cb });
        return id;
    }
    function clearTimeout_(id) { queue.delete(id); }
    function run(ms) {
        now += ms;
        const fire = [];
        for (const [id, entry] of queue.entries()) {
            if (entry.deadline <= now) {
                fire.push({ id, cb: entry.cb });
            }
        }
        // Sort by deadline so order is deterministic.
        fire.sort((a, b) => a.id - b.id);
        for (const { id, cb } of fire) {
            queue.delete(id);
            cb();
        }
    }
    return { setTimeout: setTimeout_, clearTimeout: clearTimeout_, run, _now: () => now };
}


// ── lifecycle: start → notifyReady (all sources) → lift fires once ───────

test('lift fires when all required sources arrive', () => {
    const dim = MapDim.create();
    let liftCount = 0;
    let liftReason = null;
    dim.start({
        scenarioName: 'taiwan',
        lift: (info) => { liftCount += 1; liftReason = info.reason; },
        timeoutMs: 1000,
    });
    assert.ok(dim.isActive());
    dim.notifyReady('threat_data');
    assert.ok(dim.isActive(), 'still active after partial arrival');
    dim.notifyReady('envelope');
    assert.strictEqual(liftCount, 1);
    assert.strictEqual(liftReason, 'lift');
    assert.ok(!dim.isActive());
});

test('lift fires only once even if extra sources arrive after settle', () => {
    const dim = MapDim.create();
    let liftCount = 0;
    dim.start({ lift: () => { liftCount += 1; }, timeoutMs: 1000 });
    dim.notifyReady('threat_data');
    dim.notifyReady('envelope');
    dim.notifyReady('threat_data');  // duplicate
    dim.notifyReady('envelope');     // duplicate
    assert.strictEqual(liftCount, 1);
});


// ── timeout / stale path ────────────────────────────────────────────────

test('stale fires when timeout expires before all sources arrive', () => {
    const t = makeFakeTimers();
    const dim = MapDim.create();
    let lifts = 0, stales = 0;
    dim.start({
        scenarioName: 'middle_east',
        lift: () => { lifts += 1; },
        stale: () => { stales += 1; },
        timeoutMs: 5000,
        _setTimeout: t.setTimeout,
        _clearTimeout: t.clearTimeout,
    });
    dim.notifyReady('threat_data');  // partial
    t.run(4999);
    assert.strictEqual(stales, 0, 'not stale yet');
    t.run(2);
    assert.strictEqual(stales, 1);
    assert.strictEqual(lifts, 0);
    assert.ok(!dim.isActive());
});

test('stale does not fire if all sources arrive before deadline', () => {
    const t = makeFakeTimers();
    const dim = MapDim.create();
    let stales = 0;
    dim.start({
        lift: () => {}, stale: () => { stales += 1; },
        timeoutMs: 5000,
        _setTimeout: t.setTimeout, _clearTimeout: t.clearTimeout,
    });
    dim.notifyReady('threat_data');
    dim.notifyReady('envelope');
    t.run(10000);
    assert.strictEqual(stales, 0);
});


// ── duplicate / re-entrant start ─────────────────────────────────────────

test('a second start cancels the previous session', () => {
    const t = makeFakeTimers();
    const dim = MapDim.create();
    let stalesA = 0, stalesB = 0, liftsB = 0;
    dim.start({
        scenarioName: 'A',
        stale: () => { stalesA += 1; },
        timeoutMs: 5000,
        _setTimeout: t.setTimeout, _clearTimeout: t.clearTimeout,
    });
    dim.start({
        scenarioName: 'B',
        stale: () => { stalesB += 1; },
        lift: () => { liftsB += 1; },
        timeoutMs: 5000,
        _setTimeout: t.setTimeout, _clearTimeout: t.clearTimeout,
    });
    t.run(10000);
    // Old session's stale should NOT fire (was cancelled).
    assert.strictEqual(stalesA, 0);
    // New session's stale SHOULD fire (timed out).
    assert.strictEqual(stalesB, 1);
    assert.strictEqual(liftsB, 0);
});


// ── required sources customisation ──────────────────────────────────────

test('custom requireSources is honoured for lift', () => {
    const dim = MapDim.create();
    let lifts = 0;
    dim.start({
        requireSources: ['only_one'],
        lift: () => { lifts += 1; },
        timeoutMs: 1000,
    });
    dim.notifyReady('only_one');
    assert.strictEqual(lifts, 1);
});

test('notifyReady ignores unknown sources', () => {
    const dim = MapDim.create();
    let lifts = 0;
    dim.start({
        requireSources: ['threat_data'],
        lift: () => { lifts += 1; },
        timeoutMs: 1000,
    });
    dim.notifyReady('something_else');
    assert.strictEqual(lifts, 0);
    assert.deepStrictEqual(dim.arrived(), []);
    dim.notifyReady('threat_data');
    assert.strictEqual(lifts, 1);
});


// ── force escape hatches ────────────────────────────────────────────────

test('forceLift settles immediately', () => {
    const dim = MapDim.create();
    let lifts = 0, stales = 0;
    dim.start({
        lift: () => { lifts += 1; }, stale: () => { stales += 1; },
        timeoutMs: 5000,
    });
    dim.forceLift();
    assert.strictEqual(lifts, 1);
    assert.strictEqual(stales, 0);
    assert.ok(!dim.isActive());
});

test('forceStale settles immediately', () => {
    const dim = MapDim.create();
    let lifts = 0, stales = 0;
    dim.start({
        lift: () => { lifts += 1; }, stale: () => { stales += 1; },
        timeoutMs: 5000,
    });
    dim.forceStale();
    assert.strictEqual(stales, 1);
    assert.strictEqual(lifts, 0);
});


// ── reset ───────────────────────────────────────────────────────────────

test('reset clears state without firing callbacks', () => {
    const dim = MapDim.create();
    let lifts = 0, stales = 0;
    dim.start({
        lift: () => { lifts += 1; }, stale: () => { stales += 1; },
        timeoutMs: 5000,
    });
    dim.reset();
    assert.strictEqual(lifts, 0);
    assert.strictEqual(stales, 0);
    assert.ok(!dim.isActive());
});


// ── singleton + introspection ───────────────────────────────────────────

test('default singleton is exposed', () => {
    assert.strictEqual(typeof MapDim.start, 'function');
    assert.strictEqual(typeof MapDim.notifyReady, 'function');
    assert.strictEqual(typeof MapDim.create, 'function');
    assert.strictEqual(MapDim.DEFAULT_TIMEOUT_MS, 8000);
    assert.deepStrictEqual(MapDim.DEFAULT_SOURCES, ['threat_data', 'envelope']);
});

test('arrived() reflects partial state', () => {
    const dim = MapDim.create();
    dim.start({ lift: () => {}, timeoutMs: 1000 });
    assert.deepStrictEqual(dim.arrived(), []);
    dim.notifyReady('threat_data');
    assert.deepStrictEqual(dim.arrived().sort(), ['threat_data']);
});

test('scenarioName() returns the start option', () => {
    const dim = MapDim.create();
    dim.start({ scenarioName: 'korean_peninsula', lift: () => {}, timeoutMs: 1000 });
    assert.strictEqual(dim.scenarioName(), 'korean_peninsula');
});

test('callbacks that throw do not blow up the state machine', () => {
    const dim = MapDim.create();
    dim.start({
        lift: () => { throw new Error('boom'); },
        timeoutMs: 1000,
    });
    dim.notifyReady('threat_data');
    dim.notifyReady('envelope');  // should not propagate the throw
    assert.ok(!dim.isActive());
});


// ── Two-phase model (Phase 4 commit 4) ──────────────────────────────────

test('two-phase: lift fires when liftSources arrived, done waits for the rest', () => {
    const dim = MapDim.create();
    let lifts = 0, dones = 0, stales = 0;
    dim.start({
        liftSources: ['envelope'],
        requireSources: ['envelope', 'threat_data'],
        lift: () => { lifts += 1; },
        done: () => { dones += 1; },
        stale: () => { stales += 1; },
        timeoutMs: 5000,
    });
    // Envelope arrives — Phase 1 fires.
    dim.notifyReady('envelope');
    assert.strictEqual(lifts, 1);
    assert.strictEqual(dones, 0);
    assert.ok(dim.isLifted());
    assert.ok(dim.isActive(), 'session stays active in REFRESHING window');
    // Threat data arrives — Phase 2 fires.
    dim.notifyReady('threat_data');
    assert.strictEqual(lifts, 1);
    assert.strictEqual(dones, 1);
    assert.strictEqual(stales, 0);
    assert.ok(!dim.isActive());
});

test('two-phase: stale only fires when timeout hits before Phase 1', () => {
    const dim = MapDim.create();
    let stales = 0, lifts = 0;
    let scheduled = null;
    const fakeST = (fn) => { scheduled = fn; return 1; };
    const fakeCT = () => { scheduled = null; };
    dim.start({
        liftSources: ['envelope'],
        requireSources: ['envelope', 'threat_data'],
        lift: () => { lifts += 1; },
        stale: () => { stales += 1; },
        timeoutMs: 1000,
        _setTimeout: fakeST,
        _clearTimeout: fakeCT,
    });
    // Phase 1 lifts first.
    dim.notifyReady('envelope');
    // Now fire the timeout — must NOT mark stale because lift already happened.
    if (scheduled) scheduled();
    assert.strictEqual(stales, 0);
    assert.strictEqual(lifts, 1);
});

test('two-phase: stale fires when timeout beats the envelope', () => {
    const dim = MapDim.create();
    let stales = 0, lifts = 0;
    let scheduled = null;
    const fakeST = (fn) => { scheduled = fn; return 1; };
    const fakeCT = () => { scheduled = null; };
    dim.start({
        liftSources: ['envelope'],
        requireSources: ['envelope', 'threat_data'],
        lift: () => { lifts += 1; },
        stale: () => { stales += 1; },
        timeoutMs: 1000,
        _setTimeout: fakeST,
        _clearTimeout: fakeCT,
    });
    if (scheduled) scheduled();
    assert.strictEqual(stales, 1);
    assert.strictEqual(lifts, 0);
    assert.ok(!dim.isActive());
});

test('two-phase: forceDone implicitly fires lift first', () => {
    const dim = MapDim.create();
    let lifts = 0, dones = 0;
    dim.start({
        liftSources: ['envelope'],
        requireSources: ['envelope', 'threat_data'],
        lift: () => { lifts += 1; },
        done: () => { dones += 1; },
        timeoutMs: 5000,
    });
    dim.forceDone();
    assert.strictEqual(lifts, 1);
    assert.strictEqual(dones, 1);
    assert.ok(!dim.isActive());
});

test('two-phase: notifyReady on a slow source after Phase 1 still triggers Phase 2', () => {
    const dim = MapDim.create();
    let dones = 0;
    dim.start({
        liftSources: ['envelope'],
        requireSources: ['envelope', 'threat_data'],
        lift: () => {},
        done: () => { dones += 1; },
        timeoutMs: 5000,
    });
    dim.notifyReady('envelope');
    dim.notifyReady('threat_data');
    assert.strictEqual(dones, 1);
});

test('liftRequired() exposes the configured trigger set', () => {
    const dim = MapDim.create();
    dim.start({
        liftSources: ['envelope'],
        requireSources: ['envelope', 'threat_data'],
        lift: () => {},
        timeoutMs: 1000,
    });
    assert.deepStrictEqual(dim.liftRequired(), ['envelope']);
    assert.deepStrictEqual(dim.required().sort(), ['envelope', 'threat_data']);
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
