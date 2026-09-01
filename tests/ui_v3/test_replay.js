/**
 * Unit tests for v3/ui/replay.js — the scrubber's arithmetic.
 *
 * Run:  node tests/ui_v3/test_replay.js
 *
 * Load-bearing: the right edge is LIVE (null), not "replay of now";
 * the window never exceeds R3's 90-day read cap; position<->instant
 * round-trips inside the window.
 */
'use strict';

const assert = require('assert');
const Replay = require('../../v3/ui/replay');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;

test('the default scale is seven days of 15-minute steps ending at now', () => {
    const scale = Replay.scaleFor(NOW);
    assert.strictEqual(scale.windowSec, 7 * 86400);
    assert.strictEqual(scale.steps, (7 * 86400) / 900);
    assert.strictEqual(scale.end, NOW);
    assert.strictEqual(scale.start, NOW - 7 * 86400);
});

test('the window is capped at the R3 read limit of 90 days', () => {
    const scale = Replay.scaleFor(NOW, 365 * 86400);
    assert.strictEqual(scale.windowSec, 90 * 86400,
        'a slider must not promise time travel the server refuses');
});

test('the right edge is live — null, not a replay of now', () => {
    const scale = Replay.scaleFor(NOW);
    assert.strictEqual(Replay.instantFor(scale, scale.steps), null);
    assert.strictEqual(Replay.instantFor(scale, scale.steps + 50), null);
});

test('position zero is the window start; interior positions round-trip', () => {
    const scale = Replay.scaleFor(NOW);
    assert.strictEqual(Replay.instantFor(scale, 0), scale.start);
    const mid = Math.floor(scale.steps / 2);
    const instant = Replay.instantFor(scale, mid);
    assert.strictEqual(Replay.positionFor(scale, instant), mid);
});

test('live maps back to the right edge, and out-of-window instants clamp', () => {
    const scale = Replay.scaleFor(NOW);
    assert.strictEqual(Replay.positionFor(scale, null), scale.steps);
    assert.strictEqual(Replay.positionFor(scale, scale.start - 999999), 0);
    assert.strictEqual(Replay.positionFor(scale, NOW + 999999), scale.steps);
});

test('garbage positions degrade to live rather than throwing', () => {
    const scale = Replay.scaleFor(NOW);
    assert.strictEqual(Replay.instantFor(scale, 'not-a-number'), null);
});

process.stdout.write('\n');
failures.forEach(({ name, error }) => {
    console.error(`FAIL ${name}\n  ${error.message}`);
});
console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
