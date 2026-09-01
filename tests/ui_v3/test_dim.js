/**
 * Unit tests for v3/ui/dim.js — the two-phase focus-change dim.
 *
 * Run:  node tests/ui_v3/test_dim.js
 *
 * The load-bearing ones:
 *   - a phase-1 timeout KEEPS the mask (S1-UI-049). Lifting it would show
 *     the previous scenario's numbers under the new scenario's name, which
 *     is worse than showing nothing;
 *   - once phase 1 is released the timeouts are disarmed, so a slow second
 *     leg is waited for rather than declared broken (S1-UI-048);
 *   - replay suppresses the machine entirely;
 *   - ENDED and STALE are different terminals, so "everything arrived" and
 *     "we stopped waiting" are distinguishable.
 */
'use strict';

const assert = require('assert');
const D = require('../../v3/ui/dim');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const T0 = 1000000;

// ── the happy path ───────────────────────────────────────────────────────

test('a fresh controller is idle and shows nothing', () => {
    const dim = D.createDim({});
    const v = dim.view();
    assert.strictEqual(v.phase, D.IDLE);
    assert.strictEqual(v.masked, false);
    assert.strictEqual(v.marker, false);
    assert.strictEqual(v.messageKey, null);
});

test('begin masks, conclusions release the mask, the ledger ends it', () => {
    const dim = D.createDim({});
    let v = dim.begin('taiwan', T0);
    assert.strictEqual(v.phase, D.DIMMED);
    assert.strictEqual(v.masked, true);
    assert.strictEqual(v.messageKey, 'ui.dim.loading');

    v = dim.arrived(D.LEG_CONCLUSIONS, T0 + 100);
    assert.strictEqual(v.phase, D.REFRESHING);
    assert.strictEqual(v.masked, false);
    assert.strictEqual(v.marker, true);

    v = dim.arrived(D.LEG_LEDGER, T0 + 200);
    assert.strictEqual(v.phase, D.ENDED);
    assert.strictEqual(v.marker, false);
});

test('the ledger arriving first does not end phase 1 early', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0);
    const v = dim.arrived(D.LEG_LEDGER, T0 + 10);
    assert.strictEqual(v.phase, D.DIMMED);
    assert.strictEqual(v.masked, true);
    const done = dim.arrived(D.LEG_CONCLUSIONS, T0 + 20);
    // Both legs are now in; phase 2 has nothing left to wait for.
    assert.strictEqual(done.phase, D.ENDED);
});

// ── phase 1 timeout (S1-UI-049) ──────────────────────────────────────────

test('the mask is KEPT when phase 1 overruns, and gains a sentence', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0);
    const v = dim.tick(T0 + dim.maskTimeoutMs);
    assert.strictEqual(v.phase, D.DIMMED);
    assert.strictEqual(v.masked, true, 'a lifted mask reveals the wrong scenario');
    assert.strictEqual(v.timedOut, true);
    assert.strictEqual(v.messageKey, 'ui.dim.timed_out');
    assert.strictEqual(v.offersRetry, true);
    assert.strictEqual(v.offersEscape, true);
});

test('a late arrival clears the timeout warning', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0);
    dim.tick(T0 + dim.maskTimeoutMs);
    const v = dim.arrived(D.LEG_CONCLUSIONS, T0 + dim.maskTimeoutMs + 1);
    assert.strictEqual(v.timedOut, false);
    assert.strictEqual(v.phase, D.REFRESHING);
});

test('a keypress releases the mask and leaves the marker', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0);
    const v = dim.escape();
    assert.strictEqual(v.masked, false);
    assert.strictEqual(v.phase, D.REFRESHING);
    assert.strictEqual(v.escaped, true);
});

test('escaping when nothing is masked does nothing', () => {
    const dim = D.createDim({});
    const v = dim.escape();
    assert.strictEqual(v.phase, D.IDLE);
});

// ── timeouts are disarmed after phase 1 (S1-UI-048) ──────────────────────

test('the mask timeout cannot fire once the mask is gone', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0);
    dim.arrived(D.LEG_CONCLUSIONS, T0 + 1);
    const v = dim.tick(T0 + dim.maskTimeoutMs + 1);
    assert.strictEqual(v.timedOut, false);
    assert.strictEqual(v.phase, D.REFRESHING);
});

test('phase 2 terminates in STALE, which is not ENDED', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0);
    dim.arrived(D.LEG_CONCLUSIONS, T0 + 1);
    const v = dim.tick(T0 + dim.markerTimeoutMs);
    assert.strictEqual(v.phase, D.STALE);
    assert.notStrictEqual(v.phase, D.ENDED);
    assert.strictEqual(v.messageKey, 'ui.dim.stale');
});

test('a terminal state ignores further arrivals', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0);
    dim.arrived(D.LEG_CONCLUSIONS, T0 + 1);
    dim.arrived(D.LEG_LEDGER, T0 + 2);
    const v = dim.arrived(D.LEG_CONCLUSIONS, T0 + 3);
    assert.strictEqual(v.phase, D.ENDED);
});

// ── replay (S1-UI-049) ───────────────────────────────────────────────────

test('replay suppresses the machine entirely', () => {
    const dim = D.createDim({});
    const v = dim.begin('taiwan', T0, { replay: true });
    assert.strictEqual(v.phase, D.IDLE);
    assert.strictEqual(v.masked, false);
    assert.strictEqual(v.suppressedReason, 'replay');
    assert.strictEqual(v.messageKey, 'ui.dim.suppressed');
});

test('a suppressed machine ignores ticks and arrivals', () => {
    const dim = D.createDim({});
    dim.begin('taiwan', T0, { replay: true });
    assert.strictEqual(dim.tick(T0 + 999999).phase, D.IDLE);
    assert.strictEqual(dim.arrived(D.LEG_CONCLUSIONS, T0).phase, D.IDLE);
});

// ── configuration and hygiene ────────────────────────────────────────────

test('the two widths are configurable and independent', () => {
    const dim = D.createDim({ maskTimeoutMs: 5, markerTimeoutMs: 7 });
    assert.strictEqual(dim.maskTimeoutMs, 5);
    assert.strictEqual(dim.markerTimeoutMs, 7);
    dim.begin('x', 0);
    assert.strictEqual(dim.tick(5).timedOut, true);
});

test('a nonsense width falls back to the declared default', () => {
    const dim = D.createDim({ maskTimeoutMs: -1, markerTimeoutMs: 'soon' });
    assert.strictEqual(dim.maskTimeoutMs, D.MASK_TIMEOUT_MS);
    assert.strictEqual(dim.markerTimeoutMs, D.MARKER_TIMEOUT_MS);
});

test('a tick before any begin is inert', () => {
    const dim = D.createDim({});
    assert.strictEqual(dim.tick(T0).phase, D.IDLE);
});

test('beginning again resets the legs', () => {
    const dim = D.createDim({});
    dim.begin('a', T0);
    dim.arrived(D.LEG_CONCLUSIONS, T0 + 1);
    const v = dim.begin('b', T0 + 2);
    assert.strictEqual(v.phase, D.DIMMED);
    assert.strictEqual(v.legs.conclusions, false);
    assert.strictEqual(v.scenarioId, 'b');
});

test('the view is a snapshot, not the machine', () => {
    const dim = D.createDim({});
    const v = dim.begin('a', T0);
    v.phase = 'tampered';
    assert.strictEqual(dim.view().phase, D.DIMMED);
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
