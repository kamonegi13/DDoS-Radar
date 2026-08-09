/**
 * Unit tests for v3/ui/display_mode.js — the lane's three display modes.
 *
 * Run:  node tests/ui_v3/test_display_mode.js
 *
 * The load-bearing ones:
 *   - a server-set critical marker reaches the banner past everything,
 *     including a suppressed row (S1-UI-031 + S1-UI-032);
 *   - an unloaded lane is NOT dormant (G-17: "nobody asked" and "nothing is
 *     happening" are different claims and must not draw the same picture);
 *   - stepping DOWN takes several consecutive quiet evaluations while
 *     stepping UP takes one (NP1's asymmetry, which is what the v1 score
 *     bands were spelling);
 *   - no threshold on any scoring quantity is consulted at all.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const M = require('../../v3/ui/display_mode');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

function lane(overrides) {
    return Object.assign({
        rows: [], suppressed: [], total: 0, empty: true,
        emptyReason: 'no_ranked_items',
    }, overrides || {});
}

function row(overrides) {
    return Object.assign({ itemId: 'c-1', threatLevel: 4 }, overrides || {});
}

// ── critical (S1-UI-031) ─────────────────────────────────────────────────

test('an explicit critical flag reaches the banner', () => {
    const d = M.evaluate({ lane: lane({ rows: [row({ critical: true })] }) });
    assert.strictEqual(d.mode, M.CRITICAL_BANNER);
    assert.strictEqual(d.reasonKey, 'ui.mode.reason.flagged');
    assert.strictEqual(d.criticalItemId, 'c-1');
});

test('every declared critical flag is honoured', () => {
    M.CRITICAL_FLAGS.forEach((flag) => {
        const r = row({});
        r[flag] = true;
        const d = M.evaluate({ lane: lane({ rows: [r] }) });
        assert.strictEqual(d.mode, M.CRITICAL_BANNER, flag);
    });
});

test('a flag carried in the flags array counts too', () => {
    const d = M.evaluate({
        lane: lane({ rows: [row({ flags: ['kill_switch'] })] }) });
    assert.strictEqual(d.mode, M.CRITICAL_BANNER);
});

test('the top TL band raises the banner with no flag at all', () => {
    const d = M.evaluate({ lane: lane({ rows: [row({ threatLevel: 1 })] }) });
    assert.strictEqual(d.mode, M.CRITICAL_BANNER);
    assert.strictEqual(d.reasonKey, 'ui.mode.reason.top_band');
});

test('TL5 is the calm end of the scale and raises nothing', () => {
    // DEFCON-style: TL1 is worst. Reading it the other way round is the
    // 2026-08-02 calibration inversion, and this is the display-side guard.
    const d = M.evaluate({ lane: lane({ rows: [row({ threatLevel: 5 })] }) });
    assert.strictEqual(d.mode, M.PIN_DOCK);
});

test('a snake-case threat_level from a raw payload is read too', () => {
    const d = M.evaluate({
        lane: lane({ rows: [{ item_id: 'x', threat_level: 1 }] }) });
    assert.strictEqual(d.mode, M.CRITICAL_BANNER);
    assert.strictEqual(d.criticalItemId, 'x');
});

// ── suppression cannot mute (S1-UI-032) ──────────────────────────────────

test('a suppressed critical row still raises the banner', () => {
    const d = M.evaluate({
        lane: lane({ rows: [], suppressed: [row({ critical: true })] }) });
    assert.strictEqual(d.mode, M.CRITICAL_BANNER);
});

test('suppressed non-critical rows do not hold the surface open', () => {
    const d = M.evaluate({ lane: lane({ suppressed: [row()] }) });
    assert.strictEqual(d.mode, M.DORMANT);
});

// ── G-17: unloaded is not quiet ──────────────────────────────────────────

test('a lane that has not been fetched is not dormant', () => {
    const d = M.evaluate({ lane: null });
    assert.strictEqual(d.mode, M.PIN_DOCK);
    assert.strictEqual(d.reasonKey, 'ui.mode.reason.not_loaded');
});

test('an empty lane with no server reason says so distinctly', () => {
    const d = M.evaluate({
        lane: lane({ emptyReason: null, total: 0 }), previous: M.DORMANT });
    assert.strictEqual(d.mode, M.DORMANT);
    assert.strictEqual(d.reasonKey, 'ui.mode.reason.quiet_unexplained');
});

// ── hysteresis in cycles, not in score ───────────────────────────────────

test('one ranked row lifts the surface in a single evaluation', () => {
    const d = M.evaluate({ lane: lane({ rows: [row()] }), previous: M.DORMANT });
    assert.strictEqual(d.mode, M.PIN_DOCK);
    assert.strictEqual(d.quietCycles, 0);
});

test('stepping down takes the declared number of quiet evaluations', () => {
    let mode = M.PIN_DOCK;
    let quiet = 0;
    const seen = [];
    for (let i = 0; i < M.QUIET_CYCLES_TO_STEP_DOWN; i += 1) {
        const d = M.evaluate({ lane: lane(), previous: mode, quietCycles: quiet });
        mode = d.mode;
        quiet = d.quietCycles;
        seen.push(d.mode);
    }
    assert.deepStrictEqual(
        seen.slice(0, M.QUIET_CYCLES_TO_STEP_DOWN - 1)
            .every((m) => m === M.PIN_DOCK), true);
    assert.strictEqual(seen[seen.length - 1], M.DORMANT);
});

test('a critical banner steps down to pin-dock first, never straight to dormant', () => {
    const d = M.evaluate({ lane: lane(), previous: M.CRITICAL_BANNER,
                           quietCycles: 0 });
    assert.strictEqual(d.mode, M.PIN_DOCK);
});

test('a row arriving mid-descent resets the quiet counter', () => {
    const held = M.evaluate({ lane: lane(), previous: M.PIN_DOCK, quietCycles: 1 });
    assert.strictEqual(held.quietCycles, 2);
    const back = M.evaluate({ lane: lane({ rows: [row()] }),
                              previous: held.mode, quietCycles: held.quietCycles });
    assert.strictEqual(back.quietCycles, 0);
});

test('the step-down width is configurable and honoured', () => {
    const d = M.evaluate({ lane: lane(), previous: M.PIN_DOCK,
                           quietCycles: 0, quietCyclesToStepDown: 1 });
    assert.strictEqual(d.mode, M.DORMANT);
});

// ── the pin is a floor, not a ceiling (S1-UI-034) ────────────────────────

test('always-visible lifts dormant to pin-dock', () => {
    const d = M.evaluate({ lane: lane(), previous: M.DORMANT,
                           quietCycles: 9, alwaysVisible: true });
    assert.strictEqual(d.mode, M.PIN_DOCK);
    assert.strictEqual(d.flooredByPin, true);
    assert.strictEqual(d.reasonKey, 'ui.mode.reason.pinned');
});

test('always-visible cannot hold a critical banner down', () => {
    const d = M.evaluate({ lane: lane({ rows: [row({ critical: true })] }),
                           alwaysVisible: true });
    assert.strictEqual(d.mode, M.CRITICAL_BANNER);
    assert.strictEqual(d.flooredByPin, false);
});

// ── NP6: the reason is always there ──────────────────────────────────────

test('every decision carries a reason key', () => {
    const cases = [
        { lane: null },
        { lane: lane() },
        { lane: lane({ rows: [row()] }) },
        { lane: lane({ rows: [row({ critical: true })] }) },
        { lane: lane(), previous: M.PIN_DOCK },
        { lane: lane(), alwaysVisible: true },
    ];
    cases.forEach((input) => {
        const d = M.evaluate(input);
        assert.ok(typeof d.reasonKey === 'string' && d.reasonKey.length > 0);
        assert.ok(M.MODES.indexOf(d.mode) !== -1);
    });
});

test('an unknown previous mode is ignored rather than propagated', () => {
    const d = M.evaluate({ lane: lane({ rows: [row()] }), previous: 'banner' });
    assert.strictEqual(d.previous, null);
    assert.strictEqual(d.changed, true);
});

// ── the module holds no score threshold ──────────────────────────────────

test('no v1 display band survives as a literal', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'v3', 'ui', 'display_mode.js'), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    // v1's four bands. Two of them collide with live backend thresholds,
    // which is the second reason they are not here.
    ['0.40', '0.50', '0.85', '0.78'].forEach((band) => {
        assert.strictEqual(code.indexOf(band), -1, band);
    });
});

test('score is never read, let alone compared', () => {
    const withScore = M.evaluate({
        lane: lane({ rows: [row({ score: 0.99 })] }) });
    const withoutScore = M.evaluate({ lane: lane({ rows: [row()] }) });
    assert.strictEqual(withScore.mode, withoutScore.mode);
    assert.strictEqual(withScore.reasonKey, withoutScore.reasonKey);
});

test('evaluate does not mutate its input', () => {
    const input = { lane: lane({ rows: [row()] }), previous: M.DORMANT };
    const before = JSON.stringify(input);
    M.evaluate(input);
    assert.strictEqual(JSON.stringify(input), before);
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
