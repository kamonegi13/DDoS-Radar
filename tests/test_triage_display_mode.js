/**
 * Unit tests for triage_display_mode.js — pure state machine that
 * picks dormant / pin-dock / critical-banner from the current
 * attention-score signals.
 *
 * Run:  node tests/test_triage_display_mode.js
 * Exit code 0 = all green, 1 = at least one failure.
 *
 * Mirrors the KISS pattern of test_triage_score.js / test_hud_v2_overlay.js.
 */
'use strict';

const assert = require('assert');
const {
    resolveMode, summarizeItems,
    DEFAULT_THRESHOLDS,
    MODE_DORMANT, MODE_PIN_DOCK, MODE_CRITICAL,
} = require('../triage_display_mode');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

// ── resolveMode — basic band selection ───────────────────────────────────

test('maxScore far below dormantEnter → dormant', () => {
    const r = resolveMode({ maxScore: 0.10 });
    assert.strictEqual(r.mode, MODE_DORMANT);
});

test('maxScore mid-band → pin-dock', () => {
    const r = resolveMode({ maxScore: 0.60 });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);
});

test('maxScore above criticalEnter → critical-banner', () => {
    const r = resolveMode({ maxScore: 0.92 });
    assert.strictEqual(r.mode, MODE_CRITICAL);
});

test('exactly at dormantEnter is in pin-dock band (>= semantics)', () => {
    // dormantEnter=0.40 → values >= 0.40 are NOT dormant from cold
    // (no prev). values < 0.40 are dormant.
    const r = resolveMode({ maxScore: 0.40 });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);
});

test('exactly at criticalEnter triggers critical mode', () => {
    const r = resolveMode({ maxScore: DEFAULT_THRESHOLDS.criticalEnter });
    assert.strictEqual(r.mode, MODE_CRITICAL);
});

test('zero score with no prev mode → dormant', () => {
    const r = resolveMode({ maxScore: 0 });
    assert.strictEqual(r.mode, MODE_DORMANT);
});

test('missing maxScore defaults to 0 (→ dormant)', () => {
    const r = resolveMode({});
    assert.strictEqual(r.mode, MODE_DORMANT);
});

// ── Explicit critical event ─────────────────────────────────────────────

test('hasCritical=true forces critical-banner regardless of low score', () => {
    const r = resolveMode({ maxScore: 0.05, hasCritical: true });
    assert.strictEqual(r.mode, MODE_CRITICAL);
    assert.match(r.reason, /explicit critical/);
});

test('hasCritical=true forces critical even with prevMode=dormant', () => {
    const r = resolveMode({ maxScore: 0, hasCritical: true, prevMode: MODE_DORMANT });
    assert.strictEqual(r.mode, MODE_CRITICAL);
});

// ── Hysteresis (sticky transitions) ─────────────────────────────────────

test('sticky critical: prev=critical, score in [exit, enter) stays critical', () => {
    // exit=0.78, enter=0.85. score=0.80 is between → keep critical.
    const r = resolveMode({
        maxScore: 0.80,
        prevMode: MODE_CRITICAL,
    });
    assert.strictEqual(r.mode, MODE_CRITICAL);
    assert.match(r.reason, /sticky critical/);
});

test('sticky critical: prev=critical, score < exit drops to pin-dock', () => {
    const r = resolveMode({
        maxScore: 0.70,
        prevMode: MODE_CRITICAL,
    });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);
});

test('sticky dormant: prev=dormant, score in [enter, exit) stays dormant', () => {
    // dormantEnter=0.40, dormantExit=0.50. prev=dormant + score=0.45 → keep dormant.
    const r = resolveMode({
        maxScore: 0.45,
        prevMode: MODE_DORMANT,
    });
    assert.strictEqual(r.mode, MODE_DORMANT);
    assert.match(r.reason, /sticky dormant/);
});

test('sticky dormant: prev=dormant, score >= dormantExit moves to pin-dock', () => {
    const r = resolveMode({
        maxScore: 0.55,
        prevMode: MODE_DORMANT,
    });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);
});

test('cold start (no prev): score=0.45 is in pin-dock (no sticky guard)', () => {
    const r = resolveMode({ maxScore: 0.45, prevMode: null });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);
});

test('hysteresis from pin-dock down: score below dormantEnter → dormant', () => {
    const r = resolveMode({ maxScore: 0.30, prevMode: MODE_PIN_DOCK });
    assert.strictEqual(r.mode, MODE_DORMANT);
});

test('hysteresis from pin-dock down: score in [dormantEnter, dormantExit) stays pin-dock', () => {
    // prev=pin-dock + score=0.42 → not dormant (sticky needs prev=dormant);
    // not critical (below criticalEnter). The default branch is pin-dock.
    const r = resolveMode({ maxScore: 0.42, prevMode: MODE_PIN_DOCK });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);
});

// ── alwaysVisible analyst override ──────────────────────────────────────

test('alwaysVisible=true suppresses dormant even with score=0', () => {
    const r = resolveMode({ maxScore: 0, alwaysVisible: true });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);
    assert.match(r.reason, /always-visible/);
});

test('alwaysVisible does not block critical-banner', () => {
    // alwaysVisible only blocks DORMANT — critical still wins.
    const r = resolveMode({ maxScore: 0.95, alwaysVisible: true });
    assert.strictEqual(r.mode, MODE_CRITICAL);
});

test('alwaysVisible does not block explicit critical event', () => {
    const r = resolveMode({ maxScore: 0, hasCritical: true, alwaysVisible: true });
    assert.strictEqual(r.mode, MODE_CRITICAL);
});

// ── Threshold overrides ─────────────────────────────────────────────────

test('per-user threshold override is honored', () => {
    const r = resolveMode({
        maxScore: 0.30,
        thresholds: { dormantEnter: 0.20, dormantExit: 0.25 },
    });
    assert.strictEqual(r.mode, MODE_PIN_DOCK);  // 0.30 > custom dormantEnter=0.20
});

test('inverted dormant thresholds get auto-corrected (not pathological)', () => {
    // User accidentally sets enter=0.50 / exit=0.40 (enter > exit).
    // Module swaps so enter=0.40, exit=0.50 — same hysteresis as default-ish.
    const r = resolveMode({
        maxScore: 0.45,
        prevMode: MODE_DORMANT,
        thresholds: { dormantEnter: 0.50, dormantExit: 0.40 },
    });
    // After swap: dormantEnter=0.40, dormantExit=0.50 → sticky dormant at 0.45.
    assert.strictEqual(r.mode, MODE_DORMANT);
});

test('inverted critical thresholds get auto-corrected', () => {
    const r = resolveMode({
        maxScore: 0.90,
        thresholds: { criticalEnter: 0.78, criticalExit: 0.85 },
    });
    // After swap: criticalEnter=0.85, criticalExit=0.78 → 0.90 ≥ 0.85 → critical.
    assert.strictEqual(r.mode, MODE_CRITICAL);
});

// ── Reason field shape ──────────────────────────────────────────────────

test('reason includes maxScore for debug', () => {
    const r = resolveMode({ maxScore: 0.65 });
    assert.ok(r.reason.includes('0.65') || r.reason.includes('pin-dock band'));
});

test('result carries thresholds back so caller can render them', () => {
    const r = resolveMode({ maxScore: 0.65 });
    assert.ok(r.thresholds);
    assert.strictEqual(r.thresholds.dormantEnter, 0.40);
    assert.strictEqual(r.thresholds.criticalEnter, 0.85);
});

// ── summarizeItems helper ───────────────────────────────────────────────

test('summarizeItems on empty list returns 0/false', () => {
    const s = summarizeItems([]);
    assert.strictEqual(s.maxScore, 0);
    assert.strictEqual(s.hasCritical, false);
});

test('summarizeItems on null returns 0/false', () => {
    const s = summarizeItems(null);
    assert.strictEqual(s.maxScore, 0);
});

test('summarizeItems picks the maximum score', () => {
    const s = summarizeItems([
        { score: 0.20 }, { score: 0.55 }, { score: 0.40 },
    ]);
    assert.strictEqual(s.maxScore, 0.55);
});

test('summarizeItems honors explicit criticalFlag', () => {
    const s = summarizeItems([
        { score: 0.10, criticalFlag: true },
    ]);
    assert.strictEqual(s.hasCritical, true);
});

test('summarizeItems heuristic: TL5 + scoreDelta>0 → hasCritical', () => {
    const s = summarizeItems([
        { score: 0.30, tl: 5, scoreDelta: 0.1 },
    ]);
    assert.strictEqual(s.hasCritical, true);
});

test('summarizeItems: TL5 with scoreDelta<=0 is NOT critical', () => {
    const s = summarizeItems([
        { score: 0.30, tl: 5, scoreDelta: -0.1 },
        { score: 0.30, tl: 5, scoreDelta: 0 },
    ]);
    assert.strictEqual(s.hasCritical, false);
});

test('summarizeItems: TL4 with high delta is NOT critical (only TL5 escalates)', () => {
    const s = summarizeItems([
        { score: 0.30, tl: 4, scoreDelta: 0.5 },
    ]);
    assert.strictEqual(s.hasCritical, false);
});

test('summarizeItems: NaN scores treated as 0', () => {
    const s = summarizeItems([
        { score: NaN }, { score: 0.20 }, { score: 'oops' },
    ]);
    assert.strictEqual(s.maxScore, 0.20);
});

// ── End-to-end pipeline: summarizeItems → resolveMode ───────────────────

test('full pipeline: 1 critical item among quiet ones forces banner', () => {
    const items = [
        { score: 0.10 },
        { score: 0.20, criticalFlag: true },
        { score: 0.05 },
    ];
    const summary = summarizeItems(items);
    const result = resolveMode({
        maxScore: summary.maxScore,
        hasCritical: summary.hasCritical,
    });
    assert.strictEqual(result.mode, MODE_CRITICAL);
});

test('full pipeline: all-quiet items → dormant', () => {
    const items = [{ score: 0.10 }, { score: 0.05 }, { score: 0.20 }];
    const summary = summarizeItems(items);
    const result = resolveMode({
        maxScore: summary.maxScore,
        hasCritical: summary.hasCritical,
    });
    assert.strictEqual(result.mode, MODE_DORMANT);
});

// ── Summary ─────────────────────────────────────────────────────────────

console.log('\n');
if (failed === 0) {
    console.log(`OK — ${passed} tests passed`);
    process.exit(0);
}
console.log(`FAIL — ${passed} passed, ${failed} failed`);
for (const f of failures) {
    console.log(`  ✗ ${f.name}`);
    console.log(`    ${f.error.message}`);
}
process.exit(1);
