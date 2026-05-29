/**
 * Unit tests for self_explanation.js — deterministic narrative generator (AP2).
 *
 * Run:   node tests/test_self_explanation.js
 * Exit code 0 = green, 1 = at least one failure.
 *
 * Pins the contract: same conclusion → same narrative every time, no RNG,
 * no LLM, output bounded.
 */
'use strict';

const assert = require('assert');
const { narrateTL, narrateDomain } = require('../self_explanation');

let passed = 0, failed = 0;
const failures = [];
function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1_800_000_000;

// ── narrateTL ─────────────────────────────────────────────────────────────

test('narrateTL handles null conclusion gracefully', () => {
    const out = narrateTL(null);
    assert.ok(/No threat_level/.test(out));
});

test('narrateTL surfaces unavailable_reason when present', () => {
    const c = {
        state: null,
        confidence: 0,
        conclusion_unavailable_reason: 'insufficient_data',
        metadata: { reason_detail: 'derive_tl returned None' },
    };
    const out = narrateTL(c);
    assert.ok(/unavailable/.test(out));
    assert.ok(/insufficient_data/.test(out));
    assert.ok(/derive_tl/.test(out));
    assert.ok(/Tool conclusion/.test(out));
});

test('narrateTL renders TL number, score, conf, active domains', () => {
    const c = {
        state: 3,
        confidence: 0.62,
        conclusion_unavailable_reason: null,
        metadata: {
            score: 4.2,
            active_domain_count: 2,
            convergence_bonus: 0.5,
        },
        threshold_ref: { tl1: 9, tl2: 6, tl3: 4, tl4: 2 },
    };
    const out = narrateTL(c, { now: NOW });
    assert.ok(/Threat Level: 3/.test(out));
    assert.ok(/score 4\.20/.test(out));
    assert.ok(/active domains 2/.test(out));
    assert.ok(/conf 0\.62/.test(out));
    assert.ok(/convergence \+0\.50/.test(out));
});

test('narrateTL classifies which TL floors are crossed', () => {
    const c = {
        state: 2,
        confidence: 0.7,
        conclusion_unavailable_reason: null,
        metadata: { score: 6.5 },
        threshold_ref: { tl1: 9, tl2: 6, tl3: 4, tl4: 2 },
    };
    const out = narrateTL(c, { now: NOW });
    assert.ok(/Crossed:.*TL2/.test(out));
    assert.ok(/Next:.*TL1/.test(out));
});

test('narrateTL includes calibration when present', () => {
    const c = {
        state: 4,
        confidence: 0.5,
        conclusion_unavailable_reason: null,
        metadata: { score: 2.5 },
        threshold_ref: {},
        calibration_status: { sample_size: 12, status: 'tentative', recall: 0.83 },
    };
    const out = narrateTL(c, { now: NOW });
    assert.ok(/Calibration:.*tentative.*n=12.*recall=0\.83/.test(out));
});

test('narrateTL renders last analyst view age', () => {
    const c = {
        state: 5,
        confidence: 0.3,
        conclusion_unavailable_reason: null,
        metadata: {},
        threshold_ref: {},
    };
    const out = narrateTL(c, { now: NOW, lastViewTs: NOW - 7200 });
    assert.ok(/Last analyst view: 2\.0h ago/.test(out));
});

test('narrateTL is deterministic (same input → same output)', () => {
    const c = {
        state: 3,
        confidence: 0.5,
        conclusion_unavailable_reason: null,
        metadata: { score: 4.0, active_domain_count: 2 },
        threshold_ref: { tl3: 4, tl2: 6 },
    };
    const a = narrateTL(c, { now: NOW });
    const b = narrateTL(c, { now: NOW });
    assert.strictEqual(a, b);
});

test('narrateTL output stays compact (≤ 16 lines)', () => {
    const c = {
        state: 1,
        confidence: 0.95,
        conclusion_unavailable_reason: null,
        metadata: {
            score: 11, active_domain_count: 3, convergence_bonus: 1.5,
        },
        threshold_ref: { tl1: 9, tl2: 6, tl3: 4, tl4: 2 },
        calibration_status: { sample_size: 100, status: 'calibrated', recall: 0.91 },
    };
    const out = narrateTL(c, { now: NOW, lastViewTs: NOW - 1800 });
    // Bumped from 12 → 16 in ADR-V2-016 to accommodate the
    // "What would change this" falsification block.
    assert.ok(out.split('\n').length <= 16, 'too many narrative lines: ' + out.split('\n').length);
});

// ── ADR-V2-016 Falsification block ─────────────────────────────────────────

test('narrateTL renders falsification block when metadata present', () => {
    const c = {
        state: 3,
        confidence: 0.5,
        metadata: {
            score: 4.5, active_domain_count: 1, physical_score: 0,
            falsification: {
                threshold_distance: {
                    to_higher_tl: {
                        target_tl: 2,
                        all_satisfied: false,
                        conditions: [
                            { field: 'score', current: 4.5, target: 6.0, gap: 1.5 },
                            { field: 'active_domain_count', current: 1, target: 2, gap: 1 },
                        ],
                    },
                    to_lower_tl: {
                        target_tl: 4,
                        conditions: [
                            { field: 'score', current: 4.5, trigger_below: 4.0, gap: 0.5 },
                        ],
                    },
                },
                signal_sensitivity: [
                    {
                        sensor: 'ct_log', domain: 'cyber',
                        current_contribution: 1.4,
                        hypothetical_tl_if_drops_to_zero: 4,
                        moves_tl_by: 1,
                    },
                ],
            },
        },
    };
    const out = narrateTL(c, { now: NOW });
    assert.ok(/What would change this:/.test(out), 'header missing');
    assert.ok(/Rise to TL2/.test(out), 'rise-to-higher missing');
    assert.ok(/Drop to TL4/.test(out), 'drop-to-lower missing');
    assert.ok(/ct_log/.test(out), 'top signal sensitivity missing');
});

test('narrateTL omits falsification when opts.includeFalsification=false', () => {
    const c = {
        state: 3, confidence: 0.5,
        metadata: {
            score: 4.5,
            falsification: {
                threshold_distance: { to_higher_tl: { target_tl: 2, conditions: [] } },
                signal_sensitivity: [],
            },
        },
    };
    const out = narrateTL(c, { now: NOW, includeFalsification: false });
    assert.ok(!/What would change this/.test(out));
});

test('narrateTL surfaces "Already at TL1" when no higher rung exists', () => {
    const c = {
        state: 1,
        metadata: {
            score: 12, active_domain_count: 3,
            falsification: {
                threshold_distance: {
                    to_higher_tl: { target_tl: null, conditions: [], all_satisfied: false },
                    to_lower_tl: {
                        target_tl: 2,
                        conditions: [
                            { field: 'physical_score', current: 4.0, trigger_below: 3.0, gap: 1.0 },
                        ],
                    },
                },
                signal_sensitivity: [],
            },
        },
    };
    const out = narrateTL(c, { now: NOW });
    assert.ok(/Already at TL1/.test(out));
    assert.ok(/Drop to TL2/.test(out));
});

test('narrateTL skips falsification block when metadata.falsification is empty {}', () => {
    const c = {
        state: 3, confidence: 0.5,
        metadata: { score: 4.5, falsification: {} },
    };
    const out = narrateTL(c, { now: NOW });
    assert.ok(!/What would change this/.test(out));
});

// ── narrateDomain ─────────────────────────────────────────────────────────

test('narrateDomain handles null/empty', () => {
    assert.ok(/No per_domain/.test(narrateDomain(null, 'cyber')));
    assert.ok(/No per_domain/.test(narrateDomain({}, '')));
});

test('narrateDomain surfaces unavailable_reason', () => {
    const c = { conclusion_unavailable_reason: 'insufficient_data' };
    const out = narrateDomain(c, 'cyber');
    assert.ok(/CYBER: unavailable/.test(out));
});

test('narrateDomain parses kv state and includes score', () => {
    const c = {
        state: 'cyber=STABLE;physical=ACTIVE;info=INSUFFICIENT_SIGNAL',
        conclusion_unavailable_reason: null,
        metadata: { domain_scores: { cyber: 1.2, physical: 3.5, info: 0.0 } },
        threshold_ref: { elevated_floor: 1.5, active_floor: 2.5 },
    };
    const cyberOut = narrateDomain(c, 'cyber');
    assert.ok(/CYBER: STABLE \(1\.20\)/.test(cyberOut));
    assert.ok(/Below ELEVATED floor \(1\.50\)/.test(cyberOut));

    const physOut = narrateDomain(c, 'physical');
    assert.ok(/PHYSICAL: ACTIVE \(3\.50\)/.test(physOut));
    assert.ok(/At\/above ACTIVE/.test(physOut));
});

test('narrateDomain falls back to INSUFFICIENT_SIGNAL when domain absent in state', () => {
    const c = {
        state: 'cyber=ACTIVE',
        conclusion_unavailable_reason: null,
        metadata: { domain_scores: { cyber: 3 } },
        threshold_ref: {},
    };
    const out = narrateDomain(c, 'info');
    assert.ok(/INFO: INSUFFICIENT_SIGNAL/.test(out));
});

test('narrateDomain lists top 2 contributing signals from rationale_matrix', () => {
    const c = {
        state: 'cyber=ACTIVE',
        conclusion_unavailable_reason: null,
        metadata: {
            domain_scores: { cyber: 3.0 },
            rationale_matrix: [
                { sensor: 'apt_intel', domain: 'cyber', final_contribution: 1.5 },
                { sensor: 'bgp_anomaly', domain: 'cyber', final_contribution: 1.0 },
                { sensor: 'ct_log', domain: 'cyber', final_contribution: 0.5 },
                { sensor: 'firms', domain: 'physical', final_contribution: 0.8 },
            ],
        },
        threshold_ref: { elevated_floor: 1.5, active_floor: 2.5 },
    };
    const out = narrateDomain(c, 'cyber');
    assert.ok(/Top contributors/.test(out));
    assert.ok(/apt_intel 1\.50/.test(out));
    assert.ok(/bgp_anomaly 1\.00/.test(out));
    assert.ok(!/ct_log/.test(out), 'should cap at 2 contributors');
    assert.ok(!/firms/.test(out), 'should not include other domains');
});

test('narrateDomain is deterministic', () => {
    const c = {
        state: 'cyber=STABLE',
        conclusion_unavailable_reason: null,
        metadata: { domain_scores: { cyber: 1.0 } },
        threshold_ref: { elevated_floor: 1.5 },
    };
    assert.strictEqual(narrateDomain(c, 'cyber'), narrateDomain(c, 'cyber'));
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
