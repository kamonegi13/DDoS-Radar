/**
 * The behavioural half of the G-09 gate.
 *
 * Run:  node tests/ui_v3/test_no_derivation.js
 *
 * `tests/test_v3_ui_discipline.py` checks that no backend constant or
 * ladder name appears in `v3/ui/`. That is a syntactic gate, and a
 * determined re-implementation could evade it by writing the numbers
 * differently. This file closes that off from the other side: it feeds the
 * view models projections in which the server's threat level DELIBERATELY
 * contradicts the score that would produce it, and requires the screen to
 * show the server's answer.
 *
 * The contradictions are chosen against the real ladder
 * (`v3/scoring/thresholds.py`: TL1 ≥ 9.0, TL2 ≥ 6.0, TL3 ≥ 4.0, TL4 ≥ 2.0),
 * so any ladder in the browser — in any syntax, under any constant name —
 * produces a different answer and fails here.
 *
 * It also pins the direction of the DEFCON scale, because an inverted
 * comparison is the specific mistake that broke calibration on 2026-08-02
 * and would be invisible in a screenshot.
 */
'use strict';

const assert = require('assert');
const B = require('../../v3/ui/board');
const C = require('../../v3/ui/conclusions');
const F = require('../../v3/ui/format');
const L = require('../../v3/ui/lane');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;

// A score of 99 is far above the backend's TL1 floor (9.0). A frontend
// ladder would call this TL1. The server says TL5.
const CALM_TL_WITH_SCREAMING_SCORE = {
    scenario_id: 'contradiction', participants: {}, adversaries: [], roles: {},
    threat_level: 5, threat_level_24h_ago: 5, severity_delta_24h: 0,
    observed_at: NOW, score: 99.0, scoring_mode: 'full',
    in_null_zone: false, never_observed: false,
};

// ...and the mirror image: a score of 0 with the server reporting TL1.
const CRITICAL_TL_WITH_ZERO_SCORE = Object.assign({}, CALM_TL_WITH_SCREAMING_SCORE, {
    scenario_id: 'contradiction2', threat_level: 1, score: 0.0,
});

test('the board shows the server TL even when the score contradicts it', () => {
    const board = B.buildBoard({
        scenarios: {
            scenarios: [CALM_TL_WITH_SCREAMING_SCORE],
            focused_scenario: 'contradiction', focus_source: 'command_log',
        },
    });
    assert.strictEqual(board.cards[0].tl.tl, 5,
        'a ladder would have derived TL1 from score 99');
    assert.strictEqual(board.cards[0].tl.band, 'normal');
    assert.strictEqual(board.cards[0].score, 99.0, 'the score is still shown');
});

test('the board shows TL1 for a zero score when the server says TL1', () => {
    const board = B.buildBoard({
        scenarios: {
            scenarios: [CRITICAL_TL_WITH_ZERO_SCORE],
            focused_scenario: 'contradiction2', focus_source: 'command_log',
        },
    });
    assert.strictEqual(board.cards[0].tl.tl, 1);
    assert.strictEqual(board.cards[0].tl.band, 'critical');
});

test('the conclusion face shows the server TL, not one derived from metadata', () => {
    const face = C.buildFace({
        conclusions: {
            scenario_id: 'contradiction',
            conclusions: [{
                id: 'c-1', conclusion_type: 'threat_level', state: '5',
                confidence: 0.9, observed_at: NOW,
                conclusion_unavailable_reason: null,
                metadata: { score: 99.0, cyber: 40.0, physical: 40.0, info: 19.0 },
                calibration_status: {}, source_urls: [], suppression: null,
            }],
            projection: { at: NOW, types_present: ['threat_level'],
                          types_missing: [], unreadable_rows: [],
                          unavailable_reasons: [] },
        },
    });
    assert.strictEqual(face.sections[0].rows[0].tl.tl, 5);
});

test('what-if reports the server TLs even when they contradict the scores', () => {
    // Baseline: score 0.1 but the server says TL1.
    // Counterfactual: score 50 but the server says TL5.
    // A browser-side ladder would report exactly the opposite movement.
    const diff = C.diffWhatIf({
        baseline: { settings: {}, scenarios: { s: {
            tl: 1, score: 0.1, domains: { cyber: 0.0, physical: 0.0, info: 0.1 } } } },
        counterfactual: { settings: {}, scenarios: { s: {
            tl: 5, score: 50.0, domains: { cyber: 25.0, physical: 25.0, info: 0.0 } } } },
    });
    const s = diff.scenarios[0];
    assert.strictEqual(s.tl.baseline, 1);
    assert.strictEqual(s.tl.counterfactual, 5);
    // TL1 -> TL5 is severity 5 -> 1, i.e. a fall of 4.
    assert.strictEqual(s.tl.severityDelta, -4,
        'the diff must follow the server TLs, not re-derive from the scores');
    assert.strictEqual(s.score.delta, 49.9, 'the score delta is still reported');
});

test('what-if never invents a TL the server did not send', () => {
    const diff = C.diffWhatIf({
        baseline: { settings: {}, scenarios: { s: { score: 12.0, domains: {} } } },
        counterfactual: { settings: {}, scenarios: { s: { score: 0.0, domains: {} } } },
    });
    assert.strictEqual(diff.scenarios[0].tl.baseline, null,
        'no tl in the payload means no tl on screen');
    assert.strictEqual(diff.scenarios[0].tl.counterfactual, null);
    assert.strictEqual(diff.scenarios[0].tl.severityDelta, null);
});

test('the lane never re-ranks from the score, however wrong the order looks', () => {
    const lane = L.buildLane({
        attention: {
            attention: [
                { item_id: 'looks-urgent', rank_position: 5, score: 1.0,
                  novelty: 1, confidence_delta: 1, analyst_blindness: 1,
                  analyst_state: 'active', suppressed: false },
                { item_id: 'looks-dull', rank_position: 1, score: 0.0001,
                  novelty: 0, confidence_delta: 0, analyst_blindness: 0,
                  analyst_state: 'active', suppressed: false },
            ],
            snapshot_id: 's', computed_at: NOW, empty_reason: null,
        },
    });
    assert.deepStrictEqual(lane.rows.map(r => r.itemId), ['looks-dull', 'looks-urgent'],
        'the ledger decided the order; the browser does not second-guess it');
});

test('severity conversion runs in exactly one direction', () => {
    // If this ever inverts, every "worse/better" statement in the UI flips
    // and nothing else fails. Pinned here on purpose.
    assert.strictEqual(F.severityOf(1) - F.severityOf(5), 4);
    assert.ok(F.severityOf(1) > F.severityOf(5), 'TL1 must be the more severe');
});

test('a TL outside the served range is never rendered as a level', () => {
    // A ladder that clamped would produce TL5 here. A lookup produces
    // "unknown", which is what an out-of-range value actually means.
    [0, 6, 7, -1, 2.5].forEach(bad => {
        assert.strictEqual(F.tlBand(bad).tl, null, String(bad));
        assert.strictEqual(F.tlBand(bad).band, 'unknown', String(bad));
    });
});

test('no module exposes anything that scores, caps or bonuses', () => {
    [B, C, F, L].forEach(mod => {
        Object.keys(mod).forEach(key => {
            assert.ok(!/score(?!s\b)|cap|bonus|converge/i.test(key)
                      || /^(?:rankBasis|labelTally)$/.test(key),
                `exported symbol ${key} sounds like scoring`);
        });
    });
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
