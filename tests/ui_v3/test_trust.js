/**
 * Unit tests for v3/ui/trust.js — the AP3 composite confidence chip.
 *
 * Run:  node tests/ui_v3/test_trust.js
 *
 * P8 §4 replaces HUD Row 3's twelve parallel chips with ONE chip carrying a
 * min-fold (worst-component-wins) over the reliability components, because
 * "the analyst can judge in seconds how far to trust this tool" and twelve
 * chips are not a seconds-long read.
 *
 * The load-bearing properties tested here:
 *   1. the fold is worst-wins and NOTHING can raise it (NP1);
 *   2. a component that is missing or unmeasurable can never read as
 *      healthy — it lands on the middle band with a reason that says which
 *      of the two it was (the F-12 lesson: an enum value with nothing
 *      behind it is worse than no enum value);
 *   3. every boundary comes from the server (R7's own disclosures and R10's
 *      threshold registry). The frontend owns no threshold — that is P5
 *      O-13, and hardcoding one here would re-create it.
 */
'use strict';

const assert = require('assert');
const {
    foldTrust, TRUSTED, RESERVED, DISTRUST,
    COMPONENT_IDS, worstBand,
} = require('../../v3/ui/trust');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;

/** A self_eval payload in which every component is healthy. */
function healthySelfEval(overrides) {
    return Object.assign({
        calibration: {
            recall: 0.92, recall_error: null,
            drift: 0.01, drift_error: null,
            recall_meta: { window_days: 30, labels_total: 120 },
            drift_meta: { method: 'per_cell', worst_cell: null },
        },
        null_zone: {
            any_chronic: false,
            threshold_sec: 604800,
            scenarios: [{ scenario_id: 'taiwan_contingency', is_chronic: false, ongoing: false, longest_span_sec: 0 }],
        },
        data: {
            data_age_sec: 120, max_freshness_horizon_sec: 172800,
            signal_count: 5000, tl_count: 900, conclusion_count: 400,
        },
        sensors: { count: 21 },
        epoch: { epoch_id: 'e-1', window_sec: 2592000 },
        // NOTE: R7 does not serve this block today. It is present in this
        // fixture so the fold's healthy path is reachable and testable; the
        // `todays_server_*` tests below pin what happens without it.
        ops_health: { worst_band: 'trusted', failing_count: 0, worst_monitor: null },
    }, overrides || {});
}

/** R7 exactly as it is served today: no `ops_health` block. */
function todaysSelfEval() {
    const s = healthySelfEval();
    delete s.ops_health;
    return s;
}

/** R10's calibration disclosure, trimmed to the keys the fold reads. */
const THRESHOLDS = {
    calibration: {
        DEGRADED_RECALL_FLOOR: { value: 0.7, unit: 'ratio', provenance_ref: 'S1-CALIB-027' },
        DESIGN_W_MAX_DROP: { value: 0.05, unit: 'ratio', provenance_ref: 'S1-CALIB-029' },
        MIN_RECALL_DENOM: { value: 5.0, unit: 'count', provenance_ref: 'S1-CALIB-027' },
    },
};

function fold(selfEval, thresholds, extra) {
    return foldTrust(Object.assign({
        selfEval: selfEval, thresholds: thresholds, now: NOW,
    }, extra || {}));
}

function componentById(result, id) {
    const c = result.components.filter(x => x.id === id);
    assert.strictEqual(c.length, 1, `expected exactly one '${id}' component`);
    return c[0];
}

// ── the band lattice ─────────────────────────────────────────────────────

test('worstBand is worst-wins and total', () => {
    assert.strictEqual(worstBand([TRUSTED, TRUSTED]), TRUSTED);
    assert.strictEqual(worstBand([TRUSTED, RESERVED]), RESERVED);
    assert.strictEqual(worstBand([RESERVED, DISTRUST]), DISTRUST);
    assert.strictEqual(worstBand([DISTRUST, TRUSTED, RESERVED]), DISTRUST);
});

test('an empty component set cannot be TRUSTED', () => {
    assert.notStrictEqual(worstBand([]), TRUSTED);
});

// ── happy path ───────────────────────────────────────────────────────────

test('all components healthy folds to TRUSTED', () => {
    const r = fold(healthySelfEval(), THRESHOLDS);
    assert.strictEqual(r.band, TRUSTED, JSON.stringify(r.components, null, 1));
});

test('every declared component appears in the breakdown, always', () => {
    const r = fold(healthySelfEval(), THRESHOLDS);
    assert.deepStrictEqual(r.components.map(c => c.id).sort(),
        COMPONENT_IDS.slice().sort());
});

// ── worst-wins ───────────────────────────────────────────────────────────

test('one bad component drags the whole chip down (NP1)', () => {
    const bad = healthySelfEval();
    bad.calibration = Object.assign({}, bad.calibration, { recall: 0.4 });
    const r = fold(bad, THRESHOLDS);
    assert.strictEqual(r.band, DISTRUST);
    assert.strictEqual(componentById(r, 'recall').band, DISTRUST);
});

test('nothing can raise the fold above its worst component', () => {
    const bad = healthySelfEval();
    bad.null_zone = Object.assign({}, bad.null_zone, { any_chronic: true });
    const r = fold(bad, THRESHOLDS);
    assert.strictEqual(r.band, DISTRUST);
    // the other components are still individually healthy and still say so
    assert.strictEqual(componentById(r, 'recall').band, TRUSTED);
});

test('the reason slot names the worst component, in one word (P8 §4)', () => {
    const bad = healthySelfEval();
    bad.calibration = Object.assign({}, bad.calibration, { drift: 0.4 });
    const r = fold(bad, THRESHOLDS);
    assert.strictEqual(r.reason.componentId, 'drift');
    assert.ok(/^ui\.trust\.reason\./.test(r.reason.labelKey), r.reason.labelKey);
});

test('ties pick a deterministic worst component (AP2 reproducibility)', () => {
    const bad = healthySelfEval();
    bad.calibration = Object.assign({}, bad.calibration, { recall: 0.1, drift: 0.9 });
    const a = fold(bad, THRESHOLDS);
    const b = fold(JSON.parse(JSON.stringify(bad)), THRESHOLDS);
    assert.strictEqual(a.reason.componentId, b.reason.componentId);
    assert.strictEqual(a.reason.componentId, 'recall');  // declaration order
});

// ── missing / unmeasurable components ────────────────────────────────────

test('an unmeasurable component is RESERVED, never TRUSTED', () => {
    const s = healthySelfEval();
    s.calibration = Object.assign({}, s.calibration, {
        recall: null, recall_error: 'no ground truth labels in the window',
    });
    const r = fold(s, THRESHOLDS);
    const c = componentById(r, 'recall');
    assert.strictEqual(c.band, RESERVED);
    assert.strictEqual(c.state, 'unmeasurable');
    assert.strictEqual(c.detail, 'no ground truth labels in the window');
    assert.strictEqual(r.band, RESERVED);
});

test('a component the server does not supply at all is RESERVED and says so', () => {
    const r = fold(todaysSelfEval(), THRESHOLDS);
    // L5's five liveness monitors are named by P8 §4 but R7 does not serve
    // them yet. The chip must show that gap, not quietly fold four of five.
    const c = componentById(r, 'ops_health');
    assert.strictEqual(c.band, RESERVED);
    assert.strictEqual(c.state, 'unsupplied');
    assert.strictEqual(r.band, RESERVED);
});

test('todays_server: the chip cannot read TRUSTED while ops_health is unserved', () => {
    // This is not a defect in the fold — it is the fold reporting an
    // incomplete system accurately. Folding the four served components and
    // showing blue would be G-17: a verdict that looks complete because it
    // did not say what it was built from. The chip stays amber and names
    // the gap until R7 serves the L5 monitors.
    const r = fold(todaysSelfEval(), THRESHOLDS);
    assert.strictEqual(r.band, RESERVED);
    assert.strictEqual(r.reason.componentId, 'ops_health');
    assert.strictEqual(r.reason.state, 'unsupplied');
});

test('"unsupplied" and "unmeasurable" are different states (the F-12 lesson)', () => {
    const s = todaysSelfEval();
    s.calibration = Object.assign({}, s.calibration, { recall: null, recall_error: 'x' });
    const r = fold(s, THRESHOLDS);
    assert.notStrictEqual(componentById(r, 'recall').state,
        componentById(r, 'ops_health').state);
});

test('a missing self_eval payload folds to RESERVED with every component unsupplied', () => {
    const r = fold(null, THRESHOLDS);
    assert.strictEqual(r.band, RESERVED);
    assert.ok(r.components.every(c => c.state === 'unsupplied'), 'all unsupplied');
});

// ── boundaries come from the server, never from here (P5 O-13) ───────────

test('without R10 the recall boundary is undisclosed and the band is RESERVED', () => {
    const r = fold(healthySelfEval(), null);
    const c = componentById(r, 'recall');
    assert.strictEqual(c.band, RESERVED);
    assert.strictEqual(c.state, 'boundary_undisclosed');
    // The measured value is still shown — the gap is in the boundary, not
    // the measurement, and NP6 says show which.
    assert.strictEqual(c.value, 0.92);
});

test('each component discloses the boundary it used and where it came from', () => {
    const r = fold(healthySelfEval(), THRESHOLDS);
    const recall = componentById(r, 'recall');
    assert.strictEqual(recall.boundary.value, 0.7);
    assert.strictEqual(recall.boundary.source, 'R10:calibration.DEGRADED_RECALL_FLOOR');
    assert.strictEqual(recall.boundary.provenance_ref, 'S1-CALIB-027');

    const nz = componentById(r, 'null_zone');
    assert.strictEqual(nz.boundary.value, 604800);
    assert.strictEqual(nz.boundary.source, 'R7:self_eval.null_zone.threshold_sec');
});

test('the boundary a component used moves when the server moves it', () => {
    const strict = JSON.parse(JSON.stringify(THRESHOLDS));
    strict.calibration.DEGRADED_RECALL_FLOOR.value = 0.95;
    const r = fold(healthySelfEval(), strict);   // recall 0.92 < 0.95 now
    assert.strictEqual(componentById(r, 'recall').band, DISTRUST);
});

test('boundary equality lands on the passing side, as the server states', () => {
    const s = healthySelfEval();
    s.calibration = Object.assign({}, s.calibration, { recall: 0.7 });
    assert.strictEqual(componentById(fold(s, THRESHOLDS), 'recall').band, TRUSTED);
});

// ── specific component semantics ─────────────────────────────────────────

test('drift above the disclosed max drop is DISTRUST', () => {
    const s = healthySelfEval();
    s.calibration = Object.assign({}, s.calibration, { drift: 0.06 });
    assert.strictEqual(componentById(fold(s, THRESHOLDS), 'drift').band, DISTRUST);
});

test('a chronic null zone is DISTRUST; an ongoing but non-chronic one is RESERVED', () => {
    const chronic = healthySelfEval();
    chronic.null_zone = Object.assign({}, chronic.null_zone, { any_chronic: true });
    assert.strictEqual(componentById(fold(chronic, THRESHOLDS), 'null_zone').band, DISTRUST);

    const ongoing = healthySelfEval();
    ongoing.null_zone = {
        any_chronic: false, threshold_sec: 604800,
        scenarios: [{ scenario_id: 's', is_chronic: false, ongoing: true, longest_span_sec: 100 }],
    };
    assert.strictEqual(componentById(fold(ongoing, THRESHOLDS), 'null_zone').band, RESERVED);
});

test('data older than the disclosed freshness horizon is DISTRUST', () => {
    const s = healthySelfEval();
    s.data = Object.assign({}, s.data, { data_age_sec: 172801 });
    assert.strictEqual(componentById(fold(s, THRESHOLDS), 'freshness').band, DISTRUST);
});

test('a null data age is unmeasurable, not zero', () => {
    const s = healthySelfEval();
    s.data = Object.assign({}, s.data, { data_age_sec: null });
    const c = componentById(fold(s, THRESHOLDS), 'freshness');
    assert.strictEqual(c.state, 'unmeasurable');
    assert.strictEqual(c.value, null);
});

// ── disclosure surface (NP6) ─────────────────────────────────────────────

test('the fold discloses its own rule as a template, not prose', () => {
    const r = fold(healthySelfEval(), THRESHOLDS);
    assert.strictEqual(r.foldRule, 'min');
    assert.ok(/^ui\.trust\./.test(r.labelKey));
    assert.ok(/^ui\.trust\.formula$/.test(r.formulaKey));
});

test('every component carries a dictionary key, never a bare English word', () => {
    const r = fold(healthySelfEval(), THRESHOLDS);
    r.components.forEach(c => {
        assert.ok(/^ui\.trust\.component\./.test(c.labelKey), c.labelKey);
        assert.ok(/^ui\.trust\.state\./.test(c.stateKey), c.stateKey);
    });
});

test('the result is pure: folding the same input twice is identical', () => {
    const s = healthySelfEval();
    assert.deepStrictEqual(fold(s, THRESHOLDS), fold(s, THRESHOLDS));
});

test('folding does not mutate its inputs', () => {
    const s = healthySelfEval();
    const before = JSON.stringify(s);
    fold(s, THRESHOLDS);
    assert.strictEqual(JSON.stringify(s), before);
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
