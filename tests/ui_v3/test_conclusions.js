/**
 * Unit tests for v3/ui/conclusions.js — conclusion face, derivation, what-if.
 *
 * Run:  node tests/ui_v3/test_conclusions.js
 */
'use strict';

const assert = require('assert');
const C = require('../../v3/ui/conclusions');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;

const THRESHOLDS = {
    calibration: {
        MIN_RECALL_DENOM: { value: 5.0, unit: 'count', provenance_ref: 'S1-CALIB-027' },
    },
};

const REASON_REGISTRY = [
    { guard_id: 'upstream_total_loss', reason: 'upstream_failure',
      condition: 'every consulted source failed' },
    { guard_id: 'history_below_calibration_window', reason: 'calibration_pending',
      condition: 'observed history is shorter than the calibration window' },
];

function conclusion(overrides) {
    return Object.assign({
        id: 'c-1', scenario_id: 'taiwan_contingency',
        conclusion_type: 'threat_level', state: '3', confidence: 0.72,
        observed_at: NOW, conclusion_unavailable_reason: null,
        final_judgment_disclaimer: 'Tool conclusion only — final judgment by organizational process.',
        formula_ref: 'threat_level@2',
        provenance: { formula_ref: 'threat_level@2', computed_at: NOW, inputs: {}, source_refs: [] },
        threshold_ref: {}, source_urls: [],
        calibration_status: { status: 'OK', recall: 0.9, sample_n: 40 },
        llm_prompt_sha256: null,
        input_health: { sources_ok: ['a'], sources_failed: [], consulted: 1 },
        suppression: null, metadata: {},
    }, overrides || {});
}

function r2(conclusions, extra) {
    return Object.assign({
        scenario_id: 'taiwan_contingency',
        observed_at: NOW,
        final_judgment_disclaimer: 'Tool conclusion only — final judgment by organizational process.',
        conclusions: conclusions,
        projection: {
            at: NOW,
            types_present: conclusions.map(c => c.conclusion_type),
            types_missing: [], unreadable_rows: [],
            unavailable_reasons: ['insufficient_data', 'calibration_pending',
                                  'sensor_degraded', 'upstream_failure'],
        },
    }, extra || {});
}

function face(conclusions, extra) {
    return C.buildFace({
        conclusions: r2(conclusions, extra),
        thresholds: THRESHOLDS,
        reasonRegistry: REASON_REGISTRY,
    });
}

// ── every type always has a home (S1-UI-038) ─────────────────────────────

test('all five conclusion types get a section, present or not', () => {
    const f = face([conclusion()]);
    assert.deepStrictEqual(f.sections.map(s => s.type), C.CONCLUSION_TYPES);
    assert.strictEqual(f.sections.length, 5);
});

test('a type the server did not send is marked missing, not omitted', () => {
    const f = face([conclusion()]);
    const trend = f.sections.filter(s => s.type === 'trend')[0];
    assert.strictEqual(trend.present, false);
    assert.strictEqual(trend.emptyKey, 'ui.conclusion.section.missing');
    assert.deepStrictEqual(trend.rows, []);
});

test('multiple anomaly rows all appear under one section', () => {
    const f = face([
        conclusion({ id: 'a1', conclusion_type: 'anomaly', state: 'burst' }),
        conclusion({ id: 'a2', conclusion_type: 'anomaly', state: 'surge' }),
    ]);
    const anomaly = f.sections.filter(s => s.type === 'anomaly')[0];
    assert.strictEqual(anomaly.rows.length, 2);
});

test('the TL row reads the level, and does not compute one', () => {
    const f = face([conclusion({ state: '2' })]);
    const row = f.sections[0].rows[0];
    assert.strictEqual(row.tl.tl, 2);
    assert.strictEqual(row.tl.band, 'severe');
});

test('a non-integer TL state is unknown, never a calm band', () => {
    const f = face([conclusion({ state: 'weird' })]);
    assert.strictEqual(f.sections[0].rows[0].tl.band, 'unknown');
});

test('non-TL types get no TL band at all', () => {
    const f = face([conclusion({ conclusion_type: 'trend', state: 'rising' })]);
    const trend = f.sections.filter(s => s.type === 'trend')[0];
    assert.strictEqual(trend.rows[0].tl, null);
    assert.strictEqual(trend.rows[0].state, 'rising');
});

// ── inconclusive gets a face (DP10) ──────────────────────────────────────

test('an inconclusive conclusion names its reason and the guard that spoke', () => {
    const f = face([conclusion({
        state: null, confidence: 0.0,
        conclusion_unavailable_reason: 'upstream_failure',
        suppression: {
            guard_id: 'upstream_total_loss', reason: 'upstream_failure',
            detail: '5/5 sources failed', overridden: false,
            evaluated: [
                { guard_id: 'upstream_total_loss', reason: 'upstream_failure', fired: true, detail: '5/5' },
                { guard_id: 'no_basis_at_all', reason: 'insufficient_data', fired: false, detail: '' },
            ],
        },
    })]);
    const u = f.sections[0].rows[0].unavailable;
    assert.strictEqual(u.reason, 'upstream_failure');
    assert.strictEqual(u.reasonKey, 'ui.conclusion.unavailable.upstream_failure');
    assert.strictEqual(u.guardId, 'upstream_total_loss');
    assert.strictEqual(u.guardCondition, 'every consulted source failed');
    assert.strictEqual(u.detail, '5/5 sources failed');
    assert.strictEqual(u.evaluated.length, 2, 'guards that did not fire are shown too');
    assert.strictEqual(f.sections[0].rows[0].available, false);
});

test('calibration_pending carries the condition that would clear it', () => {
    const f = C.buildFace({
        conclusions: r2([conclusion({
            state: null, conclusion_unavailable_reason: 'calibration_pending',
        })], {
            calibration_pending: {
                reason: 'calibration_pending', days_remaining: 12.5, days_observed: 17.5,
                window_days: 30, types: ['threat_level'],
                resolves_by: '観測開始から 30 日で解消します',
            },
        }),
        thresholds: THRESHOLDS, reasonRegistry: REASON_REGISTRY,
    });
    const u = f.sections[0].rows[0].unavailable;
    assert.strictEqual(u.resolution.daysRemaining, 12.5);
    assert.strictEqual(u.resolution.text, '観測開始から 30 日で解消します');
    assert.strictEqual(u.guardId, 'history_below_calibration_window');
});

test('an available conclusion has no unavailability block', () => {
    assert.strictEqual(face([conclusion()]).sections[0].rows[0].unavailable, null);
    assert.strictEqual(face([conclusion()]).sections[0].rows[0].available, true);
});

test('a published-despite-a-guard conclusion declares the override (NP1)', () => {
    const f = face([conclusion({
        suppression: { guard_id: 'g', reason: 'sensor_degraded', detail: 'x',
                       overridden: true, evaluated: [] },
    })]);
    assert.strictEqual(f.sections[0].rows[0].overridden, true);
    assert.strictEqual(f.sections[0].rows[0].available, true);
});

// ── calibration warnings (S1-UI-039) ─────────────────────────────────────

test('a DEGRADED calibration raises a high-severity note', () => {
    const notes = C.calibrationNotes({ status: 'DEGRADED', recall: 0.5, sample_n: 40 }, THRESHOLDS);
    assert.strictEqual(notes.length, 1);
    assert.strictEqual(notes[0].kind, 'degraded');
    assert.strictEqual(notes[0].severity, 'high');
});

test('a small sample is flagged provisional against the disclosed floor', () => {
    const notes = C.calibrationNotes({ status: 'OK', sample_n: 3 }, THRESHOLDS);
    assert.strictEqual(notes[0].kind, 'provisional');
    assert.strictEqual(notes[0].boundary, 5.0);
    assert.strictEqual(notes[0].boundarySource, 'R10:calibration.MIN_RECALL_DENOM');
});

test('a sample exactly at the floor is not provisional', () => {
    assert.deepStrictEqual(C.calibrationNotes({ status: 'OK', sample_n: 5 }, THRESHOLDS), []);
});

test('without R10 the sample floor is declared undisclosed, not invented', () => {
    const notes = C.calibrationNotes({ status: 'OK', sample_n: 3 }, null);
    assert.strictEqual(notes[0].kind, 'sample_floor_undisclosed');
    assert.strictEqual(notes[0].boundary, null);
});

test('a zero sample raises no provisional note (there is nothing provisional yet)', () => {
    assert.deepStrictEqual(C.calibrationNotes({ status: 'OK', sample_n: 0 }, THRESHOLDS), []);
});

// ── external strings are sanitised (S1-UI-041) ───────────────────────────

test('source URLs are split into raw and link-safe forms', () => {
    const f = face([conclusion({
        source_urls: ['https://ok.test/a', 'javascript:alert(1)'],
    })]);
    const urls = f.sections[0].rows[0].sourceUrls;
    assert.strictEqual(urls[0].href, 'https://ok.test/a');
    assert.strictEqual(urls[1].href, null, 'a javascript: URL is never linkable');
    assert.strictEqual(urls[1].raw, 'javascript:alert(1)', 'but it is still shown as text');
});

// ── replay is the same shape (P7 principle 4) ────────────────────────────

test('an ?at= envelope is flagged as replay through the same builder', () => {
    const f = C.buildFace({ conclusions: r2([conclusion()], { at: NOW - 7200 }) });
    assert.strictEqual(f.isReplay, true);
    assert.strictEqual(f.at, NOW - 7200);
    assert.strictEqual(C.buildFace({ conclusions: r2([conclusion()]) }).isReplay, false);
});

test('unreadable rows are surfaced, not swallowed', () => {
    const f = C.buildFace({
        conclusions: r2([conclusion()], {
            projection: { at: NOW, types_present: [], types_missing: [],
                          unreadable_rows: [{ id: 'x', reason: 'bad json' }],
                          unavailable_reasons: [] },
        }),
    });
    assert.deepStrictEqual(f.unreadableRows, [{ id: 'x', reason: 'bad json' }]);
});

test('a face with no envelope says so rather than rendering blank', () => {
    const f = C.buildFace({});
    assert.strictEqual(f.empty, true);
    assert.strictEqual(f.emptyKey, 'ui.conclusion.empty.not_loaded');
});

// ── derivation view ──────────────────────────────────────────────────────

function r4d(overrides) {
    return {
        derivation: Object.assign({
            conclusion_id: 'c-1', formula_ref: 'threat_level@2',
            provenance: { formula_ref: 'threat_level@2', computed_at: NOW,
                          inputs: { score: 4.2, cyber: 3.0 },
                          source_refs: ['obs:1'] },
            threshold_ref: { tl2_floor: 6.0, tl3_floor: 4.0 },
            source_urls: ['https://src.test/1'],
            llm_prompt_sha256: null,
            input_health: { sources_ok: ['a'], sources_failed: [] },
            calibration_status: { status: 'OK', sample_n: 40 },
            suppression: null, guards_evaluated: [],
        }, overrides || {}),
    };
}

test('the derivation emits every section in a fixed order', () => {
    const d = C.buildDerivation({ derivation: r4d(), thresholds: THRESHOLDS });
    assert.deepStrictEqual(d.sections.map(s => s.id), [
        'formula', 'inputs', 'thresholds', 'calibration',
        'input_health', 'guards', 'sources', 'llm_prompt',
    ]);
});

test('an empty section is present in the list and says it is empty', () => {
    const d = C.buildDerivation({ derivation: r4d() });
    const llm = d.sections.filter(s => s.id === 'llm_prompt')[0];
    assert.strictEqual(llm.present, false);
    assert.strictEqual(llm.emptyKey, 'ui.derivation.section.llm_unused');
    assert.strictEqual(llm.payload, null);
});

test('threshold and input rows are key-sorted so the view is reproducible', () => {
    const d = C.buildDerivation({ derivation: r4d() });
    assert.deepStrictEqual(
        d.sections.filter(s => s.id === 'thresholds')[0].payload.rows.map(r => r.key),
        ['tl2_floor', 'tl3_floor']);
    assert.deepStrictEqual(
        d.sections.filter(s => s.id === 'inputs')[0].payload.rows.map(r => r.key),
        ['cyber', 'score']);
});

test('suppressed contributions stay visible in the guards section (S1-UI-040)', () => {
    const d = C.buildDerivation({
        derivation: r4d({
            suppression: { guard_id: 'g1', reason: 'sensor_degraded',
                           detail: 'd', overridden: false, evaluated: [] },
            guards_evaluated: [
                { guard_id: 'g1', reason: 'sensor_degraded', fired: true, detail: 'd' },
                { guard_id: 'g2', reason: 'insufficient_data', fired: false, detail: '' },
            ],
        }),
    });
    const guards = d.sections.filter(s => s.id === 'guards')[0];
    assert.strictEqual(guards.present, true);
    assert.strictEqual(guards.payload.evaluated.length, 2);
    assert.strictEqual(guards.payload.fired.guard_id, 'g1');
});

test('a derivation URL that is not http(s) is not linkable', () => {
    const d = C.buildDerivation({
        derivation: r4d({ source_urls: ['data:text/html,<script>'] }),
    });
    assert.strictEqual(d.sections.filter(s => s.id === 'sources')[0].payload.sources[0].href, null);
});

test('a prompt with only a hash still discloses identity', () => {
    const d = C.buildDerivation({ derivation: r4d({ llm_prompt_sha256: 'abc123' }) });
    const llm = d.sections.filter(s => s.id === 'llm_prompt')[0];
    assert.strictEqual(llm.present, true);
    assert.strictEqual(llm.payload.sha256, 'abc123');
});

test('no derivation payload reports not-loaded rather than an empty tree', () => {
    const d = C.buildDerivation({});
    assert.strictEqual(d.present, false);
    assert.strictEqual(d.emptyKey, 'ui.derivation.empty.not_loaded');
});

// ── what-if is a diff, never a second engine (G-09 / DP4) ────────────────

function c6(baseTl, cfTl) {
    return {
        baseline: {
            settings: { domain_cap: 8.0 },
            scenarios: { taiwan_contingency: {
                tl: baseTl, severity: 6 - baseTl, score: 4.2,
                domains: { cyber: 3.0, physical: 1.0, info: 0.2 },
                convergence: 'dual',
            } },
        },
        counterfactual: {
            settings: { domain_cap: 8.0 },
            scenarios: { taiwan_contingency: {
                tl: cfTl, severity: 6 - cfTl, score: 6.4,
                domains: { cyber: 5.0, physical: 1.0, info: 0.2 },
                convergence: 'triple',
            } },
        },
        overlay: { settings: {}, weights: { taiwan_contingency: { TW: 1.0 } }, focus: null },
    };
}

test('what-if subtracts two server answers and reports the severity direction', () => {
    const d = C.diffWhatIf(c6(4, 2));
    const s = d.scenarios[0];
    assert.strictEqual(s.tl.baseline, 4);
    assert.strictEqual(s.tl.counterfactual, 2);
    // TL 4 -> 2 is a rise in severity: +2
    assert.strictEqual(s.tl.severityDelta, 2);
    assert.strictEqual(s.tl.changed, true);
    assert.strictEqual(s.score.delta, 6.4 - 4.2);
    assert.strictEqual(s.domains.cyber.delta, 2.0);
});

test('an unchanged what-if reports no change rather than a fake delta', () => {
    const d = C.diffWhatIf(c6(3, 3));
    assert.strictEqual(d.scenarios[0].tl.changed, false);
    assert.strictEqual(d.scenarios[0].tl.severityDelta, 0);
    assert.deepStrictEqual(d.changed, []);
});

test('what-if with no run reports not-run, and what would fill it', () => {
    assert.strictEqual(C.diffWhatIf(null).present, false);
    const state = C.diffWhatIf({ baseline: {} }).emptyState;
    assert.strictEqual(state.reasonKey, 'empty.whatif.reason_not_run');
    assert.strictEqual(state.roleKey, 'empty.whatif.role');
    assert.strictEqual(state.fillsWhenKey, 'empty.whatif.fills_when');
});

test('a scenario present on only one side still appears in the diff', () => {
    const e = c6(4, 2);
    e.counterfactual.scenarios.other = { tl: 5, score: 0.1, domains: {} };
    const d = C.diffWhatIf(e);
    assert.deepStrictEqual(d.scenarios.map(s => s.scenarioId).sort(),
        ['other', 'taiwan_contingency']);
    const other = d.scenarios.filter(s => s.scenarioId === 'other')[0];
    assert.strictEqual(other.tl.baseline, null);
    assert.strictEqual(other.tl.severityDelta, null);
});

test('both settings blocks are carried so the overlay is inspectable', () => {
    const d = C.diffWhatIf(c6(4, 2));
    assert.deepStrictEqual(d.baselineSettings, { domain_cap: 8.0 });
    assert.ok(d.overlay.weights);
});

// ── feedback (S1-UI-043) ─────────────────────────────────────────────────

test('feedback exposes all five outcomes distinctly', () => {
    assert.strictEqual(C.feedbackState({ conclusionId: 'c', label: null }).state, 'no_label');
    assert.strictEqual(C.feedbackState({ conclusionId: 'c', label: 'TRUE_POSITIVE', reason: 'r', inFlight: true }).state, 'saving');
    assert.strictEqual(C.feedbackState({ conclusionId: 'c', label: 'TRUE_POSITIVE', reason: 'r', savedAt: NOW }).state, 'saved');
    assert.strictEqual(C.feedbackState({ conclusionId: 'c', serverError: 'forbidden' }).state, 'rejected');
    assert.strictEqual(C.feedbackState({ conclusionId: 'c', networkError: 'offline' }).state, 'network_error');
});

test('a conclusion that was never persisted cannot be labelled, and says why', () => {
    const s = C.feedbackState({ conclusionId: null, label: 'TRUE_POSITIVE', reason: 'r' });
    assert.strictEqual(s.state, 'unsupported');
    assert.strictEqual(s.canSubmit, false);
});

test('a blank reason is refused before the request (C2 requires one)', () => {
    const s = C.feedbackState({ conclusionId: 'c', label: 'TRUE_POSITIVE', reason: '   ' });
    assert.strictEqual(s.canSubmit, false);
    assert.strictEqual(s.messageKey, 'ui.feedback.reason_required');
});

test('an unknown label is not submittable', () => {
    assert.strictEqual(
        C.feedbackState({ conclusionId: 'c', label: 'MAYBE', reason: 'r' }).canSubmit, false);
});

test('the tally is per-label counts plus analyst count, never one verdict', () => {
    const t = C.labelTally({
        alice: { label: 'TRUE_POSITIVE' },
        bob: { label: 'FALSE_POSITIVE' },
        carol: { label: 'TRUE_POSITIVE' },
        mallory: { label: 'NOT_A_LABEL' },
    });
    assert.strictEqual(t.counts.TRUE_POSITIVE, 2);
    assert.strictEqual(t.counts.FALSE_POSITIVE, 1);
    assert.strictEqual(t.counts.FALSE_NEGATIVE, 0);
    assert.strictEqual(t.analysts, 3, 'an unknown label counts for nobody');
});

test('an empty tally shows four zeroes, not an absence', () => {
    const t = C.labelTally({});
    assert.deepStrictEqual(Object.keys(t.counts).sort(), C.LABELS.slice().sort());
    assert.strictEqual(t.analysts, 0);
});

// ── purity ───────────────────────────────────────────────────────────────

test('none of the builders mutate their input', () => {
    const input = { conclusions: r2([conclusion()]), thresholds: THRESHOLDS,
                    reasonRegistry: REASON_REGISTRY };
    const before = JSON.stringify(input);
    C.buildFace(input);
    assert.strictEqual(JSON.stringify(input), before);

    const der = { derivation: r4d() };
    const derBefore = JSON.stringify(der);
    C.buildDerivation(der);
    assert.strictEqual(JSON.stringify(der), derBefore);

    const wi = c6(4, 2);
    const wiBefore = JSON.stringify(wi);
    C.diffWhatIf(wi);
    assert.strictEqual(JSON.stringify(wi), wiBefore);
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
