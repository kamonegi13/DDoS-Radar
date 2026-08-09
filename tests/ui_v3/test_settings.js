/**
 * Unit tests for v3/ui/settings.js — the registry-driven settings screen.
 *
 * Run:  node tests/ui_v3/test_settings.js
 *
 * The load-bearing ones:
 *   - a save whose ledger row did NOT move the resolved value is reported
 *     as exactly that. G-15's damage was never a wrong number on screen; it
 *     was that "written" and "read by something" looked identical, and this
 *     is the assertion that keeps them apart;
 *   - the effect is read from the server's re-resolution, never echoed from
 *     the request;
 *   - no diff means no request;
 *   - the widget is chosen from the declared unit, so adding a registry key
 *     needs no edit here.
 */
'use strict';

const assert = require('assert');
const S = require('../../v3/ui/settings');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const CONSUMER = 'v3.scoring.settings:resolve_settings';

function entry(overrides) {
    return Object.assign({
        key: 'SEQUENCE_WINDOW', value: 86400.0, source: 'default', unit: 's',
        default: 86400.0, why: 'how long an escalation chain stays live',
        consumer: CONSUMER, override: null, env_present: false,
    }, overrides || {});
}

function r14(entries) {
    return {
        config: entries,
        variable_keys: entries.map((e) => e.key),
        layers: ['override', 'env', 'default'],
        environment_layer_keys: [],
        pinned_note: 'O-18 群 (b) の定数は R10 が開示します',
    };
}

function r10() {
    return {
        thresholds: {
            conclusions: { A: {}, B: {} },
            calibration: { C: {} },
            scoring_pinned: { D: {}, E: {}, F: {} },
            variable: { SEQUENCE_WINDOW: {} },
        },
    };
}

// ── registry-driven ──────────────────────────────────────────────────────

test('the row is built from the wire and adds nothing of its own', () => {
    const view = S.buildSettings({ config: r14([entry()]) });
    const row = view.rows[0];
    assert.strictEqual(row.key, 'SEQUENCE_WINDOW');
    assert.strictEqual(row.value, 86400.0);
    assert.strictEqual(row.consumer, CONSUMER);
    assert.strictEqual(row.source, 'default');
    assert.strictEqual(row.writable, true);
});

test('every declared unit picks a widget without a per-key branch', () => {
    Object.keys(S.UNIT_WIDGET).forEach((unit) => {
        const w = S.widgetFor(unit);
        assert.ok([S.WIDGET_TOGGLE, S.WIDGET_RATIO, S.WIDGET_NUMBER,
                   S.WIDGET_INTEGER].indexOf(w.kind) !== -1, unit);
    });
    assert.strictEqual(S.widgetFor('bool').kind, S.WIDGET_TOGGLE);
    assert.strictEqual(S.widgetFor('ratio').kind, S.WIDGET_RATIO);
    assert.strictEqual(S.widgetFor('count').integerOnly, true);
});

test('an unheard-of unit falls back to a number rather than vanishing', () => {
    assert.strictEqual(S.widgetFor('parsecs').kind, S.WIDGET_NUMBER);
});

test('rows arrive sorted so the screen does not reshuffle between polls', () => {
    const view = S.buildSettings({ config: r14([
        entry({ key: 'SEQUENCE_WINDOW' }), entry({ key: 'DOMAIN_CAP' }),
        entry({ key: 'GLOBAL_SIGNAL_WEIGHT' })]) });
    assert.deepStrictEqual(view.rows.map((r) => r.key),
                           ['DOMAIN_CAP', 'GLOBAL_SIGNAL_WEIGHT', 'SEQUENCE_WINDOW']);
});

// ── the short list is stated, not hidden ─────────────────────────────────

test('the variable and pinned counts are both reported', () => {
    const view = S.buildSettings({ config: r14([entry()]), thresholds: r10() });
    assert.strictEqual(view.variableCount, 1);
    // Three pinned catalogues, six entries; `variable` is this screen's own
    // list and must not be counted a second time.
    assert.strictEqual(view.pinnedCount, 6);
});

test('an absent R10 leaves the pinned count absent rather than zero', () => {
    const view = S.buildSettings({ config: r14([entry()]) });
    assert.strictEqual(view.pinnedCount, null);
});

test('an empty variable list is distinguishable from an unfetched one', () => {
    assert.strictEqual(S.buildSettings({ config: null }).emptyKey,
                       'ui.settings.empty.not_loaded');
    assert.strictEqual(S.buildSettings({ config: r14([]) }).emptyKey,
                       'ui.settings.empty.no_variable_keys');
});

// ── the four badge systems, each server-fed ──────────────────────────────

test('the source badge follows the layer that answered', () => {
    ['override', 'env', 'default'].forEach((source) => {
        const view = S.buildSettings({ config: r14([entry({ source })]) });
        assert.strictEqual(view.rows[0].sourceKey, 'ui.settings.source.' + source);
    });
});

test('a source the client does not recognise is not invented', () => {
    const view = S.buildSettings({ config: r14([entry({ source: 'magic' })]) });
    assert.strictEqual(view.rows[0].source, null);
    assert.strictEqual(view.rows[0].sourceKey, 'ui.settings.source.unknown');
});

test('the env badge reports presence, not the value', () => {
    const view = S.buildSettings({ config: r14([entry({ env_present: true })]) });
    assert.strictEqual(view.rows[0].envPresent, true);
    assert.strictEqual(view.rows[0].envKey, 'ui.settings.env.present');
});

test('an override carries who, why and when', () => {
    const view = S.buildSettings({ config: r14([entry({
        source: 'override',
        override: { value: 1.0, actor_id: 'kamo', reason: 'drill', at: 1800000000 },
    })]) });
    const row = view.rows[0];
    assert.strictEqual(row.overrideActor, 'kamo');
    assert.strictEqual(row.overrideReason, 'drill');
    assert.strictEqual(row.overrideAt, 1800000000);
});

// ── ground truth (C9g) ───────────────────────────────────────────────────

test('ground truth is flattened but keeps its scenario', () => {
    const view = S.buildSettings({
        config: r14([entry()]),
        groundTruth: { ground_truth: {
            taiwan: [{ label: 'ESCALATION', observed_at: 1 }],
            ukraine: [{ label: 'CALM', observed_at: 2 }],
        }, entry_count: 2 },
    });
    assert.strictEqual(view.groundTruth.length, 2);
    assert.strictEqual(view.groundTruth[0].scenarioId, 'taiwan');
    assert.strictEqual(view.groundTruth[1].entry.label, 'CALM');
});

test('an unfetched ground truth is distinguishable from an empty one', () => {
    assert.strictEqual(S.buildSettings({ config: r14([]) }).groundTruthLoaded, false);
    assert.strictEqual(
        S.buildSettings({ config: r14([]), groundTruth: { ground_truth: {} } })
            .groundTruthLoaded, true);
});

// ── parsing refuses rather than repairs ──────────────────────────────────

test('a bool key takes only true and false', () => {
    const row = S.buildSettings({ config: r14([entry({
        key: 'GLOBAL_SIGNALS_DECOUPLED', unit: 'bool', value: true,
        default: true })]) }).rows[0];
    assert.deepStrictEqual(S.parseInput(row, true), { ok: true, value: true });
    assert.deepStrictEqual(S.parseInput(row, 'false'), { ok: true, value: false });
    assert.strictEqual(S.parseInput(row, 1).ok, false);
    assert.strictEqual(S.parseInput(row, 1).errorKey, 'ui.settings.error.not_bool');
});

test('a numeric key refuses text, emptiness and infinity', () => {
    const row = S.buildSettings({ config: r14([entry()]) }).rows[0];
    assert.strictEqual(S.parseInput(row, 'soon').errorKey,
                       'ui.settings.error.not_number');
    assert.strictEqual(S.parseInput(row, '  ').errorKey, 'ui.settings.error.empty');
    assert.strictEqual(S.parseInput(row, 'Infinity').errorKey,
                       'ui.settings.error.not_number');
});

test('a count key refuses a fraction before the round trip', () => {
    const row = S.buildSettings({ config: r14([entry({ unit: 'count', value: 3,
                                                       default: 3 })]) }).rows[0];
    assert.strictEqual(S.parseInput(row, '2.5').errorKey,
                       'ui.settings.error.not_integer');
    assert.strictEqual(S.parseInput(row, '2').value, 2);
});

// ── the diff gate (S1-UI-069) ────────────────────────────────────────────

test('no diff means no request', () => {
    const row = S.buildSettings({ config: r14([entry()]) }).rows[0];
    const diff = S.diffOf(row, '86400');
    assert.strictEqual(diff.changed, false);
    assert.strictEqual(diff.errorKey, 'ui.settings.error.no_change');
});

test('a diff carries both sides and the reader', () => {
    const row = S.buildSettings({ config: r14([entry()]) }).rows[0];
    const diff = S.diffOf(row, '43200');
    assert.strictEqual(diff.changed, true);
    assert.strictEqual(diff.from, 86400);
    assert.strictEqual(diff.to, 43200);
    assert.strictEqual(diff.consumer, CONSUMER);
    const vars = S.confirmVars(diff);
    assert.strictEqual(vars.key, 'SEQUENCE_WINDOW');
    assert.strictEqual(vars.to, '43200');
    assert.strictEqual(vars.unit, 's');
});

test('a bool flip is a diff', () => {
    const row = S.buildSettings({ config: r14([entry({
        unit: 'bool', value: true, default: true })]) }).rows[0];
    assert.strictEqual(S.diffOf(row, false).changed, true);
    assert.strictEqual(S.diffOf(row, true).changed, false);
});

test('an unparseable entry is not a diff', () => {
    const row = S.buildSettings({ config: r14([entry()]) }).rows[0];
    const diff = S.diffOf(row, 'later');
    assert.strictEqual(diff.ok, false);
    assert.strictEqual(diff.changed, false);
});

// ── saved is not in-effect (S1-UI-070 / G-15) ────────────────────────────

test('the effect is read from the server, never echoed from the request', () => {
    const outcome = S.resultOf({ ok: true, body: {
        changed: true,
        command: { command_id: 'abc' },
        effect: { config: { key: 'SEQUENCE_WINDOW', value: 43200,
                            source: 'override' } },
    } });
    assert.strictEqual(outcome.effectValue, 43200);
    assert.strictEqual(outcome.effectSource, 'override');
    assert.strictEqual(outcome.messageKey, 'ui.settings.result.applied');
});

test('a ledger row that moved nothing is reported as G-15\'s fingerprint', () => {
    const outcome = S.resultOf({ ok: true, body: {
        changed: false,
        effect: { config: { key: 'SEQUENCE_WINDOW', value: 86400,
                            source: 'default' } },
    } });
    assert.strictEqual(outcome.saved, true);
    assert.strictEqual(outcome.changed, false);
    assert.strictEqual(outcome.messageKey, 'ui.settings.result.recorded_no_effect');
});

test('a refusal carries the reason the server gave', () => {
    const outcome = S.resultOf({ ok: false, error: {
        code: 'api.bad_request', message: '理由の記載を必須とします' } });
    assert.strictEqual(outcome.saved, false);
    assert.strictEqual(outcome.messageKey, 'ui.settings.result.refused');
    assert.strictEqual(outcome.detail, '理由の記載を必須とします');
});

test('a response with no effect at all does not claim one', () => {
    const outcome = S.resultOf({ ok: true, body: { changed: true } });
    assert.strictEqual(outcome.effect, null);
    assert.strictEqual(outcome.effectValue, null);
});

test('buildSettings does not mutate its input', () => {
    const input = { config: r14([entry()]), thresholds: r10() };
    const before = JSON.stringify(input);
    S.buildSettings(input);
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
