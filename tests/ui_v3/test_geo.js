/**
 * Unit tests for v3/ui/geo.js — the geographic face of O-4.
 *
 * Run:  node tests/ui_v3/test_geo.js
 *
 * The load-bearing ones:
 *   - G-17 at three depths: "not fetched", "fetched and the ledger is
 *     empty" and "observed, nothing fired" are three different answers and
 *     none of them draws a calm world;
 *   - a suppressed row keeps its reason and never collapses into "quiet"
 *     (E-17 / S1-UI-040);
 *   - a country the ledger observed but the scenario does not list is still
 *     shown, because a participant list is not a coverage list;
 *   - the layer that needs coordinates declares itself unserved instead of
 *     rendering empty, and cannot be switched on.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const G = require('../../v3/ui/geo');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;

function scenarios(overrides) {
    return {
        scenarios: [Object.assign({
            scenario_id: 'taiwan',
            participants: { TW: 1.0, JP: 0.6, CN: 0.9 },
            roles: { TW: 'primary_target', JP: 'forward_base', CN: 'adversary' },
            adversaries: ['CN'],
            chain_country: 'CN',
            focused: true,
        }, overrides || {})],
        focused_scenario: 'taiwan',
    };
}

function evidence(rows, extra) {
    return {
        evidence: Object.assign({
            at: NOW, window_sec: 86400,
            countries: ['CN', 'GLOBAL', 'JP', 'TW'],
            filters: { domain: null, sensor: null },
            matrix: rows,
            fired: rows.filter((r) => r.status === 'FIRED' && !r.suppressed),
            fired_count: rows.filter((r) => r.status === 'FIRED' && !r.suppressed).length,
            suppressed: rows.filter((r) => r.suppressed),
            suppressed_count: rows.filter((r) => r.suppressed).length,
            observation_count: rows.length,
        }, extra || {}),
    };
}

function obs(overrides) {
    return Object.assign({
        tick_id: 't1', sensor: 'ripe_bgp', signal_source: 'ripe_bgp',
        domain: 'cyber', country: 'TW', status: 'OK', raw_score: 1.0,
        confidence: 0.8, observed_at: NOW, suppressed: false,
        suppress_reason: null, evidence_url: null, flags: null,
    }, overrides || {});
}

// ── roles are the first dimension (S1-UI-060) ────────────────────────────

test('every declared role maps to one of the five classes', () => {
    Object.keys(G.ROLE_CLASS).forEach((role) => {
        assert.ok(G.CLASSES.indexOf(G.ROLE_CLASS[role]) !== -1, role);
    });
    assert.strictEqual(Object.keys(G.ROLE_CLASS).length, 13);
});

test('an unknown role lands in the observer class and says so', () => {
    const face = G.buildFace({
        scenarios: scenarios({ roles: { TW: 'space_command' } }),
        evidence: evidence([]), scenarioId: 'taiwan',
    });
    const tw = face.markers.filter((m) => m.country === 'TW')[0];
    assert.strictEqual(tw.roleClass, G.UNKNOWN_CLASS);
    assert.strictEqual(tw.roleKnown, false);
});

test('the coupling weight is carried verbatim and never recombined', () => {
    const face = G.buildFace({ scenarios: scenarios(), evidence: evidence([]),
                               scenarioId: 'taiwan' });
    const jp = face.markers.filter((m) => m.country === 'JP')[0];
    assert.strictEqual(jp.weight, 0.6);
});

test('the adversary and chain flags come from the scenario ledger', () => {
    const face = G.buildFace({ scenarios: scenarios(), evidence: evidence([]),
                               scenarioId: 'taiwan' });
    const cn = face.markers.filter((m) => m.country === 'CN')[0];
    assert.strictEqual(cn.isAdversary, true);
    assert.strictEqual(cn.isChainCountry, true);
    assert.strictEqual(face.chainCountry, 'CN');
});

// ── suppression is not silence (E-17) ────────────────────────────────────

test('a suppressed row keeps its reason and is counted apart from fired', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([
            obs({ country: 'TW', status: 'FIRED', suppressed: true,
                  suppress_reason: 'noise_window' }),
        ]),
        scenarioId: 'taiwan',
    });
    const tw = face.markers.filter((m) => m.country === 'TW')[0];
    assert.strictEqual(tw.firedCount, 0);
    assert.strictEqual(tw.suppressedCount, 1);
    assert.strictEqual(tw.suppressed[0].reason, 'noise_window');
    assert.strictEqual(tw.stateKey, 'ui.geo.marker.suppressed_only');
});

test('fired and suppressed are never merged into one total', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([
            obs({ country: 'TW', status: 'FIRED' }),
            obs({ country: 'TW', status: 'FIRED', suppressed: true,
                  suppress_reason: 'muted' }),
        ]),
        scenarioId: 'taiwan',
    });
    assert.strictEqual(face.firedTotal, 1);
    assert.strictEqual(face.suppressedTotal, 1);
});

// ── G-17: three emptinesses ──────────────────────────────────────────────

test('no focus, no scenario, no evidence and no observation all differ', () => {
    const noFocus = G.buildFace({ scenarios: scenarios(), evidence: null,
                                  scenarioId: null });
    const missing = G.buildFace({ scenarios: scenarios(), evidence: null,
                                  scenarioId: 'ukraine' });
    const unfetched = G.buildFace({ scenarios: scenarios(), evidence: null,
                                    scenarioId: 'taiwan' });
    const empty = G.buildFace({ scenarios: scenarios(), evidence: evidence([]),
                                scenarioId: 'taiwan' });
    const keys = [noFocus, missing, unfetched, empty]
        .map((face) => face.emptyState.reasonKey);
    assert.deepStrictEqual(keys, [
        'empty.geo.reason_no_focus',
        'empty.geo.reason_scenario_not_loaded',
        'empty.geo.reason_not_loaded',
        'empty.geo.reason_no_observations',
    ]);
    assert.strictEqual(new Set(keys).size, keys.length);
    // P9 §3.5: whichever of the four holds, the other two thirds of the
    // contract are the same — the face still has to say what it shows and
    // what would fill it, or a cold-start reader learns nothing from it.
    [noFocus, missing, unfetched, empty].forEach((face) => {
        assert.strictEqual(face.emptyState.roleKey, 'empty.geo.role');
        assert.strictEqual(face.emptyState.fillsWhenKey, 'empty.geo.fills_when');
    });
});

test('observed-but-nothing-fired is its own answer', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([obs({ country: 'TW', status: 'OK' })]),
        scenarioId: 'taiwan',
    });
    assert.strictEqual(face.emptyState.reasonKey,
                       'empty.geo.reason_observed_nothing_fired');
});

test('a participant with no observation row is not "quiet"', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([obs({ country: 'TW', status: 'FIRED' })]),
        scenarioId: 'taiwan',
    });
    const jp = face.markers.filter((m) => m.country === 'JP')[0];
    assert.strictEqual(jp.stateKey, 'ui.geo.marker.unobserved');
    assert.strictEqual(jp.observations, 0);
});

test('a fired anomaly is the loudest state a marker can report', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([obs({ country: 'TW', status: 'FIRED' })]),
        scenarioId: 'taiwan',
    });
    assert.strictEqual(face.markers[0].country, 'TW');
    assert.strictEqual(face.markers[0].stateKey, 'ui.geo.marker.fired');
});

// ── S1-UI-058: no country is drawn twice, none is dropped ────────────────

test('a participant is not duplicated as an off-roster row', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([obs({ country: 'TW', status: 'FIRED' })]),
        scenarioId: 'taiwan',
    });
    const countries = face.markers.map((m) => m.country)
        .concat(face.offRoster.map((m) => m.country));
    assert.strictEqual(new Set(countries).size, countries.length);
});

test('countryless signals become their own bucket, never a participant', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([obs({ country: null, status: 'FIRED' })]),
        scenarioId: 'taiwan',
    });
    const global = face.offRoster.filter((m) => m.country === G.GLOBAL)[0];
    assert.ok(global, 'the GLOBAL bucket must exist');
    assert.strictEqual(global.firedCount, 1);
    face.markers.forEach((m) => assert.strictEqual(m.firedCount, 0));
});

test('an observed country the scenario does not list is still shown', () => {
    const face = G.buildFace({
        scenarios: scenarios(),
        evidence: evidence([obs({ country: 'PH', status: 'FIRED' })]),
        scenarioId: 'taiwan',
    });
    const ph = face.offRoster.filter((m) => m.country === 'PH')[0];
    assert.ok(ph, 'a participant list is not a coverage list');
    assert.strictEqual(ph.role, null);
    assert.strictEqual(ph.roleClass, G.UNKNOWN_CLASS);
});

// ── layers persist, and the unserved one says why (S1-UI-057 / P8 §6) ────

test('the four surviving layers are declared and no more', () => {
    assert.deepStrictEqual(G.LAYERS.map((l) => l.id),
                           ['participants', 'anomalies', 'chain', 'reference']);
});

test('the reference layer is unavailable with a stated reason', () => {
    const reference = G.LAYERS.filter((l) => l.id === 'reference')[0];
    assert.strictEqual(reference.available, false);
    assert.strictEqual(reference.defaultOn, false);
    assert.ok(reference.unavailableKey);
    const face = G.buildFace({ scenarios: scenarios(), evidence: evidence([]),
                               scenarioId: 'taiwan' });
    assert.strictEqual(face.unservedLayers.length, 1);
    assert.strictEqual(face.unservedLayers[0].id, 'reference');
});

test('the unserved layer cannot be switched on', () => {
    const next = G.toggleLayer(null, 'reference');
    assert.strictEqual(next.reference, false);
});

test('a saved layer choice survives and an absent one takes the default', () => {
    const face = G.buildFace({
        scenarios: scenarios(), evidence: evidence([]), scenarioId: 'taiwan',
        layers: { participants: false },
    });
    assert.strictEqual(face.layers.participants, false);
    assert.strictEqual(face.layers.anomalies, true);
});

test('toggling returns a new object rather than mutating the old one', () => {
    const before = { participants: true, anomalies: true, chain: true,
                     reference: false };
    const after = G.toggleLayer(before, 'anomalies');
    assert.strictEqual(before.anomalies, true);
    assert.strictEqual(after.anomalies, false);
    assert.notStrictEqual(before, after);
});

test('an unknown layer id changes nothing', () => {
    const after = G.toggleLayer({ participants: true }, 'threat_terrain');
    assert.strictEqual(after.participants, true);
});

// ── no browser-side geography ────────────────────────────────────────────

test('the module contains no coordinate table', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'v3', 'ui', 'geo.js'), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    ['lat', 'lng', 'longitude', 'latitude'].forEach((token) => {
        assert.strictEqual(code.indexOf(token), -1,
                           `${token} — the browser holds no geography`);
    });
});

test('buildFace does not mutate its input', () => {
    const input = {
        scenarios: scenarios(),
        evidence: evidence([obs({ status: 'FIRED' })]),
        scenarioId: 'taiwan', layers: { participants: true },
    };
    const before = JSON.stringify(input);
    G.buildFace(input);
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
