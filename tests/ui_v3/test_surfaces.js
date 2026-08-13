/**
 * Unit tests for v3/ui/surfaces.js — the DOM for the four WP-4.3 surfaces.
 *
 * Run:  node tests/ui_v3/test_surfaces.js
 *
 * `app.js` has `test_app_smoke.js`; this is the same argument applied to
 * the second DOM file. The wiring is where "the data arrived and the screen
 * did not change" lives, so the wiring is executed here against a fake
 * document rather than trusted.
 *
 * The load-bearing ones:
 *   - a settings save sends the parsed value with a reason and then
 *     REFETCHES; nothing is echoed from the request (S1-UI-035 / G-15);
 *   - a save with no diff and a save with no reason both send nothing;
 *   - a layer toggle persists through the injected store (S1-UI-057);
 *   - an accepted push invalidates and refetches; it never writes payload
 *     data into the document.
 */
'use strict';

const assert = require('assert');
const Surfaces = require('../../v3/ui/surfaces');
const Live = require('../../v3/ui/live');
const Dim = require('../../v3/ui/dim');
const Mode = require('../../v3/ui/display_mode');

let passed = 0, failed = 0;
const failures = [];
const pending = [];

function test(name, fn) { pending.push({ name, fn }); }

async function run() {
    for (const { name, fn } of pending) {
        try { await fn(); passed += 1; process.stdout.write('.'); }
        catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
    }
}

const NOW = 1800000000;
const IDS = ['geo-freshness', 'geo-layers', 'geo-summary', 'geo-empty',
             'geo-tilemap', 'geo-markers', 'geo-offroster', 'geo-offroster-head',
             'settings-freshness', 'settings-summary', 'settings-rows',
             'groundtruth-rows', 'mode-slot', 'critical-banner',
             'dim-overlay', 'dim-message', 'dim-retry', 'live-slot', 'stage-2'];

function element(id) {
    return {
        id, innerHTML: '', textContent: '', hidden: false, disabled: false,
        checked: false, value: '', attrs: {},
        getAttribute(name) {
            return Object.prototype.hasOwnProperty.call(this.attrs, name)
                ? this.attrs[name] : null;
        },
        setAttribute(name, v) { this.attrs[name] = v; },
    };
}

function fakeDoc() {
    const byId = Object.create(null);
    IDS.forEach((id) => { byId[id] = element(id); });
    const extra = [];
    const listeners = {};
    return {
        _byId: byId,
        _extra: extra,
        _listeners: listeners,
        getElementById(id) { return byId[id] || null; },
        querySelector(selector) {
            const m = /^\[([\w-]+)="([^"]*)"\]$/.exec(selector);
            if (!m) return null;
            const found = extra.filter((el) => el.attrs[m[1]] === m[2]);
            return found.length ? found[0] : null;
        },
        addEventListener(name, fn) { listeners[name] = fn; },
        _add(attrs) {
            const el = element(null);
            el.attrs = attrs;
            extra.push(el);
            return el;
        },
    };
}

const R14 = {
    config: [
        { key: 'SEQUENCE_WINDOW', value: 86400.0, source: 'default', unit: 's',
          default: 86400.0, why: 'chain lifetime',
          consumer: 'v3.scoring.settings:resolve_settings',
          override: null, env_present: false },
    ],
    variable_keys: ['SEQUENCE_WINDOW'],
    layers: ['override', 'env', 'default'],
    environment_layer_keys: [], pinned_note: 'note',
};

const R1 = {
    scenarios: [{ scenario_id: 'taiwan', participants: { TW: 1.0 },
                  roles: { TW: 'primary_target' }, adversaries: ['CN'],
                  chain_country: null, focused: true }],
    focused_scenario: 'taiwan',
};

const R5 = {
    evidence: {
        at: NOW, window_sec: 86400, countries: ['TW'],
        filters: {}, observation_count: 1, fired_count: 1, suppressed_count: 0,
        fired: [], suppressed: [],
        matrix: [{ sensor: 'ripe_bgp', domain: 'cyber', country: 'TW',
                   status: 'FIRED', raw_score: 3.0, confidence: 0.8,
                   observed_at: NOW, suppressed: false }],
    },
};

const APP_CONFIG = {
    app_config: { websocket: { mounted: false, reason: '合成していない',
                               unpublished: {} } },
};

function ok(body) { return { ok: true, body, observedAt: NOW, held: false }; }

function harness(overrides) {
    overrides = overrides || {};
    const doc = fakeDoc();
    const sent = [];
    const toasts = [];
    const refreshes = [];
    const invalidations = [];
    let layers = null;
    const results = Object.assign({
        R1: ok(R1), R5: ok(R5), R14: ok(R14), R10: ok({ thresholds: {
            conclusions: { A: {} }, calibration: {}, scoring_pinned: {},
            variable: {} } }),
        C9g: ok({ ground_truth: {} }), R15c: ok(APP_CONFIG),
    }, overrides.results || {});

    const surfaces = Surfaces.createSurfaces({
        doc,
        client: {
            commands: {
                setConfig(key, value, reason) {
                    sent.push({ verb: 'set', key, value, reason });
                    return Promise.resolve(overrides.commandResult || ok({
                        changed: true, command: { command_id: 'x' },
                        effect: { config: { key, value, source: 'override' } },
                    }));
                },
                clearConfig(key, reason) {
                    sent.push({ verb: 'clear', key, reason });
                    return Promise.resolve(ok({
                        changed: true,
                        effect: { config: { key, value: 86400, source: 'default' } },
                    }));
                },
            },
        },
        detector: {
            shouldRender() { return { render: true }; },
            invalidate(view, reason) { invalidations.push({ view, reason }); },
        },
        toast(kind, key, vars) { toasts.push({ kind, key, vars }); },
        refresh(reason) { refreshes.push(reason); return Promise.resolve(); },
        results() { return results; },
        focus() { return 'taiwan'; },
        layers() { return layers; },
        saveLayers(next) { layers = next; },
        ask: overrides.ask || function () { return '理由'; },
        confirm: overrides.confirm || function () { return true; },
        now() { return NOW * 1000; },
        socketFactory: null,
    });
    return { doc, surfaces, sent, toasts, refreshes, invalidations,
             results, layersNow() { return layers; } };
}

function settle(times) {
    let p = Promise.resolve();
    for (let i = 0; i < (times || 6); i += 1) p = p.then(() => {});
    return p;
}

// ── rendering ────────────────────────────────────────────────────────────

test('renderAll writes every slot it owns', async () => {
    const h = harness();
    h.surfaces.renderAll(null);
    ['geo-freshness', 'geo-layers', 'geo-summary', 'geo-markers',
     'settings-freshness', 'settings-summary', 'settings-rows',
     'groundtruth-rows', 'mode-slot', 'live-slot'].forEach((id) => {
        assert.ok(h.doc.getElementById(id).innerHTML.length > 0, id);
    });
});

test('the geographic face shows the fired country and its role class', async () => {
    const h = harness();
    h.surfaces.renderGeo();
    const markers = h.doc.getElementById('geo-markers').innerHTML;
    assert.ok(markers.indexOf('TW') !== -1, markers);
    assert.ok(markers.indexOf('geo-role-target') !== -1, markers);
});

// P9 §3.4 / D-5. The list answered "where" with thirty ISO codes; the tile
// map answers it with a picture built from the SAME markers, so the two
// cannot disagree about what fired where.
test('the tile map draws the participant in its region block', async () => {
    const h = harness();
    h.surfaces.renderGeo();
    const tiles = h.doc.getElementById('geo-tilemap').innerHTML;
    assert.ok(tiles.indexOf('data-region="east_asia"') !== -1, tiles);
    assert.ok(tiles.indexOf('data-country="TW"') !== -1, tiles);
    assert.ok(tiles.indexOf('geo-role-target') !== -1, tiles);
});

test('the tile map and the marker list carry the same countries', async () => {
    const h = harness();
    h.surfaces.renderGeo();
    const tiles = h.doc.getElementById('geo-tilemap').innerHTML;
    // The list is in two elements — participants, then the off-roster rows —
    // and the tile map draws both, the second in the 配置未定義 row when the
    // placement table does not know the country.
    const list = h.doc.getElementById('geo-markers').innerHTML
        + h.doc.getElementById('geo-offroster').innerHTML;
    const of = (html) => (html.match(/data-country="([A-Z]+)"/g) || []).sort();
    assert.ok(of(tiles).length > 0, tiles);
    assert.deepStrictEqual(of(tiles), of(list),
        'the primary visual and the accessible representation disagree');
});

test('the unserved reference layer is listed with its reason', async () => {
    const h = harness();
    h.surfaces.renderGeo();
    const layersHtml = h.doc.getElementById('geo-layers').innerHTML;
    assert.ok(layersHtml.indexOf('geo-layer-unserved') !== -1, layersHtml);
    assert.ok(layersHtml.indexOf('座標') !== -1, layersHtml);
});

test('the settings table lists the key with its consumer', async () => {
    const h = harness();
    h.surfaces.renderSettings();
    const rows = h.doc.getElementById('settings-rows').innerHTML;
    assert.ok(rows.indexOf('SEQUENCE_WINDOW') !== -1, rows);
    assert.ok(rows.indexOf('v3.scoring.settings:resolve_settings') !== -1, rows);
});

test('the live chip reports unmounted for a deployment with no channel', async () => {
    const h = harness();
    h.surfaces.renderAll(null);
    const chip = h.doc.getElementById('live-slot').innerHTML;
    assert.ok(chip.indexOf('live-unmounted') !== -1, chip);
    assert.strictEqual(h.surfaces.live.view().connection, Live.UNMOUNTED);
});

// ── the settings command path ────────────────────────────────────────────

test('a save sends the parsed value with a reason and then refetches', async () => {
    const h = harness();
    h.doc._add({ 'data-setting-key': 'SEQUENCE_WINDOW' }).value = '43200';
    h.surfaces.saveSetting('SEQUENCE_WINDOW', null);
    await settle();
    assert.deepStrictEqual(h.sent, [{ verb: 'set', key: 'SEQUENCE_WINDOW',
                                      value: 43200, reason: '理由' }]);
    assert.ok(h.refreshes.indexOf('config_committed') !== -1, h.refreshes);
});

test('a save with no diff sends nothing', async () => {
    const h = harness();
    h.doc._add({ 'data-setting-key': 'SEQUENCE_WINDOW' }).value = '86400';
    h.surfaces.saveSetting('SEQUENCE_WINDOW', null);
    await settle();
    assert.deepStrictEqual(h.sent, []);
    assert.strictEqual(h.toasts[0].key, 'ui.settings.error.no_change');
});

test('a save the analyst declines to justify sends nothing', async () => {
    const h = harness({ ask() { return null; } });
    h.doc._add({ 'data-setting-key': 'SEQUENCE_WINDOW' }).value = '43200';
    h.surfaces.saveSetting('SEQUENCE_WINDOW', null);
    await settle();
    assert.deepStrictEqual(h.sent, []);
});

test('a save the analyst does not confirm sends nothing', async () => {
    const h = harness({ confirm() { return false; } });
    h.doc._add({ 'data-setting-key': 'SEQUENCE_WINDOW' }).value = '43200';
    h.surfaces.saveSetting('SEQUENCE_WINDOW', null);
    await settle();
    assert.deepStrictEqual(h.sent, []);
});

test('a ledger row that moved nothing is announced as such', async () => {
    const h = harness({ commandResult: ok({
        changed: false,
        effect: { config: { key: 'SEQUENCE_WINDOW', value: 86400,
                            source: 'default' } } }) });
    h.doc._add({ 'data-setting-key': 'SEQUENCE_WINDOW' }).value = '43200';
    h.surfaces.saveSetting('SEQUENCE_WINDOW', null);
    await settle();
    const last = h.toasts[h.toasts.length - 1];
    assert.strictEqual(last.key, 'ui.settings.result.recorded_no_effect');
    assert.strictEqual(last.kind, 'error');
});

test('clearing an override asks for a reason too', async () => {
    const h = harness();
    h.surfaces.clearSetting('SEQUENCE_WINDOW', null);
    await settle();
    assert.deepStrictEqual(h.sent, [{ verb: 'clear', key: 'SEQUENCE_WINDOW',
                                      reason: '理由' }]);
});

test('an unknown key is refused before any request', async () => {
    const h = harness();
    h.surfaces.saveSetting('DOES_NOT_EXIST', null);
    await settle();
    assert.deepStrictEqual(h.sent, []);
    assert.strictEqual(h.toasts[0].key, 'ui.settings.error.unknown_key');
});

// ── layer persistence (S1-UI-057) ────────────────────────────────────────

test('a layer toggle is written through the injected store', async () => {
    const h = harness();
    h.surfaces.bind();
    const target = h.doc._add({ 'data-geo-layer': 'anomalies' });
    h.doc._listeners.click({ target });
    assert.strictEqual(h.layersNow().anomalies, false);
    assert.strictEqual(h.layersNow().participants, true);
});

test('the unserved layer cannot be switched on through the DOM either', async () => {
    const h = harness();
    h.surfaces.bind();
    h.doc._listeners.click({ target: h.doc._add({ 'data-geo-layer': 'reference' }) });
    assert.strictEqual(h.layersNow().reference, false);
});

// ── the dim ──────────────────────────────────────────────────────────────

test('a focus change masks and both legs end it', async () => {
    const h = harness();
    h.surfaces.noteFocusChange('taiwan', false);
    assert.strictEqual(h.doc.getElementById('dim-overlay').hidden, false);
    assert.strictEqual(h.surfaces.dim.view().masked, true);
    h.surfaces.noteArrival(Dim.LEG_CONCLUSIONS);
    h.surfaces.noteArrival(Dim.LEG_LEDGER);
    assert.strictEqual(h.surfaces.dim.view().phase, Dim.ENDED);
});

test('a replay focus change does not mask', async () => {
    const h = harness();
    h.surfaces.noteFocusChange('taiwan', true);
    assert.strictEqual(h.surfaces.dim.view().masked, false);
});

test('any key releases a mask that has been left up', async () => {
    const h = harness();
    h.surfaces.bind();
    h.surfaces.noteFocusChange('taiwan', false);
    h.doc._listeners.keydown({});
    assert.strictEqual(h.surfaces.dim.view().masked, false);
});

test('the retry affordance refetches', async () => {
    const h = harness();
    h.surfaces.bind();
    h.doc._listeners.click({ target: h.doc._add({ 'data-dim-retry': '' }) });
    assert.ok(h.refreshes.indexOf('dim_retry') !== -1, h.refreshes);
});

// ── the display mode ─────────────────────────────────────────────────────

test('a critical row raises the banner element', async () => {
    const h = harness();
    h.surfaces.renderMode({ rows: [{ itemId: 'c-1', critical: true }],
                            suppressed: [], total: 1, empty: false,
                            emptyReason: null });
    assert.strictEqual(h.doc.getElementById('critical-banner').hidden, false);
    assert.strictEqual(h.doc.getElementById('stage-2').attrs['data-mode'],
                       Mode.CRITICAL_BANNER);
});

test('a quiet lane hides the banner', async () => {
    const h = harness();
    h.surfaces.renderMode({ rows: [], suppressed: [], total: 0, empty: true,
                            emptyReason: 'no_ranked_items' });
    assert.strictEqual(h.doc.getElementById('critical-banner').hidden, true);
});

// ── the live cue ─────────────────────────────────────────────────────────

test('an accepted push invalidates the right view and refetches', async () => {
    const h = harness();
    h.surfaces.renderAll(null);
    h.surfaces.live.configure({ websocket: { mounted: true } });
    // Feed a frame straight into the client's receiver: with no socket
    // factory there is no wire, and the routing is what is under test.
    h.surfaces.live._receive('42["attention_update",{"scenario_id":"taiwan"}]');
    assert.ok(h.invalidations.some((i) => i.view === 'lane'
                                          && i.reason === 'live_push'),
              JSON.stringify(h.invalidations));
    assert.ok(h.refreshes.indexOf('live_push') !== -1, h.refreshes);
});

test('a push for another scenario changes nothing', async () => {
    const h = harness();
    h.surfaces.renderAll(null);
    const before = h.refreshes.length;
    h.surfaces.live._receive('42["conclusion_update",{"scenario_id":"other"}]');
    assert.strictEqual(h.refreshes.length, before);
});

test('no push payload ever reaches the document', async () => {
    const h = harness();
    h.surfaces.renderAll(null);
    h.surfaces.live._receive(
        '42["conclusion_update",{"scenario_id":"taiwan",'
        + '"conclusions":[{"state":"SMUGGLED"}]}]');
    const everything = IDS.map((id) => h.doc.getElementById(id).innerHTML
                                       + h.doc.getElementById(id).textContent)
        .join('');
    assert.strictEqual(everything.indexOf('SMUGGLED'), -1);
});

run().then(() => {
    console.log(`\n\n${passed} passed, ${failed} failed`);
    if (failed > 0) {
        failures.forEach(({ name, error }) => {
            console.error(`\n  FAIL: ${name}`);
            console.error('  ' + (error.stack || error));
        });
        process.exit(1);
    }
    process.exit(0);
});
