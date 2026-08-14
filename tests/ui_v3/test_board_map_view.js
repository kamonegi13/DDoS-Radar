/**
 * Unit tests for v3/ui/board_map_view.js — the real map, injectable.
 *
 * Run:  node tests/ui_v3/test_board_map_view.js
 *
 * The load-bearing ones:
 *   - no Leaflet → the tile-grid fallback is written, never a blank pane
 *     (S1-UI-008);
 *   - with Leaflet → one map instance across renders (recreating would
 *     re-fetch tiles and yank the viewport), markers cleared and refilled
 *     per render, fitBounds once;
 *   - a country without a centroid is REPORTED, not dropped (G-17);
 *   - an empty model tears the map down and shows the empty triple.
 */
'use strict';

const assert = require('assert');
const View = require('../../v3/ui/board_map_view');
const Coords = require('../../v3/ui/map_coords');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

function fakeNode() {
    return {
        innerHTML: '',
        classes: {},
        classList: {
            add(name) { this._owner.classes[name] = true; },
            remove(name) { delete this._owner.classes[name]; },
        },
    };
}

function fakeDoc(node) {
    return { getElementById: (id) => (id === 'board-map' ? node : null) };
}

function fakeLeaflet(log) {
    const layerGroup = {
        layers: [],
        clearLayers() { log.push('clearLayers'); this.layers = []; },
        addLayer(m) { this.layers.push(m); },
        addTo() { return this; },
    };
    const map = {
        removed: false,
        remove() { this.removed = true; log.push('map.remove'); },
        fitBounds(bounds) { log.push(['fitBounds', bounds.length]); },
    };
    return {
        _layerGroup: layerGroup,
        _map: map,
        mapCalls: 0,
        map(node, opts) { this.mapCalls += 1; log.push('map.create'); return map; },
        tileLayer(url, opts) {
            log.push(['tileLayer', url]);
            return { addTo() { return this; } };
        },
        layerGroup() { return layerGroup; },
        marker(at, opts) { return { at, opts }; },
        divIcon(spec) { return spec; },
    };
}

function tile(country, overrides) {
    return Object.assign({
        country,
        flag: '',
        band: 'high',
        cssVar: '--color-warning',
        scenarioIds: ['a'],
        memberships: [],
        membershipCount: 1,
        isAdversary: false,
        hasFocused: false,
    }, overrides || {});
}

function model(tiles, spilloverTiles) {
    return {
        empty: false,
        regions: [{ id: 'r', labelKey: 'k', tiles: tiles, columns: 1, rows: 1 }],
        spillover: { present: !!(spilloverTiles || []).length,
                     tiles: spilloverTiles || [] },
    };
}

function build(leaflet) {
    const node = fakeNode();
    node.classList._owner = node;
    const view = View.createBoardMapView({
        doc: fakeDoc(node),
        leaflet,
        containerId: 'board-map',
        coords: Coords,
        markerHtml: (t) => `<div data-marker="${t.country}"></div>`,
        fallbackHtml: () => '<ul class="fallback-grid"></ul>',
        emptyHtml: () => '<p class="empty-triple"></p>',
    });
    return { node, view };
}

// ── no Leaflet: the honest fallback ─────────────────────────────────────

test('without Leaflet the tile grid is written, never a blank pane', () => {
    const { node, view } = build(null);
    const outcome = view.render(model([tile('TW')]));
    assert.strictEqual(outcome.mode, 'fallback');
    assert.ok(/fallback-grid/.test(node.innerHTML));
});

// ── with Leaflet ────────────────────────────────────────────────────────

test('one map instance across renders; markers refill each time', () => {
    const log = [];
    const L = fakeLeaflet(log);
    const { view } = build(L);
    view.render(model([tile('TW'), tile('JP')]));
    view.render(model([tile('TW')]));
    assert.strictEqual(L.mapCalls, 1);
    assert.strictEqual(log.filter(e => e === 'clearLayers').length, 2);
    assert.strictEqual(L._layerGroup.layers.length, 1);
});

test('fitBounds runs once — a redraw must not yank the viewport', () => {
    const log = [];
    const L = fakeLeaflet(log);
    const { view } = build(L);
    view.render(model([tile('TW'), tile('JP')]));
    view.render(model([tile('TW'), tile('JP')]));
    assert.strictEqual(
        log.filter(e => Array.isArray(e) && e[0] === 'fitBounds').length, 1);
});

test('a country with no centroid is reported, never dropped (G-17)', () => {
    const L = fakeLeaflet([]);
    const { view } = build(L);
    const outcome = view.render(model([tile('TW')], [tile('GLOBAL')]));
    assert.strictEqual(outcome.markers, 1);
    assert.deepStrictEqual(outcome.unplaced, ['GLOBAL']);
});

test('the tile source is CARTO dark WITHOUT its labels', () => {
    // Seventh review: the basemap's own country names collided with the
    // observation counts. Our markers carry the names; the ground is quiet.
    assert.ok(/basemaps\.cartocdn\.com\/dark_nolabels/.test(View.TILE_URL));
});

// ── empty model ─────────────────────────────────────────────────────────

test('an empty model tears the map down and shows the empty triple', () => {
    const log = [];
    const L = fakeLeaflet(log);
    const { node, view } = build(L);
    view.render(model([tile('TW')]));
    const outcome = view.render({ empty: true, emptyState: {} });
    assert.strictEqual(outcome.mode, 'empty');
    assert.ok(/empty-triple/.test(node.innerHTML));
    assert.ok(log.indexOf('map.remove') !== -1);
    // And a render after the teardown builds a fresh map.
    view.render(model([tile('TW')]));
    assert.strictEqual(L.mapCalls, 2);
});

test('a missing container answers absent rather than throwing', () => {
    const view = View.createBoardMapView({
        doc: { getElementById: () => null },
        leaflet: null, coords: Coords,
        markerHtml: () => '', fallbackHtml: () => '', emptyHtml: () => '',
    });
    assert.strictEqual(view.render(model([tile('TW')])).mode, 'absent');
});

// ── report ──────────────────────────────────────────────────────────────

process.stdout.write('\n');
failures.forEach(({ name, error }) => {
    console.error(`FAIL ${name}\n  ${error.message}`);
});
console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
