/**
 * Unit tests for v3/ui/geo_tiles.js — the country-tile map (P9 §3.4).
 *
 * Run:  node tests/ui_v3/test_geo_tiles.js
 *
 * The load-bearing ones:
 *   - every scenario participant in this deployment has a cell. The
 *     expected set below is hand-copied from `geo_data.json`'s SCENARIOS
 *     rather than read from it, because a table checked against its own
 *     source cannot notice the source changing;
 *   - a country the placement table does not know is NEVER dropped — it
 *     lands in the 配置未定義 row (G-17). `GLOBAL` is the permanent example;
 *   - the tile carries what the marker carried, including the G-17 state
 *     word, and a suppressed row keeps its own dot kind (E-17);
 *   - there is no geography in the module. Placement is a design constant;
 *     a latitude would be the second reader of deployment data that
 *     `geo.js` refuses to become.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Tiles = require('../../v3/ui/geo_tiles');
const S = require('../../v3/ui/strings');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

/**
 * Every participant of every scenario in geo_data.json, measured once and
 * written down here:
 *
 *   taiwan_contingency  AU CN GU JP KR PH TW US
 *   eastern_europe      BY EE FI LT LV MD PL RO RU SK UA
 *   middle_east         IL IQ IR LB SA SY US YE
 *   korean_peninsula    CN JP KP KR US
 *   south_china_sea     CN JP MY PH TW US VN
 */
const PARTICIPANTS = [
    'AU', 'BY', 'CN', 'EE', 'FI', 'GU', 'IL', 'IQ', 'IR', 'JP', 'KP', 'KR',
    'LB', 'LT', 'LV', 'MD', 'MY', 'PH', 'PL', 'RO', 'RU', 'SA', 'SK', 'SY',
    'TW', 'UA', 'US', 'VN', 'YE',
];

function marker(country, overrides) {
    return Object.assign({
        country: country,
        role: 'primary_target',
        roleClass: 'target',
        roleKnown: true,
        weight: 1.0,
        isAdversary: false,
        isChainCountry: false,
        observations: 0,
        firedCount: 0,
        suppressedCount: 0,
        fired: [],
        suppressed: [],
        domains: [],
        sensors: [],
        stateKey: 'ui.geo.marker.unobserved',
    }, overrides || {});
}

// ── the placement table ──────────────────────────────────────────────────

test('every scenario participant has a placement', () => {
    const missing = PARTICIPANTS.filter((iso) => Tiles.placementOf(iso) === null);
    assert.deepStrictEqual(missing, [],
        `these participants have no cell and would vanish from the map: ${missing}`);
});

test('every placement names a region the map actually draws', () => {
    const regions = new Set(Tiles.REGIONS.map((r) => r.id));
    Object.keys(Tiles.PLACEMENTS).forEach((iso) => {
        const cell = Tiles.PLACEMENTS[iso];
        assert.ok(cell.region, `${iso} has no region`);
        assert.ok(regions.has(cell.region),
                  `${iso} sits in ${cell.region}, which is not a drawn region`);
        assert.ok(Number.isInteger(cell.col) && cell.col >= 1, iso);
        assert.ok(Number.isInteger(cell.row) && cell.row >= 1, iso);
    });
});

test('no two countries occupy the same cell', () => {
    const seen = new Map();
    Object.keys(Tiles.PLACEMENTS).forEach((iso) => {
        const cell = Tiles.PLACEMENTS[iso];
        const key = `${cell.region}:${cell.col}:${cell.row}`;
        assert.ok(!seen.has(key),
                  `${iso} overlaps ${seen.get(key)} at ${key}`);
        seen.set(key, iso);
    });
});

test('every region label is a real dictionary key', () => {
    Tiles.REGIONS.forEach((region) => {
        assert.ok(S.STRINGS[region.labelKey], region.labelKey);
    });
    assert.ok(S.STRINGS[Tiles.UNPLACED_LABEL_KEY]);
});

test('the placement table holds no geography', () => {
    const source = fs.readFileSync(
        path.join(__dirname, '..', '..', 'v3', 'ui', 'geo_tiles.js'), 'utf8');
    const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    ['lat:', 'lng', 'longitude', 'latitude'].forEach((token) => {
        assert.strictEqual(code.indexOf(token), -1,
            `${token} — the browser holds no coordinates (geo.js's ruling)`);
    });
});

// ── the flag ─────────────────────────────────────────────────────────────

test('the flag is derived from the ISO2, and a bad code costs nothing', () => {
    assert.strictEqual(Tiles.flagOf('JP'), '\u{1F1EF}\u{1F1F5}');
    assert.strictEqual(Tiles.flagOf('TW'), '\u{1F1F9}\u{1F1FC}');
    assert.strictEqual(Tiles.flagOf('GLOBAL'), '');
    assert.strictEqual(Tiles.flagOf('jp'), '');
    assert.strictEqual(Tiles.flagOf(null), '');
});

// ── building the map ─────────────────────────────────────────────────────

test('participants are placed in their region blocks', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('TW'), marker('JP'), marker('CN'), marker('US')],
    });
    const byId = {};
    map.regions.forEach((r) => { byId[r.id] = r; });
    assert.deepStrictEqual(Object.keys(byId).sort(),
                           ['east_asia', 'north_america']);
    assert.strictEqual(byId.east_asia.tiles.length, 3);
    assert.strictEqual(byId.north_america.tiles.length, 1);
    assert.strictEqual(map.placedCount, 4);
    assert.strictEqual(map.spilloverCount, 0);
});

test('a region with no participant is not drawn as an empty block', () => {
    const map = Tiles.buildTileMap({ markers: [marker('US')] });
    assert.deepStrictEqual(map.regions.map((r) => r.id), ['north_america']);
});

test('the region grid is sized from the cells it holds', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('CN'), marker('JP'), marker('TW')],
    });
    const east = map.regions[0];
    assert.strictEqual(east.id, 'east_asia');
    assert.strictEqual(east.columns, 3);   // JP sits in column 3
    assert.strictEqual(east.rows, 3);      // TW sits in row 3
});

test('a country with no placement lands in the spillover, never dropped', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('TW')],
        offRoster: [marker('GLOBAL', { role: null, roleClass: 'observer',
                                       roleKnown: false })],
    });
    assert.strictEqual(map.spillover.present, true);
    assert.deepStrictEqual(map.spillover.tiles.map((t) => t.country), ['GLOBAL']);
    assert.strictEqual(map.spillover.tiles[0].placed, false);
    assert.strictEqual(map.countryCount, 2);
});

test('an off-roster country the table DOES know is still placed', () => {
    // A participant list is not a coverage list (geo.js). A country observed
    // outside the scenario still belongs on the map where it lives.
    const map = Tiles.buildTileMap({
        markers: [marker('TW')],
        offRoster: [marker('VN', { role: null, roleClass: 'observer',
                                   roleKnown: false, firedCount: 1 })],
    });
    assert.strictEqual(map.spillover.present, false);
    const regions = map.regions.map((r) => r.id).sort();
    assert.deepStrictEqual(regions, ['east_asia', 'southeast_asia']);
});

// ── what a tile carries ──────────────────────────────────────────────────

test('a country with events carries one dot per domain that produced one', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('TW', {
            firedCount: 2, observations: 3, stateKey: 'ui.geo.marker.fired',
            fired: [{ sensor: 'a', domain: 'cyber' },
                    { sensor: 'b', domain: 'physical' }],
        })],
    });
    const tile = map.regions[0].tiles[0];
    assert.strictEqual(tile.hasEvents, true);
    assert.deepStrictEqual(tile.dots, [
        { domain: 'cyber', kind: 'fired' },
        { domain: 'physical', kind: 'fired' },
    ]);
});

test('a suppressed row keeps its own dot kind and is never counted as quiet', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('TW', {
            suppressedCount: 1, observations: 1,
            stateKey: 'ui.geo.marker.suppressed_only',
            suppressed: [{ sensor: 'a', domain: 'info', reason: 'muted' }],
        })],
    });
    const tile = map.regions[0].tiles[0];
    assert.strictEqual(tile.hasEvents, true);
    assert.deepStrictEqual(tile.dots, [{ domain: 'info', kind: 'suppressed' }]);
});

test('a domain that both fired and was suppressed gets one dot, the loud one', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('TW', {
            firedCount: 1, suppressedCount: 1, observations: 2,
            stateKey: 'ui.geo.marker.fired',
            fired: [{ sensor: 'a', domain: 'cyber' }],
            suppressed: [{ sensor: 'b', domain: 'cyber', reason: 'muted' }],
        })],
    });
    assert.deepStrictEqual(map.regions[0].tiles[0].dots,
                           [{ domain: 'cyber', kind: 'fired' }]);
});

test('a participant with no observation row has no dots and is not "quiet"', () => {
    const map = Tiles.buildTileMap({ markers: [marker('TW')] });
    const tile = map.regions[0].tiles[0];
    assert.deepStrictEqual(tile.dots, []);
    assert.strictEqual(tile.hasEvents, false);
    // The marker's own G-17 word, carried across rather than re-decided.
    assert.strictEqual(tile.stateKey, 'ui.geo.marker.unobserved');
});

test('the role, adversary and chain flags survive onto the tile', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('CN', { role: 'adversary', roleClass: 'adversary',
                                 isAdversary: true, isChainCountry: true })],
    });
    const tile = map.regions[0].tiles[0];
    assert.strictEqual(tile.roleClass, 'adversary');
    assert.strictEqual(tile.roleKey, 'ui.geo.role.adversary');
    assert.strictEqual(tile.isAdversary, true);
    assert.strictEqual(tile.isChainCountry, true);
});

test('a role the server did not send falls back to the unlisted label', () => {
    const map = Tiles.buildTileMap({
        markers: [marker('CN', { role: null, roleClass: 'observer',
                                 roleKnown: false })],
    });
    assert.strictEqual(map.regions[0].tiles[0].roleKey, 'ui.geo.role.unlisted');
});

test('an empty face produces an empty map rather than a grid of blanks', () => {
    const map = Tiles.buildTileMap({});
    assert.deepStrictEqual(map.regions, []);
    assert.strictEqual(map.spillover.present, false);
    assert.strictEqual(map.empty, true);
});

test('buildTileMap does not mutate its input', () => {
    const input = { markers: [marker('TW')], offRoster: [marker('GLOBAL')] };
    const before = JSON.stringify(input);
    Tiles.buildTileMap(input);
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
