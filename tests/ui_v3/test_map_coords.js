/**
 * Unit tests for v3/ui/map_coords.js — the display-only centroid table.
 *
 * Run:  node tests/ui_v3/test_map_coords.js
 *
 * The load-bearing one is the drift watch. geo.js refused a latitude
 * table in the browser because it would be "a second reader of
 * deployment data that the backend could not watch drift" — P9 §1.3
 * amends that ruling by MOVING THE WATCH HERE: every entry is compared
 * against geo_data.json's COUNTRY_COORDS, so the two tables cannot
 * diverge without a red build.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const Coords = require('../../v3/ui/map_coords');
const Tiles = require('../../v3/ui/geo_tiles');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const geoData = JSON.parse(fs.readFileSync(
    path.join(__dirname, '..', '..', 'geo_data.json'), 'utf8'));
const AUTHORITY = geoData.COUNTRY_COORDS || {};

test('every entry matches geo_data.json COUNTRY_COORDS exactly (the drift watch)', () => {
    Object.keys(Coords.COORDS).forEach((iso2) => {
        const ours = Coords.COORDS[iso2];
        const theirs = AUTHORITY[iso2];
        assert.ok(theirs,
            `${iso2} is in map_coords.js but not in geo_data.json`);
        assert.strictEqual(ours[0], theirs.lat,
            `${iso2} lat drifted: ui ${ours[0]} vs geo_data ${theirs.lat}`);
        assert.strictEqual(ours[1], theirs.lng,
            `${iso2} lng drifted: ui ${ours[1]} vs geo_data ${theirs.lng}`);
    });
});

test('every placed country of the tile table has a centroid', () => {
    Object.keys(Tiles.PLACEMENTS).forEach((iso2) => {
        assert.ok(Coords.coordsOf(iso2),
            `${iso2} has a tile cell but no centroid — it would fall off `
            + 'the real map while staying on the fallback grid');
    });
});

test('coordsOf answers null for the unknown, never a guess', () => {
    assert.strictEqual(Coords.coordsOf('ZZ'), null);
    assert.strictEqual(Coords.coordsOf('GLOBAL'), null);
});

test('latitudes and longitudes are within range', () => {
    Object.keys(Coords.COORDS).forEach((iso2) => {
        const [lat, lng] = Coords.COORDS[iso2];
        assert.ok(lat >= -90 && lat <= 90, `${iso2} lat ${lat}`);
        assert.ok(lng >= -180 && lng <= 180, `${iso2} lng ${lng}`);
    });
});

process.stdout.write('\n');
failures.forEach(({ name, error }) => {
    console.error(`FAIL ${name}\n  ${error.message}`);
});
console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
