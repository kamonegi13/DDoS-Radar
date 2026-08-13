/**
 * Unit tests for v3/ui/board_map.js — the situation view's scenario map
 * (P9 §2.2 R-F, diagnosis D-10).
 *
 * Run:  node tests/ui_v3/test_board_map.js
 *
 * The load-bearing ones:
 *   - the dominance comparison happens in SEVERITY space, never TL space.
 *     TL 2 beats TL 4 because 2 is worse — read it as "4 > 2" and the map
 *     paints the calmer scenario, which is the 2026-08-02 inversion again;
 *   - a scenario with no measured TL never wins dominance over a measured
 *     one, and a country whose every scenario is unmeasured paints as
 *     unknown rather than as calm (G-17);
 *   - a country in several scenarios keeps ALL its memberships — the tile
 *     folds nothing away, it only chooses a paint colour;
 *   - a country the placement table does not know lands in the spillover
 *     row, never on the floor;
 *   - determinism (AP2): the same rows produce the same tiles, and ties
 *     break on scenario id.
 */
'use strict';

const assert = require('assert');
const BoardMap = require('../../v3/ui/board_map');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

function scenario(id, overrides) {
    return Object.assign({
        scenario_id: id,
        display_name_ja: null,
        participants: {},
        roles: {},
        adversaries: [],
        threat_level: null,
        focused: false,
    }, overrides || {});
}

function tileOf(map, country) {
    const everywhere = map.regions.reduce(
        (all, region) => all.concat(region.tiles),
        []).concat(map.spillover.tiles);
    return everywhere.find(tile => tile.country === country) || null;
}

// ── the empty states ────────────────────────────────────────────────────

test('no input at all says the ledger has not arrived', () => {
    const map = BoardMap.buildBoardMap({ scenarios: null });
    assert.strictEqual(map.empty, true);
    assert.strictEqual(map.emptyState.reasonKey,
                       'empty.board_map.reason_not_loaded');
    assert.strictEqual(map.emptyState.roleKey, 'empty.board_map.role');
    assert.strictEqual(map.emptyState.fillsWhenKey,
                       'empty.board_map.fills_when');
});

test('an empty scenario list says no scenario is configured', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [] });
    assert.strictEqual(map.empty, true);
    assert.strictEqual(map.emptyState.reasonKey,
                       'empty.board_map.reason_no_scenarios');
});

// ── dominance is a severity comparison ──────────────────────────────────

test('TL 2 beats TL 4 — severity space, not TL space', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('calm_one', { participants: { JP: 0.5 }, threat_level: 4 }),
        scenario('hot_one', { participants: { JP: 0.9 }, threat_level: 2 }),
    ] });
    const tile = tileOf(map, 'JP');
    assert.strictEqual(tile.dominant.scenarioId, 'hot_one');
    assert.strictEqual(tile.band, 'severe');
});

test('a measured scenario always beats an unmeasured one', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('silent', { participants: { TW: 1.0 }, threat_level: null }),
        scenario('measured', { participants: { TW: 1.0 }, threat_level: 5 }),
    ] });
    const tile = tileOf(map, 'TW');
    assert.strictEqual(tile.dominant.scenarioId, 'measured');
});

test('every scenario unmeasured paints unknown, never calm', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('a', { participants: { TW: 1.0 }, threat_level: null }),
        scenario('b', { participants: { TW: 0.4 }, threat_level: null }),
    ] });
    const tile = tileOf(map, 'TW');
    assert.strictEqual(tile.dominant, null);
    assert.strictEqual(tile.band, 'unknown');
});

test('a severity tie breaks on scenario id, reproducibly', () => {
    const rows = [
        scenario('zulu', { participants: { US: 1.0 }, threat_level: 3 }),
        scenario('alpha', { participants: { US: 1.0 }, threat_level: 3 }),
    ];
    const first = tileOf(BoardMap.buildBoardMap({ scenarios: rows }), 'US');
    const again = tileOf(BoardMap.buildBoardMap(
        { scenarios: rows.slice().reverse() }), 'US');
    assert.strictEqual(first.dominant.scenarioId, 'alpha');
    assert.strictEqual(again.dominant.scenarioId, 'alpha');
});

// ── memberships are kept whole ──────────────────────────────────────────

test('a country in three scenarios carries all three', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('a', { participants: { US: 1.0 }, threat_level: 4 }),
        scenario('b', { participants: { US: 0.5 }, threat_level: 2 }),
        scenario('c', { participants: { US: 0.2 }, threat_level: null }),
    ] });
    const tile = tileOf(map, 'US');
    assert.strictEqual(tile.membershipCount, 3);
    assert.deepStrictEqual(tile.scenarioIds, ['b', 'a', 'c']);
    assert.strictEqual(tile.memberships[2].severity, null);
});

test('the display name rides along, id as its fallback', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('named', { participants: { JP: 1.0 }, threat_level: 3,
                            display_name_ja: '台湾正面' }),
        scenario('nameless', { participants: { JP: 0.2 }, threat_level: 4 }),
    ] });
    const tile = tileOf(map, 'JP');
    assert.strictEqual(tile.memberships[0].displayName, '台湾正面');
    assert.strictEqual(tile.memberships[1].displayName, 'nameless');
});

// ── adversary and focus marks ───────────────────────────────────────────

test('the adversary mark means "attacking side in ANY scenario"', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('a', { participants: { CN: 1.0, TW: 1.0 },
                        adversaries: ['CN'], threat_level: 4 }),
        scenario('b', { participants: { CN: 0.3 }, threat_level: 5 }),
    ] });
    assert.strictEqual(tileOf(map, 'CN').isAdversary, true);
    assert.strictEqual(tileOf(map, 'TW').isAdversary, false);
});

test('a tile with a focused membership says so', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('f', { participants: { TW: 1.0 }, threat_level: 4,
                        focused: true }),
        scenario('g', { participants: { US: 1.0 }, threat_level: 4 }),
    ] });
    assert.strictEqual(tileOf(map, 'TW').hasFocused, true);
    assert.strictEqual(tileOf(map, 'US').hasFocused, false);
});

// ── placement and spillover ─────────────────────────────────────────────

test('placed countries land in their region, unknown ones spill (G-17)', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('a', { participants: { TW: 1.0, ZZ: 0.5 }, threat_level: 3 }),
    ] });
    const east = map.regions.find(region => region.id === 'east_asia');
    assert.ok(east.tiles.some(tile => tile.country === 'TW'));
    assert.strictEqual(map.spillover.present, true);
    assert.ok(map.spillover.tiles.some(tile => tile.country === 'ZZ'));
    assert.strictEqual(map.countryCount, 2);
});

test('a region with no participant is not rendered as an empty block', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('a', { participants: { TW: 1.0 }, threat_level: 3 }),
    ] });
    assert.ok(map.regions.every(region => region.tiles.length > 0));
});

test('lower-case country codes are folded to upper before placement', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('a', { participants: { tw: 1.0 }, threat_level: 3 }),
    ] });
    const tile = tileOf(map, 'TW');
    assert.ok(tile);
    assert.strictEqual(tile.placed, true);
});

// ── scale facts for the lead line ───────────────────────────────────────

test('the model counts scenarios and countries', () => {
    const map = BoardMap.buildBoardMap({ scenarios: [
        scenario('a', { participants: { TW: 1.0, JP: 0.5 }, threat_level: 3 }),
        scenario('b', { participants: { JP: 1.0 }, threat_level: 4 }),
    ] });
    assert.strictEqual(map.scenarioCount, 2);
    assert.strictEqual(map.countryCount, 2);
});

// ── report ──────────────────────────────────────────────────────────────

process.stdout.write('\n');
failures.forEach(({ name, error }) => {
    console.error(`FAIL ${name}\n  ${error.message}`);
});
console.log(`${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
