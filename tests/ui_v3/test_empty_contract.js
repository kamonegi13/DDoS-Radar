/**
 * The empty-state contract, checked structurally (P9 §3.5 / diagnosis D-4).
 *
 * Run:  node tests/ui_v3/test_empty_contract.js
 *
 * S1-UI-008 forbade a blank screen and WP-4.2 obeyed it: every empty surface
 * said WHY it was empty. On the cold-start shadow that produced a page whose
 * every line was true and whose whole was useless — a first-time reader could
 * not learn from it what any of those places were FOR, or what would ever
 * make them fill. P9 §3.5 raises the requirement to three parts, and three
 * parts is the kind of rule that decays one surface at a time unless it is a
 * gate:
 *
 *   1. every `empty.<surface>.role` has a matching `.fills_when` and at
 *      least one `.reason_*`, and no orphan of any of the three exists;
 *   2. every surface the view models actually name has a full triple;
 *   3. the render path emits all three parts, for board, lane and geo.
 *
 * The third is the one that matters most: keys that exist and are never
 * rendered are exactly the shape of a check that verifies the surface
 * ADJACENT to its claim.
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const S = require('../../v3/ui/strings');
const Fmt = require('../../v3/ui/format');
const Render = require('../../v3/ui/render');
const Board = require('../../v3/ui/board');
const Lane = require('../../v3/ui/lane');
const Geo = require('../../v3/ui/geo');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const UI_DIR = path.join(__dirname, '..', '..', 'v3', 'ui');
const EMPTY_KEYS = Object.keys(S.STRINGS).filter((k) => k.indexOf('empty.') === 0);

function surfacesOf(suffix) {
    return new Set(EMPTY_KEYS
        .filter((key) => key.endsWith('.' + suffix))
        .map((key) => key.split('.')[1]));
}

// ── 1. the key families are complete ─────────────────────────────────────

test('there are empty-state families at all', () => {
    assert.ok(surfacesOf('role').size >= 8,
        `only ${surfacesOf('role').size} surfaces declare a role`);
});

test('every role has a fills_when, and every fills_when has a role', () => {
    const roles = surfacesOf('role');
    const fills = surfacesOf('fills_when');
    const missingFills = [...roles].filter((s) => !fills.has(s)).sort();
    const missingRoles = [...fills].filter((s) => !roles.has(s)).sort();
    assert.deepStrictEqual(missingFills, [],
        `these surfaces say what they are but not what would fill them: ${missingFills}`);
    assert.deepStrictEqual(missingRoles, [],
        `these surfaces say what would fill them but not what they are: ${missingRoles}`);
});

test('every surface with a role has at least one reason', () => {
    const reasons = new Set(EMPTY_KEYS
        .filter((key) => key.split('.')[2] && key.split('.')[2].indexOf('reason_') === 0)
        .map((key) => key.split('.')[1]));
    const without = [...surfacesOf('role')].filter((s) => !reasons.has(s)).sort();
    assert.deepStrictEqual(without, [],
        `these surfaces can be empty for no stated reason: ${without}`);
});

test('every empty key has a Japanese sentence behind it', () => {
    EMPTY_KEYS.forEach((key) => {
        const value = S.STRINGS[key];
        assert.ok(value && value.length > 8, `${key} is not a sentence: ${value}`);
    });
});

// The fallback for a surface whose server said nothing. P9 §3.5 forbids
// inventing a reason, so there has to be a sentence for having none.
test('there is a sentence for "the server did not say"', () => {
    assert.ok(S.STRINGS['empty.reason.unstated']);
    const state = Fmt.emptyState('board', null);
    assert.strictEqual(state.reasonKey, 'empty.reason.unstated');
    assert.strictEqual(state.reasonSupplied, false);
});

// ── 2. the surfaces the code names all have triples ──────────────────────

test('every surface named by a view model has a complete triple', () => {
    const named = new Set();
    fs.readdirSync(UI_DIR)
        .filter((name) => name.endsWith('.js'))
        .forEach((name) => {
            const source = fs.readFileSync(path.join(UI_DIR, name), 'utf8');
            const pattern = /emptyState\(\s*'([a-z_]+)'/g;
            let match = pattern.exec(source);
            while (match) {
                named.add(match[1]);
                match = pattern.exec(source);
            }
        });
    assert.ok(named.size >= 8, `only ${named.size} surfaces call emptyState`);
    named.forEach((surface) => {
        ['role', 'fills_when'].forEach((part) => {
            const key = 'empty.' + surface + '.' + part;
            assert.ok(S.STRINGS[key],
                `${surface} is rendered but has no ${part} (${key})`);
        });
    });
});

test('every reason key a view model passes is defined', () => {
    fs.readdirSync(UI_DIR)
        .filter((name) => name.endsWith('.js') && name !== 'strings.js')
        .forEach((name) => {
            const source = fs.readFileSync(path.join(UI_DIR, name), 'utf8');
            const pattern = /'(empty\.[a-z_]+\.(?:reason_[a-z_]+|unstated|unrecognised))'/g;
            let match = pattern.exec(source);
            while (match) {
                assert.ok(S.STRINGS[match[1]],
                    `${name} references ${match[1]}, which is not defined`);
                match = pattern.exec(source);
            }
        });
});

// ── 3. the render path emits all three ───────────────────────────────────

function assertThreeParts(markup, label) {
    ['empty-role', 'empty-reason', 'empty-fills'].forEach((part) => {
        assert.ok(markup.indexOf('class="' + part + '"') !== -1,
            `${label} is missing its ${part}: ${markup}`);
    });
}

test('the board render path emits role, reason and fills_when', () => {
    const board = Board.buildBoard({});
    assert.strictEqual(board.empty, true);
    const markup = Render.emptyStateHtml(board.emptyState);
    assertThreeParts(markup, 'board');
    assert.ok(markup.indexOf(S.STRINGS['empty.board.role']) !== -1);
    assert.ok(markup.indexOf(S.STRINGS['empty.board.reason_not_loaded']) !== -1);
    assert.ok(markup.indexOf(S.STRINGS['empty.board.fills_when']) !== -1);
});

test('the lane render path emits all three inside a list item', () => {
    const lane = Lane.buildLane({});
    const markup = Render.emptyStateHtml(lane.emptyState, { tag: 'li' });
    assertThreeParts(markup, 'lane');
    assert.ok(markup.indexOf('<li') === 0, markup);
});

test('the geographic face emits all three', () => {
    const face = Geo.buildFace({ scenarios: null, evidence: null,
                                 scenarioId: null });
    const markup = Render.emptyStateHtml(face.emptyState);
    assertThreeParts(markup, 'geo');
    assert.ok(markup.indexOf(S.STRINGS['empty.geo.reason_no_focus']) !== -1);
});

test('a table cell wrapper spans the table rather than one column', () => {
    const markup = Render.emptyStateHtml(
        Fmt.emptyState('sensors', 'empty.sensors.reason_none'),
        { tag: 'tr', colspan: 6 });
    assertThreeParts(markup, 'sensors');
    assert.ok(markup.indexOf('colspan="6"') !== -1, markup);
    assert.ok(markup.indexOf('<tr') === 0, markup);
});

test('an unrecognised server reason renders WITH the server word', () => {
    const lane = Lane.buildLane({
        attention: { attention: [], empty_reason: 'quarantined_by_operator' },
    });
    const markup = Render.emptyStateHtml(lane.emptyState, { tag: 'li' });
    assertThreeParts(markup, 'lane/unrecognised');
    assert.ok(markup.indexOf('quarantined_by_operator') !== -1, markup);
});

test('the three parts always render in the contract order', () => {
    const markup = Render.emptyStateHtml(Board.buildBoard({}).emptyState);
    const role = markup.indexOf('empty-role');
    const reason = markup.indexOf('empty-reason');
    const fills = markup.indexOf('empty-fills');
    assert.ok(role < reason && reason < fills,
        `role → reason → fills is the reading order: ${markup}`);
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
