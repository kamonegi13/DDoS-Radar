/**
 * Unit tests for v3/ui/lane.js — the attention lane.
 *
 * Run:  node tests/ui_v3/test_lane.js
 *
 * The two load-bearing tests here are:
 *   - `follows_the_ledger_rank_not_the_score`: the lane orders by the
 *     `rank_position` S8 wrote to the ledger, so the ordering an analyst
 *     acted on is the ordering the decision trail can replay (P5 O-8, G-03);
 *   - `nothing_can_be_silenced`: snoozed and dismissed rows stay counted on
 *     screen (S1-UI-032).
 */
'use strict';

const assert = require('assert');
const L = require('../../v3/ui/lane');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;

function row(overrides) {
    return Object.assign({
        snapshot_id: 'snap-1', computed_at: NOW,
        scenario_id: 'taiwan_contingency', item_kind: 'conclusion',
        item_id: 'c-1', rank_position: 1,
        score: 0.6, novelty: 1.0, confidence_delta: 0.75, analyst_blindness: 0.8,
        formula_ref: 'attention.score@1',
        narrative_template_ref: 'attention.row@1',
        narrative: '新規の attack_mode 結論。確信度が 0.75 上昇。',
        components: { last_fire_ts: NOW - 3600 },
        analyst_state: 'active', analyst_state_expires_at: null,
        analyst_state_at: null, suppressed: false,
    }, overrides || {});
}

function r6(rows, extra) {
    return Object.assign({
        attention: rows, snapshot_id: 'snap-1', computed_at: NOW,
        thresholds: { min_score: 0.05 },
        considered: rows.length, shown: rows.length,
        filtered_below_min_score: 0, empty_reason: null,
        formula_ref: 'attention.score@1',
        threshold_disclosure: {
            ATTENTION_DEFAULT_MIN_SCORE: { value: 0.05, unit: 'ratio', provenance_ref: 'AP1' },
        },
        narrative_templates: { 'attention.row@1': { template_id: 'attention.row' } },
    }, extra || {});
}

// ── ranking comes from the ledger ────────────────────────────────────────

test('follows_the_ledger_rank_not_the_score (P5 O-8 / G-03)', () => {
    // The score column deliberately disagrees with rank_position. If this
    // module ranked, it would sort c-hi first. It must not: the ledger's
    // position is what the decision trail replays.
    const lane = L.buildLane({
        attention: r6([
            row({ item_id: 'c-hi', rank_position: 3, score: 0.99 }),
            row({ item_id: 'c-mid', rank_position: 2, score: 0.10 }),
            row({ item_id: 'c-top', rank_position: 1, score: 0.20 }),
        ]),
    });
    assert.deepStrictEqual(lane.rows.map(r => r.itemId), ['c-top', 'c-mid', 'c-hi']);
});

test('rows arrive in any order and still come out in ledger order', () => {
    const lane = L.buildLane({
        attention: r6([
            row({ item_id: 'c', rank_position: 3 }),
            row({ item_id: 'a', rank_position: 1 }),
            row({ item_id: 'b', rank_position: 2 }),
        ]),
    });
    assert.deepStrictEqual(lane.rows.map(r => r.itemId), ['a', 'b', 'c']);
});

test('an unranked row sorts last and declares that its place is a fallback', () => {
    const lane = L.buildLane({
        attention: r6([
            row({ item_id: 'unranked', rank_position: null, score: 0.99 }),
            row({ item_id: 'ranked', rank_position: 9 }),
        ]),
    });
    assert.deepStrictEqual(lane.rows.map(r => r.itemId), ['ranked', 'unranked']);
    assert.strictEqual(lane.rows[1].rankFallback, true);
    assert.strictEqual(lane.rows[0].rankFallback, false);
});

test('equal ranks keep arrival order, so the lane is reproducible', () => {
    const lane = L.buildLane({
        attention: r6([
            row({ item_id: 'first', rank_position: 1 }),
            row({ item_id: 'second', rank_position: 1 }),
        ]),
    });
    assert.deepStrictEqual(lane.rows.map(r => r.itemId), ['first', 'second']);
});

// ── nothing can be silenced (S1-UI-032) ──────────────────────────────────

test('nothing_can_be_silenced: suppressed rows stay counted on screen', () => {
    const lane = L.buildLane({
        attention: r6([
            row({ item_id: 'a', rank_position: 1 }),
            row({ item_id: 'b', rank_position: 2, analyst_state: 'snoozed', suppressed: true }),
            row({ item_id: 'c', rank_position: 3, analyst_state: 'dismissed', suppressed: true }),
        ]),
    });
    assert.deepStrictEqual(lane.rows.map(r => r.itemId), ['a']);
    assert.strictEqual(lane.suppressedCount, 2);
    assert.strictEqual(lane.suppressedByState.snoozed, 1);
    assert.strictEqual(lane.suppressedByState.dismissed, 1);
    // and the rows themselves are still reachable, not discarded
    assert.deepStrictEqual(lane.suppressed.map(r => r.itemId), ['b', 'c']);
    assert.strictEqual(lane.total, 3);
});

test('an unknown analyst_state degrades to active rather than being trusted', () => {
    const lane = L.buildLane({
        attention: r6([row({ analyst_state: 'something_new' })]),
    });
    assert.strictEqual(lane.rows[0].analystState, 'active');
});

// ── Tier 0 cap ───────────────────────────────────────────────────────────

test('Tier 0 shows the cap and reports how many are below it', () => {
    const rows = [1, 2, 3, 4, 5, 6, 7].map(i => row({ item_id: 'c' + i, rank_position: i }));
    const lane = L.buildLane({ attention: r6(rows) });
    assert.strictEqual(lane.tier0.length, L.TIER0_ROWS);
    assert.strictEqual(lane.tier0Cap, L.TIER0_ROWS);
    assert.strictEqual(lane.hiddenBelowCap, 7 - L.TIER0_ROWS);
    assert.strictEqual(lane.rows.length, 7, 'Tier 1 still has all of them');
});

test('the cap is a display option, not a filter on the data', () => {
    const rows = [1, 2, 3].map(i => row({ item_id: 'c' + i, rank_position: i }));
    const lane = L.buildLane({ attention: r6(rows), tier0Rows: 1 });
    assert.strictEqual(lane.tier0.length, 1);
    assert.strictEqual(lane.rows.length, 3);
});

// ── narrative is the server's (P8 §5) ────────────────────────────────────

test('the row narrative is the server string, verbatim', () => {
    const lane = L.buildLane({ attention: r6([row({ narrative: 'サーバ生成の 1 行' })]) });
    assert.strictEqual(lane.rows[0].narrative, 'サーバ生成の 1 行');
    assert.strictEqual(lane.rows[0].narrativeMissingKey, null);
    assert.strictEqual(lane.rows[0].narrativeTemplateRef, 'attention.row@1');
});

test('a missing narrative is declared, never composed in the browser', () => {
    [null, '', undefined].forEach(bad => {
        const lane = L.buildLane({ attention: r6([row({ narrative: bad })]) });
        assert.strictEqual(lane.rows[0].narrative, null);
        assert.strictEqual(lane.rows[0].narrativeMissingKey, 'ui.lane.narrative.unsupplied');
    });
});

// ── ranking basis is always inspectable (AP1) ────────────────────────────

test('rankBasis exposes the three factors and the formula, not a sentence', () => {
    const lane = L.buildLane({ attention: r6([row()]) });
    const basis = L.rankBasis(lane.rows[0], lane);
    assert.strictEqual(basis.factors.novelty, 1.0);
    assert.strictEqual(basis.factors.confidence_delta, 0.75);
    assert.strictEqual(basis.factors.analyst_blindness, 0.8);
    assert.strictEqual(basis.formulaRef, 'attention.score@1');
    assert.strictEqual(basis.snapshotId, 'snap-1');
    assert.ok(basis.disclosure.ATTENTION_DEFAULT_MIN_SCORE);
});

test('a non-numeric factor reads as absent, not as zero', () => {
    const lane = L.buildLane({ attention: r6([row({ novelty: null, score: 'x' })]) });
    assert.strictEqual(lane.rows[0].factors.novelty, null);
    assert.strictEqual(lane.rows[0].score, null);
});

// ── empty states ─────────────────────────────────────────────────────────

test('an empty lane distinguishes "ranker has not run" from "nothing ranked"', () => {
    assert.strictEqual(
        L.buildLane({ attention: r6([], { empty_reason: 'ranker_has_not_run' }) })
            .emptyState.reasonKey,
        'empty.lane.reason_ranker_has_not_run');
    assert.strictEqual(
        L.buildLane({ attention: r6([], { empty_reason: 'all_rows_below_min_score' }) })
            .emptyState.reasonKey,
        'empty.lane.reason_all_rows_below_min_score');
    assert.strictEqual(L.buildLane({}).emptyState.reasonKey,
                       'empty.lane.reason_not_loaded');
});

// P9 §3.5: the reason must come from the server's state, and a state this
// build has no sentence for must be REPORTED as such rather than mapped onto
// the nearest sentence we happen to own. The old concatenation printed the
// raw key ("ui.lane.empty.whatever_the_server_said") on the analyst's screen.
test('an empty reason this build does not know is named, not guessed', () => {
    const state = L.buildLane({
        attention: r6([], { empty_reason: 'quarantined_by_operator' }),
    }).emptyState;
    assert.strictEqual(state.reasonKey, 'empty.reason.unrecognised');
    assert.strictEqual(state.reasonVars.reason, 'quarantined_by_operator');
    assert.strictEqual(state.roleKey, 'empty.lane.role');
    assert.strictEqual(state.fillsWhenKey, 'empty.lane.fills_when');
});

test('an empty lane says what it shows and what would fill it', () => {
    const state = L.buildLane({}).emptyState;
    assert.strictEqual(state.surface, 'lane');
    assert.strictEqual(state.roleKey, 'empty.lane.role');
    assert.strictEqual(state.fillsWhenKey, 'empty.lane.fills_when');
});

test('a lane whose rows are all suppressed is not "empty"', () => {
    const lane = L.buildLane({
        attention: r6([row({ analyst_state: 'snoozed', suppressed: true })]),
    });
    assert.strictEqual(lane.empty, false);
    assert.strictEqual(lane.emptyState, null);
    assert.strictEqual(lane.suppressedCount, 1);
});

test('the count that was filtered below min_score is carried, not hidden', () => {
    const lane = L.buildLane({
        attention: r6([row()], { filtered_below_min_score: 12, considered: 13 }),
    });
    assert.strictEqual(lane.filteredBelowMinScore, 12);
    assert.strictEqual(lane.considered, 13);
});

// ── purity ───────────────────────────────────────────────────────────────

test('buildLane does not mutate its input', () => {
    const input = { attention: r6([row(), row({ item_id: 'b', rank_position: 2 })]) };
    const before = JSON.stringify(input);
    L.buildLane(input);
    assert.strictEqual(JSON.stringify(input), before);
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
