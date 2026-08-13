/**
 * Unit tests for v3/ui/board.js — the Tier 0 situation board.
 *
 * Run:  node tests/ui_v3/test_board.js
 */
'use strict';

const assert = require('assert');
const B = require('../../v3/ui/board');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;

function scenario(overrides) {
    return Object.assign({
        scenario_id: 'taiwan_contingency',
        participants: { TW: 1.0, US: 0.6 },
        adversaries: ['CN'],
        focused: true,
        roles: { TW: 'primary_target', US: 'primary_ally' },
        chain_country: null,
        threat_level: 3,
        threat_level_24h_ago: 4,
        severity_delta_24h: 1,
        observed_at: NOW - 60,
        score: 4.2,
        scoring_mode: 'full',
        in_null_zone: false,
        never_observed: false,
    }, overrides || {});
}

function r1(scenarios, focused) {
    return {
        scenarios: scenarios,
        scenario_count: scenarios.length,
        focused_scenario: focused === undefined ? 'taiwan_contingency' : focused,
        focus_source: 'command_log',
    };
}

function perDomainConclusion(overrides) {
    return Object.assign({
        id: 'c-pd', conclusion_type: 'per_domain',
        state: 'cyber=ACTIVE;physical=STABLE;info=ELEVATED',
        conclusion_unavailable_reason: null,
        threshold_ref: { magnitude_denom: 10.0, active_floor: 1.0 },
        metadata: {
            domain_scores: { cyber: 5.0, physical: 0.0, info: 2.5 },
            domain_states: { cyber: 'ACTIVE', physical: 'STABLE', info: 'ELEVATED' },
        },
    }, overrides || {});
}

function r2(conclusions) {
    return { scenario_id: 'taiwan_contingency', conclusions: conclusions || [] };
}

// ── ordering (S1-UI-051) ─────────────────────────────────────────────────

test('the focused scenario is first unconditionally', () => {
    const board = B.buildBoard({
        scenarios: r1([
            scenario({ scenario_id: 'b', severity_delta_24h: 4 }),
            scenario({ scenario_id: 'taiwan_contingency', severity_delta_24h: 0 }),
        ]),
    });
    assert.strictEqual(board.cards[0].scenarioId, 'taiwan_contingency');
    assert.strictEqual(board.cards[0].focused, true);
});

test('the rest sort by how much moved, largest absolute delta first', () => {
    const board = B.buildBoard({
        scenarios: r1([
            scenario({ scenario_id: 'a', severity_delta_24h: 1 }),
            scenario({ scenario_id: 'b', severity_delta_24h: -3 }),
            scenario({ scenario_id: 'c', severity_delta_24h: 2 }),
        ], null),
    });
    assert.deepStrictEqual(board.cards.map(c => c.scenarioId), ['b', 'c', 'a']);
});

test('a scenario with no delta sorts last, not as zero', () => {
    const board = B.buildBoard({
        scenarios: r1([
            scenario({ scenario_id: 'a', severity_delta_24h: null }),
            scenario({ scenario_id: 'b', severity_delta_24h: 0 }),
        ], null),
    });
    assert.deepStrictEqual(board.cards.map(c => c.scenarioId), ['b', 'a']);
});

test('ties break on scenario id so the order is reproducible', () => {
    const board = B.buildBoard({
        scenarios: r1([
            scenario({ scenario_id: 'z', severity_delta_24h: 2 }),
            scenario({ scenario_id: 'a', severity_delta_24h: 2 }),
        ], null),
    });
    assert.deepStrictEqual(board.cards.map(c => c.scenarioId), ['a', 'z']);
});

// ── the DEFCON direction ─────────────────────────────────────────────────

test('a positive severity delta reads as escalation on the card', () => {
    const board = B.buildBoard({ scenarios: r1([scenario({ severity_delta_24h: 2 })]) });
    assert.strictEqual(board.cards[0].trend.direction, 'escalating');
});

test('TL improving from 3 to 4 is a de-escalation since last check', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ threat_level: 4 })]),
        lastSeen: { taiwan_contingency: { threat_level: 3, at: NOW - 3600 } },
    });
    const since = board.cards[0].sinceLastCheck;
    assert.strictEqual(since.seen, true);
    assert.strictEqual(since.severityDelta, -1);
    assert.strictEqual(since.labelKey, 'ui.board.since.improved');
});

test('TL worsening from 4 to 2 is reported as worsened by two severity steps', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ threat_level: 2 })]),
        lastSeen: { taiwan_contingency: { threat_level: 4, at: NOW - 3600 } },
    });
    assert.strictEqual(board.cards[0].sinceLastCheck.severityDelta, 2);
    assert.strictEqual(board.cards[0].sinceLastCheck.labelKey, 'ui.board.since.worsened');
});

test('a first sighting is declared, never reported as "unchanged"', () => {
    const board = B.buildBoard({ scenarios: r1([scenario()]), lastSeen: {} });
    const since = board.cards[0].sinceLastCheck;
    assert.strictEqual(since.seen, false);
    assert.strictEqual(since.severityDelta, null);
    assert.strictEqual(since.labelKey, 'ui.board.since.first_sighting');
});

test('rememberSeen records what was shown, immutably, and skips absences', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario(), scenario({ scenario_id: 'b', threat_level: null })], null),
    });
    const before = {};
    const after = B.rememberSeen(before, board.cards, NOW);
    assert.deepStrictEqual(before, {}, 'input must not be mutated');
    assert.deepStrictEqual(after.taiwan_contingency, { threat_level: 3, at: NOW });
    assert.strictEqual(after.b, undefined, 'a null TL is never remembered');
});

// ── availability (O-7) ───────────────────────────────────────────────────

test('a null-zone scenario is marked inconclusive on the card', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ in_null_zone: true, threat_level: null })]),
    });
    assert.strictEqual(board.cards[0].availability.state, 'inconclusive');
    assert.strictEqual(board.cards[0].tl.band, 'unknown');
});

test('never-observed is distinct from inconclusive', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ never_observed: true, threat_level: null })]),
    });
    assert.strictEqual(board.cards[0].availability.state, 'never_observed');
});

test('a missing TL is inconclusive, never a calm band', () => {
    const board = B.buildBoard({ scenarios: r1([scenario({ threat_level: null })]) });
    assert.strictEqual(board.cards[0].availability.state, 'inconclusive');
    assert.notStrictEqual(board.cards[0].tl.band, 'normal');
});

// ── domain mini-bar ──────────────────────────────────────────────────────

test('the focused card carries the domain bar from the per_domain conclusion', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario()]),
        conclusions: r2([perDomainConclusion()]),
    });
    const d = board.cards[0].domains;
    assert.deepStrictEqual(d.domains.map(x => x.domain), ['cyber', 'physical', 'info']);
    assert.strictEqual(d.domains[0].state, 'ACTIVE');
    assert.strictEqual(d.domains[0].fill, 0.5);         // 5.0 / 10.0
});

test('the bar denominator comes from the conclusion, not from this file', () => {
    const c = perDomainConclusion();
    c.threshold_ref = { magnitude_denom: 20.0 };
    const board = B.buildBoard({ scenarios: r1([scenario()]), conclusions: r2([c]) });
    assert.strictEqual(board.cards[0].domains.denominator, 20.0);
    assert.strictEqual(board.cards[0].domains.domains[0].fill, 0.25);
    assert.strictEqual(board.cards[0].domains.denominatorSource,
        'R2:conclusion.threshold_ref.magnitude_denom');
});

test('with no disclosed denominator the bar has no fill rather than a guess', () => {
    const c = perDomainConclusion();
    c.threshold_ref = {};
    const board = B.buildBoard({ scenarios: r1([scenario()]), conclusions: r2([c]) });
    assert.strictEqual(board.cards[0].domains.denominator, null);
    board.cards[0].domains.domains.forEach(d => assert.strictEqual(d.fill, null));
    // the state word still colours it — that never depended on a number
    assert.strictEqual(board.cards[0].domains.domains[0].state, 'ACTIVE');
});

test('an unrecognised domain state word maps to a neutral key (S1-UI-023)', () => {
    const c = perDomainConclusion();
    c.metadata.domain_states = { cyber: 'BRAND_NEW_WORD', physical: null, info: 'STABLE' };
    const board = B.buildBoard({ scenarios: r1([scenario()]), conclusions: r2([c]) });
    const bars = board.cards[0].domains.domains;
    assert.strictEqual(bars[0].stateKey, 'ui.domain.state.BRAND_NEW_WORD');
    assert.strictEqual(bars[1].stateKey, 'ui.domain.state.unknown');
});

test('an unavailable per_domain conclusion supplies no bar', () => {
    const c = perDomainConclusion({ conclusion_unavailable_reason: 'insufficient_data' });
    const board = B.buildBoard({ scenarios: r1([scenario()]), conclusions: r2([c]) });
    assert.strictEqual(board.cards[0].domains, null);
});

// ── background self-declaration (S1-UI-053) ──────────────────────────────

test('background cards declare their limited coverage and carry no bar', () => {
    const board = B.buildBoard({
        scenarios: r1([
            scenario(),
            scenario({ scenario_id: 'other', scoring_mode: 'lite', severity_delta_24h: 0 }),
        ]),
        conclusions: r2([perDomainConclusion()]),
    });
    const bg = board.cards.filter(c => !c.focused)[0];
    assert.strictEqual(bg.coverage.limited, true);
    assert.strictEqual(bg.coverage.scoringMode, 'lite');
    assert.strictEqual(bg.coverage.labelKey, 'ui.board.coverage.limited');
    assert.strictEqual(bg.domains, null, 'a background card must not borrow the focused bar');
});

test('the focused card declares full coverage', () => {
    const board = B.buildBoard({ scenarios: r1([scenario()]) });
    assert.strictEqual(board.cards[0].coverage.limited, false);
});

// ── empty states (no blank screens) ──────────────────────────────────────

test('an empty board says why it is empty', () => {
    assert.strictEqual(B.buildBoard({ scenarios: r1([], null) }).emptyKey,
        'ui.board.empty.no_scenarios');
    assert.strictEqual(B.buildBoard({}).emptyKey, 'ui.board.empty.not_loaded');
    assert.strictEqual(B.buildBoard({}).empty, true);
});

test('focus source is carried through so "who chose this focus" is visible', () => {
    const board = B.buildBoard({ scenarios: r1([scenario()]) });
    assert.strictEqual(board.focusSource, 'command_log');
    assert.strictEqual(board.focusedScenario, 'taiwan_contingency');
});

// ── the situation sentence (P9 R-A) ──────────────────────────────────────

test('the summary is the server sentence, verbatim', () => {
    const envelope = r1([scenario()]);
    envelope.board_summary = { text: '監視中 2 件のうち変化は 0 件。',
                               template_ref: 'board.summary@1', inputs: {} };
    const board = B.buildBoard({ scenarios: envelope });
    assert.strictEqual(board.summary.supplied, true);
    assert.strictEqual(board.summary.text, '監視中 2 件のうち変化は 0 件。');
    assert.strictEqual(board.summary.templateRef, 'board.summary@1');
    assert.strictEqual(board.summary.unsuppliedKey, null);
});

test('an unsupplied summary says so and composes nothing (G-09)', () => {
    const board = B.buildBoard({ scenarios: r1([scenario()]) });
    assert.strictEqual(board.summary.supplied, false);
    assert.strictEqual(board.summary.text, null);
    assert.strictEqual(board.summary.unsuppliedKey, 'ui.board.summary.unsupplied');
});

test('an empty summary string is not a sentence', () => {
    const envelope = r1([scenario()]);
    envelope.board_summary = { text: '', template_ref: 'x' };
    assert.strictEqual(B.buildBoard({ scenarios: envelope }).summary.supplied, false);
});

test('a board with no envelope at all still has a summary slot', () => {
    assert.strictEqual(B.buildBoard({}).summary.supplied, false);
});

// ── display name (P9 §5) ─────────────────────────────────────────────────

test('the display name is carried when the server supplies one', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ display_name_ja: '台湾正面' })]),
    });
    assert.strictEqual(board.cards[0].displayName, '台湾正面');
    assert.strictEqual(board.cards[0].scenarioId, 'taiwan_contingency',
        'the id remains the identity');
});

test('a missing display name is null rather than the id', () => {
    const board = B.buildBoard({ scenarios: r1([scenario()]) });
    assert.strictEqual(board.cards[0].displayName, null,
        'the fallback is the renderer\'s choice, not a value invented here');
});

// ── what would clear 結論不可 (O-7) ───────────────────────────────────────

function pendingEnvelope(scenarioId, extra) {
    return Object.assign({
        scenario_id: scenarioId, conclusions: [],
        calibration_pending: { days_remaining: 12, days_observed: 18,
                               window_days: 30, types: ['threat_level'] },
    }, extra || {});
}

test('an inconclusive card states the state and what would clear it', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ threat_level: null, in_null_zone: true })]),
        conclusions: pendingEnvelope('taiwan_contingency'),
    });
    const card = board.cards[0];
    assert.strictEqual(card.availability.sentenceKey,
                       'ui.board.availability.sentence.inconclusive');
    assert.strictEqual(card.resolution.labelKey, 'ui.board.resolution.days');
    assert.strictEqual(card.resolution.hint.daysRemaining, 12);
    assert.strictEqual(card.resolution.hint.windowDays, 30);
});

test('a never-observed card says that, not that it is inconclusive', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ threat_level: null, never_observed: true })]),
    });
    assert.strictEqual(board.cards[0].availability.sentenceKey,
                       'ui.board.availability.sentence.never_observed');
});

test('a card with no resolution served says the hint is unsupplied', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ threat_level: null, in_null_zone: true })]),
        conclusions: { scenario_id: 'taiwan_contingency', conclusions: [] },
    });
    assert.strictEqual(board.cards[0].resolution.hint, null);
    assert.strictEqual(board.cards[0].resolution.labelKey,
                       'ui.board.resolution.unsupplied');
});

test('another scenario\'s calibration state never lands on this card', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ scenario_id: 'baltic_pressure',
                                  threat_level: null, in_null_zone: true })],
                      'taiwan_contingency'),
        conclusions: pendingEnvelope('taiwan_contingency'),
    });
    assert.strictEqual(board.cards[0].resolution.hint, null,
        'cross-scenario attribution is the 2026-08-02 calibration incident');
    assert.strictEqual(board.cards[0].resolution.labelKey,
                       'ui.board.resolution.unsupplied');
});

test('an envelope with no scenario id cannot claim any card', () => {
    const board = B.buildBoard({
        scenarios: r1([scenario({ threat_level: null, in_null_zone: true })]),
        conclusions: pendingEnvelope(null),
    });
    assert.strictEqual(board.cards[0].resolution.hint, null);
});

test('a concluded card carries neither sentence nor resolution', () => {
    const card = B.buildBoard({
        scenarios: r1([scenario()]),
        conclusions: pendingEnvelope('taiwan_contingency'),
    }).cards[0];
    assert.strictEqual(card.availability.sentenceKey, null);
    assert.strictEqual(card.resolution.labelKey, null);
});

// ── purity ───────────────────────────────────────────────────────────────

test('buildBoard does not mutate its input', () => {
    const input = { scenarios: r1([scenario()]), conclusions: r2([perDomainConclusion()]) };
    const before = JSON.stringify(input);
    B.buildBoard(input);
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
