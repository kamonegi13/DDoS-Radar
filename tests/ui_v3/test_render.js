/**
 * Unit tests for v3/ui/render.js — the HTML builders.
 *
 * Run:  node tests/ui_v3/test_render.js
 *
 * Splitting the markup out of the DOM layer is what makes these possible.
 * In v1 the same function fetched, decided and built HTML, so none of it
 * could be exercised without a browser — and the escaping was therefore
 * never tested at all. Here the escaping IS the main subject: every case
 * that puts a hostile string through a builder and reads the output.
 */
'use strict';

const assert = require('assert');
const R = require('../../v3/ui/render');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

const NOW = 1800000000;
const XSS = '"><script>alert(1)</script>';

// ── freshness badge ──────────────────────────────────────────────────────

test('a healthy result renders the fresh band with its age', () => {
    const html = R.freshnessBadge({ ok: true, observedAt: Date.now() / 1000, held: false });
    assert.ok(/freshness-fresh/.test(html), html);
    assert.ok(/最新/.test(html));
});

test('a failed result renders the failed band and the reason', () => {
    const html = R.freshnessBadge({
        ok: false, observedAt: Date.now() / 1000 - 10, held: true,
        error: { code: 'api.unavailable', message: '停止中' },
    });
    assert.ok(/freshness-failed/.test(html), html);
    assert.ok(/停止中/.test(html), 'the failure reason is shown');
    assert.ok(/直前の取得結果を表示中/.test(html), 'and that the data is held');
});

test('a null result never renders as fresh', () => {
    assert.ok(!/freshness-fresh/.test(R.freshnessBadge(null)));
});

test('the badge discloses the boundaries it used (NP6)', () => {
    const html = R.freshnessBadge({ ok: true, observedAt: NOW, held: false });
    assert.ok(/title="[^"]*900[^"]*3600/.test(html), html);
});

test('an error message containing markup cannot break out of the badge', () => {
    const html = R.freshnessBadge({
        ok: false, observedAt: NOW, held: false,
        error: { code: 'x', message: XSS },
    });
    assert.ok(!/<script>/.test(html), html);
    assert.ok(/&lt;script&gt;/.test(html));
});

// ── trust chip ───────────────────────────────────────────────────────────

function fold(band, componentId) {
    return {
        band: band, labelKey: 'ui.trust.' + band, formulaKey: 'ui.trust.formula',
        foldRule: 'min',
        reason: { componentId: componentId, state: 'measured',
                  labelKey: 'ui.trust.reason.' + componentId, detail: null },
        components: [{
            id: componentId, band: band, state: 'measured', value: 0.5,
            unit: 'ratio', detail: null,
            boundary: { value: 0.7, unit: 'ratio', provenance_ref: 'X',
                        source: 'R10:calibration.DEGRADED_RECALL_FLOOR' },
            labelKey: 'ui.trust.component.' + componentId,
            stateKey: 'ui.trust.state.measured',
        }],
    };
}

test('the chip carries its band as a class and its reason as text', () => {
    const html = R.trustChipHtml(fold('distrust', 'recall'));
    assert.ok(/trust-distrust/.test(html), html);
    assert.ok(/結論を信じないこと/.test(html));
    assert.ok(/recall 低下/.test(html));
});

test('the chip tooltip discloses the formula and every boundary source', () => {
    const html = R.trustChipHtml(fold('reserved', 'drift'));
    assert.ok(/trust = min\(/.test(html), html);
    assert.ok(/R10:calibration.DEGRADED_RECALL_FLOOR/.test(html));
});

test('the chip has an accessible name', () => {
    assert.ok(/aria-label="[^"]+"/.test(R.trustChipHtml(fold('trusted', 'recall'))));
});

// ── card ─────────────────────────────────────────────────────────────────

function card(overrides) {
    return Object.assign({
        scenarioId: 'taiwan_contingency', displayName: null, focused: true,
        tl: { band: 'high', cssVar: '--color-warning', labelKey: 'ui.tl.3', tl: 3 },
        availability: { state: 'concluded', labelKey: 'ui.board.availability.concluded',
                        sentenceKey: null },
        resolution: { hint: null, labelKey: null },
        trend: { direction: 'escalating', delta: 1,
                 labelKey: 'ui.trend.escalating', glyph: '▲' },
        sinceLastCheck: { seen: true, previousTl: 4, severityDelta: 1, seenAt: NOW,
                          labelKey: 'ui.board.since.worsened' },
        score: 4.2, observedAt: NOW, scoringMode: 'full',
        coverage: { limited: false, scoringMode: 'full',
                    labelKey: 'ui.board.coverage.full' },
        domains: null, participantCount: 2, adversaries: ['CN'], roles: {},
    }, overrides || {});
}

//: Two hours after the card was last displayed, so the change sentence has
//: an elapsed time to state.
const CARD_NOW = NOW + 7200;

test('the card renders the TL through a CSS custom property, never a colour', () => {
    const html = R.cardHtml(card());
    assert.ok(/--tl-color: var\(--color-warning\)/.test(html), html);
    assert.ok(!/#[0-9a-fA-F]{3,6}/.test(html), 'no colour literal in the markup');
});

test('a hostile scenario id cannot break out of the data attribute', () => {
    const html = R.cardHtml(card({ scenarioId: XSS }));
    assert.ok(!/<script>/.test(html), html);
    assert.ok(/data-scenario="&quot;&gt;/.test(html), html);
});

test('a background card offers a focus button; the focused card does not', () => {
    assert.ok(/data-focus=/.test(R.cardHtml(card({ focused: false }))));
    assert.ok(!/data-focus=/.test(R.cardHtml(card({ focused: true }))));
});

test('a missing TL renders the absent mark, not a zero', () => {
    const html = R.cardHtml(card({
        tl: { band: 'unknown', cssVar: '--color-muted', labelKey: 'ui.tl.unknown', tl: null },
    }));
    assert.ok(/class="tl-value">—</.test(html), html);
});

test('a missing score renders absent rather than 0.00', () => {
    const html = R.cardHtml(card({ score: null }));
    assert.ok(/スコア —/.test(html), html);
});

test('the domain bar clamps its width and shows the state word', () => {
    const html = R.cardHtml(card({
        domains: {
            denominator: 10, denominatorSource: 'R2:...',
            domains: [{ domain: 'cyber', score: 5, state: 'ACTIVE',
                        stateKey: 'ui.domain.state.ACTIVE', fill: 0.5 }],
        },
    }));
    assert.ok(/width:50%/.test(html), html);
    assert.ok(/domain-ACTIVE/.test(html));
    assert.ok(/活性/.test(html));
});

test('a null fill renders a zero-width bar, not a full one', () => {
    const html = R.cardHtml(card({
        domains: {
            denominator: null, denominatorSource: null,
            domains: [{ domain: 'cyber', score: 5, state: 'ACTIVE',
                        stateKey: 'ui.domain.state.ACTIVE', fill: null }],
        },
    }));
    assert.ok(/width:0%/.test(html), html);
});

test('a hostile domain state word cannot inject a class or a tag', () => {
    const html = R.cardHtml(card({
        domains: {
            denominator: 10, denominatorSource: 'x',
            domains: [{ domain: 'cyber', score: 1, state: XSS,
                        stateKey: 'ui.domain.state.unknown', fill: 0.1 }],
        },
    }));
    assert.ok(!/<script>/.test(html), html);
});

// ── card: name, sentence, and the way into the scenario face (P9 R-A) ────

test('the display name is the visible name and the id stays traceable', () => {
    const html = R.cardHtml(card({ displayName: '台湾正面' }), CARD_NOW);
    assert.ok(/>台湾正面</.test(html), html);
    assert.ok(/data-scenario="taiwan_contingency"/.test(html));
    assert.ok(/title="[^"]*taiwan_contingency[^"]*"/.test(html),
        'the raw id remains reachable in the tooltip');
});

test('a scenario with no display name shows its id rather than a blank', () => {
    const html = R.cardHtml(card(), CARD_NOW);
    assert.ok(/>taiwan_contingency</.test(html), html);
});

test('the card name opens the scenario face', () => {
    const html = R.cardHtml(card(), CARD_NOW);
    assert.ok(/data-open-scenario="taiwan_contingency"/.test(html), html);
    assert.ok(/<button type="button" class="card-open"/.test(html),
        'reachable from the keyboard: a clickable <article> is not');
});

test('a hostile display name cannot break out of the title element', () => {
    const html = R.cardHtml(card({ displayName: XSS }), CARD_NOW);
    assert.ok(!/<script>/.test(html), html);
});

// ── the provenance line (P9 §2.2 R-E, D-11) ─────────────────────────────

test('a supplied derivation names each domain and its observation count', () => {
    const html = R.cardHtml(card({ derivedFrom: {
        supplied: true, unavailable: null, observedAt: NOW - 60,
        domains: [
            { domain: 'cyber', score: 3.1, state: 'ACTIVE', sources: 2 },
            { domain: 'physical', score: 0.0, state: 'STABLE', sources: 0 },
            { domain: 'info', score: 0.4, state: 'STABLE', sources: 1 },
        ],
    } }), CARD_NOW);
    assert.ok(/card-derived/.test(html), html);
    assert.ok(/サイバー 2 件 \/ 物理 0 件 \/ 情報 1 件/.test(html), html);
});

test('every provenance state carries the way into the derivation', () => {
    const states = [
        { supplied: false, reasonKey: 'ui.board.derived.absent' },
        { supplied: true, unavailable: 'insufficient_data', domains: [] },
        { supplied: true, unavailable: null, domains: [] },
    ];
    states.forEach((derivedFrom) => {
        const html = R.cardHtml(card({ derivedFrom }), CARD_NOW);
        assert.ok(/class="card-why" data-open-scenario="taiwan_contingency"/
            .test(html), JSON.stringify(derivedFrom));
    });
});

test('no record and an unavailable picture say different things', () => {
    const absent = R.cardHtml(card({ derivedFrom: {
        supplied: false, reasonKey: 'ui.board.derived.absent' } }), CARD_NOW);
    const unavailable = R.cardHtml(card({ derivedFrom: {
        supplied: true, unavailable: 'insufficient_data', domains: [] } }),
        CARD_NOW);
    assert.ok(/記録がまだありません/.test(absent), absent);
    assert.ok(/insufficient_data/.test(unavailable), unavailable);
});

test('a card without the provenance model still states its scoring scope', () => {
    // WP-4.5b merged the coverage line into the provenance line, so the
    // one origin sentence per card survives even when derived_from is
    // absent — the scope word is what remains of the old coverage line.
    const html = R.cardHtml(card(), CARD_NOW);
    assert.ok(/card-derived/.test(html), html);
    assert.ok(/由来: 全センサー採点。/.test(html), html);
    assert.ok(!/card-coverage/.test(html), 'the separate coverage line is retired');
});

test('the merged line carries scope AND domains when both exist', () => {
    const html = R.cardHtml(card({ derivedFrom: {
        supplied: true, unavailable: null, observedAt: NOW - 60,
        domains: [
            { domain: 'cyber', score: 3.1, state: 'ACTIVE', sources: 2 },
        ],
    } }), CARD_NOW);
    assert.ok(/由来: 全センサー採点 — サイバー 2 件。/.test(html), html);
});

test('the participant strip folds beyond six into a +N chip', () => {
    const many = ['TW', 'JP', 'US', 'CN', 'KR', 'PH', 'AU', 'GU'].map(
        (country) => ({ country, flag: '', role: null,
                        roleKey: 'ui.geo.role.unlisted', isAdversary: false }));
    const html = R.cardHtml(card({ participants: many }), CARD_NOW);
    assert.ok(/class="cc cc-more" title="AU, GU">\+2</.test(html), html);
    assert.ok(!/cc-iso">AU</.test(html), 'folded countries appear only in the title');
});

// ── the participant strip (P9 §3.7, D-10) ───────────────────────────────

test('the strip prints flag and ISO2 per participant, adversary dashed', () => {
    const html = R.cardHtml(card({ participants: [
        { country: 'TW', flag: '🇹🇼', role: 'primary_target',
          roleKey: 'ui.geo.role.primary_target', isAdversary: false },
        { country: 'CN', flag: '🇨🇳', role: 'adversary',
          roleKey: 'ui.geo.role.adversary', isAdversary: true },
    ] }), CARD_NOW);
    assert.ok(/card-countries/.test(html), html);
    assert.ok(/<span class="cc-iso">TW<\/span>/.test(html), html);
    assert.ok(/class="cc cc-adversary"/.test(html), html);
});

test('the change line is a sentence carrying how long ago that was', () => {
    const html = R.cardHtml(card(), CARD_NOW);
    assert.ok(/前回確認（2 時間前）から悪化しました。TL 4 → 3/.test(html), html);
});

test('a first sighting says so instead of claiming nothing changed', () => {
    const html = R.cardHtml(card({
        sinceLastCheck: { seen: false, previousTl: null, severityDelta: null,
                          seenAt: null, labelKey: 'ui.board.since.first_sighting' },
    }), CARD_NOW);
    assert.ok(/初回です/.test(html), html);
    assert.ok(!/変化はありません/.test(html));
});

test('an inconclusive card states the state and what would clear it', () => {
    const html = R.cardHtml(card({
        tl: { band: 'unknown', cssVar: '--color-muted', labelKey: 'ui.tl.unknown', tl: null },
        availability: { state: 'inconclusive',
                        labelKey: 'ui.board.availability.inconclusive',
                        sentenceKey: 'ui.board.availability.sentence.inconclusive' },
        resolution: { labelKey: 'ui.board.resolution.days',
                      hint: { daysRemaining: 12, daysObserved: 18, windowDays: 30 } },
    }), CARD_NOW);
    assert.ok(/結論を出せていません/.test(html), html);
    assert.ok(/あと 12 日/.test(html), html);
    assert.ok(/30 日のうち 18 日/.test(html), html);
});

test('an inconclusive card with no hint says the hint was not supplied', () => {
    const html = R.cardHtml(card({
        availability: { state: 'inconclusive',
                        labelKey: 'ui.board.availability.inconclusive',
                        sentenceKey: 'ui.board.availability.sentence.inconclusive' },
        resolution: { labelKey: 'ui.board.resolution.unsupplied', hint: null },
    }), CARD_NOW);
    assert.ok(/供給されていません/.test(html), html);
    assert.ok(!/あと — 日/.test(html), 'an absent hint is not rendered as a number');
});

test('a concluded card carries no inconclusive block', () => {
    const html = R.cardHtml(card(), CARD_NOW);
    assert.ok(!/card-inconclusive/.test(html), html);
    assert.ok(!/card-resolution/.test(html));
});

// ── the situation sentence ───────────────────────────────────────────────

test('the summary renders the server sentence and its template ref', () => {
    const html = R.boardSummaryHtml({ supplied: true, text: '変化は 0 件。',
                                      templateRef: 'board.summary@1',
                                      unsuppliedKey: null });
    assert.ok(/変化は 0 件。/.test(html), html);
    assert.ok(/board\.summary@1/.test(html), 'the sentence is traceable (NP6)');
});

test('an unsupplied summary says so rather than rendering empty', () => {
    const html = R.boardSummaryHtml({ supplied: false, text: null,
                                      templateRef: null,
                                      unsuppliedKey: 'ui.board.summary.unsupplied' });
    assert.ok(/供給されていません/.test(html), html);
});

test('a null summary is still a sentence, never a blank slot', () => {
    assert.ok(/供給されていません/.test(R.boardSummaryHtml(null)));
});

test('a hostile summary sentence is escaped like any other server string', () => {
    const html = R.boardSummaryHtml({ supplied: true, text: XSS,
                                      templateRef: XSS, unsuppliedKey: null });
    assert.ok(!/<script>/.test(html), html);
});

// ── the scenario face heading ────────────────────────────────────────────

test('the scope renders nothing outside the scenario view', () => {
    assert.strictEqual(R.faceScopeHtml({ present: false }), '');
    assert.strictEqual(R.faceScopeHtml(null), '');
});

test('a matching scope names the scenario and raises no notice', () => {
    const html = R.faceScopeHtml({ present: true, requested: 'x', requestedLabel: '台湾正面',
                                   served: 'x', servedLabel: '台湾正面', match: true,
                                   noticeKey: null });
    assert.ok(/台湾正面/.test(html), html);
    assert.ok(!/scenario-head-notice/.test(html));
});

test('a mismatched scope says whose numbers are actually below', () => {
    const html = R.faceScopeHtml({ present: true, requested: 'baltic_pressure',
                                   requestedLabel: 'baltic_pressure', served: 'tw',
                                   servedLabel: '台湾正面', match: false,
                                   noticeKey: 'ui.scenario.notice.other_scenario' });
    assert.ok(/台湾正面 のもの/.test(html), html);
    assert.ok(/baltic_pressure の面/.test(html), html);
});

test('a hostile scenario label cannot break out of the heading', () => {
    const html = R.faceScopeHtml({ present: true, requested: XSS, requestedLabel: XSS,
                                   served: null, servedLabel: '—', match: false,
                                   noticeKey: 'ui.scenario.notice.not_loaded' });
    assert.ok(!/<script>/.test(html), html);
});

// ── lane row ─────────────────────────────────────────────────────────────

function laneRow(overrides) {
    return Object.assign({
        itemId: 'c-1', itemKind: 'conclusion', scenarioId: 'taiwan_contingency',
        rankPosition: 1, rankFallback: false, arrivalIndex: 0, score: 0.6,
        factors: { novelty: 1, confidence_delta: 0.75, analyst_blindness: 0.8 },
        components: {}, formulaRef: 'attention.score@1',
        narrative: 'サーバ生成の 1 行。', narrativeTemplateRef: 'attention.row@1',
        narrativeMissingKey: null, analystState: 'active',
        analystStateKey: 'ui.lane.state.active', analystStateExpiresAt: null,
        suppressed: false,
    }, overrides || {});
}

const LANE = { formulaRef: 'attention.score@1', snapshotId: 'snap-1',
               thresholdDisclosure: {} };

test('the lane row shows the ledger rank and the three factors in its tooltip', () => {
    const html = R.laneRowHtml(laneRow(), LANE);
    assert.ok(/class="lane-rank-chip" title="[^"]*novelty 1[^"]*"/.test(html), html);
    assert.ok(/snap-1/.test(html), 'the snapshot the rank came from');
});

test('the header names the scenario in the analyst\'s language', () => {
    // P9 §1.6 D-23a: the sixth review read `korean_peninsula` in a row
    // body and called it raw data. The id stays in the data attributes.
    const html = R.laneRowHtml(laneRow(), LANE,
                               { taiwan_contingency: '台湾正面' });
    assert.ok(/<strong class="lane-scenario">台湾正面<\/strong>/.test(html), html);
    assert.ok(/data-open-scenario="taiwan_contingency"/.test(html),
        'machines keep reading the id');
});

test('a scenario with no display name falls back to its id, visibly', () => {
    const html = R.laneRowHtml(laneRow(), LANE, {});
    assert.ok(/<strong class="lane-scenario">taiwan_contingency<\/strong>/
        .test(html), html);
});

test('an unranked row says its position is a fallback', () => {
    const html = R.laneRowHtml(laneRow({ rankPosition: null, rankFallback: true }), LANE);
    assert.ok(/順位未確定/.test(html), html);
});

test('a missing narrative renders the declared key, never invented prose', () => {
    const html = R.laneRowHtml(laneRow({
        narrative: null, narrativeMissingKey: 'ui.lane.narrative.unsupplied',
    }), LANE);
    assert.ok(/説明文がサーバから供給されていません/.test(html), html);
});

test('a hostile narrative is escaped', () => {
    const html = R.laneRowHtml(laneRow({ narrative: XSS }), LANE);
    assert.ok(!/<script>/.test(html), html);
});

test('a hostile item id cannot inject into the action buttons', () => {
    const html = R.laneRowHtml(laneRow({ itemId: XSS }), LANE);
    assert.ok(!/<script>/.test(html), html);
    assert.strictEqual((html.match(/data-ack="[^"]*"/g) || []).length, 1);
});

test('the head line comes first and the sentence under it', () => {
    const html = R.laneRowHtml(laneRow(), LANE);
    assert.ok(html.indexOf('lane-head') < html.indexOf('lane-narrative'),
        'P9 §1.6 D-23a: who and where first, then the sentence');
    assert.ok(/<p class="lane-narrative">/.test(html),
        'a block element, so the stylesheet can give it its own weight');
});

test('the rank chip carries the position and its basis tooltip', () => {
    const html = R.laneRowHtml(laneRow(), LANE);
    assert.ok(/lane-rank-chip[^>]*>1</.test(html), html);
    assert.ok(/title="[^"]*attention\.score@1/.test(html), 'AP1: the basis stays visible');
});

test('the open button carries the scenario the row belongs to', () => {
    const html = R.laneRowHtml(laneRow(), LANE);
    assert.ok(/data-open-scenario="taiwan_contingency"/.test(html), html);
    assert.ok(/data-item-open="c-1"/.test(html), 'and which item was chosen');
});

test('a row with no scenario says why it cannot be opened', () => {
    const html = R.laneRowHtml(laneRow({ scenarioId: null }), LANE);
    assert.ok(!/data-open-scenario/.test(html), html);
    assert.ok(/シナリオが特定されていない/.test(html),
        'a silently missing button is indistinguishable from a broken one');
});

// ── conclusion row ───────────────────────────────────────────────────────

function conclusionRow(overrides) {
    return Object.assign({
        conclusionId: 'c-1', type: 'threat_level',
        typeKey: 'ui.conclusion.type.threat_level', state: '3', confidence: 0.72,
        observedAt: NOW, available: true, unavailable: null,
        calibration: { status: 'OK', recall: 0.9, precision: 0.8, sample_n: 40 },
        calibrationNotes: [], formulaRef: 'threat_level@2',
        sourceUrls: [], llmPromptSha256: null, inputHealth: {},
        suppression: null, overridden: false, metadata: {},
        tl: { band: 'high', cssVar: '--color-warning', labelKey: 'ui.tl.3', tl: 3 },
    }, overrides || {});
}

test('an http source URL becomes a link with rel=noopener', () => {
    const html = R.conclusionRowHtml(conclusionRow({
        sourceUrls: [{ raw: 'https://ok.test/a', href: 'https://ok.test/a' }],
    }));
    assert.ok(/<a href="https:\/\/ok.test\/a" rel="noopener noreferrer"/.test(html), html);
});

test('a rejected URL is rendered as text and never as an anchor', () => {
    const html = R.conclusionRowHtml(conclusionRow({
        sourceUrls: [{ raw: 'javascript:alert(1)', href: null }],
    }));
    assert.ok(!/<a /.test(html), html);
    assert.ok(/javascript:alert\(1\)/.test(html), 'but it is still shown');
});

test('an overridden suppression is announced', () => {
    const html = R.conclusionRowHtml(conclusionRow({ overridden: true }));
    assert.ok(/ガードが発火しましたが/.test(html), html);
});

test('an unavailable conclusion renders its reason, guard and resolution', () => {
    const html = R.conclusionRowHtml(conclusionRow({
        available: false, state: null,
        unavailable: {
            reason: 'upstream_failure',
            reasonKey: 'ui.conclusion.unavailable.upstream_failure',
            guardId: 'upstream_total_loss',
            guardCondition: 'every consulted source failed',
            detail: '5/5', evaluated: [
                { guard_id: 'g1', reason: 'upstream_failure', fired: true, detail: 'd' },
                { guard_id: 'g2', reason: 'insufficient_data', fired: false, detail: '' },
            ],
            resolution: null,
        },
    }));
    assert.ok(/上流ソースの取得に失敗/.test(html), html);
    assert.ok(/upstream_total_loss/.test(html));
    assert.ok(/guard-fired/.test(html) && /guard-quiet/.test(html),
        'guards that fired and guards that did not are both shown');
    assert.ok(/解消条件はサーバから供給されていません/.test(html));
});

test('a DEGRADED calibration renders its note at high severity', () => {
    const html = R.conclusionRowHtml(conclusionRow({
        calibration: { status: 'DEGRADED', recall: 0.4, sample_n: 3 },
        calibrationNotes: [
            { kind: 'degraded', severity: 'high',
              labelKey: 'ui.conclusion.calibration.degraded', value: 0.4 },
            { kind: 'provisional', severity: 'medium',
              labelKey: 'ui.conclusion.calibration.provisional',
              value: 3, boundary: 5, boundarySource: 'R10:...' },
        ],
    }));
    assert.ok(/calib-high/.test(html), html);
    assert.ok(/calib-medium/.test(html));
    assert.ok(/暫定値として扱ってください/.test(html));
});

test('a conclusion with no id offers no derivation button', () => {
    assert.ok(!/data-derive/.test(R.conclusionRowHtml(conclusionRow({ conclusionId: null }))));
    assert.ok(/data-derive/.test(R.conclusionRowHtml(conclusionRow())));
});

test('a hostile state string is escaped', () => {
    const html = R.conclusionRowHtml(conclusionRow({ state: XSS }));
    assert.ok(!/<script>/.test(html), html);
});

test('a hostile calibration status cannot break the summary line', () => {
    const html = R.conclusionRowHtml(conclusionRow({
        calibration: { status: XSS, recall: null, precision: null, sample_n: 0 },
    }));
    assert.ok(!/<script>/.test(html), html);
});

test('the feedback form shows all four labels and never one verdict', () => {
    const html = R.feedbackFormHtml('c-1',
        { counts: { TRUE_POSITIVE: 3, FALSE_POSITIVE: 1,
                    TRUE_NEGATIVE: 0, FALSE_NEGATIVE: 0 }, analysts: 4,
          labels: ['TRUE_POSITIVE', 'FALSE_POSITIVE', 'TRUE_NEGATIVE', 'FALSE_NEGATIVE'] },
        { state: 'no_label', canSubmit: false, messageKey: 'ui.feedback.no_label' });
    ['TP（正しく警報）', 'FP（誤警報）', 'TN（正しく平常）', 'FN（見逃し）']
        .forEach(label => assert.ok(html.indexOf(label) !== -1, `${label} missing`));
    assert.ok(/投稿したアナリスト 4 名/.test(html), html);
    // A zero count is printed, not omitted: 0 and "no data" are different.
    assert.strictEqual((html.match(/tally-count/g) || []).length, 4);
});

test('a conclusion with no id gets the tally but no submit buttons', () => {
    const html = R.feedbackFormHtml(null,
        { counts: { TRUE_POSITIVE: 0, FALSE_POSITIVE: 0,
                    TRUE_NEGATIVE: 0, FALSE_NEGATIVE: 0 }, analysts: 0, labels: [] },
        { state: 'unsupported', canSubmit: false, messageKey: 'ui.feedback.unsupported' });
    assert.ok(!/data-label-for="[^"]+"/.test(html), html);
    assert.ok(/保存されていない/.test(html), 'and it says why');
});

test('every feedback outcome renders its own state class inline', () => {
    ['saving', 'saved', 'rejected', 'network_error', 'no_label'].forEach(st => {
        const html = R.feedbackFormHtml('c-1',
            { counts: { TRUE_POSITIVE: 0, FALSE_POSITIVE: 0,
                        TRUE_NEGATIVE: 0, FALSE_NEGATIVE: 0 }, analysts: 0, labels: [] },
            { state: st, messageKey: 'ui.feedback.' + st, detail: null });
        assert.ok(html.indexOf('feedback-' + st) !== -1, `${st} not rendered`);
    });
});

test('a hostile server error detail cannot escape the feedback state line', () => {
    const html = R.feedbackFormHtml('c-1',
        { counts: { TRUE_POSITIVE: 0, FALSE_POSITIVE: 0,
                    TRUE_NEGATIVE: 0, FALSE_NEGATIVE: 0 }, analysts: 0, labels: [] },
        { state: 'rejected', messageKey: 'ui.feedback.rejected', detail: XSS });
    assert.ok(!/<script>/.test(html), html);
});

// ── Tier 2 row builders ──────────────────────────────────────────────────

test('a sensor row prints absent for a missing count, never "undefined"', () => {
    const html = R.sensorRowHtml({ sensor: 'ripe_bgp', domain: 'cyber',
                                   silent_for_sec: null });
    assert.ok(!/undefined/.test(html), html);
    assert.ok(!/null/.test(html), html);
});

test('a sensor with zero rows wears the silent state, not a zero duration', () => {
    // WP-4.8d(3): "swept and quiet" and "never wrote" must read apart.
    const html = R.sensorRowHtml({ sensor: 's', domain: 'cyber',
                                   observation_count: 0, fired_count: 0,
                                   suppressed_count: 0, silent_for_sec: null });
    assert.ok(/class="sensor-silent"/.test(html), html);
    assert.ok(/沈黙 — この窓で観測ゼロ/.test(html), html);
});

test('a writing sensor states when it last wrote', () => {
    const html = R.sensorRowHtml({ sensor: 's', domain: 'cyber',
                                   observation_count: 5, fired_count: 3,
                                   suppressed_count: 2, silent_for_sec: 120 });
    assert.ok(!/sensor-silent/.test(html), html);
    assert.ok(/最終観測 2 分前/.test(html), html);
});

test('a decision row is a sentence naming the automated actor', () => {
    // WP-4.8d(2): who did what to what, assembled by the renderer. The
    // VALUES stay the API's own (ja-localization §2).
    const html = R.decisionRowHtml({ decided_at: NOW, decision_type: 'attention_rank',
                                     action: 'attention.rank', target_id: 'c-1',
                                     actor_id: null, reason: null });
    assert.ok(/<li class="decision">/.test(html), html);
    assert.ok(/自動/.test(html), html);
    assert.ok(/c-1 に attention.rank を実行（attention_rank）/.test(html), html);
    assert.ok(!/decision-reason/.test(html), 'no reason line when none was given');
});

test('a decision with an actor and a reason carries both', () => {
    const html = R.decisionRowHtml({ decided_at: NOW, decision_type: 'focus',
                                     action: 'focus_set', target_id: 'taiwan_contingency',
                                     actor_id: 'admin', reason: '演習開始の報道' });
    assert.ok(/admin が taiwan_contingency に focus_set を実行（focus）/.test(html), html);
    assert.ok(/理由: 演習開始の報道/.test(html), html);
});

test('a terminal proposal offers no verbs', () => {
    const base = { proposal_id: 'p-1', proposal_type: 'weight_too_low',
                   scenario_id: 's', target_country: 'JP', prior_value: 0.4,
                   proposed_value: 0.55, sample_n: 42, state: 'applied' };
    assert.ok(!/data-proposal-apply/.test(
        R.proposalRowHtml(Object.assign({}, base, { is_terminal: true }))));
    assert.ok(/data-proposal-apply/.test(
        R.proposalRowHtml(Object.assign({}, base, { is_terminal: false,
                                                    state: 'pending' }))));
});

test('a hostile proposal id cannot inject into its action buttons', () => {
    const html = R.proposalRowHtml({ proposal_id: XSS, proposal_type: 't',
                                     scenario_id: 's', target_country: 'X',
                                     prior_value: 1, proposed_value: 2,
                                     sample_n: 1, state: 'pending',
                                     is_terminal: false });
    assert.ok(!/<script>/.test(html), html);
});

test('a what-if row marks a changed TL and signs both deltas', () => {
    const html = R.whatIfRowHtml({
        scenarioId: 's',
        tl: { baseline: 4, counterfactual: 2, severityDelta: 2, changed: true },
        score: { baseline: 1, counterfactual: 3, delta: 2 },
    });
    assert.ok(/whatif-changed/.test(html), html);
    assert.ok(/\+2/.test(html), 'the severity delta keeps its sign');
});

test('a what-if row with no server TL prints absent, not a derived one', () => {
    const html = R.whatIfRowHtml({
        scenarioId: 's',
        tl: { baseline: null, counterfactual: null, severityDelta: null, changed: false },
        score: { baseline: null, counterfactual: null, delta: null },
    });
    assert.strictEqual((html.match(/—/g) || []).length, 4);
});

test('a derivation section renders its payload or says it is empty', () => {
    const present = R.derivationSectionHtml({
        id: 'formula', titleKey: 'ui.derivation.section.formula',
        present: true, payload: { formulaRef: 'x@1' }, emptyKey: null });
    assert.ok(/計算式/.test(present), present);
    assert.ok(/formulaRef/.test(present));

    const absent = R.derivationSectionHtml({
        id: 'llm_prompt', titleKey: 'ui.derivation.section.llm_prompt',
        present: false, payload: null,
        emptyKey: 'ui.derivation.section.llm_unused' });
    assert.ok(/LLM は使用していません/.test(absent), absent);
});

test('a derivation payload containing markup is escaped inside the pre', () => {
    const html = R.derivationSectionHtml({
        id: 'inputs', titleKey: 'ui.derivation.section.inputs', present: true,
        payload: { rows: [{ key: 'k', value: XSS }] }, emptyKey: null });
    assert.ok(!/<script>/.test(html), html);
});

test('an AP3 component row shows its boundary source, or absent', () => {
    const withBoundary = R.trustComponentRowHtml({
        id: 'recall', band: 'trusted', state: 'measured', value: 0.9,
        detail: null, boundary: { value: 0.7, source: 'R10:x' },
        labelKey: 'ui.trust.component.recall', stateKey: 'ui.trust.state.measured' });
    assert.ok(/R10:x/.test(withBoundary), withBoundary);
    assert.ok(/trust-trusted/.test(withBoundary));

    const unsupplied = R.trustComponentRowHtml({
        id: 'ops_health', band: 'reserved', state: 'unsupplied', value: null,
        detail: null, boundary: null,
        labelKey: 'ui.trust.component.ops_health',
        stateKey: 'ui.trust.state.unsupplied' });
    assert.ok(/未供給/.test(unsupplied), unsupplied);
    assert.strictEqual((unsupplied.match(/—/g) || []).length, 4);
});

test('no builder emits a raw colour literal', () => {
    const html = [
        R.trustChipHtml(fold('reserved', 'recall')),
        R.cardHtml(card()),
        R.laneRowHtml(laneRow(), LANE),
        R.conclusionRowHtml(conclusionRow()),
        R.freshnessBadge({ ok: true, observedAt: NOW }),
    ].join('');
    assert.ok(!/#[0-9a-fA-F]{3}\b/.test(html), 'colours come from the stylesheet');
});

// ── term markers (P9 §2 R-C / §4) ────────────────────────────────────────

const Terms = require('../../v3/ui/terms');

test('the first card to print a TL carries its definition, the rest do not', () => {
    const marks = Terms.createMarkers('situation');
    const first = R.cardHtml(card(), CARD_NOW, marks);
    const second = R.cardHtml(card({ scenarioId: 'other' }), CARD_NOW, marks);
    assert.ok(/term-def-situation-tl/.test(first), first);
    assert.ok(!/term-def-situation-tl/.test(second),
              'the second card repeats the definition (P9 §4: visual noise)');
});

test('a card rendered without a view issues no markers at all', () => {
    const html = R.cardHtml(card(), CARD_NOW);
    assert.ok(!/term-info/.test(html), html);
});

test('the definition sits beside the term it defines, not at the end', () => {
    const marks = Terms.createMarkers('situation');
    const html = R.cardHtml(card(), CARD_NOW, marks);
    const caption = html.indexOf('tl-caption');
    const marker = html.indexOf('term-def-situation-tl');
    const lines = html.indexOf('card-lines');
    assert.ok(caption < marker && marker < lines,
              `the TL definition is not in the TL block: ${html}`);
});

test('the coverage line defines scoring_mode and the change line severity', () => {
    const marks = Terms.createMarkers('situation');
    const html = R.cardHtml(card(), CARD_NOW, marks);
    assert.ok(/term-def-situation-scoring_mode/.test(html), html);
    assert.ok(/term-def-situation-severity/.test(html), html);
    assert.deepStrictEqual(marks.marked(),
                           ['scoring_mode', 'severity', 'tl']);
});

test('a first sighting has no severity delta to define', () => {
    const marks = Terms.createMarkers('situation');
    const html = R.cardHtml(card({
        sinceLastCheck: { seen: false, previousTl: null, severityDelta: null,
                          seenAt: null,
                          labelKey: 'ui.board.since.first_sighting' },
    }), CARD_NOW, marks);
    assert.ok(!/term-def-situation-severity/.test(html), html);
});

test('an inconclusive card defines 結論不可 where it says it', () => {
    const marks = Terms.createMarkers('situation');
    const html = R.cardHtml(card({
        availability: { state: 'inconclusive',
                        labelKey: 'ui.board.availability.inconclusive',
                        sentenceKey: 'ui.board.availability.sentence.inconclusive' },
        resolution: { hint: null, labelKey: 'ui.board.resolution.unsupplied' },
    }), CARD_NOW, marks);
    assert.ok(/term-def-situation-inconclusive/.test(html), html);
    assert.ok(html.indexOf('card-inconclusive') < html.indexOf('term-def-situation-inconclusive'));
});

test('the trust chip defines the term its reason names, and only that one', () => {
    const marks = Terms.createMarkers('situation');
    const html = R.trustChipHtml(fold('distrust', 'recall'), marks);
    assert.ok(/term-def-situation-recall/.test(html), html);
    assert.deepStrictEqual(marks.marked(), ['recall']);
    // The marker is a sibling of the button, never nested inside it: a
    // focusable span inside a button is not reachable on its own.
    assert.ok(html.indexOf('</button>') < html.indexOf('term-marker'), html);
});

test('a reason already written in Japanese gets no gloss', () => {
    const marks = Terms.createMarkers('situation');
    const html = R.trustChipHtml(fold('reserved', 'ops_health'), marks);
    assert.ok(!/term-info/.test(html), html);
    assert.deepStrictEqual(marks.marked(), []);
});

test('the self-eval table defines recall, null-zone and drift where they render', () => {
    const marks = Terms.createMarkers('verify');
    const rows = ['recall', 'null_zone', 'drift', 'ops_health', 'freshness']
        .map((id) => R.trustComponentRowHtml({
            id: id, band: 'trusted', state: 'measured', value: 0.9,
            boundary: null, detail: null,
            labelKey: 'ui.trust.component.' + id,
            stateKey: 'ui.trust.state.measured',
        }, marks)).join('');
    assert.deepStrictEqual(marks.marked(), ['drift', 'null_zone', 'recall']);
    assert.ok(/term-def-verify-recall/.test(rows), rows);
    assert.ok(/term-def-verify-null_zone/.test(rows), rows);
    assert.ok(/term-def-verify-drift/.test(rows), rows);
});

test('an unavailable conclusion defines 結論不可 in the scenario view', () => {
    const marks = Terms.createMarkers('scenario');
    const html = R.conclusionRowHtml(conclusionRow({
        available: false,
        unavailable: {
            reasonKey: 'ui.conclusion.unavailable.insufficient_data',
            guardId: 'g1', guardCondition: 'c', detail: null,
            resolution: null, evaluated: [],
        },
    }), marks);
    assert.ok(/term-def-scenario-inconclusive/.test(html), html);
});

// ── the country-tile map (P9 §3.4) ───────────────────────────────────────

function tile(overrides) {
    return Object.assign({
        country: 'TW', flag: '\u{1F1F9}\u{1F1FC}', region: 'east_asia',
        col: 2, row: 3, placed: true, roleClass: 'target',
        role: 'primary_target', roleKey: 'ui.geo.role.primary_target',
        roleKnown: true, isAdversary: false, isChainCountry: false,
        firedCount: 0, suppressedCount: 0, observations: 0,
        stateKey: 'ui.geo.marker.unobserved', hasEvents: false, dots: [],
    }, overrides || {});
}

test('a tile is positioned by its placement, never by a coordinate', () => {
    const html = R.geoTileHtml(tile());
    assert.ok(/grid-column:2/.test(html), html);
    assert.ok(/grid-row:3/.test(html), html);
    assert.ok(/data-country="TW"/.test(html));
});

test('a tile prints the ISO2 as well as the flag', () => {
    const html = R.geoTileHtml(tile());
    assert.ok(/tile-iso">TW</.test(html), html);
    assert.ok(/tile-flag/.test(html));
});

test('domain dots carry their domain and their kind as classes', () => {
    const html = R.geoTileHtml(tile({
        hasEvents: true, firedCount: 1, suppressedCount: 1, observations: 2,
        stateKey: 'ui.geo.marker.fired',
        dots: [{ domain: 'cyber', kind: 'fired' },
               { domain: 'info', kind: 'suppressed' }],
    }));
    assert.ok(/tile-dot tile-dot-fired tile-domain-cyber/.test(html), html);
    assert.ok(/tile-dot tile-dot-suppressed tile-domain-info/.test(html), html);
    assert.ok(/geo-tile-events/.test(html));
});

test('an unplaced tile carries no grid position and is still drawn', () => {
    const html = R.geoTileHtml(tile({ country: 'GLOBAL', flag: '', placed: false,
                                      region: null, col: null, row: null }));
    assert.ok(!/grid-column/.test(html), html);
    assert.ok(/data-country="GLOBAL"/.test(html));
});

test('a hostile country code cannot break out of the tile attributes', () => {
    const html = R.geoTileHtml(tile({ country: XSS, flag: '' }));
    assert.ok(!/<script>/.test(html), html);
    assert.ok(/&lt;script&gt;/.test(html));
});

test('the map draws one block per region, in the design order', () => {
    const html = R.geoTileMapHtml({
        regions: [
            { id: 'east_asia', labelKey: 'ui.geo.region.east_asia',
              tiles: [tile()], columns: 3, rows: 3, firedTotal: 0 },
            { id: 'europe', labelKey: 'ui.geo.region.europe',
              tiles: [tile({ country: 'PL', region: 'europe', col: 1, row: 4 })],
              columns: 4, rows: 5, firedTotal: 0 },
        ],
        spillover: { present: false, labelKey: 'ui.geo.region.unplaced',
                     noteKey: 'ui.geo.tilemap.unplaced_note', tiles: [] },
    });
    assert.ok(html.indexOf('data-region="east_asia"')
              < html.indexOf('data-region="europe"'), html);
    assert.ok(/東アジア/.test(html));
    assert.ok(/repeat\(3,1fr\)/.test(html), html);
});

test('the spillover row is drawn with its reason, never omitted (G-17)', () => {
    const html = R.geoTileMapHtml({
        regions: [],
        spillover: { present: true, labelKey: 'ui.geo.region.unplaced',
                     noteKey: 'ui.geo.tilemap.unplaced_note',
                     tiles: [tile({ country: 'GLOBAL', flag: '', placed: false })] },
    });
    assert.ok(/配置未定義/.test(html), html);
    assert.ok(/data-country="GLOBAL"/.test(html));
    assert.ok(/観測は落としていません/.test(html));
});

// ── empty states (P9 §3.5) ───────────────────────────────────────────────

test('an empty state renders all three parts and nothing else', () => {
    const html = R.emptyStateHtml({
        surface: 'board', roleKey: 'empty.board.role',
        reasonKey: 'empty.board.reason_not_loaded', reasonVars: {},
        reasonSupplied: true, fillsWhenKey: 'empty.board.fills_when',
    });
    assert.ok(/class="empty-role"/.test(html), html);
    assert.ok(/class="empty-reason"/.test(html));
    assert.ok(/class="empty-fills"/.test(html));
    assert.ok(/role="status"/.test(html));
});

test('an empty state fills the slots its reason declares', () => {
    const html = R.emptyStateHtml({
        surface: 'lane', roleKey: 'empty.lane.role',
        reasonKey: 'empty.reason.unrecognised',
        reasonVars: { reason: 'quarantined_by_operator' },
        reasonSupplied: true, fillsWhenKey: 'empty.lane.fills_when',
    }, { tag: 'li' });
    assert.ok(/quarantined_by_operator/.test(html), html);
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
