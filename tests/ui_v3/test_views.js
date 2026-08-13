/**
 * Unit tests for v3/ui/views.js — the view split (P9 §2 R-B).
 *
 * Run:  node tests/ui_v3/test_views.js
 *
 * Routing is the thing that decides what an analyst is looking at, so it is
 * written as a pure total function and tested here rather than being an
 * emergent property of a browser. Two families carry the weight:
 *
 *   1. **every hash resolves.** A view layer whose unknown route shows
 *      nothing is a blank screen with extra steps (S1-UI-008). Malformed
 *      percent-escapes included — `decodeURIComponent` throws, and a throw
 *      inside routing takes the whole page down.
 *   2. **exactly one view is visible.** The failure this prevents is two
 *      containers on screen at once, which reads as one long page — which
 *      is D-1, the diagnosis this slice exists to fix.
 *
 * The scenario face's scope check is the third: R2 is served for the
 * FOCUSED scenario only, so asking for a background scenario's face must
 * say whose numbers are actually below, never relabel them.
 */
'use strict';

const assert = require('assert');
const V = require('../../v3/ui/views');
const S = require('../../v3/ui/strings');

let passed = 0, failed = 0;
const failures = [];

function test(name, fn) {
    try { fn(); passed += 1; process.stdout.write('.'); }
    catch (e) { failed += 1; failures.push({ name, error: e }); process.stdout.write('F'); }
}

// ── hash resolution ──────────────────────────────────────────────────────

test('an empty hash is the situation view', () => {
    ['', '#', '#/'].forEach((hash) => {
        const route = V.resolveHash(hash);
        assert.strictEqual(route.view, V.SITUATION, hash);
        assert.strictEqual(route.recognised, true, hash);
        assert.strictEqual(route.scenarioId, null);
    });
});

test('a non-string hash resolves rather than throwing', () => {
    [null, undefined, 0, {}].forEach((hash) => {
        assert.strictEqual(V.resolveHash(hash).view, V.SITUATION);
    });
});

test('the verification view has its own route', () => {
    const route = V.resolveHash('#/verify');
    assert.strictEqual(route.view, V.VERIFY);
    assert.strictEqual(route.recognised, true);
});

test('a scenario route carries the scenario id', () => {
    const route = V.resolveHash('#/scenario/taiwan_contingency');
    assert.strictEqual(route.view, V.SCENARIO);
    assert.strictEqual(route.scenarioId, 'taiwan_contingency');
});

test('a percent-encoded scenario id is decoded', () => {
    assert.strictEqual(V.resolveHash('#/scenario/a%2Fb').scenarioId, 'a/b');
});

test('a malformed escape lands on the situation board instead of throwing', () => {
    const route = V.resolveHash('#/scenario/%E0%A4%A');
    assert.strictEqual(route.view, V.SITUATION);
    assert.strictEqual(route.recognised, false);
});

test('a scenario route with no id is not a scenario view', () => {
    const route = V.resolveHash('#/scenario/');
    assert.strictEqual(route.view, V.SITUATION);
    assert.strictEqual(route.recognised, false);
});

test('an unknown hash goes home and says it was sent there', () => {
    const route = V.resolveHash('#/whatever');
    assert.strictEqual(route.view, V.SITUATION);
    assert.strictEqual(route.recognised, false);
});

test('hashFor round-trips every view', () => {
    assert.strictEqual(V.resolveHash(V.hashFor(V.SITUATION, null)).view, V.SITUATION);
    assert.strictEqual(V.resolveHash(V.hashFor(V.VERIFY, null)).view, V.VERIFY);
    const hash = V.hashFor(V.SCENARIO, 'korean peninsula/1');
    assert.strictEqual(V.resolveHash(hash).scenarioId, 'korean peninsula/1');
});

test('a scenario hash without an id degrades to the situation hash', () => {
    assert.strictEqual(V.hashFor(V.SCENARIO, null), V.hashFor(V.SITUATION, null));
});

// ── visibility ───────────────────────────────────────────────────────────

test('exactly one container is visible for every route', () => {
    ['#/', '#/verify', '#/scenario/x', '#/nonsense'].forEach((hash) => {
        const shown = V.visibilityFor(V.resolveHash(hash))
            .filter((entry) => !entry.hidden);
        assert.strictEqual(shown.length, 1, hash);
    });
});

test('the situation view holds no Tier 2 container', () => {
    const hidden = V.visibilityFor(V.resolveHash('#/'))
        .filter((entry) => entry.hidden).map((entry) => entry.view);
    assert.ok(hidden.indexOf(V.VERIFY) !== -1);
    assert.ok(hidden.indexOf(V.SCENARIO) !== -1);
});

test('visibility covers every declared container and nothing else', () => {
    const ids = V.visibilityFor(V.resolveHash('#/')).map((entry) => entry.id).sort();
    assert.deepStrictEqual(ids, Object.keys(V.CONTAINERS)
        .map((view) => V.CONTAINERS[view]).sort());
});

// ── navigation ───────────────────────────────────────────────────────────

test('the navigation has exactly two items (P9 §3.2)', () => {
    assert.strictEqual(V.navStateFor(V.resolveHash('#/')).length, 2);
});

test('the current view is the exact navigation item', () => {
    const nav = V.navStateFor(V.resolveHash('#/verify'));
    const exact = nav.filter((item) => item.exact);
    assert.strictEqual(exact.length, 1);
    assert.strictEqual(exact[0].view, V.VERIFY);
});

test('the scenario view marks 状況 as its branch but not as the page', () => {
    const nav = V.navStateFor(V.resolveHash('#/scenario/taiwan_contingency'));
    const situation = nav.filter((item) => item.view === V.SITUATION)[0];
    assert.strictEqual(situation.branch, true);
    assert.strictEqual(situation.exact, false,
        'claiming 状況 is the current page while a face is on screen would '
        + 'be a lie in the accessibility tree');
});

test('every navigation label is a defined key', () => {
    V.navStateFor(V.resolveHash('#/')).forEach((item) => {
        assert.notStrictEqual(S.t(item.labelKey), item.labelKey, item.labelKey);
    });
});

// ── scenario face scope ──────────────────────────────────────────────────

const NAMES = { taiwan_contingency: '台湾正面' };

test('the scope is absent outside the scenario view', () => {
    const scope = V.faceScope(V.resolveHash('#/'), 'taiwan_contingency', NAMES);
    assert.strictEqual(scope.present, false);
    assert.strictEqual(scope.noticeKey, null);
});

test('a served face that matches the route raises no notice', () => {
    const scope = V.faceScope(V.resolveHash('#/scenario/taiwan_contingency'),
                              'taiwan_contingency', NAMES);
    assert.strictEqual(scope.match, true);
    assert.strictEqual(scope.noticeKey, null);
    assert.strictEqual(scope.requestedLabel, '台湾正面');
});

test('a face served for another scenario says so', () => {
    const scope = V.faceScope(V.resolveHash('#/scenario/baltic_pressure'),
                              'taiwan_contingency', NAMES);
    assert.strictEqual(scope.match, false);
    assert.strictEqual(scope.noticeKey, 'ui.scenario.notice.other_scenario');
    assert.strictEqual(scope.servedLabel, '台湾正面');
    assert.strictEqual(scope.requestedLabel, 'baltic_pressure',
        'an id with no display name shows as the id, never as absent');
});

test('an unfetched face says it is unfetched rather than mismatched', () => {
    const scope = V.faceScope(V.resolveHash('#/scenario/baltic_pressure'), null, NAMES);
    assert.strictEqual(scope.noticeKey, 'ui.scenario.notice.not_loaded');
});

test('every notice the scope can raise is a defined key', () => {
    [V.faceScope(V.resolveHash('#/scenario/x'), null, null),
     V.faceScope(V.resolveHash('#/scenario/x'), 'y', null)].forEach((scope) => {
        assert.notStrictEqual(S.t(scope.noticeKey), scope.noticeKey, scope.noticeKey);
    });
});

// ── onboarding ───────────────────────────────────────────────────────────

test('the onboarding toggle names both directions', () => {
    assert.notStrictEqual(V.onboardingToggleKey(true), V.onboardingToggleKey(false));
    [true, false].forEach((open) => {
        const key = V.onboardingToggleKey(open);
        assert.notStrictEqual(S.t(key), key, key);
    });
});

// ── the DOM half ─────────────────────────────────────────────────────────

function makeDoc() {
    const nodes = {};
    ['view-situation', 'view-scenario', 'view-verify', 'nav-situation',
     'nav-verify', 'onboarding-body', 'onboarding-toggle'].forEach((id) => {
        nodes[id] = {
            id: id, hidden: false, className: '', textContent: '', attrs: {},
            listeners: {},
            setAttribute(name, value) { this.attrs[name] = value; },
            getAttribute(name) {
                return Object.prototype.hasOwnProperty.call(this.attrs, name)
                    ? this.attrs[name] : null;
            },
            addEventListener(name, fn) { this.listeners[name] = fn; },
        };
    });
    return { nodes, getElementById(id) { return nodes[id] || null; } };
}

function makeWin(hash) {
    return {
        location: { hash: hash },
        listeners: {},
        addEventListener(name, fn) { this.listeners[name] = fn; },
    };
}

test('binding shows the routed view and hides the others', () => {
    const doc = makeDoc();
    const win = makeWin('#/verify');
    V.createViews({ doc, win }).bind();
    assert.strictEqual(doc.nodes['view-verify'].hidden, false);
    assert.strictEqual(doc.nodes['view-situation'].hidden, true);
    assert.strictEqual(doc.nodes['view-scenario'].hidden, true);
});

test('the navigation announces the current page to assistive technology', () => {
    const doc = makeDoc();
    V.createViews({ doc, win: makeWin('#/verify') }).bind();
    assert.strictEqual(doc.nodes['nav-verify'].getAttribute('aria-current'), 'page');
    assert.strictEqual(doc.nodes['nav-situation'].getAttribute('aria-current'), 'false');
});

test('go() moves the hash and the screen together', () => {
    const doc = makeDoc();
    const win = makeWin('#/');
    const views = V.createViews({ doc, win });
    views.bind();
    views.go(V.hashFor(V.SCENARIO, 'taiwan_contingency'));
    assert.strictEqual(win.location.hash, '#/scenario/taiwan_contingency');
    assert.strictEqual(doc.nodes['view-scenario'].hidden, false,
        'the view must not lag the URL by one asynchronous hashchange');
    assert.strictEqual(views.route().scenarioId, 'taiwan_contingency');
});

test('a hashchange re-applies the route', () => {
    const doc = makeDoc();
    const win = makeWin('#/');
    V.createViews({ doc, win }).bind();
    win.location.hash = '#/verify';
    win.listeners.hashchange();
    assert.strictEqual(doc.nodes['view-verify'].hidden, false);
});

test('the route callback fires with the resolved route', () => {
    const doc = makeDoc();
    const seen = [];
    V.createViews({ doc, win: makeWin('#/scenario/x'),
                    onRoute: (route) => seen.push(route.view) }).bind();
    assert.deepStrictEqual(seen, [V.SCENARIO]);
});

test('a window without location or listeners still resolves to the board', () => {
    const doc = makeDoc();
    const views = V.createViews({ doc, win: {} });
    views.bind();
    assert.strictEqual(doc.nodes['view-situation'].hidden, false);
    assert.strictEqual(views.route().view, V.SITUATION);
});

test('the onboarding card is CLOSED by default and toggles open (P9 §1.4 D-17)', () => {
    const doc = makeDoc();
    const views = V.createViews({ doc, win: makeWin('#/') });
    views.bind();
    assert.strictEqual(doc.nodes['onboarding-body'].hidden, true);
    assert.strictEqual(views.onboardingOpen(), false);
    assert.strictEqual(doc.nodes['onboarding-toggle'].getAttribute('aria-expanded'),
                       'false');
    doc.nodes['onboarding-toggle'].listeners.click();
    assert.strictEqual(doc.nodes['onboarding-body'].hidden, false);
    assert.strictEqual(views.onboardingOpen(), true);
});

test('a missing element never breaks an application', () => {
    const doc = { getElementById() { return null; } };
    const views = V.createViews({ doc, win: makeWin('#/verify') });
    views.bind();
    assert.strictEqual(views.route().view, V.VERIFY);
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
