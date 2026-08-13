/**
 * Noroshi v3 L7 — which view is on screen (pure resolution + thin DOM).
 *
 * P9 §2 R-B: **one view answers one question**. WP-4.2 read P8's Tier 0/1/2
 * as three sections of one page and stacked all five loop stages under a
 * single `<main>`, which is diagnosis D-1: seven audit tables sat permanently
 * below the board an analyst is supposed to read in ten seconds, so "what am
 * I meant to be looking at" had no answer in the structure. The Tier
 * *content* is unchanged — P8 §2's inventory and its supplying APIs are
 * untouched here. What changes is WHEN a surface is on screen.
 *
 * Three views, two of them reachable from the top navigation:
 *
 *   `#/`                 状況 — the situation board and the attention lane
 *   `#/scenario/<id>`    シナリオ面 — the conclusion face, the geographic
 *                        face and the feedback surface, reached by choosing
 *                        a card or a lane row (never from the navigation:
 *                        it is a view ABOUT something, so it is entered
 *                        through the thing it is about)
 *   `#/verify`           検証 — Tier 2 in full
 *
 * The resolution half is pure and total: every hash resolves to a view,
 * unrecognised ones to the situation board with `recognised: false` rather
 * than to a blank screen (S1-UI-008 — a surface that shows nothing must at
 * minimum show something else). Node tests it directly; the DOM half only
 * sets `hidden` on the three containers and `aria-current` on two links.
 *
 * Hiding a view does NOT stop it rendering. `app.js` keeps writing into
 * every container on every cycle, so switching views shows current data
 * rather than starting a fetch — and the freshness badge inside each view
 * still speaks for its own section.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiViews = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var S = (typeof require === 'function')
        ? require('./strings')
        : (typeof window !== 'undefined' ? window.NoroshiStrings : null);
    var Fmt = (typeof require === 'function')
        ? require('./format')
        : (typeof window !== 'undefined' ? window.NoroshiFormat : null);

    var SITUATION = 'situation';
    var SCENARIO = 'scenario';
    var VERIFY = 'verify';

    //: view -> the element that holds it. The DOM half toggles `hidden` on
    //: exactly these three and nothing else: the NP7 bar, the critical
    //: banner, the toast rail, the dim overlay and the login gate are
    //: GLOBAL and live outside every view, because a disclaimer or an
    //: alarm that a route can take off the screen is not permanent
    //: (S1-UI-024a / S1-UI-030).
    var CONTAINERS = {};
    CONTAINERS[SITUATION] = 'view-situation';
    CONTAINERS[SCENARIO] = 'view-scenario';
    CONTAINERS[VERIFY] = 'view-verify';

    var HASH_SITUATION = '#/';
    var HASH_VERIFY = '#/verify';
    var HASH_SCENARIO_PREFIX = '#/scenario/';

    //: The top navigation, in full. Two items — P9 §3.2. The scenario view
    //: is deliberately not here.
    var NAV = [
        { view: SITUATION, id: 'nav-situation', labelKey: 'ui.nav.situation' },
        { view: VERIFY, id: 'nav-verify', labelKey: 'ui.nav.verify' },
    ];

    function hashFor(view, scenarioId) {
        if (view === VERIFY) return HASH_VERIFY;
        if (view === SCENARIO && scenarioId) {
            return HASH_SCENARIO_PREFIX + encodeURIComponent(String(scenarioId));
        }
        return HASH_SITUATION;
    }

    function _route(view, scenarioId, recognised) {
        return {
            view: view,
            scenarioId: scenarioId,
            recognised: recognised,
            hash: hashFor(view, scenarioId),
        };
    }

    function _decode(raw) {
        if (!raw) return null;
        try {
            var decoded = decodeURIComponent(raw);
            return decoded === '' ? null : decoded;
        } catch (err) {
            // A malformed escape is not a scenario. Falling through to the
            // situation board is the honest answer; throwing here would
            // take the whole screen down for a bad URL.
            return null;
        }
    }

    /**
     * Resolve a location hash to a view. Total: never throws, never returns
     * null, and an unknown hash lands on the situation board carrying
     * `recognised: false` so a caller can tell "home" from "sent home".
     */
    function resolveHash(hash) {
        var raw = typeof hash === 'string' ? hash : '';
        if (raw === '' || raw === '#' || raw === HASH_SITUATION) {
            return _route(SITUATION, null, true);
        }
        if (raw === HASH_VERIFY) return _route(VERIFY, null, true);
        if (raw.indexOf(HASH_SCENARIO_PREFIX) === 0) {
            var scenarioId = _decode(raw.slice(HASH_SCENARIO_PREFIX.length));
            if (scenarioId === null) return _route(SITUATION, null, false);
            return _route(SCENARIO, scenarioId, true);
        }
        return _route(SITUATION, null, false);
    }

    /** Which containers are on screen. One visible, always exactly one. */
    function visibilityFor(route) {
        var current = (route && route.view) || SITUATION;
        return Object.keys(CONTAINERS).map(function (view) {
            return { view: view, id: CONTAINERS[view], hidden: view !== current };
        });
    }

    /**
     * The navigation state.
     *
     * `exact` drives `aria-current="page"`; `branch` marks 状況 while the
     * scenario view is open, because that view was entered FROM the board
     * and marking neither item would leave the navigation looking inert.
     * The two are separate flags rather than one: telling a screen reader
     * that 状況 is the current page while the scenario face is on screen
     * would be a lie in the accessibility tree.
     */
    function navStateFor(route) {
        var current = (route && route.view) || SITUATION;
        return NAV.map(function (item) {
            return {
                view: item.view,
                id: item.id,
                labelKey: item.labelKey,
                hash: hashFor(item.view, null),
                exact: item.view === current,
                branch: item.view === SITUATION && current === SCENARIO,
            };
        });
    }

    /**
     * What the scenario view is actually showing, versus what was asked for.
     *
     * R2 is fetched for the FOCUSED scenario only (P8 §2), so choosing a
     * background card can ask for a face the server has not served. v1's
     * answer to that shape was to draw the previous scenario's numbers
     * under the new scenario's name (S1-UI-048's defect). Here the view
     * says which scenario the face below belongs to, and says so from two
     * ids it was handed — it does not fetch, guess, or silently rewrite the
     * heading.
     */
    function faceScope(route, servedScenarioId, names) {
        var present = !!(route && route.view === SCENARIO && route.scenarioId);
        var requested = present ? route.scenarioId : null;
        var served = (typeof servedScenarioId === 'string' && servedScenarioId)
            ? servedScenarioId : null;
        var label = function (id) {
            if (id === null) return Fmt.ABSENT;
            return (names && typeof names[id] === 'string' && names[id]) ? names[id] : id;
        };
        var noticeKey = null;
        if (present) {
            if (served === null) noticeKey = 'ui.scenario.notice.not_loaded';
            else if (served !== requested) noticeKey = 'ui.scenario.notice.other_scenario';
        }
        return {
            present: present,
            requested: requested,
            requestedLabel: label(requested),
            served: served,
            servedLabel: label(served),
            match: present && served !== null && served === requested,
            noticeKey: noticeKey,
        };
    }

    /**
     * The onboarding card's toggle label (P9 §3.6).
     *
     * P9 asks for the dismissal to persist in the analyst's server-side
     * preferences. R14's registry holds deployment configuration, not
     * per-analyst state, and there is no user-preference surface on any
     * served API — so the card is collapsible with the panel CLOSED by
     * default (P9 §1.4 D-17) and the state is not written anywhere.
     * Half-persisting it in `localStorage` is what S1-UI-035 forbids (a
     * decision that lives in one browser is a decision the organisation
     * cannot see), and the gap is registered on the 未着地の機能 table
     * rather than papered over.
     */
    function onboardingToggleKey(open) {
        return open ? 'ui.onboarding.collapse' : 'ui.onboarding.expand';
    }

    // ── the DOM half ────────────────────────────────────────────────────

    /**
     * @param {object} options
     * @param {Document} options.doc
     * @param {Window} [options.win]        for `location` and `hashchange`
     * @param {function} [options.onRoute]  called after every application
     */
    function createViews(options) {
        var doc = options.doc;
        var win = options.win
            || (typeof window !== 'undefined' ? window : null);
        var current = resolveHash(_readHash());
        // CLOSED by default (P9 §1.4 D-17): the card is first-sight
        // explanation, and a guide that is always open is furniture.
        var onboardingOpen = false;

        function _readHash() {
            return (win && win.location && typeof win.location.hash === 'string')
                ? win.location.hash : '';
        }

        function $(id) { return doc.getElementById(id); }

        function _applyNav() {
            navStateFor(current).forEach(function (item) {
                var node = $(item.id);
                if (!node) return;
                if (item.exact) node.setAttribute('aria-current', 'page');
                else node.setAttribute('aria-current', 'false');
                node.className = 'nav-item'
                    + (item.exact ? ' nav-current' : '')
                    + (item.branch ? ' nav-branch' : '');
            });
        }

        function apply() {
            current = resolveHash(_readHash());
            visibilityFor(current).forEach(function (entry) {
                var node = $(entry.id);
                if (node) node.hidden = entry.hidden;
            });
            _applyNav();
            if (options.onRoute) options.onRoute(current);
        }

        /** Navigate. The hash is the record of where we are, so it moves first. */
        function go(hash) {
            if (win && win.location && typeof win.location.hash === 'string') {
                win.location.hash = hash;
            }
            // Applied immediately as well as on `hashchange`: the event is
            // asynchronous, and a view that lags one click behind the URL
            // is the same class of defect as a stale redraw.
            apply();
        }

        function _applyOnboarding() {
            var body = $('onboarding-body');
            if (body) body.hidden = !onboardingOpen;
            var toggle = $('onboarding-toggle');
            if (toggle) {
                toggle.textContent = S.t(onboardingToggleKey(onboardingOpen));
                toggle.setAttribute('aria-expanded', onboardingOpen ? 'true' : 'false');
            }
        }

        function bind() {
            if (win && win.addEventListener) {
                win.addEventListener('hashchange', apply);
            }
            var toggle = $('onboarding-toggle');
            if (toggle && toggle.addEventListener) {
                toggle.addEventListener('click', function () {
                    onboardingOpen = !onboardingOpen;
                    _applyOnboarding();
                });
            }
            _applyOnboarding();
            apply();
        }

        return {
            bind: bind,
            apply: apply,
            go: go,
            route: function () { return current; },
            onboardingOpen: function () { return onboardingOpen; },
        };
    }

    return {
        createViews: createViews,
        resolveHash: resolveHash,
        hashFor: hashFor,
        visibilityFor: visibilityFor,
        navStateFor: navStateFor,
        faceScope: faceScope,
        onboardingToggleKey: onboardingToggleKey,
        CONTAINERS: CONTAINERS,
        NAV: NAV,
        SITUATION: SITUATION,
        SCENARIO: SCENARIO,
        VERIFY: VERIFY,
    };
});
