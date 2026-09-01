/**
 * Noroshi v3 L7 — what the login gate SHOWS, as a value.
 *
 * `auth.js` decides what the session IS; this decides what the screen says
 * about it. Splitting them is the same division the rest of this layer
 * uses (`board.js` / `lane.js` compute, `app.js` writes), and it is what
 * makes the gate's presentation testable under Node: `viewOf` is a pure
 * function of a session, so "an expired session says expired, not wrong
 * password" is an assertion rather than a screenshot.
 *
 * Three properties are decided here and nowhere else.
 *
 * **`checking` is not `locked`.** During the silent refresh the form is
 * present but disabled and the line reads "checking", because showing
 * "please sign in" for the half second before the server answers would
 * make every reload look like a session loss.
 *
 * **A closed gate always states a reason.** The key comes from `auth.js`'s
 * closed set; there is no branch that yields an empty line, because a form
 * with no explanation is indistinguishable from a form the analyst reached
 * by accident.
 *
 * **`<main>` is hidden whenever the gate is not open.** Not dimmed, not
 * overlaid — hidden, so an unauthenticated analyst cannot be looking at
 * panels that are about to answer 401 one at a time (§7-2 #99, and G-10's
 * failure class applied to auth).
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiGate = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var S = (typeof require === 'function')
        ? require('./strings')
        : (typeof window !== 'undefined' ? window.NoroshiStrings : null);
    var Auth = (typeof require === 'function')
        ? require('./auth')
        : (typeof window !== 'undefined' ? window.NoroshiAuth : null);

    var _t = S.t;
    var CHECKING = 'checking';

    /**
     * The gate's display, as data.
     *
     * @param {object} session  the surface from `auth.js::createSession`
     * @returns {object} `{gateHidden, mainHidden, barHidden, reasonKey,
     *                     detailMessage, submitKey, submitDisabled,
     *                     identity}`
     */
    function viewOf(session) {
        if (!session) {
            // No session object at all is a composition failure, and the
            // safe reading of it is "closed": a gate that defaulted open
            // would show the dashboard to whoever arrived.
            return {
                gateHidden: false, mainHidden: true, barHidden: true,
                reasonKey: 'ui.auth.reason.never', detailMessage: null,
                submitKey: 'ui.auth.submit', submitDisabled: false,
                identity: null,
            };
        }
        var open = session.isOpen();
        var checking = session.state() === CHECKING;
        var who = session.identity();
        return {
            gateHidden: open,
            mainHidden: !open,
            barHidden: !open,
            reasonKey: checking ? 'ui.auth.checking' : session.reasonKey(),
            // Server prose is shown only when the answer is settled — a
            // stale message under a "checking" line reads as the verdict.
            detailMessage: checking ? null : session.message(),
            submitKey: checking ? 'ui.auth.submitting' : 'ui.auth.submit',
            submitDisabled: checking,
            identity: who ? { user: who.userId || '', role: who.role || '' }
                          : null,
        };
    }

    /**
     * The gate's own DOM half. Small, and the only place that writes it.
     *
     * `app.js` owns the analyst loop's elements; this owns the gate's. One
     * 900-line DOM file for both would be the accumulation P8 §7 retired,
     * in a different spelling — so the split is by feature, and
     * `tests/test_v3_ui_discipline.py::TestTheWiringResolves` scans this
     * file too, so every id written here still has to exist in the markup.
     *
     * @param {object} options
     * @param {object} options.doc        the document
     * @param {function} options.transport (url, init) -> Promise<{status,json}>
     * @param {function} [options.cookies] () -> string (defaults to doc.cookie)
     * @param {function} [options.onOpen]  called when the session opens
     * @param {function} [options.onLock]  called when it closes
     * @param {function} [options.onRefused] (messageKey) -> void
     */
    function createGateUi(options) {
        options = options || {};
        var doc = options.doc;
        var transport = options.transport;
        var onOpen = options.onOpen || function () {};
        var onLock = options.onLock || function () {};
        var onRefused = options.onRefused || function () {};

        // The auth routes take a JSON body and, on refresh, the CSRF
        // header; the cookie itself rides because the request is
        // same-origin and the browser attaches it. Built here rather than
        // by the caller so the gate's transport shape is one thing.
        function post(path, body, headers) {
            return transport(path, {
                method: 'POST',
                headers: Object.assign({ Accept: 'application/json',
                                         'Content-Type': 'application/json' },
                                       headers || {}),
                credentials: 'same-origin',
                body: JSON.stringify(body || {}),
            });
        }

        function $(id) { return doc.getElementById(id); }

        function setHidden(id, hidden) {
            var node = $(id);
            if (node) node.hidden = hidden;
        }

        function setText(id, text) {
            var node = $(id);
            if (node) node.textContent = text;
        }

        function render() {
            var view = viewOf(session);
            setHidden('auth-gate', view.gateHidden);
            setHidden('app-main', view.mainHidden);
            setHidden('auth-bar', view.barHidden);
            setText('auth-reason', view.reasonKey ? _t(view.reasonKey) : '');
            // `textContent`, never `innerHTML`: this is the one place the
            // UI shows the server's own prose verbatim.
            setText('auth-detail', view.detailMessage
                ? _t('ui.auth.detail', { why: view.detailMessage }) : '');
            setHidden('auth-detail', !view.detailMessage);
            setText('auth-submit', _t(view.submitKey));
            var submit = $('auth-submit');
            if (submit) submit.disabled = view.submitDisabled;
            setText('auth-identity',
                    view.identity ? _t('ui.auth.identity', view.identity) : '');
        }

        var session = Auth.createSession({
            post: post,
            cookies: options.cookies || function () { return doc.cookie; },
            onChange: function (current) {
                render();
                if (current.isOpen()) onOpen(current);
                else if (current.state() !== CHECKING) onLock(current);
            },
        });

        function submit(event) {
            if (event && event.preventDefault) event.preventDefault();
            var user = ($('auth-user') || {}).value || '';
            var password = ($('auth-password') || {}).value || '';
            if (!user.trim() || !password) {
                onRefused('ui.auth.required');
                return Promise.resolve(false);
            }
            var button = $('auth-submit');
            if (button) button.disabled = true;
            return session.signIn(user.trim(), password).then(function (ok) {
                // The credential does not stay in the DOM after use.
                var field = $('auth-password');
                if (field) field.value = '';
                render();
                return ok;
            });
        }

        function bind() {
            var form = $('auth-form');
            if (form) form.addEventListener('submit', submit);
            var signout = $('auth-signout');
            if (signout) {
                signout.addEventListener('click', function () {
                    session.signOut();
                });
            }
        }

        return {
            session: session,
            render: render,
            bind: bind,
            submit: submit,
            begin: function () { return session.begin(); },
        };
    }

    return { viewOf: viewOf, createGateUi: createGateUi };
});
