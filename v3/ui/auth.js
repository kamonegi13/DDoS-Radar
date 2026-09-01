/**
 * Noroshi v3 L7 — the session, and the gate's whole decision (S1-UI-001..005).
 *
 * §7-2 #99 registered the absence of this: authorisation was never at risk
 * (every route carries an `Access` declaration the server enforces), but an
 * unauthenticated analyst reached a dashboard whose panels answered 401 one
 * by one. That is the G-10 failure class wearing an auth costume — a screen
 * that looks live and is not — so the remedy is the same: the state is
 * explicit, it is on the screen, and it is never inferred from emptiness.
 *
 * Four decisions live here rather than in the DOM layer.
 *
 * **The access token is held in memory only.** v1 keeps it in
 * `localStorage`, and `app.js` used to read a `noroshi.v3.token` key that
 * nothing ever wrote. Persisting a bearer token puts a credential where any
 * script the page executes can read it for as long as the browser lives —
 * which is exactly what S1-UI-002 spent §7-2 #103 closing for the refresh
 * token. What survives a reload is the httpOnly refresh cookie, which JS
 * cannot read at all, so `begin()` asks the server rather than a store.
 *
 * **Refresh is serialised.** Several panels fetch at once; a 401 storm must
 * produce ONE refresh, not one per panel. `_pending` is that promise, and
 * every caller waits on the same one.
 *
 * **A 401 is retried exactly once.** Once, because a token that is refused
 * after a successful refresh is not a stale token — it is a revoked session
 * or a lost privilege, and retrying that is a loop with a spinner on it.
 *
 * **A lock always carries a reason from a closed set.** "Signed out",
 * "expired", "revoked", "unavailable" and "refused" are different facts and
 * the analyst is told which. The set is closed because a reason invented at
 * a call site is a message no dictionary has (S1-UI-023).
 *
 * Everything is injected: `post` (raw transport), `cookies` (the document's
 * cookie string), `now`. There is no DOM here and no `window`, so the whole
 * state machine runs under Node.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiAuth = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var API_PREFIX = '/api/v3';
    var LOGIN_PATH = API_PREFIX + '/auth/login';
    var REFRESH_PATH = API_PREFIX + '/auth/refresh';
    var LOGOUT_PATH = API_PREFIX + '/auth/logout';

    //: The readable half of the pair `v3/api/cookies.py` declares. The SPA
    //: reads it and echoes it into the header below; the refresh token
    //: itself is httpOnly and is never visible here, which is the point.
    var CSRF_COOKIE = 'noroshi_v3_csrf_refresh';
    var CSRF_HEADER = 'X-CSRF-TOKEN';

    //: The three states. `CHECKING` is not cosmetic — it is the difference
    //: between "you are not signed in" and "we have not asked yet", and
    //: showing the sign-in form during the silent refresh would make every
    //: reload look like a session loss.
    var CHECKING = 'checking';
    var LOCKED = 'locked';
    var OPEN = 'open';
    var STATES = [CHECKING, LOCKED, OPEN];

    //: Why the gate is closed. Closed set; each maps to one i18n key.
    var REASONS = {
        never: 'ui.auth.reason.never',
        expired: 'ui.auth.reason.expired',
        revoked: 'ui.auth.reason.revoked',
        signed_out: 'ui.auth.reason.signed_out',
        refused: 'ui.auth.reason.refused',
        throttled: 'ui.auth.reason.throttled',
        unavailable: 'ui.auth.reason.unavailable',
        transport: 'ui.auth.reason.transport',
    };

    /**
     * One cookie's value out of a `document.cookie` string.
     *
     * Pure so it can be tested, and tolerant of the format's oddities: the
     * separator is `; `, values may contain `=`, and a missing cookie is
     * `null` rather than `''` — an empty CSRF token and no CSRF token lead
     * to the same refusal, but only one of them is worth reporting.
     */
    function readCookie(cookieString, name) {
        var parts = String(cookieString || '').split(';');
        for (var i = 0; i < parts.length; i += 1) {
            var entry = parts[i].trim();
            var split = entry.indexOf('=');
            if (split <= 0) continue;
            if (entry.slice(0, split) !== name) continue;
            var value = entry.slice(split + 1);
            return value === '' ? null : decodeURIComponent(value);
        }
        return null;
    }

    /**
     * Map a failed auth response onto one of the closed reasons.
     *
     * A code the surface does not declare is reported as `refused` rather
     * than guessed at, and never as success.
     */
    function reasonFor(status, body) {
        var code = body && typeof body.error === 'string' ? body.error : null;
        if (status === null || status === undefined) return 'transport';
        if (status === 503 || code === 'api.unavailable') return 'unavailable';
        if (status === 429 || code === 'api.too_many_requests') return 'throttled';
        return 'refused';
    }

    function messageOf(body) {
        var detail = body && body.error_detail;
        return (detail && detail.message) ? detail.message : null;
    }

    /**
     * Create the session.
     *
     * @param {object} options
     * @param {function} options.post    (path, body, headers) -> Promise<{status, json}>
     * @param {function} [options.cookies] () -> string   (document.cookie)
     * @param {function} [options.onChange] (session) -> void
     */
    function createSession(options) {
        options = options || {};
        var post = options.post;
        if (typeof post !== 'function') {
            throw new Error('createSession needs a post transport');
        }
        var cookies = options.cookies || function () { return ''; };
        var onChange = options.onChange || function () {};

        var _state = CHECKING;
        var _reason = 'never';
        var _message = null;
        var _identity = null;
        var _token = null;
        var _pending = null;

        function _announce() { onChange(surface); }

        function _open(payload) {
            _token = payload.access_token || null;
            _identity = {
                userId: payload.user_id || null,
                role: payload.role || null,
                accessExpiresSec: typeof payload.access_expires_sec === 'number'
                    ? payload.access_expires_sec : null,
            };
            _state = OPEN;
            _reason = null;
            _message = null;
            _announce();
            return true;
        }

        function _lock(reason, message) {
            _token = null;
            _identity = null;
            _state = LOCKED;
            _reason = Object.prototype.hasOwnProperty.call(REASONS, reason)
                ? reason : 'refused';
            _message = message || null;
            _announce();
            return false;
        }

        function csrfToken() { return readCookie(cookies(), CSRF_COOKIE); }

        function _sessionOf(response) {
            var body = response && response.json;
            return (body && body.session) ? body.session : null;
        }

        /**
         * Exchange the httpOnly refresh cookie for a new access token.
         *
         * Serialised: concurrent callers share one in-flight request, so a
         * screen with seven panels does not send seven refreshes and race
         * itself into seven different answers.
         */
        function renew(reasons) {
            // Two different failures, two different sentences. "No cookie
            // at all" and "the server refused the cookie" are not the same
            // fact, and telling the analyst the wrong one is how "your
            // session expired" comes to mean "we never had one".
            var absent = (reasons && reasons.absent) || 'never';
            var refused = (reasons && reasons.refused) || 'expired';
            if (_pending) return _pending;
            var csrf = csrfToken();
            if (!csrf) {
                // No companion cookie means no session was ever established
                // in this browser (or it was cleared by logout). Saying so
                // is better than a 401 round trip that says the same thing.
                return Promise.resolve(_lock(absent));
            }
            var headers = {};
            headers[CSRF_HEADER] = csrf;
            _pending = Promise.resolve()
                .then(function () { return post(REFRESH_PATH, {}, headers); })
                .then(function (response) {
                    var session = _sessionOf(response);
                    if (response && response.status === 200 && session) {
                        return _open(session);
                    }
                    var status = response ? response.status : null;
                    var body = response ? response.json : null;
                    var reason = reasonFor(status, body);
                    return _lock(reason === 'refused' ? refused : reason,
                                 messageOf(body));
                })
                .catch(function (err) {
                    return _lock('transport', err && err.message ? err.message
                                 : String(err));
                })
                .then(function (result) { _pending = null; return result; });
            return _pending;
        }

        /**
         * Boot. Ask the server whether this browser still has a session.
         *
         * S1-UI-004's "the session survives a reload" is answered here and
         * NOT by a persisted token: the refresh cookie is the thing that
         * survived, and it is httpOnly, so only the server can say.
         */
        function begin() {
            _state = CHECKING;
            _announce();
            return renew({ absent: 'never', refused: 'expired' });
        }

        function signIn(userId, password) {
            return Promise.resolve()
                .then(function () {
                    return post(LOGIN_PATH,
                                { user_id: userId, password: password }, {});
                })
                .then(function (response) {
                    var session = _sessionOf(response);
                    if (response && response.status === 200 && session) {
                        return _open(session);
                    }
                    var status = response ? response.status : null;
                    var body = response ? response.json : null;
                    return _lock(reasonFor(status, body), messageOf(body));
                })
                .catch(function (err) {
                    return _lock('transport', err && err.message ? err.message
                                 : String(err));
                });
        }

        /**
         * End the session. The floor moves server-side and the cookies are
         * cleared by the same response, so a failure to reach the server
         * still locks the screen — a UI that stayed open because the logout
         * request failed is the worst of both answers.
         */
        function signOut() {
            var headers = {};
            if (_token) headers.Authorization = 'Bearer ' + _token;
            return Promise.resolve()
                .then(function () { return post(LOGOUT_PATH, {}, headers); })
                .catch(function () { return null; })
                .then(function () { return _lock('signed_out'); });
        }

        /**
         * A 401 arrived mid-session. Refresh once, then say so.
         *
         * Returns a promise of "retry the original request". `false` means
         * the caller must NOT retry and the gate is now locked with the
         * reason on screen — never a silently blank panel (§7-2 #99 / G-10).
         */
        function onUnauthorized() {
            if (_state === LOCKED) return Promise.resolve(false);
            return renew({ absent: 'revoked', refused: 'revoked' });
        }

        var surface = {
            state: function () { return _state; },
            reason: function () { return _reason; },
            reasonKey: function () {
                return _reason ? REASONS[_reason] : null;
            },
            message: function () { return _message; },
            identity: function () { return _identity; },
            token: function () { return _token; },
            csrfToken: csrfToken,
            isOpen: function () { return _state === OPEN; },
            begin: begin,
            signIn: signIn,
            signOut: signOut,
            renew: renew,
            onUnauthorized: onUnauthorized,
        };
        return surface;
    }

    return {
        createSession: createSession,
        readCookie: readCookie,
        reasonFor: reasonFor,
        API_PREFIX: API_PREFIX,
        LOGIN_PATH: LOGIN_PATH,
        REFRESH_PATH: REFRESH_PATH,
        LOGOUT_PATH: LOGOUT_PATH,
        CSRF_COOKIE: CSRF_COOKIE,
        CSRF_HEADER: CSRF_HEADER,
        CHECKING: CHECKING,
        LOCKED: LOCKED,
        OPEN: OPEN,
        STATES: STATES,
        REASONS: REASONS,
    };
});
