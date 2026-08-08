/**
 * Noroshi v3 L7 — the read/command client (pure logic, injected transport).
 *
 * Every response from L6 is the same envelope: one shape, an `observed_at`,
 * a `data_freshness_sec` the dispatcher stamps, and the NP7 sentence as a
 * required field of the type. This module is the only place that knows that,
 * and it enforces three things the rest of the layer then gets for free.
 *
 * **A response without the NP7 sentence is a broken response.** G-13 was
 * four envelope shapes of which one had quietly lost the disclaimer, and
 * nothing noticed because nothing was checking. Here a missing or altered
 * sentence does not throw and does not blank the screen — it marks the
 * result `disclaimerMissing`, which the shell surfaces as a trust problem.
 * Failing loudly on it would take the screen down over a formatting bug;
 * ignoring it would repeat G-13. Recording it does neither.
 *
 * **A failed fetch keeps the last good data and says the fetch failed.**
 * S1-UI-008 requires the previous data to stay on screen — an empty screen
 * during an outage is worse than a stale one. DP2 requires the staleness to
 * be visible at the same time, which v1 did not do. So `get` returns the
 * held payload together with `ok: false` and the error, and `freshnessOf`
 * downstream can never call that state fresh.
 *
 * **A command's answer is read back, never echoed.** L6 already refuses to
 * repeat a submitted value (`command_response`); this side matches it by
 * exposing `effect` rather than the request body, so a UI cannot report
 * success on the strength of what it asked for. That is the G-15 remedy
 * seen from the browser: ninety-five dead config keys stayed invisible for
 * months because the UI showed what it had sent.
 *
 * The transport is injected so the whole module is testable under Node with
 * no browser and no server.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiClient = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var API_PREFIX = '/api/v3';

    //: The exact sentence. Pinned, not configured — a disclaimer an
    //: operator can blank is a disclaimer that can go missing (S1-CONC-005).
    var NP7_DISCLAIMER =
        'Tool conclusion only — final judgment by organizational process.';
    var DISCLAIMER_FIELD = 'final_judgment_disclaimer';

    //: Error codes L6 can return (v3/api/errors.py).
    var ERROR_CODES = ['api.unavailable', 'api.unauthenticated', 'api.forbidden',
                       'api.bad_request', 'api.not_found',
                       'api.method_not_allowed', 'api.internal_error'];

    function _query(params) {
        var parts = [];
        Object.keys(params || {}).sort().forEach(function (key) {
            var value = params[key];
            if (value === null || value === undefined || value === '') return;
            parts.push(encodeURIComponent(key) + '=' + encodeURIComponent(value));
        });
        return parts.length ? '?' + parts.join('&') : '';
    }

    function _checkDisclaimer(body) {
        if (!body || typeof body !== 'object') return false;
        return body[DISCLAIMER_FIELD] === NP7_DISCLAIMER;
    }

    function _errorOf(body, status) {
        var code = (body && typeof body.error === 'string') ? body.error : null;
        var detail = (body && body.error_detail) || null;
        return {
            code: code && ERROR_CODES.indexOf(code) !== -1 ? code : (code || 'api.transport'),
            status: status === undefined ? null : status,
            message: detail && detail.message ? detail.message : null,
            detail: detail && detail.detail ? detail.detail : null,
            // A code the frontend does not recognise is reported as-is
            // rather than mapped to something familiar (S1-UI-023).
            known: !!(code && ERROR_CODES.indexOf(code) !== -1),
        };
    }

    /**
     * Create a client.
     *
     * @param {object} options
     * @param {function} options.transport  (url, init) -> Promise<{status, json}>
     * @param {function} [options.tokenProvider] () -> string|null
     * @param {function} [options.onUnauthorized] () -> Promise<boolean>
     * @param {function} [options.now]       () -> seconds
     */
    function createClient(options) {
        options = options || {};
        var transport = options.transport;
        if (typeof transport !== 'function') {
            throw new Error('createClient needs a transport');
        }
        var tokenProvider = options.tokenProvider || function () { return null; };
        //: What to do when the surface says 401 mid-session. The POLICY is
        //: not here — `v3/ui/auth.js` owns "refresh once, then lock with a
        //: reason" — because a policy inside the fetch helper is a policy
        //: nothing can test without a fetch. Absent, a 401 is an ordinary
        //: error and the held payload stays on screen with the failure
        //: announced, which is the pre-gate behaviour.
        var onUnauthorized = options.onUnauthorized || null;
        var now = options.now || function () { return Date.now() / 1000; };

        //: Last successful body per resource key. S1-UI-008's "keep the
        //: previous data" lives here rather than in each caller, because a
        //: rule each caller must remember is a rule one caller will not.
        var held = Object.create(null);

        function _headers(hasBody) {
            var headers = { Accept: 'application/json' };
            var token = tokenProvider();
            if (token) headers.Authorization = 'Bearer ' + token;
            if (hasBody) headers['Content-Type'] = 'application/json';
            return headers;
        }

        function _result(key, ok, body, error) {
            var previous = held[key] || null;
            if (ok) held[key] = body;
            var payload = ok ? body : previous;
            return {
                key: key,
                ok: ok,
                // On failure the caller still gets something to render.
                body: payload,
                held: !ok && previous !== null,
                error: error || null,
                fetchedAt: now(),
                observedAt: payload && typeof payload.observed_at === 'number'
                    ? payload.observed_at : null,
                freshnessSec: payload && typeof payload.data_freshness_sec === 'number'
                    ? payload.data_freshness_sec : null,
                servedAt: payload && typeof payload.served_at === 'number'
                    ? payload.served_at : null,
                at: payload && typeof payload.at === 'number' ? payload.at : null,
                // Recorded, not thrown, and never silently ignored.
                disclaimerMissing: ok ? !_checkDisclaimer(body)
                    : (previous ? !_checkDisclaimer(previous) : false),
            };
        }

        function _send(method, url, body) {
            var init = {
                method: method,
                headers: _headers(body !== undefined),
                // The refresh cookie is same-origin and httpOnly; saying so
                // explicitly keeps the transport's behaviour a property of
                // this file rather than of the browser's default.
                credentials: 'same-origin',
            };
            if (body !== undefined) init.body = JSON.stringify(body);
            return transport(url, init);
        }

        /**
         * One request, with EXACTLY one 401 retry.
         *
         * Once, not "until it works": a token still refused after a
         * successful refresh is a revoked session or a lost privilege, and
         * repeating that is a spinner in place of an answer. `retried`
         * makes the bound structural rather than a convention.
         */
        function _request(key, method, path, params, body) {
            var url = API_PREFIX + path + _query(params);

            function attempt(retried) {
                return Promise.resolve()
                    .then(function () { return _send(method, url, body); })
                    .then(function (response) {
                        var status = response ? response.status : null;
                        var payload = response ? response.json : null;
                        if (status >= 200 && status < 300) {
                            return _result(key, true, payload, null);
                        }
                        if (status === 401 && onUnauthorized && !retried) {
                            return Promise.resolve(onUnauthorized())
                                .then(function (mayRetry) {
                                    if (!mayRetry) {
                                        return _result(key, false, null,
                                                       _errorOf(payload, status));
                                    }
                                    return attempt(true);
                                });
                        }
                        return _result(key, false, null,
                                       _errorOf(payload, status));
                    });
            }

            return attempt(false).catch(function (err) {
                // A thrown transport error is a network failure, which is
                // a different thing from a 4xx and must read differently.
                return _result(key, false, null, {
                    code: 'api.transport', status: null,
                    message: err && err.message ? err.message : String(err),
                    detail: null, known: false,
                });
            });
        }

        function get(key, path, params) {
            return _request(key, 'GET', path, params, undefined);
        }

        function command(key, method, path, body) {
            return _request(key, method, path, null, body || {});
        }

        // ── the read projections actually served today ──────────────────
        var reads = {
            scenarios: function () { return get('R1', '/scenarios'); },
            conclusions: function (sid, params) {
                return get('R2', '/scenarios/' + encodeURIComponent(sid) + '/conclusions',
                           params);
            },
            history: function (sid, params) {
                return get('R3', '/scenarios/' + encodeURIComponent(sid)
                           + '/conclusions/history', params);
            },
            conclusion: function (cid) {
                return get('R4', '/conclusions/' + encodeURIComponent(cid));
            },
            derivation: function (cid) {
                return get('R4d', '/conclusions/' + encodeURIComponent(cid) + '/derivation');
            },
            evidence: function (sid, params) {
                return get('R5', '/scenarios/' + encodeURIComponent(sid) + '/evidence',
                           params);
            },
            attention: function (params) { return get('R6', '/attention', params); },
            selfEval: function () { return get('R7', '/self_eval'); },
            sensors: function () { return get('R8', '/sensors'); },
            observations: function (sensorId, params) {
                return get('R8o', '/sensors/' + encodeURIComponent(sensorId)
                           + '/observations', params);
            },
            decisions: function (params) { return get('R9', '/decisions', params); },
            decision: function (commandId) {
                return get('R9i', '/decisions/' + encodeURIComponent(commandId));
            },
            thresholds: function () { return get('R10', '/thresholds'); },
            proposals: function (params) { return get('R13', '/proposals', params); },
            config: function () { return get('R14', '/config'); },
            groundTruth: function (params) { return get('C9g', '/ground_truth', params); },
            appConfig: function () { return get('R15c', '/app_config'); },
        };

        // ── the commands actually served today ──────────────────────────
        var commands = {
            focus: function (scenarioId, reason) {
                return command('C1', 'POST', '/focus',
                               { scenario_id: scenarioId, reason: reason });
            },
            feedback: function (conclusionId, payload) {
                return command('C2', 'POST',
                               '/conclusions/' + encodeURIComponent(conclusionId)
                               + '/feedback', payload);
            },
            ack: function (itemId, reason) {
                return command('C4a', 'POST',
                               '/attention/' + encodeURIComponent(itemId) + '/ack',
                               { reason: reason });
            },
            snooze: function (itemId, minutes, reason) {
                return command('C4s', 'POST',
                               '/attention/' + encodeURIComponent(itemId) + '/snooze',
                               { minutes: minutes, reason: reason });
            },
            dismiss: function (itemId, reason) {
                return command('C4d', 'POST',
                               '/attention/' + encodeURIComponent(itemId) + '/dismiss',
                               { reason: reason });
            },
            attentionThresholds: function (thresholds, reason) {
                return command('C4t', 'PUT', '/attention/thresholds',
                               { thresholds: thresholds, reason: reason });
            },
            applyProposal: function (id, reason) {
                return command('C5a', 'POST',
                               '/proposals/' + encodeURIComponent(id) + '/apply',
                               { reason: reason });
            },
            dismissProposal: function (id, reason) {
                return command('C5d', 'POST',
                               '/proposals/' + encodeURIComponent(id) + '/dismiss',
                               { reason: reason });
            },
            deferProposal: function (id, reason) {
                return command('C5f', 'POST',
                               '/proposals/' + encodeURIComponent(id) + '/defer',
                               { reason: reason });
            },
            whatIf: function (overlay) {
                return command('C6', 'POST', '/whatif', overlay || {});
            },
            setConfig: function (key, value, reason) {
                return command('C7s', 'POST', '/config/' + encodeURIComponent(key),
                               { value: value, reason: reason });
            },
            clearConfig: function (key, reason) {
                return command('C7d', 'DELETE', '/config/' + encodeURIComponent(key),
                               { reason: reason });
            },
            assertGroundTruth: function (sid, payload) {
                return command('C9p', 'POST',
                               '/scenarios/' + encodeURIComponent(sid) + '/ground_truth',
                               payload);
            },
        };

        /**
         * What a command actually did, read back from the response.
         *
         * Returns `effect` — the server's re-read of the state — and never
         * the request body. A UI that reported what it sent is exactly how
         * a configuration key can be "changed" for months without anything
         * reading it (G-15).
         */
        function effectOf(result) {
            if (!result || !result.ok || !result.body) return null;
            return {
                effect: result.body.effect === undefined ? null : result.body.effect,
                changed: result.body.changed === true,
                command: result.body.command || null,
                sequence: typeof result.body.sequence === 'number'
                    ? result.body.sequence : null,
            };
        }

        return {
            get: get,
            command: command,
            reads: reads,
            commands: commands,
            effectOf: effectOf,
            heldKeys: function () { return Object.keys(held); },
        };
    }

    /**
     * Endpoints P7 names that L6 does not serve yet.
     *
     * Listed so the shell can say "not available yet" instead of showing an
     * empty panel or reading a 404 as "there is nothing here". The two are
     * different answers and only one of them is true.
     *
     * C13 is NOT here any more: WP-4.1g landed the auth family and this
     * layer now implements the gate (`v3/ui/auth.js`), so listing it would
     * be the opposite defect — a surface declaring itself absent while it
     * is on the screen.
     */
    var DEFERRED = {
        R11: 'ui.deferred.intel_read',
        C3: 'ui.deferred.intel_verdict',
        C8: 'ui.deferred.suppressions',
        C10: 'ui.deferred.human_anchor',
        C11: 'ui.deferred.scenario_admin',
        C12: 'ui.deferred.llm_ops',
    };

    return {
        createClient: createClient,
        API_PREFIX: API_PREFIX,
        NP7_DISCLAIMER: NP7_DISCLAIMER,
        DISCLAIMER_FIELD: DISCLAIMER_FIELD,
        ERROR_CODES: ERROR_CODES,
        DEFERRED: DEFERRED,
    };
});
