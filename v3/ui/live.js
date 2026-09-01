/**
 * Noroshi v3 L7 — the live channel client (pure core, injected socket).
 *
 * §7-2 #112 registered the socket channel as a deliberate absence, and its
 * stated release condition was this file: *"when a socket client lands in
 * `v3/ui/`"*. The publisher (`v3/api/ws_publish.py`) has existed and been
 * tested since WP-4.1; the composition root declines to mount it because
 * mounting a channel nobody listens to is a write with no reader wearing a
 * different hat. This module is the reader. What it must not be is a reader
 * that PRETENDS: a page showing a green "live" chip against a deployment
 * with no channel would be worse than the polling-only page it replaced.
 *
 * Three properties carry that:
 *
 * **The deployment is asked, not assumed.** R15c (`/api/v3/app_config`)
 * reports `websocket.mounted` and, when false, the reason. `planFrom` turns
 * that into the `unmounted` state, which is a FOURTH connection state
 * alongside S1-UI-011's three — `disconnected` means "there is a channel and
 * we are not on it", and saying that about a deployment which never had one
 * is a false alarm that trains an analyst to ignore the chip. Nothing is
 * dialled while unmounted.
 *
 * **A push is a cue, not a payload.** S1-UI-009 has the v1 client merging
 * push bodies into the displayed data. v3 does not, and the reason is
 * G-13: socket payloads are NOT envelopes. They carry no
 * `final_judgment_disclaimer`, no `observed_at` stamped by the dispatcher
 * and no `data_freshness_sec`, so merging one would put un-disclaimed,
 * un-aged values on screen and would make the freshness badge lie about
 * what it is describing. So `applyMessage` returns the projection keys the
 * push INVALIDATES, and the shell refetches them through the same envelope
 * path everything else uses. Polling is not replaced — S1-UI-009's real
 * requirement — it is merely no longer the only thing that can trigger a
 * read.
 *
 * **A push for another scenario is discarded.** S1-UI-010, unchanged: a
 * tick that began before a focus change must not land after it.
 *
 * The transport is Socket.IO over a browser WebSocket, framed here rather
 * than by a vendored client library — the v3 page ships no third-party code
 * and is served file-by-file out of `v3/ui/`. The framing is Engine.IO v4
 * plus Socket.IO v5, both of which are small enough to state exactly, and
 * stating them exactly means every frame this client emits or accepts is a
 * Node assertion instead of an integration hope.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.NoroshiLive = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ── connection states (S1-UI-011 + one) ─────────────────────────────
    var UNMOUNTED = 'unmounted';
    var CONNECTING = 'connecting';
    var CONNECTED = 'connected';
    var DEGRADED = 'degraded';
    var DISCONNECTED = 'disconnected';
    var STATES = [UNMOUNTED, CONNECTING, CONNECTED, DEGRADED, DISCONNECTED];

    // ── the vocabulary, mirrored from v3/api/ws.py ──────────────────────
    var SUBSCRIBE = 'subscribe_scenario';
    var UNSUBSCRIBE = 'unsubscribe_scenario';
    var CONCLUSION_UPDATE = 'conclusion_update';
    var ATTENTION_UPDATE = 'attention_update';
    var SENSOR_STATUS = 'sensor_status';
    var NOTIFICATION_RESULT = 'notification_result';
    var SUBSCRIBED = 'subscribed';
    var ERROR = 'error';

    /**
     * What each published event makes stale.
     *
     * The values are the client's own read keys (`v3/ui/client.js`), so a
     * push resolves to "re-read R2" rather than to "write these fields".
     * `notification_result` maps to nothing on purpose: the server refuses
     * to construct one (v3 has no notification subsystem), so a client that
     * had a handler for it would be a handler for an event that cannot
     * arrive — the same emptiness as a config key nobody reads.
     */
    var INVALIDATES = {
        conclusion_update: ['R2', 'R4', 'R4d'],
        attention_update: ['R6'],
        sensor_status: ['R8', 'R7'],
    };

    /**
     * Events v3 retired, mirrored from `ws.RETIRED_EVENTS`.
     *
     * Receiving one means the server is older than this page. That is
     * reported rather than ignored: a silently dropped frame from a
     * mismatched deployment presents as "the live channel is quiet".
     */
    var RETIRED_EVENTS = ['threat_update', 'ambush_alert', 'sequence_event',
                          'intel_update', 'subscribe_theater',
                          'unsubscribe_theater'];

    // ── Engine.IO v4 / Socket.IO v5 framing ─────────────────────────────
    // Engine.IO packet type is the first character of the frame.
    var EIO_OPEN = '0';
    var EIO_CLOSE = '1';
    var EIO_PING = '2';
    var EIO_PONG = '3';
    var EIO_MESSAGE = '4';
    // Socket.IO packet type is the first character INSIDE an EIO message.
    var SIO_CONNECT = '0';
    var SIO_DISCONNECT = '1';
    var SIO_EVENT = '2';
    var SIO_CONNECT_ERROR = '4';

    var HANDSHAKE_PATH = '/socket.io/?EIO=4&transport=websocket';

    /**
     * Decode one wire frame into something with a name.
     *
     * Returns `{kind, ...}` where `kind` is one of `open` / `close` /
     * `ping` / `connected` / `connect_error` / `event` / `ignored`. Never
     * throws: a malformed frame from the network is an ordinary event on a
     * public interface, and a decoder that throws takes the socket down
     * with the bad byte.
     */
    function decodeFrame(raw) {
        if (typeof raw !== 'string' || raw.length === 0) {
            return { kind: 'ignored', reason: 'empty' };
        }
        var type = raw.charAt(0);
        var rest = raw.slice(1);
        if (type === EIO_PING) return { kind: 'ping' };
        if (type === EIO_CLOSE) return { kind: 'close' };
        if (type === EIO_OPEN) {
            var handshake = _json(rest);
            return { kind: 'open', handshake: handshake || {} };
        }
        if (type !== EIO_MESSAGE) return { kind: 'ignored', reason: 'eio:' + type };

        var sioType = rest.charAt(0);
        var body = rest.slice(1);
        if (sioType === SIO_CONNECT) {
            return { kind: 'connected', session: _json(body) || {} };
        }
        if (sioType === SIO_DISCONNECT) return { kind: 'close' };
        if (sioType === SIO_CONNECT_ERROR) {
            return { kind: 'connect_error', detail: _json(body) };
        }
        if (sioType !== SIO_EVENT) {
            return { kind: 'ignored', reason: 'sio:' + sioType };
        }
        var parsed = _json(body);
        if (!Array.isArray(parsed) || typeof parsed[0] !== 'string') {
            return { kind: 'ignored', reason: 'malformed_event' };
        }
        return { kind: 'event', event: parsed[0],
                 payload: parsed.length > 1 ? parsed[1] : null };
    }

    function _json(text) {
        if (typeof text !== 'string' || !text) return null;
        try { return JSON.parse(text); } catch (err) { return null; }
    }

    /** `42["subscribe_scenario",{...}]`, built rather than templated. */
    function encodeEvent(name, payload) {
        return EIO_MESSAGE + SIO_EVENT
            + JSON.stringify(payload === undefined ? [name] : [name, payload]);
    }

    function encodePong() { return EIO_PONG; }

    // ── what the deployment says about the channel ──────────────────────

    /**
     * Turn R15c's `app_config` into a plan.
     *
     * A body that has not arrived yet is `unknown`, which is neither
     * "mounted" nor "absent" — the chip says it is still asking rather than
     * guessing either way.
     */
    function planFrom(appConfig) {
        if (!appConfig || typeof appConfig !== 'object') {
            return { connect: false, state: CONNECTING,
                     reasonKey: 'ui.live.reason.unknown', serverReason: null,
                     unpublished: null };
        }
        var ws = appConfig.websocket;
        if (!ws || typeof ws !== 'object') {
            return { connect: false, state: UNMOUNTED,
                     reasonKey: 'ui.live.reason.undeclared', serverReason: null,
                     unpublished: null };
        }
        if (ws.mounted !== true) {
            return { connect: false, state: UNMOUNTED,
                     reasonKey: 'ui.live.reason.unmounted',
                     serverReason: typeof ws.reason === 'string' ? ws.reason : null,
                     unpublished: ws.unpublished || null };
        }
        return { connect: true, state: CONNECTING,
                 reasonKey: 'ui.live.reason.dialling', serverReason: null,
                 unpublished: ws.unpublished || null };
    }

    // ── message routing ─────────────────────────────────────────────────

    /**
     * What one published event means for the screen.
     *
     * @param {object} message  `{event, payload}` from `decodeFrame`
     * @param {string|null} focus  the scenario the page is showing
     * @returns {{accepted, invalidate, reasonKey, event, scenarioId, detail}}
     */
    function applyMessage(message, focus) {
        var event = message ? message.event : null;
        var payload = (message && message.payload) || null;
        if (typeof event !== 'string') {
            return _verdict(false, [], 'ui.live.drop.malformed', event, null, null);
        }
        if (RETIRED_EVENTS.indexOf(event) !== -1) {
            return _verdict(false, [], 'ui.live.drop.retired', event, null, event);
        }
        if (event === ERROR) {
            return _verdict(false, [], 'ui.live.drop.server_error', event, null,
                            payload && payload.code ? payload.code : null);
        }
        if (event === SUBSCRIBED) {
            return _verdict(false, [], 'ui.live.subscribed', event,
                            payload ? payload.scenario_id : null, null);
        }
        if (event === NOTIFICATION_RESULT) {
            // The server declares this one unpublishable. Arriving anyway is
            // a contract breach, and breaches are surfaced, never swallowed.
            return _verdict(false, [], 'ui.live.drop.unpublished', event,
                            null, null);
        }
        if (!Object.prototype.hasOwnProperty.call(INVALIDATES, event)) {
            return _verdict(false, [], 'ui.live.drop.unknown', event, null, null);
        }

        // S1-UI-010. A push that names a scenario is only for that scenario;
        // one that names none makes no claim and is accepted.
        var scenarioId = payload && typeof payload.scenario_id === 'string'
            ? payload.scenario_id : null;
        if (scenarioId !== null && focus !== null && focus !== undefined
                && scenarioId !== focus) {
            return _verdict(false, [], 'ui.live.drop.other_scenario', event,
                            scenarioId, null);
        }
        return _verdict(true, INVALIDATES[event].slice(), 'ui.live.accepted',
                        event, scenarioId, null);
    }

    function _verdict(accepted, invalidate, reasonKey, event, scenarioId, detail) {
        return { accepted: accepted, invalidate: invalidate,
                 reasonKey: reasonKey, event: event,
                 scenarioId: scenarioId || null, detail: detail || null };
    }

    // ── reconnection ────────────────────────────────────────────────────

    /**
     * Backoff, and the point at which "retrying" becomes "degraded".
     *
     * S1-UI-011 wants `degraded` distinguishable from `disconnected`: a
     * socket that keeps failing to establish (revoked token, proxy, load)
     * is a different fact from one that dropped once, and the difference is
     * whether an analyst should go and look at the deployment. Polling never
     * accelerates to compensate — the same clause — because a UI that
     * hammers the API when the socket is unhappy turns one degraded surface
     * into two.
     */
    var RETRY_BASE_MS = 2500;
    var RETRY_CEILING_MS = 60000;
    var ATTEMPTS_BEFORE_DEGRADED = 3;

    function backoffMs(attempt) {
        var n = typeof attempt === 'number' && attempt > 0 ? Math.floor(attempt) : 1;
        var delay = RETRY_BASE_MS * Math.pow(2, n - 1);
        return delay > RETRY_CEILING_MS ? RETRY_CEILING_MS : delay;
    }

    function stateAfterFailure(attempt) {
        var n = typeof attempt === 'number' ? attempt : 1;
        return n >= ATTEMPTS_BEFORE_DEGRADED ? DEGRADED : DISCONNECTED;
    }

    // ── the client ──────────────────────────────────────────────────────

    /**
     * Create a live client.
     *
     * @param {object} options
     * @param {function} options.socketFactory (url) -> socket-like
     * @param {function} [options.onState]   (view) -> void
     * @param {function} [options.onCue]     (verdict) -> void
     * @param {function} [options.focus]     () -> scenario id or null
     * @param {function} [options.schedule]  (fn, ms) -> handle
     * @param {function} [options.cancel]    (handle) -> void
     * @param {string} [options.origin]      ws:// or wss:// base
     */
    function createLiveClient(options) {
        options = options || {};
        var socketFactory = options.socketFactory;
        var onState = options.onState || function () {};
        var onCue = options.onCue || function () {};
        var focusOf = options.focus || function () { return null; };
        var schedule = options.schedule
            || function (fn, ms) { return setTimeout(fn, ms); };
        var cancel = options.cancel || function (h) { clearTimeout(h); };

        var state = {
            connection: CONNECTING,
            reasonKey: 'ui.live.reason.unknown',
            serverReason: null,
            subscribed: null,
            attempts: 0,
            lastEventAt: null,
            lastEvent: null,
            unpublished: null,
            plan: null,
        };
        var socket = null;
        var retryHandle = null;
        var stopped = false;

        function view() {
            return {
                connection: state.connection,
                reasonKey: state.reasonKey,
                serverReason: state.serverReason,
                subscribed: state.subscribed,
                attempts: state.attempts,
                lastEvent: state.lastEvent,
                lastEventAt: state.lastEventAt,
                unpublished: state.unpublished,
                // Polling is never suspended by this module. Stated as data
                // so a caller cannot decide otherwise without changing it.
                pollingContinues: true,
            };
        }

        function _emitState() { onState(view()); }

        function _set(connection, reasonKey) {
            state.connection = connection;
            state.reasonKey = reasonKey;
            _emitState();
        }

        /** Apply R15c and, if the channel exists, dial it. */
        function configure(appConfig) {
            var plan = planFrom(appConfig);
            state.plan = plan;
            state.serverReason = plan.serverReason;
            state.unpublished = plan.unpublished;
            if (!plan.connect) {
                _teardown();
                _set(plan.state, plan.reasonKey);
                return view();
            }
            if (socket === null) connect();
            else _emitState();
            return view();
        }

        function _teardown() {
            if (retryHandle !== null) { cancel(retryHandle); retryHandle = null; }
            if (socket && typeof socket.close === 'function') {
                try { socket.close(); } catch (err) { /* already gone */ }
            }
            socket = null;
            state.subscribed = null;
        }

        function connect() {
            if (stopped || typeof socketFactory !== 'function') return view();
            if (!state.plan || !state.plan.connect) return view();
            state.attempts += 1;
            _set(CONNECTING, 'ui.live.reason.dialling');
            var url = (options.origin || '') + HANDSHAKE_PATH;
            try {
                socket = socketFactory(url);
            } catch (err) {
                socket = null;
                return _failed(err && err.message ? err.message : null);
            }
            if (!socket) return _failed(null);
            socket.onmessage = function (event) {
                _receive(event && event.data !== undefined ? event.data : event);
            };
            socket.onerror = function () { /* close follows; state moves there */ };
            socket.onclose = function () { _failed(null); };
            return view();
        }

        function _failed(detail) {
            socket = null;
            state.subscribed = null;
            state.serverReason = detail || state.serverReason;
            _set(stateAfterFailure(state.attempts),
                 state.attempts >= ATTEMPTS_BEFORE_DEGRADED
                     ? 'ui.live.reason.degraded' : 'ui.live.reason.dropped');
            if (!stopped && retryHandle === null) {
                retryHandle = schedule(function () {
                    retryHandle = null;
                    connect();
                }, backoffMs(state.attempts));
            }
            return view();
        }

        function _send(text) {
            if (socket && typeof socket.send === 'function') socket.send(text);
        }

        function subscribe(scenarioId) {
            if (typeof scenarioId !== 'string' || !scenarioId) return view();
            if (state.subscribed === scenarioId) return view();
            if (state.subscribed) {
                _send(encodeEvent(UNSUBSCRIBE, { scenario_id: state.subscribed }));
            }
            state.subscribed = scenarioId;
            _send(encodeEvent(SUBSCRIBE, { scenario_id: scenarioId }));
            return view();
        }

        function _receive(raw) {
            var frame = decodeFrame(raw);
            if (frame.kind === 'ping') { _send(encodePong()); return; }
            if (frame.kind === 'open') return;
            if (frame.kind === 'connected') {
                state.attempts = 0;
                _set(CONNECTED, 'ui.live.reason.connected');
                var current = focusOf();
                if (current) {
                    var wanted = current;
                    state.subscribed = null;
                    subscribe(wanted);
                }
                return;
            }
            if (frame.kind === 'connect_error') {
                // Refused at the protocol level: a live socket that cannot
                // join is degraded, not merely disconnected.
                state.attempts = ATTEMPTS_BEFORE_DEGRADED;
                _failed(frame.detail && frame.detail.message
                    ? frame.detail.message : null);
                return;
            }
            if (frame.kind === 'close') { _failed(null); return; }
            if (frame.kind !== 'event') return;

            var verdict = applyMessage(frame, focusOf());
            state.lastEvent = frame.event;
            if (verdict.accepted) {
                state.lastEventAt = Date.now() / 1000;
            }
            if (frame.event === SUBSCRIBED && frame.payload) {
                state.subscribed = frame.payload.scenario_id || state.subscribed;
            }
            _emitState();
            onCue(verdict);
        }

        function stop() {
            stopped = true;
            _teardown();
            _set(DISCONNECTED, 'ui.live.reason.stopped');
            return view();
        }

        return {
            configure: configure, connect: connect, subscribe: subscribe,
            stop: stop, view: view,
            //: exposed for the suite; the shell never calls it
            _receive: _receive,
        };
    }

    return {
        createLiveClient: createLiveClient,
        planFrom: planFrom,
        applyMessage: applyMessage,
        decodeFrame: decodeFrame,
        encodeEvent: encodeEvent,
        encodePong: encodePong,
        backoffMs: backoffMs,
        stateAfterFailure: stateAfterFailure,
        STATES: STATES,
        UNMOUNTED: UNMOUNTED, CONNECTING: CONNECTING, CONNECTED: CONNECTED,
        DEGRADED: DEGRADED, DISCONNECTED: DISCONNECTED,
        INVALIDATES: INVALIDATES,
        RETIRED_EVENTS: RETIRED_EVENTS,
        SUBSCRIBE: SUBSCRIBE, UNSUBSCRIBE: UNSUBSCRIBE,
        CONCLUSION_UPDATE: CONCLUSION_UPDATE,
        ATTENTION_UPDATE: ATTENTION_UPDATE,
        SENSOR_STATUS: SENSOR_STATUS,
        NOTIFICATION_RESULT: NOTIFICATION_RESULT,
        HANDSHAKE_PATH: HANDSHAKE_PATH,
        RETRY_BASE_MS: RETRY_BASE_MS, RETRY_CEILING_MS: RETRY_CEILING_MS,
        ATTEMPTS_BEFORE_DEGRADED: ATTEMPTS_BEFORE_DEGRADED,
    };
});
