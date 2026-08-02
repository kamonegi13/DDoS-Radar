/**
 * Noroshi Map Dim — focus-change loading state machine.
 *
 * Pure module (no DOM, no fetch) that tracks whether the map should
 * currently be dimmed because the analyst just switched scenario focus
 * and the new envelope hasn't fully arrived yet.
 *
 * Contract:
 *   start({scenarioName, now?, lift, done, stale,
 *          liftSources?, requireSources?})
 *     - kicks off a dim session.
 *     - Two-phase model (Phase 4 commit 4):
 *         * Phase 1 (DIMMED → REFRESHING): when every source in
 *           `liftSources` has called notifyReady, `lift` fires and the
 *           visual dim overlay is removed. `liftSources` defaults to
 *           `requireSources`, in which case lift = done (single-phase).
 *         * Phase 2 (REFRESHING → ENDED): when every source in
 *           `requireSources` has called notifyReady, `done` fires
 *           (e.g. the refreshing-badge hides). `done` defaults to a
 *           no-op for callers that only care about the lift step.
 *     - `stale` fires only if the timeout elapses BEFORE Phase 1 lift.
 *       Once `lift` has fired, the session no longer self-stales —
 *       the analyst is free to wait as long as the slow leg needs.
 *     - `requireSources` defaults to ['threat_data', 'envelope'].
 *   notifyReady(source)
 *     - mark a source arrival. Triggers lift / done as described.
 *   isActive() / forceLift() / forceDone() / forceStale() / reset()
 *     - state introspection + manual escape hatches (e.g. for tests
 *       and ESC-key abort). isLifted() returns true if Phase 1 has
 *       already fired (we're in the REFRESHING window).
 *
 * Why this is a pure module:
 *   - lift / done / stale callbacks are caller-injected so the module
 *     can be unit-tested under Node without any DOM or window globals.
 *   - the radar.js wiring layer hands real DOM-mutating callbacks to
 *     start(); the module itself never touches the page.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.MapDim = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const DEFAULT_TIMEOUT_MS = 8000;
    const DEFAULT_SOURCES = ['threat_data', 'envelope'];

    function _now(opt) {
        if (opt && typeof opt.now === 'number') return opt.now;
        return Date.now();
    }

    function create() {
        const state = {
            active: false,
            startedAt: 0,
            scenarioName: '',
            liftSources: null,     // Phase 1 trigger set
            requireSources: null,  // Phase 2 / done trigger set
            arrived: null,         // Set
            timeoutId: null,
            timeoutMs: DEFAULT_TIMEOUT_MS,
            liftCb: null,
            doneCb: null,
            staleCb: null,
            lifted: false,         // tripped once Phase 1 (lift) fires
            ended: false,          // tripped once Phase 2 (done) OR stale fires
            // Allow tests to inject a fake setTimeout/clearTimeout pair so
            // they don't depend on real wall-clock time.
            _setTimeout: (typeof setTimeout !== 'undefined') ? setTimeout : null,
            _clearTimeout: (typeof clearTimeout !== 'undefined') ? clearTimeout : null,
        };

        function _clearPendingTimeout() {
            if (state.timeoutId !== null && state._clearTimeout) {
                state._clearTimeout(state.timeoutId);
            }
            state.timeoutId = null;
        }

        function _firePhase1(reason /* 'lift' | 'stale' */) {
            if (state.lifted || state.ended) return;
            state.lifted = true;
            // Either firing path means the visual dim should now lift,
            // so the timeout no longer needs to run.
            _clearPendingTimeout();
            const cb = (reason === 'stale') ? state.staleCb : state.liftCb;
            if (typeof cb === 'function') {
                try { cb({ reason: reason, scenarioName: state.scenarioName }); }
                catch (_) { /* swallow — caller should not throw, but be safe */ }
            }
            // 'stale' is also a terminal state — there is no Phase 2 to
            // wait for once we have given up on the slow leg.
            if (reason === 'stale') {
                state.ended = true;
                state.active = false;
            }
        }

        function _firePhase2() {
            if (state.ended) return;
            // Phase 2 implicitly fires Phase 1 if it hasn't already
            // (e.g. caller used a single-phase configuration where
            // liftSources === requireSources, or notifyReady('all') in
            // one shot).
            if (!state.lifted) {
                _firePhase1('lift');
            }
            state.ended = true;
            state.active = false;
            _clearPendingTimeout();
            if (typeof state.doneCb === 'function') {
                try { state.doneCb({ reason: 'done', scenarioName: state.scenarioName }); }
                catch (_) { /* swallow */ }
            }
        }

        function start(opts) {
            opts = opts || {};
            // Cancel any in-flight session before starting a new one.
            _clearPendingTimeout();
            state.active = true;
            state.startedAt = _now(opts);
            state.scenarioName = opts.scenarioName || '';
            state.requireSources = (Array.isArray(opts.requireSources) && opts.requireSources.length > 0)
                ? opts.requireSources.slice()
                : DEFAULT_SOURCES.slice();
            state.liftSources = (Array.isArray(opts.liftSources) && opts.liftSources.length > 0)
                ? opts.liftSources.slice()
                : state.requireSources.slice();
            state.arrived = new Set();
            state.timeoutMs = (typeof opts.timeoutMs === 'number' && opts.timeoutMs > 0)
                ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
            state.liftCb = (typeof opts.lift === 'function') ? opts.lift : null;
            state.doneCb = (typeof opts.done === 'function') ? opts.done : null;
            state.staleCb = (typeof opts.stale === 'function') ? opts.stale : null;
            state.lifted = false;
            state.ended = false;
            // Optional injected timer pair (test fixture)
            if (opts._setTimeout) state._setTimeout = opts._setTimeout;
            if (opts._clearTimeout) state._clearTimeout = opts._clearTimeout;
            if (state._setTimeout) {
                state.timeoutId = state._setTimeout(function () {
                    _firePhase1('stale');
                }, state.timeoutMs);
            }
        }

        function _allArrived(needed) {
            for (let i = 0; i < needed.length; i++) {
                if (!state.arrived.has(needed[i])) return false;
            }
            return true;
        }

        function notifyReady(source) {
            if (!state.active || state.ended) return;
            if (!state.arrived || !state.requireSources) return;
            if (typeof source !== 'string' || !source) return;
            // Accept the union of liftSources + requireSources.
            const inLift = state.liftSources.indexOf(source) >= 0;
            const inReq = state.requireSources.indexOf(source) >= 0;
            if (!inLift && !inReq) return;
            state.arrived.add(source);
            // Phase 1: lift when liftSources fully arrived.
            if (!state.lifted && _allArrived(state.liftSources)) {
                _firePhase1('lift');
            }
            // Phase 2: done when requireSources fully arrived.
            if (_allArrived(state.requireSources)) {
                _firePhase2();
            }
        }

        function _isSinglePhase() {
            // Single-phase = the lift trigger and the done trigger are the
            // same set, i.e. caller did not opt in to the two-phase model.
            // Used so legacy callers see forceLift() end the session as
            // before.
            if (!state.liftSources || !state.requireSources) return true;
            if (state.liftSources.length !== state.requireSources.length) return false;
            for (let i = 0; i < state.liftSources.length; i++) {
                if (state.requireSources.indexOf(state.liftSources[i]) < 0) return false;
            }
            return true;
        }

        function forceLift() {
            _firePhase1('lift');
            // Backward compat: in single-phase mode, lift also ends the session.
            if (_isSinglePhase()) _firePhase2();
        }
        function forceDone() { _firePhase2(); }
        function forceStale() { _firePhase1('stale'); }

        function isActive() { return state.active && !state.ended; }
        function isLifted() { return state.lifted; }
        function arrived() { return state.arrived ? Array.from(state.arrived) : []; }
        function required() { return state.requireSources ? state.requireSources.slice() : []; }
        function liftRequired() { return state.liftSources ? state.liftSources.slice() : []; }
        function scenarioName() { return state.scenarioName; }

        function reset() {
            _clearPendingTimeout();
            state.active = false;
            state.lifted = false;
            state.ended = false;
            state.arrived = null;
            state.requireSources = null;
            state.liftSources = null;
            state.scenarioName = '';
        }

        return {
            start: start,
            notifyReady: notifyReady,
            forceLift: forceLift,
            forceDone: forceDone,
            forceStale: forceStale,
            isActive: isActive,
            isLifted: isLifted,
            arrived: arrived,
            required: required,
            liftRequired: liftRequired,
            scenarioName: scenarioName,
            reset: reset,
        };
    }

    // Default singleton — most callers use `MapDim.start(...)` directly,
    // tests use create() to make isolated instances.
    const singleton = create();
    singleton.create = create;
    singleton.DEFAULT_TIMEOUT_MS = DEFAULT_TIMEOUT_MS;
    singleton.DEFAULT_SOURCES = DEFAULT_SOURCES.slice();
    return singleton;
});
