/**
 * DDoS-Radar Map Dim — focus-change loading state machine.
 *
 * Pure module (no DOM, no fetch) that tracks whether the map should
 * currently be dimmed because the analyst just switched scenario focus
 * and the new envelope hasn't fully arrived yet.
 *
 * Contract:
 *   start({scenarioName, now?, lift, stale, requireSources?})
 *     - kicks off a dim session. `lift` is called when ready, `stale`
 *       is called when timeout expires before all sources arrive.
 *     - `requireSources` defaults to ['threat_data', 'envelope']; lift
 *       fires only after every required source has called notifyReady.
 *   notifyReady(source)
 *     - mark a source arrival. When the set of arrived sources
 *       contains every requireSource, lift() is invoked exactly once.
 *   isActive() / forceLift() / forceStale() / reset()
 *     - state introspection + manual escape hatches (e.g. for tests
 *       and ESC-key abort).
 *
 * Why this is a pure module:
 *   - lift / stale callbacks are caller-injected so the module can be
 *     unit-tested under Node without any DOM or window globals.
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
            requireSources: null,
            arrived: null,         // Set
            timeoutId: null,
            timeoutMs: DEFAULT_TIMEOUT_MS,
            liftCb: null,
            staleCb: null,
            ended: false,          // tripped once lift OR stale fires
            // Allow tests to inject a fake setTimeout/clearTimeout pair so
            // they don't depend on real wall-clock time.
            _setTimeout: (typeof setTimeout !== 'undefined') ? setTimeout : null,
            _clearTimeout: (typeof clearTimeout !== 'undefined') ? clearTimeout : null,
        };

        function _settle(reason /* 'lift' | 'stale' */) {
            if (state.ended) return;
            state.ended = true;
            state.active = false;
            if (state.timeoutId !== null && state._clearTimeout) {
                state._clearTimeout(state.timeoutId);
            }
            state.timeoutId = null;
            const cb = (reason === 'stale') ? state.staleCb : state.liftCb;
            if (typeof cb === 'function') {
                try { cb({ reason: reason, scenarioName: state.scenarioName }); }
                catch (_) { /* swallow — caller should not throw, but be safe */ }
            }
        }

        function start(opts) {
            opts = opts || {};
            // Cancel any in-flight session before starting a new one.
            if (state.active && state.timeoutId !== null && state._clearTimeout) {
                state._clearTimeout(state.timeoutId);
            }
            state.active = true;
            state.startedAt = _now(opts);
            state.scenarioName = opts.scenarioName || '';
            state.requireSources = (Array.isArray(opts.requireSources) && opts.requireSources.length > 0)
                ? opts.requireSources.slice()
                : DEFAULT_SOURCES.slice();
            state.arrived = new Set();
            state.timeoutMs = (typeof opts.timeoutMs === 'number' && opts.timeoutMs > 0)
                ? opts.timeoutMs : DEFAULT_TIMEOUT_MS;
            state.liftCb = (typeof opts.lift === 'function') ? opts.lift : null;
            state.staleCb = (typeof opts.stale === 'function') ? opts.stale : null;
            state.ended = false;
            // Optional injected timer pair (test fixture)
            if (opts._setTimeout) state._setTimeout = opts._setTimeout;
            if (opts._clearTimeout) state._clearTimeout = opts._clearTimeout;
            if (state._setTimeout) {
                state.timeoutId = state._setTimeout(function () {
                    _settle('stale');
                }, state.timeoutMs);
            }
        }

        function notifyReady(source) {
            if (!state.active || state.ended) return;
            if (!state.arrived || !state.requireSources) return;
            if (typeof source !== 'string' || !source) return;
            // Only count sources that the current session declared as required.
            if (state.requireSources.indexOf(source) < 0) return;
            state.arrived.add(source);
            // Lift only once every required source has arrived.
            for (let i = 0; i < state.requireSources.length; i++) {
                if (!state.arrived.has(state.requireSources[i])) return;
            }
            _settle('lift');
        }

        function forceLift() { _settle('lift'); }
        function forceStale() { _settle('stale'); }

        function isActive() { return state.active && !state.ended; }
        function arrived() { return state.arrived ? Array.from(state.arrived) : []; }
        function required() { return state.requireSources ? state.requireSources.slice() : []; }
        function scenarioName() { return state.scenarioName; }

        function reset() {
            if (state.timeoutId !== null && state._clearTimeout) {
                state._clearTimeout(state.timeoutId);
            }
            state.active = false;
            state.ended = false;
            state.arrived = null;
            state.requireSources = null;
            state.timeoutId = null;
            state.scenarioName = '';
        }

        return {
            start: start,
            notifyReady: notifyReady,
            forceLift: forceLift,
            forceStale: forceStale,
            isActive: isActive,
            arrived: arrived,
            required: required,
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
