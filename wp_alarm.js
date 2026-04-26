/**
 * DDoS-Radar Watchpane Alarm — pure evaluator
 *
 * Extracted from radar.js so the evaluator can be unit-tested under Node
 * without a browser. Loaded as a plain script in index.html (exposes
 * `window.WatchpaneAlarm`) and via `require()` in test_wp_alarm.js.
 *
 * Design contract (per NP6 — full derivation disclosure):
 *   An alarm is fully describable as `<field> <op> <value>` where:
 *     field ∈ FIELDS                     (score, value, delta, status)
 *     op    ∈ OPS_NUMERIC | OPS_STATUS   (>, >=, <, <=, ==, != / ==, !=)
 *     value is finite number              (numeric fields)
 *           or one of STATUS_VALUES       (status field)
 *   No hidden state, no time-based decay — analyst sees exactly when it fires.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.WatchpaneAlarm = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const FIELDS         = ['score', 'value', 'delta', 'status'];
    const OPS_NUMERIC    = ['>', '>=', '<', '<=', '==', '!='];
    const OPS_STATUS     = ['==', '!='];
    const STATUS_VALUES  = ['FIRED', 'NORMAL', 'SUPPRESSED'];

    function normalizeAlarm(a) {
        if (!a || typeof a !== 'object') return null;
        const field = FIELDS.includes(a.field) ? a.field : null;
        if (!field) return null;
        const ops = (field === 'status') ? OPS_STATUS : OPS_NUMERIC;
        const op = ops.includes(a.op) ? a.op : null;
        if (!op) return null;
        let value = a.value;
        if (field === 'status') {
            value = String(value || '').toUpperCase();
            if (!STATUS_VALUES.includes(value)) return null;
        } else {
            const n = Number(value);
            if (!Number.isFinite(n)) return null;
            value = n;
        }
        return {
            field, op, value,
            last_fired_ts: Number(a.last_fired_ts) || 0,
            is_active: !!a.is_active,
            notify: a.notify !== false,
        };
    }

    function alarmMatches(alarm, env) {
        if (!alarm || !env) return false;
        const obs = (env.observations || []);
        const latest = obs.length ? obs[obs.length - 1] : null;
        const curr = env.current || null;
        let actual;
        switch (alarm.field) {
            case 'score':
                actual = latest ? Number(latest.value) : null;
                break;
            case 'value':
                actual = curr ? Number(curr.raw_value) : null;
                break;
            case 'delta':
                actual = latest ? Number(latest.delta_vs_baseline) : null;
                break;
            case 'status':
                if (!curr) return false;
                if (curr.suppressed) actual = 'SUPPRESSED';
                else actual = String(curr.status || '').toUpperCase();
                break;
            default: return false;
        }
        if (alarm.field === 'status') {
            return alarm.op === '==' ? actual === alarm.value : actual !== alarm.value;
        }
        if (actual == null || !Number.isFinite(actual)) return false;
        switch (alarm.op) {
            case '>':  return actual >  alarm.value;
            case '>=': return actual >= alarm.value;
            case '<':  return actual <  alarm.value;
            case '<=': return actual <= alarm.value;
            case '==': return actual === alarm.value;
            case '!=': return actual !== alarm.value;
            default:   return false;
        }
    }

    function alarmDescribe(alarm) {
        if (!alarm) return '';
        return alarm.field + ' ' + alarm.op + ' ' + alarm.value;
    }

    /**
     * Pure state loader / migrator.
     *
     * Accepts the raw localStorage string written by `_wpSaveState` (or any
     * legacy v1 payload that lacks `alarm` on rows). Returns a fresh state
     * object — never mutates the input. Malformed entries are dropped.
     *
     * @param {string|null} rawJson  raw localStorage string or null
     * @param {number}      version  current state version to stamp
     * @returns {{version: number, sensors: Array<{name:string, scope:string, added_at:number, alarm:object|null}>}}
     */
    function loadStateFromRaw(rawJson, version) {
        const v = Number.isFinite(version) ? version : 2;
        if (!rawJson) return { version: v, sensors: [] };
        let parsed;
        try { parsed = JSON.parse(rawJson); }
        catch (_e) { return { version: v, sensors: [] }; }
        if (!parsed || !Array.isArray(parsed.sensors)) {
            return { version: v, sensors: [] };
        }
        const sensors = parsed.sensors
            .filter(s => s && typeof s.name === 'string')
            .map(s => ({
                name: s.name,
                scope: s.scope || 'focused',
                added_at: Number(s.added_at) || Date.now(),
                alarm: normalizeAlarm(s.alarm),
            }));
        return { version: v, sensors };
    }

    /**
     * Pure edge-trigger evaluator.
     *
     * Walks every row, computes whether each alarm is active *now* given the
     * latest observation env, and reports edges (both false→true and true→false)
     * as immutable diffs. The caller is responsible for the impure side effects
     * (firing notifications for `rising` rows, persisting `nextState`).
     *
     * Why edge-trigger: a sensor that stays above threshold for hours would spam
     * notifications every poll cycle if we fired on plain truth instead of the
     * rising edge. Falling edges are reported too so a UI can clear "active" pills.
     *
     * @param {object} state    current watchpane state
     * @param {Map}    obsByKey Map keyed `${name}::${scope}` → observation env
     * @param {number} nowMs    timestamp to stamp on rising edges
     * @returns {{nextState: object, rising: Array, falling: Array, changed: boolean}}
     */
    function evaluateAlarmsEdge(state, obsByKey, nowMs) {
        const ts = Number.isFinite(nowMs) ? nowMs : Date.now();
        const rising = [];
        const falling = [];
        let changed = false;
        const nextSensors = state.sensors.map(s => {
            if (!s.alarm) return s;
            const key = s.name + '::' + s.scope;
            const env = obsByKey && typeof obsByKey.get === 'function'
                ? obsByKey.get(key)
                : (obsByKey ? obsByKey[key] : null);
            const wasActive = !!s.alarm.is_active;
            const nowActive = alarmMatches(s.alarm, env);
            if (nowActive === wasActive) return s;
            changed = true;
            const nextAlarm = {
                ...s.alarm,
                is_active: nowActive,
                last_fired_ts: nowActive ? ts : s.alarm.last_fired_ts,
            };
            const nextRow = { ...s, alarm: nextAlarm };
            if (nowActive) rising.push(nextRow);
            else           falling.push(nextRow);
            return nextRow;
        });
        const nextState = changed ? { ...state, sensors: nextSensors } : state;
        return { nextState, rising, falling, changed };
    }

    /**
     * Pure state mutation: set or clear the alarm on row `idx`.
     *
     * Returns a NEW state object — original is never touched. Out-of-range idx
     * yields the same state reference (no-op); the caller can detect this by
     * identity comparison if needed.
     *
     * @param {object} state
     * @param {number} idx     row index in state.sensors
     * @param {object|null} candidate  normalised alarm or null to clear
     * @returns {object} new state (or same reference on no-op)
     */
    function applyAlarmToState(state, idx, candidate) {
        if (!state || !Array.isArray(state.sensors)) return state;
        if (!Number.isInteger(idx) || idx < 0 || idx >= state.sensors.length) return state;
        const sensors = state.sensors.map((s, i) => {
            if (i !== idx) return s;
            return { ...s, alarm: candidate || null };
        });
        return { ...state, sensors };
    }

    return {
        FIELDS, OPS_NUMERIC, OPS_STATUS, STATUS_VALUES,
        normalizeAlarm, alarmMatches, alarmDescribe,
        loadStateFromRaw, evaluateAlarmsEdge, applyAlarmToState,
    };
});
