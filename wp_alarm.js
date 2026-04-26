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

    return {
        FIELDS, OPS_NUMERIC, OPS_STATUS, STATUS_VALUES,
        normalizeAlarm, alarmMatches, alarmDescribe,
    };
});
