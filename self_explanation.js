/**
 * DDoS-Radar Self-Explanation — deterministic narrative generation (AP2).
 *
 * Threat-intel analysts ask "why is this number what it is?" — and the
 * answer must be derivable, repeatable, and free of model opacity. This
 * module turns v2 conclusion objects into multi-line plain-text narratives
 * that explain a conclusion's state in human-readable form, *without any
 * LLM call*. All logic is template + slot-fill against the conclusion's
 * own metadata, threshold_ref, calibration_status, and rationale_matrix —
 * the same fields drill-down already exposes.
 *
 * Output is intentionally unstyled plain text (newline-separated) so the
 * caller can drop it into a `title` attribute or `<pre>` block. Length
 * stays bounded (≤ ~10 lines) so the tooltip remains a glance-readable
 * surface, not a wall of text.
 *
 * Loaded as a plain script in index.html (window.SelfExplanation) and via
 * require() in test_self_explanation.js. Mirrors the wp_alarm.js /
 * hud_v2_overlay.js / triage_score.js extraction pattern.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (typeof window !== 'undefined') {
        window.SelfExplanation = api;
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    function _fmtNum(n, digits) {
        if (typeof n !== 'number' || !isFinite(n)) return '—';
        return n.toFixed(typeof digits === 'number' ? digits : 2);
    }

    function _fmtAge(ts, now) {
        if (typeof ts !== 'number' || !isFinite(ts) || ts <= 0) return null;
        const sec = Math.max(0, (now == null ? Date.now() / 1000 : now) - ts);
        if (sec < 60) return 'just now';
        if (sec < 3600) return Math.round(sec / 60) + 'm ago';
        if (sec < 86400) return (sec / 3600).toFixed(1) + 'h ago';
        return (sec / 86400).toFixed(1) + 'd ago';
    }

    /**
     * Narrate a THREAT_LEVEL conclusion.
     *
     * @param {object} c   — v2 threat_level conclusion
     * @param {object} [opts] — { lastViewTs?: number, now?: number }
     * @returns {string} multi-line plain text (≤ ~10 lines)
     */
    function narrateTL(c, opts) {
        const now = (opts && typeof opts.now === 'number') ? opts.now : Date.now() / 1000;
        const lines = [];
        if (!c) return 'No threat_level conclusion available.';

        if (c.conclusion_unavailable_reason) {
            lines.push('TL: unavailable (' + c.conclusion_unavailable_reason + ')');
            const reason = c.metadata && c.metadata.reason_detail;
            if (reason) lines.push('Reason: ' + reason);
            lines.push('Tool conclusion only — final judgment org-side.');
            return lines.join('\n');
        }

        const tl = c.state;
        lines.push('Threat Level: ' + (tl != null ? tl : '—'));

        const md = c.metadata || {};
        const score = (typeof md.score === 'number') ? md.score : null;
        const adc = (typeof md.active_domain_count === 'number') ? md.active_domain_count : null;
        const conv = (typeof md.convergence_bonus === 'number') ? md.convergence_bonus : null;
        const conf = (typeof c.confidence === 'number') ? c.confidence : null;
        const detailParts = [];
        if (score != null) detailParts.push('score ' + _fmtNum(score));
        if (adc != null) detailParts.push('active domains ' + adc);
        if (conv != null) detailParts.push('convergence +' + _fmtNum(conv));
        if (conf != null) detailParts.push('conf ' + _fmtNum(conf));
        if (detailParts.length) lines.push(detailParts.join(' · '));

        // Threshold context — find which floors the score did/didn't cross.
        const thr = c.threshold_ref || {};
        const tlOrder = ['tl1', 'tl2', 'tl3', 'tl4', 'tl5'];
        const crossed = [];
        const next = [];
        if (score != null) {
            tlOrder.forEach((k) => {
                const v = thr[k];
                if (typeof v === 'number') {
                    if (score >= v) crossed.push(k.toUpperCase() + '≥' + _fmtNum(v));
                    else next.push(k.toUpperCase() + '≥' + _fmtNum(v));
                }
            });
        }
        if (crossed.length) lines.push('Crossed: ' + crossed.join(', '));
        if (next.length) lines.push('Next: ' + next[0]);

        // Calibration
        const cal = c.calibration_status || {};
        if (cal && (typeof cal.sample_size === 'number' || cal.status)) {
            const calBits = [];
            if (cal.status) calBits.push(cal.status);
            if (typeof cal.sample_size === 'number') calBits.push('n=' + cal.sample_size);
            if (typeof cal.recall === 'number') calBits.push('recall=' + _fmtNum(cal.recall));
            if (calBits.length) lines.push('Calibration: ' + calBits.join(' · '));
        }

        // Analyst review recency
        const lastView = opts && opts.lastViewTs;
        const ageStr = _fmtAge(lastView, now);
        if (ageStr) lines.push('Last analyst view: ' + ageStr);

        lines.push('Tool conclusion only — final judgment org-side.');
        return lines.join('\n');
    }

    /**
     * Narrate a single domain row from a per_domain conclusion.
     *
     * @param {object} c — v2 per_domain conclusion
     * @param {string} domain — 'cyber' | 'physical' | 'info'
     * @returns {string} multi-line plain text
     */
    function narrateDomain(c, domain) {
        const lines = [];
        if (!c || !domain) return 'No per_domain conclusion available.';

        if (c.conclusion_unavailable_reason) {
            lines.push(domain.toUpperCase() + ': unavailable (' + c.conclusion_unavailable_reason + ')');
            return lines.join('\n');
        }

        // Parse per_domain state ("cyber=STABLE;physical=...;info=...")
        const stateByDomain = {};
        if (typeof c.state === 'string') {
            c.state.split(';').forEach((pair) => {
                const idx = pair.indexOf('=');
                if (idx <= 0) return;
                const k = pair.slice(0, idx).trim();
                const v = pair.slice(idx + 1).trim();
                if (k && v) stateByDomain[k] = v;
            });
        }
        const status = stateByDomain[domain] || 'INSUFFICIENT_SIGNAL';
        const md = c.metadata || {};
        const scores = md.domain_scores || {};
        const score = (typeof scores[domain] === 'number') ? scores[domain] : null;

        lines.push(domain.toUpperCase() + ': ' + status + (score != null ? ' (' + _fmtNum(score) + ')' : ''));

        // Floor context — which threshold the score sits relative to.
        const thr = c.threshold_ref || {};
        const elevatedFloor = thr.elevated_floor;
        const activeFloor = thr.active_floor;
        if (typeof elevatedFloor === 'number' && score != null) {
            if (score < elevatedFloor) {
                lines.push('Below ELEVATED floor (' + _fmtNum(elevatedFloor) + ')');
            } else if (typeof activeFloor === 'number' && score < activeFloor) {
                lines.push('At ELEVATED (≥' + _fmtNum(elevatedFloor) + '), below ACTIVE (' + _fmtNum(activeFloor) + ')');
            } else if (typeof activeFloor === 'number') {
                lines.push('At/above ACTIVE (≥' + _fmtNum(activeFloor) + ')');
            }
        }

        // Top 2 contributing signals for this domain (from rationale_matrix).
        const rm = (c.metadata && c.metadata.rationale_matrix) || [];
        const inDomain = (Array.isArray(rm) ? rm : [])
            .filter(r => r && r.domain === domain && typeof r.final_contribution === 'number')
            .slice(0, 2);
        if (inDomain.length) {
            lines.push('Top contributors:');
            inDomain.forEach(r => {
                lines.push('  · ' + (r.sensor || '?') + ' ' + _fmtNum(r.final_contribution));
            });
        }

        return lines.join('\n');
    }

    /**
     * Build a single-sentence narrative for an Alert Lane (TRIAGE) item.
     * Pure template-based composition — same NP6 transparency / AP2
     * self-explanation contract as narrateTL / narrateDomain. Caller
     * gets a humanised line that survives without LLM availability.
     *
     * Input shape (from triage_score.rankItems):
     *   item.rank          : 1..N
     *   item.score         : attention score (0..1)
     *   item.kindLabel     : 'ATTACK_MODE: COORDINATED_DDOS' | 'ANOMALY: BURST'
     *   item.why           : list of short reason strings
     *   item.conclusion    : full Conclusion object
     *
     * @param {object} item
     * @param {{ now?: number, locale?: string }} [opts]
     * @returns {string}
     */
    function narrateTriage(item, opts) {
        if (!item || !item.conclusion) return '';
        const o = opts || {};
        const now = o.now || (Date.now() / 1000);
        const c = item.conclusion;
        const why = (Array.isArray(item.why) ? item.why : []).filter(Boolean);

        const parts = [];

        // Subject — kindLabel already expands to "ATTACK_MODE: COORDINATED_DDOS"
        const kind = item.kindLabel
            || String(c.conclusion_type || 'event').toUpperCase();
        parts.push(kind);

        // Scenario subject — wrapped in "on" so the sentence reads naturally.
        if (c.scenario_id) {
            parts.push('on ' + String(c.scenario_id));
        }

        // Confidence as percent.
        if (typeof c.confidence === 'number') {
            parts.push('confidence ' + Math.round(c.confidence * 100) + '%');
        }

        // Age — observed_at is unix seconds.
        const observedAt = (typeof c.observed_at === 'number') ? c.observed_at : null;
        if (observedAt) {
            parts.push('observed ' + _fmtAge(observedAt, now));
        }

        // Ranking rationale — chain the reasons with semicolons.
        if (why.length > 0) {
            parts.push('— ranked #' + item.rank + ' because ' + why.join('; '));
        } else if (typeof item.score === 'number') {
            parts.push('— ranked #' + item.rank
                      + ' (score ' + item.score.toFixed(2) + ')');
        }

        // Compose with comma joins. Defensive against accidental commas inside
        // why-strings: keep whitespace clean by trimming first.
        return parts.map(s => String(s).trim()).filter(Boolean).join(', ');
    }

    return {
        narrateTL: narrateTL,
        narrateDomain: narrateDomain,
        narrateTriage: narrateTriage,
    };
});
