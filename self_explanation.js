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
        if (sec < 60) return 'たった今';
        if (sec < 3600) return Math.round(sec / 60) + 'm 前';
        if (sec < 86400) return (sec / 3600).toFixed(1) + 'h 前';
        return (sec / 86400).toFixed(1) + 'd 前';
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
        if (!c) return 'threat_level の結論なし。';

        if (c.conclusion_unavailable_reason) {
            lines.push('TL: 結論不可（' + c.conclusion_unavailable_reason + '）');
            const reason = c.metadata && c.metadata.reason_detail;
            if (reason) lines.push('理由: ' + reason);
            lines.push('本ツールの結論であり、最終判断は組織側で行う。');
            return lines.join('\n');
        }

        const tl = c.state;
        lines.push('脅威レベル: ' + (tl != null ? tl : '—'));

        const md = c.metadata || {};
        const score = (typeof md.score === 'number') ? md.score : null;
        const adc = (typeof md.active_domain_count === 'number') ? md.active_domain_count : null;
        const conv = (typeof md.convergence_bonus === 'number') ? md.convergence_bonus : null;
        const conf = (typeof c.confidence === 'number') ? c.confidence : null;
        const detailParts = [];
        if (score != null) detailParts.push('スコア ' + _fmtNum(score));
        if (adc != null) detailParts.push('アクティブドメイン ' + adc);
        if (conv != null) detailParts.push('収斂 +' + _fmtNum(conv));
        if (conf != null) detailParts.push('確信度 ' + _fmtNum(conf));
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
        if (crossed.length) lines.push('超過閾値: ' + crossed.join(', '));
        if (next.length) lines.push('次の閾値: ' + next[0]);

        // Calibration
        const cal = c.calibration_status || {};
        if (cal && (typeof cal.sample_size === 'number' || cal.status)) {
            const calBits = [];
            if (cal.status) calBits.push(cal.status);
            if (typeof cal.sample_size === 'number') calBits.push('n=' + cal.sample_size);
            if (typeof cal.recall === 'number') calBits.push('recall=' + _fmtNum(cal.recall));
            if (calBits.length) lines.push('Calibration: ' + calBits.join(' · '));
        }

        // What would change this (ADR-V2-016 — NP6 falsification view).
        // Renders only when the conclusion carries a non-empty
        // metadata.falsification block. Skipped on INSUFFICIENT_DATA.
        const flip = !opts || opts.includeFalsification !== false;
        const fals = md.falsification || null;
        if (flip && fals && (fals.threshold_distance || fals.signal_sensitivity)) {
            const flLines = _renderFalsificationLines(fals);
            if (flLines.length) {
                lines.push('この結論が変わる条件:');
                flLines.forEach(l => lines.push('  ' + l));
            }
        }

        // Analyst review recency
        const lastView = opts && opts.lastViewTs;
        const ageStr = _fmtAge(lastView, now);
        if (ageStr) lines.push('アナリスト最終確認: ' + ageStr);

        lines.push('本ツールの結論であり、最終判断は組織側で行う。');
        return lines.join('\n');
    }

    /**
     * Render the "What would change this" lines from a falsification
     * metadata block. Returns ≤ 4 lines so the narrative stays
     * glance-readable. Lower TL number = more severe (radar.scoring.derive_tl).
     */
    function _renderFalsificationLines(fals) {
        const out = [];
        const dist = fals && fals.threshold_distance || {};
        const upObj = dist.to_higher_tl || {};
        const downObj = dist.to_lower_tl || {};

        // Higher severity (lower TL number).
        if (upObj.target_tl != null) {
            const conds = upObj.conditions || [];
            if (conds.length === 0) {
                out.push('深刻度は TL' + upObj.target_tl
                         + ' へ上昇（条件はすべて充足済み）');
            } else {
                const parts = conds.map(_fmtFalsCondGap);
                out.push('深刻度が TL' + upObj.target_tl + ' へ上昇する条件: '
                         + parts.join(' かつ '));
            }
        } else {
            out.push('既に TL1（これ以上の深刻度は未定義）');
        }

        // Lower severity (higher TL number) — what would trigger drop.
        if (downObj.target_tl != null) {
            const conds = downObj.conditions || [];
            if (conds.length) {
                const parts = conds.map(_fmtFalsCondTrigger);
                // Take the closest trigger (smallest gap) to keep the
                // narrative tight. Sort by absolute gap.
                parts.sort((a, b) => a.gap - b.gap);
                const closest = parts[0];
                out.push('深刻度が TL' + downObj.target_tl + ' へ低下する条件: '
                         + closest.text);
            }
        }

        // Top signal sensitivity — show up to 2 signals that, if
        // dropped to zero, would shift TL.
        const sens = (fals.signal_sensitivity || [])
            .filter(s => s && Number.isFinite(s.moves_tl_by) && s.moves_tl_by !== 0)
            .slice(0, 2);
        sens.forEach(s => {
            const dir = s.moves_tl_by > 0 ? '低下' : '上昇';
            out.push((s.sensor || '?') + '（' + (s.domain || '?')
                     + ' 寄与 ' + _fmtNum(s.current_contribution)
                     + '）が 0 になると深刻度は TL'
                     + s.hypothetical_tl_if_drops_to_zero + ' へ' + dir);
        });

        return out;
    }

    function _fmtFalsCondGap(c) {
        // Used in to_higher_tl: "score reaches 6.0 (currently 4.2, gap +1.8)"
        const field = c.field === 'active_domain_count' ? 'アクティブドメイン数'
                    : c.field === 'physical_score'      ? 'physical スコア'
                    : 'スコア';
        return field + ' ≥ ' + _fmtNum(c.target)
             + '（現在 ' + _fmtNum(c.current)
             + '、差 +' + _fmtNum(c.gap) + '）';
    }

    function _fmtFalsCondTrigger(c) {
        // Used in to_lower_tl: returns a {text, gap} so the caller
        // can sort by closest trigger.
        const field = c.field === 'active_domain_count' ? 'アクティブドメイン数'
                    : c.field === 'physical_score'      ? 'physical スコア'
                    : 'スコア';
        return {
            text: field + ' < ' + _fmtNum(c.trigger_below)
                + '（現在 ' + _fmtNum(c.current)
                + '、余裕 ' + _fmtNum(c.gap) + '）',
            gap: Math.abs(c.gap || 0),
        };
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
        if (!c || !domain) return 'per_domain の結論なし。';

        if (c.conclusion_unavailable_reason) {
            lines.push(domain.toUpperCase() + ': 結論不可（' + c.conclusion_unavailable_reason + '）');
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
                lines.push('ELEVATED 下限（' + _fmtNum(elevatedFloor) + '）未満');
            } else if (typeof activeFloor === 'number' && score < activeFloor) {
                lines.push('ELEVATED（≥' + _fmtNum(elevatedFloor) + '）到達、ACTIVE（' + _fmtNum(activeFloor) + '）未満');
            } else if (typeof activeFloor === 'number') {
                lines.push('ACTIVE（≥' + _fmtNum(activeFloor) + '）以上');
            }
        }

        // Top 2 contributing signals for this domain (from rationale_matrix).
        const rm = (c.metadata && c.metadata.rationale_matrix) || [];
        const inDomain = (Array.isArray(rm) ? rm : [])
            .filter(r => r && r.domain === domain && typeof r.final_contribution === 'number')
            .slice(0, 2);
        if (inDomain.length) {
            lines.push('主な寄与:');
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
            parts.push('シナリオ ' + String(c.scenario_id));
        }

        // Confidence as percent.
        if (typeof c.confidence === 'number') {
            parts.push('確信度 ' + Math.round(c.confidence * 100) + '%');
        }

        // Age — observed_at is unix seconds.
        const observedAt = (typeof c.observed_at === 'number') ? c.observed_at : null;
        if (observedAt) {
            parts.push('観測 ' + _fmtAge(observedAt, now));
        }

        // Ranking rationale — chain the reasons with semicolons.
        if (why.length > 0) {
            parts.push('— 注目度順位 #' + item.rank + ' の根拠: ' + why.join('; '));
        } else if (typeof item.score === 'number') {
            parts.push('— 注目度順位 #' + item.rank
                      + '（スコア ' + item.score.toFixed(2) + '）');
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
