"""radar.engine -- SensorRegistry and WeightedConvergenceEngine."""
from __future__ import annotations
import math
import os
import threading
import time
from typing import Optional
from radar.config import (
    FEINT_DISTRACTION_MAX_SCORE, FEINT_PRIMARY_MIN_SCORE,
    FEINT_MIN_DISTRACTION_DOMAINS,
    ESCALATION_TL_THRESHOLDS,
    DERIVATIVE_WINDOW,
    THEATER_BASELINE_WINDOW, THEATER_BASELINE_MIN_SAMPLES,
    TRIANGULATION_BONUS, SILENT_DIVERGENCE_THRESHOLD,
)


def _domain_weights() -> dict:
    return {
        "cyber":    float(os.getenv("DOMAIN_WEIGHT_CYBER",    "0.50")),
        "physical": float(os.getenv("DOMAIN_WEIGHT_PHYSICAL", "0.30")),
        "info":     float(os.getenv("DOMAIN_WEIGHT_INFO",     "0.20")),
    }
from radar.models import (
    RationaleEntry,
    DIRECTION_ADVERSARY_OFFENSIVE, DIRECTION_FRIENDLY_DEFENSIVE,
    DIRECTION_TARGET_IMPACT, DIRECTION_UNKNOWN,
)
from radar.sensors.base import BaseSensor

class SensorRegistry:
    def __init__(self): self._sensors: dict[str, BaseSensor] = {}; self._lock = threading.Lock()
    def register(self, sensor: BaseSensor):
        with self._lock: self._sensors[sensor.name] = sensor
    def get(self, name: str) -> Optional[BaseSensor]: return self._sensors.get(name)
    def set_enabled(self, name: str, enabled: bool):
        with self._lock:
            if name in self._sensors: self._sensors[name].enabled = enabled
    def health_report(self) -> dict:
        result = {}
        for name, s in self._sensors.items():
            h = s.health  # Already lock-protected
            with s._lock:
                cache_time = s._cache_time
                cb_state = s._cb_state
            result[name] = {
                "status": h, "domain": s.domain,
                "last_fetch_ts": cache_time or None,
                "cb_state": cb_state,
            }
        return result
    def config_list(self) -> list: return [s.to_config_dict() for s in self._sensors.values()]

class WeightedConvergenceEngine:
    @property
    def DOMAIN_WEIGHTS(self) -> dict:
        return _domain_weights()
    def compute_domain_scores(self, rationale: list) -> dict:
        scores = {"cyber": 0, "physical": 0, "info": 0}
        # Group entries by signal_source to deduplicate correlated sensors.
        # Sensors sharing a signal_source (e.g. "bgp" for IODA/BgpRouting/IHR)
        # contribute only the MAX(score × confidence) instead of additive sum.
        source_best: dict[str, tuple[str, float]] = {}  # source -> (domain, best_score)
        for entry in rationale:
            if isinstance(entry, RationaleEntry) and not entry.suppressed and entry.status == "FIRED":
                if entry.domain not in scores:
                    continue
                weighted = entry.score * entry.confidence
                if entry.signal_source:
                    key = entry.signal_source
                    prev_domain, prev_best = source_best.get(key, ("", 0.0))
                    if weighted > prev_best:
                        source_best[key] = (entry.domain, weighted)
                else:
                    # No signal_source: add directly (independent sensor)
                    scores[entry.domain] += weighted
        # Add deduplicated signal_source contributions
        for src, (domain, best) in source_best.items():
            scores[domain] += best
        # Round to avoid floating point noise in downstream integer comparisons
        return {d: round(s, 2) for d, s in scores.items()}
    def compute_convergence_score(self, domain_scores: dict) -> float:
        return sum(min(domain_scores.get(d, 0), 10) * w for d, w in self.DOMAIN_WEIGHTS.items())
    def compute_convergence_level(self, domain_scores: dict) -> str:
        active = sum(1 for s in domain_scores.values() if s > 0)
        return "FULL_CONVERGENCE" if active >= 3 else "DUAL_DOMAIN" if active == 2 else "SINGLE_DOMAIN" if active == 1 else "NONE"
    def apply_convergence_bonus(self, score: int, domain_scores: dict,
                                domain_confidences: dict | None = None) -> tuple:
        level = self.compute_convergence_level(domain_scores)
        _full_bonus = int(os.getenv("CONVERGENCE_FULL_BONUS", "2"))
        _dual_bonus = int(os.getenv("CONVERGENCE_DUAL_BONUS", "1"))
        raw_bonus = _full_bonus if level == "FULL_CONVERGENCE" else _dual_bonus if level == "DUAL_DOMAIN" else 0
        # Gate bonus by minimum confidence across active domains
        if raw_bonus > 0 and domain_confidences:
            active_confs = [domain_confidences[d] for d in domain_scores if domain_scores[d] > 0 and d in domain_confidences]
            if active_confs:
                gate = min(active_confs)
                bonus = round(raw_bonus * gate, 2)
            else:
                bonus = raw_bonus
        else:
            bonus = raw_bonus
        return score + bonus, bonus, level
    @staticmethod
    def compute_tl_proximity(score: float, current_tl: int) -> dict:
        """
        Compute distance from current score to TL boundaries.
        Returns dict with distance_up (pts to escalate), distance_down (pts to de-escalate),
        next_tl_up, next_tl_down, and proximity_label (NEAR_ESCALATION / NEAR_DE_ESCALATION / STABLE).
        """
        thresholds = ESCALATION_TL_THRESHOLDS  # {4:2, 3:4, 2:6, 1:9}
        # Distance to escalation (lower TL = higher threat)
        dist_up = None
        next_up = None
        for tl in sorted(thresholds.keys()):
            if tl < current_tl:
                needed = thresholds[tl] - score
                if needed > 0 and (dist_up is None or needed < dist_up):
                    dist_up = round(needed, 2)
                    next_up = tl
        # Distance to de-escalation (higher TL = lower threat)
        dist_down = None
        next_down = None
        if current_tl < 5:
            threshold_current = thresholds.get(current_tl, 0)
            if score >= threshold_current:
                dist_down = round(score - threshold_current + 0.01, 2)
                next_down = current_tl + 1
        # Proximity label
        near_threshold = 1.5
        if dist_up is not None and dist_up <= near_threshold:
            label = "NEAR_ESCALATION"
        elif dist_down is not None and dist_down <= near_threshold:
            label = "NEAR_DE_ESCALATION"
        else:
            label = "STABLE"
        return {
            "distance_up": dist_up, "next_tl_up": next_up,
            "distance_down": dist_down, "next_tl_down": next_down,
            "proximity_label": label,
        }

    @staticmethod
    def compute_eta_to_next_tl(tl_proximity: dict,
                               velocity_pt_per_sec: float) -> dict | None:
        """Project seconds until the score crosses the next TL boundary.

        Combines pt-distance (from compute_tl_proximity) with current
        velocity (pts/second, as produced by compute_velocity) to produce
        a time estimate. Direction is implicit in the sign of velocity:
          velocity > 0 → uses distance_up, projects escalation ETA
          velocity < 0 → uses distance_down, projects de-escalation ETA
          velocity ≈ 0 → returns None (no meaningful ETA)

        Returns: {eta_sec, direction, target_tl} or None if not projectable.
        ETAs longer than 7 days are also suppressed as analytically useless.
        """
        if not tl_proximity or velocity_pt_per_sec is None:
            return None
        # Anything below ~0.0001 pt/s aligns with the existing "stable"
        # threshold used for the velocity arrow display, and prevents
        # divide-by-noise blowups on flat lines.
        if abs(velocity_pt_per_sec) < 0.0001:
            return None
        if velocity_pt_per_sec > 0:
            dist = tl_proximity.get("distance_up")
            target = tl_proximity.get("next_tl_up")
            direction = "escalating"
        else:
            dist = tl_proximity.get("distance_down")
            target = tl_proximity.get("next_tl_down")
            direction = "deescalating"
        if dist is None or target is None:
            return None
        eta_sec = dist / abs(velocity_pt_per_sec)
        if eta_sec > 7 * 86400:
            return None
        return {
            "eta_sec":   round(eta_sec),
            "direction": direction,
            "target_tl": target,
        }

    @staticmethod
    def compute_domain_confidences(rationale: list) -> dict:
        """
        Compute average confidence per domain from fired rationale entries.
        Returns {domain: avg_confidence} for domains with fired entries.
        """
        domain_confs: dict[str, list] = {"cyber": [], "physical": [], "info": []}
        for entry in rationale:
            if isinstance(entry, RationaleEntry) and not entry.suppressed and entry.status == "FIRED":
                if entry.domain in domain_confs:
                    domain_confs[entry.domain].append(entry.confidence)
        return {d: round(sum(cs) / len(cs), 3) if cs else 1.0 for d, cs in domain_confs.items()}

    def build_system_note(self, threat_level: int, domain_scores: dict, convergence_level: str, rationale: list, noise_filters: list, tl_held: bool = False) -> str:
        fired = [e for e in rationale if isinstance(e, RationaleEntry) and e.status == "FIRED"]
        suppressed = [e for e in rationale if isinstance(e, RationaleEntry) and e.suppressed]
        held_note = " [HYSTERESIS HOLD]" if tl_held else ""
        parts = [f"Assessed THREAT LEVEL {threat_level}{held_note}."]
        _fb = int(os.getenv("CONVERGENCE_FULL_BONUS", "2"))
        _db = int(os.getenv("CONVERGENCE_DUAL_BONUS", "1"))
        conv_label = {"FULL_CONVERGENCE": f"⚡ FULL CONVERGENCE (+{_fb}pt bonus)", "DUAL_DOMAIN": f"⚠ DUAL DOMAIN (+{_db}pt bonus)", "SINGLE_DOMAIN": "Single Domain Activity", "NONE": ""}.get(convergence_level, "")
        if conv_label: parts.append(conv_label + ".")
        active_domains = [f"{d.upper()}({domain_scores[d]}pt)" for d in ("cyber", "physical", "info") if domain_scores.get(d, 0) > 0]
        if active_domains: parts.append(f"Active Domains: {', '.join(active_domains)}.")
        if fired: parts.append(f"Triggered Sensors: {', '.join(e.sensor for e in fired)}.")
        if suppressed: parts.append(f"Suppressed (Noise): {', '.join(e.sensor for e in suppressed)}.")
        if noise_filters: parts.append(f"Active Suppressors: {'; '.join(noise_filters)}.")
        return " ".join(parts)

    # ── Derivative & Synchronicity Methods ────────────────────────────────────
    @staticmethod
    def _linear_regression_slope(xs: list, ys: list) -> float:
        """Return the slope from least-squares linear regression."""
        n = len(xs)
        if n < 2: return 0.0
        sx, sy, sxy, sxx = sum(xs), sum(ys), sum(x*y for x,y in zip(xs,ys)), sum(x*x for x in xs)
        denom = n * sxx - sx * sx
        return (n * sxy - sx * sy) / denom if denom != 0 else 0.0

    def compute_velocity(self, ts_series: list) -> float:
        """First derivative: threat score change velocity (pt/s). Smoothed via linear regression slope over DERIVATIVE_WINDOW points."""
        pts = ts_series[-DERIVATIVE_WINDOW:] if len(ts_series) >= 2 else []
        if len(pts) < 2: return 0.0
        t0 = pts[0][0]
        xs = [p[0] - t0 for p in pts]
        ys = [p[1] for p in pts]
        return round(self._linear_regression_slope(xs, ys), 6)

    def compute_acceleration(self, ts_series: list) -> float:
        """Second derivative: rate of velocity change (pt/s²). Computed from a linear regression slope over consecutive velocity points."""
        if len(ts_series) < 4: return 0.0
        # Generate velocity series
        velocities = []
        for i in range(1, len(ts_series)):
            dt = ts_series[i][0] - ts_series[i-1][0]
            if dt > 0:
                velocities.append((ts_series[i][0], (ts_series[i][1] - ts_series[i-1][1]) / dt))
        if len(velocities) < 2: return 0.0
        t0 = velocities[0][0]
        xs = [v[0] - t0 for v in velocities]
        ys = [v[1] for v in velocities]
        return round(self._linear_regression_slope(xs, ys), 8)

    def detect_ambush_pattern(self, ts_series: list) -> tuple:
        """
        Flags an Ambush Pattern (sudden rapid escalation) when the acceleration Z-Score
        exceeds AMBUSH_ZSCORE_THRESHOLD and acceleration is positive.
        Returns: (is_ambush: bool, z_score: float, velocity: float, acceleration: float)
        """
        if len(ts_series) < 5:
            return False, 0.0, 0.0, 0.0
        velocity = self.compute_velocity(ts_series)
        # Generate acceleration time series by shifting windows rather than computing from all points
        acc_series = []
        window = min(DERIVATIVE_WINDOW, len(ts_series) // 2)
        for i in range(window, len(ts_series)):
            sub = ts_series[i-window:i+1]
            acc_series.append(self.compute_acceleration(sub))
        if len(acc_series) < 3:
            return False, 0.0, velocity, 0.0
        current_acc = acc_series[-1]
        mean_acc = sum(acc_series[:-1]) / len(acc_series[:-1])
        variance = sum((a - mean_acc) ** 2 for a in acc_series[:-1]) / len(acc_series[:-1])
        std_acc = math.sqrt(variance) if variance > 0 else 0.0
        z_score = (current_acc - mean_acc) / std_acc if std_acc > 0 else 0.0
        is_ambush = (z_score > float(os.getenv("AMBUSH_ZSCORE_THRESHOLD", "2.0"))) and (current_acc > 0) and (velocity > 0)
        return is_ambush, round(z_score, 3), round(velocity, 6), round(current_acc, 8)

    @staticmethod
    def compute_sync_score(origin_timestamps: dict) -> float:
        """
        Compute synchrony score from attack-start timestamps across multiple GEO sources.
        origin_timestamps: {country_code: timestamp_ms}
        Returns: sync_score (0.0–1.0). Exceeding SYNC_C2_THRESHOLD indicates suspected state-level C2.
        """
        codes = list(origin_timestamps.keys())
        n = len(codes)
        if n < 2: return 0.0
        pair_count = n * (n - 1) // 2
        sync_pairs = 0
        for i in range(n):
            for j in range(i + 1, n):
                dt = abs(origin_timestamps[codes[i]] - origin_timestamps[codes[j]])
                if dt <= float(os.getenv("SYNC_DELTA_MS", "500")):
                    sync_pairs += 1
        return round(sync_pairs / pair_count, 3) if pair_count > 0 else 0.0

    # ── v9: Temporal Coherence / Maskirovka / Blockade Index ─────────────────

    @staticmethod
    def compute_temporal_coherence(sequence_events: dict, theaters: list,
                                   window_sec: float = 60.0) -> tuple:
        """
        Verify that attack-start timing across multiple theaters converges within window_sec seconds.
        High synchrony (within 1 minute) is treated as evidence of state-level integrated C2.

        sequence_events: {theater: [{"ts": float, "type": str, ...}, ...]}
        theaters: list of theaters to evaluate
        Returns: (is_synchronized: bool, coherence_score: float, bonus: int, detail: str)
        """
        # Collect timestamps of the first SYNC_DDOS or NARRATIVE_BURST event per theater
        first_events: dict = {}
        for theater in theaters:
            events = sequence_events.get(theater, [])
            trigger_events = [
                e["ts"] for e in events
                if e.get("type") in ("SYNC_DDOS", "NARRATIVE_BURST")
            ]
            if trigger_events:
                first_events[theater] = min(trigger_events)

        if len(first_events) < 2:
            return False, 0.0, 0, "insufficient_events"

        ts_list = list(first_events.values())
        spread_sec = max(ts_list) - min(ts_list)

        if spread_sec <= window_sec:
            # Sync within 1 minute → state C2 bonus +2
            coherence_score = round(1.0 - spread_sec / window_sec, 3)
            detail = f"C2_SYNC_CONFIRMED: {len(first_events)} theaters within {spread_sec:.1f}s"
            return True, coherence_score, 2, detail
        elif spread_sec <= window_sec * 5:
            # Loose sync within 5 minutes → partial bonus +1
            coherence_score = round(max(0.0, 1.0 - spread_sec / (window_sec * 5)), 3)
            detail = f"C2_SYNC_PARTIAL: {len(first_events)} theaters within {spread_sec:.1f}s"
            return False, coherence_score, 1, detail

        return False, 0.0, 0, f"no_sync: spread={spread_sec:.1f}s"

    @staticmethod
    def detect_maskirovka(core_degraded: bool, narrative_burst: bool,
                          check_host_status: Optional[str],
                          telegram_intent: bool,
                          other_sensors_alive: bool = True) -> tuple:
        """
        Maskirovka (deception operation) detection:
        Flags when physical disruption (Check-Host/IODA at BLACKOUT/PARTIAL) is present
        but the narrative (Telegram mirror / RSS) is silent.

        other_sensors_alive: True when ≥1 adjacent theater's sensors are responding normally.
            Distinguishes deliberate regional suppression from a global API outage.
            When True, confidence is upgraded MEDIUM → HIGH (+1 score bonus via rationale).

        Returns: (is_maskirovka: bool, confidence: str, reason: str)
        """
        has_physical_outage   = core_degraded or check_host_status == "BLACKOUT"
        has_narrative_silence = not narrative_burst and not telegram_intent

        if has_physical_outage and has_narrative_silence:
            if other_sensors_alive:
                return True, "HIGH", (
                    "Physical outage confirmed, all narrative channels silent, "
                    "and adjacent theater sensors are live — "
                    "deliberate regional suppression confirmed (Maskirovka HIGH)"
                )
            return True, "MEDIUM", (
                "Physical outage confirmed but all narrative channels silent — "
                "possible deception operation (Maskirovka); "
                "cross-theater sensor liveness unconfirmed"
            )
        return False, "NONE", ""

    @staticmethod
    def _agg_node_status(statuses: list) -> str:
        """Worst-case node status aggregation across multiple URL checks.
        Priority: FAIL > TIMEOUT > OK > PENDING (unknown last)."""
        if "FAIL"    in statuses: return "FAIL"
        if "TIMEOUT" in statuses: return "TIMEOUT"
        if "OK"      in statuses: return "OK"
        return "PENDING"

    @staticmethod
    def compute_blockade_index(ddos_intensity: float, ripe_drop_pct: float,
                               checkhost_success_rate: Optional[float],
                               asphyxiation: bool = False) -> float:
        """
        Effective Blockade Index: attack_weight × (noise_floor + infra_degradation)
        Scores the effectiveness of "communications blackout" from 0 to 10.

        ddos_intensity:         CF spike factor (average spike multiplier)
        ripe_drop_pct:          RIPE BGP prefix drop rate (0–100)
        checkhost_success_rate: Check-Host success rate (0.0–1.0, None = unknown → treat as OK)
        asphyxiation:           CDN-masking detected — success_rate==100% but latency ≥ 3× baseline.

        Formula: attack_weight × (0.10 + 0.90 × infra_degradation)
          - infra_degradation = 1.0 − ch_success_rate (0 when OK, 1 when BLACKOUT)
          - 10% noise floor: DDoS visible even when infrastructure is healthy
          - 90% infra-weighted: real BLOCKADE requires actual connectivity loss
          - When ch_success_rate is None (API unreachable), treat as OK (conservative)
        Examples:
          spike×10 + RIPE 0% + CH OK  (1.0) → 10 × 0.10 = 1.0  (noise only)
          spike×10 + RIPE 0% + CH PARTIAL (0.5) → 10 × 0.55 = 5.5
          spike×10 + RIPE 0% + CH BLACKOUT(0.0) → 10 × 1.00 = 10.0
        """
        ripe_factor    = min(ripe_drop_pct / 100.0, 1.0)
        intensity      = min(ddos_intensity, 10.0)
        attack_weight  = intensity * (1.0 + ripe_factor)   # max 20 when RIPE 100%

        # Infrastructure degradation: 0.0 = fully reachable, 1.0 = fully unreachable
        # None (API unreachable) → treat conservatively as OK
        ch_rate        = checkhost_success_rate if checkhost_success_rate is not None else 1.0
        infra_deg      = max(0.0, 1.0 - ch_rate)

        raw = attack_weight * (0.10 + 0.90 * infra_deg)

        # Asphyxiation: CDN masks packet loss but latency tripling reveals infrastructure strain
        if asphyxiation:
            raw *= 1.5
        return round(min(raw, 10.0), 2)

    # ── Phase 2: Feint Detection ──────────────────────────────────────────────

    @staticmethod
    def detect_feint_pattern(domain_scores: dict, rationale: list) -> tuple:
        """
        Detect diversionary attack pattern: low-mid activity across multiple domains
        masking a concentrated attack in one primary domain.

        Returns: (is_feint, primary_domain, distraction_domains, confidence, detail)
        """
        distractions = []
        primaries = []
        for d, s in domain_scores.items():
            if s >= FEINT_PRIMARY_MIN_SCORE:
                primaries.append(d)
            elif 1 <= s <= FEINT_DISTRACTION_MAX_SCORE:
                distractions.append(d)

        if len(primaries) != 1 or len(distractions) < FEINT_MIN_DISTRACTION_DOMAINS:
            return False, None, [], "NONE", ""

        primary = primaries[0]
        primary_score = domain_scores[primary]
        confidence = "HIGH" if primary_score >= 7 else "MEDIUM"

        # Identify which sensors are involved in the primary domain attack
        primary_sensors = [
            e.sensor for e in rationale
            if isinstance(e, RationaleEntry) and e.domain == primary
            and e.status == "FIRED" and not e.suppressed
        ]
        detail = (
            f"Feint pattern: {', '.join(distractions)} domains show low activity "
            f"(distraction), {primary.upper()} domain at {primary_score}pt "
            f"(primary target via {', '.join(primary_sensors[:3])})"
        )
        return True, primary, distractions, confidence, detail

    # ── Phase 2: Escalation Progress Tracking ─────────────────────────────────

    @staticmethod
    def compute_escalation_progress(threat_history: list,
                                     alert_timeline: list) -> dict:
        """
        Analyze TL escalation patterns and predict time to next TL.

        threat_history: [(ts, tl), ...]
        alert_timeline: [{"ts": float, "threat_level": int, "score_with_bonus": int, ...}, ...]

        Returns dict with current_tl, tl_duration, velocity, score_trend,
        predicted_next_tl, predicted_time_sec, tl_transitions, pattern.
        """
        if not threat_history:
            return {
                "current_tl": 5, "tl_duration_sec": 0,
                "escalation_velocity": 0.0, "score_trend": 0.0,
                "predicted_next_tl": None, "predicted_time_sec": None,
                "tl_transitions": [], "pattern": "NO_DATA",
            }

        current_tl = threat_history[-1][1]
        current_ts = threat_history[-1][0]

        # Find how long we've been at the current TL
        tl_start_ts = current_ts
        for i in range(len(threat_history) - 2, -1, -1):
            if threat_history[i][1] == current_tl:
                tl_start_ts = threat_history[i][0]
            else:
                break
        tl_duration_sec = current_ts - tl_start_ts

        # Extract TL transitions (consecutive entries where TL changed)
        transitions = []
        for i in range(1, len(threat_history)):
            prev_tl = threat_history[i - 1][1]
            curr_tl = threat_history[i][1]
            if curr_tl != prev_tl:
                transitions.append({
                    "ts": threat_history[i][0],
                    "from_tl": prev_tl,
                    "to_tl": curr_tl,
                    "direction": "ESCALATE" if curr_tl < prev_tl else "DE-ESCALATE",
                })

        # Escalation velocity: TL changes per hour over observed window
        if len(threat_history) >= 2:
            time_span_h = (threat_history[-1][0] - threat_history[0][0]) / 3600
            if time_span_h > 0:
                # Negative = escalating (TL decreasing), positive = de-escalating
                tl_delta = threat_history[-1][1] - threat_history[0][1]
                esc_velocity = round(tl_delta / time_span_h, 4)
            else:
                esc_velocity = 0.0
        else:
            esc_velocity = 0.0

        # Score trend from alert_timeline (pts/hour via linear regression)
        score_trend = 0.0
        if len(alert_timeline) >= 3:
            recent = alert_timeline[-20:]
            ts_vals = [(a.get("ts", 0), a.get("score_with_bonus", 0)) for a in recent
                       if a.get("ts") and a.get("score_with_bonus") is not None]
            if len(ts_vals) >= 2:
                t0 = ts_vals[0][0]
                xs = [(t - t0) / 3600 for t, _ in ts_vals]  # hours
                ys = [s for _, s in ts_vals]
                n = len(xs)
                sx = sum(xs)
                sy = sum(ys)
                sxy = sum(x * y for x, y in zip(xs, ys))
                sxx = sum(x * x for x in xs)
                denom = n * sxx - sx * sx
                if denom != 0:
                    score_trend = round((n * sxy - sx * sy) / denom, 4)

        # Pattern detection from recent transitions
        if len(transitions) >= 3:
            dirs = [t["direction"] for t in transitions[-5:]]
            esc_count = dirs.count("ESCALATE")
            de_count = dirs.count("DE-ESCALATE")
            if esc_count >= 2 and de_count >= 2:
                pattern = "OSCILLATING"
            elif esc_count >= 2:
                pattern = "ESCALATING"
            elif de_count >= 2:
                pattern = "DE-ESCALATING"
            else:
                pattern = "STABLE"
        elif len(transitions) >= 1:
            last_dir = transitions[-1]["direction"]
            pattern = "ESCALATING" if last_dir == "ESCALATE" else "DE-ESCALATING"
        else:
            pattern = "STABLE"

        # Predict next TL and time-to-transition using score trend
        predicted_next_tl = None
        predicted_time_sec = None
        if score_trend != 0 and alert_timeline:
            current_score = alert_timeline[-1].get("score_with_bonus", 0)
            # Find the next TL boundary to cross
            if score_trend > 0:
                # Score increasing → escalating (lower TL number)
                for tl in sorted(ESCALATION_TL_THRESHOLDS.keys()):
                    threshold = ESCALATION_TL_THRESHOLDS[tl]
                    if threshold > current_score and tl < current_tl:
                        pts_needed = threshold - current_score
                        hours = pts_needed / score_trend
                        predicted_next_tl = tl
                        predicted_time_sec = round(hours * 3600)
                        break
            else:
                # Score decreasing → de-escalating (higher TL number)
                abs_trend = abs(score_trend)
                if abs_trend < 1e-6:
                    abs_trend = 1e-6  # Guard against near-zero float
                for tl in sorted(ESCALATION_TL_THRESHOLDS.keys(), reverse=True):
                    threshold = ESCALATION_TL_THRESHOLDS[tl]
                    if threshold <= current_score and tl >= current_tl:
                        continue
                    if threshold < current_score:
                        pts_drop = current_score - threshold
                        hours = pts_drop / abs_trend
                        predicted_next_tl = tl + 1 if tl < 5 else 5
                        predicted_time_sec = round(hours * 3600)
                        break

        return {
            "current_tl": current_tl,
            "tl_duration_sec": round(tl_duration_sec),
            "escalation_velocity": esc_velocity,
            "score_trend": score_trend,
            "predicted_next_tl": predicted_next_tl,
            "predicted_time_sec": predicted_time_sec,
            "tl_transitions": transitions[-10:],
            "pattern": pattern,
        }

    # ── Context-Aware Convergence (CAC) ─────────────────────────────────────

    @staticmethod
    def compute_context_alignment(rationale: list) -> dict:
        """Compute Context Alignment — an independent metric (does NOT affect score)
        showing how many of 4 context axes are in a high-risk state.

        Axes:
        1. Temporal: multiple signals occurring within business hours / outside normal patterns
        2. Spatial: signals concentrated near strategic chokepoints / proximate geography
        3. Target: signals directly targeting strategic theaters (not ambient noise)
        4. Direction: multiple ADVERSARY_OFFENSIVE signals converging

        Returns: {
            "alignment_score": 0-4 (count of aligned axes),
            "alignment_pct": 0-100,
            "axes": {"temporal": {...}, "spatial": {...}, "target": {...}, "direction": {...}},
            "label": "LOW" / "MODERATE" / "HIGH" / "CRITICAL"
        }
        """
        fired = [e for e in rationale
                 if isinstance(e, RationaleEntry) and e.status == "FIRED" and not e.suppressed]
        if not fired:
            return {
                "alignment_score": 0, "alignment_pct": 0,
                "axes": {
                    "temporal": {"aligned": False, "detail": "no_signals"},
                    "spatial": {"aligned": False, "detail": "no_signals"},
                    "target": {"aligned": False, "detail": "no_signals"},
                    "direction": {"aligned": False, "detail": "no_signals"},
                },
                "label": "LOW",
            }

        # ── Temporal axis ─────────────────────────────────────────────────
        # Aligned when: signals cluster outside normal business hours (night ops)
        # or during known high-risk temporal windows
        temporal_contexts = [e.temporal_context for e in fired if e.temporal_context]
        temporal_aligned = False
        temporal_detail = "insufficient_data"
        if temporal_contexts:
            off_hours = sum(1 for tc in temporal_contexts if not tc.get("is_business_hours", True))
            weekend = sum(1 for tc in temporal_contexts if tc.get("is_weekend", False))
            total = len(temporal_contexts)
            # Night operations or weekend activity indicates deliberate timing
            if total > 0 and (off_hours / total > 0.5 or weekend / total > 0.5):
                temporal_aligned = True
                temporal_detail = f"off_hours={off_hours}/{total} weekend={weekend}/{total}"
            else:
                temporal_detail = f"business_hours={total - off_hours}/{total}"

        # ── Spatial axis ──────────────────────────────────────────────────
        # Aligned when: signals are geographically proximate or near chokepoints
        spatial_contexts = [e.spatial_context for e in fired if e.spatial_context]
        spatial_aligned = False
        spatial_detail = "insufficient_data"
        if spatial_contexts:
            proximate = sum(1 for sc in spatial_contexts if sc.get("distance_class") == "PROXIMATE")
            near_cp = sum(1 for sc in spatial_contexts if sc.get("near_chokepoint", False))
            total = len(spatial_contexts)
            if total > 0 and (proximate / total > 0.3 or near_cp > 0):
                spatial_aligned = True
                spatial_detail = f"proximate={proximate}/{total} chokepoint={near_cp}"
            else:
                spatial_detail = f"distant={total - proximate}/{total}"

        # ── Target axis ───────────────────────────────────────────────────
        # Aligned when: signals directly target strategic theaters
        target_contexts = [e.target_context for e in fired if e.target_context]
        target_aligned = False
        target_detail = "insufficient_data"
        if target_contexts:
            direct = sum(1 for tc in target_contexts if tc.get("target_relevance") == "DIRECT")
            adv_involved = sum(1 for tc in target_contexts if tc.get("adversary_involvement", False))
            total = len(target_contexts)
            if total > 0 and (direct / total > 0.3 or adv_involved > 0):
                target_aligned = True
                target_detail = f"direct={direct}/{total} adversary={adv_involved}"
            else:
                target_detail = f"ambient={total - direct}/{total}"

        # ── Direction axis ────────────────────────────────────────────────
        # Aligned when: multiple ADVERSARY_OFFENSIVE signals present
        adv_offensive = [e for e in fired if e.direction == DIRECTION_ADVERSARY_OFFENSIVE]
        direction_aligned = False
        direction_detail = f"adversary_offensive={len(adv_offensive)}"
        if len(adv_offensive) >= 2:
            direction_aligned = True
            # High confidence if average direction_confidence is strong
            avg_dir_conf = sum(e.direction_confidence for e in adv_offensive) / len(adv_offensive)
            direction_detail += f" avg_conf={avg_dir_conf:.2f}"

        # ── Aggregate ─────────────────────────────────────────────────────
        axes = {
            "temporal": {"aligned": temporal_aligned, "detail": temporal_detail},
            "spatial": {"aligned": spatial_aligned, "detail": spatial_detail},
            "target": {"aligned": target_aligned, "detail": target_detail},
            "direction": {"aligned": direction_aligned, "detail": direction_detail},
        }
        score = sum(1 for a in axes.values() if a["aligned"])
        labels = {0: "LOW", 1: "LOW", 2: "MODERATE", 3: "HIGH", 4: "CRITICAL"}
        return {
            "alignment_score": score,
            "alignment_pct": round(score / 4 * 100),
            "axes": axes,
            "label": labels[score],
        }

    @staticmethod
    def compute_direction_summary(rationale: list) -> dict:
        """Summarize direction classifications across all fired rationale entries.

        Returns: {
            "adversary_offensive": count,
            "friendly_defensive": count,
            "target_impact": count,
            "unknown": count,
            "dominant_direction": str,
            "direction_clarity": float (0-1, how clear the dominant direction is)
        }
        """
        fired = [e for e in rationale
                 if isinstance(e, RationaleEntry) and e.status == "FIRED" and not e.suppressed]
        counts = {
            DIRECTION_ADVERSARY_OFFENSIVE: 0,
            DIRECTION_FRIENDLY_DEFENSIVE: 0,
            DIRECTION_TARGET_IMPACT: 0,
            DIRECTION_UNKNOWN: 0,
        }
        for e in fired:
            d = e.direction if e.direction in counts else DIRECTION_UNKNOWN
            counts[d] += 1

        total = sum(counts.values())
        if total == 0:
            return {
                "adversary_offensive": 0, "friendly_defensive": 0,
                "target_impact": 0, "unknown": 0,
                "dominant_direction": DIRECTION_UNKNOWN,
                "direction_clarity": 0.0,
            }

        dominant = max(counts, key=counts.get)
        clarity = counts[dominant] / total if total > 0 else 0.0

        return {
            "adversary_offensive": counts[DIRECTION_ADVERSARY_OFFENSIVE],
            "friendly_defensive": counts[DIRECTION_FRIENDLY_DEFENSIVE],
            "target_impact": counts[DIRECTION_TARGET_IMPACT],
            "unknown": counts[DIRECTION_UNKNOWN],
            "dominant_direction": dominant,
            "direction_clarity": round(clarity, 3),
        }

    @staticmethod
    def build_event_feature_summary(sensor_name: str, theater: str,
                                     value: str, rationale: list,
                                     confirmed_threats: list = None) -> dict:
        """Generate supporting information for analyst noise classification.

        Returns dict with:
        - similar_events: count of similar past confirmed events
        - recurrence_pattern: FIRST_TIME / RECURRING / FREQUENT
        - cross_domain_signals: other domains with concurrent activity
        - contradiction_warnings: signals that contradict the current alert
        """
        confirmed_threats = confirmed_threats or []

        # Count similar past events for this sensor/theater combination
        similar = [ct for ct in confirmed_threats
                   if ct.get("theater") == theater
                   and sensor_name in ct.get("sensors_active", [])]
        similar_count = len(similar)

        if similar_count == 0:
            recurrence = "FIRST_TIME"
        elif similar_count < 3:
            recurrence = "RECURRING"
        else:
            recurrence = "FREQUENT"

        # Past classification distribution
        classifications = {}
        for ct in similar:
            cls = ct.get("classification", "unknown")
            classifications[cls] = classifications.get(cls, 0) + 1

        # Cross-domain concurrent activity
        fired = [e for e in rationale
                 if isinstance(e, RationaleEntry) and e.status == "FIRED" and not e.suppressed]
        active_domains = set(e.domain for e in fired)

        # Contradiction detection: defensive signals alongside offensive ones
        contradictions = []
        offensive = [e for e in fired if e.direction == DIRECTION_ADVERSARY_OFFENSIVE]
        defensive = [e for e in fired if e.direction == DIRECTION_FRIENDLY_DEFENSIVE]
        if offensive and defensive:
            contradictions.append({
                "type": "OFFENSIVE_DEFENSIVE_COEXIST",
                "detail": (f"{len(offensive)} adversary offensive + "
                           f"{len(defensive)} friendly defensive signals"),
            })

        return {
            "similar_events": similar_count,
            "recurrence_pattern": recurrence,
            "past_classifications": classifications,
            "cross_domain_signals": sorted(active_domains),
            "contradiction_warnings": contradictions,
        }

    # ── CAC Phase D: Forecast + Co-occurrence ─────────────────────────────

    @staticmethod
    def record_forecast(db, theater: str, current_time: float,
                        threat_level: int, escalation_data: dict) -> int | None:
        """
        Record a TL forecast based on escalation prediction.
        Only records when escalation predictor has sufficient confidence.
        Returns forecast_log ID or None.

        compute_escalation_progress() returns predicted_next_tl at the top
        level (not nested under a "prediction" key) — until 2026-04 this
        function read the wrong key and silently never recorded any forecasts.
        """
        pred_tl = escalation_data.get("predicted_next_tl")
        if pred_tl is None:
            return None
        # Only forecast if predicted TL differs from current
        if pred_tl == threat_level:
            return None
        forecast_type = "tl_escalation" if pred_tl < threat_level else "tl_de_escalation"
        predicted_str = f"TL{pred_tl}"
        try:
            return db.forecast_log_add(theater, current_time, forecast_type, predicted_str)
        except Exception:
            return None

    @staticmethod
    def resolve_pending_forecasts(db, theater: str, current_time: float,
                                  current_tl: int):
        """
        Resolve any pending forecasts whose prediction window has elapsed.
        Compares predicted TL against actual TL to compute accuracy.
        """
        try:
            pending = db.forecast_log_get(theater, limit=50)
        except Exception:
            return
        for f in pending:
            if f.get("resolved_at") is not None:
                continue  # Already resolved
            age = current_time - f["ts"]
            # Resolve forecasts after 1 hour (prediction window)
            if age < 3600:
                continue
            predicted = f.get("predicted", "")
            # Extract TL number from "TLn"
            try:
                pred_tl = int(predicted.replace("TL", ""))
            except (ValueError, AttributeError):
                continue
            actual_str = f"TL{current_tl}"
            # Accuracy: 1.0 = exact match, 0.5 = off by 1, 0.0 = off by ≥2
            diff = abs(pred_tl - current_tl)
            accuracy = 1.0 if diff == 0 else 0.5 if diff == 1 else 0.0
            try:
                db.forecast_log_resolve(f["id"], actual_str, accuracy)
            except Exception:
                pass

    # ── A2: Theater Baseline Risk (auto-calculated) ──────────────────────────

    def __init__(self):
        self._theater_baselines: dict[str, list[tuple[float, float]]] = {}
        self._baseline_lock = threading.Lock()

    def record_theater_score(self, theater: str, score: float):
        """Record a score sample for theater baseline computation."""
        now = time.time()
        cutoff = now - THEATER_BASELINE_WINDOW * 86400
        with self._baseline_lock:
            history = self._theater_baselines.setdefault(theater, [])
            history.append((now, score))
            # Prune entries older than the baseline window
            self._theater_baselines[theater] = [
                (t, s) for t, s in history if t > cutoff
            ]

    def compute_theater_zscore(self, theater: str, current_score: float) -> dict:
        """Compute Z-score of current score against theater-specific baseline.

        Returns: {"z_score": float, "baseline_mean": float, "baseline_std": float,
                  "samples": int, "is_anomalous": bool}
        """
        with self._baseline_lock:
            history = list(self._theater_baselines.get(theater, []))
        scores = [s for _, s in history]
        n = len(scores)
        if n < THEATER_BASELINE_MIN_SAMPLES:
            return {"z_score": 0.0, "baseline_mean": 0.0, "baseline_std": 0.0,
                    "samples": n, "is_anomalous": False}
        mean = sum(scores) / n
        variance = sum((s - mean) ** 2 for s in scores) / n
        std = math.sqrt(variance) if variance > 0 else 0.0
        z = (current_score - mean) / std if std > 0 else 0.0
        return {
            "z_score": round(z, 3),
            "baseline_mean": round(mean, 3),
            "baseline_std": round(std, 3),
            "samples": n,
            "is_anomalous": z > 2.0,
        }

    # ── A3: Triangulation (3-domain quality bonus) ─────────────────────────

    @staticmethod
    def compute_triangulation_bonus(domain_scores: dict,
                                     domain_confidences: dict) -> tuple:
        """Award additional bonus when ALL 3 domains (cyber, physical, info)
        independently confirm anomalous activity.

        Unlike convergence_bonus (which only checks domain count), triangulation
        verifies that each domain has meaningful signal strength (score >= 1)
        AND reasonable confidence (>= 0.5).

        Returns: (bonus: float, is_triangulated: bool, detail: str)
        """
        domains = ["cyber", "physical", "info"]
        active_strong = []
        for d in domains:
            score = domain_scores.get(d, 0)
            conf = domain_confidences.get(d, 0)
            if score >= 1 and conf >= 0.5:
                active_strong.append(d)

        if len(active_strong) == 3:
            # Quality-weighted: average confidence across all 3 domains
            avg_conf = sum(domain_confidences.get(d, 1.0) for d in domains) / 3
            bonus = round(TRIANGULATION_BONUS * avg_conf, 2)
            detail = (f"Triangulation confirmed: all 3 domains active with "
                      f"avg confidence {avg_conf:.2f} (+{bonus}pt)")
            return bonus, True, detail
        return 0.0, False, ""

    # ── A1: Silent Divergence (anomaly with info silence) ──────────────────

    @staticmethod
    def detect_silent_divergence(domain_scores: dict, rationale: list) -> tuple:
        """Detect when cyber AND physical domains show anomalies but the
        information domain is completely silent.

        This pattern indicates potential pre-conflict reconnaissance or
        preparatory activity that has not yet been publicly reported —
        the most dangerous phase of escalation.

        Requires BOTH cyber AND physical to be active (>= 1pt each) while
        info is zero. A single active domain is NOT sufficient (too many
        false positives from routine cyber noise or weather events).

        Returns: (is_silent_div: bool, confidence: str, detail: str)
        """
        cyber_score = domain_scores.get("cyber", 0)
        physical_score = domain_scores.get("physical", 0)
        info_score = domain_scores.get("info", 0)

        # Require BOTH cyber AND physical active, info silent
        if cyber_score < 1 or physical_score < 1:
            return False, "NONE", ""
        if info_score > 0:
            return False, "NONE", ""

        # Count how many cyber+physical sensors actually fired
        fired_cp = [e for e in rationale
                    if isinstance(e, RationaleEntry)
                    and e.status == "FIRED" and not e.suppressed
                    and e.domain in ("cyber", "physical")]
        if len(fired_cp) < SILENT_DIVERGENCE_THRESHOLD:
            return False, "NONE", ""

        # Confidence based on signal strength
        combined = cyber_score + physical_score
        if combined >= 6:
            confidence = "HIGH"
        elif combined >= 3:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        sensors = [e.sensor for e in fired_cp]
        detail = (f"Silent Divergence: {len(fired_cp)} sensors across cyber "
                  f"({cyber_score:.1f}pt) and physical ({physical_score:.1f}pt) "
                  f"domains active, but info domain is silent. "
                  f"Sensors: {', '.join(sensors[:5])}. "
                  f"Possible pre-conflict reconnaissance/preparation phase.")
        return True, confidence, detail

    @staticmethod
    def compute_cooccurrence_boost(db, fired_sensors: list[str],
                                   theater: str) -> dict:
        """
        Compute co-occurrence-based sensitivity boost.
        When sensor pairs that historically fire together are BOTH firing,
        this returns a confidence boost factor (only UP, never down).

        Returns: {
            "boost_factor": float (1.0 = no boost, max 1.5),
            "boosted_pairs": list of sensor pair dicts,
            "reasoning": str
        }
        """
        if len(fired_sensors) < 2:
            return {"boost_factor": 1.0, "boosted_pairs": [], "reasoning": ""}

        try:
            cooc_stats = db.cooccurrence_get(theater)
        except Exception:
            return {"boost_factor": 1.0, "boosted_pairs": [], "reasoning": ""}

        fired_set = set(fired_sensors)
        boosted_pairs = []

        for stat in cooc_stats:
            sa, sb = stat["sensor_a"], stat["sensor_b"]
            if sa not in fired_set or sb not in fired_set:
                continue
            co = stat.get("co_count", 0)
            total = co + stat.get("solo_a_count", 0) + stat.get("solo_b_count", 0)
            if total < 5:
                continue  # Not enough data
            co_rate = co / total
            # Pairs that fire together >60% of the time indicate correlated
            # threats; boost confidence when they co-fire again
            if co_rate >= 0.6:
                boosted_pairs.append({
                    "sensor_a": sa, "sensor_b": sb,
                    "co_rate": round(co_rate, 3),
                    "co_count": co, "total": total,
                })

        if not boosted_pairs:
            return {"boost_factor": 1.0, "boosted_pairs": [], "reasoning": ""}

        # Boost factor: 1.0 base + 0.1 per confirmed pair, max 1.5
        # This only INCREASES sensitivity (design principle)
        boost = min(1.0 + 0.1 * len(boosted_pairs), 1.5)
        pair_names = [f"{p['sensor_a']}+{p['sensor_b']}" for p in boosted_pairs[:3]]
        reasoning = (f"Co-occurrence boost: {len(boosted_pairs)} correlated pair(s) "
                     f"firing simultaneously ({', '.join(pair_names)})")

        return {
            "boost_factor": round(boost, 2),
            "boosted_pairs": boosted_pairs,
            "reasoning": reasoning,
        }
