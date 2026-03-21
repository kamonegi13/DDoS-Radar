"""radar.engine -- SensorRegistry and WeightedConvergenceEngine."""
from __future__ import annotations
import math
import threading
from typing import Optional
from radar.config import (
    CONVERGENCE_DUAL_BONUS, CONVERGENCE_FULL_BONUS,
    AMBUSH_ZSCORE_THRESHOLD, DERIVATIVE_WINDOW,
    SYNC_DELTA_MS, SYNC_C2_THRESHOLD,
    FEINT_DISTRACTION_MAX_SCORE, FEINT_PRIMARY_MIN_SCORE,
    FEINT_MIN_DISTRACTION_DOMAINS,
    ESCALATION_TL_THRESHOLDS,
)
from radar.models import RationaleEntry
from radar.sensors.base import BaseSensor

class SensorRegistry:
    def __init__(self): self._sensors: dict[str, BaseSensor] = {}; self._lock = threading.Lock()
    def register(self, sensor: BaseSensor):
        with self._lock: self._sensors[sensor.name] = sensor
    def get(self, name: str) -> Optional[BaseSensor]: return self._sensors.get(name)
    def set_enabled(self, name: str, enabled: bool):
        with self._lock:
            if name in self._sensors: self._sensors[name].enabled = enabled
    def health_report(self) -> dict: return {name: s.health for name, s in self._sensors.items()}
    def config_list(self) -> list: return [s.to_config_dict() for s in self._sensors.values()]

class WeightedConvergenceEngine:
    DOMAIN_WEIGHTS = {"cyber": 0.50, "physical": 0.30, "info": 0.20}
    def compute_domain_scores(self, rationale: list) -> dict:
        scores = {"cyber": 0, "physical": 0, "info": 0}
        for entry in rationale:
            if isinstance(entry, RationaleEntry) and not entry.suppressed and entry.status == "FIRED":
                if entry.domain in scores:
                    scores[entry.domain] += entry.score * entry.confidence
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
        raw_bonus = CONVERGENCE_FULL_BONUS if level == "FULL_CONVERGENCE" else CONVERGENCE_DUAL_BONUS if level == "DUAL_DOMAIN" else 0
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
    def compute_threat_level(self, score: int, tl1_hard: bool, active_domains: int = 0) -> int:
        if score >= 9 and tl1_hard: return 1
        # TL2 requires DUAL_DOMAIN convergence (≥2 active domains) to prevent
        # single-domain (Cyber-only) escalation from triggering Heightened status.
        # TL1 is already gated by core_degraded (Physical) via tl1_hard.
        if score >= 6 and active_domains >= 2: return 2
        if score >= 4: return 3
        if score >= 2: return 4
        return 5

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

    def apply_hysteresis(self, new_tl: int, history: list) -> tuple:
        if not history: return new_tl, False
        last_tl = history[-1][1]
        if new_tl > last_tl:
            held = min(new_tl, last_tl + 1)
            return held, (held != new_tl)
        return new_tl, False
    def build_system_note(self, threat_level: int, domain_scores: dict, convergence_level: str, rationale: list, noise_filters: list, tl_held: bool = False) -> str:
        fired = [e for e in rationale if isinstance(e, RationaleEntry) and e.status == "FIRED"]
        suppressed = [e for e in rationale if isinstance(e, RationaleEntry) and e.suppressed]
        held_note = " [HYSTERESIS HOLD]" if tl_held else ""
        parts = [f"Assessed THREAT LEVEL {threat_level}{held_note}."]
        conv_label = {"FULL_CONVERGENCE": f"⚡ FULL CONVERGENCE (+{CONVERGENCE_FULL_BONUS}pt bonus)", "DUAL_DOMAIN": f"⚠ DUAL DOMAIN (+{CONVERGENCE_DUAL_BONUS}pt bonus)", "SINGLE_DOMAIN": "Single Domain Activity", "NONE": ""}.get(convergence_level, "")
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
        is_ambush = (z_score > AMBUSH_ZSCORE_THRESHOLD) and (current_acc > 0) and (velocity > 0)
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
                if dt <= SYNC_DELTA_MS:
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
                for tl in sorted(ESCALATION_TL_THRESHOLDS.keys(), reverse=True):
                    threshold = ESCALATION_TL_THRESHOLDS[tl]
                    if threshold <= current_score and tl >= current_tl:
                        continue
                    if threshold < current_score:
                        pts_drop = current_score - threshold
                        hours = pts_drop / abs(score_trend)
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
