"""Unit tests for WeightedConvergenceEngine and scoring helpers.

Run: python -m pytest test_engine.py -v
"""
import math
import time
import pytest

# ── Import targets (avoid full module init by importing selectively) ──
# We need to set minimal env before importing radar_api
import os
os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")

from radar_api import (
    WeightedConvergenceEngine,
    RationaleEntry,
    compute_sequence_bonus,
    register_sequence_event,
    sequence_event_log,
    compute_hod_zscore,
    hod_baseline_db,
    record_hod_sample,
    calculate_overlap,
    compute_confidence,
    SEQUENCE_WINDOW,
)


@pytest.fixture(autouse=True)
def clean_global_state():
    """Reset mutable global state between tests."""
    sequence_event_log.clear()
    hod_baseline_db.clear()
    yield
    sequence_event_log.clear()
    hod_baseline_db.clear()


# ─────────────────────────────────────────────────────────────────────────────
# WeightedConvergenceEngine
# ─────────────────────────────────────────────────────────────────────────────
class TestWeightedConvergenceEngine:
    def setup_method(self):
        self.engine = WeightedConvergenceEngine()

    # ── compute_domain_scores ──
    def test_domain_scores_basic(self):
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "2x", 3),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "OUTAGE", 1),
            RationaleEntry("gdelt", "info", "OK", "NORMAL", 0),
        ]
        scores = self.engine.compute_domain_scores(rationale)
        assert scores["cyber"] == 3
        assert scores["physical"] == 1
        assert scores["info"] == 0

    def test_domain_scores_suppressed_excluded(self):
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "2x", 3, suppressed=True),
            RationaleEntry("gdelt", "info", "FIRED", "ALERT", 1),
        ]
        scores = self.engine.compute_domain_scores(rationale)
        assert scores["cyber"] == 0  # suppressed → excluded
        assert scores["info"] == 1

    def test_domain_scores_non_fired_excluded(self):
        rationale = [
            RationaleEntry("opensky", "physical", "OK", "normal", 2),
        ]
        scores = self.engine.compute_domain_scores(rationale)
        assert scores["physical"] == 0  # status != FIRED

    # ── compute_convergence_level ──
    def test_convergence_none(self):
        assert self.engine.compute_convergence_level({"cyber": 0, "physical": 0, "info": 0}) == "NONE"

    def test_convergence_single(self):
        assert self.engine.compute_convergence_level({"cyber": 3, "physical": 0, "info": 0}) == "SINGLE_DOMAIN"

    def test_convergence_dual(self):
        assert self.engine.compute_convergence_level({"cyber": 3, "physical": 1, "info": 0}) == "DUAL_DOMAIN"

    def test_convergence_full(self):
        assert self.engine.compute_convergence_level({"cyber": 3, "physical": 1, "info": 2}) == "FULL_CONVERGENCE"

    # ── compute_convergence_score ──
    def test_convergence_score_capped(self):
        """Domain scores should be capped at 10 before weighting."""
        scores = {"cyber": 20, "physical": 0, "info": 0}
        result = self.engine.compute_convergence_score(scores)
        # cyber: min(20,10) * 0.50 = 5.0
        assert result == 5.0

    # ── compute_threat_level ──
    def test_tl5_low_score(self):
        assert self.engine.compute_threat_level(0, False) == 5
        assert self.engine.compute_threat_level(1, False) == 5

    def test_tl4_moderate(self):
        assert self.engine.compute_threat_level(2, False) == 4
        assert self.engine.compute_threat_level(3, False) == 4

    def test_tl3_elevated(self):
        assert self.engine.compute_threat_level(4, False) == 3
        assert self.engine.compute_threat_level(5, False) == 3

    def test_tl2_requires_dual_domain(self):
        # score=6 but only 1 active domain → stays at TL3
        assert self.engine.compute_threat_level(6, False, active_domains=1) == 3
        # score=6 with 2 active domains → TL2
        assert self.engine.compute_threat_level(6, False, active_domains=2) == 2

    def test_tl1_requires_hard_condition(self):
        assert self.engine.compute_threat_level(9, True) == 1
        assert self.engine.compute_threat_level(9, False, active_domains=2) == 2  # no tl1_hard → TL2

    # ── apply_hysteresis ──
    def test_hysteresis_first_entry(self):
        tl, held = self.engine.apply_hysteresis(3, [])
        assert tl == 3
        assert held is False

    def test_hysteresis_escalation_instant(self):
        """Escalation (lower TL = higher threat) applies immediately."""
        history = [(time.time(), 5)]
        tl, held = self.engine.apply_hysteresis(2, history)
        assert tl == 2  # escalation is instant
        assert held is False

    def test_hysteresis_de_escalation_capped(self):
        """De-escalation (higher TL = lower threat) limited to one step."""
        history = [(time.time(), 2)]
        tl, held = self.engine.apply_hysteresis(5, history)
        assert tl == 3  # held at 2→3 (one step)
        assert held is True

    # ── compute_velocity / acceleration ──
    def test_velocity_static(self):
        """Constant time series → velocity ≈ 0."""
        ts = [(1000 + i * 60, 5.0) for i in range(10)]
        v = self.engine.compute_velocity(ts)
        assert abs(v) < 1e-6

    def test_velocity_linear_increase(self):
        """Linearly increasing → positive velocity."""
        ts = [(1000 + i * 60, float(i)) for i in range(10)]
        v = self.engine.compute_velocity(ts)
        assert v > 0

    def test_acceleration_constant_velocity(self):
        """Constant velocity → acceleration ≈ 0."""
        ts = [(1000 + i * 60, float(i) * 0.5) for i in range(10)]
        acc = self.engine.compute_acceleration(ts)
        assert abs(acc) < 1e-4

    # ── detect_ambush_pattern ──
    def test_ambush_not_triggered_on_flat(self):
        ts = [(1000 + i * 60, 1.0) for i in range(20)]
        is_ambush, z, v, a = self.engine.detect_ambush_pattern(ts)
        assert is_ambush is False

    def test_ambush_triggered_on_exponential(self):
        """Exponential spike should trigger ambush if Z > threshold."""
        ts = [(1000 + i * 60, 1.0) for i in range(15)]
        # Append an exponential spike
        for i in range(5):
            ts.append((ts[-1][0] + 60, ts[-1][1] * 3.0))
        is_ambush, z, v, a = self.engine.detect_ambush_pattern(ts)
        # Should detect the sudden acceleration
        assert v > 0
        assert z > 0  # Z-score should be positive

    # ── compute_sync_score ──
    def test_sync_score_identical_timestamps(self):
        ts = {"CN": 1000, "RU": 1000, "KP": 1000}
        score = self.engine.compute_sync_score(ts)
        assert score == 1.0

    def test_sync_score_single_source(self):
        assert self.engine.compute_sync_score({"CN": 1000}) == 0.0

    def test_sync_score_no_sync(self):
        """Timestamps far apart → 0.0."""
        ts = {"CN": 1000, "RU": 5000}
        score = self.engine.compute_sync_score(ts)
        assert score == 0.0

    # ── compute_blockade_index ──
    def test_blockade_index_normal(self):
        idx = self.engine.compute_blockade_index(1.0, 0.0, 1.0)
        assert idx < 1.0  # low DDoS + no RIPE drop + full CH → low index

    def test_blockade_index_blackout(self):
        idx = self.engine.compute_blockade_index(10.0, 0.0, 0.0)
        assert idx >= 9.0  # max DDoS + CH blackout → near max

    def test_blockade_index_asphyxiation(self):
        normal = self.engine.compute_blockade_index(5.0, 0.0, 0.5)
        asphyx = self.engine.compute_blockade_index(5.0, 0.0, 0.5, asphyxiation=True)
        assert asphyx > normal  # asphyxiation multiplier

    def test_blockade_index_ch_none_conservative(self):
        """When CH is None (API unreachable), treat as OK (conservative)."""
        idx = self.engine.compute_blockade_index(5.0, 0.0, None)
        ok_idx = self.engine.compute_blockade_index(5.0, 0.0, 1.0)
        assert idx == ok_idx

    # ── detect_maskirovka ──
    def test_maskirovka_outage_and_silence(self):
        detected, conf, reason = self.engine.detect_maskirovka(
            core_degraded=True, narrative_burst=False,
            check_host_status="BLACKOUT", telegram_intent=False,
            other_sensors_alive=True,
        )
        assert detected is True
        assert conf == "HIGH"

    def test_maskirovka_not_triggered_when_narrative_active(self):
        detected, _, _ = self.engine.detect_maskirovka(
            core_degraded=True, narrative_burst=True,
            check_host_status="BLACKOUT", telegram_intent=False,
        )
        assert detected is False

    def test_maskirovka_medium_without_cross_theater(self):
        detected, conf, _ = self.engine.detect_maskirovka(
            core_degraded=True, narrative_burst=False,
            check_host_status="OK", telegram_intent=False,
            other_sensors_alive=False,
        )
        assert detected is True
        assert conf == "MEDIUM"

    # ── temporal coherence ──
    def test_temporal_coherence_no_events(self):
        is_sync, _, bonus, _ = self.engine.compute_temporal_coherence({}, ["TW", "JP"])
        assert is_sync is False
        assert bonus == 0

    def test_temporal_coherence_synchronized(self):
        now = time.time()
        events = {
            "TW": [{"ts": now, "type": "SYNC_DDOS"}],
            "JP": [{"ts": now + 10, "type": "NARRATIVE_BURST"}],
        }
        is_sync, score, bonus, detail = self.engine.compute_temporal_coherence(events, ["TW", "JP"])
        assert is_sync is True
        assert bonus == 2


# ─────────────────────────────────────────────────────────────────────────────
# Sequence Scorer
# ─────────────────────────────────────────────────────────────────────────────
class TestSequenceScorer:
    def test_no_events(self):
        bonus, status, chain = compute_sequence_bonus("TW")
        assert bonus == 0
        assert "NO_EVENTS" in status

    def test_partial_chain(self):
        register_sequence_event("TW", "NARRATIVE_BURST")
        register_sequence_event("TW", "ISR_SURGE")
        register_sequence_event("TW", "SYNC_DDOS")
        bonus, status, chain = compute_sequence_bonus("TW")
        assert bonus >= 1
        assert "PARTIAL" in status or "FULL" in status
        assert len(chain) == 3

    def test_full_chain(self):
        register_sequence_event("TW", "NARRATIVE_BURST")
        register_sequence_event("TW", "ISR_SURGE")
        register_sequence_event("TW", "SYNC_DDOS")
        register_sequence_event("TW", "FIRMS_ANOMALY")
        bonus, status, chain = compute_sequence_bonus("TW")
        assert bonus >= 3
        assert "FULL" in status
        assert len(chain) == 4

    def test_dedup_within_window(self):
        register_sequence_event("TW", "NARRATIVE_BURST")
        register_sequence_event("TW", "NARRATIVE_BURST")  # duplicate within 300s
        events = sequence_event_log.get("TW", [])
        assert len(events) == 1  # deduped

    def test_events_expire_after_window(self):
        """Events older than SEQUENCE_WINDOW should not count."""
        now = time.time()
        sequence_event_log["TW"] = [
            {"ts": now - SEQUENCE_WINDOW - 100, "type": "NARRATIVE_BURST", "meta": {}},
            {"ts": now - SEQUENCE_WINDOW - 50, "type": "ISR_SURGE", "meta": {}},
        ]
        bonus, status, chain = compute_sequence_bonus("TW")
        assert bonus == 0


# ─────────────────────────────────────────────────────────────────────────────
# HOD Z-Score
# ─────────────────────────────────────────────────────────────────────────────
class TestHodZscore:
    def test_insufficient_samples(self):
        z, valid, n = compute_hod_zscore("TW", 5.0, time.time())
        assert valid is False
        assert n == 0

    def test_normal_spike(self):
        """Spike within normal range should have small Z."""
        now = time.time()
        hour_bucket = int(now // 3600) * 3600
        hod = (hour_bucket // 3600) % 24
        # Seed 10 same-hour samples across previous days
        for day in range(1, 11):
            ts = hour_bucket - day * 86400 + 1800  # same hour, different day
            record_hod_sample("TW", ts, 2.0)
        z, valid, n = compute_hod_zscore("TW", 2.1, now)
        assert valid is True
        assert n >= 7
        assert abs(z) < 3.0  # within normal range

    def test_anomalous_spike(self):
        """Very high spike vs low baseline should have large Z."""
        now = time.time()
        hour_bucket = int(now // 3600) * 3600
        for day in range(1, 11):
            ts = hour_bucket - day * 86400 + 1800
            record_hod_sample("TW", ts, 1.0)
        z, valid, n = compute_hod_zscore("TW", 20.0, now)
        assert valid is True
        assert z > 3.0  # very anomalous


# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────
class TestHelpers:
    def test_calculate_overlap_empty(self):
        assert calculate_overlap({}, {"A": 1}) == 0.0

    def test_calculate_overlap_identical(self):
        d = {"A": 5.0, "B": 3.0}
        assert calculate_overlap(d, d) == 8.0

    def test_calculate_overlap_partial(self):
        d1 = {"A": 5.0, "B": 3.0}
        d2 = {"A": 2.0, "C": 10.0}
        assert calculate_overlap(d1, d2) == 2.0  # min(5,2) + min(3,0) + min(0,10)

    def test_compute_confidence_state_asn(self):
        assert compute_confidence(3.0, "CN", False, True) == "HIGH"

    def test_compute_confidence_new_actor(self):
        assert compute_confidence(5.0, "XX", True, False) == "LOW"

    def test_compute_confidence_medium(self):
        assert compute_confidence(4.0, "RU", False, False) == "MEDIUM"

    def test_compute_confidence_low(self):
        assert compute_confidence(1.5, "BR", False, False) == "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Feint Detection
# ─────────────────────────────────────────────────────────────────────────────
class TestFeintDetection:
    def setup_method(self):
        self.engine = WeightedConvergenceEngine()

    def test_feint_detected(self):
        """Cyber high + physical low + info low → feint detected."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "6x", 3),
            RationaleEntry("cf_adversary_strike", "cyber", "FIRED", "1 strike", 2),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "OUTAGE", 1),
            RationaleEntry("gdelt", "info", "FIRED", "ALERT", 1),
        ]
        domain_scores = {"cyber": 5, "physical": 1, "info": 1}
        is_feint, primary, distractions, conf, detail = self.engine.detect_feint_pattern(
            domain_scores, rationale)
        assert is_feint is True
        assert primary == "cyber"
        assert set(distractions) == {"physical", "info"}
        assert conf in ("HIGH", "MEDIUM")

    def test_feint_not_detected_balanced(self):
        """All domains similar score → no feint."""
        domain_scores = {"cyber": 3, "physical": 3, "info": 3}
        is_feint, _, _, _, _ = self.engine.detect_feint_pattern(domain_scores, [])
        assert is_feint is False

    def test_feint_not_detected_single_domain(self):
        """Only one domain active → no feint (need distraction domains)."""
        domain_scores = {"cyber": 7, "physical": 0, "info": 0}
        is_feint, _, _, _, _ = self.engine.detect_feint_pattern(domain_scores, [])
        assert is_feint is False

    def test_feint_not_detected_all_high(self):
        """All domains high → genuine full convergence, not feint."""
        domain_scores = {"cyber": 6, "physical": 5, "info": 5}
        is_feint, _, _, _, _ = self.engine.detect_feint_pattern(domain_scores, [])
        assert is_feint is False

    def test_feint_high_confidence_at_7plus(self):
        """Primary domain score ≥ 7 → HIGH confidence."""
        domain_scores = {"cyber": 7, "physical": 2, "info": 1}
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "10x", 3),
            RationaleEntry("cf_adversary_strike", "cyber", "FIRED", "2 strikes", 2),
            RationaleEntry("cf_coordinated", "cyber", "FIRED", "multi", 2),
        ]
        is_feint, _, _, conf, _ = self.engine.detect_feint_pattern(domain_scores, rationale)
        assert is_feint is True
        assert conf == "HIGH"


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Escalation Progress Tracking
# ─────────────────────────────────────────────────────────────────────────────
class TestEscalationProgress:
    def setup_method(self):
        self.engine = WeightedConvergenceEngine()

    def test_no_data(self):
        result = self.engine.compute_escalation_progress([], [])
        assert result["pattern"] == "NO_DATA"
        assert result["current_tl"] == 5

    def test_stable(self):
        """Constant TL5 history → STABLE pattern."""
        now = time.time()
        history = [(now - i * 60, 5) for i in range(10, 0, -1)]
        result = self.engine.compute_escalation_progress(history, [])
        assert result["current_tl"] == 5
        assert result["pattern"] == "STABLE"
        assert len(result["tl_transitions"]) == 0

    def test_escalating(self):
        """TL5→4→3 history → ESCALATING pattern."""
        now = time.time()
        history = [
            (now - 600, 5), (now - 540, 5), (now - 480, 5),
            (now - 420, 4), (now - 360, 4), (now - 300, 4),
            (now - 240, 3), (now - 180, 3), (now - 120, 3),
        ]
        result = self.engine.compute_escalation_progress(history, [])
        assert result["current_tl"] == 3
        assert result["pattern"] == "ESCALATING"
        assert len(result["tl_transitions"]) == 2
        assert result["tl_transitions"][0]["direction"] == "ESCALATE"

    def test_deescalating(self):
        """TL2→3→4 history → DE-ESCALATING pattern."""
        now = time.time()
        history = [
            (now - 600, 2), (now - 540, 2),
            (now - 420, 3), (now - 360, 3),
            (now - 240, 4), (now - 180, 4),
        ]
        result = self.engine.compute_escalation_progress(history, [])
        assert result["current_tl"] == 4
        assert result["pattern"] == "DE-ESCALATING"

    def test_oscillating(self):
        """TL3→4→3→4→3 → OSCILLATING pattern."""
        now = time.time()
        history = [
            (now - 600, 3), (now - 480, 4), (now - 360, 3),
            (now - 240, 4), (now - 120, 3),
        ]
        result = self.engine.compute_escalation_progress(history, [])
        assert result["pattern"] == "OSCILLATING"

    def test_score_trend_prediction(self):
        """Verify score trend calculation with linearly increasing scores."""
        now = time.time()
        history = [(now - 300, 4), (now - 240, 4), (now - 120, 3), (now, 3)]
        timeline = [
            {"ts": now - 300, "score_with_bonus": 2, "threat_level": 4},
            {"ts": now - 200, "score_with_bonus": 3, "threat_level": 4},
            {"ts": now - 100, "score_with_bonus": 4, "threat_level": 3},
        ]
        result = self.engine.compute_escalation_progress(history, timeline)
        # Score is increasing → positive trend
        assert result["score_trend"] > 0
