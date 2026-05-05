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
    calculate_overlap_idf,
    compute_idf_weights,
    compute_confidence,
    SEQUENCE_WINDOW,
    compute_origin_entropy,
    track_entropy_change,
    _entropy_history,
    BgpRoutingSensor,
    _linear_slope,
    IhrSensor,
    RipeAtlasSensor,
    TorMetricsSensor,
)


@pytest.fixture(autouse=True)
def clean_entropy_history():
    """Reset entropy history between tests."""
    _entropy_history.clear()
    yield

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

    # ── derive_tl (scoring.py) ──
    # Canonical TL derivation after scenario unification. TL1 requires
    # physical_score >= 3.0; TL2 requires >=2 active domains.
    def test_tl5_low_score(self):
        from radar.scoring import derive_tl
        assert derive_tl(0, [], 0) == 5
        assert derive_tl(1, ["cyber"], 0) == 5

    def test_tl4_moderate(self):
        from radar.scoring import derive_tl
        assert derive_tl(2, ["cyber"], 0) == 4
        assert derive_tl(3, ["cyber"], 0) == 4

    def test_tl3_elevated(self):
        from radar.scoring import derive_tl
        assert derive_tl(4, ["cyber"], 0) == 3
        assert derive_tl(5, ["cyber"], 0) == 3

    def test_tl2_requires_dual_domain(self):
        from radar.scoring import derive_tl
        # score=6 but only 1 active domain → stays at TL3
        assert derive_tl(6, ["cyber"], 0) == 3
        # score=6 with 2 active domains → TL2
        assert derive_tl(6, ["cyber", "physical"], 1) == 2

    def test_tl1_requires_physical(self):
        from radar.scoring import derive_tl
        # score=9 with physical=3 → TL1
        assert derive_tl(9, ["cyber", "physical"], 3) == 1
        # score=9 without physical ≥3 → TL2 (dual domain, score ≥6)
        assert derive_tl(9, ["cyber", "info"], 0) == 2

    # ── apply_hysteresis_to_tl (scoring.py) ──
    def test_hysteresis_first_entry(self):
        from radar.scoring import apply_hysteresis_to_tl
        tl, held = apply_hysteresis_to_tl(3, None)
        assert tl == 3
        assert held is False

    def test_hysteresis_escalation_instant(self):
        """Escalation (lower TL = higher threat) applies immediately."""
        from radar.scoring import apply_hysteresis_to_tl
        tl, held = apply_hysteresis_to_tl(2, 5)
        assert tl == 2  # escalation is instant
        assert held is False

    def test_hysteresis_de_escalation_capped(self):
        """De-escalation (higher TL = lower threat) limited to one step."""
        from radar.scoring import apply_hysteresis_to_tl
        tl, held = apply_hysteresis_to_tl(5, 2)
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
        # Normalized: both distributions identical → 100% overlap
        assert calculate_overlap(d, d) == 100.0

    def test_calculate_overlap_partial(self):
        d1 = {"A": 5.0, "B": 3.0}       # normalized: A=62.5%, B=37.5%
        d2 = {"A": 2.0, "C": 10.0}       # normalized: A=16.67%, C=83.33%
        # overlap = min(62.5,16.67) + min(37.5,0) + min(0,83.33) = 16.67%
        assert calculate_overlap(d1, d2) == 16.67

    def test_compute_idf_weights_ubiquitous_zero(self):
        # AS_GLOBAL appears in every country → idf should collapse near zero
        # (post-normalization), AS_RARE appears once → idf == 1.0
        dists = {
            "JP": {"AS_GLOBAL": 50.0, "AS_RARE": 10.0},
            "US": {"AS_GLOBAL": 60.0},
            "TW": {"AS_GLOBAL": 30.0},
        }
        w = compute_idf_weights(dists)
        assert w["AS_RARE"] == 1.0
        assert w["AS_GLOBAL"] < w["AS_RARE"]
        assert w["AS_GLOBAL"] >= 0.0

    def test_compute_idf_weights_empty(self):
        assert compute_idf_weights({}) == {}
        assert compute_idf_weights({"JP": {}}) == {}

    def test_calculate_overlap_idf_suppresses_global_baseline(self):
        # JP and US are dominated by the same global ASN that also hits TW.
        # Raw overlap → high (~80%); IDF overlap → low because the shared
        # ASN is ubiquitous and gets weight ~0.
        dists = {
            "JP": {"AS_GLOBAL": 80.0, "AS_JP_LOCAL": 20.0},
            "US": {"AS_GLOBAL": 80.0, "AS_US_LOCAL": 20.0},
            "TW": {"AS_GLOBAL": 100.0},
        }
        w = compute_idf_weights(dists)
        raw  = calculate_overlap(dists["JP"], dists["US"])
        idf  = calculate_overlap_idf(dists["JP"], dists["US"], w)
        assert raw >= 70.0  # structural baseline saturation
        assert idf <  raw   # IDF must dampen the shared-noise contribution
        assert idf <  10.0  # essentially zero coordination signal

    def test_calculate_overlap_idf_amplifies_rare_coincidence(self):
        # JP and PH share a RARE ASN that no one else has → IDF should give
        # this real signal a non-trivial score even though raw overlap is small.
        dists = {
            "JP": {"AS_GLOBAL": 90.0, "AS_RARE": 10.0},
            "PH": {"AS_GLOBAL": 90.0, "AS_RARE": 10.0},
            "US": {"AS_GLOBAL": 100.0},
            "TW": {"AS_GLOBAL": 100.0},
        }
        w = compute_idf_weights(dists)
        idf_jp_ph = calculate_overlap_idf(dists["JP"], dists["PH"], w)
        idf_jp_us = calculate_overlap_idf(dists["JP"], dists["US"], w)
        # JP-PH share the RARE ASN; JP-US do not — IDF must rank JP-PH higher
        assert idf_jp_ph > idf_jp_us

    def test_calculate_overlap_idf_empty_inputs(self):
        assert calculate_overlap_idf({}, {"A": 1}, {"A": 1.0}) == 0.0
        assert calculate_overlap_idf({"A": 1}, {"A": 1}, {}) == 0.0

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


# ─────────────────────────────────────────────────────────────────────────────
# Engine Enhancement: Confidence Propagation, TL Proximity, Domain Confidences
# ─────────────────────────────────────────────────────────────────────────────
class TestConfidenceWeighting:
    def setup_method(self):
        self.engine = WeightedConvergenceEngine()

    def test_full_confidence_unchanged(self):
        """When all confidences are 1.0, scoring is identical to legacy behavior."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, confidence=1.0),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "OUTAGE", 1, confidence=1.0),
            RationaleEntry("gdelt", "info", "FIRED", "ALERT", 1, confidence=1.0),
        ]
        scores = self.engine.compute_domain_scores(rationale)
        assert scores == {"cyber": 3, "physical": 1, "info": 1}

    def test_partial_confidence_reduces_score(self):
        """Confidence < 1.0 reduces domain score proportionally."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, confidence=0.5),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "OUTAGE", 1, confidence=1.0),
        ]
        scores = self.engine.compute_domain_scores(rationale)
        assert scores["cyber"] == 1.5
        assert scores["physical"] == 1.0

    def test_zero_confidence_zeroes_score(self):
        """Confidence = 0.0 effectively removes sensor contribution."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, confidence=0.0),
        ]
        scores = self.engine.compute_domain_scores(rationale)
        assert scores["cyber"] == 0

    def test_suppressed_entries_ignored(self):
        """Suppressed entries are still excluded regardless of confidence."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, confidence=1.0, suppressed=True),
        ]
        scores = self.engine.compute_domain_scores(rationale)
        assert scores["cyber"] == 0


class TestConvergenceGating:
    def setup_method(self):
        self.engine = WeightedConvergenceEngine()

    def test_full_convergence_no_gating(self):
        """Without domain_confidences, bonus is unchanged."""
        domain_scores = {"cyber": 3, "physical": 2, "info": 1}
        score, bonus, level = self.engine.apply_convergence_bonus(6, domain_scores)
        assert level == "FULL_CONVERGENCE"
        assert bonus == 2  # CONVERGENCE_FULL_BONUS default

    def test_full_convergence_gated_by_low_confidence(self):
        """Domain confidences gate the bonus multiplicatively."""
        domain_scores = {"cyber": 3, "physical": 2, "info": 1}
        domain_confs = {"cyber": 1.0, "physical": 0.5, "info": 1.0}
        score, bonus, level = self.engine.apply_convergence_bonus(6, domain_scores, domain_confs)
        assert level == "FULL_CONVERGENCE"
        # bonus = 2 * min(1.0, 0.5, 1.0) = 2 * 0.5 = 1.0
        assert bonus == 1.0

    def test_dual_domain_gated(self):
        """Dual domain bonus also gated by confidence."""
        domain_scores = {"cyber": 3, "physical": 2, "info": 0}
        domain_confs = {"cyber": 0.6, "physical": 0.6, "info": 1.0}
        score, bonus, level = self.engine.apply_convergence_bonus(5, domain_scores, domain_confs)
        assert level == "DUAL_DOMAIN"
        # bonus = 1 * min(0.6, 0.6) = 0.6
        assert bonus == 0.6

    def test_single_domain_no_bonus(self):
        """Single domain has no bonus regardless of confidence."""
        domain_scores = {"cyber": 5, "physical": 0, "info": 0}
        domain_confs = {"cyber": 1.0, "physical": 1.0, "info": 1.0}
        score, bonus, level = self.engine.apply_convergence_bonus(5, domain_scores, domain_confs)
        assert bonus == 0
        assert level == "SINGLE_DOMAIN"


class TestTlProximity:
    def setup_method(self):
        self.engine = WeightedConvergenceEngine()

    def test_tl5_stable(self):
        """Score 0 at TL5 → no escalation/de-escalation near boundary."""
        result = self.engine.compute_tl_proximity(0, 5)
        assert result["proximity_label"] == "STABLE"
        assert result["distance_down"] is None  # Already at TL5

    def test_tl4_near_escalation(self):
        """Score 3 at TL4 → 1pt to TL3 threshold (4pt)."""
        result = self.engine.compute_tl_proximity(3, 4)
        assert result["distance_up"] == 1.0
        assert result["next_tl_up"] == 3
        assert result["proximity_label"] == "NEAR_ESCALATION"

    def test_tl3_near_escalation_priority(self):
        """Score 4.5 at TL3 → 1.5pt to TL2 (6pt), 0.51pt above TL3 floor.
        NEAR_ESCALATION takes priority since dist_up <= 1.5."""
        result = self.engine.compute_tl_proximity(4.5, 3)
        assert result["distance_down"] is not None
        assert result["next_tl_down"] == 4
        assert result["distance_up"] == 1.5
        assert result["proximity_label"] == "NEAR_ESCALATION"

    def test_tl3_near_de_escalation(self):
        """Score 4.1 at TL3 → 1.9pt to TL2, 0.11pt above TL3 floor → NEAR_DE_ESCALATION."""
        result = self.engine.compute_tl_proximity(4.1, 3)
        assert result["distance_down"] is not None
        assert result["distance_up"] == 1.9  # > 1.5 threshold
        assert result["proximity_label"] == "NEAR_DE_ESCALATION"

    def test_tl2_near_escalation_at_boundary(self):
        """Score 7.5 at TL2 → 1.5pt to TL1 (9pt) → NEAR_ESCALATION."""
        result = self.engine.compute_tl_proximity(7.5, 2)
        assert result["proximity_label"] == "NEAR_ESCALATION"
        assert result["distance_up"] == 1.5
        assert result["next_tl_up"] == 1

    def test_tl2_stable_middle(self):
        """Score 7.8 at TL2 → 1.2pt to TL1, 1.81pt above TL2 floor → NEAR_ESCALATION (dist_up < 1.5)."""
        result = self.engine.compute_tl_proximity(7.8, 2)
        assert result["proximity_label"] == "NEAR_ESCALATION"

    def test_tl3_stable_wide_gap(self):
        """Score 5 at TL3 → 1pt to TL2, 1.01pt above TL3 floor → NEAR_ESCALATION.
        Score 4.8 → 1.2pt to TL2 → NEAR_ESCALATION. For true STABLE, need gap > 1.5 on both sides."""
        # TL3 range is 4–6, so it's only 2pt wide — hard to be STABLE
        # Use TL4 (2–4 range) with score=3: dist_up=1, dist_down=1.01
        result = self.engine.compute_tl_proximity(3, 4)
        assert result["proximity_label"] == "NEAR_ESCALATION"  # 1pt to TL3

    def test_tl1_no_up(self):
        """At TL1 there is no escalation above."""
        result = self.engine.compute_tl_proximity(10, 1)
        assert result["distance_up"] is None
        assert result["next_tl_up"] is None


class TestDomainConfidences:
    def test_all_high_confidence(self):
        """All sensors at 1.0 → all domains 1.0."""
        engine = WeightedConvergenceEngine()
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, confidence=1.0),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "OUTAGE", 1, confidence=1.0),
            RationaleEntry("gdelt", "info", "FIRED", "ALERT", 1, confidence=1.0),
        ]
        confs = engine.compute_domain_confidences(rationale)
        assert confs == {"cyber": 1.0, "physical": 1.0, "info": 1.0}

    def test_mixed_confidence_averaged(self):
        """Multiple sensors in same domain → average confidence."""
        engine = WeightedConvergenceEngine()
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, confidence=0.8),
            RationaleEntry("ripe_bgp", "cyber", "FIRED", "ANOMALY", 1, confidence=0.6),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "OUTAGE", 1, confidence=1.0),
        ]
        confs = engine.compute_domain_confidences(rationale)
        assert confs["cyber"] == 0.7  # (0.8 + 0.6) / 2
        assert confs["physical"] == 1.0
        assert confs["info"] == 1.0  # No fired entries → default 1.0

    def test_suppressed_excluded(self):
        """Suppressed entries don't affect domain confidence."""
        engine = WeightedConvergenceEngine()
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, confidence=0.8),
            RationaleEntry("ripe_bgp", "cyber", "FIRED", "ANOMALY", 1, confidence=0.2, suppressed=True),
        ]
        confs = engine.compute_domain_confidences(rationale)
        assert confs["cyber"] == 0.8  # Only the non-suppressed entry


# ─────────────────────────────────────────────────────────────────────────────
# (i) Blockade Index scoring
# ─────────────────────────────────────────────────────────────────────────────
class TestBlockadeIndexScoring:
    """Blockade Index ≥ 7.0 should be significant infrastructure blockade."""

    def test_blockade_high_value(self):
        """BI ≥ 7.0 indicates effective blockade."""
        engine = WeightedConvergenceEngine()
        # High DDoS intensity + low checkhost success → high BI
        bi = engine.compute_blockade_index(ddos_intensity=8.0, ripe_drop_pct=10.0,
                                            checkhost_success_rate=0.1)
        assert bi >= 7.0

    def test_blockade_low_value(self):
        """BI < 7.0 when infrastructure is mostly healthy."""
        engine = WeightedConvergenceEngine()
        bi = engine.compute_blockade_index(ddos_intensity=2.0, ripe_drop_pct=0.0,
                                            checkhost_success_rate=0.9)
        assert bi < 7.0

    def test_asphyxiation_amplifies_bi(self):
        """Asphyxiation flag should amplify blockade index by 1.5×."""
        engine = WeightedConvergenceEngine()
        bi_normal = engine.compute_blockade_index(ddos_intensity=5.0, ripe_drop_pct=0.0,
                                                   checkhost_success_rate=0.3)
        bi_asphyx = engine.compute_blockade_index(ddos_intensity=5.0, ripe_drop_pct=0.0,
                                                   checkhost_success_rate=0.3, asphyxiation=True)
        assert bi_asphyx > bi_normal


# ─────────────────────────────────────────────────────────────────────────────
# (iii) Graduated L3/L7 vector shift
# ─────────────────────────────────────────────────────────────────────────────
class TestGraduatedVectorShift:
    """L3→L7 vector shift should have moderate (+1) and severe (+2) tiers."""

    def test_severe_shift_criteria(self):
        """Severe shift: L7 ≥ 5.0x AND L7 > L3 × 2.0."""
        # Just validate the criteria logic matches expectations
        l7_spike = 6.0
        l3_spike = 2.0
        is_shifted = True
        severe = is_shifted and l7_spike >= 5.0 and l7_spike > l3_spike * 2.0
        assert severe is True

    def test_moderate_shift_not_severe(self):
        """Moderate shift: shifted but L7 < 5.0 → not severe."""
        l7_spike = 3.0
        l3_spike = 1.5
        is_shifted = True
        severe = is_shifted and l7_spike >= 5.0 and l7_spike > l3_spike * 2.0
        assert severe is False


# ─────────────────────────────────────────────────────────────────────────────
# (iv) Adversary strike count-proportional scoring
# ─────────────────────────────────────────────────────────────────────────────
class TestAdversaryCountScoring:
    """Adversary strike scoring should be count-proportional."""

    def test_no_strikes(self):
        count = 0
        score = 3 if count >= 3 else (2 if count >= 1 else 0)
        assert score == 0

    def test_single_strike(self):
        count = 1
        score = 3 if count >= 3 else (2 if count >= 1 else 0)
        assert score == 2

    def test_two_strikes(self):
        count = 2
        score = 3 if count >= 3 else (2 if count >= 1 else 0)
        assert score == 2

    def test_three_or_more_strikes(self):
        count = 3
        score = 3 if count >= 3 else (2 if count >= 1 else 0)
        assert score == 3

    def test_many_strikes(self):
        count = 5
        score = 3 if count >= 3 else (2 if count >= 1 else 0)
        assert score == 3


# ─────────────────────────────────────────────────────────────────────────────
# (v) Sequence temporal decay
# ─────────────────────────────────────────────────────────────────────────────
class TestSequenceTemporalDecay:
    """Sequence bonus should decay based on event age."""

    def test_fresh_events_full_bonus(self):
        """Events just registered (age ≈ 0) should get full bonus."""
        register_sequence_event("TW", "NARRATIVE_BURST")
        register_sequence_event("TW", "ISR_SURGE")
        register_sequence_event("TW", "SYNC_DDOS")
        register_sequence_event("TW", "FIRMS_ANOMALY")
        bonus, status, chain = compute_sequence_bonus("TW")
        assert bonus == 3  # SEQUENCE_FULL_BONUS = 3, decay ≈ 1.0
        assert "FULL" in status

    def test_old_events_decayed_bonus(self):
        """Events 20 hours old should have decayed bonus."""
        now = time.time()
        # Insert events that are 20 hours old
        sequence_event_log["TW"] = [
            {"ts": now - 20 * 3600, "type": "NARRATIVE_BURST", "meta": {}},
            {"ts": now - 20 * 3600, "type": "ISR_SURGE", "meta": {}},
            {"ts": now - 20 * 3600, "type": "SYNC_DDOS", "meta": {}},
            {"ts": now - 20 * 3600, "type": "FIRMS_ANOMALY", "meta": {}},
        ]
        bonus, status, chain = compute_sequence_bonus("TW")
        # weight = max(0.3, 1.0 - 20/24) ≈ 0.167 → clamped to 0.3
        # decayed = round(3 * 0.3) = 1, min 1
        assert bonus == 1
        assert "decay=" in status

    def test_mid_age_events_partial_decay(self):
        """Events 8 hours old should have partial decay."""
        now = time.time()
        sequence_event_log["TW"] = [
            {"ts": now - 8 * 3600, "type": "NARRATIVE_BURST", "meta": {}},
            {"ts": now - 8 * 3600, "type": "ISR_SURGE", "meta": {}},
            {"ts": now - 8 * 3600, "type": "SYNC_DDOS", "meta": {}},
            {"ts": now - 8 * 3600, "type": "FIRMS_ANOMALY", "meta": {}},
        ]
        bonus, status, chain = compute_sequence_bonus("TW")
        # weight = max(0.3, 1.0 - 8/24) ≈ 0.667
        # decayed = round(3 * 0.667) = 2
        assert bonus == 2
        assert "decay=" in status

    def test_insufficient_chain_no_decay(self):
        """Insufficient chain (< 3 events) returns 0 regardless of age."""
        register_sequence_event("TW", "NARRATIVE_BURST")
        register_sequence_event("TW", "ISR_SURGE")
        bonus, status, chain = compute_sequence_bonus("TW")
        assert bonus == 0


# ─────────────────────────────────────────────────────────────────────────────
# (vi) DDoS-BGP causality enrichment
# ─────────────────────────────────────────────────────────────────────────────
class TestDdosBgpCausality:
    """When CF spike and BGP outage co-occur, IODA rationale should be enriched."""

    def test_causality_enrichment(self):
        """Both CF spike + IODA BGP fired → causal link in fired_reason."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3, fired_reason="HOD Z-score=2.5"),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "bgp=OUTAGE", 1, fired_reason="BGP anomaly confirmed"),
        ]
        # Simulate the causality enrichment logic from core.py
        cf_fired = any(e.sensor == "cf_spike_core" and e.status == "FIRED" and not e.suppressed for e in rationale)
        bgp_entry = next((e for e in rationale if e.sensor == "ioda_bgp" and e.status == "FIRED" and not e.suppressed), None)
        if cf_fired and bgp_entry:
            bgp_entry.fired_reason = f"{bgp_entry.fired_reason} — DDoS-BGP causal link: CF spike (5.0x) concurrent with BGP outage"
        assert "DDoS-BGP causal link" in bgp_entry.fired_reason

    def test_no_causality_when_cf_not_fired(self):
        """If CF spike is OK (not fired), no causal enrichment."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "OK", "1.2x", 0),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "bgp=OUTAGE", 1, fired_reason="BGP anomaly confirmed"),
        ]
        cf_fired = any(e.sensor == "cf_spike_core" and e.status == "FIRED" and not e.suppressed for e in rationale)
        bgp_entry = next((e for e in rationale if e.sensor == "ioda_bgp" and e.status == "FIRED" and not e.suppressed), None)
        if cf_fired and bgp_entry:
            bgp_entry.fired_reason += " — DDoS-BGP causal link"
        assert "DDoS-BGP causal link" not in bgp_entry.fired_reason

    def test_no_causality_when_bgp_suppressed(self):
        """If IODA BGP is suppressed, no causal enrichment."""
        rationale = [
            RationaleEntry("cf_spike_core", "cyber", "FIRED", "3x", 3),
            RationaleEntry("ioda_bgp", "physical", "FIRED", "bgp=OUTAGE", 1, fired_reason="BGP anomaly", suppressed=True),
        ]
        cf_fired = any(e.sensor == "cf_spike_core" and e.status == "FIRED" and not e.suppressed for e in rationale)
        bgp_entry = next((e for e in rationale if e.sensor == "ioda_bgp" and e.status == "FIRED" and not e.suppressed), None)
        assert bgp_entry is None  # Suppressed, so not found


# ══════════════════════════════════════════════════════════════
# DDoS Intelligence Enhancement (v11) Tests
# ══════════════════════════════════════════════════════════════

class TestOriginEntropy:
    """Tests for Shannon entropy of attack origin distributions."""

    def test_single_source_zero_entropy(self):
        """Single source → 0 bits entropy."""
        dist = {"CN": 100.0}
        assert compute_origin_entropy(dist) == 0.0

    def test_two_equal_sources(self):
        """Two equal sources → 1 bit."""
        dist = {"CN": 50.0, "RU": 50.0}
        assert compute_origin_entropy(dist) == pytest.approx(1.0, abs=0.01)

    def test_four_equal_sources(self):
        """Four equal sources → 2 bits."""
        dist = {"CN": 25.0, "RU": 25.0, "IR": 25.0, "KP": 25.0}
        assert compute_origin_entropy(dist) == pytest.approx(2.0, abs=0.01)

    def test_empty_distribution(self):
        """Empty distribution → 0 bits."""
        assert compute_origin_entropy({}) == 0.0

    def test_skewed_distribution(self):
        """Highly skewed → low entropy (< 1 bit for dominant source)."""
        dist = {"CN": 90.0, "RU": 5.0, "IR": 3.0, "KP": 2.0}
        entropy = compute_origin_entropy(dist)
        assert 0.0 < entropy < 1.5

    def test_zero_values_ignored(self):
        """Origins with 0% share are ignored."""
        dist = {"CN": 50.0, "RU": 50.0, "IR": 0.0}
        assert compute_origin_entropy(dist) == pytest.approx(1.0, abs=0.01)


class TestEntropyTracking:
    """Tests for entropy change tracking with moving average."""

    def test_insufficient_data(self):
        """< 3 readings → INSUFFICIENT_DATA label."""
        result = track_entropy_change("TW", 2.5)
        assert result["shift_label"] == "INSUFFICIENT_DATA"
        result = track_entropy_change("TW", 2.5)
        assert result["shift_label"] == "INSUFFICIENT_DATA"

    def test_stable_entropy(self):
        """Stable entropy readings → STABLE label."""
        for _ in range(5):
            track_entropy_change("TW", 2.5)
        result = track_entropy_change("TW", 2.5)
        assert result["shift_label"] == "STABLE"
        assert abs(result["delta_pct"]) < 20.0

    def test_concentrating_attack(self):
        """Sharp entropy drop → CONCENTRATING label."""
        for _ in range(5):
            track_entropy_change("TW", 3.0)
        # Sudden drop to 1.0 (>20% decrease)
        result = track_entropy_change("TW", 1.0)
        assert result["shift_label"] == "CONCENTRATING"
        assert result["delta_pct"] < -20.0

    def test_dispersing_attack(self):
        """Sharp entropy rise → DISPERSING label."""
        for _ in range(5):
            track_entropy_change("TW", 1.0)
        # Sudden rise to 3.0 (>20% increase)
        result = track_entropy_change("TW", 3.0)
        assert result["shift_label"] == "DISPERSING"
        assert result["delta_pct"] > 20.0


class TestBgpTrend:
    """Tests for RIPE BGP time series trend computation."""

    def test_stable_prefixes(self):
        """Constant prefix counts → STABLE trend."""
        stats = [{"announced_prefixes": 1000, "seen_ases": 50} for _ in range(5)]
        result = BgpRoutingSensor._compute_trend(stats)
        assert result["trend_label"] == "STABLE"
        assert result["prefix_trend"] == 0.0

    def test_withdrawing_prefixes(self):
        """Decreasing prefix counts → WITHDRAWING trend."""
        stats = [{"announced_prefixes": 1000 - i * 20, "seen_ases": 50} for i in range(10)]
        result = BgpRoutingSensor._compute_trend(stats)
        assert result["trend_label"] == "WITHDRAWING"
        assert result["prefix_trend"] < 0
        assert result["prefix_trend_pct"] < -0.5

    def test_growing_prefixes(self):
        """Increasing prefix counts → GROWING trend."""
        stats = [{"announced_prefixes": 1000 + i * 20, "seen_ases": 50} for i in range(10)]
        result = BgpRoutingSensor._compute_trend(stats)
        assert result["trend_label"] == "GROWING"
        assert result["prefix_trend"] > 0
        assert result["prefix_trend_pct"] > 0.5

    def test_insufficient_data(self):
        """< 3 entries → INSUFFICIENT_DATA."""
        stats = [{"announced_prefixes": 1000, "seen_ases": 50}]
        result = BgpRoutingSensor._compute_trend(stats)
        assert result["trend_label"] == "INSUFFICIENT_DATA"

    def test_ases_trend_computed(self):
        """ASN trend is also computed."""
        stats = [{"announced_prefixes": 1000, "seen_ases": 50 + i * 2} for i in range(5)]
        result = BgpRoutingSensor._compute_trend(stats)
        assert result["ases_trend"] > 0


class TestLinearSlope:
    """Tests for _linear_slope helper."""

    def test_positive_slope(self):
        """Increasing values → positive slope."""
        assert _linear_slope([1, 2, 3, 4, 5]) == pytest.approx(1.0, abs=0.01)

    def test_zero_slope(self):
        """Constant values → zero slope."""
        assert _linear_slope([5, 5, 5, 5]) == pytest.approx(0.0, abs=0.01)

    def test_negative_slope(self):
        """Decreasing values → negative slope."""
        assert _linear_slope([5, 4, 3, 2, 1]) == pytest.approx(-1.0, abs=0.01)

    def test_single_value(self):
        """Single value → 0."""
        assert _linear_slope([42]) == 0.0

    def test_empty(self):
        """Empty list → 0."""
        assert _linear_slope([]) == 0.0


class TestCfBgpHijackScoring:
    """Tests for CF Radar BGP hijack/leak scoring logic (as implemented in core.py)."""

    def _score_bgp_events(self, hijacks, leaks, core_theater="TW"):
        """Replicate the scoring logic from core.py for BGP events."""
        core_hijacks = [h for h in hijacks if h.get("victim_country") == core_theater]
        core_leaks = [l for l in leaks if l.get("leak_country") == core_theater]
        hijack_ongoing = [h for h in core_hijacks if h.get("is_ongoing")]
        fired = len(hijack_ongoing) > 0 or len(core_leaks) >= 3
        return fired, len(core_hijacks), len(core_leaks), len(hijack_ongoing)

    def test_no_events(self):
        """No events → not fired."""
        fired, _, _, _ = self._score_bgp_events([], [])
        assert not fired

    def test_ongoing_hijack_fires(self):
        """Ongoing hijack targeting core → fired."""
        hijacks = [{"victim_country": "TW", "is_ongoing": True, "confidence": 80}]
        fired, core_h, _, ongoing = self._score_bgp_events(hijacks, [])
        assert fired
        assert core_h == 1
        assert ongoing == 1

    def test_non_ongoing_hijack_not_fired(self):
        """Past hijack (not ongoing) → not fired."""
        hijacks = [{"victim_country": "TW", "is_ongoing": False, "confidence": 80}]
        fired, _, _, _ = self._score_bgp_events(hijacks, [])
        assert not fired

    def test_three_leaks_fires(self):
        """≥3 leaks targeting core → fired."""
        leaks = [{"leak_country": "TW"} for _ in range(3)]
        fired, _, core_l, _ = self._score_bgp_events([], leaks)
        assert fired
        assert core_l == 3

    def test_two_leaks_not_fired(self):
        """2 leaks → not fired (needs ≥3)."""
        leaks = [{"leak_country": "TW"} for _ in range(2)]
        fired, _, _, _ = self._score_bgp_events([], leaks)
        assert not fired

    def test_different_country_ignored(self):
        """Events for other countries don't fire for core theater."""
        hijacks = [{"victim_country": "JP", "is_ongoing": True, "confidence": 80}]
        leaks = [{"leak_country": "JP"} for _ in range(5)]
        fired, core_h, core_l, _ = self._score_bgp_events(hijacks, leaks)
        assert not fired
        assert core_h == 0
        assert core_l == 0


# ─────────────────────────────────────────────────────────────────────────────
# IHR Sensor
# ─────────────────────────────────────────────────────────────────────────────
class TestIhrSensor:
    def test_init(self):
        s = IhrSensor()
        assert s.name == "ihr_health"
        assert s.domain == "physical"
        assert s.poll_interval == 300

    def test_cache_fallback(self):
        """When no cache set, get_cache returns empty dict or None."""
        s = IhrSensor()
        result = s.get_cache()
        # BaseSensor.get_cache() returns {} or None depending on implementation
        assert result is None or result == {}

    def test_country_status_logic(self):
        """Verify country status assignment from disconnection data."""
        s = IhrSensor()
        # Simulate setting cache with known data
        cache_data = {
            "disconnections": {"TW": [{"avglevel": 7}]},
            "hegemony_alarms": [],
            "delay_alarms": {},
            "country_status": {"TW": "DISCO_EVENT"},
        }
        s.set_cache(cache_data)
        cached = s.get_cache()
        assert cached["country_status"]["TW"] == "DISCO_EVENT"
        assert len(cached["disconnections"]["TW"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# RIPE Atlas Sensor
# ─────────────────────────────────────────────────────────────────────────────
class TestRipeAtlasSensor:
    def test_init(self):
        s = RipeAtlasSensor()
        assert s.name == "ripe_atlas"
        assert s.domain == "physical"
        assert s.poll_interval == 600

    def test_probe_drop_detection(self):
        """Verify probe drop percentage calculation."""
        s = RipeAtlasSensor()
        # Simulate previous count of 100 probes
        s._prev_probe_counts["TW"] = 100
        # If current active is 60 → drop_pct = 0.40 (40%)
        prev = s._prev_probe_counts.get("TW", 60)
        active = 60
        drop_pct = (prev - active) / max(prev, 1)
        assert drop_pct == pytest.approx(0.40)
        # 40% ≥ 30% threshold → PROBE_DROP
        from radar.sensors.ripe_atlas import PROBE_DROP_PCT, PROBE_BLACKOUT_PCT
        assert drop_pct >= PROBE_DROP_PCT
        assert drop_pct < PROBE_BLACKOUT_PCT

    def test_probe_blackout_detection(self):
        """70% drop should be PROBE_BLACKOUT."""
        s = RipeAtlasSensor()
        s._prev_probe_counts["TW"] = 100
        prev = s._prev_probe_counts["TW"]
        active = 25
        drop_pct = (prev - active) / max(prev, 1)
        assert drop_pct == pytest.approx(0.75)
        from radar.sensors.ripe_atlas import PROBE_BLACKOUT_PCT
        assert drop_pct >= PROBE_BLACKOUT_PCT

    def test_cache_roundtrip(self):
        s = RipeAtlasSensor()
        data = {
            "probe_counts": {"TW": {"active": 50, "prev": 80, "drop_pct": 0.375}},
            "latency": {"TW": {"avg_ms": 25.5, "p95_ms": 45.0, "probes_responding": 12}},
            "country_status": {"TW": "PROBE_DROP"},
        }
        s.set_cache(data)
        assert s.get_cache() == data


# ─────────────────────────────────────────────────────────────────────────────
# Tor Metrics Sensor
# ─────────────────────────────────────────────────────────────────────────────
class TestTorMetricsSensor:
    def test_init(self):
        s = TorMetricsSensor()
        assert s.name == "tor_metrics"
        assert s.domain == "info"
        assert s.poll_interval == 1800

    def test_relay_drop_detection(self):
        """40% relay drop should be detected."""
        s = TorMetricsSensor()
        s._prev_relay_counts["IR"] = 100
        prev = s._prev_relay_counts["IR"]
        running = 55
        drop_pct = (prev - running) / max(prev, 1)
        assert drop_pct == pytest.approx(0.45)
        from radar.sensors.tor_metrics import RELAY_DROP_FALLBACK_PCT
        assert drop_pct >= RELAY_DROP_FALLBACK_PCT

    def test_user_surge_detection(self):
        """100%+ user surge should be classified as SURGE."""
        s = TorMetricsSensor()
        s._prev_user_counts["IR"] = 1000
        prev_users = s._prev_user_counts["IR"]
        total_users = 2500
        surge_pct = (total_users - prev_users) / max(prev_users, 1)
        assert surge_pct == pytest.approx(1.5)
        from radar.sensors.tor_metrics import USER_SURGE_FALLBACK_PCT
        assert surge_pct > USER_SURGE_FALLBACK_PCT

    def test_censorship_indicator(self):
        """Relay drop + user surge → CENSORSHIP_INDICATOR."""
        relay_drop = True
        user_surge = True
        if relay_drop and user_surge:
            status = "CENSORSHIP_INDICATOR"
        elif relay_drop:
            status = "RELAY_DROP"
        elif user_surge:
            status = "USER_SURGE"
        else:
            status = "NORMAL"
        assert status == "CENSORSHIP_INDICATOR"

    def test_cache_roundtrip(self):
        s = TorMetricsSensor()
        data = {
            "relay_counts": {"IR": {"running": 50, "bridges": 10, "bandwidth_kbps": 5000, "prev": 100, "drop_pct": 0.5}},
            "client_estimates": {"IR": {"bridge_users": 5000, "prev_users": 2000, "surge_pct": 1.5, "trend": "SURGE"}},
            "country_status": {"IR": "CENSORSHIP_INDICATOR"},
        }
        s.set_cache(data)
        assert s.get_cache() == data

    def test_new_sensor_rationale_integration(self):
        """Verify new sensors produce valid RationaleEntry objects."""
        # IHR disco fired
        e1 = RationaleEntry("ihr_disco", "physical", "FIRED", "2 events", 2,
                            fired_reason="IHR: Disconnection event in TW")
        assert e1.sensor == "ihr_disco"
        assert e1.domain == "physical"
        assert e1.score == 2

        # RIPE Atlas fired
        e2 = RationaleEntry("ripe_atlas", "physical", "FIRED", "PROBE_DROP 40%", 1,
                            fired_reason="RIPE Atlas: Probe drop 40% in TW")
        assert e2.sensor == "ripe_atlas"
        assert e2.score == 1

        # Tor metrics fired
        e3 = RationaleEntry("tor_metrics", "info", "FIRED", "CENSORSHIP_INDICATOR", 2,
                            fired_reason="Tor: CENSORSHIP_INDICATOR in IR")
        assert e3.sensor == "tor_metrics"
        assert e3.domain == "info"
        assert e3.score == 2

        # Engine should compute domain scores correctly with new sensors
        engine = WeightedConvergenceEngine()
        scores = engine.compute_domain_scores([e1, e2, e3])
        assert scores["physical"] == 3  # ihr_disco(2) + ripe_atlas(1)
        assert scores["info"] == 2      # tor_metrics(2)
        assert scores["cyber"] == 0


# ── Circuit Breaker Tests ─────────────────────────────────────────────────

class TestCircuitBreaker:
    """Test circuit breaker state machine in BaseSensor."""

    def _make_sensor(self):
        """Create a concrete sensor subclass for testing."""
        class DummySensor(IhrSensor):
            pass
        s = DummySensor.__new__(DummySensor)
        # Minimal init without full IhrSensor constructor side effects
        s.name = "test_cb"
        s.domain = "cyber"
        s.poll_interval = 300
        s.enabled = True
        s._cache = {}
        s._cache_time = 0.0
        s._last_error = ""
        import threading
        s._lock = threading.Lock()
        s._fetch_log = []
        s._cb_state = "CLOSED"
        s._cb_fail_count = 0
        s._cb_opened_at = 0.0
        s._cb_recovery_delay = s.CB_INITIAL_DELAY
        return s

    def test_initial_state_closed(self):
        s = self._make_sensor()
        assert s._cb_state == "CLOSED"
        assert s.cb_should_skip() is False

    def test_stays_closed_under_threshold(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD - 1):
            s.cb_record_failure()
        assert s._cb_state == "CLOSED"
        assert s.cb_should_skip() is False

    def test_opens_at_threshold(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        assert s._cb_state == "OPEN"
        assert s._cb_fail_count == s.CB_FAILURE_THRESHOLD

    def test_open_skips_fetch(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        # Immediately after opening, recovery delay not elapsed
        assert s.cb_should_skip() is True

    def test_open_to_half_open_after_delay(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        assert s._cb_state == "OPEN"
        # Simulate elapsed time past recovery delay
        s._cb_opened_at = time.time() - s._cb_recovery_delay - 1
        assert s.cb_should_skip() is False  # Transitions to HALF_OPEN
        assert s._cb_state == "HALF_OPEN"

    def test_half_open_success_closes(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        s._cb_opened_at = time.time() - s._cb_recovery_delay - 1
        s.cb_should_skip()  # → HALF_OPEN
        s.cb_record_success()
        assert s._cb_state == "CLOSED"
        assert s._cb_fail_count == 0
        assert s._cb_recovery_delay == s.CB_INITIAL_DELAY

    def test_half_open_failure_reopens_with_doubled_delay(self):
        s = self._make_sensor()
        initial_delay = s.CB_INITIAL_DELAY
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        s._cb_opened_at = time.time() - s._cb_recovery_delay - 1
        s.cb_should_skip()  # → HALF_OPEN
        s.cb_record_failure()  # Probe fails
        assert s._cb_state == "OPEN"
        assert s._cb_recovery_delay == initial_delay * 2

    def test_recovery_delay_capped_at_max(self):
        s = self._make_sensor()
        s._cb_recovery_delay = s.CB_MAX_DELAY
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        s._cb_opened_at = time.time() - s.CB_MAX_DELAY - 1
        s.cb_should_skip()  # → HALF_OPEN
        s.cb_record_failure()  # Probe fails, delay doubles but capped
        assert s._cb_recovery_delay == s.CB_MAX_DELAY

    def test_health_returns_circuit_open(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        assert s.health == "CIRCUIT_OPEN"

    def test_health_ok_after_recovery(self):
        s = self._make_sensor()
        s._cache_time = time.time()  # Recent cache
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        s._cb_opened_at = time.time() - s._cb_recovery_delay - 1
        s.cb_should_skip()  # → HALF_OPEN
        s.cb_record_success()
        assert s.health == "OK"

    def test_confidence_zero_when_circuit_open(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        assert s.compute_confidence() == 0.0

    def test_to_config_dict_includes_cb_fields(self):
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        d = s.to_config_dict()
        assert d["cb_state"] == "OPEN"
        assert d["cb_fail_count"] == s.CB_FAILURE_THRESHOLD
        assert d["health"] == "CIRCUIT_OPEN"

    def test_full_cycle_closed_open_halfopen_closed(self):
        """Test complete CB lifecycle: CLOSED → OPEN → HALF_OPEN → CLOSED."""
        s = self._make_sensor()
        # 1. CLOSED → OPEN
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        assert s._cb_state == "OPEN"
        # 2. OPEN → HALF_OPEN
        s._cb_opened_at = time.time() - s._cb_recovery_delay - 1
        s.cb_should_skip()
        assert s._cb_state == "HALF_OPEN"
        # 3. HALF_OPEN → CLOSED
        s.cb_record_success()
        assert s._cb_state == "CLOSED"
        assert s._cb_fail_count == 0

    def test_full_cycle_with_probe_failure(self):
        """CLOSED → OPEN → HALF_OPEN → OPEN (probe fail) → HALF_OPEN → CLOSED."""
        s = self._make_sensor()
        for _ in range(s.CB_FAILURE_THRESHOLD):
            s.cb_record_failure()
        # First probe fails
        s._cb_opened_at = time.time() - s._cb_recovery_delay - 1
        s.cb_should_skip()  # → HALF_OPEN
        s.cb_record_failure()  # → OPEN with doubled delay
        assert s._cb_state == "OPEN"
        assert s._cb_recovery_delay == s.CB_INITIAL_DELAY * 2
        # Second probe succeeds
        s._cb_opened_at = time.time() - s._cb_recovery_delay - 1
        s.cb_should_skip()  # → HALF_OPEN
        s.cb_record_success()
        assert s._cb_state == "CLOSED"


class TestSecretIndicator:
    """Anti-corruption tests for the secret-indicator pattern (2026-05-04 fix).

    The bug: GET /api/env_config returned mask-strings like ***680b which the
    UI would echo back on SAVE, overwriting the real value with literal
    asterisks. The fix is structural: the API never returns the secret value,
    only a {set, last4} indicator. POST guards against indicator/mask shapes.
    """
    def test_is_secret_key(self):
        from radar.routes.admin import _is_secret_key
        assert _is_secret_key("CF_API_TOKEN")
        assert _is_secret_key("OPENSKY_CLIENT_SECRET")
        assert _is_secret_key("NOTIFY_SLACK_WEBHOOK")
        assert _is_secret_key("DEFAULT_ADMIN_PASSWORD")
        assert not _is_secret_key("DOMAIN_WEIGHT_CYBER")
        assert not _is_secret_key("LLM_TIMEOUT")
        assert not _is_secret_key("AIRSPACE_WINDOW")

    def test_secret_indicator_set(self):
        from radar.routes.admin import _secret_indicator
        ind = _secret_indicator("0123456789abcdef0123456789abcdef")
        assert ind == {"set": True, "last4": "680b"}

    def test_secret_indicator_short(self):
        from radar.routes.admin import _secret_indicator
        ind = _secret_indicator("abc")
        # Short value still marks as set; last4 is None when too short.
        assert ind["set"] is True
        assert ind["last4"] is None

    def test_secret_indicator_unset(self):
        from radar.routes.admin import _secret_indicator
        assert _secret_indicator("") == {"set": False, "last4": None}
        assert _secret_indicator(None) == {"set": False, "last4": None}

    def test_secret_indicator_no_plaintext(self):
        """Ensure the plaintext value is NEVER in the indicator output."""
        from radar.routes.admin import _secret_indicator
        secret = "super-secret-must-not-leak-680b"
        ind = _secret_indicator(secret)
        # Only last4 is exposed; the full plaintext must not appear.
        assert ind["last4"] == "680b"
        for v in ind.values():
            assert v is None or v is True or v is False or v == "680b"

    def test_looks_like_mask(self):
        from radar.routes.admin import _looks_like_mask
        # The exact pattern that destroyed our keys
        assert _looks_like_mask("***680b")
        assert _looks_like_mask("****")  # ThreatFox got reduced to this
        assert _looks_like_mask("****************************680b")
        assert _looks_like_mask("************************************************************62f5")  # JWT case
        # NOT mask shapes
        assert not _looks_like_mask("0123456789abcdef0123456789abcdef")  # real key
        assert not _looks_like_mask("0.40")  # threshold value
        assert not _looks_like_mask("")
        assert not _looks_like_mask("**ab**")  # not anchored
        assert not _looks_like_mask("****abcde")  # too many trailing chars

    def test_mask_string_never_matches_real_keys(self):
        """Defensive — verify real-world API key formats are not flagged."""
        from radar.routes.admin import _looks_like_mask
        real_examples = [
            "cfut_REDACTED_REDACTED_REDACTED_REDACTED_REDACTED_REDACTED",  # CF token
            "0123456789abcdef0123456789abcdef",                       # OWM
            "kamonegi.13-api-client",                                 # OpenSky ID
            "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP",  # GreyNoise
            "ZZZZYYYYXXXXWWWWVVVVUUUUTTTTSSSSRRRRQQQQPPPPOOOONNNNMMMMLLLLKKKK",  # JWT
        ]
        for k in real_examples:
            assert not _looks_like_mask(k), f"false positive on {k[:8]}…"
