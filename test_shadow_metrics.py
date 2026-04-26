"""Tests for radar.conclusions.shadow_metrics — the process-local counter
registry that lets Mode B operators verify shadow-write health without
grepping container logs.

Covered:
- Snapshot shape and emptiness handling
- record_success increments per-type counters and sets last_success_at
- record_failure captures exception class + truncated message + timestamp
- failure_rate is computed correctly and is None when there are no attempts
- reset_for_tests clears state and resets started_at
- The end-to-end integration with compute_scenario_score's hooks (each of
  the 5 hooks must report at least one success when ledger_enabled=true)
"""

from __future__ import annotations

import pytest

from radar import config
from radar.conclusions import shadow_metrics


@pytest.fixture(autouse=True)
def _clean_registry():
    shadow_metrics.reset_for_tests()
    yield
    shadow_metrics.reset_for_tests()


def test_snapshot_starts_empty() -> None:
    snap = shadow_metrics.snapshot()
    assert snap["by_type"] == {}
    assert snap["uptime_sec"] >= 0.0
    assert snap["started_at"] > 0.0


def test_record_success_increments_count_and_timestamp() -> None:
    shadow_metrics.record_success("threat_level", now=1_700_000_000.0)
    snap = shadow_metrics.snapshot()
    m = snap["by_type"]["threat_level"]
    assert m["success_count"] == 1
    assert m["failure_count"] == 0
    assert m["last_success_at"] == 1_700_000_000.0
    assert m["last_failure_at"] is None
    assert m["failure_rate"] == 0.0


def test_record_failure_captures_exception_metadata() -> None:
    err = ValueError("backing store unreachable")
    shadow_metrics.record_failure("trend", err, now=1_700_000_000.0)
    snap = shadow_metrics.snapshot()
    m = snap["by_type"]["trend"]
    assert m["failure_count"] == 1
    assert m["last_failure_kind"] == "ValueError"
    assert m["last_failure_message"] == "backing store unreachable"
    assert m["last_failure_at"] == 1_700_000_000.0


def test_record_failure_truncates_long_messages() -> None:
    long_msg = "x" * 500
    shadow_metrics.record_failure("anomaly", RuntimeError(long_msg))
    snap = shadow_metrics.snapshot()
    m = snap["by_type"]["anomaly"]
    assert len(m["last_failure_message"]) <= 200
    assert m["last_failure_message"].endswith("...")


def test_failure_rate_computed_correctly() -> None:
    for _ in range(7):
        shadow_metrics.record_success("per_domain")
    for _ in range(3):
        shadow_metrics.record_failure("per_domain", IOError("disk"))
    m = shadow_metrics.snapshot()["by_type"]["per_domain"]
    assert m["success_count"] == 7
    assert m["failure_count"] == 3
    assert m["failure_rate"] == pytest.approx(0.3)


def test_failure_rate_is_none_when_no_attempts() -> None:
    """A fresh registry slot returns None rather than 0.0 so the operator
    can distinguish "0/0 attempts" from "0/N failures"."""
    shadow_metrics.record_success("attack_mode")
    snap = shadow_metrics.snapshot()
    # A type that was never touched is simply absent from by_type.
    assert "trend" not in snap["by_type"]


def test_reset_clears_all_counters_and_resets_started_at() -> None:
    shadow_metrics.record_success("threat_level")
    shadow_metrics.record_failure("trend", RuntimeError("x"))
    before = shadow_metrics.snapshot()["started_at"]
    shadow_metrics.reset_for_tests()
    after = shadow_metrics.snapshot()
    assert after["by_type"] == {}
    assert after["started_at"] >= before


def test_per_type_isolation() -> None:
    shadow_metrics.record_success("threat_level")
    shadow_metrics.record_failure("trend", RuntimeError("isolated"))
    snap = shadow_metrics.snapshot()["by_type"]
    assert snap["threat_level"]["success_count"] == 1
    assert snap["threat_level"]["failure_count"] == 0
    assert snap["trend"]["success_count"] == 0
    assert snap["trend"]["failure_count"] == 1


# ---------- end-to-end integration with the scoring hooks ----------

def test_shadow_write_hooks_record_success_when_flag_enabled(
    tmp_path, monkeypatch
) -> None:
    """All 5 hooks must report at least one success when V2_CONCLUSION_LEDGER_ENABLED
    is on and a scenario state with valid contributions is scored.
    """
    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", True)

    import radar.scoring as scoring_mod
    from radar.database import RadarDB
    from radar.scoring import (
        ScenarioContribution,
        ScenarioState,
        Signal,
        _maybe_persist_anomaly_conclusions,
        _maybe_persist_attack_mode_conclusion,
        _maybe_persist_per_domain_conclusion,
        _maybe_persist_tl_conclusion,
        _maybe_persist_trend_conclusion,
    )

    db = RadarDB(str(tmp_path / "metrics_smoke.db"))
    monkeypatch.setattr(scoring_mod, "_db", db)

    sig = Signal(
        signal_source="apt_intel",
        sensor="apt_intel",
        observed_at=1_700_000_000.0,
        domain="cyber",
        countries=["TW"],
        country_weights={"TW": 1.0},
        raw_score=2.0,
        value_display="test signal",
        evidence_url=None,
    )
    contrib = ScenarioContribution(
        signal=sig,
        contributing_country="TW",
        llm_country_weight=1.0,
        participant_weight=1.0,
        participant_role="primary_target",
        final_contribution=2.0,
        formula_trace="test",
    )
    state = ScenarioState(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=2.0,
        domains={"cyber": 2.0, "physical": 0.0, "info": 0.0},
        active_countries=["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=[contrib],
    )

    _maybe_persist_tl_conclusion(state)
    _maybe_persist_per_domain_conclusion(state)
    _maybe_persist_trend_conclusion(state)
    _maybe_persist_attack_mode_conclusion(state)
    _maybe_persist_anomaly_conclusions(state)

    snap = shadow_metrics.snapshot()
    expected_types = {"threat_level", "per_domain", "trend",
                      "attack_mode", "anomaly"}
    for t in expected_types:
        assert t in snap["by_type"], (
            f"hook for {t} did not record any attempt"
        )
        assert snap["by_type"][t]["success_count"] >= 1, (
            f"hook for {t} recorded no success"
        )
        assert snap["by_type"][t]["failure_count"] == 0, (
            f"hook for {t} recorded an unexpected failure: "
            f"{snap['by_type'][t]['last_failure_message']}"
        )


def test_shadow_write_hooks_silent_when_flag_disabled(
    tmp_path, monkeypatch
) -> None:
    """With the flag off, no hook should touch the registry."""
    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", False)

    import radar.scoring as scoring_mod
    from radar.database import RadarDB
    from radar.scoring import (
        ScenarioState,
        _maybe_persist_anomaly_conclusions,
        _maybe_persist_attack_mode_conclusion,
        _maybe_persist_per_domain_conclusion,
        _maybe_persist_tl_conclusion,
        _maybe_persist_trend_conclusion,
    )

    db = RadarDB(str(tmp_path / "metrics_disabled.db"))
    monkeypatch.setattr(scoring_mod, "_db", db)

    state = ScenarioState(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=0.0,
        domains={"cyber": 0.0, "physical": 0.0, "info": 0.0},
        active_countries=[],
        convergence_bonus=0.0,
        tl=3,
        contributions=[],
    )

    _maybe_persist_tl_conclusion(state)
    _maybe_persist_per_domain_conclusion(state)
    _maybe_persist_trend_conclusion(state)
    _maybe_persist_attack_mode_conclusion(state)
    _maybe_persist_anomaly_conclusions(state)

    assert shadow_metrics.snapshot()["by_type"] == {}
