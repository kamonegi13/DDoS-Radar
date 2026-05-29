"""Round-trip persistence tests for the v2.0 Conclusion ledger.

Validates ADR-V2-008 (append-only) and verifies save_conclusion → SELECT →
reconstruct preserves every field except the disclaimer (which is injected
from config at read time, per NP7 tool-level constant semantics).
"""

from __future__ import annotations

import time

import pytest

from radar.conclusions import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    latest_conclusion,
    new_conclusion_id,
    save_conclusion,
)
from radar.database import RadarDB


_DISCLAIMER = "Tool conclusion only — final judgment by organizational process."


@pytest.fixture
def db(tmp_path) -> RadarDB:
    """Fresh isolated DB per test — gets v19/v20 baseline schema."""
    return RadarDB(str(tmp_path / "round_trip.db"))


def _make_conclusion(**overrides) -> Conclusion:
    base = dict(
        id=new_conclusion_id(),
        scenario_id="taiwan_contingency",
        conclusion_type=ConclusionType.THREAT_LEVEL,
        state="3",
        confidence=0.78,
        observed_at=time.time(),
        formula_ref="radar/scoring.py#derive_tl@v2.0.1",
        threshold_ref={"total": 9.0, "physical": 3.0},
        source_urls=("https://example.com/source1", "https://example.com/source2"),
        final_judgment_disclaimer=_DISCLAIMER,
        calibration_status={"sampler": "OK", "drift": 0.05},
        metadata={"importance_score": 87, "active_countries": ["TW", "US"]},
    )
    base.update(overrides)
    return Conclusion(**base)


def test_save_then_read_back_yields_equal_conclusion(db: RadarDB) -> None:
    original = _make_conclusion()
    save_conclusion(db, original)

    retrieved = latest_conclusion(db, "taiwan_contingency", ConclusionType.THREAT_LEVEL)

    assert retrieved is not None
    assert retrieved.id == original.id
    assert retrieved.scenario_id == original.scenario_id
    assert retrieved.conclusion_type is original.conclusion_type
    assert retrieved.state == original.state
    assert retrieved.confidence == original.confidence
    assert retrieved.formula_ref == original.formula_ref
    assert retrieved.threshold_ref == original.threshold_ref
    assert retrieved.source_urls == original.source_urls
    assert retrieved.calibration_status == original.calibration_status
    assert retrieved.metadata == original.metadata
    assert retrieved.conclusion_unavailable_reason is None


def test_latest_returns_most_recent_when_multiple_rows(db: RadarDB) -> None:
    """ADR-V2-008: append-only — newest by observed_at wins."""
    older = _make_conclusion(state="4", observed_at=1000.0)
    newer = _make_conclusion(state="2", observed_at=2000.0)
    save_conclusion(db, older)
    save_conclusion(db, newer)

    latest = latest_conclusion(db, "taiwan_contingency", ConclusionType.THREAT_LEVEL)

    assert latest is not None
    assert latest.state == "2"
    assert latest.id == newer.id


def test_latest_returns_none_for_unknown_scenario(db: RadarDB) -> None:
    save_conclusion(db, _make_conclusion())
    assert latest_conclusion(db, "unknown_scenario", ConclusionType.THREAT_LEVEL) is None


def test_latest_distinguishes_conclusion_types(db: RadarDB) -> None:
    tl = _make_conclusion(conclusion_type=ConclusionType.THREAT_LEVEL, state="3")
    trend = _make_conclusion(conclusion_type=ConclusionType.TREND, state="ESCALATING_24H")
    save_conclusion(db, tl)
    save_conclusion(db, trend)

    got_tl = latest_conclusion(db, "taiwan_contingency", ConclusionType.THREAT_LEVEL)
    got_trend = latest_conclusion(db, "taiwan_contingency", ConclusionType.TREND)

    assert got_tl is not None and got_tl.state == "3"
    assert got_trend is not None and got_trend.state == "ESCALATING_24H"


def test_unavailable_conclusion_round_trips(db: RadarDB) -> None:
    """NP5+8: unavailable_reason persists faithfully with state=None."""
    c = _make_conclusion(
        state=None,
        confidence=0.0,
        conclusion_unavailable_reason=ConclusionUnavailableReason.SENSOR_DEGRADED,
    )
    save_conclusion(db, c)

    got = latest_conclusion(db, "taiwan_contingency", ConclusionType.THREAT_LEVEL)

    assert got is not None
    assert got.state is None
    assert got.conclusion_unavailable_reason is ConclusionUnavailableReason.SENSOR_DEGRADED
    assert not got.is_available()


def test_disclaimer_injected_from_config_on_read(db: RadarDB, monkeypatch) -> None:
    """NP7: disclaimer is a tool-level constant — config wording wins on read."""
    from radar import config

    save_conclusion(db, _make_conclusion(final_judgment_disclaimer="OLD WORDING"))
    monkeypatch.setattr(config, "V2_NP7_DISCLAIMER", "NEW WORDING — applies to all reads")

    got = latest_conclusion(db, "taiwan_contingency", ConclusionType.THREAT_LEVEL)

    assert got is not None
    assert got.final_judgment_disclaimer == "NEW WORDING — applies to all reads"


def test_feature_flag_off_skips_persistence(monkeypatch, db: RadarDB) -> None:
    """V2_CONCLUSION_LEDGER_ENABLED=False → _maybe_persist_tl_conclusion no-op."""
    from radar import config, scoring

    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", False)
    monkeypatch.setattr(scoring, "_db", db)

    state = scoring.ScenarioState(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=5.0,
        domains={"cyber": 3.0, "physical": 2.0, "info": 0.0},
        active_countries=["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=[],
    )
    scoring._maybe_persist_tl_conclusion(state)

    assert latest_conclusion(db, "taiwan_contingency", ConclusionType.THREAT_LEVEL) is None


def test_feature_flag_on_persists_focused_tl(monkeypatch, db: RadarDB) -> None:
    """V2_CONCLUSION_LEDGER_ENABLED=True → focused TL is persisted."""
    from radar import config, scoring

    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", True)
    monkeypatch.setattr(scoring, "_db", db)

    state = scoring.ScenarioState(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=5.0,
        domains={"cyber": 3.0, "physical": 2.0, "info": 0.0},
        active_countries=["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=[],
    )
    scoring._maybe_persist_tl_conclusion(state)

    got = latest_conclusion(db, "taiwan_contingency", ConclusionType.THREAT_LEVEL)
    assert got is not None
    assert got.state == "3"
    assert got.formula_ref == scoring.DERIVE_TL_FORMULA_REF


def test_unfocused_state_with_tl_none_skips_persistence(monkeypatch, db: RadarDB) -> None:
    """Background scenarios have tl=None — must not write a row."""
    from radar import config, scoring

    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", True)
    monkeypatch.setattr(scoring, "_db", db)

    state = scoring.ScenarioState(
        scenario_id="korean_peninsula",
        is_focused=False,
        scoring_mode="lite",
        score=2.0,
        domains={"cyber": 2.0, "physical": 0.0, "info": 0.0},
        active_countries=[],
        convergence_bonus=0.0,
        tl=None,
        contributions=[],
    )
    scoring._maybe_persist_tl_conclusion(state)

    assert latest_conclusion(db, "korean_peninsula", ConclusionType.THREAT_LEVEL) is None


def test_persistence_failure_is_swallowed(monkeypatch, db: RadarDB) -> None:
    """ADR-V2-001: shadow-write must never break v1 scoring."""
    from radar import config, scoring

    monkeypatch.setattr(config, "V2_CONCLUSION_LEDGER_ENABLED", True)

    class _BrokenDB:
        def _get_conn(self):
            raise RuntimeError("simulated DB outage")

    monkeypatch.setattr(scoring, "_db", _BrokenDB())

    state = scoring.ScenarioState(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=5.0,
        domains={"cyber": 5.0, "physical": 0.0, "info": 0.0},
        active_countries=["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=[],
    )
    # Must NOT raise.
    scoring._maybe_persist_tl_conclusion(state)


# ── ADR-V2-010 inconclusive_continuity_log wiring (PF3 2026-04-29) ─────


class TestContinuityLog:
    """save_conclusion side-effects into inconclusive_continuity_log so the
    7-day chronic-failure rule has data to compute against."""

    def test_unavailable_conclusion_opens_run(self, db):
        from radar.conclusions.base import ConclusionUnavailableReason
        c = _make_conclusion(
            id="c-unavail-1",
            scenario_id="taiwan_contingency",
            state=None,
            confidence=0.0,
            observed_at=1000.0,
            conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
        )
        save_conclusion(db, c)
        rows = db._get_conn().execute(
            "SELECT * FROM inconclusive_continuity_log "
            "WHERE scenario_id=? AND conclusion_type=? "
            "ORDER BY observed_at DESC",
            ("taiwan_contingency", "threat_level"),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["is_available"] == 0
        assert rows[0]["reason"].upper() == "INSUFFICIENT_DATA"
        assert rows[0]["run_length_sec"] == 0
        assert rows[0]["first_seen_at"] == 1000.0

    def test_consecutive_unavailable_extends_run_length(self, db):
        from radar.conclusions.base import ConclusionUnavailableReason
        for i, ts in enumerate([1000.0, 1300.0, 1900.0]):
            c = _make_conclusion(
                id=f"c-cont-{i}",
                scenario_id="middle_east",
                state=None,
                confidence=0.0,
                observed_at=ts,
                conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
            )
            save_conclusion(db, c)
        rows = db._get_conn().execute(
            "SELECT observed_at, run_length_sec, first_seen_at FROM "
            "inconclusive_continuity_log WHERE scenario_id=? "
            "ORDER BY observed_at ASC",
            ("middle_east",),
        ).fetchall()
        assert len(rows) == 3
        assert rows[0]["run_length_sec"] == 0
        assert rows[1]["run_length_sec"] == 300.0
        assert rows[2]["run_length_sec"] == 900.0
        assert all(r["first_seen_at"] == 1000.0 for r in rows)

    def test_available_after_unavailable_closes_run(self, db):
        from radar.conclusions.base import ConclusionUnavailableReason
        # Open the run with an unavailable conclusion.
        save_conclusion(db, _make_conclusion(
            id="c-close-open",
            scenario_id="korean_peninsula",
            state=None,
            confidence=0.0,
            observed_at=1000.0,
            conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
        ))
        # Resolve.
        save_conclusion(db, _make_conclusion(
            id="c-close-resolved",
            scenario_id="korean_peninsula",
            state="3",
            confidence=0.85,
            observed_at=1500.0,
        ))
        rows = db._get_conn().execute(
            "SELECT observed_at, is_available, run_length_sec, reason "
            "FROM inconclusive_continuity_log WHERE scenario_id=? "
            "ORDER BY observed_at ASC",
            ("korean_peninsula",),
        ).fetchall()
        assert len(rows) == 2
        assert rows[0]["is_available"] == 0
        assert rows[1]["is_available"] == 1
        assert rows[1]["run_length_sec"] == 500.0
        assert rows[1]["reason"] == "resolved"

    def test_steady_state_available_writes_nothing(self, db):
        """Two consecutive available conclusions should NOT add continuity
        rows — the table only tracks transitions and unavailable runs."""
        for i, ts in enumerate([2000.0, 2300.0]):
            save_conclusion(db, _make_conclusion(
                id=f"c-steady-{i}",
                scenario_id="south_china_sea",
                state="3",
                confidence=0.85,
                observed_at=ts,
            ))
        rows = db._get_conn().execute(
            "SELECT COUNT(*) FROM inconclusive_continuity_log WHERE scenario_id=?",
            ("south_china_sea",),
        ).fetchone()
        assert rows[0] == 0
