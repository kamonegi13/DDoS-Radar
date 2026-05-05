"""Tests for radar.calibration._proposal_writer (post-incident, commit B)."""
from __future__ import annotations

import json
import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.calibration import _proposal_guards as guards
from radar.calibration import _proposal_writer as writer
from radar.calibration.scenario_improver import ProposalEvent
from radar.scenarios import Participant, Role, Scenario


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "writer.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.calibration.scenario_improver.db", tdb)
    monkeypatch.setattr("radar.calibration._proposal_guards.db", tdb)
    yield tdb
    tdb.close()


def _make_scenario(scenario_id="test", participants=None) -> Scenario:
    return Scenario(
        id=scenario_id,
        name_en=scenario_id, name_ja=scenario_id,
        description_en="", description_ja="",
        core_country=None, state="active", enabled=True, tier=1,
        participants={
            cc: Participant(country=cc, weight=p["weight"], role=p["role"])
            for cc, p in (participants or {}).items()
        },
    )


# ── ProposalKind taxonomy ────────────────────────────────────────────────────


class TestKindTaxonomy:
    def test_recall_positive_types(self):
        assert writer.kind_of("weight_too_low") == writer.ProposalKind.RECALL_POSITIVE
        assert writer.kind_of("missing_participant") == writer.ProposalKind.RECALL_POSITIVE

    def test_recall_negative_types(self):
        assert writer.kind_of("weight_too_high") == writer.ProposalKind.RECALL_NEGATIVE
        assert writer.kind_of("dormant_participant") == writer.ProposalKind.RECALL_NEGATIVE

    def test_structure_types(self):
        assert writer.kind_of("role_reclassify") == writer.ProposalKind.STRUCTURE

    def test_diagnostic_types(self):
        assert writer.kind_of("sensor_gap_detected") == writer.ProposalKind.DIAGNOSTIC
        assert writer.kind_of("scenario_dormant") == writer.ProposalKind.DIAGNOSTIC
        assert writer.kind_of("needs_more_data") == writer.ProposalKind.DIAGNOSTIC

    def test_discovery_and_sensor(self):
        assert writer.kind_of("scenario_discovery") == writer.ProposalKind.DISCOVERY
        assert writer.kind_of("sensor_disable") == writer.ProposalKind.SENSOR

    def test_unknown_defaults_to_structure(self):
        # Unknown types route to STRUCTURE (analyst-review tab) rather than
        # safe-apply tab — fails closed.
        assert writer.kind_of("brand_new_type") == writer.ProposalKind.STRUCTURE


# ── emit() with new columns ──────────────────────────────────────────────────


class TestEmitWritesNewColumns:
    def test_emit_persists_strength_and_vitality(self, fresh_db):
        ev = ProposalEvent(
            scenario_id="test_a",
            proposal_type="weight_too_low",
            target_country="JP",
            suggested_value={"weight": 0.7, "from": 0.5},
            evidence={},
            formula_ref="test#a",
            sample_n=20,
            why_string="t",
        )
        rid = writer.emit(ev, evidence_strength="strong",
                          vitality_state="active")
        assert rid is not None
        row = fresh_db._get_conn().execute(
            "SELECT evidence_strength, vitality_state, proposal_type "
            "FROM scenario_proposals WHERE id=?", (rid,),
        ).fetchone()
        assert row[0] == "strong"
        assert row[1] == "active"
        assert row[2] == "weight_too_low"

    def test_emit_with_null_columns_for_legacy_callers(self, fresh_db):
        ev = ProposalEvent(
            scenario_id="test_b", proposal_type="weight_too_low",
            target_country="JP", suggested_value={}, evidence={},
            formula_ref="test#b", sample_n=10, why_string="t",
        )
        rid = writer.emit(ev)
        assert rid is not None
        row = fresh_db._get_conn().execute(
            "SELECT evidence_strength, vitality_state "
            "FROM scenario_proposals WHERE id=?", (rid,),
        ).fetchone()
        assert row[0] is None
        assert row[1] is None


# ── emit_with_decision() ────────────────────────────────────────────────────


class TestEmitWithDecision:
    def test_stamps_from_decision(self, fresh_db):
        s = _make_scenario("test_c", participants={
            "JP": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
        })
        decision = guards.evaluate_for_country(s, "JP")
        ev = ProposalEvent(
            scenario_id=s.id, proposal_type="weight_too_low",
            target_country="JP", suggested_value={}, evidence={},
            formula_ref="test#c", sample_n=20, why_string="t",
        )
        rid = writer.emit_with_decision(ev, decision)
        assert rid is not None
        row = fresh_db._get_conn().execute(
            "SELECT evidence_strength, vitality_state "
            "FROM scenario_proposals WHERE id=?", (rid,),
        ).fetchone()
        # vitality_state will be 'data_gap' since no llm_intel seeded
        assert row[1] == decision.vitality.state
        assert row[0] == decision.strength


# ── Diagnostic event builders ────────────────────────────────────────────────


class TestDiagnosticBuilders:
    def test_scenario_dormant_event_shape(self):
        s = _make_scenario("scen_d", participants={
            "X": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
            "Y": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
        })
        v = guards.VitalityReport(
            state="dormant", total_signals=2,
            active_participant_count=1, total_participant_count=2,
            sensor_coverage_ratio=0.5,
            detail="quiet but coverage OK",
        )
        ev = writer.build_scenario_dormant_event(s, v)
        assert ev.proposal_type == "scenario_dormant"
        assert ev.target_country is None
        assert "1/2" in ev.why_string
        assert ev.evidence["vitality_state"] == "dormant"

    def test_sensor_gap_event_shape(self):
        s = _make_scenario("scen_e", participants={
            "X": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
        })
        v = guards.VitalityReport(
            state="data_gap", total_signals=0,
            active_participant_count=0, total_participant_count=1,
            sensor_coverage_ratio=0.0,
            detail="no signals",
        )
        ev = writer.build_sensor_gap_event(s, v)
        assert ev.proposal_type == "sensor_gap_detected"
        assert "sensor" in ev.why_string.lower()

    def test_needs_more_data_event_shape(self):
        s = _make_scenario("scen_f", participants={
            "ZZ": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
        })
        signals = {"llm_intel": 1, "sequence_events": 0,
                   "sensor_observation_ts": 0, "analyst_feedback_fn": 0,
                   "conclusions_contribution": 0}
        decision = guards.GuardDecision(
            can_emit_recall_negative=False,
            can_emit_structure_change=True,
            can_emit_diagnostic=True,
            vitality=guards.VitalityReport(
                state="active", total_signals=10,
                active_participant_count=1, total_participant_count=1,
                sensor_coverage_ratio=1.0, detail="active",
            ),
            signals=signals,
            strength="moderate",
            blocking_reasons=("strength_below_strong",),
        )
        ev = writer.build_needs_more_data_event(s, "ZZ", signals, decision)
        assert ev.proposal_type == "needs_more_data"
        assert ev.target_country == "ZZ"
        assert ev.evidence["signals"] == signals


# ── End-to-end with diagnostic emission ─────────────────────────────────────


class TestEndToEndDiagnosticEmit:
    def test_emit_scenario_dormant(self, fresh_db):
        s = _make_scenario("e2e_dormant", participants={
            "X": {"weight": 0.5, "role": Role.SECONDARY_ALLY},
        })
        v = guards.VitalityReport(
            state="dormant", total_signals=1,
            active_participant_count=1, total_participant_count=1,
            sensor_coverage_ratio=1.0, detail="quiet",
        )
        ev = writer.build_scenario_dormant_event(s, v)
        rid = writer.emit(ev, evidence_strength="moderate",
                          vitality_state="dormant")
        assert rid is not None
        row = fresh_db._get_conn().execute(
            "SELECT proposal_type, vitality_state FROM scenario_proposals "
            "WHERE id=?", (rid,),
        ).fetchone()
        assert row[0] == "scenario_dormant"
        assert row[1] == "dormant"
        assert writer.kind_of(row[0]) == writer.ProposalKind.DIAGNOSTIC


# ── Migration v30 verification ──────────────────────────────────────────────


class TestMigrationV30:
    def test_columns_exist(self, fresh_db):
        cols = [r[1] for r in fresh_db._get_conn().execute(
            "PRAGMA table_info(scenario_proposals)"
        ).fetchall()]
        assert "evidence_strength" in cols
        assert "vitality_state" in cols
