"""Tests for B (stage 2): per-country sequence event firing for
secondary effective_cores in dual-core scenarios.

Stage 1 covered scenario-wide events (NARRATIVE_BURST, SYNC_DDOS) by
adding a scenario_wide flag to _seq_fire. This stage tackles
per-country events whose data was previously only checked against
primary_ec — FIRMS_ANOMALY is the first because the data shape
(list of {"code": cc, ...}) makes the per-ec lookup trivial and the
event is high-value (kinetic strike precursor).

Tests cover the pure helper select_secondary_ec_hits() that decides
which secondary belligerents have matching sensor data and need a
sequence event registered. The helper is sensor-agnostic — it takes
a list of dicts and the country field name — so the same primitive
can be reused for ISR_SURGE, NOTAM_SURGE, etc. in subsequent stages.
"""
import pytest

from radar.scoring import select_secondary_ec_hits


class TestSelectSecondaryEcHits:
    def test_returns_empty_for_single_core(self):
        out = select_secondary_ec_hits(
            effective_cores=["TW"], primary_ec="TW",
            data=[{"code": "TW", "name": "x"}],
            country_field="code",
        )
        assert out == {}

    def test_returns_secondary_with_hits(self):
        out = select_secondary_ec_hits(
            effective_cores=["IL", "IR"], primary_ec="IL",
            data=[{"code": "IR", "lat": 32.0}],
            country_field="code",
        )
        assert "IR" in out
        assert len(out["IR"]) == 1

    def test_excludes_primary_from_result(self):
        """Primary is handled by the existing _seq_fire path; the
        helper must not double-fire it."""
        out = select_secondary_ec_hits(
            effective_cores=["IL", "IR"], primary_ec="IL",
            data=[{"code": "IL"}, {"code": "IR"}],
            country_field="code",
        )
        assert "IL" not in out
        assert "IR" in out

    def test_secondary_without_hits_omitted(self):
        out = select_secondary_ec_hits(
            effective_cores=["IL", "IR"], primary_ec="IL",
            data=[{"code": "TR"}],
            country_field="code",
        )
        assert out == {}

    def test_aggregates_multiple_hits_per_secondary(self):
        out = select_secondary_ec_hits(
            effective_cores=["IL", "IR"], primary_ec="IL",
            data=[
                {"code": "IR", "lat": 32.0},
                {"code": "IR", "lat": 35.0},
                {"code": "TR", "lat": 39.0},
            ],
            country_field="code",
        )
        assert len(out["IR"]) == 2
        assert "TR" not in out

    def test_handles_missing_field_gracefully(self):
        """Sensor rows without the country_field must be skipped, not raise."""
        out = select_secondary_ec_hits(
            effective_cores=["IL", "IR"], primary_ec="IL",
            data=[{"name": "no-code-here"}, {"code": "IR"}],
            country_field="code",
        )
        assert out == {"IR": [{"code": "IR"}]}

    def test_custom_country_field(self):
        """Reusable across sensors: ISR uses 'country', AIS uses 'code', etc."""
        out = select_secondary_ec_hits(
            effective_cores=["IL", "IR"], primary_ec="IL",
            data=[{"country": "IR", "count": 5}],
            country_field="country",
        )
        assert "IR" in out

    def test_falsy_secondary_filtered(self):
        out = select_secondary_ec_hits(
            effective_cores=["IL", "", None, "IR"], primary_ec="IL",
            data=[{"code": "IR"}],
            country_field="code",
        )
        assert list(out.keys()) == ["IR"]
