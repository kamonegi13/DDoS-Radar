"""Tests for B (stage 1): symmetric sequence-event registration in
dual-core scenarios for scenario-wide event types.

Background (ADR-009 follow-up):
  In dual-core scenarios (core_country=null, two PRINCIPAL_BELLIGERENT
  participants), the existing _seq_fire() helper promotes the spike-
  leader to focused_country and registers events ONLY for that primary
  belligerent. The secondary belligerent's sequence chain stays silent
  even when the underlying signal is scenario-wide (e.g. NARRATIVE_BURST
  reflects a theater-aggregate Z-score that applies symmetrically to
  both belligerents, not just the primary).

  This tests the pure helper resolve_seq_fire_targets() that decides
  the registration target list. Per-country events that only checked
  primary's data continue to fire for primary alone (correctness:
  honest provenance over breadth). Scenario-wide events fire for
  every effective_core symmetrically.
"""
import pytest

from radar.scoring import resolve_seq_fire_targets


class TestResolveSeqFireTargets:
    def test_single_core_returns_focused_country(self):
        out = resolve_seq_fire_targets(
            focused_country="TW", effective_cores=["TW"], scenario_wide=False,
        )
        assert out == ["TW"]

    def test_single_core_scenario_wide_returns_focused_country(self):
        out = resolve_seq_fire_targets(
            focused_country="TW", effective_cores=["TW"], scenario_wide=True,
        )
        assert out == ["TW"]

    def test_dual_core_per_country_returns_primary_only(self):
        """Per-country events: data was only checked against primary,
        so registering for secondary would be a false-provenance event."""
        out = resolve_seq_fire_targets(
            focused_country="IL",
            effective_cores=["IL", "IR"],
            scenario_wide=False,
        )
        assert out == ["IL"]

    def test_dual_core_scenario_wide_returns_both(self):
        """Scenario-wide events (NARRATIVE_BURST, SYNC_DDOS): the signal
        applies symmetrically to all belligerents; both chains should
        accrue the event so cmedium drift evaluation sees it."""
        out = resolve_seq_fire_targets(
            focused_country="IL",
            effective_cores=["IL", "IR"],
            scenario_wide=True,
        )
        assert out == ["IL", "IR"]

    def test_empty_strings_filtered(self):
        out = resolve_seq_fire_targets(
            focused_country=None,
            effective_cores=["", "IL", None, "IR"],
            scenario_wide=True,
        )
        assert out == ["IL", "IR"]

    def test_no_targets_returns_empty(self):
        out = resolve_seq_fire_targets(
            focused_country=None, effective_cores=[], scenario_wide=True,
        )
        assert out == []

    def test_dedup_secondary_equals_primary(self):
        """Defensive: if effective_cores accidentally contains the same
        country twice, the resolved list still dedupes."""
        out = resolve_seq_fire_targets(
            focused_country=None,
            effective_cores=["IL", "IR", "IL"],
            scenario_wide=True,
        )
        assert out == ["IL", "IR"]

    def test_dual_core_per_country_with_empty_focused_country(self):
        """If focused_country wasn't promoted (still empty) and the event
        is per-country, fall back to all effective_cores so we don't
        silently drop the event."""
        out = resolve_seq_fire_targets(
            focused_country=None,
            effective_cores=["IL", "IR"],
            scenario_wide=False,
        )
        assert out == ["IL", "IR"]
