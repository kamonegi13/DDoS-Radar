"""Tests for radar.shadow_sampler (ADR-025) and the focus_switch_log
schema additions in migration v13."""
from __future__ import annotations

import time

import pytest

from radar.database import RadarDB
from radar.scenarios import Role, Scenario, Participant, SensorTier
from radar.scoring import Signal, compute_scenario_score


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def tdb(tmp_path):
    """Isolated DB at migration head, no shared state."""
    p = str(tmp_path / "test_shadow.db")
    db = RadarDB(p)
    yield db
    db.close()


def _make_scenario(sid: str, name: str, core: str,
                   participants: dict[str, Participant]) -> Scenario:
    return Scenario(
        id=sid,
        name_en=name, name_ja=name,
        description_en="", description_ja="",
        core_country=core,
        state="active", enabled=True, tier=1,
        participants=participants,
    )


@pytest.fixture
def two_scenarios():
    """A focused scenario and a background scenario sharing one participant."""
    focused = _make_scenario(
        "focused_a", "Focused A", "TW",
        {
            "TW": Participant(country="TW", weight=1.0,
                              role=Role.PRIMARY_TARGET),
            "XX": Participant(country="XX", weight=1.0,
                              role=Role.ADVERSARY),
            "US": Participant(country="US", weight=0.8,
                              role=Role.PRIMARY_ALLY),
        },
    )
    background = _make_scenario(
        "background_b", "Background B", "JP",
        {
            "JP": Participant(country="JP", weight=1.0,
                              role=Role.PRIMARY_TARGET),
            "XX": Participant(country="XX", weight=1.0,
                              role=Role.ADVERSARY),
            "US": Participant(country="US", weight=0.6,
                              role=Role.PRIMARY_ALLY),
        },
    )
    return focused, background


def _signal(country: str, raw: float = 2.0,
            signal_source: str = "bgp",
            sensor: str = "ioda_bgp",
            domain: str = "physical") -> Signal:
    return Signal(
        signal_source=signal_source, sensor=sensor,
        observed_at=time.time(), domain=domain,
        countries=[country], raw_score=raw,
        value_display=f"signal for {country}",
    )


# ── Migration v13 schema ────────────────────────────────────────────────────

class TestSchemaV13:
    def test_focus_switch_log_has_source_column(self, tdb):
        cols = tdb._get_conn().execute(
            "PRAGMA table_info(focus_switch_log)").fetchall()
        names = {c[1] for c in cols}
        assert "source" in names
        assert "shadow_score_kind" in names

    def test_existing_rows_default_to_analyst(self, tdb):
        # Insert via legacy positional API (no source) and confirm DEFAULT applies.
        tdb.focus_switch_append(
            scenario_id="x", switched_at=time.time(),
            lite_score=1.0, full_score=2.0, delta=1.0, is_miss=True,
        )
        row = tdb._get_conn().execute(
            "SELECT source, shadow_score_kind FROM focus_switch_log "
            "ORDER BY id DESC LIMIT 1").fetchone()
        assert row["source"] == "analyst"
        assert row["shadow_score_kind"] is None

    def test_shadow_sampler_state_table_exists(self, tdb):
        rows = tdb._get_conn().execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='shadow_sampler_state'").fetchall()
        assert rows


# ── focus_switch_log source filter ──────────────────────────────────────────

class TestFocusSwitchSourceFilter:
    def test_stats_filter_by_source(self, tdb):
        now = time.time()
        tdb.focus_switch_append("a", now, 1.0, 2.0, 1.0, True,
                                source="analyst")
        tdb.focus_switch_append("b", now, 1.0, 1.5, 0.5, False,
                                source="shadow_sampler",
                                shadow_score_kind="piggyback")

        all_stats = tdb.focus_switch_stats(days=1, source=None)
        assert all_stats["total_switches"] == 2
        assert all_stats["source"] == "all"

        analyst_only = tdb.focus_switch_stats(days=1, source="analyst")
        assert analyst_only["total_switches"] == 1
        assert analyst_only["misses"] == 1

        shadow_only = tdb.focus_switch_stats(days=1, source="shadow_sampler")
        assert shadow_only["total_switches"] == 1
        assert shadow_only["misses"] == 0

    def test_detailed_filter_by_source(self, tdb):
        now = time.time()
        tdb.focus_switch_append("a", now, 1.0, 2.0, 1.0, True,
                                source="analyst")
        tdb.focus_switch_append("a", now, 1.0, 1.5, 0.5, False,
                                source="shadow_sampler")

        d_all = tdb.focus_switch_detailed(days=1, source=None)
        assert d_all["total_switches"] == 2

        d_shadow = tdb.focus_switch_detailed(days=1, source="shadow_sampler")
        assert d_shadow["total_switches"] == 1
        assert d_shadow["source"] == "shadow_sampler"


# ── shadow_sampler_state ────────────────────────────────────────────────────

class TestShadowSamplerState:
    def test_get_returns_none_for_missing(self, tdb):
        assert tdb.shadow_sampler_state_get("ghost") is None

    def test_upsert_creates_then_increments(self, tdb):
        t0 = time.time()
        tdb.shadow_sampler_state_upsert("a", t0, 1.0, 2.0, 1.0)
        s1 = tdb.shadow_sampler_state_get("a")
        assert s1["sample_count"] == 1
        assert s1["last_lite_score"] == 1.0

        tdb.shadow_sampler_state_upsert("a", t0 + 10, 1.5, 2.5, 1.0)
        s2 = tdb.shadow_sampler_state_get("a")
        assert s2["sample_count"] == 2
        assert s2["last_sampled_at"] == t0 + 10
        assert s2["last_lite_score"] == 1.5

    def test_least_recent_picks_never_sampled_first(self, tdb):
        t0 = time.time()
        tdb.shadow_sampler_state_upsert("a", t0, 1.0, 2.0, 1.0)
        tdb.shadow_sampler_state_upsert("b", t0 + 100, 1.0, 2.0, 1.0)
        # 'c' has never been sampled — must rank first.
        pick = tdb.shadow_sampler_least_recent_among(["a", "b", "c"])
        assert pick == "c"

    def test_least_recent_picks_oldest_when_all_sampled(self, tdb):
        t0 = time.time()
        tdb.shadow_sampler_state_upsert("a", t0 + 100, 1.0, 2.0, 1.0)
        tdb.shadow_sampler_state_upsert("b", t0 + 50, 1.0, 2.0, 1.0)
        tdb.shadow_sampler_state_upsert("c", t0 + 200, 1.0, 2.0, 1.0)
        assert tdb.shadow_sampler_least_recent_among(["a", "b", "c"]) == "b"

    def test_least_recent_empty_returns_none(self, tdb):
        assert tdb.shadow_sampler_least_recent_among([]) is None


# ── ShadowSampler.record_shadow_sample ──────────────────────────────────────

class TestShadowSampler:
    def _patch_env(self, monkeypatch, tdb, focused, background, *,
                   warmup_sec: int = 0, min_gap_sec: int = 0,
                   max_per_day: int = 200, enabled: bool = True,
                   require_overlap: bool = False):
        """Wire the sampler module to a clean DB and a 2-scenario store."""
        from radar import shadow_sampler as ss
        from radar import scenarios as sc_mod

        monkeypatch.setattr(ss, "SHADOW_SAMPLING_ENABLED", enabled)
        monkeypatch.setattr(ss, "SHADOW_SAMPLING_WARMUP_SEC", warmup_sec)
        monkeypatch.setattr(ss, "SHADOW_SAMPLING_MIN_GAP_SEC", min_gap_sec)
        monkeypatch.setattr(ss, "SHADOW_SAMPLING_MAX_PER_DAY", max_per_day)
        monkeypatch.setattr(ss, "SHADOW_SAMPLING_REQUIRE_OVERLAP", require_overlap)
        # Force warmup to be already elapsed so per-test seconds don't matter.
        monkeypatch.setattr(ss, "_PROCESS_START", 0.0)

        # Lightweight in-memory store stub.
        class _Store:
            def scorable(self):
                return [focused, background]

            def get(self, sid):
                return {"focused_a": focused,
                        "background_b": background}.get(sid)

        monkeypatch.setattr(sc_mod, "scenario_store", _Store())

        # Swap the DB used inside the sampler.
        from radar import database as db_mod
        monkeypatch.setattr(db_mod, "db", tdb)

        return ss.shadow_sampler

    def test_disabled_returns_none(self, tdb, two_scenarios, monkeypatch):
        focused, background = two_scenarios
        sampler = self._patch_env(monkeypatch, tdb, focused, background,
                                  enabled=False)
        result = sampler.record_shadow_sample(
            "focused_a", [_signal("TW")], time.time())
        assert result is None
        assert tdb.focus_switch_stats(days=1)["total_switches"] == 0

    def test_empty_signals_returns_none(self, tdb, two_scenarios, monkeypatch):
        focused, background = two_scenarios
        sampler = self._patch_env(monkeypatch, tdb, focused, background)
        assert sampler.record_shadow_sample(
            "focused_a", [], time.time()) is None
        assert tdb.focus_switch_stats(days=1)["total_switches"] == 0

    def test_records_to_focus_switch_log_with_source(self, tdb,
                                                    two_scenarios,
                                                    monkeypatch):
        focused, background = two_scenarios
        sampler = self._patch_env(monkeypatch, tdb, focused, background)
        # Signal in JP (background's primary target) so full_score > lite_score.
        result = sampler.record_shadow_sample(
            "focused_a", [_signal("JP", raw=3.0)], time.time())
        assert result is not None
        assert result["scenario_id"] == "background_b"

        d = tdb.focus_switch_detailed(days=1, source="shadow_sampler")
        assert d["total_switches"] == 1

    def test_determinism_lite_matches_background_path(self, tdb,
                                                     two_scenarios,
                                                     monkeypatch):
        """I-5: shadow_lite must equal compute_scenario_score(is_focused=False)."""
        focused, background = two_scenarios
        sampler = self._patch_env(monkeypatch, tdb, focused, background)
        signals = [_signal("JP", raw=3.0), _signal("US", raw=1.5)]

        from radar.config import GLOBAL_SIGNAL_WEIGHT, DOMAIN_CAP
        expected_lite = compute_scenario_score(
            background, signals, is_focused=False,
            global_signal_weight=GLOBAL_SIGNAL_WEIGHT,
            domain_cap=DOMAIN_CAP).score
        expected_full = compute_scenario_score(
            background, signals, is_focused=True,
            global_signal_weight=GLOBAL_SIGNAL_WEIGHT,
            domain_cap=DOMAIN_CAP).score

        result = sampler.record_shadow_sample(
            "focused_a", signals, time.time())
        assert abs(result["lite_score"] - float(expected_lite)) < 1e-6
        assert abs(result["full_score"] - float(expected_full)) < 1e-6

    def test_min_gap_blocks_repeat(self, tdb, two_scenarios, monkeypatch):
        focused, background = two_scenarios
        sampler = self._patch_env(monkeypatch, tdb, focused, background,
                                  min_gap_sec=300)
        t0 = time.time()
        first = sampler.record_shadow_sample(
            "focused_a", [_signal("JP")], t0)
        assert first is not None
        # 60s later — within min_gap → should skip (no other candidates).
        second = sampler.record_shadow_sample(
            "focused_a", [_signal("JP")], t0 + 60)
        assert second is None

    def test_max_per_day_caps_writes(self, tdb, two_scenarios, monkeypatch):
        focused, background = two_scenarios
        sampler = self._patch_env(monkeypatch, tdb, focused, background,
                                  max_per_day=1)
        t0 = time.time()
        assert sampler.record_shadow_sample(
            "focused_a", [_signal("JP")], t0) is not None
        # Second call hits the daily cap before any selection logic.
        assert sampler.record_shadow_sample(
            "focused_a", [_signal("JP")], t0 + 1000) is None

    def test_focused_excluded_from_candidates(self, tdb, two_scenarios,
                                              monkeypatch):
        focused, background = two_scenarios
        sampler = self._patch_env(monkeypatch, tdb, focused, background)
        result = sampler.record_shadow_sample(
            "focused_a", [_signal("JP")], time.time())
        assert result is not None
        assert result["scenario_id"] != "focused_a"
