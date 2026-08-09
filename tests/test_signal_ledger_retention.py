"""WP-0.1 — signal-ledger retention 60d (v3 parity prerequisite).

S5-VERIF-018: the signal-level ledger must retain at least 2x the
30-day parity window (default 60 days). The old sensor_observation_ts
TTL of 24h made a 30-day replay physically impossible (D2 G-05), which
is why the parity-eligible date is "this change ships + 30 days".

Three layers are covered here because G-15 taught us that a registered
key is not necessarily a *read* key:

  1. the key is registered with the declarative registry,
  2. the resolver actually returns it (3-layer resolution path),
  3. the scoring-tick call site consumes the resolved value
     (source-level wiring guard until WP-1.2 reachability checks land).
"""
import os
import time
import uuid
from pathlib import Path

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar import config_layered
from radar.config import SIGNAL_LEDGER_RETENTION_DAYS_DEFAULT, signal_ledger_ttl_sec
from radar.database import db


class TestRegistryKey:
    def test_key_is_registered_with_60d_default(self):
        meta = config_layered.get_meta("SIGNAL_LEDGER_RETENTION_DAYS")
        assert meta is not None, "SIGNAL_LEDGER_RETENTION_DAYS not registered"
        assert meta.default == 60
        assert meta.type_ == "int"
        assert meta.immutable is False

    def test_minimum_is_parity_floor(self):
        # S5-VERIF-018: retention MUST be >= 2x the 30d parity window.
        meta = config_layered.get_meta("SIGNAL_LEDGER_RETENTION_DAYS")
        assert meta.min_value == 60

    def test_resolver_returns_default(self):
        assert config_layered.get_config("SIGNAL_LEDGER_RETENTION_DAYS") == 60

    def test_ttl_helper_converts_days_to_seconds(self):
        assert signal_ledger_ttl_sec() == SIGNAL_LEDGER_RETENTION_DAYS_DEFAULT * 86400.0


class TestSensorObsPrune:
    @pytest.fixture
    def probe_rows(self):
        """Insert rows at 59d and 61d age; cleanup by probe sensor name."""
        probe = f"test_{uuid.uuid4().hex[:8]}"
        now = time.time()
        conn = db._get_conn()
        with conn.writing():
            for age_days in (59, 61):
                conn.execute(
                    "INSERT OR REPLACE INTO sensor_observation_ts "
                    "(sensor, scope, ts, score, baseline, status) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (probe, "focused", now - age_days * 86400, 1.0, None, "OK"),
                )
        yield probe, now
        with conn.writing():
            conn.execute(
                "DELETE FROM sensor_observation_ts WHERE sensor = ?", (probe,),
            )

    def _ages_days(self, probe: str, now: float) -> list[int]:
        rows = db._get_conn().execute(
            "SELECT ts FROM sensor_observation_ts WHERE sensor = ? ORDER BY ts",
            (probe,),
        ).fetchall()
        return [round((now - r[0]) / 86400) for r in rows]

    def test_record_prunes_only_rows_beyond_ttl(self, probe_rows):
        probe, now = probe_rows
        db.sensor_obs_record(
            sensor=probe, scope="focused", ts=now, score=2.0,
            ttl_sec=60 * 86400.0,
        )
        ages = self._ages_days(probe, now)
        assert 61 not in ages, "row older than 60d must be pruned"
        assert 59 in ages, "row within 60d must survive"
        assert 0 in ages, "the new observation itself must be recorded"

    def test_ttl_sec_has_no_hardcoded_default(self):
        # The 86400.0 default was the G-05 defect. The caller must decide.
        with pytest.raises(TypeError):
            db.sensor_obs_record(sensor="x", scope="focused", ts=time.time(), score=0.0)


class TestCallSiteWiring:
    def test_scoring_tick_passes_resolved_ttl(self):
        """G-15 guard: registered is not read. Until WP-1.2 provides runtime
        reachability checks, pin the call site to the resolver helper."""
        src = Path(__file__).resolve().parent.parent.joinpath(
            "radar", "routes", "core.py").read_text(encoding="utf-8")
        assert "_obs_ttl_sec = signal_ledger_ttl_sec()" in src, (
            "scoring tick must resolve the ttl via signal_ledger_ttl_sec()"
        )
        call = src[src.index("_db.sensor_obs_record"):]
        call = call[:call.index("except")]
        assert "ttl_sec=_obs_ttl_sec" in call, (
            "scoring tick must pass the resolved ttl so the retention knob "
            "actually flows through 3-layer resolution"
        )
