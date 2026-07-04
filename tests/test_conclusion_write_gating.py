"""Change-gated conclusion writes (2026-07-04).

The append-only ledger wrote every conclusion on every ~2min tick: one
week of anomalies = 89,884 rows / 12 distinct states (99.99% redundant,
83% of a 1.7GB DB). The gate keeps replay semantics (latest-row-at-T)
while writing only transitions + hourly heartbeats.
"""
from __future__ import annotations

import os
import time
import uuid

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

import pytest  # noqa: E402

from radar import config  # noqa: E402
from radar.conclusions.base import Conclusion, ConclusionType  # noqa: E402
from radar.conclusions.persistence import (  # noqa: E402
    save_conclusion_gated,
    save_conclusions_batch_gated,
)
from radar.database import db  # noqa: E402

_TAG = "gate" + uuid.uuid4().hex[:6]
_NOW = time.time()


def _c(*, scenario, state, observed_at,
       kind=ConclusionType.THREAT_LEVEL):
    return Conclusion(
        id=f"{_TAG}-" + uuid.uuid4().hex[:10],
        scenario_id=scenario, conclusion_type=kind, state=state,
        confidence=0.8, observed_at=observed_at,
        formula_ref="test", threshold_ref={}, source_urls=(),
        calibration_status={}, final_judgment_disclaimer="test",
        metadata={},
    )


def _rows(scenario, kind="threat_level"):
    return db._get_conn().execute(  # noqa: SLF001
        "SELECT state, observed_at FROM conclusions "
        "WHERE scenario_id = ? AND conclusion_type = ? "
        "ORDER BY observed_at",
        (scenario, kind),
    ).fetchall()


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        conn.execute("DELETE FROM conclusions WHERE id LIKE ?",
                     (f"{_TAG}-%",))
        conn.execute(
            "DELETE FROM inconclusive_continuity_log "
            "WHERE scenario_id LIKE ?", (f"{_TAG}%",),
        )


class TestSingleValuedGate:

    def test_unchanged_state_is_deduplicated(self):
        sid = f"{_TAG}_dedup"
        assert save_conclusion_gated(db, _c(scenario=sid, state="4",
                                            observed_at=_NOW - 300))
        assert not save_conclusion_gated(db, _c(scenario=sid, state="4",
                                                observed_at=_NOW - 180))
        assert not save_conclusion_gated(db, _c(scenario=sid, state="4",
                                                observed_at=_NOW - 60))
        assert len(_rows(sid)) == 1

    def test_state_change_writes_immediately(self):
        sid = f"{_TAG}_chg"
        save_conclusion_gated(db, _c(scenario=sid, state="4",
                                     observed_at=_NOW - 300))
        assert save_conclusion_gated(db, _c(scenario=sid, state="3",
                                            observed_at=_NOW - 180))
        assert len(_rows(sid)) == 2

    def test_flap_writes_every_transition(self):
        """A→B→A must produce 3 rows: comparing against the latest row of
        the TYPE (not per-state) is what keeps replay correct — otherwise
        the return to A would be swallowed and replay would read B."""
        sid = f"{_TAG}_flap"
        save_conclusion_gated(db, _c(scenario=sid, state="4",
                                     observed_at=_NOW - 300))
        save_conclusion_gated(db, _c(scenario=sid, state="3",
                                     observed_at=_NOW - 180))
        assert save_conclusion_gated(db, _c(scenario=sid, state="4",
                                            observed_at=_NOW - 60))
        assert [r["state"] for r in _rows(sid)] == ["4", "3", "4"]

    def test_heartbeat_forces_periodic_write(self, monkeypatch):
        monkeypatch.setattr(config, "V2_CONCLUSION_HEARTBEAT_SEC", 120)
        sid = f"{_TAG}_hb"
        save_conclusion_gated(db, _c(scenario=sid, state="4",
                                     observed_at=_NOW - 300))
        # 121s later, same state → heartbeat row.
        assert save_conclusion_gated(db, _c(scenario=sid, state="4",
                                            observed_at=_NOW - 179))
        assert len(_rows(sid)) == 2

    def test_gate_off_writes_every_tick(self, monkeypatch):
        monkeypatch.setattr(config, "V2_CONCLUSION_WRITE_ON_CHANGE", False)
        sid = f"{_TAG}_off"
        for i in range(3):
            assert save_conclusion_gated(
                db, _c(scenario=sid, state="4",
                       observed_at=_NOW - 300 + i * 60))
        assert len(_rows(sid)) == 3

    def test_deduplicated_tick_still_feeds_continuity(self):
        """Chronic-inconclusive tracking needs the per-tick observation
        stream even when the ledger write is deduplicated."""
        sid = f"{_TAG}_cont"
        from radar.conclusions.base import ConclusionUnavailableReason

        def _unavail(ts):
            return Conclusion(
                id=f"{_TAG}-" + uuid.uuid4().hex[:10],
                scenario_id=sid,
                conclusion_type=ConclusionType.THREAT_LEVEL,
                state=None, confidence=0.0, observed_at=ts,
                formula_ref="test", threshold_ref={}, source_urls=(),
                calibration_status={},
                conclusion_unavailable_reason=(
                    ConclusionUnavailableReason.INSUFFICIENT_DATA),
                final_judgment_disclaimer="test", metadata={},
            )

        save_conclusion_gated(db, _unavail(_NOW - 300))
        save_conclusion_gated(db, _unavail(_NOW - 180))  # deduplicated
        cont = db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM inconclusive_continuity_log "
            "WHERE scenario_id = ?", (sid,),
        ).fetchone()[0]
        assert cont == 2  # open + extend, despite the single ledger row
        assert len(_rows(sid)) == 1


class TestBatchGate:

    def test_identical_anomaly_set_is_deduplicated(self):
        sid = f"{_TAG}_set"
        batch1 = [
            _c(scenario=sid, state="bgp_spike|TW", observed_at=_NOW - 300,
               kind=ConclusionType.ANOMALY),
            _c(scenario=sid, state="gdelt_tone|CN", observed_at=_NOW - 300,
               kind=ConclusionType.ANOMALY),
        ]
        assert save_conclusions_batch_gated(db, batch1) == 2
        batch2 = [
            _c(scenario=sid, state="gdelt_tone|CN", observed_at=_NOW - 180,
               kind=ConclusionType.ANOMALY),
            _c(scenario=sid, state="bgp_spike|TW", observed_at=_NOW - 180,
               kind=ConclusionType.ANOMALY),
        ]
        assert save_conclusions_batch_gated(db, batch2) == 0
        assert len(_rows(sid, "anomaly")) == 2

    def test_set_change_rewrites_full_batch(self):
        sid = f"{_TAG}_setchg"
        save_conclusions_batch_gated(db, [
            _c(scenario=sid, state="bgp_spike|TW", observed_at=_NOW - 300,
               kind=ConclusionType.ANOMALY),
        ])
        written = save_conclusions_batch_gated(db, [
            _c(scenario=sid, state="bgp_spike|TW", observed_at=_NOW - 180,
               kind=ConclusionType.ANOMALY),
            _c(scenario=sid, state="ooni_block|TW", observed_at=_NOW - 180,
               kind=ConclusionType.ANOMALY),
        ])
        assert written == 2  # full batch at one timestamp for replay
        assert len(_rows(sid, "anomaly")) == 3

    def test_empty_batch_is_noop(self):
        assert save_conclusions_batch_gated(db, []) == 0


class TestBatchGateTimestampJitter:
    def test_batch_rows_with_jittered_timestamps_still_dedup(self):
        """Each Conclusion is built with its own time.time(), so rows in
        one tick's batch differ by microseconds. The previous-batch lookup
        must gather the whole batch (a small window around MAX), not just
        the single newest row — otherwise the signature never matches and
        every tick writes (found live 2026-07-04: anomaly kept writing
        ~4 rows/tick post-gate)."""
        sid = f"{_TAG}_jit"
        base = _NOW - 300
        batch1 = [
            _c(scenario=sid, state="llm_intel", observed_at=base + i * 0.01,
               kind=ConclusionType.ANOMALY)
            for i in range(4)
        ]
        assert save_conclusions_batch_gated(db, batch1) == 4
        batch2 = [
            _c(scenario=sid, state="llm_intel",
               observed_at=base + 120 + i * 0.01,
               kind=ConclusionType.ANOMALY)
            for i in range(4)
        ]
        assert save_conclusions_batch_gated(db, batch2) == 0
        assert len(_rows(sid, "anomaly")) == 4


class TestBatchGateIdentitySet:
    def test_multiplicity_flap_does_not_rewrite(self):
        """Anomaly rows carry their identity in metadata (signal_source /
        country / domain), not in state — several rows can share
        state='llm_intel'. Live verification 2026-07-04 showed the count
        of same-identity rows flapping tick to tick (2↔4), defeating a
        multiset signature. The gate compares the IDENTITY SET: same
        identities in different multiplicity must dedup."""
        sid = f"{_TAG}_mult"
        base = _NOW - 300
        batch1 = [
            _c(scenario=sid, state="llm_intel", observed_at=base + i * 0.01,
               kind=ConclusionType.ANOMALY)
            for i in range(4)
        ]
        assert save_conclusions_batch_gated(db, batch1) == 4
        batch2 = [
            _c(scenario=sid, state="llm_intel",
               observed_at=base + 120 + i * 0.01,
               kind=ConclusionType.ANOMALY)
            for i in range(2)
        ]
        assert save_conclusions_batch_gated(db, batch2) == 0

    def test_new_identity_in_metadata_rewrites(self):
        """Same state but a NEW contributing country in metadata is a new
        anomaly identity — the batch must be rewritten."""
        sid = f"{_TAG}_ident"
        base = _NOW - 300
        b1 = [Conclusion(
            id=f"{_TAG}-" + uuid.uuid4().hex[:10], scenario_id=sid,
            conclusion_type=ConclusionType.ANOMALY, state="llm_intel",
            confidence=0.8, observed_at=base, formula_ref="test",
            threshold_ref={}, source_urls=(), calibration_status={},
            final_judgment_disclaimer="test",
            metadata={"signal_source": "llm_intel",
                      "contributing_country": "TW", "domain": "info"},
        )]
        assert save_conclusions_batch_gated(db, b1) == 1
        b2 = [Conclusion(
            id=f"{_TAG}-" + uuid.uuid4().hex[:10], scenario_id=sid,
            conclusion_type=ConclusionType.ANOMALY, state="llm_intel",
            confidence=0.8, observed_at=base + 120, formula_ref="test",
            threshold_ref={}, source_urls=(), calibration_status={},
            final_judgment_disclaimer="test",
            metadata={"signal_source": "llm_intel",
                      "contributing_country": "CN", "domain": "info"},
        )]
        assert save_conclusions_batch_gated(db, b2) == 1
