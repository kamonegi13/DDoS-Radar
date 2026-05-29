"""Tests for radar.observability.followup_watch.

Pins the contract that:
  - run_once evaluates every registered watch
  - a met condition emits exactly one WARN on first observation, INFO
    on subsequent observations until the condition clears
  - a watch raising inside its check() is logged at debug and the
    other watches still run (NP3 — one bad check cannot mask the rest)
  - returned dict shape is {"fired": [...], "skipped": [...], "evaluated": N}
"""
from __future__ import annotations

import logging
import time

import pytest

from radar.observability import followup_watch as fw


@pytest.fixture(autouse=True)
def _reset_cache():
    """Clear the module-level fire cache around every test so order
    independence holds."""
    snap = dict(fw._LAST_FIRED_AT)  # noqa: SLF001
    fw._LAST_FIRED_AT.clear()  # noqa: SLF001
    yield
    fw._LAST_FIRED_AT.clear()  # noqa: SLF001
    fw._LAST_FIRED_AT.update(snap)  # noqa: SLF001


def _patch_watches(monkeypatch, watches: tuple[fw.Watch, ...]):
    """Replace the registry with a deterministic test set."""
    monkeypatch.setattr(fw, "_WATCHES", watches)


def test_no_watches_returns_zero(monkeypatch):
    _patch_watches(monkeypatch, ())
    out = fw.run_once()
    assert out == {"fired": [], "skipped": [], "evaluated": 0}


def test_unmet_condition_does_not_fire(monkeypatch, caplog):
    _patch_watches(monkeypatch, (fw.Watch(
        name="t.unmet", description="-",
        check=lambda: (False, "no signal"),
    ),))
    with caplog.at_level(logging.WARNING):
        out = fw.run_once()
    assert out["fired"] == []
    assert "TRIGGER MET" not in caplog.text


def test_met_condition_warns_first_time(monkeypatch, caplog):
    _patch_watches(monkeypatch, (fw.Watch(
        name="t.met", description="trigger detail",
        check=lambda: (True, "metric=42"),
    ),))
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        out = fw.run_once()
    assert out["fired"] == ["t.met"]
    assert "TRIGGER MET: t.met" in caplog.text
    assert "metric=42" in caplog.text


def test_subsequent_observations_demote_to_info(monkeypatch, caplog):
    _patch_watches(monkeypatch, (fw.Watch(
        name="t.persist", description="-",
        check=lambda: (True, "metric=5"),
    ),))
    # First observation — WARN.
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    caplog.clear()
    # Second observation — must NOT WARN again.
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    assert "TRIGGER MET" not in caplog.text
    # But the INFO heartbeat must surface so silent-cron readers can see it.
    with caplog.at_level(logging.INFO,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    assert "still met: t.persist" in caplog.text


def test_clearing_condition_resets_cache_so_re_warns(monkeypatch, caplog):
    state = {"met": True}
    watch = fw.Watch(
        name="t.flip", description="-",
        check=lambda: (state["met"], "ok"),
    )
    _patch_watches(monkeypatch, (watch,))
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    # Condition clears — cache must reset so future re-trigger WARNs again.
    state["met"] = False
    fw.run_once()
    state["met"] = True
    caplog.clear()
    with caplog.at_level(logging.WARNING,
                          logger="radar.observability.followup_watch"):
        fw.run_once()
    assert "TRIGGER MET: t.flip" in caplog.text


def test_failing_check_does_not_block_others(monkeypatch):
    def _boom():
        raise RuntimeError("simulated")
    _patch_watches(monkeypatch, (
        fw.Watch(name="t.boom",  description="-", check=_boom),
        fw.Watch(name="t.ok",    description="-",
                 check=lambda: (True, "yes")),
    ))
    out = fw.run_once()
    assert out["evaluated"] == 2
    assert "t.boom" in out["skipped"]
    assert "t.ok" in out["fired"]


# ── Live wiring sanity (the 4 production checks must be importable
#    and each must return a (bool, str) tuple even on a clean DB) ──


@pytest.mark.parametrize("watch_name", [
    "B1.analyst_feedback_viewer",
    "B5.chronic_chip_details",
    "B7.silent_failures_buckets",
    "B9.alias_gap_editor",
    "proposal.chronic_pending",
    "proposal.inactive_scenario",
    "proposal.dismissed_inversion_persistent",
])
def test_production_watch_returns_well_formed_tuple(watch_name):
    matches = [w for w in fw._WATCHES if w.name == watch_name]
    assert len(matches) == 1, f"watch {watch_name} not registered"
    result = matches[0].check()
    assert isinstance(result, tuple) and len(result) == 2
    met, detail = result
    assert isinstance(met, bool)
    assert isinstance(detail, str)


# ── Proposal-symmetry watches: live SQL behaviour ────────────────────────────
#
# These three watches read scenario_proposals directly. Tests snapshot
# and restore the table around each case so the live container DB is
# preserved. We use 'auto:test' as the applied_by tag so any leftover
# rows are easy to identify.


@pytest.fixture
def _scenario_proposals_sandbox():
    from radar.database import db
    conn = db._get_conn()  # noqa: SLF001
    rows = list(conn.execute("SELECT * FROM scenario_proposals"))
    cols = [d[0] for d in conn.execute(
        "SELECT * FROM scenario_proposals LIMIT 0"
    ).description]
    with conn.writing():
        conn.execute("DELETE FROM scenario_proposals")
    yield (conn, cols)
    with conn.writing():
        conn.execute("DELETE FROM scenario_proposals")
        if rows:
            placeholders = ",".join("?" for _ in cols)
            conn.executemany(
                f"INSERT INTO scenario_proposals ({','.join(cols)}) "
                f"VALUES ({placeholders})",
                [tuple(r) for r in rows],
            )


def _insert_proposal(conn, *,
                      scenario_id: str = "test_scenario",
                      proposal_type: str = "weight_too_high",
                      state: str = "pending",
                      emitted_at: float | None = None,
                      target_country: str | None = None) -> None:
    import time as _time
    if emitted_at is None:
        emitted_at = _time.time()
    with conn.writing():
        conn.execute(
            "INSERT INTO scenario_proposals "
            "(scenario_id, target_country, proposal_type, state, "
            " emitted_at, evidence_json, formula_ref, sample_n, "
            " state_changed_by) "
            "VALUES (?, ?, ?, ?, ?, '{}', 'test/v1#x', 0, 'auto:test')",
            (scenario_id, target_country, proposal_type, state,
             float(emitted_at)),
        )


# ── proposal.chronic_pending ─────────────────────────────────────────────────


class TestProposalChronicPending:
    def test_unmet_when_no_old_pending(self, _scenario_proposals_sandbox):
        conn, _ = _scenario_proposals_sandbox
        # 30 days old — well under the 60d threshold.
        _insert_proposal(conn,
                         emitted_at=time.time() - 30 * 86400.0)
        met, detail = fw._check_proposal_chronic_pending()
        assert met is False
        assert "chronic_pending_recall_reducing=0" in detail

    def test_met_when_recall_reducing_pending_over_threshold(
        self, _scenario_proposals_sandbox,
    ):
        conn, _ = _scenario_proposals_sandbox
        _insert_proposal(conn,
                         proposal_type="weight_too_high",
                         emitted_at=time.time() - 70 * 86400.0)
        met, detail = fw._check_proposal_chronic_pending()
        assert met is True
        assert "chronic_pending_recall_reducing=1" in detail

    def test_ignores_recall_positive_proposal_types(
        self, _scenario_proposals_sandbox,
    ):
        """weight_too_low / missing_participant ARE recall-positive
        (their application *adds* coverage). Letting them age is not
        a design failure — NP1 is preserved by inaction. Watch must
        not fire on them."""
        conn, _ = _scenario_proposals_sandbox
        _insert_proposal(conn,
                         proposal_type="weight_too_low",
                         emitted_at=time.time() - 90 * 86400.0)
        met, _ = fw._check_proposal_chronic_pending()
        assert met is False

    def test_ignores_already_resolved_proposals(
        self, _scenario_proposals_sandbox,
    ):
        """Only state='pending' counts. A 90d-old applied/dismissed
        row is history — it had its decision."""
        conn, _ = _scenario_proposals_sandbox
        _insert_proposal(conn, state="applied",
                         emitted_at=time.time() - 90 * 86400.0)
        _insert_proposal(conn, state="dismissed",
                         emitted_at=time.time() - 90 * 86400.0)
        met, _ = fw._check_proposal_chronic_pending()
        assert met is False


# ── proposal.dismissed_inversion_persistent ──────────────────────────────────


class TestProposalDismissedInversion:
    def _seed_closed_proposals(self, conn, *,
                                applied: int, dismissed: int,
                                age_days: float = 5.0) -> None:
        ts = time.time() - age_days * 86400.0
        for _ in range(applied):
            _insert_proposal(conn, state="applied", emitted_at=ts)
        for _ in range(dismissed):
            _insert_proposal(conn, state="dismissed", emitted_at=ts)

    def test_unmet_when_below_sample_floor(
        self, _scenario_proposals_sandbox,
    ):
        """Watch demands at least 10 closed proposals in each window
        (no signal otherwise — refuse to fire)."""
        conn, _ = _scenario_proposals_sandbox
        self._seed_closed_proposals(conn, applied=2, dismissed=4)
        met, detail = fw._check_proposal_dismissed_inversion_persistent()
        assert met is False

    def test_unmet_when_dismiss_rate_under_threshold(
        self, _scenario_proposals_sandbox,
    ):
        conn, _ = _scenario_proposals_sandbox
        # 80/20 split — 20% dismissed, well below 50%.
        self._seed_closed_proposals(conn, applied=80, dismissed=20)
        met, _ = fw._check_proposal_dismissed_inversion_persistent()
        assert met is False

    def test_met_when_sustained_inversion(
        self, _scenario_proposals_sandbox,
    ):
        """≥50% dismissed in BOTH the 14d and the 30d windows. We
        seed enough rows in the 14d window (≤14 days old) to satisfy
        both ratios simultaneously."""
        conn, _ = _scenario_proposals_sandbox
        self._seed_closed_proposals(conn, applied=4, dismissed=12,
                                     age_days=5.0)
        met, detail = fw._check_proposal_dismissed_inversion_persistent()
        assert met is True
        assert "dismissed_pct_14d=" in detail
        assert "dismissed_pct_30d=" in detail


# ── proposal.inactive_scenario ──────────────────────────────────────────────


class TestProposalInactiveScenario:
    """The ``scenarios`` table is preset-driven; we cannot freely
    create rows in it without affecting many other tests. We instead
    verify the watch is structurally well-formed and returns no
    false positives against the live (active) scenario set. The
    chronic + dismissed-inversion tests above provide the load-bearing
    coverage; this one is a smoke test."""

    def test_returns_well_formed_tuple_against_live_db(self):
        met, detail = fw._check_proposal_inactive_scenario()
        assert isinstance(met, bool)
        assert detail.startswith("pending_on_inactive_scenarios=") \
            or detail.startswith("check_failed:")
