"""Tests for the daily scheduler hook that fires record_failure on
chronic-inconclusive states (NP5+8 / ADR-V2-010, Phase C2).

The scheduler module's daily-tick body is large and tied to gevent;
we exercise its semantics in isolation by importing the chronic
detector + the silent-failure ledger directly. The shape under test
is "for every chronic state, exactly one record_failure call with
category='inconclusive_chronic' fires" — that is the contract Phase C2
adds to radar/scheduler.py.
"""
from __future__ import annotations

import os
import time

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "TestAdminPass123!")

import pytest  # noqa: E402

from radar.conclusions import inconclusive_continuity as ic  # noqa: E402
from radar.conclusions import shadow_metrics as sm  # noqa: E402
from radar.database import db  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_continuity_log():
    conn = db._get_conn()  # noqa: SLF001
    rows = list(conn.execute(
        "SELECT id, observed_at, scenario_id, conclusion_type, "
        "is_available, reason, run_length_sec, first_seen_at, metadata "
        "FROM inconclusive_continuity_log"
    ))
    with conn.writing():
        conn.execute("DELETE FROM inconclusive_continuity_log")
    yield
    with conn.writing():
        conn.execute("DELETE FROM inconclusive_continuity_log")
        for r in rows:
            conn.execute(
                "INSERT INTO inconclusive_continuity_log "
                "(id, observed_at, scenario_id, conclusion_type, "
                " is_available, reason, run_length_sec, first_seen_at, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(r),
            )


@pytest.fixture(autouse=True)
def _reset_silent_failures():
    """Clear silent-failure registry around each test so we can count
    exactly the calls this hook produced."""
    with sm._REGISTRY.lock:  # noqa: SLF001
        before = dict(sm._REGISTRY.by_type)  # noqa: SLF001
        sm._REGISTRY.by_type.clear()  # noqa: SLF001
    yield
    with sm._REGISTRY.lock:  # noqa: SLF001
        sm._REGISTRY.by_type.clear()  # noqa: SLF001
        sm._REGISTRY.by_type.update(before)  # noqa: SLF001


def _insert(scenario_id, conclusion_type, *,
            observed_at, first_seen_at, is_available=0,
            reason="INSUFFICIENT_DATA"):
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        conn.execute(
            "INSERT INTO inconclusive_continuity_log "
            "(observed_at, scenario_id, conclusion_type, is_available, "
            " reason, run_length_sec, first_seen_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (observed_at, scenario_id, conclusion_type, int(is_available),
             reason, max(0.0, observed_at - first_seen_at),
             first_seen_at, "{}"),
        )


# ── Hook semantics ───────────────────────────────────────────────────────────


def _run_chronic_hook():
    """Replicates the scheduler's `_cycle % 24 == 9` branch verbatim
    (kept in sync with radar/scheduler.py). Imported lazily so the
    test module load is cheap."""
    snap = ic.chronic_snapshot(db)
    chronic = snap.get("chronic", []) or []
    for st in chronic:
        sm.record_failure(
            "inconclusive_chronic",
            RuntimeError(
                f"chronic UNAVAILABLE: {st.get('scenario_id')}/"
                f"{st.get('conclusion_type')} for "
                f"{st.get('days_unavailable', 0):.1f}d"
            ),
        )
    return snap


def test_no_chronic_states_records_nothing():
    """All transient → no record_failure calls fire."""
    now = time.time()
    _insert("scenario_a", "threat_level",
            observed_at=now - 1 * 86400.0,
            first_seen_at=now - 1 * 86400.0)
    _run_chronic_hook()
    snap = sm.snapshot()
    assert "inconclusive_chronic" not in snap.get("by_type", {})


def test_two_chronic_states_record_two_failures():
    """Two chronic pairs → exactly two record_failure calls, both
    bucketed under category 'inconclusive_chronic'."""
    now = time.time()
    _insert("scenario_a", "threat_level",
            observed_at=now - 9 * 86400.0,
            first_seen_at=now - 9 * 86400.0)
    _insert("scenario_b", "anomaly",
            observed_at=now - 14 * 86400.0,
            first_seen_at=now - 14 * 86400.0)
    _run_chronic_hook()
    snap = sm.snapshot()
    bucket = snap.get("by_type", {}).get("inconclusive_chronic", {})
    assert bucket.get("failure_count") == 2


def test_inconclusive_chronic_is_not_in_np1_categories():
    """Crucially the new category must NOT pollute the NP1 silent-
    failure surface (FAULT chip). This protects the principle that
    NP5+8 chronic-inconclusive has its own dedicated CHRONIC chip and
    does not double-count toward the NP1 fault count."""
    from radar.routes.conclusions_v2 import (  # noqa: E402
        v2_self_eval as _seal,
    )
    # Black-box: poke the route's source for the category set rather
    # than fire the request (the route's auth + envelope are tested
    # elsewhere). The constant lives next to the assembly site.
    import inspect
    src = inspect.getsource(_seal)
    # The set literal must include the 4 NP1 names but NOT
    # 'inconclusive_chronic'.
    assert "'inconclusive_chronic'" not in src
    assert '"inconclusive_chronic"' not in src
    assert "focused_scoring" in src  # sanity — we found the right set
