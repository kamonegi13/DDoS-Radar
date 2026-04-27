"""Tests for scripts/list_v1_routes.py.

Pins the report shape and the --check-stale gate so the 2026-07-26 sunset
routine can rely on stable JSON contracts and a predictable exit code.

The DB hydrate path is bypassed by stubbing legacy_telemetry.snapshot
with a hand-built dict — we don't want the test depending on a live
radar.db. The route declaration list comes from the real
radar.conclusions.v1_sunset module so the tests fail loud if a route
is added/removed without intent.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

import list_v1_routes as lvr  # noqa: E402


@dataclass(frozen=True)
class _StubStat:
    key: str
    count: int
    last_seen: float
    first_seen: float = 0.0


@pytest.fixture
def fake_telemetry(monkeypatch):
    """Replace legacy_telemetry.snapshot/hydrate so tests don't touch a DB."""

    state: dict[str, _StubStat] = {}

    def _snapshot():
        return dict(state)

    def _hydrate(_db):
        return 0

    # The script does `from radar import legacy_telemetry as lt` inside
    # _list_routes; patch the underlying module so both bindings update.
    from radar import legacy_telemetry as lt
    monkeypatch.setattr(lt, "snapshot", _snapshot)
    monkeypatch.setattr(lt, "hydrate_from_db", _hydrate)

    # Also stub RadarDB so the import + construct doesn't actually open a DB.
    class _StubDB:
        def __init__(self, *a, **kw):
            pass

    monkeypatch.setattr("radar.database.RadarDB", _StubDB)

    return state


# ── _list_routes ───────────────────────────────────────────────────────────


def test_list_routes_returns_one_record_per_declared_route(fake_telemetry):
    records = lvr._list_routes(db_path=None, now=1_800_000_000.0)
    from radar.conclusions.v1_sunset import SUNSETTED_V1_ROUTES
    assert len(records) == len(SUNSETTED_V1_ROUTES)
    keys = {r["telemetry_key"] for r in records}
    expected = {entry[2] for entry in SUNSETTED_V1_ROUTES}
    assert keys == expected


def test_list_routes_zero_count_when_no_telemetry(fake_telemetry):
    records = lvr._list_routes(db_path=None, now=1_800_000_000.0)
    for r in records:
        assert r["count"] == 0
        assert r["last_seen"] == 0.0
        assert r["age_hours_since_last_seen"] is None


def test_list_routes_carries_telemetry_count(fake_telemetry):
    fake_telemetry["v1_sunset_route:/api/threat_data"] = _StubStat(
        key="v1_sunset_route:/api/threat_data",
        count=12,
        last_seen=1_800_000_000.0 - 3600.0,  # 1h ago
    )
    records = lvr._list_routes(db_path=None, now=1_800_000_000.0)
    threat = next(
        r for r in records if r["telemetry_key"] == "v1_sunset_route:/api/threat_data"
    )
    assert threat["count"] == 12
    assert threat["age_hours_since_last_seen"] == pytest.approx(1.0, abs=0.01)


def test_list_routes_days_remaining_decreases_as_now_advances(fake_telemetry):
    early = lvr._list_routes(db_path=None, now=1_700_000_000.0)
    late = lvr._list_routes(db_path=None, now=1_780_000_000.0)
    assert early[0]["days_remaining"] > late[0]["days_remaining"]


# ── _hits_in_window ────────────────────────────────────────────────────────


def test_hits_in_window_includes_recent_only(monkeypatch):
    import time as _time
    monkeypatch.setattr(_time, "time", lambda: 1_800_000_000.0)
    records = [
        {"count": 10, "last_seen": 1_800_000_000.0 - 3 * 86400.0},   # 3d ago
        {"count": 5,  "last_seen": 1_800_000_000.0 - 14 * 86400.0},  # 14d ago
        {"count": 2,  "last_seen": 1_800_000_000.0 - 0.5 * 86400.0}, # 12h ago
    ]
    assert lvr._hits_in_window(records, window_days=7.0) == 12  # 10 + 2
    assert lvr._hits_in_window(records, window_days=1.0) == 2
    assert lvr._hits_in_window(records, window_days=30.0) == 17


# ── main() exit codes ──────────────────────────────────────────────────────


def test_main_default_returns_zero(fake_telemetry, capsys):
    rc = lvr.main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pattern" in out
    assert "hits in last 7d" in out


def test_main_json_emits_parseable_output(fake_telemetry, capsys):
    rc = lvr.main(["--json"])
    assert rc == 0
    import json
    data = json.loads(capsys.readouterr().out)
    assert "records" in data
    assert "hits_last_7d" in data
    assert "hits_last_24h" in data


def test_check_stale_returns_zero_when_no_recent_hits(fake_telemetry, capsys):
    rc = lvr.main(["--check-stale"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Safe to remove" in out


def test_check_stale_returns_one_when_recent_hits_exceed_tolerance(
    fake_telemetry, capsys, monkeypatch
):
    import time as _time
    now_val = 1_800_000_000.0
    monkeypatch.setattr(_time, "time", lambda: now_val)
    fake_telemetry["v1_sunset_route:/api/threat_data"] = _StubStat(
        key="v1_sunset_route:/api/threat_data",
        count=10,
        last_seen=now_val - 3600.0,  # 1h ago — within 7d window
    )
    rc = lvr.main(["--check-stale", "--max-7d-hits", "5"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "FAIL" in err
    assert "10 hits" in err


def test_check_stale_respects_custom_tolerance(fake_telemetry, capsys, monkeypatch):
    import time as _time
    now_val = 1_800_000_000.0
    monkeypatch.setattr(_time, "time", lambda: now_val)
    fake_telemetry["v1_sunset_route:/api/threat_data"] = _StubStat(
        key="v1_sunset_route:/api/threat_data",
        count=8,
        last_seen=now_val - 86400.0,  # 1d ago
    )
    # 8 hits, tolerance 10 → pass
    rc = lvr.main(["--check-stale", "--max-7d-hits", "10"])
    assert rc == 0
    # 8 hits, tolerance 5 → fail
    rc = lvr.main(["--check-stale", "--max-7d-hits", "5"])
    assert rc == 1
