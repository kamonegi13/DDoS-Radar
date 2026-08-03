"""Tests for scripts/remediate_cross_scenario_labels.py — the 2026-08-02
cross-scenario attribution remediation.

Uses a throwaway sqlite file (NOT the shared test DB): the script is a
raw-sqlite one-shot that must run inside the container against prod, so
tests pin its selection logic against real note strings from the
contaminated production window.
"""

from __future__ import annotations

import importlib
import json
import sqlite3
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))


@pytest.fixture()
def remediation(tmp_path, monkeypatch):
    """Import the script module pointed at a temp DB + temp geo file."""
    db_path = tmp_path / "radar.db"
    geo_path = tmp_path / "geo_data.json"
    geo_path.write_text(json.dumps({
        "SCENARIOS": {
            "korean_peninsula": {"participants": {
                "KR": {"role": "primary_target"},
                "KP": {"role": "adversary"},
                "US": {"role": "primary_ally"},
                "JP": {"role": "forward_base"},
                "CN": {"role": "strategic_observer"},
            }},
            "middle_east": {"participants": {
                "IL": {"role": "principal_belligerent"},
                "IR": {"role": "principal_belligerent"},
                "YE": {"role": "proxy_front"},
                "US": {"role": "force_projection"},
            }},
        },
    }))
    monkeypatch.setenv("RADAR_DB_PATH", str(db_path))
    monkeypatch.setenv("RADAR_GEO_PATH", str(geo_path))
    import remediate_cross_scenario_labels as mod
    importlib.reload(mod)  # re-read env-derived module constants

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE analyst_feedback ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " conclusion_id TEXT, label TEXT, analyst_id TEXT,"
        " observed_at REAL, observed_outcome_url TEXT, notes TEXT)"
    )
    conn.execute(
        "CREATE TABLE threshold_history ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " emitted_at REAL, key TEXT, value TEXT, scope_scenario_id TEXT,"
        " effective_from REAL, effective_to REAL, derived_from TEXT,"
        " applied_by TEXT, revertible_to_id INTEGER, sample_n INTEGER,"
        " formula_ref TEXT, evidence_json TEXT, magnitude_pct REAL,"
        " state TEXT)"
    )
    conn.commit()
    yield mod, conn
    conn.close()


def _label(conn, label, analyst_id, notes):
    conn.execute(
        "INSERT INTO analyst_feedback "
        "(conclusion_id, label, analyst_id, observed_at, notes) "
        "VALUES ('c1', ?, ?, 1000.0, ?)",
        (label, analyst_id, notes),
    )
    conn.commit()


def test_supporting_role_episode_is_contaminated(remediation):
    mod, conn = remediation
    # Real production note (07-27): a US-anchored Iran article graded
    # korean_peninsula FALSE_NEGATIVE.
    _label(conn, "FALSE_NEGATIVE", "auto:rss",
           "episode=korean_peninsula/US/2026-07-27 rss/regex: fatalities=1 "
           "expected_severity>=3 tool_TL=5(sev=1) ticks_in_window=72 "
           "(Iran halts strikes as Trump gives space to talks)")
    attribution = mod.load_attribution_sets(conn)
    contaminated, stats = mod.find_contaminated(conn, attribution)
    assert len(contaminated) == 1
    assert stats["purge:korean_peninsula/FALSE_NEGATIVE"] == 1


def test_conflict_party_episode_is_kept(remediation):
    mod, conn = remediation
    _label(conn, "FALSE_NEGATIVE", "auto:rss",
           "episode=korean_peninsula/KP/2026-07-05 rss/regex: fatalities=1 "
           "expected_severity>=3 tool_TL=4(sev=2) ticks_in_window=22 "
           "(North Korea's Kim oversees latest naval weapons tests)")
    _label(conn, "TRUE_POSITIVE", "auto:rss",
           "episode=middle_east/IR/2026-07-18 rss/regex: fatalities=1 "
           "expected_severity>=3 tool_TL=3(sev=3) ticks_in_window=75 "
           "(Iran says tankers exploded from Hormuz mines)")
    attribution = mod.load_attribution_sets(conn)
    contaminated, stats = mod.find_contaminated(conn, attribution)
    assert contaminated == []
    assert stats["kept"] == 2


def test_non_rss_and_unknown_scenarios_untouched(remediation):
    mod, conn = remediation
    _label(conn, "TRUE_POSITIVE", "auto:gdelt",
           "auto-correlation: ACLED=0 GDELT=1 top_severity=1")
    _label(conn, "FALSE_NEGATIVE", "auto:rss",
           "episode=retired_scenario/US/2026-07-01 rss/regex: fatalities=1 "
           "expected_severity>=3 tool_TL=5(sev=1) ticks_in_window=10 (x)")
    attribution = mod.load_attribution_sets(conn)
    contaminated, stats = mod.find_contaminated(conn, attribution)
    assert contaminated == []
    assert stats["unknown_scenario_kept"] == 1


def test_db_participants_override_presets(remediation):
    mod, conn = remediation
    # Admin config in the DB says CN was promoted to adversary for korea:
    # the DB view must win over the geo preset.
    conn.execute(
        "CREATE TABLE scenario_participants "
        "(scenario_id TEXT, country TEXT, weight REAL, role TEXT)"
    )
    for cc, role in [("KR", "primary_target"), ("KP", "adversary"),
                     ("CN", "adversary"), ("US", "primary_ally")]:
        conn.execute(
            "INSERT INTO scenario_participants VALUES "
            "('korean_peninsula', ?, 1.0, ?)", (cc, role),
        )
    conn.commit()
    attribution = mod.load_attribution_sets(conn)
    assert attribution["korean_peninsula"] == frozenset({"KR", "KP", "CN"})
    # Scenario absent from DB keeps its preset-derived set.
    assert attribution["middle_east"] == frozenset({"IL", "IR", "YE"})


def test_apply_purges_and_exports(remediation, tmp_path):
    mod, conn = remediation
    _label(conn, "FALSE_NEGATIVE", "auto:rss",
           "episode=korean_peninsula/CN/2026-07-19 rss/regex: fatalities=1 "
           "expected_severity>=3 tool_TL=4(sev=2) ticks_in_window=75 "
           "(Japanese officials open X accounts to counter China)")
    attribution = mod.load_attribution_sets(conn)
    contaminated, _ = mod.find_contaminated(conn, attribution)
    result = mod.purge_rows(conn, contaminated, apply=True)
    assert result["purged"] == 1
    left = conn.execute("SELECT COUNT(*) FROM analyst_feedback").fetchone()[0]
    assert left == 0
    assert Path(result["export"]).exists()


def test_threshold_reset_supersedes_active_calibrator_rows(remediation):
    mod, conn = remediation
    conn.execute(
        "INSERT INTO threshold_history "
        "(emitted_at, key, value, scope_scenario_id, effective_from,"
        " derived_from, applied_by, sample_n, formula_ref, evidence_json,"
        " magnitude_pct, state) VALUES "
        "(100.0, 'tl_thresholds.korean_peninsula.tl3_total', '3.258',"
        " 'korean_peninsula', 100.0, 'x', 'auto:tl_calibrator', 0, 'x',"
        " '{}', 5.0, 'active')"
    )
    conn.commit()
    results = mod.reset_calibrator_thresholds(conn, apply=True)
    assert results == [{
        "key": "tl_thresholds.korean_peninsula.tl3_total",
        "prior": 3.258, "reset_to": 4.0,
    }]
    states = conn.execute(
        "SELECT state, value, applied_by FROM threshold_history "
        "ORDER BY id"
    ).fetchall()
    assert states[0][0] == "superseded"
    assert states[1] == ("active", "4.0", mod.RESET_APPLIED_BY)
