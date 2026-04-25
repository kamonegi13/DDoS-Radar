"""Tests for v2.0 Conclusion model (Phase 0 scaffolding).

Validates the unified output schema introduced by docs/design/v2-migration.md.
Covers ADR-V2-001 (single schema), ADR-V2-008 (append-only ledger compatibility),
and constraint ⑥ (NP7 disclaimer required).
"""

from __future__ import annotations

import json
import time

import pytest

from radar.conclusions import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    new_conclusion_id,
)


_DISCLAIMER = "Tool conclusion only — final judgment by organizational process."


def _base_kwargs(**overrides) -> dict:
    """Return a valid Conclusion kwarg dict; tests override fields per case."""
    base = {
        "id": new_conclusion_id(),
        "scenario_id": "taiwan_contingency",
        "conclusion_type": ConclusionType.THREAT_LEVEL,
        "state": "3",
        "confidence": 0.78,
        "observed_at": time.time(),
        "formula_ref": "radar/scoring.py#derive_tl@v2.0.1",
        "threshold_ref": {"total": 9.0, "physical": 3.0},
        "source_urls": ("https://example.com/source1",),
        "final_judgment_disclaimer": _DISCLAIMER,
    }
    base.update(overrides)
    return base


def test_conclusion_id_is_unique() -> None:
    assert new_conclusion_id() != new_conclusion_id()


def test_minimal_threat_level_conclusion_constructs() -> None:
    c = Conclusion(**_base_kwargs())
    assert c.is_available()
    assert c.conclusion_type is ConclusionType.THREAT_LEVEL
    assert c.state == "3"
    assert c.confidence == 0.78


def test_unavailable_conclusion_requires_null_state() -> None:
    """NP5+8 (a): unavailable_reason and state are mutually exclusive."""
    with pytest.raises(ValueError, match="state=None"):
        Conclusion(
            **_base_kwargs(
                state="3",
                conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
            )
        )


def test_available_conclusion_requires_non_null_state() -> None:
    with pytest.raises(ValueError, match="non-null state"):
        Conclusion(**_base_kwargs(state=None))


def test_unavailable_conclusion_with_null_state_is_valid() -> None:
    c = Conclusion(
        **_base_kwargs(
            state=None,
            confidence=0.0,
            conclusion_unavailable_reason=ConclusionUnavailableReason.INSUFFICIENT_DATA,
        )
    )
    assert not c.is_available()
    assert c.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA


def test_disclaimer_is_required() -> None:
    """Constraint ⑥ from v2-migration.md §2 — NP7 disclaimer cannot be empty."""
    with pytest.raises(ValueError, match="final_judgment_disclaimer"):
        Conclusion(**_base_kwargs(final_judgment_disclaimer=""))


@pytest.mark.parametrize("bad_conf", [-0.01, 1.01, 2.0, -1.0])
def test_confidence_must_be_between_zero_and_one(bad_conf: float) -> None:
    with pytest.raises(ValueError, match="confidence must be"):
        Conclusion(**_base_kwargs(confidence=bad_conf))


def test_conclusion_is_frozen() -> None:
    """NP6: once derived, conclusions are immutable downstream."""
    c = Conclusion(**_base_kwargs())
    with pytest.raises(Exception):
        c.state = "5"  # type: ignore[misc]


def test_to_dict_serialization_round_trip() -> None:
    c = Conclusion(
        **_base_kwargs(
            llm_prompt_sha256="a" * 64,
            calibration_status={"sampler": "OK", "drift": 0.05, "sample_n": 240},
            metadata={"importance_score": 87},
        )
    )
    d = c.to_dict()
    assert d["conclusion_type"] == "threat_level"
    assert d["state"] == "3"
    assert d["llm_prompt_sha256"] == "a" * 64
    assert d["calibration_status"]["sampler"] == "OK"
    assert d["metadata"]["importance_score"] == 87
    assert d["final_judgment_disclaimer"] == _DISCLAIMER


def test_to_db_row_serializes_json_fields() -> None:
    c = Conclusion(
        **_base_kwargs(
            calibration_status={"sampler": "OK"},
            metadata={"importance_score": 50},
        )
    )
    row = c.to_db_row()
    # JSON-encoded fields must be strings the DB can store.
    assert isinstance(row["threshold_ref"], str)
    assert isinstance(row["source_urls"], str)
    assert isinstance(row["calibration_status"], str)
    assert isinstance(row["metadata"], str)
    # Round-trip back to ensure it's valid JSON.
    assert json.loads(row["threshold_ref"]) == {"total": 9.0, "physical": 3.0}
    assert json.loads(row["source_urls"]) == ["https://example.com/source1"]
    assert json.loads(row["metadata"]) == {"importance_score": 50}


def test_unavailable_reason_serializes_to_string() -> None:
    c = Conclusion(
        **_base_kwargs(
            state=None,
            confidence=0.0,
            conclusion_unavailable_reason=ConclusionUnavailableReason.SENSOR_DEGRADED,
        )
    )
    row = c.to_db_row()
    assert row["conclusion_unavailable_reason"] == "sensor_degraded"
    assert row["state"] is None


def test_all_conclusion_types_construct() -> None:
    """Smoke test that the schema accepts all 5 domains from CLAUDE.md tool def."""
    for ct in ConclusionType:
        c = Conclusion(**_base_kwargs(conclusion_type=ct))
        assert c.conclusion_type is ct


def test_db_migration_v19_creates_conclusions_table(tmp_path) -> None:
    """Smoke test for migration v19 — conclusions table exists with expected cols."""
    import sqlite3
    from radar.database import RadarDB

    db_path = tmp_path / "test_v19.db"
    db = RadarDB(str(db_path))

    with sqlite3.connect(str(db_path)) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(conclusions)")}
    expected = {
        "id", "scenario_id", "conclusion_type", "state", "confidence",
        "observed_at", "formula_ref", "threshold_ref", "source_urls",
        "llm_prompt_sha256", "calibration_status",
        "conclusion_unavailable_reason", "metadata",
    }
    assert expected.issubset(cols), f"Missing columns: {expected - cols}"


def test_db_migration_v20_creates_llm_prompts_and_fk_column(tmp_path) -> None:
    """Smoke test for migration v20 — llm_prompts table + llm_call_log.prompt_sha256."""
    import sqlite3
    from radar.database import RadarDB

    db_path = tmp_path / "test_v20.db"
    db = RadarDB(str(db_path))

    with sqlite3.connect(str(db_path)) as conn:
        prompt_cols = {row[1] for row in conn.execute("PRAGMA table_info(llm_prompts)")}
        call_cols = {row[1] for row in conn.execute("PRAGMA table_info(llm_call_log)")}

    assert {"prompt_sha256", "prompt_text", "model", "use_count"}.issubset(prompt_cols)
    assert "prompt_sha256" in call_cols, "llm_call_log must gain prompt_sha256 FK col"
