"""Tests for ACLED + GDELT auto-correlation ETL — ADR-V2-005.

Covers:
- Classifier rules (FALSE_NEGATIVE > TRUE_POSITIVE > FALSE_POSITIVE >
  TRUE_NEGATIVE > None) with deterministic mock evidence.
- Provenance tagging — ``analyst_id`` carries which source(s) corroborated.
- Idempotency — re-running over the same (conclusion, source) pair does not
  produce duplicate analyst_feedback rows.
- ACLED client graceful degradation when creds are missing.
- Window edge cases — events at ``observed_at`` are inclusive, events after
  the forward window are ignored, FALSE_POSITIVE only fires once the
  horizon has fully elapsed.
"""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")
os.environ.setdefault("SERVER_HOST", "127.0.0.1")
os.environ.setdefault("SERVER_PORT", "8000")

from radar import config
from radar.conclusions.base import (
    Conclusion,
    ConclusionType,
    new_conclusion_id,
)
from radar.conclusions.feedback import (
    FeedbackLabel,
    list_feedback,
    save_feedback,
)
from radar.conclusions.ground_truth_etl import (
    AUTO_ANALYST_ACLED,
    AUTO_ANALYST_BOTH,
    AUTO_ANALYST_GDELT,
    AutoFeedback,
    EvidenceSource,
    ExternalEvent,
    classify_conclusion,
    has_existing_auto_feedback,
    list_conclusions_in_window,
)
from radar.conclusions.persistence import save_conclusion
from radar.database import db
from radar.sensors import acled as acled_module


# ── helpers ──────────────────────────────────────────────────────────────


_NOW = 1_800_000_000.0  # fixed clock for deterministic horizon math


def _make_conclusion(
    *, kind: ConclusionType, state: str, observed_at: float,
    scenario_id: str = "gt_etl_test_scenario",
    confidence: float = 0.7,
) -> Conclusion:
    return Conclusion(
        id=f"gt_etl_test_{new_conclusion_id()}",
        scenario_id=scenario_id,
        conclusion_type=kind,
        state=state,
        confidence=confidence,
        observed_at=observed_at,
        formula_ref="test#unit",
        threshold_ref={},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
    )


def _acled_event(
    *, country: str, at: float, fatalities: int = 0,
    url: str = "https://example.test/acled/1",
) -> ExternalEvent:
    return ExternalEvent(
        source=EvidenceSource.ACLED,
        country=country,
        event_at=at,
        severity=max(1, fatalities),
        url=url,
        summary=f"acled mock fatalities={fatalities}",
    )


def _gdelt_event(*, country: str, at: float, severity: int = 1) -> ExternalEvent:
    return ExternalEvent(
        source=EvidenceSource.GDELT,
        country=country,
        event_at=at,
        severity=severity,
        url="https://api.gdeltproject.org/api/v2/doc/doc",
        summary="gdelt mock spike",
    )


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    yield
    try:
        conn = db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM analyst_feedback WHERE conclusion_id LIKE 'gt_etl_test_%'"
            )
            conn.execute(
                "DELETE FROM conclusions WHERE id LIKE 'gt_etl_test_%'"
            )
    except Exception:
        pass


# ── Rule 1: FALSE_NEGATIVE (NP1 critical) ────────────────────────────────


def test_tl5_with_critical_acled_event_yields_false_negative():
    """The NP1-critical case: tool said calm (TL5=NORMAL), ACLED records
    a mass-casualty escalation in the forward window."""
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="5", observed_at=obs_at)
    evidence = [_acled_event(country="TW", at=obs_at + 6 * 3600, fatalities=15)]

    result = classify_conclusion(
        c, evidence, participant_countries=["TW", "JP"], now=_NOW,
    )
    assert result is not None
    assert result.label == FeedbackLabel.FALSE_NEGATIVE
    assert result.analyst_id == AUTO_ANALYST_ACLED
    assert "fatalities=15" in result.notes


def test_tl1_with_critical_acled_event_is_true_positive_not_false_negative():
    """Inversion sentinel (2026-07-03): TL1 is CRITICAL — the tool's MOST
    alarmed state. A mass-casualty event corroborating it is a success
    (TRUE_POSITIVE). The inverted classifier scored this exact case as a
    FALSE_NEGATIVE, punishing the tool for warning."""
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="1", observed_at=obs_at)
    evidence = [_acled_event(country="TW", at=obs_at + 6 * 3600, fatalities=15)]

    result = classify_conclusion(
        c, evidence, participant_countries=["TW", "JP"], now=_NOW,
    )
    assert result is not None
    assert result.label == FeedbackLabel.TRUE_POSITIVE


def test_tl5_with_only_low_severity_does_not_trigger_false_negative():
    """A 2-fatality event isn't escalation worth flagging the tool for."""
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="5", observed_at=obs_at)
    evidence = [_acled_event(country="TW", at=obs_at + 1 * 3600, fatalities=2)]

    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
        false_negative_fatalities_severity=10,
    )
    # No FALSE_NEGATIVE; horizon hasn't elapsed so no TRUE_NEGATIVE either.
    assert result is None


def test_false_negative_takes_precedence_over_true_positive():
    """FALSE_NEGATIVE is more important than TRUE_POSITIVE — check the
    rule order. The FALSE_NEGATIVE check only fires for TL=5 (NORMAL), so
    the rule dominance only matters when the tool sat calm through a
    critical event. Verify the ordering anyway."""
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="5", observed_at=obs_at)
    evidence = [_acled_event(country="TW", at=obs_at + 1, fatalities=20)]

    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
    )
    assert result.label == FeedbackLabel.FALSE_NEGATIVE


# ── Rule 2: TRUE_POSITIVE ─────────────────────────────────────────────────


def test_high_tl_with_corroborating_acled_yields_true_positive():
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    evidence = [_acled_event(country="TW", at=obs_at + 12 * 3600, fatalities=5)]

    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
    )
    assert result.label == FeedbackLabel.TRUE_POSITIVE
    assert result.analyst_id == AUTO_ANALYST_ACLED
    assert result.observed_outcome_url == "https://example.test/acled/1"


def test_attack_mode_fired_with_corroboration_yields_true_positive():
    """ATTACK_MODE is the second high-severity surface that gets auto-checked."""
    obs_at = _NOW - 12 * 3600
    c = _make_conclusion(
        kind=ConclusionType.ATTACK_MODE,
        state="SYNC_DDOS", observed_at=obs_at,
    )
    evidence = [_acled_event(country="TW", at=obs_at + 3 * 3600, fatalities=3)]
    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
    )
    assert result.label == FeedbackLabel.TRUE_POSITIVE


def test_attack_mode_insufficient_data_is_never_classified():
    """INSUFFICIENT_DATA conclusions don't represent a tool call to validate."""
    obs_at = _NOW - 12 * 3600
    c = _make_conclusion(
        kind=ConclusionType.ATTACK_MODE,
        state="INSUFFICIENT_DATA", observed_at=obs_at,
    )
    evidence = [_acled_event(country="TW", at=obs_at + 3 * 3600, fatalities=3)]
    assert classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
    ) is None


def test_provenance_tags_both_when_acled_and_gdelt_corroborate():
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    evidence = [
        _acled_event(country="TW", at=obs_at + 6 * 3600, fatalities=2),
        _gdelt_event(country="TW", at=obs_at + 8 * 3600, severity=2),
    ]
    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
    )
    assert result.label == FeedbackLabel.TRUE_POSITIVE
    assert result.analyst_id == AUTO_ANALYST_BOTH
    assert "ACLED=1" in result.notes and "GDELT=1" in result.notes


# ── Rule 3: FALSE_POSITIVE ────────────────────────────────────────────────


def test_severe_tl_with_no_evidence_after_horizon_yields_false_positive():
    fp_horizon = config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS
    obs_at = _NOW - (fp_horizon + 1) * 86400
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="2", observed_at=obs_at)

    result = classify_conclusion(
        c, [], participant_countries=["TW"], now=_NOW,
    )
    assert result.label == FeedbackLabel.FALSE_POSITIVE
    assert result.observed_outcome_url is None
    assert "no ACLED/GDELT" in result.notes


def test_elevated_tl_is_not_an_alert_so_never_false_positive():
    """TL4 (ELEVATED) is a calm-side state, not an alert the tool should
    be penalized for. The inverted classifier treated TL≥3 (including
    NORMAL) as alerts and flooded FALSE_POSITIVEs onto calm rows."""
    fp_horizon = config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS
    obs_at = _NOW - (fp_horizon + 1) * 86400
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="4", observed_at=obs_at)
    assert classify_conclusion(
        c, [], participant_countries=["TW"], now=_NOW,
    ) is None


def test_severe_tl_within_horizon_returns_none_pending_more_observation():
    """We can't know yet — wait for the horizon to elapse before deciding."""
    fp_horizon = config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS
    obs_at = _NOW - (fp_horizon - 1) * 86400  # not yet elapsed
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="2", observed_at=obs_at)
    assert classify_conclusion(
        c, [], participant_countries=["TW"], now=_NOW,
    ) is None


# ── Rule 4: TRUE_NEGATIVE ─────────────────────────────────────────────────


def test_tl5_with_no_events_after_horizon_yields_true_negative():
    fp_horizon = config.GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS
    obs_at = _NOW - (fp_horizon + 1) * 86400
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="5", observed_at=obs_at)

    result = classify_conclusion(
        c, [], participant_countries=["TW"], now=_NOW,
    )
    assert result.label == FeedbackLabel.TRUE_NEGATIVE
    # No-event labels carry the honest "auto:horizon" identity (they
    # assert an absence; nothing corroborated them).
    from radar.conclusions.ground_truth_etl import AUTO_ANALYST_HORIZON
    assert result.analyst_id == AUTO_ANALYST_HORIZON


# ── Window / scoping ──────────────────────────────────────────────────────


def test_event_in_non_participant_country_is_ignored():
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    evidence = [_acled_event(country="US", at=obs_at + 1 * 3600, fatalities=20)]

    # US is not a participant of this scenario; the event should not count.
    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
    )
    assert result is None


def test_event_after_forward_window_does_not_corroborate():
    obs_at = _NOW - 96 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    # Event happens 4 days later — well past the 72h default forward window.
    evidence = [_acled_event(country="TW", at=obs_at + 90 * 3600, fatalities=5)]
    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
        window_hours=72,
    )
    # No TP, no TN (horizon was 7d * 86400 from obs_at = _NOW - 96h, only
    # 4d elapsed) so this should be None.
    assert result is None


def test_event_at_exact_observed_at_counts_as_corroboration():
    """Edge: an event at the conclusion's clock tick is in the window."""
    obs_at = _NOW - 24 * 3600
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    evidence = [_acled_event(country="TW", at=obs_at, fatalities=5)]
    result = classify_conclusion(
        c, evidence, participant_countries=["TW"], now=_NOW,
    )
    assert result is not None
    assert result.label == FeedbackLabel.TRUE_POSITIVE


def test_per_domain_and_trend_conclusions_are_never_auto_classified():
    """Diagnostic surfaces don't carry primary-recall signal; auto-labeling
    them would noise up Design W. Only TL and ATTACK_MODE are eligible."""
    obs_at = _NOW - 24 * 3600
    pd = _make_conclusion(
        kind=ConclusionType.PER_DOMAIN, state="DEGRADING", observed_at=obs_at,
    )
    tr = _make_conclusion(
        kind=ConclusionType.TREND, state="ESCALATING", observed_at=obs_at,
    )
    evidence = [_acled_event(country="TW", at=obs_at + 1, fatalities=5)]
    assert classify_conclusion(
        pd, evidence, participant_countries=["TW"], now=_NOW,
    ) is None
    assert classify_conclusion(
        tr, evidence, participant_countries=["TW"], now=_NOW,
    ) is None


# ── Idempotency + DB layer ────────────────────────────────────────────────


def test_has_existing_auto_feedback_returns_false_for_new_pair():
    obs_at = _NOW - 1
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    save_conclusion(db, c)
    assert has_existing_auto_feedback(db, c.id, AUTO_ANALYST_ACLED) is False


def test_has_existing_auto_feedback_detects_prior_run():
    obs_at = _NOW - 1
    c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=obs_at)
    save_conclusion(db, c)
    save_feedback(
        db,
        AutoFeedback(
            conclusion_id=c.id,
            label=FeedbackLabel.TRUE_POSITIVE,
            analyst_id=AUTO_ANALYST_ACLED,
            observed_at=time.time(),
            observed_outcome_url=None,
            notes="first-pass",
        ).to_analyst_feedback(),
    )
    assert has_existing_auto_feedback(db, c.id, AUTO_ANALYST_ACLED) is True
    # Different source should still be free to write its own row.
    assert has_existing_auto_feedback(db, c.id, AUTO_ANALYST_GDELT) is False


def test_list_conclusions_in_window_orders_ascending():
    older = _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="2", observed_at=_NOW - 2,
    )
    newer = _make_conclusion(
        kind=ConclusionType.THREAT_LEVEL, state="3", observed_at=_NOW - 1,
    )
    save_conclusion(db, older)
    save_conclusion(db, newer)
    rows = list_conclusions_in_window(db, since=_NOW - 10, until=_NOW)
    test_ids = [r.id for r in rows if r.id.startswith("gt_etl_test_")]
    assert test_ids.index(older.id) < test_ids.index(newer.id)


# ── ACLED client safety net ──────────────────────────────────────────────


def test_acled_fetch_returns_empty_when_creds_missing(monkeypatch):
    """Without ACLED creds we never raise; the ETL just sees no evidence."""
    monkeypatch.setattr(acled_module, "ACLED_API_KEY", "")
    monkeypatch.setattr(acled_module, "ACLED_API_EMAIL", "")
    out = acled_module.fetch_events(
        ["TW"], since_epoch=_NOW - 86400, until_epoch=_NOW,
    )
    assert out == []


def test_acled_fetch_returns_empty_for_unsupported_country(monkeypatch):
    """A country not in the iso2 map yields no API call (avoid wasted quota)."""
    called = {"n": 0}

    class _FakeSession:
        def get(self, *args, **kwargs):
            called["n"] += 1
            raise AssertionError("should not be called")

    out = acled_module.fetch_events(
        ["XX"], since_epoch=_NOW - 86400, until_epoch=_NOW,
        api_key="dummy", api_email="dummy@test", session=_FakeSession(),
    )
    assert out == []
    assert called["n"] == 0


def test_acled_fetch_parses_normalized_rows(monkeypatch):
    """Happy path: API returns one row, we normalize to ACLEDEvent."""
    class _FakeResp:
        status_code = 200
        def json(self):
            return {"data": [{
                "country": "Taiwan",
                "event_date": "2026-04-20",
                "event_type": "Battles",
                "sub_event_type": "Armed clash",
                "fatalities": "7",
                "location": "Kinmen",
                "source": "https://news.test/acled-row-1",
                "notes": "skirmish at coastline",
            }]}

    class _FakeSession:
        def get(self, *args, **kwargs):
            return _FakeResp()

    out = acled_module.fetch_events(
        ["TW"], since_epoch=_NOW - 86400, until_epoch=_NOW,
        api_key="dummy", api_email="dummy@test", session=_FakeSession(),
    )
    assert len(out) == 1
    e = out[0]
    assert e.country == "TW"
    assert e.fatalities == 7
    assert e.source_url == "https://news.test/acled-row-1"
    assert "skirmish" in e.notes


def test_acled_fetch_drops_rows_with_unparseable_date(monkeypatch):
    class _FakeResp:
        status_code = 200
        def json(self):
            return {"data": [{
                "country": "Taiwan",
                "event_date": "not-a-date",
                "fatalities": "1",
            }]}
    class _FakeSession:
        def get(self, *args, **kwargs):
            return _FakeResp()
    out = acled_module.fetch_events(
        ["TW"], since_epoch=_NOW - 86400, until_epoch=_NOW,
        api_key="dummy", api_email="dummy@test", session=_FakeSession(),
    )
    assert out == []


# ── Internal-source evidence (PF1 extension 2026-04-29) ─────────────────


class TestInternalSourceProvenance:
    """Provenance helper handles new LLM_INTEL and SEQUENCE source kinds."""

    def test_provenance_llm_intel_only(self):
        from radar.conclusions.ground_truth_etl import (
            AUTO_ANALYST_LLM_INTEL, EvidenceSource, ExternalEvent, _provenance,
        )
        events = [ExternalEvent(
            source=EvidenceSource.LLM_INTEL,
            country="TW", event_at=_NOW, severity=1,
            url="radar://llm_intel/abc", summary="diplomatic pendant 0.85",
        )]
        analyst, url, notes = _provenance(events)
        assert analyst == AUTO_ANALYST_LLM_INTEL
        assert "LLM_INTEL=1" in notes

    def test_provenance_sequence_only(self):
        from radar.conclusions.ground_truth_etl import (
            AUTO_ANALYST_SEQUENCE, EvidenceSource, ExternalEvent, _provenance,
        )
        events = [ExternalEvent(
            source=EvidenceSource.SEQUENCE,
            country="UA", event_at=_NOW, severity=1,
            url="radar://sequence_events/SURGE", summary="sequence_event SURGE",
        )]
        analyst, _, notes = _provenance(events)
        assert analyst == AUTO_ANALYST_SEQUENCE
        assert "SEQUENCE=1" in notes

    def test_provenance_mixed_internal_sources(self):
        from radar.conclusions.ground_truth_etl import (
            AUTO_ANALYST_MIXED, EvidenceSource, ExternalEvent, _provenance,
        )
        events = [
            ExternalEvent(EvidenceSource.LLM_INTEL, "IL", _NOW, 1, "u1", "s1"),
            ExternalEvent(EvidenceSource.SEQUENCE, "IL", _NOW, 1, "u2", "s2"),
        ]
        analyst, _, _ = _provenance(events)
        assert analyst == AUTO_ANALYST_MIXED

    def test_provenance_acled_overrides_internal(self):
        """ACLED is human-curated and outranks internal sources for analyst_id."""
        from radar.conclusions.ground_truth_etl import (
            AUTO_ANALYST_ACLED, EvidenceSource, ExternalEvent, _provenance,
        )
        events = [
            ExternalEvent(EvidenceSource.ACLED, "TW", _NOW, 5, "u1", "acled"),
            ExternalEvent(EvidenceSource.LLM_INTEL, "TW", _NOW, 1, "u2", "llm"),
        ]
        analyst, _, _ = _provenance(events)
        assert analyst == AUTO_ANALYST_ACLED


class TestInternalSourceFalseNegative:
    """Rule 1 (FALSE_NEGATIVE) uses EXTERNAL evidence only. The internal-source
    substitute (≥2 distinct LLM_INTEL/SEQUENCE) was removed 2026-05-29 as
    circular — internal signals cannot reveal what the tool itself missed."""

    def test_two_internal_sources_do_not_trigger_false_negative(self):
        """Even 2 distinct internal sources must NOT flip TL=1 to FN: those
        signals feed the score, so using them to judge a miss is circular."""
        from radar.conclusions.ground_truth_etl import (
            EvidenceSource, ExternalEvent, classify_conclusion,
        )
        c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="1",
                             observed_at=_NOW - 3600)
        events = [
            ExternalEvent(EvidenceSource.LLM_INTEL, "TW", _NOW, 1, "u1", "llm"),
            ExternalEvent(EvidenceSource.SEQUENCE, "TW", _NOW, 1, "u2", "seq"),
        ]
        verdict = classify_conclusion(
            c, events, participant_countries=["TW"],
        )
        if verdict is not None:
            assert verdict.label.value != "FALSE_NEGATIVE"

    def test_one_internal_source_alone_does_not_trigger(self):
        """Single LLM_INTEL event is too weak to flip TL=1 alone."""
        from radar.conclusions.ground_truth_etl import (
            EvidenceSource, ExternalEvent, classify_conclusion,
        )
        c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="1",
                             observed_at=_NOW - 3600)
        events = [
            ExternalEvent(EvidenceSource.LLM_INTEL, "TW", _NOW, 1, "u1", "llm"),
        ]
        verdict = classify_conclusion(
            c, events, participant_countries=["TW"],
        )
        if verdict is not None:
            assert verdict.label.value != "FALSE_NEGATIVE"

    def test_two_same_source_internal_does_not_trigger(self):
        """Two LLM_INTEL events (same source) → only 1 distinct internal
        source → still not enough for the substitute rule."""
        from radar.conclusions.ground_truth_etl import (
            EvidenceSource, ExternalEvent, classify_conclusion,
        )
        c = _make_conclusion(kind=ConclusionType.THREAT_LEVEL, state="1",
                             observed_at=_NOW - 3600)
        events = [
            ExternalEvent(EvidenceSource.LLM_INTEL, "TW", _NOW, 1, "u1", "llm-1"),
            ExternalEvent(EvidenceSource.LLM_INTEL, "TW", _NOW, 1, "u2", "llm-2"),
        ]
        verdict = classify_conclusion(
            c, events, participant_countries=["TW"],
        )
        if verdict is not None:
            assert verdict.label.value != "FALSE_NEGATIVE"


# ── graded under-rating classifier (NP1 — independent-evidence FN) ──────────


class TestExpectedSeverityFloor:
    """expected_severity_floor maps external-event magnitude → minimum
    severity (5=CRITICAL … 1=NORMAL) the tool should have shown. Drives the
    graded FALSE_NEGATIVE path."""

    def test_mass_casualty_demands_severity4(self):
        from radar.conclusions.ground_truth_etl import expected_severity_floor
        # fatalities at/above threshold → severity ≥ 4, i.e. TL ≤ 2 (SEVERE)
        assert expected_severity_floor(
            fatalities=25, confidence=0.85, mass_casualty_threshold=10,
        ) == 4

    def test_counted_fatality_below_threshold_demands_severity3(self):
        from radar.conclusions.ground_truth_etl import expected_severity_floor
        assert expected_severity_floor(
            fatalities=3, confidence=0.85, mass_casualty_threshold=10,
        ) == 3

    def test_kinetic_verb_no_fatalities_demands_severity3(self):
        from radar.conclusions.ground_truth_etl import expected_severity_floor
        # confidence 0.60 = kinetic verb only (rss_extractor ladder)
        assert expected_severity_floor(
            fatalities=0, confidence=0.60, mass_casualty_threshold=10,
        ) == 3

    def test_escalation_verb_only_demands_severity2(self):
        from radar.conclusions.ground_truth_etl import expected_severity_floor
        # confidence 0.40 = escalation verb only, fatalities 0
        assert expected_severity_floor(
            fatalities=0, confidence=0.40, mass_casualty_threshold=10,
        ) == 2

    def test_default_threshold_from_config(self):
        from radar.conclusions.ground_truth_etl import expected_severity_floor
        # falls back to config.GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES (10)
        assert expected_severity_floor(fatalities=10, confidence=0.85) == 4
        assert expected_severity_floor(fatalities=9, confidence=0.85) == 3


class TestLabelForThreatLevel:
    """label_for_threat_level: under-rating → FN, met/exceeded → TP.
    tool_tl is the raw DEFCON-style TL (1=CRITICAL … 5=NORMAL); the floor
    is in severity space (bigger = worse)."""

    def test_under_rating_is_false_negative(self):
        from radar.conclusions.ground_truth_etl import label_for_threat_level
        # tool showed TL=4 (ELEVATED, severity 2) but a mass-casualty event
        # warranted severity ≥ 4 → miss
        assert label_for_threat_level(
            tool_tl=4, expected_severity_floor=4,
        ) == FeedbackLabel.FALSE_NEGATIVE

    def test_tl5_normal_under_kinetic_is_false_negative(self):
        from radar.conclusions.ground_truth_etl import label_for_threat_level
        # TL=5 is NORMAL (severity 1) — calm through armed violence → miss
        assert label_for_threat_level(
            tool_tl=5, expected_severity_floor=3,
        ) == FeedbackLabel.FALSE_NEGATIVE

    def test_meeting_floor_is_true_positive(self):
        from radar.conclusions.ground_truth_etl import label_for_threat_level
        # TL=2 (SEVERE) has severity 4 — meets a mass-casualty floor
        assert label_for_threat_level(
            tool_tl=2, expected_severity_floor=4,
        ) == FeedbackLabel.TRUE_POSITIVE

    def test_exceeding_floor_is_true_positive(self):
        from radar.conclusions.ground_truth_etl import label_for_threat_level
        # TL=1 (CRITICAL, severity 5) exceeds a kinetic floor of 3.
        # Inversion sentinel: the pre-2026-07-03 classifier graded exactly
        # this case FALSE_NEGATIVE.
        assert label_for_threat_level(
            tool_tl=1, expected_severity_floor=3,
        ) == FeedbackLabel.TRUE_POSITIVE
