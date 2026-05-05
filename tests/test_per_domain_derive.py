"""Tests for radar.conclusions.per_domain.derive_per_domain builder.

Pins the existing v2.0 PER_DOMAIN deriver behavior shipped in the Phase 0
scaffold. The thresholds in this builder (ACTIVE_FLOOR=3.0, ELEVATED_FLOOR=1.5,
DEGRADE_DELTA=1.5 absolute) intentionally diverge from spec §6.3 (5.0 / 2.0 +
30% relative DEGRADING). Calibration is deferred to Phase 1.3 — this file
locks current behavior so calibration shows up as a single intentional diff.

Coverage targets (NP6 disclosure surface):
- 5 classification states (ACTIVE / ELEVATED / STABLE / DEGRADING / INSUFFICIENT_SIGNAL)
- ACTIVE_FLOOR / ELEVATED_FLOOR boundary handling
- DEGRADING via prior persisted PER_DOMAIN row (real DB round-trip)
- Packed `state` string format (`cyber=X;physical=Y;info=Z`)
- All-domains-INSUFFICIENT_SIGNAL → INSUFFICIENT_DATA (NP5+8 + NP1)
- source_urls deduplicated and sorted across all domains
- Confidence formula: 0.5 * breadth + 0.5 * magnitude
- metadata.domain_scores / domain_states / domain_source_counts shape
"""

from __future__ import annotations

import pytest

from radar import config
from radar.conclusions import (
    Conclusion,
    ConclusionType,
    ConclusionUnavailableReason,
    derive_per_domain,
    save_conclusion,
)
from radar.conclusions.base import new_conclusion_id
from radar.conclusions.per_domain import (
    ACTIVE_FLOOR,
    DEGRADE_DELTA,
    DOMAINS,
    ELEVATED_FLOOR,
    FORMULA_REF,
)
from radar.database import RadarDB
from radar.scoring import ScenarioContribution, ScenarioState, Signal


@pytest.fixture
def db(tmp_path) -> RadarDB:
    return RadarDB(str(tmp_path / "per_domain_derive.db"))


@pytest.fixture
def now() -> float:
    return 1_700_000_000.0


def _signal(
    *,
    signal_source: str = "apt_intel",
    sensor: str = "apt_intel",
    domain: str = "cyber",
    countries: list[str] | None = None,
    raw_score: float = 1.0,
    observed_at: float = 1_700_000_000.0,
    value_display: str = "",
    evidence_url: str | None = None,
) -> Signal:
    return Signal(
        signal_source=signal_source,
        sensor=sensor,
        observed_at=observed_at,
        domain=domain,
        countries=countries if countries is not None else ["TW"],
        country_weights={c: 1.0 for c in (countries or ["TW"])},
        raw_score=raw_score,
        value_display=value_display,
        evidence_url=evidence_url,
    )


def _contribution(
    sig: Signal,
    *,
    country: str = "TW",
    llm_country_weight: float = 1.0,
    participant_weight: float = 1.0,
    role: str = "primary_target",
    final_contribution: float | None = None,
) -> ScenarioContribution:
    fc = (
        final_contribution
        if final_contribution is not None
        else sig.raw_score * llm_country_weight * participant_weight
    )
    return ScenarioContribution(
        signal=sig,
        contributing_country=country,
        llm_country_weight=llm_country_weight,
        participant_weight=participant_weight,
        participant_role=role,
        final_contribution=fc,
        formula_trace="test",
    )


def _state(
    contributions: list[ScenarioContribution],
    *,
    domains: dict[str, float] | None = None,
    **overrides,
) -> ScenarioState:
    base = dict(
        scenario_id="taiwan_contingency",
        is_focused=True,
        scoring_mode="full",
        score=sum(c.final_contribution for c in contributions),
        domains=domains if domains is not None else {"cyber": 0.0, "physical": 0.0, "info": 0.0},
        active_countries=["TW"],
        convergence_bonus=0.0,
        tl=3,
        contributions=contributions,
    )
    base.update(overrides)
    return ScenarioState(**base)


# ── schema / NP6 disclosure surface ────────────────────────────────────


def test_returns_single_conclusion_of_per_domain_type(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": 1.0, "physical": 0.0, "info": 0.0}), now=now)
    assert isinstance(out, Conclusion)
    assert out.conclusion_type is ConclusionType.PER_DOMAIN


def test_formula_ref_is_versioned(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": 1.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.formula_ref == FORMULA_REF
    assert "@v" in out.formula_ref


def test_threshold_ref_mirrors_module_constants(db, now) -> None:
    """Drift guard: every threshold the deriver applies is on threshold_ref.

    If a constant changes without a matching threshold_ref update, replay
    against historical rows breaks. This test fails loudly on that drift.
    """
    out = derive_per_domain(db, _state([], domains={"cyber": 1.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.threshold_ref == {
        "active_floor": ACTIVE_FLOOR,
        "elevated_floor": ELEVATED_FLOOR,
        "degrade_delta": DEGRADE_DELTA,
    }


def test_disclaimer_attached_per_np7(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": 1.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.final_judgment_disclaimer == config.V2_NP7_DISCLAIMER


# ── classification: 5 states ───────────────────────────────────────────


def test_active_state_at_or_above_active_floor(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": ACTIVE_FLOOR, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "ACTIVE"


def test_elevated_state_between_floors(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": ELEVATED_FLOOR, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "ELEVATED"


def test_stable_state_below_elevated_with_signal(db, now) -> None:
    """A positive but sub-ELEVATED score is STABLE, not INSUFFICIENT_SIGNAL."""
    out = derive_per_domain(db, _state([], domains={"cyber": 0.5, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "STABLE"


def test_insufficient_signal_when_score_zero(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": 0.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "INSUFFICIENT_SIGNAL"


def test_negative_score_treated_as_insufficient_signal(db, now) -> None:
    """The classifier guards `cur <= 0`; pinned to keep the boundary explicit."""
    out = derive_per_domain(db, _state([], domains={"cyber": -1.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "INSUFFICIENT_SIGNAL"


def test_active_floor_boundary_inclusive(db, now) -> None:
    just_below = _state([], domains={"cyber": ACTIVE_FLOOR - 0.01, "physical": 0.0, "info": 0.0})
    just_at = _state([], domains={"cyber": ACTIVE_FLOOR, "physical": 0.0, "info": 0.0})
    assert derive_per_domain(db, just_below, now=now).metadata["domain_states"]["cyber"] == "ELEVATED"
    assert derive_per_domain(db, just_at, now=now).metadata["domain_states"]["cyber"] == "ACTIVE"


def test_elevated_floor_boundary_inclusive(db, now) -> None:
    just_below = _state([], domains={"cyber": ELEVATED_FLOOR - 0.01, "physical": 0.0, "info": 0.0})
    just_at = _state([], domains={"cyber": ELEVATED_FLOOR, "physical": 0.0, "info": 0.0})
    assert derive_per_domain(db, just_below, now=now).metadata["domain_states"]["cyber"] == "STABLE"
    assert derive_per_domain(db, just_at, now=now).metadata["domain_states"]["cyber"] == "ELEVATED"


# ── DEGRADING via prior persisted PER_DOMAIN row ───────────────────────


def _seed_prior(db: RadarDB, *, scenario_id: str, observed_at: float,
                cyber: float = 0.0, physical: float = 0.0, info: float = 0.0) -> None:
    """Write a prior PER_DOMAIN row so derive_per_domain can detect DEGRADING."""
    prior = Conclusion(
        id=new_conclusion_id(),
        scenario_id=scenario_id,
        conclusion_type=ConclusionType.PER_DOMAIN,
        state=f"cyber=ACTIVE;physical=STABLE;info=STABLE",
        confidence=0.5,
        observed_at=observed_at,
        formula_ref=FORMULA_REF,
        threshold_ref={"active_floor": ACTIVE_FLOOR},
        source_urls=(),
        final_judgment_disclaimer=config.V2_NP7_DISCLAIMER,
        metadata={
            "domain_scores": {"cyber": cyber, "physical": physical, "info": info},
            "domain_states": {"cyber": "ACTIVE", "physical": "STABLE", "info": "STABLE"},
        },
    )
    save_conclusion(db, prior)


def test_degrading_when_drop_at_or_above_degrade_delta(db, now) -> None:
    """Prior cyber=4.0, current=2.0, drop=2.0 >= DEGRADE_DELTA(1.5) → DEGRADING.

    Current score (2.0) is above ELEVATED_FLOOR(1.5) but below ACTIVE_FLOOR(3.0),
    so DEGRADING wins over the static ELEVATED bucket — pinning the rule that
    the descent signal beats the level signal.
    """
    _seed_prior(db, scenario_id="taiwan_contingency", observed_at=now - 60, cyber=4.0)
    out = derive_per_domain(db, _state([], domains={"cyber": 2.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "DEGRADING"


def test_no_degrading_when_drop_below_threshold(db, now) -> None:
    """Drop strictly below DEGRADE_DELTA → ELEVATED, not DEGRADING."""
    _seed_prior(db, scenario_id="taiwan_contingency", observed_at=now - 60, cyber=2.0)
    out = derive_per_domain(db, _state([], domains={"cyber": 1.5, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "ELEVATED"


def test_active_overrides_degrading(db, now) -> None:
    """Even after a drop, score >= ACTIVE_FLOOR keeps the ACTIVE label.

    Prior cyber=8.0, current=4.0 — drop of 4.0 exceeds DEGRADE_DELTA but
    current still meets ACTIVE_FLOOR. The classifier's order (ACTIVE first)
    is what's pinned here.
    """
    _seed_prior(db, scenario_id="taiwan_contingency", observed_at=now - 60, cyber=8.0)
    out = derive_per_domain(db, _state([], domains={"cyber": 4.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "ACTIVE"


def test_no_prior_row_yields_no_degrading(db, now) -> None:
    """First-ever conclusion for a scenario can't classify as DEGRADING."""
    out = derive_per_domain(db, _state([], domains={"cyber": 1.5, "physical": 0.0, "info": 0.0}), now=now)
    assert out.metadata["domain_states"]["cyber"] == "ELEVATED"


# ── packed state string format ─────────────────────────────────────────


def test_state_string_packs_all_three_domains_in_canonical_order(db, now) -> None:
    out = derive_per_domain(
        db,
        _state([], domains={"cyber": ACTIVE_FLOOR, "physical": 0.0, "info": ELEVATED_FLOOR}),
        now=now,
    )
    assert out.state == "cyber=ACTIVE;physical=INSUFFICIENT_SIGNAL;info=ELEVATED"


def test_state_string_uses_module_domain_order(db, now) -> None:
    """DOMAINS tuple drives serialization order; pinned to keep grep-friendly format."""
    out = derive_per_domain(db, _state([], domains={"cyber": 1.0, "physical": 1.0, "info": 1.0}), now=now)
    assert out.state is not None
    parts = out.state.split(";")
    assert [p.split("=")[0] for p in parts] == list(DOMAINS)


# ── all-INSUFFICIENT path → INSUFFICIENT_DATA Conclusion ───────────────


def test_all_domains_silent_yields_insufficient_data(db, now) -> None:
    """NP5+8 + NP1: zero-everything tick still emits a visible row."""
    out = derive_per_domain(db, _state([], domains={"cyber": 0.0, "physical": 0.0, "info": 0.0}), now=now)
    assert not out.is_available()
    assert out.conclusion_unavailable_reason is ConclusionUnavailableReason.INSUFFICIENT_DATA
    assert out.metadata.get("is_transient") is True
    assert out.state is None
    assert out.confidence == 0.0


# ── source_urls aggregation ────────────────────────────────────────────


def test_source_urls_deduplicated_and_sorted_across_domains(db, now) -> None:
    contributions = [
        _contribution(_signal(domain="cyber", evidence_url="https://b.example/x")),
        _contribution(_signal(domain="cyber", evidence_url="https://a.example/y")),
        _contribution(_signal(domain="physical", evidence_url="https://b.example/x")),  # dup
        _contribution(_signal(domain="info", evidence_url="https://c.example/z")),
        _contribution(_signal(domain="info", evidence_url=None)),  # filtered
    ]
    out = derive_per_domain(
        db,
        _state(contributions, domains={"cyber": 1.0, "physical": 1.0, "info": 1.0}),
        now=now,
    )
    assert out.source_urls == (
        "https://a.example/y",
        "https://b.example/x",
        "https://c.example/z",
    )


def test_source_urls_only_count_known_domains(db, now) -> None:
    """A signal in an unknown domain (e.g. typo) must not pollute source_urls."""
    contributions = [
        _contribution(_signal(domain="cyber", evidence_url="https://a.example")),
        _contribution(_signal(domain="bogus_domain", evidence_url="https://b.example")),
    ]
    out = derive_per_domain(
        db,
        _state(contributions, domains={"cyber": 1.0, "physical": 0.0, "info": 0.0}),
        now=now,
    )
    assert out.source_urls == ("https://a.example",)


# ── confidence formula ────────────────────────────────────────────────


def test_confidence_zero_when_all_domains_silent(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": 0.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.confidence == 0.0


def test_confidence_combines_breadth_and_magnitude(db, now) -> None:
    """confidence = 0.5 * (available/3) + 0.5 * (sum/12).

    With cyber=ACTIVE_FLOOR=3.0 only: breadth = 1/3, magnitude = 3.0/12 = 0.25.
    Expected = 0.5 * 0.333 + 0.5 * 0.25 = 0.292.
    """
    out = derive_per_domain(db, _state([], domains={"cyber": 3.0, "physical": 0.0, "info": 0.0}), now=now)
    assert out.confidence == round(0.5 * (1.0 / 3.0) + 0.5 * (3.0 / 12.0), 3)


def test_confidence_caps_magnitude_at_one(db, now) -> None:
    """A massive single-domain score caps magnitude at 1.0 — single domain
    can never get full confidence because breadth tops out at 0.5 (1/3 * 0.5).
    """
    out = derive_per_domain(db, _state([], domains={"cyber": 1000.0, "physical": 0.0, "info": 0.0}), now=now)
    expected = round(0.5 * (1.0 / 3.0) + 0.5 * 1.0, 3)
    assert out.confidence == expected


def test_confidence_max_when_all_three_active(db, now) -> None:
    out = derive_per_domain(db, _state([], domains={"cyber": 4.0, "physical": 4.0, "info": 4.0}), now=now)
    assert out.confidence == round(0.5 * 1.0 + 0.5 * 1.0, 3)


# ── metadata shape ────────────────────────────────────────────────────


def test_metadata_records_per_domain_scores(db, now) -> None:
    out = derive_per_domain(
        db,
        _state([], domains={"cyber": 1.234, "physical": 5.678, "info": 0.0}),
        now=now,
    )
    scores = out.metadata["domain_scores"]
    assert scores["cyber"] == 1.234
    assert scores["physical"] == 5.678
    assert scores["info"] == 0.0


def test_metadata_records_source_counts_per_domain(db, now) -> None:
    contributions = [
        _contribution(_signal(domain="cyber", evidence_url="https://a")),
        _contribution(_signal(domain="cyber", evidence_url="https://b")),
        _contribution(_signal(domain="physical", evidence_url="https://c")),
    ]
    out = derive_per_domain(
        db,
        _state(contributions, domains={"cyber": 2.0, "physical": 1.0, "info": 0.0}),
        now=now,
    )
    counts = out.metadata["domain_source_counts"]
    assert counts["cyber"] == 2
    assert counts["physical"] == 1
    assert counts["info"] == 0


# ── persistence round-trip (DEGRADING relies on it) ────────────────────


def test_round_trip_via_save_then_latest_for_degrading(db, now) -> None:
    """End-to-end: write tick 1, score drops at tick 2 → DEGRADING.

    This is the live path the shadow-write hook uses. If `save_conclusion` /
    `latest_conclusion` schemas drift apart, this test fails before any
    silent calibration breakage hits production.
    """
    s1 = _state([], domains={"cyber": 4.0, "physical": 0.0, "info": 0.0})
    c1 = derive_per_domain(db, s1, now=now)
    save_conclusion(db, c1)

    s2 = _state([], domains={"cyber": 2.0, "physical": 0.0, "info": 0.0})
    c2 = derive_per_domain(db, s2, now=now + 60)
    assert c2.metadata["domain_states"]["cyber"] == "DEGRADING"
