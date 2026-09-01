"""Shared builders for the WP-3.1 suites.

Kept out of conftest so the helpers are imported by name: a fixture that
appears by magic is a fixture nobody checks, and these ones decide what
"a healthy tick" means in every availability test.
"""
from __future__ import annotations

from v3.conclusions import InputHealth, ScenarioContext
from v3.conclusions import thresholds as T
from v3.kernel import Provenance, ThreatLevel
from v3.ledger import LedgerStore, TLObservation
from v3.scoring.contributions import Contribution
from v3.scoring.result import BonusBreakdown, ScoringResult

NOW = 1_786_000_000.0
LONG_HISTORY = T.CALIBRATION_MIN_HISTORY_SEC + 86400.0


def provenance(formula_ref: str = "test@clause") -> Provenance:
    return Provenance(formula_ref=formula_ref, computed_at=NOW)


def healthy(history_span_sec: float = LONG_HISTORY,
            sources: int = 4) -> InputHealth:
    """Enough sources answering, and a scenario old enough to trust."""
    return InputHealth(
        sources_ok=tuple(f"sensor_{i}" for i in range(sources)),
        history_span_sec=history_span_sec)


def contribution(*, sensor: str = "ripe_bgp", signal_source: str = "bgp",
                 domain: str = "cyber", country: str = "TW",
                 raw_score: float = 3.0, score: float = 2.4,
                 llm_country_weight: float = 1.0,
                 participant_weight: float = 0.8,
                 role: str = "primary_target") -> Contribution:
    return Contribution(
        sensor=sensor, signal_source=signal_source, domain=domain,
        country=country, role=role, raw_score=raw_score,
        llm_country_weight=llm_country_weight,
        participant_weight=participant_weight, score=score,
        trace=f"{raw_score:.2f} (raw) = {score:.2f}")


def scoring_result(*, scenario_id: str = "taiwan_contingency",
                   tl: int = 4, score: float = 2.5,
                   domains=None, contributions=(),
                   active_countries=("TW",), scoring_mode: str = "full",
                   convergence_bonus: float = 0.0) -> ScoringResult:
    domains = domains or {"cyber": score, "physical": 0.0, "info": 0.0}
    level = ThreatLevel(tl)
    return ScoringResult(
        scenario_id=scenario_id, scoring_mode=scoring_mode,
        threat_level=level, raw_threat_level=level, hysteresis_held=False,
        score=score, base_score=score, domain_scores=domains,
        convergence="none", convergence_bonus=convergence_bonus,
        bonuses=BonusBreakdown(), active_domains=tuple(
            d for d, v in domains.items() if v > 0),
        active_countries=tuple(active_countries),
        contributions=tuple(contributions), provenance=provenance())


def context(*, scenario_id: str = "taiwan_contingency", health=None,
            result="default", now: float = NOW, **kwargs) -> ScenarioContext:
    if result == "default":
        result = scoring_result(scenario_id=scenario_id)
    return ScenarioContext(
        scenario_id=scenario_id, now=now,
        health=healthy() if health is None else health,
        result=result, **kwargs)


def store_with_tl(tmp_path, scenario_id: str, series, *,
                  name: str = "v3.db") -> LedgerStore:
    """`series` is [(observed_at, tl_or_None), ...]."""
    store = LedgerStore(str(tmp_path / name))
    for index, (observed_at, tl) in enumerate(series):
        store.append_tl(TLObservation(
            tick_id=f"t{index}", scenario_id=scenario_id,
            observed_at=observed_at,
            threat_level=None if tl is None else ThreatLevel(tl),
            score=0.0))
    return store


__all__ = ["NOW", "LONG_HISTORY", "provenance", "healthy", "contribution",
           "scoring_result", "context", "store_with_tl"]
