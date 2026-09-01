"""All five conclusions for one scenario, every tick, without exception.

The tool definition names five outputs, so a tick produces five kinds of
answer. Some of those answers are "I cannot tell you, and here is which
guard stopped me" — but there is no input for which a kind goes missing,
and `derive_all` proves it by construction: each type's derivation returns
at least one conclusion, and this function concatenates them.

That property is what the chronic-null-zone view depends on. A dropped row
is indistinguishable from a healthy tick when you read the series back,
which is how a permanently unavailable conclusion type went unnoticed for
two months while the chronic counter said zero.

Building the `ScenarioContext` is the caller's impure step (clock, ledger
reads, source health). This module is a pure function of it.
"""
from __future__ import annotations

from v3.conclusions import anomaly, attack_mode, per_domain, threat_level
from v3.conclusions import trend as trend_module
from v3.conclusions import vocabulary as V
from v3.conclusions.conclusion import Conclusion
from v3.conclusions.context import ScenarioContext

DEFAULT_CADENCE_SEC = 900.0


def derive_all(context: ScenarioContext, *, store,
               cadence_sec: float = DEFAULT_CADENCE_SEC
               ) -> tuple[Conclusion, ...]:
    """The five types, in the order S1-CONC-001 lists them."""
    produced: list[Conclusion] = [
        threat_level.derive(context),
        trend_module.derive(context, store=store, cadence_sec=cadence_sec),
        per_domain.derive(context),
    ]
    produced.extend(anomaly.derive(context, store=store))
    produced.append(attack_mode.derive(context))

    missing = set(V.CONCLUSION_TYPES) - {item.conclusion_type
                                         for item in produced}
    if missing:
        # Not reachable from the derivations above; kept because the whole
        # value of this layer is that a type never silently goes absent,
        # and an assertion that can never fire is cheaper than the two
        # months it took to notice last time.
        raise AssertionError(
            f"derive_all produced no conclusion of type(s) {sorted(missing)}; "
            f"a missing type reads as a healthy tick in every downstream view")
    return tuple(produced)


def latest_of_each_type(conclusions) -> dict:
    """S1-CONC-007's bundle rule: newest row per type, types independent."""
    newest: dict = {}
    for item in conclusions:
        current = newest.get(item.conclusion_type)
        if current is None or item.observed_at >= current.observed_at:
            newest[item.conclusion_type] = item
    return newest


__all__ = ["derive_all", "latest_of_each_type", "DEFAULT_CADENCE_SEC"]
