"""Every number the effective scoring path uses, and how each may move.

P6 O-18 splits thresholds in two, against the measured evidence that
"register everything" is the wrong repair: 95 of 98 registered keys went
unread for months and nobody noticed (G-15), so what NP6 asked for was
disclosure, not runtime variability.

    registry_backed   an analyst plausibly turns this dial, AND the
                      effective path already reads it from configuration.
                      Resolved OUTSIDE the kernel and handed in as
                      `ScoringSettings`.
    pinned            a constant on the effective path. Disclosed here
                      with the clause holding its value, and changeable
                      only by editing this file — which forces review and
                      re-calibration.

The second criterion matters and is why this catalogue is smaller than the
S1 threshold tables. S1-scoring-core lists `CONVERGENCE_FULL_BONUS` and
`DOMAIN_WEIGHT_CYBER` as configurable, and they are — but only in the
engine formula family, which P6 O-14 determined does not reach the served
threat level (`radar/scoring.py:1521-1546` sums uncapped-by-weight domain
totals and hardcodes the bonus tiers at `scoring.py:1168-1174`). Promoting
them here would install a live dial that does nothing, which is precisely
the G-15 shape this ruling exists to stop.

Pinned values are resolved once at import into plain numbers, so no
formula touches a clock at tick time: `Threshold.resolve()` stamps
`time.time()`, and a kernel whose idempotence depends on nobody looking is
not idempotent (WP-2.4 completion condition 1).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from v3.kernel import Threshold

# ── (a) operationally variable — resolved outside the kernel ───────────────


@dataclass(frozen=True, slots=True)
class VariableKey:
    """A registry-backed threshold plus the case for it being variable.

    `why` is required by O-18: the selection has to be justifiable rather
    than habitual, and the justification has to survive being read back.
    """

    threshold: Threshold
    default: Any
    why: str

    @property
    def key(self) -> str:
        return self.threshold.key


VARIABLE: dict[str, VariableKey] = {
    "DOMAIN_CAP": VariableKey(
        Threshold.registry_backed("DOMAIN_CAP", unit="score"), 6.0,
        "The per-domain ceiling decides how much one loud domain can carry "
        "a scenario toward TL2's floor. Calibration moves it whenever a "
        "sensor family is re-scaled, and S1-PIPE-025 already records it as "
        "DB-overridable. Effective: applied at radar/scoring.py:1521."),
    "GLOBAL_SIGNALS_DECOUPLED": VariableKey(
        Threshold.registry_backed("GLOBAL_SIGNALS_DECOUPLED", unit="bool"), True,
        "Decides whether countryless signals can light a domain and so "
        "satisfy TL2's two-domain gate on nothing in particular "
        "(S1-SCORE-012, the Phase 9 regression that put a ~1.5 floor under "
        "every scenario). An operator needs to re-isolate global noise "
        "during an incident, not after a deploy."),
    "GLOBAL_SIGNAL_WEIGHT": VariableKey(
        Threshold.registry_backed("GLOBAL_SIGNAL_WEIGHT", unit="ratio"), 0.5,
        "Scales the separate global-threat envelope (S1-SCORE-013) and the "
        "legacy coupled path. Tuned against the prevailing global "
        "background level, which drifts on its own schedule."),
    "LLM_INTEL_PRIMARY_COUNTRY_ONLY": VariableKey(
        Threshold.registry_backed("LLM_INTEL_PRIMARY_COUNTRY_ONLY", unit="bool"),
        True,
        "Turns off LLM multi-country bleed (S1-SCORE-014). Must be "
        "reversible in operation, because the failure mode — one report "
        "scoring four unrelated scenarios — is discovered while it is "
        "happening."),
    "LLM_INTEL_PRIMARY_THRESHOLD": VariableKey(
        Threshold.registry_backed("LLM_INTEL_PRIMARY_THRESHOLD", unit="ratio"),
        0.8,
        "The primary-country ratio cut. S1-SCORE-014 records it as "
        "DB-overridable already, and its right value depends on how "
        "confidently the current model attributes countries — which "
        "changes when the model changes."),
    "CONVERGENCE_SCENARIO_SPECIFIC": VariableKey(
        Threshold.registry_backed("CONVERGENCE_SCENARIO_SPECIFIC", unit="bool"),
        False,
        "S1-SCORE-007's participant-count downgrade. Default-OFF is itself "
        "an unresolved owner ruling (S1-scoring-core ACCIDENTAL A1), so "
        "the flag has to be flippable while that ruling is pending."),
    "SEQUENCE_WINDOW": VariableKey(
        Threshold.registry_backed("SEQUENCE_WINDOW", unit="s"), 86400.0,
        "How long an escalation chain stays live. Different watches "
        "escalate on different clocks (S1-SCORE-022; read from the "
        "environment today at radar/scoring.py:195)."),
    "SEQUENCE_FULL_BONUS": VariableKey(
        Threshold.registry_backed("SEQUENCE_FULL_BONUS", unit="score"), 3.0,
        "What a complete four-link chain adds. The primary recall dial for "
        "sequence detection (S1-SCORE-021; radar/scoring.py:225)."),
    "SEQUENCE_PARTIAL_BONUS": VariableKey(
        Threshold.registry_backed("SEQUENCE_PARTIAL_BONUS", unit="score"), 2.0,
        "What a three-link chain adds. Paired with SEQUENCE_FULL_BONUS and "
        "read from the environment at radar/scoring.py:229 — NOTE: this "
        "key appears in neither S1 threshold catalogue, which is why the "
        "partial tier is missing from S1-SCORE-021's description."),
}

# ── (b) pinned — disclosed constants, changed only by editing this file ───

_PINNED: dict[str, Threshold] = {
    # ADR-V3-004: the TL derivation must not change during the parity
    # period. Changing a floor makes every parity difference
    # uninterpretable — improvement and regression become
    # indistinguishable. That is the strongest possible case for
    # "not runtime-variable".
    "TL1_SCORE_FLOOR": Threshold.pinned(
        9.0, unit="score",
        provenance_ref="S1-SCORE-004 TL1 floor; radar/scoring.py:1219; "
                       "ADR-V3-004 freezes it for parity"),
    "TL1_PHYSICAL_FLOOR": Threshold.pinned(
        3.0, unit="score",
        provenance_ref="S1-SCORE-004 TL1 physical gate; "
                       "tests/test_scenario_scoring.py::TestDeriveTL::"
                       "test_tl1_needs_physical pins physical 2.9 -> TL2"),
    "TL2_SCORE_FLOOR": Threshold.pinned(
        6.0, unit="score",
        provenance_ref="S1-SCORE-004 TL2 floor; radar/scoring.py:1221; "
                       "ADR-V3-004"),
    "TL2_MIN_DOMAINS": Threshold.pinned(
        2, unit="count",
        provenance_ref="S1-SCORE-004 TL2 domain gate; "
                       "tests/test_scenario_scoring.py::TestDeriveTL::"
                       "test_tl2_needs_two_domains pins 7.0/1 domain -> TL3"),
    "TL3_SCORE_FLOOR": Threshold.pinned(
        4.0, unit="score",
        provenance_ref="S1-SCORE-004 TL3 floor; radar/scoring.py:1223; "
                       "ADR-V3-004"),
    "TL4_SCORE_FLOOR": Threshold.pinned(
        2.0, unit="score",
        provenance_ref="S1-SCORE-004 TL4 floor; radar/scoring.py:1225; "
                       "ADR-V3-004"),
    # S1-SCORE-006/007. Both tiers are literals on the effective path
    # (radar/scoring.py:1170, 1173) — the CONVERGENCE_FULL_BONUS config key
    # is read only by the engine family, which O-14 excluded.
    "CONVERGENCE_FULL_BONUS": Threshold.pinned(
        2.0, unit="score",
        provenance_ref="S1-SCORE-007 tier table; literal 2.0 at "
                       "radar/scoring.py:1170 (the CONVERGENCE_FULL_BONUS "
                       "key is engine-family only — P6 O-14)"),
    "CONVERGENCE_DUAL_BONUS": Threshold.pinned(
        1.0, unit="score",
        provenance_ref="S1-SCORE-006/007 dual tier; literal 1.0 at "
                       "radar/scoring.py:1173"),
    "CONVERGENCE_FULL_MIN_DOMAINS": Threshold.pinned(
        3, unit="count",
        provenance_ref="S1-SCORE-003/007; radar/scoring.py:1168 (n >= 3)"),
    "CONVERGENCE_DUAL_MIN_DOMAINS": Threshold.pinned(
        2, unit="count",
        provenance_ref="S1-SCORE-003/007; radar/scoring.py:1172 (n == 2)"),
    "CONVERGENCE_MIN_PARTICIPANTS": Threshold.pinned(
        2, unit="count",
        provenance_ref="S1-SCORE-007 participant downgrade gate; "
                       "radar/scoring.py:1169 (n_distinct_participants < 2)"),
    # S1-PIPE-022's cap of 15 is deliberately ABSENT. It clips
    # `score_with_bonus` (radar/routes/core.py:2003), which is the engine
    # family's number and reaches alert_history / daily_summary / What-If
    # only. The served scenario score is floored at 0 and never clipped
    # above (radar/routes/core.py:2201-2202). Pinning the cap here would
    # have suppressed TL1 on precisely the ticks that earn it. Recorded as
    # a NON_EFFECTIVE exclusion in `registry`.
    # S1-SCORE-021 / 022: the chain shape. Changing any of these re-times
    # every sequence bonus at once, which is a re-calibration.
    "SEQUENCE_MIN_CHAIN": Threshold.pinned(
        3, unit="count",
        provenance_ref="S1-SCORE-021 minimum chain length; "
                       "radar/scoring.py:228 (found_count >= 3)"),
    "SEQUENCE_FULL_CHAIN": Threshold.pinned(
        4, unit="count",
        provenance_ref="S1-SCORE-021; radar/scoring.py:224 "
                       "(found_count == 4, the full chain_def)"),
    "SEQUENCE_DECAY_HORIZON_H": Threshold.pinned(
        24.0, unit="h",
        provenance_ref="S1-SCORE-021 linear decay horizon; "
                       "radar/scoring.py:220 (1.0 - age_hours / 24.0)"),
    "SEQUENCE_DECAY_FLOOR": Threshold.pinned(
        0.3, unit="ratio",
        provenance_ref="S1-SCORE-021 decay floor; "
                       "tests/test_engine.py::TestSequenceTemporalDecay pins "
                       "age 20h -> floor 0.3 -> bonus 1"),
    "SEQUENCE_MIN_BONUS": Threshold.pinned(
        1.0, unit="score",
        provenance_ref="radar/scoring.py:226,230 (max(1, decayed_bonus)) — "
                       "a qualifying chain never decays to zero. NOT "
                       "described by S1-SCORE-021"),
    "SEQUENCE_DEDUP_WINDOW_S": Threshold.pinned(
        300.0, unit="s",
        provenance_ref="S1-SCORE-022 / S1-PIPE-019 event dedup window"),
    # S1-PIPE-026's focused-only bonus set. NOTE: S1-scoring-pipeline §7
    # item 5 records that these constants have NO clause in
    # S1-scoring-core. They are transcribed from radar/scoring.py:1053-1058
    # and 1131-1133, which is unambiguous even though the spec is silent —
    # see the WP-2.4 report's spec-gap list.
    "VELOCITY_MIN_OBSERVATIONS": Threshold.pinned(
        4, unit="count",
        provenance_ref="radar/scoring.py:1057 VELOCITY_MIN_OBSERVATIONS "
                       "(no S1 clause)"),
    "ACCELERATION_MIN_OBSERVATIONS": Threshold.pinned(
        8, unit="count",
        provenance_ref="radar/scoring.py:1089 (len(series) < 8) "
                       "(no S1 clause)"),
    "VELOCITY_BONUS_CAP": Threshold.pinned(
        1.5, unit="score",
        provenance_ref="radar/scoring.py:1054 VELOCITY_BONUS_CAP — "
                       "~17% of the TL3->TL2 gap (no S1 clause)"),
    "VELOCITY_BONUS_SCALE": Threshold.pinned(
        0.5, unit="multiplier",
        provenance_ref="radar/scoring.py:1124 (pts/hour x 0.5) "
                       "(no S1 clause)"),
    "VELOCITY_EPSILON": Threshold.pinned(
        0.0001, unit="score",
        provenance_ref="radar/scoring.py:1121 (abs(velocity) > 0.0001) "
                       "(no S1 clause)"),
    "ACCELERATION_BONUS_MAX": Threshold.pinned(
        0.5, unit="score",
        provenance_ref="radar/scoring.py:1055 ACCELERATION_BONUS_MAX "
                       "(no S1 clause)"),
    "ACCELERATION_BONUS_SCALE": Threshold.pinned(
        0.3, unit="multiplier",
        provenance_ref="radar/scoring.py:1132 (pts/h^2 x 0.3) "
                       "(no S1 clause)"),
    "ACCELERATION_MIN_PTS_PER_H2": Threshold.pinned(
        0.1, unit="score",
        provenance_ref="radar/scoring.py:1131 (acc_pts_per_hour2 > 0.1) "
                       "(no S1 clause)"),
    "SILENT_DIVERGENCE_BONUS": Threshold.pinned(
        0.5, unit="score",
        provenance_ref="radar/scoring.py:1138 SILENT_DIVERGENCE_BONUS "
                       "(no S1 clause)"),
    "CONTEXT_ALIGNMENT_BONUS": Threshold.pinned(
        0.5, unit="score",
        provenance_ref="radar/scoring.py:1139 CONTEXT_ALIGNMENT_BONUS "
                       "(no S1 clause)"),
    # S1-SCORE-028.
    "TEMPORAL_COHERENCE_WINDOW_S": Threshold.pinned(
        10.0, unit="s",
        provenance_ref="S1-SCORE-028 (two scenarios' events within 10s)"),
    "TEMPORAL_COHERENCE_BONUS": Threshold.pinned(
        2.0, unit="score",
        provenance_ref="S1-SCORE-028 (+2 when synchronised)"),
}


def _pinned_number(name: str) -> float:
    """The constant behind a pinned threshold, as a plain number."""
    resolved = _PINNED[name].resolve().value
    # Ratio / Percentage arrive typed; the formulas want the fraction.
    return float(getattr(resolved, "value", resolved))


TL1_SCORE_FLOOR = _pinned_number("TL1_SCORE_FLOOR")
TL1_PHYSICAL_FLOOR = _pinned_number("TL1_PHYSICAL_FLOOR")
TL2_SCORE_FLOOR = _pinned_number("TL2_SCORE_FLOOR")
TL2_MIN_DOMAINS = int(_pinned_number("TL2_MIN_DOMAINS"))
TL3_SCORE_FLOOR = _pinned_number("TL3_SCORE_FLOOR")
TL4_SCORE_FLOOR = _pinned_number("TL4_SCORE_FLOOR")

CONVERGENCE_FULL_BONUS = _pinned_number("CONVERGENCE_FULL_BONUS")
CONVERGENCE_DUAL_BONUS = _pinned_number("CONVERGENCE_DUAL_BONUS")
CONVERGENCE_FULL_MIN_DOMAINS = int(_pinned_number("CONVERGENCE_FULL_MIN_DOMAINS"))
CONVERGENCE_DUAL_MIN_DOMAINS = int(_pinned_number("CONVERGENCE_DUAL_MIN_DOMAINS"))
CONVERGENCE_MIN_PARTICIPANTS = int(_pinned_number("CONVERGENCE_MIN_PARTICIPANTS"))

SEQUENCE_MIN_CHAIN = int(_pinned_number("SEQUENCE_MIN_CHAIN"))
SEQUENCE_FULL_CHAIN = int(_pinned_number("SEQUENCE_FULL_CHAIN"))
SEQUENCE_DECAY_HORIZON_H = _pinned_number("SEQUENCE_DECAY_HORIZON_H")
SEQUENCE_DECAY_FLOOR = _pinned_number("SEQUENCE_DECAY_FLOOR")
SEQUENCE_MIN_BONUS = _pinned_number("SEQUENCE_MIN_BONUS")
SEQUENCE_DEDUP_WINDOW_S = _pinned_number("SEQUENCE_DEDUP_WINDOW_S")

TEMPORAL_COHERENCE_WINDOW_S = _pinned_number("TEMPORAL_COHERENCE_WINDOW_S")
TEMPORAL_COHERENCE_BONUS = _pinned_number("TEMPORAL_COHERENCE_BONUS")

VELOCITY_MIN_OBSERVATIONS = int(_pinned_number("VELOCITY_MIN_OBSERVATIONS"))
ACCELERATION_MIN_OBSERVATIONS = int(
    _pinned_number("ACCELERATION_MIN_OBSERVATIONS"))
VELOCITY_BONUS_CAP = _pinned_number("VELOCITY_BONUS_CAP")
VELOCITY_BONUS_SCALE = _pinned_number("VELOCITY_BONUS_SCALE")
VELOCITY_EPSILON = _pinned_number("VELOCITY_EPSILON")
ACCELERATION_BONUS_MAX = _pinned_number("ACCELERATION_BONUS_MAX")
ACCELERATION_BONUS_SCALE = _pinned_number("ACCELERATION_BONUS_SCALE")
ACCELERATION_MIN_PTS_PER_H2 = _pinned_number("ACCELERATION_MIN_PTS_PER_H2")
SILENT_DIVERGENCE_BONUS = _pinned_number("SILENT_DIVERGENCE_BONUS")
CONTEXT_ALIGNMENT_BONUS = _pinned_number("CONTEXT_ALIGNMENT_BONUS")

# S1-SCORE-021's chain definition, in order. Not a threshold — a
# vocabulary — but pinned for the same reason: adding a link silently
# re-scales every chain that was previously "full".
SEQUENCE_CHAIN_TYPES: tuple[str, ...] = (
    "NARRATIVE_BURST", "ISR_SURGE", "SYNC_DDOS", "FIRMS_ANOMALY")


def pinned_threshold(name: str) -> Threshold:
    """The declaration behind a constant, for disclosure (NP6)."""
    return _PINNED[name]


def pinned_names() -> tuple[str, ...]:
    return tuple(sorted(_PINNED))


__all__ = [
    "VARIABLE", "VariableKey", "pinned_threshold", "pinned_names",
    "TL1_SCORE_FLOOR", "TL1_PHYSICAL_FLOOR", "TL2_SCORE_FLOOR",
    "TL2_MIN_DOMAINS", "TL3_SCORE_FLOOR", "TL4_SCORE_FLOOR",
    "CONVERGENCE_FULL_BONUS", "CONVERGENCE_DUAL_BONUS",
    "CONVERGENCE_FULL_MIN_DOMAINS", "CONVERGENCE_DUAL_MIN_DOMAINS",
    "CONVERGENCE_MIN_PARTICIPANTS",
    "SEQUENCE_MIN_CHAIN", "SEQUENCE_FULL_CHAIN", "SEQUENCE_DECAY_HORIZON_H",
    "SEQUENCE_DECAY_FLOOR", "SEQUENCE_MIN_BONUS", "SEQUENCE_DEDUP_WINDOW_S",
    "SEQUENCE_CHAIN_TYPES",
    "TEMPORAL_COHERENCE_WINDOW_S", "TEMPORAL_COHERENCE_BONUS",
    "VELOCITY_MIN_OBSERVATIONS", "ACCELERATION_MIN_OBSERVATIONS",
    "VELOCITY_BONUS_CAP", "VELOCITY_BONUS_SCALE", "VELOCITY_EPSILON",
    "ACCELERATION_BONUS_MAX", "ACCELERATION_BONUS_SCALE",
    "ACCELERATION_MIN_PTS_PER_H2",
    "SILENT_DIVERGENCE_BONUS", "CONTEXT_ALIGNMENT_BONUS",
]
