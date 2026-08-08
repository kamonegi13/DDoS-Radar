"""The closed vocabularies L3 publishes, and the NP7 text it must carry.

Two enumerations and one string. All three are closed on purpose:

    ConclusionType        the five outputs the tool definition names
    UnavailableReason     the four answers to "why can't you tell me?"
    NP7_DISCLAIMER        the sentence that says this is not the verdict

`UnavailableReason` is the one that earned its own module. F-12 found
three of its four values with no generation path anywhere in the codebase,
so every inability to conclude arrived as `insufficient_data` and an
analyst could not tell "the feeds are down" from "the world is quiet". The
enum was not the defect; the enum with nothing behind it was. So the values
live here and the conditions that produce them live in `availability.py`,
where a registry pairs each reason with the guard that emits it and a test
reaches every one (cutover condition C-08, override forbidden).
"""
from __future__ import annotations

from v3.kernel.errors import DomainError

# ── the five outputs (CLAUDE.md's tool definition, S1-CONC-001) ────────────
THREAT_LEVEL = "threat_level"
TREND = "trend"
PER_DOMAIN = "per_domain"
ANOMALY = "anomaly"
ATTACK_MODE = "attack_mode"

CONCLUSION_TYPES: tuple[str, ...] = (THREAT_LEVEL, TREND, PER_DOMAIN,
                                     ANOMALY, ATTACK_MODE)

# ── the four reasons (S1-CONC-003, F-12) ──────────────────────────────────
INSUFFICIENT_DATA = "insufficient_data"
CALIBRATION_PENDING = "calibration_pending"
SENSOR_DEGRADED = "sensor_degraded"
UPSTREAM_FAILURE = "upstream_failure"

UNAVAILABLE_REASONS: tuple[str, ...] = (INSUFFICIENT_DATA, CALIBRATION_PENDING,
                                        SENSOR_DEGRADED, UPSTREAM_FAILURE)

# S1-CONC-001 / §3: the exact production string, pinned rather than
# configured. O-18: NP6 asks for disclosure, not runtime variability, and
# a disclaimer an operator can blank is a disclaimer that can go missing.
NP7_DISCLAIMER = ("Tool conclusion only — final judgment by organizational "
                  "process.")

# S1-CONC-044: the tool is "alert" at severity >= 3 (TL1..TL3) and "calm"
# below it. The same number decides which conclusions a guard may suppress
# (NP1: an alarm is never withheld for want of clean inputs), so it is
# stated once, here.
ALERT_MIN_SEVERITY = 3


def require_conclusion_type(value: str) -> str:
    if value not in CONCLUSION_TYPES:
        raise DomainError(
            f"unknown conclusion type {value!r}; the tool publishes exactly "
            f"{list(CONCLUSION_TYPES)} (CLAUDE.md's five outputs)")
    return value


def require_unavailable_reason(value: str) -> str:
    if value not in UNAVAILABLE_REASONS:
        raise DomainError(
            f"unknown unavailable reason {value!r}; the closed set is "
            f"{list(UNAVAILABLE_REASONS)} (S1-CONC-003). Adding a reason "
            f"means adding a guard in availability.py — a reason with no "
            f"generation path is defect F-12.")
    return value


__all__ = [
    "THREAT_LEVEL", "TREND", "PER_DOMAIN", "ANOMALY", "ATTACK_MODE",
    "CONCLUSION_TYPES",
    "INSUFFICIENT_DATA", "CALIBRATION_PENDING", "SENSOR_DEGRADED",
    "UPSTREAM_FAILURE", "UNAVAILABLE_REASONS",
    "NP7_DISCLAIMER", "ALERT_MIN_SEVERITY",
    "require_conclusion_type", "require_unavailable_reason",
]
