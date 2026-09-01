"""Replaying the legacy side, through a subprocess that never boots the app.

The parent process — every module under `v3/` — must never import `radar`;
the kernel discipline gate enforces it over the whole tree. So the legacy
scoring functions are invoked by spawning `_v2_subprocess`, which installs
the `sys.modules` sandbox described in its docstring and then calls the
REAL `compute_scenario_score` / `apply_hysteresis_to_tl` (S5-VERIF-031
forbids reproducing them here).

The subprocess reports back what it touched — database attempts, loaded
radar modules, thread count — and `replay()` verifies those claims rather
than trusting them. A run that boots the application is a run whose
results were produced under different conditions than it declares, so it
fails loudly instead of returning numbers.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

from v3.intel import adjudication as INTEL
from v3.kernel import ThreatLevel
from v3.kernel.errors import DomainError
from v3.parity.adapter import LedgerInputAdapter, to_wire
from v3.parity.compare import THREAT_LEVEL, Contributor, Reading, TickKey
from v3.parity.driver_v3 import ReplayResult
from v3.ledger import LedgerStore
from v3.scoring import Scenario

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SUBPROCESS_MODULE = "v3.parity._v2_subprocess"
DEFAULT_TIMEOUT_SEC = 600

#: The sandbox is only honest if these hold. `radar.routes` or
#: `radar.sensors` appearing means `radar/__init__.py` ran after all.
FORBIDDEN_MODULE_PREFIXES = ("radar.routes", "radar.sensors",
                             "radar.scheduler", "radar.ws")

#: Everything the scoring dependency chain legitimately pulls in. Checked
#: on every run, not only in tests: a NEW radar module appearing means the
#: sandbox's reach changed, and whether that is safe is a decision for a
#: reviewer rather than a surprise discovered later in a parity number.
EXPECTED_MODULES = frozenset({
    "radar", "radar.config", "radar.config_layered", "radar.database",
    "radar.models", "radar.state", "radar.scoring", "radar.scenarios",
    "radar.conclusions", "radar.geo",
    # Admitted 2026-08-08 for §7-2 #38: the driver must apply production's
    # OWN intel age term (`_age_weight`) rather than a copy, and calling it
    # means importing the module that owns it. Reviewed at import time
    # before admitting, which is what this check exists to force:
    #   * one logger and one INFO line about the decay setting
    #   * one `threading.Lock` — a lock, not a thread (`:302`); the
    #     measured thread count stays 1 and the harness asserts it
    #   * module-level data (credibility bootstrap, media ecosystems,
    #     stopwords, dedup constants)
    #   * `intel_queue = IntelQueue()` at `:1211`, and the class defines no
    #     `__init__`, so construction touches nothing
    #   * `from radar.database import db` binds the refusing stub; every
    #     use of it is inside a method none of which this path calls
    "radar.intel_queue",
})


@dataclass(frozen=True, slots=True)
class SandboxEvidence:
    """What the subprocess reports about its own isolation."""

    radar_modules: tuple[str, ...] = ()
    database_attempts: tuple[str, ...] = ()
    thread_count: int = 1

    @property
    def booted_application(self) -> bool:
        return any(module.startswith(prefix)
                   for module in self.radar_modules
                   for prefix in FORBIDDEN_MODULE_PREFIXES)

    def as_dict(self) -> dict:
        return {"radar_modules": list(self.radar_modules),
                "database_attempts": list(self.database_attempts),
                "thread_count": self.thread_count,
                "booted_application": self.booted_application}


@dataclass(frozen=True, slots=True)
class LegacyReplayResult(ReplayResult):
    """A ReplayResult plus the isolation evidence for the run."""

    sandbox: SandboxEvidence = field(default_factory=SandboxEvidence)


def scenario_to_spec(scenario) -> dict:
    """A v3 `Scenario` as the subprocess's JSON scenario spec.

    Both sides are built from THIS one description, so a difference in
    participants or weights cannot be the reason they disagree
    (S5-VERIF-031).
    """
    return {
        "scenario_id": scenario.scenario_id,
        "core_country": scenario.core_country,
        "participants": {
            participant.country: {
                "weight": participant.weight.value,
                "role": participant.role or "primary_target",
            }
            for participant in scenario.participants
        },
    }


def replay(store: LedgerStore, scenarios: Sequence[Scenario], *,
           start: float, end: float,
           tick_interval_sec: float, domain_cap: float = 6.0,
           global_signal_weight: float = 0.5,
           config_overrides: Optional[Mapping[str, object]] = None,
           previous_tl: Optional[Mapping[str, int]] = None,
           timeout_sec: int = DEFAULT_TIMEOUT_SEC,
           python_executable: Optional[str] = None) -> LegacyReplayResult:
    """Score the window with the legacy formulas, in a sandboxed subprocess."""
    if not scenarios:
        raise DomainError("legacy replay needs at least one scenario")
    adapter = LedgerInputAdapter(store, tick_interval_sec=tick_interval_sec)
    request = {
        "scenarios": [scenario_to_spec(s) for s in scenarios],
        "domain_cap": domain_cap,
        "global_signal_weight": global_signal_weight,
        "previous_tl": dict(previous_tl or {}),
        "config_overrides": dict(config_overrides or {}),
        # The SAME admission predicate the v3 side applies (§7-2 #105).
        # Production would not have scored an unadjudicated intel item
        # either — `get_active_rationale` selects `auto_confirmed` and
        # `confirmed` only — so feeding one to the legacy formulas here
        # would manufacture a disagreement the harness invented. This is
        # the §7-2 #38 lesson applied to a second asymmetry: both sides
        # must receive the input each system would actually have.
        "ticks": [{"tick_ts": tick.tick_ts,
                   "rows": to_wire(INTEL.scoreable_rows(
                       store, tick.rows, until=tick.tick_ts))}
                  for tick in adapter.ticks(start, end)],
    }

    try:
        completed = subprocess.run(
            [python_executable or sys.executable, "-m", SUBPROCESS_MODULE],
            input=json.dumps(request), capture_output=True, text=True,
            cwd=str(REPO_ROOT), timeout=timeout_sec)
    except subprocess.TimeoutExpired as exc:
        # Same diagnostic quality as the exit-code path: a 30-day window
        # is one call with ~21,600 ticks, so "it timed out" without the
        # shape of the request is not actionable.
        captured = (exc.stderr or b"")
        if isinstance(captured, bytes):
            captured = captured.decode("utf-8", "replace")
        raise RuntimeError(
            f"legacy parity driver timed out after {timeout_sec}s with "
            f"{len(request['ticks'])} tick(s) x {len(request['scenarios'])} "
            f"scenario(s). The subprocess is spawned ONCE for the whole "
            f"window; raise timeout_sec for long windows.\n"
            f"{captured[-4000:]}") from exc
    if completed.returncode != 0:
        raise RuntimeError(
            f"legacy parity driver failed (exit {completed.returncode}):\n"
            f"{completed.stderr[-4000:]}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"legacy parity driver produced non-JSON stdout — something "
            f"printed over the protocol:\n{completed.stdout[:2000]}") from exc

    sandbox = SandboxEvidence(
        radar_modules=tuple(payload.get("radar_modules", ())),
        database_attempts=tuple(payload.get("database_attempts", ())),
        thread_count=int(payload.get("thread_count", 1)))
    # Verify the isolation claim rather than trusting it.
    unexpected = sorted(set(sandbox.radar_modules) - EXPECTED_MODULES)
    if unexpected:
        raise RuntimeError(
            f"the legacy driver loaded radar modules outside the sandbox's "
            f"known set: {unexpected}. The scoring dependency chain has "
            f"changed; review what those modules do at import time before "
            f"extending EXPECTED_MODULES, because this check is what stands "
            f"between a parity run and an application boot.")
    if sandbox.booted_application:
        raise RuntimeError(
            f"the legacy driver booted the application — results were "
            f"produced under uncontrolled conditions (threads, network, "
            f"production database). Modules: {sandbox.radar_modules}")

    readings: dict[TickKey, Reading] = {}
    series: dict[str, list] = {}
    for row in payload["results"]:
        level = None if row["tl"] is None else ThreatLevel(int(row["tl"]))
        reading = Reading(
            threat_level=level,
            state=None if level is None else f"TL{level.value}",
            contributing=tuple(
                Contributor(c["sensor"], c["signal_source"], c["country"])
                for c in row["contributions"]))
        key = TickKey(row["scenario_id"], THREAT_LEVEL, row["tick_ts"])
        readings[key] = reading
        series.setdefault(row["scenario_id"], []).append(
            (row["tick_ts"], reading))

    return LegacyReplayResult(
        readings=readings,
        tl_series={key: tuple(value) for key, value in series.items()},
        formula_ref=payload.get("formula_ref", ""),
        thresholds={"domain_cap": domain_cap,
                    "global_signal_weight": global_signal_weight,
                    **dict(config_overrides or {})},
        sandbox=sandbox)


__all__ = ["replay", "LegacyReplayResult", "SandboxEvidence",
           "scenario_to_spec", "SUBPROCESS_MODULE",
           "FORBIDDEN_MODULE_PREFIXES"]
