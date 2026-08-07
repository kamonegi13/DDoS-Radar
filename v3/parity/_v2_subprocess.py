"""Runs INSIDE the legacy driver's subprocess. Never imported in-process.

This module imports `radar.*`, which is why every import is inside
`main()` and why `v3/parity/driver_v2.py` spawns it rather than calling it.
Importing it from the parent process would boot the legacy application:
40 threads, live outbound HTTP within 0.3 s (OpenSky has zero stagger),
`RadarDB.__init__` running an integrity check and the full migration chain
against `radar/persistence/radar.db`, plus atexit handlers that write state
at interpreter shutdown regardless of what the program did.

**How the boot is avoided.** Not by environment flags — only two of the
39 threads are gated (`BG_SCORING_ENABLED`, `BG_OBSERVER_ENABLED`), and
`PERSISTENCE_DIR` is derived from `radar/config.py`'s own `__file__` with
no override, so the database path cannot be redirected by configuration.
Instead, two entries are placed in `sys.modules` BEFORE any radar import:

  1. a synthetic `radar` package carrying only `__path__`. Python skips
     `radar/__init__.py` when the package is already in `sys.modules`, and
     every thread spawn, `restore_state()`, `startup_cleanup()`, atexit
     handler and signal handler lives in that file.
  2. a stub `radar.database` whose `db` refuses every attribute. This
     prevents `radar/database.py:7094`'s module-level
     `RadarDB(_DB_PATH)` — the one heavy dependency `radar/scoring.py`
     pulls in — from ever constructing.

The stub is a firewall, not a redirect. Nothing is pointed at a scratch
database; any database access simply raises. That is a stronger guarantee
than isolation-by-temp-file, because it PROVES the scoring path performed
no I/O rather than hiding where the I/O went (S5-VERIF-021).

**What still runs, honestly stated:**
  * `radar/config.py` reads `config.env` and `geo_data.json` from the
    working directory at import (`config.py:34`, `:110`). Both are
    read-only. `config.env` holds secrets, which therefore enter this
    subprocess's environment — it is spawned with the repo as cwd and
    inherits no more than the parent already had.
  * `radar/scoring.py` creates three module-level `threading.Lock()`
    objects. Locks, not threads; measured thread count stays at 1.
  * `compute_scenario_score` ends by attempting conclusion persistence.
    `radar.config.V2_CONCLUSION_LEDGER_ENABLED` is set False on the module
    after import to skip it, and the stub catches it regardless — those
    calls sit inside the legacy code's own "non-fatal" handlers, so the
    returned score is unaffected either way.
  * Exactly ONE database call is still attempted, and it is a read:
    `radar/scenarios.py:232`'s `validate_scenario_id` consults the
    reserved-identifier table while a Scenario is being constructed. The
    stub refuses it, the legacy code treats the failure as non-fatal, and
    the scenario parses anyway. It is reported in `database_attempts` so
    the harness states it rather than implying zero.
    Verified: 8 radar modules load, 1 thread, one refused read, and the
    real database's mtime does not change.

**What is NOT compared, and why.** The focused-scenario bonus fold
(S1-PIPE-026: sequence, temporal coherence, velocity, acceleration,
silent divergence, context alignment) lives inside the GET handler at
`radar/routes/core.py:2156-2213`, not inside any callable function. It
cannot be invoked without the HTTP layer, and reimplementing it here is
exactly what S5-VERIF-031 forbids. The harness therefore compares the
scoring CORE — contributions, dedup, domain totals, convergence bonus,
`derive_tl`, `apply_hysteresis_to_tl` — and the v3 side is driven with no
focused scenario so that neither side folds bonuses. This becomes
comparable once D2 A-01's decomposition extracts that block.
"""
from __future__ import annotations

import json
import sys

#: The signal source production stamps on an intel contribution
#: (`radar/intel_queue.py:1024-1025` returns `sensor` and `signal_source`
#: both as this literal). The v3 projection recovers `origin` from the same
#: string (`v3/parity/adapter.py`), so a test compares the two spellings
#: rather than letting one import the other — this module is the LEGACY
#: side and must not take its vocabulary from the rewrite.
LLM_INTEL_SIGNAL_SOURCE = "llm_intel"

#: No environment variables are set. They would be pointless here: every
#: switch the legacy system exposes (`BG_SCORING_ENABLED`,
#: `BG_OBSERVER_ENABLED`, `RADAR_RATE_LIMIT_ENABLED`, `PLUGIN_ENABLED`)
#: gates something inside `radar/__init__.py`, and that file never runs
#: under the stub. The one flag that does matter — the v2 conclusion
#: ledger — is turned off as a module attribute after import, below.


class _RefusingDatabase:
    """Stands in for the legacy DB singleton and answers nothing.

    Every access raises, and the caller (legacy code) catches it in its own
    non-fatal handler. The list of what was attempted is reported back, so
    the harness can state exactly which database calls the scoring path
    tried to make rather than assuming it made none.
    """

    def __init__(self):
        self.attempts: list[str] = []

    def __getattr__(self, name: str):
        if name.startswith("_ipython") or name.startswith("__"):
            raise AttributeError(name)

        def _refuse(*args, **kwargs):
            self.attempts.append(name)
            raise AssertionError(
                f"parity replay attempted database access ({name}); "
                f"S5-VERIF-021 forbids it")
        return _refuse


def _install_sandbox():
    """Put the two stubs in `sys.modules`, then return the refusing DB."""
    import os.path
    import types

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))

    package = types.ModuleType("radar")
    package.__path__ = [os.path.join(repo_root, "radar")]
    sys.modules["radar"] = package

    database = types.ModuleType("radar.database")
    refusing = _RefusingDatabase()
    database.db = refusing
    sys.modules["radar.database"] = database
    return refusing


def _build_scenario(spec: dict):
    from radar.scenarios import _parse_scenario_json
    return _parse_scenario_json(spec["scenario_id"], {
        "name_en": spec.get("name_en", spec["scenario_id"]),
        "name_ja": spec.get("name_ja", spec["scenario_id"]),
        "core_country": spec.get("core_country"),
        "participants": {
            country: {"weight": entry["weight"], "role": entry["role"]}
            for country, entry in spec["participants"].items()
        },
    })


def _intel_age_weight(age_sec: float, source_type: str = "") -> float:
    """PRODUCTION's age term, called. Not a second implementation.

    `radar/intel_queue.py:88-106`. S5-VERIF-031 forbids reproducing a
    formula in the harness, and this one is worth the clause twice over:
    the function reads its tau from the environment
    (`INTEL_AGE_DECAY_TAU_HOURS`, `config.env:96` = 12.0) and can be
    switched off entirely (`INTEL_AGE_DECAY_ENABLED`). A copy here would
    hold the deployed value at the moment it was written and then quietly
    stop agreeing with the system it is supposed to be measuring.

    `source_type` is passed empty. The per-source tau override
    (`INTEL_AGE_DECAY_TAU_HOURS_<TYPE>`) is unset in the deployed
    `config.env` and is deliberately not ported (design sheet §7-2 #36) —
    but the base tau IS read live, so a changed deployment shows up here as
    a real disagreement with v3's pinned 12h rather than being absorbed.
    """
    from radar.intel_queue import _age_weight
    return float(_age_weight(age_sec, source_type))


def _production_score(row: dict, *, now: float) -> float:
    """The number production's scoring core actually receives.

    An intel row is the one case where the ledger's `raw_score` is NOT
    what legacy scores. `intel_queue.get_active_rationale` multiplies
    `score_delta` by the age weight and publishes the PRODUCT as `score`
    (`radar/intel_queue.py:1001-1003`, `:1026`), and both consumers take
    that field (`radar/routes/core.py:1925` positional 5, `:2078`
    `raw_score=`). v3 stores the undecayed number with the item's own
    `observed_at` and applies the term in L2 instead, so handing the raw
    number to this side compared a decayed reading against an undecayed
    one and blamed the difference on the rewrite (§7-2 #38).

    Age is measured from the item's `observed_at` to the TICK, which is
    what `now = time.time()` means at `get_active_rationale`'s call site.
    Production then overwrites the timestamp with the tick's own clock
    (`core.py:2074`), which is why the age has to be taken here — one
    step later it no longer exists.
    """
    score = float(row.get("raw_score") or 0.0)
    if (row.get("signal_source") or "") != LLM_INTEL_SIGNAL_SOURCE:
        return score
    return score * _intel_age_weight(now - float(row["observed_at"]))


def _build_signals(rows: list, scoring, *, now: float):
    """Rows -> legacy Signals, via the REAL `rationale_to_signal`.

    The admission predicate (suppressed / not FIRED / score <= 0) and the
    empty-signal_source fallback are NOT reproduced here. They live in
    `radar/scoring.py:rationale_to_signal`, and copying them into the
    harness is the exact anti-pattern S5-VERIF-031 names — the clause's
    cited example is a hand-copied `derive_tl` that stopped tracking its
    original. A `None` return IS the rejection.
    """
    from radar.models import RationaleEntry

    signals = []
    for row in rows:
        country = (row.get("country") or "").strip()
        if country.upper() == "GLOBAL":
            country = ""      # legacy spells a countryless signal as ""
        entry = RationaleEntry(
            sensor=row["sensor"],
            domain=row["domain"],
            status=row["status"],
            value=str(row.get("value") or ""),
            score=_production_score(row, now=now),
            suppressed=bool(row.get("suppressed")),
            suppress_reason=row.get("suppress_reason"),
            confidence=(1.0 if row.get("confidence") is None
                        else float(row["confidence"])),
            signal_source=row.get("signal_source") or "",
        )
        signal = scoring.rationale_to_signal(
            entry, source_country=country,
            observed_at=float(row["observed_at"]),
            evidence_url=row.get("evidence_url") or None)
        if signal is not None:
            signals.append(signal)
    return signals


def main() -> int:
    refusing = _install_sandbox()

    import logging
    logging.disable(logging.CRITICAL)   # keep stdout pure JSON

    # Set on the module rather than through the environment: `config.env`
    # sets this true (`config.env:201`), and the conclusion tail of
    # compute_scenario_score would otherwise attempt ledger writes. The
    # refusing stub would catch them, but not attempting is cleaner than
    # being caught.
    import radar.config as radar_config
    radar_config.V2_CONCLUSION_LEDGER_ENABLED = False

    request = json.loads(sys.stdin.read())

    # The legacy scoring path reads these off `radar.config` at call time
    # rather than taking them as arguments, so the settings the v3 side is
    # given have to be mirrored onto the module or the two sides are
    # running different configurations and every difference is
    # misattributed to the rewrite.
    for key, value in (request.get("config_overrides") or {}).items():
        if not hasattr(radar_config, key):
            raise AssertionError(
                f"parity config override {key!r} does not exist on "
                f"radar.config; setting it would be a no-op that looks "
                f"like a control")
        setattr(radar_config, key, value)

    import radar.scoring as scoring
    scenarios = {spec["scenario_id"]: _build_scenario(spec)
                 for spec in request["scenarios"]}
    domain_cap = float(request.get("domain_cap", 6.0))
    global_weight = float(request.get("global_signal_weight", 0.5))

    previous_tl: dict = dict(request.get("previous_tl") or {})
    results = []

    for tick in request["ticks"]:
        signals = _build_signals(tick["rows"], scoring,
                                 now=float(tick["tick_ts"]))
        for scenario_id, scenario in scenarios.items():
            # THE REAL FUNCTIONS. S5-VERIF-031: no formula is reproduced
            # here; this file only marshals arguments.
            state = scoring.compute_scenario_score(
                scenario, signals, False,
                global_signal_weight=global_weight, domain_cap=domain_cap)
            held, was_held = scoring.apply_hysteresis_to_tl(
                state.tl, previous_tl.get(scenario_id))
            previous_tl[scenario_id] = held
            results.append({
                "tick_ts": tick["tick_ts"],
                "scenario_id": scenario_id,
                "tl": held,
                "raw_tl": state.tl,
                "hysteresis_held": bool(was_held),
                "score": state.score,
                "domains": dict(state.domains),
                "convergence_bonus": state.convergence_bonus,
                "active_countries": list(state.active_countries),
                "contributions": [
                    {"sensor": c.signal.sensor,
                     "signal_source": c.signal.signal_source,
                     "country": c.contributing_country,
                     "score": c.final_contribution,
                     "trace": c.formula_trace}
                    for c in state.contributions],
            })

    json.dump({
        "results": results,
        "formula_ref": "radar/scoring.py#compute_scenario_score+derive_tl"
                       "+apply_hysteresis_to_tl",
        "database_attempts": sorted(set(refusing.attempts)),
        "radar_modules": sorted(m for m in sys.modules
                                if m == "radar" or m.startswith("radar.")),
        "thread_count": __import__("threading").active_count(),
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
