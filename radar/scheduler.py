"""radar.scheduler -- Background sensor scheduler and cache cleanup."""
from __future__ import annotations
import logging
import time
import threading
from radar.config import (
    DEFAULT_FOCUSED_SCENARIO,
    CF_HEADERS, OWM_API_KEY,
    GDELT_TONE_ALERT_THRESHOLD, GDELT_HISTORY_WINDOW,
    CACHE_EXPIRY, SEQUENCE_WINDOW,
)
from radar.sensors.base import BaseSensor
from radar.state import _cf_scoring_cache, _cf_cache_lock
from radar.database import db as _db
from radar.scoring import _asn_cache

log = logging.getLogger("radar")

def _build_default_context() -> dict:
    """Build sensor context from the focused scenario + all enabled scenarios
    (ADR-005). Per-country sensors target the focused scenario's participants;
    LLM sensors receive the union across all scorable scenarios.

    The "focused" set is the union of analyst-active focuses recorded in
    `radar.state._active_focus` (TTL-bounded) plus DEFAULT_FOCUSED_SCENARIO.
    This keeps FOCUSED_ONLY sensors in sync with the analyst's current view
    (scenario-refactor §8.1, P0-3)."""
    from radar.scenarios import (
        scenario_store, derive_country_context, derive_global_fetch_targets,
    )
    from radar.state import get_active_focus_ids

    # Collect the analyst-active focuses, falling back to the default.
    _focus_ids = list(get_active_focus_ids())
    if DEFAULT_FOCUSED_SCENARIO not in _focus_ids:
        _focus_ids.append(DEFAULT_FOCUSED_SCENARIO)

    focused_scenarios = [sc for sc in (scenario_store.get(sid) for sid in _focus_ids) if sc]
    if not focused_scenarios:
        _fallback = scenario_store.scorable()
        if _fallback:
            focused_scenarios = [_fallback[0]]

    if not focused_scenarios:
        # Store not yet loaded — return minimal context; scheduler will pick
        # up real targets on the next cycle.
        return {
            "all_targets": [], "strategic_theaters": [], "adversary_states": [],
            "all_participant_countries": [],
            "cf_headers": CF_HEADERS, "owm_api_key": OWM_API_KEY,
            "weather_conditions": {},
            "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD,
            "gdelt_history_window": GDELT_HISTORY_WINDOW,
        }

    # Union per-country targets across every active focus.
    strategic: set[str] = set()
    adversaries: set[str] = set()
    for sc in focused_scenarios:
        ctx = derive_country_context(sc)
        strategic |= set(ctx["strategic_theaters"])
        adversaries |= set(ctx["adversary_states"])

    global_targets = derive_global_fetch_targets()
    return {
        "all_targets":         sorted(strategic | adversaries),
        "strategic_theaters":  sorted(strategic),
        "adversary_states":    sorted(adversaries),
        "all_participant_countries": global_targets["all_participant_countries"],
        "cf_headers":          CF_HEADERS,
        "owm_api_key":         OWM_API_KEY,
        "weather_conditions":  {},
        "gdelt_tone_threshold": GDELT_TONE_ALERT_THRESHOLD,
        "gdelt_history_window": GDELT_HISTORY_WINDOW,
    }

def _sensor_scheduler_worker(sensor: BaseSensor, registry=None,
                             initial_delay: float = 0.0):
    """Dedicated background fetch thread for a sensor.
    - Normal: periodic fetch every poll_interval
    - On failure: retry up to 3 times at shorter intervals [5min, 10min, 30min]
    - Emits sensor_status via WS on health changes
    - initial_delay: seconds to wait before first fetch (for staggering shared-API sensors)
    """
    from radar.ws import emit_sensor_status

    if not sensor.enabled:
        log.info(f"[Sensor/{sensor.name}] DISABLED — waiting for re-enablement")
        while not sensor.enabled:
            time.sleep(60)
        log.info(f"[Sensor/{sensor.name}] RE-ENABLED — starting scheduler")

    if initial_delay > 0:
        time.sleep(initial_delay)

    _last_health = sensor.health
    # Track whether a persistent-CIRCUIT_OPEN warning has been emitted so
    # we don't spam the log on every skip cycle.
    _cb_persistent_warned = False

    def _do_fetch() -> bool:
        ctx = _build_default_context()
        ctx["_registry"] = registry
        if sensor.name == "gdelt":
            owm = registry.get("openweather")
            if owm: ctx["weather_conditions"] = owm.get_cache().get("conditions", {})
        sensor.fetch(ctx)
        log_entries = sensor.get_fetch_log()
        return bool(log_entries and log_entries[-1].get("success"))

    def _check_health_change():
        nonlocal _last_health
        new_health = sensor.health
        if new_health != _last_health:
            log.info(f"[Sensor/{sensor.name}] Health: {_last_health} → {new_health}")
            emit_sensor_status(sensor.name, new_health)
            _last_health = new_health

    def _guarded_fetch() -> bool:
        """Fetch with circuit breaker integration."""
        nonlocal _cb_persistent_warned
        if sensor.cb_should_skip():
            # Emit a one-time warning when CB has failed 2+ probes
            # (recovery_delay > CB_INITIAL_DELAY means at least one probe already failed)
            with sensor._lock:
                delay = sensor._cb_recovery_delay
            if delay > sensor.CB_INITIAL_DELAY and not _cb_persistent_warned:
                log.error(
                    f"[CB/{sensor.name}] Sensor has been CIRCUIT_OPEN through multiple "
                    f"recovery probes (next retry in {delay:.0f}s) — "
                    f"check connectivity or API availability"
                )
                emit_sensor_status(sensor.name, "CIRCUIT_OPEN_PERSISTENT")
                _cb_persistent_warned = True
            return False
        try:
            ok = _do_fetch()
        except Exception as e:
            log.error(f"[Sensor/{sensor.name}] Fetch error: {e}")
            ok = False
        if ok:
            sensor.cb_record_success()
            _cb_persistent_warned = False  # Reset on recovery
        else:
            sensor.cb_record_failure()
        _check_health_change()
        return ok

    # Initial fetch: yield to event loop between attempts so HTTP requests
    # are not starved when many sensors start concurrently under gevent.
    _STARTUP_RETRY_DELAYS = [60, 300, 600]  # 1min, 5min, 10min
    time.sleep(0)  # yield to gevent event loop before first fetch
    if not _guarded_fetch():
        for delay in _STARTUP_RETRY_DELAYS:
            time.sleep(delay)
            if _guarded_fetch():
                break

    while True:
        time.sleep(sensor.poll_interval)
        _guarded_fetch()


# ── Cache cleanup worker ──
_CF_CACHE_MAX_SIZE = 1000  # Hard cap on _cf_scoring_cache entries


def _cache_cleanup_worker(registry=None):
    """Daemon thread: removes expired cache entries from all caches every hour.
    Also runs a full SQLite prune + WAL checkpoint once every 24 hours.
    """
    CLEANUP_INTERVAL  = 3600   # 1 hour
    DB_CLEANUP_EVERY  = 24     # cycles → once per day
    SEQ_LOG_WINDOW    = SEQUENCE_WINDOW  # 24h
    _cycle = 0

    while True:
        time.sleep(CLEANUP_INTERVAL)
        _cycle += 1
        try:
            now = time.time()

            # sequence_event_log: prune old events in SQLite
            _db.seq_cleanup(now - SEQ_LOG_WINDOW)

            # _cf_scoring_cache: sweep expired entries, then enforce MAX SIZE cap
            with _cf_cache_lock:
                for k in [k for k, v in list(_cf_scoring_cache.items())
                          if now - v["time"] > CACHE_EXPIRY * 3]:
                    _cf_scoring_cache.pop(k, None)
                # If still over cap after TTL eviction, drop oldest entries
                if len(_cf_scoring_cache) > _CF_CACHE_MAX_SIZE:
                    overflow = len(_cf_scoring_cache) - _CF_CACHE_MAX_SIZE
                    oldest = sorted(_cf_scoring_cache.items(), key=lambda x: x[1]["time"])
                    for k, _ in oldest[:overflow]:
                        _cf_scoring_cache.pop(k, None)

            # _asn_cache: sweep expired entries
            for k in [k for k, v in list(_asn_cache.items()) if now - v["time"] > CACHE_EXPIRY * 3]:
                _asn_cache.pop(k, None)

            # greynoise _ip_cache: remove entries older than TTL
            gn = registry.get("greynoise")
            if gn:
                with gn._ip_lock:
                    stale_ips = [k for k, v in list(gn._ip_cache.items())
                                 if now - v["fetched_at"] > gn.IP_CACHE_TTL]
                    for k in stale_ips:
                        gn._ip_cache.pop(k, None)

            log.info(f"[Cleanup] cycle={_cycle} baseline={_db.baseline_len()} "
                     f"seqlog={_db.seq_total()} "
                     f"cf_cache={len(_cf_scoring_cache)} asn_cache={len(_asn_cache)}")

            # Auto-reject stale pending intel items
            from radar.intel_queue import intel_queue as _iq
            _iq.auto_reject_stale()

            # Deterministic auto-judge recheck (Phase 4 commit 5).
            # Runs on the same cadence as auto_reject_stale; LLM-free, so
            # it works in air-gapped deployments. Decisions are tagged
            # analyst="auto:rule_*" for analyst-recall exclusion.
            try:
                from radar.intel_auto_judge import run_sweep as _aj_sweep
                _aj_summary = _aj_sweep(limit=200)
                if _aj_summary.get("confirm") or _aj_summary.get("reject"):
                    log.info(
                        "[AutoJudge] sweep evaluated=%d confirm=%d reject=%d pending=%d errors=%d",
                        _aj_summary.get("evaluated", 0),
                        _aj_summary.get("confirm", 0),
                        _aj_summary.get("reject", 0),
                        _aj_summary.get("pending", 0),
                        _aj_summary.get("errors", 0),
                    )
            except Exception as _aj_exc:
                log.warning("[AutoJudge] sweep failed: %s", _aj_exc)

            # Weekly observability: intel sensor audit + Layer 1 backtest.
            # Cadence-gated inside maybe_run() to once per
            # WEEKLY_DIAGNOSTICS_INTERVAL_HOURS (default 168h = 7d).
            # Read-only — no DB writes, no LLM calls (Phase 4 N3).
            try:
                from radar import diagnostics as _diag
                _diag.maybe_run()
            except Exception as _diag_exc:
                log.warning("[WeeklyDiag] maybe_run failed: %s", _diag_exc)

            # Phase B: per-scenario TL threshold calibrator (auto-tune).
            # Runs once per day on the cleanup_worker's hourly tick — a
            # separate cadence gate inside calibrate_all_scenarios is not
            # needed because the governor's cooldown (default 72h per key)
            # bounds the actual write rate. The recall_metrics CI gate +
            # bounded magnitude (10%) provide additional safety.
            # Phase B v1: emits proposals to threshold_history; actual
            # *application* in derive_tl is gated on a separate feature
            # flag (future commit) so the conclusion_diff_log 100% match
            # invariant is preserved during shadow rollout.
            if _cycle % 24 == 1:  # ~daily (cleanup_worker is hourly)
                try:
                    from radar.calibration.tl_threshold_calibrator import (
                        calibrate_all_scenarios,
                    )
                    cal_result = calibrate_all_scenarios()
                    accepted = sum(r.get("accepted", 0) for r in cal_result.values())
                    submitted = sum(r.get("submitted", 0) for r in cal_result.values())
                    if submitted:
                        log.info(
                            "[TLCalib] daily pass: %d scenarios, %d submitted, %d accepted",
                            len(cal_result), submitted, accepted,
                        )
                except Exception as _tlc_exc:
                    log.warning("[TLCalib] calibrate_all_scenarios failed: %s", _tlc_exc)

            # Phase C: per-sensor LLM_CONFIDENCE_MIN calibrator.
            # Daily pass; emits proposals to threshold_history.
            if _cycle % 24 == 1:
                try:
                    from radar.calibration.llm_confidence_calibrator import (
                        calibrate_all_sensors,
                    )
                    cal_c = calibrate_all_sensors()
                    accepted_c = sum(
                        1 for r in cal_c.values()
                        if r.get("accepted")
                    )
                    if accepted_c:
                        log.info(
                            "[LLMConfCalib] %d/%d sensors → %d accepted",
                            len(cal_c), len(cal_c), accepted_c,
                        )
                except Exception as _llmc_exc:
                    log.warning(
                        "[LLMConfCalib] calibrate_all_sensors failed: %s",
                        _llmc_exc,
                    )

            # Phase D: α-broken sensor disable proposer (24h ack window).
            # Daily classify pass; per-tick escalation check.
            try:
                from radar.calibration.sensor_disable_proposer import (
                    propose_disables,
                )
                d_counts = propose_disables()
                if d_counts.get("new_proposals") or d_counts.get("escalated"):
                    log.info(
                        "[SensorDisable] classified=%d alpha=%d new=%d escalated=%d",
                        d_counts["classified"], d_counts["alpha"],
                        d_counts["new_proposals"], d_counts["escalated"],
                    )
            except Exception as _d_exc:
                log.warning("[SensorDisable] propose_disables failed: %s", _d_exc)

            # Phase F1: scenario improvement proposer (daily).
            if _cycle % 24 == 2:  # offset by 2 cycles vs other dailies
                try:
                    from radar.calibration.scenario_improver import (
                        run_once as _improver_once,
                    )
                    f1_result = _improver_once()
                    total = sum(
                        sum(per.values()) for per in f1_result.values()
                    )
                    if total:
                        log.info(
                            "[ScenarioImprover] %d scenarios scanned, %d proposals emitted",
                            len(f1_result), total,
                        )
                except Exception as _f1_exc:
                    log.warning(
                        "[ScenarioImprover] run_once failed: %s", _f1_exc,
                    )

            # Phase F2-a: scenario structure proposer (role + dormancy).
            # Same cadence as F1 (offset by 3 cycles to spread load).
            if _cycle % 24 == 3:
                try:
                    from radar.calibration.scenario_structure_proposer import (
                        run_once as _f2a_once,
                    )
                    f2a_result = _f2a_once()
                    total_f2a = sum(
                        sum(per.values()) for per in f2a_result.values()
                    )
                    if total_f2a:
                        log.info(
                            "[StructureProposer] %d scenarios scanned, "
                            "%d proposals emitted",
                            len(f2a_result), total_f2a,
                        )
                except Exception as _f2a_exc:
                    log.warning(
                        "[StructureProposer] run_once failed: %s", _f2a_exc,
                    )

            # Tier 3 G.2/G.3a: scenario discovery pipeline (daily).
            # Computes country co-occurrence matrix → DBSCAN clusters →
            # emits scenario_proposals for novel cluster candidates. NP7
            # never auto-applies; analyst Wizard apply path is required.
            if _cycle % 24 == 4:
                try:
                    from radar.calibration.scenario_discoverer import (
                        run_once as _disc_once,
                    )
                    disc_result = _disc_once()
                    if not disc_result.get("skipped"):
                        log.info(
                            "[Discovery] run_id=%s clusters=%d proposals=%d",
                            disc_result.get("discovery_run_id"),
                            disc_result.get("n_clusters", 0),
                            disc_result.get("n_proposals", 0),
                        )
                except Exception as _disc_exc:
                    log.warning("[Discovery] run_once failed: %s", _disc_exc)

            # Tier 4 G.3b: LLM annotator for discovery clusters.
            # Default: both env flags off — annotator is a no-op. Enable
            # via G3B_SHADOW_ENABLED=true to start observation period;
            # G3B_LLM_ENABLED=true to surface annotations to UI.
            if _cycle % 24 == 5:
                try:
                    from radar.calibration.g3b_llm_annotator import (
                        run_once as _g3b_once,
                    )
                    g3b_result = _g3b_once()
                    if not g3b_result.get("skipped") and g3b_result.get("annotated"):
                        log.info(
                            "[G3B] %s annotations=%d errors=%d circuit_open=%s",
                            g3b_result.get("state"),
                            g3b_result.get("annotated", 0),
                            g3b_result.get("errors", 0),
                            g3b_result.get("circuit_open", False),
                        )
                except Exception as _g3b_exc:
                    log.warning("[G3B] run_once failed: %s", _g3b_exc)

            # Phase G1: ground-truth correlation ETL (auto-feedback).
            # Reads the conclusions ledger over the last 14 days, pulls
            # GDELT tone spikes (+ ACLED fatality counts when API creds
            # are configured), and writes auto-labelled rows into
            # `analyst_feedback` with analyst_id `auto:gdelt` /
            # `auto:acled` / `auto:both`. Without this pass the table is
            # empty and the TL / LLM-confidence calibrators above have
            # nothing to learn from. Gated on V2_GROUND_TRUTH_ETL_ENABLED.
            if _cycle % 24 == 6:
                try:
                    from radar.calibration.auto_feedback_etl import (
                        run_ground_truth_pass,
                    )
                    gt_counts = run_ground_truth_pass()
                    if gt_counts:
                        log.info(
                            "[GroundTruthETL] daily pass: scanned=%d "
                            "labelled=%d skipped=%d",
                            gt_counts.get("scanned", 0),
                            sum(v for k, v in gt_counts.items()
                                if k.startswith("labelled_")),
                            sum(v for k, v in gt_counts.items()
                                if k.startswith("skipped_")),
                        )
                except Exception as _gt_exc:
                    log.warning("[GroundTruthETL] daily pass failed: %s", _gt_exc)

            # Phase G2: RSS narrative auto-feedback ETL.
            # Same idea, but the evidence comes from the public-RSS
            # kinetic-regex extractor (radar.conclusions.rss_extractor).
            # No API key required; complements GDELT in regions where
            # GDELT's English-press bias under-counts events.
            if _cycle % 24 == 7:
                try:
                    from radar.calibration.auto_feedback_etl import (
                        run_rss_narrative_pass,
                    )
                    rss_counts = run_rss_narrative_pass()
                    if rss_counts:
                        log.info(
                            "[RssNarrativeETL] daily pass: feeds=%d "
                            "matched=%d persisted=%d",
                            rss_counts.get("feeds_fetched", 0),
                            rss_counts.get("matched_items", 0),
                            rss_counts.get("persisted", 0),
                        )
                except Exception as _rss_exc:
                    log.warning(
                        "[RssNarrativeETL] daily pass failed: %s", _rss_exc,
                    )

            # Phase G3: auto-apply tier governor (self-promoting).
            # Reads its own audit log + threshold_history + diff_log to
            # decide whether the system should promote (0→1→2→3) or
            # demote based on observed reliability. Every transition
            # is recorded to auto_apply_tier_state for NP6 audit.
            # Failures here are caught inside the module; this outer
            # try/except is the last-resort safety net.
            if _cycle % 24 == 8:
                try:
                    from radar.calibration.auto_apply_tier_governor import (
                        run_once as _tier_once,
                    )
                    tg = _tier_once()
                    if tg.get("transition") not in (None, "unchanged"):
                        log.info(
                            "[TierGovernor] %s prior=%d new=%d reason=%s",
                            tg.get("transition"),
                            tg.get("prior_tier"),
                            tg.get("new_tier"),
                            tg.get("reason"),
                        )
                except Exception as _tg_exc:
                    log.warning(
                        "[TierGovernor] daily pass failed: %s", _tg_exc,
                    )

            # Chronic-inconclusive detector (ADR-V2-010 / NP5+8). Daily
            # pass: snapshot the inconclusive_continuity_log, flag every
            # (scenario, conclusion_type) whose open run has lasted past
            # the threshold, and register one record_failure() per
            # chronic state so the silent-failure ledger reflects the
            # NP5+8 contract breach. The detector itself is NP3-tolerant
            # — this outer try/except is just a safety net.
            if _cycle % 24 == 9:
                try:
                    from radar.conclusions.inconclusive_continuity import (
                        chronic_snapshot as _chronic_snap,
                    )
                    from radar.conclusions.shadow_metrics import (
                        record_failure as _record_failure,
                    )
                    from radar.database import db as _shared_db
                    snap = _chronic_snap(_shared_db)
                    chronic = snap.get("chronic", []) or []
                    for st in chronic:
                        try:
                            _record_failure(
                                "inconclusive_chronic",
                                RuntimeError(
                                    f"chronic UNAVAILABLE: "
                                    f"{st.get('scenario_id')}/"
                                    f"{st.get('conclusion_type')} "
                                    f"for {st.get('days_unavailable', 0):.1f}d"
                                ),
                            )
                        except Exception:
                            # record_failure must not be load-bearing.
                            pass
                    if chronic:
                        log.warning(
                            "[ChronicInconclusive] %d chronic state(s) "
                            "flagged (threshold=%.1fd)",
                            len(chronic),
                            float(snap.get("threshold_days", 0)),
                        )
                except Exception as _chronic_exc:
                    log.warning(
                        "[ChronicInconclusive] daily pass failed: %s",
                        _chronic_exc,
                    )

            # Inactive-scenario auto-dismiss (D1, 2026-05-08). Closes
            # the original "pending decisions should be auto-processed"
            # ask: a pending scenario_proposal whose target scenario
            # has been moved to paused / archived state can never be
            # applied (the wizard's apply path checks scenario state),
            # and is a dead-letter by definition. Mechanical cleanup —
            # no statistical judgment, no false-positive risk: the
            # operator's choice to pause/archive a scenario is the
            # judgment, this hook just propagates it.
            #
            # Symmetric with the chronic-inconclusive scheduler hook
            # (offset 9): both auto-react to a state the analyst has
            # already implicitly declared.
            if _cycle % 24 == 10:
                try:
                    from radar.calibration import (
                        proposal_lifecycle as _plc,
                    )
                    n = _plc.auto_dismiss_inactive_scenario_proposals()
                    if n > 0:
                        log.info(
                            "[ProposalLifecycle] auto-dismissed %d "
                            "pending proposals on inactive scenarios", n,
                        )
                    # D3 — diagnostic auto-acknowledge (Phase 4 of the
                    # 2026-05-08 seam closure). Diagnostic-only types
                    # (sensor_gap_detected / scenario_dormant /
                    # needs_more_data) have no Apply path; their
                    # 'pending' state is misleading. After 7 days we
                    # mark them dismissed so the wizard's pending
                    # lists self-clear.
                    n_diag = _plc.auto_acknowledge_diagnostic_proposals()
                    if n_diag > 0:
                        log.info(
                            "[ProposalLifecycle] auto-acknowledged %d "
                            "diagnostic-only pending proposals", n_diag,
                        )
                    # Drift event lifecycle (P1-2, 2026-05-10): same daily
                    # hook handles drift events symmetrically with proposals.
                    # Amber events older than 3d -> auto-acknowledged so the
                    # AUTO-TUNE chip's unack count reflects only attention-
                    # worthy items. Red events older than 1d are escalated
                    # via the notification channels (Slack/Teams/Discord
                    # webhook) so an analyst is paged before the dashboard
                    # check.
                    n_amber = _plc.auto_acknowledge_amber_drift_events()
                    if n_amber > 0:
                        log.info(
                            "[DriftLifecycle] auto-acknowledged %d "
                            "amber drift events past timeout", n_amber,
                        )
                    # Stale actionable proposals (D5, 2026-05-10):
                    # dismiss non-diagnostic pending rows on active
                    # scenarios after 30d of inactivity. The underlying
                    # signal is too old to drive a valid weight change.
                    n_stale = _plc.auto_dismiss_stale_pending_proposals()
                    if n_stale > 0:
                        log.info(
                            "[ProposalLifecycle] auto-dismissed %d stale "
                            "pending proposals past 30d timeout", n_stale,
                        )
                    red_events = _plc.list_old_unack_red_drift_events()
                    if red_events:
                        try:
                            from radar.notifications import notify_drift_unack
                            notify_drift_unack(red_events)
                        except Exception as _drift_notify_exc:
                            log.warning(
                                "[DriftLifecycle] notify_drift_unack failed: %s",
                                _drift_notify_exc,
                            )
                except Exception as _plc_exc:
                    log.warning(
                        "[ProposalLifecycle] auto-dismiss/ack "
                        "failed: %s", _plc_exc,
                    )

            # D4 (2026-05-08) — drip existing pending scenario_proposals
            # through the Phase 3 auto-apply gate. Phase 3 only gates
            # NEW emissions; rows that were already pending before the
            # flag was flipped never see the gate (the dedup window
            # blocks the proposer from re-emitting them). D4 closes
            # that gap by drip-feeding existing pending through the
            # same evaluation logic at scheduler tick rate. Rate-
            # limited to REPROCESS_MAX_PER_TICK applies/call so a
            # sudden tier promotion doesn't fire a flood.
            if _cycle % 24 == 12:
                try:
                    from radar.calibration import (
                        proposal_lifecycle as _plc,
                    )
                    summary = _plc.reprocess_pending_through_gate()
                    if summary.get("applied", 0) > 0:
                        log.info(
                            "[ProposalLifecycle] reprocess: applied %d "
                            "of %d checked (skipped: type=%d age=%d "
                            "state_changed=%d, errors=%d)",
                            summary["applied"], summary["checked"],
                            summary["skipped_type"],
                            summary["skipped_age"],
                            summary["skipped_state_changed"],
                            summary["errors"],
                        )
                except Exception as _rp_exc:
                    log.warning(
                        "[ProposalLifecycle] reprocess failed: %s",
                        _rp_exc,
                    )

            # Follow-up watch — auto-detect when a deferred backlog
            # item's trigger condition is met (B1 / B5+ / B7 / B9 from
            # the 2026-05-05 audit). Emits a WARN on first transition
            # to "met"; subsequent days log at INFO. Stateless across
            # process restarts on purpose — false re-warns after a
            # restart are cheaper than missed transitions.
            if _cycle % 24 == 11:
                try:
                    from radar.observability.followup_watch import (
                        run_once as _followup_once,
                    )
                    fw = _followup_once()
                    if fw.get("fired"):
                        log.debug(
                            "[FollowupWatch] %d watch(es) currently met",
                            len(fw["fired"]),
                        )
                except Exception as _fw_exc:
                    log.warning(
                        "[FollowupWatch] daily pass failed: %s", _fw_exc,
                    )

            # Phase F3: scenario drift watchdog (per-scenario).
            # Runs hourly so dwell-time (≥3 consecutive runs = 3h) reaches
            # surfacing in <1 day. Records each detection; the API render
            # layer filters by consecutive_runs ≥ 3 before showing in UI.
            try:
                from radar.calibration.drift_watchdog import run_once as _drift_once
                drift_result = _drift_once()
                total_emitted = sum(
                    sum(per_sig.values()) for per_sig in drift_result.values()
                )
                if total_emitted:
                    log.info(
                        "[DriftWatchdog] %d scenarios scanned, %d signal events recorded",
                        len(drift_result), total_emitted,
                    )
            except Exception as _drift_exc:
                log.warning("[DriftWatchdog] run_once failed: %s", _drift_exc)

            # ATTENTION adaptive learning (commit O): hourly observation
            # tick + nightly p95 recompute + nightly cleanup.
            try:
                from radar.attention_learning import (
                    observe as _att_observe,
                    recompute_p95 as _att_recompute,
                    cleanup_old_observations as _att_cleanup,
                )
                obs_result = _att_observe()
                if obs_result.get("recorded", 0) > 0:
                    log.debug(
                        "[ATTENTION] observed %d rules, skipped %d",
                        obs_result["recorded"], obs_result["skipped"],
                    )
                if _cycle % 24 == 6:  # nightly
                    rec = _att_recompute()
                    cleaned = _att_cleanup()
                    log.info(
                        "[ATTENTION] nightly: p95 updated %d rules, "
                        "%d obs cleaned",
                        rec.get("rules_updated", 0), cleaned,
                    )
            except Exception as _att_exc:
                log.warning("[ATTENTION] tick failed: %s", _att_exc)

            # LLM pipeline health summary (hourly visibility)
            try:
                from radar.config import LLM_ENABLED
                stats = _iq.stats()
                llm_calls = _db.llm_call_stats(hours=1)
                total_calls = llm_calls.get("total", 0)
                log.info(
                    f"[LLM-Health] enabled={LLM_ENABLED} "
                    f"calls_1h={total_calls} "
                    f"intel(pending={stats.get('pending',0)} "
                    f"auto={stats.get('auto_confirmed',0)} "
                    f"confirmed={stats.get('confirmed',0)} "
                    f"total={stats.get('total',0)})"
                )
            except Exception:
                pass  # non-critical diagnostic

            # Hourly: WAL checkpoint (flush WAL to main DB file)
            _db.wal_checkpoint()

            # Daily: prune SQLite tables
            if _cycle % DB_CLEANUP_EVERY == 0:
                _db.periodic_cleanup()

        except Exception as e:
            log.error(f"[Cleanup] Error: {e}")


# ── Cross-source corroboration worker ────────────────────────────────────────

def _corroboration_worker():
    """Daemon thread: runs the cross-source corroboration pass every 30 minutes.
    Looks for independent-source signals in the same theater+time window and
    synthesises them into a single 'corroborated' intel item via LLM.
    """
    CORR_INTERVAL = 1800  # 30 minutes
    # Stagger startup so the main sensor fetches have time to populate the DB
    time.sleep(300)  # 5-minute initial delay
    while True:
        try:
            from radar.intel_corroboration import corroboration_engine
            created = corroboration_engine.run_once()
            if created:
                log.info(f"[Corroboration] Worker: {created} new corroborated items")
        except Exception as e:
            log.error(f"[Corroboration] Worker error: {e}")
        time.sleep(CORR_INTERVAL)


def _bg_scoring_worker(interval_sec: int = 60, startup_delay_sec: int = 20):
    """Daemon: trigger periodic threat scoring even when no client is viewing.

    Without this, `threat_history` only grows when a user has the dashboard
    open, because `/api/threat_data` is the only writer. That produced
    sparse, gap-ridden 24h sparklines whenever the page was closed —
    notably ~5 rows in 24h instead of the expected ~96 (15-min poll) or
    ~1440 (60s tick) cadence.

    The worker drives the same code path users hit by invoking the route
    handler in-process via Flask's test client, bypassing only the network
    layer (not the cache, not the scoring, not the persistence path). The
    `?focus=` parameter picks the DEFAULT_FOCUSED_SCENARIO when scorable;
    falls back to the first scorable scenario otherwise.

    Auth: re-issues a short-lived admin JWT each cycle. The first admin
    user discovered in the DB is used as the JWT identity so the
    require_role gate accepts the call. If no admin exists the worker
    logs once and idles until one appears.

    Disable via BG_SCORING_ENABLED=false in config.env.
    """
    log.info(f"[bg_scoring] worker thread started (interval={interval_sec}s, "
             f"startup_delay={startup_delay_sec}s)")
    # Give other workers (HOD prefill, sensor schedulers) time to populate
    # initial caches before we trigger the first score.
    time.sleep(startup_delay_sec)

    # Late imports to avoid circulars during module init.
    from radar import app
    from radar.scenarios import scenario_store
    from radar.config import DEFAULT_FOCUSED_SCENARIO
    from flask_jwt_extended import create_access_token

    _no_admin_warned = False

    while True:
        try:
            scorable = scenario_store.scorable()
            if not scorable:
                time.sleep(interval_sec)
                continue

            default = scenario_store.get(DEFAULT_FOCUSED_SCENARIO)
            target = default if (default and default.is_scorable) else scorable[0]

            # Resolve an admin identity for the JWT. The default admin user
            # is created on first startup; later admins may be added via
            # the User Management UI.
            admin_name = next(
                (u["username"] for u in _db.user_list() if u.get("role") == "admin"),
                None,
            )

            if not admin_name:
                if not _no_admin_warned:
                    log.warning("[bg_scoring] no admin user found — "
                                "skipping until one is provisioned")
                    _no_admin_warned = True
                time.sleep(interval_sec)
                continue
            _no_admin_warned = False

            with app.app_context():
                token = create_access_token(
                    identity=admin_name,
                    additional_claims={"role": "admin", "src": "bg_scoring"},
                )

            with app.test_client() as client:
                rsp = client.get(
                    f"/api/threat_data?focus={target.id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                if rsp.status_code != 200:
                    log.warning(
                        f"[bg_scoring] /api/threat_data returned "
                        f"HTTP {rsp.status_code} for focus={target.id}"
                    )
        except Exception:
            log.exception("[bg_scoring] cycle failed (continuing)")

        time.sleep(interval_sec)
