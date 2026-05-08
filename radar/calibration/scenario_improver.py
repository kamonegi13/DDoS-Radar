"""Scenario improvement proposer (Phase F1).

Continuously analyzes per-scenario operational data and emits ranked
suggestions for participant additions/removals/weight changes. All
suggestions go to the `scenario_proposals` ledger as 'pending' rows;
analyst applies, dismisses, or snoozes via API. Tool NEVER auto-applies
structural scenario changes (NP7).

Phase F1 v1 scope: 3 rules.

  1. weight_too_low      — participant whose signal contribution is in the
                            top quartile of cohort but current weight
                            is in the bottom quartile → suggest weight += 0.15
  2. weight_too_high     — participant has 30d zero contribution AND
                            no analyst FN involving this country →
                            suggest weight -= 0.15 (preserves participant
                            in scenario; full removal is a 2nd-step suggestion)
  3. missing_participant — country appears in ≥3 sequence_events for this
                            scenario but is not in the participant list →
                            suggest addition with role inferred from the
                            cyber/physical signal mix

Proposals are deduplicated: the same (scenario, rule, target_country)
within 7 days does not produce a fresh row — that proposal sits as
pending and updates its evidence on each cron pass instead.

NP integrity:
  NP1 — recall-reducing proposals (weight decrease, removal) require
        analyst confirmation modal before apply. Recall-positive
        proposals (weight increase, addition) are 1-click.
  NP6 — every proposal has formula_ref + evidence (signal contribution
        percentiles, fire counts, recall) + sample_n
  NP7 — proposals only; the apply endpoint requires authenticated
        analyst click and writes to geo_data.json (or scenario_store
        live state); never automated
  NP3 — sub-step failure → no proposal (silent NP3 degradation)
  AP3 — accepted/dismissed/snoozed counts queryable via list_recent
  AP4 — every proposal replayable
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

from radar.database import db

log = logging.getLogger("radar.calibration.scenario_improver")


PROPOSER_VERSION = "scenario_improver/v1"
APPLIED_BY = "auto:scenario_improver"


def _stale_days() -> float:
    return float(os.getenv("SCENARIO_IMPROVER_STALE_DAYS", "30"))


def _missing_participant_event_threshold() -> int:
    return int(os.getenv("SCENARIO_IMPROVER_MISSING_EVENT_N", "3"))


def _dedup_window_days() -> float:
    return float(os.getenv("SCENARIO_IMPROVER_DEDUP_DAYS", "7"))


def _weight_step() -> float:
    return float(os.getenv("SCENARIO_IMPROVER_WEIGHT_STEP", "0.15"))


def _max_active_per_scenario() -> int:
    """Per-scenario active proposal cap (F1/F3 dedup ceiling guardrail)."""
    return int(os.getenv("SCENARIO_IMPROVER_MAX_ACTIVE", "5"))


@dataclass(frozen=True)
class ProposalEvent:
    scenario_id: str
    proposal_type: str  # 'weight_too_low' | 'weight_too_high' | 'missing_participant'
    target_country: Optional[str]
    suggested_value: dict
    evidence: dict
    formula_ref: str
    sample_n: int
    why_string: str


def _is_recall_reducing(proposal_type: str) -> bool:
    """NP1 hardening flag — UI should require confirmation modal for
    proposals that could reduce recall."""
    return proposal_type in ("weight_too_high", "participant_remove")


def _has_recent_pending_for(scenario_id: str, proposal_type: str,
                             target_country: Optional[str]) -> bool:
    """Dedup check: same (scenario, rule, target) recently in the
    ledger as either ``pending`` OR ``applied``?

    Phase 3 (2026-05-08) widens this from the historical pending-only
    check. Rationale: when the auto-apply path is enabled, a row that
    was emitted, auto-applied, and now sits at ``state='applied'``
    represents a change that's already in effect. Re-emitting another
    pending of the same shape within the dedup window is wasted work
    at best; at worst it would oscillate the live config if the
    proposer's rule re-fires before the scenario's contribution
    statistics catch up to the new weight.

    Pre-fix this function only checked ``state='pending'`` so an
    auto-applied row would NOT block a fresh emission in the
    following tick — exactly the oscillation risk above.
    """
    cutoff = time.time() - _dedup_window_days() * 86400
    conn = db._get_conn()  # noqa: SLF001
    try:
        if target_country is None:
            row = conn.execute(
                "SELECT 1 FROM scenario_proposals "
                "WHERE scenario_id=? AND proposal_type=? "
                "AND target_country IS NULL "
                "AND state IN ('pending','applied') "
                "AND emitted_at > ? LIMIT 1",
                (scenario_id, proposal_type, cutoff),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT 1 FROM scenario_proposals "
                "WHERE scenario_id=? AND proposal_type=? "
                "AND target_country=? "
                "AND state IN ('pending','applied') "
                "AND emitted_at > ? LIMIT 1",
                (scenario_id, proposal_type, target_country, cutoff),
            ).fetchone()
        return row is not None
    except Exception:
        return False


def _active_proposal_count(scenario_id: str) -> int:
    try:
        conn = db._get_conn()  # noqa: SLF001
        row = conn.execute(
            "SELECT COUNT(*) FROM scenario_proposals "
            "WHERE scenario_id=? AND state='pending'",
            (scenario_id,),
        ).fetchone()
        return row[0] if row else 0
    except Exception:
        return 0


def _emit(
    event: ProposalEvent,
    *,
    evidence_strength: Optional[str] = None,
    vitality_state: Optional[str] = None,
) -> Optional[int]:
    """Insert a pending proposal row. Skips if dedup or active-count
    cap blocks it. Returns row id on success, None on skip.

    Post-incident (migration v30): evidence_strength + vitality_state
    are stamped onto the row when the caller has already evaluated the
    guards. Both default to None for legacy callers (rows show as
    uncategorized in the Wizard until re-emitted).
    """
    if _has_recent_pending_for(
            event.scenario_id, event.proposal_type, event.target_country):
        return None
    if _active_proposal_count(event.scenario_id) >= _max_active_per_scenario():
        log.debug(
            "scenario_improver: %s active proposal cap reached, skipping new",
            event.scenario_id,
        )
        return None
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, sample_n, "
            " why_string, evidence_strength, vitality_state, state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            (time.time(), event.scenario_id, event.proposal_type,
             event.target_country,
             json.dumps(event.suggested_value, sort_keys=True),
             json.dumps(event.evidence, sort_keys=True),
             event.formula_ref, int(event.sample_n), event.why_string,
             evidence_strength, vitality_state),
        )
        new_id = cur.lastrowid
    # D2 (2026-05-08): supersede any older pending rows that survived
    # past the dedup window (default 7 days). The dedup check at the
    # top of this function only blocks duplicates *within* the window;
    # an unresolved row from before the window is the symptom of an
    # analyst who never closed it. The new emission is, by
    # construction, the new authoritative version — mark the stragglers
    # as ``superseded`` so the wizard's pending lists self-clear and
    # the proposal.chronic_pending watch can settle.
    try:
        from radar.calibration.proposal_lifecycle import (
            supersede_duplicate_pending,
        )
        supersede_duplicate_pending(
            scenario_id=event.scenario_id,
            proposal_type=event.proposal_type,
            target_country=event.target_country,
            new_proposal_id=int(new_id),
        )
    except Exception as _sd_exc:
        log.debug("supersede hook (non-fatal): %s", _sd_exc)

    # ── Phase 3 (2026-05-08): tier-governor-gated auto-apply ─────────
    # NP1: recall-positive proposals (weight_too_low / missing_participant)
    # auto-apply at T1+ — withholding them is itself a recall reduction.
    # NP7: recall-reducing proposals (weight_too_high / dormant_participant)
    # require T3 + strong evidence + non-protected role; HIGH cooldown
    # is triggered after a successful apply so chained changes can't
    # pile on. role_reclassify is MED.
    # Behind a flag (default OFF) for safe rollout.
    try:
        if _auto_apply_enabled():
            _maybe_auto_apply(int(new_id), event,
                               evidence_strength=evidence_strength,
                               vitality_state=vitality_state)
    except Exception as _aa_exc:
        log.debug("auto-apply hook (non-fatal): %s", _aa_exc)
    return new_id


# ── Phase 3 auto-apply helpers ───────────────────────────────────────────────


def _auto_apply_enabled() -> bool:
    """Master flag for the tier-governor-gated auto-apply path. Default
    False so phase 3 ships dormant. Phase 5 flips it after monitoring
    confirms tier governor is at T1+ and metrics are clean."""
    raw = os.getenv("SCENARIO_IMPROVER_AUTO_APPLY_ENABLED", "false")
    return raw.strip().lower() in ("1", "true", "yes", "on")


# Minimum evidence_strength required for each proposal_type's auto-apply.
# 'weak' / 'insufficient' / None all fail the bar. The ladder
# (insufficient < weak < moderate < strong) is the proposer's own
# classification per _proposal_guards.
_AUTO_APPLY_MIN_EVIDENCE: dict[str, str] = {
    "weight_too_low":      "weak",      # recall+; weak OK (NP1 priority)
    "missing_participant": "moderate",  # recall+; new participant needs more
    "role_reclassify":     "strong",    # structural — strong evidence required
    "weight_too_high":     "strong",    # recall-; strong required
    "dormant_participant": "strong",    # recall-; strong required
}

_EVIDENCE_RANK = {
    None: 0, "": 0, "insufficient": 0, "weak": 1, "moderate": 2, "strong": 3,
}


def _impact_for_type(proposal_type: str) -> Optional[str]:
    """Return 'low' | 'med' | 'high' for proposal_types that may
    auto-apply, else None (analyst-only / diagnostic / discovery)."""
    if proposal_type in ("weight_too_low", "missing_participant"):
        return "low"
    if proposal_type == "role_reclassify":
        return "med"
    if proposal_type in ("weight_too_high", "dormant_participant"):
        return "high"
    return None


def _maybe_auto_apply(
    proposal_id: int, event: ProposalEvent, *,
    evidence_strength: Optional[str], vitality_state: Optional[str],
) -> None:
    """Decision tree for auto-apply. Returns nothing — leaves the
    proposal at ``state='pending'`` if any guard fails, in which case
    the analyst path remains the only way to apply it."""
    impact = _impact_for_type(event.proposal_type)
    if impact is None:
        # scenario_discovery / diagnostic / sensor_disable etc.
        return

    # Evidence floor.
    min_required = _AUTO_APPLY_MIN_EVIDENCE.get(event.proposal_type, "strong")
    if _EVIDENCE_RANK.get(evidence_strength, 0) \
            < _EVIDENCE_RANK.get(min_required, 0):
        log.debug(
            "[auto-apply] %s id=%d skipped: evidence=%s < required=%s",
            event.proposal_type, proposal_id, evidence_strength,
            min_required,
        )
        return

    # Recall-reducing proposals: must be against a non-protected role.
    # The proposer's _rule_weight_too_high already filters at emit-time;
    # this re-check is a defense-in-depth re-validation against the
    # CURRENT scenario state (in case role was just reclassified).
    if event.proposal_type in ("weight_too_high", "dormant_participant"):
        try:
            from radar.scenarios import scenario_store
            sc = scenario_store.get(event.scenario_id)
            if sc is None or event.target_country is None:
                return
            p = sc.participants.get(event.target_country)
            if p is None:
                return
            from radar.calibration._proposal_guards import is_role_protected
            if is_role_protected(p):
                log.info(
                    "[auto-apply] %s id=%d skipped: role protected",
                    event.proposal_type, proposal_id,
                )
                return
        except Exception as exc:
            log.debug("[auto-apply] role re-check failed: %s", exc)
            return

    # Tier governor gate.
    from radar.calibration import auto_apply_tier_governor as tg
    marker = f"auto:scenario_improver:{event.proposal_type}"
    if not tg.is_apply_allowed(marker, impact_override=impact):
        log.debug(
            "[auto-apply] %s id=%d skipped: tier governor "
            "denied (impact=%s, current_tier=%d)",
            event.proposal_type, proposal_id, impact,
            tg.current_tier().tier,
        )
        return

    # Apply.
    try:
        from radar.calibration.scenario_apply import (
            apply_scenario_improver_proposal,
        )
        result = apply_scenario_improver_proposal(
            proposal_id, applied_by=marker,
        )
    except Exception as exc:
        try:
            from radar.conclusions.shadow_metrics import record_failure
            record_failure("scenario_improver_auto_apply", exc)
        except Exception:
            pass
        log.warning("[auto-apply] %s id=%d crashed: %s",
                    event.proposal_type, proposal_id, exc)
        return

    if not result.ok:
        log.info(
            "[auto-apply] %s id=%d not applied: %s",
            event.proposal_type, proposal_id, result.error,
        )
        return

    log.info(
        "[auto-apply] %s id=%d applied at impact=%s by=%s",
        event.proposal_type, proposal_id, impact, marker,
    )

    # HIGH cool-down: pause LOW/MED auto-apply for the configured
    # window so chained changes can't pile on a freshly-applied HIGH.
    if impact == "high":
        try:
            tg.trigger_high_cooldown(triggered_by=marker)
        except Exception as exc:
            log.debug("[auto-apply] HIGH cooldown trigger failed: %s",
                      exc)


# ── Rules ──


def _rule_weight_too_low(scenario) -> list[ProposalEvent]:
    """Participant with high recent signal contribution but low weight."""
    if not scenario.participants:
        return []
    cutoff = time.time() - 30 * 86400
    conn = db._get_conn()  # noqa: SLF001
    contribs: dict[str, int] = {}
    for cc in scenario.participants:
        try:
            row = conn.execute(
                "SELECT COUNT(*) FROM sensor_observation_ts "
                "WHERE scope=? AND ts > ?",
                (f"theater:{cc}", cutoff),
            ).fetchone()
            contribs[cc] = row[0] if row else 0
        except Exception:
            contribs[cc] = 0
    if not contribs:
        return []
    sorted_contribs = sorted(contribs.values())
    if len(sorted_contribs) < 3:
        return []
    p75 = sorted_contribs[int(len(sorted_contribs) * 0.75)]
    weights = sorted([p.weight for p in scenario.participants.values()])
    p25_w = weights[len(weights) // 4]
    if p75 == 0:
        return []
    out = []
    for cc, p in scenario.participants.items():
        if contribs[cc] < p75:
            continue
        if p.weight > p25_w:
            continue
        new_weight = round(min(0.95, p.weight + _weight_step()), 2)
        if new_weight == p.weight:
            continue
        out.append(ProposalEvent(
            scenario_id=scenario.id,
            proposal_type="weight_too_low",
            target_country=cc,
            suggested_value={"weight": new_weight, "from": p.weight},
            evidence={
                "contribution": contribs[cc],
                "cohort_p75": p75,
                "weight": p.weight,
                "cohort_p25_weight": p25_w,
            },
            formula_ref=f"{PROPOSER_VERSION}#weight_too_low",
            sample_n=sum(contribs.values()),
            why_string=(
                f"{cc} contributed {contribs[cc]} sensor observations in 30d "
                f"(top quartile of {scenario.id}) but weight is {p.weight:.2f} "
                f"(bottom quartile). Suggest raising weight to {new_weight:.2f} "
                f"to better reflect observed signal volume."
            ),
        ))
    return out


def _rule_weight_too_high(scenario) -> list[ProposalEvent]:
    """Recall-reducing rule — strict guards per post-incident redesign.

    Emits weight_too_high ONLY when:
      P1: role NOT in PROTECTED_ROLES (primary_target / principal_belligerent
          / adversary / core_country are recall-load-bearing)
      P2: ≥4 of 5 data sources show zero AND analyst_feedback_fn == 0
      P3: scenario vitality is 'active' (data_gap or dormant scenarios
          emit a diagnostic-level proposal instead, see commit D)

    NP1 — recall-reducing path is the strictest in the system.
    NP3 — guard module is fault-tolerant; this rule itself never raises.
    NP6 — evidence_json carries the full multi-source signal dict so the
          analyst can reproduce the dormancy claim.
    """
    # Lazy import to avoid circular dep with _proposal_guards (which can
    # itself read this module's helpers in the future).
    from radar.calibration import _proposal_guards as _guards

    vitality = _guards.scenario_vitality(scenario, days=int(_stale_days()))
    if vitality.state != "active":
        # Dormant or data_gap scenarios produce a diagnostic proposal at
        # the scenario level, not weight_too_high per participant.
        # Diagnostic emission lives in commit D's _rule_scenario_diagnostic.
        return []

    # Phase B guard (2026-04-30): same sensor-coverage check as
    # _rule_dormant_participant. weight_too_high uses the same 5/5
    # zero-source evidence as dormant_participant, so it is exposed to
    # the same false-positive when sensors are silent globally. NP1.
    coverage_ok, coverage_details = _guards.sensor_coverage_healthy(
        days=int(_stale_days()),
    )
    if not coverage_ok:
        log.info(
            "[scenario_improver] weight_too_high rule skipped for %s — "
            "global sensor coverage degraded (total_signals=%d < min=%d). "
            "Investigate sensors before trusting per-country dormancy.",
            scenario.id,
            coverage_details.get("total_global_signals", -1),
            coverage_details.get("min_threshold", -1),
        )
        return []

    out: list[ProposalEvent] = []
    for cc, p in scenario.participants.items():
        if p.weight <= 0:
            continue
        if _guards.is_role_protected(p):
            # P1: identity-load-bearing role; never propose weight reduction.
            continue
        signals = _guards.collect_multi_source_signals(
            cc, days=int(_stale_days()),
        )
        strength = _guards.evidence_strength(
            signals, role_protected=False,
        )
        if strength != "strong":
            # Insufficient evidence for a recall-reducing proposal.
            # Caller (commit D's diagnostic emitter) handles needs_more_data.
            continue
        new_weight = round(max(0.10, p.weight - _weight_step()), 2)
        if new_weight == p.weight:
            continue
        out.append(ProposalEvent(
            scenario_id=scenario.id,
            proposal_type="weight_too_high",
            target_country=cc,
            suggested_value={"weight": new_weight, "from": p.weight},
            evidence={
                "stale_days": int(_stale_days()),
                "current_weight": p.weight,
                "signals": signals,
                "evidence_strength": strength,
                "vitality_state": vitality.state,
                "role": p.role.value if hasattr(p.role, "value") else str(p.role),
            },
            formula_ref=f"{PROPOSER_VERSION}#weight_too_high",
            sample_n=sum(int(v or 0) for v in signals.values()),
            why_string=(
                f"{cc} (weight {p.weight:.2f}, role={p.role.value if hasattr(p.role,'value') else p.role}) "
                f"is dormant across {_guards.zero_source_count(signals)}/5 "
                f"data sources over {int(_stale_days())}d, with zero analyst "
                f"FN labels for this scenario. Evidence strength: {strength}. "
                f"Scenario vitality: {vitality.state}. Suggest lowering "
                f"weight to {new_weight:.2f}. Recall-reducing proposal — "
                f"requires NP7 confirmation before apply."
            ),
        ))
    return out


def _rule_missing_participant(scenario) -> list[ProposalEvent]:
    """A country fired ≥N sequence_events for THIS scenario but isn't a
    participant. Scenario filter is essential — without it, a country
    active in scenario A would be proposed as missing for scenarios
    B, C, D, E (the 2026-04-29 secondary incident: UA proposed for
    taiwan_contingency / middle_east / korean_peninsula / south_china_sea
    because it had eastern_europe sequence_events)."""
    cutoff = time.time() - 30 * 86400
    conn = db._get_conn()  # noqa: SLF001
    try:
        rows = conn.execute(
            "SELECT theater, COUNT(*) FROM sequence_events "
            "WHERE scenario_id=? AND ts > ? GROUP BY theater",
            (scenario.id, cutoff),
        ).fetchall()
    except Exception:
        return []
    out = []
    for theater, n in rows:
        if not theater:
            continue
        if theater in scenario.participants:
            continue
        if n < _missing_participant_event_threshold():
            continue
        out.append(ProposalEvent(
            scenario_id=scenario.id,
            proposal_type="missing_participant",
            target_country=theater,
            suggested_value={
                "weight": 0.30,  # conservative initial weight
                "role": "strategic_observer",  # default role; analyst can refine
            },
            evidence={
                "fire_count_30d": n,
                "threshold": _missing_participant_event_threshold(),
            },
            formula_ref=f"{PROPOSER_VERSION}#missing_participant",
            sample_n=n,
            why_string=(
                f"Country {theater} produced {n} sequence_events in 30d but "
                f"is not a participant in scenario {scenario.id}. Consider "
                f"adding with weight 0.30 / role=strategic_observer "
                f"(analyst should refine before applying)."
            ),
        ))
    return out


# ── Diagnostic rule (post-incident, commit D) ──


def _rule_scenario_diagnostic(scenario) -> list[ProposalEvent]:
    """Emit scenario-level diagnostic when vitality is dormant or data_gap.

    NP5+8 transitional 結論不可 made explicit:
      - data_gap → sensor_gap_detected (sensor side suspected)
      - dormant  → scenario_dormant    (scenario relevance suspected)

    These are informational; the Wizard's Diagnostic tab surfaces them
    without an Apply path. NP7 — never auto-mutates anything.
    """
    from radar.calibration import _proposal_guards as _guards
    from radar.calibration import _proposal_writer as _writer
    vitality = _guards.scenario_vitality(scenario, days=int(_stale_days()))
    if vitality.state == "active":
        return []
    if vitality.state == "data_gap":
        return [_writer.build_sensor_gap_event(scenario, vitality)]
    if vitality.state == "dormant":
        return [_writer.build_scenario_dormant_event(scenario, vitality)]
    return []


# ── Driver ──


def run_once() -> dict:
    """Iterate all registered scenarios + apply all rules. Returns
    per-scenario counts."""
    out: dict[str, dict] = {}
    try:
        from radar.scenarios import scenario_store
        scenarios = list(scenario_store._scenarios.values())  # noqa: SLF001
    except Exception as exc:
        log.warning("scenario_improver: failed to enumerate scenarios: %s", exc)
        return out
    # Diagnostic rule runs first; if it fires, structural rules will also
    # run for the active subset (guards inside each rule short-circuit
    # by vitality), so per-scenario the right shape always emerges.
    rules = [
        ("scenario_diagnostic", _rule_scenario_diagnostic),  # post-incident
        ("weight_too_low", _rule_weight_too_low),
        ("weight_too_high", _rule_weight_too_high),
        ("missing_participant", _rule_missing_participant),
    ]
    # Guard-aware emit pulls evidence_strength + vitality_state from the
    # event's evidence dict when present (rules write them there).
    from radar.calibration import _proposal_guards as _guards

    def _vitality_for(sc):
        try:
            return _guards.scenario_vitality(sc, days=int(_stale_days()))
        except Exception:
            return None

    for sc in scenarios:
        per_rule: dict[str, int] = {}
        vitality = _vitality_for(sc)
        vitality_state = vitality.state if vitality else None
        for name, fn in rules:
            try:
                events = fn(sc) or []
            except Exception as exc:
                log.debug(
                    "scenario_improver: %s/%s failed (non-fatal): %s",
                    sc.id, name, exc,
                )
                events = []
            emitted = 0
            for ev in events:
                strength = ev.evidence.get("evidence_strength") if isinstance(
                    ev.evidence, dict) else None
                vitality_in_ev = ev.evidence.get("vitality_state") if isinstance(
                    ev.evidence, dict) else None
                rid = _emit(
                    ev,
                    evidence_strength=strength,
                    vitality_state=vitality_in_ev or vitality_state,
                )
                if rid is not None:
                    emitted += 1
            per_rule[name] = emitted
        out[sc.id] = per_rule
    return out


def list_pending(*, scenario_id: Optional[str] = None,
                  hours: int = 168) -> list[dict]:
    """Return pending proposals for analyst UI.

    Phase C/E (2026-04-30): SELECT now includes evidence_strength,
    vitality_state, and state so the Wizard can route rows to the
    correct tab and show settled/superseded items in the history view.
    Earlier rows (pre-Phase C) may have NULL evidence_strength —
    those show as 'unrated' in the UI.
    """
    try:
        conn = db._get_conn()  # noqa: SLF001
        cutoff = time.time() - hours * 3600
        select_cols = (
            "SELECT id, scenario_id, proposal_type, target_country, "
            "suggested_value_json, evidence_json, formula_ref, "
            "sample_n, why_string, emitted_at, "
            "evidence_strength, vitality_state, state "
            "FROM scenario_proposals "
        )
        if scenario_id:
            rows = conn.execute(
                select_cols
                + "WHERE state='pending' AND scenario_id=? "
                "AND emitted_at > ? ORDER BY emitted_at DESC",
                (scenario_id, cutoff),
            ).fetchall()
        else:
            rows = conn.execute(
                select_cols
                + "WHERE state='pending' AND emitted_at > ? "
                "ORDER BY emitted_at DESC",
                (cutoff,),
            ).fetchall()
    except Exception as exc:
        log.warning("list_pending failed: %s", exc)
        return []
    out = []
    for r in rows:
        try:
            suggested = json.loads(r[4] or "{}")
            evidence = json.loads(r[5] or "{}")
        except Exception:
            suggested, evidence = {}, {}
        out.append({
            "id": r[0],
            "scenario_id": r[1],
            "proposal_type": r[2],
            "target_country": r[3],
            "suggested_value": suggested,
            "evidence": evidence,
            "formula_ref": r[6],
            "sample_n": r[7],
            "why_string": r[8],
            "emitted_at": r[9],
            "evidence_strength": r[10],
            "vitality_state": r[11],
            "state": r[12] or "pending",
            "is_recall_reducing": _is_recall_reducing(r[2]),
        })
    return out


def update_state(proposal_id: int, *, new_state: str, by: str) -> bool:
    """Apply / dismiss / snooze. Caller is responsible for the actual
    apply mutation (geo_data.json or scenario_store live state); this
    function only updates the ledger."""
    if new_state not in ("applied", "dismissed", "snoozed_30d",
                          "reverted", "superseded"):
        return False
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            cur = conn.execute(
                "UPDATE scenario_proposals SET state=?, "
                "state_changed_at=?, state_changed_by=? "
                "WHERE id=? AND state='pending'",
                (new_state, time.time(), by, proposal_id),
            )
            return cur.rowcount > 0
    except Exception as exc:
        log.warning("update_state failed: %s", exc)
        return False


__all__ = [
    "ProposalEvent",
    "run_once",
    "list_pending",
    "update_state",
]
