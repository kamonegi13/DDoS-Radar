"""ATTENTION rules engine — drives the CONTROLS panel ATTENTION section.

Background
----------
The redesigned Tools Hub (commit L) needs a way to surface "what
analyst should look at right now" rather than presenting every panel
as equal. This module declares a registry of attention rules — each
rule has a tool affiliation, severity, threshold (with hysteresis),
and an evaluator that pulls live metrics from the existing
sub-systems.

Rules are evaluated on every API call (the front-end polls every 5s).
Hysteresis is enforced via an in-memory cache: a rule only exits the
ATTENTION list after its metric drops below the *exit* threshold,
even if it briefly fell below the *enter* threshold and bounced back.

NP integrity
------------
NP1 — recall-affecting events (recall_negative pending, kill switch
      engaged) are CRITICAL severity and cannot be snoozed.
NP3 — every metric source is wrapped in try/except. A broken sub-system
      yields a missing metric (rule skipped) rather than crashing the
      whole evaluator.
NP6 — every fired rule includes the metric value, threshold, and a
      humanised message in the response so analysts can audit why
      they were alerted.
NP7 — snooze is recorded in DB so it survives restarts; CRITICAL rules
      reject snooze attempts at the API layer (see commit M routes).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional

log = logging.getLogger("radar.attention")


Severity = Literal["critical", "warning", "info"]
ThresholdMode = Literal["absolute", "ratio_to_p50", "boolean"]


@dataclass(frozen=True)
class AttentionRule:
    """Declarative description of one ATTENTION condition."""
    rule_id: str
    tool_id: str
    severity: Severity
    enter_threshold: float
    exit_threshold: float
    threshold_mode: ThresholdMode
    eval_fn: Callable[[dict], Optional[float]]   # returns observed value, or None
    message_template: str
    can_snooze: bool = True
    description: str = ""


# ── Metric collection ──────────────────────────────────────────────────────


def _collect_metrics() -> dict:
    """Gather all metrics in one pass. Each source is wrapped — failure
    of one collector doesn't poison the others."""
    metrics: dict = {}

    # Auto-tune metrics
    try:
        from radar.calibration._proposal_writer import TYPE_TO_KIND, ProposalKind
        from radar.database import db as _db
        cutoff = time.time() - 7 * 86400
        rows = _db._get_conn().execute(  # noqa: SLF001
            "SELECT proposal_type, COUNT(*) FROM scenario_proposals "
            "WHERE state='pending' AND emitted_at >= ? GROUP BY proposal_type",
            (cutoff,),
        ).fetchall()
        by_kind = {k.value: 0 for k in ProposalKind}
        total = 0
        for ptype, n in rows:
            n = int(n or 0)
            total += n
            kind = TYPE_TO_KIND.get(ptype, ProposalKind.STRUCTURE)
            by_kind[kind.value] = by_kind.get(kind.value, 0) + n
        metrics["autotune_pending_total"] = total
        metrics["autotune_recall_negative"] = by_kind.get("recall_negative", 0)
        metrics["autotune_recall_positive"] = by_kind.get("recall_positive", 0)
        metrics["autotune_diagnostic"] = by_kind.get("diagnostic", 0)
    except Exception as exc:
        log.debug("autotune metrics failed: %s", exc)

    # Drift unack count
    try:
        from radar.database import db as _db
        cutoff = time.time() - 7 * 86400
        row = _db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM scenario_drift_events "
            "WHERE ack_state='unack' AND consecutive_runs >= 3 "
            "AND emitted_at >= ?",
            (cutoff,),
        ).fetchone()
        metrics["drift_unack"] = int((row[0] if row else 0) or 0)
    except Exception:
        pass

    # Sensor disable proposals approaching ack expiry
    try:
        import json
        from radar.database import db as _db
        rows = _db._get_conn().execute(  # noqa: SLF001
            "SELECT suggested_value_json FROM scenario_proposals "
            "WHERE proposal_type='sensor_disable' AND state='pending'"
        ).fetchall()
        ack_imminent = 0
        now = time.time()
        for r in rows:
            try:
                sv = json.loads(r[0] or "{}")
                ack_due = sv.get("ack_due_at")
                if isinstance(ack_due, (int, float)) and (ack_due - now) < 4 * 3600:
                    ack_imminent += 1
            except Exception:
                continue
        metrics["sensor_disable_ack_imminent"] = ack_imminent
    except Exception:
        pass

    # Proposal-quality inversion: dismissed_pct over closed proposals (30d)
    try:
        from radar.database import db as _db
        cutoff30 = time.time() - 30 * 86400
        rows = _db._get_conn().execute(  # noqa: SLF001
            "SELECT state, COUNT(*) FROM scenario_proposals "
            "WHERE state IN ('applied','dismissed','snoozed_30d','reverted') "
            "AND emitted_at >= ? GROUP BY state",
            (cutoff30,),
        ).fetchall()
        d = {state: int(n or 0) for state, n in rows}
        total_closed = sum(d.values())
        dismissed_pct = ((d.get("dismissed", 0) / total_closed)
                         if total_closed >= 10 else 0.0)
        metrics["dismissed_pct_30d"] = dismissed_pct
    except Exception:
        pass

    # LLM Feature Hub metrics
    try:
        from radar import llm_features
        states = llm_features.list_states()
        metrics["llm_kill_switch"] = bool(
            states[0]["kill_switch_active"] if states else False
        )
        # Feature in shadow > 7 days — read history
        feature_in_long_shadow = 0
        history = llm_features.list_history(hours=7 * 24, limit=500)
        # Naive: if a feature is currently shadow and earliest history
        # row is > 7d old AND new_state stays shadow.
        from collections import defaultdict
        last_state_change_by_feature: dict[str, float] = {}
        for h in history:
            k = h["feature_key"]
            if k not in last_state_change_by_feature:
                last_state_change_by_feature[k] = h["changed_at"]
        for s in states:
            if s["current_state"] == "shadow":
                last_changed = last_state_change_by_feature.get(s["key"])
                if last_changed and (time.time() - last_changed) > 7 * 86400:
                    feature_in_long_shadow += 1
        metrics["feature_long_shadow"] = feature_in_long_shadow
    except Exception:
        pass

    # LLM Intel queue metrics
    try:
        from radar.intel_queue import intel_queue
        s = intel_queue.stats()
        metrics["llm_intel_pending"] = int(s.get("pending", 0) or 0)
        metrics["llm_intel_review_needed"] = int(s.get("review_needed", 0) or 0)
    except Exception:
        pass

    # LLM Intel: oldest pending age
    try:
        from radar.database import db as _db
        row = _db._get_conn().execute(  # noqa: SLF001
            "SELECT MIN(ts) FROM llm_intel WHERE status='pending'"
        ).fetchone()
        if row and row[0]:
            metrics["llm_intel_oldest_age_h"] = (time.time() - row[0]) / 3600.0
    except Exception:
        pass

    # Sensor health (rough — count from sensor registry if available)
    try:
        from radar import routes as _routes
        registry = getattr(_routes, "registry", None)
        if registry is not None:
            sensors = list(registry._sensors.values())  # noqa: SLF001
            err = 0
            stale = 0
            for s in sensors:
                state = getattr(s, "_health_state", None) or getattr(s, "state", None)
                if state == "ERROR":
                    err += 1
                elif state == "STALE":
                    stale += 1
            metrics["sensor_error"] = err
            metrics["sensor_stale"] = stale
    except Exception:
        pass

    return metrics


# ── Rule registry ──────────────────────────────────────────────────────────


_DEFAULT_RULES: tuple[AttentionRule, ...] = (
    # Auto-tune
    AttentionRule(
        rule_id="autotune_recall_negative",
        tool_id="autotune", severity="critical",
        enter_threshold=1, exit_threshold=1,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("autotune_recall_negative"),
        message_template=("{value} recall-reducing proposal(s) pending — "
                          "review before applying (NP1 risk)."),
        can_snooze=False,
        description="Recall-reducing proposal accumulated; analyst review required.",
    ),
    AttentionRule(
        rule_id="autotune_drift_unack",
        tool_id="autotune", severity="warning",
        enter_threshold=1, exit_threshold=1,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("drift_unack"),
        message_template=("{value} drift signal(s) past dwell threshold "
                          "and unacknowledged."),
    ),
    AttentionRule(
        rule_id="autotune_pending_volume",
        tool_id="autotune", severity="info",
        enter_threshold=20, exit_threshold=15,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("autotune_pending_total"),
        message_template="{value} pending proposals (>{enter}).",
    ),
    AttentionRule(
        rule_id="autotune_sensor_disable_imminent",
        tool_id="autotune", severity="critical",
        enter_threshold=1, exit_threshold=1,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("sensor_disable_ack_imminent"),
        message_template=("{value} sensor auto-disable proposal(s) within "
                          "4h of expiry — ack required."),
        can_snooze=False,
    ),
    AttentionRule(
        rule_id="autotune_quality_inversion",
        tool_id="autotune", severity="warning",
        enter_threshold=0.50, exit_threshold=0.40,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("dismissed_pct_30d"),
        message_template=("{pct} of recently closed proposals were dismissed — "
                          "rules may be misfiring."),
    ),

    # LLM Features
    AttentionRule(
        rule_id="llm_kill_switch",
        tool_id="llm-features", severity="critical",
        enter_threshold=1, exit_threshold=1,
        threshold_mode="boolean",
        eval_fn=lambda m: 1 if m.get("llm_kill_switch") else 0,
        message_template="LLM kill switch is engaged — all LLM features OFF.",
        can_snooze=False,
    ),
    AttentionRule(
        rule_id="llm_feature_long_shadow",
        tool_id="llm-features", severity="info",
        enter_threshold=1, exit_threshold=1,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("feature_long_shadow"),
        message_template=("{value} feature(s) in shadow > 7 days — review "
                          "for opt-in promotion."),
    ),

    # LLM Intel
    AttentionRule(
        rule_id="llm_intel_review_needed",
        tool_id="llm-intel", severity="warning",
        enter_threshold=1, exit_threshold=1,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("llm_intel_review_needed"),
        message_template="{value} item(s) flagged for explicit analyst review.",
    ),
    AttentionRule(
        rule_id="llm_intel_stale_pending",
        tool_id="llm-intel", severity="warning",
        enter_threshold=4.0, exit_threshold=2.0,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("llm_intel_oldest_age_h"),
        message_template=("Oldest pending item is {value:.1f}h old "
                          "(>{enter:.0f}h threshold)."),
    ),

    # Sensor watchpane
    AttentionRule(
        rule_id="sensor_error",
        tool_id="watchpane", severity="critical",
        enter_threshold=1, exit_threshold=1,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("sensor_error"),
        message_template=("{value} sensor(s) in ERROR state — graceful "
                          "degradation active."),
        can_snooze=False,
    ),
    AttentionRule(
        rule_id="sensor_stale_multi",
        tool_id="watchpane", severity="warning",
        enter_threshold=3, exit_threshold=2,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("sensor_stale"),
        message_template="{value} sensor(s) stale (>3× poll interval).",
    ),
    AttentionRule(
        rule_id="sensor_stale_single",
        tool_id="watchpane", severity="info",
        enter_threshold=1, exit_threshold=0,
        threshold_mode="absolute",
        eval_fn=lambda m: m.get("sensor_stale"),
        message_template="{value} sensor stale.",
    ),
)


def all_rules() -> tuple[AttentionRule, ...]:
    return _DEFAULT_RULES


# ── Hysteresis state ───────────────────────────────────────────────────────


# In-memory cache of currently-firing rule_ids. The cache is initialised
# empty on every process restart — losing hysteresis state for a few
# seconds is acceptable. The set is updated by evaluate().
_active_rules: set[str] = set()


def _is_firing(rule: AttentionRule, value: Optional[float]) -> bool:
    """Apply hysteresis: a rule transitions from off→on when value
    reaches enter_threshold (inclusive), from on→off when value drops
    BELOW exit_threshold (strict). Between exit and enter it keeps its
    previous state.

    For thresholds expressed as "1 / 0", that means:
      - value 0  → not firing (regardless of prior)
      - value 1  → fires (or stays firing)
      - value 5  → fires
    Which matches the natural-language description "fire when ≥1
    pending; clear when 0 pending".
    """
    if value is None:
        return False
    was_active = rule.rule_id in _active_rules
    if rule.threshold_mode == "boolean":
        return bool(value)
    if was_active:
        # Stays active until value drops strictly below exit
        return value >= rule.exit_threshold and value > 0
    # Was inactive: requires reaching enter threshold (inclusive)
    return value >= rule.enter_threshold


# ── Snooze persistence ────────────────────────────────────────────────────


def _is_snoozed(rule_id: str) -> bool:
    """DB-backed snooze check. Returns True if a snooze row exists with
    snooze_until > now."""
    try:
        from radar.database import db as _db
        row = _db._get_conn().execute(  # noqa: SLF001
            "SELECT snooze_until FROM attention_snooze WHERE rule_id=?",
            (rule_id,),
        ).fetchone()
        if not row:
            return False
        return float(row[0] or 0) > time.time()
    except Exception:
        return False


def snooze(rule_id: str, *, hours: float = 24.0, by: str) -> bool:
    """Mark a rule as snoozed for `hours`. Returns True on success.

    Rejects critical rules at the rule layer (the API layer does the
    same check at 403/400 level)."""
    rule = next((r for r in _DEFAULT_RULES if r.rule_id == rule_id), None)
    if rule is None:
        return False
    if not rule.can_snooze:
        return False
    until = time.time() + max(0.5, hours) * 3600
    try:
        from radar.database import db as _db
        conn = _db._get_conn()  # noqa: SLF001
        with conn.writing():
            conn.execute(
                "INSERT INTO attention_snooze (rule_id, snooze_until, by) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(rule_id) DO UPDATE SET "
                "  snooze_until=excluded.snooze_until, by=excluded.by",
                (rule_id, until, by),
            )
        return True
    except Exception as exc:
        log.warning("snooze(%s) failed: %s", rule_id, exc)
        return False


# ── Evaluator ─────────────────────────────────────────────────────────────


def _format_message(rule: AttentionRule, value: Optional[float]) -> str:
    try:
        if rule.threshold_mode == "boolean":
            return rule.message_template
        # Provide common substitutions
        return rule.message_template.format(
            value=value,
            enter=rule.enter_threshold,
            exit=rule.exit_threshold,
            pct=f"{(value or 0) * 100:.0f}%" if rule.rule_id.endswith(
                "quality_inversion") else (value or 0),
        )
    except Exception:
        return rule.message_template


def evaluate() -> list[dict]:
    """Return the current list of firing ATTENTION rules. NP3-safe."""
    metrics = _collect_metrics()
    out: list[dict] = []
    new_active: set[str] = set()
    for rule in _DEFAULT_RULES:
        try:
            value = rule.eval_fn(metrics)
        except Exception as exc:
            log.debug("eval %s failed: %s", rule.rule_id, exc)
            value = None
        firing = _is_firing(rule, value)
        if firing:
            new_active.add(rule.rule_id)
            if _is_snoozed(rule.rule_id):
                # Snoozed rules don't surface, but stay tracked for hysteresis
                continue
            out.append({
                "rule_id": rule.rule_id,
                "tool_id": rule.tool_id,
                "severity": rule.severity,
                "value": value,
                "enter_threshold": rule.enter_threshold,
                "exit_threshold": rule.exit_threshold,
                "message": _format_message(rule, value),
                "can_snooze": rule.can_snooze,
                "description": rule.description,
            })
    # Atomic swap (single-greenlet model)
    _active_rules.clear()
    _active_rules.update(new_active)
    return out


def per_tool_status() -> dict[str, dict]:
    """Aggregate ATTENTION verdicts by tool_id for the card grid badges.
    Each tool gets the highest severity rule (critical > warning > info)."""
    rules = evaluate()
    sev_rank = {"critical": 0, "warning": 1, "info": 2}
    out: dict[str, dict] = {}
    for r in rules:
        tid = r["tool_id"]
        if tid not in out or sev_rank[r["severity"]] < sev_rank[out[tid]["severity"]]:
            out[tid] = {
                "severity": r["severity"],
                "text": r["message"][:60],  # bounded for card display
            }
    return out


__all__ = [
    "AttentionRule", "all_rules",
    "evaluate", "per_tool_status",
    "snooze",
]
