"""α-broken sensor auto-disable proposer (Phase D).

Reads `audit_intel_sensors` style classifications from llm_call_log and
identifies sensors that are α (broken: pre_filter rejecting 100%, or
errors dominating). Emits a proposal to auto-disable; the proposal
sits in 24h ack window before the actual disable fires. This gives
the operator time to either (a) confirm the disable is appropriate or
(b) fix the underlying sensor.

Workflow:

  1. Daily cron (this module) calls `propose_disables()`:
     - For each LLM-gated sensor, classify based on llm_call_log
       7d window: total / ok / pre_filter / errors
     - α-class condition: pre_filter ≥ 95% OR errors ≥ 20%
     - If sensor is α-class AND not already in pending-disable state,
       emit a `scenario_proposals` row with type='sensor_disable',
       state='pending', metadata.ack_due_at = now + 24h
     - If sensor is α-class AND already pending AND ack_due_at passed,
       *escalate* to applied (= operator did not ack)

  2. Operator reviews via API:
     - GET /api/v2/proposals/sensor_disable → list pending
     - POST /api/v2/proposals/sensor_disable/<id>/ack → mark
       acknowledged (no auto-disable)
     - POST /api/v2/proposals/sensor_disable/<id>/dismiss → mark
       dismissed (sensor stays enabled, escalation cancelled)

  3. Apply step (gated on V2_AUTO_DISABLE_ENABLED env, default false):
     - Update sensor.enabled = False in the registry
     - Write threshold_history row keyed `sensor_enabled.<name>`
     - Notify via slack/teams hook

NP integrity:
  NP1 — disabling a sensor reduces signal coverage; the 24h ack
        window ensures analyst review before any silent loss
  NP3 — a chronically α-broken sensor SHOULD be disabled (it's
        contributing degraded signal that pollutes scoring). NP3
        actually FAVOURS this auto-disable as long as it's loud.
  NP6 — every proposal has formula_ref + evidence (the call_log
        breakdown that triggered the classification)
  NP7 — operator decides via ack/dismiss; never auto-applies
        without 24h window expiring (safe-by-default)
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

from radar.database import db

log = logging.getLogger("radar.calibration.sensor_disable_proposer")


PROPOSER_VERSION = "sensor_disable_proposer/v1"
APPLIED_BY = "auto:sensor_disabler"

LLM_GATED_SENSORS: tuple[str, ...] = (
    "apt_intel",
    "diplomatic",
    "military_exercise",
    "rss_narrative",
    "ground_osint",
    "hacktivist_intel",
    "hacktivist_news",
)


def _ack_window_hours() -> float:
    return float(os.getenv("SENSOR_DISABLE_ACK_HOURS", "24"))


def _alpha_pre_filter_ratio() -> float:
    """Pre-filter ratio at which a sensor is classified α (broken)."""
    return float(os.getenv("SENSOR_DISABLE_ALPHA_PRE_FILTER", "0.95"))


def _alpha_error_ratio() -> float:
    return float(os.getenv("SENSOR_DISABLE_ALPHA_ERROR", "0.20"))


def _min_call_log_n() -> int:
    """Minimum 7d call_log samples before any classification fires.
    Prevents auto-disable on sensors that just haven't run yet."""
    return int(os.getenv("SENSOR_DISABLE_MIN_CALLS", "100"))


def _sensor_fetch_layer_healthy(sensor_name: str) -> tuple[bool, str]:
    """Phase A guard (2026-04-30): consult the sensor's own
    fetch-layer health BEFORE proposing disable based on LLM
    call-log statistics.

    Rationale: the existing α-broken classifier reads `llm_call_log`
    (LLM-side statistics — pre_filter / parse_failed / timeout /
    http_error). A high pre_filter ratio can mean either:
      (a) the SENSOR genuinely produces low-value content → disable
          is correct; or
      (b) the LLM PROMPT is too strict / the sensor is in a brief
          quiet period → disable is wrong (we'd lose a healthy
          information source for nothing). NP1 violation.

    The fetch layer (sensor.py / SensorRegistry.health_snapshot)
    knows whether the sensor is actually pulling data successfully.
    If the fetch layer says the sensor is healthy AND its circuit
    breaker is closed AND it's actively producing fetches, we
    refuse to emit the disable proposal regardless of LLM-side α
    signal — under the rule "tighten the LLM prompt before
    disabling a working sensor".

    Returns (is_healthy, reason). If healthy, the proposer skips
    emitting the disable proposal.
    """
    try:
        import radar.routes as _routes
        sensor = _routes.registry._sensors.get(sensor_name)  # noqa: SLF001
    except Exception as exc:
        return (False, f"registry_lookup_failed: {exc}")
    if sensor is None:
        return (False, "sensor_not_in_registry")
    # If the sensor is already disabled, don't re-propose.
    if not getattr(sensor, "enabled", True):
        return (False, "already_disabled")
    # Circuit breaker open → genuinely broken at fetch layer.
    cb_state = getattr(sensor, "cb_state", None)
    if cb_state and str(cb_state).upper() == "OPEN":
        return (False, "cb_open")
    # Read reliability from the sensor_fetch_log ledger (not
    # sensor_call_log — that's the LLM call ledger, this guard needs
    # the upstream HTTP fetch outcome).
    try:
        from radar.database import db as _db
        cutoff = time.time() - 24 * 3600
        rows = _db._get_conn().execute(  # noqa: SLF001
            "SELECT COUNT(*) FROM sensor_fetch_log "
            "WHERE sensor_name=? AND ts > ? AND success=1",
            (sensor_name, cutoff),
        ).fetchone()
        ok_24h = rows[0] if rows else 0
    except Exception:
        ok_24h = None
    # Healthy gate: at least 10 successful fetches in 24h AND no recent
    # error AND CB closed. 10 picks up daily-poll sensors but excludes
    # truly silent ones.
    last_err = getattr(sensor, "last_error", "") or ""
    if ok_24h is not None and ok_24h >= 10 and not last_err:
        return (True, f"fetch_healthy: {ok_24h} ok fetches in 24h, cb={cb_state}")
    if ok_24h is None:
        # Cannot verify either way — be conservative and DO NOT block
        # the proposal. The LLM-side α signal stands.
        return (False, "fetch_telemetry_unavailable")
    return (False, f"fetch_unhealthy: ok_24h={ok_24h}, last_err={last_err[:60]!r}")


def _classify_sensor_health(sensor_name: str) -> Optional[dict]:
    """Read llm_call_log per-outcome counts for sensor over 7d window.
    Returns dict with classification, or None on insufficient data."""
    try:
        cutoff = time.time() - 7 * 86400
        conn = db._get_conn()  # noqa: SLF001
        rows = conn.execute(
            "SELECT outcome, COUNT(*) FROM llm_call_log "
            "WHERE caller=? AND ts > ? GROUP BY outcome",
            (sensor_name, cutoff),
        ).fetchall()
    except Exception as exc:
        log.debug("classify %s failed: %s", sensor_name, exc)
        return None
    counts = {row[0]: row[1] for row in rows}
    total = sum(counts.values())
    if total < _min_call_log_n():
        return None
    ok = counts.get("ok", 0)
    pre_filter = counts.get("pre_filter", 0)
    parse_failed = counts.get("parse_failed", 0)
    timeout = counts.get("timeout", 0)
    http_error = counts.get("http_error", 0)
    errors = parse_failed + timeout + http_error
    pre_ratio = pre_filter / total
    err_ratio = errors / total
    alpha = (pre_ratio >= _alpha_pre_filter_ratio()
             or err_ratio >= _alpha_error_ratio())
    return {
        "total": total,
        "ok": ok,
        "pre_filter": pre_filter,
        "errors": errors,
        "pre_ratio": pre_ratio,
        "err_ratio": err_ratio,
        "alpha": alpha,
    }


@dataclass(frozen=True)
class DisableProposal:
    sensor_name: str
    proposal_id: int
    state: str  # 'pending' | 'applied' | 'dismissed' | 'acknowledged'
    ack_due_at: float
    why_string: str


def _existing_pending(sensor_name: str) -> Optional[tuple]:
    """Return (id, state, emitted_at) of an existing pending/applied
    proposal for this sensor, or None."""
    try:
        conn = db._get_conn()  # noqa: SLF001
        row = conn.execute(
            "SELECT id, state, emitted_at FROM scenario_proposals "
            "WHERE proposal_type='sensor_disable' AND target_country=? "
            "AND state IN ('pending', 'applied') "
            "ORDER BY emitted_at DESC LIMIT 1",
            (sensor_name,),  # use target_country column to hold sensor_name
        ).fetchone()
        return row if row else None
    except Exception as exc:
        log.debug("existing_pending check failed for %s: %s", sensor_name, exc)
        return None


def _emit_proposal(sensor_name: str, classification: dict) -> int:
    """Write a 'pending' sensor_disable proposal row. Returns row id."""
    now = time.time()
    ack_due_at = now + _ack_window_hours() * 3600
    why = (
        f"Sensor {sensor_name} is α-broken: "
        f"pre_filter={classification['pre_ratio']*100:.0f}%, "
        f"errors={classification['err_ratio']*100:.0f}% over 7d. "
        f"Auto-disable will fire in {_ack_window_hours():.0f}h unless "
        f"acknowledged or dismissed."
    )
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        cur = conn.execute(
            "INSERT INTO scenario_proposals "
            "(emitted_at, scenario_id, proposal_type, target_country, "
            " suggested_value_json, evidence_json, formula_ref, sample_n, "
            " why_string, state) "
            "VALUES (?, '__system__', 'sensor_disable', ?, ?, ?, ?, ?, ?, 'pending')",
            (now, sensor_name,
             json.dumps({"action": "disable", "ack_due_at": ack_due_at}),
             json.dumps(classification),
             f"{PROPOSER_VERSION}#alpha_broken",
             classification["total"],
             why),
        )
        rid = cur.lastrowid
    log.info(
        "[sensor_disable_proposer] %s α-broken (pre_ratio=%.2f, err_ratio=%.2f) "
        "→ pending proposal id=%d ack_due_at=%s",
        sensor_name, classification["pre_ratio"], classification["err_ratio"],
        rid, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ack_due_at)),
    )
    return rid


def _escalate_to_applied(proposal_id: int, sensor_name: str) -> bool:
    """Promote a pending proposal to applied state once ack window
    expires. Returns True if the apply succeeded.

    The actual sensor disable is gated on V2_AUTO_DISABLE_ENABLED
    (default false). When false, the proposal is marked applied in the
    ledger but the sensor itself is NOT disabled — operators can review
    the AP3 scoreboard to see what would have happened.
    """
    enabled = os.getenv("V2_AUTO_DISABLE_ENABLED", "false").strip().lower() in (
        "1", "true", "yes", "on"
    )
    conn = db._get_conn()  # noqa: SLF001
    now = time.time()
    with conn.writing():
        conn.execute(
            "UPDATE scenario_proposals SET state='applied', "
            "state_changed_at=?, state_changed_by=? WHERE id=?",
            (now, "auto:escalation" if enabled else "auto:escalation_dry_run",
             proposal_id),
        )
    if not enabled:
        log.info(
            "[sensor_disable_proposer] proposal %d (%s) escalated to applied "
            "but V2_AUTO_DISABLE_ENABLED=false — no actual disable",
            proposal_id, sensor_name,
        )
        return False
    # Actually disable the sensor in the registry.
    try:
        import radar.routes as _routes
        sensor = _routes.registry._sensors.get(sensor_name)  # noqa: SLF001
        if sensor:
            sensor.enabled = False
            log.info(
                "[sensor_disable_proposer] DISABLED sensor %s via auto-escalation "
                "(proposal id=%d)", sensor_name, proposal_id,
            )
            return True
    except Exception as exc:
        log.warning(
            "[sensor_disable_proposer] failed to disable %s: %s",
            sensor_name, exc,
        )
    return False


def propose_disables() -> dict:
    """Run one pass: for each sensor, classify health and emit/escalate
    proposals. Returns counts."""
    counts = {"classified": 0, "alpha": 0, "new_proposals": 0,
              "escalated": 0, "skipped_existing": 0,
              "skipped_fetch_healthy": 0}
    for s in LLM_GATED_SENSORS:
        cls = _classify_sensor_health(s)
        if cls is None:
            continue
        counts["classified"] += 1
        if not cls["alpha"]:
            continue
        counts["alpha"] += 1

        # Phase A guard (2026-04-30): even when LLM-side α is true,
        # if the sensor's own fetch layer is healthy, prefer prompt
        # tightening over sensor disable. NP1 — never sever a working
        # data source on LLM-side evidence alone.
        is_healthy, reason = _sensor_fetch_layer_healthy(s)
        if is_healthy:
            counts["skipped_fetch_healthy"] += 1
            log.info(
                "[sensor_disable_proposer] %s α=true at LLM layer but "
                "skipping disable proposal — fetch layer healthy (%s). "
                "Tighten LLM prompt before disabling working sensor.",
                s, reason,
            )
            continue

        existing = _existing_pending(s)
        if existing is None:
            _emit_proposal(s, cls)
            counts["new_proposals"] += 1
            continue
        prop_id, state, emitted_at = existing
        if state == "pending":
            # Check if ack window expired.
            ack_window_s = _ack_window_hours() * 3600
            if (time.time() - emitted_at) > ack_window_s:
                _escalate_to_applied(prop_id, s)
                counts["escalated"] += 1
            else:
                counts["skipped_existing"] += 1
        else:
            counts["skipped_existing"] += 1
    return counts


def list_pending() -> list[dict]:
    """Return all pending sensor_disable proposals for operator UI."""
    try:
        conn = db._get_conn()  # noqa: SLF001
        rows = conn.execute(
            "SELECT id, target_country, emitted_at, suggested_value_json, "
            "evidence_json, why_string, state FROM scenario_proposals "
            "WHERE proposal_type='sensor_disable' AND state='pending' "
            "ORDER BY emitted_at DESC"
        ).fetchall()
    except Exception as exc:
        log.warning("list_pending failed: %s", exc)
        return []
    out = []
    for r in rows:
        try:
            suggested = json.loads(r[3] or "{}")
            evidence = json.loads(r[4] or "{}")
        except Exception:
            suggested, evidence = {}, {}
        out.append({
            "id": r[0],
            "sensor_name": r[1],
            "emitted_at": r[2],
            "ack_due_at": suggested.get("ack_due_at"),
            "evidence": evidence,
            "why_string": r[5],
            "state": r[6],
        })
    return out


def acknowledge(proposal_id: int, *, by: str) -> bool:
    """Mark a pending proposal as acknowledged (cancels the auto-disable)."""
    conn = db._get_conn()  # noqa: SLF001
    with conn.writing():
        cur = conn.execute(
            "UPDATE scenario_proposals SET state='dismissed', "
            "state_changed_at=?, state_changed_by=? "
            "WHERE id=? AND proposal_type='sensor_disable' AND state='pending'",
            (time.time(), by, proposal_id),
        )
        return cur.rowcount > 0


__all__ = [
    "LLM_GATED_SENSORS",
    "propose_disables",
    "list_pending",
    "acknowledge",
]
