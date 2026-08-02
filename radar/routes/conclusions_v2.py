"""v2 API skeleton — read-only access to the conclusions ledger.

Phase 1 scope (per docs/design/v2-phase1-handoff.md):
  - GET /api/v2/scenarios/<id>/conclusions             — bundle of latest 5 types
  - GET /api/v2/scenarios/<id>/conclusions/<type>      — single domain
  - GET /api/v2/conclusions/<conclusion_id>            — one row by id
  - GET /api/v2/conclusions/<conclusion_id>/audit_trace — formula + sources +
                                                          LLM prompt full text

All endpoints are gated behind `config.V2_API_ENABLED`. When the flag is off,
the routes return 503 so v1 clients aren't tempted to consume v2 prematurely.

NP6 (audit_trace) and NP7 (envelope-level disclaimer) are enforced here
rather than at the dataclass level so that `not_enabled` / `not_found`
responses still carry the disclaimer.
"""

from __future__ import annotations

from flask import jsonify, request
from flask_jwt_extended import jwt_required

from radar.conclusions.api import (
    API_VERSION,
    build_envelope,
    build_error,
    build_unavailable,
)
from radar.conclusions.base import ConclusionType
from radar.conclusions.feedback import (
    AnalystFeedback,
    FeedbackLabel,
    coerce_label,
    list_feedback,
    now_seconds,
    save_feedback,
    summarize_feedback,
)
from radar.conclusions.markdown import render_scenario_markdown
from radar.conclusions.persistence import (
    get_conclusion_by_id,
    latest_conclusion,
)
from radar.routes import _require_admin, _require_analyst, _safe_int, bp


_ALL_TYPES = (
    ConclusionType.THREAT_LEVEL,
    ConclusionType.TREND,
    ConclusionType.PER_DOMAIN,
    ConclusionType.ANOMALY,
    ConclusionType.ATTACK_MODE,
)


def _v2_enabled_or_503():
    """Guard helper. Returns a Flask response if the flag is off, else None."""
    from radar import config
    if not config.V2_API_ENABLED:
        body, status = build_error(
            503,
            "v2 API not enabled",
            detail="Set V2_API_ENABLED=true to opt in (Phase 1 read-only).",
        )
        return jsonify(body), status
    return None


def _parse_conclusion_type(raw: str):
    """Parse a path/query value into a ConclusionType, or return None on miss."""
    try:
        return ConclusionType(raw)
    except ValueError:
        return None


@bp.route("/api/v2/scenarios/<scenario_id>/threat_history", methods=["GET"])
@jwt_required()
def v2_scenario_threat_history(scenario_id: str):
    """Per-scenario TL history (migration v33 — HUD sparkline divergence
    fix 2026-04-29).

    Returns the TL series for one scenario over the lookback window so
    the HUD sparkline can render scenario-specific bars instead of the
    legacy "whichever scenario was focused at the time" mishmash.

    Query params:
      hours  : lookback window in hours (default 24, max 168)
      limit  : max rows (default 1000, hard cap)

    Response: { scenario_id, hours, history: [[ts, level], ...] }
    """
    from flask import request as _req
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    try:
        hours = max(1, min(int(_req.args.get("hours", "24")), 168))
    except (ValueError, TypeError):
        hours = 24
    try:
        limit = max(1, min(int(_req.args.get("limit", "1000")), 5000))
    except (ValueError, TypeError):
        limit = 1000

    from radar.database import db
    import time as _time
    since_ts = _time.time() - hours * 3600
    rows = db.threat_list_scoped(scenario_id,
                                  since_ts=since_ts,
                                  limit=limit)
    return jsonify({
        "api_version": API_VERSION,
        "scenario_id": scenario_id,
        "hours": hours,
        "history": [[r[0], r[1]] for r in rows],
        "final_judgment_disclaimer": _np7_disclaimer(),
    })


def _np7_disclaimer():
    from radar import config as _cfg
    return _cfg.V2_NP7_DISCLAIMER


@bp.route("/api/v2/scenarios/<scenario_id>/conclusions", methods=["GET"])
@jwt_required()
def v2_scenario_conclusions(scenario_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db

    conclusions = []
    for ct in _ALL_TYPES:
        c = latest_conclusion(db, scenario_id, ct)
        if c is not None:
            conclusions.append(c)

    if not conclusions:
        return jsonify(build_unavailable(scenario_id, ConclusionType.THREAT_LEVEL,
                                         detail="no conclusions for this scenario yet"))
    return jsonify(build_envelope(scenario_id, conclusions))


@bp.route("/api/v2/scenarios/<scenario_id>/conclusions/<conclusion_type>",
          methods=["GET"])
@jwt_required()
def v2_scenario_conclusion_single(scenario_id: str, conclusion_type: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    ct = _parse_conclusion_type(conclusion_type)
    if ct is None:
        body, status = build_error(
            400,
            "unknown conclusion_type",
            detail=f"valid: {[t.value for t in _ALL_TYPES]}",
        )
        return jsonify(body), status

    from radar.database import db
    c = latest_conclusion(db, scenario_id, ct)
    if c is None:
        return jsonify(build_unavailable(scenario_id, ct))
    return jsonify(build_envelope(scenario_id, [c]))


@bp.route("/api/v2/conclusions/<conclusion_id>", methods=["GET"])
@jwt_required()
def v2_conclusion_by_id(conclusion_id: str):
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db
    c = get_conclusion_by_id(db, conclusion_id)
    if c is None:
        body, status = build_error(
            404, "conclusion not found", conclusion_id=conclusion_id,
        )
        return jsonify(body), status
    return jsonify(build_envelope(c.scenario_id, [c]))


@bp.route("/api/v2/conclusions/<conclusion_id>/audit_trace", methods=["GET"])
@jwt_required()
def v2_conclusion_audit_trace(conclusion_id: str):
    """NP6 — return the full derivation: formula_ref, threshold_ref, source
    URLs, calibration status, and the resolved LLM prompt text (system + user)
    if a sha256 is linked.

    Phase 1 skeleton: ledger row + LLM prompt full-text resolution. We do
    NOT yet resolve formula_ref to source code (that's Phase 3 — would
    require a code-snippet store keyed by git rev).
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db
    c = get_conclusion_by_id(db, conclusion_id)
    if c is None:
        body, status = build_error(
            404, "conclusion not found", conclusion_id=conclusion_id,
        )
        return jsonify(body), status

    trace = {
        "api_version": API_VERSION,
        "conclusion_id": c.id,
        "scenario_id": c.scenario_id,
        "conclusion_type": c.conclusion_type.value,
        "observed_at": c.observed_at,
        "final_judgment_disclaimer": _disclaimer(),
        "formula_ref": c.formula_ref,
        "threshold_ref": dict(c.threshold_ref),
        "source_urls": list(c.source_urls),
        "calibration_status": dict(c.calibration_status),
        "metadata": dict(c.metadata),
    }
    if c.llm_prompt_sha256:
        trace["llm_prompt"] = _resolve_llm_prompt(db, c.llm_prompt_sha256)
    else:
        trace["llm_prompt"] = None
    return jsonify(trace)


@bp.route("/api/v2/scenarios/<scenario_id>/conclusions.md", methods=["GET"])
@jwt_required()
def v2_scenario_conclusions_markdown(scenario_id: str):
    """Phase 3 — single-file Markdown export of a scenario's latest conclusions.

    Pure text/markdown response (not the JSON envelope) so analysts can pipe
    the body straight into a wiki, ticket, or local file. NP6 disclosure is
    preserved: when ?include_audit=1 each section embeds the resolved LLM
    prompt full text via an expandable <details> block.

    NP7 disclaimer is rendered once at the top as a blockquote — the same
    string shipped in JSON envelopes' final_judgment_disclaimer field.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db

    conclusions = []
    for ct in _ALL_TYPES:
        c = latest_conclusion(db, scenario_id, ct)
        if c is not None:
            conclusions.append(c)

    audit_traces = None
    include_audit = request.args.get("include_audit", "0").lower() in (
        "1", "true", "yes",
    )
    if include_audit:
        audit_traces = {}
        for c in conclusions:
            if c.llm_prompt_sha256:
                audit_traces[c.id] = {
                    "llm_prompt": _resolve_llm_prompt(db, c.llm_prompt_sha256),
                }

    body = render_scenario_markdown(
        scenario_id,
        conclusions,
        disclaimer=_disclaimer(),
        api_version=API_VERSION,
        audit_traces=audit_traces,
    )
    filename = f"{scenario_id}-conclusions.md"
    return (
        body,
        200,
        {
            "Content-Type": "text/markdown; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@bp.route("/api/v2/conclusions/<conclusion_id>/feedback", methods=["POST"])
@jwt_required()
def v2_conclusion_feedback_submit(conclusion_id: str):
    """ADR-V2-011 — submit one analyst feedback row against a conclusion.

    Body: `{label, observed_outcome_url?, notes?}`. The analyst_id and
    observed_at are server-derived (JWT identity, server clock) so the
    client cannot spoof either. Returns the new id + the post-write
    aggregate so the UI can update its multi-analyst view in one round-trip.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from flask_jwt_extended import get_jwt_identity
    from radar.database import db

    target = get_conclusion_by_id(db, conclusion_id)
    if target is None:
        body, status = build_error(
            404, "conclusion not found", conclusion_id=conclusion_id,
        )
        return jsonify(body), status

    payload = request.get_json(silent=True) or {}
    label = coerce_label(payload.get("label"))
    if label is None:
        body, status = build_error(
            400, "invalid feedback label",
            detail="valid: TRUE_POSITIVE, FALSE_POSITIVE, "
                   "TRUE_NEGATIVE, FALSE_NEGATIVE",
        )
        return jsonify(body), status

    raw_url = payload.get("observed_outcome_url")
    outcome_url = raw_url.strip() if isinstance(raw_url, str) and raw_url.strip() else None
    raw_notes = payload.get("notes")
    notes = raw_notes.strip() if isinstance(raw_notes, str) and raw_notes.strip() else None
    if notes and len(notes) > 2000:
        notes = notes[:2000]

    fb = AnalystFeedback(
        conclusion_id=conclusion_id,
        label=label,
        analyst_id=get_jwt_identity() or "analyst",
        observed_at=now_seconds(),
        observed_outcome_url=outcome_url,
        notes=notes,
    )
    new_id = save_feedback(db, fb)

    # Human-confirmed escalation → revive the confirmed_threats ground-
    # truth ledger (dormant since 2023). Both TRUE_POSITIVE (tool alerted
    # and was right) and FALSE_NEGATIVE (tool stayed calm and missed it)
    # assert a REAL escalation occurred — confirmed_threats records real
    # threats independent of whether the tool caught them. Only genuine
    # human labels with an outcome URL qualify. Best-effort — never breaks
    # the feedback path.
    if (
        label in (FeedbackLabel.TRUE_POSITIVE, FeedbackLabel.FALSE_NEGATIVE)
        and outcome_url
        and not fb.analyst_id.startswith("auto:")
    ):
        try:
            from radar.scenarios import scenario_store
            sc = scenario_store.get(target.scenario_id)
            country = getattr(sc, "core_country", None) or target.scenario_id
            missed = label is FeedbackLabel.FALSE_NEGATIVE
            if missed:
                # The tool's TL was calm and does not describe the real
                # event; record a HIGH floor (TL3) plus a distinct
                # classification so the miss is auditable.
                tl_val = 3
                classification = (
                    f"human_confirmed_miss:{target.conclusion_type.value}")
            else:
                try:
                    tl_val = int(target.state or "")
                except (TypeError, ValueError):
                    tl_val = 0
                classification = (
                    f"human_confirmed:{target.conclusion_type.value}")
            db.confirmed_threat_add(
                theater=country,
                ts=target.observed_at,
                classification=classification,
                sensors_active=[],
                threat_level=tl_val,
                notes=(notes or f"human label via feedback {new_id}: "
                                f"{outcome_url}")[:500],
                created_by=fb.analyst_id,
            )
        except Exception:
            import logging
            logging.getLogger("radar.routes.conclusions_v2").debug(
                "confirmed_threats write skipped", exc_info=True,
            )

    summary = summarize_feedback(db, conclusion_id)
    return jsonify({
        "api_version": API_VERSION,
        "final_judgment_disclaimer": _disclaimer(),
        "feedback_id": new_id,
        "summary": summary,
    }), 201


@bp.route("/api/v2/conclusions/<conclusion_id>/feedback", methods=["GET"])
@jwt_required()
def v2_conclusion_feedback_list(conclusion_id: str):
    """Return the per-conclusion feedback ledger + aggregate counts.

    Read path is what enforces the "show multiple analysts, never a single
    verdict" rule from v2-migration §11 — the response shape is
    `{summary, items}` so the UI can render counts even when listing the
    raw rows would be too noisy.
    """
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard
    from radar.database import db

    target = get_conclusion_by_id(db, conclusion_id)
    if target is None:
        body, status = build_error(
            404, "conclusion not found", conclusion_id=conclusion_id,
        )
        return jsonify(body), status

    limit = _safe_int(request.args.get("limit"), 50, min_val=1, max_val=1000)
    rows = list_feedback(db, conclusion_id, limit=limit)
    items = [{
        "id": r.id,
        "label": r.label.value,
        "analyst_id": r.analyst_id,
        "observed_at": r.observed_at,
        "observed_outcome_url": r.observed_outcome_url,
        "notes": r.notes,
    } for r in rows]
    return jsonify({
        "api_version": API_VERSION,
        "final_judgment_disclaimer": _disclaimer(),
        "conclusion_id": conclusion_id,
        "summary": summarize_feedback(db, conclusion_id),
        "items": items,
    })


def _disclaimer() -> str:
    from radar import config
    return config.V2_NP7_DISCLAIMER


# /api/v2/admin/conclusion_diff_stats RETIRED 2026-05-29 along with the
# v1-vs-v2 diff sampler (the migration-rollout monitor it surfaced).


@bp.route("/api/v2/admin/shadow_write_metrics", methods=["GET"])
def v2_shadow_write_metrics():
    """Mode B observability — process-local counters for the 5 shadow-write
    hooks in compute_scenario_score.

    Unlike most /api/v2 routes this one is NOT gated by V2_API_ENABLED. The
    operator needs to read it during the Shadow phase precisely *because*
    the public v2 API is still off — otherwise there is no way to verify
    that V2_CONCLUSION_LEDGER_ENABLED=true is actually producing rows.
    Admin auth is still required so the surface stays internal.

    Counters are reset on process restart; `started_at` / `uptime_sec` let
    the operator interpret whether a "0 successes" reading means "broken"
    or "just restarted, no scoring tick has run yet".
    """
    auth_err = _require_admin()
    if auth_err is not None:
        return auth_err

    from radar import config
    from radar.conclusions.shadow_metrics import snapshot

    snap = snapshot()
    return jsonify({
        "api_version": API_VERSION,
        "ledger_enabled": config.V2_CONCLUSION_LEDGER_ENABLED,
        "metrics": snap,
        "final_judgment_disclaimer": _disclaimer(),
    })


@bp.route("/api/v2/replay/<scenario_id>", methods=["GET"])
@jwt_required()
def v2_replay(scenario_id):
    """AP4 — Decision Trail / Replay: return the conclusions envelope as
    it appeared at a given past instant.

    Query parameter ``?at=<unix_seconds>`` selects the moment. For each
    of the 5 ConclusionType buckets we return the latest row whose
    ``observed_at <= at`` (or unavailable if no row exists by that time).
    Same envelope shape as ``/api/v2/scenarios/<id>/conclusions`` so the
    frontend renders into the existing surfaces (HUD overlay + Triage
    Lane + Self-Explanation tooltips) without code branching.

    NP6: every replayed conclusion is a real persisted ledger row — the
    analyst can drill into it via /api/v2/conclusions/<id>/audit_trace
    and see the same formula / sources / LLM prompt that drove the
    original decision. Replay is *exactly* time-travel of the ledger,
    not regenerated narrative.
    """
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard

    raw_at = request.args.get("at")
    try:
        at = float(raw_at) if raw_at is not None else None
    except (TypeError, ValueError):
        body, status = build_error(400, "invalid 'at' parameter",
                                   detail="must be a unix timestamp in seconds")
        return jsonify(body), status
    if at is None:
        import time as _time
        at = _time.time()

    from radar.database import db as _shared_db
    rows = _shared_db._get_conn().execute(  # noqa: SLF001 — established pattern
        "SELECT * FROM conclusions "
        "WHERE scenario_id = ? AND observed_at <= ? "
        "ORDER BY conclusion_type, observed_at DESC",
        (scenario_id, at),
    ).fetchall()

    # Keep only the latest row per conclusion_type. The cursor returns rows
    # already ordered by (type ASC, observed_at DESC), so the first row of
    # each type is the most recent ≤ at.
    latest_by_type: dict[str, dict] = {}
    for row in rows:
        t = row["conclusion_type"]
        if t in latest_by_type:
            continue
        latest_by_type[t] = dict(row)

    # Ledger rows store metadata as JSON text — re-hydrate so the frontend
    # sees the same shape /api/v2/scenarios/<id>/conclusions returns.
    import json as _json
    for c in latest_by_type.values():
        for k in ("metadata", "threshold_ref", "calibration_status", "source_urls"):
            v = c.get(k)
            if isinstance(v, str):
                try:
                    c[k] = _json.loads(v)
                except Exception:  # noqa: BLE001
                    pass

    return jsonify({
        "api_version": API_VERSION,
        "scenario_id": scenario_id,
        "replay_at": at,
        "conclusions": list(latest_by_type.values()),
        "final_judgment_disclaimer": _disclaimer(),
    })


@bp.route("/api/v2/self_eval", methods=["GET"])
@jwt_required()
def v2_self_eval():
    """AP3 — Self-Evaluation: tool's own health metrics surfaced to the HUD.

    Returns recall (overall + per-conclusion-type), null-zone tracking
    (consecutive days where every focused-scenario conclusion has been
    INSUFFICIENT_DATA), and a calibration drift indicator. The HUD reads
    these values to render the trust chips so analysts can decide
    at-a-glance how much weight to put on the displayed conclusions.

    Returns 200 with `data: null` when there is not yet enough analyst
    feedback to compute recall — the HUD renders "—" placeholders.
    Never errors out; NP3 fault-tolerant.
    """
    auth_err = _require_analyst()
    if auth_err is not None:
        return auth_err
    guard = _v2_enabled_or_503()
    if guard is not None:
        return guard

    import time as _time
    from radar import config as _config

    out: dict = {
        "api_version": API_VERSION,
        "generated_at": _time.time(),
        "recall": None,
        "null_zone_days": None,
        "drift": None,
        "final_judgment_disclaimer": _disclaimer(),
    }

    try:
        # Recall — re-use the same collect_metrics path the CI gate uses
        # so the chip and the gate cannot disagree. Windowed to the same
        # horizon as per-conclusion calibration_status (2026-07-04): the
        # previous all-time aggregate was a different number under the
        # same "recall" label, and would have silently shifted once the
        # 180d feedback retention started pruning. The auto/human split
        # is surfaced so the analyst can see when recall is entirely
        # self-graded (AP3 — zero human labels means the number has no
        # independent anchor).
        import sys
        from pathlib import Path
        scripts_dir = Path(__file__).resolve().parent.parent.parent / "scripts"
        if str(scripts_dir) not in sys.path:
            sys.path.insert(0, str(scripts_dir))
        from report_recall_metrics import collect_metrics  # noqa: E402

        from radar.conclusions import calibration as _calib_mod
        from radar.database import db as _shared_db
        _window_days = int(getattr(_calib_mod, "_WINDOW_DAYS", 30))
        _since = _time.time() - _window_days * 86400.0
        cells = collect_metrics(
            _shared_db, exclude_auto=False, since=_since,
        )
        human_cells = collect_metrics(
            _shared_db, exclude_auto=True, since=_since,
        )
        if cells:
            tp = sum(c.tp for c in cells)
            fn = sum(c.fn for c in cells)
            recall = tp / (tp + fn) if (tp + fn) > 0 else None
            out["recall"] = (
                None if recall is None else round(float(recall), 3)
            )
        labels_total = sum(c.total for c in cells)
        labels_human = sum(c.total for c in human_cells)
        out["recall_meta"] = {
            "window_days":  _window_days,
            "labels_total": labels_total,
            "labels_human": labels_human,
            "labels_auto":  labels_total - labels_human,
            "source":       "ground_truth",
        }
    except Exception as e:  # noqa: BLE001
        out["recall"] = None
        out["recall_error"] = str(e)

    try:
        # Null-zone — count consecutive recent days where every observed
        # threat_level conclusion was INSUFFICIENT_DATA. Cheap heuristic:
        # walk the last 30 days of conclusions, compute longest tail-run
        # of all-INSUFFICIENT_DATA buckets ending today.
        from radar.database import db as _shared_db
        rows = _shared_db._get_conn().execute(  # noqa: SLF001 — established pattern
            "SELECT date(observed_at, 'unixepoch') AS d, "
            "       SUM(CASE WHEN conclusion_unavailable_reason IS NULL "
            "                THEN 1 ELSE 0 END) AS n_avail, "
            "       COUNT(*) AS n_total "
            "FROM conclusions WHERE conclusion_type = 'threat_level' "
            "  AND observed_at >= ? "
            "GROUP BY d ORDER BY d DESC LIMIT 30",
            (_time.time() - 30 * 86400.0,),
        ).fetchall()
        run = 0
        for row in rows:
            n_avail = row["n_avail"] if row["n_avail"] is not None else 0
            n_total = row["n_total"] if row["n_total"] is not None else 0
            if n_total > 0 and n_avail == 0:
                run += 1
            else:
                break
        out["null_zone_days"] = run
    except Exception as e:  # noqa: BLE001
        out["null_zone_days"] = None
        out["null_zone_error"] = str(e)

    # Drift — global miss-rate aggregate from the ground-truth calibration
    # signal (2026-05-29: repointed off the dead shadow sampler, whose
    # lite-vs-full delta is ≡0 since the score paths were unified, so it
    # always reported drift≈0 / "good" regardless of reality).
    #
    # The HUD chip (radar.js#hud-drift-value) reads `data.drift` as a flat
    # fraction in [0, 1]; bands are good ≤0.05, warn ≤0.10, crit >0.10. We
    # map drift = mean(1 - recall) — the miss rate — across scenarios whose
    # calibration is no longer INSUFFICIENT_DATA. recall=1.0 ⇒ drift 0
    # (good); recall=0.90 ⇒ 0.10 (warn); recall<0.90 ⇒ crit. This makes the
    # chip move when the tool actually starts missing escalations (NP1).
    try:
        from radar.database import db as _shared_db
        from radar.scenarios import scenario_store
        from radar.conclusions import calibration_status_for
        from radar.conclusions import calibration as _calib_mod
        miss_rates = []
        worst = None
        for sc in scenario_store.scorable():
            cs = calibration_status_for(_shared_db, sc.id)
            if cs.get("status") == "INSUFFICIENT_DATA" or cs.get("recall") is None:
                continue
            miss = 1.0 - float(cs["recall"])
            miss_rates.append(miss)
            if worst is None or miss > worst[1]:
                worst = (sc.id, miss)
        if miss_rates:
            out["drift"] = round(sum(miss_rates) / len(miss_rates), 4)
            out["drift_meta"] = {
                "method":        "mean_miss_rate_ground_truth",
                "scenarios_n":   len(miss_rates),
                "max_miss_rate": round(worst[1], 4) if worst else None,
                "worst_scenario": worst[0] if worst else None,
                "window_days":   _calib_mod._WINDOW_DAYS,
                "source":        "ground_truth",
            }
        else:
            out["drift"] = None
            out["drift_meta"] = {
                "method":        "mean_miss_rate_ground_truth",
                "scenarios_n":   0,
                "source":        "ground_truth",
                "reason":        "no_scenarios_with_sufficient_recall_samples",
            }
    except Exception as e:  # noqa: BLE001
        out["drift"] = None
        out["drift_meta"] = {"error": str(e)}

    # bg_observer — per-cycle audit summary (ADR-V2-015 Phase 5).
    # Never errors out (NP3); returns nulls if the table is empty or
    # the worker is disabled. The OBS-BG chip reads these fields.
    try:
        from radar.database import db as _shared_db
        bg_summary = _shared_db.bg_observer_cycle_summary(hours=24)
        out["bg_observer"] = {
            "enabled": bool(_config.BG_OBSERVER_ENABLED),
            "cycles_24h": bg_summary.get("cycles", 0),
            "empty_rate_24h": bg_summary.get("empty_rate"),
            "matches_per_cycle_avg": bg_summary.get("matches_per_cycle_avg"),
            "matches_total_24h": bg_summary.get("matches_total", 0),
            "alias_gap": bg_summary.get("alias_gap", []),
            "last_cycle_at": bg_summary.get("last_at"),
        }
    except Exception as e:  # noqa: BLE001
        out["bg_observer"] = {
            "enabled": bool(_config.BG_OBSERVER_ENABLED),
            "error": str(e),
        }

    # silent_failures — Phase 2 audit follow-up. Every NP1-violating
    # silent except now calls record_failure(<category>, exc) so the
    # operator can distinguish "everything is fine" from "the engine
    # has been silently dropping signals all afternoon". Categories
    # surfaced here:
    #   - focused_scoring         (SF4: scoring outer except)
    #   - llm_intel_signals       (SF2: drop of confirmed LLM intel)
    #   - bg_observer_drain       (SF3: bg_observer queue drain)
    #   - auto_judge_override_trail (SF6: AP4 ledger DB write)
    # Plus the existing builder-level categories already populated by
    # _maybe_persist_* in scoring.py (threat_level, per_domain, trend,
    # attack_mode, ...). The HUD FAULT chip reads `total_recent_failures`.
    try:
        from radar.conclusions.shadow_metrics import snapshot as _sm_snapshot
        snap = _sm_snapshot()
        # Aggregate failure_count over a 1-hour window so the chip
        # reflects current degradation, not lifetime totals. Lacking
        # per-bucket time series, we surface lifetime failure_count and
        # last_failure_at so the HUD can compute "recent" client-side.
        np1_categories = {
            "focused_scoring",
            "llm_intel_signals",
            "bg_observer_drain",
            "auto_judge_override_trail",
        }
        np1_failure_count = sum(
            int(by.get("failure_count", 0))
            for ct, by in snap.get("by_type", {}).items()
            if ct in np1_categories
        )
        out["silent_failures"] = {
            "uptime_sec": snap.get("uptime_sec"),
            "by_category": snap.get("by_type", {}),
            "np1_categories": sorted(np1_categories),
            "np1_failure_count_lifetime": np1_failure_count,
        }
    except Exception as e:  # noqa: BLE001
        out["silent_failures"] = {"error": str(e)}

    # attention metrics collection errors (SF5).
    try:
        from radar.attention import _collect_metrics as _att_metrics  # noqa: SLF001
        m = _att_metrics()
        out["attention_collection_errors"] = int(m.get("_collection_errors", 0))
    except Exception as e:  # noqa: BLE001
        out["attention_collection_errors"] = None
        out["attention_error"] = str(e)

    # Phase 8 (LLM survey v10) — per-model + per-use_case operational
    # metrics. Conclusion-level recall is overall-only because a single
    # conclusion can be informed by multiple LLM calls; the per-model
    # rollup surfaces operational quality (ok rate, latency, confidence,
    # auto_confirmed share) which is the meaningful AP3 signal once the
    # 5-model stack is rolled out. Falls back to empty dicts on any
    # failure so the chip can render "—" without breaking the response.
    try:
        from radar.database import db as _shared_db
        routing = _shared_db.llm_routing_stats(hours=24)
        out["by_model"] = routing.get("by_model", {})
        out["by_use_case"] = routing.get("by_use_case", {})
        out["shadow_diff"] = routing.get("shadow_diff", {})
        # Phase 9.2 C6 — SHADOW_DUAL A/B between legacy and v10 candidate.
        # Only populated when at least one routing feature is in
        # SHADOW_DUAL state and the joined table has paired rows.
        out["shadow_dual_diff"] = routing.get("shadow_dual_diff", {})
    except Exception as e:  # noqa: BLE001
        out["by_model"] = {}
        out["by_use_case"] = {}
        out["shadow_diff"] = {}
        out["shadow_dual_diff"] = {}
        out["routing_error"] = str(e)

    # Phase 9.2 C9 — embedding pipeline rollup.
    try:
        from radar.database import db as _shared_db
        out["embedding_dedupe"] = _shared_db.llm_embedding_stats(hours=24)
    except Exception as e:  # noqa: BLE001
        out["embedding_dedupe"] = {}
        out["embedding_error"] = str(e)

    # Phase 9.2 C6 — derived Phase 1 GO judgment. Single scalar boolean
    # plus per-axis breakdown so the LLM Console "Self-Eval" tab can
    # render a green/red GO chip without analyst SQL.
    out["phase8_go_status"] = _compute_phase8_go(out.get("shadow_dual_diff", {}))

    # Phase 9 (2026-05-13) — TL distribution skew metric.
    # The existing `drift` metric measures per-scenario score-magnitude
    # drift; it cannot detect "TL=5 share dropped to 0%" — the failure
    # mode that left the 2026-04-28 RAISE_THRESHOLDS advisory unactioned
    # for 15+ days. This block surfaces TL=5 (peacetime calm) share over a
    # configurable rolling window so the AP3 CALIBRATION chip can warn
    # before the next governance deadline slips silently.
    try:
        if _config.CALIBRATION_SKEW_METRIC_ENABLED:
            from radar.database import db as _shared_db
            _window_hours = _config.CALIBRATION_SKEW_WINDOW_DAYS * 24
            _stats = _shared_db.tl_calibration_stats(hours=_window_hours)
            _n_total = int(_stats.get("total_observations", 0))
            _dist = _stats.get("distribution", {}) or {}
            _tl5_pct = float(_dist.get("TL5", {}).get("pct", 0.0))
            _has_enough = _n_total >= _config.CALIBRATION_SKEW_MIN_OBSERVATIONS
            _alert = bool(
                _has_enough and _tl5_pct < _config.CALIBRATION_SKEW_TL5_MIN_PCT
            )
            out["tl_distribution_skew"] = {
                "tl5_pct":            round(_tl5_pct, 1),
                "tl5_min_pct":        _config.CALIBRATION_SKEW_TL5_MIN_PCT,
                "window_days":        _config.CALIBRATION_SKEW_WINDOW_DAYS,
                "n_observations":     _n_total,
                "min_observations":   _config.CALIBRATION_SKEW_MIN_OBSERVATIONS,
                "have_enough_data":   _has_enough,
                "calibration_skew_alert": _alert,
                "distribution_pct":   {
                    k: float(v.get("pct", 0.0)) for k, v in _dist.items()
                },
                "method":             "tl5_share_vs_floor",
            }
        else:
            out["tl_distribution_skew"] = {
                "enabled": False,
                "calibration_skew_alert": False,
            }
    except Exception as e:  # noqa: BLE001
        out["tl_distribution_skew"] = {
            "calibration_skew_alert": False,
            "error": str(e),
        }

    return jsonify(out)


# ── Phase 1 GO judgment ────────────────────────────────────────────────────


_PHASE1_GO_THRESHOLDS = {
    "schema_compliance": 0.99,        # primary or shadow must hit
    "agreement_rate":    0.60,        # ≥ 60% agreement required
    "verdict_reproducibility": 1.00,  # = 1.00 required (deterministic)
}


def _compute_phase8_go(shadow_dual_diff: dict) -> dict:
    """Reduce shadow_dual_diff into a per-use_case GO/NO-GO breakdown
    plus an overall_go scalar so the UI chip renders without parsing
    nested objects."""
    out: dict = {}
    overall = True
    have_data = False
    for uc, diff in (shadow_dual_diff or {}).items():
        if not isinstance(diff, dict):
            continue
        have_data = True
        sc = diff.get("schema_compliance") or {}
        agree = diff.get("agreement_rate")
        repro = diff.get("verdict_reproducibility")

        sc_ok = (
            isinstance(sc.get("shadow"), (int, float))
            and sc["shadow"] >= _PHASE1_GO_THRESHOLDS["schema_compliance"]
        )
        agree_ok = (
            isinstance(agree, (int, float))
            and agree >= _PHASE1_GO_THRESHOLDS["agreement_rate"]
        )
        repro_ok = (
            repro is None
            or repro >= _PHASE1_GO_THRESHOLDS["verdict_reproducibility"]
        )
        all_ok = sc_ok and agree_ok and repro_ok
        out[uc] = {
            "schema_compliance": {
                "value": sc.get("shadow"),
                "ok": sc_ok,
                "threshold": _PHASE1_GO_THRESHOLDS["schema_compliance"],
            },
            "agreement_rate": {
                "value": agree,
                "ok": agree_ok,
                "threshold": _PHASE1_GO_THRESHOLDS["agreement_rate"],
            },
            "verdict_reproducibility": {
                "value": repro,
                "ok": repro_ok,
                "threshold": _PHASE1_GO_THRESHOLDS["verdict_reproducibility"],
            },
            "n_paired": diff.get("n_paired"),
            "use_case_go": all_ok,
        }
        if not all_ok:
            overall = False
    return {
        "by_use_case": out,
        "overall_go": overall if have_data else None,
        "have_data": have_data,
    }


def _resolve_llm_prompt(db, sha256: str) -> dict:
    """Look up the full prompt text for an audit trace. Returns a dict with
    sha256, model, and the prompt body. If the row is missing (purged or
    flag was off when the call happened) returns sha256 + a missing flag.
    """
    from radar.llm_prompts import get_prompt
    row = get_prompt(db, sha256)
    if row is None:
        return {"sha256": sha256, "missing": True}
    return {
        "sha256": sha256,
        "model": row.get("model"),
        "temperature": row.get("temperature"),
        "prompt_text": row.get("prompt_text"),
        "first_seen_at": row.get("first_seen_at"),
        "last_seen_at": row.get("last_seen_at"),
        "use_count": row.get("use_count"),
    }
