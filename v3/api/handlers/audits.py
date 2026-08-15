"""WP-0.4 v2 (0.4e) — the sampled audit's surface.

The queue an auditor works from, and the two verdicts they leave. Small
on purpose: the audit measures the GENERATOR, so the work is checking a
sample of what the machine claimed, not re-deriving it.

The read serves the sample MINUS what has already been judged, and says
what the audit currently concludes — including that it has not yet
concluded anything, which is the state the tool starts in and the one a
reader is most likely to misread as "fine".
"""
from __future__ import annotations

from v3.api import errors as E
from v3.api.envelope import ApiResponse, command_response, tool_response
from v3.api.write import Change
from v3.calibration import audit as AUDIT
from v3.calibration.epoch import CURRENT_EPOCH, EpochStamp
from v3.calibration.thresholds import CALIBRATION_WINDOW_SEC
from v3.commands import calibration as C
from v3.commands import spec as SPEC


def _stamp(now: float) -> EpochStamp:
    since = max(float(CURRENT_EPOCH.started_at),
                float(now) - CALIBRATION_WINDOW_SEC)
    return EpochStamp(epoch_id=CURRENT_EPOCH.epoch_id, since=since,
                      until=float(now), exclude_auto=False)


def read_audits(context) -> ApiResponse:
    """R18 — the audit sample, what is left to judge, and the verdict."""
    stamp = _stamp(context.now)
    labels = context.ledger.labels_in_epoch(
        epoch_id=stamp.epoch_id, since=stamp.since, until=stamp.until)
    verdicts = AUDIT.audit_verdicts(context.ledger, until=context.now)
    state = AUDIT.evaluate(labels, verdicts)
    outstanding = []
    for row in AUDIT.sample_of(labels):
        label_id = str(row["label_id"])
        if label_id in verdicts:
            continue
        outstanding.append({
            "label_id": label_id,
            "scenario_id": row["scenario_id"],
            "conclusion_type": row["conclusion_type"],
            "conclusion_id": row["conclusion_id"],
            "label": row["label"],
            "analyst_id": row["analyst_id"],
            "rule_id": row["rule_id"],
            "reason": row.get("reason"),
            "observed_outcome_url": row.get("observed_outcome_url"),
            "observed_at": row["observed_at"],
        })
    return tool_response(
        observed_at=context.now, audit=state.as_dict(),
        outstanding=outstanding, outstanding_count=len(outstanding),
        epoch_id=stamp.epoch_id,
        note="自動生成ラベルの標本監査です。全件確認ではありません — "
             "監査が測るのは生成器であり、実測誤り率が上限を超えると"
             "自動系列は成長を停止します（既存ラベルは残ります: "
             "誤り率を測った証拠そのものであるため）。")


def _known_label(context, label_id: str) -> dict:
    if not isinstance(label_id, str) or not label_id.strip():
        raise E.bad_request("label_id が空です")
    rows = context.read.ledger.labels_in_epoch(
        epoch_id=CURRENT_EPOCH.epoch_id, since=CURRENT_EPOCH.started_at,
        until=context.now)
    for row in rows:
        if str(row["label_id"]) == label_id:
            return row
    raise E.not_found(f"ラベル {label_id}", label_id=label_id)


def _audit(context, *, label_id: str, action: str) -> ApiResponse:
    row = _known_label(context, label_id)
    if not row.get("is_automated"):
        raise E.bad_request(
            "監査対象は自動生成ラベルのみです（人手ラベルの再確認は "
            "系列の分離を崩します）", label_id=label_id)
    body = context.body
    committed = context.commit(Change(
        action=action,
        target=SPEC.Target(kind=C.TARGET_LABEL, id=label_id),
        payload={"reason": body.get("reason")},
        reason=body.get("reason")))
    return command_response(str(row["scenario_id"]), committed,
                            observed_at=context.now, label_id=label_id)


def audit_correct(context, *, label_id: str) -> ApiResponse:
    """C15c — the generator got this one right."""
    return _audit(context, label_id=label_id,
                  action=C.LABEL_AUDIT_CORRECT)


def audit_incorrect(context, *, label_id: str) -> ApiResponse:
    """C15i — it did not. Enough of these freeze the series."""
    return _audit(context, label_id=label_id,
                  action=C.LABEL_AUDIT_INCORRECT)


__all__ = ["read_audits", "audit_correct", "audit_incorrect"]
