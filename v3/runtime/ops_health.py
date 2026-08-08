"""The operational axis of AP3: is the deployment being looked after?

WP-0.3 built this for the v1 process (`radar/verification/ops_health.py`)
after a month in which the backup cron failed silently — `docker` was not
on cron's PATH, every run errored into a log nobody read, and the state
that made it invisible was not "no backup" but "nobody could say". So the
rule this module inherits verbatim is: **an unknown age is INSUFFICIENT,
never OK.**

Why it lives under `v3/runtime/` rather than in a handler: the facts are
about the deployment, not about the ledger's contents. A file's size and
a marker file's mtime are things the composition root knows because it
chose the paths, and a read handler that stat()ed a path would be a
projection whose answer depends on something no `ReadOnlyLedger` can
show. The probe runs where the paths are known and its result is handed
to the API the same way `adapters` and `app_config` already are.

What v3 can and cannot answer today is stated in the monitors themselves
rather than by omission:

    backup     answerable IF a marker exists for the v3 ledger. v3 has no
               backup job of its own yet, so on most deployments this is
               INSUFFICIENT with the reason named — which is the correct
               answer, and it is the one the month of silence needed.
    capacity   answerable now, from the ledger file and the retention
               span. No daily sample series exists yet, so the estimate is
               a ratio against the retention target rather than v1's
               linear extrapolation, and it says which one it is.
    l5_checks  NOT answerable. v3 has no L5 verification layer at all —
               no firing-liveness, config-reachability, window-unit or
               gate-lineage checks and no heartbeat table.
    llm_health NOT answerable. v3 records LLM calls (`llm_call`) but has
               no health roll-up over them.

Folding four of those into "fine" because two of them are green is the
shape of G-17. So the block reports each one, and the fold is the worst.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Optional

OK = "OK"
WARN = "WARN"
ANOMALY = "ANOMALY"
INSUFFICIENT = "INSUFFICIENT"
UNSUPPLIED = "UNSUPPLIED"

#: Worst-wins order. `UNSUPPLIED` and `INSUFFICIENT` rank with WARN rather
#: than with OK, which is the whole ruling: "we cannot tell" is not "fine".
VERDICT_RANK: dict = {OK: 0, INSUFFICIENT: 1, UNSUPPLIED: 1, WARN: 1,
                      ANOMALY: 2}

HOUR_SEC = 3600.0
DAY_SEC = 86400.0

#: `radar/verification/ops_health.py:74-78`, transcribed.
BACKUP_CADENCE_HOURS = 24.0
BACKUP_SLACK_HOURS = 2.0
BACKUP_WARN_AGE_HOURS = BACKUP_CADENCE_HOURS + BACKUP_SLACK_HOURS      # 26
BACKUP_ANOMALY_AGE_HOURS = 2 * BACKUP_CADENCE_HOURS + BACKUP_SLACK_HOURS  # 50
BACKUP_MARKER_NAME = "backup_state.json"

REASON_BACKUP_FRESH = "backup_fresh"
REASON_BACKUP_OVERDUE = "backup_overdue"
REASON_BACKUP_SILENT = "backup_silent"
REASON_BACKUP_ABSENT = "backup_marker_absent"
REASON_BACKUP_CORRUPT = "backup_marker_corrupt"
REASON_BACKUP_SKEW = "backup_marker_clock_skew"

#: ADR-V3-005's retention target, and S3's steady-state estimate band.
RETENTION_TARGET_DAYS = 60.0
CAPACITY_BAND_MIN_GB = 3.0
CAPACITY_BAND_MAX_GB = 16.0
GIGABYTE = float(1024 ** 3)

REASON_CAPACITY_OK = "capacity_within_band"
REASON_CAPACITY_DIVERGENT = "capacity_estimate_divergent"
REASON_CAPACITY_EARLY = "capacity_span_short"
REASON_CAPACITY_UNREADABLE = "capacity_unreadable"

MONITOR_BACKUP = "backup"
MONITOR_CAPACITY = "capacity"
MONITOR_L5 = "l5_checks"
MONITOR_LLM = "llm_health"

#: Declared in order. The order is also the tie-break when two monitors
#: share the worst verdict, so `worst_monitor` is reproducible (AP2).
MONITOR_IDS: tuple[str, ...] = (MONITOR_BACKUP, MONITOR_CAPACITY,
                                MONITOR_L5, MONITOR_LLM)


#: Verdict → the UI's three-band vocabulary (P8 §4). "We cannot tell"
#: lands on `reserved`, never on `trusted`.
BAND_TRUSTED = "trusted"
BAND_RESERVED = "reserved"
BAND_DISTRUST = "distrust"
VERDICT_BAND: dict = {OK: BAND_TRUSTED, WARN: BAND_RESERVED,
                      INSUFFICIENT: BAND_RESERVED, UNSUPPLIED: BAND_RESERVED,
                      ANOMALY: BAND_DISTRUST}


def monitor(monitor_id: str, verdict: str, reason: str, **fields) -> dict:
    return {"monitor": monitor_id, "verdict": verdict, "reason": reason,
            **fields}


_monitor = monitor


def marker_path(ledger_path: str) -> Path:
    """Beside the ledger, so a backup job and this check agree by
    construction rather than by two configured paths."""
    return Path(str(ledger_path)).expanduser().parent / BACKUP_MARKER_NAME


def read_marker(path) -> tuple:
    """`(completed_at, reason)`. Never raises — a probe that raised would
    take the whole self-evaluation down (S1-CONC-038)."""
    target = Path(path)
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError:
        return (None, REASON_BACKUP_ABSENT)
    try:
        payload = json.loads(raw)
        completed = float(payload["completed_at"])
    except (ValueError, TypeError, KeyError):
        return (None, REASON_BACKUP_CORRUPT)
    return (completed, None)


def backup_monitor(path, *, now: float) -> dict:
    completed, reason = read_marker(path)
    if completed is None:
        return _monitor(
            MONITOR_BACKUP, INSUFFICIENT, reason, age_hours=None,
            warn_age_hours=BACKUP_WARN_AGE_HOURS,
            anomaly_age_hours=BACKUP_ANOMALY_AGE_HOURS,
            note="バックアップ経過時間が判定できません。OK にはしません — "
                 "2026-07-04〜08-03 の 1 か月の沈黙はまさにこの状態でした")
    age_hours = (float(now) - completed) / HOUR_SEC
    if age_hours < 0:
        return _monitor(MONITOR_BACKUP, INSUFFICIENT, REASON_BACKUP_SKEW,
                        age_hours=age_hours,
                        warn_age_hours=BACKUP_WARN_AGE_HOURS,
                        anomaly_age_hours=BACKUP_ANOMALY_AGE_HOURS)
    if age_hours >= BACKUP_ANOMALY_AGE_HOURS:
        verdict, reason = ANOMALY, REASON_BACKUP_SILENT
    elif age_hours >= BACKUP_WARN_AGE_HOURS:
        verdict, reason = WARN, REASON_BACKUP_OVERDUE
    else:
        verdict, reason = OK, REASON_BACKUP_FRESH
    return _monitor(MONITOR_BACKUP, verdict, reason, age_hours=age_hours,
                    warn_age_hours=BACKUP_WARN_AGE_HOURS,
                    anomaly_age_hours=BACKUP_ANOMALY_AGE_HOURS)


def _file_bytes(path) -> Optional[int]:
    total = 0
    found = False
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{path}{suffix}")
        try:
            total += candidate.stat().st_size
            found = found or suffix == ""
        except OSError:
            continue
    return total if found else None


def capacity_monitor(ledger_path, *, span_sec: Optional[float]) -> dict:
    """Project the ledger's size forward to the retention horizon.

    A ratio rather than v1's linear regression over daily samples, and it
    says so: v3 keeps no capacity sample series, so a regression here
    would be a trend line drawn through one point. `early_estimate` is
    true until the observed span reaches a fifth of the target, because a
    projection from three days of data is a direction, not a number.
    """
    total = _file_bytes(ledger_path)
    if total is None:
        return _monitor(MONITOR_CAPACITY, INSUFFICIENT,
                        REASON_CAPACITY_UNREADABLE, db_bytes=None,
                        note="台帳ファイルが読めません。0 バイトとは記録"
                             "しません（幻の 0 サンプルを混ぜないため）")
    observed_days = None if span_sec is None else float(span_sec) / DAY_SEC
    if not observed_days or observed_days <= 0:
        return _monitor(MONITOR_CAPACITY, INSUFFICIENT, REASON_CAPACITY_EARLY,
                        db_bytes=total, observed_days=observed_days,
                        estimated_steady_state_gb=None,
                        band_min_gb=CAPACITY_BAND_MIN_GB,
                        band_max_gb=CAPACITY_BAND_MAX_GB)
    projected = (total / GIGABYTE) * (RETENTION_TARGET_DAYS / observed_days)
    early = observed_days < RETENTION_TARGET_DAYS / 5.0
    within = CAPACITY_BAND_MIN_GB <= projected <= CAPACITY_BAND_MAX_GB
    verdict = OK if within else WARN
    reason = REASON_CAPACITY_OK if within else REASON_CAPACITY_DIVERGENT
    if early:
        verdict, reason = INSUFFICIENT, REASON_CAPACITY_EARLY
    return _monitor(MONITOR_CAPACITY, verdict, reason, db_bytes=total,
                    observed_days=observed_days,
                    estimated_steady_state_gb=projected,
                    early_estimate=early,
                    retention_target_days=RETENTION_TARGET_DAYS,
                    band_min_gb=CAPACITY_BAND_MIN_GB,
                    band_max_gb=CAPACITY_BAND_MAX_GB)


#: The two monitors v3 structurally cannot answer, and why. Declared here
#: rather than omitted, because an omitted monitor and a healthy one look
#: identical in a fold — which is G-17 exactly.
UNSUPPLIED_MONITORS: tuple[dict, ...] = (
    _monitor(MONITOR_L5, UNSUPPLIED, "l5_layer_absent",
             note="v3 に L5 検証層がありません（発火生存・設定到達性・"
                  "窓単位・ゲート系譜の 4 検査と heartbeat が未着地）。"
                  "着地 WP: L5 スライス"),
    _monitor(MONITOR_LLM, UNSUPPLIED, "llm_rollup_absent",
             note="v3 は llm_call を記録しますが健全性ロールアップを"
                  "持ちません。着地 WP: L5 スライス"),
)


def probe(ledger_path, *, span_sec: Optional[float] = None,
          now: Optional[float] = None,
          marker: Optional[Any] = None) -> dict:
    """The composition root's one call. Handed to the API as a mapping."""
    at = time.time() if now is None else float(now)
    path = marker_path(ledger_path) if marker is None else Path(marker)
    monitors = [backup_monitor(path, now=at),
                capacity_monitor(ledger_path, span_sec=span_sec)]
    monitors.extend(dict(item) for item in UNSUPPLIED_MONITORS)
    return fold(monitors, now=at)


def fold(monitors, *, now: float) -> dict:
    """Worst-wins, with the declaration order as the tie-break."""
    ordered = sorted(
        monitors,
        key=lambda item: (-VERDICT_RANK.get(item["verdict"], 1),
                          MONITOR_IDS.index(item["monitor"])
                          if item["monitor"] in MONITOR_IDS else 99))
    worst = ordered[0] if ordered else None
    failing = [item for item in monitors if item["verdict"] != OK]
    return {
        "monitors": list(monitors),
        "monitor_count": len(monitors),
        "failing_count": len(failing),
        "worst_verdict": None if worst is None else worst["verdict"],
        "worst_monitor": None if worst is None else worst["monitor"],
        "worst_reason": None if worst is None else worst["reason"],
        "worst_band": (BAND_RESERVED if worst is None
                       else VERDICT_BAND.get(worst["verdict"],
                                             BAND_RESERVED)),
        # The boundary the chip displays: how many monitors may be
        # non-OK before the composite stops being trusted. Zero, and it
        # is served rather than written into the page (§7-2 #96).
        "threshold": 0,
        "probed_at": float(now),
    }


#: What R7 serves when the composition root ran no probe. Every monitor
#: is present and every one says why it is absent, so the chip reports a
#: MEASURED reserved with a named cause rather than "the server has no
#: such field" — the distinction §7-2 #94 was registered for.
PROBE_ABSENT_REASON = "probe_not_composed"


def probe_absent(*, now: float) -> dict:
    monitors = [
        monitor(MONITOR_BACKUP, UNSUPPLIED, PROBE_ABSENT_REASON,
                age_hours=None, warn_age_hours=BACKUP_WARN_AGE_HOURS,
                anomaly_age_hours=BACKUP_ANOMALY_AGE_HOURS,
                note="この配備は ops プローブなしで構成されています"
                     "（v3/runtime/ops_health.py::probe が呼ばれていない）"),
        monitor(MONITOR_CAPACITY, UNSUPPLIED, PROBE_ABSENT_REASON,
                db_bytes=None, estimated_steady_state_gb=None,
                band_min_gb=CAPACITY_BAND_MIN_GB,
                band_max_gb=CAPACITY_BAND_MAX_GB,
                note="同上。台帳ファイルの所在は合成ルートだけが知る"),
    ]
    monitors.extend(dict(item) for item in UNSUPPLIED_MONITORS)
    return fold(monitors, now=now)


__all__ = ["OK", "WARN", "ANOMALY", "INSUFFICIENT", "UNSUPPLIED",
           "BAND_TRUSTED", "BAND_RESERVED", "BAND_DISTRUST", "VERDICT_BAND",
           "PROBE_ABSENT_REASON", "monitor", "probe_absent",
           "VERDICT_RANK", "MONITOR_IDS", "MONITOR_BACKUP", "MONITOR_CAPACITY",
           "MONITOR_L5", "MONITOR_LLM", "UNSUPPLIED_MONITORS",
           "BACKUP_WARN_AGE_HOURS", "BACKUP_ANOMALY_AGE_HOURS",
           "BACKUP_MARKER_NAME", "RETENTION_TARGET_DAYS", "backup_monitor",
           "capacity_monitor", "fold", "marker_path", "probe", "read_marker"]
