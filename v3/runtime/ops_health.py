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

    tick_loop  answerable now, from the runtime's own counters. Added
               after the shadow container reported HEALTHY for its whole
               run while every tick failed and `tl_observation` stayed empty —
               G-17 reproduced at the container layer. It lives HERE, and
               not in the healthcheck, because this module is already the
               operational axis: one measurement then reaches `/healthz`,
               `GET /api/v3/self_eval` (AP3) and the start-up disclosure,
               instead of a second mechanism that will disagree with this
               one the first time either is edited.
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
from typing import Any, Mapping, Optional

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

#: How long a deployment may go without a SUCCESSFUL tick before the loop
#: is reported as late, and then as stopped-in-place. Multiples of the
#: configured cadence rather than absolute times: an hourly deployment is
#: not late at minute five, and a one-second cadence must not turn every
#: blip into an alarm — hence the floors.
LOOP_OVERDUE_INTERVALS = 3.0
LOOP_STALLED_INTERVALS = 10.0
#: The overdue floor is the tick's DESIGNED worst case, stage by stage —
#: not a round number. It was 300s, which was the FETCH stage's budget
#: alone (policy.FETCH_BUDGET_REQUESTS 120 × the measured ~2.5s/request
#: the budget was derived from), and it was honest until 2026-08-13,
#: when the tick gained an LLM stage. After that, a tick doing exactly
#: its designed work — a full fetch stage plus a full article budget —
#: was reported late every time, and the shadow's healthz sat at 503
#: for most of every healthy cycle (measured: 57×503 / 4×200 in 30 min
#: at a ~525s cadence). A late-alarm that fires on the designed
#: workload is the crying-wolf failure the first-tick grace already
#: names.
#:
#:   fetch stage      300s  policy.FETCH_BUDGET_REQUESTS × ~2.5s
#:   LLM stage        155s  availability probe worst case (5s connect
#:                          + 30s read) + LLM_ARTICLES_PER_TICK (4)
#:                          × LLM_TIMEOUT default (30s), one attempt
#:   score + write     60s  margin; measured well under this
#:   ─────────────────────
#:                    515s
#:
#: `tests/test_runtime_ops_health.py` recomputes this sum from the
#: source constants, so a future budget change that forgets this floor
#: fails a test instead of resurrecting the flapping (D2 F-13: a pin
#: that imports only itself checks nothing).
LOOP_MIN_OVERDUE_SEC = 515.0
LOOP_MIN_STALLED_SEC = 1800.0

#: The FIRST tick gets its own, much larger budget, and the number is
#: measured rather than chosen. A cold ledger has an empty
#: `fetch_schedule`, so every adapter is due at once and the sweep runs
#: every URL with the retry ladder and the rate limiters in it: the
#: observed cold sweep in the shadow container was still fetching after
#: fifteen minutes. Judging that by the steady-state budget would call a
#: container `degraded` for doing exactly what it is supposed to be doing
#: on its first minute of life — crying wolf, which is how a real alarm
#: comes to be ignored.
#:
#: This grace applies ONLY while `errors == 0`. A tick that has RAISED is
#: not a slow tick, and it is an ANOMALY on the spot however young the
#: deployment is — which is what the defect this monitor exists for looked
#: like.
LOOP_FIRST_TICK_INTERVALS = 20.0
LOOP_MIN_FIRST_TICK_SEC = 1800.0

REASON_LOOP_PRODUCING = "loop_producing"
REASON_LOOP_STARTING = "loop_starting"
REASON_LOOP_NEVER_SUCCEEDED = "loop_never_succeeded"
REASON_LOOP_OVERDUE = "loop_overdue"
REASON_LOOP_STALLED = "loop_stalled"
REASON_LOOP_STOPPED = "loop_stopped"
REASON_LOOP_NOT_STARTED = "loop_not_started"
REASON_LOOP_UNSUPPLIED = "loop_status_unsupplied"

REASON_SWEEP_COMPLETE = "sweep_complete"
REASON_SWEEP_PARTIAL = "sweep_partial"
REASON_SWEEP_DARK = "sweep_partial_sources_never_observed"
REASON_SWEEP_UNSUPPLIED = "sweep_not_reported"

MONITOR_LOOP = "tick_loop"
MONITOR_SWEEP = "sweep"
MONITOR_BACKUP = "backup"
MONITOR_CAPACITY = "capacity"
MONITOR_L5 = "l5_checks"
MONITOR_LLM = "llm_health"

#: Declared in order. The order is also the tie-break when two monitors
#: share the worst verdict, so `worst_monitor` is reproducible (AP2).
#: `tick_loop` leads deliberately: when several monitors are equally bad,
#: the one an operator has to act on first is the one saying the tool has
#: concluded nothing.
MONITOR_IDS: tuple[str, ...] = (MONITOR_LOOP, MONITOR_SWEEP, MONITOR_BACKUP,
                                MONITOR_CAPACITY, MONITOR_L5, MONITOR_LLM)


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


def loop_budgets(interval_sec: float) -> tuple[float, float]:
    """`(overdue_after, stalled_after)` for one configured cadence."""
    cadence = max(float(interval_sec), 0.0)
    return (max(cadence * LOOP_OVERDUE_INTERVALS, LOOP_MIN_OVERDUE_SEC),
            max(cadence * LOOP_STALLED_INTERVALS, LOOP_MIN_STALLED_SEC))


def first_tick_grace(interval_sec: float) -> float:
    """How long a deployment may have produced NOTHING and still be new."""
    return max(float(interval_sec) * LOOP_FIRST_TICK_INTERVALS,
               LOOP_MIN_FIRST_TICK_SEC)


def _loop_verdict(status: Mapping, *, now: float, overdue: float,
                  stalled: float, grace: float) -> tuple[str, str]:
    """Verdict and reason from the loop's counters. Pure, and ordered.

    The order is the argument. "Is the thread alive" is asked first
    because a dead thread makes every later question moot; "has it EVER
    succeeded" comes next because a tool that has never concluded
    anything is not a degraded tool, it is a silent one — and that is the
    state the container was in for its whole run. Only then does age
    matter.
    """
    if not bool(status.get("running")):
        return (ANOMALY, REASON_LOOP_NOT_STARTED
                if status.get("started_at") is None else REASON_LOOP_STOPPED)

    last_success = status.get("last_tick_at")
    if last_success is None:
        # Nothing has been produced yet, and the two ways to arrive here
        # are not the same fact. A tick that RAISED is proof the loop is
        # not going to produce, and says so at once. A tick still running
        # is the measured cold sweep, which takes far longer than a
        # steady-state interval — so it gets `first_tick_grace` and the
        # word `starting`, which is NP5+8's transient inability said out
        # loud rather than rounded to either neighbour.
        if int(status.get("errors") or 0) > 0:
            return (ANOMALY, REASON_LOOP_NEVER_SUCCEEDED)
        started_at = status.get("started_at")
        if started_at is not None and (float(now) - float(started_at)) \
                > grace:
            return (ANOMALY, REASON_LOOP_NEVER_SUCCEEDED)
        return (INSUFFICIENT, REASON_LOOP_STARTING)

    age = float(now) - float(last_success)
    if age > stalled:
        return (ANOMALY, REASON_LOOP_STALLED)
    if age > overdue:
        return (WARN, REASON_LOOP_OVERDUE)
    return (OK, REASON_LOOP_PRODUCING)


def loop_monitor(status: Optional[Mapping], *, now: float,
                 interval_sec: float) -> dict:
    """Is the loop PRODUCING? Not "is the process up".

    `status` is `v3.runtime.loop.LoopStatus.as_dict()`, handed over by the
    composition root — a mapping rather than the type, so this module
    stays importable without the loop and testable with a literal.

    `None` is UNSUPPLIED, never OK. A deployment that wired no loop probe
    has not told us the loop is fine; it has told us nothing, and the
    whole reason this monitor exists is that those two were the same
    answer.
    """
    overdue, stalled = loop_budgets(interval_sec)
    grace = first_tick_grace(interval_sec)
    fields = {"overdue_after_sec": overdue, "stalled_after_sec": stalled,
              "first_tick_grace_sec": grace,
              "interval_sec": float(interval_sec)}
    if not isinstance(status, Mapping):
        return _monitor(
            MONITOR_LOOP, UNSUPPLIED, REASON_LOOP_UNSUPPLIED,
            running=None, ticks=None, errors=None, last_error="",
            last_success_at=None, since_last_success_sec=None, **fields,
            note="この配備はティックループの状態を渡していません。OK には "
                 "しません — 「回っている」と「渡されていない」を同じ答えに "
                 "したのが、影コンテナが稼働中ずっと HEALTHY を出し続けた原因です")
    verdict, reason = _loop_verdict(status, now=now, overdue=overdue,
                                    stalled=stalled, grace=grace)
    last_success = status.get("last_tick_at")
    return _monitor(
        MONITOR_LOOP, verdict, reason,
        running=bool(status.get("running")),
        ticks=int(status.get("ticks") or 0),
        errors=int(status.get("errors") or 0),
        consecutive_errors=int(status.get("consecutive_errors") or 0),
        last_error=str(status.get("last_error") or ""),
        last_error_at=status.get("last_error_at"),
        started_at=status.get("started_at"),
        last_success_at=last_success,
        since_last_success_sec=(None if last_success is None
                                else float(now) - float(last_success)),
        **fields)


def sweep_monitor(sweep: Optional[Mapping]) -> dict:
    """Did the last tick reach every source it meant to? G-19's surface.

    `sweep` is `v3.runtime.health.sweep_coverage`'s mapping, carried from
    the last completed tick by the composition root — the same route the
    loop status takes, and for the same reason: only the layer that ran the
    tick saw what the tick planned.

    Three verdicts, and the middle one is the whole point:

      OK            every due source was fetched.
      INSUFFICIENT  the budget deferred some, but every deferred source
                    still has a reading in force, so the tick scored from
                    all of them anyway. A staged sweep, not a blind one.
      ANOMALY       a deferred source has NEVER been observed, so the tool
                    concluded without it having ever said anything. That is
                    the cold-start state, it is transient by design, and it
                    is reported as loudly as a fault because a conclusion
                    drawn from 40% of the catalogue must not read like a
                    quiet world (G-17).

    UNSUPPLIED when no tick has reported yet — never OK. "No tick has told
    us" and "the last tick was complete" are the two answers this whole
    module exists to keep apart.
    """
    if not isinstance(sweep, Mapping) or not sweep:
        return _monitor(
            MONITOR_SWEEP, UNSUPPLIED, REASON_SWEEP_UNSUPPLIED,
            due=None, fetched=None, coverage=None, deferred=[],
            deferred_never_observed=[],
            note="まだ 1 ティックも掃引結果を報告していません。OK には "
                 "しません — 「全部取れた」と「まだ誰も報告していない」を "
                 "同じ答えにするのが G-17 の形です")
    deferred = list(sweep.get("deferred") or ())
    dark = list(sweep.get("deferred_never_observed") or ())
    fields = {"due": sweep.get("due"), "fetched": sweep.get("fetched"),
              "coverage": sweep.get("coverage"), "deferred": deferred,
              "deferred_never_observed": dark}
    if dark:
        return _monitor(
            MONITOR_SWEEP, ANOMALY, REASON_SWEEP_DARK, **fields,
            note="予算により延期された取得元のうち、L1 に観測が 1 行も無い "
                 "ものがあります。結論はそのセンサーの発言を一度も含まずに "
                 "出ています（冷起動では一時的で、掃引が進めば解消します）")
    if deferred:
        return _monitor(
            MONITOR_SWEEP, INSUFFICIENT, REASON_SWEEP_PARTIAL, **fields,
            note="今ティックは予算により一部の取得元を次ティックへ回しました。"
                 "延期分はいずれも直近の観測が有効期間内にあるため、"
                 "採点には反映されています")
    return _monitor(MONITOR_SWEEP, OK, REASON_SWEEP_COMPLETE, **fields)


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
          marker: Optional[Any] = None,
          loop_status: Optional[Mapping] = None,
          sweep: Optional[Mapping] = None,
          interval_sec: float = 60.0) -> dict:
    """The composition root's one call. Handed to the API as a mapping."""
    at = time.time() if now is None else float(now)
    path = marker_path(ledger_path) if marker is None else Path(marker)
    monitors = [loop_monitor(loop_status, now=at, interval_sec=interval_sec),
                sweep_monitor(sweep),
                backup_monitor(path, now=at),
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
        loop_monitor(None, now=now, interval_sec=0.0),
        sweep_monitor(None),
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


def supplied_or_absent(supplied, *, now: float) -> dict:
    """The fold the composition root ran, or the fully-declared absence.

    ONE resolution of "did anyone probe", shared by R7 and R15h, because
    two copies of this three-line decision are two chances for the health
    probe and the self-evaluation to answer differently about the same
    deployment.
    """
    if isinstance(supplied, Mapping) and supplied.get("monitors"):
        return dict(supplied)
    return probe_absent(now=now)


def monitor_named(folded: Mapping, monitor_id: str) -> dict:
    """One monitor out of a fold, or a declared absence in its place.

    Never `None`: a caller that had to handle a missing monitor would have
    to invent a verdict for it, and the invented one is always the
    convenient one.
    """
    for row in folded.get("monitors", ()) or ():
        if row.get("monitor") == monitor_id:
            return dict(row)
    return monitor(monitor_id, UNSUPPLIED, "monitor_absent_from_fold",
                   note=f"{monitor_id} がこの fold に含まれていません")


__all__ = ["OK", "WARN", "ANOMALY", "INSUFFICIENT", "UNSUPPLIED",
           "BAND_TRUSTED", "BAND_RESERVED", "BAND_DISTRUST", "VERDICT_BAND",
           "PROBE_ABSENT_REASON", "monitor", "monitor_named", "probe_absent",
           "supplied_or_absent",
           "VERDICT_RANK", "MONITOR_IDS", "MONITOR_LOOP", "MONITOR_SWEEP",
           "MONITOR_BACKUP", "MONITOR_CAPACITY", "sweep_monitor",
           "REASON_SWEEP_COMPLETE", "REASON_SWEEP_PARTIAL",
           "REASON_SWEEP_DARK", "REASON_SWEEP_UNSUPPLIED",
           "MONITOR_L5", "MONITOR_LLM", "UNSUPPLIED_MONITORS",
           "BACKUP_WARN_AGE_HOURS", "BACKUP_ANOMALY_AGE_HOURS",
           "BACKUP_MARKER_NAME", "RETENTION_TARGET_DAYS", "backup_monitor",
           "capacity_monitor", "fold", "marker_path", "probe", "read_marker",
           "loop_monitor", "loop_budgets", "first_tick_grace",
           "LOOP_FIRST_TICK_INTERVALS", "LOOP_MIN_FIRST_TICK_SEC",
           "LOOP_OVERDUE_INTERVALS", "LOOP_STALLED_INTERVALS",
           "LOOP_MIN_OVERDUE_SEC", "LOOP_MIN_STALLED_SEC",
           "REASON_LOOP_PRODUCING", "REASON_LOOP_STARTING",
           "REASON_LOOP_NEVER_SUCCEEDED", "REASON_LOOP_OVERDUE",
           "REASON_LOOP_STALLED", "REASON_LOOP_STOPPED",
           "REASON_LOOP_NOT_STARTED", "REASON_LOOP_UNSUPPLIED"]
