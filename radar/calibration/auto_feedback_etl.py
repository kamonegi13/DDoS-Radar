"""Daily auto-feedback ETL — schedule-side wrapper.

Background
----------
The v2 conclusions ledger fills up at ~5 rows / scoring tick × ~5 scenarios
≈ 36k rows / day. None of those rows turn into calibration signal until
something writes a labelled `analyst_feedback` row pointing at the
conclusion. There are two automated label sources and one human source:

  * GDELT tone-spike correlation (always available, no API key)
  * ACLED fatality correlation     (optional, requires API key + email)
  * RSS narrative kinetic regex    (always available, no API key)
  * Human analyst                  (manual; not in scope here)

Until 2026-05-05 the auto sources existed only as standalone CLI scripts
(`scripts/run_ground_truth_etl.py`, `scripts/run_rss_etl.py`) that nobody
was running on a cron. As a result `analyst_feedback` was empty, and the
TL / LLM-confidence / sensor-disable calibrators (which already run
daily inside `radar.scheduler`) had nothing to learn from. This module
plumbs the auto sources into the existing scheduler tick so the loop
closes itself: ledger → auto_feedback → calibration proposals → analyst
approval (the only manual step).

NP3: every ETL pass is wrapped in try/except by the caller; failures
must never crash the scheduler. Per-pass cooldown is implicit in the
"once-per-day at a specific cycle offset" gate inside scheduler.py.

ACLED graceful degradation: if `ACLED_API_KEY` / `ACLED_API_EMAIL` are
unset (the OPSEC-friendly default), the ground-truth pass silently
falls back to GDELT-only correlation. Recall recovery is somewhat
lower without fatality counts but the pipeline still produces useful
auto-feedback rows.
"""
from __future__ import annotations

import logging
import os
import sys
import time
from typing import Optional

log = logging.getLogger("radar.calibration.auto_feedback_etl")


# Add scripts/ to sys.path so we can import the existing run_etl
# library functions without duplicating their bodies. The CLI wrappers
# (main()) inside the scripts stay intact for ad-hoc / dry-run use.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SCRIPTS_DIR = os.path.join(_REPO_ROOT, "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)


def run_ground_truth_pass(
    *,
    window_days: int = 14,
    limit: int = 1000,
) -> Optional[dict]:
    """One ground-truth correlation pass over the conclusions ledger.

    Returns the etl-counter dict (scanned / labelled / etc.) on success,
    or ``None`` when the gate flag is off or the underlying pipeline
    raised. The caller is expected to log the result; ``None`` is
    *not* an error in itself — `V2_GROUND_TRUTH_ETL_ENABLED=false` is
    the documented opt-in default for some deployments.
    """
    from radar import config as _cfg
    if not _cfg.V2_GROUND_TRUTH_ETL_ENABLED:
        log.debug("V2_GROUND_TRUTH_ETL_ENABLED=false — skipping pass")
        return None

    try:
        from run_ground_truth_etl import run_etl as _gt_run_etl
    except Exception as exc:  # pragma: no cover — import-time failure
        log.warning("[auto_feedback_etl] cannot import ground-truth ETL: %s", exc)
        return None

    from radar.database import db as _db
    from radar.scenarios import scenario_store
    if not scenario_store.loaded:
        try:
            from radar.config import _raw_geo
            scenario_store.load(_raw_geo)
        except Exception as exc:
            log.warning("[auto_feedback_etl] scenario_store load failed: %s", exc)
            return None

    # OPSEC graceful degrade — only enable ACLED if both creds are set.
    enable_acled = bool(getattr(_cfg, "ACLED_API_KEY", "")) \
                   and bool(getattr(_cfg, "ACLED_API_EMAIL", ""))

    now = time.time()
    return _gt_run_etl(
        _db,
        since=now - window_days * 86400,
        until=now,
        scenario_filter=None,
        limit=limit,
        dry_run=False,
        enable_gdelt=True,
        enable_acled=enable_acled,
        enable_llm_intel=True,
        enable_sequence=True,
    )


def run_rss_narrative_pass(
    *,
    window_days: int = 14,
    limit: int = 1000,
    use_llm: bool = False,
) -> Optional[dict]:
    """One RSS narrative ETL pass.

    Returns the etl-counter dict on success or ``None`` on a guard exit.
    Re-uses the exact pipeline that `scripts/run_rss_etl.py main()`
    drives so behaviour stays consistent between the cron-style CLI and
    the scheduler-driven path.
    """
    from radar import config as _cfg
    if not _cfg.V2_GROUND_TRUTH_ETL_ENABLED:
        # The RSS ETL shares the same gate flag as the ground-truth ETL —
        # both are "auto-feedback writers" and should default-on/off
        # together so the analyst sees a single dial.
        log.debug("V2_GROUND_TRUTH_ETL_ENABLED=false — skipping RSS pass")
        return None

    try:
        from run_rss_etl import run_etl as _rss_run_etl
    except Exception as exc:  # pragma: no cover
        log.warning("[auto_feedback_etl] cannot import RSS ETL: %s", exc)
        return None

    from radar.database import db as _db
    from radar.scenarios import scenario_store
    if not scenario_store.loaded:
        try:
            from radar.config import _raw_geo
            scenario_store.load(_raw_geo)
        except Exception as exc:
            log.warning("[auto_feedback_etl] scenario_store load failed: %s", exc)
            return None

    # Default feed list — bg_observer's 9-feed mix is already curated
    # and verified live; reuse it unless the operator overrode it.
    feeds_csv = os.environ.get("BG_OBSERVER_FEEDS", "").strip()
    if not feeds_csv:
        # Fall back to the in-code default the bg_observer uses.
        from radar import background_observer as _bg
        feeds = list(getattr(_bg, "_DEFAULT_FEEDS", ()))
    else:
        feeds = [u.strip() for u in feeds_csv.split(",") if u.strip()]
    if not feeds:
        log.info("[auto_feedback_etl] no RSS feeds configured — skipping pass")
        return None

    now = time.time()
    return _rss_run_etl(
        _db,
        feeds=feeds,
        since=now - window_days * 86400,
        until=now,
        scenario_filter=None,
        limit=limit,
        dry_run=False,
        use_llm=use_llm,
    )
