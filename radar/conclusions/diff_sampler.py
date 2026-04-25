"""v1/v2 conclusion diff sampler — rollout-monitoring helper for ADR-V2-001.

Phase 1 priority 6: every focused scoring cycle samples the v1 in-memory TL
against the latest v2 ledger row for the same (scenario, conclusion_type)
and appends a conclusion_diff_log entry. Analysts review the diff_kind
distribution before flipping the v2 default-on switch.

Diff kinds:
  match              — v1 == v2 (the happy path, expected to dominate)
  v2_missing         — v2 ledger has no row yet (warm-up / flag-off)
  v1_missing         — v1 produced no TL (insufficient signal); v2 may have
                       last-known. Recorded so we can see whether v2's
                       "stale-OK" semantics surprise analysts.
  divergence         — both present, states differ. The interesting case.

Invariants (mirroring shadow_sampler):
  I-1  Sampler never mutates v1 scoring state or v2 ledger rows.
  I-2  All failures are swallowed — diff sampling cannot break /api/threat_data.
  I-3  Sampling is gated by V2_CONCLUSION_DIFF_SAMPLER_ENABLED AND
       V2_CONCLUSION_LEDGER_ENABLED. Without ledger writes, every cycle
       would record v2_missing, which is noise.
  I-4  Append-only. We never UPDATE / DELETE rows here.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Optional

from radar import config
from radar.conclusions.base import ConclusionType
from radar.conclusions.persistence import latest_conclusion

if TYPE_CHECKING:
    from radar.database import RadarDB
    from radar.scoring import ScenarioState


log = logging.getLogger("radar")


_INSERT_SQL = """
INSERT INTO conclusion_diff_log (
    sampled_at, scenario_id, conclusion_type,
    v1_state, v2_state, v2_conclusion_id,
    is_match, diff_kind, metadata
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def sample_focused_tl_diff(db: "RadarDB", state: "ScenarioState") -> Optional[dict]:
    """Sample one (v1, v2) TL diff row for the focused scenario.

    Called from /api/threat_data after focused scoring + the v2 shadow-write
    have both completed. Returns the recorded row dict on write, None when
    the sampler is disabled or skipped.
    """
    if not config.V2_CONCLUSION_DIFF_SAMPLER_ENABLED:
        return None
    if not config.V2_CONCLUSION_LEDGER_ENABLED:
        return None
    try:
        return _sample_inner(db, state)
    except Exception:
        log.exception("[ConclusionDiffSampler] non-fatal failure")
        return None


def _sample_inner(db: "RadarDB", state: "ScenarioState") -> Optional[dict]:
    v1_state = str(state.tl) if state.tl is not None else None
    v2_row = latest_conclusion(db, state.scenario_id, ConclusionType.THREAT_LEVEL)
    v2_state = v2_row.state if v2_row is not None else None
    v2_id = v2_row.id if v2_row is not None else None

    diff_kind = _classify(v1_state, v2_state, v2_row is not None)
    is_match = 1 if diff_kind == "match" else 0

    metadata = {
        "score": round(state.score, 3),
        "scoring_mode": state.scoring_mode,
        "is_focused": state.is_focused,
    }
    if v2_row is not None and v2_row.confidence:
        metadata["v2_confidence"] = v2_row.confidence

    sampled_at = time.time()
    conn = db._get_conn()  # noqa: SLF001 — established internal pattern
    with conn.writing():
        conn.execute(
            _INSERT_SQL,
            (
                sampled_at, state.scenario_id, ConclusionType.THREAT_LEVEL.value,
                v1_state, v2_state, v2_id,
                is_match, diff_kind, json.dumps(metadata, sort_keys=True),
            ),
        )
    return {
        "sampled_at": sampled_at,
        "scenario_id": state.scenario_id,
        "v1_state": v1_state,
        "v2_state": v2_state,
        "diff_kind": diff_kind,
        "is_match": bool(is_match),
    }


def _classify(v1: Optional[str], v2: Optional[str], v2_present: bool) -> str:
    if not v2_present:
        return "v2_missing"
    if v1 is None and v2 is not None:
        return "v1_missing"
    if v1 is not None and v2 is None:
        # v2 row exists but state is null (unavailable_reason set) while
        # v1 produced a TL — record as divergence so analysts can see it.
        return "divergence"
    if v1 == v2:
        return "match"
    return "divergence"
