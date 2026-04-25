"""v2 API envelope construction — keeps NP7 disclaimer enforcement and
api_version stamping in one place so every endpoint stays consistent.

Endpoints must NOT hand-roll response dicts; they call `build_envelope()`
or `build_unavailable()` so that:
  1. `final_judgment_disclaimer` is always present (NP7).
  2. `api_version` matches the documented contract.
  3. Conclusion → dict serialization uses the canonical `to_dict()`.
"""

from __future__ import annotations

import time
from typing import Iterable, Optional

from radar import config
from radar.conclusions.base import Conclusion, ConclusionType, ConclusionUnavailableReason


API_VERSION = "2.0"


def build_envelope(
    scenario_id: str,
    conclusions: Iterable[Conclusion],
    *,
    observed_at: Optional[float] = None,
) -> dict:
    """Wrap a list of Conclusions in the v2 API envelope. observed_at defaults
    to the latest conclusion's timestamp, or now() if the list is empty.
    """
    items = [c.to_dict() for c in conclusions]
    if observed_at is None:
        observed_at = (
            max((c.observed_at for c in conclusions), default=time.time())
        )
    return {
        "api_version": API_VERSION,
        "scenario_id": scenario_id,
        "observed_at": observed_at,
        "final_judgment_disclaimer": config.V2_NP7_DISCLAIMER,
        "conclusions": items,
    }


def build_unavailable(
    scenario_id: str,
    conclusion_type: ConclusionType,
    *,
    reason: ConclusionUnavailableReason = ConclusionUnavailableReason.INSUFFICIENT_DATA,
    detail: str = "",
) -> dict:
    """Envelope for a (scenario, type) pair the ledger has no row for yet.

    Returns a dict shaped like a Conclusion JSON but with state=null and an
    explicit `conclusion_unavailable_reason`. We do NOT instantiate a
    Conclusion here because there's no formula_ref / source_urls to record —
    this is "we have nothing to say yet", not "we tried and failed".
    """
    now = time.time()
    return {
        "api_version": API_VERSION,
        "scenario_id": scenario_id,
        "observed_at": now,
        "final_judgment_disclaimer": config.V2_NP7_DISCLAIMER,
        "conclusions": [
            {
                "id": None,
                "scenario_id": scenario_id,
                "conclusion_type": conclusion_type.value,
                "state": None,
                "confidence": 0.0,
                "observed_at": now,
                "formula_ref": None,
                "threshold_ref": {},
                "source_urls": [],
                "llm_prompt_sha256": None,
                "calibration_status": {},
                "conclusion_unavailable_reason": reason.value,
                "metadata": {
                    "reason_detail": detail or "no conclusion ledger row yet",
                    "is_transient": True,
                },
            }
        ],
    }
