"""A stored conclusion row back into a `Conclusion`.

The API projects the ledger; it does not re-derive. That is what makes
completion condition 1 achievable at all — a read that had to re-derive
would need the fetch cycle, and re-running the fetch cycle from a GET is
A-01 verbatim.

Reading a row back means rebuilding the object, and the object refuses to
exist without a `Provenance`, an `InputHealth` and the NP7 disclaimer. So
this module reconstructs those from the columns and the metadata blob
rather than skipping the constructor with a dict — S1-CONC-006's
hand-built dict bypassed every schema invariant and is registered as
ACCIDENTAL A2. A row that cannot be rebuilt is reported as such; it is
not served as a thinner conclusion, because a conclusion that lost its
provenance on the way out is indistinguishable from one that never had
any (NP6).
"""
from __future__ import annotations

import json
from typing import Any, Optional

from v3.conclusions import Conclusion, GuardVerdict, InputHealth, Suppression
from v3.kernel import Provenance
from v3.kernel.errors import DomainError


class UnreadableConclusionRow(DomainError):
    """The row exists but cannot be rebuilt into a published judgement."""


def _loads(value, *, name: str, default):
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise UnreadableConclusionRow(
            f"conclusion column {name} is not JSON: {exc}") from exc


def _provenance(payload: Any, *, formula_ref: str,
                observed_at: float) -> Provenance:
    if not isinstance(payload, dict):
        raise UnreadableConclusionRow(
            "the row carries no provenance; a published judgement without "
            "its derivation is not republishable (NP6)")
    return Provenance(
        formula_ref=payload.get("formula_ref") or formula_ref,
        computed_at=float(payload.get("computed_at") or observed_at),
        inputs=dict(payload.get("inputs") or {}),
        source_refs=tuple(payload.get("source_refs") or ()))


def _input_health(payload: Any) -> InputHealth:
    if not isinstance(payload, dict):
        # G-17: absent health is not healthy health. An empty InputHealth
        # says "nothing was consulted", which is the honest reading of a
        # row that recorded none.
        return InputHealth()
    return InputHealth(
        sources_ok=tuple(payload.get("sources_ok") or ()),
        sources_failed=tuple(payload.get("sources_failed") or ()),
        sources_stale=tuple(payload.get("sources_stale") or ()),
        history_span_sec=float(payload.get("history_span_sec") or 0.0))


def _suppression(payload: Any) -> Optional[Suppression]:
    if not isinstance(payload, dict):
        return None
    return Suppression(
        guard_id=payload.get("guard_id") or "",
        reason=payload.get("reason") or "",
        detail=payload.get("detail") or "",
        overridden=bool(payload.get("overridden")),
        evaluated=tuple(
            GuardVerdict(guard_id=item.get("guard_id", ""),
                         reason=item.get("reason", ""),
                         fired=bool(item.get("fired")),
                         detail=item.get("detail", ""))
            for item in (payload.get("evaluated") or [])
            if isinstance(item, dict)))


def from_row(row: dict) -> Conclusion:
    """Rebuild one `Conclusion`. Raises rather than thinning the record."""
    if not isinstance(row, dict):
        raise UnreadableConclusionRow(
            f"a conclusion row is a mapping, got {type(row).__name__}")
    metadata = dict(_loads(row.get("metadata"), name="metadata", default={}))
    provenance_payload = metadata.pop("provenance", None)
    health_payload = metadata.pop("input_health", None)
    suppression_payload = metadata.pop("suppression", None)
    observed_at = float(row["observed_at"])
    try:
        return Conclusion(
            conclusion_id=row["id"],
            scenario_id=row["scenario_id"],
            conclusion_type=row["conclusion_type"],
            observed_at=observed_at,
            confidence=float(row["confidence"]),
            state=row.get("state"),
            unavailable_reason=row.get("conclusion_unavailable_reason"),
            provenance=_provenance(provenance_payload,
                                   formula_ref=row.get("formula_ref") or "",
                                   observed_at=observed_at),
            input_health=_input_health(health_payload),
            suppression=_suppression(suppression_payload),
            threshold_ref=_loads(row.get("threshold_ref"),
                                 name="threshold_ref", default={}),
            source_urls=tuple(_loads(row.get("source_urls"),
                                     name="source_urls", default=[])),
            calibration_status=_loads(row.get("calibration_status"),
                                      name="calibration_status", default={}),
            llm_prompt_sha256=row.get("llm_prompt_sha256"),
            metadata=metadata)
    except UnreadableConclusionRow:
        raise
    except (DomainError, KeyError, TypeError, ValueError) as exc:
        raise UnreadableConclusionRow(
            f"conclusion row {row.get('id')!r} cannot be rebuilt: {exc}"
        ) from exc


def tl_point(row: dict) -> dict:
    """One TL row as JSON.

    `LedgerStore` hands back a kernel `ThreatLevel` here, deliberately —
    it is the type that refuses to be ordered or arithmetically compared,
    which is what stopped the two scale inversions. It is also not JSON,
    so the projection converts it exactly once, here, rather than in each
    handler that happens to notice.

    `None` stays `None`: the null zone is a state (NP5+8), and defaulting
    it to 5/NORMAL on the way out is G-17 with better manners.
    """
    level = row.get("threat_level")
    value = None if level is None else int(getattr(level, "value", level))
    return {**{key: item for key, item in row.items()
               if key != "threat_level"},
            "threat_level": value,
            "severity": None if value is None else 6 - value}


__all__ = ["from_row", "tl_point", "UnreadableConclusionRow"]
