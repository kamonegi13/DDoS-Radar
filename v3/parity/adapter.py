"""The single input adapter both systems read through (S5-VERIF-031).

The clause has two halves and this module is the first: legacy and v3
receive parity input from ONE adapter, never from two readers that agree
today. The second half — do not copy the formula into the harness — is why
the legacy driver spawns a subprocess around the real `radar.scoring`
functions instead of reimplementing them. `scripts/phase9_backtest_
simulation.py:43-53` is the counterexample both halves exist to prevent: a
hand-copied `derive_tl` with a comment promising to track the original,
which then did not.

What the adapter emits is the ledger's own rows, unchanged. The two
side-specific projections (`to_v3_observations`, `to_wire`) are pure
functions OF those rows, so neither side can be fed something the other
never saw.

Ticks reconstruct S5-VERIF-017's latest-row-at-T semantics: at instant T a
sensor's contribution is its most recent row at or before T, provided that
row is still inside its own freshness horizon. Without the horizon a
sensor that died on day 3 would keep contributing for the remaining 27
days of the window — which is defect B-03, reproduced by the very harness
meant to detect it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterator, Mapping, Sequence

from v3.kernel import Ratio
from v3.kernel.errors import DomainError
from v3.ledger import LedgerStore
from v3.ledger.schema import SIGNAL_RETENTION_DAYS
from v3.scoring import CountryWeight, Observation
from v3.scoring.inputs import ORIGIN_LLM_INTEL, ORIGIN_SENSOR

#: Used per-row when a stored horizon is non-positive (the L1 schema
#: should prevent it, but a zero would silently make a row never fresh).
_FALLBACK_HORIZON_SEC = 3600.0
#: The lookback bound when the ledger declares no horizon at all. Nothing
#: older than the signal retention window can exist, so it cannot be too
#: small — the property the window-derived bound failed to have.
_RETENTION_FALLBACK_SEC = SIGNAL_RETENTION_DAYS * 86400.0


@dataclass(frozen=True, slots=True)
class TickInput:
    """Everything in force at one instant, as raw ledger rows."""

    tick_ts: float
    rows: tuple[Mapping, ...]

    @property
    def sensors(self) -> frozenset:
        return frozenset(row["sensor"] for row in self.rows)


def _row_key(row: Mapping) -> tuple:
    return (row["sensor"], row["signal_source"], row["country"])


class LedgerInputAdapter:
    """Turns the v3 observation ledger into a tick series."""

    def __init__(self, store: LedgerStore, *,
                 tick_interval_sec: float):
        if tick_interval_sec <= 0:
            raise DomainError(
                f"tick_interval_sec must be positive, got {tick_interval_sec}")
        self._store = store
        self._tick_interval_sec = float(tick_interval_sec)

    @property
    def tick_interval_sec(self) -> float:
        return self._tick_interval_sec

    def tick_timestamps(self, start: float, end: float) -> tuple[float, ...]:
        if end < start:
            raise DomainError(
                f"parity window must move forward, got {start} -> {end}")
        stamps = []
        current = start
        while current <= end:
            stamps.append(current)
            current += self._tick_interval_sec
        return tuple(stamps)

    def ticks(self, start: float, end: float) -> Iterator[TickInput]:
        """Latest-row-at-T for every tick in the window.

        One query for the window, then a forward fold — the alternative is
        a query per (tick x sensor x country), which for a 30-day window at
        a 120 s tick is upwards of a million round trips.
        """
        # Reach back one horizon before the window so a row still in force
        # at `start` is not missed just because it was written earlier.
        # The bound comes from the WHOLE ledger, never from the window —
        # see `_lookback_horizon`.
        lookback = start - self._lookback_horizon()
        rows = self._store.signals_between(lookback, end)
        in_force: dict[tuple, Mapping] = {}
        index = 0
        for tick_ts in self.tick_timestamps(start, end):
            while index < len(rows) and rows[index]["observed_at"] <= tick_ts:
                row = rows[index]
                in_force[_row_key(row)] = row
                index += 1
            live = tuple(
                row for row in in_force.values()
                if self._is_fresh(row, tick_ts))
            yield TickInput(tick_ts=tick_ts, rows=live)

    def _lookback_horizon(self) -> float:
        """How far before the window to read, bounded by the whole ledger.

        Deriving this from rows inside the window is circular and was the
        harness's worst defect: a slow sensor (say a 30-day horizon,
        last observed 20 days before the window) contributes no in-window
        row, so its horizon never enters the maximum, so the lookback is
        too short to load it, so it is absent from the early ticks — on
        BOTH sides. A shared blind spot raises the agreement rate while
        concealing a detection gap, which is the one failure direction
        this harness must never produce.

        `max_freshness_horizon()` scans the whole table instead. If the
        ledger is empty it returns None, and the retention window is the
        correct bound: nothing older than that can exist.
        """
        horizon = self._store.max_freshness_horizon()
        if horizon and horizon > 0:
            return float(horizon)
        return _RETENTION_FALLBACK_SEC

    @staticmethod
    def _is_fresh(row: Mapping, at_ts: float) -> bool:
        horizon = float(row.get("freshness_horizon_sec") or 0.0)
        if horizon <= 0:
            horizon = _FALLBACK_HORIZON_SEC
        age = at_ts - float(row["observed_at"])
        return 0 <= age <= horizon

    def snapshot_id(self, start: float, end: float) -> str:
        """A content hash of the input window (S5-VERIF-030).

        Identifies exactly which rows a run consumed, so a disagreement
        can be re-run against the same input rather than against whatever
        the ledger holds later.
        """
        digest = hashlib.sha256()
        digest.update(f"{start}:{end}:{self._tick_interval_sec}".encode())
        for row in self._store.signals_between(start, end):
            digest.update(json.dumps(
                {key: row[key] for key in sorted(row)},
                sort_keys=True, default=str, allow_nan=False).encode())
        return digest.hexdigest()


# ── the two projections, both pure functions of the same rows ────────────

def to_v3_observations(rows: Sequence[Mapping]) -> tuple[Observation, ...]:
    """Ledger rows as scoring-kernel observations.

    `origin` is recovered from `signal_source`, not guessed. S1-INTEL-020
    pins the intel signal source to the literal `llm_intel` ("信号系統は
    llm_intel 固定 MUST") and it is the dedup unit S1-SCORE-008 folds on,
    so the row already states what it is; the L1 table has no separate
    `origin` column. Recovering it matters because the WP-2.4 addendum's
    age term fires on origin alone — projecting an intel row as an
    ordinary sensor reading would score a two-day-old report at full
    weight, which is the silent direction.
    """
    built = []
    for row in rows:
        country = (row.get("country") or "").strip()
        countries = ((CountryWeight(country, Ratio(1.0)),) if country
                     and country.upper() != "GLOBAL" else ())
        confidence = row.get("confidence")
        source = row.get("signal_source") or ""
        origin = (ORIGIN_LLM_INTEL if source == ORIGIN_LLM_INTEL
                  else ORIGIN_SENSOR)
        built.append(Observation(
            sensor=row["sensor"],
            domain=row["domain"],
            status=row["status"],
            score=float(row.get("raw_score") or 0.0),
            signal_source=source,
            countries=countries,
            confidence=Ratio(1.0 if confidence is None else float(confidence)),
            suppressed=bool(row.get("suppressed")),
            suppress_reason=row.get("suppress_reason"),
            value=str(row.get("payload") or ""),
            origin=origin,
            # Carried for every row, not only intel: an observation whose
            # own timestamp is dropped here cannot be aged by anything
            # downstream, and the harness would have no way to notice.
            observed_at=float(row["observed_at"]),
        ))
    return tuple(built)


def to_wire(rows: Sequence[Mapping]) -> list[dict]:
    """Ledger rows as JSON for the legacy driver's subprocess.

    Deliberately the same field names the ledger uses. Renaming here would
    put a translation step between the two sides, and a translation step
    is a place for them to diverge.
    """
    wire = []
    for row in rows:
        wire.append({
            "sensor": row["sensor"],
            "signal_source": row.get("signal_source") or row["sensor"],
            "domain": row["domain"],
            "country": (row.get("country") or "").strip(),
            "status": row["status"],
            "raw_score": float(row.get("raw_score") or 0.0),
            "confidence": (None if row.get("confidence") is None
                           else float(row["confidence"])),
            "suppressed": bool(row.get("suppressed")),
            "observed_at": float(row["observed_at"]),
            "value": str(row.get("payload") or ""),
            "evidence_url": row.get("evidence_url"),
        })
    return wire


__all__ = ["LedgerInputAdapter", "TickInput", "to_v3_observations", "to_wire"]
