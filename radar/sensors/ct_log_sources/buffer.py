"""radar.sensors.ct_log_sources.buffer -- ObservationBuffer.

Decouples evidence acquisition (push or pull) from the orchestrator's
score timing. Both certstream's ws worker and crt.sh's fetch_domain()
write here; the orchestrator's fetch() reads from here.

Idempotency:
  Both sources can deliver the same cert (a watched domain has a new
  Let's Encrypt cert; certstream sees it within seconds, the next
  hourly crt.sh backfill returns it again). The buffer collapses
  duplicates on (domain, serial, issuer_norm, day_bucket). Day bucket
  exists because some sources emit blank serials — without the day
  fallback, two distinct re-issuances by the same CA on different
  days would be lost.

Bounded:
  CT_LOG_BUFFER_MAX_OBS caps the buffer; on overflow we evict by
  oldest not_before_ts, not by insertion order, so a sudden burst
  of fresh observations doesn't kick out the older anomaly we
  haven't scored yet.

Threading:
  Single coarse-grained lock. Writes are O(1) (dict insert + linked
  list maintained by collections.OrderedDict's move_to_end). Reads
  return copies. p99 lock-hold time should stay well under the
  50ms budget called out in the plan; if it doesn't, we can shard
  by `hash(domain) % N` later without changing the contract.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone

from radar.sensors.ct_log_sources.base import CertObservation


class ObservationBuffer:
    """In-memory store of CertObservations awaiting scoring."""

    def __init__(self, max_obs: int, window_hours: int):
        # OrderedDict keyed by (domain, serial, issuer_norm, day_bucket).
        # Value is the CertObservation. We rely on OrderedDict insertion
        # order for the bounded-eviction policy: when capacity is hit we
        # evict by oldest not_before_ts (sorted scan), not by FIFO, so we
        # keep a separate lookup of the oldest.
        self._obs: OrderedDict[tuple, CertObservation] = OrderedDict()
        self._max_obs = max(100, int(max_obs))
        self._window_sec = max(3600, int(window_hours) * 3600)
        self._lock = threading.Lock()

        # Source freshness: last time each source successfully wrote.
        # Used by the operator panel to show "certstream silent for 2h".
        self._source_last_record_ts: dict[str, float] = {}

        # Per-domain freshness: last time we observed any cert for this
        # domain via any source. Used for the stale-domain detector.
        self._domain_last_observed_ts: dict[str, float] = {}

        # Counters
        self._records_total = 0
        self._duplicates_collapsed = 0
        self._evicted_for_capacity = 0

    @staticmethod
    def _key(obs: CertObservation) -> tuple:
        # Day-bucket the not_before to handle missing serials. UTC date
        # truncation: int(ts // 86400). Same CA reissuing the same domain
        # on the same UTC day collapses; reissuing the next day fires
        # again (which matches operator intuition — daily reissue is news).
        day = int(obs.not_before_ts // 86400)
        return (obs.domain.lower(), obs.serial.lower(), obs.issuer_norm, day)

    def record(self, obs: CertObservation) -> bool:
        """Insert one observation. Returns True if newly recorded, False
        if it was a duplicate (idempotent re-record).
        """
        if not obs.domain or not obs.issuer_norm:
            return False
        key = self._key(obs)
        with self._lock:
            if key in self._obs:
                self._duplicates_collapsed += 1
                return False
            self._obs[key] = obs
            self._records_total += 1
            self._source_last_record_ts[obs.source_name] = obs.observed_at_ts
            prev = self._domain_last_observed_ts.get(obs.domain, 0.0)
            if obs.observed_at_ts > prev:
                self._domain_last_observed_ts[obs.domain] = obs.observed_at_ts

            if len(self._obs) > self._max_obs:
                self._evict_oldest_locked()
        return True

    def _evict_oldest_locked(self) -> None:
        """Drop the observation with the smallest not_before_ts.

        Lock must be held by caller. O(N) on the buffer size; called only
        on overflow so the total cost is bounded by the ratio of arrival
        rate to capacity. With the default 5000 cap and ~50 inserts/sec
        peak this runs at most ~10x/sec.
        """
        if not self._obs:
            return
        oldest_key = min(self._obs, key=lambda k: self._obs[k].not_before_ts)
        self._obs.pop(oldest_key, None)
        self._evicted_for_capacity += 1

    def drain_for_scoring(self, now: float | None = None) -> dict[str, list[CertObservation]]:
        """Return observations grouped by domain, filtered to the
        observation window. Does NOT delete — _inspect_domain handles
        re-fire suppression via the DB known_ca history table.

        Anything older than window_sec is dropped from the buffer here
        as cleanup; nothing outside the window can affect the next
        scoring decision.
        """
        if now is None:
            now = time.time()
        cutoff = now - self._window_sec
        out: dict[str, list[CertObservation]] = {}
        to_drop: list[tuple] = []
        with self._lock:
            for key, obs in self._obs.items():
                if obs.not_before_ts < cutoff:
                    to_drop.append(key)
                    continue
                out.setdefault(obs.domain, []).append(obs)
            for key in to_drop:
                self._obs.pop(key, None)
        return out

    def last_observation_ts(self, domain: str) -> float | None:
        with self._lock:
            return self._domain_last_observed_ts.get(domain.lower())

    def source_freshness(self) -> dict[str, float]:
        with self._lock:
            return dict(self._source_last_record_ts)

    def stats(self) -> dict:
        with self._lock:
            n = len(self._obs)
            return {
                "observations_total": self._records_total,
                "observations_in_buffer": n,
                "capacity": self._max_obs,
                "capacity_used_pct": round(100.0 * n / self._max_obs, 1),
                "duplicates_collapsed": self._duplicates_collapsed,
                "evicted_for_capacity": self._evicted_for_capacity,
                "window_hours": self._window_sec // 3600,
                "domains_seen": len(self._domain_last_observed_ts),
            }

    def coverage_report(
        self, watched_domains: list[str], now: float | None = None
    ) -> dict:
        """Per-domain freshness summary for the operator panel.

        Returns counts of observed in last 24h / 72h, list of stalest
        domains, and list of never-observed domains.
        """
        if now is None:
            now = time.time()
        watched = [d.lower() for d in watched_domains]
        with self._lock:
            seen = dict(self._domain_last_observed_ts)
        observed_24h = 0
        observed_72h = 0
        never = []
        ages: list[tuple[str, float]] = []
        for d in watched:
            ts = seen.get(d)
            if ts is None:
                never.append(d)
                continue
            age = now - ts
            if age < 86400:
                observed_24h += 1
            if age < 86400 * 3:
                observed_72h += 1
            ages.append((d, age))
        ages.sort(key=lambda x: -x[1])
        stalest = [{"domain": d, "age_sec": round(a, 1)} for d, a in ages[:10]]
        return {
            "watched_total": len(watched),
            "observed_24h": observed_24h,
            "observed_72h": observed_72h,
            "never_observed_count": len(never),
            "never_observed_sample": never[:10],
            "stalest_observed": stalest,
        }


def make_observation(
    *,
    domain: str,
    issuer_raw: str,
    issuer_norm: str,
    common_name: str,
    subject_alt_names: list[str] | tuple[str, ...] | None,
    not_before_iso: str | None,
    serial: str,
    source_name: str,
    observed_at_ts: float | None = None,
) -> CertObservation | None:
    """Helper: build a CertObservation from raw source fields.

    Returns None if not_before could not be parsed — sources should
    not record observations whose freshness we can't determine.
    """
    if not domain or not issuer_norm:
        return None
    nb_ts = _parse_iso_to_ts(not_before_iso) if not_before_iso else 0.0
    if nb_ts <= 0:
        return None
    sans = tuple((s or "").strip().lower() for s in (subject_alt_names or ()) if s)
    return CertObservation(
        domain=domain.lower(),
        issuer_norm=issuer_norm,
        issuer_raw=(issuer_raw or "")[:200],
        common_name=(common_name or "")[:200],
        subject_alt_names=sans,
        not_before_ts=nb_ts,
        serial=(serial or "").lower(),
        source_name=source_name,
        observed_at_ts=observed_at_ts if observed_at_ts is not None else time.time(),
    )


def _parse_iso_to_ts(s: str) -> float:
    """Parse the various crt.sh / certstream ISO datetime forms to UTC ts."""
    if not s:
        return 0.0
    try:
        clean = s.replace("T", " ").split(".")[0].rstrip("Z").strip()
        dt = datetime.fromisoformat(clean).replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0
