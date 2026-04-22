"""radar.sensors.ct_log_sources.base -- source contract.

The orchestrator must be able to treat every source uniformly when
aggregating health for the operator panel and when deciding which
source to consult next. This module defines the contract.

Design notes:

  * CertObservation is intentionally narrow. It carries only what the
    orchestrator's _inspect_domain logic needs (domain match, issuer
    classification, freshness gating). Source-specific metadata
    (crt.sh row id, certstream message id, ...) stays inside the
    source and is not exposed across the boundary.

  * issuer_norm is the dedup key we share with the existing DB-backed
    `ct_log_known_ca_per_domain` table. Sources MUST normalize using
    `_parse_issuer` from radar.sensors.ct_log so that an observation
    arriving via certstream and again via crt.sh-backfill collapses
    to the same key in the buffer.

  * The pull/push split exists because gevent monkey-patch cooperates
    with synchronous requests but not with arbitrary asyncio. Push
    sources own their own worker threads; pull sources are driven by
    the orchestrator's fetch() cycle.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable, Literal


@dataclass(frozen=True)
class CertObservation:
    """One certificate matching a watched domain.

    Frozen so that the buffer's idempotency check (hash on a stable
    tuple of fields) is safe across concurrent writers.

    Fields:
        domain          watched domain that matched (normalized lowercase)
        issuer_norm     issuer canonical form (O= component, lowercased) —
                        the dedup/comparison key shared with the DB
        issuer_raw      issuer as-seen, capped to 200 chars for display
        common_name     cert CN, capped to 200 chars
        subject_alt_names  tuple of SANs (immutable) — used by the
                        orchestrator's wildcard-TLD detector
        not_before_ts   cert validity start as Unix timestamp (UTC)
        serial          cert serial number as hex string (may be empty
                        if source did not provide one)
        source_name     "crtsh" | "certstream" | "certspotter" | ... —
                        which source delivered this observation
        observed_at_ts  when our worker received the observation; used
                        for source-freshness reporting in the operator
                        panel, NOT for any scoring decision
    """
    domain: str
    issuer_norm: str
    issuer_raw: str
    common_name: str
    subject_alt_names: tuple[str, ...]
    not_before_ts: float
    serial: str
    source_name: str
    observed_at_ts: float


@runtime_checkable
class CtLogSource(Protocol):
    """Common surface every source exposes for diagnostics."""

    name: str
    kind: Literal["pull", "push"]

    def health(self) -> dict:
        """Return a uniform-shape health dict.

        Required keys:
            status: "healthy" | "degraded" | "dead" | "unknown"
            last_success_ts: float (0.0 if never)
            consecutive_failures: int
            mode_counters: dict[str, int]  (timeout, http_5xx, etc.)
            source_specific: dict (free-form per source)
        """
        ...


class BaseCtLogPullSource:
    """Base for pull sources. Subclasses implement fetch_domain()."""

    name: str = "pull_source"
    kind: Literal["pull"] = "pull"

    def fetch_domain(self, domain: str) -> list[CertObservation] | None:
        """Synchronously query the source for one watched domain.

        Returns:
            list[CertObservation] — possibly empty, observations will be
                                    handed to the buffer by the caller
            None                  — hard transport failure; caller MUST
                                    NOT treat this as "no certs found"
        """
        raise NotImplementedError

    def health(self) -> dict:
        raise NotImplementedError


class BaseCtLogPushSource:
    """Base for push sources. Owns its own worker thread.

    Lifecycle:
        __init__ takes a buffer reference and the watched-domain set.
        start() spawns the worker and returns immediately.
        stop()  signals the worker to exit and joins; idempotent.
    """

    name: str = "push_source"
    kind: Literal["push"] = "push"

    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def health(self) -> dict:
        raise NotImplementedError
