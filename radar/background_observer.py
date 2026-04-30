"""Background Observer — per-scenario observation health (AP3).

Closes the observability gap exposed by the per-scenario OBS chip: the
"C-lite" mechanism is correctly wired (every scoring tick re-scores
all scenarios) but the actual per-country signal supply is heavily
geographically biased — Taiwan / Korea / South China Sea scenarios
receive ~0 LLM intel rows in a 24h window because the existing intel
pipeline ingests UA/RU/IL-heavy sources.

This module periodically rotates through NON-focused scenarios and
their participant countries, fetches public RSS feeds via anonymous
HTTP GET, runs the deterministic regex extractor in
``radar.conclusions.rss_extractor``, and writes findings as ephemeral
``Signal`` objects to a thread-safe queue that the scoring tick drains
on its next pass.

OPSEC + NP3 contract:
    1. No API keys, no per-deployment registration.
    2. No LLM dependency. The regex baseline is always sufficient;
       the LLM augmentation hook in ``rss_extractor.extract_kinetic``
       is intentionally unused here so the observer remains usable in
       offline / air-gapped LLM-less deployments.
    3. Default disabled (``BG_OBSERVER_ENABLED=false``). Operators
       opt-in by flipping the flag — adding outbound HTTP traffic
       should be a deliberate operational decision.
    4. Findings are EPHEMERAL signals: they expire after
       ``BG_OBSERVER_SIGNAL_TTL_SEC`` (default 30m). The
       ``scenario_contribution_log`` row written when they score is
       the durable artefact, surfaced via the OBS chip
       (signal_volume_24h metric).

Architecture:
    BackgroundObserver.tick()  → one cycle:
        - pick next non-focused active scenario (round-robin)
        - pick next participant country within that scenario
        - fetch RSS feeds (configurable, default Western+non-Western mix)
        - extract kinetic events scoped to that country
        - for each match, push a Signal to ``_signal_queue``
    drain_signals(now)  → called by the scoring tick to read fresh
        signals (filters by TTL).

The pure scheduling logic is testable without HTTP: tests inject a
fake fetcher + fake clock to drive the cycle.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.request
import defusedxml.ElementTree as ET
from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from radar import config
from radar.conclusions.rss_extractor import (
    KineticMatch,
    extract_kinetic_regex,
    extract_kinetic_regex_all,
    verify_alias_coverage,
)

log = logging.getLogger("bg_observer")


# ── Module-level signal queue ──────────────────────────────────────────────
# `_signal_queue` accumulates Signal-shaped dicts (kept loose so we don't
# have to import radar.scoring at module load — that would create a
# circular import via radar/routes/__init__.py). The scoring tick drains
# the queue at the start of each pass via drain_signals().
_signal_queue: deque = deque()
_queue_lock = threading.Lock()


@dataclass(frozen=True)
class _PendingSignal:
    """Wire format between observer and scoring tick. Kept independent
    of radar.scoring.Signal to avoid import cycles."""
    observed_at: float
    domain: str
    countries: tuple[str, ...]
    raw_score: float
    sensor: str
    signal_source: str
    value_display: str
    evidence_url: Optional[str]


# ── Public API ─────────────────────────────────────────────────────────────


def drain_signals(now: Optional[float] = None) -> list[_PendingSignal]:
    """Return all queued signals younger than the configured TTL and clear
    the queue. Called by the scoring tick on each pass."""
    if now is None:
        now = time.time()
    cutoff = now - config.BG_OBSERVER_SIGNAL_TTL_SEC
    out: list[_PendingSignal] = []
    with _queue_lock:
        while _signal_queue:
            sig = _signal_queue.popleft()
            if sig.observed_at >= cutoff:
                out.append(sig)
    return out


def queue_size() -> int:
    """For monitoring. Thread-safe."""
    with _queue_lock:
        return len(_signal_queue)


def _enqueue(sig: _PendingSignal) -> None:
    with _queue_lock:
        if len(_signal_queue) >= config.BG_OBSERVER_MAX_QUEUE:
            _signal_queue.popleft()  # drop oldest under pressure
        _signal_queue.append(sig)


# ── HTTP fetch ─────────────────────────────────────────────────────────────


_HTTP_USER_AGENT = "Mozilla/5.0 (compatible; news-aggregator)"
_HTTP_TIMEOUT_SEC = 15


def _default_fetch_feed(url: str) -> list[dict]:
    """Anonymous GET + minimal RSS/Atom parse. Returns list of items.

    Defensive: any HTTP / parse failure returns []. The pipeline is
    designed to keep producing useful auto-feedback rows even when a
    couple of upstream feeds are flaky or unreachable.
    """
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": _HTTP_USER_AGENT, "Accept": "*/*"},
        )
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_SEC) as resp:
            body = resp.read()
    except Exception as e:  # noqa: BLE001
        log.debug("[bg_observer] fetch failed %s: %s", url, e)
        return []

    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        log.debug("[bg_observer] XML parse failed %s: %s", url, e)
        return []

    items: list[dict] = []
    for item in root.iter("item"):
        items.append({
            "title": (item.findtext("title") or "").strip(),
            "summary": (item.findtext("description") or "").strip(),
            "link": (item.findtext("link") or "").strip(),
        })
    for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
        title = entry.find("{http://www.w3.org/2005/Atom}title")
        summary = entry.find("{http://www.w3.org/2005/Atom}summary")
        link_el = entry.find("{http://www.w3.org/2005/Atom}link")
        href = link_el.attrib.get("href", "") if link_el is not None else ""
        items.append({
            "title": (title.text or "").strip() if title is not None else "",
            "summary": (summary.text or "").strip() if summary is not None else "",
            "link": href,
        })
    return items


# ── BackgroundObserver class ───────────────────────────────────────────────


class BackgroundObserver:
    """Broadcast scanner over all scorable scenarios' participant unions.

    ADR-V2-015 Phase 3: replaced the round-robin (1 scenario × 1 country
    per cycle) with a broadcast scan that evaluates every fetched RSS
    item against every participant simultaneously. The scoring layer's
    per-scenario participant filter handles routing — emitting one
    Signal per detected country lets the same item count toward every
    scenario whose participants include that country.

    Why broadcast? The old design fetched all 9 feeds (~360 items)
    every cycle but kept matches for only one country, throwing away
    the other 8/9 of potential matches. Fetch cost is scope-independent;
    only the filter was scoped. Recall improvement is structural, not
    statistical.

    Fetcher and clock are injectable so tests run offline.
    """

    def __init__(
        self,
        scorable_scenarios_fn: Callable[[], Iterable],
        focused_id_fn: Callable[[], Optional[str]],
        feeds: Optional[list[str]] = None,
        fetch_feed_fn: Callable[[str], list[dict]] = _default_fetch_feed,
        now_fn: Callable[[], float] = time.time,
        log_fn: Optional[Callable[..., None]] = None,
        cycle_log_fn: Optional[Callable[[dict], None]] = None,
    ) -> None:
        self._scorable_fn = scorable_scenarios_fn
        self._focused_fn = focused_id_fn
        self._feeds = list(feeds) if feeds is not None else list(config.BG_OBSERVER_FEEDS)
        self._fetch_feed = fetch_feed_fn
        self._now = now_fn
        self._log = log_fn or log.info
        # Persistence hook for AP3/AP4 cycle audit. Default: lazy-import
        # radar.database so unit tests can run without a DB; injected
        # callable for test fixtures.
        self._cycle_log_fn = cycle_log_fn

    def _fetch_all(self) -> tuple[list[dict], int, int]:
        """Fetch every configured feed. Returns (items, attempted, failed).

        Per-feed exceptions are absorbed so one bad feed cannot starve
        the cycle; the failure count is surfaced in the cycle log so
        AP3 can detect chronic feed outages.
        """
        items: list[dict] = []
        attempted = 0
        failed = 0
        for url in self._feeds:
            attempted += 1
            try:
                feed_items = self._fetch_feed(url)
                if not feed_items:
                    # Empty result is treated as failure for AP3 visibility
                    # — distinguishes "fetched but empty" from "fetched and
                    # parsed N items". Real causes: 403, malformed XML,
                    # rate-limit. Either way, recall is reduced.
                    failed += 1
                else:
                    items.extend(feed_items)
            except Exception:  # noqa: BLE001
                failed += 1
        return items, attempted, failed

    def _gather_participants(self) -> tuple[list[str], list, str | None]:
        """Return (participants_union, scenarios_observed, focused_id).

        The participant union is **all** scorable scenarios' participants
        (focused included) — bg_observer no longer skips the focused
        scenario because the broadcast scan is far cheaper than the
        per-cycle fetch and the duplicate signals are de-duped by the
        scoring layer's ``dedup_by_source_country_max``. Including the
        focused scenario also gives the AP3 OBS chip a consistent
        per-country view across focus changes.
        """
        scenarios = list(self._scorable_fn())
        focused = self._focused_fn()
        participants: set[str] = set()
        for sc in scenarios:
            participants.update(getattr(sc, "participants", {}).keys())
        return sorted(participants), scenarios, focused

    def _persist_cycle_log(self, row: dict) -> None:
        """Persist a cycle audit row. Falls back silently on any error
        (NP3 — observer must not break itself by trying to log)."""
        if self._cycle_log_fn is not None:
            try:
                self._cycle_log_fn(row)
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            from radar.database import db as _db
            _db.bg_observer_cycle_append(row)
        except Exception:  # noqa: BLE001
            pass

    def tick(self) -> dict:
        """One observation cycle (broadcast). Returns a status dict.

        Each cycle:
          1. Resolve the participant union over all scorable scenarios.
          2. Verify alias coverage (NP6 — record any gap).
          3. Fetch every feed once.
          4. For each item, run multi-country extraction scoped to the
             participant union.
          5. Emit one Signal per (country, item) match.
          6. Persist a cycle log row for AP3/AP4.

        Non-fatal: per-feed and per-item exceptions are absorbed.
        """
        started_at = self._now()
        if not config.BG_OBSERVER_ENABLED:
            return {"enabled": False}

        participants, scenarios, focused = self._gather_participants()
        scenarios_observed = sorted(s.id for s in scenarios)

        # Coverage gap surfaces in cycle log for AP3 self-eval; we still
        # proceed because uncovered countries simply produce no matches
        # — having SOME observation is better than none (NP1).
        alias_gap = verify_alias_coverage(set(participants))

        if not participants:
            row = {
                "started_at": started_at,
                "duration_ms": int((self._now() - started_at) * 1000),
                "feeds_attempted": 0,
                "feeds_failed": 0,
                "items_total": 0,
                "items_with_country": 0,
                "items_with_kinetic": 0,
                "items_with_fatalities": 0,
                "matches_emitted": 0,
                "matches_by_country": {},
                "alias_gap": alias_gap,
                "scenarios_observed": scenarios_observed,
                "drop_reason": "no_participants",
            }
            self._persist_cycle_log(row)
            return {"enabled": True, "reason": "no_participants"}

        items, feeds_attempted, feeds_failed = self._fetch_all()

        items_with_country = 0
        items_with_kinetic = 0
        items_with_fatalities = 0
        matches: list[KineticMatch] = []
        for item in items:
            text = ((item.get("title") or "") + " — "
                    + (item.get("summary") or "")).strip()
            if not text:
                continue
            try:
                item_matches = extract_kinetic_regex_all(
                    text, allowed_countries=participants,
                )
            except Exception:  # noqa: BLE001
                continue
            if not item_matches:
                continue
            items_with_country += 1
            for m in item_matches:
                if m.fatalities > 0 and m.confidence >= 0.85:
                    items_with_fatalities += 1
                if m.confidence == 0.60:
                    items_with_kinetic += 1
                matches.append(m)

        now = self._now()
        matches_by_country: dict[str, int] = {}
        for m in matches:
            sig = _PendingSignal(
                observed_at=now,
                domain="info",
                countries=(m.country,),
                # 3-tier raw_score per ADR-V2-015 Phase 6:
                #   conf 0.85 (fatalities): 0.4 + 0.05 * fatalities (capped)
                #   conf 0.60 (kinetic verb only):    0.45
                #   conf 0.40 (escalation verb only): 0.25
                raw_score=(
                    min(1.0, 0.4 + 0.05 * m.fatalities) if m.confidence >= 0.85
                    else 0.45 if m.confidence >= 0.60
                    else 0.25
                ),
                sensor="bg_observer_rss",
                signal_source="bg_observer",
                value_display=(
                    f"rss:{m.country} fatalities={m.fatalities} "
                    f"conf={m.confidence:.2f}"
                ),
                evidence_url=None,
            )
            _enqueue(sig)
            matches_by_country[m.country] = matches_by_country.get(m.country, 0) + 1

        row = {
            "started_at": started_at,
            "duration_ms": int((self._now() - started_at) * 1000),
            "feeds_attempted": feeds_attempted,
            "feeds_failed": feeds_failed,
            "items_total": len(items),
            "items_with_country": items_with_country,
            "items_with_kinetic": items_with_kinetic,
            "items_with_fatalities": items_with_fatalities,
            "matches_emitted": len(matches),
            "matches_by_country": matches_by_country,
            "alias_gap": alias_gap,
            "scenarios_observed": scenarios_observed,
            "drop_reason": None,
        }
        self._persist_cycle_log(row)

        result = {
            "enabled": True,
            "participants": len(participants),
            "scenarios_observed": len(scenarios_observed),
            "feeds_items": len(items),
            "feeds_failed": feeds_failed,
            "matches": len(matches),
            "matches_by_country": matches_by_country,
            "alias_gap": alias_gap,
            "queued_total": queue_size(),
        }
        try:
            self._log("[bg_observer] cycle %s", result)
        except Exception:  # noqa: BLE001
            pass
        return result


# ── Daemon worker ──────────────────────────────────────────────────────────


def _worker_loop(observer: "BackgroundObserver") -> None:
    """Run BackgroundObserver.tick() forever, sleeping between cycles.

    Failures are caught + logged so a transient exception (e.g. DNS
    flapping, scenario_store mid-reload) cannot kill the worker.
    """
    while True:
        try:
            observer.tick()
        except Exception:  # noqa: BLE001
            log.exception("[bg_observer] cycle error (continuing)")
        time.sleep(config.BG_OBSERVER_INTERVAL_SEC)


def start_worker() -> Optional[threading.Thread]:
    """DEPRECATED (ADR-V2-015 Phase 4) — kept as a no-op compat shim.

    The ticker is now owned by ``BackgroundObserverSensor`` registered
    in ``radar/__init__.py``. Calling this function would either
    double-start the worker or have no effect, so it logs a warning
    and returns None. Removed in the release after Phase 4 lands.
    """
    log.warning(
        "[bg_observer] start_worker() is deprecated — "
        "BackgroundObserverSensor now owns the ticker (ADR-V2-015 Phase 4)"
    )
    return None
