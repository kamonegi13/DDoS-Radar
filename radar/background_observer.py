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
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from radar import config
from radar.conclusions.rss_extractor import KineticMatch, extract_kinetic_regex

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
    """Round-robin scheduler over non-focused scenarios + their participants.

    Stateless across cycles except for two indices (scenario rotation +
    per-scenario country rotation). Fetcher and clock are injectable so
    tests run offline.
    """

    def __init__(
        self,
        scorable_scenarios_fn: Callable[[], Iterable],
        focused_id_fn: Callable[[], Optional[str]],
        feeds: Optional[list[str]] = None,
        fetch_feed_fn: Callable[[str], list[dict]] = _default_fetch_feed,
        now_fn: Callable[[], float] = time.time,
        log_fn: Optional[Callable[..., None]] = None,
    ) -> None:
        self._scorable_fn = scorable_scenarios_fn
        self._focused_fn = focused_id_fn
        self._feeds = list(feeds) if feeds is not None else list(config.BG_OBSERVER_FEEDS)
        self._fetch_feed = fetch_feed_fn
        self._now = now_fn
        self._scenario_idx = 0
        self._country_idx_per_scenario: dict[str, int] = {}
        self._log = log_fn or log.info

    def _pick_scenario(self):
        scenarios = list(self._scorable_fn())
        focused = self._focused_fn()
        candidates = [s for s in scenarios if s.id != focused]
        if not candidates:
            return None
        # Sort for determinism so round-robin is stable across restarts
        candidates.sort(key=lambda s: s.id)
        sc = candidates[self._scenario_idx % len(candidates)]
        self._scenario_idx += 1
        return sc

    def _pick_country(self, scenario) -> Optional[str]:
        participants = sorted(getattr(scenario, "participants", {}).keys())
        if not participants:
            return None
        idx = self._country_idx_per_scenario.get(scenario.id, 0)
        country = participants[idx % len(participants)]
        self._country_idx_per_scenario[scenario.id] = idx + 1
        return country

    def _fetch_all(self) -> list[dict]:
        items: list[dict] = []
        for url in self._feeds:
            items.extend(self._fetch_feed(url))
        return items

    def tick(self) -> dict:
        """One observation cycle. Returns a small status dict for monitoring.

        Caller is responsible for sleeping between ticks. Non-fatal: any
        exception during fetch / extract is caught at the per-feed level
        so a single bad feed cannot starve the rotation.
        """
        if not config.BG_OBSERVER_ENABLED:
            return {"enabled": False}

        scenario = self._pick_scenario()
        if scenario is None:
            return {"reason": "no_non_focused_scenario"}
        country = self._pick_country(scenario)
        if country is None:
            return {"reason": "no_participants", "scenario_id": scenario.id}

        items = self._fetch_all()
        matches: list[KineticMatch] = []
        for item in items:
            text = ((item.get("title") or "") + " — " + (item.get("summary") or "")).strip()
            if not text:
                continue
            m = extract_kinetic_regex(text, allowed_countries=[country])
            if m is not None:
                matches.append(m)

        now = self._now()
        for m in matches:
            sig = _PendingSignal(
                observed_at=now,
                domain="info",  # RSS narrative → information-domain by default
                countries=(m.country,),
                raw_score=min(1.0, 0.4 + 0.05 * m.fatalities),  # cap at 1.0
                sensor="bg_observer_rss",
                signal_source="bg_observer",
                value_display=f"rss:{m.country} fatalities={m.fatalities}",
                evidence_url=None,
            )
            _enqueue(sig)

        result = {
            "enabled": True,
            "scenario_id": scenario.id,
            "country": country,
            "feeds_items": len(items),
            "matches": len(matches),
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
    """Spawn the background daemon. Returns the thread (None if disabled).

    Imported and called from radar/__init__.py during application startup.
    The deferred imports here avoid circular dependencies during module
    loading (scenario_store loads geo_data.json which references config).
    """
    if not config.BG_OBSERVER_ENABLED:
        log.info("[bg_observer] disabled (BG_OBSERVER_ENABLED=false)")
        return None

    from radar.scenarios import scenario_store

    def scorable():
        return scenario_store.scorable() if scenario_store.loaded else []

    def focused_id():
        # The "currently focused scenario" lives in process state per-request,
        # not globally. For the background observer the safest signal is
        # "default focused scenario" from config. The observer is harmless
        # if it accidentally polls the focused scenario (just one extra
        # signal; OBS chip still shows the same green health). The tradeoff
        # is acceptable to avoid leaking request state into a daemon thread.
        from radar.config import DEFAULT_FOCUSED_SCENARIO
        return DEFAULT_FOCUSED_SCENARIO

    observer = BackgroundObserver(
        scorable_scenarios_fn=scorable,
        focused_id_fn=focused_id,
    )
    t = threading.Thread(
        target=_worker_loop, args=(observer,),
        daemon=True, name="bg_observer",
    )
    t.start()
    log.info("[bg_observer] started — interval=%ds, feeds=%d",
             config.BG_OBSERVER_INTERVAL_SEC, len(observer._feeds))
    return t
