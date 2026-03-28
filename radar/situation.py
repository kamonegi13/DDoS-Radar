"""radar.situation -- Situation Board Engine.

Aggregates existing sensor data and climate indicators per theater to produce:
  1. Situation Summary — structured state with direction vector per theater
  2. Wire — factual one-liners derived from sensor observations

No new data collection; purely a re-projection of existing caches along
the theater axis for analyst situational awareness.
"""
from __future__ import annotations
import logging
import threading
import time
import math
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("radar")

# Direction labels
DIR_ESCALATING = "ESCALATING"
DIR_STABLE = "STABLE"
DIR_DE_ESCALATING = "DE-ESCALATING"


@dataclass
class WireItem:
    """A single factual observation in the Situation Wire."""
    ts: float
    theater: str
    source: str          # Sensor/indicator origin (e.g. "GDELT", "RSS", "S1")
    text: str            # One-line factual statement
    severity: int = 0    # 0=routine, 1=notable, 2=significant
    sync_theaters: list = field(default_factory=list)  # Other theaters with near-simultaneous events

    def to_dict(self) -> dict:
        import datetime
        d = {
            "ts": self.ts,
            "ts_iso": datetime.datetime.fromtimestamp(
                self.ts, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "theater": self.theater,
            "source": self.source,
            "text": self.text,
            "severity": self.severity,
        }
        if self.sync_theaters:
            d["sync_theaters"] = self.sync_theaters
        return d


@dataclass
class TheaterSituation:
    """Aggregated situation for a single theater."""
    theater: str
    theater_name: str = ""               # Full country name
    direction: str = DIR_STABLE          # ESCALATING / STABLE / DE-ESCALATING
    direction_score: float = 0.0         # Continuous score for direction
    tone_current: Optional[float] = None
    tone_delta_7d: Optional[float] = None
    media_concentration: Optional[float] = None  # RSS z-score
    aviation_change_pct: Optional[float] = None
    shipping_dark_gaps: int = 0
    forex_z: Optional[float] = None
    climate_axes_active: int = 0         # How many climate axes have signals
    climate_indicators: list = field(default_factory=list)  # Active indicator codes
    convergence_level: str = ""
    threat_level: int = 5                # 1-5 from engine
    wire: list = field(default_factory=list)  # WireItem list
    wire_density_6h: int = 0             # Wire events in last 6 hours
    wire_density_trend: str = ""         # INCREASING / STABLE / DECREASING

    def to_dict(self) -> dict:
        return {
            "theater": self.theater,
            "theater_name": self.theater_name,
            "direction": self.direction,
            "direction_score": round(self.direction_score, 2),
            "tone_current": round(self.tone_current, 1) if self.tone_current is not None else None,
            "tone_delta_7d": round(self.tone_delta_7d, 1) if self.tone_delta_7d is not None else None,
            "media_concentration": round(self.media_concentration, 1) if self.media_concentration is not None else None,
            "aviation_change_pct": round(self.aviation_change_pct, 1) if self.aviation_change_pct is not None else None,
            "shipping_dark_gaps": self.shipping_dark_gaps,
            "forex_z": round(self.forex_z, 1) if self.forex_z is not None else None,
            "climate_axes_active": self.climate_axes_active,
            "climate_indicators": self.climate_indicators,
            "convergence_level": self.convergence_level,
            "threat_level": self.threat_level,
            "wire": [w.to_dict() for w in self.wire],
            "wire_density_6h": self.wire_density_6h,
            "wire_density_trend": self.wire_density_trend,
        }


class SituationEngine:
    """Computes per-theater situation summaries from existing sensor data."""

    def __init__(self):
        self._situations: dict[str, TheaterSituation] = {}
        self._wire_history: list[WireItem] = []
        self._tone_history: dict[str, list[tuple[float, float]]] = {}
        self._last_reported: dict[str, dict] = {}  # (theater, source) -> {value, ts}
        self._lock = threading.RLock()
        self._last_update: float = 0.0
        self._restore_from_db()

    def _restore_from_db(self):
        """Load persisted wire items from SQLite on startup."""
        try:
            from radar.database import db
            cutoff = time.time() - 48 * 3600
            rows = db.situation_wire_load(cutoff)
            if rows:
                for r in rows:
                    self._wire_history.append(WireItem(
                        ts=r["ts"], theater=r["theater"], source=r["source"],
                        text=r["text"], severity=r["severity"],
                    ))
                log.info(f"[Situation] Restored {len(rows)} wire items from DB")
        except Exception as e:
            log.debug(f"[Situation] DB restore skipped: {e}")

    def _persist_wire(self, items: list[WireItem]):
        """Save new wire items to SQLite."""
        try:
            from radar.database import db
            db.situation_wire_save([{
                "ts": w.ts, "theater": w.theater, "source": w.source,
                "text": w.text, "severity": w.severity,
            } for w in items])
        except Exception as e:
            log.debug(f"[Situation] DB persist error: {e}")

    def _should_emit(self, theater: str, source: str, value: float, threshold: float = 0.3) -> bool:
        """Check if a wire item should be emitted based on value change from last report.

        Returns True if:
          - Never reported before for this (theater, source)
          - Value changed by more than threshold from last reported value
          - More than 6 hours since last report (periodic refresh)
        """
        key = f"{theater}:{source}"
        now = time.time()
        with self._lock:
            prev = self._last_reported.get(key)
            if prev is None:
                self._last_reported[key] = {"value": value, "ts": now}
                return True
            elapsed = now - prev["ts"]
            delta = abs(value - prev["value"])
            if delta > threshold or elapsed > 6 * 3600:
                self._last_reported[key] = {"value": value, "ts": now}
                return True
            return False

    def update(self, registry, global_cache: dict) -> None:
        """Recompute situation summaries from current sensor caches."""
        now = time.time()
        strategic = global_cache.get("strategic", {})
        country_intel = strategic.get("country_intel", {})
        target_details = global_cache.get("data", {})

        # Use the active theater set from the scoring loop (reflects Target Visibility)
        active_list = global_cache.get("active_theaters", [])
        if active_list:
            configured_theaters = set(active_list)
        else:
            # Fallback to config.env defaults
            try:
                from radar.config import DEFAULT_CORE, DEFAULT_CORRELATES, DEFAULT_ADVERSARIES, DEFAULT_PINS
                configured_theaters = {DEFAULT_CORE}
                configured_theaters.update(DEFAULT_CORRELATES)
                configured_theaters.update(DEFAULT_ADVERSARIES)
                configured_theaters.update(DEFAULT_PINS)
            except Exception:
                configured_theaters = set(country_intel.keys()) | set(target_details.keys())

        theaters = set()
        for code in configured_theaters:
            if code in country_intel or code in target_details:
                theaters.add(code)

        # Get climate events from climate engine
        climate_events_by_theater: dict[str, list] = {}
        try:
            from radar.climate_state import climate_engine
            feed = climate_engine.get_feed(limit=200)
            for ev in feed:
                th = ev.get("theater", "")
                if th and th in configured_theaters:
                    climate_events_by_theater.setdefault(th, []).append(ev)
                    theaters.add(th)
        except Exception:
            pass

        # Sensor caches
        gdelt_tones = self._get_sensor_cache(registry, "gdelt", "gdelt_tones")
        rss_narratives = self._get_sensor_cache(registry, "rss_narrative", "narratives")
        opensky_airports = self._get_sensor_cache(registry, "opensky", "airports")
        ais_cache = self._get_sensor_cache(registry, "ais_maritime")

        # Resolve country names from geo_data
        try:
            from radar.config import COUNTRY_COORDS
            _country_names = {code: data.get("name", code) for code, data in COUNTRY_COORDS.items()}
        except Exception:
            _country_names = {}

        new_situations: dict[str, TheaterSituation] = {}
        new_wire: list[WireItem] = []

        for theater in theaters:
            sit = TheaterSituation(theater=theater)
            sit.theater_name = _country_names.get(theater, theater)

            # ── GDELT tone ──
            gdelt = gdelt_tones.get(theater, {})
            if gdelt.get("tone_current") is not None:
                sit.tone_current = gdelt["tone_current"]
                sit.tone_delta_7d = gdelt.get("delta")

                # Track tone history for trend
                with self._lock:
                    hist = self._tone_history.setdefault(theater, [])
                    hist.append((now, gdelt["tone_current"]))
                    cutoff = now - 7 * 86400
                    self._tone_history[theater] = [
                        (t, v) for t, v in hist if t > cutoff
                    ]

                # Generate wire item for notable tone changes
                delta = gdelt.get("delta")
                if delta is not None and abs(delta) > 1.0 and self._should_emit(theater, "Media Tone", gdelt["tone_current"], 0.5):
                    tname = sit.theater_name
                    if delta < 0:
                        direction_desc = f"hostile media coverage toward {tname} is intensifying"
                    else:
                        direction_desc = f"media coverage toward {tname} is softening"
                    sev = 1 if abs(delta) > 2.0 else 0
                    new_wire.append(WireItem(
                        ts=now, theater=theater, source="Media Tone",
                        text=f"GDELT global media tone toward {tname}: {gdelt['tone_current']:.1f} "
                             f"(shifted {delta:+.1f} from baseline) — {direction_desc}",
                        severity=sev,
                    ))

            # ── RSS media concentration ──
            rss = rss_narratives.get(theater, {})
            if rss.get("z_score") is not None:
                sit.media_concentration = rss["z_score"]
                article_count = rss.get("article_count", 0)
                status = rss.get("status", "NORMAL")
                if (status in ("BURST", "CRITICAL_BURST") or (rss["z_score"] > 1.0)) and self._should_emit(theater, "State Media", rss["z_score"], 0.5):
                    tname = sit.theater_name
                    sev = 2 if status == "CRITICAL_BURST" else (1 if status == "BURST" else 0)
                    new_wire.append(WireItem(
                        ts=now, theater=theater, source="State Media",
                        text=f"State-affiliated media published {article_count} articles referencing {tname} "
                             f"({rss['z_score']:.1f}\u03c3 above normal rate) — elevated editorial focus",
                        severity=sev,
                    ))

            # ── Aviation ──
            airport_data = opensky_airports.get(theater, {})
            count = airport_data.get("count", -1)
            if count >= 0:
                # Check climate engine's aviation history for baseline
                try:
                    from radar.climate_state import climate_engine
                    av_hist = climate_engine.aviation_route._history.get(theater, [])
                    if len(av_hist) >= 3:
                        counts = [c for _, c in av_hist[:-1]]
                        mean = sum(counts) / len(counts)
                        if mean > 0:
                            change_pct = ((count - mean) / mean) * 100
                            sit.aviation_change_pct = change_pct
                            if abs(change_pct) > 10 and self._should_emit(theater, "Aviation", change_pct, 5.0):
                                airport_name = airport_data.get("airport", theater)
                                tname = sit.theater_name
                                if change_pct < 0:
                                    desc = f"civilian flights near {airport_name} ({tname}) dropped {abs(change_pct):.0f}% below normal — airlines may be avoiding this airspace"
                                else:
                                    desc = f"civilian flights near {airport_name} ({tname}) increased {change_pct:.0f}% above normal"
                                new_wire.append(WireItem(
                                    ts=now, theater=theater, source="Aviation",
                                    text=f"OpenSky: {count} aircraft tracked — {desc}",
                                    severity=1 if abs(change_pct) > 20 else 0,
                                ))
                except Exception:
                    pass

            # ── Shipping (theater-agnostic but report if dark gaps exist) ──
            dark_gaps = ais_cache.get("dark_gaps", [])
            if dark_gaps:
                sit.shipping_dark_gaps = len(dark_gaps)

            # ── Forex ──
            try:
                from radar.climate_state import climate_engine
                forex_hist = climate_engine.forex._history
                # Find currency matching this theater
                for ccy, th_code in climate_engine.forex.CURRENCIES.items():
                    if th_code == theater:
                        with climate_engine.forex._lock:
                            rates = forex_hist.get(ccy, [])
                        if len(rates) >= 3:
                            vals = [r for _, r in rates]
                            latest = vals[-1]
                            mean = sum(vals[:-1]) / len(vals[:-1])
                            std = math.sqrt(sum((r - mean) ** 2 for r in vals[:-1]) / len(vals[:-1])) if len(vals) > 2 else 0.01
                            std = max(std, mean * 0.001)
                            z = (latest - mean) / std
                            sit.forex_z = z
                            if abs(z) > 1.0 and self._should_emit(theater, "Currency", z, 0.3):
                                prev = vals[-2]
                                daily_pct = ((latest - prev) / prev * 100) if prev else 0
                                tname = sit.theater_name
                                if z > 0:
                                    desc = f"{ccy} weakening against USD — potential capital flight or market stress in {tname}"
                                else:
                                    desc = f"{ccy} strengthening against USD — unusual currency movement for {tname}"
                                new_wire.append(WireItem(
                                    ts=now, theater=theater, source="Currency",
                                    text=f"{ccy}/USD at {latest:.2f} ({daily_pct:+.1f}% daily change, "
                                         f"{z:.1f}\u03c3 from baseline) — {desc}",
                                    severity=1 if z > 1.5 else 0,
                                ))
                        break
            except Exception:
                pass

            # ── Climate indicators active ──
            climate_evts = climate_events_by_theater.get(theater, [])
            if climate_evts:
                axes_active = {e["axis"] for e in climate_evts if e.get("axis") != "context"}
                indicators = list({e["indicator"] for e in climate_evts if e.get("axis") != "context"})
                sit.climate_axes_active = len(axes_active)
                sit.climate_indicators = sorted(indicators)

                # Convert climate events to wire items (use detail for richer text)
                _indicator_labels = {
                    "T2": "Media Tempo", "T4": "Search Trend",
                    "S1": "Aviation", "S2": "Shipping", "S3": "Currency",
                    "O1": "Cert Surge", "O3": "Narrative", "CAL": "Calendar",
                }
                for ev in climate_evts[:5]:  # Limit per theater
                    ind = ev.get("indicator", "CLM")
                    src_label = _indicator_labels.get(ind, ind)
                    sev = ev.get("severity", 0)
                    if self._should_emit(theater, src_label, sev, 0.5):
                        new_wire.append(WireItem(
                            ts=ev.get("ts", now),
                            theater=theater,
                            source=src_label,
                            text=ev.get("detail", "") or ev.get("headline", ""),
                            severity=sev,
                        ))

            # ── Convergence and threat from engine ──
            sit.convergence_level = strategic.get("convergence_level", "")
            sit.threat_level = strategic.get("threat_level", 5)

            # Per-theater threat from target details
            td = target_details.get(theater, {})
            if td:
                # Use velocity as additional escalation signal
                velocity = td.get("velocity", 0)
                if velocity and abs(velocity) > 0.5 and self._should_emit(theater, "Threat Engine", velocity, 0.3):
                    tname = sit.theater_name
                    if velocity > 0:
                        desc = f"threat score for {tname} is accelerating upward — increasing attack intensity"
                    else:
                        desc = f"threat score for {tname} is decelerating — attack intensity diminishing"
                    new_wire.append(WireItem(
                        ts=now, theater=theater, source="Threat Engine",
                        text=f"Threat velocity {velocity:+.2f} — {desc}",
                        severity=1 if abs(velocity) > 1.0 else 0,
                    ))

            # ── Compute direction vector ──
            sit.direction_score, sit.direction = self._compute_direction(theater, sit, now)

            new_situations[theater] = sit

        # Deduplicate wire: keep latest per (theater, source) per hour
        seen_wire = set()
        deduped_wire = []
        for w in reversed(new_wire):
            key = (w.theater, w.source, int(w.ts // 3600))
            if key not in seen_wire:
                seen_wire.add(key)
                deduped_wire.append(w)
        deduped_wire.reverse()

        # ── Cross-theater sync detection ──
        # Mark wire items that have near-simultaneous (30min) events in other theaters
        SYNC_WINDOW = 30 * 60  # 30 minutes
        notable = [w for w in deduped_wire if w.severity >= 1]
        for w in notable:
            synced = set()
            for other in notable:
                if other.theater == w.theater:
                    continue
                if abs(other.ts - w.ts) <= SYNC_WINDOW:
                    synced.add(other.theater)
            if synced:
                w.sync_theaters = sorted(synced)

        with self._lock:
            self._situations = new_situations

            # Merge wire: remove old matching keys, add new
            new_keys = {(w.theater, w.source, int(w.ts // 3600)) for w in deduped_wire}
            self._wire_history = [
                w for w in self._wire_history
                if (w.theater, w.source, int(w.ts // 3600)) not in new_keys
            ]
            self._wire_history.extend(deduped_wire)

            # Trim to 48h and max 500 items
            cutoff = now - 48 * 3600
            self._wire_history = [w for w in self._wire_history if w.ts > cutoff]
            self._wire_history = self._wire_history[-500:]

            # ── Temporal density per theater ──
            cutoff_6h = now - 6 * 3600
            cutoff_12h = now - 12 * 3600
            for theater, sit in self._situations.items():
                recent_6h = sum(1 for w in self._wire_history
                                if w.theater == theater and w.ts > cutoff_6h)
                prev_6h = sum(1 for w in self._wire_history
                              if w.theater == theater and cutoff_12h < w.ts <= cutoff_6h)
                sit.wire_density_6h = recent_6h
                if recent_6h > prev_6h + 2:
                    sit.wire_density_trend = "INCREASING"
                elif recent_6h < prev_6h - 2:
                    sit.wire_density_trend = "DECREASING"
                else:
                    sit.wire_density_trend = "STABLE"

            self._last_update = now

        # Persist new wire items to DB
        if deduped_wire:
            self._persist_wire(deduped_wire)

    def _compute_direction(self, theater: str, sit: TheaterSituation, now: float) -> tuple[float, str]:
        """Compute direction vector from multiple signal trends.

        Positive = escalating, negative = de-escalating, near-zero = stable.
        """
        signals = []

        # 1. GDELT tone trend (negative delta = escalating)
        if sit.tone_delta_7d is not None:
            # Normalize: delta of -3 ≈ strong escalation signal
            signals.append(-sit.tone_delta_7d / 3.0)

        # 2. Media concentration (high z = escalating)
        if sit.media_concentration is not None:
            signals.append(sit.media_concentration / 2.0)

        # 3. Aviation drop (negative change = escalating)
        if sit.aviation_change_pct is not None:
            signals.append(-sit.aviation_change_pct / 20.0)

        # 4. Forex stress (high z = escalating)
        if sit.forex_z is not None:
            signals.append(sit.forex_z / 2.0)

        # 5. Climate indicator convergence (more axes = more escalation)
        if sit.climate_axes_active > 0:
            signals.append(sit.climate_axes_active * 0.3)

        # 6. Tone history trend (slope over 7 days)
        with self._lock:
            tone_hist = list(self._tone_history.get(theater, []))
        if len(tone_hist) >= 4:
            # Simple linear slope using first/last halves
            mid = len(tone_hist) // 2
            first_half_avg = sum(v for _, v in tone_hist[:mid]) / mid
            second_half_avg = sum(v for _, v in tone_hist[mid:]) / (len(tone_hist) - mid)
            tone_slope = (second_half_avg - first_half_avg)
            # Negative slope (worsening tone) = escalation
            signals.append(-tone_slope / 2.0)

        if not signals:
            return 0.0, DIR_STABLE

        score = sum(signals) / len(signals)

        # Clamp to [-2, 2] range
        score = max(-2.0, min(2.0, score))

        if score > 0.3:
            return score, DIR_ESCALATING
        elif score < -0.3:
            return score, DIR_DE_ESCALATING
        return score, DIR_STABLE

    def get_board(self, theater_filter: str = "") -> dict:
        """Return full situation board for API."""
        with self._lock:
            situations = dict(self._situations)
            wire = list(self._wire_history)

        # Filter and sort by direction score (most escalating first)
        result = []
        for code, sit in sorted(situations.items(),
                                key=lambda x: -x[1].direction_score):
            if theater_filter and code != theater_filter:
                continue
            # Attach recent wire items for this theater (build dict without mutating shared object)
            theater_wire = [w for w in wire if w.theater == code]
            theater_wire.sort(key=lambda w: -w.ts)
            d = sit.to_dict()
            d["wire"] = [w.to_dict() for w in theater_wire[:10]]
            result.append(d)

        return {
            "theaters": result,
            "last_update": self._last_update,
        }

    def get_wire(self, theater: str = "", limit: int = 50) -> list[dict]:
        """Return wire items, optionally filtered by theater."""
        with self._lock:
            wire = list(self._wire_history)
        if theater:
            wire = [w for w in wire if w.theater == theater]
        wire.sort(key=lambda w: -w.ts)
        return [w.to_dict() for w in wire[:limit]]

    @staticmethod
    def _get_sensor_cache(registry, sensor_name: str, key: str = "") -> dict:
        """Safely retrieve sensor cache data."""
        sensor = registry.get(sensor_name)
        if not sensor:
            return {}
        cache = sensor.get_cache()
        if key:
            return cache.get(key, {})
        return cache
