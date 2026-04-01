"""radar.sensors.convergence_tracker -- ConvergenceTrackerSensor.

Detects PERSISTENT multi-sensor elevation across a theater over time.
Unlike the per-cycle convergence bonus in WeightedConvergenceEngine (which
rewards simultaneous firing in a single scoring cycle), this sensor watches
for sustained, cross-domain elevation over a configurable time window.

Theory:
  A single sensor spiking once = noise or isolated event.
  THREE OR MORE distinct sensors elevated SIMULTANEOUSLY for HOURS = pre-conflict
  pattern, consistent with historical pre-invasion intelligence.

Processing flow:
  Every cycle: snapshot each sensor's "elevated" state per theater
  → store timestamped snapshots in rolling SQLite window
  → if ≥ CONVERGENCE_MIN_SENSORS elevated for ≥ CONVERGENCE_MIN_HOURS:
      → LLM synthesis: explain the convergence pattern
      → intel_queue.submit() with source_type="convergence"

Sensor elevation criteria (tuned to be conservative — avoids false positives):
  rss_narrative     : is_burst = True
  diplomatic        : submitted > 0 in last window
  military_exercise : submitted > 0 in last window
  apt_intel         : submitted > 0 in last window
  telegram_mirror   : is_burst = True OR has_attack_intent = True
  gdelt             : z_score > 1.5 (sustained media negativity)
  ioda              : any theater outage active
  bgp_routing       : anomaly detected
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time

from radar.sensors.base import BaseSensor
from radar.config import LLM_ENABLED

log = logging.getLogger("radar")

_POLL_INTERVAL      = int(os.getenv("CONVERGENCE_TRACKER_INTERVAL", "3600"))   # 1 hour
_MIN_SENSORS        = int(os.getenv("CONVERGENCE_MIN_SENSORS", "3"))            # sensors that must be elevated
_MIN_HOURS          = float(os.getenv("CONVERGENCE_MIN_HOURS", "6"))            # sustained elevation window
_SNAPSHOT_RETENTION = int(os.getenv("CONVERGENCE_SNAPSHOT_RETENTION_H", "72")) # hours of history to keep

# One LLM alert per theater per day (avoid repeating for ongoing convergences)
_alerted: dict[str, float] = {}   # theater → last alert timestamp
_ALERT_COOLDOWN = 86400            # 24 hours


def _elevation_db_path() -> str:
    return os.path.join(
        os.getenv("DB_PATH", "persistence"),
        "convergence_snapshots.db"
    )


class _SnapshotDB:
    """Lightweight SQLite store for per-theater sensor elevation snapshots."""

    def __init__(self):
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            path = _elevation_db_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS snapshots ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  theater TEXT NOT NULL,"
                "  ts REAL NOT NULL,"
                "  elevated_sensors TEXT NOT NULL"  # JSON list of sensor names
                ")"
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_theater_ts ON snapshots(theater, ts)")
            self._conn.commit()
        return self._conn

    def record(self, theater: str, elevated_sensors: list[str]) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute(
                "INSERT INTO snapshots (theater, ts, elevated_sensors) VALUES (?, ?, ?)",
                (theater, time.time(), json.dumps(elevated_sensors))
            )
            conn.commit()

    def get_snapshots(self, theater: str, since_ts: float) -> list[dict]:
        with self._lock:
            conn = self._get_conn()
            rows = conn.execute(
                "SELECT ts, elevated_sensors FROM snapshots WHERE theater=? AND ts>=? ORDER BY ts ASC",
                (theater, since_ts)
            ).fetchall()
        return [{"ts": r[0], "sensors": json.loads(r[1])} for r in rows]

    def prune(self, cutoff_ts: float) -> None:
        with self._lock:
            conn = self._get_conn()
            conn.execute("DELETE FROM snapshots WHERE ts < ?", (cutoff_ts,))
            conn.commit()


_snapshot_db = _SnapshotDB()


def _is_elevated(sensor_name: str, cache: dict, theater: str) -> bool:
    """Return True if a sensor's cached data indicates elevated state for theater."""
    try:
        if sensor_name == "rss_narrative":
            return cache.get("narratives", {}).get(theater, {}).get("is_burst", False)

        if sensor_name == "telegram_mirror":
            td = cache.get("telegram", {}).get(theater, {})
            return td.get("is_burst", False) or td.get("has_attack_intent", False)

        if sensor_name == "gdelt":
            td = cache.get("gdelt_tones", cache).get(theater, cache.get(theater, {}))
            # gdelt cache structure varies; check z_score or dow_z_score
            z = td.get("dow_z_score", td.get("z_score", 0.0))
            if isinstance(z, (int, float)) and z > 1.5:
                return True
            delta = td.get("tone_delta")
            return isinstance(delta, (int, float)) and delta < -2.0

        if sensor_name == "diplomatic":
            return cache.get("diplomatic", {}).get("submitted", 0) > 0

        if sensor_name == "military_exercise":
            return cache.get("military_exercise", {}).get("submitted", 0) > 0

        if sensor_name == "apt_intel":
            return cache.get("apt_intel", {}).get("submitted", 0) > 0

        if sensor_name == "ioda":
            ioda_data = cache.get("ioda", {})
            theater_data = ioda_data.get(theater, {})
            return theater_data.get("is_outage", False) or theater_data.get("score", 0) > 0.3

        if sensor_name == "bgp_routing":
            bgp_data = cache.get("bgp", cache)
            theater_data = bgp_data.get(theater, {})
            return theater_data.get("anomaly_detected", False)

    except Exception:
        pass
    return False


# Sensors to monitor, in priority order
_MONITORED_SENSORS = [
    "diplomatic",
    "military_exercise",
    "apt_intel",
    "rss_narrative",
    "telegram_mirror",
    "gdelt",
    "ioda",
    "bgp_routing",
]


class ConvergenceTrackerSensor(BaseSensor):
    """Detects sustained multi-sensor convergence as a pre-conflict indicator."""

    def __init__(self):
        super().__init__("convergence_tracker", "info", _POLL_INTERVAL)

    def fetch(self, context: dict) -> dict:
        from radar.engine import SensorRegistry
        registry: SensorRegistry | None = context.get("_registry")
        if registry is None:
            self.log_fetch(True, 0, 0, 0, "no_registry")
            return {"convergence_tracker": {"error": "no_registry"}}

        strategic_theaters = context.get("strategic_theaters", [])
        t0 = time.time()
        alerts_submitted = 0
        now = time.time()
        window_start = now - _MIN_HOURS * 3600

        # Prune old snapshots
        _snapshot_db.prune(now - _SNAPSHOT_RETENTION * 3600)

        convergence_states: dict = {}

        for theater in strategic_theaters:
            # Build current snapshot: which sensors are elevated right now?
            elevated_now: list[str] = []
            for sensor_name in _MONITORED_SENSORS:
                sensor = registry.get(sensor_name)
                if sensor is None:
                    continue
                cache = sensor.get_cache() or {}
                if _is_elevated(sensor_name, cache, theater):
                    elevated_now.append(sensor_name)

            # Record snapshot (even if not elevated — gives continuous history)
            _snapshot_db.record(theater, elevated_now)

            # Check sustained convergence: how many distinct sensors were elevated
            # at least once during the window?
            snapshots = _snapshot_db.get_snapshots(theater, window_start)
            if len(snapshots) < 2:
                convergence_states[theater] = {"elevated_now": elevated_now, "converged": False}
                continue

            # Count sensors elevated in ≥50% of snapshots (sustained, not just one spike)
            sensor_hit_counts: dict[str, int] = {}
            for snap in snapshots:
                for s in snap["sensors"]:
                    sensor_hit_counts[s] = sensor_hit_counts.get(s, 0) + 1

            min_hits = max(1, len(snapshots) // 2)
            sustained_sensors = [s for s, count in sensor_hit_counts.items() if count >= min_hits]
            converged = len(sustained_sensors) >= _MIN_SENSORS

            convergence_states[theater] = {
                "elevated_now":      elevated_now,
                "sustained_sensors": sustained_sensors,
                "snapshot_count":    len(snapshots),
                "window_hours":      round(_MIN_HOURS, 1),
                "converged":         converged,
            }

            if not converged:
                continue

            # Check alert cooldown (avoid repeated alerts for same ongoing convergence)
            last_alert = _alerted.get(theater, 0.0)
            if now - last_alert < _ALERT_COOLDOWN:
                log.debug(f"[ConvergenceTracker] {theater}: converged but in cooldown")
                continue

            # LLM synthesis
            llm_submitted = self._submit_convergence_alert(
                theater, sustained_sensors, elevated_now, snapshots, registry
            )
            if llm_submitted:
                _alerted[theater] = now
                alerts_submitted += 1

        duration_ms = round((time.time() - t0) * 1000)
        self.log_fetch(True, duration_ms, 0, alerts_submitted)
        result_data = {"convergence_tracker": {
            "alerts_submitted": alerts_submitted,
            "theaters_checked": len(strategic_theaters),
            "states": convergence_states,
        }}
        self.set_cache(result_data)
        return result_data

    def _build_sensor_context(self, sustained_sensors: list[str], theater: str, registry) -> str:
        """Build rich context lines for each elevated sensor for LLM synthesis.

        Pulls actual intel queue headlines and sensor cache values so the LLM
        has real content to synthesize from rather than just sensor names.
        """
        from radar.database import db as _db
        lines = []
        for s in sustained_sensors:
            sensor = registry.get(s)
            cache = (sensor.get_cache() or {}) if sensor else {}

            if s == "rss_narrative":
                nd = cache.get("narratives", {}).get(theater, {})
                z = nd.get("z_score", nd.get("dow_z_score", "?"))
                theme = nd.get("dominant_theme", "")
                lines.append(f"  - rss_narrative: Z-score={z}" + (f", theme={theme!r}" if theme else ""))

            elif s == "gdelt":
                td = cache.get("gdelt_tones", cache).get(theater, cache.get(theater, {}))
                tone = td.get("tone_delta", td.get("mean_tone", "?"))
                lines.append(f"  - gdelt: tone_delta={tone} (negative = hostile media coverage)")

            elif s in ("diplomatic", "military_exercise", "apt_intel"):
                # Pull actual recent headlines from intel queue for substance
                recent = _db.intel_list(source_type=s if s != "apt_intel" else "apt",
                                        theater=theater, limit=2)
                if not recent:
                    recent = _db.intel_list(source_type=s, limit=2)
                if recent:
                    headlines = "; ".join(r.get("headline", "")[:80] for r in recent[:2])
                    lines.append(f"  - {s}: {headlines}")
                else:
                    lines.append(f"  - {s}: recent intel items submitted")

            elif s == "telegram_mirror":
                td = cache.get("telegram", {}).get(theater, {})
                status = td.get("status", "?")
                snippet = td.get("snippet", "")[:80]
                lines.append(f"  - telegram_mirror: status={status}" + (f", snippet={snippet!r}" if snippet else ""))

            elif s == "ioda":
                td = cache.get("ioda", {}).get(theater, {})
                lines.append(f"  - ioda: outage_score={td.get('score','?')}, is_outage={td.get('is_outage','?')}")

            elif s == "bgp_routing":
                lines.append(f"  - bgp_routing: BGP prefix anomaly detected for {theater}")

            else:
                lines.append(f"  - {s}: elevated")

        return "\n".join(lines)

    def _submit_convergence_alert(
        self,
        theater: str,
        sustained_sensors: list[str],
        elevated_now: list[str],
        snapshots: list[dict],
        registry,
    ) -> bool:
        """Build LLM synthesis of the convergence pattern and submit to intel_queue."""
        if not LLM_ENABLED:
            return False

        try:
            from radar.intel_queue import intel_queue
            from radar.llm_client import llm_analyze_json, llm_available, safe_float, safe_enum, today_str
        except Exception:
            return False

        if not llm_available():
            return False

        sensor_summary = self._build_sensor_context(sustained_sensors, theater, registry)
        window_h = round(_MIN_HOURS, 0)

        system_prompt = (
            "You are a strategic intelligence analyst. "
            "Multiple independent sensors have been simultaneously elevated for a sustained period, "
            "indicating a possible pre-conflict convergence pattern. "
            "Synthesize the available sensor signals into a coherent assessment. "
            "Respond ONLY with a JSON object, no explanation."
        )
        user_prompt = (
            f"Today's date: {today_str()}\n"
            f"Theater: {theater}\n"
            f"Convergence window: {window_h} hours\n"
            f"Sensors sustained as elevated ({len(sustained_sensors)} of {len(_MONITORED_SENSORS)}):\n"
            f"{sensor_summary}\n\n"
            "Return a JSON object:\n"
            "{\n"
            '  "headline": "One-sentence convergence assessment (max 100 chars)",\n'
            '  "pattern_type": "pre-conflict_buildup|active_conflict|escalation_spike|noise_convergence",\n'
            '  "dominant_domain": "cyber|physical|info|mixed",\n'
            '  "assessment": "2-3 sentence synthesis of what the multi-sensor pattern suggests",\n'
            '  "urgency": "critical|high|medium|low",\n'
            '  "confidence": 0.0\n'
            "}\n"
            "Confidence guide:\n"
            "- 0.75+: Physical + info + cyber domains all elevated with concrete evidence in each\n"
            "- 0.60-0.74: Two domains elevated with military or diplomatic sensor involved\n"
            "- 0.50-0.59: Multi-sensor but dominated by info domain (could be propaganda cycle)\n"
            "- <0.50: Convergence likely coincidental — set pattern_type=noise_convergence\n"
            "Be conservative. Set confidence < 0.55 if the pattern is ambiguous or if\n"
            "the elevated sensors are all info-domain (rss_narrative, gdelt, telegram)."
        )

        result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=400)
        if not result["ok"]:
            log.debug(f"[ConvergenceTracker] LLM parse failed for {theater}: {result.get('error')}")
            return False

        data = result["data"]
        confidence = safe_float(data.get("confidence"), default=0.0)

        _PATTERN_TYPES = {"pre-conflict_buildup", "active_conflict", "escalation_spike", "noise_convergence"}
        pattern_type = safe_enum(data.get("pattern_type"), _PATTERN_TYPES, "noise_convergence")

        if confidence < 0.50 or pattern_type == "noise_convergence":
            log.debug(f"[ConvergenceTracker] {theater}: LLM assessed as noise (conf={confidence:.2f})")
            return False

        urgency = safe_enum(data.get("urgency"), {"critical", "high", "medium", "low"}, "medium")

        # Additive scoring: base + sensor_bonus, capped to avoid disproportionate inflation
        # Max: 3.0 + min((8-3)*0.2, 1.0) = 4.0 (8 sensors all elevated at critical)
        base_score  = {"critical": 3.0, "high": 2.5, "medium": 2.0, "low": 1.5}.get(urgency, 2.0)
        sensor_bonus = round(min((len(sustained_sensors) - _MIN_SENSORS) * 0.2, 1.0), 1)
        score_delta = round(base_score + sensor_bonus, 1)

        # Use LLM-determined dominant_domain for accurate domain weighting
        _VALID_DOMAINS = {"cyber", "physical", "info", "mixed"}
        dominant_domain = safe_enum(data.get("dominant_domain"), _VALID_DOMAINS, "mixed")

        item = {
            "source_type":  "convergence",
            "source_id":    f"convergence_{theater.lower()}",
            "theater":      theater,
            "ts":           time.time(),
            "confidence":   round(confidence, 3),
            "raw_text":     f"Convergence: {', '.join(sustained_sensors)}\n{data.get('assessment', '')}",
            "raw_url":      "",
            "headline":     data.get("headline", f"Multi-sensor convergence: {theater} ({len(sustained_sensors)} sensors)")[:100],
            "llm_fields": {
                "pattern_type":      pattern_type,
                "dominant_domain":   dominant_domain,
                "sustained_sensors": sustained_sensors,
                "elevated_now":      elevated_now,
                "window_hours":      window_h,
                "snapshot_count":    len(snapshots),
                "assessment":        data.get("assessment", ""),
                "urgency":           urgency,
                "escalation_signal": True,
            },
            "score_delta":  score_delta,
            "domain":       dominant_domain,
        }

        item_id = intel_queue.submit(item)
        if item_id:
            log.info(
                f"[ConvergenceTracker] ALERT submitted: {item['headline'][:60]} "
                f"(theater={theater}, sensors={sustained_sensors}, conf={confidence:.2f}, urgency={urgency})"
            )
            return True
        return False
