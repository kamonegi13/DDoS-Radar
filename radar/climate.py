"""radar.climate -- Strategic Climate Engine.

Indirect intelligence indicators inspired by the "Pentagon Pizza Index":
observable behavioral byproducts that give analysts intuitive early warning
without directly measuring threats.

Indicators:
  T2  State media tempo anomaly    (reuses RSS narrative sensor data)
  T4  Search behavior proxy        (Google Trends via pytrends)
  S1  Civilian aviation rerouting  (reuses OpenSky sensor data)
  S2  Commercial shipping rerouting(reuses AIS maritime sensor data)
  S3  Forex volatility monitor     (new: ECB/exchangerate API)
  O1  Domain lookalike surge       (enhances CT Log sensor data)
  O3  Narrative target shift       (reuses GDELT + RSS data)

Context layers:
  Calendar anniversaries & diplomatic deadlines (curated data)
"""
from __future__ import annotations
import logging
import math
import threading
import time
import datetime
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("radar")

# ── Climate Feed Event ────────────────────────────────────────────────────────

AXIS_TIME = "time"
AXIS_SPACE = "space"
AXIS_TARGET = "target"
AXIS_CONTEXT = "context"

CLIMATE_LEVELS = ["FROZEN", "COOL", "WARMING", "HOT", "FLASHPOINT"]


@dataclass
class ClimateEvent:
    """A single observation in the Climate Feed."""
    ts: float                       # Unix timestamp
    indicator: str                  # e.g. "T2", "S1", "O3"
    axis: str                       # "time" | "space" | "target" | "context"
    headline: str                   # One-line English summary
    detail: str                     # Analyst-readable detail (raw fact)
    severity: int = 0               # 0=info, 1=notable, 2=significant
    theater: str = ""               # Related theater code (if applicable)
    meta: dict = field(default_factory=dict)  # Arbitrary extra data

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "ts_iso": datetime.datetime.fromtimestamp(self.ts, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "indicator": self.indicator,
            "axis": self.axis,
            "headline": self.headline,
            "detail": self.detail,
            "severity": self.severity,
            "theater": self.theater,
            "meta": self.meta,
        }


# ── Seasonal Baseline Utility ────────────────────────────────────────────────

class SeasonalBaseline:
    """Temporal-aware baseline with (weekday, 6h-bucket) granularity.

    Prevents false positives from regular cyclical patterns (e.g. weekend
    media silence, nighttime aviation drop, forex market closures).

    3-level fallback for cold-start:
      1. Exact (weekday, hour_bucket) — requires ≥3 samples
      2. Same hour_bucket across all weekdays — requires ≥3 samples
      3. All historical data (equivalent to flat average)
    """
    MIN_BUCKET_SAMPLES = 3

    def __init__(self, retention_days: int = 30):
        self._data: list[tuple[float, float]] = []  # (ts, value)
        self._retention = retention_days * 86400

    def record(self, value: float, ts: float = 0.0):
        """Record an observation. Call AFTER get_baseline() to keep baseline uncontaminated."""
        if ts == 0.0:
            ts = time.time()
        self._data.append((ts, value))
        # Lazy prune every 50 records
        if len(self._data) % 50 == 0:
            cutoff = ts - self._retention
            self._data = [(t, v) for t, v in self._data if t > cutoff]

    def get_baseline(self, ts: float = 0.0, std_floor: float = 0.5
                     ) -> tuple[float, float, int, str]:
        """Return (mean, std, sample_count, level) for the temporal bucket at *ts*.

        level: 'exact' | 'hour' | 'all' | 'none'
        Call BEFORE record() so current observation doesn't contaminate the baseline.
        """
        if ts == 0.0:
            ts = time.time()
        if len(self._data) < 2:
            return 0.0, 1.0, 0, "none"

        weekday, hour_bucket = self._bucket(ts)

        # Level 1: exact (weekday, hour_bucket)
        exact = [v for t, v in self._data if self._bucket(t) == (weekday, hour_bucket)]
        if len(exact) >= self.MIN_BUCKET_SAMPLES:
            mean, std = self._stats(exact, std_floor)
            return mean, std, len(exact), "exact"

        # Level 2: same hour_bucket, any weekday
        hourly = [v for t, v in self._data if self._bucket(t)[1] == hour_bucket]
        if len(hourly) >= self.MIN_BUCKET_SAMPLES:
            mean, std = self._stats(hourly, std_floor)
            return mean, std, len(hourly), "hour"

        # Level 3: all data
        all_vals = [v for _, v in self._data]
        mean, std = self._stats(all_vals, std_floor)
        return mean, std, len(all_vals), "all"

    def sample_count(self) -> int:
        """Total number of recorded observations."""
        return len(self._data)

    @staticmethod
    def _bucket(ts: float) -> tuple[int, int]:
        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
        return dt.weekday(), dt.hour // 6

    @staticmethod
    def _stats(values: list[float], std_floor: float) -> tuple[float, float]:
        n = len(values)
        mean = sum(values) / n
        std = (math.sqrt(sum((v - mean) ** 2 for v in values) / n)
               if n > 1 else std_floor)
        return mean, max(std, std_floor)


# ── Calendar Context ──────────────────────────────────────────────────────────

# Curated historical events for anniversary matching (month, day, description)
_HISTORICAL_CALENDAR = [
    (3, 8,  "1996 Taiwan Strait Crisis: PLA missile tests begin", "TW"),
    (3, 23, "1996 Taiwan presidential election amid missile crisis", "TW"),
    (7, 7,  "1937 Marco Polo Bridge Incident", "CN"),
    (8, 23, "2020 Belarus internet shutdown during protests", "BY"),
    (9, 18, "1931 Mukden Incident / Manchurian Incident", "CN"),
    (10, 1, "PRC National Day — heightened military posture", "CN"),
    (10, 10, "ROC National Day (Double Ten Day)", "TW"),
    (2, 24, "2022 Russia-Ukraine invasion begins", "UA"),
    (8, 8,  "2008 Russia-Georgia War begins", "GE"),
    (4, 1,  "2001 Hainan Island EP-3 incident", "CN"),
    (6, 25, "1950 Korean War begins", "KR"),
    (1, 13, "2021 Myanmar coup d'état", "MM"),
    (7, 25, "2015 Turkish strikes on PKK", "TR"),
    (9, 11, "2001 September 11 attacks", "US"),
    (5, 20, "Taiwan presidential inauguration day", "TW"),
    (4, 17, "2018 US Syria strikes", "SY"),
    (1, 3,  "2020 Soleimani assassination", "IR"),
    (11, 24, "2015 Turkey shoots down Russian Su-24", "TR"),
]


def get_calendar_context(now: Optional[datetime.datetime] = None) -> list[ClimateEvent]:
    """Return anniversary events within ±2 days of current date."""
    if now is None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
    events = []
    today = (now.month, now.day)
    for month, day, desc, theater in _HISTORICAL_CALENDAR:
        # Check ±2 day window
        try:
            event_date = now.replace(month=month, day=day)
        except ValueError:
            continue
        delta = abs((now.date() - event_date.date()).days)
        if delta <= 2:
            severity = 1 if delta == 0 else 0
            headline = f"Anniversary: {desc}" if delta == 0 else f"Near anniversary ({delta}d): {desc}"
            events.append(ClimateEvent(
                ts=now.timestamp(),
                indicator="CAL",
                axis=AXIS_CONTEXT,
                headline=headline,
                detail=desc,
                severity=severity,
                theater=theater,
                meta={"date": f"{month:02d}-{day:02d}", "delta_days": delta},
            ))
    return events


# ── T2: State Media Tempo Analysis ────────────────────────────────────────────

class MediaTempoAnalyzer:
    """Detects anomalous publication frequency in state media RSS feeds.

    Taps into RssNarrativeSensor's cache metadata — specifically article_count
    vs historical baseline. A dramatic change in publication tempo (surge or
    silence) is an operational byproduct, not content-based signal.

    Uses SeasonalBaseline (weekday × 6h bucket) to avoid false positives
    from regular weekly publication patterns (e.g. weekend media silence).
    """

    def __init__(self):
        self._baselines: dict[str, SeasonalBaseline] = {}  # theater -> baseline
        self._lock = threading.Lock()

    def analyze(self, registry) -> list[ClimateEvent]:
        """Analyze current RSS cache for tempo anomalies."""
        events = []
        now = time.time()
        rss = registry.get("rss_narrative")
        if not rss:
            return events
        cache = rss.get_cache()
        narratives = cache.get("narratives", {})

        for theater, data in narratives.items():
            article_count = data.get("article_count", 0)

            with self._lock:
                bl = self._baselines.setdefault(theater, SeasonalBaseline(7))
                mean, std, n, level = bl.get_baseline(now, std_floor=0.5)
                bl.record(article_count, now)

            if n < 4:
                continue

            z = (article_count - mean) / std

            if z > 1.5:
                sev = 2 if z > 3.5 else (1 if z > 2.5 else 0)
                events.append(ClimateEvent(
                    ts=now, indicator="T2", axis=AXIS_TIME,
                    headline=f"State media tempo surge: {theater}",
                    detail=f"{article_count} articles (baseline avg {mean:.0f}, {z:.1f}σ, {level}) — publication rate above normal",
                    severity=sev,
                    theater=theater,
                    meta={"article_count": article_count, "baseline_mean": round(mean, 1),
                          "z_score": round(z, 2), "baseline_level": level},
                ))
            elif z < -1.5 and mean > 2:
                events.append(ClimateEvent(
                    ts=now, indicator="T2", axis=AXIS_TIME,
                    headline=f"State media silence: {theater}",
                    detail=f"{article_count} articles vs baseline {mean:.0f} — unusual silence ({z:.1f}σ below normal, {level})",
                    severity=1 if z < -2.0 else 0,
                    theater=theater,
                    meta={"article_count": article_count, "baseline_mean": round(mean, 1),
                          "z_score": round(z, 2), "baseline_level": level},
                ))

        return events


# ── S1: Civilian Aviation Route Deviation ─────────────────────────────────────

class AviationRouteAnalyzer:
    """Detects changes in civilian aviation patterns near conflict zones.

    Monitors aircraft count per airport from OpenSky data. A sustained drop
    in flights near a conflict zone = airlines self-rerouting (skin in the game).
    """

    def __init__(self):
        self._baselines: dict[str, SeasonalBaseline] = {}  # airport -> baseline
        self._lock = threading.Lock()

    def analyze(self, registry) -> list[ClimateEvent]:
        events = []
        now = time.time()
        opensky = registry.get("opensky")
        if not opensky:
            return events
        cache = opensky.get_cache()
        airports = cache.get("airports", {})

        for code, data in airports.items():
            count = data.get("count", -1)
            if count < 0:
                continue

            with self._lock:
                bl = self._baselines.setdefault(code, SeasonalBaseline(7))
                mean, std, n, level = bl.get_baseline(now, std_floor=1.0)
                bl.record(count, now)

            if n < 6:
                continue
            if mean < 3:
                continue  # Too few flights for meaningful baseline

            z = (count - mean) / std

            if z < -1.5:
                drop_pct = round((1 - count / mean) * 100) if mean > 0 else 0
                airport_name = data.get("airport", code)
                sev = 2 if z < -3.0 else (1 if z < -2.0 else 0)
                events.append(ClimateEvent(
                    ts=now, indicator="S1", axis=AXIS_SPACE,
                    headline=f"Aviation drop near {airport_name}",
                    detail=f"{count} aircraft vs baseline {mean:.0f} ({drop_pct}% reduction, {z:.1f}σ, {level}) — possible airspace avoidance",
                    severity=sev,
                    theater=code,
                    meta={"airport": airport_name, "count": count, "baseline_mean": round(mean, 1),
                          "drop_pct": drop_pct, "z_score": round(z, 2), "baseline_level": level},
                ))

        return events


# ── S2: Commercial Shipping Rerouting ─────────────────────────────────────────

class ShippingRouteAnalyzer:
    """Detects changes in commercial shipping near chokepoints.

    Monitors AIS anomaly patterns. Increase in dark gaps or decrease in vessel
    density near cable landing stations = commercial shipping rerouting.
    """

    def __init__(self):
        self._history: list[tuple[float, int, int]] = []  # [(ts, dark_gaps, stationary)]
        self._lock = threading.Lock()

    def analyze(self, registry) -> list[ClimateEvent]:
        events = []
        now = time.time()
        ais = registry.get("ais_maritime")
        if not ais:
            return events
        cache = ais.get_cache()
        dark_gaps = cache.get("dark_gaps", [])
        stationary = cache.get("stationary_anomalies", [])

        n_dark = len(dark_gaps)
        n_stat = len(stationary)

        with self._lock:
            self._history.append((now, n_dark, n_stat))
            cutoff = now - 7 * 86400
            self._history = [(t, d, s) for t, d, s in self._history if t > cutoff]
            hist = list(self._history)

        if len(hist) < 4:
            return events

        dark_counts = [d for _, d, _ in hist[:-1]]
        dark_mean = sum(dark_counts) / len(dark_counts) if dark_counts else 0

        if n_dark > 0:
            # Group by chokepoint for detail
            cp_names = list({g["chokepoint"] for g in dark_gaps})
            sev = 2 if n_dark >= 3 else (1 if n_dark >= 2 or n_dark > dark_mean * 1.5 else 0)
            events.append(ClimateEvent(
                ts=now, indicator="S2", axis=AXIS_SPACE,
                headline=f"Shipping dark gaps: {n_dark} vessels",
                detail=f"{n_dark} AIS dark gaps detected near {', '.join(cp_names[:3])} (baseline avg {dark_mean:.0f}) — possible EMCON or rerouting",
                severity=sev,
                meta={"dark_gap_count": n_dark, "chokepoints": cp_names[:5],
                      "baseline_mean": round(dark_mean, 1)},
            ))

        return events


# ── S3: Forex Volatility Monitor ──────────────────────────────────────────────

class ForexMonitor:
    """Monitors currency stress for target countries.

    Fetches daily exchange rates from free API. Detects unusual volatility
    and correlation breakdowns between regional currencies.
    """

    # Target currencies mapped to theater codes
    CURRENCIES = {
        "TWD": "TW", "JPY": "JP", "KRW": "KR", "CNY": "CN",
        "PHP": "PH", "UAH": "UA", "RUB": "RU", "ILS": "IL",
    }

    def __init__(self):
        self._baselines: dict[str, SeasonalBaseline] = {}  # currency -> baseline
        self._prev_rates: dict[str, float] = {}             # currency -> last rate (for daily_change)
        self._lock = threading.Lock()
        self._last_fetch: float = 0.0

    def fetch_and_analyze(self) -> list[ClimateEvent]:
        """Fetch rates and produce climate events. Called periodically."""
        events = []
        now = time.time()

        # Rate limit: once per 4 hours
        if now - self._last_fetch < 14400:
            return self._analyze_existing(now)

        try:
            import requests
            from radar.config import GLOBAL_PROXIES, SSL_VERIFY
            resp = requests.get(
                "https://api.exchangerate-api.com/v4/latest/USD",
                timeout=15, proxies=GLOBAL_PROXIES, verify=SSL_VERIFY
            )
            if resp.status_code != 200:
                log.warning(f"[Climate/Forex] HTTP {resp.status_code}")
                return events
            data = resp.json()
            rates = data.get("rates", {})
            self._last_fetch = now

            with self._lock:
                for ccy in self.CURRENCIES:
                    rate = rates.get(ccy)
                    if rate:
                        bl = self._baselines.setdefault(ccy, SeasonalBaseline(30))
                        bl.record(rate, now)
                        self._prev_rates[ccy] = rate

            log.info(f"[Climate/Forex] Updated {len(self.CURRENCIES)} currencies")
        except Exception as e:
            log.warning(f"[Climate/Forex] Fetch error: {e}")

        return self._analyze_existing(now)

    def _analyze_existing(self, now: float) -> list[ClimateEvent]:
        events = []
        with self._lock:
            for ccy, theater in self.CURRENCIES.items():
                bl = self._baselines.get(ccy)
                if not bl or bl.sample_count() < 7:
                    continue  # Need ≥7 samples for meaningful z-scores
                latest_rate = self._prev_rates.get(ccy)
                if latest_rate is None:
                    continue

                # Get baseline with std floor at 0.5% of mean (forex daily noise)
                mean, std, n, level = bl.get_baseline(now, std_floor=0.01)
                # Apply proportional floor: 0.5% of mean
                std = max(std, mean * 0.005) if mean > 0 else std

                z = (latest_rate - mean) / std

                # Compute daily change from previous fetch
                # (prev_rates stores the most recent rate; we need second-latest)
                # Use baseline data to approximate previous
                prev = mean  # Fallback: compare against baseline mean
                if bl.sample_count() >= 2:
                    prev = bl._data[-2][1]  # Second-latest raw observation
                daily_change_pct = ((latest_rate - prev) / prev * 100) if prev else 0

                # Weakening = rate going up for most currencies (more local per USD)
                # Thresholds: z > 2.0 filters out normal daily fluctuation noise
                if z > 2.0 or daily_change_pct > 2.0:
                    sev = 2 if z > 3.5 else (1 if z > 2.5 or daily_change_pct > 2.0 else 0)
                    events.append(ClimateEvent(
                        ts=now, indicator="S3", axis=AXIS_SPACE,
                        headline=f"{ccy} weakening: +{daily_change_pct:.1f}% vs USD",
                        detail=f"{ccy}/USD at {latest_rate:.2f} (baseline {mean:.2f}, {z:.1f}σ, {level}) — capital stress signal for {theater}",
                        severity=sev,
                        theater=theater,
                        meta={"currency": ccy, "rate": latest_rate, "baseline_mean": round(mean, 4),
                              "daily_change_pct": round(daily_change_pct, 2), "z_score": round(z, 2),
                              "baseline_level": level},
                    ))
        return events


# ── T4: Search Behavior Proxy ─────────────────────────────────────────────────

class SearchBehaviorAnalyzer:
    """Google Trends crisis keyword monitoring.

    The modern Pentagon Pizza Index: millions of people "voting with their searches."
    Tracks crisis-related keywords in target countries.
    """

    # Keywords by language/country
    KEYWORD_SETS = {
        "TW": {"keywords": ["VPN", "防空避難", "護照更新", "軍事演習", "撤離"], "geo": "TW"},
        "JP": {"keywords": ["VPN", "避難", "パスポート更新", "有事", "防空壕"], "geo": "JP"},
        "KR": {"keywords": ["VPN", "대피", "여권갱신", "비상사태", "방공호"], "geo": "KR"},
        "UA": {"keywords": ["VPN", "евакуація", "бомбосховище", "паспорт", "виїзд"], "geo": "UA"},
    }

    def __init__(self):
        self._cache: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._last_fetch: float = 0.0
        self._available = None  # None = not checked yet

    def _check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            from pytrends.request import TrendReq  # noqa: F401
            self._available = True
        except ImportError:
            log.info("[Climate/T4] pytrends not installed — Search Behavior indicator disabled")
            self._available = False
        return self._available

    def fetch_and_analyze(self) -> list[ClimateEvent]:
        """Fetch Google Trends data and produce events. Called periodically."""
        events = []
        now = time.time()

        if not self._check_available():
            return events

        # Rate limit: once per 6 hours (Google Trends is aggressive with rate limits)
        if now - self._last_fetch < 21600:
            return self._analyze_cached(now)

        try:
            from pytrends.request import TrendReq
            pytrends = TrendReq(hl='en-US', tz=0, timeout=(10, 25))

            for theater, cfg in self.KEYWORD_SETS.items():
                try:
                    pytrends.build_payload(
                        cfg["keywords"][:5],
                        cat=0, timeframe="now 7-d", geo=cfg["geo"]
                    )
                    df = pytrends.interest_over_time()
                    if df is not None and not df.empty:
                        # Get latest values and 7-day averages
                        result = {}
                        for kw in cfg["keywords"][:5]:
                            if kw in df.columns:
                                vals = df[kw].tolist()
                                latest = vals[-1] if vals else 0
                                avg = sum(vals[:-1]) / max(len(vals) - 1, 1) if len(vals) > 1 else 0
                                result[kw] = {"latest": latest, "avg": round(avg, 1)}
                        with self._lock:
                            self._cache[theater] = {"data": result, "ts": now}
                    time.sleep(2)  # Be polite to Google
                except Exception as e:
                    log.debug(f"[Climate/T4] Trends fetch error for {theater}: {e}")

            self._last_fetch = now
        except Exception as e:
            log.warning(f"[Climate/T4] Google Trends error: {e}")

        return self._analyze_cached(now)

    def _analyze_cached(self, now: float) -> list[ClimateEvent]:
        events = []
        with self._lock:
            for theater, cached in self._cache.items():
                data = cached.get("data", {})
                spikes = []
                for kw, vals in data.items():
                    latest = vals.get("latest", 0)
                    avg = vals.get("avg", 0)
                    if avg > 0 and latest > avg * 1.5:
                        ratio = latest / avg
                        spikes.append((kw, latest, avg, ratio))

                if spikes:
                    top = sorted(spikes, key=lambda x: -x[3])[:3]
                    detail_parts = [f'"{kw}" {ratio:.1f}× above baseline' for kw, _, _, ratio in top]
                    max_ratio = top[0][3]
                    sev = 2 if max_ratio > 4.0 else (1 if max_ratio > 2.0 else 0)
                    events.append(ClimateEvent(
                        ts=now, indicator="T4", axis=AXIS_TIME,
                        headline=f"Crisis search surge in {theater}",
                        detail=f"Google Trends spike in {theater}: {'; '.join(detail_parts)}",
                        severity=sev,
                        theater=theater,
                        meta={"spikes": [{"keyword": kw, "latest": l, "avg": a, "ratio": round(r, 1)} for kw, l, a, r in top]},
                    ))
        return events


# ── O1: Domain Lookalike Surge ────────────────────────────────────────────────

class DomainLookalikeAnalyzer:
    """Detects surge in certificate issuance for government/military lookalike domains.

    Enhances existing CT Log sensor data by analyzing patterns of certificate
    issuance targeting specific country domains.
    """

    def analyze(self, registry) -> list[ClimateEvent]:
        events = []
        now = time.time()
        ct = registry.get("ct_log")
        if not ct:
            return events
        cache = ct.get_cache()
        ct_data = cache.get("ct_data", {})
        status_map = cache.get("country_status", {})

        for country, data in ct_data.items():
            status = status_map.get(country, "NORMAL")

            gov_count = data.get("gov_count", 0)
            wildcard_count = data.get("wildcard_count", 0)
            surge_pct = data.get("surge_pct", 0)
            total = data.get("total_recent", 0)
            recent_certs = data.get("recent_certs", [])

            if status == "GOV_CERT_SURGE":
                cert_names = [c["name"] for c in recent_certs[:3]]
                events.append(ClimateEvent(
                    ts=now, indicator="O1", axis=AXIS_TARGET,
                    headline=f"Gov domain cert surge: {country}",
                    detail=f"{gov_count} government domain certs for {country} ({wildcard_count} wildcards). Recent: {', '.join(cert_names)}",
                    severity=2,
                    theater=country,
                    meta={"gov_count": gov_count, "wildcard_count": wildcard_count,
                          "total": total, "recent_certs": cert_names},
                ))
            elif status == "CERT_SURGE":
                sev = 1 if surge_pct > 0.5 else 0
                events.append(ClimateEvent(
                    ts=now, indicator="O1", axis=AXIS_TARGET,
                    headline=f"Certificate issuance surge: {country}",
                    detail=f"{total} certs for {country} domains (+{surge_pct:.0%} vs previous cycle)",
                    severity=sev,
                    theater=country,
                    meta={"total": total, "surge_pct": round(surge_pct, 2)},
                ))
            elif gov_count > 0 and status != "NORMAL":
                # Any government cert activity worth noting
                events.append(ClimateEvent(
                    ts=now, indicator="O1", axis=AXIS_TARGET,
                    headline=f"Gov domain cert activity: {country}",
                    detail=f"{gov_count} government domain certs detected for {country}",
                    severity=0,
                    theater=country,
                    meta={"gov_count": gov_count, "total": total},
                ))

        return events


# ── O3: Narrative Target Shift ────────────────────────────────────────────────

class NarrativeTargetAnalyzer:
    """Detects shifts in who state media is targeting.

    Tracks which countries/entities are receiving hostile media tone.
    A shift in targeting reveals strategic intent.
    """

    def __init__(self):
        self._history: dict[str, list[tuple[float, float]]] = {}  # country -> [(ts, tone)]
        self._lock = threading.Lock()

    def analyze(self, registry) -> list[ClimateEvent]:
        events = []
        now = time.time()
        gdelt = registry.get("gdelt")
        if not gdelt:
            return events
        cache = gdelt.get_cache()
        tones = cache.get("gdelt_tones", {})

        targets_hostile = []
        for country, data in tones.items():
            tone = data.get("tone_current")
            baseline = data.get("tone_baseline")
            delta = data.get("delta")
            dow_z = data.get("dow_z")
            is_alert = data.get("is_alert", False)

            if tone is None:
                continue

            # Record history
            with self._lock:
                hist = self._history.setdefault(country, [])
                hist.append((now, tone))
                cutoff = now - 14 * 86400
                self._history[country] = [(t, v) for t, v in hist if t > cutoff]

            if delta is not None and delta < -1.5:
                targets_hostile.append((country, tone, delta, dow_z, is_alert))

        # Report hostile or shifting tone targets
        for country, tone, delta, dow_z, is_alert in sorted(targets_hostile, key=lambda x: x[2]):
            z_str = f", DoW Z-score {dow_z:.1f}" if dow_z is not None else ""
            sev = 2 if delta < -5 else (1 if delta < -3 or is_alert else 0)
            events.append(ClimateEvent(
                ts=now, indicator="O3", axis=AXIS_TARGET,
                headline=f"Narrative tone shift: {country}",
                detail=f"GDELT tone {tone:.1f} (Δ{delta:+.1f} from baseline{z_str}) — media hostility directed at {country}",
                severity=sev,
                theater=country,
                meta={"tone": round(tone, 1), "delta": round(delta, 1),
                      "dow_z": round(dow_z, 1) if dow_z else None},
            ))

        return events


# ── Strategic Climate Engine ──────────────────────────────────────────────────

class StrategicClimateEngine:
    """Aggregates all climate indicators and computes the Climate Gauge."""

    def __init__(self):
        self.media_tempo = MediaTempoAnalyzer()
        self.aviation_route = AviationRouteAnalyzer()
        self.shipping_route = ShippingRouteAnalyzer()
        self.forex = ForexMonitor()
        self.search_behavior = SearchBehaviorAnalyzer()
        self.domain_lookalike = DomainLookalikeAnalyzer()
        self.narrative_target = NarrativeTargetAnalyzer()

        self._feed: list[ClimateEvent] = []
        self._gauge_level: str = "COOL"
        self._gauge_score: float = 0.0
        self._lock = threading.Lock()
        self._last_update: float = 0.0
        self._restore_from_db()

    def _restore_from_db(self):
        """Load persisted climate events from SQLite on startup."""
        try:
            from radar.database import db
            cutoff = time.time() - 48 * 3600
            rows = db.climate_events_load(cutoff)
            if rows:
                for r in rows:
                    self._feed.append(ClimateEvent(
                        ts=r["ts"], indicator=r["indicator"], axis=r["axis"],
                        headline=r["headline"], detail=r["detail"],
                        severity=r["severity"], theater=r["theater"],
                        meta=r.get("meta", {}),
                    ))
                self._gauge_score, self._gauge_level = self._compute_gauge()
                log.info(f"[Climate] Restored {len(rows)} events from DB")
        except Exception as e:
            log.debug(f"[Climate] DB restore skipped: {e}")

    def _persist_to_db(self, events: list[ClimateEvent]):
        """Save new climate events to SQLite."""
        try:
            from radar.database import db
            db.climate_events_save([{
                "ts": e.ts, "indicator": e.indicator, "axis": e.axis,
                "headline": e.headline, "detail": e.detail,
                "severity": e.severity, "theater": e.theater,
                "meta": e.meta,
            } for e in events])
        except Exception as e:
            log.debug(f"[Climate] DB persist error: {e}")

    def update(self, registry) -> dict:
        """Run all analyzers and update the climate feed. Returns summary dict."""
        now = time.time()
        new_events: list[ClimateEvent] = []

        # Existing-data analyzers (cheap, run every cycle)
        new_events.extend(self.media_tempo.analyze(registry))
        new_events.extend(self.aviation_route.analyze(registry))
        new_events.extend(self.shipping_route.analyze(registry))
        new_events.extend(self.domain_lookalike.analyze(registry))
        new_events.extend(self.narrative_target.analyze(registry))

        # External API analyzers (self-rate-limited)
        new_events.extend(self.forex.fetch_and_analyze())
        new_events.extend(self.search_behavior.fetch_and_analyze())

        # Calendar context
        new_events.extend(get_calendar_context())

        # Deduplicate: keep latest per (indicator, theater) combo per hour
        seen = set()
        deduped = []
        for ev in reversed(new_events):
            key = (ev.indicator, ev.theater, int(ev.ts // 3600))
            if key not in seen:
                seen.add(key)
                deduped.append(ev)
        deduped.reverse()

        # Update feed: replace existing events with same (indicator, theater, hour)
        with self._lock:
            cutoff = now - 48 * 3600
            self._feed = [e for e in self._feed if e.ts > cutoff]

            # Remove old entries that match new ones by (indicator, theater, hour)
            new_keys = {(e.indicator, e.theater, int(e.ts // 3600)) for e in deduped}
            self._feed = [e for e in self._feed
                          if (e.indicator, e.theater, int(e.ts // 3600)) not in new_keys]
            self._feed.extend(deduped)
            self._feed = self._feed[-200:]

            # Compute gauge
            self._gauge_score, self._gauge_level = self._compute_gauge()
            self._last_update = now

            # Persist new events to DB (inside lock to prevent race with _restore_from_db)
            if deduped:
                self._persist_to_db(deduped)

        return self.get_summary()

    def _compute_gauge(self) -> tuple[float, str]:
        """Compute climate gauge from recent events (last 6 hours).

        Design: measures "how many distinct signals are currently active"
        rather than "how many events accumulated over time."
        Each unique (indicator, theater) pair counts ONCE using its max severity.
        This prevents persistent low-severity conditions from inflating the score.
        """
        now = time.time()
        cutoff = now - 6 * 3600
        recent = [e for e in self._feed if e.ts > cutoff and e.axis != AXIS_CONTEXT]

        if not recent:
            return 0.0, "FROZEN"

        # Deduplicate: per (indicator, theater), keep MAX severity seen in window
        # This prevents the same signal repeating every hour from accumulating 6×
        signal_max: dict[tuple[str, str], int] = {}
        for e in recent:
            key = (e.indicator, e.theater)
            signal_max[key] = max(signal_max.get(key, 0), e.severity)

        # Score: weight each unique signal by its max severity
        sev_weights = {0: 0.2, 1: 1.0, 2: 2.0}
        sev0_signals = sum(1 for s in signal_max.values() if s == 0)
        sev0_score = min(sev0_signals * 0.2, 2.0)  # Cap sev=0 contribution
        sev12_score = sum(sev_weights.get(s, 0) for s in signal_max.values() if s > 0)
        base_score = sev12_score + sev0_score

        # Convergence bonus: reward genuine cross-domain convergence on SAME theater
        # Indicator-to-domain mapping (independent analysis axes)
        _INDICATOR_DOMAIN = {
            "T2": "info", "T4": "info",     # Information domain
            "S1": "physical", "S2": "physical",  # Physical domain
            "S3": "economic",                # Economic domain (independent)
            "O1": "cyber", "O3": "info",     # Note: O3 shares info domain with T2
        }
        # Per-theater: count how many DIFFERENT domains have active signals
        theater_domains: dict[str, set] = {}
        for (indicator, theater), sev in signal_max.items():
            if theater and sev > 0:  # Only count sev>=1 for convergence
                domain = _INDICATOR_DOMAIN.get(indicator, indicator)
                theater_domains.setdefault(theater, set()).add(domain)
        # Convergence bonus: theaters with 2+ domains converging (genuine multi-domain signal)
        convergence_bonus = sum(
            (len(domains) - 1) * 0.5
            for domains in theater_domains.values()
            if len(domains) >= 2
        )
        convergence_bonus = min(convergence_bonus, 3.0)  # Cap

        total = base_score + convergence_bonus

        # Map to level
        if total >= 15:
            return total, "FLASHPOINT"
        elif total >= 8:
            return total, "HOT"
        elif total >= 3:
            return total, "WARMING"
        elif total > 0:
            return total, "COOL"
        return 0.0, "FROZEN"

    def get_summary(self) -> dict:
        """Return current climate state for API consumption."""
        with self._lock:
            now = time.time()
            recent_events = [e for e in self._feed if e.ts > now - 24 * 3600]
            # Indicators breakdown
            indicator_counts = {}
            for e in recent_events:
                if e.axis != AXIS_CONTEXT:
                    indicator_counts[e.indicator] = indicator_counts.get(e.indicator, 0) + 1

            return {
                "gauge": {
                    "level": self._gauge_level,
                    "score": round(self._gauge_score, 1),
                    "levels": CLIMATE_LEVELS,
                },
                "feed": [e.to_dict() for e in reversed(recent_events[-50:])],
                "indicators_active": indicator_counts,
                "last_update": self._last_update,
                "calendar": [e.to_dict() for e in recent_events if e.axis == AXIS_CONTEXT],
            }

    def get_feed(self, axis: str = "", limit: int = 50) -> list[dict]:
        """Return filtered feed events."""
        with self._lock:
            events = self._feed
            if axis:
                events = [e for e in events if e.axis == axis]
            return [e.to_dict() for e in reversed(events[-limit:])]
