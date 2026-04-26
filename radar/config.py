"""radar.config -- Configuration constants and geo data loading."""
from __future__ import annotations
import os
import json
import logging
import urllib3

log = logging.getLogger("radar")

def _load_env(path: str = "config.env") -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv(path)
        log.info(f"[Config] Loaded via python-dotenv: {path}")
        return
    except ImportError:
        pass
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
        log.info(f"[Config] Loaded manually: {path}")
    except FileNotFoundError:
        log.info(f"[Config] {path} not found — using defaults")


_load_env()

COUNTRY_COORDS, STATE_ASNS, AIRPORT_BOXES, CHOKEPOINTS = {}, {}, {}, []

# Country → Region mapping for UI grouping
COUNTRY_REGIONS: dict[str, str] = {
    # East Asia
    "CN": "East Asia", "JP": "East Asia", "KR": "East Asia", "TW": "East Asia",
    "KP": "East Asia", "MN": "East Asia", "HK": "East Asia", "MO": "East Asia",
    # SE Asia
    "PH": "SE Asia", "VN": "SE Asia", "TH": "SE Asia", "ID": "SE Asia",
    "MY": "SE Asia", "SG": "SE Asia", "MM": "SE Asia", "KH": "SE Asia",
    "LA": "SE Asia", "TL": "SE Asia", "BN": "SE Asia",
    # South Asia
    "IN": "S. Asia", "PK": "S. Asia", "BD": "S. Asia", "LK": "S. Asia",
    "NP": "S. Asia", "MV": "S. Asia", "AF": "S. Asia", "BT": "S. Asia",
    # Central Asia
    "KZ": "C. Asia", "UZ": "C. Asia", "KG": "C. Asia", "TJ": "C. Asia",
    "TM": "C. Asia", "AZ": "C. Asia", "AM": "C. Asia", "GE": "C. Asia",
    # Middle East
    "IR": "Middle East", "IQ": "Middle East", "SA": "Middle East", "AE": "Middle East",
    "IL": "Middle East", "YE": "Middle East", "SY": "Middle East", "LB": "Middle East",
    "JO": "Middle East", "KW": "Middle East", "QA": "Middle East", "OM": "Middle East",
    "BH": "Middle East", "TR": "Middle East",
    # North Africa
    "EG": "N. Africa", "LY": "N. Africa", "TN": "N. Africa", "DZ": "N. Africa",
    "MA": "N. Africa", "SD": "N. Africa",
    # Sub-Saharan Africa
    "NG": "Africa", "GH": "Africa", "SN": "Africa", "ET": "Africa",
    "KE": "Africa", "TZ": "Africa", "ZA": "Africa", "RW": "Africa",
    "UG": "Africa", "ZM": "Africa", "ZW": "Africa", "AO": "Africa",
    "CD": "Africa", "CM": "Africa", "CI": "Africa", "MG": "Africa",
    "MZ": "Africa", "ML": "Africa", "NE": "Africa",
    # Western Europe
    "GB": "W. Europe", "FR": "W. Europe", "DE": "W. Europe", "IT": "W. Europe",
    "ES": "W. Europe", "NL": "W. Europe", "BE": "W. Europe", "PT": "W. Europe",
    "CH": "W. Europe", "AT": "W. Europe", "IE": "W. Europe", "GR": "W. Europe",
    "LU": "W. Europe", "MT": "W. Europe", "CY": "W. Europe", "IS": "W. Europe",
    "AD": "W. Europe",
    # Northern Europe
    "SE": "N. Europe", "NO": "N. Europe", "DK": "N. Europe", "FI": "N. Europe",
    "EE": "N. Europe", "LV": "N. Europe", "LT": "N. Europe",
    # Eastern Europe
    "UA": "E. Europe", "PL": "E. Europe", "CZ": "E. Europe", "SK": "E. Europe",
    "HU": "E. Europe", "RO": "E. Europe", "BG": "E. Europe", "BY": "E. Europe",
    "MD": "E. Europe", "RS": "E. Europe", "HR": "E. Europe", "BA": "E. Europe",
    "AL": "E. Europe", "MK": "E. Europe", "ME": "E. Europe", "SI": "E. Europe",
    "XK": "E. Europe",
    # Russia
    "RU": "Russia",
    # North America
    "US": "N. America", "CA": "N. America", "MX": "N. America", "PR": "N. America",
    # Latin America
    "BR": "L. America", "AR": "L. America", "CO": "L. America", "CL": "L. America",
    "PE": "L. America", "VE": "L. America", "EC": "L. America", "BO": "L. America",
    "UY": "L. America", "PY": "L. America", "GY": "L. America", "SR": "L. America",
    # Caribbean / C. America
    "CU": "Caribbean", "DO": "Caribbean", "JM": "Caribbean",
    "GT": "Caribbean", "HN": "Caribbean", "SV": "Caribbean",
    "CR": "Caribbean", "PA": "Caribbean", "NI": "Caribbean",
    # Oceania
    "AU": "Oceania", "NZ": "Oceania", "MU": "Oceania", "FJ": "Oceania",
    "PG": "Oceania", "GU": "Oceania",
}
ISR_HOTSPOTS: list = []
ADVERSARY_NARRATIVE_SOURCES: dict = {}   # keyed by adversary country code (RU/CN/IR/KP/BY)
STRATEGIC_BLOCS: dict = {}               # bloc definitions for UI grouping
COUNTRY_BLOC_TAGS: dict = {}             # country -> list of blocs (multi-threat countries)
TACTICAL_KEYWORDS: dict = {}
NARRATIVE_GEO_TERMS: dict = {}
CABLE_ROUTES: list = []
THREAT_ACTOR_MAPPING:  dict = {}
INFRASTRUCTURE_URLS:   dict = {}
TELEGRAM_CHANNEL_META: dict = {}
_raw_geo: dict = {}
try:
    with open("geo_data.json", "r", encoding="utf-8") as f:
        geo_data = json.load(f)
        COUNTRY_COORDS      = geo_data.get("COUNTRY_COORDS", {})
        STATE_ASNS          = geo_data.get("STATE_ASNS", {})
        AIRPORT_BOXES       = geo_data.get("AIRPORT_BOXES", {})
        CHOKEPOINTS         = geo_data.get("CHOKEPOINTS", [])
        ISR_HOTSPOTS        = geo_data.get("ISR_HOTSPOTS", [])
        ADVERSARY_NARRATIVE_SOURCES = geo_data.get("ADVERSARY_NARRATIVE_SOURCES", {})
        STRATEGIC_BLOCS     = geo_data.get("STRATEGIC_BLOCS", {})
        COUNTRY_BLOC_TAGS   = geo_data.get("COUNTRY_BLOC_TAGS", {})
        TACTICAL_KEYWORDS   = geo_data.get("TACTICAL_KEYWORDS", {})
        NARRATIVE_GEO_TERMS = geo_data.get("NARRATIVE_GEO_TERMS", {})
        CABLE_ROUTES        = geo_data.get("CABLE_ROUTES", [])
        THREAT_ACTOR_MAPPING   = geo_data.get("THREAT_ACTOR_MAPPING", {})
        INFRASTRUCTURE_URLS    = geo_data.get("INFRASTRUCTURE_URLS", {})
        TELEGRAM_CHANNEL_META  = geo_data.get("TELEGRAM_CHANNEL_META", {})
        _raw_geo = geo_data  # Expose full geo_data for calendar scheduled events
        log.info("[Config] Loaded static data from geo_data.json")
except Exception as e:
    log.warning(f"Failed to load geo_data.json: {e}")

# ── Proxy & SSL Configuration ──
HTTP_PROXY  = os.getenv("HTTP_PROXY", "")
HTTPS_PROXY = os.getenv("HTTPS_PROXY", "")
GLOBAL_PROXIES = {}
if HTTP_PROXY:  GLOBAL_PROXIES["http"]  = HTTP_PROXY
if HTTPS_PROXY: GLOBAL_PROXIES["https"] = HTTPS_PROXY

SSL_VERIFY_ENV = os.getenv("SSL_VERIFY", "true").lower()
SSL_VERIFY = False if SSL_VERIFY_ENV in ("false", "0", "no") else True

if not SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    log.warning("SSL Verification is DISABLED via config.env")

CF_API_TOKEN               = os.getenv("CF_API_TOKEN", "")
OWM_API_KEY                = os.getenv("OWM_API_KEY", "")
CURRENT_DATE_RANGE         = os.getenv("CURRENT_DATE_RANGE",  "1d")
BASELINE_DATE_RANGE        = os.getenv("BASELINE_DATE_RANGE", "28d")
CACHE_EXPIRY               = int(os.getenv("CACHE_EXPIRY", "900"))
SCORE_REFRESH_SEC          = int(os.getenv("SCORE_REFRESH_SEC", "60"))   # Minimum scoring recalculation interval (seconds)
SERVER_HOST                = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT                = int(os.getenv("SERVER_PORT", "8000"))
FLASK_DEBUG                = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")


# Scenario-centric scoring (ADR-005/P1). All per-country lists are derived
# from the focused scenario's participants at request time; legacy
# DEFAULT_CORE/CORRELATES/ADVERSARIES/PINS env vars have been removed.
DEFAULT_FOCUSED_SCENARIO = os.getenv("DEFAULT_FOCUSED_SCENARIO", "taiwan_contingency")
GLOBAL_SIGNAL_WEIGHT     = float(os.getenv("GLOBAL_SIGNAL_WEIGHT", "0.5"))
DOMAIN_CAP               = float(os.getenv("DOMAIN_CAP", "6.0"))

# C-lite → C-medium migration evaluation (scenario-refactor §9.3.1).
# A focus switch is a "miss" when |full_score - lite_score| > C_MEDIUM_DELTA_MISS.
# If the miss-rate over a C_MEDIUM_WINDOW_DAYS window exceeds
# C_MEDIUM_MISS_THRESHOLD, the evaluator recommends migrating that scenario
# to C-medium (per-country low-frequency fetches for background participants).
C_MEDIUM_WINDOW_DAYS    = int(os.getenv("C_MEDIUM_WINDOW_DAYS", "28"))
C_MEDIUM_MISS_THRESHOLD = float(os.getenv("C_MEDIUM_MISS_THRESHOLD", "0.15"))
C_MEDIUM_DELTA_MISS     = float(os.getenv("C_MEDIUM_DELTA_MISS", "2.0"))
C_MEDIUM_MIN_SWITCHES   = int(os.getenv("C_MEDIUM_MIN_SWITCHES", "10"))

# Shadow Sampling (ADR-025). Background harness that synthesises (lite, full)
# score pairs for non-focused scenarios at low frequency, populating
# focus_switch_log with source='shadow_sampler' so that the C-medium
# recommendation does not depend on analyst focus rotation.
# - ENABLED: master switch.
# - INTERVAL_SEC=0 means "piggyback on the focused scoring cycle"; non-zero
#   would imply a dedicated cadence (not implemented in v1).
# - MIN_GAP_SEC: per-scenario lockout (anti-thrash); a scenario won't be
#   re-sampled within this window even if it's the least-recent.
# - MAX_PER_DAY: global cap to bound write volume on focus_switch_log.
# - REQUIRE_PARTICIPANT_OVERLAP: when true, only sample background scenarios
#   that share at least one participant country with the focused scenario
#   (since shadow piggybacks on the focused signal set, signals for
#   non-overlapping scenarios will degrade to global-only).
# - WARMUP_SEC: skip shadow sampling for the first N seconds after process
#   start to let baselines stabilise.
# - C_MEDIUM_DELTA_MISS_SHADOW: separate (typically more conservative) miss
#   threshold for shadow-sourced rows; analyst rows still use C_MEDIUM_DELTA_MISS.
SHADOW_SAMPLING_ENABLED              = os.getenv("SHADOW_SAMPLING_ENABLED", "true").lower() in ("true", "1", "yes")
SHADOW_SAMPLING_INTERVAL_SEC         = int(os.getenv("SHADOW_SAMPLING_INTERVAL_SEC", "0"))
SHADOW_SAMPLING_MIN_GAP_SEC          = int(os.getenv("SHADOW_SAMPLING_MIN_GAP_SEC", "300"))
SHADOW_SAMPLING_MAX_PER_DAY          = int(os.getenv("SHADOW_SAMPLING_MAX_PER_DAY", "200"))
SHADOW_SAMPLING_REQUIRE_OVERLAP      = os.getenv("SHADOW_SAMPLING_REQUIRE_OVERLAP", "false").lower() in ("true", "1", "yes")
SHADOW_SAMPLING_WARMUP_SEC           = int(os.getenv("SHADOW_SAMPLING_WARMUP_SEC", "600"))
C_MEDIUM_DELTA_MISS_SHADOW           = float(os.getenv("C_MEDIUM_DELTA_MISS_SHADOW", "1.4"))

# TL recalibration advisory (scenario-refactor §7.3.1). Operator-facing
# flag surfaced through /api/analytics/tl_recalibration_advisory.
TL_RECALIBRATION_MIN_OBS            = int(os.getenv("TL_RECALIBRATION_MIN_OBS", "100"))
TL_RECALIBRATION_SKEW_THRESHOLD_PCT = float(os.getenv("TL_RECALIBRATION_SKEW_THRESHOLD_PCT", "70.0"))

# Background TL display (scenario-refactor Phase 5 extension).
# When False, the scenario bar renders only a score for background scenarios
# (TL is only shown for focused). When True, background scenarios also show TL.
SHOW_BACKGROUND_TL = os.getenv("SHOW_BACKGROUND_TL", "false").lower() in ("true", "1", "yes")

# v2.0 Conclusion Model ledger (docs/design/v2-migration.md ADR-V2-001/008).
# Phase 1 shadow-write: when ENABLED, every focused TL derivation is also
# persisted as a Conclusion row. v1 API responses are unchanged. Default off
# until Phase 2 default-on flip per the three-stage rollout plan.
V2_CONCLUSION_LEDGER_ENABLED = os.getenv("V2_CONCLUSION_LEDGER_ENABLED", "false").lower() in ("true", "1", "yes")
V2_NP7_DISCLAIMER = os.getenv(
    "V2_NP7_DISCLAIMER",
    "Tool conclusion only — final judgment by organizational process.",
)

# v2.0 LLM prompt persistence (ADR-V2-009). Phase 1 shadow-write: every LLM
# call's (system, prompt) pair is persisted to llm_prompts (sha256-deduped)
# and llm_call_log gains a prompt_sha256 link. Default off until Phase 2.
V2_LLM_PROMPT_PERSISTENCE_ENABLED = os.getenv("V2_LLM_PROMPT_PERSISTENCE_ENABLED", "false").lower() in ("true", "1", "yes")

# v2.0 API surface (/api/v2/...). Phase 1 read-only skeleton — endpoints serve
# the latest rows from the conclusions ledger if present, or an explicit
# "no conclusion yet" envelope otherwise. v1 API is unaffected.
# Default flipped to true on 2026-04-26 (Mode C activation) — all 5
# readiness conditions passed via scripts/check_mode_c_readiness.py.
# v1 sunset T+90d targets 2026-07-26 (ADR-V2-003 IN_PROGRESS).
# Set V2_API_ENABLED=false to opt out (e.g. emergency rollback).
V2_API_ENABLED = os.getenv("V2_API_ENABLED", "true").lower() in ("true", "1", "yes")

# v2.0 Phase 1 priority 6: v1/v2 conclusion diff sampler.
# When ENABLED, every focused scoring cycle samples the focused TL from v1
# (in-memory ScenarioState) against the latest v2 ledger row and appends a
# conclusion_diff_log entry. Used to gate the default-on flip (ADR-V2-001).
# Implies V2_CONCLUSION_LEDGER_ENABLED — without ledger writes there is no
# v2 row to compare against.
V2_CONCLUSION_DIFF_SAMPLER_ENABLED = os.getenv(
    "V2_CONCLUSION_DIFF_SAMPLER_ENABLED", "false",
).lower() in ("true", "1", "yes")

# v2.0 Phase 2 individual-rollback flags (per docs/design/v2-migration.md §10.3).
# Each conclusion type ships behind its own flag so a misbehaving deriver can
# be disabled without taking down THREAT_LEVEL. All imply V2_CONCLUSION_LEDGER_ENABLED.
V2_TREND_ENABLED = os.getenv("V2_TREND_ENABLED", "false").lower() in ("true", "1", "yes")
V2_PER_DOMAIN_ENABLED = os.getenv("V2_PER_DOMAIN_ENABLED", "false").lower() in ("true", "1", "yes")
V2_ATTACK_MODE_ENABLED = os.getenv("V2_ATTACK_MODE_ENABLED", "false").lower() in ("true", "1", "yes")
V2_CONTINUITY_LOG_ENABLED = os.getenv("V2_CONTINUITY_LOG_ENABLED", "false").lower() in ("true", "1", "yes")

# Continuity threshold: NP5+8 marks a (scenario, type) pair as a design
# failure when the unavailable run length crosses this many seconds.
# Default 7 days = 604_800; can be tightened in production.
V2_CONTINUITY_FAILURE_SEC = float(os.getenv("V2_CONTINUITY_FAILURE_SEC", str(7 * 24 * 3600)))

CF_HEADERS = {"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}

AIRSPACE_WINDOW             = int(os.getenv("AIRSPACE_WINDOW", "20"))
AIRSPACE_ANOMALY_THRESHOLD  = float(os.getenv("AIRSPACE_ANOMALY_THRESHOLD", "0.40"))
AIRSPACE_CLOSURE_THRESHOLD  = float(os.getenv("AIRSPACE_CLOSURE_THRESHOLD", "0.05"))
GDELT_TONE_ALERT_THRESHOLD  = float(os.getenv("GDELT_TONE_ALERT_THRESHOLD", "-15.0"))
GDELT_HISTORY_WINDOW        = int(os.getenv("GDELT_HISTORY_WINDOW", "28"))
CONVERGENCE_DUAL_BONUS      = int(os.getenv("CONVERGENCE_DUAL_BONUS", "1"))
CONVERGENCE_FULL_BONUS      = int(os.getenv("CONVERGENCE_FULL_BONUS", "2"))
# Domain weights for convergence scoring (must sum to 1.0)
DOMAIN_WEIGHT_CYBER         = float(os.getenv("DOMAIN_WEIGHT_CYBER",    "0.50"))
DOMAIN_WEIGHT_PHYSICAL      = float(os.getenv("DOMAIN_WEIGHT_PHYSICAL", "0.30"))
DOMAIN_WEIGHT_INFO          = float(os.getenv("DOMAIN_WEIGHT_INFO",     "0.20"))
THREAT_LEVEL_HYSTERESIS_CYCLES = int(os.getenv("THREAT_LEVEL_HYSTERESIS_CYCLES", "1"))
HOD_BASELINE_DAYS  = 28  # Days of same-hour history to retain across all HOD sensors
HOD_MIN_SAME_HOUR  = 7   # Minimum same-hour samples before HOD Z-score is valid
HOD_MAX_ENTRIES    = HOD_BASELINE_DAYS * 24  # 672 hourly entries per theater

SEVERE_WEATHER_IDS = (
    set(range(200, 233)) | {500, 502, 503, 504} | {521, 522, 531} |
    {600, 602, 621, 622} | {711, 762} | {771, 781} | {900, 902}
)

# ── Theater Baseline & Cross-Domain Correlation ─────────────────────────────
THEATER_BASELINE_WINDOW      = int(os.getenv("THEATER_BASELINE_WINDOW", "30"))      # Days for auto-baseline
THEATER_BASELINE_MIN_SAMPLES = int(os.getenv("THEATER_BASELINE_MIN_SAMPLES", "20")) # Min samples for Z-score
TRIANGULATION_BONUS          = float(os.getenv("TRIANGULATION_BONUS", "0.5"))       # Extra bonus for 3-domain convergence
SILENT_DIVERGENCE_THRESHOLD  = int(os.getenv("SILENT_DIVERGENCE_THRESHOLD", "2"))   # Min cyber+physical anomalies for silent divergence

# ── Deep Pattern Analysis Config ───────────────────────────────────────────────
# A. DDoS Acceleration Engine
AMBUSH_ZSCORE_THRESHOLD = float(os.getenv("AMBUSH_ZSCORE_THRESHOLD", "2.0"))
DERIVATIVE_WINDOW       = int(os.getenv("DERIVATIVE_WINDOW", "5"))
SYNC_DELTA_MS           = float(os.getenv("SYNC_DELTA_MS", "500"))
SYNC_C2_THRESHOLD       = float(os.getenv("SYNC_C2_THRESHOLD", "0.70"))
# B. Narrative Burst Detector
NARRATIVE_ZSCORE_ALERT    = float(os.getenv("NARRATIVE_ZSCORE_ALERT", "2.0"))
NARRATIVE_ZSCORE_CRITICAL = float(os.getenv("NARRATIVE_ZSCORE_CRITICAL", "3.0"))
NARRATIVE_BASELINE_DAYS   = int(os.getenv("NARRATIVE_BASELINE_DAYS", "30"))
NARRATIVE_POLL_INTERVAL   = int(os.getenv("NARRATIVE_POLL_INTERVAL", "1800"))
# C. Sequence Scorer
SEQUENCE_WINDOW          = int(os.getenv("SEQUENCE_WINDOW", "86400"))
SEQUENCE_FULL_BONUS      = int(os.getenv("SEQUENCE_FULL_BONUS", "3"))
SEQUENCE_PARTIAL_BONUS   = int(os.getenv("SEQUENCE_PARTIAL_BONUS", "2"))
# D. Maritime / ISR
AIS_DARK_GAP_THRESHOLD   = int(os.getenv("AIS_DARK_GAP_THRESHOLD", "3600"))
AIS_ANCHOR_RADIUS_KM     = float(os.getenv("AIS_ANCHOR_RADIUS_KM", "50"))
ISR_ICAO_TYPES           = [t.strip().upper() for t in os.getenv(
    "ISR_ICAO_TYPES", "RC135,RC-135,E3,E-3,RQ4,RQ-4,P8,P-8,EP3,EP-3,U2,TR1,E8,E-8"
).split(",") if t.strip()]
ISR_SURGE_THRESHOLD      = int(os.getenv("ISR_SURGE_THRESHOLD", "3"))

# ── Phase 2: Adaptive Z-score Config ─────────────────────────────────────────
ADAPTIVE_ZSCORE_ENABLED       = os.getenv("ADAPTIVE_ZSCORE_ENABLED", "true").lower() in ("true", "1", "yes")
ADAPTIVE_ZSCORE_MIN_SAMPLES   = int(os.getenv("ADAPTIVE_ZSCORE_MIN_SAMPLES", "50"))
ADAPTIVE_ZSCORE_SENSITIVITY   = float(os.getenv("ADAPTIVE_ZSCORE_SENSITIVITY", "1.5"))

# ── Phase 2: Space Weather Noise Filter Config ───────────────────────────────
SPACE_WEATHER_KP_SUPPRESS_THRESHOLD = int(os.getenv("SPACE_WEATHER_KP_SUPPRESS_THRESHOLD", "6"))
SPACE_WEATHER_XRAY_SUPPRESS_CLASS   = os.getenv("SPACE_WEATHER_XRAY_SUPPRESS_CLASS", "M")

# ── Phase 2: Feint Detection Config ──────────────────────────────────────────
FEINT_DISTRACTION_MAX_SCORE   = int(os.getenv("FEINT_DISTRACTION_MAX_SCORE", "3"))
FEINT_PRIMARY_MIN_SCORE       = int(os.getenv("FEINT_PRIMARY_MIN_SCORE", "5"))
FEINT_MIN_DISTRACTION_DOMAINS = int(os.getenv("FEINT_MIN_DISTRACTION_DOMAINS", "2"))

# ── Phase 2: Escalation Progress Config ──────────────────────────────────────
ESCALATION_HISTORY_MAX        = int(os.getenv("ESCALATION_HISTORY_MAX", "100"))
# TL thresholds (score_with_bonus boundaries): TL4=2, TL3=4, TL2=6, TL1=9
ESCALATION_TL_THRESHOLDS      = {4: 2, 3: 4, 2: 6, 1: 9}

# ── Confidence Propagation Config ──────────────────────────────────────────
CONFIDENCE_MIN_SAMPLES        = int(os.getenv("CONFIDENCE_MIN_SAMPLES", "10"))

# OpenSky Network authentication
# Basic auth deprecated after 2026-03-18 → migrated to OAuth2 Bearer token
# Set OPENSKY_CLIENT_ID / OPENSKY_CLIENT_SECRET in config.env
# Authenticated: 4000 req/day (anonymous: 400 req/day)
OPENSKY_CLIENT_ID     = os.getenv("OPENSKY_CLIENT_ID", "")
OPENSKY_CLIENT_SECRET = os.getenv("OPENSKY_CLIENT_SECRET", "")
OPENSKY_TOKEN_URL     = "https://auth.opensky-network.org/auth/realms/opensky-network/protocol/openid-connect/token"

# ── State Persistence ──────────────────────────────────────────────────────────
PERSISTENCE_DIR           = os.path.join(os.path.dirname(os.path.abspath(__file__)), "persistence")
PERSISTENCE_STATE_FILE    = os.path.join(PERSISTENCE_DIR, "state.json")
PERSISTENCE_SAVE_INTERVAL = int(os.getenv("PERSISTENCE_SAVE_INTERVAL", "300"))  # seconds (default: 5 min)

OPENSKY_MIN_INTERVAL = int(os.getenv("OPENSKY_MIN_INTERVAL", "10"))

# ── Phase C: New Sensor Config ─────────────────────────────────────────────
# S1: NOTAM anomaly detection
NOTAM_SURGE_THRESHOLD         = int(os.getenv("NOTAM_SURGE_THRESHOLD", "20"))
NOTAM_MILITARY_KEYWORDS       = [kw.strip().upper() for kw in os.getenv(
    "NOTAM_MILITARY_KEYWORDS",
    "MILITARY,MIL AIRSPACE,PROHIBITED AREA,RESTRICTED AREA,DANGER AREA,"
    "LIVE FIRING,MISSILE,EXERCISE,TFR,NO FLY,HAZARD AREA,COMBAT,"
    "AIR DEFENSE,AIR REFUELING"
).split(",") if kw.strip()]

# S4: USGS Seismic
USGS_MIN_MAGNITUDE            = float(os.getenv("USGS_MIN_MAGNITUDE", "4.0"))
USGS_CABLE_RADIUS_KM          = float(os.getenv("USGS_CABLE_RADIUS_KM", "200"))

# S6: GPS Jamming
GPS_JAM_THRESHOLD             = float(os.getenv("GPS_JAM_THRESHOLD", "3.0"))
GPS_JAM_CRITICAL_THRESHOLD    = float(os.getenv("GPS_JAM_CRITICAL_THRESHOLD", "7.0"))

# S7: CT Log (signal-model redesign — see ADR-024)
# Legacy CT_LOG_SURGE_THRESHOLD removed: the surge-volume scoring path was
# replaced by identity-match scoring (untrusted CA / wildcard at gov-TLD).
# New domain warm-up window: a domain whose first observation is younger than
# this is treated as "learning" — every CA seen is recorded into the known-CA
# table without firing an anomaly. Without a warm-up the very first poll would
# fire UNTRUSTED_CA_DETECTED for every CA the project has never recorded
# before, even when those CAs are perfectly normal for that domain. 14 days
# typically covers a full ACME renewal cycle (LE = 90d but most enterprises
# rotate every 60-90d; 14d is the floor that still catches multi-CA enterprise
# setups visible only at renewal time).
CT_LOG_WARMUP_DAYS                  = int(os.getenv("CT_LOG_WARMUP_DAYS", "14"))
# How far back the sensor looks for newly-issued certs at each poll.
CT_LOG_OBSERVATION_WINDOW_HOURS     = int(os.getenv("CT_LOG_OBSERVATION_WINDOW_HOURS", "24"))
# Hard cap on watched-domain queries per fetch (per theater). crt.sh enforces
# an aggressive unauthenticated rate limit (empirically ~5-10 req/min); the v1
# default of 8 queries × N theaters with 0.4s pacing was rate-limited on >75%
# of requests. Round-robin across cycles ensures all domains in the watched
# set are covered over time — at 2/cycle on a 9-domain set the full sweep
# completes every ~5 hours, which is well within the relevance window of the
# CA-anomaly signal we are measuring.
CT_LOG_MAX_QUERIES_PER_THEATER      = int(os.getenv("CT_LOG_MAX_QUERIES_PER_THEATER", "2"))
# Per-domain query timeout. Phase 2 raised the floor from 10s → 30s after
# production telemetry showed crt.sh response times routinely fall in the
# 7-30s band even when the upstream eventually delivers a 200 — clipping at
# 10s was the dominant driver of the chronic-silence symptom that started
# this whole rework. Certspotter typically completes in <3s, so the bump
# only affects crt.sh fallback latency, not the fast path.
CT_LOG_QUERY_TIMEOUT_SEC            = int(os.getenv("CT_LOG_QUERY_TIMEOUT_SEC", "30"))
# Pacing between successive crt.sh queries within a cycle. crt.sh prefers
# polite serial clients; 4s gives us a sustainable ~15 req/min upper bound
# across all theaters, comfortably under the unauthenticated rate limit even
# when multiple theaters fire in the same cycle.
CT_LOG_INTER_QUERY_SLEEP_SEC        = float(os.getenv("CT_LOG_INTER_QUERY_SLEEP_SEC", "4.0"))
# Multi-source pipeline (Phase 1 of the post-ADR-024 transport rework — see
# docs/_archive/scenario-refactor-v1.8.1.md). Sources (crt.sh REST, certstream ws,
# certspotter REST) write into an ObservationBuffer; the orchestrator drains
# it at score time. Buffer cap protects against memory blow-up under a
# certstream burst; it should be larger than the realistic peak of cert
# matches in a single observation window (matches/sec × window_sec).
CT_LOG_BUFFER_MAX_OBS               = int(os.getenv("CT_LOG_BUFFER_MAX_OBS", "5000"))
# Degraded-mode poll interval. Triggered after _UPSTREAM_FAIL_THRESHOLD
# consecutive zero-data cycles; resets to _NORMAL_INTERVAL on first success.
CT_LOG_DEGRADED_INTERVAL_SEC        = int(os.getenv("CT_LOG_DEGRADED_INTERVAL_SEC", "14400"))
# Certspotter primary source (Phase 2). Optional API token raises the free
# tier's 30 req/hr cap substantially when provisioned; without one the
# token-bucket caps local issuance at CT_LOG_CERTSPOTTER_RATE_LIMIT_CALLS
# per CT_LOG_CERTSPOTTER_RATE_LIMIT_WINDOW_SEC. Defaults sized for the
# free tier with headroom.
CERTSPOTTER_API_TOKEN               = os.getenv("CERTSPOTTER_API_TOKEN", "").strip()
CT_LOG_CERTSPOTTER_RATE_LIMIT_CALLS      = int(os.getenv("CT_LOG_CERTSPOTTER_RATE_LIMIT_CALLS", "25"))
CT_LOG_CERTSPOTTER_RATE_LIMIT_WINDOW_SEC = int(os.getenv("CT_LOG_CERTSPOTTER_RATE_LIMIT_WINDOW_SEC", "3600"))
# Certstream push source (Phase 2 second-half). Calidog's free public ws is
# the only push-side CT log feed that fits the project's free-OSINT mandate.
# Disable via CT_LOG_CERTSTREAM_ENABLED=false if the operator wants to fall
# back to pull-only operation. Liveness budget: a healthy ws should write
# into the buffer at least once every CT_LOG_CERTSTREAM_LIVENESS_SEC; missed
# budgets surface in upstream_health() but do not by themselves trigger CB.
# Default DISABLED as of 2026-04-23: live verification confirmed
# wss://certstream.calidog.io/* accepts connections, sends zero messages
# (no certs, no heartbeats), and the server closes with normal-closure
# code 1000 at exactly ~60s. Reproduced with bare websocket-client outside
# gevent and with a browser-like User-Agent — it is the upstream, not us.
# Pull sources (certspotter + crt.sh) carry the CT load until Calidog's
# stream is restored or an alternative push feed is identified.
# Set CT_LOG_CERTSTREAM_ENABLED=true to opt back in for live monitoring
# (e.g. once Calidog is fixed).
CT_LOG_CERTSTREAM_ENABLED       = os.getenv("CT_LOG_CERTSTREAM_ENABLED", "false").lower() == "true"
CT_LOG_CERTSTREAM_URL           = os.getenv("CT_LOG_CERTSTREAM_URL", "wss://certstream.calidog.io/full-stream")
CT_LOG_CERTSTREAM_LIVENESS_SEC  = int(os.getenv("CT_LOG_CERTSTREAM_LIVENESS_SEC", "900"))
# ws ping/pong cadence — RFC 6455 control frames. Default DISABLED
# (ping_interval=0) because under gevent monkey-patching, websocket-client's
# ping thread races the recv loop's pong handler and falsely trips
# ping_timeout every ~60s, churning the connection. Liveness is instead
# enforced by an in-worker watchdog that reconnects when no Calidog
# heartbeat has arrived within CT_LOG_CERTSTREAM_HEARTBEAT_BUDGET_SEC.
# Set CT_LOG_CERTSTREAM_PING_INTERVAL > 0 only to re-enable the RFC 6455
# path for non-gevent deployments.
CT_LOG_CERTSTREAM_PING_INTERVAL = int(os.getenv("CT_LOG_CERTSTREAM_PING_INTERVAL", "0"))
CT_LOG_CERTSTREAM_PING_TIMEOUT  = int(os.getenv("CT_LOG_CERTSTREAM_PING_TIMEOUT", "0"))
# Application-layer liveness watchdog. Calidog emits heartbeat frames every
# ~30s; 120s (4× period) tolerates network jitter without waiting on OS TCP
# keepalive (~2h default).
CT_LOG_CERTSTREAM_HEARTBEAT_BUDGET_SEC = int(os.getenv("CT_LOG_CERTSTREAM_HEARTBEAT_BUDGET_SEC", "120"))
# Reconnect backoff bounds. Capped exponential: 1s, 2s, 4s, ... up to ceiling.
CT_LOG_CERTSTREAM_RECONNECT_MAX_SEC = int(os.getenv("CT_LOG_CERTSTREAM_RECONNECT_MAX_SEC", "60"))

# Watched domains by theater — loaded from geo_data.json above.
CT_LOG_WATCHED_DOMAINS: dict[str, list[str]] = {
    k: v for k, v in (_raw_geo.get("CT_LOG_WATCHED_DOMAINS", {}) or {}).items()
    if k != "_comment" and isinstance(v, list)
}

# Globally-trusted CA name substrings. A cert whose issuer name contains any of
# these substrings (case-insensitive) is considered "trusted" and never fires
# an anomaly, regardless of per-domain history. The list is intentionally
# weighted toward CAs that gov entities legitimately use across the full set
# of monitored countries (LE/ACME ecosystem, major commercial CAs, EU-trusted
# QWAC issuers). State-aligned CAs from monitored adversary nations are
# DELIBERATELY ABSENT — a Russian gov domain suddenly issued by a Russian-
# state CA when its history shows DigiCert is exactly the anomaly we want to
# detect. Per-domain known-CA history is the second allow-channel for those
# legitimate cases.
CT_LOG_TRUSTED_CAS_GLOBAL: tuple[str, ...] = (
    # ACME / ISRG ecosystem (dominates gov domain issuance worldwide)
    "let's encrypt", "isrg root", "r3", "r10", "r11", "r12", "r13", "r14",
    "e1", "e5", "e6", "e7", "e8",
    # Major commercial roots
    "digicert", "sectigo", "comodo", "globalsign", "entrust", "identrust",
    "godaddy", "starfield", "ssl.com", "amazon", "microsoft", "google trust",
    "gts ca", "cloudflare", "verisign", "thawte", "geotrust", "usertrust",
    "aaa certificate", "baltimore cybertrust", "quovadis",
    # EU eIDAS / national QWACs commonly used by gov entities outside the
    # adversary set
    "swisssign", "actalis", "harica", "buypass", "zerossl", "d-trust",
    "telia", "atos trustcenter", "trustwave",
)

# ── LLM Intelligence ──────────────────────────────────────────────────────────
LLM_ENABLED               = os.getenv("LLM_ENABLED", "false").lower() in ("true", "1", "yes")
LLM_HOST                  = os.getenv("LLM_HOST", "http://localhost:11434")
LLM_MODEL                 = os.getenv("LLM_MODEL", "llama3.2:3b")
LLM_TIMEOUT               = int(os.getenv("LLM_TIMEOUT", "30"))
LLM_AUTO_CONFIRM_THRESHOLD = float(os.getenv("LLM_AUTO_CONFIRM_THRESHOLD", "0.80"))
LLM_CONFIDENCE_MIN        = float(os.getenv("LLM_CONFIDENCE_MIN", "0.35"))
LLM_PENDING_AUTO_REJECT_HOURS  = float(os.getenv("LLM_PENDING_AUTO_REJECT_HOURS", "24"))
INTEL_RETENTION_DAYS           = int(os.getenv("INTEL_RETENTION_DAYS", "7"))
# How long a confirmed/auto_confirmed intel item contributes to the threat score.
# After this TTL the item is still in the DB but excluded from active rationale.
# Extended to 48h to pair with exponential age-decay (tau=12h default); a hard
# TTL alone caused a cliff effect (full score for 24h, then zero).
INTEL_ITEM_TTL_HOURS           = float(os.getenv("INTEL_ITEM_TTL_HOURS", "48"))
# Max number of active intel items per (source_type, theater) that contribute to score.
# Prevents a single noisy sensor from dominating the total score via accumulation.
# Top N items ranked by decayed score are kept; the rest are excluded from active rationale.
INTEL_MAX_ITEMS_PER_SOURCE_THEATER = int(os.getenv("INTEL_MAX_ITEMS_PER_SOURCE_THEATER", "2"))

# ── Intel Age-Decay (ADR-023) ──────────────────────────────────────────────
# Exponential decay: effective_score = score_delta * exp(-age_sec / (tau_hours * 3600))
# Smooths the binary TTL cliff. At age=tau the weight is e^-1 ≈ 0.37; at age=2*tau ≈ 0.14.
# Per-source_type override: INTEL_AGE_DECAY_TAU_HOURS_<SOURCE> (e.g. ..._DIPLOMATIC=6).
INTEL_AGE_DECAY_ENABLED   = os.getenv("INTEL_AGE_DECAY_ENABLED", "true").lower() in ("true", "1", "yes")
INTEL_AGE_DECAY_TAU_HOURS = float(os.getenv("INTEL_AGE_DECAY_TAU_HOURS", "12"))

# Cross-source corroboration: how far back to look for signals from independent sources
CORROBORATION_WINDOW_HOURS    = float(os.getenv("CORROBORATION_WINDOW_HOURS", "8"))
# Cooldown per theater after a corroboration event fires (prevents re-triggering same event)
CORROBORATION_COOLDOWN_HOURS  = float(os.getenv("CORROBORATION_COOLDOWN_HOURS", "12"))
# Minimum number of distinct independent source_types needed to trigger synthesis
CORROBORATION_MIN_SOURCES     = int(os.getenv("CORROBORATION_MIN_SOURCES", "2"))
# Minimum pairwise source independence score (0.0=same stream, 1.0=fully independent)
CORROBORATION_MIN_INDEPENDENCE = float(os.getenv("CORROBORATION_MIN_INDEPENDENCE", "0.70"))

# CT_LOG_GOV_TLDS removed — last used by the legacy `gov_count` metric the
# ADR-024 redesign deprecated. The wildcard-TLD detector now uses the
# canonical _GOV_TLD_WILDCARD_TARGETS frozenset in radar/sensors/ct_log.py.
