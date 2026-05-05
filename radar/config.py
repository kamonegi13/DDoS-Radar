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

# v2.0 Phase 2 後半 (ADR-V2-005): LLM augmentation for ATTACK_MODE conclusions.
# When ENABLED, every successful rule-based attack-mode classification is also
# sent to the LLM for narrative + agreement + confidence nudge (±0.10 max).
# Rule remains the authority for `state`. INSUFFICIENT_DATA rows pass through
# unaugmented (NP1: do not invent a mode when rules abstained).
V2_ATTACK_MODE_LLM_AUGMENT_ENABLED = os.getenv(
    "V2_ATTACK_MODE_LLM_AUGMENT_ENABLED", "false",
).lower() in ("true", "1", "yes")

# Continuity threshold: NP5+8 marks a (scenario, type) pair as a design
# failure when the unavailable run length crosses this many seconds.
# Default 7 days = 604_800; can be tightened in production.
V2_CONTINUITY_FAILURE_SEC = float(os.getenv("V2_CONTINUITY_FAILURE_SEC", str(7 * 24 * 3600)))

# v2.0 Phase 2 完了条件 (ADR-V2-005): ACLED + GDELT auto-correlation ETL.
# When ENABLED, scripts/run_ground_truth_etl.py classifies recent conclusions
# against ACLED political-violence events + GDELT tone spikes and writes
# auto-feedback rows (analyst_id="auto:acled" / "auto:gdelt") into
# analyst_feedback for Design W recall calibration.
V2_GROUND_TRUTH_ETL_ENABLED = os.getenv(
    "V2_GROUND_TRUTH_ETL_ENABLED", "false",
).lower() in ("true", "1", "yes")
ACLED_API_KEY = os.getenv("ACLED_API_KEY", "")
ACLED_API_EMAIL = os.getenv("ACLED_API_EMAIL", "")
# Forward window for matching escalation evidence to a conclusion.
GROUND_TRUTH_WINDOW_HOURS = int(os.getenv("GROUND_TRUTH_WINDOW_HOURS", "72"))
# A high-confidence conclusion older than this with zero corroborating events
# is auto-labeled FALSE_POSITIVE. 7 days mirrors the inconclusive_continuity
# rule (ADR-V2-010) so noise patterns line up.
GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS = int(
    os.getenv("GROUND_TRUTH_FALSE_POSITIVE_HORIZON_DAYS", "7"),
)
# An ACLED event with this many fatalities (or more) inside the forward
# window flips a TL=1 conclusion to FALSE_NEGATIVE — the NP1-critical case
# where the tool stayed quiet through a real escalation.
GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES = int(
    os.getenv("GROUND_TRUTH_FALSE_NEGATIVE_FATALITIES", "10"),
)

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
# Identity-match scoring (untrusted CA / wildcard at gov-TLD) replaces
# surge-volume thresholding.
# Domain warm-up window: a domain whose first observation is younger than
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

# ── Background Observer (AP3 — per-scenario observation health) ─────────
# Periodic per-country RSS fetch for NON-focused scenarios. Closes the
# observability gap exposed by the OBS chip: Asia-Pacific / SCS / Korea
# scenarios receive ~0 LLM intel rows in 24h because the existing intel
# pipeline is geographically biased toward sources covering UA/RU/IL.
# Background observer rotates round-robin through non-focused scenarios
# and their participants, fetches public RSS feeds (anonymous HTTP GET,
# no API keys), runs the regex extractor (radar.conclusions.rss_extractor),
# and writes findings as ephemeral Signals into the next scoring tick.
# No LLM dependency. Default off — opt-in per NP3 (adds outbound HTTP).
BG_OBSERVER_ENABLED        = os.getenv("BG_OBSERVER_ENABLED", "false").lower() in ("true", "1", "yes")
BG_OBSERVER_INTERVAL_SEC   = int(os.getenv("BG_OBSERVER_INTERVAL_SEC", "300"))    # 5 min cycle
BG_OBSERVER_SIGNAL_TTL_SEC = int(os.getenv("BG_OBSERVER_SIGNAL_TTL_SEC", "1800")) # signals age out after 30m
BG_OBSERVER_MAX_QUEUE      = int(os.getenv("BG_OBSERVER_MAX_QUEUE", "200"))       # hard cap to bound memory
# Phase 7.5h (audit Security L1) — every default feed must be HTTPS
# so a network-path adversary cannot inject malicious RSS that flows
# into the LLM analysis pipeline. The previous Xinhua entry used
# plain HTTP; it has been removed from the default list. Operators
# can re-add it (or any regional source) via the BG_OBSERVER_FEEDS
# env var, but the default ships with TLS-only feeds.
BG_OBSERVER_FEEDS          = [
    u.strip() for u in os.getenv(
        "BG_OBSERVER_FEEDS",
        "https://feeds.bbci.co.uk/news/world/rss.xml,"
        "https://www.aljazeera.com/xml/rss/all.xml,"
        "https://apnews.com/rss/apf-topnews",
    ).split(",") if u.strip()
]


# ── LLM Intelligence ──────────────────────────────────────────────────────────
# Phase 9.1 C3 — these keys are now registered with radar/config_layered.py
# below so the Settings UI can edit them through the unified surface. The
# module-level constants here remain for backward compatibility (existing
# `from radar.config import LLM_TIMEOUT` keeps working) but they reflect the
# value AT IMPORT TIME ONLY. Code paths that mutate config at runtime should
# read via `from radar.config_layered import get_config; get_config('LLM_TIMEOUT')`
# instead so DB overrides take effect without a restart.
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


# ─────────────────────────────────────────────────────────────────────────────
# Phase 9.1 C3 — declarative key registration with config_layered
#
# Every key listed here becomes editable through the unified Settings UI
# (Phase 9.4). Three flags drive UI behavior:
#
#   restart_required=True   — DB write succeeds but takes effect after redeploy
#                              (UI shows a "restart pending" badge)
#   immutable=True          — env-only; UI displays read-only with an
#                              "edit in config.env" hint (typically ports,
#                              host names, transport-level settings)
#   secret=True             — value is never echoed back over the API
#
# domain= prefixes group keys for the Settings left-nav. Convention:
#   llm.connection / llm.intel_pipeline / llm.routing / llm.embedding
#   sensor.* / scoring.* / network / server / api_keys
# ─────────────────────────────────────────────────────────────────────────────
try:  # pragma: no cover — registration is best-effort, never fatal
    from radar.config_layered import (
        ConfigKey, register,
        GROUP_OPERATE, GROUP_TUNE, GROUP_LLM_HEALTH,
        GROUP_INFRASTRUCTURE, GROUP_ACCESS,
        TIMING_LIVE_NEXT_TICK, TIMING_LIVE_IMMEDIATE,
        TIMING_LIVE_NEXT_CYCLE, TIMING_RESTART_REQUIRED,
    )

    register(
        # ════════════════════════════════════════════════════════════════
        # OPERATE — weekly tuning surface for analysts
        # ════════════════════════════════════════════════════════════════
        ConfigKey(
            key="DEFAULT_FOCUSED_SCENARIO", domain="operate.scope",
            default="taiwan_contingency", type_="str",
            description="Startup default for the focused scenario.",
            group=GROUP_OPERATE, apply_timing=TIMING_RESTART_REQUIRED,
            restart_required=True,
            what="Which scenario the engine boots into. The focused scenario "
                 "runs every sensor at full coverage; non-focused scenarios "
                 "run in C-lite mode (LLM intel + global signals only).",
            why="Compute / API-quota budget. Running every sensor on every "
                "scenario every cycle would saturate upstreams. Focusing one "
                "scenario keeps recall high where it matters now.",
            when="On deployment, set to your primary watch theatre. Analysts "
                 "can re-focus at runtime via the scenario picker — this "
                 "value is only the boot default.",
        ),
        ConfigKey(
            key="GLOBAL_SIGNAL_WEIGHT", domain="operate.scope",
            default=0.5, type_="float",
            description="Weight applied to global (non-scenario) signals.",
            group=GROUP_OPERATE, min_value=0.0, max_value=1.0,
        ),
        ConfigKey(
            key="DOMAIN_CAP", domain="operate.scope",
            default=6.0, type_="float",
            description="Per-domain score cap before normalization.",
            group=GROUP_OPERATE, min_value=1.0, max_value=20.0,
        ),
        ConfigKey(
            key="SHOW_BACKGROUND_TL", domain="operate.scope",
            default=False, type_="bool",
            description="Show background-scenario threat levels in HUD.",
            group=GROUP_OPERATE,
        ),

        # ── Notifications (operationally tuned) ──────────────────────────
        ConfigKey(
            key="NOTIFY_ENABLED", domain="operate.notifications",
            default=True, type_="bool",
            description="Master switch for outbound alert notifications.",
            group=GROUP_OPERATE,
        ),
        ConfigKey(
            key="NOTIFY_DEBOUNCE_SEC", domain="operate.notifications",
            default=300, type_="int",
            description="Suppress repeat alerts of same type within this window.",
            group=GROUP_OPERATE, unit="s", min_value=0, max_value=3600,
        ),

        # ── LLM intel queue thresholds (analyst-tuned) ───────────────────
        ConfigKey(
            key="LLM_AUTO_CONFIRM_THRESHOLD", domain="operate.intel",
            default=0.80, type_="float",
            description="Confidence ≥ this → AUTO-CONFIRMED on submission.",
            group=GROUP_OPERATE, min_value=0.5, max_value=1.0,
            apply_timing=TIMING_LIVE_NEXT_CYCLE,
            impact_level="med",
            what="Confidence floor that promotes an LLM-extracted intel item "
                 "from PENDING (analyst review) to AUTO-CONFIRMED (counted "
                 "in scoring immediately).",
            why="Trades analyst load against precision. Lower → more items "
                 "auto-confirmed (less review burden, more false positives). "
                 "Higher → safer, but analysts queue grows and reaction "
                 "latency increases.",
            when="Bump to 0.85 if the auto-judge audit shows reversal rate "
                 "above ~10%. Drop to 0.75 if you observe known events "
                 "stuck in PENDING for hours.",
        ),
        ConfigKey(
            key="LLM_CONFIDENCE_MIN", domain="operate.intel",
            default=0.35, type_="float",
            description="Confidence < this → silently discarded.",
            group=GROUP_OPERATE, min_value=0.1, max_value=0.9,
            apply_timing=TIMING_LIVE_NEXT_CYCLE,
            impact_level="med",
            what="Confidence floor below which an LLM extraction is "
                 "discarded silently — never reaches PENDING or scoring.",
            why="NP1 (recall > precision). Set lower than you think; many "
                 "early-stage signals come back at 0.40-0.55 and are real. "
                 "Raised from 0.55 → 0.35 in 2026-04 after observability "
                 "showed military_exercise averaging 0.39 (all silently "
                 "dropped).",
            when="Drop further if you suspect a sensor (Telegram, ground "
                 "OSINT) is dropping items the analyst would have wanted "
                 "to see.",
        ),
        ConfigKey(
            key="LLM_PENDING_AUTO_REJECT_HOURS",
            domain="operate.intel",
            default=24.0, type_="float",
            description="Hours after which unreviewed PENDING items are "
                        "auto-rejected. 0 = disabled.",
            group=GROUP_OPERATE, min_value=0, max_value=168, unit="h",
            apply_timing=TIMING_LIVE_NEXT_CYCLE,
            what="How long an item can sit in PENDING before the auto-judge "
                 "marks it REJECTED (analyst can still override).",
            why="Prevents unbounded PENDING queue growth. Stale uncorroborated "
                 "items lose evidentiary value rapidly.",
            when="Set lower (8-12h) for high-tempo operations; higher (48h+) "
                 "if analyst coverage is gappy. 0 disables auto-reject.",
        ),
        ConfigKey(
            key="INTEL_RETENTION_DAYS", domain="operate.intel",
            default=7, type_="int",
            description="Days to retain intel rows in the DB.",
            group=GROUP_OPERATE, min_value=1, max_value=90, unit="d",
            what="Days the radar.db keeps intel rows before periodic_cleanup "
                 "deletes them.",
            why="Bounds DB growth. After confirmation/rejection, the row's "
                 "audit trail lives in conclusions_ledger anyway, so the "
                 "intel row itself is short-lived.",
            when="Raise to 30+d for long-arc analyses; lower to 3d if disk "
                 "is constrained or you don't need historical re-scoring.",
        ),
        ConfigKey(
            key="INTEL_ITEM_TTL_HOURS", domain="operate.intel",
            default=48.0, type_="float",
            description="Hours a confirmed intel item contributes to score.",
            group=GROUP_OPERATE, min_value=1, max_value=168, unit="h",
        ),
        ConfigKey(
            key="INTEL_MAX_ITEMS_PER_SOURCE_THEATER",
            domain="operate.intel",
            default=2, type_="int",
            description="Cap on active intel items per (source, theater).",
            group=GROUP_OPERATE, min_value=1, max_value=50,
        ),
        ConfigKey(
            key="INTEL_AGE_DECAY_ENABLED", domain="operate.intel",
            default=True, type_="bool",
            description="Exponential age-decay on confirmed intel "
                        "contributions (ADR-023).",
            group=GROUP_OPERATE,
        ),
        ConfigKey(
            key="INTEL_AGE_DECAY_TAU_HOURS", domain="operate.intel",
            default=12.0, type_="float",
            description="Decay time constant: weight=1/e at age=τ.",
            group=GROUP_OPERATE, min_value=0.5, max_value=168, unit="h",
        ),
        ConfigKey(
            key="LLM_OVERRIDE_WINDOW", domain="operate.intel",
            default=3600, type_="int",
            description="Seconds within which AUTO-CONFIRMED can be overridden.",
            group=GROUP_OPERATE, min_value=300, max_value=86400, unit="s",
        ),

        # ── Cross-source corroboration ───────────────────────────────────
        ConfigKey(
            key="CORROBORATION_WINDOW_HOURS", domain="operate.corroboration",
            default=8.0, type_="float",
            description="How far back to look for signals from independent sources.",
            group=GROUP_OPERATE, min_value=1, max_value=72, unit="h",
        ),
        ConfigKey(
            key="CORROBORATION_COOLDOWN_HOURS", domain="operate.corroboration",
            default=12.0, type_="float",
            description="Cooldown per theater after a corroboration event fires.",
            group=GROUP_OPERATE, min_value=1, max_value=72, unit="h",
        ),
        ConfigKey(
            key="CORROBORATION_MIN_SOURCES", domain="operate.corroboration",
            default=2, type_="int",
            description="Minimum number of distinct independent source_types.",
            group=GROUP_OPERATE, min_value=2, max_value=10,
        ),
        ConfigKey(
            key="CORROBORATION_MIN_INDEPENDENCE", domain="operate.corroboration",
            default=0.70, type_="float",
            description="Minimum pairwise source independence score.",
            group=GROUP_OPERATE, min_value=0.0, max_value=1.0,
        ),

        # ════════════════════════════════════════════════════════════════
        # TUNE — performance/scoring tuning (monthly)
        # ════════════════════════════════════════════════════════════════

        # ── Threat scoring core ──────────────────────────────────────────
        ConfigKey(
            key="THREAT_LEVEL_HYSTERESIS_CYCLES", domain="tune.scoring",
            default=1, type_="int",
            description="Cycles a TL change must persist before promotion.",
            group=GROUP_TUNE, min_value=0, max_value=10,
            impact_level="high",
            impact_warning="Hysteresis controls how fast TL transitions. "
                          "Too low → TL flips on every tick (alarm fatigue). "
                          "Too high → real escalations are masked.",
            what="Number of consecutive scoring ticks a new TL must hold "
                 "before the system actually promotes/demotes the threat "
                 "level on the HUD and alerts.",
            why="Single-tick TL changes are mostly noise (one upstream "
                 "blipped, one transient corroboration). Hysteresis "
                 "filters those without losing real escalations, which "
                 "almost always span ≥ 2 ticks.",
            when="Raise to 2-3 if the HUD is flickering between TL bands. "
                 "Drop to 0 only for a debugging session — never in "
                 "production (false-alert generator).",
        ),
        ConfigKey(
            key="DOMAIN_WEIGHT_CYBER", domain="tune.scoring",
            default=0.50, type_="float",
            description="Cyber domain weight (must sum to 1.0 across 3).",
            group=GROUP_TUNE, min_value=0.0, max_value=1.0,
            impact_level="high",
            impact_warning="Domain weights must sum to 1.0. Changing this "
                          "rebalances all threat scores globally.",
            what="Weight of the cyber-domain sub-score in the convergence "
                 "formula. The 3 weights (cyber + physical + info) MUST "
                 "sum to 1.0 — the registry validator rejects writes that "
                 "violate this invariant.",
            why="Cyber traditionally leads physical/info in pre-conflict "
                 "phases (DDoS, BGP anomalies, CT-log shenanigans). The "
                 "default 0.50 reflects that historic precedence.",
            when="Lower (e.g. 0.40) when narrative-domain signal is "
                 "dominating an analysis (ground OSINT cycle). Raise back "
                 "to 0.50+ during ddos surge campaigns.",
        ),
        ConfigKey(
            key="DOMAIN_WEIGHT_PHYSICAL", domain="tune.scoring",
            default=0.30, type_="float",
            description="Physical domain weight (must sum to 1.0 across 3).",
            group=GROUP_TUNE, min_value=0.0, max_value=1.0,
            impact_level="high",
            impact_warning="Domain weights must sum to 1.0. Changing this "
                          "rebalances all threat scores globally.",
            what="Weight of the physical-domain sub-score (airspace, ISR, "
                 "AIS, GPS jamming, seismic, FIRMS). 3 weights sum to 1.0.",
            why="Physical signals are slower but more reliable. The 0.30 "
                 "default keeps physical influence meaningful without "
                 "letting an isolated airspace closure dominate.",
            when="Raise during kinetic phases (active mobilisation). Lower "
                 "if physical sensors are degraded (NOTAM disabled, IHR "
                 "down) so you don't reward partial coverage.",
        ),
        ConfigKey(
            key="DOMAIN_WEIGHT_INFO", domain="tune.scoring",
            default=0.20, type_="float",
            description="Info domain weight (must sum to 1.0 across 3).",
            group=GROUP_TUNE, min_value=0.0, max_value=1.0,
            impact_level="high",
            impact_warning="Domain weights must sum to 1.0. Changing this "
                          "rebalances all threat scores globally.",
            what="Weight of the info-domain sub-score (narrative bursts, "
                 "diplomatic, military exercise, hacktivist news, GDELT "
                 "tone). 3 weights sum to 1.0.",
            why="Info-domain signals lead by 24-72h but are noisier "
                 "(propaganda, off-topic news). The 0.20 default keeps "
                 "info as a leading indicator without dominating the score.",
            when="Raise (0.30+) during info-ops campaigns where the "
                 "narrative signal is reliable. Lower if false-positive "
                 "rate climbs from media cycles unrelated to the scenario.",
        ),
        ConfigKey(
            key="CONVERGENCE_DUAL_BONUS", domain="tune.scoring",
            default=1, type_="int",
            description="Bonus when 2 of 3 domains converge.",
            group=GROUP_TUNE, min_value=0, max_value=10,
        ),
        ConfigKey(
            key="CONVERGENCE_FULL_BONUS", domain="tune.scoring",
            default=2, type_="int",
            description="Bonus when all 3 domains converge.",
            group=GROUP_TUNE, min_value=0, max_value=10,
        ),
        ConfigKey(
            key="TRIANGULATION_BONUS", domain="tune.scoring",
            default=0.5, type_="float",
            description="Extra bonus for 3-domain convergence.",
            group=GROUP_TUNE, min_value=0.0, max_value=5.0,
        ),
        ConfigKey(
            key="SILENT_DIVERGENCE_THRESHOLD", domain="tune.scoring",
            default=2, type_="int",
            description="Min cyber+physical anomalies for silent divergence.",
            group=GROUP_TUNE, min_value=1, max_value=10,
        ),

        # ── Sequence chain ───────────────────────────────────────────────
        ConfigKey(
            key="SEQUENCE_WINDOW", domain="tune.sequence",
            default=86400, type_="int",
            description="Chain detection window (seconds).",
            group=GROUP_TUNE, min_value=600, max_value=604800, unit="s",
        ),
        ConfigKey(
            key="SEQUENCE_FULL_BONUS", domain="tune.sequence",
            default=3, type_="int",
            description="Full-chain bonus points.",
            group=GROUP_TUNE, min_value=0, max_value=20,
        ),
        ConfigKey(
            key="SEQUENCE_PARTIAL_BONUS", domain="tune.sequence",
            default=2, type_="int",
            description="Partial-chain bonus points.",
            group=GROUP_TUNE, min_value=0, max_value=20,
        ),

        # ── Adaptive Z-score baseline ────────────────────────────────────
        ConfigKey(
            key="ADAPTIVE_ZSCORE_ENABLED", domain="tune.zscore",
            default=True, type_="bool",
            description="Use adaptive Z-score baselines per theater.",
            group=GROUP_TUNE,
        ),
        ConfigKey(
            key="ADAPTIVE_ZSCORE_MIN_SAMPLES", domain="tune.zscore",
            default=50, type_="int",
            description="Min samples before adaptive baseline takes over.",
            group=GROUP_TUNE, min_value=10, max_value=1000,
        ),
        ConfigKey(
            key="ADAPTIVE_ZSCORE_SENSITIVITY", domain="tune.zscore",
            default=1.5, type_="float",
            description="Sensitivity multiplier for adaptive Z thresholds.",
            group=GROUP_TUNE, min_value=0.5, max_value=5.0,
        ),
        ConfigKey(
            key="THEATER_BASELINE_WINDOW", domain="tune.zscore",
            default=30, type_="int",
            description="Days for theater auto-baseline.",
            group=GROUP_TUNE, min_value=7, max_value=180, unit="d",
        ),
        ConfigKey(
            key="THEATER_BASELINE_MIN_SAMPLES", domain="tune.zscore",
            default=20, type_="int",
            description="Min samples for theater Z-score.",
            group=GROUP_TUNE, min_value=5, max_value=200,
        ),

        # ── DDoS acceleration engine ─────────────────────────────────────
        ConfigKey(
            key="AMBUSH_ZSCORE_THRESHOLD", domain="tune.ddos",
            default=2.0, type_="float",
            description="Ambush Z-score threshold.",
            group=GROUP_TUNE, min_value=0.5, max_value=10.0,
        ),
        ConfigKey(
            key="DERIVATIVE_WINDOW", domain="tune.ddos",
            default=5, type_="int",
            description="Velocity derivative window (cycles).",
            group=GROUP_TUNE, min_value=2, max_value=60,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="SYNC_DELTA_MS", domain="tune.ddos",
            default=500.0, type_="float",
            description="C2 sync delta (ms).",
            group=GROUP_TUNE, min_value=10, max_value=10000, unit="ms",
        ),
        ConfigKey(
            key="SYNC_C2_THRESHOLD", domain="tune.ddos",
            default=0.70, type_="float",
            description="C2 sync score threshold.",
            group=GROUP_TUNE, min_value=0.0, max_value=1.0,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),

        # ── Narrative burst detector ─────────────────────────────────────
        ConfigKey(
            key="NARRATIVE_ZSCORE_ALERT", domain="tune.narrative",
            default=2.0, type_="float",
            description="Narrative alert Z-score.",
            group=GROUP_TUNE, min_value=1.0, max_value=10.0,
        ),
        ConfigKey(
            key="NARRATIVE_ZSCORE_CRITICAL", domain="tune.narrative",
            default=3.0, type_="float",
            description="Narrative critical Z-score.",
            group=GROUP_TUNE, min_value=2.0, max_value=15.0,
        ),
        ConfigKey(
            key="NARRATIVE_BASELINE_DAYS", domain="tune.narrative",
            default=30, type_="int",
            description="Narrative baseline days.",
            group=GROUP_TUNE, min_value=7, max_value=180, unit="d",
        ),

        # ── Airspace ─────────────────────────────────────────────────────
        ConfigKey(
            key="AIRSPACE_ANOMALY_THRESHOLD", domain="tune.airspace",
            default=0.40, type_="float",
            description="Airspace anomaly threshold.",
            group=GROUP_TUNE, min_value=0.0, max_value=1.0,
        ),
        ConfigKey(
            key="AIRSPACE_CLOSURE_THRESHOLD", domain="tune.airspace",
            default=0.05, type_="float",
            description="Airspace closure threshold.",
            group=GROUP_TUNE, min_value=0.0, max_value=1.0,
        ),
        ConfigKey(
            key="AIRSPACE_WINDOW", domain="tune.airspace",
            default=20, type_="int",
            description="Airspace baseline window (cycles).",
            group=GROUP_TUNE, min_value=3, max_value=200,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),

        # ── Maritime / ISR ───────────────────────────────────────────────
        ConfigKey(
            key="AIS_DARK_GAP_THRESHOLD", domain="tune.maritime",
            default=3600, type_="int",
            description="AIS dark-gap threshold (seconds).",
            group=GROUP_TUNE, min_value=600, max_value=86400, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="AIS_ANCHOR_RADIUS_KM", domain="tune.maritime",
            default=50.0, type_="float",
            description="AIS anchor detection radius (km).",
            group=GROUP_TUNE, min_value=1, max_value=500, unit="km",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="ISR_SURGE_THRESHOLD", domain="tune.maritime",
            default=3, type_="int",
            description="ISR surge threshold (aircraft).",
            group=GROUP_TUNE, min_value=1, max_value=50,
        ),
        ConfigKey(
            key="GPS_JAM_THRESHOLD", domain="tune.maritime",
            default=3.0, type_="float",
            description="GPS jamming threshold.",
            group=GROUP_TUNE, min_value=0.5, max_value=20.0,
        ),
        ConfigKey(
            key="GPS_JAM_CRITICAL_THRESHOLD", domain="tune.maritime",
            default=7.0, type_="float",
            description="GPS jamming critical threshold.",
            group=GROUP_TUNE, min_value=1.0, max_value=30.0,
        ),
        ConfigKey(
            key="USGS_MIN_MAGNITUDE", domain="tune.maritime",
            default=4.0, type_="float",
            description="USGS minimum magnitude for cable risk.",
            group=GROUP_TUNE, min_value=2.0, max_value=8.0,
        ),

        # ── GDELT ────────────────────────────────────────────────────────
        ConfigKey(
            key="GDELT_TONE_ALERT_THRESHOLD", domain="tune.gdelt",
            default=-15.0, type_="float",
            description="GDELT tone alert threshold (negative = hostile).",
            group=GROUP_TUNE, min_value=-100.0, max_value=0.0,
            what="GDELT geopolitical tone score below which the sensor "
                 "fires (range −100…+100; more negative = more hostile).",
            why="Empirical baselines: −12…−15 precedes military tension; "
                 "−18…−25 precedes invasion. -15.0 is the early-warning "
                 "floor that catches escalation before kinetic onset.",
            when="Tighten (e.g. −12) for earlier signal at the cost of "
                 "more noise; loosen (−18) when tone is dominated by "
                 "routine media cycles unrelated to the scenario.",
        ),
        ConfigKey(
            key="GDELT_HISTORY_WINDOW", domain="tune.gdelt",
            default=28, type_="int",
            description="GDELT history window (days).",
            group=GROUP_TUNE, min_value=7, max_value=180, unit="d",
            what="Look-back window for the GDELT tone baseline used by "
                 "the z-score detector.",
            why="Long enough to absorb weekly news cycles (28d ≈ 4 weeks), "
                 "short enough that a regime shift doesn't take months to "
                 "show up as the new normal.",
            when="Shorten to 14d during regime transitions so baseline "
                 "reflects current reality. Lengthen for slow-news "
                 "regions.",
        ),

        # ════════════════════════════════════════════════════════════════
        # LLM HEALTH — connection / features / routing / embedding
        # ════════════════════════════════════════════════════════════════
        ConfigKey(
            key="LLM_ENABLED", domain="llm.connection",
            default=False, type_="bool",
            description="Master switch for LLM-powered text analysis.",
            group=GROUP_LLM_HEALTH,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="LLM_HOST", domain="llm.connection",
            default="http://localhost:11434", type_="str",
            description="Ollama API endpoint URL. Inside Docker on Mac/Win "
                        "use http://host.docker.internal:11434.",
            group=GROUP_LLM_HEALTH,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="LLM_MODEL", domain="llm.connection",
            default="llama3.2:3b", type_="str",
            description="Production fallback model. Used when no use_case "
                        "is supplied or the routing feature is OFF/SHADOW.",
            group=GROUP_LLM_HEALTH,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="LLM_TIMEOUT", domain="llm.connection",
            default=30, type_="int",
            description="Per-call HTTP timeout in seconds (live).",
            group=GROUP_LLM_HEALTH, min_value=5, max_value=600, unit="s",
            apply_timing=TIMING_LIVE_IMMEDIATE,
        ),
        ConfigKey(
            key="LLM_FEATURE_KILL_SWITCH", domain="llm.connection",
            default=False, type_="bool",
            description="Global kill switch — forces every LLM feature OFF.",
            group=GROUP_LLM_HEALTH,
            apply_timing=TIMING_LIVE_IMMEDIATE,
            impact_level="high",
            impact_warning="Disables ALL LLM analysis system-wide. Threat "
                          "scoring continues but loses LLM-extracted intel.",
        ),
        ConfigKey(
            key="LLM_EMBEDDING_MODEL", domain="llm.embedding",
            default="granite-embedding:278m", type_="str",
            description="Ollama tag of the embedding model used for OSINT dedupe.",
            group=GROUP_LLM_HEALTH,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),

        # ════════════════════════════════════════════════════════════════
        # INFRASTRUCTURE — restart-required transport / cache / polling
        # ════════════════════════════════════════════════════════════════
        ConfigKey(
            key="HTTP_PROXY", domain="infra.network",
            default="", type_="str",
            description="Outbound HTTP proxy (blank to disable).",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="HTTPS_PROXY", domain="infra.network",
            default="", type_="str",
            description="Outbound HTTPS proxy (blank to disable).",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="SSL_VERIFY", domain="infra.network",
            default=True, type_="bool",
            description="Verify TLS certs on outbound HTTP. Disable only "
                        "for diagnostic use.",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
            impact_level="med",
        ),
        ConfigKey(
            key="CACHE_EXPIRY", domain="infra.cache",
            default=900, type_="int",
            description="Default cache expiry (seconds).",
            group=GROUP_INFRASTRUCTURE, min_value=60, max_value=86400, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="OPENSKY_MIN_INTERVAL", domain="infra.poll",
            default=10, type_="int",
            description="OpenSky minimum poll interval (seconds).",
            group=GROUP_INFRASTRUCTURE, min_value=1, max_value=600, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="NARRATIVE_POLL_INTERVAL", domain="infra.poll",
            default=1800, type_="int",
            description="Narrative poll interval (seconds).",
            group=GROUP_INFRASTRUCTURE, min_value=300, max_value=86400, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="TELEGRAM_MIRROR_POLL_INTERVAL", domain="infra.poll",
            default=300, type_="int",
            description="Telegram mirror poll interval (seconds).",
            group=GROUP_INFRASTRUCTURE, min_value=60, max_value=3600, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="CHECKHOST_POLL_INTERVAL", domain="infra.poll",
            default=600, type_="int",
            description="Check-Host poll interval (seconds).",
            group=GROUP_INFRASTRUCTURE, min_value=60, max_value=3600, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="CHECKHOST_TIMEOUT_MS", domain="infra.poll",
            default=5000, type_="int",
            description="Check-Host timeout (ms).",
            group=GROUP_INFRASTRUCTURE, min_value=500, max_value=60000, unit="ms",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="CHECKHOST_NODES", domain="infra.poll",
            default=[], type_="list[str]",
            description="Check-Host node list.",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="TELEGRAM_ATTACK_KEYWORDS", domain="infra.poll",
            default=[], type_="list[str]",
            description="Telegram attack keywords (comma-separated).",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_LIVE_NEXT_TICK,
        ),
        ConfigKey(
            key="TELEGRAM_CLAIM_CONFIDENCE_THRESHOLD",
            domain="infra.poll",
            default=0.5, type_="float",
            description="Telegram claim confidence threshold.",
            group=GROUP_INFRASTRUCTURE, min_value=0.0, max_value=1.0,
        ),

        # ── Server / bootstrap ───────────────────────────────────────────
        ConfigKey(
            key="SERVER_HOST", domain="infra.server",
            default="127.0.0.1", type_="str",
            description="Bind address. Bootstrap-only.",
            group=GROUP_INFRASTRUCTURE, bootstrap=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="SERVER_PORT", domain="infra.server",
            default=8000, type_="int",
            description="Bind port. Bootstrap-only.",
            group=GROUP_INFRASTRUCTURE, bootstrap=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="FLASK_DEBUG", domain="infra.server",
            default=False, type_="bool",
            description="Flask debug mode. NEVER enable in production.",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
            impact_level="high",
            impact_warning="Debug mode exposes the Werkzeug debugger which "
                          "is an arbitrary-code-execution surface. Production: NEVER.",
        ),
        ConfigKey(
            key="PERSISTENCE_SAVE_INTERVAL", domain="infra.server",
            default=300, type_="int",
            description="Persistence save interval (seconds).",
            group=GROUP_INFRASTRUCTURE, min_value=30, max_value=3600, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),

        # ── Plugins ──────────────────────────────────────────────────────
        ConfigKey(
            key="PLUGIN_DIR", domain="infra.plugins",
            default="plugins", type_="str",
            description="Plugin loader directory.",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="PLUGIN_ENABLED", domain="infra.plugins",
            default="*", type_="str",
            description="Enabled plugins (comma-separated, * = all).",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),
        ConfigKey(
            key="PLUGIN_DISABLED", domain="infra.plugins",
            default="", type_="str",
            description="Plugins to explicitly disable (comma-separated).",
            group=GROUP_INFRASTRUCTURE,
            apply_timing=TIMING_RESTART_REQUIRED, restart_required=True,
        ),

        # ════════════════════════════════════════════════════════════════
        # ACCESS — secrets, JWT, admin (env-only via secret/immutable flags)
        # ════════════════════════════════════════════════════════════════
        ConfigKey(
            key="JWT_SECRET_KEY", domain="access.jwt",
            default="", type_="str",
            description="JWT signing secret. Random if blank (rotates per restart).",
            group=GROUP_ACCESS, secret=True, immutable=True, bootstrap=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="JWT_ACCESS_EXPIRES", domain="access.jwt",
            default=3600, type_="int",
            description="Access-token expiry (seconds).",
            group=GROUP_ACCESS, immutable=True, bootstrap=True, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="JWT_REFRESH_EXPIRES", domain="access.jwt",
            default=86400, type_="int",
            description="Refresh-token expiry (seconds).",
            group=GROUP_ACCESS, immutable=True, bootstrap=True, unit="s",
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="DEFAULT_ADMIN_PASSWORD", domain="access.admin",
            default="", type_="str",
            description="Admin password on first startup. Change via API after deploy.",
            group=GROUP_ACCESS, secret=True, immutable=True, bootstrap=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),

        # ── External API credentials ─────────────────────────────────────
        ConfigKey(
            key="CF_API_TOKEN", domain="access.api_keys",
            default="", type_="str",
            description="Cloudflare Radar API token.",
            group=GROUP_ACCESS, secret=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="OWM_API_KEY", domain="access.api_keys",
            default="", type_="str",
            description="OpenWeatherMap API key.",
            group=GROUP_ACCESS, secret=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="GREYNOISE_API_KEY", domain="access.api_keys",
            default="", type_="str",
            description="GreyNoise API key (optional, lifts rate limits).",
            group=GROUP_ACCESS, secret=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="THREATFOX_API_KEY", domain="access.api_keys",
            default="", type_="str",
            description="ThreatFox API key (optional).",
            group=GROUP_ACCESS, secret=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="OPENSKY_CLIENT_ID", domain="access.api_keys",
            default="", type_="str",
            description="OpenSky OAuth2 client ID.",
            group=GROUP_ACCESS, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="OPENSKY_CLIENT_SECRET", domain="access.api_keys",
            default="", type_="str",
            description="OpenSky OAuth2 client secret.",
            group=GROUP_ACCESS, secret=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="ACLED_API_KEY", domain="access.api_keys",
            default="", type_="str",
            description="ACLED ground-truth API key.",
            group=GROUP_ACCESS, secret=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="ACLED_API_EMAIL", domain="access.api_keys",
            default="", type_="str",
            description="ACLED API email (paired with API key).",
            group=GROUP_ACCESS, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),
        ConfigKey(
            key="CERTSPOTTER_API_TOKEN", domain="access.api_keys",
            default="", type_="str",
            description="Certspotter API token (optional, raises rate limits).",
            group=GROUP_ACCESS, secret=True, immutable=True,
            apply_timing=TIMING_RESTART_REQUIRED,
        ),

        # ── Webhooks (URLs are secrets — they are bearer-style endpoints) ─
        ConfigKey(
            key="NOTIFY_SLACK_WEBHOOK", domain="access.webhooks",
            default="", type_="str",
            description="Slack webhook URL.",
            group=GROUP_ACCESS, secret=True,
            apply_timing=TIMING_LIVE_IMMEDIATE,
        ),
        ConfigKey(
            key="NOTIFY_TEAMS_WEBHOOK", domain="access.webhooks",
            default="", type_="str",
            description="Microsoft Teams webhook URL.",
            group=GROUP_ACCESS, secret=True,
            apply_timing=TIMING_LIVE_IMMEDIATE,
        ),
        ConfigKey(
            key="NOTIFY_WEBHOOK_URL", domain="access.webhooks",
            default="", type_="str",
            description="Generic webhook URL.",
            group=GROUP_ACCESS, secret=True,
            apply_timing=TIMING_LIVE_IMMEDIATE,
        ),

        # ── Auto-apply tier governor (self-promoting calibration) ────────
        # Cap on the auto_apply tier the system can promote itself to.
        # 0 = halt all auto-apply (proposals still recorded for audit).
        # 3 = full self-tuning, including HIGH-impact registry keys.
        # The governor will never *exceed* this cap; analysts can pin
        # the system at a lower tier even if metrics qualify for more.
        ConfigKey(
            key="AUTO_CALIBRATION_TIER_CAP", domain="audit.changes",
            default=3, type_="int",
            description="Auto-apply tier ceiling (0=off, 3=full).",
            group=GROUP_OPERATE, min_value=0, max_value=3,
            apply_timing=TIMING_LIVE_IMMEDIATE,
            impact_level="high",
            impact_warning="Lowering this halts auto-tune at runtime; "
                           "raising it lets the governor consider "
                           "promotion on the next daily evaluation.",
            what="Maximum auto-apply tier the self-promoting governor "
                 "is allowed to reach. Tier 0 disables auto-apply "
                 "system-wide; Tier 3 enables full self-tuning across "
                 "LOW/MED/HIGH impact keys.",
            why="Operator kill-switch separate from per-proposal safety "
                 "rules. Independent of the tier governor's own "
                 "evaluation so an analyst can pin the system back to "
                 "a known-good state during an incident.",
            when="Drop to 0 immediately on any suspicion of mis-tuning. "
                 "Restore to 3 after the cause is understood; the "
                 "governor will re-promote on its own schedule if "
                 "conditions warrant.",
        ),
        ConfigKey(
            key="AUTO_APPLY_HIGH_COOLDOWN_HOURS", domain="audit.changes",
            default=24.0, type_="float",
            description="Cooldown for LOW/MED calibrators after a HIGH change.",
            group=GROUP_OPERATE, min_value=1.0, max_value=168.0, unit="h",
            apply_timing=TIMING_LIVE_IMMEDIATE,
            what="When a HIGH-impact key is auto-applied at Tier 3, "
                 "downstream LOW/MED calibrators are paused for this "
                 "many hours so they don't pile chained proposals onto "
                 "a single unproven change.",
            why="Anti-oscillation. A HIGH change rebalances the entire "
                 "scoring landscape; LOW/MED calibrators that propose "
                 "during the absorption window are reacting to a "
                 "transient state.",
            when="Lengthen to 48-72h during initial Tier 3 operation; "
                 "shorten to 12h once the system shows stable behaviour "
                 "across multiple HIGH changes.",
        ),
    )
except Exception:
    # Registration is best-effort. NP3 — never crash on registry errors.
    import traceback as _tb
    _tb.print_exc()
