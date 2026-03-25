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
    "PG": "Oceania",
}
ISR_HOTSPOTS: list = []
ADVERSARY_NARRATIVE_SOURCES: dict = {}   # keyed by adversary country code (RU/CN/IR/KP/BY)
STRATEGIC_BLOCS: dict = {}               # bloc definitions for UI grouping
COUNTRY_BLOC_TAGS: dict = {}             # country -> list of blocs (multi-threat countries)
TACTICAL_KEYWORDS: dict = {}
HISTORICAL_EVENTS: list = []
CABLE_ROUTES: list = []
THREAT_ACTOR_MAPPING:  dict = {}
INFRASTRUCTURE_URLS:   dict = {}
TELEGRAM_CHANNEL_META: dict = {}
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
        HISTORICAL_EVENTS   = geo_data.get("HISTORICAL_EVENTS", [])
        CABLE_ROUTES        = geo_data.get("CABLE_ROUTES", [])
        THREAT_ACTOR_MAPPING   = geo_data.get("THREAT_ACTOR_MAPPING", {})
        INFRASTRUCTURE_URLS    = geo_data.get("INFRASTRUCTURE_URLS", {})
        TELEGRAM_CHANNEL_META  = geo_data.get("TELEGRAM_CHANNEL_META", {})
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


DEFAULT_CORE        = os.getenv("DEFAULT_CORE", "TW")
DEFAULT_CORRELATES  = [x.strip() for x in os.getenv("DEFAULT_CORRELATES", "JP,US").split(",") if x.strip()]
DEFAULT_ADVERSARIES = [x.strip() for x in os.getenv("DEFAULT_ADVERSARIES", "CN,RU,KP").split(",") if x.strip()]
DEFAULT_PINS        = [x.strip() for x in os.getenv("DEFAULT_PINS", "TW,JP,US").split(",") if x.strip()]

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
SEQUENCE_PARTIAL_BONUS   = int(os.getenv("SEQUENCE_PARTIAL_BONUS", "1"))
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

# S7: CT Log
CT_LOG_SURGE_THRESHOLD        = int(os.getenv("CT_LOG_SURGE_THRESHOLD", "100"))
CT_LOG_GOV_TLDS: dict[str, list] = {
    "TW": ["gov.tw", "mil.tw"],
    "JP": ["go.jp", "mod.go.jp"],
    "KR": ["go.kr", "mil.kr"],
    "CN": ["gov.cn", "mil.cn"],
    "RU": ["gov.ru", "mil.ru"],
    "UA": ["gov.ua", "mil.gov.ua"],
    "IR": ["gov.ir", "ir"],
    "IL": ["gov.il", "idf.il"],
    "US": ["gov", "mil"],
    "PH": ["gov.ph"],
}
