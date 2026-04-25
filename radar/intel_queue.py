"""radar.intel_queue -- LLM Intelligence Queue Manager.

Manages the lifecycle of LLM-analyzed intel items:
  - Receiving new items from sensors
  - Auto-confirming high-confidence items (≥ LLM_AUTO_CONFIRM_THRESHOLD)
  - Discarding low-confidence items (< LLM_CONFIDENCE_MIN)
  - Adjusting source credibility based on CLASSIFY THREAT outcomes
  - Applying confirmed score deltas to the threat engine

Usage (from sensor):
    from radar.intel_queue import intel_queue
    intel_queue.submit(item_dict)

Usage (from routes):
    from radar.intel_queue import intel_queue
    items = intel_queue.list_items(source_type="hacktivist")
    intel_queue.confirm(item_id, analyst="admin")
    intel_queue.reject(item_id, analyst="admin")
    intel_queue.override(item_id, analyst="admin")
"""
from __future__ import annotations
import logging
import math
import os
import threading
import time
import uuid
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qs
from radar.config import LLM_ENABLED
from radar.database import db


def _auto_confirm_threshold() -> float:
    return float(os.getenv("LLM_AUTO_CONFIRM_THRESHOLD", "0.80"))

def _confidence_min() -> float:
    return float(os.getenv("LLM_CONFIDENCE_MIN", "0.35"))

def _tier3_conf_threshold() -> float:
    # Tier 3 (corroborated) confidence floor. Lower than tier1/tier2
    # because corroboration from a separate ecosystem provides the
    # safety net normally supplied by per-call confidence.
    return float(os.getenv("LLM_AUTO_CONFIRM_TIER3_CONF", "0.70"))

def _tier3_cred_threshold() -> float:
    return float(os.getenv("LLM_AUTO_CONFIRM_TIER3_CRED", "0.75"))

def _item_ttl_seconds() -> float:
    """How long (seconds) a confirmed item contributes to active rationale.
    Acts as a hard floor; age-decay (ADR-023) usually zeroes contribution
    well before this TTL is reached."""
    return float(os.getenv("INTEL_ITEM_TTL_HOURS", "48")) * 3600

def _max_items_per_source_country() -> int:
    """Max active items per (source_type, theater) in rationale. Prevents score inflation."""
    return int(os.getenv("INTEL_MAX_ITEMS_PER_SOURCE_COUNTRY", "2"))

def _pending_auto_reject_hours() -> float:
    """Hours after which unreviewed PENDING items are automatically rejected.
    Set to 0 to disable auto-reject."""
    return float(os.getenv("LLM_PENDING_AUTO_REJECT_HOURS", "24"))

def _decay_enabled() -> bool:
    """Whether to apply age-decay to confirmed intel contributions (ADR-023)."""
    return os.getenv("INTEL_AGE_DECAY_ENABLED", "true").strip().lower() not in (
        "false", "0", "no", "off", ""
    )

def _decay_tau_hours(source_type: str = "") -> float:
    """Decay time constant τ (hours) for exponential age-decay.

    Per-source override via INTEL_AGE_DECAY_TAU_HOURS_<SOURCE_TYPE_UPPER>;
    falls back to INTEL_AGE_DECAY_TAU_HOURS (default 12h).
    Returning 0 or negative disables decay (weight stays 1.0).
    """
    if source_type:
        per_source = os.getenv(
            f"INTEL_AGE_DECAY_TAU_HOURS_{source_type.upper()}", ""
        ).strip()
        if per_source:
            try:
                return float(per_source)
            except ValueError:
                pass
    return float(os.getenv("INTEL_AGE_DECAY_TAU_HOURS", "12"))

def _age_weight(age_sec: float, source_type: str = "") -> float:
    """Exponential age-decay weight applied to LLM intel contributions.

    Fresh intel (age=0) gets full weight 1.0; weight falls to 1/e ≈ 0.37
    at age=τ, to 0.14 at age=2τ. Binary TTL cut-off is preserved as a hard
    safety floor (enforced elsewhere by _item_ttl_seconds()).

    Design intent (ADR-023): eliminate the cliff effect where analyst
    confirmation flipped contribution from 0 to full in one step, and the
    24h→24h+1s TTL boundary dropped an active item to 0 instantly. Score now
    reflects both analyst validation AND recency.
    """
    if not _decay_enabled():
        return 1.0
    tau_hours = _decay_tau_hours(source_type)
    if tau_hours <= 0:
        return 1.0
    age_clamped = max(0.0, float(age_sec))
    return math.exp(-age_clamped / (tau_hours * 3600.0))

log = logging.getLogger("radar")

# ── Age-decay startup log (ADR-023) ───────────────────────────────────────────
# Emit once at import so operators can confirm active decay settings without
# reading env files. Per-source τ overrides are logged lazily on first use.
if _decay_enabled():
    log.info(
        "[IntelAgeDecay] ADR-023 active: tau=%.1fh (w=e^-1 at age=tau, "
        "w=0.14 at 2*tau). TTL floor: %.1fh",
        _decay_tau_hours(),
        float(os.getenv("INTEL_ITEM_TTL_HOURS", "48")),
    )
else:
    log.info("[IntelAgeDecay] DISABLED via INTEL_AGE_DECAY_ENABLED=false — using binary TTL only")

# ── Source credibility bootstrap ──────────────────────────────────────────────
# Analyst feedback is the only path to adjust credibility upward after creation,
# but several archetypes of source are institutionally high- or low-authority
# from the moment they first appear. Seeding the initial credibility breaks the
# bootstrap deadlock where a government CERT advisory (authority-backed, zero
# marketing incentive, legally accountable) could never auto-confirm until an
# analyst happened to confirm one by hand.
#
# 0.85 — government CERT / national cyber authority (CISA, NCSC-UK, JPCERT,
#        CERT-Bund, ACSC, CCCS): advisories are published only for confirmed
#        threats, attribution is reviewed, no marketing incentive.
# 0.75 — established defense/military reporting (USNI, PACOM, DefenseNews,
#        Stars & Stripes, Janes): editorial standards, professional OSINT
#        pipeline, but still secondary sourcing.
# 0.60 — state propaganda outlets (TASS, PLA Daily, Xinhua, Sputnik): may
#        carry authentic signal but also deliberate misdirection — never
#        auto-confirm, always analyst review.
# 0.60 — hacktivist Telegram channels: frequent false claims of attacks that
#        never materialized; treat as leads, not intelligence.
# 0.70 — default for unrecognized source_id (conservative middle).
#
# Each bucket is matched by source_id prefix because source_id is assembled
# deterministically by each sensor (e.g. "cert_cisa_advisories",
# "military_usni_news", "hacktivist_dragonforceio").
_CREDIBILITY_BOOTSTRAP: list[tuple[tuple[str, ...], float]] = [
    # Government CERTs — prefix matches radar.sensors.apt_intel._CERT_SOURCES
    (("cert_cisa_advisories", "cert_cisa_alerts", "cert_ncsc_uk",
      "cert_jpcert", "cert_cert_bund", "cert_acsc", "cert_cccs"), 0.85),
    # Established defense reporting — matches military_exercise._MILITARY_SOURCES
    (("military_pacom_news", "military_usni_news", "military_defense_news",
      "military_janes", "military_stars_stripes"), 0.75),
    # State propaganda: distinctly below auto-confirm threshold
    (("military_tass_military", "military_pla_daily"), 0.60),
    # Hacktivist feeds: aspirational claims, high false-positive rate
    (("hacktivist_",), 0.60),
]


# ── Media ecosystem classification ───────────────────────────────────────────
# Used to determine corroboration independence: sources within the same
# ecosystem cannot corroborate each other (TASS + Sputnik = same ecosystem).
# State media ecosystems end with "_state" and are never auto-confirmed.
_MEDIA_ECOSYSTEMS: list[tuple[str, str]] = [
    # Russian state media
    ("military_tass_military", "ru_state"),
    ("military_sputnik", "ru_state"),
    ("military_ria_novosti", "ru_state"),
    ("military_rt_", "ru_state"),
    # Chinese state media
    ("military_pla_daily", "cn_state"),
    ("military_xinhua", "cn_state"),
    ("military_global_times", "cn_state"),
    ("military_cctv", "cn_state"),
    # Iranian state media
    ("military_press_tv", "ir_state"),
    ("military_fars_news", "ir_state"),
    ("military_tasnim", "ir_state"),
    # US government sources (not state propaganda but government-published)
    ("military_pacom_news", "us_gov"),
    ("military_stars_stripes", "us_gov"),
    # Independent defense reporting
    ("military_usni_news", "independent"),
    ("military_defense_news", "independent"),
    ("military_janes", "independent"),
    # CERTs (independent by nature — each country's CERT is separate)
    ("cert_", "cert"),
    # Hacktivist channels (independent per channel but low credibility)
    ("hacktivist_", "hacktivist"),
]


def classify_ecosystem(source_id: str) -> str:
    """Classify a source_id into its media ecosystem.

    Longest-prefix match wins, matching the same strategy as
    _initial_credibility(). Returns empty string for unclassified sources.
    """
    sid = (source_id or "").lower()
    best_len = 0
    best_eco = ""
    for prefix, eco in _MEDIA_ECOSYSTEMS:
        if sid.startswith(prefix) and len(prefix) > best_len:
            best_len = len(prefix)
            best_eco = eco
    return best_eco


def _corroboration_payload(corroborators: list, *source_ids: str) -> dict:
    """Build the dict written to llm_fields for corroboration tracking.

    Always returns BOTH `corroborating_sources` and `corroborating_ecosystems`
    so the two never drift apart — the triage UI relies on ecosystem diversity
    to flag independent corroboration. `*source_ids` are extra source IDs
    whose ecosystems should be included beyond the corroborator list itself
    (typically the previously-stored primary source and the incoming source).
    """
    eco_set = {classify_ecosystem(s) for s in corroborators}
    for sid in source_ids:
        eco_set.add(classify_ecosystem(sid))
    return {
        "corroborating_sources": list(corroborators),
        "corroborating_ecosystems": sorted(eco_set - {""}),
    }


_AUTO_CONFIRM_ELIGIBLE_ECOSYSTEMS: frozenset[str] = frozenset(
    {"independent", "cert", "us_gov"}
)


def _resolve_auto_confirm_status(
    *,
    confidence: float,
    credibility: float,
    ecosystem: str,
    corroborator_count: int,
    source_id: str,
    headline: str,
) -> tuple[str, str]:
    """Decide auto_confirm tier for an item.

    Returns (status, verdict_tag). status is "auto_confirmed" or "pending".
    verdict_tag distinguishes tier1 / tier2 / tier3 / pending so analytics
    can break out the corroborated tier separately.

    Ecosystem gate (ADR-025): state-media and unclassified sources are
    always pending regardless of confidence/credibility. Tier 3 does not
    relax this — corroboration from inside the same propaganda ecosystem
    is not real corroboration.
    """
    if ecosystem not in _AUTO_CONFIRM_ELIGIBLE_ECOSYSTEMS:
        log.info(f"[Intel] ECOSYSTEM_GATE: {source_id!r} "
                 f"(eco={ecosystem!r}) held for analyst review "
                 f"despite conf={confidence:.2f}/cred={credibility:.2f}")
        return ("pending", "pending")
    if confidence >= 0.85 and credibility >= 0.80:
        log.info(f"[Intel] AUTO-CONFIRMED (tier1): {headline[:80]} "
                 f"(conf={confidence:.2f}, cred={credibility:.2f})")
        return ("auto_confirmed", "auto_confirmed")
    if confidence >= _auto_confirm_threshold() and credibility >= 0.75:
        log.info(f"[Intel] AUTO-CONFIRMED (tier2): {headline[:80]} "
                 f"(conf={confidence:.2f}, cred={credibility:.2f})")
        return ("auto_confirmed", "auto_confirmed")
    if (confidence >= _tier3_conf_threshold()
            and credibility >= _tier3_cred_threshold()
            and corroborator_count >= 1):
        log.info(f"[Intel] AUTO-CONFIRMED (tier3 corroborated): {headline[:80]} "
                 f"(conf={confidence:.2f}, cred={credibility:.2f}, "
                 f"corroborators={corroborator_count})")
        return ("auto_confirmed", "auto_confirmed_corroborated")
    log.info(f"[Intel] PENDING review: {headline[:80]} "
             f"(conf={confidence:.2f}, cred={credibility:.2f}, "
             f"corroborators={corroborator_count})")
    return ("pending", "pending")


def _initial_credibility(source_id: str) -> float:
    """Return the seed credibility weight for a newly-seen source_id.

    Longest-prefix match wins so that e.g. "cert_cisa_advisories" is scored
    before a hypothetical "cert_" wildcard. Falls back to 0.70 when nothing
    matches — same as the schema default.
    """
    sid = (source_id or "").lower()
    best_len = 0
    best_weight = 0.70
    for prefixes, weight in _CREDIBILITY_BOOTSTRAP:
        for p in prefixes:
            if sid.startswith(p) and len(p) > best_len:
                best_len = len(p)
                best_weight = weight
    return best_weight


# In-memory set of currently active (auto_confirmed or confirmed) item IDs
# for fast rationale injection into the scoring engine.
# Protected by _active_lock for thread-safe access from sensor threads,
# analyst routes, and the cleanup worker.
_active_item_ids: set[str] = set()
_active_lock = threading.Lock()

# Stop-words to exclude from Jaccard headline comparison
_HEADLINE_STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for",
    "of", "is", "are", "was", "were", "be", "by", "with", "from",
    "this", "that", "as", "it", "its", "has", "have", "had",
    "near", "over", "after", "before", "during", "amid",
})

_DEDUP_WINDOW_SECONDS = 48 * 3600   # 48-hour dedup window
_JACCARD_THRESHOLD = 0.60           # headline similarity threshold for same-event dedup
_XTYPE_JACCARD_THRESHOLD = 0.70     # stricter threshold for cross-source-type dedup


def _normalize_url(url: str) -> str:
    """Minimal URL normalization for dedup comparison."""
    if not url:
        return ""
    try:
        p = urlparse(url)
        # Normalize scheme to https
        scheme = "https"
        # Strip tracking params
        qs = parse_qs(p.query, keep_blank_values=False)
        for k in list(qs):
            if k.startswith("utm_") or k in ("ref", "source", "fbclid", "gclid"):
                del qs[k]
        clean_q = urlencode(sorted(qs.items()), doseq=True)
        # Strip trailing slash from path
        path = p.path.rstrip("/") or "/"
        return f"{scheme}://{p.netloc}{path}{'?' + clean_q if clean_q else ''}"
    except Exception:
        return url


def _headline_tokens(headline: str) -> frozenset:
    """Extract significant words from a headline for Jaccard comparison."""
    import re
    words = re.findall(r"[a-z]{3,}", headline.lower())
    return frozenset(w for w in words if w not in _HEADLINE_STOPWORDS)


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0.0


class IntelQueue:
    """LLM Intel item lifecycle manager."""

    def _record_verdict(self, source_type: str, verdict: str,
                        confidence: float, headline: str) -> None:
        """Update the most recent llm_call_log row for this source_type with
        the queue verdict (auto_confirmed/pending/discarded_low_conf/discarded_dedup/discarded_dedup_xtype).

        Best-effort: never raises. The llm_client already wrote a row with empty
        verdict — we patch it in place via db.llm_call_patch_verdict() which
        matches by caller (sensor module leaf name).
        """
        # Map source_type (what the sensor writes into the item dict) to the
        # caller module name(s) that llm_analyze_json records in llm_call_log.
        # caller = the leaf module name returned by _infer_caller, so it must
        # match the .py filename stem exactly. Keys on the left are the
        # `source_type` values the sensors actually submit — historically this
        # table used "apt" while the sensor submits "apt_intel", which silently
        # dropped every apt_intel verdict patch for years.
        _CALLER_BY_TYPE = {
            "hacktivist":   ("hacktivist_intel_sensor", "hacktivist_news_sensor"),
            "diplomatic":   ("diplomatic",),
            "military":     ("military_exercise",),
            "ground_osint": ("ground_osint_sensor",),
            "apt_intel":    ("apt_intel",),
            "narrative":    ("rss_narrative",),
        }
        callers = _CALLER_BY_TYPE.get(source_type, ())
        if not callers:
            return
        db.llm_call_patch_verdict(callers, verdict, window_sec=60)

    def _maybe_promote_corroborated(self, ex_id: str) -> None:
        """Re-evaluate a pending item that just gained a corroborator.

        Tier 3 only triggers when at least one independent source agrees,
        and corroboration is enriched DURING the dedup pass. So a pending
        item can only ever cross the tier-3 threshold here — the original
        submit() call had ``corroborator_count = 0`` for the new item and
        could not consult the existing record's count. Without this hook
        the corroborated item sits pending until manual review, defeating
        the entire point of tier 3.
        """
        fresh = db.intel_get(ex_id)
        if not fresh or fresh.get("status") != "pending":
            return
        ex_source_id = fresh.get("source_id", "")
        ex_source = db.intel_source_get(ex_source_id)
        ex_credibility = ex_source["credibility_weight"] if ex_source else 0.70
        ex_ecosystem = classify_ecosystem(ex_source_id)
        ex_llm = fresh.get("llm_fields", {}) or {}
        ex_corroborator_count = len(ex_llm.get("corroborating_sources", []))
        status, verdict_tag = _resolve_auto_confirm_status(
            confidence=fresh.get("confidence", 0.0),
            credibility=ex_credibility,
            ecosystem=ex_ecosystem,
            corroborator_count=ex_corroborator_count,
            source_id=ex_source_id,
            headline=fresh.get("headline", ""),
        )
        if status != "auto_confirmed":
            return
        db.intel_update_status(
            ex_id, "auto_confirmed",
            confirmed_by=None, confirmed_at=time.time(),
        )
        with _active_lock:
            _active_item_ids.add(ex_id)
        self._record_verdict(
            fresh.get("source_type", "unknown"),
            verdict_tag,
            fresh.get("confidence", 0.0),
            fresh.get("headline", ""),
        )
        log.info(
            f"[Intel] LATE_PROMOTION: {ex_id} → auto_confirmed "
            f"(corroborators={ex_corroborator_count}, tag={verdict_tag})"
        )

    def submit(self, item: dict) -> Optional[str]:
        """Accept a new LLM-analyzed item from a sensor.

        item must contain:
            source_type  : hacktivist | diplomatic | military | ground_osint
            source_id    : channel/feed identifier (for credibility tracking)
            theater      : e.g. "TW" (legacy, kept for backward compat)
            countries    : list[str] — multi-country tags (Phase 3)
            country_weights : dict[str, float] — LLM relevance per country
            ts           : Unix timestamp of the original text
            confidence   : LLM confidence (0.0–1.0)
            raw_text     : original text
            raw_url      : source URL (optional)
            headline     : LLM-generated one-line summary
            llm_fields   : dict of source-type-specific extracted fields
            score_delta  : points to add on confirmation
            domain       : cyber | physical | info

        Returns item ID if accepted, None if discarded.
        """
        if not LLM_ENABLED:
            return None

        confidence = float(item.get("confidence", 0.0))
        source_id = item.get("source_id", "unknown")
        source_type = item.get("source_type", "unknown")
        headline = item.get("headline", "")

        # Multi-country support (Phase 3): derive countries from item,
        # fall back to legacy theater field for backward compatibility
        countries: list[str] = item.get("countries", [])
        country_weights: dict[str, float] = item.get("country_weights", {})
        theater = item.get("theater", "")
        if not countries and theater:
            countries = [theater]
            country_weights = {theater: 1.0}

        # Discard below minimum threshold
        if confidence < _confidence_min():
            log.debug(f"[Intel] Discarded low-confidence item ({confidence:.2f}) from {source_id}")
            self._record_verdict(source_type, "discarded_low_conf", confidence, headline)
            try:
                db.hidden_signal_log(
                    scenario_id=None,
                    country=(countries[0] if countries else theater) or None,
                    sensor=source_type, domain=item.get("domain", "info"),
                    hide_reason=f"intel_low_confidence ({confidence:.2f} < {_confidence_min():.2f})",
                    detail={"headline": headline, "source_id": source_id,
                            "confidence": confidence},
                )
            except Exception:
                pass
            return None

        # ── Layer 0: Cross-source-type raw_url dedup ──────────────────────────
        # Same URL = same article regardless of source_type.  Fastest and
        # most reliable dedup — runs before any Jaccard computation.
        raw_url = item.get("raw_url", "")
        norm_url = _normalize_url(raw_url)
        if norm_url and len(norm_url) > 15:
            since = time.time() - _DEDUP_WINDOW_SECONDS
            url_matches = db.intel_find_by_raw_url(norm_url, since_ts=since)
            # Also check original URL in case normalization changed it
            if not url_matches and norm_url != raw_url:
                url_matches = db.intel_find_by_raw_url(raw_url, since_ts=since)
            if url_matches:
                ex = url_matches[0]
                ex_llm = ex.get("llm_fields", {})
                corroborators: list = ex_llm.get("corroborating_sources", [])
                if source_id not in corroborators and source_id != ex.get("source_id"):
                    corroborators.append(source_id)
                    db.intel_update_llm_fields(ex["id"], {"corroborating_sources": corroborators})
                    self._maybe_promote_corroborated(ex["id"])
                log.info(
                    f"[Intel] Cross-type URL dedup: discarded {source_type}/{source_id!r} "
                    f"(URL matches existing {ex['source_type']}/{ex['source_id']!r})"
                )
                self._record_verdict(source_type, "discarded_dedup_xtype", confidence, headline)
                return None

        # ── Intra-source-type dedup: discard wire-service echo chambers ──────────
        # Within the same source_type with overlapping countries, check if we
        # already have a recent item (48h) with a similar headline (Jaccard >= 0.60
        # on significant words). If so, this is most likely the same event reported
        # by multiple outlets citing the same underlying source.
        #
        # Confidence-based replacement: if the new item has higher confidence than
        # the existing match, replace the existing item's analysis (headline,
        # confidence, score_delta, etc.) while preserving corroborating sources.
        #
        # Distinct-event protection: even if Jaccard matches, do NOT merge items
        # that have non-overlapping countries, different actors, or different
        # diplomatic actions (these are similar-but-distinct events).
        if headline:
            new_tokens = _headline_tokens(headline)
            new_llm = item.get("llm_fields", {})
            new_countries_set = set(countries)
            since = time.time() - _DEDUP_WINDOW_SECONDS
            existing = db.intel_list(source_type=source_type,
                                     limit=50, since_ts=since)
            for ex in existing:
                ex_countries_set = set(ex.get("countries", []))
                if not ex_countries_set and ex.get("theater"):
                    ex_countries_set = {ex["theater"]}
                if new_countries_set and ex_countries_set and not (new_countries_set & ex_countries_set):
                    continue  # non-overlapping regions — distinct events

                same_source = (ex.get("source_id") == source_id)
                ex_tokens = _headline_tokens(ex.get("headline", ""))
                jacc = _jaccard(new_tokens, ex_tokens)
                if jacc < _JACCARD_THRESHOLD:
                    continue  # sufficiently different headline — not a duplicate

                # Same source + similar headline = re-scraped identical content → discard
                if same_source:
                    log.debug(
                        f"[Intel] Dedup SKIP same-source: {source_id!r} "
                        f"Jaccard={jacc:.2f} headline={headline[:60]!r}"
                    )
                    self._record_verdict(source_type, "discarded_dedup", confidence, headline)
                    return None

                # Cross-source dedup: different source, similar headline
                # ── Distinct-event protection ──
                ex_llm = ex.get("llm_fields", {})
                # Different attributed actors → distinct events
                new_actor = new_llm.get("attributed_actor", "")
                ex_actor = ex_llm.get("attributed_actor", "")
                if new_actor and ex_actor and new_actor.lower() != ex_actor.lower():
                    continue  # different actors, not a duplicate
                # Different diplomatic actions → distinct events
                new_action = new_llm.get("diplomatic_action", "")
                ex_action = ex_llm.get("diplomatic_action", "")
                if new_action and ex_action and new_action != ex_action:
                    continue  # different actions, not a duplicate

                # ── Confidence-based replacement ──
                if confidence > ex.get("confidence", 0):
                    # New item is better — replace existing analysis, keep provenance
                    corroborators: list = list(ex_llm.get("corroborating_sources") or [])
                    old_src = ex.get("source_id", "")
                    if old_src and old_src not in corroborators:
                        corroborators.append(old_src)
                    merged_llm = new_llm.copy()
                    merged_llm.update(_corroboration_payload(corroborators, old_src, source_id))
                    db.intel_update_llm_fields(ex["id"], merged_llm)
                    db.intel_update_core_fields(
                        ex["id"],
                        headline=headline[:200],
                        confidence=confidence,
                        score_delta=float(item.get("score_delta", 0)),
                        raw_text=item.get("raw_text", "")[:1000],
                        raw_url=item.get("raw_url", ""),
                    )
                    log.info(
                        f"[Intel] Dedup REPLACE: {ex['source_id']!r} conf={ex['confidence']:.2f} "
                        f"→ {source_id!r} conf={confidence:.2f} (Jaccard={jacc:.2f})"
                    )
                else:
                    # Existing is same or better — just record corroborator
                    corroborators = list(ex_llm.get("corroborating_sources") or [])
                    if source_id not in corroborators:
                        corroborators.append(source_id)
                        db.intel_update_llm_fields(
                            ex["id"],
                            _corroboration_payload(corroborators, ex.get("source_id", "")),
                        )
                        self._maybe_promote_corroborated(ex["id"])
                    log.debug(
                        f"[Intel] Intra-type dedup: discarded {source_id!r} "
                        f"(Jaccard={jacc:.2f} vs {ex['source_id']!r}, "
                        f"headline: {headline[:60]})"
                    )
                    self._record_verdict(source_type, "discarded_dedup", confidence, headline)
                    return None  # don't create a new item either way
        # ─────────────────────────────────────────────────────────────────────────

        # ── Layer 2: Cross-source-type headline Jaccard dedup ────────────────
        # Catches duplicates where raw_url differs or is empty, but headlines
        # are substantially similar across different source_types.
        # Stricter threshold (0.70) because different LLM prompts naturally
        # produce more divergent headlines for the same article.
        if headline:
            _xt_tokens = _headline_tokens(headline)
            _xt_countries = set(countries)
            since = time.time() - _DEDUP_WINDOW_SECONDS
            xtype_existing = db.intel_list(source_type=None, limit=80, since_ts=since)
            for ex in xtype_existing:
                if ex.get("source_type") == source_type:
                    continue  # already checked in intra-source-type pass
                ex_countries_set = set(ex.get("countries", []))
                if not ex_countries_set and ex.get("theater"):
                    ex_countries_set = {ex["theater"]}
                if _xt_countries and ex_countries_set and not (_xt_countries & ex_countries_set):
                    continue  # non-overlapping regions — distinct events
                ex_tokens = _headline_tokens(ex.get("headline", ""))
                jacc = _jaccard(_xt_tokens, ex_tokens)
                if jacc < _XTYPE_JACCARD_THRESHOLD:
                    continue
                # Cross-source-type match — record corroboration and discard
                ex_llm = ex.get("llm_fields", {})
                corroborators: list = list(ex_llm.get("corroborating_sources") or [])
                if source_id not in corroborators and source_id != ex.get("source_id"):
                    corroborators.append(source_id)
                    db.intel_update_llm_fields(
                        ex["id"],
                        _corroboration_payload(corroborators, ex.get("source_id", "")),
                    )
                    self._maybe_promote_corroborated(ex["id"])
                log.info(
                    f"[Intel] Cross-type headline dedup: discarded {source_type}/{source_id!r} "
                    f"(Jaccard={jacc:.2f} vs {ex['source_type']}/{ex['source_id']!r})"
                )
                self._record_verdict(source_type, "discarded_dedup_xtype", confidence, headline)
                return None
        # ─────────────────────────────────────────────────────────────────────────

        # Seed archetype credibility on first sight. After this, intel_source
        # ops update the weight via analyst feedback only.
        source = db.intel_source_get(source_id)
        if source is None:
            seed = _initial_credibility(source_id)
            db.intel_source_upsert(source_id, source_type, credibility_weight=seed)
            source = db.intel_source_get(source_id)

        credibility = source["credibility_weight"] if source else 0.70

        item_id = item.get("id") or str(uuid.uuid4())
        now = time.time()

        # Determine initial status via staged auto_confirm with state media gate.
        # Fail-closed: only sources with a known-trusted ecosystem classification
        # are eligible for auto-confirm. State media and unclassified sources are
        # always held for analyst review.
        _ecosystem = classify_ecosystem(source_id)
        _llm_fields = item.get("llm_fields", {}) or {}
        _corroborator_count = len(_llm_fields.get("corroborating_sources", []))
        status, _verdict_tag = _resolve_auto_confirm_status(
            confidence=confidence,
            credibility=credibility,
            ecosystem=_ecosystem,
            corroborator_count=_corroborator_count,
            source_id=source_id,
            headline=headline,
        )
        if status == "auto_confirmed":
            with _active_lock:
                _active_item_ids.add(item_id)
        self._record_verdict(source_type, _verdict_tag, confidence, headline)

        record = {
            "id":          item_id,
            "source_type": source_type,
            "source_id":   source_id,
            "theater":     theater,
            "countries":   countries,
            "country_weights": country_weights,
            "ts":          item.get("ts", now),
            "status":      status,
            "confidence":  confidence,
            "raw_text":    item.get("raw_text", ""),
            "raw_url":     item.get("raw_url", ""),
            "headline":    item.get("headline", ""),
            "llm_fields":  item.get("llm_fields", {}),
            "score_delta": float(item.get("score_delta", 0.0)),
            "domain":      item.get("domain", "info"),
            "confirmed_by":  None,
            "confirmed_at":  now if status == "auto_confirmed" else None,
            "override_at":   None,
            "created_at":    now,
        }
        db.intel_upsert(record)

        # Push real-time notification to connected clients
        try:
            from radar.ws import emit_intel_update
            emit_intel_update(theater, {
                "id": item_id, "headline": headline[:120],
                "source_type": source_type, "status": status,
            })
        except Exception:
            pass  # WS not initialized during tests or early startup

        return item_id

    def confirm(self, item_id: str, analyst: str = "analyst") -> bool:
        """Manually confirm a PENDING item. Returns True if successful."""
        item = db.intel_get(item_id)
        if not item or item["status"] != "pending":
            return False
        now = time.time()
        db.intel_update_status(item_id, "confirmed",
                               confirmed_by=analyst, confirmed_at=now)
        with _active_lock:
            _active_item_ids.add(item_id)
        if item.get("source_id"):
            db.intel_source_record_outcome(item["source_id"], confirmed=True)
        log.info(f"[Intel] CONFIRMED by {analyst}: {item.get('headline', '')[:80]}")
        return True

    def reject(self, item_id: str, analyst: str = "analyst",
               classification: str = "irrelevant") -> bool:
        """Reject a PENDING item. Returns True if successful.

        classification:
            "irrelevant"     — accurate report but not relevant to the scenario.
                               No credibility penalty (source is not at fault).
            "false_positive" — inaccurate or misleading information.
                               Credibility penalty applied (-0.10).
        """
        item = db.intel_get(item_id)
        if not item or item["status"] != "pending":
            return False
        db.intel_update_status(item_id, "rejected",
                               confirmed_by=analyst, confirmed_at=time.time())
        with _active_lock:
            _active_item_ids.discard(item_id)
        if item.get("source_id") and classification == "false_positive":
            db.intel_source_record_outcome(item["source_id"], confirmed=False)
        tag = "FALSE_POS" if classification == "false_positive" else "IRRELEVANT"
        log.info(f"[Intel] REJECTED ({tag}) by {analyst}: {item.get('headline', '')[:80]}")
        return True

    def revert(self, item_id: str, analyst: str = "analyst") -> bool:
        """Revert a confirmed or rejected item back to pending.
        This undoes a manual confirm/reject decision so the analyst can re-decide.
        Not applicable to auto_confirmed items (use override() for those).
        Returns True if successful.

        Credibility handling:
          - Reverting a CONFIRMED item undoes the +0.05 credit (applies -0.05).
          - Reverting a REJECTED item has no credibility effect (the original
            reject may or may not have applied a penalty depending on its
            classification; that decision stands until the analyst re-decides).
        """
        item = db.intel_get(item_id)
        if not item or item["status"] not in ("confirmed", "rejected"):
            return False
        was_confirmed = item["status"] == "confirmed"
        db.intel_update_status(item_id, "pending",
                               confirmed_by=None, confirmed_at=None)
        if was_confirmed:
            with _active_lock:
                _active_item_ids.discard(item_id)
            if item.get("source_id"):
                # Undo the +0.05 from the original confirm — not a false positive.
                db.intel_source_update_credibility(item["source_id"], -0.05)
        log.info(f"[Intel] REVERTED to pending by {analyst}: {item.get('headline', '')[:80]}")
        return True

    def auto_reject_stale(self) -> int:
        """Auto-reject PENDING items older than LLM_PENDING_AUTO_REJECT_HOURS.
        Called hourly by the cache cleanup worker. Returns count of items rejected.
        """
        max_age_h = _pending_auto_reject_hours()
        if max_age_h <= 0:
            return 0
        cutoff = time.time() - max_age_h * 3600
        items = db.intel_list(status="pending", limit=500, before_ts=cutoff)
        rejected = 0
        for item in items:
            db.intel_update_status(item["id"], "rejected",
                                   confirmed_by="auto", confirmed_at=time.time())
            with _active_lock:
                _active_item_ids.discard(item["id"])
            rejected += 1
            log.info(f"[Intel] AUTO-REJECTED (stale): {item.get('headline', '')[:80]}")
        if rejected:
            log.info(f"[Intel] Auto-rejected {rejected} stale pending items (>{max_age_h}h)")
        return rejected

    def override(self, item_id: str, analyst: str = "analyst") -> bool:
        """Override an AUTO-CONFIRMED item (undo its score contribution).
        No time window restriction — analysts can override any auto_confirmed
        item as long as it has not already been overridden.
        Returns True if successful.
        """
        item = db.intel_get(item_id)
        if not item or item["status"] != "auto_confirmed":
            return False
        now = time.time()
        db.intel_update_status(item_id, "overridden",
                               confirmed_by=analyst, override_at=now)
        with _active_lock:
            _active_item_ids.discard(item_id)
        if item.get("source_id"):
            db.intel_source_record_outcome(item["source_id"], confirmed=False)
        log.info(f"[Intel] OVERRIDDEN by {analyst}: {item.get('headline', '')[:80]}")
        return True

    def notify_classify_threat(self, theater: str, classification: str,
                                ts: float = None):
        """Called when analyst submits a CLASSIFY THREAT event.
        Updates credibility of LLM sources active at that time.
        """
        if not LLM_ENABLED:
            return
        window_start = (ts or time.time()) - 3600  # ±1h window
        active = db.intel_active_in_window(since_ts=window_start)
        if not active:
            return

        is_confirmed = classification == "confirmed_threat"
        is_false_pos = classification in ("false_positive", "exercise")

        for item in active:
            src = item.get("source_id")
            if not src:
                continue
            if is_confirmed:
                db.intel_source_record_outcome(src, confirmed=True)
            elif is_false_pos:
                db.intel_source_record_outcome(src, confirmed=False)
                # If item is still actively contributing to score, flag for review
                with _active_lock:
                    if item["id"] in _active_item_ids:
                        db.intel_update_status(item["id"], "review_needed")
                        _active_item_ids.discard(item["id"])

        log.info(f"[Intel] classify_threat={classification} for {theater}, "
                 f"updated {len(active)} active items")

    def get_active_rationale(self) -> list[dict]:
        """Return rationale entries for all currently confirmed/auto_confirmed items.
        These are injected into the WeightedConvergenceEngine as llm_intel signals.

        Age-decay (ADR-023): each item's contribution is weighted by
        exp(-age_sec / τ) where τ is per-source configurable (default 12h).
        This smooths the confirm→full-weight cliff and lets older intel fade
        naturally rather than dropping at the TTL boundary. TTL is retained as
        a hard floor (default 48h).

        Score accumulation cap: at most INTEL_MAX_ITEMS_PER_SOURCE_COUNTRY items per
        (source_type, theater) pair contribute. Ranking is by *decayed* score so
        fresh high-signal items dominate the cap, and stale items exit the cap
        even if their raw score_delta was high.
        """
        if not LLM_ENABLED:
            return []
        # Fetch only confirmed/auto_confirmed items at the DB level
        items_ac = db.intel_list(status="auto_confirmed", limit=100)
        items_c  = db.intel_list(status="confirmed", limit=100)
        ttl = _item_ttl_seconds()
        cap = _max_items_per_source_country()
        now = time.time()

        # Filter to active items within TTL; compute decayed score upfront so
        # both ranking and Signal payload reuse the same value.
        active = []
        for item in items_ac + items_c:
            if item.get("override_at"):
                continue
            age_sec = now - item["ts"]
            if age_sec > ttl:
                continue
            weight = _age_weight(age_sec, item.get("source_type", ""))
            decayed = float(item["score_delta"]) * weight
            active.append((item, age_sec, weight, decayed))

        # Second pass: apply per-(source_type, theater) cap ranked by decayed score.
        from collections import defaultdict
        groups: dict = defaultdict(list)
        for tup in active:
            item = tup[0]
            key = (item["source_type"], item.get("theater", ""))
            groups[key].append(tup)

        result = []
        for key, group_tuples in groups.items():
            # Sort descending by decayed score; ties broken by confidence
            group_tuples.sort(key=lambda t: (t[3], t[0]["confidence"]), reverse=True)
            for item, age_sec, weight, decayed in group_tuples[:cap]:
                age_h = age_sec / 3600.0
                detail = (
                    f"[{item['source_type'].upper()}] {item['headline']} "
                    f"(age {age_h:.1f}h, w={weight:.2f})"
                )
                result.append({
                    "sensor":           "llm_intel",
                    "signal_source":    "llm_intel",
                    "score":            decayed,
                    "score_raw":        float(item["score_delta"]),
                    "age_hours":        age_h,
                    "age_weight":       weight,
                    "confidence":       item["confidence"],
                    "domain":           item["domain"],
                    "theater":          item.get("theater", ""),
                    "countries":        item.get("countries", []),
                    "country_weights":  item.get("country_weights", {}),
                    "status":           "FIRED",
                    "detail":           detail,
                    "suppressed":       False,
                    "raw_url":          item.get("raw_url", ""),
                    "llm_reasoning":    item.get("llm_fields", {}).get("gate_reason", ""),
                    # Provenance (F1): expose source ts + headline so the
                    # downstream rationale entry carries an analyst-verifiable trail.
                    "ts":               item["ts"],
                    "headline":         item.get("headline", ""),
                    "raw_text":         item.get("raw_text", ""),
                    "source_type":      item["source_type"],
                    "source_id":        item.get("source_id", ""),
                })
        return result

    def list_items(self, source_type: str = None, status: str = None,
                   theater: str = None, limit: int = 100) -> list[dict]:
        return db.intel_list(source_type=source_type, status=status,
                             theater=theater, limit=limit)

    def list_sources(self) -> list[dict]:
        return db.intel_source_list()

    def reseed_existing_credibility(self) -> int:
        """Apply _initial_credibility() to llm_sources rows that pre-date the
        bootstrap table. Only updates rows that have never received analyst
        feedback (confirmed_count=0 and false_positive_count=0) so we never
        overwrite learned state. Called once during startup restore.
        """
        updated = 0
        for row in db.intel_source_list():
            seed = _initial_credibility(row["source_id"])
            if abs(row["credibility_weight"] - seed) < 1e-6:
                continue  # already at target
            if row["confirmed_count"] > 0 or row["false_positive_count"] > 0:
                continue  # learned state present — respect it
            if db.intel_source_reset_credibility(row["source_id"], seed):
                log.info(
                    f"[Intel] Reseeded credibility: {row['source_id']} "
                    f"{row['credibility_weight']:.2f} → {seed:.2f}"
                )
                updated += 1
        return updated

    def enforce_archetype_floor(self) -> int:
        """Raise credibility back to archetype floor for sources that have
        decayed below it.  The floor is bootstrap_value - 0.20, ensuring
        that established defense reporting (bootstrap 0.75) can never drop
        below 0.55, and state propaganda (bootstrap 0.60) cannot drop below
        0.40.  This prevents the death-spiral where noisy-but-accurate sources
        are permanently locked out of auto-confirm.

        Unlike reseed_existing_credibility(), this runs even on sources with
        analyst feedback — that's the point: prior "irrelevant" rejects were
        incorrectly penalising credibility, and this corrects the baseline.

        Called once at startup, after reseed_existing_credibility().
        """
        updated = 0
        for row in db.intel_source_list():
            seed = _initial_credibility(row["source_id"])
            floor = max(seed - 0.20, 0.30)
            if row["credibility_weight"] < floor - 1e-6:
                db.intel_source_update_credibility(
                    row["source_id"],
                    floor - row["credibility_weight"],
                )
                log.info(
                    f"[Intel] Archetype floor applied: {row['source_id']} "
                    f"{row['credibility_weight']:.2f} → {floor:.2f} "
                    f"(bootstrap={seed:.2f})"
                )
                updated += 1
        return updated

    def promote_pending_after_reseed(self) -> int:
        """Sweep pending items that would now qualify for auto-confirm under the
        current credibility table. Exists because the reseed retroactively
        raises a source's weight above the auto-confirm floor: any pending item
        from that source that already has confidence ≥ threshold was only
        pending because of a bug/bootstrap gap, not because an analyst decided
        to hold it. Promote those so the scoring engine actually sees them.

        Called once during startup restore, after reseed_existing_credibility.
        """
        threshold = _auto_confirm_threshold()
        promoted = 0
        # Load every source's current credibility once so we don't re-query
        # inside the pending loop.
        creds = {s["source_id"]: s["credibility_weight"]
                 for s in db.intel_source_list()}
        for item in db.intel_list(status="pending", limit=500):
            conf = item.get("confidence", 0.0)
            if conf < threshold:
                continue
            sid = item.get("source_id", "")
            if creds.get(sid, 0.0) < 0.75:
                continue
            # Ecosystem gate (fail-closed): only promote sources with
            # known-trusted ecosystem classification
            if classify_ecosystem(sid) not in {"independent", "cert", "us_gov"}:
                continue
            now = time.time()
            db.intel_update_status(
                item["id"], "auto_confirmed",
                confirmed_by="system_reseed", confirmed_at=now,
            )
            with _active_lock:
                _active_item_ids.add(item["id"])
            log.info(
                f"[Intel] PROMOTED after reseed: {item.get('headline', '')[:80]} "
                f"(src={sid}, conf={conf:.2f}, cred={creds.get(sid, 0):.2f})"
            )
            promoted += 1
        return promoted

    def stats(self) -> dict:
        counts = db.intel_status_counts()
        return {
            "auto_confirmed": counts.get("auto_confirmed", 0),
            "pending":        counts.get("pending", 0),
            "confirmed":      counts.get("confirmed", 0),
            "rejected":       counts.get("rejected", 0),
            "overridden":     counts.get("overridden", 0),
            "review_needed":  counts.get("review_needed", 0),
            "total":          sum(counts.values()),
            "llm_enabled":    LLM_ENABLED,
            "auto_threshold": _auto_confirm_threshold(),
            "confidence_min": _confidence_min(),
            "item_ttl_hours": _item_ttl_seconds() / 3600,
            "max_items_per_source_country": _max_items_per_source_country(),
        }


# Module-level singleton
intel_queue = IntelQueue()
