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
import os
import threading
import time
import uuid
from typing import Optional
from radar.config import LLM_ENABLED
from radar.database import db


def _auto_confirm_threshold() -> float:
    return float(os.getenv("LLM_AUTO_CONFIRM_THRESHOLD", "0.80"))

def _confidence_min() -> float:
    return float(os.getenv("LLM_CONFIDENCE_MIN", "0.35"))

def _item_ttl_seconds() -> float:
    """How long (seconds) a confirmed item contributes to active rationale."""
    return float(os.getenv("INTEL_ITEM_TTL_HOURS", "24")) * 3600

def _max_items_per_source_theater() -> int:
    """Max active items per (source_type, theater) in rationale. Prevents score inflation."""
    return int(os.getenv("INTEL_MAX_ITEMS_PER_SOURCE_THEATER", "2"))

def _pending_auto_reject_hours() -> float:
    """Hours after which unreviewed PENDING items are automatically rejected.
    Set to 0 to disable auto-reject."""
    return float(os.getenv("LLM_PENDING_AUTO_REJECT_HOURS", "24"))

log = logging.getLogger("radar")

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
_JACCARD_THRESHOLD = 0.50           # headline similarity threshold for same-event dedup


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
        the queue verdict (auto_confirmed/pending/discarded_low_conf/discarded_dedup).

        Best-effort: never raises. The llm_client already wrote a row with empty
        verdict — we patch it in place by matching caller (sensor module) and
        the highest-id row within the last few seconds. If matching fails we
        skip silently rather than create a duplicate row.
        """
        try:
            from radar.database import db
            # Map source_type to caller module name(s) used by llm_analyze_json
            # caller comes from _infer_caller (sys._getframe) so it's the leaf
            # module name like "hacktivist_intel_sensor".
            _CALLER_BY_TYPE = {
                "hacktivist": ("hacktivist_intel_sensor", "hacktivist_news_sensor"),
                "diplomatic": ("diplomatic",),
                "military":   ("military_exercise",),
                "ground_osint": ("ground_osint_sensor",),
                "apt":        ("apt_intel",),
                "narrative":  ("rss_narrative",),
            }
            callers = _CALLER_BY_TYPE.get(source_type, ())
            if not callers:
                return
            conn = db._get_conn()
            placeholders = ",".join("?" * len(callers))
            cutoff = time.time() - 60  # last minute
            with conn.writing():
                conn.execute(
                    f"UPDATE llm_call_log SET verdict=? "
                    f"WHERE id = (SELECT id FROM llm_call_log "
                    f"WHERE caller IN ({placeholders}) AND ts >= ? "
                    f"AND verdict='' ORDER BY id DESC LIMIT 1)",
                    (verdict, *callers, cutoff),
                )
        except Exception:
            pass

    def submit(self, item: dict) -> Optional[str]:
        """Accept a new LLM-analyzed item from a sensor.

        item must contain:
            source_type  : hacktivist | diplomatic | military | ground_osint
            source_id    : channel/feed identifier (for credibility tracking)
            theater      : e.g. "CN-TW"
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
        theater = item.get("theater", "")
        headline = item.get("headline", "")

        # Discard below minimum threshold
        if confidence < _confidence_min():
            log.debug(f"[Intel] Discarded low-confidence item ({confidence:.2f}) from {source_id}")
            self._record_verdict(source_type, "discarded_low_conf", confidence, headline)
            return None

        # ── Intra-source-type dedup: discard wire-service echo chambers ──────────
        # Within the same source_type + theater pair, check if we already have a
        # recent item (48h) with a similar headline (Jaccard ≥ 0.50 on significant
        # words). If so, this is most likely the same event reported by multiple
        # outlets citing the same underlying source (e.g. PACOM press release
        # re-published by USNI, DefenseNews, Stars&Stripes).
        #
        # Confidence-based replacement: if the new item has higher confidence than
        # the existing match, replace the existing item's analysis (headline,
        # confidence, score_delta, etc.) while preserving corroborating sources.
        #
        # Distinct-event protection: even if Jaccard matches, do NOT merge items
        # that have different theaters, actors, or diplomatic actions (these are
        # similar-but-distinct events that happen to share vocabulary).
        if headline:
            new_tokens = _headline_tokens(headline)
            new_llm = item.get("llm_fields", {})
            since = time.time() - _DEDUP_WINDOW_SECONDS
            existing = db.intel_list(source_type=source_type, theater=theater,
                                     limit=50, since_ts=since)
            for ex in existing:
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
                    corroborators: list = ex_llm.get("corroborating_sources", [])
                    old_src = ex.get("source_id", "")
                    if old_src and old_src not in corroborators:
                        corroborators.append(old_src)
                    merged_llm = new_llm.copy()
                    merged_llm["corroborating_sources"] = corroborators
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
                    corroborators = ex_llm.get("corroborating_sources", [])
                    if source_id not in corroborators:
                        corroborators.append(source_id)
                        db.intel_update_llm_fields(ex["id"], {"corroborating_sources": corroborators})
                    log.debug(
                        f"[Intel] Intra-type dedup: discarded {source_id!r} "
                        f"(Jaccard={jacc:.2f} vs {ex['source_id']!r}, "
                        f"headline: {headline[:60]})"
                    )
                    self._record_verdict(source_type, "discarded_dedup", confidence, headline)
                    return None  # don't create a new item either way
        # ─────────────────────────────────────────────────────────────────────────

        source = db.intel_source_get(source_id)
        if source is None:
            db.intel_source_upsert(source_id, source_type)
            source = db.intel_source_get(source_id)

        credibility = source["credibility_weight"] if source else 0.70

        item_id = item.get("id") or str(uuid.uuid4())
        now = time.time()

        # Determine initial status
        if confidence >= _auto_confirm_threshold() and credibility >= 0.75:
            status = "auto_confirmed"
            with _active_lock:
                _active_item_ids.add(item_id)
            log.info(f"[Intel] AUTO-CONFIRMED: {item.get('headline', '')[:80]} "
                     f"(conf={confidence:.2f}, cred={credibility:.2f})")
        else:
            status = "pending"
            log.info(f"[Intel] PENDING review: {item.get('headline', '')[:80]} "
                     f"(conf={confidence:.2f}, cred={credibility:.2f})")
        self._record_verdict(source_type, status, confidence, headline)

        record = {
            "id":          item_id,
            "source_type": source_type,
            "source_id":   source_id,
            "theater":     theater,
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

    def reject(self, item_id: str, analyst: str = "analyst") -> bool:
        """Reject a PENDING item. Returns True if successful."""
        item = db.intel_get(item_id)
        if not item or item["status"] != "pending":
            return False
        db.intel_update_status(item_id, "rejected",
                               confirmed_by=analyst, confirmed_at=time.time())
        with _active_lock:
            _active_item_ids.discard(item_id)
        if item.get("source_id"):
            db.intel_source_record_outcome(item["source_id"], confirmed=False)
        log.info(f"[Intel] REJECTED by {analyst}: {item.get('headline', '')[:80]}")
        return True

    def revert(self, item_id: str, analyst: str = "analyst") -> bool:
        """Revert a confirmed or rejected item back to pending.
        This undoes a manual confirm/reject decision so the analyst can re-decide.
        Not applicable to auto_confirmed items (use override() for those).
        Returns True if successful.
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
                db.intel_source_record_outcome(item["source_id"], confirmed=False)
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

        Score accumulation cap: at most INTEL_MAX_ITEMS_PER_SOURCE_THEATER items per
        (source_type, theater) pair contribute to the score. Items are ranked by
        score_delta descending so the highest-signal items are always included.
        This prevents a single noisy sensor from accumulating unbounded score.
        """
        if not LLM_ENABLED:
            return []
        # Fetch only confirmed/auto_confirmed items at the DB level
        items_ac = db.intel_list(status="auto_confirmed", limit=100)
        items_c  = db.intel_list(status="confirmed", limit=100)
        ttl = _item_ttl_seconds()
        cap = _max_items_per_source_theater()
        now = time.time()

        # Filter to active items within TTL
        active = []
        for item in items_ac + items_c:
            if item.get("override_at"):
                continue
            if now - item["ts"] > ttl:
                continue
            active.append(item)

        # Second pass: apply per-(source_type, theater) cap ranked by score_delta
        # Group and sort descending; keep top `cap` items per group
        from collections import defaultdict
        groups: dict = defaultdict(list)
        for item in active:
            key = (item["source_type"], item.get("theater", ""))
            groups[key].append(item)

        result = []
        for key, group_items in groups.items():
            # Sort descending by score_delta; ties broken by confidence
            group_items.sort(key=lambda x: (x["score_delta"], x["confidence"]), reverse=True)
            for item in group_items[:cap]:
                result.append({
                    "sensor":        "llm_intel",
                    "signal_source": "llm_intel",
                    "score":         item["score_delta"],
                    "confidence":    item["confidence"],
                    "domain":        item["domain"],
                    "theater":       item.get("theater", ""),
                    "status":        "FIRED",
                    "detail":        f"[{item['source_type'].upper()}] {item['headline']}",
                    "suppressed":    False,
                })
        return result

    def list_items(self, source_type: str = None, status: str = None,
                   theater: str = None, limit: int = 100) -> list[dict]:
        return db.intel_list(source_type=source_type, status=status,
                             theater=theater, limit=limit)

    def list_sources(self) -> list[dict]:
        return db.intel_source_list()

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
            "max_items_per_source_theater": _max_items_per_source_theater(),
        }


# Module-level singleton
intel_queue = IntelQueue()
