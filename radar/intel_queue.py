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
import time
import uuid
from typing import Optional
from radar.config import LLM_ENABLED
from radar.database import db


def _auto_confirm_threshold() -> float:
    return float(os.getenv("LLM_AUTO_CONFIRM_THRESHOLD", "0.80"))

def _confidence_min() -> float:
    return float(os.getenv("LLM_CONFIDENCE_MIN", "0.55"))

def _override_window() -> int:
    return int(os.getenv("LLM_OVERRIDE_WINDOW", "3600"))

log = logging.getLogger("radar")

# In-memory set of currently active (auto_confirmed or confirmed) item IDs
# for fast rationale injection into the scoring engine
_active_item_ids: set[str] = set()


class IntelQueue:
    """LLM Intel item lifecycle manager."""

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

        # Discard below minimum threshold
        if confidence < _confidence_min():
            log.debug(f"[Intel] Discarded low-confidence item ({confidence:.2f}) from {item.get('source_id')}")
            return None

        source_id = item.get("source_id", "unknown")
        source = db.intel_source_get(source_id)
        if source is None:
            db.intel_source_upsert(source_id, item.get("source_type", "unknown"))
            source = db.intel_source_get(source_id)

        credibility = source["credibility_weight"] if source else 0.70

        item_id = item.get("id") or str(uuid.uuid4())
        now = time.time()

        # Determine initial status
        if confidence >= _auto_confirm_threshold() and credibility >= 0.75:
            status = "auto_confirmed"
            _active_item_ids.add(item_id)
            log.info(f"[Intel] AUTO-CONFIRMED: {item.get('headline', '')[:80]} "
                     f"(conf={confidence:.2f}, cred={credibility:.2f})")
        else:
            status = "pending"
            log.info(f"[Intel] PENDING review: {item.get('headline', '')[:80]} "
                     f"(conf={confidence:.2f}, cred={credibility:.2f})")

        record = {
            "id":          item_id,
            "source_type": item.get("source_type", "unknown"),
            "source_id":   source_id,
            "theater":     item.get("theater", ""),
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
        return item_id

    def confirm(self, item_id: str, analyst: str = "analyst") -> bool:
        """Manually confirm a PENDING item. Returns True if successful."""
        item = db.intel_get(item_id)
        if not item or item["status"] != "pending":
            return False
        now = time.time()
        db.intel_update_status(item_id, "confirmed",
                               confirmed_by=analyst, confirmed_at=now)
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
        _active_item_ids.discard(item_id)
        if item.get("source_id"):
            db.intel_source_record_outcome(item["source_id"], confirmed=False)
        log.info(f"[Intel] REJECTED by {analyst}: {item.get('headline', '')[:80]}")
        return True

    def override(self, item_id: str, analyst: str = "analyst") -> bool:
        """Override an AUTO-CONFIRMED item (undo its score contribution).
        Only allowed within LLM_OVERRIDE_WINDOW seconds of confirmation.
        Returns True if successful.
        """
        item = db.intel_get(item_id)
        if not item or item["status"] != "auto_confirmed":
            return False
        confirmed_at = item.get("confirmed_at") or item.get("created_at", 0)
        if time.time() - confirmed_at > _override_window():
            log.warning(f"[Intel] OVERRIDE rejected — outside window: {item_id}")
            return False
        now = time.time()
        db.intel_update_status(item_id, "overridden",
                               confirmed_by=analyst, override_at=now)
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
                # Flag the item so UI can highlight it
                if item["status"] == "auto_confirmed" and item["id"] not in _active_item_ids:
                    continue
                # If still active, mark as needing review
                if item["id"] in _active_item_ids:
                    db.intel_update_status(item["id"], "review_needed")
                    _active_item_ids.discard(item["id"])

        log.info(f"[Intel] classify_threat={classification} for {theater}, "
                 f"updated {len(active)} active items")

    def get_active_rationale(self) -> list[dict]:
        """Return rationale entries for all currently confirmed/auto_confirmed items.
        These are injected into the WeightedConvergenceEngine as llm_intel signals.
        """
        if not LLM_ENABLED:
            return []
        items = db.intel_list(status=None, limit=200)
        result = []
        for item in items:
            if item["status"] not in ("auto_confirmed", "confirmed"):
                continue
            if item.get("override_at"):
                continue
            # Only include items less than 24h old
            if time.time() - item["ts"] > 86400:
                continue
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
        all_items = db.intel_list(limit=500)
        auto = sum(1 for i in all_items if i["status"] == "auto_confirmed")
        pending = sum(1 for i in all_items if i["status"] == "pending")
        confirmed = sum(1 for i in all_items if i["status"] == "confirmed")
        rejected = sum(1 for i in all_items if i["status"] == "rejected")
        overridden = sum(1 for i in all_items if i["status"] == "overridden")
        review_needed = sum(1 for i in all_items if i["status"] == "review_needed")
        return {
            "auto_confirmed": auto,
            "pending":        pending,
            "confirmed":      confirmed,
            "rejected":       rejected,
            "overridden":     overridden,
            "review_needed":  review_needed,
            "total":          len(all_items),
            "llm_enabled":    LLM_ENABLED,
            "auto_threshold": _auto_confirm_threshold(),
            "confidence_min": _confidence_min(),
            "override_window": _override_window(),
        }


# Module-level singleton
intel_queue = IntelQueue()
