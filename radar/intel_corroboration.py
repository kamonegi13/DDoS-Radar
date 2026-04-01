"""radar.intel_corroboration -- Cross-source corroboration engine.

Periodically scans the intel_queue DB for independent-source signals in the
same theater and time window, then uses an LLM to synthesize them into a
single high-confidence "corroborated" item.

Two-layer design
────────────────
Layer 1 (intra-source-type, synchronous in intel_queue.submit):
    Headline Jaccard ≥ 0.50 within same source_type + theater → discard echo-chamber
    duplicate, record corroborating source_id in the winner's llm_fields.

Layer 2 (cross-source, async — THIS MODULE):
    Multiple INDEPENDENT source_types (e.g. military + hacktivist + narrative)
    all produce signals for the same theater within CORROBORATION_WINDOW_HOURS.
    Genuine corroboration from truly independent data streams → LLM synthesizes
    a "corroborated" item with elevated confidence and score.

Source independence matrix
──────────────────────────
    Score 0.0 = identical data stream (e.g. two wires citing same press release)
    Score 1.0 = completely independent data stream

    Pairs with low independence (< CORROBORATION_MIN_INDEPENDENCE) are NOT counted
    as corroborating evidence.  This prevents Telegram→ground_osint and
    Telegram→hacktivist from both "confirming" each other (same channel).

Cooldown
────────
    After a corroboration fires for a theater, a cooldown of
    CORROBORATION_COOLDOWN_HOURS prevents re-triggering on the same ongoing event.

Usage:
    from radar.intel_corroboration import corroboration_engine
    corroboration_engine.run_once()   # called by scheduler every 30 min
"""
from __future__ import annotations
import logging
import os
import time
import uuid
from collections import defaultdict
from typing import Optional

from radar.database import db
from radar.config import LLM_ENABLED

log = logging.getLogger("radar")

# ── Source independence matrix ────────────────────────────────────────────────
# Pairwise independence scores.  Symmetric — look up (a, b) or (b, a).
# Any pair not listed defaults to _DEFAULT_INDEPENDENCE.
_INDEPENDENCE: dict[frozenset, float] = {
    # Same Telegram data stream: hacktivist and ground_osint both read _intercept_log
    frozenset({"ground_osint", "hacktivist"}):   0.15,

    # Wire-service amplification: multiple defense outlets often cite the same press release
    frozenset({"military", "military"}):         0.20,

    # RSS narrative monitors adversary media; diplomatic monitors official statements —
    # they often cover the same event from different angles.  Moderate independence.
    frozenset({"narrative", "diplomatic"}):      0.50,

    # Military + apt_intel: physical posturing vs cyber indicators — fully independent
    frozenset({"military", "apt_intel"}):        0.90,

    # Military + hacktivist/ground_osint: completely separate data domains
    frozenset({"military", "hacktivist"}):       0.85,
    frozenset({"military", "ground_osint"}):     0.85,
    frozenset({"military", "narrative"}):        0.85,

    # Diplomatic + cyber sensors: independent
    frozenset({"diplomatic", "apt_intel"}):      0.90,
    frozenset({"diplomatic", "hacktivist"}):     0.80,
    frozenset({"diplomatic", "ground_osint"}):   0.80,
    frozenset({"diplomatic", "narrative"}):      0.50,

    # APT intel vs Telegram/narrative: independent
    frozenset({"apt_intel", "hacktivist"}):      0.85,
    frozenset({"apt_intel", "ground_osint"}):    0.85,
    frozenset({"apt_intel", "narrative"}):       0.85,

    # Narrative vs hacktivist/ground_osint: moderate — narrative tracks adversary media,
    # hacktivist tracks the same actors in Telegram.  Related but not identical.
    frozenset({"narrative", "hacktivist"}):      0.45,
    frozenset({"narrative", "ground_osint"}):    0.45,
}
_DEFAULT_INDEPENDENCE = 0.70  # for unlisted pairs

# Corroborated items go through intel_queue so they are reviewed / auto-confirmed
# like any other item.  We track per-theater cooldown in memory.
_cooldown_until: dict[str, float] = {}  # theater → Unix timestamp


def _independence(a: str, b: str) -> float:
    key = frozenset({a, b})
    return _INDEPENDENCE.get(key, _DEFAULT_INDEPENDENCE)


def _corr_window_seconds() -> float:
    return float(os.getenv("CORROBORATION_WINDOW_HOURS", "8")) * 3600


def _corr_cooldown_seconds() -> float:
    return float(os.getenv("CORROBORATION_COOLDOWN_HOURS", "12")) * 3600


def _min_sources() -> int:
    return int(os.getenv("CORROBORATION_MIN_SOURCES", "2"))


def _min_independence() -> float:
    return float(os.getenv("CORROBORATION_MIN_INDEPENDENCE", "0.70"))


def _select_independent_group(source_types: list[str]) -> list[str]:
    """Greedy: pick the largest subset of source_types where every pair has
    independence ≥ _min_independence().  Returns an empty list if no 2-member
    subset qualifies."""
    threshold = _min_independence()
    unique = list(dict.fromkeys(source_types))  # preserve order, deduplicate

    selected: list[str] = []
    for st in unique:
        # Check that this source_type is independent from ALL already-selected ones
        if all(_independence(st, s) >= threshold for s in selected):
            selected.append(st)

    return selected if len(selected) >= _min_sources() else []


class CorroborationEngine:
    """Scans the intel DB for independent multi-source signals and synthesizes them."""

    def run_once(self) -> int:
        """Run one corroboration pass.  Returns the number of corroborated items created."""
        if not LLM_ENABLED:
            return 0

        from radar.llm_client import llm_analyze_json, llm_available, safe_float, safe_enum, today_str
        from radar.intel_queue import intel_queue

        if not llm_available():
            log.debug("[Corroboration] LLM not available — skipping")
            return 0

        window = _corr_window_seconds()
        since = time.time() - window

        # Fetch all active-status items within the corroboration window
        items = db.intel_list(status=None, limit=500, since_ts=since)

        # Filter: only confirmed/auto_confirmed/pending items from real sensors
        # (exclude previously generated "corroborated" items to prevent recursion)
        real_types = {
            "hacktivist", "ground_osint", "diplomatic", "military",
            "narrative", "apt_intel",
        }
        candidates = [
            i for i in items
            if i["source_type"] in real_types
            and i["status"] in ("auto_confirmed", "confirmed", "pending")
        ]

        # Group by theater
        by_theater: dict[str, list[dict]] = defaultdict(list)
        for item in candidates:
            theater = item.get("theater", "")
            if theater:
                by_theater[theater].append(item)

        created = 0
        for theater, theater_items in by_theater.items():
            # Check cooldown
            if time.time() < _cooldown_until.get(theater, 0):
                continue

            # Collect distinct source_types present in this theater+window
            source_types_present = [i["source_type"] for i in theater_items]
            independent_group = _select_independent_group(source_types_present)
            if not independent_group:
                continue

            # Gather the best item (highest confidence) from each source_type
            # in the independent group
            best_by_type: dict[str, dict] = {}
            for st in independent_group:
                candidates_st = [i for i in theater_items if i["source_type"] == st]
                if candidates_st:
                    best_by_type[st] = max(candidates_st, key=lambda x: x["confidence"])

            if len(best_by_type) < _min_sources():
                continue

            # Synthesize with LLM
            corr_item = self._synthesize(theater, best_by_type, independent_group)
            if corr_item:
                item_id = intel_queue.submit(corr_item)
                if item_id:
                    created += 1
                    _cooldown_until[theater] = time.time() + _corr_cooldown_seconds()
                    log.info(
                        f"[Corroboration] Created corroborated item for {theater}: "
                        f"{corr_item['headline'][:60]} "
                        f"(sources={','.join(independent_group)}, conf={corr_item['confidence']:.2f})"
                    )

        if created:
            log.info(f"[Corroboration] Pass complete: {created} corroborated items created")
        return created

    def _synthesize(self, theater: str, best_by_type: dict[str, dict],
                    source_types: list[str]) -> Optional[dict]:
        """Call LLM to synthesize multiple independent signals into one corroborated item.
        Returns a dict ready for intel_queue.submit(), or None on failure."""
        from radar.llm_client import llm_analyze_json, safe_float, safe_enum, today_str

        # Build context block for LLM
        source_blocks = []
        for st, item in best_by_type.items():
            source_blocks.append(
                f"[{st.upper()}] {item['headline']}\n"
                f"  Confidence: {item['confidence']:.2f}  Theater: {theater}\n"
                f"  Domain: {item.get('domain', 'info')}"
            )

        context = "\n\n".join(source_blocks)
        source_list = ", ".join(source_types)

        system_prompt = (
            "You are a senior threat intelligence analyst. "
            "You have received independent signals from multiple surveillance systems "
            "all pointing to the same theater. Your task is to assess whether these "
            "signals constitute genuine multi-source corroboration of a single threat event, "
            "or whether they are coincidental/unrelated. "
            "Respond ONLY with a JSON object."
        )
        user_prompt = (
            f"Today's date: {today_str()}\n"
            f"Theater: {theater}\n"
            f"Independent source types: {source_list}\n\n"
            "Signals received:\n"
            f"{context}\n\n"
            "These signals come from INDEPENDENT data streams "
            f"(pairwise independence scores all ≥ {_min_independence():.2f}). "
            "Assess whether they describe the same underlying threat event.\n\n"
            "Return a JSON object:\n"
            "{\n"
            '  "same_event": true or false,\n'
            '  "headline": "One-sentence synthesis (max 120 chars) — be specific",\n'
            '  "threat_type": "ddos|military_escalation|cyber_intrusion|hybrid|disinformation|unknown",\n'
            '  "urgency": "critical|high|medium|low",\n'
            '  "domain": "cyber|physical|info|mixed",\n'
            '  "confidence": 0.0,\n'
            '  "reasoning": "One sentence explaining why these signals are (or are not) the same event"\n'
            "}\n"
            "Confidence guide:\n"
            "- 0.85-0.95: Signals describe clearly the same active threat event with named actors/targets\n"
            "- 0.70-0.84: Signals are consistent with same event, some ambiguity\n"
            "- 0.55-0.69: Signals are in same theater and timeframe but may be coincidental\n"
            "- <0.55: Signals appear unrelated — set same_event=false\n"
            "If same_event=false, still return the JSON but set confidence<0.55."
        )

        result = llm_analyze_json(user_prompt, system=system_prompt, max_tokens=300)
        if not result["ok"]:
            log.debug(f"[Corroboration] LLM parse failed for {theater}: {result.get('error')}")
            return None

        data = result["data"]
        if not data.get("same_event", False):
            log.debug(f"[Corroboration] LLM: not same event for {theater} — {data.get('reasoning', '')[:80]}")
            return None

        confidence = safe_float(data.get("confidence"), default=0.0)
        if confidence < 0.55:
            return None

        # Boost confidence modestly for having multiple independent sources
        n_sources = len(source_types)
        source_bonus = min((n_sources - 2) * 0.03, 0.06)  # max +0.06 for 4 sources
        confidence = min(confidence + source_bonus, 0.95)

        urgency = safe_enum(data.get("urgency"), {"critical", "high", "medium", "low"}, "medium")
        domain = safe_enum(data.get("domain"), {"cyber", "physical", "info", "mixed"}, "mixed")

        # Score: base by urgency + source bonus (additive, capped)
        base_score = {"critical": 3.0, "high": 2.5, "medium": 2.0, "low": 1.5}.get(urgency, 2.0)
        score_bonus = min((n_sources - 2) * 0.3, 0.9)  # max +0.9 for 5 sources
        score_delta = round(base_score + score_bonus, 1)

        # Collect source item IDs for traceability
        source_ids = [item.get("source_id", "") for item in best_by_type.values()]
        source_item_ids = [item["id"] for item in best_by_type.values()]

        return {
            "source_type":  "corroborated",
            "source_id":    f"corroborated_{theater}",
            "theater":      theater,
            "ts":           time.time(),
            "confidence":   round(confidence, 3),
            "raw_text":     f"Multi-source corroboration [{source_list}]\n{context[:800]}",
            "raw_url":      "",
            "headline":     data.get("headline", f"Multi-source corroboration: {theater}")[:120],
            "llm_fields": {
                "threat_type":       data.get("threat_type", "unknown"),
                "urgency":           urgency,
                "contributing_sources": source_types,
                "contributing_source_ids": source_ids,
                "contributing_item_ids":   source_item_ids,
                "reasoning":         data.get("reasoning", "")[:200],
                "n_independent_sources": n_sources,
            },
            "score_delta":  score_delta,
            "domain":       domain,
        }


# Module-level singleton
corroboration_engine = CorroborationEngine()
