"""N per-payload drafts -> the ONE row production writes per country.

`normalize` is called once per fetched payload and sees exactly that
payload (§2-2 barrier 1). Production does not work that way: it sweeps a
country's ISR zones and sums the counts BEFORE asking whether the total
reached the surge threshold, pools three RIPE Atlas measurements' RTTs
BEFORE taking a p95, and folds BGP hijacks and route leaks into one
disjunction. None of those folds can happen in a function that can only
see one payload, so they happen here — design sheet §3-5 H-1(b)/(c) and
§7-2 #11/#12/#13/#23/#28/#29/#31/#41/#51.

**The order is the finding, not a detail.** Three aircraft over each of
two zones is a six-aircraft surge in production and two non-surges in a
per-zone threshold. Thresholding before summing does not merely round
differently; it removes a detection, which under NP1 is the worst
available outcome.

**A missing reduction is loud.** `signal_observation` is UNIQUE on
`(tick_id, sensor, signal_source, country)`; a re-record with different
content raises `DomainError` and — worse — a re-record with IDENTICAL
content is dropped without a word (`store.py:282-295`, S5-VERIF-019).
`reduce_drafts` therefore checks the uniqueness invariant for EVERY
adapter, reduced or not, and names the register entry in the failure. An
adapter that grows a second per-country row now fails here, at the layer
that can fix it, instead of at the ledger or in silence.

Everything in this module is a pure function of its arguments. Baseline
values arrive as a mapping the caller read from L1 (`v3/runtime/baselines.py`),
in the same shape and for the same reason `NormalizeContext` takes
geography rather than reading `geo_data.json`: a reduction that reads a
database mid-fold cannot be replayed, and replay is what parity rests on.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from v3.adapters.info.telegram_mirror import CHANNEL_SOURCE_PREFIX
from v3.adapters.info.travel_advisory import SOURCE_PREFIX as \
    ADVISORY_SOURCE_PREFIX
from v3.adapters.types import ObservationDraft
from v3.kernel.errors import DomainError
# Re-exported so `v3.runtime.reduce` stays the ONE name a caller needs
# after the 800-line split (`tests/test_runtime_reduce.py` reaches every
# fold through this module). Listed rather than star-imported: a star
# import would make "what this module offers" a fact about three other
# files.
from v3.runtime.reduce_common import (CHECKHOST_URL_OK_RATE,  # noqa: F401
                                      NARRATIVE_SOURCE_PREFIX, PENDING_PREFIX,
                                      Reduction)
from v3.runtime.reduce_cyber import _fold_cloudflare
from v3.runtime.reduce_info import (_fold_ct_log, _fold_gdelt,
                                    _fold_named_sources, _fold_ripe_bgp,
                                    _fold_tor)
from v3.runtime.reduce_physical import (_fold_ais, _fold_check_host,
                                        _fold_ihr, _fold_isr, _fold_mil_air,
                                        _fold_ripe_atlas,
                                        _fold_space_weather)


REDUCTIONS: tuple[Reduction, ...] = (
    Reduction("isr_hotspot", _fold_isr, "§3-5 H-1(b)(c)",
              "radar/sensors/isr_hotspot.py:85-107 / core.py:1218-1246",
              "sum the country's zones, then threshold; concatenate "
              "hotspots[] so the overlay join on `name` still resolves"),
    Reduction("mil_support_air", _fold_mil_air, "§3-5 H-1(b)",
              "radar/sensors/mil_support_air.py:128-158 / core.py:1753-1800",
              "sum per category, then the three-threshold OR ladder"),
    Reduction("cloudflare_radar", _fold_cloudflare, "§7-2 #12, #13, #9, #11",
              "radar/routes/core.py:1150-1170 / :762-817 / :1006-1025",
              "hijack OR leak into one cf_bgp_hijack entry; the four "
              "attack-origin payloads into avg_spike and production's "
              "one cf_spike_core entry"),
    Reduction("space_weather", _fold_space_weather, "§7-2 #11",
              "radar/sensors/space_weather.py:102-140 / core.py:1404-1410",
              "Kp OR X-ray; the joined sentence is rebuilt, not "
              "concatenated"),
    Reduction("ripe_atlas", _fold_ripe_atlas, "§7-2 #28, #29",
              "radar/sensors/ripe_atlas.py:133,137-147 / core.py:1533-1547",
              "pool RTTs across measurements, then p95"),
    Reduction("ripe_bgp", _fold_ripe_bgp, "§7-2 #9, #135",
              "radar/sensors/bgp_routing.py:67-77 / core.py:1140-1148",
              "hour-of-day Z-score decides ANOMALY; below seven same-hour "
              "samples a v3-only pooled-series verdict decides it instead "
              "(#135), and below seven samples of ANY hour it is withheld"),
    Reduction("ct_log", _fold_ct_log, "§7-2 #8, #9",
              "radar/sensors/ct_log.py:273-341 / core.py:1836-1848",
              "known-CA ledger + warm-up marker turn a candidate into "
              "score 3"),
    Reduction("check_host", _fold_check_host, "§7-2 #11, #9",
              "radar/sensors/checkhost.py:225-239 / core.py:1370-1383",
              "fraction of the country's URLs that are up"),
    Reduction("ais_maritime", _fold_ais, "§7-2 #11, #23",
              "radar/routes/core.py:1249-1259",
              "one row per country; printed counts span the cycle"),
    Reduction("ihr_health", _fold_ihr, "§7-2 #31",
              "radar/sensors/ihr.py:167-177",
              "min(ladder_rank) is the precedence chain, as data"),
    Reduction("tor_metrics", _fold_tor, "§7-2 #41",
              "radar/routes/core.py:1553-1579",
              "/summary and /clients reconciled into one entry"),
    Reduction("gdelt", _fold_gdelt, "§7-2 #41",
              "radar/sensors/gdelt.py:57 / core.py:1127-1132",
              "the two windows become one entry carrying the delta"),
    Reduction("telegram_mirror",
              _fold_named_sources("telegram_mirror", CHANNEL_SOURCE_PREFIX,
                                  ("channel", "detection_status",
                                   "keyword_hits", "target_urls")),
              "§7-2 #51", "radar/routes/core.py:1349-1356",
              "channels fold into one theatre entry"),
    Reduction("rss_narrative",
              _fold_named_sources("rss_narrative", NARRATIVE_SOURCE_PREFIX,
                                  ("feed", "adversary", "keyword_hits",
                                   "article_count", "normalized_freq")),
              "§7-2 #51", "radar/routes/core.py:1197-1216",
              "feeds fold into one theatre entry"),
    Reduction("travel_advisory",
              _fold_named_sources("travel_advisory", ADVISORY_SOURCE_PREFIX,
                                  ("source", "level", "level_label",
                                   "title")),
              "§7-2 #51", "radar/routes/core.py:1660-1690",
              "the three governments fold into one entry"),
)

BY_ADAPTER: Mapping[str, Reduction] = {r.adapter_id: r for r in REDUCTIONS}


def reduced_adapter_ids() -> tuple[str, ...]:
    return tuple(sorted(BY_ADAPTER))


def registry_disclosure() -> list[dict]:
    """Every fold this layer performs, with its provenance (NP6)."""
    return [{"adapter_id": r.adapter_id, "register_ref": r.register_ref,
             "production_ref": r.production_ref, "note": r.note}
            for r in REDUCTIONS]


def _require_writable(adapter_id: str,
                      drafts: Sequence[ObservationDraft]) -> None:
    """One row per `(signal_source, country)`, or say what collided.

    L1 would catch this too, but badly: a same-key row with different
    content raises from inside a transaction, and a same-key row with
    IDENTICAL content is discarded without a word (`store.py:290`). The
    second shape is how a fold that was never written becomes an
    observation that was never made.
    """
    seen: dict = {}
    for draft in drafts:
        key = (draft.signal_source, draft.country or "GLOBAL")
        if key in seen:
            raise DomainError(
                f"{adapter_id} produced {seen[key] + 1} rows for "
                f"signal_source={draft.signal_source!r} "
                f"country={draft.country or 'GLOBAL'!r} after reduction. "
                f"L1 is UNIQUE on (tick_id, sensor, signal_source, country): "
                f"identical rows are dropped SILENTLY and differing ones "
                f"raise inside the write. Give this adapter a fold in "
                f"v3/runtime/reduce.py (design sheet §7-2 #11) or give the "
                f"rows distinct signal_source values.")
        seen[key] = seen.get(key, 0) + 1


def reduce_drafts(adapter_id: str, drafts: Sequence[ObservationDraft], *,
                  baselines: Optional[Mapping[str, Any]] = None,
                  now: Optional[float] = None
                  ) -> tuple[ObservationDraft, ...]:
    """Fold one adapter's cycle output, and refuse to return an unwritable set.

    PURE. `baselines` is what the caller already read from L1 and `now` is
    the cycle instant the caller is using; nothing here opens a database
    or reads a clock, so a fold can be replayed from recorded payloads
    exactly as it ran.

    `now` is an argument rather than a `time.time()` call for the reason
    `NormalizeContext.now` is: two of these folds compare a stored
    timestamp with the present (a CT warm-up, an AIS dark gap), and a fold
    that fetched its own clock would give a different answer on replay
    than it gave live.

    Adapters with no declared fold pass through — and are still checked,
    which is the point: the check is what turns "nobody wrote a reducer
    for the adapter that grew a second row" from a silent halving into a
    sentence naming the adapter.
    """
    supplied = dict(baselines or {})
    if now is None:
        raise DomainError(
            f"reduce_drafts needs the cycle instant for {adapter_id!r}: a "
            f"fold that reads its own clock cannot be replayed")
    reduction = BY_ADAPTER.get(adapter_id)
    result = tuple(reduction.fold(tuple(drafts), supplied, float(now))) \
        if reduction else tuple(drafts)
    _require_writable(adapter_id, result)
    return result


__all__ = ["Reduction", "REDUCTIONS", "BY_ADAPTER", "reduce_drafts",
           "reduced_adapter_ids", "registry_disclosure",
           "CHECKHOST_URL_OK_RATE", "PENDING_PREFIX"]
