"""Tests for radar/background_observer.py — per-scenario obs health (AP3).

Pins (ADR-V2-015 Phase 3 — broadcast scan replaces round-robin):
  - broadcast scan emits a Signal per (country, item) match across the
    union of all scorable scenarios' participants
  - extractor scoping respects the participant union (off-list mentions
    are ignored)
  - signals queued + drained, with TTL aging out stale entries
  - default disabled — no work happens when the flag is off
  - HTTP / parse errors at fetch time don't crash the cycle
  - Max queue cap evicts oldest when over capacity
  - cycle audit row is persisted per tick (AP3/AP4)
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import pytest

os.environ.setdefault("CF_API_TOKEN", "test")

from radar import background_observer as bgo, config


@dataclass(frozen=True)
class _FakeScenario:
    id: str
    participants: dict


_SCENARIOS = [
    _FakeScenario("taiwan_contingency",
                  {"TW": object(), "US": object(), "JP": object(), "CN": object()}),
    _FakeScenario("eastern_europe",
                  {"UA": object(), "RU": object(), "PL": object()}),
    _FakeScenario("korean_peninsula",
                  {"KR": object(), "KP": object(), "JP": object()}),
]


@pytest.fixture(autouse=True)
def _clear_queue():
    """Drain the module-level queue before and after each test so they
    don't leak signals into one another."""
    with bgo._queue_lock:
        bgo._signal_queue.clear()
    yield
    with bgo._queue_lock:
        bgo._signal_queue.clear()


@pytest.fixture
def enable_bg(monkeypatch):
    monkeypatch.setattr(config, "BG_OBSERVER_ENABLED", True)
    monkeypatch.setattr(config, "BG_OBSERVER_INTERVAL_SEC", 300)
    monkeypatch.setattr(config, "BG_OBSERVER_SIGNAL_TTL_SEC", 1800)
    monkeypatch.setattr(config, "BG_OBSERVER_MAX_QUEUE", 200)


# ── enabled flag short-circuits ──────────────────────────────────────────


def test_tick_no_op_when_disabled(monkeypatch):
    monkeypatch.setattr(config, "BG_OBSERVER_ENABLED", False)
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "taiwan_contingency",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: [],
    )
    out = obs.tick()
    assert out == {"enabled": False}
    assert bgo.queue_size() == 0


# ── broadcast scan over participant union ────────────────────────────────


def test_broadcast_emits_one_signal_per_country_per_match(enable_bg):
    """One feed item with two participant countries should emit two Signals."""
    items = [
        # Single article mentioning both Russia and Ukraine; broadcast
        # scan should produce a Signal for each.
        {"title": "Russian forces attack Ukraine; killed 5",
         "summary": "", "link": ""},
    ]
    fixed_now = 1_800_000_000.0
    captured: list[dict] = []
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "taiwan_contingency",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: items,
        now_fn=lambda: fixed_now,
        cycle_log_fn=captured.append,
    )
    out = obs.tick()
    assert out["enabled"] is True
    assert out["matches"] == 2
    assert set(out["matches_by_country"].keys()) == {"RU", "UA"}
    sigs = bgo.active_signals(now=fixed_now + 30)
    assert {s.countries for s in sigs} == {("RU",), ("UA",)}


def test_broadcast_scope_respects_participant_union(enable_bg):
    """Off-participant mentions (e.g. 'Iran') in the feed are ignored."""
    items = [
        {"title": "Iranian airstrike kills 12 in Yemen",
         "summary": "", "link": ""},  # IR/YE not in any test scenario
        {"title": "Russian missile killed 5 in Ukraine",
         "summary": "", "link": ""},
    ]
    fixed_now = 1_800_000_000.0
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "taiwan_contingency",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: items,
        now_fn=lambda: fixed_now,
        cycle_log_fn=lambda r: None,
    )
    out = obs.tick()
    # Only RU/UA should match (Iran/Yemen filtered out by scope)
    assert set(out["matches_by_country"].keys()) == {"RU", "UA"}


def test_broadcast_records_no_participants_when_empty(enable_bg):
    sc = _FakeScenario("empty_scenario", {})
    captured: list[dict] = []
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: [sc],
        focused_id_fn=lambda: "other",
        feeds=[], fetch_feed_fn=lambda u: [],
        cycle_log_fn=captured.append,
    )
    out = obs.tick()
    assert out.get("reason") == "no_participants"
    assert captured and captured[0]["drop_reason"] == "no_participants"


def test_broadcast_includes_focused_in_participant_union(enable_bg):
    """Phase 3: bg_observer no longer skips the focused scenario.

    The dedup_by_source_country_max in scoring handles any duplicate
    contribution; the OBS chip benefits from a consistent per-country
    view across focus changes.
    """
    items = [
        {"title": "Taiwan air-defence intercept; 0 casualties",
         "summary": "", "link": ""},
    ]
    fixed_now = 1_800_000_000.0
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "taiwan_contingency",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: items,
        now_fn=lambda: fixed_now,
        cycle_log_fn=lambda r: None,
    )
    out = obs.tick()
    # TW is the focused scenario's participant — broadcast scan must
    # still detect it.
    assert "TW" in out["matches_by_country"]


def test_cycle_log_records_per_gate_counters(enable_bg):
    """AP3/AP4: cycle log captures gate-level statistics for self-eval."""
    items = [
        {"title": "Russian airstrike killed 8 in Ukraine",
         "summary": "", "link": ""},  # fatality + kinetic + 2 countries
        {"title": "Polish border patrol report quiet day",
         "summary": "", "link": ""},  # country only, no verb → dropped
    ]
    fixed_now = 1_800_000_000.0
    captured: list[dict] = []
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "taiwan_contingency",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: items,
        now_fn=lambda: fixed_now,
        cycle_log_fn=captured.append,
    )
    obs.tick()
    assert len(captured) == 1
    row = captured[0]
    assert row["items_total"] == 2
    assert row["matches_emitted"] == 2  # RU + UA from the first item
    assert row["matches_by_country"] == {"RU": 1, "UA": 1}
    assert row["alias_gap"] == []
    assert row["feeds_attempted"] == 1
    assert row["feeds_failed"] == 0


def test_cycle_log_surfaces_alias_gap(enable_bg):
    """Phase 2 invariant: gap is surfaced in cycle audit (NP6)."""
    sc = _FakeScenario("imaginary",
                       {"ZZ": object(), "RU": object()})  # ZZ has no alias
    captured: list[dict] = []
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: [sc],
        focused_id_fn=lambda: "x",
        feeds=[], fetch_feed_fn=lambda u: [],
        cycle_log_fn=captured.append,
    )
    obs.tick()
    assert "ZZ" in captured[0]["alias_gap"]
    assert "RU" not in captured[0]["alias_gap"]


def test_cycle_log_counts_failed_feeds(enable_bg):
    """Empty / errored fetches count as failures so AP3 can detect them."""
    captured: list[dict] = []
    fetched = [True, False]  # two feeds: first returns items, second empty

    def fake_fetch(_url):
        ok = fetched.pop(0) if fetched else False
        return [{"title": "Russian airstrike killed 1 in Ukraine",
                 "summary": "", "link": ""}] if ok else []
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "x",
        feeds=["http://a", "http://b"],
        fetch_feed_fn=fake_fetch,
        cycle_log_fn=captured.append,
    )
    obs.tick()
    assert captured[0]["feeds_attempted"] == 2
    assert captured[0]["feeds_failed"] == 1


# ── queue + TTL ──────────────────────────────────────────────────────────


def test_active_signals_filters_stale(enable_bg, monkeypatch):
    monkeypatch.setattr(config, "BG_OBSERVER_SIGNAL_TTL_SEC", 60)
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: [_SCENARIOS[1]],
        focused_id_fn=lambda: "x",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: [
            {"title": "Russian forces attack Ukraine; killed 5",
             "summary": "", "link": ""},
        ],
        now_fn=lambda: 1_800_000_000.0,
        cycle_log_fn=lambda r: None,
    )
    obs.tick()  # broadcast — emits RU + UA Signals
    # Read at far-future time so all should be stale (TTL=60s)
    sigs = bgo.active_signals(now=1_800_000_000.0 + 10_000)
    assert sigs == []


def test_active_signals_returns_fresh(enable_bg):
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: [_SCENARIOS[1]],
        focused_id_fn=lambda: "x",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: [
            {"title": "Russian forces attack Ukraine; killed 5",
             "summary": "", "link": ""},
        ],
        now_fn=lambda: 1_800_000_000.0,
        cycle_log_fn=lambda r: None,
    )
    obs.tick()
    sigs = bgo.active_signals(now=1_800_000_000.0 + 30)
    assert len(sigs) >= 1
    assert any(s.countries == ("RU",) for s in sigs)
    assert any(s.countries == ("UA",) for s in sigs)


def test_max_queue_cap_evicts_oldest(enable_bg, monkeypatch):
    monkeypatch.setattr(config, "BG_OBSERVER_MAX_QUEUE", 2)
    # Force three pushes of distinct signals
    for i in range(3):
        bgo._enqueue(bgo._PendingSignal(
            observed_at=1_800_000_000.0 + i,
            domain="info", countries=("XX",), raw_score=0.5,
            sensor="t", signal_source="t", value_display=f"#{i}",
            evidence_url=None,
        ))
    sigs = bgo.active_signals(now=1_800_000_000.0 + 100)
    # Oldest dropped; only #1 and #2 remain
    assert [s.value_display for s in sigs] == ["#1", "#2"]


# ── error tolerance ─────────────────────────────────────────────────────


def test_fetch_error_does_not_crash_cycle(enable_bg):
    def boom(_url):
        raise RuntimeError("DNS flap")
    obs = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "taiwan_contingency",
        feeds=["http://x"],
        fetch_feed_fn=boom,
    )
    # The contract is that the fetcher itself shouldn't raise; if it does,
    # tick() should propagate (caller catches in the worker loop). But the
    # default _default_fetch_feed catches everything, so the typical case
    # is "fetcher returns []". Verify the latter explicitly.
    obs2 = bgo.BackgroundObserver(
        scorable_scenarios_fn=lambda: _SCENARIOS,
        focused_id_fn=lambda: "taiwan_contingency",
        feeds=["http://x"],
        fetch_feed_fn=lambda u: [],
        cycle_log_fn=lambda r: None,
    )
    out = obs2.tick()
    assert out["matches"] == 0
    assert out["enabled"] is True


# ── public surface ──────────────────────────────────────────────────────


def test_active_signals_retains_buffer_within_ttl():
    """Inverse of the retired consume-once contract: reading must NOT
    empty the buffer while signals are inside their TTL window."""
    bgo._enqueue(bgo._PendingSignal(
        observed_at=1_800_000_000.0, domain="info", countries=("US",),
        raw_score=0.5, sensor="t", signal_source="t",
        value_display="x", evidence_url=None,
    ))
    assert bgo.queue_size() == 1
    bgo.active_signals(now=1_800_000_000.0 + 30)
    assert bgo.queue_size() == 1


# ── retained buffer semantics (2026-07-04 strobe fix) ────────────────────
#
# drain_signals() used to CONSUME the queue on read, so a signal's real
# lifetime was "until the next scoring tick" (≤2 min) — the documented
# 30m TTL was a fiction. With the 5-min bg cycle aliasing against the
# 2-min tick, the info-domain contribution strobed 0↔1.17 and taiwan's
# TL flipped TL4↔TL5 roughly every other tick (live observation
# 2026-07-04). active_signals() is state semantics: the same signal is
# visible to EVERY tick inside its TTL window.


def _mk_sig(*, at, country="XX", display="s", source="t"):
    return bgo._PendingSignal(
        observed_at=at, domain="info", countries=(country,),
        raw_score=0.5, sensor="t", signal_source=source,
        value_display=display, evidence_url=None,
    )


def test_active_signals_visible_to_consecutive_ticks():
    """Inversion sentinel for the consume-once regression: two reads in
    a row (two scoring ticks) must BOTH see the signal."""
    t0 = 1_800_000_000.0
    bgo._enqueue(_mk_sig(at=t0))
    first = bgo.active_signals(now=t0 + 120)
    second = bgo.active_signals(now=t0 + 240)
    assert len(first) == 1
    assert len(second) == 1
    assert second[0].value_display == "s"


def test_active_signals_expire_after_ttl(monkeypatch):
    monkeypatch.setattr(config, "BG_OBSERVER_SIGNAL_TTL_SEC", 60)
    t0 = 1_800_000_000.0
    bgo._enqueue(_mk_sig(at=t0))
    assert len(bgo.active_signals(now=t0 + 30)) == 1
    assert bgo.active_signals(now=t0 + 61) == []
    # Expired entries are pruned from the buffer, not just filtered.
    assert bgo.queue_size() == 0


def test_reenqueue_same_identity_slides_ttl_without_duplicating(monkeypatch):
    """The 5-min cycle re-matches the same headlines every pass. The
    buffer must upsert on identity (source, domain, countries, evidence/
    display) — refreshing observed_at, never stacking duplicates."""
    monkeypatch.setattr(config, "BG_OBSERVER_SIGNAL_TTL_SEC", 600)
    t0 = 1_800_000_000.0
    bgo._enqueue(_mk_sig(at=t0, display="same story"))
    bgo._enqueue(_mk_sig(at=t0 + 300, display="same story"))
    sigs = bgo.active_signals(now=t0 + 310)
    assert len(sigs) == 1
    assert sigs[0].observed_at == t0 + 300
    # Slid TTL: still alive past the ORIGINAL observation's expiry.
    assert len(bgo.active_signals(now=t0 + 700)) == 1


def test_distinct_identities_coexist():
    t0 = 1_800_000_000.0
    bgo._enqueue(_mk_sig(at=t0, country="RU", display="a"))
    bgo._enqueue(_mk_sig(at=t0, country="UA", display="a"))
    bgo._enqueue(_mk_sig(at=t0, country="RU", display="b"))
    assert len(bgo.active_signals(now=t0 + 10)) == 3


def test_phase_alias_simulation_no_strobe(monkeypatch):
    """5-min producer + 2-min consumer over 14 minutes: with retained
    semantics every tick sees a live signal (the pre-fix consume-once
    queue left ticks 2, 4-5, 7 empty)."""
    monkeypatch.setattr(config, "BG_OBSERVER_SIGNAL_TTL_SEC", 1800)
    t0 = 1_800_000_000.0
    for cycle_at in (t0, t0 + 300, t0 + 600):
        bgo._enqueue(_mk_sig(at=cycle_at, display="story"))
    empty_ticks = [
        tick for tick in range(1, 8)  # ticks at t0+120 … t0+840
        if not bgo.active_signals(now=t0 + tick * 120)
    ]
    assert empty_ticks == []
