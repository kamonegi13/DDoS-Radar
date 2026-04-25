"""Tests for Phase 3: multi-country intel support.

Covers:
  - DB migration v6: countries/country_weights columns
  - _intel_row_to_dict() parsing of new JSON columns
  - intel_queue.submit() backward compat (theater → countries derivation)
  - Dedup with multi-country overlap check
  - get_active_rationale() output includes countries/country_weights
"""
import json
import os
import pytest
import tempfile
import time
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")
os.environ["LLM_ENABLED"] = "true"

from radar.database import RadarDB


@pytest.fixture
def testdb(tmp_path):
    db_path = str(tmp_path / "test_intel.db")
    tdb = RadarDB(db_path)
    yield tdb
    tdb.close()


def _make_record(**overrides):
    now = time.time()
    rec = {
        "id": str(uuid.uuid4()),
        "source_type": "hacktivist",
        "source_id": "hacktivist_test_ch",
        "theater": "TW",
        "countries": ["TW"],
        "country_weights": {"TW": 1.0},
        "ts": now,
        "status": "pending",
        "confidence": 0.75,
        "raw_text": "test raw text",
        "raw_url": "https://example.com",
        "headline": "Test headline",
        "llm_fields": {"key": "value"},
        "score_delta": 2.0,
        "domain": "cyber",
        "confirmed_by": None,
        "confirmed_at": None,
        "override_at": None,
        "created_at": now,
    }
    rec.update(overrides)
    return rec


# ── DB round-trip: countries/country_weights ────────────────────────────────

class TestDBCountryColumns:
    def test_upsert_and_get_single_country(self, testdb):
        rec = _make_record(countries=["TW"], country_weights={"TW": 1.0})
        testdb.intel_upsert(rec)
        got = testdb.intel_get(rec["id"])
        assert got is not None
        assert got["countries"] == ["TW"]
        assert got["country_weights"] == {"TW": 1.0}
        assert got["theater"] == "TW"

    def test_upsert_and_get_multi_country(self, testdb):
        rec = _make_record(
            countries=["TW", "JP", "US"],
            country_weights={"TW": 1.0, "JP": 0.6, "US": 0.3},
        )
        testdb.intel_upsert(rec)
        got = testdb.intel_get(rec["id"])
        assert got["countries"] == ["TW", "JP", "US"]
        assert got["country_weights"]["JP"] == 0.6

    def test_upsert_empty_countries_returns_empty_list(self, testdb):
        rec = _make_record(countries=[], country_weights={})
        testdb.intel_upsert(rec)
        got = testdb.intel_get(rec["id"])
        assert got["countries"] == []
        assert got["country_weights"] == {}

    def test_intel_list_includes_countries(self, testdb):
        rec = _make_record(countries=["UA", "RU"], country_weights={"UA": 1.0, "RU": 0.5})
        testdb.intel_upsert(rec)
        items = testdb.intel_list(source_type="hacktivist", limit=10)
        assert len(items) == 1
        assert items[0]["countries"] == ["UA", "RU"]

    def test_intel_active_in_window_includes_countries(self, testdb):
        rec = _make_record(
            status="auto_confirmed",
            countries=["TW"],
            country_weights={"TW": 1.0},
            confirmed_at=time.time(),
        )
        testdb.intel_upsert(rec)
        items = testdb.intel_active_in_window(since_ts=time.time() - 3600)
        assert len(items) == 1
        assert items[0]["countries"] == ["TW"]
        assert items[0]["country_weights"] == {"TW": 1.0}


# ── intel_queue.submit() backward compat ────────────────────────────────────

class TestSubmitBackwardCompat:
    """When a sensor sends only theater (no countries), submit() derives them."""

    def test_country_only_derives_countries(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        q = IntelQueue()

        item = {
            "source_type": "hacktivist",
            "source_id": "hacktivist_test",
            "theater": "UA",
            "ts": time.time(),
            "confidence": 0.50,
            "raw_text": "Ukraine government under DDoS attack",
            "headline": "DDoS on UA gov sites",
            "llm_fields": {},
            "score_delta": 2.0,
            "domain": "cyber",
        }
        item_id = q.submit(item)
        assert item_id is not None
        got = testdb.intel_get(item_id)
        assert got["countries"] == ["UA"]
        assert got["country_weights"] == {"UA": 1.0}

    def test_explicit_countries_preserved(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        q = IntelQueue()

        item = {
            "source_type": "diplomatic",
            "source_id": "diplomatic_test",
            "theater": "TW",
            "countries": ["TW", "JP"],
            "country_weights": {"TW": 1.0, "JP": 0.5},
            "ts": time.time(),
            "confidence": 0.60,
            "raw_text": "Taiwan strait tensions",
            "headline": "TW-JP defense statement",
            "llm_fields": {},
            "score_delta": 1.5,
            "domain": "info",
        }
        item_id = q.submit(item)
        assert item_id is not None
        got = testdb.intel_get(item_id)
        assert got["countries"] == ["TW", "JP"]
        assert got["country_weights"]["JP"] == 0.5


# ── Dedup: multi-country overlap ────────────────────────────────────────────

class TestDedupMultiCountry:
    def _submit(self, q, testdb, **overrides):
        item = {
            "source_type": "military",
            "source_id": "military_test",
            "theater": "TW",
            "countries": ["TW"],
            "country_weights": {"TW": 1.0},
            "ts": time.time(),
            "confidence": 0.60,
            "raw_text": "PLA exercise near Taiwan strait live fire drills",
            "headline": "PLA live fire exercise near Taiwan strait",
            "llm_fields": {},
            "score_delta": 2.0,
            "domain": "physical",
        }
        item.update(overrides)
        return q.submit(item)

    def test_same_countries_same_headline_deduped(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        q = IntelQueue()

        id1 = self._submit(q, testdb, source_id="mil_a")
        assert id1 is not None
        id2 = self._submit(
            q, testdb,
            source_id="mil_b",
            headline="PLA live fire exercise near Taiwan strait region",
        )
        assert id2 is None  # deduped

    def test_non_overlapping_countries_not_deduped(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        q = IntelQueue()

        id1 = self._submit(
            q, testdb,
            source_id="mil_a",
            theater="TW", countries=["TW"], country_weights={"TW": 1.0},
            headline="PLA exercise near Taiwan strait",
        )
        assert id1 is not None
        id2 = self._submit(
            q, testdb,
            source_id="mil_b",
            theater="UA", countries=["UA"], country_weights={"UA": 1.0},
            headline="PLA exercise near Ukraine border",
        )
        assert id2 is not None  # different region, not deduped

    def test_overlapping_countries_deduped(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        q = IntelQueue()

        id1 = self._submit(
            q, testdb,
            source_id="mil_a",
            countries=["TW", "JP"], country_weights={"TW": 1.0, "JP": 0.5},
            headline="PLA naval exercise Taiwan Japan waters",
        )
        assert id1 is not None
        id2 = self._submit(
            q, testdb,
            source_id="mil_b",
            countries=["JP"], country_weights={"JP": 1.0},
            headline="PLA naval exercise Taiwan Japan waters patrol",
        )
        assert id2 is None  # overlapping JP, similar headline → deduped


# ── get_active_rationale() multi-country output ─────────────────────────────

class TestActiveRationale:
    def test_rationale_includes_countries(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        q = IntelQueue()

        rec = _make_record(
            status="auto_confirmed",
            countries=["TW", "JP"],
            country_weights={"TW": 1.0, "JP": 0.6},
            confirmed_at=time.time(),
            score_delta=2.0,
        )
        testdb.intel_upsert(rec)

        from radar.intel_queue import _active_item_ids, _active_lock
        with _active_lock:
            _active_item_ids.add(rec["id"])

        rationale = q.get_active_rationale()
        assert len(rationale) >= 1
        entry = rationale[0]
        assert entry["countries"] == ["TW", "JP"]
        assert entry["country_weights"]["JP"] == 0.6
        assert entry["theater"] == "TW"

        with _active_lock:
            _active_item_ids.discard(rec["id"])

    def test_rationale_backward_compat_country_only(self, testdb, monkeypatch):
        monkeypatch.setattr("radar.intel_queue.db", testdb)
        from radar.intel_queue import IntelQueue
        q = IntelQueue()

        rec = _make_record(
            status="confirmed",
            countries=[],
            country_weights={},
            confirmed_at=time.time(),
            score_delta=1.5,
        )
        testdb.intel_upsert(rec)

        from radar.intel_queue import _active_item_ids, _active_lock
        with _active_lock:
            _active_item_ids.add(rec["id"])

        rationale = q.get_active_rationale()
        assert len(rationale) >= 1
        entry = rationale[0]
        assert entry["countries"] == []
        assert entry["country_weights"] == {}
        assert entry["theater"] == "TW"

        with _active_lock:
            _active_item_ids.discard(rec["id"])
