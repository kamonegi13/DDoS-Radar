"""Tests for 1.1B: source_type breakdown in intel_confidence_distribution.

Background:
  intel_confidence_distribution() returns a global histogram across
  all LLM intel items. When tier3 corroborated auto-confirm landed
  (commit be8b7c9), operators needed to see whether confidence
  distribution differs by source_type (apt_intel vs hacktivist_news
  vs diplomatic vs ...) so per-sensor calibration drift becomes
  visible without shelling into the DB.

  This change adds a `by_source_type` field with the same histogram
  structure repeated per source_type. The existing `buckets` field
  (global aggregate) remains for backward compatibility — UI
  consumers that already rendered the global histogram are not
  forced to migrate.
"""
import os
import time
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

import pytest

from radar.database import db


@pytest.fixture
def fresh_intel(monkeypatch, tmp_path):
    """Insert a small known set of llm_intel rows and yield."""
    # Use the live DB but tag rows with a probe prefix so we can
    # filter to our test rows in assertions; cleanup at teardown.
    probe = f"test_{uuid.uuid4().hex[:8]}"
    now = time.time()
    rows = [
        # source_type, confidence, status
        ("apt_intel", 0.85, "auto_confirmed"),
        ("apt_intel", 0.45, "discarded_low_confidence"),
        ("apt_intel", 0.70, "pending"),
        ("hacktivist_news", 0.55, "pending"),
        ("hacktivist_news", 0.92, "auto_confirmed"),
        ("diplomatic", 0.30, "discarded_low_confidence"),
    ]
    conn = db._get_conn()
    with conn.writing():
        for i, (st, conf, status) in enumerate(rows):
            conn.execute(
                "INSERT INTO llm_intel "
                "(id, source_type, source_id, theater, ts, status, confidence, "
                "raw_text, raw_url, headline, llm_fields, score_delta, domain, "
                "created_at, countries, country_weights) "
                "VALUES (?, ?, '', '', ?, ?, ?, '', '', ?, '{}', 0.0, 'info', "
                "?, '[]', '{}')",
                (f"{probe}_{i}", st, now - 60, status, conf, f"probe-{i}", now - 60),
            )
    yield probe
    with conn.writing():
        conn.execute("DELETE FROM llm_intel WHERE id LIKE ?", (f"{probe}_%",))


class TestConfidenceDistributionBySourceType:
    def test_returns_by_source_type_field(self, fresh_intel):
        out = db.intel_confidence_distribution(hours=1)
        assert "by_source_type" in out, \
            f"expected 'by_source_type' key in response, got {list(out.keys())}"

    def test_per_source_type_has_total_and_buckets(self, fresh_intel):
        out = db.intel_confidence_distribution(hours=1)
        by_st = out["by_source_type"]
        # apt_intel had 3 probe rows
        assert "apt_intel" in by_st
        apt = by_st["apt_intel"]
        assert "total" in apt
        assert "buckets" in apt
        assert apt["total"] >= 3, \
            f"expected >=3 apt_intel rows, got {apt['total']}"

    def test_per_source_type_auto_confirmable_pct(self, fresh_intel):
        """Per-source-type auto_confirmable_pct is the calibration
        signal operators care about — surface it alongside buckets."""
        out = db.intel_confidence_distribution(hours=1)
        by_st = out["by_source_type"]
        # hacktivist_news had 1 of 2 above 0.80 → 50%
        if "hacktivist_news" in by_st:
            hn = by_st["hacktivist_news"]
            assert "auto_confirmable_pct" in hn

    def test_global_aggregate_still_present(self, fresh_intel):
        """Backward compat: existing `buckets`, `status_counts`,
        `total`, `auto_confirmable_pct` keys at the top level must
        survive so existing UI consumers do not break."""
        out = db.intel_confidence_distribution(hours=1)
        for key in ("buckets", "status_counts", "total", "auto_confirmable_pct"):
            assert key in out, \
                f"top-level key {key!r} dropped — breaks backward compat"

    def test_empty_window_returns_empty_by_source_type(self):
        """Zero-row window must return by_source_type as an empty
        dict, not raise or omit the field."""
        out = db.intel_confidence_distribution(hours=0)
        assert "by_source_type" in out
        assert isinstance(out["by_source_type"], dict)
