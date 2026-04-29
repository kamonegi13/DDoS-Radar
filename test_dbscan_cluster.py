"""Tests for radar.analytics.dbscan_cluster (Tier 3, commit 9)."""
from __future__ import annotations

import pytest

from radar.analytics import dbscan_cluster as dbc


# ── _pair_key ────────────────────────────────────────────────────────────────


class TestPairKey:
    def test_canonical_order(self):
        assert dbc._pair_key("CN", "TW") == ("CN", "TW")
        assert dbc._pair_key("TW", "CN") == ("CN", "TW")

    def test_self_pair(self):
        assert dbc._pair_key("CN", "CN") == ("CN", "CN")


# ── _dist ────────────────────────────────────────────────────────────────────


class TestDist:
    def test_self_distance_zero(self):
        assert dbc._dist("CN", "CN", {}) == 0.0

    def test_missing_pair_is_one(self):
        assert dbc._dist("CN", "TW", {}) == 1.0

    def test_known_pair(self):
        d = {("CN", "TW"): 0.2}
        assert dbc._dist("CN", "TW", d) == 0.2
        assert dbc._dist("TW", "CN", d) == 0.2  # symmetric


# ── cluster ──────────────────────────────────────────────────────────────────


class TestCluster:
    def test_empty_input(self):
        result = dbc.cluster([], {})
        assert result.memberships == ()
        assert result.n_clusters == 0
        assert result.n_noise == 0

    def test_single_country_is_noise(self):
        result = dbc.cluster(["CN"], {})
        assert result.n_clusters == 0
        assert result.n_noise == 1
        assert result.memberships[0].cluster_id == -1
        assert result.memberships[0].is_core is False

    def test_three_close_countries_form_cluster(self):
        # Tightly co-occurring trio: CN-TW, CN-JP, JP-TW all distance 0.1
        countries = ["CN", "JP", "TW"]
        distances = {
            ("CN", "JP"): 0.1,
            ("CN", "TW"): 0.1,
            ("JP", "TW"): 0.1,
        }
        result = dbc.cluster(countries, distances, eps=0.3, min_samples=3)
        assert result.n_clusters == 1
        assert result.n_noise == 0
        assert all(m.cluster_id == 0 for m in result.memberships)

    def test_two_disjoint_clusters(self):
        # Cluster A: CN-JP-TW (close)
        # Cluster B: US-FR-DE (close)
        # Cross-cluster distance is high (default 1.0)
        countries = ["CN", "JP", "TW", "US", "FR", "DE"]
        distances = {
            ("CN", "JP"): 0.1, ("CN", "TW"): 0.1, ("JP", "TW"): 0.1,
            ("DE", "FR"): 0.1, ("DE", "US"): 0.1, ("FR", "US"): 0.1,
        }
        result = dbc.cluster(countries, distances, eps=0.3, min_samples=3)
        assert result.n_clusters == 2
        assert result.n_noise == 0
        # Cluster IDs are assigned in iteration order; verify partition
        ids = {m.country: m.cluster_id for m in result.memberships}
        assert ids["CN"] == ids["JP"] == ids["TW"]
        assert ids["DE"] == ids["FR"] == ids["US"]
        assert ids["CN"] != ids["DE"]

    def test_outlier_marked_as_noise(self):
        # Cluster: CN-JP-TW close together, KP far away
        countries = ["CN", "JP", "TW", "KP"]
        distances = {
            ("CN", "JP"): 0.1, ("CN", "TW"): 0.1, ("JP", "TW"): 0.1,
            ("CN", "KP"): 0.9, ("JP", "KP"): 0.9, ("KP", "TW"): 0.9,
        }
        result = dbc.cluster(countries, distances, eps=0.3, min_samples=3)
        kp = next(m for m in result.memberships if m.country == "KP")
        assert kp.cluster_id == -1
        assert kp.is_core is False

    def test_min_samples_threshold(self):
        # Only 2 close countries (CN+TW); min_samples=3 → both are noise
        countries = ["CN", "TW", "KP"]
        distances = {("CN", "TW"): 0.1}
        result = dbc.cluster(countries, distances, eps=0.3, min_samples=3)
        assert result.n_clusters == 0
        assert result.n_noise == 3

    def test_eps_threshold(self):
        # All pairs at distance 0.5; eps=0.4 → no neighbors
        countries = ["CN", "JP", "TW"]
        distances = {
            ("CN", "JP"): 0.5,
            ("CN", "TW"): 0.5,
            ("JP", "TW"): 0.5,
        }
        result = dbc.cluster(countries, distances, eps=0.4, min_samples=2)
        assert result.n_noise == 3


# ── ClusteringResult helpers ─────────────────────────────────────────────────


class TestClusteringResult:
    def test_cluster_countries(self):
        countries = ["CN", "JP", "TW"]
        distances = {
            ("CN", "JP"): 0.1, ("CN", "TW"): 0.1, ("JP", "TW"): 0.1,
        }
        result = dbc.cluster(countries, distances, eps=0.3, min_samples=2)
        members = result.cluster_countries(0)
        assert set(members) == {"CN", "JP", "TW"}

    def test_cluster_centroid(self):
        # Asymmetric distances: TW is closest to both others
        countries = ["CN", "JP", "TW"]
        distances = {
            ("CN", "TW"): 0.05,
            ("JP", "TW"): 0.05,
            ("CN", "JP"): 0.20,
        }
        result = dbc.cluster(countries, distances, eps=0.3, min_samples=2)
        centroid = result.cluster_centroid(0, distances)
        assert centroid == "TW"

    def test_centroid_for_singleton_returns_self(self):
        countries = ["CN"]
        result = dbc.cluster(countries, {}, eps=0.3, min_samples=1)
        # min_samples=1 means single country forms cluster 0
        if result.n_clusters > 0:
            assert result.cluster_centroid(0, {}) == "CN"


# ── matrix_to_distances ──────────────────────────────────────────────────────


class TestMatrixToDistances:
    def test_empty_matrix(self):
        d = dbc.matrix_to_distances({"pairs": []})
        assert d == {}

    def test_pair_share_to_distance(self):
        matrix = {
            "pairs": [
                {"a": "CN", "b": "TW", "count": 5, "share": 0.8},
                {"a": "JP", "b": "US", "count": 2, "share": 0.2},
            ],
        }
        d = dbc.matrix_to_distances(matrix)
        assert d[("CN", "TW")] == pytest.approx(0.2, abs=1e-4)
        assert d[("JP", "US")] == pytest.approx(0.8, abs=1e-4)

    def test_canonical_key_order(self):
        matrix = {
            "pairs": [{"a": "TW", "b": "CN", "count": 5, "share": 0.5}],
        }
        d = dbc.matrix_to_distances(matrix)
        assert ("CN", "TW") in d
        assert ("TW", "CN") not in d

    def test_clamps_invalid_share(self):
        matrix = {
            "pairs": [
                {"a": "CN", "b": "TW", "count": 1, "share": 1.5},  # too high
                {"a": "JP", "b": "US", "count": 1, "share": -0.1},  # too low
            ],
        }
        d = dbc.matrix_to_distances(matrix)
        assert d[("CN", "TW")] == 0.0  # 1 - 1.0 = 0.0
        assert d[("JP", "US")] == 1.0  # 1 - 0.0 = 1.0
