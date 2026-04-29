"""Tests for radar.calibration.lineage (Tier 2, commit 7)."""
from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("DEFAULT_ADMIN_PASSWORD", "testpass")

from radar.calibration import lineage, threshold_history


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    from radar.database import RadarDB
    p = tmp_path / "lineage.db"
    tdb = RadarDB(str(p))
    monkeypatch.setattr("radar.calibration.threshold_history.db", tdb)
    monkeypatch.setattr("radar.calibration.lineage.db", tdb)
    yield tdb
    tdb.close()


def _commit_row(*, value, predecessor_id=None):
    return threshold_history.record_change(
        key="test.lineage", value=value, scope_scenario_id=None,
        derived_from="test", applied_by="auto:test", sample_n=10,
        formula_ref="test#lineage", evidence={}, magnitude_pct=0.0,
        revertible_to_id=predecessor_id,
    )


# ── Single-row case ──


class TestSingleRow:
    def test_returns_self_only_when_no_chain(self, fresh_db):
        rid = _commit_row(value=0.5)
        graph = lineage.walk_lineage(rid)
        assert graph is not None
        assert graph.root_id == rid
        assert len(graph.nodes) == 1
        assert graph.nodes[0].role == "self"
        assert graph.nodes[0].depth == 0

    def test_returns_none_for_missing_id(self, fresh_db):
        graph = lineage.walk_lineage(99999999)
        assert graph is None


# ── Linear chain ──


class TestLinearChain:
    def test_walks_ancestors(self, fresh_db):
        a = _commit_row(value=0.1)
        b = _commit_row(value=0.2, predecessor_id=a)
        c = _commit_row(value=0.3, predecessor_id=b)
        graph = lineage.walk_lineage(c)
        assert graph is not None
        ancestors = graph.ancestors
        assert len(ancestors) == 2
        depths = [n.depth for n in ancestors]
        assert depths == [1, 2]
        ids = [n.record.id for n in ancestors]
        assert ids == [b, a]

    def test_walks_descendants(self, fresh_db):
        a = _commit_row(value=0.1)
        b = _commit_row(value=0.2, predecessor_id=a)
        c = _commit_row(value=0.3, predecessor_id=b)
        graph = lineage.walk_lineage(a)
        assert graph is not None
        descendants = graph.descendants
        assert len(descendants) == 2
        depths = [n.depth for n in descendants]
        assert sorted(depths) == [1, 2]
        ids = sorted([n.record.id for n in descendants])
        assert ids == sorted([b, c])


# ── Branched descendants ──


class TestBranchedDescendants:
    def test_captures_fanout(self, fresh_db):
        # a → b1, b2 (both reference a)
        a = _commit_row(value=0.1)
        b1 = _commit_row(value=0.2, predecessor_id=a)
        b2 = _commit_row(value=0.3, predecessor_id=a)
        graph = lineage.walk_lineage(a)
        assert graph is not None
        descendants_ids = {n.record.id for n in graph.descendants}
        assert descendants_ids == {b1, b2}


# ── Depth bound ──


class TestDepthBound:
    def test_max_depth_truncates(self, fresh_db):
        a = _commit_row(value=0.1)
        b = _commit_row(value=0.2, predecessor_id=a)
        c = _commit_row(value=0.3, predecessor_id=b)
        d = _commit_row(value=0.4, predecessor_id=c)
        graph = lineage.walk_lineage(d, max_depth=2)
        # Self + 2 ancestors max
        ancestors = graph.ancestors
        assert len(ancestors) == 2  # b and c, not a


# ── Serialization ──


class TestToDict:
    def test_to_dict_includes_role_and_depth(self, fresh_db):
        a = _commit_row(value=0.1)
        b = _commit_row(value=0.2, predecessor_id=a)
        graph = lineage.walk_lineage(b)
        out = graph.to_dict()
        assert out["root_id"] == b
        assert out["counts"]["self"] == 1
        assert out["counts"]["ancestors"] == 1
        assert out["counts"]["descendants"] == 0
        roles = [n["lineage_role"] for n in out["nodes"]]
        assert "self" in roles
        assert "ancestor" in roles


# ── Endpoint integration ──


@pytest.fixture
def client():
    import secrets
    from radar_api import app
    from radar import config
    from radar.auth import _hash_password
    from radar.database import db as live_db
    app.config["TESTING"] = True
    user = live_db.user_get("admin")
    if user:
        salt = secrets.token_hex(16)
        live_db.user_update_password(
            user["id"], _hash_password("TestAdminPass123!", salt), salt,
        )
    config.V2_API_ENABLED = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def admin_headers(client):
    resp = client.post("/api/auth/login", json={
        "username": "admin", "password": "TestAdminPass123!",
    })
    assert resp.status_code == 200
    return {"Authorization": f"Bearer {resp.get_json()['access_token']}"}


@pytest.fixture(autouse=True)
def cleanup_test_rows():
    yield
    try:
        from radar.database import db as live_db
        conn = live_db._get_conn()
        with conn.writing():
            conn.execute(
                "DELETE FROM threshold_history WHERE key='test.lineage_endpoint'"
            )
    except Exception:
        pass


class TestEndpoint:
    def test_lineage_endpoint_returns_404_for_missing(
        self, client, admin_headers,
    ):
        r = client.get("/api/v2/threshold_history/99999999/lineage",
                       headers=admin_headers)
        assert r.status_code == 404

    def test_lineage_endpoint_returns_graph(
        self, client, admin_headers, monkeypatch,
    ):
        from radar.database import db as live_db
        # Commit two rows in the production DB to have something to walk.
        a = threshold_history.record_change(
            key="test.lineage_endpoint", value=0.1,
            scope_scenario_id=None, derived_from="test",
            applied_by="auto:test", sample_n=10,
            formula_ref="test#endpoint", evidence={}, magnitude_pct=0.0,
        )
        b = threshold_history.record_change(
            key="test.lineage_endpoint", value=0.2,
            scope_scenario_id=None, derived_from="test",
            applied_by="auto:test", sample_n=10,
            formula_ref="test#endpoint", evidence={}, magnitude_pct=0.0,
            revertible_to_id=a,
        )
        r = client.get(f"/api/v2/threshold_history/{b}/lineage",
                       headers=admin_headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["data"]["root_id"] == b
        assert body["data"]["counts"]["ancestors"] == 1
        assert body["data"]["counts"]["self"] == 1
