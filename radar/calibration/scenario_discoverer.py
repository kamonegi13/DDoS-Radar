"""Scenario discovery pipeline (Tier 3, commit 10).

Glues the G.2 cooccurrence ETL (radar/analytics/cooccurrence.py) and
the G.3a DBSCAN clusterer (radar/analytics/dbscan_cluster.py) together
into a single daily pass:

  1. compute_matrix() → snapshot (or reuse latest within freshness)
  2. matrix_to_distances() → distance map
  3. cluster() → ClusteringResult
  4. Persist scenario_discovery_run + per-cluster discovery_cluster rows
  5. Emit scenario_proposals of type='scenario_discovery' for clusters
     that don't overlap with any existing scenario's participant set

Scheduler hook fires daily (cycle 4/24). Output is suggest-only —
NP7 forbids auto-creating scenarios. The Wizard UI in commit 14
surfaces these clusters as "candidate scenarios for analyst review".

Tunable env knobs:
  DISCOVERY_DBSCAN_EPS          (default 0.6)
  DISCOVERY_DBSCAN_MIN_SAMPLES  (default 3)
  DISCOVERY_SNAPSHOT_FRESH_HOURS (default 23) — reuse snapshot if newer
                                                 than this; else recompute

NP3: empty cooccurrence matrix → no clusters → no proposals (silent
     no-op). Missing tables → caught and logged.
NP6: every cluster row has formula_ref + the eps/min_samples it ran
     under. The proposal row has the cluster's countries in
     evidence_json.
NP7: never auto-applies. discovery_cluster rows are intermediate
     artifacts; only the scenario_proposals rows surface to the
     analyst, and the Wizard requires explicit confirmation.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

from radar.analytics import cooccurrence
from radar.analytics import dbscan_cluster as dbc
from radar.database import db

log = logging.getLogger("radar.calibration.scenario_discoverer")


PIPELINE_VERSION = "scenario_discoverer/v1"


def _eps() -> float:
    return float(os.getenv("DISCOVERY_DBSCAN_EPS", "0.6"))


def _min_samples() -> int:
    return int(os.getenv("DISCOVERY_DBSCAN_MIN_SAMPLES", "3"))


def _snapshot_fresh_hours() -> float:
    return float(os.getenv("DISCOVERY_SNAPSHOT_FRESH_HOURS", "23"))


# ── Snapshot freshness ──────────────────────────────────────────────────────


def _maybe_take_snapshot() -> Optional[dict]:
    """Return the latest cooccurrence snapshot, recomputing it if the
    most recent one is stale. Returns None on hard failure."""
    snap = cooccurrence.get_latest_snapshot()
    fresh_window = _snapshot_fresh_hours() * 3600
    now = time.time()
    if snap is not None and (now - snap["emitted_at"]) < fresh_window:
        return snap
    log.info("scenario_discoverer: refreshing cooccurrence snapshot")
    cooccurrence.run_once()
    return cooccurrence.get_latest_snapshot()


# ── Persistence ──────────────────────────────────────────────────────────────


def _persist_run(
    snapshot_id: int, result: dbc.ClusteringResult,
    distances: dict,
) -> Optional[int]:
    """Write one scenario_discovery_run row and per-cluster
    discovery_cluster rows. Returns the run id."""
    metadata = {
        "n_clusters": result.n_clusters,
        "n_noise": result.n_noise,
        "n_countries": len(result.memberships),
    }
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            cur = conn.execute(
                "INSERT INTO scenario_discovery_run "
                "(emitted_at, matrix_snapshot_id, algorithm, eps, "
                " min_samples, n_clusters, n_noise, formula_ref, "
                " metadata_json) "
                "VALUES (?, ?, 'dbscan', ?, ?, ?, ?, ?, ?)",
                (time.time(), snapshot_id, result.eps, result.min_samples,
                 result.n_clusters, result.n_noise,
                 f"{PIPELINE_VERSION}#dbscan",
                 json.dumps(metadata, sort_keys=True)),
            )
            run_id = cur.lastrowid
            for cid in range(result.n_clusters):
                members = list(result.cluster_countries(cid))
                centroid = result.cluster_centroid(cid, distances)
                conn.execute(
                    "INSERT INTO discovery_cluster "
                    "(run_id, cluster_index, countries_json, centroid_json, "
                    " annotation_state, formula_ref) "
                    "VALUES (?, ?, ?, ?, 'none', ?)",
                    (run_id, cid,
                     json.dumps(members, sort_keys=True),
                     json.dumps({"centroid": centroid}, sort_keys=True),
                     f"{PIPELINE_VERSION}#cluster"),
                )
        return run_id
    except Exception as exc:
        log.warning("persist_run failed: %s", exc)
        return None


def _emit_proposals(run_id: int, result: dbc.ClusteringResult) -> int:
    """Emit a scenario_proposals row for each cluster that does NOT
    fully overlap an existing scenario's participants. Returns count
    of proposals emitted."""
    try:
        from radar.scenarios import scenario_store
        existing_country_sets = [
            set(s.participants.keys())
            for s in scenario_store._scenarios.values()  # noqa: SLF001
        ]
    except Exception as exc:
        log.warning("scenario enumeration failed: %s", exc)
        existing_country_sets = []

    n_emitted = 0
    for cid in range(result.n_clusters):
        members = set(result.cluster_countries(cid))
        if not members:
            continue
        # Already-known cluster: members are a subset of an existing
        # scenario's participants AND that subset is "most" of the cluster
        # (Jaccard ≥ 0.7). Skip — no novel finding.
        if any(_jaccard(members, ex) >= 0.7 for ex in existing_country_sets):
            continue
        rid = _emit_one_proposal(run_id, cid, sorted(members))
        if rid is not None:
            n_emitted += 1
    return n_emitted


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _cluster_fingerprint(countries: list[str]) -> str:
    """Phase D (2026-04-30) — stable cluster identity for dedup.

    Two discovery proposals describe the same cluster when their
    countries SETS match, regardless of run_id or cluster_index. Using
    a sorted CSV string as a fingerprint stored in formula_ref's
    qualifier portion lets us SELECT prior pendings with the same set
    in one indexed lookup.
    """
    return ",".join(sorted(countries))


def _emit_one_proposal(run_id: int, cluster_id: int,
                        countries: list[str]) -> Optional[int]:
    """Write one scenario_proposals row for a discovery cluster.

    proposal_type='scenario_discovery' is new; the Wizard's apply path
    interprets it as 'create scenario' rather than 'mutate participant'.
    NP7: this stays pending until analyst confirmation.

    Phase D (2026-04-30): supersession by fingerprint. If a pending
    discovery proposal with the same countries SET already exists, we
    mark it 'superseded' and emit the new one (with the latest run_id
    and the fingerprint stamped in evidence_json). This stops the
    pre-fix behavior where every calibration tick added another copy
    of the same cluster (two IL/IR/UA proposals in the audit log).
    """
    fingerprint = _cluster_fingerprint(countries)
    why = (
        f"Discovery cluster {cluster_id} from run {run_id} groups "
        f"{len(countries)} countries that frequently co-occur in "
        f"llm_intel: {', '.join(countries)}. No existing scenario covers "
        f"this group. Consider creating a new scenario; analyst should "
        f"validate the relationship before applying."
    )
    try:
        conn = db._get_conn()  # noqa: SLF001
        with conn.writing():
            # Supersede any prior pending discovery proposals with the
            # same countries fingerprint. We match on fingerprint stored
            # in evidence_json — falling back to a LIKE pattern over
            # suggested_value_json for back-compat with rows emitted
            # before this commit.
            now_ts = time.time()
            superseded = conn.execute(
                "UPDATE scenario_proposals "
                "SET state='superseded', state_changed_at=?, "
                "    state_changed_by='auto:phase_d_fingerprint' "
                "WHERE proposal_type='scenario_discovery' "
                "AND state='pending' "
                "AND (json_extract(evidence_json, '$.cluster_fingerprint')=? "
                "     OR suggested_value_json LIKE ?)",
                (now_ts, fingerprint,
                 f'%"{countries[0]}"%' if countries else '%'),
            )
            if superseded.rowcount > 0:
                log.info(
                    "[scenario_discoverer] superseded %d prior pending "
                    "proposal(s) with same countries fingerprint=%s",
                    superseded.rowcount, fingerprint,
                )
            cur = conn.execute(
                "INSERT INTO scenario_proposals "
                "(emitted_at, scenario_id, proposal_type, target_country, "
                " suggested_value_json, evidence_json, formula_ref, "
                " sample_n, why_string, state) "
                "VALUES (?, '__discovery__', 'scenario_discovery', NULL, "
                "        ?, ?, ?, ?, ?, 'pending')",
                (time.time(),
                 json.dumps({"countries": countries,
                             "discovery_run_id": run_id,
                             "cluster_index": cluster_id,
                             "cluster_fingerprint": fingerprint},
                            sort_keys=True),
                 json.dumps({"discovery_run_id": run_id,
                             "cluster_index": cluster_id,
                             "country_count": len(countries),
                             "cluster_fingerprint": fingerprint},
                            sort_keys=True),
                 f"{PIPELINE_VERSION}#cluster_{cluster_id}",
                 len(countries), why),
            )
            return cur.lastrowid
    except Exception as exc:
        log.warning("emit_one_proposal failed: %s", exc)
        return None


# ── Driver ───────────────────────────────────────────────────────────────────


def run_once() -> dict:
    """Full pipeline: snapshot → cluster → persist → propose.

    Returns a summary dict for the run_now dispatcher and scheduler.
    """
    snap = _maybe_take_snapshot()
    if snap is None or snap["cell_count"] == 0:
        return {
            "skipped": True,
            "reason": "no_snapshot" if snap is None else "empty_matrix",
            "n_clusters": 0,
            "n_proposals": 0,
        }
    distances = dbc.matrix_to_distances(snap["matrix"])
    countries = list(snap["matrix"].get("countries", []))
    if not countries:
        return {"skipped": True, "reason": "no_countries",
                "n_clusters": 0, "n_proposals": 0}
    result = dbc.cluster(
        countries, distances,
        eps=_eps(), min_samples=_min_samples(),
    )
    run_id = _persist_run(snap["id"], result, distances)
    if run_id is None:
        return {"skipped": True, "reason": "persist_failed",
                "n_clusters": result.n_clusters, "n_proposals": 0}
    n_proposals = _emit_proposals(run_id, result)
    return {
        "skipped": False,
        "snapshot_id": snap["id"],
        "discovery_run_id": run_id,
        "n_clusters": result.n_clusters,
        "n_noise": result.n_noise,
        "n_countries": len(countries),
        "n_proposals": n_proposals,
        "eps": result.eps,
        "min_samples": result.min_samples,
    }


__all__ = ["run_once"]
