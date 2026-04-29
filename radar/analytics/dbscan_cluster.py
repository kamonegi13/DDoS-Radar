"""Pure-Python DBSCAN clustering over country-pair distances (G.3a).

No numpy / scipy dependency — DDoS-Radar runs in a constrained Python
environment and we only ever cluster a few dozen countries, so a
pure-Python O(N²) implementation is comfortable.

Algorithm (Ester et al., 1996):
  1. For each point, find neighbors within `eps` distance.
  2. A point is a "core" point if it has ≥ `min_samples` neighbors
     (including itself).
  3. Cluster IDs propagate transitively from core points: each
     unvisited point gets the cluster ID of the first core point that
     reaches it.
  4. Points that are not core and not reachable from any core point
     are marked as noise (cluster_id = -1).

Input shape:
  countries: list[str]                  — point labels
  distances: dict[tuple[a, b], float]   — symmetric, (a < b) keys

Output shape:
  list[ClusterMembership(country, cluster_id, is_core)]

NP3: when distances is empty (no pairs in matrix), returns every
country as noise (cluster_id=-1) rather than raising.
NP6: each cluster's centroid is the country closest to all other
members (lowest avg distance); usable as the cluster's representative
in UI without querying back into the matrix.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("radar.analytics.dbscan_cluster")


@dataclass(frozen=True)
class ClusterMembership:
    country: str
    cluster_id: int   # -1 for noise; 0..N for clusters
    is_core: bool


@dataclass(frozen=True)
class ClusteringResult:
    memberships: tuple[ClusterMembership, ...]
    n_clusters: int
    n_noise: int
    eps: float
    min_samples: int

    def cluster_countries(self, cluster_id: int) -> tuple[str, ...]:
        return tuple(
            m.country for m in self.memberships
            if m.cluster_id == cluster_id
        )

    def cluster_centroid(
        self, cluster_id: int, distances: dict,
    ) -> Optional[str]:
        """Member with the lowest average distance to all other members."""
        members = self.cluster_countries(cluster_id)
        if not members:
            return None
        if len(members) == 1:
            return members[0]
        best = members[0]
        best_avg = float("inf")
        for c in members:
            tot = 0.0
            n = 0
            for o in members:
                if c == o:
                    continue
                tot += _dist(c, o, distances)
                n += 1
            avg = tot / n if n > 0 else float("inf")
            if avg < best_avg:
                best_avg = avg
                best = c
        return best


def _pair_key(a: str, b: str) -> tuple[str, str]:
    """Return canonical (lower, higher) key for a country pair."""
    return (a, b) if a < b else (b, a)


def _dist(a: str, b: str, distances: dict) -> float:
    """Look up distance between two countries.

    A pair missing from `distances` means "no observed co-occurrence" —
    for clustering purposes we treat that as distance=1.0 (max distance,
    not infinity, so DBSCAN's eps comparison still works as expected).
    """
    if a == b:
        return 0.0
    return distances.get(_pair_key(a, b), 1.0)


def _neighbors(
    point: str, countries: list[str], distances: dict, eps: float,
) -> list[str]:
    return [
        other for other in countries
        if other != point and _dist(point, other, distances) <= eps
    ]


def cluster(
    countries: list[str],
    distances: dict,
    *,
    eps: float = 0.6,
    min_samples: int = 3,
) -> ClusteringResult:
    """Run DBSCAN over the given point set.

    `distances` is a {(a, b): distance} dict with canonical key order
    (a < b). Missing pairs are treated as distance=1.0 (the max).

    Returns one ClusterMembership per input country. Empty input yields
    an empty result; non-empty input always returns a result with at
    least the noise bucket populated.
    """
    n = len(countries)
    cluster_id_of: dict[str, int] = {c: -1 for c in countries}
    is_core: dict[str, bool] = {c: False for c in countries}
    visited: set[str] = set()

    next_cluster = 0
    for point in countries:
        if point in visited:
            continue
        visited.add(point)
        nbrs = _neighbors(point, countries, distances, eps)
        if len(nbrs) + 1 < min_samples:
            # not a core point; remains noise unless picked up later
            continue
        is_core[point] = True
        cluster_id_of[point] = next_cluster
        # BFS expansion
        queue = list(nbrs)
        while queue:
            q = queue.pop(0)
            if q not in visited:
                visited.add(q)
                q_nbrs = _neighbors(q, countries, distances, eps)
                if len(q_nbrs) + 1 >= min_samples:
                    is_core[q] = True
                    for other in q_nbrs:
                        if other not in visited or cluster_id_of[other] == -1:
                            queue.append(other)
            if cluster_id_of[q] == -1:
                cluster_id_of[q] = next_cluster
        next_cluster += 1

    memberships = tuple(
        ClusterMembership(country=c,
                          cluster_id=cluster_id_of[c],
                          is_core=is_core[c])
        for c in countries
    )
    n_noise = sum(1 for m in memberships if m.cluster_id == -1)
    return ClusteringResult(
        memberships=memberships,
        n_clusters=next_cluster,
        n_noise=n_noise,
        eps=eps,
        min_samples=min_samples,
    )


def matrix_to_distances(matrix: dict) -> dict[tuple[str, str], float]:
    """Convert a CooccurrenceMatrix.to_dict() shape into a distance map.

    distance(A, B) = 1.0 - share, where share is pair_count / total_buckets.
    A pair with share=0 (i.e. not in matrix.pairs at all) is treated as
    distance=1.0 by `_dist`; we don't need to add it explicitly.
    """
    out: dict[tuple[str, str], float] = {}
    for p in matrix.get("pairs", []):
        share = float(p.get("share", 0.0) or 0.0)
        # Bound to [0, 1] in case of ETL bug.
        share = min(1.0, max(0.0, share))
        key = _pair_key(p["a"], p["b"])
        out[key] = round(1.0 - share, 6)
    return out


__all__ = [
    "ClusterMembership",
    "ClusteringResult",
    "cluster",
    "matrix_to_distances",
]
