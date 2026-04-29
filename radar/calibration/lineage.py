"""Threshold history lineage walker (Phase F2-d).

Given a row in threshold_history, this module walks the chain of
predecessors (older rows superseded by this one) and successors (newer
rows that reference this one as their revertible_to_id) so analysts can
audit how a threshold value evolved.

The structural ancestry comes from the `revertible_to_id` foreign key:
  - A row's *predecessor* = threshold_history[id == this.revertible_to_id]
  - A row's *successors* = threshold_history[revertible_to_id == this.id]

`derived_from` is a string identifier (calibrator version + reason),
not a foreign key. It is preserved on each LineageNode for context but
is not used as a graph edge.

Public API:
  walk_lineage(row_id) -> LineageGraph
  LineageGraph.to_dict() -> JSON-serializable

NP6: every node carries the full ThresholdRecord (formula_ref,
evidence, applied_by, sample_n, magnitude_pct) so a single walk gives
the analyst everything needed to reproduce a decision.

NP3: graceful no-op when the row id does not exist; bounded depth
(default 50) prevents runaway in the unlikely case of a cycle.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Optional

from radar.calibration.threshold_history import ThresholdRecord, get_by_id
from radar.database import db

log = logging.getLogger("radar.calibration.lineage")


@dataclass(frozen=True)
class LineageNode:
    """Single row in a lineage walk, with role + depth metadata."""
    record: ThresholdRecord
    role: str   # "self" | "ancestor" | "descendant"
    depth: int  # 0 for self; +1 per generation away

    def to_dict(self) -> dict:
        d = asdict(self.record)
        d["lineage_role"] = self.role
        d["lineage_depth"] = self.depth
        return d


@dataclass(frozen=True)
class LineageGraph:
    """Result of walk_lineage: root row plus all reachable predecessors
    and successors."""
    root_id: int
    nodes: tuple[LineageNode, ...] = field(default_factory=tuple)

    @property
    def ancestors(self) -> tuple[LineageNode, ...]:
        return tuple(n for n in self.nodes if n.role == "ancestor")

    @property
    def descendants(self) -> tuple[LineageNode, ...]:
        return tuple(n for n in self.nodes if n.role == "descendant")

    @property
    def self_node(self) -> Optional[LineageNode]:
        for n in self.nodes:
            if n.role == "self":
                return n
        return None

    def to_dict(self) -> dict:
        return {
            "root_id": self.root_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "counts": {
                "ancestors": len(self.ancestors),
                "descendants": len(self.descendants),
                "self": 1 if self.self_node else 0,
            },
        }


def _walk_ancestors(start: ThresholdRecord, *, max_depth: int) -> list[LineageNode]:
    """Follow revertible_to_id pointers backwards. Bounded by max_depth
    and an explicit visited-set to defend against cycles."""
    out: list[LineageNode] = []
    visited: set[int] = {start.id}
    current = start
    depth = 0
    while current.revertible_to_id is not None and depth < max_depth:
        depth += 1
        prior = get_by_id(current.revertible_to_id)
        if prior is None:
            break
        if prior.id in visited:
            log.warning(
                "lineage cycle detected at row %d (visited=%s)",
                prior.id, sorted(visited),
            )
            break
        visited.add(prior.id)
        out.append(LineageNode(record=prior, role="ancestor", depth=depth))
        current = prior
    return out


def _walk_descendants(start: ThresholdRecord, *,
                       max_depth: int) -> list[LineageNode]:
    """Find rows whose revertible_to_id points at the start (BFS).

    Uses a queue-style traversal so a fan-out (rare but possible if a
    revert and a new commit both reference the same predecessor) is
    captured fully.
    """
    out: list[LineageNode] = []
    visited: set[int] = {start.id}
    frontier: list[tuple[int, int]] = [(start.id, 0)]  # (id, depth)
    try:
        conn = db._get_conn()  # noqa: SLF001
    except Exception as exc:
        log.debug("descendants: db conn failed: %s", exc)
        return out

    while frontier:
        parent_id, depth = frontier.pop(0)
        if depth >= max_depth:
            continue
        try:
            rows = conn.execute(
                "SELECT id FROM threshold_history "
                "WHERE revertible_to_id=? ORDER BY id ASC",
                (parent_id,),
            ).fetchall()
        except Exception as exc:
            log.debug("descendants query failed at parent=%d: %s",
                      parent_id, exc)
            continue
        for r in rows:
            child_id = r[0]
            if child_id in visited:
                continue
            visited.add(child_id)
            child = get_by_id(child_id)
            if child is None:
                continue
            out.append(LineageNode(
                record=child, role="descendant", depth=depth + 1,
            ))
            frontier.append((child_id, depth + 1))
    return out


def walk_lineage(row_id: int, *, max_depth: int = 50) -> Optional[LineageGraph]:
    """Build a LineageGraph rooted at `row_id`.

    Returns None if the root row does not exist. NP3: any subtree
    failure during walking is logged and skipped — the partial graph
    is still returned. The graph always includes the root as a 'self'
    node when the root exists.
    """
    root = get_by_id(row_id)
    if root is None:
        return None
    nodes: list[LineageNode] = [
        LineageNode(record=root, role="self", depth=0),
    ]
    nodes.extend(_walk_ancestors(root, max_depth=max_depth))
    nodes.extend(_walk_descendants(root, max_depth=max_depth))
    return LineageGraph(root_id=row_id, nodes=tuple(nodes))


__all__ = [
    "LineageNode",
    "LineageGraph",
    "walk_lineage",
]
