"""
GraphVisualizer — serialise the attack graph into D3-compatible JSON for the
frontend force-directed graph.

Output shape (matches the Prompt 6 data model):
  nodes: [{id, label, type, criticality, compromised, x, y}]
  edges: [{source, target, technique, weight, exploited}]
  paths: [{id, hops, risk_score, highlighted}]
"""
from __future__ import annotations

import math
from typing import Any

import networkx as nx


def _deterministic_layout(graph: nx.DiGraph) -> dict[str, tuple[float, float]]:
    """
    Numpy-free seed layout: place nodes on concentric rings by type so the
    frontend force simulation starts from a sensible, stable arrangement.
    Coordinates are in [-1, 1]; the frontend re-runs its own force layout.
    """
    ring_order = ["NetworkSegment", "Asset", "Service", "Finding", "Credential"]
    by_ring: dict[str, list[str]] = {}
    for n, data in graph.nodes(data=True):
        by_ring.setdefault(data.get("type", "Asset"), []).append(n)

    positions: dict[str, tuple[float, float]] = {}
    for ring_idx, node_type in enumerate(ring_order):
        members = sorted(by_ring.get(node_type, []))
        radius = 0.2 + 0.2 * ring_idx
        count = max(len(members), 1)
        for i, n in enumerate(members):
            angle = (2 * math.pi * i) / count
            positions[n] = (radius * math.cos(angle), radius * math.sin(angle))
    # Any unexpected types fall back to origin-ish.
    for n in graph.nodes:
        positions.setdefault(n, (0.0, 0.0))
    return positions


class GraphVisualizer:
    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph

    def to_d3(
        self,
        paths: list[dict[str, Any]] | None = None,
        compromised: set[str] | None = None,
        layout: bool = True,
    ) -> dict[str, Any]:
        """
        Build the D3 payload. ``compromised`` is a set of asset entity_ids to flag
        as owned. When ``layout`` is True, 2-D coordinates are precomputed with a
        deterministic spring layout so the frontend can render immediately.
        """
        compromised = compromised or set()
        positions: dict[str, Any] = {}
        if layout and self.graph.number_of_nodes():
            # Deterministic seed → stable coordinates across requests (numpy-free).
            positions = _deterministic_layout(self.graph)

        nodes = []
        for n, data in self.graph.nodes(data=True):
            pos = positions.get(n, (0.0, 0.0))
            entity = data.get("entity_id", n)
            nodes.append({
                "id": entity if data.get("type") == "Asset" else n,
                "node_key": n,
                "label": data.get("label", n),
                "type": data.get("type", "Unknown"),
                "criticality": data.get("criticality"),
                "compromised": entity in compromised,
                "internet_exposed": data.get("internet_exposed", False),
                "x": round(float(pos[0]) * 500, 2),
                "y": round(float(pos[1]) * 500, 2),
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "source": self.graph.nodes[u].get("entity_id", u),
                "target": self.graph.nodes[v].get("entity_id", v),
                "source_key": u,
                "target_key": v,
                "technique": data.get("type"),
                "weight": data.get("weight", 1.0),
                "exploited": data.get("type") == "EXPLOITS" or data.get("dest_compromisable", False),
            })

        path_summaries = []
        for i, p in enumerate(paths or []):
            path_summaries.append({
                "id": p.get("id", f"path-{i}"),
                "hops": p.get("hops"),
                "risk_score": p.get("risk_score"),
                "nodes": p.get("nodes"),
                "highlighted": i == 0,  # highlight the highest-risk path by default
            })

        return {"nodes": nodes, "edges": edges, "paths": path_summaries}
