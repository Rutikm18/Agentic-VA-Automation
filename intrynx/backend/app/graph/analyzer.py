"""
PathAnalyzer — attack-path discovery, scoring, chokepoint and blast-radius
analysis over the GraphBuilder graph.

The analyzer works on an attacker *movement projection* of the full multi-type
graph: a directed edge Asset_A → Asset_B means an attacker who controls A can
reach and compromise B. B is "compromisable" when it carries an exploitable
finding; the movement edge inherits the cost of B's easiest exploit so that
NetworkX shortest-path uses real attack complexity as edge weight.

Equivalent Neo4j Cypher (used when a Neo4jClient is connected — see
``CYPHER_SHORTEST_PATH``) runs the same query server-side for >10k-node graphs.
"""
from __future__ import annotations

from typing import Any

import networkx as nx
import structlog

logger = structlog.get_logger()

# ── Cypher query examples (server-side equivalents) ───────────────────────────

CYPHER_SHORTEST_PATH = """
// Shortest attack path from any internet-exposed asset to a target.
MATCH (src:GraphNode {type: 'Asset', internet_exposed: true})
MATCH (tgt:GraphNode {type: 'Asset', entity_id: $target_id})
MATCH p = shortestPath((src)-[:CONNECTS_TO|SAME_SEGMENT|CREDENTIAL_REUSE|EXPLOITS*..10]->(tgt))
RETURN p, reduce(c = 0.0, r IN relationships(p) | c + coalesce(r.weight, 1.0)) AS cost
ORDER BY cost ASC
"""

CYPHER_BLAST_RADIUS = """
// All assets reachable from a compromised asset within 10 hops.
MATCH (src:GraphNode {type: 'Asset', entity_id: $asset_id})
MATCH (src)-[:CONNECTS_TO|SAME_SEGMENT|CREDENTIAL_REUSE*..10]->(reached:GraphNode {type: 'Asset'})
RETURN DISTINCT reached.entity_id AS asset_id
"""

CYPHER_CHOKEPOINTS = """
// Assets that appear on the most shortest paths to critical targets.
MATCH (tgt:GraphNode {type: 'Asset', criticality: 'critical'})
MATCH (src:GraphNode {type: 'Asset', internet_exposed: true})
MATCH p = shortestPath((src)-[*..10]->(tgt))
UNWIND nodes(p) AS hop
WITH hop, count(DISTINCT p) AS path_count
WHERE hop.type = 'Asset'
RETURN hop.entity_id AS asset_id, path_count ORDER BY path_count DESC
"""

# Relationship types an attacker can traverse for lateral movement.
_MOVEMENT_RELS = frozenset({"CONNECTS_TO", "SAME_SEGMENT", "CREDENTIAL_REUSE"})

# When several movement relationships link the same asset pair, the most
# reliable one labels the projected edge. Credential reuse is the most reliable.
_REL_PRIORITY = {"CREDENTIAL_REUSE": 3, "CONNECTS_TO": 2, "SAME_SEGMENT": 1}


class PathAnalyzer:
    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph
        self._movement: nx.DiGraph | None = None

    # ── attacker movement projection ──────────────────────────────────────────────

    def _exploit_info(self, asset_node: str) -> dict[str, Any]:
        """Best (easiest) exploitable finding on an asset: {cvss, weight, finding}."""
        best: dict[str, Any] | None = None
        for _, fid, edata in self.graph.out_edges(asset_node, data=True):
            if edata.get("type") != "HAS_FINDING":
                continue
            fdata = self.graph.nodes[fid]
            if not (fdata.get("exploitable") or fdata.get("exploit_validated")):
                continue
            # Weight from the EXPLOITS edge (Finding→Asset), fallback by severity.
            weight = 2.0
            for _, _tgt, xd in self.graph.out_edges(fid, data=True):
                if xd.get("type") == "EXPLOITS":
                    weight = xd.get("weight", 2.0)
                    break
            cand = {"finding": fdata.get("entity_id"), "cvss": fdata.get("cvss", 0.0), "weight": weight}
            if best is None or cand["weight"] < best["weight"]:
                best = cand
        return best or {}

    def movement_graph(self) -> nx.DiGraph:
        """
        Build (and cache) the Asset→Asset movement projection. Edge weight is the
        cost to compromise the destination (its easiest exploit), plus a small
        base cost for the hop itself so longer chains cost more.
        """
        if self._movement is not None:
            return self._movement

        mv = nx.DiGraph()
        for n, data in self.graph.nodes(data=True):
            if data.get("type") == "Asset":
                mv.add_node(n, **data)

        # Collapse parallel movement edges (MultiDiGraph) into one projected edge
        # per asset pair, keeping the lowest hop cost and the highest-priority rel.
        best: dict[tuple[str, str], dict[str, Any]] = {}
        for u, v, edata in self.graph.edges(data=True):
            rel = edata.get("type")
            if rel not in _MOVEMENT_RELS or not (mv.has_node(u) and mv.has_node(v)):
                continue
            hop_cost = edata.get("weight", 1.0)
            cur = best.get((u, v))
            if cur is None or _REL_PRIORITY.get(rel, 0) > _REL_PRIORITY.get(cur["rel"], 0):
                best[(u, v)] = {"rel": rel, "hop_cost": min(hop_cost, cur["hop_cost"]) if cur else hop_cost}
            elif hop_cost < cur["hop_cost"]:
                cur["hop_cost"] = hop_cost

        for (u, v), info in best.items():
            dest_exploit = self._exploit_info(v)
            cost = info["hop_cost"] + dest_exploit.get("weight", 3.0)  # no exploit ⇒ expensive
            mv.add_edge(
                u, v,
                weight=cost,
                rel=info["rel"],
                dest_compromisable=bool(dest_exploit),
                dest_cvss=dest_exploit.get("cvss", 0.0),
                dest_finding=dest_exploit.get("finding"),
            )
        self._movement = mv
        return mv

    def _source_assets(self, source_type: str) -> list[str]:
        mv = self.movement_graph()
        if source_type == "internet_exposed":
            return [n for n, d in mv.nodes(data=True) if d.get("internet_exposed")]
        if source_type == "any":
            return list(mv.nodes)
        # treat source_type as an explicit asset entity_id
        return [n for n, d in mv.nodes(data=True) if d.get("entity_id") == source_type]

    # ── find_paths_to_target ──────────────────────────────────────────────────────

    def find_paths_to_target(
        self,
        target_asset_id: Any,
        source_type: str = "internet_exposed",
        max_hops: int = 10,
        max_paths_per_source: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Return scored attack paths from every source asset to the target.
        Each path: {source, target, hops, nodes, edges, risk_score}.
        """
        mv = self.movement_graph()
        target_node = f"asset:{target_asset_id}"
        if not mv.has_node(target_node):
            return []

        paths: list[dict[str, Any]] = []
        for src in self._source_assets(source_type):
            if src == target_node:
                continue
            try:
                simple = nx.all_simple_paths(mv, src, target_node, cutoff=max_hops)
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                continue
            # Keep the cheapest few paths per source.
            scored = []
            for node_path in simple:
                scored.append(self._materialise_path(mv, node_path))
            scored.sort(key=lambda p: p["risk_score"], reverse=True)
            paths.extend(scored[:max_paths_per_source])

        paths.sort(key=lambda p: p["risk_score"], reverse=True)
        logger.info("graph.paths.found", target=str(target_asset_id), count=len(paths))
        return paths

    def _materialise_path(self, mv: nx.DiGraph, node_path: list[str]) -> dict[str, Any]:
        edges = []
        for a, b in zip(node_path, node_path[1:]):
            ed = mv.edges[a, b]
            edges.append({
                "source": mv.nodes[a].get("entity_id"),
                "target": mv.nodes[b].get("entity_id"),
                "technique": ed.get("rel"),
                "weight": ed.get("weight"),
                "exploited": ed.get("dest_compromisable", False),
                "cvss": ed.get("dest_cvss", 0.0),
            })
        path = {
            "source": mv.nodes[node_path[0]].get("entity_id"),
            "target": mv.nodes[node_path[-1]].get("entity_id"),
            "hops": len(node_path) - 1,
            "nodes": [mv.nodes[n].get("entity_id") for n in node_path],
            "edges": edges,
        }
        path["risk_score"] = self.score_path(path)
        return path

    # ── score_path ────────────────────────────────────────────────────────────────

    def score_path(self, path: dict[str, Any]) -> float:
        """
        Risk score 0–100 from: sum of exploit CVSS along the path, a penalty for
        the number of hops (longer chains are less likely), and a bonus when a
        credential-reuse edge is present (very reliable lateral movement).
        """
        edges = path.get("edges", [])
        sum_cvss = sum(_safe_float(e.get("cvss")) for e in edges)
        hops = path.get("hops", len(edges))
        has_cred_reuse = any(e.get("technique") == "CREDENTIAL_REUSE" for e in edges)

        raw = sum_cvss * 2.0          # CVSS 0-10 → up to 20 per hop
        raw -= hops * 1.5             # each extra hop lowers feasibility
        if has_cred_reuse:
            raw += 8.0
        return round(max(0.0, min(100.0, raw)), 2)

    # ── identify_chokepoints ──────────────────────────────────────────────────────

    def identify_chokepoints(
        self, paths: list[dict[str, Any]], threshold: float = 0.5
    ) -> list[dict[str, Any]]:
        """
        Assets that appear in more than ``threshold`` (default 50%) of all paths —
        cutting these breaks the most attack routes. Excludes each path's own
        source and target endpoints so genuine intermediary chokepoints surface.
        """
        if not paths:
            return []
        total = len(paths)
        counts: dict[str, int] = {}
        for p in paths:
            interior = p["nodes"][1:-1] if len(p["nodes"]) > 2 else []
            for asset_id in set(interior):
                counts[asset_id] = counts.get(asset_id, 0) + 1

        chokepoints = [
            {
                "asset_id": aid,
                "path_count": cnt,
                "path_fraction": round(cnt / total, 3),
                "remediation_priority": _priority(cnt / total),
            }
            for aid, cnt in counts.items()
            if cnt / total > threshold
        ]
        chokepoints.sort(key=lambda c: c["path_count"], reverse=True)
        return chokepoints

    # ── find_blast_radius ──────────────────────────────────────────────────────────

    def find_blast_radius(self, compromised_asset_id: Any, max_hops: int = 10) -> dict[str, Any]:
        """
        Assets reachable (and thus at risk) if ``compromised_asset_id`` is owned.
        Returns {origin, reachable: [asset_id], count, by_distance: {hop: [...]}}.
        """
        mv = self.movement_graph()
        origin = f"asset:{compromised_asset_id}"
        if not mv.has_node(origin):
            return {"origin": str(compromised_asset_id), "reachable": [], "count": 0, "by_distance": {}}

        lengths = nx.single_source_shortest_path_length(mv, origin, cutoff=max_hops)
        by_distance: dict[int, list[str]] = {}
        reachable: list[str] = []
        for node, dist in lengths.items():
            if node == origin:
                continue
            entity = mv.nodes[node].get("entity_id")
            reachable.append(entity)
            by_distance.setdefault(dist, []).append(entity)

        return {
            "origin": str(compromised_asset_id),
            "reachable": reachable,
            "count": len(reachable),
            "by_distance": {str(k): v for k, v in sorted(by_distance.items())},
        }


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _priority(fraction: float) -> str:
    if fraction >= 0.8:
        return "critical"
    if fraction >= 0.65:
        return "high"
    return "medium"
