"""
GraphBuilder — turns engagement assets/services/findings into an attack graph.

The canonical graph is an in-memory ``networkx.DiGraph`` (so analysis is
deterministic and fully testable without a database). When a connected
``Neo4jClient`` is supplied, the same graph is mirrored into Neo4j via batched
``UNWIND`` writes for large-scale Cypher shortest-path queries.

Node types        : Asset, Service, Finding, Credential, NetworkSegment
Relationship types: HAS_SERVICE, HAS_FINDING, EXPLOITS, CONNECTS_TO,
                    SAME_SEGMENT, CREDENTIAL_REUSE

Node id convention: ``"{type}:{uuid}"`` e.g. ``asset:<uuid>`` — keeps the graph
namespaced so an asset and a finding can never collide.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any, Iterable

import networkx as nx
import structlog

from app.graph.neo4j_client import Neo4jClient

logger = structlog.get_logger()

# Environments that imply an internet-facing asset (attack source).
_EXPOSED_ENVIRONMENTS: frozenset[str] = frozenset(
    {"dmz", "external", "internet", "public", "perimeter", "edge"}
)

# Cypher cost = attack complexity. Lower = easier to exploit.
_AC_COMPLEXITY = {"L": 1.0, "M": 2.0, "H": 3.0}
_SEVERITY_COMPLEXITY = {
    "critical": 1.0, "high": 1.5, "medium": 2.5, "low": 3.0, "info": 4.0,
}


def asset_node_id(asset_id: Any) -> str:
    return f"asset:{asset_id}"


def service_node_id(service_id: Any) -> str:
    return f"service:{service_id}"


def finding_node_id(finding_id: Any) -> str:
    return f"finding:{finding_id}"


def _enum_value(v: Any, default: str = "") -> str:
    """Normalise a value that may be an Enum, str, or None to a lowercase str."""
    if v is None:
        return default
    return str(getattr(v, "value", v)).lower()


def _to_float(v: Any, default: float = 0.0) -> float:
    if v is None:
        return default
    if isinstance(v, Decimal):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def exploit_complexity(finding: Any) -> float:
    """
    Edge cost for an EXPLOITS edge. Derived from the CVSS Attack Complexity
    component when present, otherwise estimated from severity. Lower = easier.
    """
    vector = getattr(finding, "cvss_vector", None) or ""
    for token in str(vector).split("/"):
        if token.startswith("AC:"):
            return _AC_COMPLEXITY.get(token[3:].upper(), 2.0)
    sev = _enum_value(getattr(finding, "severity", None), "medium")
    return _SEVERITY_COMPLEXITY.get(sev, 2.5)


def is_internet_exposed(asset: Any) -> bool:
    tags = getattr(asset, "tags", None) or {}
    if isinstance(tags, dict) and tags.get("internet_exposed"):
        return True
    return _enum_value(getattr(asset, "environment", None)) in _EXPOSED_ENVIRONMENTS


class GraphBuilder:
    def __init__(self, neo4j: Neo4jClient | None = None):
        # MultiDiGraph: a pair of assets can be linked by several relationship
        # types at once (e.g. SAME_SEGMENT *and* CREDENTIAL_REUSE).
        self.graph = nx.MultiDiGraph()
        self._neo4j = neo4j

    # ── build_asset_graph ─────────────────────────────────────────────────────────

    def build_asset_graph(
        self,
        engagement_id: Any,
        assets: Iterable[Any],
        services: Iterable[Any] = (),
        findings: Iterable[Any] = (),
        credentials: Iterable[dict[str, Any]] | None = None,
        network_topology: dict[str, Any] | None = None,
    ) -> nx.MultiDiGraph:
        """
        Build the full multi-type attack graph. Returns the populated DiGraph
        (also stored on ``self.graph``).
        """
        g = self.graph
        g.clear()
        g.graph["engagement_id"] = str(engagement_id)

        assets = list(assets)
        services = list(services)
        findings = list(findings)

        # ── Asset nodes ──
        for a in assets:
            g.add_node(
                asset_node_id(a.id),
                type="Asset",
                entity_id=str(a.id),
                label=getattr(a, "hostname", None) or getattr(a, "ip_address", None) or str(a.id),
                ip=getattr(a, "ip_address", None),
                criticality=_enum_value(getattr(a, "criticality", None), "medium"),
                internet_exposed=is_internet_exposed(a),
                compromised=False,
            )

        # ── Service nodes + HAS_SERVICE ──
        for s in services:
            sid = service_node_id(s.id)
            g.add_node(
                sid,
                type="Service",
                entity_id=str(s.id),
                label=f"{getattr(s, 'service_name', None) or 'svc'}:{getattr(s, 'port', '')}",
                port=getattr(s, "port", None),
            )
            aid = asset_node_id(getattr(s, "asset_id", None))
            if g.has_node(aid):
                g.add_edge(aid, sid, type="HAS_SERVICE")

        # ── Finding nodes + HAS_FINDING ──
        for f in findings:
            fid = finding_node_id(f.id)
            cvss = _to_float(getattr(f, "cvss_score", None))
            g.add_node(
                fid,
                type="Finding",
                entity_id=str(f.id),
                label=getattr(f, "title", None) or str(f.id),
                cvss=cvss,
                severity=_enum_value(getattr(f, "severity", None), "info"),
                exploitable=bool(getattr(f, "exploitable", False)),
                exploit_validated=bool(getattr(f, "exploit_validated", False)),
                mitre=list(getattr(f, "mitre_techniques", None) or []),
            )
            aid = asset_node_id(getattr(f, "asset_id", None))
            if getattr(f, "asset_id", None) is not None and g.has_node(aid):
                g.add_edge(aid, fid, type="HAS_FINDING")

        # ── derived edges ──
        self.add_exploit_edges(findings)
        if network_topology:
            self.add_network_edges(assets, network_topology)
        if credentials:
            self._add_credential_edges(credentials)

        logger.info(
            "graph.build.done",
            engagement=str(engagement_id),
            nodes=g.number_of_nodes(),
            edges=g.number_of_edges(),
        )
        return g

    # ── add_exploit_edges ─────────────────────────────────────────────────────────

    def add_exploit_edges(self, findings: Iterable[Any]) -> int:
        """
        For each exploitable finding add an EXPLOITS edge Finding→Asset with
        ``weight = exploit_complexity`` (lower = easier). Returns edges added.
        """
        added = 0
        for f in findings:
            if not (getattr(f, "exploitable", False) or getattr(f, "exploit_validated", False)):
                continue
            aid = asset_node_id(getattr(f, "asset_id", None))
            fid = finding_node_id(f.id)
            if not (self.graph.has_node(aid) and self.graph.has_node(fid)):
                continue
            self.graph.add_edge(
                fid, aid,
                type="EXPLOITS",
                weight=exploit_complexity(f),
                cvss=_to_float(getattr(f, "cvss_score", None)),
                validated=bool(getattr(f, "exploit_validated", False)),
            )
            added += 1
        return added

    # ── add_network_edges ─────────────────────────────────────────────────────────

    def add_network_edges(self, assets: Iterable[Any], network_topology: dict[str, Any]) -> int:
        """
        Add CONNECTS_TO (directed reachability) and SAME_SEGMENT edges from
        segmentation data.

        ``network_topology`` =
          {
            "segments":    {"<segment-name>": ["<asset_id>", ...]},
            "connections": [["<src_asset_id>", "<dst_asset_id>"], ...],
          }
        Assets in the same segment are fully reachable from one another.
        """
        added = 0
        segments = network_topology.get("segments", {}) or {}
        for seg_name, member_ids in segments.items():
            seg_node = f"segment:{seg_name}"
            self.graph.add_node(seg_node, type="NetworkSegment", label=seg_name)
            members = [asset_node_id(m) for m in member_ids if self.graph.has_node(asset_node_id(m))]
            for m in members:
                self.graph.add_edge(m, seg_node, type="IN_SEGMENT")
            # SAME_SEGMENT lateral reachability (both directions).
            for i, a in enumerate(members):
                for b in members[i + 1:]:
                    self.graph.add_edge(a, b, type="SAME_SEGMENT", weight=1.0)
                    self.graph.add_edge(b, a, type="SAME_SEGMENT", weight=1.0)
                    added += 2

        for pair in network_topology.get("connections", []) or []:
            if len(pair) != 2:
                continue
            src, dst = asset_node_id(pair[0]), asset_node_id(pair[1])
            if self.graph.has_node(src) and self.graph.has_node(dst):
                self.graph.add_edge(src, dst, type="CONNECTS_TO", weight=1.0)
                added += 1
        return added

    def _add_credential_edges(self, credentials: Iterable[dict[str, Any]]) -> int:
        """
        CREDENTIAL_REUSE edges between assets sharing a credential.
        ``credentials`` items: {"id": ..., "label": ..., "reused_on": [asset_ids]}.
        """
        added = 0
        for cred in credentials:
            cid = f"credential:{cred.get('id')}"
            self.graph.add_node(cid, type="Credential", label=cred.get("label", str(cred.get("id"))))
            hosts = [asset_node_id(h) for h in cred.get("reused_on", []) if self.graph.has_node(asset_node_id(h))]
            for h in hosts:
                self.graph.add_edge(h, cid, type="HAS_CREDENTIAL")
            for i, a in enumerate(hosts):
                for b in hosts[i + 1:]:
                    self.graph.add_edge(a, b, type="CREDENTIAL_REUSE", weight=0.5, credential=cid)
                    self.graph.add_edge(b, a, type="CREDENTIAL_REUSE", weight=0.5, credential=cid)
                    added += 2
        return added

    # ── PostgreSQL loader ───────────────────────────────────────────────────────

    async def build_from_db(self, db: Any, engagement_id: Any) -> nx.MultiDiGraph:
        """Load assets/services/findings for an engagement and build the graph."""
        from sqlalchemy import select

        from app.models.asset import Asset
        from app.models.finding import Finding
        from app.models.service import Service

        assets = list((await db.execute(
            select(Asset).where(Asset.engagement_id == engagement_id)
        )).scalars().all())
        asset_ids = [a.id for a in assets]

        services = []
        findings = list((await db.execute(
            select(Finding).where(Finding.engagement_id == engagement_id)
        )).scalars().all())
        if asset_ids:
            services = list((await db.execute(
                select(Service).where(Service.asset_id.in_(asset_ids))
            )).scalars().all())

        graph = self.build_asset_graph(engagement_id, assets, services, findings)
        if self._neo4j is not None:
            self.sync_to_neo4j(engagement_id)
        return graph

    # ── Neo4j mirror ──────────────────────────────────────────────────────────────

    def sync_to_neo4j(self, engagement_id: Any) -> dict[str, int]:
        """Mirror the current in-memory graph into Neo4j via batched writes."""
        if self._neo4j is None:
            return {"nodes": 0, "edges": 0}
        self._neo4j.ensure_schema()

        nodes = [
            {"key": n, "engagement_id": str(engagement_id), **{k: v for k, v in data.items()}}
            for n, data in self.graph.nodes(data=True)
        ]
        # Single :GraphNode label keyed by `key`, with the real node type kept as
        # a property — avoids assuming the APOC plugin for dynamic labels.
        self._neo4j.run_write(
            "UNWIND $batch AS n MERGE (x:GraphNode {key: n.key}) SET x += n",
            nodes,
        )
        edges = [
            {"src": u, "dst": v, **{k: val for k, val in data.items()}}
            for u, v, data in self.graph.edges(data=True)
        ]
        self._neo4j.run_write(
            "UNWIND $batch AS e "
            "MATCH (a:GraphNode {key: e.src}) MATCH (b:GraphNode {key: e.dst}) "
            "MERGE (a)-[r:REL {type: e.type}]->(b) SET r += e",
            edges,
        )
        logger.info("graph.neo4j.synced", nodes=len(nodes), edges=len(edges))
        return {"nodes": len(nodes), "edges": len(edges)}
